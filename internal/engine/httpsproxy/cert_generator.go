package httpsproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"time"

	"github.com/soapbucket/sbproxy/internal/config"
)

// CertGenerator generates per-host leaf certificates signed by a CA certificate.
// It uses ECDSA P-256 keys for fast generation and 24-hour validity for security.
// Generated certificates are cached using the existing CertificateCache to avoid
// regenerating certs for the same hostname within the TTL window.
type CertGenerator struct {
	caCert *x509.Certificate
	caKey  interface{} // crypto.PrivateKey (ecdsa, rsa, or ed25519)
	cache  *config.CertificateCache
}

// NewCertGenerator creates a CertGenerator from a parsed CA certificate and its
// private key. The cache is used to store and retrieve previously generated leaf
// certificates. If cache is nil, every call to GetOrCreateCert will generate a
// fresh certificate.
func NewCertGenerator(caCert *x509.Certificate, caKey interface{}, cache *config.CertificateCache) (*CertGenerator, error) {
	if caCert == nil {
		return nil, fmt.Errorf("CA certificate is required")
	}
	if caKey == nil {
		return nil, fmt.Errorf("CA private key is required")
	}
	if !caCert.IsCA {
		return nil, fmt.Errorf("provided certificate is not a CA certificate")
	}
	return &CertGenerator{
		caCert: caCert,
		caKey:  caKey,
		cache:  cache,
	}, nil
}

// NewCertGeneratorFromTLS creates a CertGenerator from a tls.Certificate (which
// bundles raw DER bytes and the private key). This is a convenience wrapper for
// callers that already hold a *tls.Certificate loaded from PEM/secrets.
func NewCertGeneratorFromTLS(tlsCert *tls.Certificate, cache *config.CertificateCache) (*CertGenerator, error) {
	if tlsCert == nil {
		return nil, fmt.Errorf("TLS certificate is required")
	}
	if len(tlsCert.Certificate) == 0 {
		return nil, fmt.Errorf("TLS certificate has no certificate data")
	}
	caCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}
	return NewCertGenerator(caCert, tlsCert.PrivateKey, cache)
}

// certValidity is the lifetime of generated leaf certificates.
const certValidity = 24 * time.Hour

// GetOrCreateCert returns a TLS certificate for the given hostname. If a valid
// (non-expired) certificate exists in the cache it is returned immediately.
// Otherwise a new ECDSA P-256 leaf certificate is generated, signed by the CA,
// stored in the cache, and returned.
func (g *CertGenerator) GetOrCreateCert(hostname string) (*tls.Certificate, error) {
	if hostname == "" {
		return nil, fmt.Errorf("hostname is required")
	}

	// Check cache first.
	if g.cache != nil {
		if cached, found := g.cache.Get(hostname); found {
			slog.Debug("cert_generator: cache hit", "hostname", hostname)
			return cached, nil
		}
	}

	cert, err := g.generateLeafCert(hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to generate leaf certificate for %s: %w", hostname, err)
	}

	// Store in cache.
	if g.cache != nil {
		g.cache.Set(hostname, cert)
	}

	slog.Debug("cert_generator: generated new leaf certificate", "hostname", hostname)
	return cert, nil
}

// generateLeafCert creates a new ECDSA P-256 leaf certificate for hostname,
// signed by the CA certificate.
func (g *CertGenerator) generateLeafCert(hostname string) (*tls.Certificate, error) {
	// Generate ECDSA P-256 private key (fast generation, small key size).
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	// Random serial number (128 bits).
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore:             now.Add(-5 * time.Minute), // Small backdate for clock skew.
		NotAfter:              now.Add(certValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Set SAN: IP address or DNS name.
	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{hostname}
		// For wildcard hostnames, also include the bare domain.
		if len(hostname) > 2 && hostname[0] == '*' && hostname[1] == '.' {
			template.DNSNames = append(template.DNSNames, hostname[2:])
		}
	}

	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		g.caCert,
		&leafKey.PublicKey,
		g.caKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to sign leaf certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  leafKey,
	}, nil
}

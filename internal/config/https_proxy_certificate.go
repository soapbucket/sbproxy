// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"sync"
	"time"
)

// CertificateLoader handles loading and managing certificates for HTTPS proxy
type CertificateLoader struct {
	secretResolver SecretResolver // Function to resolve secret values
}

// SecretResolver resolves secret names to their values
// In production, this would fetch from vault/secrets manager
type SecretResolver func(secretName string) (string, error)

// NewCertificateLoader creates a new certificate loader
func NewCertificateLoader(resolver SecretResolver) *CertificateLoader {
	if resolver == nil {
		// Default resolver that returns error for all secrets
		resolver = func(secretName string) (string, error) {
			return "", fmt.Errorf("no secret resolver configured")
		}
	}

	return &CertificateLoader{
		secretResolver: resolver,
	}
}

// LoadServerCertificate loads the server TLS certificate from configuration
// If certificate config is nil, returns nil (will use default)
func (cl *CertificateLoader) LoadServerCertificate(config *CertificateConfig) (*tls.Certificate, error) {
	if config == nil {
		slog.Info("no server certificate configuration provided, using defaults")
		return nil, nil
	}

	if config.CertSecret == "" || config.KeySecret == "" {
		return nil, fmt.Errorf("certificate and key secrets must be provided")
	}

	// Resolve certificate secret
	certPEM, err := cl.secretResolver(config.CertSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve certificate secret: %w", err)
	}

	// Resolve key secret
	keyPEM, err := cl.secretResolver(config.KeySecret)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve key secret: %w", err)
	}

	// Parse certificate and key
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate and key: %w", err)
	}

	// Parse the certificate to validate it
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse x509 certificate: %w", err)
	}

	// Check if certificate is already expired
	if time.Now().After(x509Cert.NotAfter) {
		return nil, fmt.Errorf("certificate has expired: %v", x509Cert.NotAfter)
	}

	// Check if certificate will expire soon (within 7 days)
	if time.Until(x509Cert.NotAfter) < 7*24*time.Hour {
		slog.Warn("server certificate will expire soon",
			"expiry", x509Cert.NotAfter,
			"days_remaining", time.Until(x509Cert.NotAfter).Hours()/24)
	}

	slog.Info("loaded server certificate",
		"subject", x509Cert.Subject.String(),
		"expiry", x509Cert.NotAfter)

	return &cert, nil
}

// LoadMITMCACertificate loads the MITM CA certificate for certificate generation
// Returns both the CA certificate and CA key pair
func (cl *CertificateLoader) LoadMITMCACertificate(config *CertSpoofingConfig) (*tls.Certificate, error) {
	if config == nil || !config.Enabled {
		slog.Debug("MITM certificate spoofing disabled")
		return nil, nil
	}

	if config.CertificateSecret == "" || config.KeySecret == "" {
		return nil, fmt.Errorf("MITM certificate and key secrets must be provided")
	}

	// Resolve MITM CA certificate secret
	certPEM, err := cl.secretResolver(config.CertificateSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve MITM CA certificate secret: %w", err)
	}

	// Resolve MITM CA key secret
	keyPEM, err := cl.secretResolver(config.KeySecret)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve MITM CA key secret: %w", err)
	}

	// Parse certificate and key
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse MITM CA certificate and key: %w", err)
	}

	// Parse the certificate to validate it
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse MITM CA x509 certificate: %w", err)
	}

	// Verify it's a CA certificate
	if !x509Cert.IsCA {
		return nil, fmt.Errorf("provided MITM certificate is not a CA certificate")
	}

	slog.Info("loaded MITM CA certificate",
		"subject", x509Cert.Subject.String(),
		"expiry", x509Cert.NotAfter)

	return &cert, nil
}

// MITMCertificateGenerator generates certificates signed by the MITM CA
type MITMCertificateGenerator struct {
	caCert *tls.Certificate
	caX509 *x509.Certificate
}

// NewMITMCertificateGenerator creates a new MITM certificate generator
func NewMITMCertificateGenerator(caCert *tls.Certificate) (*MITMCertificateGenerator, error) {
	if caCert == nil {
		return nil, fmt.Errorf("CA certificate required")
	}

	// Parse CA certificate
	caX509, err := x509.ParseCertificate(caCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	return &MITMCertificateGenerator{
		caCert: caCert,
		caX509: caX509,
	}, nil
}

// GenerateCertificate generates a certificate signed by the MITM CA for the given hostname
func (gen *MITMCertificateGenerator) GenerateCertificate(hostname string) (*tls.Certificate, error) {
	if hostname == "" {
		return nil, fmt.Errorf("hostname required")
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Generate server certificate template
	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 1, 0), // Valid for 1 month
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	if ip := net.ParseIP(hostname); ip != nil {
		certTemplate.IPAddresses = []net.IP{ip}
	} else {
		// Add hostname as SAN (Subject Alternative Name)
		certTemplate.DNSNames = []string{hostname}

		// Handle wildcard hostnames
		if len(hostname) > 0 && hostname[0] == '*' && len(hostname) > 2 {
			// For wildcard, also add the bare domain
			certTemplate.DNSNames = append(certTemplate.DNSNames, hostname[2:])
		}
	}

	// Generate private key for server certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Sign the certificate with the CA
	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		certTemplate,
		gen.caX509,
		&privateKey.PublicKey,
		gen.caCert.PrivateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Create tls.Certificate
	cert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  privateKey,
	}

	slog.Debug("generated MITM certificate", "hostname", hostname)

	return cert, nil
}

// CertificateManager handles complete certificate lifecycle
type CertificateManager struct {
	loader    *CertificateLoader
	generator *MITMCertificateGenerator
}

// NewCertificateManager creates a new certificate manager
func NewCertificateManager(loader *CertificateLoader) *CertificateManager {
	return &CertificateManager{
		loader: loader,
	}
}

// Initialize loads certificates from configuration
func (cm *CertificateManager) Initialize(httpsCfg *HTTPSProxyConfig) error {
	if httpsCfg == nil {
		return fmt.Errorf("HTTPS proxy config required")
	}

	// Load MITM CA certificate if spoofing is enabled
	if httpsCfg.CertificateSpoofing != nil && httpsCfg.CertificateSpoofing.Enabled {
		mitmCA, err := cm.loader.LoadMITMCACertificate(httpsCfg.CertificateSpoofing)
		if err != nil {
			return fmt.Errorf("failed to load MITM CA certificate: %w", err)
		}

		if mitmCA != nil {
			gen, err := NewMITMCertificateGenerator(mitmCA)
			if err != nil {
				return fmt.Errorf("failed to create certificate generator: %w", err)
			}
			cm.generator = gen
		}
	}

	slog.Info("certificate manager initialized")
	return nil
}

// GetOrGenerateCertificate gets a certificate for the hostname, generating if needed
func (cm *CertificateManager) GetOrGenerateCertificate(hostname string, cache *CertificateCache) (*tls.Certificate, error) {
	if hostname == "" {
		return nil, fmt.Errorf("hostname required")
	}

	// Check cache first
	if cache != nil {
		if cached, found := cache.Get(hostname); found {
			slog.Debug("using cached certificate", "hostname", hostname)
			return cached, nil
		}
	}

	// Generate new certificate if generator available
	if cm.generator == nil {
		return nil, fmt.Errorf("MITM certificate generator not initialized")
	}

	cert, err := cm.generator.GenerateCertificate(hostname)
	if err != nil {
		return nil, err
	}

	// Cache the certificate
	if cache != nil {
		cache.Set(hostname, cert)
	}

	return cert, nil
}

type cachedCertificate struct {
	cert      *tls.Certificate
	expiresAt time.Time
}

// defaultCertCacheMaxSize is the default upper bound on cached certificates.
const defaultCertCacheMaxSize = 10000

// CertificateCache is a TTL-aware, bounded cache for generated MITM certificates.
type CertificateCache struct {
	mu      sync.RWMutex
	certs   map[string]cachedCertificate
	ttl     time.Duration
	maxSize int
}

// NewCertificateCache creates a new certificate cache with TTL and a default
// maximum size of 10,000 entries.
func NewCertificateCache(ttl time.Duration) *CertificateCache {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &CertificateCache{
		certs:   make(map[string]cachedCertificate),
		ttl:     ttl,
		maxSize: defaultCertCacheMaxSize,
	}
}

// NewCertificateCacheWithMaxSize creates a certificate cache with custom TTL and max size.
func NewCertificateCacheWithMaxSize(ttl time.Duration, maxSize int) *CertificateCache {
	cc := NewCertificateCache(ttl)
	if maxSize > 0 {
		cc.maxSize = maxSize
	}
	return cc
}

// Get retrieves a certificate from cache if not expired.
// Lazily cleans expired entries when a miss is detected.
func (cc *CertificateCache) Get(hostname string) (*tls.Certificate, bool) {
	if cc == nil {
		return nil, false
	}

	cc.mu.RLock()
	cached, ok := cc.certs[hostname]
	cc.mu.RUnlock()
	if !ok {
		return nil, false
	}
	now := time.Now()
	if !cached.expiresAt.IsZero() && now.After(cached.expiresAt) {
		// Entry expired - take write lock, delete it, and run lazy cleanup
		cc.mu.Lock()
		delete(cc.certs, hostname)
		cc.cleanExpiredLocked(now)
		cc.mu.Unlock()
		return nil, false
	}
	return cached.cert, true
}

// Set stores a certificate in cache. If the cache is at capacity, expired
// entries are cleaned first. If still at capacity, one arbitrary entry is
// evicted to make room.
func (cc *CertificateCache) Set(hostname string, cert *tls.Certificate) {
	if cc == nil {
		return
	}

	cc.mu.Lock()
	defer cc.mu.Unlock()

	if cc.certs == nil {
		cc.certs = make(map[string]cachedCertificate)
	}

	// If at capacity, try cleaning expired entries first
	if len(cc.certs) >= cc.maxSize {
		cc.cleanExpiredLocked(time.Now())
	}

	// Still at capacity after cleanup - evict one arbitrary entry
	if len(cc.certs) >= cc.maxSize {
		for key := range cc.certs {
			delete(cc.certs, key)
			break
		}
	}

	cc.certs[hostname] = cachedCertificate{
		cert:      cert,
		expiresAt: time.Now().Add(cc.ttl),
	}
}

// Clear removes all cached certificates.
func (cc *CertificateCache) Clear() {
	if cc == nil {
		return
	}
	cc.mu.Lock()
	cc.certs = make(map[string]cachedCertificate)
	cc.mu.Unlock()
}

// CleanExpired removes all certificates whose TTL has elapsed or whose
// underlying X.509 NotAfter date has passed. Safe for concurrent use.
func (cc *CertificateCache) CleanExpired() {
	if cc == nil {
		return
	}
	cc.mu.Lock()
	cc.cleanExpiredLocked(time.Now())
	cc.mu.Unlock()
}

// cleanExpiredLocked removes expired entries. Caller must hold cc.mu write lock.
func (cc *CertificateCache) cleanExpiredLocked(now time.Time) {
	for key, cached := range cc.certs {
		// Remove entries past their cache TTL
		if !cached.expiresAt.IsZero() && now.After(cached.expiresAt) {
			delete(cc.certs, key)
			continue
		}
		// Remove entries whose X.509 certificate has expired (NotAfter)
		if cached.cert != nil && len(cached.cert.Certificate) > 0 {
			x509Cert, err := x509.ParseCertificate(cached.cert.Certificate[0])
			if err == nil && now.After(x509Cert.NotAfter) {
				delete(cc.certs, key)
			}
		}
	}
}

// Len returns the number of certificates currently in the cache.
func (cc *CertificateCache) Len() int {
	if cc == nil {
		return 0
	}
	cc.mu.RLock()
	n := len(cc.certs)
	cc.mu.RUnlock()
	return n
}

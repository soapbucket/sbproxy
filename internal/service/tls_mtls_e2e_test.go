package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// testCA generates a self-signed CA certificate and key for testing mTLS.
func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return cert, key, certPEM
}

// testLeafCert creates a server or client certificate signed by the given CA.
func testLeafCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, isServer bool) (tls.Certificate, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<32))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	if isServer {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = []string{"localhost", "127.0.0.1"}
		template.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load X509 key pair: %v", err)
	}
	return tlsCert, certPEM
}

// TestMTLS_RequireMode_RejectsWithoutClientCert verifies that a TLS server
// configured with ClientAuth = RequireAnyClientCert rejects connections that
// do not present a client certificate.
func TestMTLS_RequireMode_RejectsWithoutClientCert(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	serverCert, _ := testLeafCert(t, caCert, caKey, "localhost", true)

	// Build server TLS config with require mode
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}

	// Start HTTPS test server
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	srv.TLS = serverTLSConfig
	srv.StartTLS()
	defer srv.Close()

	// Client WITHOUT a client cert (but trusts the server CA)
	clientTLSConfig := &tls.Config{
		RootCAs:    caPool,
		MinVersion: tls.VersionTLS12,
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: clientTLSConfig},
		Timeout:   5 * time.Second,
	}

	_, err := client.Get(srv.URL)
	if err == nil {
		t.Fatal("expected connection to fail without client cert in require mode")
	}
	// The error should indicate a TLS handshake failure
	t.Logf("got expected error: %v", err)
}

// TestMTLS_VerifyIfGiven_AcceptsWithoutCert verifies that verify_if_given mode
// accepts connections without a client certificate.
func TestMTLS_VerifyIfGiven_AcceptsWithoutCert(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	serverCert, _ := testLeafCert(t, caCert, caKey, "localhost", true)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "no-cert-ok")
	}))
	srv.TLS = serverTLSConfig
	srv.StartTLS()
	defer srv.Close()

	// Client without client cert
	clientTLSConfig := &tls.Config{
		RootCAs:    caPool,
		MinVersion: tls.VersionTLS12,
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: clientTLSConfig},
		Timeout:   5 * time.Second,
	}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("expected connection to succeed without cert in verify_if_given mode: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "no-cert-ok" {
		t.Errorf("unexpected body: %s", string(body))
	}
}

// TestMTLS_VerifyIfGiven_ValidatesWhenPresent verifies that verify_if_given
// mode validates client certificates when one is presented, rejecting
// certificates not signed by the expected CA.
func TestMTLS_VerifyIfGiven_ValidatesWhenPresent(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	serverCert, _ := testLeafCert(t, caCert, caKey, "localhost", true)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = serverTLSConfig
	srv.StartTLS()
	defer srv.Close()

	// Create a different CA (not trusted by the server) and sign a client cert with it
	rogueCACert, rogueCAKey, _ := testCA(t)
	rogueClientCert, _ := testLeafCert(t, rogueCACert, rogueCAKey, "rogue-client", false)

	clientTLSConfig := &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{rogueClientCert},
		MinVersion:   tls.VersionTLS12,
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: clientTLSConfig},
		Timeout:   5 * time.Second,
	}

	_, err := client.Get(srv.URL)
	if err == nil {
		t.Fatal("expected connection to fail with untrusted client cert in verify_if_given mode")
	}
	t.Logf("got expected error for rogue cert: %v", err)
}

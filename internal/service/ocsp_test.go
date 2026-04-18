package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestNewOCSPStapler(t *testing.T) {
	s := NewOCSPStapler()
	if s == nil {
		t.Fatal("expected non-nil stapler")
	}
	if s.cache == nil {
		t.Fatal("expected non-nil cache")
	}
}

func TestOCSPStapler_Fetch_NotImplemented(t *testing.T) {
	s := NewOCSPStapler()

	cert, issuer := generateTestCertPair(t)
	_, err := s.Fetch(cert, issuer)
	if err == nil {
		t.Fatal("expected error from stub Fetch")
	}
}

func TestOCSPStapler_Fetch_NilCert(t *testing.T) {
	s := NewOCSPStapler()
	_, err := s.Fetch(nil, nil)
	if err == nil {
		t.Fatal("expected error for nil cert")
	}
}

func TestOCSPStapler_PutAndStapleTo(t *testing.T) {
	s := NewOCSPStapler()

	cert, _ := generateTestCertPair(t)
	fakeOCSP := []byte("fake-ocsp-response")

	s.Put(cert, fakeOCSP)

	// Create a TLS certificate from the x509 cert.
	tlsCert := &tls.Certificate{
		Certificate: [][]byte{cert.Raw},
	}

	err := s.StapleTo(tlsCert, nil)
	if err != nil {
		t.Fatalf("StapleTo: %v", err)
	}

	if string(tlsCert.OCSPStaple) != string(fakeOCSP) {
		t.Errorf("OCSPStaple = %q, want %q", tlsCert.OCSPStaple, fakeOCSP)
	}
}

func TestOCSPStapler_StapleTo_NoCached(t *testing.T) {
	s := NewOCSPStapler()

	cert, _ := generateTestCertPair(t)
	tlsCert := &tls.Certificate{
		Certificate: [][]byte{cert.Raw},
	}

	err := s.StapleTo(tlsCert, nil)
	if err == nil {
		t.Fatal("expected error when no cached response")
	}
}

func TestOCSPStapler_StapleTo_NilCert(t *testing.T) {
	s := NewOCSPStapler()
	err := s.StapleTo(nil, nil)
	if err == nil {
		t.Fatal("expected error for nil tls cert")
	}
}

func TestOCSPStapler_StapleTo_EmptyCert(t *testing.T) {
	s := NewOCSPStapler()
	tlsCert := &tls.Certificate{}
	err := s.StapleTo(tlsCert, nil)
	if err == nil {
		t.Fatal("expected error for empty certificate data")
	}
}

func TestOCSPStapler_Put_NilCert(t *testing.T) {
	s := NewOCSPStapler()
	// Should not panic.
	s.Put(nil, []byte("data"))
}

func TestOCSPStapler_Put_EmptyResponse(t *testing.T) {
	s := NewOCSPStapler()
	cert, _ := generateTestCertPair(t)
	// Should not panic and should not store.
	s.Put(cert, nil)

	tlsCert := &tls.Certificate{Certificate: [][]byte{cert.Raw}}
	err := s.StapleTo(tlsCert, nil)
	if err == nil {
		t.Fatal("expected error - empty response should not be cached")
	}
}

// generateTestCertPair creates a self-signed CA and a leaf certificate for testing.
func generateTestCertPair(t *testing.T) (leaf *x509.Certificate, issuer *x509.Certificate) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	// Suppress unused variable warning for PEM encoding helper.
	_ = pem.EncodeToMemory

	return leafCert, caCert
}

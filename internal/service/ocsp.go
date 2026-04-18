// Package service manages the HTTP server lifecycle including graceful shutdown and TLS configuration.
package service

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
)

// OCSPStapler fetches and caches OCSP responses for stapling.
//
// TODO: Full OCSP stapling implementation requires golang.org/x/crypto/ocsp,
// which is not currently in go.mod. The Fetch method returns a placeholder error
// until that dependency is available. StapleTo works if raw OCSP response bytes
// are provided externally.
type OCSPStapler struct {
	mu    sync.RWMutex
	cache map[string][]byte // certificate fingerprint -> DER-encoded OCSP response
}

// NewOCSPStapler creates an OCSPStapler with an empty cache.
func NewOCSPStapler() *OCSPStapler {
	return &OCSPStapler{
		cache: make(map[string][]byte),
	}
}

// fingerprint returns a hex-encoded SHA-256 fingerprint of the certificate's raw bytes.
func fingerprint(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", h)
}

// Fetch retrieves an OCSP response for the given certificate chain.
//
// TODO: Implement OCSP request/response using golang.org/x/crypto/ocsp once
// the dependency is added. This would:
//  1. Build an OCSP request from cert and issuer
//  2. POST to the cert's OCSP responder URL
//  3. Parse and validate the response
//  4. Cache the DER-encoded response
func (s *OCSPStapler) Fetch(cert, issuer *x509.Certificate) ([]byte, error) {
	if cert == nil || issuer == nil {
		return nil, fmt.Errorf("ocsp: cert and issuer must not be nil")
	}

	fp := fingerprint(cert)

	// Check cache first.
	s.mu.RLock()
	if cached, ok := s.cache[fp]; ok {
		s.mu.RUnlock()
		return cached, nil
	}
	s.mu.RUnlock()

	// TODO: Full implementation requires golang.org/x/crypto/ocsp.
	// Once available, build an ocsp.Request, POST to cert.OCSPServer[0],
	// parse the response, validate it, and cache the DER bytes.
	return nil, fmt.Errorf("ocsp: fetch not implemented (golang.org/x/crypto/ocsp dependency not available)")
}

// Put stores a pre-fetched OCSP response in the cache for the given certificate.
// This is useful when OCSP responses are obtained externally (e.g., from a CDN or
// certificate provider API).
func (s *OCSPStapler) Put(cert *x509.Certificate, derResponse []byte) {
	if cert == nil || len(derResponse) == 0 {
		return
	}
	fp := fingerprint(cert)
	s.mu.Lock()
	s.cache[fp] = derResponse
	s.mu.Unlock()
}

// StapleTo attaches the cached OCSP response to a TLS certificate.
// The issuer is used to look up the cached response by fingerprint of the leaf certificate.
func (s *OCSPStapler) StapleTo(tlsCert *tls.Certificate, issuer *x509.Certificate) error {
	if tlsCert == nil {
		return fmt.Errorf("ocsp: tls certificate must not be nil")
	}
	if len(tlsCert.Certificate) == 0 {
		return fmt.Errorf("ocsp: tls certificate has no certificate data")
	}

	// Parse the leaf certificate to get its fingerprint.
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return fmt.Errorf("ocsp: parse leaf certificate: %w", err)
	}

	fp := fingerprint(leaf)
	s.mu.RLock()
	cached, ok := s.cache[fp]
	s.mu.RUnlock()

	if !ok {
		return fmt.Errorf("ocsp: no cached response for certificate %s", leaf.Subject.CommonName)
	}

	tlsCert.OCSPStaple = cached
	return nil
}

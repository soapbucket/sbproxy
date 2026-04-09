// Package service manages the HTTP server lifecycle including graceful shutdown and TLS configuration.
package service

import (
	"github.com/soapbucket/sbproxy/internal/request/fingerprint"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

var (
	tlsCertLoadTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sbproxy_tls_cert_load_total",
		Help: "Number of TLS certificate loads by source and host",
	}, []string{"source", "host"})

	tlsCertLoadErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sbproxy_tls_cert_load_errors_total",
		Help: "Number of TLS certificate load failures by source and host",
	}, []string{"source", "host"})

	tlsHandshakeTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sbproxy_tls_handshake_total",
		Help: "Number of TLS handshakes by source",
	}, []string{"source", "host"})
)

// certMagicConfig holds the global CertMagic configuration
var certMagicConfig *certmagic.Config

// GetTLSManager returns the tls manager.
func GetTLSManager(certDir, keyDir string) *tls.Config {
	slog.Debug("GetTLSManager", "certDir", certDir, "keyDir", keyDir)

	// Create a new CertMagic config
	cfg := certmagic.NewDefault()
	cfg.Storage = &certmagic.FileStorage{Path: certDir}

	tlsConfig := cfg.TLSConfig()
	tlsConfig.GetCertificate = getSelfSignedOrLetsEncryptCert(cfg, certDir, keyDir)
	return tlsConfig
}

func getSelfSignedOrLetsEncryptCert(cfg *certmagic.Config, certDir, keyDir string) func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		slog.Debug("getSelfSignedOrLetsEncryptCert", "host", hello.ServerName)

		keyFile := GetConfigPath(hello.ServerName+".key", keyDir)
		crtFile := GetConfigPath(hello.ServerName+".crt", certDir)

		certificate, err := tls.LoadX509KeyPair(crtFile, keyFile)
		if err != nil {
			slog.Debug("certificate file not found, using ACME", "host", hello.ServerName, "error", err)
			return cfg.GetCertificate(hello)
		}
		slog.Info("loaded existing certificate", "host", hello.ServerName)
		return &certificate, nil
	}
}

// GetACMETLSConfig returns a TLS configuration using CertMagic for automatic HTTPS
func GetACMETLSConfig(ctx context.Context, config Config, configDir string, _ interface{}) *tls.Config {
	slog.Debug("GetACMETLSConfig (CertMagic)", "configDir", configDir)

	// Configure CertMagic logging to use slog
	certmagic.Default.Logger = zap.NewNop() // Disable zap logging, we'll use slog

	// Determine cache directory
	cacheDir := config.ProxyConfig.CertificateSettings.ACMECacheDir
	if cacheDir == "" {
		cacheDir = filepath.Join(configDir, "acme-cache")
	}
	if !filepath.IsAbs(cacheDir) {
		cacheDir = filepath.Join(configDir, cacheDir)
	}

	// Ensure cache directory exists
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		slog.Error("failed to create ACME cache directory", "dir", cacheDir, "error", err)
	}

	// Create storage
	storage := &certmagic.FileStorage{Path: cacheDir}

	// Prepare ACME issuer template
	acmeDirectoryURL := config.ProxyConfig.CertificateSettings.ACMEDirectoryURL
	issuerTemplate := certmagic.ACMEIssuer{
		Email:                   config.ProxyConfig.CertificateSettings.ACMEEmail,
		Agreed:                  true,
		DisableHTTPChallenge:    true,  // Disable HTTP-01: the proxy's HTTP server already binds the port and the ACME challenge handler is not mounted in the router
		DisableTLSALPNChallenge: false, // Enable TLS-ALPN-01 (works through GetCertificate callback and crucial for QUIC)
		AltTLSALPNPort:          config.ProxyConfig.HTTPSBindPort,
	}

	// Configure custom ACME directory URL if specified (for staging/testing with Pebble)
	if acmeDirectoryURL != "" {
		issuerTemplate.CA = acmeDirectoryURL

		// For testing with Pebble, we need to trust its self-signed certificate
		if config.ProxyConfig.CertificateSettings.ACMEInsecureSkipVerify {
			issuerTemplate.TrustedRoots = loadPebbleRootCert(config, acmeDirectoryURL)
			if issuerTemplate.TrustedRoots != nil {
				slog.Info("ACME (CertMagic) TrustedRoots set on issuer",
					"subjects", len(issuerTemplate.TrustedRoots.Subjects()))
			} else {
				slog.Error("ACME (CertMagic) TrustedRoots is nil!")
			}
			slog.Warn("ACME (CertMagic) configured for testing with custom CA",
				"directory_url", acmeDirectoryURL)
		}

		slog.Info("ACME (CertMagic) using custom directory URL",
			"directory_url", acmeDirectoryURL,
			"email", config.ProxyConfig.CertificateSettings.ACMEEmail)
	} else {
		slog.Info("ACME (CertMagic) using Let's Encrypt production",
			"email", config.ProxyConfig.CertificateSettings.ACMEEmail)
	}

	// Create a custom cache with a callback that returns configs with our issuer
	var cfg *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return cfg, nil
		},
		Logger: zap.NewNop(),
	})

	// Create the CertMagic config with our custom cache
	cfg = certmagic.New(cache, certmagic.Config{
		Storage: storage,
		Logger:  zap.NewNop(),
	})

	// Create ACME issuer with the configured template
	acmeIssuer := certmagic.NewACMEIssuer(cfg, issuerTemplate)

	// Set the issuer (replaces any defaults and prevents fallback to Let's Encrypt)
	// We only want the custom CA (Pebble) during testing
	cfg.Issuers = []certmagic.Issuer{acmeIssuer}

	// Disable default issuers to prevent fallback to Let's Encrypt
	cfg.OnDemand = &certmagic.OnDemandConfig{
		DecisionFunc: func(ctx context.Context, name string) error {
			// If specific domains are configured, check against whitelist
			if len(config.ProxyConfig.CertificateSettings.ACMEDomains) > 0 {
				for _, domain := range config.ProxyConfig.CertificateSettings.ACMEDomains {
					if matchDomain(name, domain) {
						slog.Debug("ACME on-demand: domain allowed", "domain", name, "matched", domain)
						return nil
					}
				}
				slog.Warn("ACME on-demand: domain not in whitelist", "domain", name)
				return fmt.Errorf("domain %s not in ACME whitelist", name)
			}
			// Allow all domains if no whitelist configured
			slog.Debug("ACME on-demand: allowing all domains", "domain", name)
			return nil
		},
	}

	// Store config globally for certificate management
	certMagicConfig = cfg

	// Get the TLS config
	tlsConfig := cfg.TLSConfig()
	tlsConfig.MinVersion = fingerprint.GetTLSVersion(config.ProxyConfig.CertificateSettings.MinTLSVersion)

	// Log the configured TLS version
	tlsVersionStr := "1.2"
	if tlsConfig.MinVersion == tls.VersionTLS13 {
		tlsVersionStr = "1.3"
	}
	slog.Info("TLS configuration for ACME (CertMagic)",
		"min_tls_version", tlsVersionStr,
		"configured_value", config.ProxyConfig.CertificateSettings.MinTLSVersion,
		"cache_dir", cacheDir)

	if config.ProxyConfig.EnableHTTP3 {
		tlsConfig.NextProtos = []string{"h3", "h2", "http/1.1", "acme-tls/1"}
	} else {
		tlsConfig.NextProtos = []string{"h2", "http/1.1", "acme-tls/1"}
	}
	tlsConfig.CipherSuites = fingerprint.GetTLSCiphersFromNames(config.ProxyConfig.CertificateSettings.TLSCipherSuites)

	// Override GetCertificate to check for existing certificates first
	tlsConfig.GetCertificate = getCertificateWithCertMagicFallback(config, configDir, cfg)

	return tlsConfig
}

// validateCertificateKey checks that a certificate has a valid private key.
// CertMagic may return a certificate with a nil PrivateKey when the ACME flow
// is still in progress or has failed silently. Passing such a certificate to
// Go's TLS layer causes a cryptic "certificate private key (<nil>) does not
// implement crypto.Signer" error. This guard converts that into a clear error.
func validateCertificateKey(cert *tls.Certificate, serverName string) (*tls.Certificate, error) {
	if cert == nil {
		return nil, nil
	}
	if cert.PrivateKey == nil {
		slog.Error("certificate has nil private key (ACME certificate may still be pending)", "host", serverName)
		return nil, fmt.Errorf("certificate for %s has nil private key (ACME certificate may still be pending)", serverName)
	}
	return cert, nil
}

// getCertificateWithCertMagicFallback checks for existing certificates in the cert directory first,
// then falls back to CertMagic ACME if no certificate is found
func getCertificateWithCertMagicFallback(config Config, configDir string, cfg *certmagic.Config) func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		serverName := hello.ServerName
		if serverName == "" {
			serverName = "localhost"
		}
		slog.Debug("getCertificateWithCertMagicFallback", "host", serverName)

		// Get certificate and key directories from config
		certDir := config.ProxyConfig.CertificateSettings.CertificateDir
		keyDir := config.ProxyConfig.CertificateSettings.CertificateKeyDir

		// If directories are not configured, default to configDir
		if certDir == "" {
			certDir = configDir
		}
		if keyDir == "" {
			keyDir = configDir
		}

		// Resolve relative paths
		if !filepath.IsAbs(certDir) {
			certDir = filepath.Join(configDir, certDir)
		}
		if !filepath.IsAbs(keyDir) {
			keyDir = filepath.Join(configDir, keyDir)
		}

		// Construct file paths for the host
		certFile := filepath.Join(certDir, serverName+".crt")
		keyFile := filepath.Join(keyDir, serverName+".key")

		// Check if certificate and key files exist
		if _, err := os.Stat(certFile); os.IsNotExist(err) {
			slog.Info("certificate file not found, using CertMagic ACME", "host", serverName, "cert_file", certFile)
			tlsHandshakeTotal.WithLabelValues("acme", serverName).Inc()
			cert, err := cfg.GetCertificate(hello)
			if err != nil {
				tlsCertLoadErrors.WithLabelValues("acme", serverName).Inc()
				return nil, err
			}
			tlsCertLoadTotal.WithLabelValues("acme", serverName).Inc()
			return validateCertificateKey(cert, serverName)
		}
		if _, err := os.Stat(keyFile); os.IsNotExist(err) {
			slog.Info("key file not found, using CertMagic ACME", "host", serverName, "key_file", keyFile)
			tlsHandshakeTotal.WithLabelValues("acme", serverName).Inc()
			cert, err := cfg.GetCertificate(hello)
			if err != nil {
				tlsCertLoadErrors.WithLabelValues("acme", serverName).Inc()
				return nil, err
			}
			tlsCertLoadTotal.WithLabelValues("acme", serverName).Inc()
			return validateCertificateKey(cert, serverName)
		}

		// Try to load the existing certificate and key pair
		certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			slog.Error("failed to load existing certificate, using CertMagic ACME", "host", serverName, "error", err)
			tlsCertLoadErrors.WithLabelValues("file", serverName).Inc()
			tlsHandshakeTotal.WithLabelValues("acme", serverName).Inc()
			cert, err := cfg.GetCertificate(hello)
			if err != nil {
				tlsCertLoadErrors.WithLabelValues("acme", serverName).Inc()
				return nil, err
			}
			tlsCertLoadTotal.WithLabelValues("acme", serverName).Inc()
			return validateCertificateKey(cert, serverName)
		}

		tlsHandshakeTotal.WithLabelValues("file", serverName).Inc()
		tlsCertLoadTotal.WithLabelValues("file", serverName).Inc()
		slog.Info("loaded existing certificate from file", "host", serverName)
		return &certificate, nil
	}
}

// getDynamicCertificate dynamically loads certificates and keys from configured directories.
// Falls back to the proxy's default tls_cert/tls_key if no per-host certificate is found.
func getDynamicCertificate(config Config, configDir string) func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	var (
		fallbackCert *tls.Certificate
		fallbackOnce sync.Once
		fallbackErr  error
	)

	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		serverName := hello.ServerName
		if serverName == "" {
			serverName = "localhost"
			slog.Debug("empty ServerName, using default localhost certificate")
		}
		slog.Debug("getDynamicCertificate", "host", serverName)

		// Get certificate and key directories from config
		certDir := config.ProxyConfig.CertificateSettings.CertificateDir
		keyDir := config.ProxyConfig.CertificateSettings.CertificateKeyDir

		if certDir == "" {
			certDir = configDir
		}
		if keyDir == "" {
			keyDir = configDir
		}

		if !filepath.IsAbs(certDir) {
			certDir = filepath.Join(configDir, certDir)
		}
		if !filepath.IsAbs(keyDir) {
			keyDir = filepath.Join(configDir, keyDir)
		}

		// Try per-host certificate files
		certFile := filepath.Join(certDir, serverName+".crt")
		keyFile := filepath.Join(keyDir, serverName+".key")

		if _, err := os.Stat(certFile); err == nil {
			if _, err := os.Stat(keyFile); err == nil {
				certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
				if err != nil {
					tlsCertLoadErrors.WithLabelValues("per_host", serverName).Inc()
					slog.Error("failed to load certificate for host", "server", serverName, "error", err)
					return nil, fmt.Errorf("failed to load certificate for host %s: %w", serverName, err)
				}
				tlsHandshakeTotal.WithLabelValues("per_host", serverName).Inc()
				tlsCertLoadTotal.WithLabelValues("per_host", serverName).Inc()
				slog.Debug("loaded per-host certificate", "host", serverName)
				return &certificate, nil
			}
		}

		// Fall back to proxy default tls_cert/tls_key
		fallbackOnce.Do(func() {
			tlsCert := config.ProxyConfig.TLSCert
			tlsKey := config.ProxyConfig.TLSKey
			if tlsCert == "" || tlsKey == "" {
				fallbackErr = fmt.Errorf("no per-host certificate for %s and no default tls_cert/tls_key configured", serverName)
				return
			}

			if !filepath.IsAbs(tlsCert) {
				tlsCert = filepath.Join(configDir, tlsCert)
			}
			if !filepath.IsAbs(tlsKey) {
				tlsKey = filepath.Join(configDir, tlsKey)
			}

			cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
			if err != nil {
				fallbackErr = fmt.Errorf("failed to load default TLS certificate: %w", err)
				return
			}
			fallbackCert = &cert
			slog.Info("loaded default TLS certificate as fallback", "cert", tlsCert)
		})

		if fallbackErr != nil {
			return nil, fallbackErr
		}

		tlsHandshakeTotal.WithLabelValues("fallback", serverName).Inc()
		slog.Warn("no per-host certificate found, using default TLS certificate", "host", serverName)
		return fallbackCert, nil
	}
}

// ManageCertificate explicitly manages a certificate for the given domain
// This can be called to pre-fetch certificates before they're needed
func ManageCertificate(ctx context.Context, domain string) error {
	if certMagicConfig == nil {
		return fmt.Errorf("CertMagic not initialized")
	}
	return certMagicConfig.ManageSync(ctx, []string{domain})
}

// PreManageACMEDomains pre-obtains certificates for the configured ACME domains.
// This MUST be called after GetACMETLSConfig but BEFORE the HTTPS server starts,
// so that the TLS-ALPN-01 solver can temporarily bind the HTTPS port to present
// the challenge certificate. Once certificates are cached, subsequent requests
// are served directly from the cache without needing the solver.
func PreManageACMEDomains(ctx context.Context, domains []string) error {
	if len(domains) == 0 {
		return nil
	}
	if certMagicConfig == nil {
		return fmt.Errorf("CertMagic not initialized")
	}

	slog.Info("pre-managing ACME certificates", "domains", domains)
	manageCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	if err := certMagicConfig.ManageSync(manageCtx, domains); err != nil {
		return fmt.Errorf("failed to pre-manage ACME certificates: %w", err)
	}

	slog.Info("ACME certificates pre-managed successfully", "domains", domains)
	return nil
}

// GetACMEHTTPHandler returns the HTTP handler for ACME HTTP-01 challenges
// This should be mounted at /.well-known/acme-challenge/ on port 80
func GetACMEHTTPHandler() http.Handler {
	if certMagicConfig == nil {
		return http.NotFoundHandler()
	}

	// Get the first issuer if it's an ACME issuer
	for _, issuer := range certMagicConfig.Issuers {
		if acmeIssuer, ok := issuer.(*certmagic.ACMEIssuer); ok {
			return acmeIssuer.HTTPChallengeHandler(http.NotFoundHandler())
		}
	}
	return http.NotFoundHandler()
}

// loadPebbleRootCert loads the root certificate for Pebble or other test ACME servers
// It tries to fetch from the management API or load from a file
func loadPebbleRootCert(config Config, acmeDirectoryURL string) *x509.CertPool {
	pool := x509.NewCertPool()

	// Try to load from config file if specified
	if config.ProxyConfig.CertificateSettings.ACMECACertFile != "" {
		certPEM, err := os.ReadFile(config.ProxyConfig.CertificateSettings.ACMECACertFile)
		if err != nil {
			slog.Warn("failed to read ACME CA cert file", "file", config.ProxyConfig.CertificateSettings.ACMECACertFile, "error", err)
		} else if pool.AppendCertsFromPEM(certPEM) {
			slog.Info("loaded ACME CA certificate from file", "file", config.ProxyConfig.CertificateSettings.ACMECACertFile)
			return pool
		}
	}

	// Try to fetch from Pebble's management API
	// Pebble exposes root certs at https://<host>:15000/roots/0
	// We need to skip TLS verification for this initial fetch
	pebbleMgmtURL := getPebbleMgmtURL(acmeDirectoryURL)
	if pebbleMgmtURL != "" {
		certPEM, err := fetchPebbleRootCert(pebbleMgmtURL)
		if err != nil {
			slog.Warn("failed to fetch Pebble root cert", "url", pebbleMgmtURL, "error", err)
		} else if pool.AppendCertsFromPEM(certPEM) {
			slog.Info("loaded Pebble root certificate from management API", "url", pebbleMgmtURL)
		}
	}

	// For Pebble/testing: if insecure skip verify is true, also trust the ACME server's own certificate.
	// This is needed because Pebble's directory endpoint (port 14000) often uses a self-signed cert
	// not signed by the root CA we just fetched.
	if config.ProxyConfig.CertificateSettings.ACMEInsecureSkipVerify {
		slog.Info("fetching ACME server certificate to add to trusted roots", "url", acmeDirectoryURL)
		cert, err := fetchServerCertificate(acmeDirectoryURL)
		if err != nil {
			slog.Warn("failed to fetch ACME server certificate", "url", acmeDirectoryURL, "error", err)
		} else {
			pool.AddCert(cert)
			slog.Info("trusted ACME server's own certificate", "url", acmeDirectoryURL)
		}
	}

	if len(pool.Subjects()) > 0 {
		return pool
	}

	slog.Warn("could not load ACME CA certificate, using system roots")
	return nil // Fall back to system roots
}

// fetchServerCertificate connects to the server and returns its certificate
func fetchServerCertificate(urlStr string) (*x509.Certificate, error) {
	hostPort := extractHostPort(urlStr)
	if hostPort == "" {
		return nil, fmt.Errorf("invalid URL: %s", urlStr)
	}

	// Connect with insecure skip verify to get the cert
	conf := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // Intentional to fetch cert
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", hostPort, conf)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	return certs[0], nil
}

// getPebbleMgmtURL derives Pebble's management URL from its ACME directory URL
func getPebbleMgmtURL(acmeDirectoryURL string) string {
	// Pebble ACME is on port 14000, management is on port 15000
	// https://pebble:14000/dir -> https://pebble:15000/roots/0
	if acmeDirectoryURL == "" {
		return ""
	}

	// Simple string replacement for common patterns
	mgmtURL := acmeDirectoryURL
	mgmtURL = replacePort(mgmtURL, "14000", "15000")
	mgmtURL = replacePort(mgmtURL, ":14000/", ":15000/")

	// Remove path and add /roots/0
	if idx := findPathStart(mgmtURL); idx > 0 {
		mgmtURL = mgmtURL[:idx]
	}
	return mgmtURL + "/roots/0"
}

func replacePort(s, old, new string) string {
	for i := 0; i <= len(s)-len(old); i++ {
		if s[i:i+len(old)] == old {
			return s[:i] + new + s[i+len(old):]
		}
	}
	return s
}

func findPathStart(url string) int {
	// Skip https://
	start := 0
	if len(url) > 8 && url[:8] == "https://" {
		start = 8
	} else if len(url) > 7 && url[:7] == "http://" {
		start = 7
	}
	// Find first / after host
	for i := start; i < len(url); i++ {
		if url[i] == '/' {
			return i
		}
	}
	return len(url)
}

// fetchPebbleRootCert fetches the root certificate from Pebble's management API
func fetchPebbleRootCert(mgmtURL string) ([]byte, error) {
	// Create an HTTP client that skips TLS verification (needed to bootstrap)
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // Intentional for fetching Pebble root cert
			},
		},
	}

	resp, err := httpClient.Get(mgmtURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %s", resp.Status)
	}

	certPEM, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	slog.Debug("fetched Pebble root cert", "size", len(certPEM), "preview", string(certPEM[:min(100, len(certPEM))]))

	return certPEM, nil
}

func extractHostPort(url string) string {
	// https://pebble:15000/roots/0 -> pebble:15000
	start := 0
	if len(url) > 8 && url[:8] == "https://" {
		start = 8
	} else if len(url) > 7 && url[:7] == "http://" {
		start = 7
	}
	end := findPathStart(url)
	return url[start:end]
}

func extractHost(url string) string {
	hp := extractHostPort(url)
	for i := 0; i < len(hp); i++ {
		if hp[i] == ':' {
			return hp[:i]
		}
	}
	return hp
}

func findBodyStart(response string) int {
	// Find \r\n\r\n which separates headers from body
	for i := 0; i < len(response)-3; i++ {
		if response[i:i+4] == "\r\n\r\n" {
			return i + 4
		}
	}
	return -1
}

// matchDomain checks if a domain name matches a pattern.
// Supports exact match ("example.com") and wildcard ("*.example.com").
// A wildcard pattern matches any subdomain: "*.example.com" matches
// "foo.example.com" and "bar.baz.example.com" but not "example.com" itself.
func matchDomain(name, pattern string) bool {
	if pattern == name {
		return true
	}
	if len(pattern) > 2 && pattern[:2] == "*." {
		suffix := pattern[1:] // ".example.com"
		return len(name) > len(suffix) && name[len(name)-len(suffix):] == suffix
	}
	return false
}

// parseClientAuthType maps a configuration string to a tls.ClientAuthType constant.
// Supported values: "none", "request", "require", "verify_if_given", "require_and_verify".
func parseClientAuthType(value string) tls.ClientAuthType {
	switch value {
	case "request":
		return tls.RequestClientCert
	case "require":
		return tls.RequireAnyClientCert
	case "verify_if_given":
		return tls.VerifyClientCertIfGiven
	case "require_and_verify":
		return tls.RequireAndVerifyClientCert
	default:
		return tls.NoClientCert
	}
}

// applyClientAuth configures mTLS client certificate authentication on the given TLS config.
// It reads the client CA certificate from a file path or base64-encoded data and sets
// ClientAuth and ClientCAs on the tls.Config.
func applyClientAuth(tlsConfig *tls.Config, settings CertificateSettings) {
	if settings.ClientAuth == "" || settings.ClientAuth == "none" {
		return
	}

	authType := parseClientAuthType(settings.ClientAuth)
	tlsConfig.ClientAuth = authType

	// Load client CA certificates for verification
	pool := x509.NewCertPool()
	loaded := false

	// Prefer base64-encoded data over file path
	if settings.ClientCACertData != "" {
		decoded, err := base64.StdEncoding.DecodeString(settings.ClientCACertData)
		if err != nil {
			slog.Error("failed to decode base64 client CA certificate data", "error", err)
		} else if pool.AppendCertsFromPEM(decoded) {
			loaded = true
			slog.Info("loaded client CA certificate from base64 data for mTLS")
		} else {
			slog.Error("failed to parse client CA certificate from base64 data")
		}
	}

	if !loaded && settings.ClientCACertFile != "" {
		caCert, err := os.ReadFile(settings.ClientCACertFile)
		if err != nil {
			slog.Error("failed to read client CA certificate file", "file", settings.ClientCACertFile, "error", err)
		} else if pool.AppendCertsFromPEM(caCert) {
			loaded = true
			slog.Info("loaded client CA certificate from file for mTLS", "file", settings.ClientCACertFile)
		} else {
			slog.Error("failed to parse client CA certificate from file", "file", settings.ClientCACertFile)
		}
	}

	if loaded {
		tlsConfig.ClientCAs = pool
	} else if authType >= tls.VerifyClientCertIfGiven {
		slog.Warn("mTLS client_auth requires verification but no client CA certificate was loaded; client connections requiring verification will fail",
			"client_auth", settings.ClientAuth)
	}

	slog.Info("mTLS client authentication configured",
		"client_auth", settings.ClientAuth,
		"client_ca_loaded", loaded)
}

// Ensure acme package is imported for the error types
var _ = acme.Account{}

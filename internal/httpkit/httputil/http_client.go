// Package common provides shared HTTP utilities, helper functions, and type definitions used across packages.
package httputil

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/soapbucket/sbproxy/internal/loader/settings"
	"github.com/soapbucket/sbproxy/internal/security/certpin"
	"github.com/soapbucket/sbproxy/internal/platform/dns"
	"github.com/soapbucket/sbproxy/internal/observe/metric"

	"golang.org/x/net/http2"
)

// HTTPClient represents an optimized HTTP client
type HTTPClient struct {
	Client *http.Client
	config HTTPClientConfig
	pool   *sync.Pool
}

// NewHTTPClient creates a new HTTP client with the given configuration
func NewHTTPClient(config HTTPClientConfig) *HTTPClient {
	transport := createHTTPTransport(config)

	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}

	return &HTTPClient{
		Client: client,
		config: config,
		pool: &sync.Pool{
			New: func() interface{} {
				return make([]byte, 0, 4096)
			},
		},
	}
}

// createHTTPTransport creates an optimized HTTP transport
func createHTTPTransport(config HTTPClientConfig) http.RoundTripper {
	slog.Debug("creating HTTP transport", "config", config)
	
	// Global TLS enforcement: if SB_ENFORCE_TLS_VERIFY is true, override per-origin skip_tls_verify.
	// This prevents any origin from disabling certificate verification in production.
	skipTLS := config.SkipTLSVerifyHost
	if skipTLS && settings.Global.EnforceTLSVerify {
		originName := config.OriginName
		if originName == "" {
			originName = "unknown"
		}
		slog.Error("TLS verification enforcement: origin requested skip_tls_verify but SB_ENFORCE_TLS_VERIFY is enabled, overriding to enforce TLS verification",
			"origin", originName,
			"connection_type", "http_client",
			"action", "skip_tls_verify overridden to false")
		metric.TLSInsecureSkipVerifyEnabled(originName, "http_client")
		skipTLS = false
	}

	// Create base TLS config
	baseTLSConfig := &tls.Config{
		InsecureSkipVerify:     skipTLS,
		SessionTicketsDisabled: false,
		ClientSessionCache:     tls.NewLRUClientSessionCache(256),
	}
	switch config.MinTLSVersion {
	case "1.3":
		baseTLSConfig.MinVersion = tls.VersionTLS13
	case "1.2", "":
		baseTLSConfig.MinVersion = tls.VersionTLS12
	default:
		baseTLSConfig.MinVersion = tls.VersionTLS12
	}

	// CRITICAL SECURITY WARNING: Log and record metric when TLS verification is disabled
	if skipTLS {
		originName := config.OriginName
		if originName == "" {
			originName = "unknown"
		}
		slog.Warn("CRITICAL SECURITY WARNING: TLS certificate verification is disabled",
			"origin", originName,
			"connection_type", "http_client",
			"risk", "man-in-the-middle attacks possible",
			"recommendation", "enable TLS verification in production environments")
		metric.TLSInsecureSkipVerifyEnabled(originName, "http_client")
	}
	
	// Set up mutual TLS (mTLS) if configured
	// Support both file paths and base64-encoded data (prefer base64 if both provided)
	hasClientCert := (config.MTLSClientCertFile != "" || config.MTLSClientCertData != "") &&
		(config.MTLSClientKeyFile != "" || config.MTLSClientKeyData != "")
	
	if hasClientCert {
		originName := config.OriginName
		if originName == "" {
			originName = "unknown"
		}
		
		// Load client certificate and key (prefer base64 data over file paths)
		var cert tls.Certificate
		var err error
		var certSource string
		
		if config.MTLSClientCertData != "" && config.MTLSClientKeyData != "" {
			// Load from base64-encoded data
			certPEM, err := base64.StdEncoding.DecodeString(config.MTLSClientCertData)
			if err != nil {
				slog.Error("failed to decode base64 mTLS client certificate",
					"origin", originName,
					"error", err)
			} else {
				keyPEM, err := base64.StdEncoding.DecodeString(config.MTLSClientKeyData)
				if err != nil {
					slog.Error("failed to decode base64 mTLS client key",
						"origin", originName,
						"error", err)
				} else {
					cert, err = tls.X509KeyPair(certPEM, keyPEM)
					if err != nil {
						slog.Error("failed to parse mTLS client certificate from base64 data",
							"origin", originName,
							"error", err)
					} else {
						certSource = "base64_data"
					}
				}
			}
		} else if config.MTLSClientCertFile != "" && config.MTLSClientKeyFile != "" {
			// Load from file paths
			cert, err = tls.LoadX509KeyPair(config.MTLSClientCertFile, config.MTLSClientKeyFile)
			if err != nil {
				slog.Error("failed to load mTLS client certificate from file",
					"origin", originName,
					"cert_file", config.MTLSClientCertFile,
					"key_file", config.MTLSClientKeyFile,
					"error", err)
			} else {
				certSource = fmt.Sprintf("file:%s", config.MTLSClientCertFile)
			}
		} else {
			slog.Error("mTLS configuration incomplete: both certificate and key must be provided (either as files or base64 data)",
				"origin", originName)
		}
		
		if err == nil && certSource != "" {
			baseTLSConfig.Certificates = []tls.Certificate{cert}
			slog.Info("mTLS client certificate loaded",
				"origin", originName,
				"source", certSource)
			
			// Load CA certificate if provided for server verification (prefer base64 over file)
			var caCertData []byte
			var caCertSource string
			
			if config.MTLSCACertData != "" {
				// Load from base64-encoded data
				decoded, err := base64.StdEncoding.DecodeString(config.MTLSCACertData)
				if err != nil {
					slog.Error("failed to decode base64 mTLS CA certificate",
						"origin", originName,
						"error", err)
				} else {
					caCertData = decoded
					caCertSource = "base64_data"
				}
			} else if config.MTLSCACertFile != "" {
				// Load from file path
				var err error
				caCertData, err = os.ReadFile(config.MTLSCACertFile)
				if err != nil {
					slog.Error("failed to load mTLS CA certificate from file",
						"origin", originName,
						"ca_cert_file", config.MTLSCACertFile,
						"error", err)
				} else {
					caCertSource = fmt.Sprintf("file:%s", config.MTLSCACertFile)
				}
			}
			
			if len(caCertData) > 0 {
				caCertPool := x509.NewCertPool()
				if !caCertPool.AppendCertsFromPEM(caCertData) {
					slog.Error("failed to parse mTLS CA certificate",
						"origin", originName,
						"source", caCertSource)
				} else {
					baseTLSConfig.RootCAs = caCertPool
					// When using custom RootCAs, we need to set ServerName or InsecureSkipVerify
					// Extract server name from config if available, otherwise use default behavior
					// (InsecureSkipVerify is already set if configured)
					// Note: when using custom RootCAs without InsecureSkipVerify,
					// ServerName should be set explicitly in production.
					slog.Info("mTLS CA certificate loaded",
						"origin", originName,
						"source", caCertSource)
				}
			}
		}
	}
	
	// Set up certificate pinning if configured
	var certPinner *certpin.CertificatePinner
	if config.CertificatePinning != nil && config.CertificatePinning.Enabled {
		originName := config.OriginName
		if originName == "" {
			originName = "unknown"
		}
		
		// Validate certificate pinning configuration
		if err := certpin.ValidateConfig(config.CertificatePinning); err != nil {
			slog.Error("invalid certificate pinning configuration",
				"origin", originName,
				"error", err)
		} else {
			var err error
			certPinner, err = certpin.NewCertificatePinner(config.CertificatePinning, originName)
			if err != nil {
				slog.Error("failed to create certificate pinner",
					"origin", originName,
					"error", err)
			} else {
				slog.Info("certificate pinning enabled",
					"origin", originName,
					"primary_pin", config.CertificatePinning.PinSHA256,
					"backup_pins_count", len(config.CertificatePinning.BackupPins))
				
				// Record metrics
				metric.CertPinEnabledSet(originName, true)
				
				// Check for pin expiration warnings (7 days) and record expiry metric
				certPinner.WarnIfPinExpiringSoon(7)
				if config.CertificatePinning.PinExpiry != "" {
					expiryTime, err := time.Parse(time.RFC3339, config.CertificatePinning.PinExpiry)
					if err == nil {
						daysUntilExpiry := time.Until(expiryTime).Hours() / 24
						metric.CertPinExpiryDaysSet(originName, daysUntilExpiry)
					}
				}
				
				// Apply certificate pinning to TLS config
				baseTLSConfig = certPinner.GetTLSConfig(baseTLSConfig)
			}
		}
	}
	
	// If HTTP/3 is enabled, return an HTTP/3 Transport
	if config.EnableHTTP3 && !config.HTTP11Only {
		return &http3.Transport{
			TLSClientConfig:    baseTLSConfig,
			DisableCompression: config.DisableCompression,
		}
	}

	// Create dial function with DNS caching support
	dial := func(dialTimeout, keepAlive time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			slog.Debug("dialing", "network", network, "addr", addr, "dialTimeout", dialTimeout, "keepAlive", keepAlive)

			// Use DNS resolver if available (for hostname resolution)
			host, port, err := net.SplitHostPort(addr)
			if err == nil && host != "" {
				// Check if host is already an IP address
				if ip := net.ParseIP(host); ip == nil {
					// Host is a hostname, resolve using DNS cache
					resolver := dns.GetGlobalResolver()
					if resolver != nil {
						ips, err := resolver.LookupIP(ctx, network, host)
						if err == nil && len(ips) > 0 {
							// Use first IP address
							addr = net.JoinHostPort(ips[0].String(), port)
						}
					}
				}
			}

			conn, err := (&net.Dialer{
				Timeout:   dialTimeout,
				KeepAlive: keepAlive,
				DualStack: true,
			}).DialContext(ctx, network, addr)

			return conn, err
		}
	}

	// Create TLS dial function to track handshake failures
	originName := config.OriginName
	if originName == "" {
		originName = "unknown"
	}
	
	dialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Dial the connection
		conn, err := dial(config.DialTimeout, config.KeepAlive)(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		
		// Create a copy of TLS config for this connection
		// Extract hostname from address for ServerName (required for SNI)
		tlsConfig := baseTLSConfig
		if !baseTLSConfig.InsecureSkipVerify && baseTLSConfig.ServerName == "" {
			// Extract hostname from address (format: hostname:port)
			host, _, err := net.SplitHostPort(addr)
			if err == nil && host != "" {
				// Create a new TLS config with ServerName set
				// Clone the config properly to avoid copying the mutex
				tlsConfigCopy := tls.Config{
					Rand:                        baseTLSConfig.Rand,
					Time:                        baseTLSConfig.Time,
					Certificates:                baseTLSConfig.Certificates,
					GetCertificate:              baseTLSConfig.GetCertificate,
					GetClientCertificate:        baseTLSConfig.GetClientCertificate,
					GetConfigForClient:          baseTLSConfig.GetConfigForClient,
					VerifyPeerCertificate:       baseTLSConfig.VerifyPeerCertificate,
					RootCAs:                     baseTLSConfig.RootCAs,
					NextProtos:                  baseTLSConfig.NextProtos,
					ServerName:                  host,
					ClientCAs:                   baseTLSConfig.ClientCAs,
					InsecureSkipVerify:          baseTLSConfig.InsecureSkipVerify,
					CipherSuites:                baseTLSConfig.CipherSuites,
					SessionTicketsDisabled:      baseTLSConfig.SessionTicketsDisabled,
					ClientSessionCache:          baseTLSConfig.ClientSessionCache,
					MinVersion:                  baseTLSConfig.MinVersion,
					MaxVersion:                  baseTLSConfig.MaxVersion,
					CurvePreferences:            baseTLSConfig.CurvePreferences,
					DynamicRecordSizingDisabled: baseTLSConfig.DynamicRecordSizingDisabled,
					Renegotiation:               baseTLSConfig.Renegotiation,
					KeyLogWriter:                baseTLSConfig.KeyLogWriter,
				}
				tlsConfig = &tlsConfigCopy
			}
		}
		
		// Perform TLS handshake
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			// Extract TLS version from error or config
			tlsVersion := "unknown"
			if tlsConfig.MinVersion != 0 {
				switch tlsConfig.MinVersion {
				case tls.VersionTLS10:
					tlsVersion = "1.0"
				case tls.VersionTLS11:
					tlsVersion = "1.1"
				case tls.VersionTLS12:
					tlsVersion = "1.2"
				case tls.VersionTLS13:
					tlsVersion = "1.3"
				}
			}
			
			// Determine error type
			errorType := "handshake_failed"
			errStr := err.Error()
			if strings.Contains(errStr, "certificate") {
				errorType = "certificate_error"
			} else if strings.Contains(errStr, "timeout") {
				errorType = "timeout"
			} else if strings.Contains(errStr, "protocol") {
				errorType = "protocol_error"
			}
			
			// Record TLS handshake failure metric
			metric.TLSHandshakeFailure(originName, errorType, tlsVersion)
			
			conn.Close()
			return nil, err
		}
		
		// Record successful TLS version usage
		state := tlsConn.ConnectionState()
		tlsVersion := "unknown"
		switch state.Version {
		case tls.VersionTLS10:
			tlsVersion = "1.0"
		case tls.VersionTLS11:
			tlsVersion = "1.1"
		case tls.VersionTLS12:
			tlsVersion = "1.2"
		case tls.VersionTLS13:
			tlsVersion = "1.3"
		}
		metric.TLSVersionUsage(originName, tlsVersion)
		
		return tlsConn, nil
	}

	// Create transport
	baseTransport := &http.Transport{
		// Connection pooling optimizations for high throughput
		MaxIdleConns:          config.MaxIdleConns,
		MaxIdleConnsPerHost:   config.MaxIdleConnsPerHost,
		MaxConnsPerHost:       config.MaxConnsPerHost,
		IdleConnTimeout:       config.IdleConnTimeout,
		TLSHandshakeTimeout:   config.TLSHandshakeTimeout,
		ResponseHeaderTimeout: config.ResponseHeaderTimeout,
		ExpectContinueTimeout: config.ExpectContinueTimeout,

		// Performance tuning
		DisableCompression: config.DisableCompression,
		DisableKeepAlives:  config.DisableKeepAlives,
		ForceAttemptHTTP2:  config.ForceAttemptHTTP2 && !config.HTTP11Only,
		WriteBufferSize:    config.WriteBufferSize,
		ReadBufferSize:     config.ReadBufferSize,

		TLSClientConfig: baseTLSConfig,
		DialContext:     dial(config.DialTimeout, config.KeepAlive),
		DialTLSContext:  dialTLS,
	}

	// Configure HTTP/2 if not HTTP/1.1 only
	if !config.HTTP11Only {
		_ = http2.ConfigureTransport(baseTransport)
	}

	// Wrap transport to track connection reuse and HTTP/2 streams
	return &metricsTransport{
		base:       baseTransport,
		originName: originName,
	}
}

// metricsTransport wraps http.RoundTripper to track connection reuse and HTTP/2 streams
type metricsTransport struct {
	base       http.RoundTripper
	originName string
	// Track connection reuse per target using sync.Map for lock-free reads
	connReuseStats sync.Map // map[string]*connectionReuseStats
}

type connectionReuseStats struct {
	totalRequests     atomic.Int64
	newConnections    atomic.Int64
	reusedConnections atomic.Int64
}

// RoundTrip performs the round trip operation on the metricsTransport.
func (t *metricsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	target := req.URL.Host
	if target == "" {
		target = "unknown"
	}

	// Get or create stats for this target (lock-free fast path)
	val, _ := t.connReuseStats.LoadOrStore(target, &connectionReuseStats{})
	stats := val.(*connectionReuseStats)

	// Make the request
	resp, err := t.base.RoundTrip(req)

	// Track HTTP/2 stream usage based on response protocol
	if resp != nil {
		if resp.ProtoMajor == 2 {
			metric.HTTP2Stream(t.originName, "success")
		}
	} else if err != nil {
		if req.URL.Scheme == "https" {
			metric.HTTP2Stream(t.originName, "error")
		}
	}

	// Track connection reuse with atomics (no locks)
	total := stats.totalRequests.Add(1)
	if resp != nil && err == nil {
		if total > 1 {
			stats.reusedConnections.Add(1)
		} else {
			stats.newConnections.Add(1)
		}
	}

	// Update reuse rate metric periodically (every 10 requests)
	if total%10 == 0 {
		reused := stats.reusedConnections.Load()
		reuseRate := float64(reused) / float64(total)
		metric.UpstreamConnectionReuseRateSet(t.originName, target, reuseRate)
	}

	return resp, err
}

// Do makes an HTTP request with the given parameters
func (c *HTTPClient) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	slog.Debug("making request", "method", req.Method, "url", req.URL, "headers", req.Header)
	
	origin := c.config.OriginName
	if origin == "" {
		origin = "unknown"
	}
	targetHost := req.URL.Host
	if targetHost == "" {
		targetHost = "unknown"
	}
	
	// Measure upstream response time
	startTime := time.Now()
	
	// Make the request with context
	resp, err := c.Client.Do(req.WithContext(ctx))
	
	// Calculate upstream response time
	upstreamDuration := time.Since(startTime).Seconds()
	
	if err != nil {
		// Record upstream response time with error status
		metric.UpstreamResponseTime(origin, targetHost, 0, upstreamDuration)
		
		// Check if error is a timeout
		if ctx.Err() == context.DeadlineExceeded || strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline") {
			timeoutType := "request_timeout"
			metric.RequestTimeout(origin, timeoutType, targetHost)
		}
		slog.Error("failed to make HTTP request", "method", req.Method, "url", req.URL, "headers", req.Header, "error", err)
		return nil, fmt.Errorf("failed to make HTTP request: %w", err)
	}
	
	// Record upstream response time metric
	metric.UpstreamResponseTime(origin, targetHost, resp.StatusCode, upstreamDuration)
	
	slog.Debug("request made", "method", req.Method, "url", req.URL, "headers", req.Header, "status", resp.StatusCode)

	return resp, nil
}

// MakeCallbackAsync makes an HTTP callback request asynchronously
func (c *HTTPClient) AsyncDo(ctx context.Context, req *http.Request) <-chan HTTPCallbackResult {
	slog.Debug("making request asynchronously", "method", req.Method, "url", req.URL, "headers", req.Header)
	resultChan := make(chan HTTPCallbackResult, 1)

	go func() {
		defer close(resultChan)

		resp, err := c.Do(ctx, req)
		slog.Debug("request made asynchronously", "method", req.Method, "url", req.URL, "headers", req.Header, "status", resp.StatusCode, "error", err)

		resultChan <- HTTPCallbackResult{
			Response: resp,
			Error:    err,
		}
	}()

	return resultChan
}

func (c *HTTPClient) doByMethod(ctx context.Context, method string, url string, body io.ReadCloser, header http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		slog.Error("failed to create HTTP request", "method", method, "url", url, "header", header, "error", err)
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header = header
	return c.Do(ctx, req)
}

// Get makes a GET request
func (c *HTTPClient) Get(ctx context.Context, url string, header http.Header) (*http.Response, error) {
	return c.doByMethod(ctx, "GET", url, io.NopCloser(nil), header)
}

// Post makes a POST request
func (c *HTTPClient) Post(ctx context.Context, url string, body io.ReadCloser, header http.Header) (*http.Response, error) {
	return c.doByMethod(ctx, "POST", url, body, header)
}

// Put makes a PUT request
func (c *HTTPClient) Put(ctx context.Context, url string, body io.ReadCloser, header http.Header) (*http.Response, error) {
	return c.doByMethod(ctx, "PUT", url, body, header)
}

// Delete makes a DELETE request
func (c *HTTPClient) Delete(ctx context.Context, url string, header http.Header) (*http.Response, error) {
	return c.doByMethod(ctx, "DELETE", url, io.NopCloser(nil), header)
}

// JSONPost makes a POST request with a JSON body
func (c *HTTPClient) JSONPost(ctx context.Context, url string, obj any, header http.Header) (*http.Response, error) {
	return c.doJSONByMethod(ctx, "POST", url, obj, header)
}

// JSONPut makes a PUT request with a JSON body
func (c *HTTPClient) JSONPut(ctx context.Context, url string, obj any, header http.Header) (*http.Response, error) {
	return c.doJSONByMethod(ctx, "PUT", url, obj, header)
}

// JSONDelete makes a DELETE request with a JSON body
func (c *HTTPClient) JSONDelete(ctx context.Context, url string, obj any, header http.Header) (*http.Response, error) {
	return c.doJSONByMethod(ctx, "DELETE", url, obj, header)
}

func (c *HTTPClient) doJSONByMethod(ctx context.Context, method string, url string, obj any, header http.Header) (*http.Response, error) {

	var body []byte
	var err error
	if obj != nil {
		body, err = json.Marshal(obj)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal object: %w", err)
		}
	}
	
	// Initialize header if nil
	if header == nil {
		header = make(http.Header)
	}
	header.Set("Content-Type", "application/json")
	return c.doByMethod(ctx, method, url, io.NopCloser(bytes.NewReader(body)), header)
}

// Close closes the HTTP client and cleans up resources
func (c *HTTPClient) Close() error {
	// The default HTTP client doesn't need explicit cleanup
	// but this method is provided for interface consistency
	return nil
}

// Global HTTP client instance for reuse across services
var (
	globalHTTPClient *HTTPClient
	httpClientMutex  sync.RWMutex
)

// GetGlobalHTTPClient returns the global HTTP client instance
func GetGlobalHTTPClient() *HTTPClient {
	httpClientMutex.RLock()
	if globalHTTPClient != nil {
		client := globalHTTPClient
		httpClientMutex.RUnlock()
		return client
	}
	httpClientMutex.RUnlock()

	httpClientMutex.Lock()
	defer httpClientMutex.Unlock()
	if globalHTTPClient == nil {
		globalHTTPClient = NewHTTPClient(DefaultHTTPClientConfig())
	}
	return globalHTTPClient
}

// SetGlobalHTTPClientConfig updates the global HTTP client configuration
func SetGlobalHTTPClientConfig(config HTTPClientConfig) {
	httpClientMutex.Lock()
	defer httpClientMutex.Unlock()
	if globalHTTPClient != nil {
		globalHTTPClient.Close()
	}
	globalHTTPClient = NewHTTPClient(config)
}

// ResetGlobalHTTPClient resets the global HTTP client (useful for testing)
func ResetGlobalHTTPClient() {
	httpClientMutex.Lock()
	defer httpClientMutex.Unlock()
	if globalHTTPClient != nil {
		globalHTTPClient.Close()
		globalHTTPClient = nil
	}
}

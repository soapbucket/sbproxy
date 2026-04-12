// Package common provides shared HTTP utilities, helper functions, and type definitions used across packages.
package httputil

import (
	"net/http"
	"time"

	"github.com/soapbucket/sbproxy/internal/security/certpin"
)

// HTTPClientConfig represents configuration for the HTTP client
type HTTPClientConfig struct {
	// Timeout is the maximum time to wait for a response
	Timeout time.Duration
	// MaxIdleConns is the maximum number of idle connections
	MaxIdleConns int
	// MaxIdleConnsPerHost is the maximum number of idle connections per host
	MaxIdleConnsPerHost int
	// IdleConnTimeout is the maximum time an idle connection will be kept alive
	IdleConnTimeout time.Duration
	// DisableKeepAlives disables HTTP keep-alives
	DisableKeepAlives bool
	// MaxConnsPerHost limits the number of connections per host
	MaxConnsPerHost int
	// ResponseHeaderTimeout is the maximum time to wait for response headers
	ResponseHeaderTimeout time.Duration
	// ExpectContinueTimeout is the maximum time to wait for 100-continue
	ExpectContinueTimeout time.Duration
	// WriteBufferSize is the size of the write buffer
	WriteBufferSize int
	// ReadBufferSize is the size of the read buffer
	ReadBufferSize int
	// ForceAttemptHTTP2 forces HTTP/2 usage
	ForceAttemptHTTP2 bool
	// EnableHTTP3 enables HTTP/3 support
	EnableHTTP3 bool
	// DisableCompression disables compression
	DisableCompression bool
	// TLSHandshakeTimeout is the maximum time to wait for TLS handshake
	TLSHandshakeTimeout time.Duration
	// DialTimeout is the maximum time to wait for connection
	DialTimeout time.Duration
	// KeepAlive is the keep-alive duration
	KeepAlive time.Duration
	// SkipTLSVerifyHost skips TLS host verification
	SkipTLSVerifyHost bool
	// MinTLSVersion enforces a minimum TLS version for outbound connections ("1.2" or "1.3")
	MinTLSVersion string
	// HTTP11Only forces HTTP/1.1 only
	HTTP11Only bool
	// CertificatePinning enables certificate pinning for this connection
	CertificatePinning *certpin.CertificatePinningConfig
	// OriginName is used for logging in certificate pinning
	OriginName string
	// Mutual TLS (mTLS) configuration for backend connections
	MTLSClientCertFile string // Path to client certificate file
	MTLSClientKeyFile  string // Path to client private key file
	MTLSCACertFile     string // Optional: Path to CA certificate file for server verification
	// Base64-encoded certificate data (alternative to file paths)
	MTLSClientCertData string // Base64-encoded client certificate
	MTLSClientKeyData  string // Base64-encoded client private key
	MTLSCACertData     string // Optional: Base64-encoded CA certificate
}

// DefaultHTTPClientConfig returns a default configuration optimized for high throughput
// Buffer sizes optimized per OPTIMIZATIONS.md #16: 64KB for high-throughput scenarios
func DefaultHTTPClientConfig() HTTPClientConfig {
	return HTTPClientConfig{
		Timeout:               30 * time.Second,
		MaxIdleConns:          1000,
		MaxIdleConnsPerHost:   100,
		MaxConnsPerHost:       0, // unlimited
		IdleConnTimeout:       90 * time.Second,
		DisableKeepAlives:     false,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		WriteBufferSize:       64 * 1024, // Optimized from 32KB to 64KB (per OPTIMIZATIONS.md #16)
		ReadBufferSize:        64 * 1024, // Optimized from 32KB to 64KB (per OPTIMIZATIONS.md #16)
		ForceAttemptHTTP2:     true,
		EnableHTTP3:           false,
		DisableCompression:    false,
		TLSHandshakeTimeout:   10 * time.Second,
		DialTimeout:           10 * time.Second,
		KeepAlive:             90 * time.Second,
		SkipTLSVerifyHost:     false,
		HTTP11Only:            false,
	}
}

// HighThroughputHTTPClientConfig returns a configuration optimized for maximum throughput
func HighThroughputHTTPClientConfig() HTTPClientConfig {
	config := DefaultHTTPClientConfig()
	config.MaxIdleConns = 2000
	config.MaxIdleConnsPerHost = 200
	config.MaxConnsPerHost = 0
	config.IdleConnTimeout = 5 * time.Minute
	config.WriteBufferSize = 64 * 1024
	config.ReadBufferSize = 64 * 1024
	config.KeepAlive = 5 * time.Minute
	return config
}

// HighBandwidthHTTPClientConfig returns a configuration optimized for high-bandwidth, high-latency networks
// Uses 256KB buffers per OPTIMIZATIONS.md #16 for high-bandwidth scenarios
func HighBandwidthHTTPClientConfig() HTTPClientConfig {
	config := DefaultHTTPClientConfig()
	config.MaxIdleConns = 2000
	config.MaxIdleConnsPerHost = 200
	config.MaxConnsPerHost = 0
	config.IdleConnTimeout = 5 * time.Minute
	config.WriteBufferSize = 256 * 1024 // 256KB for high-bandwidth, high-latency networks
	config.ReadBufferSize = 256 * 1024  // 256KB for high-bandwidth, high-latency networks
	config.KeepAlive = 5 * time.Minute
	return config
}

// HTTPTransportOptions allows tuning of the underlying http.Transport for performance and memory
type HTTPTransportOptions struct {
	// Connection pooling
	MaxIdleConns        int
	MaxIdleConnsPerHost int
	MaxConnsPerHost     int

	// Timeouts
	ResponseHeaderTimeout time.Duration
	ExpectContinueTimeout time.Duration

	// Performance toggles
	DisableCompression bool
	DisableKeepAlives  bool

	// Buffers
	WriteBufferSize int
	ReadBufferSize  int

	// HTTP versions
	ForceAttemptHTTP2 *bool
	EnableHTTP3       *bool
	MinTLSVersion     string

	// Mutual TLS (mTLS) configuration
	MTLSClientCertFile string // Path to client certificate file
	MTLSClientKeyFile  string // Path to client private key file
	MTLSCACertFile     string // Optional: Path to CA certificate file
	// Base64-encoded certificate data (alternative to file paths)
	MTLSClientCertData string // Base64-encoded client certificate
	MTLSClientKeyData  string // Base64-encoded client private key
	MTLSCACertData     string // Optional: Base64-encoded CA certificate
}

// HTTPCallbackResult represents the result of an async callback
type HTTPCallbackResult struct {
	Response *http.Response
	Error    error
}

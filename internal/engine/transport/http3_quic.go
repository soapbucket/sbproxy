// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// HTTP3QUICConfig configures HTTP/3 QUIC optimizations
type HTTP3QUICConfig struct {
	// Enable HTTP/3
	Enabled bool
	
	// Enable 0-RTT
	Enable0RTT bool
	
	// Maximum idle timeout
	MaxIdleTimeout time.Duration
	
	// Keep alive period
	KeepAlivePeriod time.Duration
	
	// Enable connection migration
	EnableMigration bool
	
	// Maximum receive stream flow control window
	MaxStreamReceiveWindow uint64
	
	// Maximum connection flow control window
	MaxConnectionReceiveWindow uint64
	
	// Initial max data (for 0-RTT)
	InitialMaxData uint64
	
	// Initial max stream data (for 0-RTT)
	InitialMaxStreamData uint64
	
	// Maximum number of streams per connection
	MaxStreamsPerConnection int
	
	// Enable QUIC datagram support
	EnableDatagrams bool
	
	// Retry on QUIC error
	RetryOnError bool
	
	// Fallback to HTTP/2 on error
	FallbackToHTTP2 bool
	
	// Disable compression
	DisableCompression bool
}

// HTTP3QUICTransport implements an optimized HTTP/3 transport with QUIC features
type HTTP3QUICTransport struct {
	config HTTP3QUICConfig
	
	// HTTP/3 client
	http3Client *http.Client
	
	// Fallback HTTP/2 client
	http2Client *http.Client
	
	// TLS config
	tlsConfig *tls.Config
	
	// QUIC config
	quicConfig *quic.Config
	
	// Statistics
	stats HTTP3Stats
}

// NewHTTP3QUICTransport creates a new HTTP/3 QUIC transport
func NewHTTP3QUICTransport(config HTTP3QUICConfig, tlsConfig *tls.Config) (*HTTP3QUICTransport, error) {
	// Set defaults
	if config.MaxIdleTimeout == 0 {
		config.MaxIdleTimeout = 30 * time.Second
	}
	if config.KeepAlivePeriod == 0 {
		config.KeepAlivePeriod = 15 * time.Second
	}
	if config.MaxStreamReceiveWindow == 0 {
		config.MaxStreamReceiveWindow = 6 * 1024 * 1024 // 6 MB
	}
	if config.MaxConnectionReceiveWindow == 0 {
		config.MaxConnectionReceiveWindow = 15 * 1024 * 1024 // 15 MB
	}
	if config.MaxStreamsPerConnection == 0 {
		config.MaxStreamsPerConnection = 100
	}
	
	// Configure QUIC
	quicConfig := &quic.Config{
		MaxIdleTimeout:             config.MaxIdleTimeout,
		KeepAlivePeriod:            config.KeepAlivePeriod,
		EnableDatagrams:            config.EnableDatagrams,
		Allow0RTT:                  config.Enable0RTT,
		MaxIncomingStreams:         int64(config.MaxStreamsPerConnection),
		MaxIncomingUniStreams:      int64(config.MaxStreamsPerConnection / 2),
		DisablePathMTUDiscovery:    false,
	}
	
	// Configure 0-RTT if enabled
	if config.Enable0RTT {
		if tlsConfig.ClientSessionCache == nil {
			tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(100)
		}
		
		// Set initial flow control limits for 0-RTT
		if config.InitialMaxData > 0 {
			quicConfig.InitialStreamReceiveWindow = config.InitialMaxStreamData
			quicConfig.InitialConnectionReceiveWindow = config.InitialMaxData
		}
	}
	
	// Create HTTP/3 client
	// Use quic-go's real HTTP/3 transport so this transport works end to end.
	http3Client := &http.Client{
		Transport: &http3.Transport{
			TLSClientConfig:    tlsConfig,
			QUICConfig:         quicConfig,
			DisableCompression: config.DisableCompression,
		},
		Timeout: config.MaxIdleTimeout * 2,
	}
	
	t := &HTTP3QUICTransport{
		config:      config,
		http3Client: http3Client,
		tlsConfig:   tlsConfig,
		quicConfig:  quicConfig,
	}
	
	// Create fallback transport if enabled
	if config.FallbackToHTTP2 {
		http2Transport := &http.Transport{
			TLSClientConfig:     tlsConfig,
			ForceAttemptHTTP2:   true,
			IdleConnTimeout:     config.MaxIdleTimeout,
			DisableCompression:  config.DisableCompression,
		}
		
		t.http2Client = &http.Client{
			Transport: http2Transport,
			Timeout:   config.MaxIdleTimeout * 2,
		}
	}
	
	return t, nil
}

// RoundTrip implements http.RoundTripper with HTTP/3 optimizations
func (t *HTTP3QUICTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddUint64(&t.stats.TotalRequests, 1)
	
	if !t.config.Enabled {
		if t.http2Client != nil {
			resp, err := t.http2Client.Transport.RoundTrip(req)
			if err == nil {
				atomic.AddUint64(&t.stats.HTTP2Requests, 1)
			}
			return resp, err
		}
		return nil, errors.New("HTTP/3 disabled and no fallback configured")
	}
	
	// Only use HTTP/3 for HTTPS
	if req.URL.Scheme != "https" {
		if t.http2Client != nil {
			resp, err := t.http2Client.Transport.RoundTrip(req)
			if err == nil {
				atomic.AddUint64(&t.stats.HTTP2Requests, 1)
			}
			return resp, err
		}
		return nil, errors.New("HTTP/3 only supports HTTPS")
	}
	
	// Try HTTP/3 request
	resp, err := t.http3Client.Transport.RoundTrip(req)
	if err != nil {
		atomic.AddUint64(&t.stats.FailedRequests, 1)
		
		slog.Debug("HTTP/3 request failed",
			"error", err,
			"url", req.URL.String())
		
		// Retry if configured
		if t.config.RetryOnError {
			slog.Debug("retrying HTTP/3 request", "url", req.URL.String())
			resp, err = t.http3Client.Transport.RoundTrip(req)
			if err == nil {
				atomic.AddUint64(&t.stats.HTTP3Requests, 1)
				atomic.AddUint64(&t.stats.RetriedRequests, 1)
				return resp, nil
			}
		}
		
		// Fallback to HTTP/2 if configured
		if t.config.FallbackToHTTP2 && t.http2Client != nil {
			atomic.AddUint64(&t.stats.FallbackRequests, 1)
			slog.Info("falling back to HTTP/2",
				"url", req.URL.String(),
				"error", err)
			
			resp, err := t.http2Client.Transport.RoundTrip(req)
			if err == nil {
				atomic.AddUint64(&t.stats.HTTP2Requests, 1)
			}
			return resp, err
		}
		
		return nil, fmt.Errorf("HTTP/3 request failed: %w", err)
	}
	
	atomic.AddUint64(&t.stats.HTTP3Requests, 1)
	return resp, nil
}

// CloseIdleConnections closes idle connections
func (t *HTTP3QUICTransport) CloseIdleConnections() {
	if rt, ok := t.http3Client.Transport.(interface{ Close() error }); ok {
		_ = rt.Close()
	}
	
	if t.http2Client != nil {
		if rt, ok := t.http2Client.Transport.(interface{ CloseIdleConnections() }); ok {
			rt.CloseIdleConnections()
		}
	}
}

// GetStats returns HTTP/3 QUIC statistics
func (t *HTTP3QUICTransport) GetStats() HTTP3Stats {
	return HTTP3Stats{
		TotalRequests:    atomic.LoadUint64(&t.stats.TotalRequests),
		HTTP3Requests:    atomic.LoadUint64(&t.stats.HTTP3Requests),
		HTTP2Requests:    atomic.LoadUint64(&t.stats.HTTP2Requests),
		FailedRequests:   atomic.LoadUint64(&t.stats.FailedRequests),
		RetriedRequests:  atomic.LoadUint64(&t.stats.RetriedRequests),
		FallbackRequests: atomic.LoadUint64(&t.stats.FallbackRequests),
	}
}

// HTTP3Stats represents HTTP/3 QUIC statistics
type HTTP3Stats struct {
	TotalRequests    uint64
	HTTP3Requests    uint64
	HTTP2Requests    uint64
	FailedRequests   uint64
	RetriedRequests  uint64
	FallbackRequests uint64
}

// String returns a formatted string representation of stats
func (s HTTP3Stats) String() string {
	total := s.TotalRequests
	if total == 0 {
		return "No requests"
	}
	
	http3Pct := float64(s.HTTP3Requests) / float64(total) * 100
	http2Pct := float64(s.HTTP2Requests) / float64(total) * 100
	failPct := float64(s.FailedRequests) / float64(total) * 100
	
	return fmt.Sprintf("Total: %d, HTTP/3: %d (%.1f%%), HTTP/2: %d (%.1f%%), Failed: %d (%.1f%%), Retried: %d, Fallback: %d",
		total, s.HTTP3Requests, http3Pct, s.HTTP2Requests, http2Pct, 
		s.FailedRequests, failPct, s.RetriedRequests, s.FallbackRequests)
}


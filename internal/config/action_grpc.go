// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

const (
	// DefaultGRPCMaxRecvMsgSize is the default value for grpc max recv msg size.
	DefaultGRPCMaxRecvMsgSize = 4 * 1024 * 1024 // 4MB
	// DefaultGRPCMaxSendMsgSize is the default value for grpc max send msg size.
	DefaultGRPCMaxSendMsgSize = 4 * 1024 * 1024 // 4MB
)

func init() {
	loaderFns[TypeGRPC] = NewGRPCAction
}

// GRPCAction represents a grpc action.
type GRPCAction struct {
	GRPCConfig

	targetURL *url.URL `json:"-"`
}

// NewGRPCAction creates and initializes a new GRPCAction.
func NewGRPCAction(data []byte) (ActionConfig, error) {
	config := &GRPCAction{}
	if err := json.Unmarshal(data, config); err != nil {
		return nil, err
	}

	// Validate URL
	if config.URL == "" {
		return nil, fmt.Errorf("grpc: url is required")
	}

	// Parse target URL
	var err error
	config.targetURL, err = url.Parse(config.URL)
	if err != nil {
		return nil, fmt.Errorf("grpc: invalid url: %w", err)
	}

	// Normalize scheme: grpc:// -> https://, grpcs:// -> https://
	if config.targetURL.Scheme == "grpc" {
		config.targetURL.Scheme = "https"
	} else if config.targetURL.Scheme == "grpcs" {
		config.targetURL.Scheme = "https"
	} else if config.targetURL.Scheme != "http" && config.targetURL.Scheme != "https" {
		return nil, fmt.Errorf("grpc: url must use http://, https://, grpc://, or grpcs:// scheme")
	}

	// Set defaults
	// Check if fields were explicitly set in JSON to determine defaults
	var jsonData map[string]interface{}
	json.Unmarshal(data, &jsonData)

	// StripBasePath defaults to true for gRPC (unless explicitly set to false)
	if _, explicitlySet := jsonData["strip_base_path"]; !explicitlySet {
		config.StripBasePath = true
	}

	// PreserveQuery defaults to true for gRPC (unless explicitly set to false)
	if _, explicitlySet := jsonData["preserve_query"]; !explicitlySet {
		config.PreserveQuery = true
	}

	// ForwardMetadata defaults to true (unless explicitly set to false)
	if _, explicitlySet := jsonData["forward_metadata"]; !explicitlySet {
		config.ForwardMetadata = true
	}

	if config.MaxCallRecvMsgSize == 0 {
		config.MaxCallRecvMsgSize = DefaultGRPCMaxRecvMsgSize
	}
	if config.MaxCallSendMsgSize == 0 {
		config.MaxCallSendMsgSize = DefaultGRPCMaxSendMsgSize
	}

	// gRPC requires HTTP/2, so ensure HTTP/1.1 only is disabled
	if config.HTTP11Only {
		slog.Warn("grpc: HTTP/1.1 only is enabled, but gRPC requires HTTP/2. Disabling HTTP/1.1 only mode",
			"url", config.URL)
		config.HTTP11Only = false
	}

	// Ensure HTTP/2 is enabled
	config.EnableHTTP3 = false // gRPC doesn't support HTTP/3

	// Initialize base transport with connection settings
	baseTransport := ClientConnectionTransportFn(&config.BaseConnection)

	// Wrap with gRPC-specific transport
	config.tr = &grpcTransport{
		base:   baseTransport,
		config: config,
	}

	// Security warning for TLS verification disabled
	if config.SkipTLSVerifyHost {
		originName := config.URL
		if originName == "" {
			originName = "unknown"
		}
		slog.Warn("CRITICAL SECURITY WARNING: TLS certificate verification is disabled",
			"origin", originName,
			"connection_type", "grpc",
			"risk", "man-in-the-middle attacks possible",
			"recommendation", "enable TLS verification in production environments")
		metric.TLSInsecureSkipVerifyEnabled(originName, "grpc")
	}

	return config, nil
}

// RefreshTransport performs the refresh transport operation on the GRPCAction.
func (c *GRPCAction) RefreshTransport() {
	baseTransport := ClientConnectionTransportFn(&c.BaseConnection)
	c.tr = &grpcTransport{
		base:   baseTransport,
		config: c,
	}
}

// IsProxy reports whether the GRPCAction is proxy.
func (c *GRPCAction) IsProxy() bool {
	return true
}

// GetType returns the type for the GRPCAction.
func (c *GRPCAction) GetType() string {
	return TypeGRPC
}

// Rewrite performs the rewrite operation on the GRPCAction.
func (c *GRPCAction) Rewrite() RewriteFn {
	return func(pr *httputil.ProxyRequest) {
		req := pr.In.URL

		slog.Debug("grpc: rewriting request", "target_url", c.targetURL.String(), "incoming_path", req.Path)

		// Build the target URL based on StripBasePath setting
		targetURL := &url.URL{
			Scheme: c.targetURL.Scheme,
			Host:   c.targetURL.Host,
		}

		if c.StripBasePath {
			targetURL.Path = req.Path
		} else {
			// Append incoming path to target base path
			targetURL.Path = c.targetURL.Path + req.Path
		}

		// Merge query parameters if PreserveQuery is enabled
		if c.PreserveQuery {
			if req.RawQuery != "" || c.targetURL.RawQuery != "" {
				query := c.targetURL.Query()
				for k, vs := range pr.In.URL.Query() {
					for _, v := range vs {
						query.Add(k, v)
					}
				}
				targetURL.RawQuery = query.Encode()
			}
		} else {
			// Use only target query
			targetURL.RawQuery = c.targetURL.RawQuery
		}

		// Set the URL
		pr.SetURL(targetURL)

		outReq := pr.Out

		// Set host
		hostname := targetURL.Host
		outReq.Host = hostname
		outReq.Header.Set("Host", hostname)

		// Ensure proper Content-Type for gRPC
		contentType := outReq.Header.Get("Content-Type")
		if contentType == "" {
			// Default to application/grpc if not set
			outReq.Header.Set("Content-Type", "application/grpc")
		} else if c.EnableGRPCWeb && strings.HasPrefix(contentType, "application/grpc-web") {
			// gRPC-Web uses application/grpc-web+proto or application/grpc-web+json
			// Keep it as-is
		} else if !strings.HasPrefix(contentType, "application/grpc") {
			// If it's not a gRPC content type, log a warning but don't change it
			// Some clients might send custom content types
			slog.Debug("grpc: unexpected content-type", "content_type", contentType)
		}

		// TE: trailers is required for gRPC over HTTP/2.
		// Connection-specific headers are not set here because the streaming
		// proxy path strips hop-by-hop headers before the upstream request.
		outReq.Header.Set("TE", "trailers")

		// Forward gRPC metadata headers if enabled
		if c.ForwardMetadata {
			// gRPC metadata headers are prefixed with "grpc-" or "grpc-metadata-"
			// We'll forward all headers that start with these prefixes
			for key, values := range pr.In.Header {
				lowerKey := strings.ToLower(key)
				if strings.HasPrefix(lowerKey, "grpc-") {
					// Forward gRPC headers
					for _, value := range values {
						outReq.Header.Add(key, value)
					}
				}
			}
		}

		slog.Debug("grpc: request rewritten", "url", outReq.URL.String(), "content_type", outReq.Header.Get("Content-Type"))
	}
}

// grpcTransport wraps the base transport with gRPC-specific handling
type grpcTransport struct {
	base   http.RoundTripper
	config *GRPCAction
}

// RoundTrip performs the round trip operation on the grpcTransport.
func (t *grpcTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	start := time.Now()

	// Validate gRPC request
	contentType := r.Header.Get("Content-Type")
	isGRPCWeb := strings.HasPrefix(contentType, "application/grpc-web")
	isGRPC := strings.HasPrefix(contentType, "application/grpc") || isGRPCWeb

	if !isGRPC && !t.config.EnableGRPCWeb {
		slog.Debug("grpc: non-gRPC content-type detected", "content_type", contentType)
		// Still forward, but log it
	}

	// Forward to backend
	resp, err := t.base.RoundTrip(r)
	if err != nil {
		slog.Error("grpc: backend request failed", "error", err, "url", r.URL.String())
		return nil, err
	}

	duration := time.Since(start)

	// Ensure response has proper gRPC headers
	if resp.Header.Get("Content-Type") == "" {
		// Set default gRPC content type if not present
		if isGRPCWeb {
			resp.Header.Set("Content-Type", "application/grpc-web+proto")
		} else {
			resp.Header.Set("Content-Type", "application/grpc")
		}
	}

	if t.config.cfg != nil && !t.config.cfg.DisableCompression {
		// Enable gRPC compression if configured
		resp.Header.Set("grpc-encoding", "gzip, br, snappy, zstd, deflate, identity")
	}

	// Forward gRPC status and metadata from response headers
	// gRPC status is typically in grpc-status header
	if t.config.ForwardMetadata {
		// Forward all grpc-* headers from response
		for key, values := range resp.Header {
			lowerKey := strings.ToLower(key)
			if strings.HasPrefix(lowerKey, "grpc-") {
				// Already in response, keep it
				_ = values
			}
		}
	}

	slog.Debug("grpc: backend request completed",
		"duration", duration,
		"status", resp.StatusCode,
		"grpc_status", resp.Header.Get("grpc-status"),
		"url", r.URL.String())

	return resp, nil
}

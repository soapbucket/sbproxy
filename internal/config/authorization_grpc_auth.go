// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/logging"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

func init() {
	authLoaderFuns[AuthTypeGRPCAuth] = NewGRPCAuthConfig
}

// GRPCAuthImpl implements AuthConfig for gRPC external auth (Envoy ext_authz compatible).
// It uses a lightweight HTTP/2 JSON approach instead of the full gRPC framework.
type GRPCAuthImpl struct {
	GRPCAuthConfig

	client *http.Client
}

// checkRequest represents the Envoy ext_authz CheckRequest sent to the auth server.
type checkRequest struct {
	Attributes *checkAttributes `json:"attributes"`
}

// checkAttributes holds the request attributes for the check request.
type checkAttributes struct {
	Request *checkRequestAttrs `json:"request"`
}

// checkRequestAttrs holds HTTP-level attributes for the check request.
type checkRequestAttrs struct {
	HTTP *checkHTTPAttrs `json:"http"`
}

// checkHTTPAttrs holds individual HTTP attributes for the check request.
type checkHTTPAttrs struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Host    string            `json:"host"`
	Scheme  string            `json:"scheme"`
	Headers map[string]string `json:"headers"`
}

// checkResponse represents the Envoy ext_authz CheckResponse from the auth server.
type checkResponse struct {
	Status         *checkStatus          `json:"status"`
	OKResponse     *checkOKResponse      `json:"ok_response,omitempty"`
	DeniedResponse *checkDeniedResponse  `json:"denied_response,omitempty"`
}

// checkStatus holds the gRPC status code (0 = OK).
type checkStatus struct {
	Code int `json:"code"`
}

// checkOKResponse holds headers to add on a successful auth check.
type checkOKResponse struct {
	Headers []checkHeader `json:"headers,omitempty"`
}

// checkDeniedResponse holds the denied status and body.
type checkDeniedResponse struct {
	Status *checkDeniedStatus `json:"status,omitempty"`
	Body   string             `json:"body,omitempty"`
}

// checkDeniedStatus holds the HTTP status code for a denied response.
type checkDeniedStatus struct {
	Code int `json:"code"`
}

// checkHeader represents a single header key-value pair in a check response.
type checkHeader struct {
	Header *checkHeaderKV `json:"header,omitempty"`
}

// checkHeaderKV holds the key and value for a response header.
type checkHeaderKV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// NewGRPCAuthConfig creates and initializes a new GRPCAuthConfig.
func NewGRPCAuthConfig(data []byte) (AuthConfig, error) {
	cfg := &GRPCAuthImpl{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	if cfg.Address == "" {
		return nil, fmt.Errorf("grpc_auth: address is required")
	}

	// Set up HTTP client with timeout
	timeout := 5 * time.Second
	if cfg.Timeout.Duration > 0 {
		timeout = cfg.Timeout.Duration
	}

	transport := &http.Transport{
		ForceAttemptHTTP2: true,
	}

	if cfg.TLS {
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		if cfg.TLSCACert != "" {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM([]byte(cfg.TLSCACert)) {
				return nil, fmt.Errorf("grpc_auth: failed to parse TLS CA certificate")
			}
			tlsConfig.RootCAs = pool
		}
		transport.TLSClientConfig = tlsConfig
	}

	cfg.client = &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	return cfg, nil
}

// Authenticate performs the authenticate operation on the GRPCAuthImpl.
func (c *GRPCAuthImpl) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Build check request with HTTP attributes
		headers := make(map[string]string, len(r.Header))
		for key, values := range r.Header {
			headers[strings.ToLower(key)] = values[0]
		}

		checkReq := &checkRequest{
			Attributes: &checkAttributes{
				Request: &checkRequestAttrs{
					HTTP: &checkHTTPAttrs{
						Method:  r.Method,
						Path:    r.URL.Path,
						Host:    r.Host,
						Scheme:  grpcAuthScheme(r),
						Headers: headers,
					},
				},
			},
		}

		body, err := json.Marshal(checkReq)
		if err != nil {
			slog.Error("grpc_auth: failed to marshal check request", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Build the URL for the auth server
		scheme := "http"
		if c.TLS {
			scheme = "https"
		}
		url := fmt.Sprintf("%s://%s/envoy.service.auth.v3.Authorization/Check", scheme, c.Address)

		authReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			slog.Error("grpc_auth: failed to create request", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		authReq.Header.Set("Content-Type", "application/json")

		// Make the auth request
		resp, err := c.client.Do(authReq)
		if err != nil {
			ipAddress := grpcAuthExtractIP(r)
			logging.LogAuthenticationAttempt(r.Context(), false, "grpc_auth", "", ipAddress, "auth_server_error")
			origin := grpcAuthOrigin(c.cfg)
			metric.AuthFailure(origin, "grpc_auth", "auth_server_error", ipAddress)
			emitSecurityAuthFailure(r.Context(), c.cfg, r, "grpc_auth", "auth_server_error")

			slog.Error("grpc_auth: request failed", "error", err, "address", c.Address)

			if c.FailOpen {
				slog.Warn("grpc_auth: fail_open enabled, allowing request", "address", c.Address)
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, "Authentication Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		defer resp.Body.Close()

		// Parse the check response
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			ipAddress := grpcAuthExtractIP(r)
			logging.LogAuthenticationAttempt(r.Context(), false, "grpc_auth", "", ipAddress, "response_read_error")
			origin := grpcAuthOrigin(c.cfg)
			metric.AuthFailure(origin, "grpc_auth", "response_read_error", ipAddress)
			emitSecurityAuthFailure(r.Context(), c.cfg, r, "grpc_auth", "response_read_error")

			slog.Error("grpc_auth: failed to read response", "error", err)

			if c.FailOpen {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, "Authentication Service Unavailable", http.StatusServiceUnavailable)
			return
		}

		var checkResp checkResponse
		if err := json.Unmarshal(respBody, &checkResp); err != nil {
			ipAddress := grpcAuthExtractIP(r)
			logging.LogAuthenticationAttempt(r.Context(), false, "grpc_auth", "", ipAddress, "response_parse_error")
			origin := grpcAuthOrigin(c.cfg)
			metric.AuthFailure(origin, "grpc_auth", "response_parse_error", ipAddress)
			emitSecurityAuthFailure(r.Context(), c.cfg, r, "grpc_auth", "response_parse_error")

			slog.Error("grpc_auth: failed to parse response", "error", err)

			if c.FailOpen {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, "Authentication Service Unavailable", http.StatusServiceUnavailable)
			return
		}

		// Check status code (0 = OK in gRPC)
		if checkResp.Status != nil && checkResp.Status.Code == 0 {
			// Auth succeeded - copy trust headers from auth response
			if checkResp.OKResponse != nil {
				for _, h := range checkResp.OKResponse.Headers {
					if h.Header != nil && h.Header.Key != "" {
						// Only copy headers that are in the trust list (if configured)
						if len(c.TrustHeaders) == 0 || grpcAuthHeaderTrusted(c.TrustHeaders, h.Header.Key) {
							r.Header.Set(h.Header.Key, h.Header.Value)
						}
					}
				}
			}

			ipAddress := grpcAuthExtractIP(r)
			logging.LogAuthenticationAttempt(r.Context(), true, "grpc_auth", "", ipAddress, "")

			next.ServeHTTP(w, r)
			return
		}

		// Auth denied
		ipAddress := grpcAuthExtractIP(r)
		logging.LogAuthenticationAttempt(r.Context(), false, "grpc_auth", "", ipAddress, "denied")
		origin := grpcAuthOrigin(c.cfg)
		metric.AuthFailure(origin, "grpc_auth", "denied", ipAddress)
		emitSecurityAuthFailure(r.Context(), c.cfg, r, "grpc_auth", "denied")

		// Determine the denied status code
		statusCode := http.StatusForbidden
		if checkResp.DeniedResponse != nil && checkResp.DeniedResponse.Status != nil && checkResp.DeniedResponse.Status.Code > 0 {
			statusCode = checkResp.DeniedResponse.Status.Code
		}

		// Write the denied response body
		deniedBody := "Forbidden"
		if checkResp.DeniedResponse != nil && checkResp.DeniedResponse.Body != "" {
			deniedBody = checkResp.DeniedResponse.Body
		}

		w.WriteHeader(statusCode)
		w.Write([]byte(deniedBody))
	})
}

func grpcAuthScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	return "http"
}

func grpcAuthExtractIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return strings.Split(forwarded, ",")[0]
	}
	return r.RemoteAddr
}

func grpcAuthOrigin(cfg *Config) string {
	if cfg != nil {
		return cfg.ID
	}
	return "unknown"
}

func grpcAuthHeaderTrusted(trustHeaders []string, header string) bool {
	lower := strings.ToLower(header)
	for _, h := range trustHeaders {
		if strings.ToLower(h) == lower {
			return true
		}
	}
	return false
}

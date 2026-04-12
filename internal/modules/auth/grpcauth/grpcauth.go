// Package grpcauth registers the grpc_auth authentication provider.
// It implements the Envoy ext_authz protocol over HTTP/2 JSON.
package grpcauth

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
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterAuth("grpc_auth", New)
}

// Config holds configuration for the grpc_auth provider.
type Config struct {
	Type         string   `json:"type"`
	Disabled     bool     `json:"disabled,omitempty"`
	Address      string   `json:"address"`
	TimeoutSecs  float64  `json:"timeout,omitempty"`
	TLS          bool     `json:"tls,omitempty"`
	TLSCACert    string   `json:"tls_ca_cert,omitempty"`
	FailOpen     bool     `json:"fail_open,omitempty"`
	TrustHeaders []string `json:"trust_headers,omitempty"`

	// Parsed timeout (not from JSON directly - computed from TimeoutSecs).
	timeout time.Duration
}

// checkRequest is the Envoy ext_authz CheckRequest.
type checkRequest struct {
	Attributes *checkAttributes `json:"attributes"`
}

type checkAttributes struct {
	Request *checkRequestAttrs `json:"request"`
}

type checkRequestAttrs struct {
	HTTP *checkHTTPAttrs `json:"http"`
}

type checkHTTPAttrs struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Host    string            `json:"host"`
	Scheme  string            `json:"scheme"`
	Headers map[string]string `json:"headers"`
}

// checkResponse is the Envoy ext_authz CheckResponse.
type checkResponse struct {
	Status         *checkStatus         `json:"status"`
	OKResponse     *checkOKResponse     `json:"ok_response,omitempty"`
	DeniedResponse *checkDeniedResponse `json:"denied_response,omitempty"`
}

type checkStatus struct {
	Code int `json:"code"`
}

type checkOKResponse struct {
	Headers []checkHeader `json:"headers,omitempty"`
}

type checkDeniedResponse struct {
	Status *checkDeniedStatus `json:"status,omitempty"`
	Body   string             `json:"body,omitempty"`
}

type checkDeniedStatus struct {
	Code int `json:"code"`
}

type checkHeader struct {
	Header *checkHeaderKV `json:"header,omitempty"`
}

type checkHeaderKV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// provider is the runtime auth provider.
type provider struct {
	cfg    *Config
	client *http.Client
}

// New creates a new grpc_auth provider from raw JSON configuration.
func New(data json.RawMessage) (plugin.AuthProvider, error) {
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	if cfg.Address == "" {
		return nil, fmt.Errorf("grpc_auth: address is required")
	}

	timeout := 5 * time.Second
	if cfg.TimeoutSecs > 0 {
		timeout = time.Duration(cfg.TimeoutSecs * float64(time.Second))
	}
	cfg.timeout = timeout

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

	return &provider{
		cfg: cfg,
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
	}, nil
}

func (p *provider) Type() string { return "grpc_auth" }

func (p *provider) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
						Scheme:  scheme(r),
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

		urlScheme := "http"
		if p.cfg.TLS {
			urlScheme = "https"
		}
		authURL := fmt.Sprintf("%s://%s/envoy.service.auth.v3.Authorization/Check", urlScheme, p.cfg.Address)

		authReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, authURL, bytes.NewReader(body))
		if err != nil {
			slog.Error("grpc_auth: failed to create request", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		authReq.Header.Set("Content-Type", "application/json")

		resp, err := p.client.Do(authReq)
		if err != nil {
			ipAddress := extractIP(r)
			logging.LogAuthenticationAttempt(r.Context(), false, "grpc_auth", "", ipAddress, "auth_server_error")
			metric.AuthFailure("unknown", "grpc_auth", "auth_server_error", ipAddress)

			slog.Error("grpc_auth: request failed", "error", err, "address", p.cfg.Address)

			if p.cfg.FailOpen {
				slog.Warn("grpc_auth: fail_open enabled, allowing request", "address", p.cfg.Address)
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, "Authentication Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			ipAddress := extractIP(r)
			logging.LogAuthenticationAttempt(r.Context(), false, "grpc_auth", "", ipAddress, "response_read_error")
			metric.AuthFailure("unknown", "grpc_auth", "response_read_error", ipAddress)

			slog.Error("grpc_auth: failed to read response", "error", err)

			if p.cfg.FailOpen {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, "Authentication Service Unavailable", http.StatusServiceUnavailable)
			return
		}

		var checkResp checkResponse
		if err := json.Unmarshal(respBody, &checkResp); err != nil {
			ipAddress := extractIP(r)
			logging.LogAuthenticationAttempt(r.Context(), false, "grpc_auth", "", ipAddress, "response_parse_error")
			metric.AuthFailure("unknown", "grpc_auth", "response_parse_error", ipAddress)

			slog.Error("grpc_auth: failed to parse response", "error", err)

			if p.cfg.FailOpen {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, "Authentication Service Unavailable", http.StatusServiceUnavailable)
			return
		}

		// gRPC status code 0 = OK.
		if checkResp.Status != nil && checkResp.Status.Code == 0 {
			if checkResp.OKResponse != nil {
				for _, h := range checkResp.OKResponse.Headers {
					if h.Header != nil && h.Header.Key != "" {
						if len(p.cfg.TrustHeaders) == 0 || headerTrusted(p.cfg.TrustHeaders, h.Header.Key) {
							r.Header.Set(h.Header.Key, h.Header.Value)
						}
					}
				}
			}

			ipAddress := extractIP(r)
			logging.LogAuthenticationAttempt(r.Context(), true, "grpc_auth", "", ipAddress, "")

			next.ServeHTTP(w, r)
			return
		}

		// Auth denied.
		ipAddress := extractIP(r)
		logging.LogAuthenticationAttempt(r.Context(), false, "grpc_auth", "", ipAddress, "denied")
		metric.AuthFailure("unknown", "grpc_auth", "denied", ipAddress)

		statusCode := http.StatusForbidden
		if checkResp.DeniedResponse != nil && checkResp.DeniedResponse.Status != nil && checkResp.DeniedResponse.Status.Code > 0 {
			statusCode = checkResp.DeniedResponse.Status.Code
		}

		deniedBody := "Forbidden"
		if checkResp.DeniedResponse != nil && checkResp.DeniedResponse.Body != "" {
			deniedBody = checkResp.DeniedResponse.Body
		}

		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(deniedBody))
	})
}

func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	return "http"
}

func extractIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return strings.Split(forwarded, ",")[0]
	}
	return r.RemoteAddr
}

func headerTrusted(trustHeaders []string, header string) bool {
	lower := strings.ToLower(header)
	for _, h := range trustHeaders {
		if strings.ToLower(h) == lower {
			return true
		}
	}
	return false
}

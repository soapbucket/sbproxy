// Package forwardauth registers the forward auth provider.
// Forward auth delegates authentication to an external service via a subrequest.
package forwardauth

import (
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
	plugin.RegisterAuth("forward", New)
}

// Config holds configuration for the forward auth provider.
type Config struct {
	Type           string        `json:"type"`
	Disabled       bool          `json:"disabled,omitempty"`
	URL            string        `json:"url"`
	Method         string        `json:"method,omitempty"`
	TrustHeaders   []string      `json:"trust_headers,omitempty"`
	ForwardHeaders []string      `json:"forward_headers,omitempty"`
	ForwardBody    bool          `json:"forward_body,omitempty"`
	SuccessStatus  []int         `json:"success_status,omitempty"`
	TimeoutSeconds float64       `json:"timeout,omitempty"` // seconds
	Timeout        time.Duration `json:"-"`
}

// provider is the runtime auth provider.
type provider struct {
	cfg          *Config
	client       *http.Client
	successCodes map[int]bool
}

// New creates a new forward auth provider from raw JSON configuration.
func New(data json.RawMessage) (plugin.AuthProvider, error) {
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	if cfg.URL == "" {
		return nil, fmt.Errorf("forward auth: url is required")
	}

	if cfg.Method == "" {
		cfg.Method = http.MethodGet
	} else {
		cfg.Method = strings.ToUpper(cfg.Method)
	}

	successCodes := make(map[int]bool)
	if len(cfg.SuccessStatus) == 0 {
		successCodes[http.StatusOK] = true
	} else {
		for _, code := range cfg.SuccessStatus {
			successCodes[code] = true
		}
	}

	timeout := 5 * time.Second
	if cfg.TimeoutSeconds > 0 {
		timeout = time.Duration(cfg.TimeoutSeconds * float64(time.Second))
	}

	return &provider{
		cfg:          cfg,
		client:       &http.Client{Timeout: timeout},
		successCodes: successCodes,
	}, nil
}

func (p *provider) Type() string { return "forward" }

func (p *provider) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body io.Reader
		if p.cfg.ForwardBody && r.Body != nil {
			body = r.Body
		}

		authReq, err := http.NewRequestWithContext(r.Context(), p.cfg.Method, p.cfg.URL, body)
		if err != nil {
			slog.Error("forward auth: failed to create request", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Forward configured headers from original request.
		if len(p.cfg.ForwardHeaders) > 0 {
			for _, header := range p.cfg.ForwardHeaders {
				if val := r.Header.Get(header); val != "" {
					authReq.Header.Set(header, val)
				}
			}
		} else {
			// Default: forward Authorization and Cookie headers.
			if auth := r.Header.Get("Authorization"); auth != "" {
				authReq.Header.Set("Authorization", auth)
			}
			if cookie := r.Header.Get("Cookie"); cookie != "" {
				authReq.Header.Set("Cookie", cookie)
			}
		}

		// Forward request metadata as X-Forwarded-* headers.
		authReq.Header.Set("X-Forwarded-Method", r.Method)
		authReq.Header.Set("X-Forwarded-Proto", scheme(r))
		authReq.Header.Set("X-Forwarded-Host", r.Host)
		authReq.Header.Set("X-Forwarded-Uri", r.RequestURI)
		if r.RemoteAddr != "" {
			authReq.Header.Set("X-Forwarded-For", r.RemoteAddr)
		}

		resp, err := p.client.Do(authReq)
		if err != nil {
			ipAddress := extractIP(r)
			logging.LogAuthenticationAttempt(r.Context(), false, "forward", "", ipAddress, "auth_server_error")
			metric.AuthFailure("unknown", "forward", "auth_server_error", ipAddress)

			slog.Error("forward auth: request failed", "error", err, "url", p.cfg.URL)
			http.Error(w, "Authentication Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		defer resp.Body.Close()

		if p.successCodes[resp.StatusCode] {
			// Copy trust headers from auth response to the downstream request.
			for _, header := range p.cfg.TrustHeaders {
				if val := resp.Header.Get(header); val != "" {
					r.Header.Set(header, val)
				}
			}

			ipAddress := extractIP(r)
			logging.LogAuthenticationAttempt(r.Context(), true, "forward", "", ipAddress, "")

			next.ServeHTTP(w, r)
			return
		}

		// Auth failed - forward the auth server's response.
		ipAddress := extractIP(r)
		logging.LogAuthenticationAttempt(r.Context(), false, "forward", "", ipAddress, "denied")
		metric.AuthFailure("unknown", "forward", "denied", ipAddress)

		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
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

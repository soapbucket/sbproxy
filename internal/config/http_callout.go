// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"io"
	"log/slog"
	"net/http"
	"time"
)

const (
	defaultCalloutTimeout = 5 * time.Second
	maxCalloutBodySize    = 64 * 1024 // 64KB max response from callout
)

// ExecuteHTTPCallout performs the mid-request HTTP callout for request enrichment.
// On success, it injects the callout response headers into the outbound request.
// On failure with fail_mode "open" (default), the request proceeds without enrichment.
// On failure with fail_mode "closed", a non-nil error is returned and the caller
// should return HTTP 502.
func ExecuteHTTPCallout(cfg *HTTPCalloutConfig, req *http.Request) error {
	if cfg == nil || cfg.URL == "" {
		return nil
	}

	timeout := cfg.Timeout.Duration
	if timeout == 0 {
		timeout = defaultCalloutTimeout
	}

	method := cfg.Method
	if method == "" {
		method = http.MethodGet
	}

	failClosed := cfg.FailMode == "closed"

	// Build callout request using the inbound request's context for cancellation
	calloutReq, err := http.NewRequestWithContext(req.Context(), method, cfg.URL, nil)
	if err != nil {
		slog.Error("http_callout: failed to create request", "url", cfg.URL, "error", err)
		if failClosed {
			return err
		}
		return nil
	}

	// Forward configured headers
	for k, v := range cfg.Headers {
		calloutReq.Header.Set(k, v)
	}

	client := &http.Client{
		Timeout: timeout,
		// Don't follow redirects for callouts
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(calloutReq)
	if err != nil {
		slog.Warn("http_callout: request failed",
			"url", cfg.URL,
			"error", err)
		if failClosed {
			return err
		}
		return nil
	}

	// Drain and close the response body
	io.Copy(io.Discard, io.LimitReader(resp.Body, maxCalloutBodySize))
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		slog.Warn("http_callout: upstream returned error",
			"url", cfg.URL,
			"status", resp.StatusCode)
		if failClosed {
			return &CalloutError{StatusCode: resp.StatusCode, URL: cfg.URL}
		}
		return nil
	}

	// Inject callout response headers into the upstream request.
	// Only inject headers that start with "X-" to avoid overwriting standard headers.
	for key, values := range resp.Header {
		if len(key) > 2 && key[0] == 'X' && key[1] == '-' {
			for _, v := range values {
				req.Header.Add(key, v)
			}
		}
	}

	slog.Debug("http_callout: enrichment applied",
		"url", cfg.URL,
		"status", resp.StatusCode)

	return nil
}

// CalloutError represents a failure from the callout upstream.
type CalloutError struct {
	StatusCode int
	URL        string
}

// Error implements the error interface.
func (e *CalloutError) Error() string {
	return "http_callout: upstream " + e.URL + " returned status " + http.StatusText(e.StatusCode)
}

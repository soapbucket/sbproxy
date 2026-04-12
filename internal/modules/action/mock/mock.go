// Package mock provides a synthetic response action module. It returns a
// configurable HTTP response with optional simulated latency. Registers under "mock".
package mock

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterAction("mock", New)
}

// Duration is a JSON-decodable time.Duration using a string like "200ms", "1s".
type Duration struct {
	time.Duration
}

// UnmarshalJSON decodes a duration from a JSON string or number (nanoseconds).
func (d *Duration) UnmarshalJSON(b []byte) error {
	// Try string first ("200ms", "1s", etc.)
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		dur, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("mock: parse duration %q: %w", s, err)
		}
		d.Duration = dur
		return nil
	}
	// Fall back to nanoseconds number.
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("mock: decode duration: %w", err)
	}
	d.Duration = time.Duration(n)
	return nil
}

// Config holds mock action configuration.
type Config struct {
	StatusCode int               `json:"status_code,omitempty"` // HTTP status (default 200)
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
	Delay      Duration          `json:"delay,omitempty"` // simulated latency
}

// Handler is the mock action handler.
type Handler struct {
	cfg Config
}

// New is the ActionFactory for the mock module.
func New(raw json.RawMessage) (plugin.ActionHandler, error) {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("mock: parse config: %w", err)
	}
	if cfg.StatusCode == 0 {
		cfg.StatusCode = http.StatusOK
	}
	return &Handler{cfg: cfg}, nil
}

// Type returns the action type name.
func (h *Handler) Type() string { return "mock" }

// ServeHTTP writes the synthetic response, optionally sleeping first.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.cfg.Delay.Duration > 0 {
		timer := time.NewTimer(h.cfg.Delay.Duration)
		select {
		case <-timer.C:
		case <-r.Context().Done():
			timer.Stop()
			http.Error(w, "request cancelled", http.StatusServiceUnavailable)
			return
		}
	}

	body := []byte(h.cfg.Body)

	header := w.Header()
	for k, v := range h.cfg.Headers {
		header.Set(k, v)
	}
	if header.Get("Content-Length") == "" {
		header.Set("Content-Length", strconv.Itoa(len(body)))
	}
	if header.Get("Content-Type") == "" && len(body) > 0 {
		header.Set("Content-Type", "text/plain; charset=utf-8")
	}

	w.WriteHeader(h.cfg.StatusCode)
	if len(body) > 0 {
		_, _ = io.Copy(w, bytes.NewReader(body))
	}
}

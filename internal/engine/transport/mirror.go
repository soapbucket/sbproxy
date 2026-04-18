// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"time"
)

// MirrorConfig configures traffic mirroring.
type MirrorConfig struct {
	URL        string  `json:"url" yaml:"url"`
	Percentage float64 `json:"percentage,omitempty" yaml:"percentage"` // 0.0-1.0, default 1.0
	TimeoutMs  int     `json:"timeout_ms,omitempty" yaml:"timeout_ms"`
}

const (
	defaultMirrorTimeout     = 5 * time.Second
	defaultMirrorMaxBodySize = 1 * 1024 * 1024 // 1 MB
)

// Mirror copies a request to a shadow upstream, discarding the response.
// The shadow request runs in a separate goroutine and does not affect
// the primary request's latency or response.
//
// The original request body is read, buffered, and restored so the primary
// handler can still consume it. If the body exceeds 1 MB it is skipped.
func Mirror(ctx context.Context, req *http.Request, cfg MirrorConfig, client *http.Client) {
	// Apply sampling
	pct := cfg.Percentage
	if pct <= 0 {
		pct = 1.0
	}
	if pct < 1.0 && rand.Float64() > pct {
		return
	}

	// Determine timeout
	timeout := defaultMirrorTimeout
	if cfg.TimeoutMs > 0 {
		timeout = time.Duration(cfg.TimeoutMs) * time.Millisecond
	}

	// Buffer the request body so both mirror and primary can read it
	var bodyBuf []byte
	if req.Body != nil && req.ContentLength != 0 {
		var err error
		bodyBuf, err = io.ReadAll(io.LimitReader(req.Body, defaultMirrorMaxBodySize+1))
		if err != nil {
			slog.Debug("mirror: failed to read body", "error", err)
			return
		}
		// If body exceeds the limit, restore it for primary but skip mirror
		if int64(len(bodyBuf)) > defaultMirrorMaxBodySize {
			req.Body = io.NopCloser(bytes.NewReader(bodyBuf))
			return
		}
		// Restore body for primary handler
		req.Body = io.NopCloser(bytes.NewReader(bodyBuf))
	}

	// Build mirror request using a detached context so it survives client disconnect
	mirrorCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)

	var mirrorBody io.Reader
	if len(bodyBuf) > 0 {
		mirrorBody = bytes.NewReader(bodyBuf)
	}

	mirrorReq, err := http.NewRequestWithContext(mirrorCtx, req.Method, cfg.URL+req.URL.Path, mirrorBody)
	if err != nil {
		cancel()
		slog.Debug("mirror: failed to create request", "error", err)
		return
	}

	// Preserve query string
	mirrorReq.URL.RawQuery = req.URL.RawQuery

	// Copy headers
	for k, vv := range req.Header {
		for _, v := range vv {
			mirrorReq.Header.Add(k, v)
		}
	}

	// Dispatch in a goroutine - fire and forget
	go func() {
		defer cancel()

		resp, doErr := client.Do(mirrorReq)
		if doErr != nil {
			slog.Debug("mirror: request failed", "url", cfg.URL, "error", doErr)
			return
		}
		// Drain and close
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()
}

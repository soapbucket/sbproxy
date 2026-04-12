// Package payloadlimit registers the payload_limit transform.
package payloadlimit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterTransform("payload_limit", New)
}

// Config holds configuration for the payload_limit transform.
type Config struct {
	Type    string `json:"type"`
	MaxSize int64  `json:"max_size"`
	Action  string `json:"action,omitempty"`
}

// payloadLimitTransform implements plugin.TransformHandler.
type payloadLimitTransform struct {
	maxSize int64
	action  string
}

// New creates a new payload_limit transform.
func New(data json.RawMessage) (plugin.TransformHandler, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("payload_limit: %w", err)
	}

	if cfg.MaxSize <= 0 {
		return nil, fmt.Errorf("payload_limit: max_size must be positive")
	}

	if cfg.Action == "" {
		cfg.Action = "reject"
	}
	if cfg.Action != "truncate" && cfg.Action != "reject" && cfg.Action != "warn" {
		return nil, fmt.Errorf("payload_limit: invalid action %q (must be truncate, reject, or warn)", cfg.Action)
	}

	return &payloadLimitTransform{maxSize: cfg.MaxSize, action: cfg.Action}, nil
}

func (c *payloadLimitTransform) Type() string { return "payload_limit" }
func (c *payloadLimitTransform) Apply(resp *http.Response) error {
	// Fast path: check Content-Length header first
	if resp.ContentLength >= 0 && resp.ContentLength <= c.maxSize {
		return nil
	}

	if resp.ContentLength > c.maxSize {
		return c.handleOversize(resp)
	}

	// Content-Length unknown (-1) — read body to check
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if int64(len(body)) <= c.maxSize {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	switch c.action {
	case "truncate":
		truncated := body[:c.maxSize]
		resp.Body = io.NopCloser(bytes.NewReader(truncated))
		resp.Header.Set("Content-Length", strconv.FormatInt(c.maxSize, 10))
		resp.Header.Set("X-Payload-Truncated", "true")
	case "reject":
		errBody := []byte(`{"error":"response payload exceeds size limit"}`)
		resp.StatusCode = http.StatusRequestEntityTooLarge
		resp.Body = io.NopCloser(bytes.NewReader(errBody))
		resp.Header.Set("Content-Length", strconv.Itoa(len(errBody)))
		resp.Header.Set("Content-Type", "application/json")
	case "warn":
		resp.Header.Set("X-Payload-Warning", fmt.Sprintf("response size %d exceeds limit %d", len(body), c.maxSize))
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}

	return nil
}

func (c *payloadLimitTransform) handleOversize(resp *http.Response) error {
	switch c.action {
	case "truncate":
		limited := io.LimitReader(resp.Body, c.maxSize)
		body, err := io.ReadAll(limited)
		if err != nil {
			return err
		}
		resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		resp.Header.Set("X-Payload-Truncated", "true")
	case "reject":
		resp.Body.Close()
		errBody := []byte(`{"error":"response payload exceeds size limit"}`)
		resp.StatusCode = http.StatusRequestEntityTooLarge
		resp.Body = io.NopCloser(bytes.NewReader(errBody))
		resp.Header.Set("Content-Length", strconv.Itoa(len(errBody)))
		resp.Header.Set("Content-Type", "application/json")
	case "warn":
		resp.Header.Set("X-Payload-Warning", fmt.Sprintf("content-length %d exceeds limit %d", resp.ContentLength, c.maxSize))
	}
	return nil
}

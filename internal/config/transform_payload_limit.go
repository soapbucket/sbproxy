// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/soapbucket/sbproxy/internal/transformer"
)

func init() {
	transformLoaderFns[TransformPayloadLimit] = NewPayloadLimitTransform
}

// PayloadLimitTransformConfig is the runtime config for payload size limiting.
type PayloadLimitTransformConfig struct {
	PayloadLimitTransform
}

// NewPayloadLimitTransform creates a new payload limit transformer.
func NewPayloadLimitTransform(data []byte) (TransformConfig, error) {
	cfg := &PayloadLimitTransformConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
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

	cfg.tr = transformer.Func(cfg.limit)

	return cfg, nil
}

func (c *PayloadLimitTransformConfig) limit(resp *http.Response) error {
	// Fast path: check Content-Length header first (zero alloc)
	if resp.ContentLength >= 0 && resp.ContentLength <= c.MaxSize {
		return nil
	}

	if resp.ContentLength > c.MaxSize {
		return c.handleOversize(resp)
	}

	// Content-Length unknown (-1) — read body to check
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if int64(len(body)) <= c.MaxSize {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	// Body exceeds limit
	switch c.Action {
	case "truncate":
		truncated := body[:c.MaxSize]
		resp.Body = io.NopCloser(bytes.NewReader(truncated))
		resp.Header.Set("Content-Length", strconv.FormatInt(c.MaxSize, 10))
		resp.Header.Set("X-Payload-Truncated", "true")
	case "reject":
		errBody := []byte(`{"error":"response payload exceeds size limit"}`)
		resp.StatusCode = http.StatusRequestEntityTooLarge
		resp.Body = io.NopCloser(bytes.NewReader(errBody))
		resp.Header.Set("Content-Length", strconv.Itoa(len(errBody)))
		resp.Header.Set("Content-Type", "application/json")
	case "warn":
		resp.Header.Set("X-Payload-Warning", fmt.Sprintf("response size %d exceeds limit %d", len(body), c.MaxSize))
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}

	return nil
}

func (c *PayloadLimitTransformConfig) handleOversize(resp *http.Response) error {
	switch c.Action {
	case "truncate":
		limited := io.LimitReader(resp.Body, c.MaxSize)
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
		resp.Header.Set("X-Payload-Warning", fmt.Sprintf("content-length %d exceeds limit %d", resp.ContentLength, c.MaxSize))
	}
	return nil
}

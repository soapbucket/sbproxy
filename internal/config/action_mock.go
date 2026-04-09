// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"
)

func init() {
	loaderFns[TypeMock] = LoadMockConfig
}

var _ ActionConfig = (*MockActionConfig)(nil)

// MockActionConfig holds configuration for mock action.
type MockActionConfig struct {
	MockConfig
}

// LoadMockConfig loads and validates a mock action configuration.
func LoadMockConfig(data []byte) (ActionConfig, error) {
	cfg := &MockActionConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	// Set defaults
	if cfg.StatusCode == 0 {
		cfg.StatusCode = http.StatusOK
	}

	cfg.tr = MockTransportFn(cfg)
	return cfg, nil
}

// MockTransportFn creates a transport function that returns a synthetic response.
var MockTransportFn = func(cfg *MockActionConfig) TransportFn {
	return func(req *http.Request) (*http.Response, error) {
		// Simulate delay if configured
		if cfg.Delay.Duration > 0 {
			timer := time.NewTimer(cfg.Delay.Duration)
			select {
			case <-timer.C:
			case <-req.Context().Done():
				timer.Stop()
				return nil, req.Context().Err()
			}
		}

		body := []byte(cfg.Body)

		respHeaders := make(http.Header)
		for k, v := range cfg.Headers {
			respHeaders.Set(k, v)
		}
		// Set Content-Length if not explicitly provided
		if respHeaders.Get("Content-Length") == "" {
			respHeaders.Set("Content-Length", strconv.Itoa(len(body)))
		}
		// Set Content-Type if not explicitly provided and body is non-empty
		if respHeaders.Get("Content-Type") == "" && len(body) > 0 {
			respHeaders.Set("Content-Type", "text/plain; charset=utf-8")
		}

		return &http.Response{
			StatusCode: cfg.StatusCode,
			Header:     respHeaders,
			Body:       io.NopCloser(bytes.NewReader(body)),
			Request:    req,
		}, nil
	}
}

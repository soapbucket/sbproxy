package rag

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	json "github.com/goccy/go-json"
)

// HTTPClient is a shared REST client with retry, timeout, auth, and logging
// for RAG providers that use REST APIs (Vectara, Ragie, Cloudflare, Nuclia, etc.).
type HTTPClient struct {
	base       *http.Client
	baseURL    string
	authHeader string // e.g., "Authorization" or "x-api-key"
	authValue  string // e.g., "Bearer xxx" or raw key
	retries    int
	backoff    time.Duration
	logger     *slog.Logger
	headers    map[string]string // additional static headers
}

// HTTPClientOption configures an HTTPClient.
type HTTPClientOption func(*HTTPClient)

// NewHTTPClient creates a new shared REST client.
func NewHTTPClient(baseURL string, opts ...HTTPClientOption) *HTTPClient {
	c := &HTTPClient{
		base: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: baseURL,
		retries: 3,
		backoff: 500 * time.Millisecond,
		logger:  slog.Default(),
		headers: make(map[string]string),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// WithAuth sets the authentication header.
func WithAuth(header, value string) HTTPClientOption {
	return func(c *HTTPClient) {
		c.authHeader = header
		c.authValue = value
	}
}

// WithBearerAuth sets Bearer token authentication.
func WithBearerAuth(token string) HTTPClientOption {
	return func(c *HTTPClient) {
		c.authHeader = "Authorization"
		c.authValue = "Bearer " + token
	}
}

// WithAPIKeyAuth sets API key authentication via a named header.
func WithAPIKeyAuth(header, key string) HTTPClientOption {
	return func(c *HTTPClient) {
		c.authHeader = header
		c.authValue = key
	}
}

// WithTimeout sets the HTTP client timeout.
func WithTimeout(d time.Duration) HTTPClientOption {
	return func(c *HTTPClient) {
		c.base.Timeout = d
	}
}

// WithRetries sets the number of retry attempts.
func WithRetries(n int) HTTPClientOption {
	return func(c *HTTPClient) {
		c.retries = n
	}
}

// WithBackoff sets the initial backoff duration between retries.
func WithBackoff(d time.Duration) HTTPClientOption {
	return func(c *HTTPClient) {
		c.backoff = d
	}
}

// WithLogger sets the structured logger.
func WithLogger(l *slog.Logger) HTTPClientOption {
	return func(c *HTTPClient) {
		c.logger = l
	}
}

// WithHeader adds a static header to all requests.
func WithHeader(key, value string) HTTPClientOption {
	return func(c *HTTPClient) {
		c.headers[key] = value
	}
}

// WithHTTPClient sets a custom underlying HTTP client.
func WithHTTPClient(client *http.Client) HTTPClientOption {
	return func(c *HTTPClient) {
		c.base = client
	}
}

// Do executes an HTTP request with retry, auth, and JSON marshaling.
// body is marshaled to JSON (if non-nil). result is unmarshaled from the response (if non-nil).
func (c *HTTPClient) Do(ctx context.Context, method, path string, body any, result any) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	url := c.baseURL + path

	var lastErr error
	for attempt := 0; attempt <= c.retries; attempt++ {
		if attempt > 0 {
			backoff := c.backoff * time.Duration(1<<(attempt-1))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}

		// Reset body reader for retry.
		if body != nil {
			data, _ := json.Marshal(body)
			bodyReader = bytes.NewReader(data)
		}

		req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}

		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Accept", "application/json")

		if c.authHeader != "" && c.authValue != "" {
			req.Header.Set(c.authHeader, c.authValue)
		}

		for k, v := range c.headers {
			req.Header.Set(k, v)
		}

		resp, err := c.base.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("http request: %w", err)
			c.logger.Warn("rag http request failed",
				"method", method, "url", url, "attempt", attempt+1, "error", err)
			continue
		}

		respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("read response body: %w", err)
			continue
		}

		// Retry on 429 (rate limit) and 5xx (server errors).
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			lastErr = &HTTPError{
				StatusCode: resp.StatusCode,
				Body:       string(respBody),
			}
			c.logger.Warn("rag http retryable error",
				"method", method, "url", url, "status", resp.StatusCode, "attempt", attempt+1)
			continue
		}

		// Non-retryable error.
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return &HTTPError{
				StatusCode: resp.StatusCode,
				Body:       string(respBody),
			}
		}

		// Success - unmarshal result if provided.
		if result != nil && len(respBody) > 0 {
			if err := json.Unmarshal(respBody, result); err != nil {
				return fmt.Errorf("unmarshal response: %w", err)
			}
		}
		return nil
	}

	return fmt.Errorf("all %d attempts failed: %w", c.retries+1, lastErr)
}

// DoRaw executes an HTTP request and returns the raw response body.
// Useful for file uploads or non-JSON responses.
func (c *HTTPClient) DoRaw(ctx context.Context, method, path string, body io.Reader, contentType string) ([]byte, int, error) {
	url := c.baseURL + path

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, 0, fmt.Errorf("create request: %w", err)
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if c.authHeader != "" && c.authValue != "" {
		req.Header.Set(c.authHeader, c.authValue)
	}
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	resp, err := c.base.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response: %w", err)
	}

	return respBody, resp.StatusCode, nil
}

// HTTPError represents a non-successful HTTP response.
type HTTPError struct {
	StatusCode int
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("http %d: %s", e.StatusCode, e.Body)
}

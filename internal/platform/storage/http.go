// Package storage provides storage backend abstractions for caching and persistence.
package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

func init() {
	Register("http", NewHTTPStorage)
}

// HTTPStorage implements ConfigStorage by fetching JSON from a remote API
type HTTPStorage struct {
	baseURL string
	client  *http.Client
	token   string
	driver  string
}

// Get retrieves a value from the HTTPStorage.
func (s *HTTPStorage) Get(ctx context.Context, key string) ([]byte, error) {
	url := fmt.Sprintf("%s?hostname=%s", s.baseURL, key)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrKeyNotFound
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http storage: unexpected status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// GetByID returns the by id for the HTTPStorage.
func (s *HTTPStorage) GetByID(ctx context.Context, id string) ([]byte, error) {
	url := fmt.Sprintf("%s?origin_id=%s", s.baseURL, id)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrKeyNotFound
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http storage: unexpected status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// ValidateProxyAPIKey performs the validate proxy api key operation on the HTTPStorage.
func (s *HTTPStorage) ValidateProxyAPIKey(ctx context.Context, originID string, apiKey string) (*ProxyKeyValidationResult, error) {
	// Call backend endpoint: POST /api/v1/origins/{origin_id}/proxy-keys/validate/
	// The backend validates the key against bcrypt hashes and returns key metadata

	// Extract the base URL (remove query params)
	baseURL := s.baseURL
	if idx := bytes.IndexByte([]byte(baseURL), '?'); idx > 0 {
		baseURL = baseURL[:idx]
	}

	url := fmt.Sprintf("%s/origins/%s/proxy-keys/validate/", baseURL, originID)

	// Send key in request body (don't put in URL/query params to avoid logging)
	payload := map[string]string{"key": apiKey}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("invalid proxy API key")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http storage: unexpected status %d", resp.StatusCode)
	}

	var result struct {
		KeyID   string `json:"key_id"`
		KeyName string `json:"key_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &ProxyKeyValidationResult{
		ProxyKeyID:   result.KeyID,
		ProxyKeyName: result.KeyName,
	}, nil
}

// Put performs the put operation on the HTTPStorage.
func (s *HTTPStorage) Put(ctx context.Context, key string, data []byte) error { return ErrReadOnly }
// Delete performs the delete operation on the HTTPStorage.
func (s *HTTPStorage) Delete(ctx context.Context, key string) error      { return ErrReadOnly }
// DeleteByPrefix performs the delete by prefix operation on the HTTPStorage.
func (s *HTTPStorage) DeleteByPrefix(ctx context.Context, prefix string) error { return ErrReadOnly }
// Close releases resources held by the HTTPStorage.
func (s *HTTPStorage) Close() error                                     { return nil }
// Driver performs the driver operation on the HTTPStorage.
func (s *HTTPStorage) Driver() string                                   { return s.driver }
// ListKeys performs the list keys operation on the HTTPStorage.
func (s *HTTPStorage) ListKeys(ctx context.Context) ([]string, error) { return nil, ErrListKeysNotSupported }
// ListKeysByWorkspace performs the list keys by workspace operation on the HTTPStorage.
func (s *HTTPStorage) ListKeysByWorkspace(ctx context.Context, workspaceID string) ([]string, error) {
	return nil, ErrListKeysNotSupported
}

// NewHTTPStorage creates and initializes a new HTTPStorage.
func NewHTTPStorage(settings Settings) (Storage, error) {
	url, ok := settings.Params["url"]
	if !ok {
		return nil, fmt.Errorf("http storage: url is required")
	}

	return &HTTPStorage{
		baseURL: url,
		token:   settings.Params["token"],
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		driver: "http",
	}, nil
}

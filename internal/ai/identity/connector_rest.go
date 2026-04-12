// connector_rest.go resolves permissions via an HMAC-signed REST API call.
package identity

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	json "github.com/goccy/go-json"
)

// RESTConnector resolves permissions via an HMAC-signed REST API call.
type RESTConnector struct {
	url          string
	sharedSecret string
	httpClient   *http.Client
	timeout      time.Duration
}

// NewRESTConnector creates a REST-based permission connector.
func NewRESTConnector(url, sharedSecret string, timeout time.Duration) *RESTConnector {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &RESTConnector{
		url:          url,
		sharedSecret: sharedSecret,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		timeout: timeout,
	}
}

// restResolveRequest is the JSON body sent to the REST endpoint.
type restResolveRequest struct {
	CredentialType string `json:"credential_type"`
	Credential     string `json:"credential"`
}

// restResolveResponse is the expected JSON response from the REST endpoint.
type restResolveResponse struct {
	Principal   string   `json:"principal"`
	Groups      []string `json:"groups"`
	Models      []string `json:"models"`
	Permissions []string `json:"permissions"`
}

// Resolve calls the REST API with an HMAC-SHA256 signed request body.
// The endpoint receives a POST to {url}/resolve with a JSON body.
// Authentication is provided via X-Signature header containing HMAC-SHA256(shared_secret, body).
// Returns nil, nil when the endpoint returns 404 (credential not found).
func (r *RESTConnector) Resolve(ctx context.Context, credentialType, credential string) (*CachedPermission, error) {
	reqBody := restResolveRequest{
		CredentialType: credentialType,
		Credential:     credential,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("identity: REST marshal request: %w", err)
	}

	endpoint := r.url + "/resolve"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("identity: REST create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// Sign request body with HMAC-SHA256 if a shared secret is configured.
	if r.sharedSecret != "" {
		mac := hmac.New(sha256.New, []byte(r.sharedSecret))
		mac.Write(bodyBytes)
		sig := hex.EncodeToString(mac.Sum(nil))
		httpReq.Header.Set("X-Signature", sig)
	}

	resp, err := r.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("identity: REST request failed: %w", err)
	}
	defer resp.Body.Close()

	// 404 means credential not found - return nil (will become a negative cache entry).
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("identity: REST unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var result restResolveResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("identity: REST decode response: %w", err)
	}

	now := time.Now()
	return &CachedPermission{
		Principal:   result.Principal,
		Groups:      result.Groups,
		Models:      result.Models,
		Permissions: result.Permissions,
		CachedAt:    now,
		ExpiresAt:   now.Add(5 * time.Minute),
	}, nil
}

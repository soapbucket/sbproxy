// tool_auth.go configures per-tool authentication for upstream API calls.
package mcp

import (
	"encoding/base64"
	"fmt"
	"net/http"
)

// ToolAuthConfig configures per-tool authentication for upstream API calls.
type ToolAuthConfig struct {
	// Type: "bearer_token", "api_key", "basic"
	Type string `json:"type"`

	// BearerToken for bearer_token auth type
	Token string `json:"token,omitempty"`

	// APIKey for api_key auth type
	APIKey     string `json:"api_key,omitempty"`
	APIKeyName string `json:"api_key_name,omitempty"` // Header name, default "X-API-Key"
	APIKeyIn   string `json:"api_key_in,omitempty"`   // "header" (default) or "query"

	// Basic auth credentials
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// ToolAuthProvider manages authentication for tool HTTP requests.
type ToolAuthProvider struct {
	config *ToolAuthConfig
}

// NewToolAuthProvider creates a new auth provider from config.
func NewToolAuthProvider(config *ToolAuthConfig) *ToolAuthProvider {
	if config == nil {
		return nil
	}
	return &ToolAuthProvider{config: config}
}

// ApplyAuth adds authentication to an HTTP request based on the configured auth type.
func (p *ToolAuthProvider) ApplyAuth(req *http.Request) error {
	if p == nil || p.config == nil {
		return nil
	}

	switch p.config.Type {
	case "bearer_token":
		return p.applyBearerToken(req)
	case "api_key":
		return p.applyAPIKey(req)
	case "basic":
		return p.applyBasicAuth(req)
	default:
		return fmt.Errorf("unsupported auth type: %s", p.config.Type)
	}
}

func (p *ToolAuthProvider) applyBearerToken(req *http.Request) error {
	if p.config.Token == "" {
		return fmt.Errorf("bearer_token auth requires token")
	}
	req.Header.Set("Authorization", "Bearer "+p.config.Token)
	return nil
}

func (p *ToolAuthProvider) applyAPIKey(req *http.Request) error {
	if p.config.APIKey == "" {
		return fmt.Errorf("api_key auth requires api_key")
	}

	name := p.config.APIKeyName
	if name == "" {
		name = "X-API-Key"
	}

	if p.config.APIKeyIn == "query" {
		q := req.URL.Query()
		q.Set(name, p.config.APIKey)
		req.URL.RawQuery = q.Encode()
	} else {
		req.Header.Set(name, p.config.APIKey)
	}
	return nil
}

func (p *ToolAuthProvider) applyBasicAuth(req *http.Request) error {
	if p.config.Username == "" {
		return fmt.Errorf("basic auth requires username")
	}
	credentials := base64.StdEncoding.EncodeToString(
		[]byte(p.config.Username + ":" + p.config.Password),
	)
	req.Header.Set("Authorization", "Basic "+credentials)
	return nil
}

// Package classifierpkg is a stub for the prompt-classifier client.
// It provides the same types and constructors so that the rest of the codebase
// compiles, but every operation is a no-op or returns an error.
package classifierpkg

import (
	"context"
	"fmt"
	"time"
)

// ---------- option helpers ----------

// Option configures a Client.
type Option func(*Client)

// WithPoolSize sets the connection pool size (no-op in stub).
func WithPoolSize(n int) Option { return func(*Client) {} }

// WithTimeout sets the request timeout (no-op in stub).
func WithTimeout(d time.Duration) Option { return func(*Client) {} }

// ---------- client ----------

// Client is a stub classifier client.
type Client struct{}

// NewClient creates a stub client. The address and options are accepted
// for API compatibility but ignored.
func NewClient(_ string, _ ...Option) *Client { return &Client{} }

// WaitReady always returns an error because the real sidecar is not present.
func (c *Client) WaitReady(_ context.Context) error {
	return fmt.Errorf("classifier sidecar not available (stub)")
}

// ClassifyForTenant is a stub that always returns an error.
func (c *Client) ClassifyForTenant(_ string, _ int, _ string) (*Response, error) {
	return nil, fmt.Errorf("classifier sidecar not available (stub)")
}

// EmbedOne is a stub that always returns an error.
func (c *Client) EmbedOne(_ string) ([]float32, error) {
	return nil, fmt.Errorf("classifier sidecar not available (stub)")
}

// Embed is a stub that always returns an error.
func (c *Client) Embed(_ ...string) (*EmbedResponse, error) {
	return nil, fmt.Errorf("classifier sidecar not available (stub)")
}

// Register is a stub that always returns an error.
func (c *Client) Register(_ string, _ *TenantConfig) error {
	return fmt.Errorf("classifier sidecar not available (stub)")
}

// Delete is a stub that always returns an error.
func (c *Client) Delete(_ string) error {
	return fmt.Errorf("classifier sidecar not available (stub)")
}

// Version is a stub that always returns an error.
func (c *Client) Version() (*VersionResponse, error) {
	return nil, fmt.Errorf("classifier sidecar not available (stub)")
}

// Close is a no-op for the stub client.
func (c *Client) Close() {}

// ---------- response types ----------

// Response is the classification response.
type Response struct {
	Labels     []ResponseLabel `json:"labels,omitempty"`
	Normalized string          `json:"normalized,omitempty"`
}

// ResponseLabel is a single label result.
type ResponseLabel struct {
	Label string  `json:"label"`
	Name  string  `json:"name"`
	Score float64 `json:"score"`
}

// EmbedResponse holds embedding vectors.
type EmbedResponse struct {
	Embeddings [][]float32 `json:"embeddings"`
}

// VersionResponse holds sidecar version info.
type VersionResponse struct {
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	Mode           string   `json:"mode,omitempty"`
	EmbedSupported bool     `json:"embed_supported,omitempty"`
	Capabilities   []string `json:"capabilities,omitempty"`
}

// ---------- tenant config types ----------

// TenantConfig holds the full tenant configuration for the sidecar.
type TenantConfig struct {
	Labels         []TenantLabel         `json:"labels,omitempty"`
	Classification *TenantClassification `json:"classification,omitempty"`
	Normalization  *TenantNormalization  `json:"normalization,omitempty"`
}

// TenantLabel defines a single label with patterns.
type TenantLabel struct {
	Name     string   `json:"name"`
	Patterns []string `json:"patterns"`
	Weight   float64  `json:"weight,omitempty"`
}

// TenantClassification holds classification thresholds.
type TenantClassification struct {
	ConfidenceThreshold float64 `json:"confidence_threshold,omitempty"`
	DefaultLabel        string  `json:"default_label,omitempty"`
}

// TenantNormalization holds text normalization settings.
type TenantNormalization struct {
	UnicodeNFKC bool             `json:"unicode_nfkc,omitempty"`
	Trim        bool             `json:"trim,omitempty"`
	Rules       []TenantNormRule `json:"rules,omitempty"`
}

// TenantNormRule is a single normalization rule.
type TenantNormRule struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	Replace string `json:"replace"`
	Enabled bool   `json:"enabled"`
}

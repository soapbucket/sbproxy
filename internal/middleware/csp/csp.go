// Package csp implements Content Security Policy header generation and management.
package csp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

const (
	// NonceHeader is the header name for CSP nonce
	NonceHeader = "X-CSP-Nonce"
)

// Config holds configuration for CSP.
type Config struct {
	Enabled    bool   `json:"enabled,omitempty"`
	Policy     string `json:"policy,omitempty"` // Simple string policy (for backward compatibility)
	ReportOnly bool   `json:"report_only,omitempty"`
	ReportURI  string `json:"report_uri,omitempty"`

	// Enhanced CSP features
	Directives    *Directives        `json:"directives,omitempty"`     // Structured directives
	EnableNonce   bool               `json:"enable_nonce,omitempty"`   // Enable nonce generation
	EnableHash    bool               `json:"enable_hash,omitempty"`    // Enable hash calculation
	DynamicRoutes map[string]*Config `json:"dynamic_routes,omitempty"` // Route-specific CSP
}

// Directives represents structured CSP directives
type Directives struct {
	DefaultSrc              []string `json:"default_src,omitempty"`
	ScriptSrc               []string `json:"script_src,omitempty"`
	StyleSrc                []string `json:"style_src,omitempty"`
	ImgSrc                  []string `json:"img_src,omitempty"`
	FontSrc                 []string `json:"font_src,omitempty"`
	ConnectSrc              []string `json:"connect_src,omitempty"`
	FrameSrc                []string `json:"frame_src,omitempty"`
	ObjectSrc               []string `json:"object_src,omitempty"`
	MediaSrc                []string `json:"media_src,omitempty"`
	FrameAncestors          []string `json:"frame_ancestors,omitempty"`
	BaseURI                 []string `json:"base_uri,omitempty"`
	FormAction              []string `json:"form_action,omitempty"`
	UpgradeInsecureRequests bool     `json:"upgrade_insecure_requests,omitempty"`
}

// ViolationReport represents a CSP violation report from the browser
type ViolationReport struct {
	Body struct {
		DocumentURI        string `json:"document-uri"`
		Referrer           string `json:"referrer"`
		ViolatedDirective  string `json:"violated-directive"`
		EffectiveDirective string `json:"effective-directive"`
		OriginalPolicy     string `json:"original-policy"`
		Disposition        string `json:"disposition"`
		BlockedURI         string `json:"blocked-uri"`
		LineNumber         int    `json:"line-number"`
		ColumnNumber       int    `json:"column-number"`
		SourceFile         string `json:"source-file"`
		StatusCode         int    `json:"status-code"`
		ScriptSample       string `json:"script-sample"`
	} `json:"csp-report"`
}

// GenerateNonce generates a random nonce for CSP
func GenerateNonce() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// CalculateHash calculates SHA-256 hash of content for CSP hash source
func CalculateHash(content string) string {
	if content == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(content))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// BuildPolicy builds a CSP policy string from directives
func BuildPolicy(directives *Directives, nonce string, hashes []string) string {
	if directives == nil {
		return ""
	}

	var parts []string

	// Default source
	if len(directives.DefaultSrc) > 0 {
		parts = append(parts, "default-src "+strings.Join(directives.DefaultSrc, " "))
	}

	// Script source (with nonce/hash support)
	if len(directives.ScriptSrc) > 0 {
		scriptSrc := make([]string, len(directives.ScriptSrc))
		copy(scriptSrc, directives.ScriptSrc)
		if nonce != "" {
			scriptSrc = append(scriptSrc, fmt.Sprintf("'nonce-%s'", nonce))
		}
		for _, hash := range hashes {
			scriptSrc = append(scriptSrc, fmt.Sprintf("'sha256-%s'", hash))
		}
		parts = append(parts, "script-src "+strings.Join(scriptSrc, " "))
	}

	// Style source (with nonce/hash support)
	if len(directives.StyleSrc) > 0 {
		styleSrc := make([]string, len(directives.StyleSrc))
		copy(styleSrc, directives.StyleSrc)
		if nonce != "" {
			styleSrc = append(styleSrc, fmt.Sprintf("'nonce-%s'", nonce))
		}
		for _, hash := range hashes {
			styleSrc = append(styleSrc, fmt.Sprintf("'sha256-%s'", hash))
		}
		parts = append(parts, "style-src "+strings.Join(styleSrc, " "))
	}

	// Image source
	if len(directives.ImgSrc) > 0 {
		parts = append(parts, "img-src "+strings.Join(directives.ImgSrc, " "))
	}

	// Font source
	if len(directives.FontSrc) > 0 {
		parts = append(parts, "font-src "+strings.Join(directives.FontSrc, " "))
	}

	// Connect source
	if len(directives.ConnectSrc) > 0 {
		parts = append(parts, "connect-src "+strings.Join(directives.ConnectSrc, " "))
	}

	// Frame source
	if len(directives.FrameSrc) > 0 {
		parts = append(parts, "frame-src "+strings.Join(directives.FrameSrc, " "))
	}

	// Object source
	if len(directives.ObjectSrc) > 0 {
		parts = append(parts, "object-src "+strings.Join(directives.ObjectSrc, " "))
	}

	// Media source
	if len(directives.MediaSrc) > 0 {
		parts = append(parts, "media-src "+strings.Join(directives.MediaSrc, " "))
	}

	// Frame ancestors
	if len(directives.FrameAncestors) > 0 {
		parts = append(parts, "frame-ancestors "+strings.Join(directives.FrameAncestors, " "))
	}

	// Base URI
	if len(directives.BaseURI) > 0 {
		parts = append(parts, "base-uri "+strings.Join(directives.BaseURI, " "))
	}

	// Form action
	if len(directives.FormAction) > 0 {
		parts = append(parts, "form-action "+strings.Join(directives.FormAction, " "))
	}

	// Upgrade insecure requests
	if directives.UpgradeInsecureRequests {
		parts = append(parts, "upgrade-insecure-requests")
	}

	return strings.Join(parts, "; ")
}

// GetCSPForRoute returns the CSP config for a specific route, falling back to default
func (c *Config) GetCSPForRoute(path string) *Config {
	if c.DynamicRoutes == nil {
		return c
	}

	// Check for exact match first
	if routeCSP, ok := c.DynamicRoutes[path]; ok {
		slog.Debug("CSP exact route match found",
			"path", path,
			"route", path)
		return routeCSP
	}

	// Check for prefix matches (longest match wins)
	var bestMatch *Config
	var bestMatchLen int
	var bestMatchRoute string
	for route, routeCSP := range c.DynamicRoutes {
		if strings.HasPrefix(path, route) && len(route) > bestMatchLen {
			bestMatch = routeCSP
			bestMatchLen = len(route)
			bestMatchRoute = route
		}
	}

	if bestMatch != nil {
		slog.Debug("CSP prefix route match found",
			"path", path,
			"matched_route", bestMatchRoute)
		return bestMatch
	}

	slog.Debug("CSP using default policy (no route match)",
		"path", path)
	return c
}

// BuildPolicyString builds the final CSP policy string for a request
func (c *Config) BuildPolicyString(r *http.Request, nonce string, hashes []string) string {
	// Use route-specific CSP if available
	routeCSP := c.GetCSPForRoute(r.URL.Path)

	// If simple policy string is provided, use it (backward compatibility)
	if routeCSP.Policy != "" {
		policy := routeCSP.Policy
		// Inject nonce if enabled
		if routeCSP.EnableNonce && nonce != "" {
			// Add nonce to script-src and style-src if they exist
			policy = InjectNonceIntoPolicy(policy, nonce)
			slog.Debug("CSP nonce injected into policy string",
				"path", r.URL.Path,
				"has_nonce", true)
		}
		return policy
	}

	// Build from structured directives
	if routeCSP.Directives != nil {
		policy := BuildPolicy(routeCSP.Directives, nonce, hashes)
		if policy != "" {
			slog.Debug("CSP policy built from structured directives",
				"path", r.URL.Path,
				"has_nonce", nonce != "",
				"has_hashes", len(hashes) > 0,
				"policy_length", len(policy))
		}
		return policy
	}

	slog.Debug("CSP policy is empty (no policy string or directives)",
		"path", r.URL.Path)
	return ""
}

// InjectNonceIntoPolicy injects nonce into an existing policy string
func InjectNonceIntoPolicy(policy, nonce string) string {
	// Simple approach: append nonce to script-src and style-src directives
	parts := strings.Split(policy, ";")
	var result []string

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "script-src") || strings.HasPrefix(part, "style-src") {
			// Check if nonce already exists
			if !strings.Contains(part, "'nonce-") {
				part += " 'nonce-" + nonce + "'"
			}
		}
		result = append(result, part)
	}

	return strings.Join(result, "; ")
}

// nonceContextKey is a custom type for context keys to avoid collisions
type nonceContextKey struct{}

var nonceContextKeyValue = nonceContextKey{}

// WithNonce stores the CSP nonce in the request context
func WithNonce(ctx context.Context, nonce string) context.Context {
	return context.WithValue(ctx, nonceContextKeyValue, nonce)
}

// GetNonce retrieves the CSP nonce from the request context
func GetNonce(ctx context.Context) (string, bool) {
	nonce, ok := ctx.Value(nonceContextKeyValue).(string)
	return nonce, ok
}

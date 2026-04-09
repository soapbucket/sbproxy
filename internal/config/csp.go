// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

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
	// CSPNonceHeader is the header name for CSP nonce
	CSPNonceHeader = "X-CSP-Nonce"
)

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

// BuildCSPPolicy builds a CSP policy string from directives
func BuildCSPPolicy(directives *CSPDirectives, nonce string, hashes []string) string {
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
func (c *CSPConfig) GetCSPForRoute(path string) *CSPConfig {
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
	var bestMatch *CSPConfig
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
func (c *CSPConfig) BuildPolicyString(r *http.Request, nonce string, hashes []string) string {
	// Use route-specific CSP if available
	routeCSP := c.GetCSPForRoute(r.URL.Path)

	// If simple policy string is provided, use it (backward compatibility)
	if routeCSP.Policy != "" {
		policy := routeCSP.Policy
		// Inject nonce if enabled
		if routeCSP.EnableNonce && nonce != "" {
			// Add nonce to script-src and style-src if they exist
			policy = injectNonceIntoPolicy(policy, nonce)
			slog.Debug("CSP nonce injected into policy string",
				"path", r.URL.Path,
				"has_nonce", true)
		}
		return policy
	}

	// Build from structured directives
	if routeCSP.Directives != nil {
		policy := BuildCSPPolicy(routeCSP.Directives, nonce, hashes)
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

// injectNonceIntoPolicy injects nonce into an existing policy string
func injectNonceIntoPolicy(policy, nonce string) string {
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

// cspNonceContextKey is a custom type for context keys to avoid collisions
type cspNonceContextKey struct{}

var cspNonceContextKeyValue = cspNonceContextKey{}

// WithCSPNonce stores the CSP nonce in the request context
func WithCSPNonce(ctx context.Context, nonce string) context.Context {
	return context.WithValue(ctx, cspNonceContextKeyValue, nonce)
}

// GetCSPNonce retrieves the CSP nonce from the request context
func GetCSPNonce(ctx context.Context) (string, bool) {
	nonce, ok := ctx.Value(cspNonceContextKeyValue).(string)
	return nonce, ok
}


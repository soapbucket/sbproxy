// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func init() {
	policyLoaderFns[PolicyTypeCSRF] = NewCSRFPolicy
}

// CSRFPolicyConfig implements PolicyConfig for CSRF protection
type CSRFPolicyConfig struct {
	CSRFPolicy

	// Internal
	config      *Config
	secret      []byte
	methods     map[string]bool
	exemptPaths map[string]bool
}

// NewCSRFPolicy creates a new CSRF policy config
func NewCSRFPolicy(data []byte) (PolicyConfig, error) {
	cfg := &CSRFPolicyConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	// Validate secret
	if cfg.Secret == "" {
		return nil, fmt.Errorf("CSRF policy requires a secret key")
	}
	cfg.secret = []byte(cfg.Secret)

	// Set defaults
	if cfg.CookieName == "" {
		cfg.CookieName = "_csrf"
	}
	if cfg.CookiePath == "" {
		cfg.CookiePath = "/"
	}
	if cfg.CookieSameSite == "" {
		cfg.CookieSameSite = "Lax"
	}
	if cfg.HeaderName == "" {
		cfg.HeaderName = "X-CSRF-Token"
	}
	if cfg.FormFieldName == "" {
		cfg.FormFieldName = "_csrf"
	}
	if cfg.TokenLength == 0 {
		cfg.TokenLength = 32
	}
	if len(cfg.Methods) == 0 {
		cfg.Methods = []string{"POST", "PUT", "DELETE", "PATCH"}
	}

	// Build method map
	cfg.methods = make(map[string]bool, len(cfg.Methods))
	for _, method := range cfg.Methods {
		cfg.methods[strings.ToUpper(method)] = true
	}

	// Build exempt paths map
	cfg.exemptPaths = make(map[string]bool, len(cfg.ExemptPaths))
	for _, path := range cfg.ExemptPaths {
		cfg.exemptPaths[path] = true
	}

	return cfg, nil
}

// Init initializes the policy config
func (p *CSRFPolicyConfig) Init(config *Config) error {
	p.config = config
	return nil
}

// Apply implements the middleware pattern for CSRF protection
func (p *CSRFPolicyConfig) Apply(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.Disabled {
			next.ServeHTTP(w, r)
			return
		}

		// Check if path is exempt
		if p.exemptPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		// Get or create CSRF token cookie (for all requests, not just state-changing ones)
		cookie, err := r.Cookie(p.CookieName)
		var token string

		if err != nil || cookie.Value == "" {
			// Generate new token
			token, err = p.generateToken()
			if err != nil {
				http.Error(w, "Failed to generate CSRF token", http.StatusInternalServerError)
				return
			}
			// Set cookie
			p.setCSRFCookie(w, r, token)
		} else {
			token = cookie.Value
		}

		// Check if method requires CSRF protection
		if p.methods[r.Method] {
			// Extract token from request
			requestToken := p.extractToken(r)

			if requestToken == "" {
				// Record CSRF validation failure metric
			origin := "unknown"
			if p.config != nil {
				origin = p.config.ID
			}
				metric.CSRFValidationFailure(origin, "token_missing")
				reqctx.RecordPolicyViolation(r.Context(), "csrf", "CSRF token missing")
				http.Error(w, "CSRF token missing", http.StatusForbidden)
				return
			}

			// Validate token
			if !p.validateToken(token, requestToken) {
				// Record CSRF validation failure metric
			origin := "unknown"
			if p.config != nil {
				origin = p.config.ID
			}
				metric.CSRFValidationFailure(origin, "token_invalid")
				reqctx.RecordPolicyViolation(r.Context(), "csrf", "Invalid CSRF token")
				http.Error(w, "Invalid CSRF token", http.StatusForbidden)
				return
			}
		}

		// All checks passed, continue to next handler
		next.ServeHTTP(w, r)
	})
}

// generateToken generates a new CSRF token
func (p *CSRFPolicyConfig) generateToken() (string, error) {
	// Generate random bytes
	randomBytes := make([]byte, p.TokenLength)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Create HMAC signature
	mac := hmac.New(sha256.New, p.secret)
	mac.Write(randomBytes)
	signature := mac.Sum(nil)

	// Combine random bytes and signature
	token := append(randomBytes, signature...)

	// Encode to base64
	return base64.URLEncoding.EncodeToString(token), nil
}

// validateToken validates a CSRF token
func (p *CSRFPolicyConfig) validateToken(cookieToken, requestToken string) bool {
	// Tokens must match exactly (double-submit cookie pattern)
	// Both tokens are signed, so we compare them directly
	return cookieToken == requestToken && p.verifyTokenSignature(cookieToken)
}

// verifyTokenSignature verifies that a token has a valid signature
func (p *CSRFPolicyConfig) verifyTokenSignature(token string) bool {
	// Decode token
	tokenBytes, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return false
	}

	// Token should be randomBytes + signature
	if len(tokenBytes) < p.TokenLength+sha256.Size {
		return false
	}

	randomBytes := tokenBytes[:p.TokenLength]
	signature := tokenBytes[p.TokenLength:]

	// Verify HMAC
	mac := hmac.New(sha256.New, p.secret)
	mac.Write(randomBytes)
	expectedSignature := mac.Sum(nil)

	return hmac.Equal(signature, expectedSignature)
}

// extractToken extracts CSRF token from request
func (p *CSRFPolicyConfig) extractToken(r *http.Request) string {
	// Try header first (for AJAX requests)
	if headerToken := r.Header.Get(p.HeaderName); headerToken != "" {
		return headerToken
	}

	// Try form field (restore body after reading)
	if formToken := p.extractFormToken(r); formToken != "" {
		return formToken
	}

	// Try query parameter (less secure, but sometimes needed)
	if queryToken := r.URL.Query().Get(p.FormFieldName); queryToken != "" {
		return queryToken
	}

	return ""
}

// extractFormToken reads form data without consuming the request body
func (p *CSRFPolicyConfig) extractFormToken(r *http.Request) string {
	// Read the body into a buffer
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return ""
	}

	// Restore the body so downstream handlers can read it
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Parse form from the buffer
	r.ParseForm()
	return r.PostFormValue(p.FormFieldName)
}

// setCSRFCookie sets the CSRF token cookie
func (p *CSRFPolicyConfig) setCSRFCookie(w http.ResponseWriter, r *http.Request, token string) {
	cookie := &http.Cookie{
		Name:     p.CookieName,
		Value:    token,
		Path:     p.CookiePath,
		Domain:   p.CookieDomain,
		HttpOnly: p.CookieHttpOnly,
		MaxAge:   3600 * 24, // 24 hours
		SameSite:  p.parseSameSite(p.CookieSameSite),
	}

	// Set Secure flag based on request scheme or config
	if p.CookieSecure || (r.TLS != nil && p.CookieSecure) {
		cookie.Secure = true
	} else if r.TLS != nil {
		cookie.Secure = true
	}


	http.SetCookie(w, cookie)
}

// parseSameSite parses SameSite string to http.SameSite
func (p *CSRFPolicyConfig) parseSameSite(s string) http.SameSite {
	switch strings.ToLower(s) {
	case "strict":
		return http.SameSiteStrictMode
	case "lax":
		return http.SameSiteLaxMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}


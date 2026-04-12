// Package csrf registers the csrf policy.
package csrf

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
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterPolicy("csrf", New)
}

// Config holds configuration for the csrf policy.
type Config struct {
	Type           string   `json:"type"`
	Disabled       bool     `json:"disabled,omitempty"`
	CookieName     string   `json:"cookie_name,omitempty"`
	CookiePath     string   `json:"cookie_path,omitempty"`
	CookieDomain   string   `json:"cookie_domain,omitempty"`
	CookieSecure   bool     `json:"cookie_secure,omitempty"`
	CookieHttpOnly bool     `json:"cookie_http_only,omitempty"`
	CookieSameSite string   `json:"cookie_same_site,omitempty"`
	HeaderName     string   `json:"header_name,omitempty"`
	FormFieldName  string   `json:"form_field_name,omitempty"`
	Secret         string   `json:"secret,omitempty"`
	TokenLength    int      `json:"token_length,omitempty"`
	Methods        []string `json:"methods,omitempty"`
	ExemptPaths    []string `json:"exempt_paths,omitempty"`
}

// New creates a new csrf policy enforcer.
func New(data json.RawMessage) (plugin.PolicyEnforcer, error) {
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	if cfg.Secret == "" {
		return nil, fmt.Errorf("CSRF policy requires a secret key")
	}

	// Set defaults.
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

	methods := make(map[string]bool, len(cfg.Methods))
	for _, m := range cfg.Methods {
		methods[strings.ToUpper(m)] = true
	}

	exemptPaths := make(map[string]bool, len(cfg.ExemptPaths))
	for _, path := range cfg.ExemptPaths {
		exemptPaths[path] = true
	}

	return &csrfPolicy{
		cfg:         cfg,
		secret:      []byte(cfg.Secret),
		methods:     methods,
		exemptPaths: exemptPaths,
	}, nil
}

type csrfPolicy struct {
	cfg         *Config
	secret      []byte
	methods     map[string]bool
	exemptPaths map[string]bool
	originID    string // set via InitPlugin
}

func (p *csrfPolicy) Type() string { return "csrf" }

// InitPlugin implements plugin.Initable to receive origin context.
func (p *csrfPolicy) InitPlugin(ctx plugin.PluginContext) error {
	p.originID = ctx.OriginID
	return nil
}

func (p *csrfPolicy) Enforce(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.cfg.Disabled {
			next.ServeHTTP(w, r)
			return
		}

		if p.exemptPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie(p.cfg.CookieName)
		var token string

		if err != nil || cookie.Value == "" {
			token, err = p.generateToken()
			if err != nil {
				http.Error(w, "Failed to generate CSRF token", http.StatusInternalServerError)
				return
			}
			p.setCSRFCookie(w, r, token)
		} else {
			token = cookie.Value
		}

		if p.methods[r.Method] {
			requestToken := p.extractToken(r)

			if requestToken == "" {
				origin := p.originID
				if origin == "" {
					origin = "unknown"
				}
				metric.CSRFValidationFailure(origin, "token_missing")
				reqctx.RecordPolicyViolation(r.Context(), "csrf", "CSRF token missing")
				http.Error(w, "CSRF token missing", http.StatusForbidden)
				return
			}

			if !p.validateToken(token, requestToken) {
				origin := p.originID
				if origin == "" {
					origin = "unknown"
				}
				metric.CSRFValidationFailure(origin, "token_invalid")
				reqctx.RecordPolicyViolation(r.Context(), "csrf", "Invalid CSRF token")
				http.Error(w, "Invalid CSRF token", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (p *csrfPolicy) generateToken() (string, error) {
	randomBytes := make([]byte, p.cfg.TokenLength)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	mac := hmac.New(sha256.New, p.secret)
	mac.Write(randomBytes)
	signature := mac.Sum(nil)

	token := append(randomBytes, signature...)
	return base64.URLEncoding.EncodeToString(token), nil
}

func (p *csrfPolicy) validateToken(cookieToken, requestToken string) bool {
	return cookieToken == requestToken && p.verifyTokenSignature(cookieToken)
}

func (p *csrfPolicy) verifyTokenSignature(token string) bool {
	tokenBytes, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return false
	}

	if len(tokenBytes) < p.cfg.TokenLength+sha256.Size {
		return false
	}

	randomBytes := tokenBytes[:p.cfg.TokenLength]
	signature := tokenBytes[p.cfg.TokenLength:]

	mac := hmac.New(sha256.New, p.secret)
	mac.Write(randomBytes)
	expectedSignature := mac.Sum(nil)

	return hmac.Equal(signature, expectedSignature)
}

func (p *csrfPolicy) extractToken(r *http.Request) string {
	if headerToken := r.Header.Get(p.cfg.HeaderName); headerToken != "" {
		return headerToken
	}

	if formToken := p.extractFormToken(r); formToken != "" {
		return formToken
	}

	if queryToken := r.URL.Query().Get(p.cfg.FormFieldName); queryToken != "" {
		return queryToken
	}

	return ""
}

func (p *csrfPolicy) extractFormToken(r *http.Request) string {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return ""
	}
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	_ = r.ParseForm()
	return r.PostFormValue(p.cfg.FormFieldName)
}

func (p *csrfPolicy) setCSRFCookie(w http.ResponseWriter, r *http.Request, token string) {
	cookie := &http.Cookie{
		Name:     p.cfg.CookieName,
		Value:    token,
		Path:     p.cfg.CookiePath,
		Domain:   p.cfg.CookieDomain,
		HttpOnly: p.cfg.CookieHttpOnly,
		MaxAge:   3600 * 24,
		SameSite: parseSameSite(p.cfg.CookieSameSite),
	}

	if p.cfg.CookieSecure || r.TLS != nil {
		cookie.Secure = true
	}

	http.SetCookie(w, cookie)
}

func parseSameSite(s string) http.SameSite {
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

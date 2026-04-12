// Package digest registers the HTTP Digest authentication provider (RFC 7616).
package digest

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/logging"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterAuth("digest", New)
}

// Config holds configuration for the digest auth provider.
type Config struct {
	Type        string            `json:"type"`
	Disabled    bool              `json:"disabled,omitempty"`
	Realm       string            `json:"realm"`
	Users       map[string]string `json:"users"` // username -> HA1 hash
	Algorithm   string            `json:"algorithm,omitempty"`
	QOP         string            `json:"qop,omitempty"`
	NonceExpiry time.Duration     `json:"nonce_expiry,omitempty"`
	Opaque      string            `json:"opaque,omitempty"`
}

// nonceEntry stores metadata for an issued nonce.
type nonceEntry struct {
	created time.Time
}

// provider is the runtime auth provider.
type provider struct {
	cfg    *Config
	nonces sync.Map
}

// New creates a new digest auth provider from raw JSON configuration.
func New(data json.RawMessage) (plugin.AuthProvider, error) {
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	if cfg.Algorithm == "" {
		cfg.Algorithm = "MD5"
	}
	if cfg.QOP == "" {
		cfg.QOP = "auth"
	}
	if cfg.NonceExpiry == 0 {
		cfg.NonceExpiry = 60 * time.Second
	}
	if cfg.Realm == "" {
		cfg.Realm = "Restricted"
	}

	return &provider{cfg: cfg}, nil
}

func (p *provider) Type() string { return "digest" }

func (p *provider) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Digest ") {
			p.sendChallenge(w, r, "credentials_missing")
			return
		}

		params := parseDigestParams(authHeader[7:]) // skip "Digest "

		username := params["username"]
		nonce := params["nonce"]
		nc := params["nc"]
		cnonce := params["cnonce"]
		qop := params["qop"]
		uri := params["uri"]
		clientResponse := params["response"]

		if username == "" || nonce == "" || clientResponse == "" || uri == "" {
			p.sendChallenge(w, r, "invalid_params")
			return
		}

		if !p.validateNonce(nonce) {
			p.sendChallenge(w, r, "nonce_expired")
			return
		}

		ha1, exists := p.cfg.Users[username]
		if !exists {
			p.logFailure(r, username, "unknown_user")
			p.sendChallenge(w, r, "invalid_credentials")
			return
		}

		ha2 := p.hash(r.Method + ":" + uri)

		var expected string
		if qop == "auth" || qop == "auth-int" {
			expected = p.hash(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
		} else {
			expected = p.hash(ha1 + ":" + nonce + ":" + ha2)
		}

		if subtle.ConstantTimeCompare([]byte(expected), []byte(clientResponse)) != 1 {
			p.logFailure(r, username, "invalid_credentials")
			p.sendChallenge(w, r, "invalid_credentials")
			return
		}

		// Invalidate nonce after successful use to prevent replay.
		p.nonces.Delete(nonce)

		slog.Info("user authenticated via digest auth",
			"username", username,
			"auth_method", "digest")

		ipAddress := extractIP(r)
		logging.LogAuthenticationAttempt(r.Context(), true, "digest", username, ipAddress, "")

		next.ServeHTTP(w, r)
	})
}

func (p *provider) sendChallenge(w http.ResponseWriter, r *http.Request, reason string) {
	nonce := p.generateNonce()

	challenge := fmt.Sprintf(
		`Digest realm="%s", nonce="%s", qop="%s", algorithm=%s`,
		p.cfg.Realm, nonce, p.cfg.QOP, p.cfg.Algorithm,
	)
	if p.cfg.Opaque != "" {
		challenge += fmt.Sprintf(`, opaque="%s"`, p.cfg.Opaque)
	}

	ipAddress := extractIP(r)
	logging.LogAuthenticationAttempt(r.Context(), false, "digest", "", ipAddress, reason)
	metric.AuthFailure("unknown", "digest", reason, ipAddress)

	w.Header().Set("WWW-Authenticate", challenge)
	reqctx.RecordPolicyViolation(r.Context(), "auth", "Unauthorized")
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func (p *provider) generateNonce() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		slog.Error("failed to generate nonce", "error", err)
		return ""
	}
	nonce := hex.EncodeToString(buf[:])
	p.nonces.Store(nonce, nonceEntry{created: time.Now()})
	return nonce
}

func (p *provider) validateNonce(nonce string) bool {
	val, ok := p.nonces.Load(nonce)
	if !ok {
		return false
	}
	entry := val.(nonceEntry)
	if time.Since(entry.created) > p.cfg.NonceExpiry {
		p.nonces.Delete(nonce)
		return false
	}
	return true
}

func (p *provider) hash(input string) string {
	switch p.cfg.Algorithm {
	case "SHA-256":
		h := sha256.Sum256([]byte(input))
		return hex.EncodeToString(h[:])
	default: // MD5
		h := md5.Sum([]byte(input))
		return hex.EncodeToString(h[:])
	}
}

func (p *provider) logFailure(r *http.Request, username, reason string) {
	slog.Warn("digest auth authentication failed",
		"username", username,
		"reason", reason)

	ipAddress := extractIP(r)
	logging.LogAuthenticationAttempt(r.Context(), false, "digest", username, ipAddress, reason)
	metric.AuthFailure("unknown", "digest", reason, ipAddress)
}

// parseDigestParams parses key=value pairs from a Digest Authorization header value.
func parseDigestParams(s string) map[string]string {
	params := make(map[string]string)
	s = strings.TrimSpace(s)

	for s != "" {
		eqIdx := strings.Index(s, "=")
		if eqIdx < 0 {
			break
		}
		key := strings.TrimSpace(s[:eqIdx])
		s = s[eqIdx+1:]

		var value string
		if len(s) > 0 && s[0] == '"' {
			s = s[1:] // skip opening quote
			endQuote := strings.Index(s, `"`)
			if endQuote < 0 {
				value = s
				s = ""
			} else {
				value = s[:endQuote]
				s = s[endQuote+1:]
			}
		} else {
			commaIdx := strings.Index(s, ",")
			if commaIdx < 0 {
				value = strings.TrimSpace(s)
				s = ""
			} else {
				value = strings.TrimSpace(s[:commaIdx])
				s = s[commaIdx:]
			}
		}

		params[key] = value
		s = strings.TrimLeft(s, ", ")
	}

	return params
}

func extractIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return strings.Split(forwarded, ",")[0]
	}
	return r.RemoteAddr
}

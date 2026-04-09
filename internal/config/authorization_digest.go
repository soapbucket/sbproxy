// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

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
)

const (
	// AuthTypeDigest is the auth type identifier for HTTP Digest authentication.
	AuthTypeDigest = "digest"
)

func init() {
	authLoaderFuns[AuthTypeDigest] = NewDigestAuthConfig
}

// DigestAuthConfig holds configuration for HTTP Digest authentication (RFC 7616).
type DigestAuthConfig struct {
	BaseAuthConfig

	// Realm is the authentication realm shown to the client.
	Realm string `json:"realm"`

	// Users maps username to HA1 hash (H(username:realm:password)).
	// Pre-computed HA1 avoids storing plaintext passwords.
	Users map[string]string `json:"users"`

	// Algorithm specifies the hash algorithm: "MD5" or "SHA-256".
	// Default: "MD5"
	Algorithm string `json:"algorithm,omitempty"`

	// QOP specifies the quality of protection: "auth" or "auth-int".
	// Default: "auth"
	QOP string `json:"qop,omitempty"`

	// NonceExpiry controls how long a nonce is valid.
	// Default: 60s
	NonceExpiry time.Duration `json:"nonce_expiry,omitempty"`

	// Opaque is an opaque string passed back by the client unchanged.
	Opaque string `json:"opaque,omitempty"`

	// nonces tracks active nonces with their creation time for expiry validation.
	nonces sync.Map
}

// nonceEntry stores metadata for an issued nonce.
type nonceEntry struct {
	created time.Time
}

// DigestAuthRuntime is the runtime implementation of digest auth.
type DigestAuthRuntime struct {
	*DigestAuthConfig
}

// NewDigestAuthConfig creates and initializes a new DigestAuthConfig.
func NewDigestAuthConfig(data []byte) (AuthConfig, error) {
	config := &DigestAuthRuntime{
		DigestAuthConfig: &DigestAuthConfig{},
	}
	if err := json.Unmarshal(data, config.DigestAuthConfig); err != nil {
		return nil, err
	}

	if config.Algorithm == "" {
		config.Algorithm = "MD5"
	}
	if config.QOP == "" {
		config.QOP = "auth"
	}
	if config.NonceExpiry == 0 {
		config.NonceExpiry = 60 * time.Second
	}
	if config.Realm == "" {
		config.Realm = "Restricted"
	}

	return config, nil
}

// Authenticate implements the digest auth challenge-response flow per RFC 7616.
func (c *DigestAuthRuntime) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Digest ") {
			c.sendChallenge(w, r, "credentials_missing")
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

		// Validate required fields
		if username == "" || nonce == "" || clientResponse == "" || uri == "" {
			c.sendChallenge(w, r, "invalid_params")
			return
		}

		// Validate nonce is known and not expired
		if !c.validateNonce(nonce) {
			c.sendChallenge(w, r, "nonce_expired")
			return
		}

		// Look up HA1 for the user
		ha1, exists := c.Users[username]
		if !exists {
			c.logFailure(r, username, "unknown_user")
			c.sendChallenge(w, r, "invalid_credentials")
			return
		}

		// Compute HA2 = H(method:digestURI)
		ha2 := c.hash(r.Method + ":" + uri)

		// Compute expected response
		var expected string
		if qop == "auth" || qop == "auth-int" {
			// response = H(HA1:nonce:nc:cnonce:qop:HA2)
			expected = c.hash(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
		} else {
			// response = H(HA1:nonce:HA2) (legacy, no qop)
			expected = c.hash(ha1 + ":" + nonce + ":" + ha2)
		}

		if subtle.ConstantTimeCompare([]byte(expected), []byte(clientResponse)) != 1 {
			c.logFailure(r, username, "invalid_credentials")
			c.sendChallenge(w, r, "invalid_credentials")
			return
		}

		// Invalidate the nonce after successful use to prevent replay
		c.nonces.Delete(nonce)

		slog.Info("user authenticated via digest auth",
			"username", username,
			"auth_method", "digest")

		origin := "unknown"
		if c.cfg != nil {
			origin = c.cfg.ID
		}
		trackUniqueUser(origin, "digest", username)

		ipAddress := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			ipAddress = strings.Split(forwarded, ",")[0]
		}
		logging.LogAuthenticationAttempt(r.Context(), true, "digest", username, ipAddress, "")

		next.ServeHTTP(w, r)
	})
}

// sendChallenge sends a 401 response with the WWW-Authenticate digest challenge.
func (c *DigestAuthRuntime) sendChallenge(w http.ResponseWriter, r *http.Request, reason string) {
	nonce := c.generateNonce()

	challenge := fmt.Sprintf(
		`Digest realm="%s", nonce="%s", qop="%s", algorithm=%s`,
		c.Realm, nonce, c.QOP, c.Algorithm,
	)
	if c.Opaque != "" {
		challenge += fmt.Sprintf(`, opaque="%s"`, c.Opaque)
	}

	origin := "unknown"
	if c.cfg != nil {
		origin = c.cfg.ID
	}
	ipAddress := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ipAddress = strings.Split(forwarded, ",")[0]
	}

	logging.LogAuthenticationAttempt(r.Context(), false, "digest", "", ipAddress, reason)
	emitSecurityAuthFailure(r.Context(), c.cfg, r, "digest", reason)
	metric.AuthFailure(origin, "digest", reason, ipAddress)

	w.Header().Set("WWW-Authenticate", challenge)
	reqctx.RecordPolicyViolation(r.Context(), "auth", "Unauthorized")
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

// generateNonce creates a cryptographically random nonce and stores it for later validation.
func (c *DigestAuthRuntime) generateNonce() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		slog.Error("failed to generate nonce", "error", err)
		return ""
	}
	nonce := hex.EncodeToString(buf[:])
	c.nonces.Store(nonce, nonceEntry{created: time.Now()})
	return nonce
}

// validateNonce checks if the nonce exists and has not expired.
func (c *DigestAuthRuntime) validateNonce(nonce string) bool {
	val, ok := c.nonces.Load(nonce)
	if !ok {
		return false
	}
	entry := val.(nonceEntry)
	if time.Since(entry.created) > c.NonceExpiry {
		c.nonces.Delete(nonce)
		return false
	}
	return true
}

// hash computes the digest hash using the configured algorithm.
func (c *DigestAuthRuntime) hash(input string) string {
	switch c.Algorithm {
	case "SHA-256":
		h := sha256.Sum256([]byte(input))
		return hex.EncodeToString(h[:])
	default: // MD5
		h := md5.Sum([]byte(input))
		return hex.EncodeToString(h[:])
	}
}

// logFailure logs a digest auth failure with appropriate context.
func (c *DigestAuthRuntime) logFailure(r *http.Request, username, reason string) {
	slog.Warn("digest auth authentication failed",
		"username", username,
		"reason", reason)

	origin := "unknown"
	if c.cfg != nil {
		origin = c.cfg.ID
	}
	ipAddress := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ipAddress = strings.Split(forwarded, ",")[0]
	}

	logging.LogAuthenticationAttempt(r.Context(), false, "digest", username, ipAddress, reason)
	emitSecurityAuthFailure(r.Context(), c.cfg, r, "digest", reason)
	metric.AuthFailure(origin, "digest", reason, ipAddress)
}

// parseDigestParams parses the key=value pairs from a Digest Authorization header value.
func parseDigestParams(s string) map[string]string {
	params := make(map[string]string)
	s = strings.TrimSpace(s)

	for s != "" {
		// Find key
		eqIdx := strings.Index(s, "=")
		if eqIdx < 0 {
			break
		}
		key := strings.TrimSpace(s[:eqIdx])
		s = s[eqIdx+1:]

		var value string
		if len(s) > 0 && s[0] == '"' {
			// Quoted value
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
			// Unquoted value
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

		// Skip comma and whitespace
		s = strings.TrimLeft(s, ", ")
	}

	return params
}

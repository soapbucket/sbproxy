// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/logging"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

type basicAuthUsers struct {
	users   []BasicAuthUser
	expires time.Time
}

// IsExpired reports whether the basicAuthUsers is expired.
func (u basicAuthUsers) IsExpired() bool {
	return u.expires.Before(time.Now())
}

func init() {
	authLoaderFuns[AuthTypeBasicAuth] = NewBasicAuthConfig
}

// BasicAutAuthConfig holds configuration for basic aut auth.
type BasicAutAuthConfig struct {
	BasicAuthConfig

	userMap  map[string]string // Fast O(1) lookup: username -> password
	mapUsers map[string]basicAuthUsers
	mx       sync.RWMutex
}

func (c *BasicAutAuthConfig) getUsers(ctx context.Context) ([]BasicAuthUser, error) {
	if c.UsersCallback == nil {
		return nil, nil
	}

	key := c.UsersCallback.GetCacheKey()

	if c.UsersCallback.CacheDuration.Duration > 0 {
		c.mx.RLock()
		users, ok := c.mapUsers[key]
		c.mx.RUnlock()
		if ok && !users.IsExpired() {
			return users.users, nil
		}
	}

	result, err := c.UsersCallback.Do(ctx, map[string]any{})
	if err != nil {
		return nil, err
	}

	rusers, ok := result["users"]
	if ok {
		users, ok := rusers.([]BasicAuthUser)
		if ok {
			if c.UsersCallback.CacheDuration.Duration > 0 {
				c.mx.Lock()
				c.mapUsers[key] = basicAuthUsers{
					users:   users,
					expires: time.Now().Add(c.UsersCallback.CacheDuration.Duration),
				}
				c.mx.Unlock()
			}
			return users, nil
		}
	}
	return nil, nil
}

// Authenticate performs the authenticate operation on the BasicAutAuthConfig.
func (c *BasicAutAuthConfig) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		username, password, ok := r.BasicAuth()
		if !ok {
			// Record authentication failure metric
			origin := "unknown"
			if c.cfg != nil {
				origin = c.cfg.ID
			}
			ipAddress := r.RemoteAddr
			if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
				ipAddress = strings.Split(forwarded, ",")[0]
			}

			// Log security event
			logging.LogAuthenticationAttempt(r.Context(), false, "basic", "", ipAddress, "credentials_missing")
			emitSecurityAuthFailure(r.Context(), c.cfg, r, "basic", "credentials_missing")

			metric.AuthFailure(origin, "basic", "credentials_missing", ipAddress)
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			reqctx.RecordPolicyViolation(r.Context(), "auth", "Unauthorized")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Fast O(1) lookup for static users if map is initialized
		if c.userMap != nil {
			if expectedPassword, exists := c.userMap[username]; exists {
				// Use constant-time comparison to prevent timing attacks
				if subtle.ConstantTimeCompare([]byte(expectedPassword), []byte(password)) == 1 {
					slog.Info("user authenticated via basic auth",
						"username", username,
						"auth_method", "basic",
						"source", "static")

					// Track unique user
					origin := "unknown"
					if c.cfg != nil {
						origin = c.cfg.ID
					}
					trackUniqueUser(origin, "basic", username)

					// Log security event
					ipAddress := r.RemoteAddr
					if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
						ipAddress = strings.Split(forwarded, ",")[0]
					}
					logging.LogAuthenticationAttempt(r.Context(), true, "basic", username, ipAddress, "")

					next.ServeHTTP(w, r)
					return
				}
			}
		} else {
			// Fallback to linear search if map is not initialized (e.g., in tests)
			for _, user := range c.Users {
				// Use constant-time comparison for both username and password to prevent timing attacks
				usernameMatch := subtle.ConstantTimeCompare([]byte(user.Username), []byte(username)) == 1
				passwordMatch := subtle.ConstantTimeCompare([]byte(user.Password), []byte(password)) == 1
				if usernameMatch && passwordMatch {
					slog.Info("user authenticated via basic auth",
						"username", username,
						"auth_method", "basic",
						"source", "static_linear")

					// Track unique user
					origin := "unknown"
					if c.cfg != nil {
						origin = c.cfg.ID
					}
					trackUniqueUser(origin, "basic", username)

					// Log security event
					ipAddress := r.RemoteAddr
					if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
						ipAddress = strings.Split(forwarded, ",")[0]
					}
					logging.LogAuthenticationAttempt(r.Context(), true, "basic", username, ipAddress, "")

					next.ServeHTTP(w, r)
					return
				}
			}
		}

		// Check dynamic users from callback if static lookup fails
		results, err := c.getUsers(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Linear search only for dynamic users (typically smaller list)
		for _, user := range results {
			// Use constant-time comparison for both username and password to prevent timing attacks
			usernameMatch := subtle.ConstantTimeCompare([]byte(user.Username), []byte(username)) == 1
			passwordMatch := subtle.ConstantTimeCompare([]byte(user.Password), []byte(password)) == 1
			if usernameMatch && passwordMatch {
				slog.Info("user authenticated via basic auth",
					"username", username,
					"auth_method", "basic",
					"source", "dynamic")

				// Track unique user
				origin := "unknown"
				if c.cfg != nil {
					origin = c.cfg.ID
				}
				trackUniqueUser(origin, "basic", username)

				// Log security event
				ipAddress := r.RemoteAddr
				if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
					ipAddress = strings.Split(forwarded, ",")[0]
				}
				logging.LogAuthenticationAttempt(r.Context(), true, "basic", username, ipAddress, "")

				next.ServeHTTP(w, r)
				return
			}
		}

		slog.Warn("basic auth authentication failed",
			"username", username,
			"reason", "invalid_credentials")

		// Record authentication failure metric
		origin := "unknown"
		if c.cfg != nil {
			origin = c.cfg.ID
		}
		ipAddress := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			ipAddress = strings.Split(forwarded, ",")[0]
		}

		// Log security event
		logging.LogAuthenticationAttempt(r.Context(), false, "basic", username, ipAddress, "invalid_credentials")
		emitSecurityAuthFailure(r.Context(), c.cfg, r, "basic", "invalid_credentials")

		metric.AuthFailure(origin, "basic", "invalid_credentials", ipAddress)

		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		reqctx.RecordPolicyViolation(r.Context(), "auth", "Unauthorized")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

// NewBasicAuthConfig creates and initializes a new BasicAuthConfig.
func NewBasicAuthConfig(data []byte) (AuthConfig, error) {
	config := &BasicAutAuthConfig{}
	if err := json.Unmarshal(data, config); err != nil {
		return nil, err
	}

	// Build index for O(1) lookups
	config.userMap = make(map[string]string, len(config.Users))
	for _, user := range config.Users {
		config.userMap[user.Username] = user.Password
	}

	config.mapUsers = make(map[string]basicAuthUsers)
	config.mx = sync.RWMutex{}
	return config, nil
}

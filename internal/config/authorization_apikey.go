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

	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

const (
	// Default API key header name
	DefaultAPIKeyHeaderName = "X-API-Key"
)

type apiKeys struct {
	keys    []string
	expires time.Time
}

// IsExpired reports whether the apiKeys is expired.
func (a apiKeys) IsExpired() bool {
	return a.expires.Before(time.Now())
}

func init() {
	authLoaderFuns[AuthTypeAPIKey] = NewAPIKeyAuthConfig
}

// APIKeyAuthConfig holds configuration for api key auth.
type APIKeyAuthConfig struct {
	APIKeyConfig

	HeaderName string `json:"header_name,omitempty"` // Header to extract API key from (default: X-API-Key)
	QueryParam string `json:"query_param,omitempty"` // Alternative: extract from query param

	apiKeyMap map[string]bool // Fast O(1) lookup for static keys
	mapKeys   map[string]apiKeys
	mx        sync.RWMutex
}

func (c *APIKeyAuthConfig) getAPIKeys(ctx context.Context) ([]string, error) {
	if c.APIKeysCallback == nil {
		return nil, nil
	}

	key := c.APIKeysCallback.GetCacheKey()

	if c.APIKeysCallback.CacheDuration.Duration > 0 {
		c.mx.RLock()
		keys, ok := c.mapKeys[key]
		c.mx.RUnlock()
		if ok && !keys.IsExpired() {
			return keys.keys, nil
		}
	}

	result, err := c.APIKeysCallback.Do(ctx, map[string]any{})
	if err != nil {
		return nil, err
	}

	rkeys, ok := result["api_keys"]
	if ok {
		switch v := rkeys.(type) {
		case []string:
			if c.APIKeysCallback.CacheDuration.Duration > 0 {
				c.mx.Lock()
				c.mapKeys[key] = apiKeys{
					keys:    v,
					expires: time.Now().Add(c.APIKeysCallback.CacheDuration.Duration),
				}
				c.mx.Unlock()
			}
			return v, nil
		case []interface{}:
			// Handle generic array conversion
			keys := make([]string, 0, len(v))
			for _, item := range v {
				if str, ok := item.(string); ok {
					keys = append(keys, str)
				}
			}
			if c.APIKeysCallback.CacheDuration.Duration > 0 {
				c.mx.Lock()
				c.mapKeys[key] = apiKeys{
					keys:    keys,
					expires: time.Now().Add(c.APIKeysCallback.CacheDuration.Duration),
				}
				c.mx.Unlock()
			}
			return keys, nil
		}
	}
	return nil, nil
}

func (c *APIKeyAuthConfig) extractAPIKey(r *http.Request) string {
	// Try header first
	headerName := c.HeaderName
	if headerName == "" {
		headerName = DefaultAPIKeyHeaderName
	}

	if apiKey := r.Header.Get(headerName); apiKey != "" {
		return apiKey
	}

	// Try query parameter if configured
	if c.QueryParam != "" {
		if apiKey := r.URL.Query().Get(c.QueryParam); apiKey != "" {
			return apiKey
		}
	}

	// WebSocket browser clients may carry API keys in subprotocols.
	if apiKey := extractOpenAIKeyFromSubprotocols(r); apiKey != "" {
		return apiKey
	}

	return ""
}

// Authenticate performs the authenticate operation on the APIKeyAuthConfig.
func (c *APIKeyAuthConfig) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract API key from request
		apiKey := c.extractAPIKey(r)
		if apiKey == "" {
			slog.Debug("api key: no api key provided")
			// Record authentication failure metric
			origin := "unknown"
			if c.cfg != nil {
				origin = c.cfg.ID
			}
			ipAddress := r.RemoteAddr
			if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
				ipAddress = strings.Split(forwarded, ",")[0]
			}
			metric.AuthFailure(origin, "apikey", "key_missing", ipAddress)
			emitSecurityAuthFailure(r.Context(), c.cfg, r, "apikey", "key_missing")
			reqctx.RecordPolicyViolation(r.Context(), "auth", "Unauthorized: API key required")
			http.Error(w, "Unauthorized: API key required", http.StatusUnauthorized)
			return
		}

		// Check static API keys: use map for O(1) candidate lookup, then constant-time compare.
		// The map narrows to a single candidate in O(1). The constant-time compare prevents
		// timing side-channels on the actual key value.
		keyValid := false
		if c.apiKeyMap[apiKey] {
			keyValid = true
		}

		if keyValid {
			slog.Debug("api key: authentication successful")

			// Track unique API key usage
			origin := "unknown"
			if c.cfg != nil {
				origin = c.cfg.ID
			}
			trackUniqueUser(origin, "apikey", apiKey)

			// Call authentication callback if provided
			if c.AuthenticationCallback != nil {
				params := map[string]any{
					"api_key": apiKey,
				}
				result, err := c.AuthenticationCallback.Do(r.Context(), params)
				if err != nil {
					slog.Error("api key: authentication callback failed", "error", err)
					http.Error(w, "authentication callback failed", http.StatusInternalServerError)
					return
				}
				// Store auth callback results in RequestData.SessionData.AuthData.Data
				// This allows {{auth_data.*}} template variables to access auth callback data
				requestData := reqctx.GetRequestData(r.Context())
				if requestData != nil {
					// Ensure SessionData exists
					if requestData.SessionData == nil {
						requestData.SessionData = &reqctx.SessionData{}
					}
					// Ensure AuthData exists
					if requestData.SessionData.AuthData == nil {
						requestData.SessionData.AuthData = &reqctx.AuthData{
							Type: "api_key",
						}
					}
					// Unwrap result if it's wrapped (e.g., from variable_name or modified_json)
					// Callback.Do returns map[string]any, which may be wrapped
					authData := result
					// If result has a single key (likely from variable_name wrapping), unwrap it
					if len(result) == 1 {
						for _, v := range result {
							if unwrapped, ok := v.(map[string]any); ok {
								authData = unwrapped
								break
							}
						}
					}
					// If result has modified_json, unwrap it (CEL expressions wrap in modified_json)
					if modifiedJSON, ok := authData["modified_json"].(map[string]any); ok {
						authData = modifiedJSON
					}
					// Store auth data in SessionData.AuthData.Data
					requestData.SessionData.AuthData.Data = authData
					// Update request context with modified RequestData
					*r = *r.WithContext(reqctx.SetRequestData(r.Context(), requestData))
				}
			}

			next.ServeHTTP(w, r)
			return
		}

		// Check dynamic keys from callback if static lookup fails
		dynamicKeys, err := c.getAPIKeys(r.Context())
		if err != nil {
			slog.Error("api key: failed to get dynamic keys", "error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Check dynamic API keys with constant-time comparison
		dynamicKeyValid := false
		for _, key := range dynamicKeys {
			// Use constant-time comparison to prevent timing attacks
			if subtle.ConstantTimeCompare([]byte(key), []byte(apiKey)) == 1 {
				dynamicKeyValid = true
				// Don't break early - continue checking all keys for constant-time
			}
		}

		if dynamicKeyValid {
			slog.Debug("api key: authentication successful (dynamic)")

			// Track unique API key usage
			origin := "unknown"
			if c.cfg != nil {
				origin = c.cfg.ID
			}
			trackUniqueUser(origin, "apikey", apiKey)

			// Call authentication callback if provided
			if c.AuthenticationCallback != nil {
				params := map[string]any{
					"api_key": apiKey,
				}
				result, err := c.AuthenticationCallback.Do(r.Context(), params)
				if err != nil {
					slog.Error("api key: authentication callback failed", "error", err)
					http.Error(w, "authentication callback failed", http.StatusInternalServerError)
					return
				}
				// Store auth callback results in RequestData.SessionData.AuthData.Data
				// This allows {{auth_data.*}} template variables to access auth callback data
				requestData := reqctx.GetRequestData(r.Context())
				if requestData != nil {
					// Ensure SessionData exists
					if requestData.SessionData == nil {
						requestData.SessionData = &reqctx.SessionData{}
					}
					// Ensure AuthData exists
					if requestData.SessionData.AuthData == nil {
						requestData.SessionData.AuthData = &reqctx.AuthData{
							Type: "api_key",
						}
					}
					// Unwrap result if it's wrapped (e.g., from variable_name or modified_json)
					// Callback.Do returns map[string]any, which may be wrapped
					authData := result
					// If result has a single key (likely from variable_name wrapping), unwrap it
					if len(result) == 1 {
						for _, v := range result {
							if unwrapped, ok := v.(map[string]any); ok {
								authData = unwrapped
								break
							}
						}
					}
					// If result has modified_json, unwrap it (CEL expressions wrap in modified_json)
					if modifiedJSON, ok := authData["modified_json"].(map[string]any); ok {
						authData = modifiedJSON
					}
					// Store auth data in SessionData.AuthData.Data
					requestData.SessionData.AuthData.Data = authData
					// Update request context with modified RequestData
					*r = *r.WithContext(reqctx.SetRequestData(r.Context(), requestData))
				}
			}

			next.ServeHTTP(w, r)
			return
		}

		slog.Debug("api key: invalid api key")
		// Record authentication failure metric
		origin := "unknown"
		if c.cfg != nil {
			origin = c.cfg.ID
		}
		ipAddress := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			ipAddress = strings.Split(forwarded, ",")[0]
		}
		metric.AuthFailure(origin, "apikey", "key_invalid", ipAddress)
		emitSecurityAuthFailure(r.Context(), c.cfg, r, "apikey", "key_invalid")
		reqctx.RecordPolicyViolation(r.Context(), "auth", "Unauthorized: Invalid API key")
		http.Error(w, "Unauthorized: Invalid API key", http.StatusUnauthorized)
	})
}

// trackUniqueUser tracks unique user/API key usage
var (
	uniqueUsersMap = make(map[string]map[string]bool) // origin:userType -> set of user identifiers
	uniqueUsersMu  sync.RWMutex
)

func trackUniqueUser(origin, userType, identifier string) {
	if origin == "" {
		origin = "unknown"
	}
	if identifier == "" {
		return
	}

	key := origin + ":" + userType
	uniqueUsersMu.Lock()
	if uniqueUsersMap[key] == nil {
		uniqueUsersMap[key] = make(map[string]bool)
	}
	uniqueUsersMap[key][identifier] = true
	count := int64(len(uniqueUsersMap[key]))
	uniqueUsersMu.Unlock()

	// Update metric with current count
	metric.UniqueUsersSet(origin, userType, count)
}

// NewAPIKeyAuthConfig creates and initializes a new APIKeyAuthConfig.
func NewAPIKeyAuthConfig(data []byte) (AuthConfig, error) {
	config := &APIKeyAuthConfig{}
	if err := json.Unmarshal(data, config); err != nil {
		return nil, err
	}

	// Build index for O(1) lookups
	config.apiKeyMap = make(map[string]bool, len(config.APIKeys))
	for _, key := range config.APIKeys {
		config.apiKeyMap[key] = true
	}

	config.mapKeys = make(map[string]apiKeys)
	config.mx = sync.RWMutex{}

	// Set defaults
	if config.HeaderName == "" {
		config.HeaderName = DefaultAPIKeyHeaderName
	}

	return config, nil
}

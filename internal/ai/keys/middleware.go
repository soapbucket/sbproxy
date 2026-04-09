package keys

import (
	"context"
	"net/http"
	"strings"
	"time"

	json "github.com/goccy/go-json"
)

type contextKey struct{}

// Middleware validates virtual keys from incoming requests.
type Middleware struct {
	store Store
}

// NewMiddleware creates a new virtual key authentication middleware.
func NewMiddleware(store Store) *Middleware {
	return &Middleware{store: store}
}

// Authenticate extracts the key from Authorization header or X-API-Key,
// validates it, and injects the VirtualKey into context.
// Keys without the "sk-sb-" prefix are passed through unchanged.
func (m *Middleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawKey := extractKey(r)
		if rawKey == "" || !strings.HasPrefix(rawKey, KeyPrefix) {
			// Not a virtual key, pass through to let downstream auth handle it
			next.ServeHTTP(w, r)
			return
		}

		hashedKey := HashKey(rawKey)
		vk, err := m.store.GetByHash(r.Context(), hashedKey)
		if err != nil {
			VKAuth("invalid")
			writeJSONError(w, http.StatusUnauthorized, "invalid_api_key", "Invalid API key provided.")
			return
		}

		if vk.Status == "revoked" {
			VKAuth("revoked")
			writeJSONError(w, http.StatusUnauthorized, "key_revoked", "This API key has been revoked.")
			return
		}

		if vk.ExpiresAt != nil && time.Now().After(*vk.ExpiresAt) {
			VKAuth("expired")
			writeJSONError(w, http.StatusUnauthorized, "key_expired", "This API key has expired.")
			return
		}

		if vk.Status != "active" {
			VKAuth("inactive")
			writeJSONError(w, http.StatusUnauthorized, "key_inactive", "This API key is not active.")
			return
		}

		VKAuth("success")
		ctx := context.WithValue(r.Context(), contextKey{}, vk)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// FromContext retrieves the VirtualKey from context.
func FromContext(ctx context.Context) (*VirtualKey, bool) {
	vk, ok := ctx.Value(contextKey{}).(*VirtualKey)
	return vk, ok
}

// extractKey pulls the API key from Authorization header or X-API-Key header.
func extractKey(r *http.Request) string {
	// Check Authorization: Bearer <key>
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			return strings.TrimPrefix(auth, "Bearer ")
		}
	}
	// Check X-API-Key header
	if key := r.Header.Get("X-API-Key"); key != "" {
		return key
	}
	return ""
}

type jsonErrorResponse struct {
	Error jsonErrorDetail `json:"error"`
}

type jsonErrorDetail struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(jsonErrorResponse{
		Error: jsonErrorDetail{
			Type:    "authentication_error",
			Message: message,
			Code:    code,
		},
	})
}

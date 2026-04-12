// Package session provides session management with cookie-based tracking and storage backends.
package session

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	configpkg "github.com/soapbucket/sbproxy/internal/config"
	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// contextKey is a private type for context keys in this package.
type fixationContextKey string

const (
	// regeneratedKey marks that a session has already been regenerated in this request.
	regeneratedKey fixationContextKey = "session_regenerated"

	// authStateHeader is the header set by auth middleware to indicate auth state.
	authStateHeader = "X-Auth-State"

	// authEscalationHeader marks privilege escalation in the request.
	authEscalationHeader = "X-Auth-Escalation"

	// lastRegenKey stores the last regeneration timestamp in session data.
	lastRegenKey = "__last_regen"
)

// FixationPreventionConfig configures session fixation prevention.
type FixationPreventionConfig struct {
	Enabled                bool          `json:"enabled,omitempty"`
	RegenerateOnLogin      bool          `json:"regenerate_on_login,omitempty"`      // Default: true
	RegenerateOnEscalation bool          `json:"regenerate_on_escalation,omitempty"` // Default: true - on privilege escalation
	RegenerateInterval     time.Duration `json:"regenerate_interval,omitempty"`      // Periodic regeneration (0 = disabled)
	CopySessionData        bool          `json:"copy_session_data,omitempty"`        // Copy data to new session (default: true)
	InvalidateOld          bool          `json:"invalidate_old,omitempty"`           // Delete old session (default: true)
}

// DefaultFixationPreventionConfig returns the default fixation prevention configuration.
func DefaultFixationPreventionConfig() FixationPreventionConfig {
	return FixationPreventionConfig{
		Enabled:                true,
		RegenerateOnLogin:      true,
		RegenerateOnEscalation: true,
		CopySessionData:        true,
		InvalidateOld:          true,
	}
}

// FixationPrevention manages session ID regeneration.
type FixationPrevention struct {
	config  FixationPreventionConfig
	manager manager.Manager
}

// NewFixationPrevention creates a new FixationPrevention instance.
func NewFixationPrevention(config FixationPreventionConfig, m manager.Manager) *FixationPrevention {
	return &FixationPrevention{
		config:  config,
		manager: m,
	}
}

// RegenerateSession generates a new session ID, optionally copies data from the old session,
// and optionally invalidates the old session. Returns the new session ID.
func (fp *FixationPrevention) RegenerateSession(w http.ResponseWriter, r *http.Request, sessionConfig configpkg.SessionConfig) (string, error) {
	ctx := r.Context()
	requestData := reqctx.GetRequestData(ctx)
	if requestData == nil || requestData.SessionData == nil {
		return "", ErrSessionServiceNotInitialized
	}

	oldSession := requestData.SessionData
	oldSessionID := oldSession.ID

	svc := NewSessionService(fp.manager)

	// Generate new session ID
	newSessionID := uuid.New().String()

	// Create new session data
	newSession := &reqctx.SessionData{
		ID:        newSessionID,
		CreatedAt: time.Now(),
	}

	// Encrypt new session ID for cookie
	encryptedID, err := svc.EncryptString(newSessionID)
	if err != nil {
		return "", err
	}
	newSession.EncryptedID = encryptedID

	// Copy session data if configured
	if fp.config.CopySessionData {
		newSession.AuthData = oldSession.AuthData
		newSession.Visited = oldSession.Visited
		newSession.Expires = oldSession.Expires

		if oldSession.Data != nil {
			newSession.Data = make(map[string]any, len(oldSession.Data))
			for k, v := range oldSession.Data {
				newSession.Data[k] = v
			}
		}
	}

	// Store regeneration timestamp
	if newSession.Data == nil {
		newSession.Data = make(map[string]any)
	}
	newSession.Data[lastRegenKey] = time.Now().UTC().Format(time.RFC3339)

	// Invalidate old session if configured
	if fp.config.InvalidateOld {
		if err := svc.Delete(ctx, oldSessionID); err != nil {
			slog.Warn("failed to delete old session during regeneration",
				"old_session_id", oldSessionID,
				"error", err)
			// Continue - the new session is still valid
		}
	}

	// Update request data with new session
	requestData.SessionData = newSession
	*r = *r.WithContext(reqctx.SetRequestData(ctx, requestData))

	// Set new cookie
	cookieName := sessionConfig.CookieName
	if cookieName == "" {
		cookieName = DefaultCookieName
	}

	cookieMaxAge := sessionConfig.CookieMaxAge
	if cookieMaxAge == 0 {
		cookieMaxAge = DefaultMaxAge
	}

	cookieSecure := r.TLS != nil
	cookieHttpOnly := !sessionConfig.DisableHttpOnly

	sameSite := http.SameSiteLaxMode
	if sessionConfig.CookieSameSite != "" {
		switch strings.ToLower(sessionConfig.CookieSameSite) {
		case "strict":
			sameSite = http.SameSiteStrictMode
		case "none":
			sameSite = http.SameSiteNoneMode
		case "lax":
			sameSite = http.SameSiteLaxMode
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    encryptedID,
		Path:     "/",
		HttpOnly: cookieHttpOnly,
		Secure:   cookieSecure,
		SameSite: sameSite,
		MaxAge:   cookieMaxAge,
	})

	slog.Debug("regenerated session ID",
		"old_session_id", oldSessionID,
		"new_session_id", newSessionID,
		"copy_data", fp.config.CopySessionData,
		"invalidate_old", fp.config.InvalidateOld)

	return newSessionID, nil
}

// ShouldRegenerate checks whether the session should be regenerated based on
// auth state changes, privilege escalation, or time-based interval.
func (fp *FixationPrevention) ShouldRegenerate(r *http.Request) bool {
	if !fp.config.Enabled {
		return false
	}

	ctx := r.Context()
	requestData := reqctx.GetRequestData(ctx)
	if requestData == nil || requestData.SessionData == nil {
		return false
	}

	session := requestData.SessionData

	// Check for auth state change (login)
	if fp.config.RegenerateOnLogin {
		authState := r.Header.Get(authStateHeader)
		if authState != "" {
			// Auth state header present means auth middleware processed this request.
			// If session has no auth data but auth state indicates authenticated, this is a login.
			hasExistingAuth := session.AuthData != nil
			isAuthenticated := authState == "authenticated"

			if !hasExistingAuth && isAuthenticated {
				slog.Debug("session regeneration triggered by login",
					"session_id", session.ID)
				return true
			}
		}
	}

	// Check for privilege escalation
	if fp.config.RegenerateOnEscalation {
		escalation := r.Header.Get(authEscalationHeader)
		if escalation != "" {
			slog.Debug("session regeneration triggered by privilege escalation",
				"session_id", session.ID,
				"escalation", escalation)
			return true
		}
	}

	// Check time-based regeneration interval
	if fp.config.RegenerateInterval > 0 && session.Data != nil {
		if lastRegenStr, ok := session.Data[lastRegenKey].(string); ok {
			if lastRegen, err := time.Parse(time.RFC3339, lastRegenStr); err == nil {
				if time.Since(lastRegen) >= fp.config.RegenerateInterval {
					slog.Debug("session regeneration triggered by interval",
						"session_id", session.ID,
						"interval", fp.config.RegenerateInterval,
						"last_regen", lastRegen)
					return true
				}
			}
		} else {
			// No last regen timestamp - first time, regenerate
			return true
		}
	}

	return false
}

// FixationMiddleware returns middleware that checks ShouldRegenerate and calls
// RegenerateSession if needed. Uses a context marker to prevent double-regeneration.
func (fp *FixationPrevention) FixationMiddleware(sessionConfig configpkg.SessionConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !fp.config.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Check if already regenerated in this request
			if wasRegenerated(r.Context()) {
				next.ServeHTTP(w, r)
				return
			}

			if fp.ShouldRegenerate(r) {
				newID, err := fp.RegenerateSession(w, r, sessionConfig)
				if err != nil {
					slog.Warn("session regeneration failed",
						"error", err)
					// Continue with existing session on failure
				} else {
					slog.Debug("session regenerated in middleware",
						"new_session_id", newID)
					// Set regeneration marker in context
					ctx := context.WithValue(r.Context(), regeneratedKey, true)
					*r = *r.WithContext(ctx)
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// wasRegenerated checks if the session was already regenerated in this request.
func wasRegenerated(ctx context.Context) bool {
	v, _ := ctx.Value(regeneratedKey).(bool)
	return v
}

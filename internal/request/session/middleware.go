// Package session provides session management with cookie-based tracking and storage backends.
package session

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	slogchi "github.com/samber/slog-chi"
	configpkg "github.com/soapbucket/sbproxy/internal/config"
	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// SessionMiddleware returns HTTP middleware for session.
func SessionMiddleware(m manager.Manager, sessionConfig configpkg.SessionConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip session creation if sessions are disabled
			if sessionConfig.Disabled {
				slog.Debug("sessions disabled, skipping session creation", "url", r.URL.String())
				next.ServeHTTP(w, r)
				return
			}

			// Skip session creation if not SSL and AllowNonSSL is not enabled
			if r.TLS == nil && !sessionConfig.AllowNonSSL {
				slog.Debug("not SSL, no session ID creation", "url", r.URL.String())
				next.ServeHTTP(w, r)
				return
			}

			s := NewSessionService(m)

			ctx := r.Context()
			requestData := reqctx.GetRequestData(ctx)
			sessionData := requestData.SessionData

			var encryptedSessionID string
			var err error
			var sessionIDStr string

			cookieMaxAge := sessionConfig.MaxAge
			if cookieMaxAge == 0 {
				cookieMaxAge = DefaultMaxAge
			}

			cookieName := sessionConfig.CookieName
			if cookieName == "" {
				cookieName = DefaultCookieName
			}

			duration := time.Second * time.Duration(cookieMaxAge)

			if sessionData == nil {
				cookie, _ := r.Cookie(cookieName)
				if cookie != nil {
					if sessionIDStr, err = s.DecryptString(cookie.Value); err != nil {
						slog.Warn("failed to decrypt session ID", "error", err)
						// Log session decryption failure

					} else {
						// Retrieve session from cache using the decrypted session ID
						sessionData, err = s.Get(ctx, sessionIDStr)
						if err != nil {
							slog.Warn("failed to get session data from cache", "error", err)
							// Log session retrieval failure

						}
					}
				}
			}

			if sessionData == nil {
				sessionData = &reqctx.SessionData{
					ID:        uuid.New().String(),
					CreatedAt: time.Now(),
				}
				encryptedSessionID, err = s.EncryptString(sessionData.ID)
				if err != nil {
					slog.Warn("failed to encrypt session ID", "error", err)
				}
				sessionIDStr = sessionData.ID
				sessionData.EncryptedID = encryptedSessionID

				if len(sessionConfig.OnSessionStart) > 0 {
					slog.Debug("executing session callbacks", "callbacks", sessionConfig.OnSessionStart)

					// Prepare callback data using the 9-namespace model
					callbackData := make(map[string]any)

					// Populate namespace context objects
					if requestData.OriginCtx != nil {
						callbackData["origin"] = requestData.OriginCtx
					}
					if requestData.ServerCtx != nil {
						callbackData["server"] = requestData.ServerCtx
					}
					if requestData.VarsCtx != nil && requestData.VarsCtx.Data != nil {
						callbackData["vars"] = requestData.VarsCtx.Data
					}
					if requestData.FeaturesCtx != nil && requestData.FeaturesCtx.Data != nil {
						callbackData["features"] = requestData.FeaturesCtx.Data
					}
					if requestData.ClientCtx != nil {
						callbackData["client"] = requestData.ClientCtx
					}
					callbackData["session"] = map[string]any{
						"id":   sessionData.ID,
						"data": sessionData.Data,
					}
					if requestData.Snapshot != nil {
						callbackData["request"] = requestData.Snapshot
					}
					if requestData.CtxObj != nil {
						callbackData["ctx"] = requestData.CtxObj
					}

					// Execute callbacks sequentially (respects async flag for each callback)
					result, err := sessionConfig.OnSessionStart.DoSequentialWithType(ctx, callbackData, "on_session_start")
					if err != nil {
						slog.Error("failed to execute session callbacks", "error", err)
						httputil.HandleError(http.StatusInternalServerError, err, w, r)
						return
					}
					sessionData.Data = result
					// Note: Session callback data is stored in sessionData.Data
					// Template variables can access it via RequestData.SessionData.Data
					// No need to copy to RequestData.Data - the template resolver checks SessionData.Data
				}
			} else {
				// Track session duration for existing sessions
				if !sessionData.CreatedAt.IsZero() {
					sessionDuration := time.Since(sessionData.CreatedAt).Seconds()
					configID := "unknown"
					if requestData := reqctx.GetRequestData(r.Context()); requestData != nil && requestData.Config != nil {
						configData := reqctx.ConfigParams(requestData.Config)
						if id := configData.GetConfigID(); id != "" {
							configID = id
						}
					}
					sessionType := "standard"
					if sessionData.AuthData != nil {
						sessionType = "authenticated"
					}
					metric.SessionDuration(configID, sessionType, sessionDuration)
				}
			}
			sessionData.Expires = time.Now().Add(duration)

			// Track the visited URL (limit to last 10)
			if r.URL != nil {
				sessionData.AddVisitedURL(r.URL.String())
			}

			requestData.SessionData = sessionData

			// Initialize cookie jar if enabled
			if sessionConfig.EnableCookieJar {
				// Get configuration or use defaults
				opts := DefaultCookieJarOptions()
				if sessionConfig.CookieJarConfig != nil {
					if sessionConfig.CookieJarConfig.MaxCookies > 0 {
						opts.MaxCookies = sessionConfig.CookieJarConfig.MaxCookies
					}
					if sessionConfig.CookieJarConfig.MaxCookieSize > 0 {
						opts.MaxCookieSize = sessionConfig.CookieJarConfig.MaxCookieSize
					}
					opts.StoreSecureOnly = sessionConfig.CookieJarConfig.StoreSecureOnly
					opts.StoreHttpOnly = !sessionConfig.CookieJarConfig.DisableStoreHttpOnly
				}

				// Create the cookie jar and store in request data for logging/debugging
				jar := NewSessionDataCookieJarWithConfig(
					sessionData,
					opts.MaxCookies,
					opts.MaxCookieSize,
					opts.StoreSecureOnly,
					opts.StoreHttpOnly,
				)

				// Store jar reference in data map for access by transport
				requestData.SetData("__cookie_jar", jar)

				slog.Debug("initialized session cookie jar",
					"session_id", sessionIDStr,
					"cookie_count", jar.GetCookieCount(),
					"max_cookies", opts.MaxCookies)
			}

			// Update request context with modified RequestData
			// Session callback data is accessible via RequestData.SessionData.Data
			// Auth callback data is accessible via RequestData.SessionData.AuthData.Data
			*r = *r.WithContext(reqctx.SetRequestData(r.Context(), requestData))

			// Cookie Secure flag: set to true if request is TLS, false otherwise
			// If we've reached this point, session creation is allowed (either TLS or AllowNonSSL is true)
			cookieSecure := r.TLS != nil

			// Cookie HttpOnly flag: default to true unless explicitly disabled
			cookieHttpOnly := !sessionConfig.DisableHttpOnly

			sameSite := http.SameSiteLaxMode
			if sessionConfig.SameSite != "" {
				switch strings.ToLower(sessionConfig.SameSite) {
				case "strict":
					sameSite = http.SameSiteStrictMode
				case "none":
					sameSite = http.SameSiteNoneMode
				case "lax":
					sameSite = http.SameSiteLaxMode
				default:
					sameSite = http.SameSiteLaxMode
				}
			}

			slogchi.AddCustomAttributes(r, slog.String("session_id", sessionIDStr))

			http.SetCookie(w, &http.Cookie{
				Name:     cookieName,
				Value:    sessionData.EncryptedID,
				Path:     "/",
				HttpOnly: cookieHttpOnly,
				Secure:   cookieSecure,
				SameSite: sameSite,
				MaxAge:   cookieMaxAge,
			})

			slog.Debug("adding session ID to request", "session_id", sessionIDStr, "url", r.URL.String(), "expires_at", sessionData.Expires.Format(time.RFC3339))
			next.ServeHTTP(w, r)

			// Retrieve updated session data from request context (may have been modified by transport)
			updatedRequestData := reqctx.GetRequestData(r.Context())
			if updatedRequestData != nil && updatedRequestData.SessionData != nil {
				sessionData = updatedRequestData.SessionData

				// If cookie jar was enabled, sync it one more time before save
				if sessionConfig.EnableCookieJar {
					if jar, ok := updatedRequestData.Data["__cookie_jar"].(*SessionDataCookieJar); ok {
						jar.SyncToSessionData()
						sessionData = &jar.SessionData

						slog.Debug("synced cookie jar to session before save",
							"session_id", sessionIDStr,
							"cookie_count", jar.GetCookieCount())
					}
				}
			}

			// save the session last
			if err := s.Save(ctx, sessionData, duration); err != nil {
				slog.Warn("failed to save session data", "error", err)
			}

		})
	}
}

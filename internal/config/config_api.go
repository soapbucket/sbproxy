// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
)

// APIHandler performs the api handler operation.
func APIHandler(c *Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		apiConfig := c.APIConfig
		if apiConfig == nil || !apiConfig.EnableAPI {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := apiConfig.AltAPIPath
			if strings.HasPrefix(r.URL.Path, path) {
				slog.Debug("API request", "path", r.URL.Path)

				if apiConfig.APIBearer != "" && r.Header.Get("Authorization") != "Bearer "+apiConfig.APIBearer {
					httputil.HandleError(http.StatusUnauthorized, ErrUnauthorizedAPIAccess, w, r)
					return
				}

				switch strings.TrimPrefix(r.URL.Path, path) {
				case "config":
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
					w.Header().Set("Pragma", "no-cache")
					w.Header().Set("Expires", "0")

					w.WriteHeader(http.StatusOK)
					data, _ := json.Marshal(c)
					_, _ = w.Write(data)
					return

				default:
					http.NotFound(w, r)
					return
				}

			}

			next.ServeHTTP(w, r)
		})
	}
}

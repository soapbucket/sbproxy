// Package session provides session management with cookie-based tracking and storage backends.
package session

import (
	"log/slog"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// CookieJarOptions holds configuration for creating a cookie jar
type CookieJarOptions struct {
	MaxCookies      int
	MaxCookieSize   int
	StoreSecureOnly bool
	StoreHttpOnly   bool
}

// DefaultCookieJarOptions returns default cookie jar options
func DefaultCookieJarOptions() CookieJarOptions {
	return CookieJarOptions{
		MaxCookies:      100,
		MaxCookieSize:   4096,
		StoreSecureOnly: false,
		StoreHttpOnly:   true,
	}
}

// CreateSessionCookieJarFn creates a function that returns a cookie jar for a request
// The cookie jar is backed by the session data and will be synced back to the session
func CreateSessionCookieJarFn(opts CookieJarOptions) func(*http.Request) http.CookieJar {
	return func(req *http.Request) http.CookieJar {
		// Extract session from request context
		requestData := reqctx.GetRequestData(req.Context())
		if requestData == nil || requestData.SessionData == nil {
			slog.Debug("no session data in request context, cookie jar not available")
			return nil
		}

		// Create cookie jar from session data with configuration
		jar := NewSessionDataCookieJarWithConfig(
			requestData.SessionData,
			opts.MaxCookies,
			opts.MaxCookieSize,
			opts.StoreSecureOnly,
			opts.StoreHttpOnly,
		)

		slog.Debug("created session cookie jar",
			"session_id", requestData.SessionData.ID,
			"cookie_count", jar.GetCookieCount(),
			"max_cookies", opts.MaxCookies)

		return jar
	}
}

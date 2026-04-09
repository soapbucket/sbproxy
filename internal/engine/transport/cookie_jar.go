// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"log/slog"
	"net/http"
)

// CookieJarTransport wraps a RoundTripper to inject and capture cookies from a session-based cookie jar
type CookieJarTransport struct {
	Base     http.RoundTripper
	GetJarFn func(*http.Request) http.CookieJar
}

// RoundTrip executes a single HTTP transaction, injecting cookies before the request
// and capturing Set-Cookie headers from the response
func (t *CookieJarTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Get cookie jar for this request (from session)
	jar := t.GetJarFn(req)
	
	if jar != nil {
		// Get cookies for the target URL
		cookies := jar.Cookies(req.URL)
		
		if len(cookies) > 0 {
			// Add cookies to request
			for _, cookie := range cookies {
				req.AddCookie(cookie)
			}
			
			slog.Debug("injected cookies into proxied request",
				"url", req.URL.String(),
				"host", req.URL.Host,
				"cookie_count", len(cookies))
		}
	}
	
	// Execute request with base transport
	resp, err := t.Base.RoundTrip(req)
	
	// Capture response cookies and store in jar
	if err == nil && jar != nil {
		if cookies := resp.Cookies(); len(cookies) > 0 {
			jar.SetCookies(req.URL, cookies)
			
			slog.Debug("captured cookies from proxied response",
				"url", req.URL.String(),
				"host", req.URL.Host,
				"cookie_count", len(cookies))
			
			// Sync jar back to session data if it supports the interface
			// This avoids import cycle by using interface instead of concrete type
			type sessionSyncer interface {
				SyncToSessionData()
			}
			
			if syncer, ok := jar.(sessionSyncer); ok {
				syncer.SyncToSessionData()
				
				slog.Debug("synced cookie jar to session data",
					"url", req.URL.String())
			}
		}
	}
	
	return resp, err
}

// NewCookieJarTransport creates a new CookieJarTransport
func NewCookieJarTransport(base http.RoundTripper, getJarFn func(*http.Request) http.CookieJar) *CookieJarTransport {
	return &CookieJarTransport{
		Base:     base,
		GetJarFn: getJarFn,
	}
}


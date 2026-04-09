// Package session provides session management with cookie-based tracking and storage backends.
package session

import (
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// SerializableCookie represents a cookie that can be serialized to JSON
type SerializableCookie struct {
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Path     string    `json:"path,omitempty"`
	Domain   string    `json:"domain,omitempty"`
	Expires  time.Time `json:"expires,omitempty"`
	MaxAge   int       `json:"max_age,omitempty"`
	Secure   bool      `json:"secure,omitempty"`
	HttpOnly bool      `json:"http_only,omitempty"`
	SameSite string    `json:"same_site,omitempty"`
	HostOnly bool      `json:"host_only,omitempty"` // If true, cookie only matches exact host (no subdomains)
}

// ToHTTPCookie converts SerializableCookie to http.Cookie
func (sc *SerializableCookie) ToHTTPCookie() *http.Cookie {
	cookie := &http.Cookie{
		Name:     sc.Name,
		Value:    sc.Value,
		Path:     sc.Path,
		Domain:   sc.Domain,
		Expires:  sc.Expires,
		MaxAge:   sc.MaxAge,
		Secure:   sc.Secure,
		HttpOnly: sc.HttpOnly,
	}

	// Parse SameSite
	switch sc.SameSite {
	case "Strict":
		cookie.SameSite = http.SameSiteStrictMode
	case "Lax":
		cookie.SameSite = http.SameSiteLaxMode
	case "None":
		cookie.SameSite = http.SameSiteNoneMode
	}

	return cookie
}

// FromHTTPCookie creates SerializableCookie from http.Cookie
func FromHTTPCookie(cookie *http.Cookie) *SerializableCookie {
	sc := &SerializableCookie{
		Name:     cookie.Name,
		Value:    cookie.Value,
		Path:     cookie.Path,
		Domain:   cookie.Domain,
		Expires:  cookie.Expires,
		MaxAge:   cookie.MaxAge,
		Secure:   cookie.Secure,
		HttpOnly: cookie.HttpOnly,
	}

	// Convert SameSite to string
	switch cookie.SameSite {
	case http.SameSiteStrictMode:
		sc.SameSite = "Strict"
	case http.SameSiteLaxMode:
		sc.SameSite = "Lax"
	case http.SameSiteNoneMode:
		sc.SameSite = "None"
	}

	return sc
}

// SessionDataCookieJar represents a session data cookie jar.
type SessionDataCookieJar struct {
	reqctx.SessionData

	CookieJar []SerializableCookie
	mu        sync.RWMutex

	// Configuration
	maxCookies      int
	maxCookieSize   int
	storeSecureOnly bool
	storeHttpOnly   bool
}

// SetCookies implements http.CookieJar.SetCookies
func (s *SessionDataCookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	for _, cookie := range cookies {
		// Check if cookie is expired - this is a deletion request
		if !cookie.Expires.IsZero() && cookie.Expires.Before(now) {
			// Cookie deletion: remove existing cookie with same name/domain/path
			effectiveDomain := cookie.Domain
			if effectiveDomain == "" {
				effectiveDomain = u.Host
			} else if effectiveDomain[0] != '.' {
				effectiveDomain = "." + effectiveDomain
			}
			effectivePath := cookie.Path
			if effectivePath == "" {
				effectivePath = "/"
			}
			s.removeCookie(cookie.Name, effectiveDomain, effectivePath)
			continue
		}

		// Check if cookie should be set for this URL
		shouldSet := s.shouldSetCookie(u, cookie)
		if !shouldSet {
			continue
		}

		// Apply configuration filters
		if s.storeSecureOnly && !cookie.Secure {
			continue
		}

		if !s.storeHttpOnly && cookie.HttpOnly {
			continue
		}

		// Check cookie size limit
		if s.maxCookieSize > 0 && len(cookie.Value) > s.maxCookieSize {
			continue
		}

		// Convert to serializable format
		sc := FromHTTPCookie(cookie)

		// Handle domain per RFC 6265
		if sc.Domain == "" {
			// Domain omitted - host-only cookie (matches exact host only)
			// Strip port from host (ports don't belong in cookie domains)
			hostWithoutPort := u.Host
			if colonIdx := len(hostWithoutPort) - 1; colonIdx > 0 {
				for i := colonIdx; i >= 0; i-- {
					if hostWithoutPort[i] == ':' {
						hostWithoutPort = hostWithoutPort[:i]
						break
					}
					if hostWithoutPort[i] == ']' {
						// IPv6 address, don't strip
						break
					}
				}
			}
			sc.Domain = hostWithoutPort
			sc.HostOnly = true
		} else {
			// Domain explicitly set - matches domain and subdomains
			sc.HostOnly = false
			// Strip port from domain if present (shouldn't be there, but be defensive)
			domain := sc.Domain
			if colonIdx := len(domain) - 1; colonIdx > 0 {
				for i := colonIdx; i >= 0; i-- {
					if domain[i] == ':' {
						domain = domain[:i]
						break
					}
					if domain[i] == ']' {
						break
					}
				}
			}
			// Normalize domain by ensuring leading dot for subdomain matching
			if len(domain) > 0 && domain[0] != '.' {
				domain = "." + domain
			}
			sc.Domain = domain
		}
		
		// Set path if empty (default to /)
		if sc.Path == "" {
			sc.Path = "/"
		}

		// Remove existing cookie with same name, domain, and path
		s.removeCookie(sc.Name, sc.Domain, sc.Path)

		// Check max cookies limit (after removing old one)
		if s.maxCookies > 0 && len(s.CookieJar) >= s.maxCookies {
			// Remove oldest cookie (first in slice)
			if len(s.CookieJar) > 0 {
				s.CookieJar = s.CookieJar[1:]
			}
		}

		// Add new cookie
		s.CookieJar = append(s.CookieJar, *sc)
	}
}

// Cookies implements http.CookieJar.Cookies
func (s *SessionDataCookieJar) Cookies(u *url.URL) []*http.Cookie {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*http.Cookie
	now := time.Now()

	for _, sc := range s.CookieJar {
		cookie := sc.ToHTTPCookie()

		// Check if cookie is expired
		if !cookie.Expires.IsZero() && cookie.Expires.Before(now) {
			continue
		}

		// Check if cookie should be sent for this URL
		if s.shouldSendCookie(u, cookie) {
			result = append(result, cookie)
		}
	}

	return result
}

// shouldSetCookie determines if a cookie should be set for the given URL
func (s *SessionDataCookieJar) shouldSetCookie(u *url.URL, cookie *http.Cookie) bool {
	// Determine the effective domain for matching
	effectiveDomain := cookie.Domain
	if effectiveDomain == "" {
		effectiveDomain = u.Host
	}
	
	// Strip port from effectiveDomain (ports don't belong in cookie domains)
	if colonIdx := len(effectiveDomain) - 1; colonIdx > 0 {
		for i := colonIdx; i >= 0; i-- {
			if effectiveDomain[i] == ':' {
				effectiveDomain = effectiveDomain[:i]
				break
			}
			if effectiveDomain[i] == ']' {
				// IPv6 address, don't strip
				break
			}
		}
	}

	// Only check domain match for setting
	// Path matching is only enforced when retrieving cookies (Cookies method)
	// Per RFC 6265, the path attribute is a directive to the user agent about
	// when to send the cookie, not a restriction on when to accept it
	domainMatch := s.domainMatches(u.Host, effectiveDomain)
	return domainMatch
}

// shouldSendCookie determines if a cookie should be sent for the given URL
func (s *SessionDataCookieJar) shouldSendCookie(u *url.URL, cookie *http.Cookie) bool {
	// Find the serializable cookie to check HostOnly flag
	var sc *SerializableCookie
	for i := range s.CookieJar {
		if s.CookieJar[i].Name == cookie.Name && s.CookieJar[i].Domain == cookie.Domain && s.CookieJar[i].Path == cookie.Path {
			sc = &s.CookieJar[i]
			break
		}
	}

	// Check domain match with HostOnly awareness
	if sc != nil && sc.HostOnly {
		// Host-only cookie: exact match only (strip port for comparison)
		requestHost := u.Host
		if colonIdx := len(requestHost) - 1; colonIdx > 0 {
			for i := colonIdx; i >= 0; i-- {
				if requestHost[i] == ':' {
					requestHost = requestHost[:i]
					break
				}
				if requestHost[i] == ']' {
					break
				}
			}
		}
		
		cookieHost := cookie.Domain
		if colonIdx := len(cookieHost) - 1; colonIdx > 0 {
			for i := colonIdx; i >= 0; i-- {
				if cookieHost[i] == ':' {
					cookieHost = cookieHost[:i]
					break
				}
				if cookieHost[i] == ']' {
					break
				}
			}
		}
		
		if requestHost != cookieHost {
			return false
		}
	} else {
		// Normal domain matching (with subdomain support)
		if !s.domainMatches(u.Host, cookie.Domain) {
			return false
		}
	}

	// Check path match
	if cookie.Path != "" && !s.pathMatches(u.Path, cookie.Path) {
		return false
	}

	return true
}

// domainMatches checks if the request host matches the cookie domain
func (s *SessionDataCookieJar) domainMatches(host, domain string) bool {
	if domain == "" {
		return true
	}

	// Strip port from host if present (cookies don't include ports)
	if colonIdx := len(host) - 1; colonIdx > 0 {
		for i := colonIdx; i >= 0; i-- {
			if host[i] == ':' {
				host = host[:i]
				break
			}
			if host[i] == ']' {
				// IPv6 address, don't strip
				break
			}
		}
	}

	// Remove leading dot from domain if present
	if len(domain) > 0 && domain[0] == '.' {
		domain = domain[1:]
	}

	// Exact match
	if host == domain {
		return true
	}

	// Subdomain match - host must end with .domain
	if len(host) > len(domain) && host[len(host)-len(domain)-1:] == "."+domain {
		return true
	}

	return false
}

// pathMatches checks if the request path matches the cookie path
func (s *SessionDataCookieJar) pathMatches(requestPath, cookiePath string) bool {
	if cookiePath == "" {
		return true
	}

	// Exact match
	if requestPath == cookiePath {
		return true
	}

	// Prefix match - request path should start with cookie path
	if len(requestPath) >= len(cookiePath) && requestPath[:len(cookiePath)] == cookiePath {
		// If cookie path ends with /, it matches any path starting with it
		if cookiePath[len(cookiePath)-1] == '/' {
			return true
		}
		// If cookie path doesn't end with /, ensure the next character is a path separator
		if len(requestPath) > len(cookiePath) && requestPath[len(cookiePath)] == '/' {
			return true
		}
	}

	return false
}

// removeCookie removes a cookie with the given name, domain, and path
func (s *SessionDataCookieJar) removeCookie(name, domain, path string) {
	for i, sc := range s.CookieJar {
		if sc.Name == name && sc.Domain == domain && sc.Path == path {
			// Remove the cookie by slicing
			s.CookieJar = append(s.CookieJar[:i], s.CookieJar[i+1:]...)
			break
		}
	}
}

// ClearCookies removes all cookies from the session
func (s *SessionDataCookieJar) ClearCookies() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CookieJar = make([]SerializableCookie, 0)
}

// GetCookieCount returns the number of cookies in the session
func (s *SessionDataCookieJar) GetCookieCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.CookieJar)
}

// NewSessionDataCookieJar creates a new SessionDataCookieJar from SessionData
// This initializes the CookieJar from any existing cookies stored in the session
func NewSessionDataCookieJar(sessionData *reqctx.SessionData) *SessionDataCookieJar {
	jar := &SessionDataCookieJar{
		SessionData: *sessionData,
		CookieJar:   make([]SerializableCookie, 0),
	}

	// If there are cookies stored in session data, load them
	if sessionData.Data != nil {
		if cookiesData, ok := sessionData.Data["cookies"]; ok {
			// Handle different possible types for cookies storage
			// When loaded from JSON, it might be []interface{} instead of []SerializableCookie
			switch v := cookiesData.(type) {
			case []SerializableCookie:
				jar.CookieJar = v
			case []interface{}:
				// Try to convert from JSON unmarshaled format
				for _, item := range v {
					if cookieMap, ok := item.(map[string]interface{}); ok {
						cookie := SerializableCookie{}
						if name, ok := cookieMap["name"].(string); ok {
							cookie.Name = name
						}
						if value, ok := cookieMap["value"].(string); ok {
							cookie.Value = value
						}
						if path, ok := cookieMap["path"].(string); ok {
							cookie.Path = path
						}
						if domain, ok := cookieMap["domain"].(string); ok {
							cookie.Domain = domain
						}
						if secure, ok := cookieMap["secure"].(bool); ok {
							cookie.Secure = secure
						}
						if httpOnly, ok := cookieMap["http_only"].(bool); ok {
							cookie.HttpOnly = httpOnly
						}
						if sameSite, ok := cookieMap["same_site"].(string); ok {
							cookie.SameSite = sameSite
						}
						if maxAge, ok := cookieMap["max_age"].(float64); ok {
							cookie.MaxAge = int(maxAge)
						}
						if hostOnly, ok := cookieMap["host_only"].(bool); ok {
							cookie.HostOnly = hostOnly
						}
						// Parse Expires field from JSON string
						if expiresStr, ok := cookieMap["expires"].(string); ok && expiresStr != "" {
							if parsed, err := time.Parse(time.RFC3339, expiresStr); err == nil {
								cookie.Expires = parsed
							}
						}
						jar.CookieJar = append(jar.CookieJar, cookie)
					}
				}
			}
		}
	}

	return jar
}

// NewSessionDataCookieJarWithConfig creates a new SessionDataCookieJar with configuration
func NewSessionDataCookieJarWithConfig(sessionData *reqctx.SessionData, maxCookies, maxCookieSize int, storeSecureOnly, storeHttpOnly bool) *SessionDataCookieJar {
	jar := NewSessionDataCookieJar(sessionData)
	jar.maxCookies = maxCookies
	jar.maxCookieSize = maxCookieSize
	jar.storeSecureOnly = storeSecureOnly
	jar.storeHttpOnly = storeHttpOnly
	return jar
}

// SyncToSessionData syncs cookies back to SessionData for persistence
// This should be called before saving the session to ensure cookies are persisted
func (s *SessionDataCookieJar) SyncToSessionData() {
	s.mu.RLock()
	cookiesCopy := make([]SerializableCookie, len(s.CookieJar))
	copy(cookiesCopy, s.CookieJar)
	s.mu.RUnlock()

	// Store cookies in SessionData.Data for persistence
	if s.SessionData.Data == nil {
		s.SessionData.Data = make(map[string]any)
	}

	s.SessionData.Data["cookies"] = cookiesCopy
}

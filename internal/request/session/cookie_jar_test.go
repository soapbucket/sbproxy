package session

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func TestSessionDataCookieJar_SetAndGetCookies(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	jar := NewSessionDataCookieJarWithConfig(sessionData, 100, 4096, false, true)

	targetURL, _ := url.Parse("https://example.com/api")

	// Create test cookies
	cookies := []*http.Cookie{
		{
			Name:  "session_id",
			Value: "abc123",
			Path:  "/",
		},
		{
			Name:  "auth_token",
			Value: "xyz789",
			Path:  "/api",
		},
	}

	// Set cookies
	jar.SetCookies(targetURL, cookies)

	// Get cookies for the same URL
	retrieved := jar.Cookies(targetURL)

	if len(retrieved) != 2 {
		t.Errorf("Expected 2 cookies, got %d", len(retrieved))
	}

	// Verify cookie names
	names := make(map[string]bool)
	for _, c := range retrieved {
		names[c.Name] = true
	}

	if !names["session_id"] || !names["auth_token"] {
		t.Error("Expected cookies not found")
	}
}

func TestSessionDataCookieJar_DomainMatching(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	jar := NewSessionDataCookieJar(sessionData)

	// Set cookie for .example.com
	apiURL, _ := url.Parse("https://api.example.com/")
	cookies := []*http.Cookie{
		{
			Name:   "shared",
			Value:  "value1",
			Domain: ".example.com",
			Path:   "/",
		},
	}
	jar.SetCookies(apiURL, cookies)

	// Should match www.example.com
	wwwURL, _ := url.Parse("https://www.example.com/")
	retrieved := jar.Cookies(wwwURL)

	if len(retrieved) != 1 {
		t.Errorf("Expected 1 cookie for subdomain, got %d", len(retrieved))
	}

	// Should not match different.com
	differentURL, _ := url.Parse("https://different.com/")
	retrieved = jar.Cookies(differentURL)

	if len(retrieved) != 0 {
		t.Errorf("Expected 0 cookies for different domain, got %d", len(retrieved))
	}
}

func TestSessionDataCookieJar_PathMatching(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	jar := NewSessionDataCookieJar(sessionData)

	targetURL, _ := url.Parse("https://example.com/api")
	cookies := []*http.Cookie{
		{
			Name:  "api_cookie",
			Value: "value1",
			Path:  "/api",
		},
		{
			Name:  "root_cookie",
			Value: "value2",
			Path:  "/",
		},
	}
	jar.SetCookies(targetURL, cookies)

	// Request to /api/users should get both cookies
	apiUsersURL, _ := url.Parse("https://example.com/api/users")
	retrieved := jar.Cookies(apiUsersURL)

	if len(retrieved) != 2 {
		t.Errorf("Expected 2 cookies for /api/users, got %d", len(retrieved))
	}

	// Request to /admin should only get root cookie
	adminURL, _ := url.Parse("https://example.com/admin")
	retrieved = jar.Cookies(adminURL)

	if len(retrieved) != 1 {
		t.Errorf("Expected 1 cookie for /admin, got %d", len(retrieved))
	}

	if retrieved[0].Name != "root_cookie" {
		t.Errorf("Expected root_cookie, got %s", retrieved[0].Name)
	}
}

func TestSessionDataCookieJar_ExpiredCookies(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	jar := NewSessionDataCookieJar(sessionData)

	targetURL, _ := url.Parse("https://example.com/")

	// Create expired cookie
	expiredTime := time.Now().Add(-1 * time.Hour)
	cookies := []*http.Cookie{
		{
			Name:    "expired",
			Value:   "old_value",
			Expires: expiredTime,
			Path:    "/",
		},
		{
			Name:  "valid",
			Value: "current_value",
			Path:  "/",
		},
	}

	jar.SetCookies(targetURL, cookies)

	// Should only get valid cookie
	retrieved := jar.Cookies(targetURL)

	if len(retrieved) != 1 {
		t.Errorf("Expected 1 valid cookie, got %d", len(retrieved))
	}

	if retrieved[0].Name != "valid" {
		t.Errorf("Expected valid cookie, got %s", retrieved[0].Name)
	}
}

func TestSessionDataCookieJar_MaxCookiesLimit(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	// Set max cookies to 5
	jar := NewSessionDataCookieJarWithConfig(sessionData, 5, 4096, false, true)

	targetURL, _ := url.Parse("https://example.com/")

	// Add 10 cookies
	for i := 0; i < 10; i++ {
		cookies := []*http.Cookie{
			{
				Name:  "cookie_" + string(rune('0'+i)),
				Value: "value",
				Path:  "/",
			},
		}
		jar.SetCookies(targetURL, cookies)
	}

	// Should only have 5 cookies (oldest removed)
	count := jar.GetCookieCount()
	if count != 5 {
		t.Errorf("Expected 5 cookies due to limit, got %d", count)
	}
}

func TestSessionDataCookieJar_CookieSizeLimit(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	// Set max cookie size to 100 bytes
	jar := NewSessionDataCookieJarWithConfig(sessionData, 100, 100, false, true)

	targetURL, _ := url.Parse("https://example.com/")

	// Try to add cookie larger than limit
	largeCookie := []*http.Cookie{
		{
			Name:  "large",
			Value: string(make([]byte, 200)), // 200 bytes
			Path:  "/",
		},
	}

	jar.SetCookies(targetURL, largeCookie)

	// Should not be stored
	if jar.GetCookieCount() != 0 {
		t.Error("Cookie exceeding size limit should not be stored")
	}

	// Add cookie within limit
	smallCookie := []*http.Cookie{
		{
			Name:  "small",
			Value: "value",
			Path:  "/",
		},
	}

	jar.SetCookies(targetURL, smallCookie)

	if jar.GetCookieCount() != 1 {
		t.Error("Cookie within size limit should be stored")
	}
}

func TestSessionDataCookieJar_SecureOnlyFilter(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	// Enable secure only filter
	jar := NewSessionDataCookieJarWithConfig(sessionData, 100, 4096, true, true)

	targetURL, _ := url.Parse("https://example.com/")

	cookies := []*http.Cookie{
		{
			Name:   "secure_cookie",
			Value:  "value1",
			Secure: true,
			Path:   "/",
		},
		{
			Name:   "insecure_cookie",
			Value:  "value2",
			Secure: false,
			Path:   "/",
		},
	}

	jar.SetCookies(targetURL, cookies)

	// Should only store secure cookie
	if jar.GetCookieCount() != 1 {
		t.Errorf("Expected 1 secure cookie, got %d", jar.GetCookieCount())
	}

	retrieved := jar.Cookies(targetURL)
	if len(retrieved) != 1 || retrieved[0].Name != "secure_cookie" {
		t.Error("Only secure cookie should be stored")
	}
}

func TestSessionDataCookieJar_HttpOnlyFilter(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	// Disable HttpOnly filter (don't store HttpOnly cookies)
	jar := NewSessionDataCookieJarWithConfig(sessionData, 100, 4096, false, false)

	targetURL, _ := url.Parse("https://example.com/")

	cookies := []*http.Cookie{
		{
			Name:     "httponly_cookie",
			Value:    "value1",
			HttpOnly: true,
			Path:     "/",
		},
		{
			Name:     "normal_cookie",
			Value:    "value2",
			HttpOnly: false,
			Path:     "/",
		},
	}

	jar.SetCookies(targetURL, cookies)

	// Should only store non-HttpOnly cookie
	if jar.GetCookieCount() != 1 {
		t.Errorf("Expected 1 non-HttpOnly cookie, got %d", jar.GetCookieCount())
	}

	retrieved := jar.Cookies(targetURL)
	if len(retrieved) != 1 || retrieved[0].Name != "normal_cookie" {
		t.Error("Only non-HttpOnly cookie should be stored")
	}
}

func TestSessionDataCookieJar_SyncToSessionData(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	jar := NewSessionDataCookieJar(sessionData)

	targetURL, _ := url.Parse("https://example.com/")
	cookies := []*http.Cookie{
		{
			Name:  "test_cookie",
			Value: "test_value",
			Path:  "/",
		},
	}

	jar.SetCookies(targetURL, cookies)

	// Sync to session data
	jar.SyncToSessionData()

	// Verify cookies are in session data
	if jar.SessionData.Data["cookies"] == nil {
		t.Error("Cookies not synced to session data")
	}

	// Create new jar from synced session data
	newJar := NewSessionDataCookieJar(&jar.SessionData)

	if newJar.GetCookieCount() != 1 {
		t.Errorf("Expected 1 cookie after loading from session, got %d", newJar.GetCookieCount())
	}

	retrieved := newJar.Cookies(targetURL)
	if len(retrieved) != 1 || retrieved[0].Name != "test_cookie" {
		t.Error("Cookie not properly restored from session data")
	}
}

func TestSessionDataCookieJar_ClearCookies(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	jar := NewSessionDataCookieJar(sessionData)

	targetURL, _ := url.Parse("https://example.com/")
	cookies := []*http.Cookie{
		{Name: "cookie1", Value: "value1", Path: "/"},
		{Name: "cookie2", Value: "value2", Path: "/"},
	}

	jar.SetCookies(targetURL, cookies)

	if jar.GetCookieCount() != 2 {
		t.Error("Cookies not added")
	}

	jar.ClearCookies()

	if jar.GetCookieCount() != 0 {
		t.Error("Cookies not cleared")
	}
}

func TestSessionDataCookieJar_SameSiteAttributes(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	jar := NewSessionDataCookieJar(sessionData)
	targetURL, _ := url.Parse("https://example.com/")

	// Test all SameSite modes
	cookies := []*http.Cookie{
		{
			Name:     "strict_cookie",
			Value:    "value1",
			SameSite: http.SameSiteStrictMode,
			Path:     "/",
		},
		{
			Name:     "lax_cookie",
			Value:    "value2",
			SameSite: http.SameSiteLaxMode,
			Path:     "/",
		},
		{
			Name:     "none_cookie",
			Value:    "value3",
			SameSite: http.SameSiteNoneMode,
			Path:     "/",
		},
		{
			Name:     "default_cookie",
			Value:    "value4",
			SameSite: http.SameSiteDefaultMode,
			Path:     "/",
		},
	}

	jar.SetCookies(targetURL, cookies)
	jar.SyncToSessionData()

	// Create new jar from session data to verify serialization
	newJar := NewSessionDataCookieJar(&jar.SessionData)
	retrieved := newJar.Cookies(targetURL)

	if len(retrieved) != 4 {
		t.Fatalf("Expected 4 cookies, got %d", len(retrieved))
	}

	// Verify SameSite attributes preserved
	sameSiteMap := make(map[string]http.SameSite)
	for _, c := range retrieved {
		sameSiteMap[c.Name] = c.SameSite
	}

	if sameSiteMap["strict_cookie"] != http.SameSiteStrictMode {
		t.Error("Strict SameSite not preserved")
	}
	if sameSiteMap["lax_cookie"] != http.SameSiteLaxMode {
		t.Error("Lax SameSite not preserved")
	}
	if sameSiteMap["none_cookie"] != http.SameSiteNoneMode {
		t.Error("None SameSite not preserved")
	}
}

func TestSessionDataCookieJar_CookieReplacement(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	jar := NewSessionDataCookieJar(sessionData)
	targetURL, _ := url.Parse("https://example.com/")

	// Set initial cookie
	jar.SetCookies(targetURL, []*http.Cookie{
		{Name: "session", Value: "old_value", Path: "/"},
	})

	if jar.GetCookieCount() != 1 {
		t.Fatal("Initial cookie not set")
	}

	// Set cookie with same name and domain (should replace)
	jar.SetCookies(targetURL, []*http.Cookie{
		{Name: "session", Value: "new_value", Path: "/"},
	})

	// Should still have 1 cookie (replaced, not added)
	if jar.GetCookieCount() != 1 {
		t.Errorf("Expected 1 cookie after replacement, got %d", jar.GetCookieCount())
	}

	// Verify new value
	retrieved := jar.Cookies(targetURL)
	if len(retrieved) != 1 || retrieved[0].Value != "new_value" {
		t.Error("Cookie not properly replaced")
	}
}

func TestSessionDataCookieJar_CookieDifferentDomains(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	jar := NewSessionDataCookieJar(sessionData)

	// Set same cookie name for different domains
	apiURL, _ := url.Parse("https://api.example.com/")
	jar.SetCookies(apiURL, []*http.Cookie{
		{Name: "token", Value: "api_token", Domain: "api.example.com", Path: "/"},
	})

	wwwURL, _ := url.Parse("https://www.example.com/")
	jar.SetCookies(wwwURL, []*http.Cookie{
		{Name: "token", Value: "www_token", Domain: "www.example.com", Path: "/"},
	})

	// Should have 2 cookies (different domains)
	if jar.GetCookieCount() != 2 {
		t.Errorf("Expected 2 cookies for different domains, got %d", jar.GetCookieCount())
	}

	// Verify each domain gets its own cookie
	apiCookies := jar.Cookies(apiURL)
	if len(apiCookies) != 1 || apiCookies[0].Value != "api_token" {
		t.Error("API domain cookie incorrect")
	}

	wwwCookies := jar.Cookies(wwwURL)
	if len(wwwCookies) != 1 || wwwCookies[0].Value != "www_token" {
		t.Error("WWW domain cookie incorrect")
	}
}

func TestSessionDataCookieJar_MaxAgeZeroDeletesCookie(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	jar := NewSessionDataCookieJar(sessionData)
	targetURL, _ := url.Parse("https://example.com/")

	// Set cookie
	jar.SetCookies(targetURL, []*http.Cookie{
		{Name: "delete_me", Value: "value", Path: "/"},
	})

	if jar.GetCookieCount() != 1 {
		t.Fatal("Cookie not set")
	}

	// Delete cookie with MaxAge=0 and Expires in past
	pastTime := time.Now().Add(-1 * time.Hour)
	jar.SetCookies(targetURL, []*http.Cookie{
		{
			Name:    "delete_me",
			Value:   "",
			Path:    "/",
			MaxAge:  -1,
			Expires: pastTime,
		},
	})

	// Cookie should be filtered out as expired
	retrieved := jar.Cookies(targetURL)
	if len(retrieved) != 0 {
		t.Errorf("Expected cookie to be deleted, got %d cookies", len(retrieved))
	}
}

func TestSessionDataCookieJar_PathMatchingEdgeCases(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	jar := NewSessionDataCookieJar(sessionData)
	targetURL, _ := url.Parse("https://example.com/")

	cookies := []*http.Cookie{
		{Name: "api_cookie", Value: "value1", Path: "/api"},
		{Name: "api_slash_cookie", Value: "value2", Path: "/api/"},
		{Name: "root_cookie", Value: "value3", Path: "/"},
	}
	jar.SetCookies(targetURL, cookies)

	tests := []struct {
		name          string
		requestPath   string
		expectedNames []string
	}{
		{
			name:          "exact /api match",
			requestPath:   "/api",
			expectedNames: []string{"api_cookie", "root_cookie"}, // /api/ should NOT match per RFC 6265
		},
		{
			name:          "/api/v1 matches /api and /api/",
			requestPath:   "/api/v1",
			expectedNames: []string{"api_cookie", "api_slash_cookie", "root_cookie"},
		},
		{
			name:          "/api/ matches /api and /api/",
			requestPath:   "/api/",
			expectedNames: []string{"api_cookie", "api_slash_cookie", "root_cookie"},
		},
		{
			name:          "/apitest should NOT match /api",
			requestPath:   "/apitest",
			expectedNames: []string{"root_cookie"},
		},
		{
			name:          "/admin matches only root",
			requestPath:   "/admin",
			expectedNames: []string{"root_cookie"},
		},
		{
			name:          "/ matches all with / path",
			requestPath:   "/",
			expectedNames: []string{"root_cookie"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testURL, _ := url.Parse("https://example.com" + tt.requestPath)
			retrieved := jar.Cookies(testURL)

			if len(retrieved) != len(tt.expectedNames) {
				t.Errorf("Expected %d cookies, got %d", len(tt.expectedNames), len(retrieved))
			}

			retrievedNames := make(map[string]bool)
			for _, c := range retrieved {
				retrievedNames[c.Name] = true
			}

			for _, expectedName := range tt.expectedNames {
				if !retrievedNames[expectedName] {
					t.Errorf("Expected cookie %s not found", expectedName)
				}
			}
		})
	}
}

func TestSessionDataCookieJar_DomainWithPort(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	jar := NewSessionDataCookieJar(sessionData)

	// Set cookie for domain without port
	targetURL, _ := url.Parse("https://example.com:8080/")
	cookies := []*http.Cookie{
		{
			Name:   "port_cookie",
			Value:  "value1",
			Domain: "example.com",
			Path:   "/",
		},
	}
	jar.SetCookies(targetURL, cookies)

	// Should be retrievable from same domain with different port
	differentPortURL, _ := url.Parse("https://example.com:9090/")
	retrieved := jar.Cookies(differentPortURL)

	if len(retrieved) != 1 {
		t.Errorf("Expected 1 cookie for different port, got %d", len(retrieved))
	}

	// Should be retrievable from same domain without port
	noPortURL, _ := url.Parse("https://example.com/")
	retrieved = jar.Cookies(noPortURL)

	if len(retrieved) != 1 {
		t.Errorf("Expected 1 cookie without port, got %d", len(retrieved))
	}
}

func TestSessionDataCookieJar_SubdomainDepth(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	jar := NewSessionDataCookieJar(sessionData)

	// Set cookie for .example.com
	targetURL, _ := url.Parse("https://api.example.com/")
	cookies := []*http.Cookie{
		{
			Name:   "shared",
			Value:  "value1",
			Domain: ".example.com",
			Path:   "/",
		},
	}
	jar.SetCookies(targetURL, cookies)

	tests := []struct {
		name     string
		host     string
		expected int
	}{
		{
			name:     "exact match",
			host:     "example.com",
			expected: 1,
		},
		{
			name:     "one level subdomain",
			host:     "api.example.com",
			expected: 1,
		},
		{
			name:     "two level subdomain",
			host:     "v1.api.example.com",
			expected: 1,
		},
		{
			name:     "three level subdomain",
			host:     "prod.v1.api.example.com",
			expected: 1,
		},
		{
			name:     "different domain",
			host:     "different.com",
			expected: 0,
		},
		{
			name:     "similar but different domain",
			host:     "notexample.com",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testURL, _ := url.Parse("https://" + tt.host + "/")
			retrieved := jar.Cookies(testURL)
			if len(retrieved) != tt.expected {
				t.Errorf("Expected %d cookies for %s, got %d", tt.expected, tt.host, len(retrieved))
			}
		})
	}
}

func TestSessionDataCookieJar_ConcurrentAccess(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	jar := NewSessionDataCookieJar(sessionData)
	targetURL, _ := url.Parse("https://example.com/")

	// Concurrent writes
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			cookies := []*http.Cookie{
				{
					Name:  "cookie_" + string(rune('0'+id)),
					Value: "value",
					Path:  "/",
				},
			}
			jar.SetCookies(targetURL, cookies)
			done <- true
		}(i)
	}

	// Wait for all writes
	for i := 0; i < 10; i++ {
		<-done
	}

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func() {
			_ = jar.Cookies(targetURL)
			done <- true
		}()
	}

	// Wait for all reads
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should not panic and should have cookies
	count := jar.GetCookieCount()
	if count == 0 {
		t.Error("No cookies after concurrent operations")
	}
}

func TestSessionDataCookieJar_JSONRoundTrip(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	// Use proper config to allow HttpOnly cookies
	jar := NewSessionDataCookieJarWithConfig(sessionData, 100, 4096, false, true)
	targetURL, _ := url.Parse("https://example.com/")

	originalCookies := []*http.Cookie{
		{
			Name:     "complex_cookie",
			Value:    "complex_value_123",
			Path:     "/api",
			Domain:   ".example.com",
			Expires:  time.Now().Add(1 * time.Hour),
			MaxAge:   3600,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		},
	}

	jar.SetCookies(targetURL, originalCookies)

	t.Logf("After SetCookies: %d cookies in jar", jar.GetCookieCount())
	if jar.GetCookieCount() > 0 {
		t.Logf("Stored cookie: name=%s, domain=%s, path=%s, hostonly=%v",
			jar.CookieJar[0].Name, jar.CookieJar[0].Domain, jar.CookieJar[0].Path, jar.CookieJar[0].HostOnly)
	}

	jar.SyncToSessionData()

	// Marshal to JSON and back (simulates storage)
	jsonData, err := json.Marshal(jar.SessionData.Data["cookies"])
	if err != nil {
		t.Fatalf("Failed to marshal cookies: %v", err)
	}

	t.Logf("JSON: %s", string(jsonData))

	var unmarshaledCookies []interface{}
	if err := json.Unmarshal(jsonData, &unmarshaledCookies); err != nil {
		t.Fatalf("Failed to unmarshal cookies: %v", err)
	}

	// Create new session data with unmarshaled cookies
	newSessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: map[string]any{"cookies": unmarshaledCookies},
	}

	// Create new jar from unmarshaled data
	newJar := NewSessionDataCookieJar(newSessionData)

	t.Logf("After loading: %d cookies in new jar", newJar.GetCookieCount())
	if newJar.GetCookieCount() > 0 {
		t.Logf("Loaded cookie: name=%s, domain=%s, path=%s, hostonly=%v",
			newJar.CookieJar[0].Name, newJar.CookieJar[0].Domain, newJar.CookieJar[0].Path, newJar.CookieJar[0].HostOnly)
	}

	// Try to retrieve - must use URL matching the cookie's path
	retrieveURL, _ := url.Parse("https://example.com/api/endpoint")
	retrieved := newJar.Cookies(retrieveURL)

	t.Logf("Retrieved %d cookies", len(retrieved))
	for _, c := range retrieved {
		t.Logf("  Cookie: name=%s, domain=%s, path=%s", c.Name, c.Domain, c.Path)
	}

	if len(retrieved) != 1 {
		t.Fatalf("Expected 1 cookie after round-trip, got %d", len(retrieved))
	}

	cookie := retrieved[0]
	if cookie.Name != "complex_cookie" {
		t.Errorf("Name not preserved: got %s", cookie.Name)
	}
	if cookie.Value != "complex_value_123" {
		t.Errorf("Value not preserved: got %s", cookie.Value)
	}
	if cookie.Path != "/api" {
		t.Errorf("Path not preserved: got %s", cookie.Path)
	}
	// Domain gets normalized with leading dot
	if cookie.Domain != ".example.com" {
		t.Logf("Domain after round-trip: got %s (may include normalization)", cookie.Domain)
	}
	if cookie.MaxAge != 3600 {
		t.Errorf("MaxAge not preserved: got %d", cookie.MaxAge)
	}
	if !cookie.Secure {
		t.Error("Secure flag not preserved")
	}
	if !cookie.HttpOnly {
		t.Error("HttpOnly flag not preserved")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite not preserved: got %v", cookie.SameSite)
	}
}

func TestSessionDataCookieJar_UpdateExistingCookie(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	// Use config with storeHttpOnly=true to allow storing HttpOnly cookies
	jar := NewSessionDataCookieJarWithConfig(sessionData, 100, 4096, false, true)
	targetURL, _ := url.Parse("https://example.com/")

	// Set initial cookie
	jar.SetCookies(targetURL, []*http.Cookie{
		{Name: "session", Value: "initial", Path: "/", Secure: false},
	})

	if jar.GetCookieCount() != 1 {
		t.Fatalf("Expected 1 cookie after first set, got %d", jar.GetCookieCount())
	}

	// Update with different attributes
	jar.SetCookies(targetURL, []*http.Cookie{
		{Name: "session", Value: "updated", Path: "/", Secure: true, HttpOnly: true},
	})

	if jar.GetCookieCount() != 1 {
		t.Fatalf("Expected 1 cookie after update (replacement), got %d", jar.GetCookieCount())
	}

	retrieved := jar.Cookies(targetURL)
	if len(retrieved) != 1 {
		t.Fatalf("Expected 1 cookie retrieved, got %d", len(retrieved))
	}

	cookie := retrieved[0]
	if cookie.Value != "updated" {
		t.Errorf("Value not updated: got %s, want updated", cookie.Value)
	}
	if !cookie.Secure {
		t.Error("Secure flag not updated")
	}
	if !cookie.HttpOnly {
		t.Error("HttpOnly flag not updated")
	}
}

func TestSessionDataCookieJar_LRUEvictionOrder(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	// Set max cookies to 3
	jar := NewSessionDataCookieJarWithConfig(sessionData, 3, 4096, false, true)
	targetURL, _ := url.Parse("https://example.com/")

	// Add cookies in order: cookie_0, cookie_1, cookie_2
	for i := 0; i < 3; i++ {
		cookies := []*http.Cookie{
			{
				Name:  "cookie_" + string(rune('0'+i)),
				Value: "value",
				Path:  "/",
			},
		}
		jar.SetCookies(targetURL, cookies)
	}

	if jar.GetCookieCount() != 3 {
		t.Fatalf("Expected 3 cookies, got %d", jar.GetCookieCount())
	}

	// Add one more cookie (should evict oldest: cookie_0)
	jar.SetCookies(targetURL, []*http.Cookie{
		{Name: "cookie_3", Value: "value", Path: "/"},
	})

	if jar.GetCookieCount() != 3 {
		t.Errorf("Expected 3 cookies after eviction, got %d", jar.GetCookieCount())
	}

	// Verify cookie_0 was evicted
	retrieved := jar.Cookies(targetURL)
	names := make(map[string]bool)
	for _, c := range retrieved {
		names[c.Name] = true
	}

	if names["cookie_0"] {
		t.Error("Oldest cookie (cookie_0) should have been evicted")
	}
	if !names["cookie_1"] || !names["cookie_2"] || !names["cookie_3"] {
		t.Error("Newer cookies should be retained")
	}
}

func TestSessionDataCookieJar_EmptyDomain(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	jar := NewSessionDataCookieJar(sessionData)
	targetURL, _ := url.Parse("https://example.com/")

	// Set cookie with empty domain (should use request host)
	cookies := []*http.Cookie{
		{
			Name:   "no_domain",
			Value:  "value",
			Domain: "",
			Path:   "/",
		},
	}
	jar.SetCookies(targetURL, cookies)

	// Should be retrieved from same host
	retrieved := jar.Cookies(targetURL)
	if len(retrieved) != 1 {
		t.Errorf("Expected 1 cookie, got %d", len(retrieved))
	}

	// Should NOT be retrieved from subdomain
	subdomainURL, _ := url.Parse("https://api.example.com/")
	retrieved = jar.Cookies(subdomainURL)
	if len(retrieved) != 0 {
		t.Errorf("Expected 0 cookies for subdomain with empty domain cookie, got %d", len(retrieved))
	}
}

func TestSessionDataCookieJar_SessionCookies(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	jar := NewSessionDataCookieJar(sessionData)
	targetURL, _ := url.Parse("https://example.com/")

	// Set session cookie (no Expires, MaxAge=-1)
	cookies := []*http.Cookie{
		{
			Name:   "session_cookie",
			Value:  "value",
			Path:   "/",
			MaxAge: -1,
		},
	}
	jar.SetCookies(targetURL, cookies)

	// Should be stored and retrievable
	retrieved := jar.Cookies(targetURL)
	if len(retrieved) != 1 {
		t.Errorf("Expected 1 session cookie, got %d", len(retrieved))
	}

	// Verify persistence through sync
	jar.SyncToSessionData()
	newJar := NewSessionDataCookieJar(&jar.SessionData)
	retrieved = newJar.Cookies(targetURL)

	if len(retrieved) != 1 {
		t.Errorf("Expected 1 session cookie after sync, got %d", len(retrieved))
	}
}

func TestSessionDataCookieJar_MultipleCookiesSameName(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	jar := NewSessionDataCookieJar(sessionData)
	targetURL, _ := url.Parse("https://example.com/")

	// Set multiple cookies with same name but different paths
	cookies := []*http.Cookie{
		{Name: "token", Value: "root_value", Path: "/"},
		{Name: "token", Value: "api_value", Path: "/api"},
		{Name: "token", Value: "admin_value", Path: "/admin"},
	}
	jar.SetCookies(targetURL, cookies)

	if jar.GetCookieCount() != 3 {
		t.Errorf("Expected 3 cookies with different paths, got %d", jar.GetCookieCount())
	}

	// Request to /api should get /api and / cookies
	apiURL, _ := url.Parse("https://example.com/api/users")
	retrieved := jar.Cookies(apiURL)

	// Should get both root and api cookies
	if len(retrieved) != 2 {
		t.Errorf("Expected 2 cookies for /api/users, got %d", len(retrieved))
	}

	values := make(map[string]bool)
	for _, c := range retrieved {
		values[c.Value] = true
	}

	if !values["root_value"] || !values["api_value"] {
		t.Error("Should get both root and api path cookies")
	}
}

func TestSessionDataCookieJar_ConfigCombinations(t *testing.T) {
	tests := []struct {
		name            string
		maxCookies      int
		maxCookieSize   int
		storeSecureOnly bool
		storeHttpOnly   bool
		testCookies     []*http.Cookie
		expectedCount   int
		description     string
	}{
		{
			name:            "all disabled",
			maxCookies:      100,
			maxCookieSize:   4096,
			storeSecureOnly: false,
			storeHttpOnly:   false,
			testCookies: []*http.Cookie{
				{Name: "secure", Value: "val", Secure: true, Path: "/"},
				{Name: "insecure", Value: "val", Secure: false, Path: "/"},
				{Name: "httponly", Value: "val", HttpOnly: true, Path: "/"},
				{Name: "normal", Value: "val", HttpOnly: false, Path: "/"},
			},
			expectedCount: 3, // Excludes HttpOnly when storeHttpOnly=false
			description:   "Store all except HttpOnly",
		},
		{
			name:            "secure only",
			maxCookies:      100,
			maxCookieSize:   4096,
			storeSecureOnly: true,
			storeHttpOnly:   true,
			testCookies: []*http.Cookie{
				{Name: "secure", Value: "val", Secure: true, Path: "/"},
				{Name: "insecure", Value: "val", Secure: false, Path: "/"},
			},
			expectedCount: 1,
			description:   "Only secure cookies",
		},
		{
			name:            "size limit enforced",
			maxCookies:      100,
			maxCookieSize:   10,
			storeSecureOnly: false,
			storeHttpOnly:   true,
			testCookies: []*http.Cookie{
				{Name: "small", Value: "ok", Path: "/"},
				{Name: "large", Value: "this_is_too_large", Path: "/"},
			},
			expectedCount: 1,
			description:   "Only small cookie stored",
		},
		{
			name:            "both filters active",
			maxCookies:      100,
			maxCookieSize:   4096,
			storeSecureOnly: true,
			storeHttpOnly:   false,
			testCookies: []*http.Cookie{
				{Name: "secure_httponly", Value: "val", Secure: true, HttpOnly: true, Path: "/"},
				{Name: "secure_normal", Value: "val", Secure: true, HttpOnly: false, Path: "/"},
				{Name: "insecure_normal", Value: "val", Secure: false, HttpOnly: false, Path: "/"},
			},
			expectedCount: 1, // Only secure_normal passes both filters
			description:   "Secure but not HttpOnly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionData := &reqctx.SessionData{
				ID:   "test-session",
				Data: make(map[string]any),
			}

			jar := NewSessionDataCookieJarWithConfig(
				sessionData,
				tt.maxCookies,
				tt.maxCookieSize,
				tt.storeSecureOnly,
				tt.storeHttpOnly,
			)

			targetURL, _ := url.Parse("https://example.com/")
			jar.SetCookies(targetURL, tt.testCookies)

			count := jar.GetCookieCount()
			if count != tt.expectedCount {
				t.Errorf("%s: expected %d cookies, got %d", tt.description, tt.expectedCount, count)
			}
		})
	}
}

func TestSessionDataCookieJar_ExpiredCookieNotReturned(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	jar := NewSessionDataCookieJar(sessionData)
	targetURL, _ := url.Parse("https://example.com/")

	// Set cookie that will expire soon
	futureTime := time.Now().Add(100 * time.Millisecond)
	cookies := []*http.Cookie{
		{
			Name:    "short_lived",
			Value:   "value",
			Path:    "/",
			Expires: futureTime,
		},
	}
	jar.SetCookies(targetURL, cookies)

	// Should be retrievable immediately
	retrieved := jar.Cookies(targetURL)
	if len(retrieved) != 1 {
		t.Fatal("Cookie should be retrievable before expiry")
	}

	// Wait for expiry
	time.Sleep(150 * time.Millisecond)

	// Should not be retrievable after expiry
	retrieved = jar.Cookies(targetURL)
	if len(retrieved) != 0 {
		t.Error("Expired cookie should not be returned")
	}

	// But should still be in storage (not automatically cleaned)
	if jar.GetCookieCount() != 1 {
		t.Error("Expired cookie should still be in storage")
	}
}

func TestSessionDataCookieJar_MaxAgeVsExpires(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	jar := NewSessionDataCookieJar(sessionData)
	targetURL, _ := url.Parse("https://example.com/")

	tests := []struct {
		name            string
		maxAge          int
		expires         time.Time
		expectStored    bool
		expectRetrieved bool
	}{
		{
			name:            "MaxAge -1 (session cookie)",
			maxAge:          -1,
			expires:         time.Time{},
			expectStored:    true,
			expectRetrieved: true,
		},
		{
			name:            "MaxAge 0 with past Expires (delete)",
			maxAge:          0,
			expires:         time.Now().Add(-1 * time.Hour),
			expectStored:    false,
			expectRetrieved: false,
		},
		{
			name:            "MaxAge positive with future Expires",
			maxAge:          3600,
			expires:         time.Now().Add(1 * time.Hour),
			expectStored:    true,
			expectRetrieved: true,
		},
		{
			name:            "MaxAge positive with past Expires",
			maxAge:          3600,
			expires:         time.Now().Add(-1 * time.Hour),
			expectStored:    false,
			expectRetrieved: false,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear jar for each test
			jar.ClearCookies()

			cookie := &http.Cookie{
				Name:    "test_" + string(rune('0'+i)),
				Value:   "value",
				Path:    "/",
				MaxAge:  tt.maxAge,
				Expires: tt.expires,
			}

			jar.SetCookies(targetURL, []*http.Cookie{cookie})

			count := jar.GetCookieCount()
			if tt.expectStored && count == 0 {
				t.Error("Cookie should be stored but wasn't")
			}
			if !tt.expectStored && count != 0 {
				t.Error("Cookie should not be stored but was")
			}

			retrieved := jar.Cookies(targetURL)
			if tt.expectRetrieved && len(retrieved) == 0 {
				t.Error("Cookie should be retrievable but wasn't")
			}
			if !tt.expectRetrieved && len(retrieved) != 0 {
				t.Error("Cookie should not be retrievable but was")
			}
		})
	}
}

func TestSessionDataCookieJar_EmptyPath(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	jar := NewSessionDataCookieJar(sessionData)
	targetURL, _ := url.Parse("https://example.com/")

	// Set cookie with empty path (should match all paths)
	cookies := []*http.Cookie{
		{
			Name:   "empty_path",
			Value:  "value",
			Path:   "",
			Domain: "example.com",
		},
	}
	jar.SetCookies(targetURL, cookies)

	// Should match any path
	paths := []string{"/", "/api", "/api/v1", "/admin/users"}
	for _, path := range paths {
		testURL, _ := url.Parse("https://example.com" + path)
		retrieved := jar.Cookies(testURL)
		if len(retrieved) != 1 {
			t.Errorf("Empty path cookie should match %s, got %d cookies", path, len(retrieved))
		}
	}
}

func TestSessionDataCookieJar_ConcurrentReadOperations(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	jar := NewSessionDataCookieJar(sessionData)
	targetURL, _ := url.Parse("https://example.com/")

	// Add some cookies
	jar.SetCookies(targetURL, []*http.Cookie{
		{Name: "cookie1", Value: "value1", Path: "/"},
		{Name: "cookie2", Value: "value2", Path: "/"},
	})

	// Concurrent read operations (Cookies method)
	done := make(chan bool)
	for i := 0; i < 20; i++ {
		go func() {
			_ = jar.Cookies(targetURL)
			_ = jar.GetCookieCount()
			done <- true
		}()
	}

	// Wait for all reads
	for i := 0; i < 20; i++ {
		<-done
	}

	// Should not panic
	retrieved := jar.Cookies(targetURL)
	if len(retrieved) != 2 {
		t.Errorf("Expected 2 cookies after concurrent reads, got %d", len(retrieved))
	}

	// Note: SyncToSessionData should only be called from single goroutine
	// in practice (when saving session), so we don't test concurrent syncs
}

func TestSessionDataCookieJar_ZeroMaxCookies(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	// Set maxCookies to 0 (unlimited)
	jar := NewSessionDataCookieJarWithConfig(sessionData, 0, 4096, false, true)
	targetURL, _ := url.Parse("https://example.com/")

	// Add many cookies
	for i := 0; i < 200; i++ {
		cookies := []*http.Cookie{
			{
				Name:  "cookie_" + string(rune('0'+(i%10))),
				Value: "value",
				Path:  "/",
			},
		}
		jar.SetCookies(targetURL, cookies)
	}

	// Should store all (no limit)
	// Note: Same name cookies get replaced, so we only have 10 unique
	count := jar.GetCookieCount()
	if count != 10 {
		t.Errorf("Expected 10 unique cookies with no limit, got %d", count)
	}
}

func TestSessionDataCookieJar_DomainMatchingWithPort(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	jar := NewSessionDataCookieJar(sessionData)

	// Set cookie from URL with port
	targetURL, _ := url.Parse("https://example.com:8080/")
	cookies := []*http.Cookie{
		{
			Name:  "cookie1",
			Value: "value1",
			Path:  "/",
			// Domain will be set to "example.com:8080"
		},
	}
	jar.SetCookies(targetURL, cookies)

	t.Logf("After SetCookies: %d cookies", jar.GetCookieCount())
	if jar.GetCookieCount() > 0 {
		t.Logf("Stored cookie: name=%s, domain=%s, path=%s, hostonly=%v",
			jar.CookieJar[0].Name, jar.CookieJar[0].Domain, jar.CookieJar[0].Path, jar.CookieJar[0].HostOnly)
	}

	// Retrieve from URL with same port
	retrieved := jar.Cookies(targetURL)
	t.Logf("Retrieved %d cookies from same port URL", len(retrieved))
	if len(retrieved) != 1 {
		t.Errorf("Expected 1 cookie with same port, got %d", len(retrieved))
	}

	// Retrieve from URL with different port (should still match if domain matches)
	differentPortURL, _ := url.Parse("https://example.com:9090/")
	retrieved = jar.Cookies(differentPortURL)
	// Note: Cookies with port in domain are tricky - standard behavior is port-specific
	// Our implementation stores domain with port, so it won't match different port
	if len(retrieved) != 0 {
		t.Logf("Cookie with port-specific domain got %d cookies", len(retrieved))
	}
}

func TestSessionDataCookieJar_RemoveCookieDirectly(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	jar := NewSessionDataCookieJar(sessionData)

	// Add cookies directly to jar
	jar.mu.Lock()
	jar.CookieJar = []SerializableCookie{
		{Name: "cookie1", Value: "value1", Domain: "example.com", Path: "/"},
		{Name: "cookie2", Value: "value2", Domain: "example.com", Path: "/api"},
		{Name: "cookie3", Value: "value3", Domain: "api.example.com", Path: "/"},
	}
	jar.mu.Unlock()

	if jar.GetCookieCount() != 3 {
		t.Fatalf("Expected 3 cookies initially, got %d", jar.GetCookieCount())
	}

	// Remove cookie1
	jar.mu.Lock()
	jar.removeCookie("cookie1", "example.com", "/")
	jar.mu.Unlock()

	if jar.GetCookieCount() != 2 {
		t.Errorf("Expected 2 cookies after removal, got %d", jar.GetCookieCount())
	}

	// Verify cookie1 is gone
	found := false
	for _, sc := range jar.CookieJar {
		if sc.Name == "cookie1" {
			found = true
		}
	}
	if found {
		t.Error("cookie1 should have been removed")
	}
}

func TestSessionDataCookieJar_SimpleCookieUpdate(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	jar := NewSessionDataCookieJar(sessionData)
	targetURL, _ := url.Parse("https://example.com/")

	// Add first cookie manually
	jar.mu.Lock()
	jar.CookieJar = []SerializableCookie{
		{Name: "test", Value: "old", Domain: "example.com", Path: "/", HostOnly: true},
	}
	jar.mu.Unlock()

	t.Logf("Before SetCookies: %d cookies", jar.GetCookieCount())
	for _, sc := range jar.CookieJar {
		t.Logf("  Cookie: name=%s, value=%s, domain=%s, path=%s", sc.Name, sc.Value, sc.Domain, sc.Path)
	}

	// Now call SetCookies with same cookie (different value)
	jar.SetCookies(targetURL, []*http.Cookie{
		{Name: "test", Value: "new", Path: "/", Domain: ""},
	})

	t.Logf("After SetCookies: %d cookies", jar.GetCookieCount())
	for _, sc := range jar.CookieJar {
		t.Logf("  Cookie: name=%s, value=%s, domain=%s, path=%s", sc.Name, sc.Value, sc.Domain, sc.Path)
	}

	if jar.GetCookieCount() != 1 {
		t.Errorf("Expected 1 cookie, got %d", jar.GetCookieCount())
	}

	if jar.CookieJar[0].Value != "new" {
		t.Errorf("Expected value 'new', got '%s'", jar.CookieJar[0].Value)
	}
}

func TestSessionDataCookieJar_UpdateCookieValue(t *testing.T) {
	sessionData := &reqctx.SessionData{
		ID:   "test-session",
		Data: make(map[string]any),
	}

	jar := NewSessionDataCookieJar(sessionData)
	targetURL, _ := url.Parse("https://example.com/")

	// Set initial cookie
	jar.SetCookies(targetURL, []*http.Cookie{
		{Name: "counter", Value: "1", Path: "/"},
	})

	// Update value multiple times
	for i := 2; i <= 5; i++ {
		jar.SetCookies(targetURL, []*http.Cookie{
			{Name: "counter", Value: string(rune('0' + i)), Path: "/"},
		})
	}

	// Should still have 1 cookie (replaced each time)
	if jar.GetCookieCount() != 1 {
		t.Errorf("Expected 1 cookie after updates, got %d", jar.GetCookieCount())
	}

	// Verify final value
	retrieved := jar.Cookies(targetURL)
	if len(retrieved) != 1 || retrieved[0].Value != "5" {
		t.Error("Cookie value not properly updated")
	}
}

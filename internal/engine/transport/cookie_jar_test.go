package transport

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// mockCookieJar implements http.CookieJar for testing
type mockCookieJar struct {
	cookies  map[string][]*http.Cookie
	setCalls int
	getCalls int
}

func newMockCookieJar() *mockCookieJar {
	return &mockCookieJar{
		cookies: make(map[string][]*http.Cookie),
	}
}

func (m *mockCookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	m.setCalls++
	m.cookies[u.Host] = append(m.cookies[u.Host], cookies...)
}

func (m *mockCookieJar) Cookies(u *url.URL) []*http.Cookie {
	m.getCalls++
	return m.cookies[u.Host]
}

// cookieJarMockRoundTripper implements http.RoundTripper for testing
type cookieJarMockRoundTripper struct {
	response    *http.Response
	err         error
	lastRequest *http.Request
}

func (m *cookieJarMockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	m.lastRequest = req
	return m.response, m.err
}

func TestCookieJarTransport_InjectsCookies(t *testing.T) {
	// Create mock backend
	jar := newMockCookieJar()
	targetURL, _ := url.Parse("https://backend.example.com/api")

	// Pre-populate jar with cookies
	jar.SetCookies(targetURL, []*http.Cookie{
		{Name: "session_id", Value: "abc123"},
		{Name: "auth_token", Value: "xyz789"},
	})

	// Create mock transport
	mockTransport := &cookieJarMockRoundTripper{
		response: &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Body:       http.NoBody,
		},
	}

	// Create cookie jar transport
	transport := NewCookieJarTransport(mockTransport, func(r *http.Request) http.CookieJar {
		return jar
	})

	// Make request
	req := httptest.NewRequest("GET", "https://backend.example.com/api/users", nil)
	_, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}

	// Verify cookies were injected
	if mockTransport.lastRequest == nil {
		t.Fatal("Request not passed to base transport")
	}

	cookies := mockTransport.lastRequest.Cookies()
	if len(cookies) != 2 {
		t.Errorf("Expected 2 cookies injected, got %d", len(cookies))
	}

	// Verify cookie jar was queried
	if jar.getCalls != 1 {
		t.Errorf("Expected 1 Cookies() call, got %d", jar.getCalls)
	}
}

func TestCookieJarTransport_CapturesCookies(t *testing.T) {
	jar := newMockCookieJar()

	// Create mock response with Set-Cookie headers
	mockTransport := &cookieJarMockRoundTripper{
		response: &http.Response{
			StatusCode: 200,
			Header: http.Header{
				"Set-Cookie": []string{
					"new_cookie=value1; Path=/",
					"another_cookie=value2; Path=/api",
				},
			},
			Body: http.NoBody,
		},
	}

	// Create cookie jar transport
	transport := NewCookieJarTransport(mockTransport, func(r *http.Request) http.CookieJar {
		return jar
	})

	// Make request
	req := httptest.NewRequest("GET", "https://backend.example.com/api", nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}

	// Verify response cookies were captured
	cookies := resp.Cookies()
	if len(cookies) != 2 {
		t.Errorf("Expected 2 cookies in response, got %d", len(cookies))
	}

	// Verify jar was updated
	if jar.setCalls != 1 {
		t.Errorf("Expected 1 SetCookies() call, got %d", jar.setCalls)
	}

	storedCookies := jar.cookies["backend.example.com"]
	if len(storedCookies) != 2 {
		t.Errorf("Expected 2 cookies stored in jar, got %d", len(storedCookies))
	}
}

func TestCookieJarTransport_NoJar(t *testing.T) {
	// Create mock transport
	mockTransport := &cookieJarMockRoundTripper{
		response: &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Body:       http.NoBody,
		},
	}

	// Create cookie jar transport that returns nil jar
	transport := NewCookieJarTransport(mockTransport, func(r *http.Request) http.CookieJar {
		return nil
	})

	// Make request - should not panic
	req := httptest.NewRequest("GET", "https://backend.example.com/api", nil)
	_, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}

	// Verify no cookies were added to request
	if mockTransport.lastRequest == nil {
		t.Fatal("Request not passed to base transport")
	}

	cookies := mockTransport.lastRequest.Cookies()
	if len(cookies) != 0 {
		t.Errorf("Expected 0 cookies when jar is nil, got %d", len(cookies))
	}
}

func TestCookieJarTransport_ErrorHandling(t *testing.T) {
	jar := newMockCookieJar()

	// Create mock transport that returns error
	mockTransport := &cookieJarMockRoundTripper{
		err: http.ErrServerClosed,
	}

	// Create cookie jar transport
	transport := NewCookieJarTransport(mockTransport, func(r *http.Request) http.CookieJar {
		return jar
	})

	// Make request
	req := httptest.NewRequest("GET", "https://backend.example.com/api", nil)
	_, err := transport.RoundTrip(req)

	// Should return the error
	if err != http.ErrServerClosed {
		t.Errorf("Expected error to be propagated, got %v", err)
	}

	// Jar should not be updated on error
	if jar.setCalls != 0 {
		t.Errorf("SetCookies should not be called on error, got %d calls", jar.setCalls)
	}
}

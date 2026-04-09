package cel

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func TestNewMatcher(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		wantErr bool
	}{
		{
			name:    "simple method match",
			expr:    `request.method == 'GET'`,
			wantErr: false,
		},
		{
			name:    "path match",
			expr:    `request.path.startsWith('/api/')`,
			wantErr: false,
		},
		{
			name:    "header match",
			expr:    `request.headers['content-type'] == 'application/json'`,
			wantErr: false,
		},
		{
			name:    "complex expression",
			expr:    `request.method == 'POST' && request.path.startsWith('/api/') && request.headers['content-type'] == 'application/json'`,
			wantErr: false,
		},
		{
			name:    "invalid expression - not boolean",
			expr:    `request.method`,
			wantErr: true,
		},
		{
			name:    "syntax error",
			expr:    `request.method == `,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewMatcher(tt.expr)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewMatcher() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMatcherMatch(t *testing.T) {
	tests := []struct {
		name      string
		expr      string
		setupReq  func() *http.Request
		wantMatch bool
	}{
		{
			name: "match GET method",
			expr: `request.method == 'GET'`,
			setupReq: func() *http.Request {
				return httptest.NewRequest("GET", "http://example.com/test", nil)
			},
			wantMatch: true,
		},
		{
			name: "match POST method",
			expr: `request.method == 'POST'`,
			setupReq: func() *http.Request {
				return httptest.NewRequest("GET", "http://example.com/test", nil)
			},
			wantMatch: false,
		},
		{
			name: "match path prefix",
			expr: `request.path.startsWith('/api/')`,
			setupReq: func() *http.Request {
				return httptest.NewRequest("GET", "http://example.com/api/users", nil)
			},
			wantMatch: true,
		},
		{
			name: "match header",
			expr: `request.headers['content-type'] == 'application/json'`,
			setupReq: func() *http.Request {
				req := httptest.NewRequest("POST", "http://example.com/api/users", nil)
				req.Header.Set("Content-Type", "application/json")
				return req
			},
			wantMatch: true,
		},
		{
			name: "match query string",
			expr: `request.query.contains('source=mobile')`,
			setupReq: func() *http.Request {
				return httptest.NewRequest("GET", "http://example.com/test?source=mobile", nil)
			},
			wantMatch: true,
		},
		{
			name: "match with null context variable",
			expr: `size(client.fingerprint) == 0 || client.fingerprint['hash'] == ''`,
			setupReq: func() *http.Request {
				return httptest.NewRequest("GET", "http://example.com/test", nil)
			},
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewMatcher(tt.expr)
			if err != nil {
				t.Fatalf("NewMatcher() error = %v", err)
			}

			req := tt.setupReq()
			got := matcher.Match(req)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestMatcherWithFingerprint(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	requestData := reqctx.NewRequestData()
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	requestData.ClientCtx = &reqctx.ClientContext{
		IP: "192.168.1.1",
		Fingerprint: &reqctx.Fingerprint{
			Hash:        "abc123",
			Version:     "v1.0",
			CookieCount: 5,
		},
	}

	tests := []struct {
		name      string
		expr      string
		wantMatch bool
	}{
		{
			name:      "fingerprint exists",
			expr:      `size(client.fingerprint) > 0`,
			wantMatch: true,
		},
		{
			name:      "fingerprint hash match",
			expr:      `size(client.fingerprint) > 0 && client.fingerprint['hash'] == 'abc123'`,
			wantMatch: true,
		},
		{
			name:      "fingerprint version check",
			expr:      `size(client.fingerprint) > 0 && client.fingerprint['version'] == 'v1.0'`,
			wantMatch: true,
		},
		{
			name:      "fingerprint cookie count",
			expr:      `size(client.fingerprint) > 0 && client.fingerprint['cookie_count'] >= 5`,
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewMatcher(tt.expr)
			if err != nil {
				t.Fatalf("NewMatcher() error = %v", err)
			}

			got := matcher.Match(req)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestMatcherWithUserAgent(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	requestData := reqctx.NewRequestData()
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	requestData.ClientCtx = &reqctx.ClientContext{
		IP: "192.168.1.1",
		UserAgent: &reqctx.UserAgent{
			Family:       "Chrome",
			Major:        "120",
			OSFamily:     "Mac OS X",
			OSMajor:      "10",
			DeviceFamily: "Mac",
		},
	}

	tests := []struct {
		name      string
		expr      string
		wantMatch bool
	}{
		{
			name:      "user agent exists",
			expr:      `size(client.user_agent) > 0`,
			wantMatch: true,
		},
		{
			name:      "browser family match",
			expr:      `size(client.user_agent) > 0 && client.user_agent['family'] == 'Chrome'`,
			wantMatch: true,
		},
		{
			name:      "os family match",
			expr:      `size(client.user_agent) > 0 && client.user_agent['os_family'] == 'Mac OS X'`,
			wantMatch: true,
		},
		{
			name:      "device family match",
			expr:      `size(client.user_agent) > 0 && client.user_agent['device_family'] == 'Mac'`,
			wantMatch: true,
		},
		{
			name:      "browser version check",
			expr:      `size(client.user_agent) > 0 && client.user_agent['major'] == '120'`,
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewMatcher(tt.expr)
			if err != nil {
				t.Fatalf("NewMatcher() error = %v", err)
			}

			got := matcher.Match(req)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestMatcherWithLocation(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	requestData := reqctx.NewRequestData()
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	requestData.ClientCtx = &reqctx.ClientContext{
		IP: "192.168.1.1",
		Location: &reqctx.Location{
			Country:       "United States",
			CountryCode:   "US",
			Continent:     "North America",
			ContinentCode: "NA",
			ASN:           "AS15169",
			ASName:        "Google LLC",
		},
	}

	tests := []struct {
		name      string
		expr      string
		wantMatch bool
	}{
		{
			name:      "location exists",
			expr:      `size(client.location) > 0`,
			wantMatch: true,
		},
		{
			name:      "country code match",
			expr:      `size(client.location) > 0 && client.location['country_code'] == 'US'`,
			wantMatch: true,
		},
		{
			name:      "continent match",
			expr:      `size(client.location) > 0 && client.location['continent_code'] == 'NA'`,
			wantMatch: true,
		},
		{
			name:      "ASN match",
			expr:      `size(client.location) > 0 && client.location['asn'] == 'AS15169'`,
			wantMatch: true,
		},
		{
			name:      "country name match",
			expr:      `size(client.location) > 0 && client.location['country'] == 'United States'`,
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewMatcher(tt.expr)
			if err != nil {
				t.Fatalf("NewMatcher() error = %v", err)
			}

			got := matcher.Match(req)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

// TestMatcherHeaderNormalization verifies that CEL headers are stored under
// lowercase keys only. Matches HTTP/2 convention.
func TestMatcherHeaderNormalization(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("X-Admin", "true")

	tests := []struct {
		name      string
		expr      string
		wantMatch bool
	}{
		{
			name:      "lowercase key x-admin matches",
			expr:      `request.headers['x-admin'] == 'true'`,
			wantMatch: true,
		},
		{
			name:      "original casing X-Admin does not match",
			expr:      `request.headers['X-Admin'] == 'true'`,
			wantMatch: false,
		},
		{
			name:      "underscore form x_admin does not match",
			expr:      `request.headers['x_admin'] == 'true'`,
			wantMatch: false,
		},
		{
			name:      "content-type lowercase matches",
			expr:      `request.headers['content-type'] == 'application/json'`,
			wantMatch: false, // header not set on this request
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewMatcher(tt.expr)
			if err != nil {
				t.Fatalf("NewMatcher() error = %v", err)
			}

			got := matcher.Match(req)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v for expr %q", got, tt.wantMatch, tt.expr)
			}
		})
	}
}

func TestMatcherComplexExpressions(t *testing.T) {
	req := httptest.NewRequest("POST", "http://example.com/api/users?source=mobile", nil)
	requestData := reqctx.NewRequestData()
	requestData.ClientCtx = &reqctx.ClientContext{
		IP: "192.168.1.1",
		Location: &reqctx.Location{
			CountryCode: "US",
		},
		UserAgent: &reqctx.UserAgent{
			Family: "Chrome",
		},
		Fingerprint: &reqctx.Fingerprint{
			Hash:    "test123",
			Version: "v1.0",
		},
	}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "abc123"})

	tests := []struct {
		name      string
		expr      string
		wantMatch bool
	}{
		{
			name: "multiple conditions",
			expr: `request.method == 'POST' && 
			       request.path.startsWith('/api/') &&
			       request.headers['content-type'] == 'application/json'`,
			wantMatch: true,
		},
		{
			name: "with context variables",
			expr: `size(client.user_agent) > 0 && client.user_agent['family'] == 'Chrome' &&
			       size(client.location) > 0 && client.location['country_code'] == 'US'`,
			wantMatch: true,
		},
		{
			name: "all context variables",
			expr: `size(client.fingerprint) > 0 &&
			       size(client.user_agent) > 0 &&
			       size(client.location) > 0 &&
			       request.method == 'POST'`,
			wantMatch: true,
		},
		{
			name: "request method and path check",
			expr: `request.method == 'POST' &&
			       request.query.contains('source=mobile')`,
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewMatcher(tt.expr)
			if err != nil {
				t.Fatalf("NewMatcher() error = %v", err)
			}

			got := matcher.Match(req)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

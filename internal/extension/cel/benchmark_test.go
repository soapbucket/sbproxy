package cel

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"golang.org/x/net/html"
)

// Benchmark Request Context Creation
func BenchmarkNewRequestContext(b *testing.B) {
	b.ReportAllocs()
	req := httptest.NewRequest("GET", "http://example.com/test?param1=value1&param2=value2", nil)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "abc123"})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rc := NewRequestContext(req)
		rc.Release()
	}
}

func BenchmarkNewRequestContextWithAllData(b *testing.B) {
	b.ReportAllocs()
	req := httptest.NewRequest("GET", "http://example.com/test?param1=value1", nil)
	req.Header.Set("Content-Type", "application/json")

	// Add all context data
	requestData := reqctx.NewRequestData()
	requestData.Fingerprint = &reqctx.Fingerprint{
		Hash:    "test123",
		Version: "v1.0",
	}
	requestData.UserAgent = &reqctx.UserAgent{
		Family: "Chrome",
		Major:  "120",
	}
	requestData.Location = &reqctx.Location{
		CountryCode: "US",
	}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	requestData.SessionData = &reqctx.SessionData{
		ID: "session123",
	}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rc := NewRequestContext(req)
		rc.Release()
	}
}

// Benchmark Request Matchers
func BenchmarkMatcherSimple(b *testing.B) {
	b.ReportAllocs()
	matcher, _ := NewMatcher(`request.method == 'GET'`)
	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matcher.Match(req)
	}
}

func BenchmarkMatcherComplex(b *testing.B) {
	b.ReportAllocs()
	matcher, _ := NewMatcher(`request.method == 'POST' && request.path.startsWith('/api/') && request.headers['content-type'] == 'application/json'`)
	req := httptest.NewRequest("POST", "http://example.com/api/users", nil)
	req.Header.Set("Content-Type", "application/json")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matcher.Match(req)
	}
}

/*
func BenchmarkMatcherWithContextVariables(b *testing.B) {
	b.ReportAllocs()
	matcher, _ := NewMatcher(`user_agent != null && user_agent['family'] == 'Chrome' && size(location) > 0 && location['country_code'] == 'US'`)

	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	requestData := reqctx.NewRequestData()
	requestData.UserAgent = &reqctx.UserAgent{
		UserAgentFamily: "Chrome",
	}
	requestData.Location = &reqctx.Location{
		CountryCode: "US",
	}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matcher.Match(req)
	}
}
*/

// Benchmark Request Modifiers
func BenchmarkModifierSimple(b *testing.B) {
	b.ReportAllocs()
	modifier, _ := NewModifier(`{"add_headers": {"X-Custom": "value"}}`)
	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = modifier.Modify(req)
	}
}

func BenchmarkModifierComplex(b *testing.B) {
	b.ReportAllocs()
	modifier, _ := NewModifier(`{
		"add_headers": {"X-Custom": "value"},
		"set_headers": {"Content-Type": "application/json"},
		"delete_headers": ["X-Old"],
		"add_query": {"param": "value"}
	}`)
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("X-Old", "value")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = modifier.Modify(req)
	}
}

/*
func BenchmarkModifierWithContextVariables(b *testing.B) {
	b.ReportAllocs()
	modifier, _ := NewModifier(`{
		"add_headers": {
			"X-Country": size(location) > 0 ? location['country_code'] : "UNKNOWN",
			"X-Browser": user_agent != null ? user_agent['family'] : "UNKNOWN"
		}
	}`)

	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	requestData := reqctx.NewRequestData()
	requestData.UserAgent = &reqctx.UserAgent{
		UserAgentFamily: "Chrome",
	}
	requestData.Location = &reqctx.Location{
		CountryCode: "US",
	}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = modifier.Modify(req)
	}
}
*/

// Benchmark Response Modifiers
func BenchmarkResponseModifierSimple(b *testing.B) {
	b.ReportAllocs()
	modifier, _ := NewResponseModifier(`{"add_headers": {"X-Custom": "value"}}`)
	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Create a fresh response for each iteration
		testResp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewBufferString("test body")),
			Request:    req,
		}
		_ = modifier.ModifyResponse(testResp)
	}
}

func BenchmarkResponseModifierWithBody(b *testing.B) {
	b.ReportAllocs()
	modifier, _ := NewResponseModifier(`{"body": response.body + " [modified]"}`)
	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewBufferString("test body")),
			Request:    req,
		}
		_ = modifier.ModifyResponse(resp)
	}
}

// Benchmark JSON Modifiers using CompileJSONModifier.
func BenchmarkJSONModifierSimple(b *testing.B) {
	b.ReportAllocs()
	modifier, err := CompileJSONModifier(`{"result": json.name}`)
	if err != nil {
		b.Fatalf("compile error: %v", err)
	}
	input := map[string]any{"name": "test"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		modifier.ModifyJSON(input)
	}
}

func BenchmarkJSONModifierComplex(b *testing.B) {
	b.ReportAllocs()
	modifier, err := CompileJSONModifier(`{"modified_json": {"env": json.env, "limit": json.limits.rpm, "backend": json.backends.primary}}`)
	if err != nil {
		b.Fatalf("compile error: %v", err)
	}
	input := map[string]any{
		"env":      "production",
		"limits":   map[string]any{"rpm": 10000, "burst": 1000},
		"backends": map[string]any{"primary": "https://api.example.com", "fallback": "https://fallback.example.com"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		modifier.ModifyJSON(input)
	}
}

func BenchmarkJSONModifierModifiedJSON(b *testing.B) {
	b.ReportAllocs()
	modifier, err := CompileJSONModifier(`{"modified_json": {"name": json.name + "_modified", "count": json.count}}`)
	if err != nil {
		b.Fatalf("compile error: %v", err)
	}
	input := map[string]any{"name": "original", "count": 42}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		modifier.ModifyJSON(input)
	}
}

// Benchmark Token Matchers
func BenchmarkTokenMatcherSimple(b *testing.B) {
	b.ReportAllocs()
	matcher, _ := NewTokenMatcher(`token.data == 'a'`)
	token := html.Token{
		Type: html.StartTagToken,
		Data: "a",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matcher.Match(token)
	}
}

func BenchmarkTokenMatcherWithAttributes(b *testing.B) {
	b.ReportAllocs()
	matcher, _ := NewTokenMatcher(`token.data == 'a' && token.attrs['href'].startsWith('https://')`)
	token := html.Token{
		Type: html.StartTagToken,
		Data: "a",
		Attr: []html.Attribute{
			{Key: "href", Val: "https://example.com"},
			{Key: "class", Val: "btn btn-primary"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matcher.Match(token)
	}
}

// Benchmark Converter Functions
func BenchmarkConvertFingerprintToMap(b *testing.B) {
	b.ReportAllocs()
	fp := &reqctx.Fingerprint{
		Hash:        "abc123",
		Version:     "v1.0",
		CookieCount: 5,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = convertFingerprintToMap(fp)
	}
}

func BenchmarkConvertUserAgentToMap(b *testing.B) {
	b.ReportAllocs()
	ua := &reqctx.UserAgent{
		Family:       "Chrome",
		Major:        "120",
		OSFamily:     "Mac OS X",
		DeviceFamily: "Mac",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = convertUserAgentToMap(ua)
	}
}

func BenchmarkConvertLocationToMap(b *testing.B) {
	b.ReportAllocs()
	location := &reqctx.Location{
		Country:       "United States",
		CountryCode:   "US",
		Continent:     "North America",
		ContinentCode: "NA",
		ASN:           "AS15169",
		ASName:        "Google LLC",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = convertLocationToMap(location)
	}
}

func BenchmarkConvertSessionDataToMap(b *testing.B) {
	b.ReportAllocs()
	sd := &reqctx.SessionData{
		ID:      "session123",
		Expires: time.Now().Add(24 * time.Hour),
		AuthData: &reqctx.AuthData{
			Type: "oauth",
			Data: map[string]any{
				"id":       "user123",
				"email":    "test@example.com",
				"name":     "Test User",
				"provider": "google",
				"roles":    []string{"admin"},
			},
		},
		Data:    map[string]any{"key": "value"},
		Visited: []reqctx.VisitedURL{{URL: "/page1"}, {URL: "/page2"}},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = convertSessionDataToMap(sd)
	}
}

// Benchmark End-to-End Scenarios
func BenchmarkEndToEndRequestMatchAndModify(b *testing.B) {
	b.ReportAllocs()
	matcher, _ := NewMatcher(`request.method == 'POST' && request.path.startsWith('/api/')`)
	modifier, _ := NewModifier(`{"add_headers": {"X-Processed": "true"}}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "http://example.com/api/users", nil)
		if matcher.Match(req) {
			_, _ = modifier.Modify(req)
		}
	}
}

/*
func BenchmarkEndToEndWithContextVariables(b *testing.B) {
	b.ReportAllocs()
	matcher, _ := NewMatcher(`user_agent != null && user_agent['family'] == 'Chrome'`)
	modifier, _ := NewModifier(`{"add_headers": {"X-Country": size(location) > 0 ? location['country_code'] : "UNKNOWN"}}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "http://example.com/test", nil)

		requestData := reqctx.NewRequestData()
		requestData.UserAgent = &reqctx.UserAgent{
			UserAgentFamily: "Chrome",
		}
		requestData.Location = &reqctx.Location{
			CountryCode: "US",
		}
		req = req.WithContext(reqctx.SetRequestData(req.Context(), requestData))

		if matcher.Match(req) {
			_, _ = modifier.Modify(req)
		}
	}
}
*/

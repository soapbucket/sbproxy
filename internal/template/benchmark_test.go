package template_test

import (
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	templateresolver "github.com/soapbucket/sbproxy/internal/template"
)

func BenchmarkResolveSimple(b *testing.B) {
	b.ReportAllocs()

	req := httptest.NewRequest("GET", "/test/path", nil)
	req.Header.Set("Content-Type", "application/json")

	rd := &reqctx.RequestData{
		ID:   "bench-id",
		Data: map[string]any{"key": "value"},
	}
	ctx := reqctx.SetRequestData(req.Context(), rd)
	req = req.WithContext(ctx)

	// Warm cache
	templateresolver.Resolve("{{request.method}}", req)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		templateresolver.Resolve("{{request.method}}", req)
	}
}

func BenchmarkResolveCacheHit(b *testing.B) {
	b.ReportAllocs()

	req := httptest.NewRequest("GET", "/test/path?q=1", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "BenchBrowser")

	rd := &reqctx.RequestData{
		ID:   "bench-id",
		Data: map[string]any{"user": "alice"},
		Config: map[string]any{
			"config_id": "bench-config",
		},
	}
	ctx := reqctx.SetRequestData(req.Context(), rd)
	req = req.WithContext(ctx)

	tmpl := "Method: {{request.method}}, Path: {{request.path}}, User: {{request.data.user}}"
	// Warm cache
	templateresolver.Resolve(tmpl, req)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		templateresolver.Resolve(tmpl, req)
	}
}

func BenchmarkResolveWithContext(b *testing.B) {
	b.ReportAllocs()

	ctx := map[string]any{
		"name":    "Alice",
		"role":    "admin",
		"version": "1.0",
	}
	tmpl := "User: {{name}}, Role: {{role}}, Version: {{version}}"

	// Warm cache
	templateresolver.ResolveWithContext(tmpl, ctx)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		templateresolver.ResolveWithContext(tmpl, ctx)
	}
}

func BenchmarkResolveStaticText(b *testing.B) {
	b.ReportAllocs()

	req := httptest.NewRequest("GET", "/test", nil)
	rd := &reqctx.RequestData{ID: "bench"}
	ctx := reqctx.SetRequestData(req.Context(), rd)
	req = req.WithContext(ctx)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		templateresolver.Resolve("no templates here, just static text", req)
	}
}

func BenchmarkBuildContextFull(b *testing.B) {
	b.ReportAllocs()

	req := httptest.NewRequest("GET", "/test/path?q=search", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "BenchBrowser/1.0")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US")
	req.RemoteAddr = "192.168.1.1:1234"

	rd := &reqctx.RequestData{
		ID:     "bench-id",
		Config: map[string]any{"config_id": "bench-config"},
		Data:   map[string]any{"key": "value"},
		Variables: map[string]any{
			"env": "production",
		},
		SessionData: &reqctx.SessionData{
			ID:   "session-123",
			Data: map[string]any{"logged_in": true},
			AuthData: &reqctx.AuthData{
				Type: "jwt",
				Data: map[string]any{"user_id": "u-123"},
			},
		},
		Location: &reqctx.Location{
			Country:     "US",
			CountryCode: "US",
		},
		UserAgent: &reqctx.UserAgent{
			Family: "Chrome",
			Major:  "120",
		},
	}
	ctx := reqctx.SetRequestData(req.Context(), rd)
	req = req.WithContext(ctx)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		templateresolver.BuildContext(req)
	}
}

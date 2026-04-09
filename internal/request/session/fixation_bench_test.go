package session

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func BenchmarkFixationPrevention_ShouldRegenerate_NoSession(b *testing.B) {
	b.ReportAllocs()
	fp := NewFixationPrevention(FixationPreventionConfig{
		Enabled:           true,
		RegenerateOnLogin: true,
	}, nil)
	req := httptest.NewRequest("GET", "/api/test", nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fp.ShouldRegenerate(req)
	}
}

func BenchmarkFixationPrevention_ShouldRegenerate_WithSession(b *testing.B) {
	b.ReportAllocs()
	fp := NewFixationPrevention(FixationPreventionConfig{
		Enabled:           true,
		RegenerateOnLogin: true,
	}, nil)
	rd := reqctx.NewRequestData()
	rd.SessionData = &reqctx.SessionData{
		ID:        "test-session-id",
		CreatedAt: time.Now(),
		AuthData:  &reqctx.AuthData{},
	}
	ctx := reqctx.SetRequestData(context.Background(), rd)
	req := httptest.NewRequest("GET", "/api/test", nil)
	req = req.WithContext(ctx)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fp.ShouldRegenerate(req)
	}
}

func BenchmarkFixationPrevention_ShouldRegenerate_IntervalCheck(b *testing.B) {
	b.ReportAllocs()
	fp := NewFixationPrevention(FixationPreventionConfig{
		Enabled:            true,
		RegenerateOnLogin:  true,
		RegenerateInterval: 15 * time.Minute,
	}, nil)
	rd := reqctx.NewRequestData()
	rd.SessionData = &reqctx.SessionData{
		ID:        "test-session-id",
		CreatedAt: time.Now(),
		Data: map[string]any{
			"__last_regen": time.Now().UTC().Format(time.RFC3339),
		},
	}
	ctx := reqctx.SetRequestData(context.Background(), rd)
	req := httptest.NewRequest("GET", "/api/test", nil)
	req = req.WithContext(ctx)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fp.ShouldRegenerate(req)
	}
}

func BenchmarkFixationPrevention_ShouldRegenerate_Disabled(b *testing.B) {
	b.ReportAllocs()
	fp := NewFixationPrevention(FixationPreventionConfig{
		Enabled: false,
	}, nil)
	req := httptest.NewRequest("GET", "/api/test", nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fp.ShouldRegenerate(req)
	}
}

package config

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func BenchmarkConfigServeHTTP_CompiledHandler(b *testing.B) {
	b.ReportAllocs()

	cfg := &Config{
		ID: "bench-cfg",
		action: &stubAction{
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}),
		},
		policies: []PolicyConfig{
			&stubPolicy{},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		cfg.ServeHTTP(rr, req)
	}
}

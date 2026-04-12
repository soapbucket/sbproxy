package logging_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/soapbucket/sbproxy/internal/observe/logging"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func BenchmarkRequestLoggerMiddleware(b *testing.B) {
	b.ReportAllocs()

	logger := zap.NewNop()
	cfg := &logging.RequestLoggingConfig{Enabled: true}
	handler := logging.RequestLoggerMiddlewareZap(logger, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest("GET", "/test/path", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "BenchBrowser")
	req.RemoteAddr = "192.168.1.1:1234"

	rd := &reqctx.RequestData{
		ID:     "bench-id",
		Config: map[string]any{"config_id": "bench-config"},
	}
	ctx := reqctx.SetRequestData(req.Context(), rd)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(w, req)
	}
}

package requestdata_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/request/data"
)

func BenchmarkRequestDataMiddleware(b *testing.B) {
	b.ReportAllocs()

	handler := requestdata.RequestDataMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Create fresh request each iteration because the middleware mutates headers
		req := httptest.NewRequest("GET", "/test", nil)
		handler.ServeHTTP(w, req)
	}
}

func BenchmarkNewRequestData(b *testing.B) {
	b.ReportAllocs()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = requestdata.NewRequestData("test-id-123", 0)
	}
}

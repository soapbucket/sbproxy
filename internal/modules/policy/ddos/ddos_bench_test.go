package ddos

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newBenchEnforcer creates a DDoS enforcer configured for benchmarking.
func newBenchEnforcer(b *testing.B) *ddosPolicy {
	b.Helper()

	cfg := map[string]interface{}{
		"type":     "ddos_protection",
		"disabled": false,
		"detection": map[string]interface{}{
			"request_rate_threshold":    1000000, // very high to avoid triggering blocks
			"connection_rate_threshold": 1000000,
			"detection_window":          "60s",
		},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		b.Fatalf("failed to marshal config: %v", err)
	}

	enforcer, err := New(data)
	if err != nil {
		b.Fatalf("failed to create enforcer: %v", err)
	}
	return enforcer.(*ddosPolicy)
}

// BenchmarkDDoSEnforce measures single-request enforcement throughput.
func BenchmarkDDoSEnforce(b *testing.B) {
	dp := newBenchEnforcer(b)

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := dp.Enforce(okHandler)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

// BenchmarkDDoSConcurrent measures concurrent enforcement throughput.
func BenchmarkDDoSConcurrent(b *testing.B) {
	dp := newBenchEnforcer(b)

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := dp.Enforce(okHandler)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = "10.0.0.1:12345"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}
	})
}

// BenchmarkDDoSEnforce_Disabled measures enforcement when policy is disabled.
func BenchmarkDDoSEnforce_Disabled(b *testing.B) {
	cfg := map[string]interface{}{
		"type":     "ddos_protection",
		"disabled": true,
	}
	data, _ := json.Marshal(cfg)
	enforcer, err := New(data)
	if err != nil {
		b.Fatalf("failed to create enforcer: %v", err)
	}
	dp := enforcer.(*ddosPolicy)

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := dp.Enforce(okHandler)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

// BenchmarkDDoSEnforce_MultipleIPs measures enforcement with many distinct IPs.
func BenchmarkDDoSEnforce_MultipleIPs(b *testing.B) {
	dp := newBenchEnforcer(b)

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := dp.Enforce(okHandler)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ip := "10.0." + string(rune('0'+i%10)) + "." + string(rune('0'+i%10)) + ":12345"
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = ip
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

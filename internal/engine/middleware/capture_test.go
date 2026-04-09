package middleware

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/app/capture"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/platform/messenger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestCaptureManager(t *testing.T) *capture.Manager {
	t.Helper()

	msg, err := messenger.NewMessenger(messenger.Settings{Driver: messenger.DriverMemory})
	require.NoError(t, err)

	cache, err := cacher.NewCacher(cacher.Settings{Driver: cacher.DriverMemory})
	require.NoError(t, err)

	ctx := context.Background()
	mgr := capture.NewManager(ctx, msg, cache)

	t.Cleanup(func() {
		mgr.Close()
		msg.Close()
		cache.Close()
	})

	return mgr
}

func TestCaptureMiddleware_BasicCapture(t *testing.T) {
	mgr := newTestCaptureManager(t)
	cfg := &reqctx.TrafficCaptureConfig{
		Enabled:     true,
		SampleRate:  1.0,
		MaxBodySize: "10kb",
		Retention:   "1h",
	}

	hostname := "capture-test.example.com"

	// Create a simple handler that returns 200 with a body
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"hello"}`))
	})

	handler := CaptureMiddleware(mgr, cfg, hostname)(inner)

	// Create a request with body
	body := bytes.NewBufferString(`{"input":"test"}`)
	req := httptest.NewRequest("POST", "https://capture-test.example.com/api/test", body)
	req.Header.Set("Content-Type", "application/json")

	// Set up request data in context
	requestData := reqctx.NewRequestData()
	requestData.ID = "test-request-id"
	requestData.Config = map[string]any{
		"config_id": "test-config",
		"workspace_id": "test-tenant",
	}
	ctx := reqctx.SetRequestData(req.Context(), requestData)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Verify the response passed through correctly
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, `{"message":"hello"}`, rr.Body.String())

	// Wait for capture processing
	time.Sleep(300 * time.Millisecond)

	// Verify exchange was captured
	exchanges, err := mgr.List(context.Background(), hostname, capture.ListOptions{Limit: 10})
	require.NoError(t, err)
	require.Len(t, exchanges, 1)

	ex := exchanges[0]
	assert.Equal(t, "POST", ex.Request.Method)
	assert.Equal(t, "/api/test", ex.Request.Path)
	assert.Equal(t, 200, ex.Response.StatusCode)
	assert.Equal(t, `{"message":"hello"}`, string(ex.Response.Body))
	assert.Contains(t, string(ex.Request.Body), `{"input":"test"}`)
	assert.Equal(t, "test-request-id", ex.Meta["request_id"])
	assert.Equal(t, "test-config", ex.Meta["config_id"])
	assert.True(t, ex.Duration > 0, "duration should be positive")
}

func TestCaptureMiddleware_Disabled(t *testing.T) {
	mgr := newTestCaptureManager(t)
	cfg := &reqctx.TrafficCaptureConfig{
		Enabled: false,
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := CaptureMiddleware(mgr, cfg, "disabled.example.com")(inner)

	req := httptest.NewRequest("GET", "https://disabled.example.com/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	// No exchanges should be captured
	time.Sleep(100 * time.Millisecond)
	exchanges, err := mgr.List(context.Background(), "disabled.example.com", capture.ListOptions{Limit: 10})
	require.NoError(t, err)
	assert.Empty(t, exchanges)
}

func TestCaptureMiddleware_BodyTruncation(t *testing.T) {
	mgr := newTestCaptureManager(t)
	cfg := &reqctx.TrafficCaptureConfig{
		Enabled:     true,
		SampleRate:  1.0,
		MaxBodySize: "50",  // 50 bytes
		Retention:   "1h",
	}

	hostname := "truncate-test.example.com"

	// Handler returns a large body
	largeBody := bytes.Repeat([]byte("x"), 200)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(largeBody)
	})

	handler := CaptureMiddleware(mgr, cfg, hostname)(inner)

	// Request with large body
	reqBody := bytes.Repeat([]byte("y"), 200)
	req := httptest.NewRequest("POST", "https://"+hostname+"/api/test", bytes.NewReader(reqBody))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Verify the full response was sent to the client
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Len(t, rr.Body.Bytes(), 200)

	// Wait for capture
	time.Sleep(300 * time.Millisecond)

	exchanges, err := mgr.List(context.Background(), hostname, capture.ListOptions{Limit: 10})
	require.NoError(t, err)
	require.Len(t, exchanges, 1)

	ex := exchanges[0]

	// Large request body should not be captured to avoid mutating downstream semantics.
	assert.True(t, ex.Request.Truncated, "request metadata should mark oversized request body")
	assert.Nil(t, ex.Request.Body, "oversized request body should not be captured")

	// Response body should be truncated
	assert.True(t, ex.Response.Truncated, "response body should be truncated")
	assert.Len(t, ex.Response.Body, 50, "response body should be truncated to 50 bytes")
}

func TestCaptureMiddleware_RequestBodyPreserved(t *testing.T) {
	mgr := newTestCaptureManager(t)
	cfg := &reqctx.TrafficCaptureConfig{
		Enabled:     true,
		SampleRate:  1.0,
		MaxBodySize: "10kb",
		Retention:   "1h",
	}

	hostname := "preserve-test.example.com"
	bodyContent := `{"preserved":"yes"}`

	// Inner handler reads the body — must still work after capture middleware
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// The body should still be readable
		if string(body) != bodyContent {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("body preserved"))
	})

	handler := CaptureMiddleware(mgr, cfg, hostname)(inner)

	req := httptest.NewRequest("POST", "https://"+hostname+"/api/test", bytes.NewBufferString(bodyContent))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// The inner handler should have been able to read the body
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "body preserved", rr.Body.String())
}

func TestCaptureMiddleware_OversizedRequestBodyPreserved(t *testing.T) {
	mgr := newTestCaptureManager(t)
	cfg := &reqctx.TrafficCaptureConfig{
		Enabled:     true,
		SampleRate:  1.0,
		MaxBodySize: "32",
		Retention:   "1h",
	}

	hostname := "oversize-preserve-test.example.com"
	bodyContent := string(bytes.Repeat([]byte("z"), 128))

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if string(body) != bodyContent {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := CaptureMiddleware(mgr, cfg, hostname)(inner)

	req := httptest.NewRequest("POST", "https://"+hostname+"/api/test", bytes.NewBufferString(bodyContent))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestCaptureMiddleware_SampleRate(t *testing.T) {
	mgr := newTestCaptureManager(t)
	cfg := &reqctx.TrafficCaptureConfig{
		Enabled:     true,
		SampleRate:  -1, // Negative = 0% after parsing — no captures
		MaxBodySize: "10kb",
		Retention:   "1h",
	}

	hostname := "sample-test.example.com"

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := CaptureMiddleware(mgr, cfg, hostname)(inner)

	// Send 100 requests
	for range 100 {
		req := httptest.NewRequest("GET", "https://"+hostname+"/", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	}

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	// With 0% sample rate (negative clamped to 0), nothing should be captured
	exchanges, err := mgr.List(context.Background(), hostname, capture.ListOptions{Limit: 1000})
	require.NoError(t, err)
	assert.Empty(t, exchanges)
}

func TestCaptureMiddleware_LowSampleRate(t *testing.T) {
	mgr := newTestCaptureManager(t)
	cfg := &reqctx.TrafficCaptureConfig{
		Enabled:     true,
		SampleRate:  0.01, // 1% capture rate
		MaxBodySize: "10kb",
		Retention:   "1h",
	}

	hostname := "lowsample-test.example.com"

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := CaptureMiddleware(mgr, cfg, hostname)(inner)

	// Send 1000 requests
	for range 1000 {
		req := httptest.NewRequest("GET", "https://"+hostname+"/", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
	}

	time.Sleep(500 * time.Millisecond)

	// With 1% sample rate and 1000 requests, we should have ~10 captures (±15)
	exchanges, err := mgr.List(context.Background(), hostname, capture.ListOptions{Limit: 1000})
	require.NoError(t, err)
	t.Logf("captured %d out of 1000 requests with 1%% sample rate", len(exchanges))
	assert.True(t, len(exchanges) < 100, "should capture far fewer than 100 exchanges with 1%% rate")
	// With statistical sampling, we don't assert exact numbers
}

func TestCaptureMiddleware_NilConfig(t *testing.T) {
	mgr := newTestCaptureManager(t)

	// Nil config should be a no-op
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := CaptureMiddleware(mgr, nil, "nil.example.com")(inner)

	req := httptest.NewRequest("GET", "https://nil.example.com/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestRecorder_Flush(t *testing.T) {
	inner := httptest.NewRecorder()
	rec := acquireRecorder(inner, 1024)
	defer releaseRecorder(rec)

	rec.WriteHeader(http.StatusOK)
	rec.Write([]byte("hello"))
	rec.Flush() // Should not panic

	assert.Equal(t, http.StatusOK, rec.statusCode)
	assert.Equal(t, int64(5), rec.bodySize)
}

func TestRecorder_DoubleWriteHeader(t *testing.T) {
	inner := httptest.NewRecorder()
	rec := acquireRecorder(inner, 1024)
	defer releaseRecorder(rec)

	rec.WriteHeader(http.StatusOK)
	rec.WriteHeader(http.StatusNotFound) // Should be ignored

	assert.Equal(t, http.StatusOK, rec.statusCode)
}

func BenchmarkCaptureMiddleware(b *testing.B) {
	b.ReportAllocs()
	msg, _ := messenger.NewMessenger(messenger.Settings{Driver: messenger.DriverNoop})
	cache, _ := cacher.NewCacher(cacher.Settings{Driver: cacher.DriverMemory})
	ctx := context.Background()
	mgr := capture.NewManager(ctx, msg, cache, capture.WithBufferSize(524288))
	defer mgr.Close()

	cfg := &reqctx.TrafficCaptureConfig{
		Enabled:     true,
		SampleRate:  1.0,
		MaxBodySize: "10kb",
		Retention:   "1h",
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	handler := CaptureMiddleware(mgr, cfg, "bench.example.com")(inner)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest("GET", "https://bench.example.com/api/test", nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
		}
	})
}

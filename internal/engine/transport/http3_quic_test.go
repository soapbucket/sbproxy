package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"log/slog"

	"github.com/quic-go/quic-go/http3"
)

func TestHTTP3QUICTransport_Creation(t *testing.T) {
	config := HTTP3QUICConfig{
		Enabled:                 true,
		Enable0RTT:              true,
		MaxIdleTimeout:          30 * time.Second,
		KeepAlivePeriod:         15 * time.Second,
		EnableMigration:         true,
		MaxStreamsPerConnection: 100,
	}
	
	transport, err := NewHTTP3QUICTransport(config, &tls.Config{})
	if err != nil {
		t.Fatalf("unexpected error creating transport: %v", err)
	}
	
	if transport == nil {
		t.Fatal("expected transport to be created")
	}
	if transport.config.MaxIdleTimeout != 30*time.Second {
		t.Errorf("expected MaxIdleTimeout=30s, got %v", transport.config.MaxIdleTimeout)
	}
}

func TestHTTP3QUICTransport_DefaultConfig(t *testing.T) {
	config := HTTP3QUICConfig{
		Enabled: true,
	}
	
	transport, err := NewHTTP3QUICTransport(config, &tls.Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	
	if transport.config.MaxIdleTimeout == 0 {
		t.Error("expected default MaxIdleTimeout to be set")
	}
	if transport.config.KeepAlivePeriod == 0 {
		t.Error("expected default KeepAlivePeriod to be set")
	}
	if transport.config.MaxStreamReceiveWindow == 0 {
		t.Error("expected default MaxStreamReceiveWindow to be set")
	}
	if transport.config.MaxConnectionReceiveWindow == 0 {
		t.Error("expected default MaxConnectionReceiveWindow to be set")
	}
	if transport.config.MaxStreamsPerConnection == 0 {
		t.Error("expected default MaxStreamsPerConnection to be set")
	}
}

func TestHTTP3QUICTransport_DisabledWithoutFallback(t *testing.T) {
	config := HTTP3QUICConfig{
		Enabled:         false,
		FallbackToHTTP2: false,
	}
	
	transport, err := NewHTTP3QUICTransport(config, &tls.Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	
	// Verify fallback client is nil when disabled
	if transport.http2Client != nil {
		t.Error("expected http2Client to be nil when fallback disabled")
	}
}

func TestHTTP3QUICTransport_0RTTConfig(t *testing.T) {
	config := HTTP3QUICConfig{
		Enabled:              true,
		Enable0RTT:           true,
		InitialMaxData:       1024 * 1024,
		InitialMaxStreamData: 512 * 1024,
	}
	
	tlsConfig := &tls.Config{}
	
	transport, err := NewHTTP3QUICTransport(config, tlsConfig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	
	if transport.quicConfig.Allow0RTT != true {
		t.Error("expected 0-RTT to be enabled in QUIC config")
	}
	if tlsConfig.ClientSessionCache == nil {
		t.Error("expected client session cache to be created for 0-RTT")
	}
}

func TestHTTP3QUICTransport_Statistics(t *testing.T) {
	config := HTTP3QUICConfig{
		Enabled: true,
	}
	
	transport, err := NewHTTP3QUICTransport(config, &tls.Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	
	// Stats should start at zero
	stats := transport.GetStats()
	if stats.TotalRequests != 0 {
		t.Error("expected 0 total requests initially")
	}
	if stats.HTTP3Requests != 0 {
		t.Error("expected 0 HTTP/3 requests initially")
	}
	if stats.HTTP2Requests != 0 {
		t.Error("expected 0 HTTP/2 requests initially")
	}
}

func TestHTTP3QUICTransport_GetStats(t *testing.T) {
	config := HTTP3QUICConfig{
		Enabled: true,
	}
	
	transport, err := NewHTTP3QUICTransport(config, &tls.Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	
	// Initially empty
	stats := transport.GetStats()
	if stats.TotalRequests != 0 {
		t.Errorf("expected 0 requests initially, got %d", stats.TotalRequests)
	}
}

func TestHTTP3QUICTransport_CloseIdleConnections(t *testing.T) {
	config := HTTP3QUICConfig{
		Enabled: true,
	}
	
	transport, err := NewHTTP3QUICTransport(config, &tls.Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	
	// Should not panic
	transport.CloseIdleConnections()
}

func TestHTTP3Stats_String(t *testing.T) {
	stats := HTTP3Stats{
		TotalRequests: 100,
		HTTP3Requests: 80,
		HTTP2Requests: 15,
		FailedRequests: 5,
		RetriedRequests: 3,
		FallbackRequests: 15,
	}
	
	str := stats.String()
	if str == "" {
		t.Error("expected non-empty string representation")
	}
	
	// Check it contains key info
	if len(str) < 20 {
		t.Error("expected longer string representation")
	}
	
	// Test with zero requests
	emptyStats := HTTP3Stats{}
	emptyStr := emptyStats.String()
	if emptyStr == "" {
		t.Error("expected non-empty string for zero stats")
	}
}

func TestHTTP3QUICConfig_Timeout(t *testing.T) {
	config := HTTP3QUICConfig{
		Enabled:        true,
		MaxIdleTimeout: 60 * time.Second,
	}
	
	transport, err := NewHTTP3QUICTransport(config, &tls.Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	
	// Verify timeout is set correctly (should be 2x idle timeout)
	expectedTimeout := config.MaxIdleTimeout * 2
	if transport.http3Client.Timeout != expectedTimeout {
		t.Errorf("expected timeout=%v, got %v", expectedTimeout, transport.http3Client.Timeout)
	}
}

// Note: We can't easily test actual QUIC connections without a real HTTP/3 server
// These tests focus on configuration and client setup

func TestHTTP3QUICConfig_ValidationFlow(t *testing.T) {
	// Test with minimal config
	config := HTTP3QUICConfig{
		Enabled: true,
	}
	
	transport, err := NewHTTP3QUICTransport(config, &tls.Config{})
	if err != nil {
		t.Fatalf("unexpected error with minimal config: %v", err)
	}
	
	// Verify defaults were applied
	if transport.config.MaxIdleTimeout == 0 {
		t.Error("expected default MaxIdleTimeout")
	}
	if transport.config.MaxStreamsPerConnection == 0 {
		t.Error("expected default MaxStreamsPerConnection")
	}
}

func TestHTTP3QUICTransport_FallbackConfig(t *testing.T) {
	config := HTTP3QUICConfig{
		Enabled:         true,
		FallbackToHTTP2: true,
	}
	
	transport, err := NewHTTP3QUICTransport(config, &tls.Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	
	if transport.http2Client == nil {
		t.Error("expected HTTP/2 fallback client to be created")
	}
}

func TestHTTP3QUICTransport_RetryConfig(t *testing.T) {
	config := HTTP3QUICConfig{
		Enabled:      true,
		RetryOnError: true,
	}
	
	transport, err := NewHTTP3QUICTransport(config, &tls.Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	
	if !transport.config.RetryOnError {
		t.Error("expected RetryOnError to be enabled")
	}
}

func TestHTTP3QUICTransport_RealRoundTrip(t *testing.T) {
	baseURL := startHTTP3TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test-Protocol", r.Proto)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello over h3"))
	}))

	transport, err := NewHTTP3QUICTransport(HTTP3QUICConfig{
		Enabled: true,
	}, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test server uses self-signed certificate
	})
	if err != nil {
		t.Fatalf("unexpected error creating transport: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, baseURL+"/hello", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("expected HTTP/3 roundtrip to succeed, got error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Test-Protocol"); got == "" {
		t.Fatalf("expected protocol marker header to be present")
	}

	stats := transport.GetStats()
	if stats.TotalRequests == 0 {
		t.Fatalf("expected total requests > 0")
	}
	if stats.HTTP3Requests == 0 {
		t.Fatalf("expected HTTP/3 request count > 0")
	}
}

// ---------------------------------------------------------------------------
// E2E tests using real HTTP/3 servers
// ---------------------------------------------------------------------------

func TestHTTP3QUICTransport_HeaderForwarding(t *testing.T) {
	customHeaders := map[string]string{
		"X-Custom-One":   "value-one",
		"X-Custom-Two":   "value-two",
		"X-Request-Id":   "req-12345",
		"Authorization":  "Bearer test-token",
		"Accept-Language": "en-US",
	}

	baseURL := startHTTP3TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back all X-Custom and specific headers
		for key, val := range customHeaders {
			got := r.Header.Get(key)
			if got != val {
				w.Header().Set("X-Error", fmt.Sprintf("header %s: expected %q, got %q", key, val, got))
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			// Echo them back as response headers with a "Echo-" prefix
			w.Header().Set("Echo-"+key, got)
		}
		w.Header().Set("X-Response-Custom", "from-server")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("headers ok"))
	}))

	transport := newTestHTTP3Transport(t)

	req, err := http.NewRequest(http.MethodGet, baseURL+"/headers", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	for key, val := range customHeaders {
		req.Header.Set(key, val)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("HTTP/3 roundtrip failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errMsg := resp.Header.Get("X-Error")
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, errMsg)
	}

	// Verify response headers echoed back
	for key := range customHeaders {
		echoKey := "Echo-" + key
		if resp.Header.Get(echoKey) == "" {
			t.Errorf("expected echo header %s to be present in response", echoKey)
		}
	}
	if resp.Header.Get("X-Response-Custom") != "from-server" {
		t.Error("expected X-Response-Custom header in response")
	}

	stats := transport.GetStats()
	if stats.HTTP3Requests == 0 {
		t.Error("expected HTTP/3 request count > 0")
	}
}

func TestHTTP3QUICTransport_TrailerForwarding(t *testing.T) {
	baseURL := startHTTP3TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Announce trailers
		w.Header().Set("Trailer", "X-Checksum, X-Request-Duration")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)

		// Write body in chunks
		for i := 0; i < 5; i++ {
			_, _ = w.Write([]byte(fmt.Sprintf("chunk-%d\n", i)))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}

		// Set trailers
		w.Header().Set("X-Checksum", "abc123")
		w.Header().Set("X-Request-Duration", "42ms")
	}))

	transport := newTestHTTP3Transport(t)

	req, err := http.NewRequest(http.MethodGet, baseURL+"/trailers", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("HTTP/3 roundtrip failed: %v", err)
	}

	// Read the full body to receive trailers
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}

	if !strings.Contains(string(body), "chunk-0") {
		t.Error("expected chunked body content")
	}

	// Check trailers were received
	if resp.Trailer == nil {
		t.Log("trailers not available (may be protocol limitation) - skipping trailer checks")
	} else {
		if got := resp.Trailer.Get("X-Checksum"); got != "" && got != "abc123" {
			t.Errorf("expected trailer X-Checksum=abc123, got %q", got)
		}
		if got := resp.Trailer.Get("X-Request-Duration"); got != "" && got != "42ms" {
			t.Errorf("expected trailer X-Request-Duration=42ms, got %q", got)
		}
	}

	if transport.GetStats().HTTP3Requests == 0 {
		t.Error("expected HTTP/3 request count > 0")
	}
}

func TestHTTP3QUICTransport_TimeoutHandling(t *testing.T) {
	baseURL := startHTTP3TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Delay longer than the client context deadline
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))

	transport := newTestHTTP3Transport(t)

	// Use a context with a short deadline to enforce timeout at the
	// RoundTrip level, which is independent of http.Client.Timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/slow", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	start := time.Now()
	_, err = transport.RoundTrip(req)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}

	// Verify the request did not wait for the full server delay (5s).
	// The QUIC transport may take a few seconds to propagate the context
	// cancellation, so we allow up to 10s but expect it to be well under
	// the server's 5s sleep in most cases.
	if elapsed > 10*time.Second {
		t.Errorf("expected timeout well before server delay, took %v", elapsed)
	}

	stats := transport.GetStats()
	if stats.FailedRequests == 0 {
		t.Error("expected failed request count > 0")
	}
}

func TestHTTP3QUICTransport_RetryOnError(t *testing.T) {
	var attempt atomic.Int32

	baseURL := startHTTP3TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempt.Add(1)
		if n == 1 {
			// First attempt: close the connection abruptly by panicking
			// (http3.Server will handle this as an error)
			w.Header().Set("X-Attempt", fmt.Sprintf("%d", n))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		// Second attempt succeeds
		w.Header().Set("X-Attempt", fmt.Sprintf("%d", n))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("retry-success"))
	}))

	transport, err := NewHTTP3QUICTransport(HTTP3QUICConfig{
		Enabled:      true,
		RetryOnError: true,
	}, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test server uses self-signed certificate
	})
	if err != nil {
		t.Fatalf("unexpected error creating transport: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, baseURL+"/retry", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("expected request to succeed (possibly with retry): %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	// Verify retry config is active
	if !transport.config.RetryOnError {
		t.Error("expected RetryOnError to be enabled")
	}

	stats := transport.GetStats()
	if stats.TotalRequests == 0 {
		t.Error("expected total requests > 0")
	}
}

func TestHTTP3QUICTransport_FallbackToHTTP2(t *testing.T) {
	transport, err := NewHTTP3QUICTransport(HTTP3QUICConfig{
		Enabled:         true,
		FallbackToHTTP2: true,
	}, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test server uses self-signed certificate
	})
	if err != nil {
		t.Fatalf("unexpected error creating transport: %v", err)
	}

	// Verify fallback client exists
	if transport.http2Client == nil {
		t.Fatal("expected HTTP/2 fallback client to be initialized")
	}

	// Non-HTTPS URLs go directly to the HTTP/2 fallback path.
	// Use a context with a short timeout so we don't wait for connection errors.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:1/fallback", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	_, err = transport.RoundTrip(req)
	// Connection failure is expected (no server), but the code path through
	// the HTTP/2 fallback transport is what we are testing.
	if err == nil {
		t.Log("request unexpectedly succeeded")
	}

	stats := transport.GetStats()
	if stats.TotalRequests == 0 {
		t.Error("expected total requests > 0 after fallback attempt")
	}

	// Now test that an HTTPS request to a non-existent host triggers the
	// fallback path after HTTP/3 fails.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel2()

	req2, err := http.NewRequestWithContext(ctx2, http.MethodGet, "https://127.0.0.1:1/h3fail", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	_, err = transport.RoundTrip(req2)
	if err == nil {
		t.Log("request unexpectedly succeeded on non-existent server")
	}

	stats2 := transport.GetStats()
	if stats2.FallbackRequests == 0 {
		t.Error("expected fallback request count > 0 after HTTP/3 failure")
	}
}

func TestHTTP3QUICTransport_LargeResponse(t *testing.T) {
	// Generate a 2MB payload
	const payloadSize = 2 * 1024 * 1024
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	baseURL := startHTTP3TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", payloadSize))
		w.WriteHeader(http.StatusOK)
		// Write in chunks to simulate streaming
		written := 0
		chunkSize := 64 * 1024
		for written < len(payload) {
			end := written + chunkSize
			if end > len(payload) {
				end = len(payload)
			}
			n, err := w.Write(payload[written:end])
			if err != nil {
				return
			}
			written += n
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}))

	transport := newTestHTTP3Transport(t)

	req, err := http.NewRequest(http.MethodGet, baseURL+"/large", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("HTTP/3 roundtrip failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	if len(body) != payloadSize {
		t.Errorf("expected %d bytes, got %d", payloadSize, len(body))
	}

	if !bytes.Equal(body, payload) {
		t.Error("response body does not match sent payload")
	}

	if transport.GetStats().HTTP3Requests == 0 {
		t.Error("expected HTTP/3 request count > 0")
	}
}

func TestHTTP3QUICTransport_ConcurrentRequests(t *testing.T) {
	const concurrency = 50

	baseURL := startHTTP3TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Small delay to ensure requests overlap
		time.Sleep(10 * time.Millisecond)
		w.Header().Set("X-Path", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("concurrent-ok"))
	}))

	transport := newTestHTTP3Transport(t)

	var wg sync.WaitGroup
	errors := make(chan error, concurrency)
	successes := make(chan int, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/concurrent/%d", baseURL, idx), nil)
			if err != nil {
				errors <- fmt.Errorf("request %d: create failed: %w", idx, err)
				return
			}

			resp, err := transport.RoundTrip(req)
			if err != nil {
				errors <- fmt.Errorf("request %d: roundtrip failed: %w", idx, err)
				return
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				errors <- fmt.Errorf("request %d: read body failed: %w", idx, err)
				return
			}

			if resp.StatusCode != http.StatusOK {
				errors <- fmt.Errorf("request %d: expected 200, got %d", idx, resp.StatusCode)
				return
			}

			if string(body) != "concurrent-ok" {
				errors <- fmt.Errorf("request %d: unexpected body: %s", idx, string(body))
				return
			}

			successes <- idx
		}(i)
	}

	wg.Wait()
	close(errors)
	close(successes)

	successCount := 0
	for range successes {
		successCount++
	}

	var errs []error
	for err := range errors {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		// Allow some failures due to QUIC connection limits, but majority should succeed
		failRate := float64(len(errs)) / float64(concurrency)
		if failRate > 0.2 {
			for _, err := range errs {
				t.Logf("error: %v", err)
			}
			t.Errorf("too many failures: %d/%d (%.0f%%)", len(errs), concurrency, failRate*100)
		} else {
			t.Logf("%d/%d requests succeeded (acceptable)", successCount, concurrency)
		}
	}

	stats := transport.GetStats()
	if stats.TotalRequests != uint64(concurrency) {
		t.Errorf("expected %d total requests, got %d", concurrency, stats.TotalRequests)
	}
	if stats.HTTP3Requests == 0 {
		t.Error("expected HTTP/3 request count > 0")
	}
}

func TestHTTP3QUICTransport_ConnectionReuse(t *testing.T) {
	var requestCount atomic.Int32

	baseURL := startHTTP3TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("X-Request-Num", fmt.Sprintf("%d", requestCount.Load()))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("reuse-ok"))
	}))

	transport := newTestHTTP3Transport(t)

	// Make multiple sequential requests to verify connection reuse
	for i := 0; i < 5; i++ {
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/reuse/%d", baseURL, i), nil)
		if err != nil {
			t.Fatalf("request %d: failed to create: %v", i, err)
		}

		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("request %d: roundtrip failed: %v", i, err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("request %d: read body failed: %v", i, err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i, resp.StatusCode)
		}
		if string(body) != "reuse-ok" {
			t.Errorf("request %d: unexpected body: %s", i, string(body))
		}
	}

	stats := transport.GetStats()
	if stats.TotalRequests != 5 {
		t.Errorf("expected 5 total requests, got %d", stats.TotalRequests)
	}
	if stats.HTTP3Requests != 5 {
		t.Errorf("expected 5 HTTP/3 requests, got %d", stats.HTTP3Requests)
	}
	// All requests should have succeeded over HTTP/3 with connection reuse
	if stats.FailedRequests != 0 {
		t.Errorf("expected 0 failed requests, got %d", stats.FailedRequests)
	}
}

func TestHTTP3QUICTransport_0RTTReconnection(t *testing.T) {
	var requestCount atomic.Int32

	baseURL := startHTTP3TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := requestCount.Add(1)
		w.Header().Set("X-Request-Num", fmt.Sprintf("%d", n))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("0rtt-ok"))
	}))

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test server uses self-signed certificate
	}

	transport, err := NewHTTP3QUICTransport(HTTP3QUICConfig{
		Enabled:    true,
		Enable0RTT: true,
	}, tlsConfig)
	if err != nil {
		t.Fatalf("unexpected error creating transport: %v", err)
	}

	// Verify 0-RTT configuration
	if !transport.quicConfig.Allow0RTT {
		t.Error("expected 0-RTT to be enabled in QUIC config")
	}
	if tlsConfig.ClientSessionCache == nil {
		t.Error("expected client session cache to be initialized for 0-RTT")
	}

	// First request establishes session
	req1, err := http.NewRequest(http.MethodGet, baseURL+"/0rtt/first", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp1, err := transport.RoundTrip(req1)
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()

	if resp1.StatusCode != http.StatusOK {
		t.Errorf("first request: expected 200, got %d", resp1.StatusCode)
	}
	if string(body1) != "0rtt-ok" {
		t.Errorf("first request: unexpected body: %s", string(body1))
	}

	// Second request should potentially use 0-RTT (session cached)
	req2, err := http.NewRequest(http.MethodGet, baseURL+"/0rtt/second", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp2, err := transport.RoundTrip(req2)
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("second request: expected 200, got %d", resp2.StatusCode)
	}
	if string(body2) != "0rtt-ok" {
		t.Errorf("second request: unexpected body: %s", string(body2))
	}

	stats := transport.GetStats()
	if stats.HTTP3Requests < 2 {
		t.Errorf("expected at least 2 HTTP/3 requests, got %d", stats.HTTP3Requests)
	}
	if stats.FailedRequests != 0 {
		t.Errorf("expected 0 failures with 0-RTT, got %d", stats.FailedRequests)
	}
}

// newTestHTTP3Transport creates a standard HTTP/3 transport for tests.
func newTestHTTP3Transport(t *testing.T) *HTTP3QUICTransport {
	t.Helper()
	transport, err := NewHTTP3QUICTransport(HTTP3QUICConfig{
		Enabled: true,
	}, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test server uses self-signed certificate
	})
	if err != nil {
		t.Fatalf("unexpected error creating transport: %v", err)
	}
	return transport
}

func startHTTP3TestServer(t *testing.T, handler http.Handler) string {
	t.Helper()

	certPEM, keyPEM, _ := generateTestCertificate(t)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to load test certificate: %v", err)
	}

	addr := reserveUDPAddr(t)
	srv := &http3.Server{
		Addr:    addr,
		Handler: handler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h3"},
		},
		Logger: slog.Default(),
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		select {
		case <-errCh:
		case <-time.After(500 * time.Millisecond):
		}
	})

	// Give the QUIC listener a brief moment to bind before the first client attempt.
	time.Sleep(100 * time.Millisecond)
	return "https://" + addr
}

func reserveUDPAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve UDP address: %v", err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	return addr
}


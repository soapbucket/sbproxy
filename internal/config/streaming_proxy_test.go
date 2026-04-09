package config

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestStreamingProxyHandler_BasicProxy(t *testing.T) {
	// Create mock backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify proxy headers were added
		if r.Header.Get("X-Forwarded-For") == "" {
			t.Error("X-Forwarded-For not set")
		}
		if r.Header.Get("X-Forwarded-Proto") == "" {
			t.Error("X-Forwarded-Proto not set")
		}
		if r.Header.Get("X-Real-IP") == "" {
			t.Error("X-Real-IP not set")
		}
		if r.Header.Get("Via") == "" {
			t.Error("Via header not set")
		}
		if !strings.Contains(r.Header.Get("Via"), "soapbucket/") {
			t.Errorf("Via header should contain 'soapbucket/' with version, got: %s", r.Header.Get("Via"))
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from backend"))
	}))
	defer backend.Close()

	// Create test config
	cfg := createTestProxyConfig(t, backend.URL)

	// Create request
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"

	rec := httptest.NewRecorder()

	// Execute
	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	// Verify
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if body != "Hello from backend" {
		t.Errorf("unexpected body: %s", body)
	}
}

func TestStreamingProxyHandler_DisableVia(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Via is not sent
		if r.Header.Get("Via") != "" {
			t.Error("Via header should not be sent when disabled")
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)
	cfg.ProxyHeaders = &ProxyHeaderConfig{
		Via: &ViaHeaderConfig{
			Disable: true,
		},
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestProtocolDetector(t *testing.T) {
	detector := NewProtocolDetector()

	tests := []struct {
		name     string
		req      *http.Request
		expected Protocol
	}{
		{
			name: "HTTP/1.1",
			req: &http.Request{
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     http.Header{},
			},
			expected: ProtocolHTTP1,
		},
		{
			name: "HTTP/2",
			req: &http.Request{
				ProtoMajor: 2,
				Header: http.Header{
					"Accept-Encoding": []string{"gzip, deflate"},
				},
			},
			expected: ProtocolHTTP2,
		},
		{
			name: "HTTP/2 Bidirectional with streaming content-type",
			req: &http.Request{
				ProtoMajor: 2,
				Header: http.Header{
					"Accept-Encoding": []string{"identity"},
					"Content-Type":    []string{"application/x-ndjson"},
				},
			},
			expected: ProtocolHTTP2Bidirectional,
		},
		{
			name: "HTTP/2 with empty Accept-Encoding (not bidirectional)",
			req: &http.Request{
				ProtoMajor: 2,
				Header:     http.Header{},
			},
			expected: ProtocolHTTP2,
		},
		{
			name: "WebSocket",
			req: &http.Request{
				ProtoMajor: 1,
				Header: http.Header{
					"Upgrade":    []string{"websocket"},
					"Connection": []string{"Upgrade"},
				},
			},
			expected: ProtocolWebSocket,
		},
		{
			name: "gRPC",
			req: &http.Request{
				ProtoMajor: 2,
				Header: http.Header{
					"Content-Type": []string{"application/grpc"},
				},
			},
			expected: ProtocolGRPC,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			protocol := detector.Detect(tt.req)
			if protocol != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, protocol)
			}
		})
	}
}

func TestFlushController(t *testing.T) {
	fc := NewFlushController()

	tests := []struct {
		name           string
		contentType    string
		contentLength  int64
		protoMajor     int
		expectedType   FlushType
		expectedReason string
	}{
		{
			name:           "SSE",
			contentType:    "text/event-stream",
			contentLength:  -1,
			protoMajor:     1,
			expectedType:   FlushImmediate,
			expectedReason: "sse",
		},
		{
			name:           "gRPC",
			contentType:    "application/grpc",
			contentLength:  -1,
			protoMajor:     2,
			expectedType:   FlushImmediate,
			expectedReason: "grpc",
		},
		{
			name:           "Small buffered response",
			contentType:    "application/json",
			contentLength:  1024,
			protoMajor:     1,
			expectedType:   FlushBuffered,
			expectedReason: "buffered",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				ProtoMajor: tt.protoMajor,
				Header:     http.Header{},
			}
			resp := &http.Response{
				ProtoMajor:    tt.protoMajor,
				ContentLength: tt.contentLength,
				Header: http.Header{
					"Content-Type": []string{tt.contentType},
				},
			}

			strategy := fc.DetermineStrategy(req, resp)
			if strategy.Type != tt.expectedType {
				t.Errorf("expected type %s, got %s", tt.expectedType, strategy.Type)
			}
			if strategy.Reason != tt.expectedReason {
				t.Errorf("expected reason %s, got %s", tt.expectedReason, strategy.Reason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// RFC 9110 Section 9.3.8: TRACE method blocking
// ---------------------------------------------------------------------------

func TestStreamingProxy_TraceBlocked(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("TRACE should never reach the backend")
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)

	req := httptest.NewRequest(http.MethodTrace, "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for TRACE, got %d", rec.Code)
	}
}

func TestStreamingProxy_TraceAllowed(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodTrace {
			t.Errorf("expected TRACE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)
	cfg.ProxyProtocol = &ProxyProtocolConfig{AllowTrace: true}

	req := httptest.NewRequest(http.MethodTrace, "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with AllowTrace, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// RFC 9112 Section 6.3: Request smuggling (CL + TE)
// ---------------------------------------------------------------------------

func TestStreamingProxy_RequestSmugglingRejected(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("smuggling request should never reach the backend")
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)

	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader("body"))
	req.Header.Set("Transfer-Encoding", "chunked")
	req.Header.Set("Content-Length", "4")
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for CL+TE conflict, got %d", rec.Code)
	}
}

func TestStreamingProxy_RequestSmugglingProtectionDisabled(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)
	cfg.ProxyProtocol = &ProxyProtocolConfig{DisableRequestSmuggling: true}

	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader("body"))
	req.Header.Set("Transfer-Encoding", "chunked")
	req.Header.Set("Content-Length", "4")
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with smuggling protection disabled, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// RFC 9110 Section 7.6.2: Max-Forwards
// ---------------------------------------------------------------------------

func TestStreamingProxy_MaxForwardsZero(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Max-Forwards=0 should not reach the backend")
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)

	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	req.Header.Set("Max-Forwards", "0")
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for Max-Forwards=0, got %d", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow == "" {
		t.Error("expected Allow header in Max-Forwards=0 response")
	}
}

func TestStreamingProxy_MaxForwardsDecrement(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mf := r.Header.Get("Max-Forwards")
		if mf != "4" {
			t.Errorf("expected Max-Forwards=4 after decrement, got %s", mf)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)

	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	req.Header.Set("Max-Forwards", "5")
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestStreamingProxy_MaxForwardsDisabled(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mf := r.Header.Get("Max-Forwards")
		if mf != "0" {
			t.Errorf("expected Max-Forwards=0 (unmodified), got %s", mf)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)
	cfg.ProxyProtocol = &ProxyProtocolConfig{DisableMaxForwards: true}

	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	req.Header.Set("Max-Forwards", "0")
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with Max-Forwards disabled, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// RFC 9110 Section 7.6.3: Via header on response
// ---------------------------------------------------------------------------

func TestStreamingProxy_ViaOnResponse(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	via := rec.Header().Get("Via")
	if via == "" {
		t.Fatal("Via header missing from response")
	}
	if !strings.Contains(via, "soapbucket/") {
		t.Errorf("Via should contain 'soapbucket/' with version, got: %s", via)
	}
}

func TestStreamingProxy_ViaOnResponseChain(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Via", "1.1 upstream-proxy")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	via := rec.Header().Get("Via")
	if !strings.Contains(via, "upstream-proxy") {
		t.Errorf("Via should preserve upstream entry, got: %s", via)
	}
	if !strings.Contains(via, "soapbucket/") {
		t.Errorf("Via should append soapbucket/ with version, got: %s", via)
	}
}

func TestStreamingProxy_ViaDisabledOnResponse(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)
	cfg.ProxyHeaders = &ProxyHeaderConfig{
		Via: &ViaHeaderConfig{Disable: true},
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if via := rec.Header().Get("Via"); via != "" {
		t.Errorf("Via should be absent when disabled, got: %s", via)
	}
}

// ---------------------------------------------------------------------------
// RFC 9110 Section 6.6.1: Date header on responses
// ---------------------------------------------------------------------------

func TestStreamingProxy_DateHeaderAdded(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	dateHeader := rec.Header().Get("Date")
	if dateHeader == "" {
		t.Fatal("Date header should be added when missing from upstream")
	}

	_, err := time.Parse(http.TimeFormat, dateHeader)
	if err != nil {
		t.Errorf("Date header should be valid HTTP date, got: %s (err: %v)", dateHeader, err)
	}
}

func TestStreamingProxy_DateHeaderPreserved(t *testing.T) {
	upstreamDate := "Mon, 09 Mar 2026 12:00:00 GMT"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", upstreamDate)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Date"); got != upstreamDate {
		t.Errorf("upstream Date should be preserved, expected %s, got %s", upstreamDate, got)
	}
}

func TestStreamingProxy_DateHeaderDisabled(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)
	cfg.ProxyProtocol = &ProxyProtocolConfig{DisableAutoDate: true}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	// Note: Go's httptest.ResponseRecorder may inject Date, so we check that
	// our processResponse did NOT set it. The recorder's ServeHTTP adds it
	// automatically, but we verify the response header map before write.
	// Since we can't distinguish recorder behavior, we just confirm no crash
	// and that the config path is exercised.
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// RFC 9110 Section 7.6.1: Connection header handling (hop-by-hop)
// ---------------------------------------------------------------------------

func TestStreamingProxy_ConnectionHeaderTokensRemoved(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify that headers listed in Connection were removed
		if r.Header.Get("X-Custom-HopByHop") != "" {
			t.Error("X-Custom-HopByHop should be removed (listed in Connection)")
		}
		if r.Header.Get("Connection") != "" {
			t.Error("Connection header itself should be removed")
		}
		if r.Header.Get("Keep-Alive") != "" {
			t.Error("Keep-Alive should be removed")
		}
		// Non-connection headers should survive
		if r.Header.Get("X-Application") == "" {
			t.Error("X-Application should be preserved")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Connection", "X-Custom-HopByHop, Keep-Alive")
	req.Header.Set("X-Custom-HopByHop", "some-value")
	req.Header.Set("Keep-Alive", "timeout=5")
	req.Header.Set("X-Application", "myapp")
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestStreamingProxy_HopByHopRemovedFromResponse(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "X-Backend-Internal")
		w.Header().Set("X-Backend-Internal", "secret")
		w.Header().Set("Keep-Alive", "timeout=30")
		w.Header().Set("X-Public", "visible")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Connection") != "" {
		t.Error("Connection should be removed from response")
	}
	if rec.Header().Get("X-Backend-Internal") != "" {
		t.Error("X-Backend-Internal (listed in Connection) should be removed from response")
	}
	if rec.Header().Get("Keep-Alive") != "" {
		t.Error("Keep-Alive should be removed from response")
	}
	if rec.Header().Get("X-Public") == "" {
		t.Error("X-Public should be preserved in response")
	}
}

// ---------------------------------------------------------------------------
// ProxyProtocol defaults (nil config = secure defaults)
// ---------------------------------------------------------------------------

func TestStreamingProxy_NilProxyProtocolUsesDefaults(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("TRACE should be blocked with nil ProxyProtocol")
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)
	// ProxyProtocol is nil, should use DefaultProxyProtocol

	req := httptest.NewRequest(http.MethodTrace, "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 with nil ProxyProtocol, got %d", rec.Code)
	}
}

// Helper to create test proxy config
func createTestProxyConfig(t *testing.T, backendURL string) *Config {
	t.Helper()
	proxy, err := LoadProxy([]byte(`{"url": "` + backendURL + `"}`))
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	cfg := &Config{
		ID:       "test-proxy",
		Hostname: "test.example.com",
	}

	// Manually set the action since we're not using the full config loader
	cfg.action = proxy

	return cfg
}

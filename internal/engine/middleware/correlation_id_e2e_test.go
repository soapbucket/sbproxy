package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// TestCorrelationID_E2E_GeneratedWhenMissing verifies that a request without
// an X-Request-ID header gets one generated from the internal request ID. This
// exercises the full path: FastPathMiddleware sets the ID, CorrelationIDMiddleware
// propagates it.
func TestCorrelationID_E2E_GeneratedWhenMissing(t *testing.T) {
	const generatedID = "fast-path-generated-uuid"

	var upstreamReceivedID string

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamReceivedID = r.Header.Get(httputil.HeaderXRequestID)
		w.WriteHeader(http.StatusOK)
	})

	handler := CorrelationIDMiddleware(upstream)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/api/data", nil)
	// No X-Request-ID on the incoming request.

	// Simulate FastPathMiddleware having set the RequestData.ID.
	rd := &reqctx.RequestData{ID: generatedID}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), rd))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Response should carry the generated ID.
	respID := rr.Header().Get(httputil.HeaderXRequestID)
	if respID != generatedID {
		t.Errorf("response X-Request-ID = %q, want %q", respID, generatedID)
	}

	// Upstream should have received the same ID.
	if upstreamReceivedID != generatedID {
		t.Errorf("upstream X-Request-ID = %q, want %q", upstreamReceivedID, generatedID)
	}
}

// TestCorrelationID_E2E_PreservesClientID verifies that when a client sends a
// valid X-Request-ID, the same value is propagated to the upstream and returned
// in the response.
func TestCorrelationID_E2E_PreservesClientID(t *testing.T) {
	const clientID = "client-trace-xyz-789"

	var upstreamReceivedID string

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamReceivedID = r.Header.Get(httputil.HeaderXRequestID)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	handler := CorrelationIDMiddleware(upstream)

	req := httptest.NewRequest(http.MethodPost, "http://example.com/api/submit", nil)
	req.Header.Set(httputil.HeaderXRequestID, clientID)

	// Even though RequestData has a different internal ID, the client-provided
	// one should take precedence.
	rd := &reqctx.RequestData{ID: "internal-should-not-be-used"}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), rd))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Response header.
	if got := rr.Header().Get(httputil.HeaderXRequestID); got != clientID {
		t.Errorf("response X-Request-ID = %q, want %q", got, clientID)
	}

	// Upstream propagation.
	if upstreamReceivedID != clientID {
		t.Errorf("upstream X-Request-ID = %q, want %q", upstreamReceivedID, clientID)
	}
}

// TestCorrelationID_E2E_UpstreamReceivesSameID exercises a full proxy-like
// scenario: request -> CorrelationIDMiddleware -> simulated upstream server.
// The upstream is an httptest.Server to exercise real HTTP transport.
func TestCorrelationID_E2E_UpstreamReceivesSameID(t *testing.T) {
	const clientID = "e2e-correlation-abc"

	upstreamReceivedCh := make(chan string, 1)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamReceivedCh <- r.Header.Get(httputil.HeaderXRequestID)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Simulate the middleware setting the header, then the inner handler
	// making a call to the upstream.
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Forward the request to the upstream server, propagating headers.
		upReq, err := http.NewRequest(http.MethodGet, upstream.URL+"/backend", nil)
		if err != nil {
			t.Fatalf("failed to create upstream request: %v", err)
		}
		// Copy the correlation ID header that the middleware set.
		upReq.Header.Set(httputil.HeaderXRequestID, r.Header.Get(httputil.HeaderXRequestID))

		resp, err := http.DefaultClient.Do(upReq)
		if err != nil {
			t.Fatalf("upstream request failed: %v", err)
		}
		resp.Body.Close()

		w.WriteHeader(resp.StatusCode)
	})

	handler := CorrelationIDMiddleware(innerHandler)

	req := httptest.NewRequest(http.MethodGet, "http://proxy.example.com/forward", nil)
	req.Header.Set(httputil.HeaderXRequestID, clientID)
	rd := &reqctx.RequestData{ID: "internal-id"}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), rd))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Check the upstream received the correct ID.
	select {
	case receivedID := <-upstreamReceivedCh:
		if receivedID != clientID {
			t.Errorf("upstream received X-Request-ID = %q, want %q", receivedID, clientID)
		}
	default:
		t.Fatal("upstream did not receive the request")
	}

	// Check response header.
	if got := rr.Header().Get(httputil.HeaderXRequestID); got != clientID {
		t.Errorf("response X-Request-ID = %q, want %q", got, clientID)
	}
}

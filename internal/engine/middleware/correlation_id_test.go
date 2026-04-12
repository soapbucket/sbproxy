package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func TestCorrelationIDMiddleware_IncomingIDReused(t *testing.T) {
	incomingID := "client-trace-abc123"

	handler := CorrelationIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request header was preserved for upstream propagation.
		got := r.Header.Get(httputil.HeaderXRequestID)
		if got != incomingID {
			t.Errorf("request X-Request-ID = %q, want %q", got, incomingID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(httputil.HeaderXRequestID, incomingID)

	// Put a RequestData on context so middleware has a fallback (should not be used).
	rd := &reqctx.RequestData{ID: "internal-id"}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), rd))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Verify response header carries the client-provided ID.
	if got := rr.Header().Get(httputil.HeaderXRequestID); got != incomingID {
		t.Errorf("response X-Request-ID = %q, want %q", got, incomingID)
	}
}

func TestCorrelationIDMiddleware_FallbackToInternalID(t *testing.T) {
	internalID := "uuid-from-fastpath"

	handler := CorrelationIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get(httputil.HeaderXRequestID)
		if got != internalID {
			t.Errorf("request X-Request-ID = %q, want %q", got, internalID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rd := &reqctx.RequestData{ID: internalID}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), rd))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get(httputil.HeaderXRequestID); got != internalID {
		t.Errorf("response X-Request-ID = %q, want %q", got, internalID)
	}
}

func TestCorrelationIDMiddleware_TooLongIDRejected(t *testing.T) {
	internalID := "internal-fallback"

	// Build a string longer than maxRequestIDLength (128 chars).
	longID := make([]byte, maxRequestIDLength+1)
	for i := range longID {
		longID[i] = 'x'
	}

	handler := CorrelationIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get(httputil.HeaderXRequestID)
		if got != internalID {
			t.Errorf("request X-Request-ID = %q, want %q (long ID should be rejected)", got, internalID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(httputil.HeaderXRequestID, string(longID))
	rd := &reqctx.RequestData{ID: internalID}
	req = req.WithContext(reqctx.SetRequestData(req.Context(), rd))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get(httputil.HeaderXRequestID); got != internalID {
		t.Errorf("response X-Request-ID = %q, want %q", got, internalID)
	}
}

func TestCorrelationIDMiddleware_NoRequestData(t *testing.T) {
	// No incoming X-Request-ID and no RequestData in context.
	handler := CorrelationIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// No ID available, so no header should be set.
	if got := rr.Header().Get(httputil.HeaderXRequestID); got != "" {
		t.Errorf("response X-Request-ID should be empty, got %q", got)
	}
}

func TestCorrelationIDMiddleware_ExactMaxLength(t *testing.T) {
	// Exactly maxRequestIDLength should be accepted.
	exactID := make([]byte, maxRequestIDLength)
	for i := range exactID {
		exactID[i] = 'a'
	}

	handler := CorrelationIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get(httputil.HeaderXRequestID)
		if got != string(exactID) {
			t.Errorf("request X-Request-ID length = %d, want %d", len(got), maxRequestIDLength)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(httputil.HeaderXRequestID, string(exactID))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get(httputil.HeaderXRequestID); got != string(exactID) {
		t.Errorf("response X-Request-ID length = %d, want %d", len(got), maxRequestIDLength)
	}
}

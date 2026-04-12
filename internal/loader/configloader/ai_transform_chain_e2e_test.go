package configloader

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestAITransformChain_SSEPassthrough verifies SSE responses pass through non-SSE transforms
func TestAITransformChain_SSEPassthrough(t *testing.T) {
	resetCache()
	mock := mockOpenAIServer(t)
	defer mock.Close()
	cfg := aiProxyOriginJSON(t, "sse-xform.test", mock.URL, nil)

	r := newTestRequest(t, "POST", "http://sse-xform.test/v1/chat/completions")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hi"}],"stream":true}`))
	w := serveAIProxy(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("expected SSE content type, got %q", ct)
	}
}

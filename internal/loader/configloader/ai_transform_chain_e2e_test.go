package configloader

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// TestAITransformChain_SSEPassthrough verifies SSE responses pass through
// non-SSE transforms gracefully.
func TestAITransformChain_SSEPassthrough(t *testing.T) {
	resetCache()

	sseBody := "data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\ndata: [DONE]\n\n"

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sseBody))
	}))
	defer mockUpstream.Close()

	configJSON := `{
		"id": "ai-sse-test",
		"hostname": "ai-sse-test.local",
		"workspace_id": "test",
		"version": "1",
		"action": {
			"type": "proxy",
			"url": "` + mockUpstream.URL + `"
		},
		"transforms": [
			{
				"type": "sse_chunking",
				"provider": "openai"
			},
			{
				"type": "token_count",
				"provider": "openai"
			}
		]
	}`

	mockStore := &mockStorage{
		data: map[string][]byte{
			"ai-sse-test.local": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	req := httptest.NewRequest("POST", "http://ai-sse-test.local/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}],"stream":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "ai-sse-test.local"

	requestData := reqctx.NewRequestData()
	ctx := reqctx.SetRequestData(req.Context(), requestData)
	req = req.WithContext(ctx)

	cfg, err := Load(req, mgr)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	rr := httptest.NewRecorder()
	cfg.ServeHTTP(rr, req)

	resp := rr.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// SSE chunking should have set X-Stream-Chunks header
	if v := resp.Header.Get("X-Stream-Chunks"); v == "" {
		t.Error("expected X-Stream-Chunks header from sse_chunking transform")
	}
}

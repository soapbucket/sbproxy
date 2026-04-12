package configloader

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/soapbucket/sbproxy/internal/config"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// compileTestOrigin builds a CompiledOrigin from a raw JSON config for testing.
// The JSON should be a full origin object with at least "hostname" and "action".
func compileTestOrigin(t *testing.T, rawJSON []byte) *config.CompiledOrigin {
	t.Helper()
	raw := &config.RawOrigin{}
	if err := json.Unmarshal(rawJSON, raw); err != nil {
		t.Fatalf("compileTestOrigin: unmarshal failed: %v", err)
	}
	// Parse into Config so we can get a service provider
	cfg, err := config.Load(rawJSON)
	if err != nil {
		t.Fatalf("compileTestOrigin: config.Load failed: %v", err)
	}
	compiled, err := config.CompileOrigin(raw, config.NewServiceProvider(cfg))
	if err != nil {
		t.Fatalf("compileTestOrigin: compile failed: %v", err)
	}
	return compiled
}

// serveOriginJSON compiles a JSON config and serves a single request, returning the response.
func serveOriginJSON(t *testing.T, originJSON []byte, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	compiled := compileTestOrigin(t, originJSON)
	// Ensure request has reqctx data
	if reqctx.GetRequestData(r.Context()) == nil {
		rd := reqctx.NewRequestData()
		ctx := reqctx.SetRequestData(r.Context(), rd)
		r = r.WithContext(ctx)
	}
	w := httptest.NewRecorder()
	compiled.ServeHTTP(w, r)
	return w
}

// newTestRequest creates a GET request with reqctx initialized.
func newTestRequest(t *testing.T, method, url string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, url, nil)
	rd := reqctx.NewRequestData()
	ctx := reqctx.SetRequestData(r.Context(), rd)
	return r.WithContext(ctx)
}

// originJSON builds a JSON origin config map from key-value pairs.
// Requires at minimum "hostname" and "action" keys.
func originJSON(t *testing.T, fields map[string]any) []byte {
	t.Helper()
	// Ensure workspace_id and id are set
	if _, ok := fields["workspace_id"]; !ok {
		fields["workspace_id"] = "test-workspace"
	}
	if _, ok := fields["id"]; !ok {
		fields["id"] = "test-origin"
	}
	data, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("originJSON: %v", err)
	}
	return data
}

// echoOriginJSON returns a JSON origin config with the echo action.
func echoOriginJSON(t *testing.T, hostname string, extra map[string]any) []byte {
	t.Helper()
	fields := map[string]any{
		"hostname": hostname,
		"action": map[string]any{
			"type": "echo",
		},
	}
	for k, v := range extra {
		fields[k] = v
	}
	return originJSON(t, fields)
}

// mockOpenAIServer creates an httptest.Server that mimics OpenAI API endpoints.
// It supports /v1/chat/completions (streaming and non-streaming), /v1/models,
// /v1/embeddings, /v1/health, /v1/images/generations, /v1/moderations, and /v1/rerank.
func mockOpenAIServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/chat/completions"):
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				writeJSON(w, map[string]any{"error": map[string]any{"message": "method not allowed", "type": "invalid_request_error"}})
				return
			}
			body, _ := io.ReadAll(r.Body)
			var req map[string]any
			_ = json.Unmarshal(body, &req)

			model, _ := req["model"].(string)
			if model == "" {
				w.WriteHeader(http.StatusBadRequest)
				writeJSON(w, map[string]any{"error": map[string]any{"message": "model is required", "type": "invalid_request_error"}})
				return
			}

			// Check if streaming requested
			if stream, ok := req["stream"].(bool); ok && stream {
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Cache-Control", "no-cache")
				w.Header().Set("X-Request-Id", r.Header.Get("X-Request-Id"))
				flusher, _ := w.(http.Flusher)
				fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]any{
					"id": "chatcmpl-stream-test", "object": "chat.completion.chunk", "model": model,
					"choices": []map[string]any{{
						"index": 0, "delta": map[string]any{"role": "assistant", "content": "Hello"},
						"finish_reason": nil,
					}},
				}))
				if flusher != nil {
					flusher.Flush()
				}
				fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]any{
					"id": "chatcmpl-stream-test", "object": "chat.completion.chunk", "model": model,
					"choices": []map[string]any{{
						"index": 0, "delta": map[string]any{"content": "!"},
						"finish_reason": "stop",
					}},
					"usage": map[string]any{"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12},
				}))
				if flusher != nil {
					flusher.Flush()
				}
				fmt.Fprint(w, "data: [DONE]\n\n")
				if flusher != nil {
					flusher.Flush()
				}
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Request-Id", r.Header.Get("X-Request-Id"))
			writeJSON(w, map[string]any{
				"id": "chatcmpl-test-123", "object": "chat.completion", "model": model,
				"choices": []map[string]any{{
					"index":         0,
					"message":       map[string]any{"role": "assistant", "content": "Hello! How can I help you?"},
					"finish_reason": "stop",
				}},
				"usage": map[string]any{"prompt_tokens": 10, "completion_tokens": 8, "total_tokens": 18},
			})

		case strings.HasSuffix(path, "/models"):
			w.Header().Set("Content-Type", "application/json")
			writeJSON(w, map[string]any{
				"object": "list",
				"data": []map[string]any{
					{"id": "gpt-4o-mini", "object": "model", "owned_by": "openai"},
					{"id": "gpt-4o", "object": "model", "owned_by": "openai"},
				},
			})

		case strings.HasSuffix(path, "/embeddings"):
			w.Header().Set("Content-Type", "application/json")
			writeJSON(w, map[string]any{
				"object": "list",
				"model":  "text-embedding-3-small",
				"data": []map[string]any{
					{"object": "embedding", "index": 0, "embedding": []float64{0.1, 0.2, 0.3}},
				},
				"usage": map[string]any{"prompt_tokens": 5, "total_tokens": 5},
			})

		case strings.HasSuffix(path, "/images/generations"):
			w.Header().Set("Content-Type", "application/json")
			writeJSON(w, map[string]any{
				"created": 1700000000,
				"data": []map[string]any{
					{"url": "https://example.com/image.png", "revised_prompt": "test"},
				},
			})

		case strings.HasSuffix(path, "/rerank"):
			w.Header().Set("Content-Type", "application/json")
			writeJSON(w, map[string]any{
				"results": []map[string]any{
					{"index": 0, "relevance_score": 0.95},
					{"index": 1, "relevance_score": 0.42},
				},
			})

		case path == "/v1/health" || path == "/health":
			w.Header().Set("Content-Type", "application/json")
			writeJSON(w, map[string]any{"status": "ok"})

		default:
			w.WriteHeader(http.StatusNotFound)
			writeJSON(w, map[string]any{"error": map[string]any{"message": "unknown endpoint", "type": "not_found"}})
		}
	}))
}

// aiProxyOriginJSON builds a JSON origin config with the ai_proxy action
// pointing to a mock server URL.
func aiProxyOriginJSON(t *testing.T, hostname, mockURL string, extra map[string]any) []byte {
	t.Helper()
	fields := map[string]any{
		"hostname": hostname,
		"action": map[string]any{
			"type": "ai_proxy",
			"providers": []map[string]any{
				{
					"name":     "openai",
					"api_key":  "test-key-mock",
					"base_url": mockURL + "/v1",
					"models":   []string{"gpt-4o-mini", "gpt-4o"},
				},
			},
			"default_model": "gpt-4o-mini",
			"routing":       map[string]any{"strategy": "fallback_chain"},
		},
	}
	for k, v := range extra {
		fields[k] = v
	}
	return originJSON(t, fields)
}

// aiProxyMultiProviderJSON builds a JSON origin config with multiple ai_proxy providers.
func aiProxyMultiProviderJSON(t *testing.T, hostname string, mockURLs []string, extra map[string]any) []byte {
	t.Helper()
	providers := make([]map[string]any, len(mockURLs))
	for i, u := range mockURLs {
		providers[i] = map[string]any{
			"name":     fmt.Sprintf("provider-%d", i),
			"api_key":  fmt.Sprintf("test-key-%d", i),
			"base_url": u + "/v1",
			"models":   []string{"gpt-4o-mini"},
		}
	}
	fields := map[string]any{
		"hostname": hostname,
		"action": map[string]any{
			"type":          "ai_proxy",
			"providers":     providers,
			"default_model": "gpt-4o-mini",
			"routing":       map[string]any{"strategy": "fallback_chain"},
		},
	}
	for k, v := range extra {
		fields[k] = v
	}
	return originJSON(t, fields)
}

// writeJSON encodes v as JSON to the response writer.
func writeJSON(w http.ResponseWriter, v any) {
	data, _ := json.Marshal(v)
	_, _ = w.Write(data)
}

// jsonStr marshals v to a JSON string, panicking on error.
func jsonStr(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(data)
}

// serveAIProxy compiles an ai_proxy origin and serves a request, returning the response.
func serveAIProxy(t *testing.T, cfgJSON []byte, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	compiled := compileTestOrigin(t, cfgJSON)
	if reqctx.GetRequestData(r.Context()) == nil {
		rd := reqctx.NewRequestData()
		ctx := reqctx.SetRequestData(r.Context(), rd)
		r = r.WithContext(ctx)
	}
	w := httptest.NewRecorder()
	compiled.ServeHTTP(w, r)
	return w
}

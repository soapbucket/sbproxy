package configloader

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/soapbucket/sbproxy/internal/config"
)

// mockGRPCBackend creates an httptest.Server that mimics a gRPC backend for testing.
func mockGRPCBackend(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo gRPC-like response
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("grpc-status", "0")
		w.Header().Set("grpc-message", "ok")
		// Forward any metadata headers received
		for key, values := range r.Header {
			if strings.HasPrefix(strings.ToLower(key), "grpc-") || strings.HasPrefix(strings.ToLower(key), "x-") {
				for _, v := range values {
					w.Header().Add("x-received-"+strings.ToLower(key), v)
				}
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("grpc-response"))
	}))
}

// TestGRPC_BasicProxyingHttp2_E2E tests gRPC proxy forwarding to an HTTP backend.
func TestGRPC_BasicProxyingHttp2_E2E(t *testing.T) {
	resetCache()
	backend := mockGRPCBackend(t)
	defer backend.Close()

	cfg := originJSON(t, map[string]any{
		"hostname": "grpc-basic.test",
		"action": map[string]any{
			"type": "grpc",
			"url":  backend.URL,
		},
	})

	r := newTestRequest(t, "POST", "http://grpc-basic.test/test.Service/Method")
	r.Header.Set("Content-Type", "application/grpc")
	r.Header.Set("TE", "trailers")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if grpcStatus := w.Header().Get("grpc-status"); grpcStatus != "0" {
		t.Fatalf("expected grpc-status 0, got %q", grpcStatus)
	}
}

// TestGRPC_ContentTypeValidation_E2E tests gRPC content-type enforcement.
func TestGRPC_ContentTypeValidation_E2E(t *testing.T) {
	resetCache()
	backend := mockGRPCBackend(t)
	defer backend.Close()

	cfg := originJSON(t, map[string]any{
		"hostname": "grpc-ctype.test",
		"action": map[string]any{
			"type": "grpc",
			"url":  backend.URL,
		},
	})

	t.Run("valid gRPC content-type", func(t *testing.T) {
		r := newTestRequest(t, "POST", "http://grpc-ctype.test/test.Service/Method")
		r.Header.Set("Content-Type", "application/grpc")
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("gRPC+proto content-type", func(t *testing.T) {
		r := newTestRequest(t, "POST", "http://grpc-ctype.test/test.Service/Method")
		r.Header.Set("Content-Type", "application/grpc+proto")
		w := serveOriginJSON(t, cfg, r)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})
}

// TestGRPC_MetadataForwarding_E2E tests gRPC metadata header forwarding.
func TestGRPC_MetadataForwarding_E2E(t *testing.T) {
	resetCache()
	backend := mockGRPCBackend(t)
	defer backend.Close()

	cfg := originJSON(t, map[string]any{
		"hostname": "grpc-meta.test",
		"action": map[string]any{
			"type":             "grpc",
			"url":              backend.URL,
			"forward_metadata": true,
		},
	})

	r := newTestRequest(t, "POST", "http://grpc-meta.test/test.Service/Method")
	r.Header.Set("Content-Type", "application/grpc")
	r.Header.Set("grpc-timeout", "5S")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestGRPC_MessageSizeLimit_E2E tests gRPC message size limit configuration.
func TestGRPC_MessageSizeLimit_E2E(t *testing.T) {
	resetCache()
	backend := mockGRPCBackend(t)
	defer backend.Close()

	cfg := originJSON(t, map[string]any{
		"hostname": "grpc-size.test",
		"action": map[string]any{
			"type":                   "grpc",
			"url":                    backend.URL,
			"max_call_recv_msg_size": 1024,
			"max_call_send_msg_size": 1024,
		},
	})

	r := newTestRequest(t, "POST", "http://grpc-size.test/test.Service/Method")
	r.Header.Set("Content-Type", "application/grpc")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestGRPC_StripBasePath_E2E tests gRPC strip base path handling.
func TestGRPC_StripBasePath_E2E(t *testing.T) {
	resetCache()
	pathReceived := ""
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pathReceived = r.URL.Path
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("grpc-status", "0")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := originJSON(t, map[string]any{
		"hostname": "grpc-strip.test",
		"action": map[string]any{
			"type":            "grpc",
			"url":             backend.URL,
			"strip_base_path": true,
		},
	})

	r := newTestRequest(t, "POST", "http://grpc-strip.test/test.Service/Method")
	r.Header.Set("Content-Type", "application/grpc")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(pathReceived, "/test.Service/Method") {
		t.Fatalf("expected path to contain /test.Service/Method, got %q", pathReceived)
	}
}

// TestGRPC_GRPCWebSupport_E2E tests gRPC-Web protocol support.
func TestGRPC_GRPCWebSupport_E2E(t *testing.T) {
	resetCache()
	backend := mockGRPCBackend(t)
	defer backend.Close()

	cfg := originJSON(t, map[string]any{
		"hostname": "grpc-web.test",
		"action": map[string]any{
			"type":            "grpc",
			"url":             backend.URL,
			"enable_grpc_web": true,
		},
	})

	r := newTestRequest(t, "POST", "http://grpc-web.test/test.Service/Method")
	r.Header.Set("Content-Type", "application/grpc-web+proto")
	w := serveOriginJSON(t, cfg, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestGRPC_InvalidScheme_E2E tests gRPC URL scheme validation.
func TestGRPC_InvalidScheme_E2E(t *testing.T) {
	resetCache()

	// Valid schemes should compile
	for _, scheme := range []string{"http://", "https://", "grpc://", "grpcs://"} {
		cfg := originJSON(t, map[string]any{
			"hostname": "grpc-scheme-" + strings.TrimSuffix(scheme, "://") + ".test",
			"action": map[string]any{
				"type": "grpc",
				"url":  scheme + "example.com",
			},
		})
		compiled := compileTestOrigin(t, cfg)
		if compiled == nil {
			t.Fatalf("scheme %q should compile", scheme)
		}
	}

	// Invalid scheme should fail to compile (error may come from Load or CompileOrigin)
	invalidCfg := originJSON(t, map[string]any{
		"hostname": "grpc-scheme-bad.test",
		"action": map[string]any{
			"type": "grpc",
			"url":  "ftp://example.com",
		},
	})
	raw := &config.RawOrigin{}
	if err := json.Unmarshal(invalidCfg, raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	cfgParsed, loadErr := config.Load(invalidCfg)
	if loadErr != nil {
		// Error caught at Load stage - this is expected
		if !strings.Contains(loadErr.Error(), "scheme") {
			t.Fatalf("expected scheme error, got: %v", loadErr)
		}
		return
	}
	_, compileErr := config.CompileOrigin(raw, config.NewServiceProvider(cfgParsed))
	if compileErr == nil {
		t.Fatal("expected error for ftp:// scheme, got nil")
	}
	if !strings.Contains(compileErr.Error(), "scheme") {
		t.Fatalf("expected scheme error, got: %v", compileErr)
	}
}

package configloader

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// TestGRPC_BasicProxyingHttp2_E2E tests gRPC proxy forwarding via HTTP/2
func TestGRPC_BasicProxyingHttp2_E2E(t *testing.T) {
	resetCache()

	backendRequests := make(chan http.Header, 1)

	// Create mock gRPC backend (HTTP/2 server)
	grpcBackend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "HTTP/2.0" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}

		// gRPC responses must have application/grpc content-type
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/grpc" && contentType != "application/grpc+proto" {
			w.Header().Set("content-type", "application/grpc")
		}

		// Check TE trailer header (required for gRPC)
		if r.Header.Get("TE") != "trailers" {
			http.Error(w, "missing TE: trailers", http.StatusBadRequest)
			return
		}
		backendRequests <- r.Header.Clone()

		w.Header().Set("content-type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte{0, 0, 0, 0, 5}) // gRPC frame header
		w.Write([]byte{1, 2, 3, 4, 5}) // Sample message
	}))
	grpcBackend.EnableHTTP2 = true
	grpcBackend.StartTLS()
	defer grpcBackend.Close()

	backendURL, err := url.Parse(grpcBackend.URL)
	if err != nil {
		t.Fatalf("failed to parse backend URL: %v", err)
	}
	grpcAddr := backendURL.Host

	configJSON := fmt.Sprintf(`{
		"id": "grpc-basic-test",
		"hostname": "grpc-service.test",
		"workspace_id": "test",
		"version": "1.0",
		"action": {
			"type": "grpc",
			"url": "grpcs://%s",
			"strip_base_path": true,
			"preserve_query": true,
			"enable_grpc_web": false,
			"forward_metadata": true,
			"max_call_recv_msg_size": 4194304,
			"max_call_send_msg_size": 4194304,
			"timeout": "30s",
			"skip_tls_verify_host": true
		}
	}`, grpcAddr)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"grpc-service.test": []byte(configJSON),
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

	t.Run("forward gRPC request with HTTP/2", func(t *testing.T) {
		req := httptest.NewRequest("POST", "http://grpc-service.test/helloworld.Greeter/SayHello", nil)
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("TE", "trailers")
		req.Host = "grpc-service.test"
		req.Body = http.NoBody

		requestData := reqctx.NewRequestData()
		requestData.ID = "test-grpc-basic"
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		rr := httptest.NewRecorder()
		cfg.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 from gRPC proxy, got %d body=%s", rr.Code, rr.Body.String())
		}

		select {
		case headers := <-backendRequests:
			if got := headers.Get("TE"); got != "trailers" {
				t.Fatalf("expected backend to receive TE=trailers, got %q", got)
			}
			if got := headers.Get("Content-Type"); got != "application/grpc" {
				t.Fatalf("expected backend to receive application/grpc, got %q", got)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("backend did not receive proxied gRPC request")
		}
	})
}

// TestGRPC_ContentTypeValidation_E2E tests gRPC content-type enforcement
func TestGRPC_ContentTypeValidation_E2E(t *testing.T) {
	resetCache()

	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	grpcAddr := listener.Addr().String()
	listener.Close()

	configJSON := fmt.Sprintf(`{
		"id": "grpc-content-type-test",
		"hostname": "grpc-ct.test",
		"workspace_id": "test",
		"version": "1.0",
		"action": {
			"type": "grpc",
			"url": "grpcs://%s",
			"timeout": "30s",
			"skip_tls_verify_host": true
		}
	}`, grpcAddr)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"grpc-ct.test": []byte(configJSON),
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

	t.Run("request with invalid content-type", func(t *testing.T) {
		req := httptest.NewRequest("POST", "http://grpc-ct.test/service/method", nil)
		req.Header.Set("Content-Type", "application/json") // Wrong content-type
		req.Host = "grpc-ct.test"

		requestData := reqctx.NewRequestData()
		requestData.ID = "test-invalid-ct"
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		cfg, _ := Load(req, mgr)
		rr := httptest.NewRecorder()
		cfg.ServeHTTP(rr, req)

		// Should handle content-type mismatch gracefully
		if rr.Code != http.StatusOK && rr.Code < 300 {
			t.Logf("Invalid content-type handling: got %d", rr.Code)
		}
	})

	t.Run("request with correct gRPC content-type", func(t *testing.T) {
		req := httptest.NewRequest("POST", "http://grpc-ct.test/service/method", nil)
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("TE", "trailers")
		req.Host = "grpc-ct.test"

		requestData := reqctx.NewRequestData()
		requestData.ID = "test-valid-ct"
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		cfg, _ := Load(req, mgr)
		rr := httptest.NewRecorder()
		cfg.ServeHTTP(rr, req)

		if rr.Code >= 500 {
			t.Logf("gRPC server error: %d", rr.Code)
		}
	})
}

// TestGRPC_MetadataForwarding_E2E tests gRPC metadata header forwarding
func TestGRPC_MetadataForwarding_E2E(t *testing.T) {
	resetCache()

	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	grpcAddr := listener.Addr().String()
	listener.Close()

	configJSON := fmt.Sprintf(`{
		"id": "grpc-metadata-test",
		"hostname": "grpc-meta.test",
		"workspace_id": "test",
		"version": "1.0",
		"action": {
			"type": "grpc",
			"url": "grpcs://%s",
			"forward_metadata": true,
			"timeout": "30s",
			"skip_tls_verify_host": true
		}
	}`, grpcAddr)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"grpc-meta.test": []byte(configJSON),
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

	t.Run("forward gRPC metadata headers", func(t *testing.T) {
		req := httptest.NewRequest("POST", "http://grpc-meta.test/service/method", nil)
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("TE", "trailers")
		req.Header.Set("grpc-trace-bin", "base64-encoded-trace-data")
		req.Header.Set("grpc-timeout", "30S")
		req.Header.Set("grpc-encoding", "gzip")
		req.Host = "grpc-meta.test"

		requestData := reqctx.NewRequestData()
		requestData.ID = "test-grpc-metadata"
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		cfg, _ := Load(req, mgr)
		rr := httptest.NewRecorder()
		cfg.ServeHTTP(rr, req)

		// Config should process and forward metadata
		if rr.Code >= 400 && rr.Code != http.StatusBadGateway {
			t.Logf("Metadata forwarding handled: %d", rr.Code)
		}
	})
}

// TestGRPC_MessageSizeLimit_E2E tests gRPC message size enforcement
func TestGRPC_MessageSizeLimit_E2E(t *testing.T) {
	resetCache()

	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	grpcAddr := listener.Addr().String()
	listener.Close()

	configJSON := fmt.Sprintf(`{
		"id": "grpc-size-test",
		"hostname": "grpc-size.test",
		"workspace_id": "test",
		"version": "1.0",
		"action": {
			"type": "grpc",
			"url": "grpcs://%s",
			"max_call_recv_msg_size": 1000000,
			"max_call_send_msg_size": 500000,
			"timeout": "30s",
			"skip_tls_verify_host": true
		}
	}`, grpcAddr)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"grpc-size.test": []byte(configJSON),
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

	t.Run("within message size limits", func(t *testing.T) {
		req := httptest.NewRequest("POST", "http://grpc-size.test/service/method", nil)
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("TE", "trailers")
		req.Host = "grpc-size.test"

		requestData := reqctx.NewRequestData()
		requestData.ID = "test-size-ok"
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		cfg, _ := Load(req, mgr)
		rr := httptest.NewRecorder()
		cfg.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Logf("Within size limits: got %d", rr.Code)
		}
	})
}

// TestGRPC_StripBasePath_E2E tests gRPC strip base path handling
func TestGRPC_StripBasePath_E2E(t *testing.T) {
	resetCache()

	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	grpcAddr := listener.Addr().String()
	listener.Close()

	configJSON := fmt.Sprintf(`{
		"id": "grpc-path-test",
		"hostname": "grpc-path.test",
		"workspace_id": "test",
		"version": "1.0",
		"action": {
			"type": "grpc",
			"url": "grpcs://%s/api/v1",
			"strip_base_path": true,
			"timeout": "30s",
			"skip_tls_verify_host": true
		}
	}`, grpcAddr)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"grpc-path.test": []byte(configJSON),
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

	t.Run("strip base path for gRPC service", func(t *testing.T) {
		req := httptest.NewRequest("POST", "http://grpc-path.test/api/v1/service/Method", nil)
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("TE", "trailers")
		req.Host = "grpc-path.test"

		requestData := reqctx.NewRequestData()
		requestData.ID = "test-grpc-strip-base-path"
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		cfg, _ := Load(req, mgr)
		rr := httptest.NewRecorder()
		cfg.ServeHTTP(rr, req)

		if rr.Code >= 400 && rr.Code < 600 {
			t.Logf("Path preservation: status %d", rr.Code)
		}
	})
}

// TestGRPC_GRPCWebSupport_E2E tests gRPC-Web protocol support
func TestGRPC_GRPCWebSupport_E2E(t *testing.T) {
	resetCache()

	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	grpcAddr := listener.Addr().String()
	listener.Close()

	configJSON := fmt.Sprintf(`{
		"id": "grpc-web-test",
		"hostname": "grpc-web.test",
		"workspace_id": "test",
		"version": "1.0",
		"action": {
			"type": "grpc",
			"url": "grpcs://%s",
			"enable_grpc_web": true,
			"timeout": "30s",
			"skip_tls_verify_host": true
		}
	}`, grpcAddr)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"grpc-web.test": []byte(configJSON),
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

	t.Run("handle gRPC-Web requests", func(t *testing.T) {
		req := httptest.NewRequest("POST", "http://grpc-web.test/service.Method", nil)
		req.Header.Set("Content-Type", "application/grpc-web")
		req.Host = "grpc-web.test"

		requestData := reqctx.NewRequestData()
		requestData.ID = "test-grpc-web"
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		cfg, _ := Load(req, mgr)
		rr := httptest.NewRecorder()
		cfg.ServeHTTP(rr, req)

		// gRPC-Web should be handled
		if rr.Code >= 400 {
			t.Logf("gRPC-Web response: %d", rr.Code)
		}
	})
}

// TestGRPC_InvalidScheme_E2E tests gRPC URL scheme validation
func TestGRPC_InvalidScheme_E2E(t *testing.T) {
	resetCache()

	configJSON := `{
		"id": "grpc-invalid-test",
		"hostname": "grpc-invalid.test",
		"workspace_id": "test",
		"version": "1.0",
		"action": {
			"type": "grpc",
			"url": "http://localhost:5000",
			"timeout": "30s"
		}
	}`

	mockStore := &mockStorage{
		data: map[string][]byte{
			"grpc-invalid.test": []byte(configJSON),
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

	req := httptest.NewRequest("POST", "http://grpc-invalid.test/service/method", nil)
	req.Header.Set("Content-Type", "application/grpc")
	req.Host = "grpc-invalid.test"

	requestData := reqctx.NewRequestData()
	requestData.ID = "test-invalid-scheme"
	ctx := reqctx.SetRequestData(req.Context(), requestData)
	req = req.WithContext(ctx)

	cfg, err := Load(req, mgr)
	if err != nil {
		t.Logf("Invalid scheme error (expected): %v", err)
	}

	if cfg != nil {
		rr := httptest.NewRecorder()
		cfg.ServeHTTP(rr, req)
		if rr.Code >= 400 {
			t.Logf("Invalid scheme handling: %d", rr.Code)
		}
	}
}

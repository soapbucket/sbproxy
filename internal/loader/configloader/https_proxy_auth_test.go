package configloader

import (
	"context"
	"errors"
	"testing"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/platform/storage"
)

func TestAuthenticateProxyClient(t *testing.T) {
	resetCache()
	proxyConfigJSON := []byte(`{
		"id": "proxy-origin",
		"hostname": "proxy-origin.test",
		"workspace_id": "ws-1",
		"version": "1.0",
		"action": {
			"type": "https_proxy"
		}
	}`)

	mockStore := &mockStorage{
		dataByID: map[string][]byte{
			"proxy-origin": proxyConfigJSON,
		},
		proxyValidation: map[string]*storage.ProxyKeyValidationResult{
			"proxy-origin:secret-key": {
				ProxyKeyID:   "key-1",
				ProxyKeyName: "primary",
			},
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5,
				HostnameFallback:      true,
			},
		},
	}

	result, err := AuthenticateProxyClient(context.Background(), "proxy-origin", "secret-key", mgr)
	if err != nil {
		t.Fatalf("AuthenticateProxyClient returned error: %v", err)
	}
	if result.WorkspaceID != "ws-1" {
		t.Fatalf("expected workspace ws-1, got %s", result.WorkspaceID)
	}
	if result.ProxyKeyName != "primary" {
		t.Fatalf("expected key name primary, got %s", result.ProxyKeyName)
	}
	if result.ProxyConfig == nil {
		t.Fatal("expected proxy config to be returned")
	}
}

func TestLoadForProxyHost(t *testing.T) {
	resetCache()
	targetConfigJSON := []byte(`{
		"id": "managed-target",
		"hostname": "managed.test",
		"workspace_id": "ws-1",
		"version": "1.0",
		"action": {
			"type": "static",
			"body": "ok"
		}
	}`)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"managed.test": targetConfigJSON,
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5,
				HostnameFallback:      true,
			},
		},
	}

	auth := &ProxyAuthResult{WorkspaceID: "ws-1"}
	cfg, err := LoadForProxyHost(context.Background(), auth, "managed.test", mgr)
	if err != nil {
		t.Fatalf("LoadForProxyHost returned error: %v", err)
	}
	if cfg.ID != "managed-target" {
		t.Fatalf("expected managed-target config, got %s", cfg.ID)
	}
}

func TestLoadForProxyHostWorkspaceMismatch(t *testing.T) {
	resetCache()
	targetConfigJSON := []byte(`{
		"id": "managed-target",
		"hostname": "managed.test",
		"workspace_id": "ws-2",
		"version": "1.0",
		"action": {
			"type": "static",
			"body": "ok"
		}
	}`)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"managed.test": targetConfigJSON,
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5,
				HostnameFallback:      true,
			},
		},
	}

	auth := &ProxyAuthResult{WorkspaceID: "ws-1"}
	_, err := LoadForProxyHost(context.Background(), auth, "managed.test", mgr)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound on workspace mismatch, got %v", err)
	}
}


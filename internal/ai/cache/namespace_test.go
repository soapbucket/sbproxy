package cache

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNamespaceResolver_Global(t *testing.T) {
	tests := []struct {
		name string
		cfg  *NamespaceConfig
	}{
		{name: "explicit global mode", cfg: &NamespaceConfig{Mode: "global"}},
		{name: "empty mode defaults to global", cfg: &NamespaceConfig{}},
		{name: "nil config defaults to global", cfg: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nr := NewNamespaceResolver(tt.cfg)
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			ns := nr.Resolve(context.Background(), r)
			assert.Empty(t, ns, "global mode should return empty namespace")
		})
	}
}

func TestNamespaceResolver_PerWorkspace(t *testing.T) {
	tests := []struct {
		name      string
		setupCtx  func() context.Context
		setupReq  func() *http.Request
		wantNS    string
	}{
		{
			name: "workspace from context",
			setupCtx: func() context.Context {
				rd := &reqctx.RequestData{
					Config: map[string]any{"workspace_id": "ws-abc123"},
				}
				return reqctx.SetRequestData(context.Background(), rd)
			},
			setupReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/", nil)
			},
			wantNS: "ws:ws-abc123",
		},
		{
			name: "workspace from header fallback",
			setupCtx: func() context.Context {
				return context.Background()
			},
			setupReq: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("X-SB-Workspace", "ws-header456")
				return r
			},
			wantNS: "ws:ws-header456",
		},
		{
			name: "context takes priority over header",
			setupCtx: func() context.Context {
				rd := &reqctx.RequestData{
					Config: map[string]any{"workspace_id": "ws-from-ctx"},
				}
				return reqctx.SetRequestData(context.Background(), rd)
			},
			setupReq: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("X-SB-Workspace", "ws-from-header")
				return r
			},
			wantNS: "ws:ws-from-ctx",
		},
		{
			name: "no workspace available",
			setupCtx: func() context.Context {
				return context.Background()
			},
			setupReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/", nil)
			},
			wantNS: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nr := NewNamespaceResolver(&NamespaceConfig{Mode: "per_workspace"})
			ns := nr.Resolve(tt.setupCtx(), tt.setupReq())
			assert.Equal(t, tt.wantNS, ns)
		})
	}
}

func TestNamespaceResolver_PerUser(t *testing.T) {
	tests := []struct {
		name     string
		setupCtx func() context.Context
		setupReq func() *http.Request
		wantNS   string
	}{
		{
			name: "user from X-SB-User header",
			setupCtx: func() context.Context {
				return context.Background()
			},
			setupReq: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("X-SB-User", "user-42")
				return r
			},
			wantNS: "user:user-42",
		},
		{
			name: "user from context debug headers",
			setupCtx: func() context.Context {
				rd := &reqctx.RequestData{
					DebugHeaders: map[string]string{"X-Sb-User-Id": "ctx-user-99"},
				}
				return reqctx.SetRequestData(context.Background(), rd)
			},
			setupReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/", nil)
			},
			wantNS: "user:ctx-user-99",
		},
		{
			name: "X-SB-User header takes priority over context",
			setupCtx: func() context.Context {
				rd := &reqctx.RequestData{
					DebugHeaders: map[string]string{"X-Sb-User-Id": "ctx-user"},
				}
				return reqctx.SetRequestData(context.Background(), rd)
			},
			setupReq: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("X-SB-User", "header-user")
				return r
			},
			wantNS: "user:header-user",
		},
		{
			name: "fallback to Authorization header hash",
			setupCtx: func() context.Context {
				return context.Background()
			},
			setupReq: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("Authorization", "Bearer sk-test-key-12345")
				return r
			},
			wantNS: func() string {
				h := sha256.Sum256([]byte("Bearer sk-test-key-12345"))
				return "user:" + fmt.Sprintf("%x", h[:8])
			}(),
		},
		{
			name: "no user info available",
			setupCtx: func() context.Context {
				return context.Background()
			},
			setupReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/", nil)
			},
			wantNS: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nr := NewNamespaceResolver(&NamespaceConfig{Mode: "per_user"})
			ns := nr.Resolve(tt.setupCtx(), tt.setupReq())
			assert.Equal(t, tt.wantNS, ns)
		})
	}
}

func TestNamespaceResolver_PerKey(t *testing.T) {
	tests := []struct {
		name   string
		auth   string
		wantNS string
	}{
		{
			name: "API key produces hashed namespace",
			auth: "Bearer sk-prod-abc123",
			wantNS: func() string {
				h := sha256.Sum256([]byte("Bearer sk-prod-abc123"))
				return "key:" + fmt.Sprintf("%x", h)
			}(),
		},
		{
			name:   "no Authorization header",
			auth:   "",
			wantNS: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nr := NewNamespaceResolver(&NamespaceConfig{Mode: "per_key"})
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.auth != "" {
				r.Header.Set("Authorization", tt.auth)
			}
			ns := nr.Resolve(context.Background(), r)
			assert.Equal(t, tt.wantNS, ns)
		})
	}
}

func TestNamespaceResolver_Custom(t *testing.T) {
	tests := []struct {
		name         string
		customHeader string
		headerValue  string
		wantNS       string
	}{
		{
			name:         "custom header with value",
			customHeader: "X-Tenant-ID",
			headerValue:  "tenant-alpha",
			wantNS:       "custom:tenant-alpha",
		},
		{
			name:         "custom header missing from request",
			customHeader: "X-Tenant-ID",
			headerValue:  "",
			wantNS:       "",
		},
		{
			name:         "no custom header configured",
			customHeader: "",
			headerValue:  "",
			wantNS:       "",
		},
		{
			name:         "pipe characters are sanitized",
			customHeader: "X-Tenant-ID",
			headerValue:  "tenant|with|pipes",
			wantNS:       "custom:tenant_with_pipes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nr := NewNamespaceResolver(&NamespaceConfig{Mode: "custom", CustomHeader: tt.customHeader})
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.headerValue != "" {
				r.Header.Set(tt.customHeader, tt.headerValue)
			}
			ns := nr.Resolve(context.Background(), r)
			assert.Equal(t, tt.wantNS, ns)
		})
	}
}

func TestNamespacedKey(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		key       string
		want      string
	}{
		{name: "with namespace", namespace: "ws:abc", key: "cache-key-1", want: "ws:abc|cache-key-1"},
		{name: "empty namespace", namespace: "", key: "cache-key-1", want: "cache-key-1"},
		{name: "empty key", namespace: "ws:abc", key: "", want: "ws:abc|"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NamespacedKey(tt.namespace, tt.key)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNamespaceResolver_MissingContext(t *testing.T) {
	modes := []string{"per_workspace", "per_user", "per_key", "custom"}

	for _, mode := range modes {
		t.Run("nil request "+mode, func(t *testing.T) {
			nr := NewNamespaceResolver(&NamespaceConfig{Mode: mode, CustomHeader: "X-Test"})
			// nil request should not panic.
			ns := nr.Resolve(context.Background(), nil)
			assert.Empty(t, ns, "nil request should return empty namespace for mode %s", mode)
		})
	}

	t.Run("nil context with per_workspace", func(t *testing.T) {
		nr := NewNamespaceResolver(&NamespaceConfig{Mode: "per_workspace"})
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-SB-Workspace", "ws-fallback")
		// Passing nil context should still work via header fallback.
		//nolint:staticcheck // SA1012: intentionally passing nil context for test
		ns := nr.Resolve(nil, r)
		assert.Equal(t, "ws:ws-fallback", ns)
	})
}

func TestNamespaceIsolation(t *testing.T) {
	// Verify that different namespaces produce different prefixed keys.
	nr1 := NewNamespaceResolver(&NamespaceConfig{Mode: "per_workspace"})
	nr2 := NewNamespaceResolver(&NamespaceConfig{Mode: "per_workspace"})

	ctx1 := reqctx.SetRequestData(context.Background(), &reqctx.RequestData{
		Config: map[string]any{"workspace_id": "workspace-A"},
	})
	ctx2 := reqctx.SetRequestData(context.Background(), &reqctx.RequestData{
		Config: map[string]any{"workspace_id": "workspace-B"},
	})

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	ns1 := nr1.Resolve(ctx1, r)
	ns2 := nr2.Resolve(ctx2, r)

	require.NotEqual(t, ns1, ns2, "different workspaces must produce different namespaces")

	baseKey := "abc123hash"
	key1 := NamespacedKey(ns1, baseKey)
	key2 := NamespacedKey(ns2, baseKey)
	require.NotEqual(t, key1, key2, "namespaced keys must differ for different workspaces")
	assert.Equal(t, "ws:workspace-A|abc123hash", key1)
	assert.Equal(t, "ws:workspace-B|abc123hash", key2)
}

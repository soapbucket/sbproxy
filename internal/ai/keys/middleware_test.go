package keys

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func setupMiddlewareTest(t *testing.T) (*Middleware, *MemoryStore, string, *VirtualKey) {
	t.Helper()
	store := NewMemoryStore()
	mw := NewMiddleware(store)

	rawKey, hashedKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}
	vk := &VirtualKey{
		ID:          "vk-test-mw",
		Name:        "middleware test key",
		HashedKey:   hashedKey,
		WorkspaceID: "ws-1",
		Status:      "active",
		CreatedAt:   time.Now().UTC(),
	}
	if err := store.Create(context.Background(), vk); err != nil {
		t.Fatalf("setup Create() error = %v", err)
	}

	return mw, store, rawKey, vk
}

func TestMiddleware_ValidKey_BearerAuth(t *testing.T) {
	mw, _, rawKey, _ := setupMiddlewareTest(t)

	var gotVK *VirtualKey
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vk, ok := FromContext(r.Context())
		if ok {
			gotVK = vk
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer "+rawKey)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if gotVK == nil {
		t.Fatal("VirtualKey not found in context")
	}
	if gotVK.ID != "vk-test-mw" {
		t.Errorf("VirtualKey.ID = %q, want %q", gotVK.ID, "vk-test-mw")
	}
}

func TestMiddleware_ValidKey_XAPIKey(t *testing.T) {
	mw, _, rawKey, _ := setupMiddlewareTest(t)

	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := FromContext(r.Context())
		if !ok {
			t.Error("VirtualKey not found in context for X-API-Key")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", rawKey)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestMiddleware_InvalidKey(t *testing.T) {
	mw, _, _, _ := setupMiddlewareTest(t)

	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for invalid key")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer sk-sb-invalid-key-value")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestMiddleware_RevokedKey(t *testing.T) {
	mw, store, rawKey, _ := setupMiddlewareTest(t)
	store.Revoke(context.Background(), "vk-test-mw")

	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for revoked key")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+rawKey)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestMiddleware_ExpiredKey(t *testing.T) {
	store := NewMemoryStore()
	mw := NewMiddleware(store)

	rawKey, hashedKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}
	expired := time.Now().Add(-1 * time.Hour)
	vk := &VirtualKey{
		ID:          "vk-expired",
		HashedKey:   hashedKey,
		WorkspaceID: "ws-1",
		Status:      "active",
		ExpiresAt:   &expired,
	}
	store.Create(context.Background(), vk)

	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for expired key")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+rawKey)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestMiddleware_NonVirtualKey_Passthrough(t *testing.T) {
	mw, _, _, _ := setupMiddlewareTest(t)

	called := false
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		_, ok := FromContext(r.Context())
		if ok {
			t.Error("VirtualKey should not be in context for non-virtual key")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer sk-regular-openai-key")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("handler should be called for non-virtual key passthrough")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestMiddleware_NoKey_Passthrough(t *testing.T) {
	mw, _, _, _ := setupMiddlewareTest(t)

	called := false
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("handler should be called when no key is present")
	}
}

func TestFromContext_Empty(t *testing.T) {
	ctx := context.Background()
	vk, ok := FromContext(ctx)
	if ok || vk != nil {
		t.Error("FromContext() on empty context should return nil, false")
	}
}

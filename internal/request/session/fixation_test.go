package session

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
	configpkg "github.com/soapbucket/sbproxy/internal/config"
	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/platform/messenger"
	"github.com/soapbucket/sbproxy/internal/platform/storage"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// --- Mock infrastructure ---

type fixationMockManager struct {
	cache *fixationMockSessionCache
}

func newFixationMockManager() *fixationMockManager {
	return &fixationMockManager{
		cache: &fixationMockSessionCache{
			sessions: make(map[string][]byte),
			deleted:  make(map[string]bool),
		},
	}
}

func (m *fixationMockManager) EncryptString(s string) (string, error) { return "enc:" + s, nil }
func (m *fixationMockManager) DecryptString(s string) (string, error) {
	if len(s) > 4 && s[:4] == "enc:" {
		return s[4:], nil
	}
	return s, nil
}
func (m *fixationMockManager) EncryptStringWithContext(data, ctx string) (string, error) {
	return "enc:" + data, nil
}
func (m *fixationMockManager) DecryptStringWithContext(data, ctx string) (string, error) {
	if len(data) > 4 && data[:4] == "enc:" {
		return data[4:], nil
	}
	return data, nil
}
func (m *fixationMockManager) SignString(s string) (string, error)      { return "sig:" + s, nil }
func (m *fixationMockManager) VerifyString(s, sig string) (bool, error) { return sig == "sig:"+s, nil }
func (m *fixationMockManager) GetSessionCache() manager.SessionCache    { return m.cache }
func (m *fixationMockManager) GetStorage() storage.Storage              { return nil }
func (m *fixationMockManager) GetGlobalSettings() manager.GlobalSettings {
	return manager.GlobalSettings{}
}
func (m *fixationMockManager) GetCache(manager.CacheLevel) cacher.Cacher { return nil }
func (m *fixationMockManager) GetMessenger() messenger.Messenger         { return nil }
func (m *fixationMockManager) GetServerContext() context.Context         { return context.Background() }
func (m *fixationMockManager) GetCallbackPool() manager.WorkerPool       { return nil }
func (m *fixationMockManager) GetCachePool() manager.WorkerPool          { return nil }
func (m *fixationMockManager) Close() error                              { return nil }

type fixationMockSessionCache struct {
	mu       sync.RWMutex
	sessions map[string][]byte
	deleted  map[string]bool
}

func (c *fixationMockSessionCache) Get(_ context.Context, key string) (io.Reader, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if data, ok := c.sessions[key]; ok {
		return bytes.NewReader(data), nil
	}
	return nil, cacher.ErrNotFound
}

func (c *fixationMockSessionCache) Put(_ context.Context, key string, r io.Reader, _ time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	c.sessions[key] = data
	return nil
}

func (c *fixationMockSessionCache) Delete(_ context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.sessions, key)
	c.deleted[key] = true
	return nil
}

// --- Tests ---

func TestFixationPrevention_RegenerateSession(t *testing.T) {
	mgr := newFixationMockManager()
	config := DefaultFixationPreventionConfig()
	fp := NewFixationPrevention(config, mgr)

	sessionConfig := configpkg.SessionConfig{
		CookieName:   "_sb.s",
		CookieMaxAge: 3600,
	}

	oldSessionID := "old-session-123"
	oldSession := &reqctx.SessionData{
		ID:        oldSessionID,
		CreatedAt: time.Now().Add(-10 * time.Minute),
		Data:      map[string]any{"user_pref": "dark"},
	}

	requestData := &reqctx.RequestData{
		SessionData: oldSession,
	}

	ctx := reqctx.SetRequestData(context.Background(), requestData)
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	newID, err := fp.RegenerateSession(rec, req, sessionConfig)
	if err != nil {
		t.Fatalf("RegenerateSession returned error: %v", err)
	}

	if newID == "" {
		t.Fatal("expected non-empty new session ID")
	}

	if newID == oldSessionID {
		t.Fatalf("new session ID should differ from old, got %s", newID)
	}

	// Verify a Set-Cookie header was written
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected Set-Cookie header in response")
	}

	found := false
	for _, c := range cookies {
		if c.Name == "_sb.s" {
			found = true
			if c.Value == "" {
				t.Error("cookie value should not be empty")
			}
			break
		}
	}
	if !found {
		t.Error("expected cookie with name _sb.s")
	}

	// Verify old session was deleted
	if !mgr.cache.deleted[oldSessionID] {
		t.Error("expected old session to be deleted")
	}
}

func TestFixationPrevention_CopySessionData(t *testing.T) {
	mgr := newFixationMockManager()
	config := DefaultFixationPreventionConfig()
	config.CopySessionData = true
	fp := NewFixationPrevention(config, mgr)

	sessionConfig := configpkg.SessionConfig{}

	oldSession := &reqctx.SessionData{
		ID:        "old-session-456",
		CreatedAt: time.Now().Add(-5 * time.Minute),
		AuthData:  &reqctx.AuthData{Type: "jwt", Data: map[string]any{"sub": "user1"}},
		Visited: []reqctx.VisitedURL{
			{URL: "/page1", Visited: time.Now()},
		},
		Data: map[string]any{
			"cart_items": 3,
			"theme":      "dark",
		},
	}

	requestData := &reqctx.RequestData{
		SessionData: oldSession,
	}

	ctx := reqctx.SetRequestData(context.Background(), requestData)
	req := httptest.NewRequest(http.MethodGet, "/checkout", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	_, err := fp.RegenerateSession(rec, req, sessionConfig)
	if err != nil {
		t.Fatalf("RegenerateSession returned error: %v", err)
	}

	// Get updated request data
	updatedRD := reqctx.GetRequestData(req.Context())
	if updatedRD == nil || updatedRD.SessionData == nil {
		t.Fatal("expected updated session data in context")
	}

	newSession := updatedRD.SessionData

	// Verify data was copied
	if newSession.AuthData == nil {
		t.Fatal("expected AuthData to be copied")
	}
	if newSession.AuthData.Type != "jwt" {
		t.Errorf("expected AuthData.Type 'jwt', got '%s'", newSession.AuthData.Type)
	}

	if len(newSession.Visited) != 1 {
		t.Errorf("expected 1 visited URL, got %d", len(newSession.Visited))
	}

	if v, ok := newSession.Data["cart_items"]; !ok || v != 3 {
		t.Errorf("expected cart_items=3 in copied data, got %v", v)
	}
	if v, ok := newSession.Data["theme"]; !ok || v != "dark" {
		t.Errorf("expected theme=dark in copied data, got %v", v)
	}

	// Verify regeneration timestamp was set
	if _, ok := newSession.Data[lastRegenKey]; !ok {
		t.Error("expected last_regen timestamp in session data")
	}
}

func TestFixationPrevention_NoCopySessionData(t *testing.T) {
	mgr := newFixationMockManager()
	config := DefaultFixationPreventionConfig()
	config.CopySessionData = false
	fp := NewFixationPrevention(config, mgr)

	sessionConfig := configpkg.SessionConfig{}

	oldSession := &reqctx.SessionData{
		ID:   "old-session-789",
		Data: map[string]any{"important": "data"},
	}

	requestData := &reqctx.RequestData{
		SessionData: oldSession,
	}

	ctx := reqctx.SetRequestData(context.Background(), requestData)
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	_, err := fp.RegenerateSession(rec, req, sessionConfig)
	if err != nil {
		t.Fatalf("RegenerateSession returned error: %v", err)
	}

	updatedRD := reqctx.GetRequestData(req.Context())
	newSession := updatedRD.SessionData

	// Data should not contain the old key (only lastRegenKey)
	if v, ok := newSession.Data["important"]; ok {
		t.Errorf("expected data not to be copied, but found important=%v", v)
	}
}

func TestFixationPrevention_ShouldRegenerate_AuthStateChange(t *testing.T) {
	mgr := newFixationMockManager()
	config := DefaultFixationPreventionConfig()
	fp := NewFixationPrevention(config, mgr)

	tests := []struct {
		name        string
		authState   string
		hasAuthData bool
		want        bool
	}{
		{
			name:        "login: no existing auth, state=authenticated",
			authState:   "authenticated",
			hasAuthData: false,
			want:        true,
		},
		{
			name:        "already authenticated: has auth data, state=authenticated",
			authState:   "authenticated",
			hasAuthData: true,
			want:        false,
		},
		{
			name:        "no auth header: no trigger",
			authState:   "",
			hasAuthData: false,
			want:        false,
		},
		{
			name:        "anonymous state: no trigger",
			authState:   "anonymous",
			hasAuthData: false,
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &reqctx.SessionData{
				ID: "test-session",
			}
			if tt.hasAuthData {
				session.AuthData = &reqctx.AuthData{Type: "jwt"}
			}

			requestData := &reqctx.RequestData{
				SessionData: session,
			}

			ctx := reqctx.SetRequestData(context.Background(), requestData)
			req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
			if tt.authState != "" {
				req.Header.Set(authStateHeader, tt.authState)
			}

			got := fp.ShouldRegenerate(req)
			if got != tt.want {
				t.Errorf("ShouldRegenerate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFixationPrevention_ShouldRegenerate_Escalation(t *testing.T) {
	mgr := newFixationMockManager()
	config := DefaultFixationPreventionConfig()
	fp := NewFixationPrevention(config, mgr)

	session := &reqctx.SessionData{
		ID:       "test-session",
		AuthData: &reqctx.AuthData{Type: "jwt"},
	}

	requestData := &reqctx.RequestData{
		SessionData: session,
	}

	ctx := reqctx.SetRequestData(context.Background(), requestData)
	req := httptest.NewRequest(http.MethodPost, "/admin/sudo", nil).WithContext(ctx)
	req.Header.Set(authEscalationHeader, "admin")

	if !fp.ShouldRegenerate(req) {
		t.Error("expected ShouldRegenerate=true on privilege escalation")
	}
}

func TestFixationPrevention_ShouldRegenerate_Interval(t *testing.T) {
	mgr := newFixationMockManager()
	config := DefaultFixationPreventionConfig()
	config.RegenerateOnLogin = false
	config.RegenerateOnEscalation = false
	config.RegenerateInterval = 15 * time.Minute
	fp := NewFixationPrevention(config, mgr)

	// Session with recent regeneration - should NOT regenerate
	recentSession := &reqctx.SessionData{
		ID: "recent-session",
		Data: map[string]any{
			lastRegenKey: time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339),
		},
	}

	requestData := &reqctx.RequestData{SessionData: recentSession}
	ctx := reqctx.SetRequestData(context.Background(), requestData)
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)

	if fp.ShouldRegenerate(req) {
		t.Error("expected ShouldRegenerate=false for recently regenerated session")
	}

	// Session with old regeneration - should regenerate
	oldSession := &reqctx.SessionData{
		ID: "old-session",
		Data: map[string]any{
			lastRegenKey: time.Now().Add(-20 * time.Minute).UTC().Format(time.RFC3339),
		},
	}

	requestData2 := &reqctx.RequestData{SessionData: oldSession}
	ctx2 := reqctx.SetRequestData(context.Background(), requestData2)
	req2 := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx2)

	if !fp.ShouldRegenerate(req2) {
		t.Error("expected ShouldRegenerate=true for session past interval")
	}
}

func TestFixationPrevention_Middleware(t *testing.T) {
	mgr := newFixationMockManager()
	config := DefaultFixationPreventionConfig()
	fp := NewFixationPrevention(config, mgr)

	sessionConfig := configpkg.SessionConfig{
		CookieName:   "_sb.s",
		CookieMaxAge: 3600,
	}

	handlerCalled := false
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	middleware := fp.FixationMiddleware(sessionConfig)
	handler := middleware(innerHandler)

	// Create session without auth data and set X-Auth-State to trigger regeneration
	session := &reqctx.SessionData{
		ID:        "fixation-test-session",
		CreatedAt: time.Now().Add(-10 * time.Minute),
		Data:      map[string]any{"key": "value"},
	}

	requestData := &reqctx.RequestData{
		SessionData: session,
	}

	ctx := reqctx.SetRequestData(context.Background(), requestData)
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil).WithContext(ctx)
	req.Header.Set(authStateHeader, "authenticated")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !handlerCalled {
		t.Error("expected inner handler to be called")
	}

	// Verify session was regenerated (Set-Cookie should be present)
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Error("expected Set-Cookie header after session regeneration")
	}
}

func TestFixationPrevention_Middleware_NoRegenWhenDisabled(t *testing.T) {
	mgr := newFixationMockManager()
	config := FixationPreventionConfig{Enabled: false}
	fp := NewFixationPrevention(config, mgr)

	sessionConfig := configpkg.SessionConfig{}

	handlerCalled := false
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	middleware := fp.FixationMiddleware(sessionConfig)
	handler := middleware(innerHandler)

	session := &reqctx.SessionData{ID: "test"}
	requestData := &reqctx.RequestData{SessionData: session}
	ctx := reqctx.SetRequestData(context.Background(), requestData)
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	req.Header.Set(authStateHeader, "authenticated")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !handlerCalled {
		t.Error("expected inner handler to be called")
	}

	// No cookie should be set since fixation prevention is disabled
	cookies := rec.Result().Cookies()
	if len(cookies) > 0 {
		t.Error("expected no Set-Cookie header when fixation prevention is disabled")
	}
}

func TestFixationPrevention_Middleware_NoDuplicateRegeneration(t *testing.T) {
	mgr := newFixationMockManager()
	config := DefaultFixationPreventionConfig()
	fp := NewFixationPrevention(config, mgr)

	sessionConfig := configpkg.SessionConfig{
		CookieName:   "_sb.s",
		CookieMaxAge: 3600,
	}

	regenCount := 0
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that the context has the regenerated marker
		if wasRegenerated(r.Context()) {
			regenCount++
		}
	})

	// Stack two fixation middlewares
	middleware := fp.FixationMiddleware(sessionConfig)
	handler := middleware(middleware(innerHandler))

	session := &reqctx.SessionData{
		ID:   "double-regen-test",
		Data: map[string]any{},
	}

	requestData := &reqctx.RequestData{SessionData: session}
	ctx := reqctx.SetRequestData(context.Background(), requestData)
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	req.Header.Set(authStateHeader, "authenticated")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if regenCount != 1 {
		t.Errorf("expected regeneration marker set once, but inner handler saw it %d times", regenCount)
	}
}

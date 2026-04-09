package configloader

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/config/forward"
	"github.com/soapbucket/sbproxy/internal/config/rule"
	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/request/geoip"
	"github.com/soapbucket/sbproxy/internal/platform/messenger"
	"github.com/soapbucket/sbproxy/internal/cache/object"
	"github.com/soapbucket/sbproxy/internal/platform/storage"
	"github.com/soapbucket/sbproxy/internal/request/uaparser"
)

// Mock Storage implementation
type mockStorage struct {
	mu              sync.Mutex
	data            map[string][]byte
	dataByID        map[string][]byte
	proxyValidation map[string]*storage.ProxyKeyValidationResult
	getError        error
	getErrors       map[string]error
	callCount       int
}

func (m *mockStorage) Get(ctx context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount++
	if m.getErrors != nil {
		if err, ok := m.getErrors[key]; ok && err != nil {
			return nil, err
		}
	}
	if m.getError != nil {
		return nil, m.getError
	}
	if data, ok := m.data[key]; ok {
		return data, nil
	}
	return nil, storage.ErrKeyNotFound
}

func (m *mockStorage) GetByID(ctx context.Context, id string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dataByID != nil {
		if data, ok := m.dataByID[id]; ok {
			return data, nil
		}
	}
	if data, ok := m.data[id]; ok {
		return data, nil
	}
	return nil, storage.ErrKeyNotFound
}

func (m *mockStorage) Put(ctx context.Context, key string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = data
	return nil
}

func (m *mockStorage) Delete(ctx context.Context, key string) error {
	delete(m.data, key)
	return nil
}

func (m *mockStorage) DeleteByPrefix(ctx context.Context, prefix string) error {
	return errors.New("not implemented")
}

func (m *mockStorage) Driver() string {
	return "mock"
}

func (m *mockStorage) Close() error {
	return nil
}

func (m *mockStorage) ListKeys(ctx context.Context) ([]string, error) {
	keys := make([]string, 0, len(m.data))
	for k := range m.data {
		keys = append(keys, k)
	}
	return keys, nil
}

func (m *mockStorage) ListKeysByWorkspace(ctx context.Context, workspaceID string) ([]string, error) {
	return nil, nil
}

func (m *mockStorage) ValidateProxyAPIKey(ctx context.Context, originID string, apiKey string) (*storage.ProxyKeyValidationResult, error) {
	if m.proxyValidation == nil {
		return nil, errors.New("not implemented")
	}
	if result, ok := m.proxyValidation[originID+":"+apiKey]; ok {
		return result, nil
	}
	return nil, errors.New("invalid proxy API key")
}

// Mock Manager implementation
type mockManager struct {
	storage  storage.Storage
	settings manager.GlobalSettings
}

func (m *mockManager) GetStorage() storage.Storage {
	return m.storage
}

func (m *mockManager) GetGlobalSettings() manager.GlobalSettings {
	return m.settings
}

func (m *mockManager) GetCachePool() manager.WorkerPool {
	return nil
}

func (m *mockManager) GetCallbackPool() manager.WorkerPool {
	return nil
}

func (m *mockManager) GetServerContext() context.Context {
	return context.Background()
}

func (m *mockManager) GetLocation(*http.Request) (*geoip.Result, error) {
	return nil, errors.New("not implemented")
}

func (m *mockManager) GetUserAgent(*http.Request) (*uaparser.Result, error) {
	return nil, errors.New("not implemented")
}

func (m *mockManager) EncryptString(s string) (string, error) {
	return s, nil
}

func (m *mockManager) EncryptStringWithContext(data string, context string) (string, error) {
	return data, nil
}

func (m *mockManager) DecryptString(s string) (string, error) {
	return s, nil
}

func (m *mockManager) DecryptStringWithContext(data string, context string) (string, error) {
	return data, nil
}

func (m *mockManager) SignString(s string) (string, error) {
	return s, nil
}

func (m *mockManager) VerifyString(s1, s2 string) (bool, error) {
	return true, nil
}

func (m *mockManager) GetSessionCache() manager.SessionCache {
	return &mockSessionCache{
		sessions: make(map[string][]byte),
	}
}

// mockSessionCache is a simple in-memory session cache for testing
type mockSessionCache struct {
	sessions map[string][]byte
	mu       sync.RWMutex
}

func (m *mockSessionCache) Get(ctx context.Context, sessionID string) (io.Reader, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if data, ok := m.sessions[sessionID]; ok {
		return bytes.NewReader(data), nil
	}
	return nil, cacher.ErrNotFound
}

func (m *mockSessionCache) Put(ctx context.Context, sessionID string, session io.Reader, expires time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := io.ReadAll(session)
	if err != nil {
		return err
	}
	m.sessions[sessionID] = data
	return nil
}

func (m *mockSessionCache) Delete(ctx context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, sessionID)
	return nil
}

func (m *mockManager) GetCache(level manager.CacheLevel) cacher.Cacher {
	return nil
}

func (m *mockManager) GetMessenger() messenger.Messenger {
	return nil
}

func (m *mockManager) Close() error {
	return nil
}

// Helper function to create a config JSON
func createConfigJSON(hostname, id string, disabled bool, forwardRules []forward.ForwardRule) []byte {
	// Create a minimal valid config with a noop action
	configMap := map[string]interface{}{
		"id":           id,
		"hostname":     hostname,
		"workspace_id": "test-workspace",
		"disabled":     disabled,
		"action": map[string]interface{}{
			"action_type": "noop",
		},
	}

	if len(forwardRules) > 0 {
		configMap["forward_rules"] = forwardRules
	}

	data, _ := json.Marshal(configMap)
	return data
}

// Helper function to reset the package-level cache
func resetCache() {
	cache, _ = objectcache.NewObjectCache(10*time.Minute, 1*time.Minute, 1000, 100*1024*1024)
	failsafeSnapshots.resetForTests()
}

func TestLoad(t *testing.T) {
	resetCache()

	tests := []struct {
		name       string
		hostname   string
		configData []byte
		wantErr    bool
		wantID     string
	}{
		{
			name:       "load existing config",
			hostname:   "example.com",
			configData: createConfigJSON("example.com", "config-1", false, nil),
			wantErr:    false,
			wantID:     "config-1",
		},
		{
			name:       "load non-existent config returns null-config",
			hostname:   "notfound.com",
			configData: nil,
			wantErr:    false,
			wantID:     "null-config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCache()

			storage := &mockStorage{
				data: make(map[string][]byte),
			}

			if tt.configData != nil {
				storage.data[tt.hostname] = tt.configData
			}

			mgr := &mockManager{
				storage: storage,
				settings: manager.GlobalSettings{
					OriginLoaderSettings: manager.OriginLoaderSettings{
						MaxOriginForwardDepth: DefaultMaxForwardDepth,
					},
				},
			}

			req := httptest.NewRequest(http.MethodGet, "http://"+tt.hostname+"/", nil)
			req.Host = tt.hostname

			cfg, err := Load(req, mgr)

			if (err != nil) != tt.wantErr {
				t.Errorf("Load() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && cfg.ID != tt.wantID {
				t.Errorf("Load() config ID = %v, want %v", cfg.ID, tt.wantID)
			}
		})
	}
}

func TestGetConfigByHostname_CacheHit(t *testing.T) {
	resetCache()

	storage := &mockStorage{
		data: make(map[string][]byte),
	}
	storage.data["example.com"] = createConfigJSON("example.com", "config-1", false, nil)

	mgr := &mockManager{
		storage: storage,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: DefaultMaxForwardDepth,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Host = "example.com"

	// First call - cache miss, loads from storage
	cfg1, err := getConfigByHostname(context.Background(), req, "example.com", 0, mgr, nil)
	if err != nil {
		t.Fatalf("getConfigByHostname() error = %v", err)
	}
	if cfg1.ID != "config-1" {
		t.Errorf("First call config ID = %v, want config-1", cfg1.ID)
	}
	if storage.callCount != 1 {
		t.Errorf("Expected 1 storage call, got %d", storage.callCount)
	}

	// Second call - should hit cache, no storage call
	cfg2, err := getConfigByHostname(context.Background(), req, "example.com", 0, mgr, nil)
	if err != nil {
		t.Fatalf("getConfigByHostname() error = %v", err)
	}
	if cfg2.ID != "config-1" {
		t.Errorf("Second call config ID = %v, want config-1", cfg2.ID)
	}
	if storage.callCount != 1 {
		t.Errorf("Expected 1 storage call (cache hit), got %d", storage.callCount)
	}
}

func TestGetConfigByHostname_MaxForwardDepth(t *testing.T) {
	resetCache()

	storage := &mockStorage{
		data: make(map[string][]byte),
	}

	// Create a chain of forwards that exceeds max depth
	storage.data["host1.com"] = createConfigJSON("host1.com", "config-1", false, []forward.ForwardRule{
		{Hostname: "host2.com"},
	})
	storage.data["host2.com"] = createConfigJSON("host2.com", "config-2", false, []forward.ForwardRule{
		{Hostname: "host3.com"},
	})
	storage.data["host3.com"] = createConfigJSON("host3.com", "config-3", false, []forward.ForwardRule{
		{Hostname: "host4.com"},
	})

	mgr := &mockManager{
		storage: storage,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 2, // Set max depth to 2
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://host1.com/", nil)
	req.Host = "host1.com"

	_, err := getConfigByHostname(context.Background(), req, "host1.com", 0, mgr, nil)
	if !errors.Is(err, ErrMaxForwardDepthReached) {
		t.Errorf("Expected ErrMaxForwardDepthReached, got %v", err)
	}
}

func TestGetConfigByHostname_ForwardRules(t *testing.T) {
	resetCache()

	storage := &mockStorage{
		data: make(map[string][]byte),
	}

	// host1.com forwards to host2.com
	storage.data["host1.com"] = createConfigJSON("host1.com", "config-1", false, []forward.ForwardRule{
		{Hostname: "host2.com"},
	})
	storage.data["host2.com"] = createConfigJSON("host2.com", "config-2", false, nil)

	mgr := &mockManager{
		storage: storage,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: DefaultMaxForwardDepth,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://host1.com/", nil)
	req.Host = "host1.com"

	cfg, err := getConfigByHostname(context.Background(), req, "host1.com", 0, mgr, nil)
	if err != nil {
		t.Fatalf("getConfigByHostname() error = %v", err)
	}

	// Should return config-2 (forwarded)
	if cfg.ID != "config-2" {
		t.Errorf("Expected forwarded config ID config-2, got %v", cfg.ID)
	}

	// Should have parent set
	if cfg.Parent == nil {
		t.Error("Expected parent to be set")
	} else if cfg.Parent.ID != "config-1" {
		t.Errorf("Expected parent ID config-1, got %v", cfg.Parent.ID)
	}
}

func TestGetConfigByHostname_HostnameFallback(t *testing.T) {
	resetCache()

	storage := &mockStorage{
		data: make(map[string][]byte),
	}

	// Only store config for hostname without port
	storage.data["example.com"] = createConfigJSON("example.com", "config-1", false, nil)

	mgr := &mockManager{
		storage: storage,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: DefaultMaxForwardDepth,
				HostnameFallback:      true,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com:8080/", nil)
	req.Host = "example.com:8080"

	cfg, err := getConfigByHostname(context.Background(), req, "example.com:8080", 0, mgr, nil)
	if err != nil {
		t.Fatalf("getConfigByHostname() error = %v", err)
	}

	// Should fallback and find config-1
	if cfg.ID != "config-1" {
		t.Errorf("Expected config-1 (from fallback), got %v", cfg.ID)
	}
}

func TestGetConfigByHostname_NoHostnameFallback(t *testing.T) {
	resetCache()

	storage := &mockStorage{
		data: make(map[string][]byte),
	}

	// Only store config for hostname without port
	storage.data["example.com"] = createConfigJSON("example.com", "config-1", false, nil)

	mgr := &mockManager{
		storage: storage,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: DefaultMaxForwardDepth,
				HostnameFallback:      false, // Disabled
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com:8080/", nil)
	req.Host = "example.com:8080"

	cfg, err := getConfigByHostname(context.Background(), req, "example.com:8080", 0, mgr, nil)
	if err != nil {
		t.Fatalf("getConfigByHostname() error = %v", err)
	}

	// Should return null-config since fallback is disabled
	if cfg.ID != "null-config" {
		t.Errorf("Expected null-config, got %v", cfg.ID)
	}
	if !cfg.Disabled {
		t.Error("Expected null-config to be disabled")
	}
}

func TestGetConfigByHostname_NullConfig(t *testing.T) {
	resetCache()

	storage := &mockStorage{
		data: make(map[string][]byte),
	}

	mgr := &mockManager{
		storage: storage,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: DefaultMaxForwardDepth,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://notfound.com/", nil)
	req.Host = "notfound.com"

	cfg, err := getConfigByHostname(context.Background(), req, "notfound.com", 0, mgr, nil)
	if err != nil {
		t.Fatalf("getConfigByHostname() error = %v", err)
	}

	if cfg.ID != "null-config" {
		t.Errorf("Expected null-config ID, got %v", cfg.ID)
	}
	if !cfg.Disabled {
		t.Error("Expected null-config to be disabled")
	}
	if cfg.Hostname != "notfound.com" {
		t.Errorf("Expected hostname notfound.com, got %v", cfg.Hostname)
	}
}

func TestGetConfigByHostname_StorageError(t *testing.T) {
	resetCache()

	expectedErr := errors.New("storage connection error")
	storage := &mockStorage{
		data:     make(map[string][]byte),
		getError: expectedErr,
	}

	mgr := &mockManager{
		storage: storage,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: DefaultMaxForwardDepth,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Host = "example.com"

	_, err := getConfigByHostname(context.Background(), req, "example.com", 0, mgr, nil)
	if err == nil {
		t.Error("Expected error from storage, got nil")
	}
	if !errors.Is(err, expectedErr) {
		t.Errorf("Expected error %v, got %v", expectedErr, err)
	}
}

func TestGetConfigByHostname_InvalidJSON(t *testing.T) {
	resetCache()

	storage := &mockStorage{
		data: make(map[string][]byte),
	}
	storage.data["example.com"] = []byte("invalid json")

	mgr := &mockManager{
		storage: storage,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: DefaultMaxForwardDepth,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Host = "example.com"

	_, err := getConfigByHostname(context.Background(), req, "example.com", 0, mgr, nil)
	if err == nil {
		t.Error("Expected JSON unmarshal error, got nil")
	}
}

func TestGetConfigByHostname_DefaultMaxForwardDepth(t *testing.T) {
	resetCache()

	storage := &mockStorage{
		data: make(map[string][]byte),
	}
	storage.data["example.com"] = createConfigJSON("example.com", "config-1", false, nil)

	mgr := &mockManager{
		storage: storage,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 0, // Should use DefaultMaxForwardDepth
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Host = "example.com"

	// Try to exceed DefaultMaxForwardDepth
	_, err := getConfigByHostname(context.Background(), req, "example.com", DefaultMaxForwardDepth+1, mgr, nil)
	if !errors.Is(err, ErrMaxForwardDepthReached) {
		t.Errorf("Expected ErrMaxForwardDepthReached with default depth, got %v", err)
	}
}

func TestGetConfigByHostname_ParentChain(t *testing.T) {
	resetCache()

	storage := &mockStorage{
		data: make(map[string][]byte),
	}

	// Create a chain: host1 -> host2 -> host3
	storage.data["host1.com"] = createConfigJSON("host1.com", "config-1", false, []forward.ForwardRule{
		{Hostname: "host2.com"},
	})
	storage.data["host2.com"] = createConfigJSON("host2.com", "config-2", false, []forward.ForwardRule{
		{Hostname: "host3.com"},
	})
	storage.data["host3.com"] = createConfigJSON("host3.com", "config-3", false, nil)

	mgr := &mockManager{
		storage: storage,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: DefaultMaxForwardDepth,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://host1.com/", nil)
	req.Host = "host1.com"

	cfg, err := getConfigByHostname(context.Background(), req, "host1.com", 0, mgr, nil)
	if err != nil {
		t.Fatalf("getConfigByHostname() error = %v", err)
	}

	// Should return config-3
	if cfg.ID != "config-3" {
		t.Errorf("Expected final config ID config-3, got %v", cfg.ID)
	}

	// Verify parent chain: config-3 -> config-2 -> config-1
	if cfg.Parent == nil {
		t.Fatal("Expected parent to be set")
	}
	if cfg.Parent.ID != "config-2" {
		t.Errorf("Expected parent ID config-2, got %v", cfg.Parent.ID)
	}
	if cfg.Parent.Parent == nil {
		t.Fatal("Expected grandparent to be set")
	}
	if cfg.Parent.Parent.ID != "config-1" {
		t.Errorf("Expected grandparent ID config-1, got %v", cfg.Parent.Parent.ID)
	}
}

func TestGetConfigByHostname_CachedForwardRule(t *testing.T) {
	resetCache()

	storage := &mockStorage{
		data: make(map[string][]byte),
	}

	// host1.com forwards to host2.com
	storage.data["host1.com"] = createConfigJSON("host1.com", "config-1", false, []forward.ForwardRule{
		{Hostname: "host2.com"},
	})
	storage.data["host2.com"] = createConfigJSON("host2.com", "config-2", false, nil)

	mgr := &mockManager{
		storage: storage,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: DefaultMaxForwardDepth,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://host1.com/", nil)
	req.Host = "host1.com"

	// First call - loads from storage and follows forward
	cfg1, err := getConfigByHostname(context.Background(), req, "host1.com", 0, mgr, nil)
	if err != nil {
		t.Fatalf("getConfigByHostname() error = %v", err)
	}
	if cfg1.ID != "config-2" {
		t.Errorf("First call: expected config-2, got %v", cfg1.ID)
	}

	firstCallCount := storage.callCount

	// Second call - should use cache and still follow forward
	cfg2, err := getConfigByHostname(context.Background(), req, "host1.com", 0, mgr, nil)
	if err != nil {
		t.Fatalf("getConfigByHostname() error = %v", err)
	}
	if cfg2.ID != "config-2" {
		t.Errorf("Second call: expected config-2, got %v", cfg2.ID)
	}

	// The cached config should apply forward rules, so we might get additional storage calls
	// But host1.com should be cached
	if storage.callCount > firstCallCount+1 {
		t.Errorf("Expected at most %d storage calls, got %d", firstCallCount+1, storage.callCount)
	}
}

// createConfigJSONWithRequestRules creates a config JSON with request_rules and must_match_rules
func createConfigJSONWithRequestRules(hostname, id string, requestRules []rule.RequestRule, mustMatchRules bool) []byte {
	configMap := map[string]interface{}{
		"id":           id,
		"hostname":     hostname,
		"workspace_id": "test-workspace",
		"action": map[string]interface{}{
			"action_type": "noop",
		},
	}
	if len(requestRules) > 0 {
		configMap["request_rules"] = requestRules
	}
	if mustMatchRules {
		configMap["must_match_rules"] = true
	}
	data, _ := json.Marshal(configMap)
	return data
}

func TestMustMatchRules_NoRules_LoadsNormally(t *testing.T) {
	resetCache()

	// Config with must_match_rules=true but no request_rules should load normally
	stor := &mockStorage{data: make(map[string][]byte)}
	stor.data["example.com"] = createConfigJSONWithRequestRules("example.com", "config-1", nil, true)

	mgr := &mockManager{
		storage: stor,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: DefaultMaxForwardDepth,
				HostnameFallback:      true,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/anything", nil)
	req.Host = "example.com"

	cfg, err := getConfigByHostname(context.Background(), req, "example.com", 0, mgr, nil)
	if err != nil {
		t.Fatalf("getConfigByHostname() error = %v", err)
	}
	if cfg.ID != "config-1" {
		t.Errorf("Expected config-1, got %v", cfg.ID)
	}
	if cfg.Disabled {
		t.Error("Config should not be disabled")
	}
}

func TestMustMatchRules_Match_LoadsConfig(t *testing.T) {
	resetCache()

	requestRules := []rule.RequestRule{
		{Path: &rule.PathConditions{Prefix: "/api"}},
	}
	stor := &mockStorage{data: make(map[string][]byte)}
	stor.data["example.com"] = createConfigJSONWithRequestRules("example.com", "config-1", requestRules, true)

	mgr := &mockManager{
		storage: stor,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: DefaultMaxForwardDepth,
				HostnameFallback:      true,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/api/test", nil)
	req.Host = "example.com"

	cfg, err := getConfigByHostname(context.Background(), req, "example.com", 0, mgr, nil)
	if err != nil {
		t.Fatalf("getConfigByHostname() error = %v", err)
	}
	if cfg.ID != "config-1" {
		t.Errorf("Expected config-1, got %v", cfg.ID)
	}
	if cfg.Disabled {
		t.Error("Config should not be disabled for matching request")
	}
}

func TestMustMatchRules_NoMatch_ReturnsDisabled(t *testing.T) {
	resetCache()

	requestRules := []rule.RequestRule{
		{Path: &rule.PathConditions{Prefix: "/api"}},
	}
	stor := &mockStorage{data: make(map[string][]byte)}
	stor.data["example.com"] = createConfigJSONWithRequestRules("example.com", "config-1", requestRules, true)

	mgr := &mockManager{
		storage: stor,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: DefaultMaxForwardDepth,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/other", nil)
	req.Host = "example.com"

	cfg, err := getConfigByHostname(context.Background(), req, "example.com", 0, mgr, nil)
	if err != nil {
		t.Fatalf("getConfigByHostname() error = %v", err)
	}
	if cfg.ID != "rules-not-matched" {
		t.Errorf("Expected rules-not-matched, got %v", cfg.ID)
	}
	if !cfg.Disabled {
		t.Error("Config should be disabled for non-matching request")
	}
}

func TestMustMatchRules_False_LoadsRegardless(t *testing.T) {
	resetCache()

	requestRules := []rule.RequestRule{
		{Path: &rule.PathConditions{Prefix: "/api"}},
	}
	// must_match_rules=false (default), so configloader should load normally
	stor := &mockStorage{data: make(map[string][]byte)}
	stor.data["example.com"] = createConfigJSONWithRequestRules("example.com", "config-1", requestRules, false)

	mgr := &mockManager{
		storage: stor,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: DefaultMaxForwardDepth,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/other", nil)
	req.Host = "example.com"

	cfg, err := getConfigByHostname(context.Background(), req, "example.com", 0, mgr, nil)
	if err != nil {
		t.Fatalf("getConfigByHostname() error = %v", err)
	}
	if cfg.ID != "config-1" {
		t.Errorf("Expected config-1 (handler will 404, not configloader), got %v", cfg.ID)
	}
	if cfg.Disabled {
		t.Error("Config should not be disabled when must_match_rules is false")
	}
}

// --- Wildcard Hostname Fallback Tests ---

func createSimpleConfigJSON(hostname, id string) []byte {
	configMap := map[string]interface{}{
		"id":           id,
		"hostname":     hostname,
		"workspace_id": "test-workspace",
		"action": map[string]interface{}{
			"action_type": "noop",
		},
	}
	data, _ := json.Marshal(configMap)
	return data
}

func TestWildcardFallback_ExactMatchTakesPriority(t *testing.T) {
	resetCache()

	stor := &mockStorage{data: make(map[string][]byte)}
	stor.data["api.example.com"] = createSimpleConfigJSON("api.example.com", "exact-config")
	stor.data["*.example.com"] = createSimpleConfigJSON("*.example.com", "wildcard-config")

	mgr := &mockManager{
		storage: stor,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: DefaultMaxForwardDepth,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/", nil)
	req.Host = "api.example.com"

	cfg, err := getConfigByHostname(context.Background(), req, "api.example.com", 0, mgr, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if cfg.ID != "exact-config" {
		t.Errorf("expected exact-config, got %s", cfg.ID)
	}
}

func TestWildcardFallback_MatchesWildcard(t *testing.T) {
	resetCache()

	stor := &mockStorage{data: make(map[string][]byte)}
	stor.data["*.example.com"] = createSimpleConfigJSON("*.example.com", "wildcard-config")

	mgr := &mockManager{
		storage: stor,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: DefaultMaxForwardDepth,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://foo.example.com/", nil)
	req.Host = "foo.example.com"

	cfg, err := getConfigByHostname(context.Background(), req, "foo.example.com", 0, mgr, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if cfg.ID != "wildcard-config" {
		t.Errorf("expected wildcard-config, got %s", cfg.ID)
	}
}

func TestWildcardFallback_NoWildcard_ReturnsNullConfig(t *testing.T) {
	resetCache()

	stor := &mockStorage{data: make(map[string][]byte)}

	mgr := &mockManager{
		storage: stor,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: DefaultMaxForwardDepth,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://unknown.example.com/", nil)
	req.Host = "unknown.example.com"

	cfg, err := getConfigByHostname(context.Background(), req, "unknown.example.com", 0, mgr, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if cfg.ID != "null-config" {
		t.Errorf("expected null-config, got %s", cfg.ID)
	}
}

func TestWildcardFallback_PortStrippedBeforeWildcard(t *testing.T) {
	resetCache()

	stor := &mockStorage{data: make(map[string][]byte)}
	stor.data["*.example.com"] = createSimpleConfigJSON("*.example.com", "wildcard-config")

	mgr := &mockManager{
		storage: stor,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: DefaultMaxForwardDepth,
				HostnameFallback:      true,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com:8080/", nil)
	req.Host = "api.example.com:8080"

	cfg, err := getConfigByHostname(context.Background(), req, "api.example.com:8080", 0, mgr, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if cfg.ID != "wildcard-config" {
		t.Errorf("expected wildcard-config (via port strip then wildcard), got %s", cfg.ID)
	}
}

// --- Host Filter Pre-Check Tests ---

type mockHostFilter struct {
	allow       bool
	lastChecked string
}

func (m *mockHostFilter) Check(hostname string) bool {
	m.lastChecked = hostname
	return m.allow
}

func TestHostFilter_Rejects(t *testing.T) {
	resetCache()

	// Set host filter that rejects everything
	oldFilter := hostFilter
	hostFilter = &mockHostFilter{allow: false}
	defer func() { hostFilter = oldFilter }()

	stor := &mockStorage{data: make(map[string][]byte)}
	stor.data["example.com"] = createSimpleConfigJSON("example.com", "config-1")

	mgr := &mockManager{
		storage: stor,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: DefaultMaxForwardDepth,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Host = "example.com"

	cfg, err := Load(req, mgr)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if cfg.ID != "host-filtered" {
		t.Errorf("expected host-filtered, got %s", cfg.ID)
	}
	if !cfg.Disabled {
		t.Error("expected disabled config for filtered host")
	}
}

func TestHostFilter_Passes(t *testing.T) {
	resetCache()

	// Set host filter that allows everything
	oldFilter := hostFilter
	hostFilter = &mockHostFilter{allow: true}
	defer func() { hostFilter = oldFilter }()

	stor := &mockStorage{data: make(map[string][]byte)}
	stor.data["example.com"] = createSimpleConfigJSON("example.com", "config-1")

	mgr := &mockManager{
		storage: stor,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: DefaultMaxForwardDepth,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Host = "example.com"

	cfg, err := Load(req, mgr)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if cfg.ID == "host-filtered" {
		t.Errorf("expected host filter pass, got host-filtered config")
	}
}

func TestHostFilter_NormalizesHostPortBeforeCheck(t *testing.T) {
	resetCache()

	filter := &mockHostFilter{allow: true}
	oldFilter := hostFilter
	hostFilter = filter
	defer func() { hostFilter = oldFilter }()

	stor := &mockStorage{data: make(map[string][]byte)}
	stor.data["example.com"] = createSimpleConfigJSON("example.com", "config-1")

	mgr := &mockManager{
		storage: stor,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: DefaultMaxForwardDepth,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com:8443/", nil)
	req.Host = "example.com:8443"

	cfg, err := Load(req, mgr)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if cfg.ID == "host-filtered" {
		t.Errorf("expected host filter to pass, got %s", cfg.ID)
	}
	if filter.lastChecked != "example.com" {
		t.Errorf("expected host filter check on normalized hostname example.com, got %s", filter.lastChecked)
	}
}

func TestHostFilter_NilBypassesFilter(t *testing.T) {
	resetCache()

	oldFilter := hostFilter
	hostFilter = nil
	defer func() { hostFilter = oldFilter }()

	stor := &mockStorage{data: make(map[string][]byte)}
	stor.data["example.com"] = createSimpleConfigJSON("example.com", "config-1")

	mgr := &mockManager{
		storage: stor,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: DefaultMaxForwardDepth,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Host = "example.com"

	cfg, err := Load(req, mgr)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if cfg.ID != "config-1" {
		t.Errorf("expected config-1, got %s", cfg.ID)
	}
}

package configloader

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/soapbucket/sbproxy/internal/observe/events"
	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/platform/messenger"
)

type testFailsafeMessenger struct {
	messages map[string][]*messenger.Message
}

func (m *testFailsafeMessenger) Send(ctx context.Context, channel string, msg *messenger.Message) error {
	if m.messages == nil {
		m.messages = make(map[string][]*messenger.Message)
	}
	m.messages[channel] = append(m.messages[channel], msg)
	return nil
}
func (m *testFailsafeMessenger) Subscribe(context.Context, string, func(context.Context, *messenger.Message) error) error {
	return nil
}
func (m *testFailsafeMessenger) Unsubscribe(context.Context, string) error { return nil }
func (m *testFailsafeMessenger) Driver() string                            { return "test" }
func (m *testFailsafeMessenger) Close() error                              { return nil }

func createConfigJSONWithFailsafe(hostname, id string, failsafe map[string]any) []byte {
	configMap := map[string]any{
		"id":           id,
		"hostname":     hostname,
		"workspace_id": "test-workspace",
		"action": map[string]any{
			"action_type": "noop",
		},
	}
	if failsafe != nil {
		configMap["failsafe_origin"] = failsafe
	}
	data, _ := json.Marshal(configMap)
	return data
}

func TestGetConfigByHostname_UsesFailsafeSnapshotOnStorageError(t *testing.T) {
	resetCache()

	stor := &mockStorage{data: make(map[string][]byte)}
	stor.data["example.com"] = createConfigJSON("example.com", "config-1", false, nil)

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

	cfg, err := getConfigByHostname(context.Background(), req, "example.com", 0, mgr, nil)
	if err != nil {
		t.Fatalf("initial load error = %v", err)
	}
	if cfg.ConfigMode != configModeActive {
		t.Fatalf("initial config mode = %q, want %q", cfg.ConfigMode, configModeActive)
	}

	cache.Delete("example.com")
	stor.getErrors = map[string]error{"example.com": context.DeadlineExceeded}

	cfg, err = getConfigByHostname(context.Background(), req, "example.com", 0, mgr, nil)
	if err != nil {
		t.Fatalf("failsafe load error = %v", err)
	}
	if cfg.ConfigMode != configModeFailsafe {
		t.Fatalf("config mode = %q, want %q", cfg.ConfigMode, configModeFailsafe)
	}
	if cfg.ConfigReason != configReasonSourceUnavailable {
		t.Fatalf("config reason = %q, want %q", cfg.ConfigReason, configReasonSourceUnavailable)
	}
}

func TestGetConfigByHostname_UsesFailsafeSnapshotOnInvalidConfig(t *testing.T) {
	resetCache()

	stor := &mockStorage{data: make(map[string][]byte)}
	stor.data["example.com"] = createConfigJSON("example.com", "config-1", false, nil)

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

	if _, err := getConfigByHostname(context.Background(), req, "example.com", 0, mgr, nil); err != nil {
		t.Fatalf("initial load error = %v", err)
	}

	cache.Delete("example.com")
	stor.data["example.com"] = []byte("invalid json")

	cfg, err := getConfigByHostname(context.Background(), req, "example.com", 0, mgr, nil)
	if err != nil {
		t.Fatalf("failsafe load error = %v", err)
	}
	if cfg.ConfigMode != configModeFailsafe {
		t.Fatalf("config mode = %q, want %q", cfg.ConfigMode, configModeFailsafe)
	}
	if cfg.ConfigReason != configReasonLoadFailed {
		t.Fatalf("config reason = %q, want %q", cfg.ConfigReason, configReasonLoadFailed)
	}
}

func TestFailsafeSnapshot_PersistsToDisk(t *testing.T) {
	resetCache()
	t.Setenv(failsafeDirEnv, filepath.Join(t.TempDir(), "failsafe"))

	originalStore := failsafeSnapshots
	failsafeSnapshots = newFailsafeSnapshotStore()
	defer func() {
		failsafeSnapshots = originalStore
		failsafeSnapshots.resetForTests()
	}()

	payload := createConfigJSON("example.com", "config-1", false, nil)
	failsafeSnapshots.save("example.com", "ws-1", "1.0.0", "rev-1", payload, nil)

	failsafeSnapshots = newFailsafeSnapshotStore()
	snapshot, ok := failsafeSnapshots.load("example.com")
	if !ok {
		t.Fatal("expected persisted snapshot to be loaded")
	}
	if snapshot.Revision != "rev-1" {
		t.Fatalf("snapshot revision = %q, want %q", snapshot.Revision, "rev-1")
	}
	if string(snapshot.Payload) != string(payload) {
		t.Fatalf("snapshot payload mismatch")
	}
}

func TestGetConfigByHostname_LkgWinsBeforeExplicitFailsafe(t *testing.T) {
	resetCache()

	stor := &mockStorage{data: make(map[string][]byte)}
	stor.data["failsafe.internal"] = createConfigJSON("failsafe.internal", "failsafe-config", false, nil)
	stor.data["example.com"] = createConfigJSONWithFailsafe("example.com", "primary-config", map[string]any{
		"hostname": "failsafe.internal",
	})

	mgr := &mockManager{
		storage: stor,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{MaxOriginForwardDepth: DefaultMaxForwardDepth},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Host = "example.com"

	if _, err := getConfigByHostname(context.Background(), req, "example.com", 0, mgr, nil); err != nil {
		t.Fatalf("initial load error = %v", err)
	}

	cache.Delete("example.com")
	stor.getError = context.DeadlineExceeded

	cfg, err := getConfigByHostname(context.Background(), req, "example.com", 0, mgr, nil)
	if err != nil {
		t.Fatalf("failsafe load error = %v", err)
	}
	if cfg.ID != "primary-config" {
		t.Fatalf("expected LKG primary-config to win, got %q", cfg.ID)
	}
}

func TestGetConfigByHostname_UsesExplicitFailsafeHostname(t *testing.T) {
	resetCache()

	stor := &mockStorage{data: make(map[string][]byte)}
	stor.data["failsafe.internal"] = createConfigJSONWithFailsafe("failsafe.internal", "failsafe-config", nil)
	stor.data["example.com"] = createConfigJSONWithFailsafe("example.com", "primary-config", map[string]any{
		"hostname": "failsafe.internal",
	})

	mgr := &mockManager{
		storage: stor,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{MaxOriginForwardDepth: DefaultMaxForwardDepth},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Host = "example.com"

	if _, err := getConfigByHostname(context.Background(), req, "example.com", 0, mgr, nil); err != nil {
		t.Fatalf("initial load error = %v", err)
	}

	failsafeSnapshots.mu.Lock()
	failsafeSnapshots.byHost["example.com"].Payload = nil
	failsafeSnapshots.mu.Unlock()
	cache.Delete("example.com")
	stor.getErrors = map[string]error{"example.com": context.DeadlineExceeded}

	cfg, err := getConfigByHostname(context.Background(), req, "example.com", 0, mgr, nil)
	if err != nil {
		t.Fatalf("explicit failsafe load error = %v", err)
	}
	if cfg.ID != "failsafe-config" {
		t.Fatalf("expected failsafe-config, got %q", cfg.ID)
	}
	if cfg.ConfigReason != configReasonExplicitFailsafe {
		t.Fatalf("config reason = %q, want %q", cfg.ConfigReason, configReasonExplicitFailsafe)
	}
}

func TestGetConfigByHostname_ExplicitFailsafeEmitsEventMode(t *testing.T) {
	resetCache()

	msg := &testFailsafeMessenger{}
	events.Init(msg, "test:events")

	stor := &mockStorage{data: make(map[string][]byte)}
	targetData := map[string]any{
		"id":           "failsafe-config",
		"hostname":     "failsafe.internal",
		"workspace_id": "ws-1",
		"version":      "1.0.0",
		"events":       []string{"config.*"},
		"action": map[string]any{
			"action_type": "noop",
		},
	}
	targetJSON, _ := json.Marshal(targetData)
	stor.data["failsafe.internal"] = targetJSON
	stor.data["example.com"] = createConfigJSONWithFailsafe("example.com", "primary-config", map[string]any{
		"hostname": "failsafe.internal",
	})

	mgr := &mockManager{
		storage: stor,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{MaxOriginForwardDepth: DefaultMaxForwardDepth},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Host = "example.com"

	if _, err := getConfigByHostname(context.Background(), req, "example.com", 0, mgr, nil); err != nil {
		t.Fatalf("initial load error = %v", err)
	}

	failsafeSnapshots.mu.Lock()
	failsafeSnapshots.byHost["example.com"].Payload = nil
	failsafeSnapshots.mu.Unlock()
	cache.Delete("example.com")
	stor.getErrors = map[string]error{"example.com": context.DeadlineExceeded}

	if _, err := getConfigByHostname(context.Background(), req, "example.com", 0, mgr, nil); err != nil {
		t.Fatalf("explicit failsafe load error = %v", err)
	}

	channel := "test:events:ws-1"
	if len(msg.messages[channel]) == 0 {
		t.Fatalf("expected config events to be emitted")
	}

	found := false
	for _, message := range msg.messages[channel] {
		var payload map[string]any
		if err := json.Unmarshal(message.Body, &payload); err != nil {
			t.Fatalf("unmarshal event: %v", err)
		}
		if payload["type"] == "config.failsafe_served" {
			if payload["failsafe_mode"] != "explicit_failsafe" {
				t.Fatalf("failsafe_mode = %v, want explicit_failsafe", payload["failsafe_mode"])
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("expected config.failsafe_served event")
	}
}

func TestGetConfigByHostname_UsesExplicitFailsafeEmbeddedOrigin(t *testing.T) {
	resetCache()

	embeddedOrigin := map[string]any{
		"id":           "embedded-failsafe",
		"hostname":     "embedded.internal",
		"workspace_id": "test-workspace",
		"action": map[string]any{
			"action_type": "noop",
		},
	}
	stor := &mockStorage{data: make(map[string][]byte)}
	stor.data["example.com"] = createConfigJSONWithFailsafe("example.com", "primary-config", map[string]any{
		"origin": embeddedOrigin,
	})

	mgr := &mockManager{
		storage: stor,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{MaxOriginForwardDepth: DefaultMaxForwardDepth},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Host = "example.com"

	if _, err := getConfigByHostname(context.Background(), req, "example.com", 0, mgr, nil); err != nil {
		t.Fatalf("initial load error = %v", err)
	}

	failsafeSnapshots.mu.Lock()
	failsafeSnapshots.byHost["example.com"].Payload = nil
	failsafeSnapshots.mu.Unlock()
	cache.Delete("example.com")
	stor.getErrors = map[string]error{"example.com": context.DeadlineExceeded}

	cfg, err := getConfigByHostname(context.Background(), req, "example.com", 0, mgr, nil)
	if err != nil {
		t.Fatalf("embedded failsafe load error = %v", err)
	}
	if cfg.ID != "embedded-failsafe" {
		t.Fatalf("expected embedded-failsafe, got %q", cfg.ID)
	}
}

func TestGetConfigByHostname_UsesWildcardExplicitFailsafe(t *testing.T) {
	resetCache()

	stor := &mockStorage{data: make(map[string][]byte)}
	stor.data["failsafe.internal"] = createConfigJSON("failsafe.internal", "failsafe-config", false, nil)
	stor.data["*.example.com"] = createConfigJSONWithFailsafe("*.example.com", "wildcard-config", map[string]any{
		"hostname": "failsafe.internal",
	})

	mgr := &mockManager{
		storage: stor,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{MaxOriginForwardDepth: DefaultMaxForwardDepth},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://unknown.example.com/", nil)
	req.Host = "unknown.example.com"

	if _, err := getConfigByHostname(context.Background(), req, "*.example.com", 0, mgr, nil); err != nil {
		t.Fatalf("initial wildcard load error = %v", err)
	}

	failsafeSnapshots.mu.Lock()
	failsafeSnapshots.byHost["*.example.com"].Payload = nil
	failsafeSnapshots.mu.Unlock()
	stor.data["*.example.com"] = []byte("invalid json")

	cfg, err := getConfigByHostname(context.Background(), req, "unknown.example.com", 0, mgr, nil)
	if err != nil {
		t.Fatalf("wildcard explicit failsafe load error = %v", err)
	}
	if cfg.ID != "failsafe-config" {
		t.Fatalf("expected failsafe-config, got %q", cfg.ID)
	}
}

func BenchmarkGetConfigByHostname_CacheHit(b *testing.B) {
	resetCache()

	stor := &mockStorage{data: make(map[string][]byte)}
	stor.data["example.com"] = createConfigJSON("example.com", "config-1", false, nil)

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

	if _, err := getConfigByHostname(context.Background(), req, "example.com", 0, mgr, nil); err != nil {
		b.Fatalf("warmup load error = %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfg, err := getConfigByHostname(context.Background(), req, "example.com", 0, mgr, nil)
		if err != nil {
			b.Fatalf("cache hit error = %v", err)
		}
		if cfg == nil {
			b.Fatal("nil config on cache hit")
		}
	}
}

func BenchmarkGetConfigByHostname_FailsafeSnapshot(b *testing.B) {
	resetCache()

	stor := &mockStorage{data: make(map[string][]byte)}
	stor.data["example.com"] = createConfigJSON("example.com", "config-1", false, nil)

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

	if _, err := getConfigByHostname(context.Background(), req, "example.com", 0, mgr, nil); err != nil {
		b.Fatalf("warmup load error = %v", err)
	}

	cache.Delete("example.com")
	stor.getError = context.DeadlineExceeded

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfg, err := getConfigByHostname(context.Background(), req, "example.com", 0, mgr, nil)
		if err != nil {
			b.Fatalf("failsafe snapshot error = %v", err)
		}
		if cfg == nil {
			b.Fatal("nil config on failsafe snapshot path")
		}
	}
}

func BenchmarkGetConfigByHostname_ExplicitFailsafeHostname(b *testing.B) {
	resetCache()

	stor := &mockStorage{data: make(map[string][]byte)}
	stor.data["failsafe.internal"] = createConfigJSON("failsafe.internal", "failsafe-config", false, nil)
	stor.data["example.com"] = createConfigJSONWithFailsafe("example.com", "primary-config", map[string]any{
		"hostname": "failsafe.internal",
	})

	mgr := &mockManager{
		storage: stor,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{MaxOriginForwardDepth: DefaultMaxForwardDepth},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Host = "example.com"

	if _, err := getConfigByHostname(context.Background(), req, "example.com", 0, mgr, nil); err != nil {
		b.Fatalf("warmup load error = %v", err)
	}

	failsafeSnapshots.mu.Lock()
	failsafeSnapshots.byHost["example.com"].Payload = nil
	failsafeSnapshots.mu.Unlock()
	cache.Delete("example.com")
	stor.getErrors = map[string]error{"example.com": context.DeadlineExceeded}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfg, err := getConfigByHostname(context.Background(), req, "example.com", 0, mgr, nil)
		if err != nil {
			b.Fatalf("explicit failsafe error = %v", err)
		}
		if cfg == nil {
			b.Fatal("nil config on explicit failsafe path")
		}
	}
}

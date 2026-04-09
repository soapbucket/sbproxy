package featureflags

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/platform/messenger"
)

func TestCacheManager_GetFlags_Empty(t *testing.T) {
	cm := &cacheManager{
		cache:         make(map[string]map[string]any),
		defaultValues: map[string]any{"dark_mode": false},
	}

	flags := cm.GetFlags(context.Background(), "ws-1")
	if flags["dark_mode"] != false {
		t.Errorf("dark_mode = %v, want false", flags["dark_mode"])
	}
}

func TestCacheManager_GetFlags_Defaults(t *testing.T) {
	cm := &cacheManager{
		cache:         make(map[string]map[string]any),
		defaultValues: map[string]any{"dark_mode": false, "max_requests": 1000},
	}

	flags := cm.GetFlags(context.Background(), "ws-1")
	if len(flags) != 2 {
		t.Fatalf("GetFlags() returned %d items, want 2", len(flags))
	}
	if flags["dark_mode"] != false {
		t.Errorf("dark_mode = %v, want false", flags["dark_mode"])
	}
	if flags["max_requests"] != 1000 {
		t.Errorf("max_requests = %v, want 1000", flags["max_requests"])
	}
}

func TestCacheManager_GetFlags_WorkspaceOverride(t *testing.T) {
	cm := &cacheManager{
		cache: map[string]map[string]any{
			"ws-1": {"dark_mode": true, "custom_flag": "enabled"},
		},
		defaultValues: map[string]any{"dark_mode": false, "max_requests": 1000},
	}

	flags := cm.GetFlags(context.Background(), "ws-1")
	if flags["dark_mode"] != true {
		t.Errorf("dark_mode = %v, want true (overridden)", flags["dark_mode"])
	}
	if flags["max_requests"] != 1000 {
		t.Errorf("max_requests = %v, want 1000 (default)", flags["max_requests"])
	}
	if flags["custom_flag"] != "enabled" {
		t.Errorf("custom_flag = %v, want enabled", flags["custom_flag"])
	}
}

func TestCacheManager_GetFlag(t *testing.T) {
	cm := &cacheManager{
		cache: map[string]map[string]any{
			"ws-1": {"feature_x": true},
		},
		defaultValues: map[string]any{"feature_y": "default_val"},
	}

	// Workspace-level flag
	val, ok := cm.GetFlag(context.Background(), "ws-1", "feature_x")
	if !ok || val != true {
		t.Errorf("GetFlag(feature_x) = (%v, %v), want (true, true)", val, ok)
	}

	// Default flag
	val, ok = cm.GetFlag(context.Background(), "ws-1", "feature_y")
	if !ok || val != "default_val" {
		t.Errorf("GetFlag(feature_y) = (%v, %v), want (default_val, true)", val, ok)
	}

	// Missing flag
	_, ok = cm.GetFlag(context.Background(), "ws-1", "nonexistent")
	if ok {
		t.Error("GetFlag(nonexistent) returned true, want false")
	}
}

func TestCacheManager_HandleMessage_Set(t *testing.T) {
	cm := &cacheManager{
		cache:                make(map[string]map[string]any),
		defaultValues:        make(map[string]any),
		maxWorkspaces:        defaultMaxWorkspaces,
		maxFlagsPerWorkspace: defaultMaxFlagsPerWorkspace,
	}

	payload, _ := json.Marshal(flagMessage{
		WorkspaceID: "ws-1",
		Action:      "set",
		Key:         "dark_mode",
		Value:       true,
	})

	err := cm.handleMessage(context.Background(), &messenger.Message{Body: payload})
	if err != nil {
		t.Fatalf("handleMessage() error: %v", err)
	}

	val, ok := cm.GetFlag(context.Background(), "ws-1", "dark_mode")
	if !ok || val != true {
		t.Errorf("after set: GetFlag(dark_mode) = (%v, %v), want (true, true)", val, ok)
	}
}

func TestCacheManager_HandleMessage_Delete(t *testing.T) {
	cm := &cacheManager{
		cache: map[string]map[string]any{
			"ws-1": {"dark_mode": true, "other": "val"},
		},
		defaultValues: make(map[string]any),
	}

	payload, _ := json.Marshal(flagMessage{
		WorkspaceID: "ws-1",
		Action:      "delete",
		Key:         "dark_mode",
	})

	err := cm.handleMessage(context.Background(), &messenger.Message{Body: payload})
	if err != nil {
		t.Fatalf("handleMessage() error: %v", err)
	}

	_, ok := cm.GetFlag(context.Background(), "ws-1", "dark_mode")
	if ok {
		t.Error("dark_mode should be deleted")
	}

	// other flag should still exist
	val, ok := cm.GetFlag(context.Background(), "ws-1", "other")
	if !ok || val != "val" {
		t.Errorf("other flag should still exist, got (%v, %v)", val, ok)
	}
}

func TestCacheManager_HandleMessage_Invalid(t *testing.T) {
	cm := &cacheManager{
		cache:                make(map[string]map[string]any),
		defaultValues:        make(map[string]any),
		maxWorkspaces:        defaultMaxWorkspaces,
		maxFlagsPerWorkspace: defaultMaxFlagsPerWorkspace,
	}

	// Invalid JSON
	err := cm.handleMessage(context.Background(), &messenger.Message{Body: []byte("not json")})
	if err != nil {
		t.Errorf("handleMessage(invalid JSON) should not return error, got: %v", err)
	}

	// Missing required fields
	payload, _ := json.Marshal(flagMessage{Action: "set"})
	err = cm.handleMessage(context.Background(), &messenger.Message{Body: payload})
	if err != nil {
		t.Errorf("handleMessage(missing fields) should not return error, got: %v", err)
	}
}

func TestCacheManager_HandleMessage_UnknownAction(t *testing.T) {
	cm := &cacheManager{
		cache:                make(map[string]map[string]any),
		defaultValues:        make(map[string]any),
		maxWorkspaces:        defaultMaxWorkspaces,
		maxFlagsPerWorkspace: defaultMaxFlagsPerWorkspace,
	}

	payload, _ := json.Marshal(flagMessage{
		WorkspaceID: "ws-1",
		Action:      "unknown",
		Key:         "flag",
	})

	err := cm.handleMessage(context.Background(), &messenger.Message{Body: payload})
	if err != nil {
		t.Errorf("handleMessage(unknown action) should not return error, got: %v", err)
	}
}

func TestCacheManager_ThreadSafety(t *testing.T) {
	cm := &cacheManager{
		cache:                make(map[string]map[string]any),
		defaultValues:        map[string]any{"base": true},
		maxWorkspaces:        defaultMaxWorkspaces,
		maxFlagsPerWorkspace: defaultMaxFlagsPerWorkspace,
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(3)
		go func(n int) {
			defer wg.Done()
			payload, _ := json.Marshal(flagMessage{
				WorkspaceID: "ws-1",
				Action:      "set",
				Key:         "flag",
				Value:       n,
			})
			cm.handleMessage(context.Background(), &messenger.Message{Body: payload})
		}(i)
		go func() {
			defer wg.Done()
			cm.GetFlags(context.Background(), "ws-1")
		}()
		go func() {
			defer wg.Done()
			cm.GetFlag(context.Background(), "ws-1", "flag")
		}()
	}
	wg.Wait()
}

func TestCacheManager_PeriodicClear(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cm := &cacheManager{
		cache: map[string]map[string]any{
			"ws-1": {"flag": true},
		},
		defaultValues: make(map[string]any),
	}

	// Start periodic clear with very short TTL
	go cm.periodicClear(ctx, 50*time.Millisecond)

	// Wait for at least one clear cycle
	time.Sleep(100 * time.Millisecond)

	cm.mu.RLock()
	count := len(cm.cache)
	cm.mu.RUnlock()

	if count != 0 {
		t.Errorf("cache should be cleared after TTL, got %d entries", count)
	}
}

func TestNoopManager(t *testing.T) {
	m := NoopManager{}

	flags := m.GetFlags(context.Background(), "ws-1")
	if flags != nil {
		t.Errorf("NoopManager.GetFlags() = %v, want nil", flags)
	}

	val, ok := m.GetFlag(context.Background(), "ws-1", "key")
	if ok || val != nil {
		t.Errorf("NoopManager.GetFlag() = (%v, %v), want (nil, false)", val, ok)
	}

	if err := m.Close(); err != nil {
		t.Errorf("NoopManager.Close() error: %v", err)
	}
}

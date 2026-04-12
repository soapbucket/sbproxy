package configloader

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/config"
	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/middleware/forward"
	"github.com/soapbucket/sbproxy/internal/platform/messenger"
)

// TestOriginCacheRefresh_EndToEnd tests the complete flow of origin cache refresh via message bus
func TestOriginCacheRefresh_EndToEnd(t *testing.T) {
	resetCache()

	// Create test messenger
	testMessenger := NewTestMessenger()
	defer testMessenger.Close()

	// Create a chain of origins with parent/child relationships:
	// child1 -> parent -> grandparent
	// child2 -> parent
	// standalone (no relationships)

	parentConfig := createConfigJSON("parent.test", "parent-origin", false, []forward.ForwardRule{
		{
			Hostname: "grandparent.test",
			Rules:    nil, // Always forward
		},
	})

	child1Config := createConfigJSON("child1.test", "child1-origin", false, []forward.ForwardRule{
		{
			Hostname: "parent.test",
			Rules:    nil, // Always forward
		},
	})

	child2Config := createConfigJSON("child2.test", "child2-origin", false, []forward.ForwardRule{
		{
			Hostname: "parent.test",
			Rules:    nil, // Always forward
		},
	})

	grandparentConfig := createConfigJSON("grandparent.test", "grandparent-origin", false, nil)

	standaloneConfig := createConfigJSON("standalone.test", "standalone-origin", false, nil)

	// Create mock storage
	mockStore := &mockStorage{
		data: map[string][]byte{
			"parent.test":      parentConfig,
			"child1.test":      child1Config,
			"child2.test":      child2Config,
			"grandparent.test": grandparentConfig,
			"standalone.test":  standaloneConfig,
		},
	}

	// Create mock manager with test messenger
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

	// Override GetMessenger to return test messenger
	mgrWithMessenger := &mockManagerWithMessenger{
		mockManager: mgr,
		messenger:   testMessenger,
	}

	// Step 1: Load all origins into cache
	t.Run("Step 1: Load origins into cache", func(t *testing.T) {
		hostnames := []string{"parent.test", "child1.test", "child2.test", "grandparent.test", "standalone.test"}

		for _, hostname := range hostnames {
			req := httptest.NewRequest(http.MethodGet, "http://"+hostname+"/", nil)
			req.Host = hostname

			cfg, err := Load(req, mgrWithMessenger)
			if err != nil {
				t.Fatalf("Failed to load config for %s: %v", hostname, err)
			}

			if cfg == nil {
				t.Fatalf("Config should not be nil for %s", hostname)
			}

			// Verify config is cached
			entry, ok := defaultLoader.cache.Get(hostname)
			if !ok {
				t.Fatalf("Config for %s should be in cache", hostname)
			}

			loadedCfg, ok := entry.(*config.Config)
			if !ok {
				t.Fatalf("Cached entry for %s should be *config.Config", hostname)
			}

			if loadedCfg.ID == "" {
				t.Fatalf("Config ID should not be empty for %s", hostname)
			}

			t.Logf("✓ Loaded and cached config for %s (ID: %s)", hostname, loadedCfg.ID)
		}

		// Verify all origins are in cache (count hostname-only keys, skip workspace-partitioned keys)
		keys := defaultLoader.cache.GetKeys()
		hostnameKeys := 0
		for _, k := range keys {
			if strings.Count(k, ":") < 2 {
				hostnameKeys++
			}
		}
		if hostnameKeys != len(hostnames) {
			t.Errorf("Expected %d cached origins, got %d (total keys: %d)", len(hostnames), hostnameKeys, len(keys))
		}
	})

	// Step 2: Start the cache refresh subscriber
	t.Run("Step 2: Start cache refresh subscriber", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		topic := "origin_cache_refresh"
		err := StartOriginCacheRefreshSubscriber(ctx, mgrWithMessenger, topic)
		if err != nil {
			t.Fatalf("Failed to start cache refresh subscriber: %v", err)
		}

		// Give subscriber time to initialize
		time.Sleep(50 * time.Millisecond)

		t.Logf("✓ Cache refresh subscriber started on topic: %s", topic)
	})

	// Step 3: Send refresh message for parent origin
	t.Run("Step 3: Send refresh message for parent origin", func(t *testing.T) {
		ctx := context.Background()
		topic := "origin_cache_refresh"

		// Send refresh message for parent origin
		err := testMessenger.SendOriginRefreshMessage(ctx, topic, "parent-origin", "parent.test")
		if err != nil {
			t.Fatalf("Failed to send refresh message: %v", err)
		}

		// Give message time to be processed
		time.Sleep(100 * time.Millisecond)

		t.Logf("✓ Sent refresh message for parent-origin (parent.test)")
	})

	// Step 4: Verify parent and related origins are purged
	t.Run("Step 4: Verify parent and related origins are purged", func(t *testing.T) {
		// Give cache purge time to complete
		time.Sleep(50 * time.Millisecond)

		// Parent should be purged
		if _, ok := defaultLoader.cache.Get("parent.test"); ok {
			t.Error("parent.test should be purged from cache")
		} else {
			t.Logf("✓ parent.test purged from cache")
		}

		// Children should be purged (they forward to parent)
		if _, ok := defaultLoader.cache.Get("child1.test"); ok {
			t.Error("child1.test should be purged from cache (forwards to parent)")
		} else {
			t.Logf("✓ child1.test purged from cache")
		}

		if _, ok := defaultLoader.cache.Get("child2.test"); ok {
			t.Error("child2.test should be purged from cache (forwards to parent)")
		} else {
			t.Logf("✓ child2.test purged from cache")
		}

		// Grandparent should be purged (parent forwards to grandparent)
		if _, ok := defaultLoader.cache.Get("grandparent.test"); ok {
			t.Error("grandparent.test should be purged from cache (parent forwards to it)")
		} else {
			t.Logf("✓ grandparent.test purged from cache")
		}

		// Standalone should NOT be purged (no relationship)
		if _, ok := defaultLoader.cache.Get("standalone.test"); !ok {
			t.Error("standalone.test should NOT be purged from cache (no relationship)")
		} else {
			t.Logf("✓ standalone.test still in cache (no relationship)")
		}
	})

	// Step 5: Reload origins and test refresh by config_id only
	t.Run("Step 5: Test refresh by config_id only", func(t *testing.T) {
		// Reload standalone into cache
		req := httptest.NewRequest(http.MethodGet, "http://standalone.test/", nil)
		req.Host = "standalone.test"

		_, err := Load(req, mgrWithMessenger)
		if err != nil {
			t.Fatalf("Failed to reload standalone config: %v", err)
		}

		// Verify it's cached
		if _, ok := defaultLoader.cache.Get("standalone.test"); !ok {
			t.Fatal("standalone.test should be in cache after reload")
		}

		// Send refresh message with array format (only config_id, no hostname)
		ctx := context.Background()
		topic := "origin_cache_refresh"

		err = testMessenger.SendOriginRefreshMessage(ctx, topic, "standalone-origin", "")
		if err != nil {
			t.Fatalf("Failed to send refresh message: %v", err)
		}

		// Give message time to be processed
		time.Sleep(100 * time.Millisecond)

		// Verify standalone is purged (found by config_id)
		if _, ok := defaultLoader.cache.Get("standalone.test"); ok {
			t.Error("standalone.test should be purged from cache after refresh")
		} else {
			t.Logf("✓ standalone.test purged from cache (found by config_id)")
		}
	})

	// Step 6: Test refresh with JSON body
	t.Run("Step 6: Test refresh with JSON body", func(t *testing.T) {
		// Reload parent into cache
		req := httptest.NewRequest(http.MethodGet, "http://parent.test/", nil)
		req.Host = "parent.test"

		_, err := Load(req, mgrWithMessenger)
		if err != nil {
			t.Fatalf("Failed to reload parent config: %v", err)
		}

		// Verify it's cached
		if _, ok := defaultLoader.cache.Get("parent.test"); !ok {
			t.Fatal("parent.test should be in cache after reload")
		}

		// Send refresh message with JSON body (array format)
		ctx := context.Background()
		topic := "origin_cache_refresh"

		batch := OriginCacheRefreshBatch{
			Updates: []OriginCacheRefreshMessage{{
				ConfigID:       "parent-origin",
				ConfigHostname: "parent.test",
			}},
		}

		body, err := json.Marshal(batch)
		if err != nil {
			t.Fatalf("Failed to marshal refresh message: %v", err)
		}

		err = testMessenger.Send(ctx, topic, &messenger.Message{
			Body:    body,
			Channel: topic,
			Params:  make(map[string]string),
		})
		if err != nil {
			t.Fatalf("Failed to send refresh message: %v", err)
		}

		// Give message time to be processed
		time.Sleep(100 * time.Millisecond)

		// Verify parent is purged
		if _, ok := defaultLoader.cache.Get("parent.test"); ok {
			t.Error("parent.test should be purged from cache after refresh")
		} else {
			t.Logf("✓ parent.test purged from cache (JSON body message)")
		}
	})
}

// mockManagerWithMessenger extends mockManager to return a messenger
type mockManagerWithMessenger struct {
	*mockManager
	messenger messenger.Messenger
}

func (m *mockManagerWithMessenger) GetMessenger() messenger.Messenger {
	return m.messenger
}

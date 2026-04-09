package configloader

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/config/forward"
	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/platform/messenger"
)

// TestPurgeOriginCache_Unit tests the cache purging logic in isolation
func TestPurgeOriginCache_Unit(t *testing.T) {
	resetCache()

	// Create test origins with relationships
	parentConfig := createConfigJSON("parent.test", "parent-origin", false, []forward.ForwardRule{
		{
			Hostname: "grandparent.test",
			Rules:    nil,
		},
	})

	childConfig := createConfigJSON("child.test", "child-origin", false, []forward.ForwardRule{
		{
			Hostname: "parent.test",
			Rules:    nil,
		},
	})

	grandparentConfig := createConfigJSON("grandparent.test", "grandparent-origin", false, nil)
	standaloneConfig := createConfigJSON("standalone.test", "standalone-origin", false, nil)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"parent.test":      parentConfig,
			"child.test":        childConfig,
			"grandparent.test": grandparentConfig,
			"standalone.test":  standaloneConfig,
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
			},
		},
	}

	// Load all configs into cache
	hostnames := []string{"parent.test", "child.test", "grandparent.test", "standalone.test"}
	for _, hostname := range hostnames {
		req := httptest.NewRequest(http.MethodGet, "http://"+hostname+"/", nil)
		req.Host = hostname
		_, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load %s: %v", hostname, err)
		}
	}

	// Verify all are cached
	for _, hostname := range hostnames {
		if _, ok := cache.Get(hostname); !ok {
			t.Fatalf("%s should be in cache", hostname)
		}
	}

	// Test: Purge parent origin
	ctx := context.Background()
	err := PurgeOriginCache(ctx, "parent-origin", "parent.test")
	if err != nil {
		t.Fatalf("PurgeOriginCache failed: %v", err)
	}

	// Verify parent is purged
	if _, ok := cache.Get("parent.test"); ok {
		t.Error("parent.test should be purged")
	}

	// Verify child is purged (forwards to parent)
	if _, ok := cache.Get("child.test"); ok {
		t.Error("child.test should be purged (forwards to parent)")
	}

	// Verify grandparent is purged (parent forwards to it)
	if _, ok := cache.Get("grandparent.test"); ok {
		t.Error("grandparent.test should be purged (parent forwards to it)")
	}

	// Verify standalone is NOT purged
	if _, ok := cache.Get("standalone.test"); !ok {
		t.Error("standalone.test should NOT be purged (no relationship)")
	}
}

// TestFindRelatedHostnames tests the related hostname discovery logic
func TestFindRelatedHostnames(t *testing.T) {
	resetCache()

	// Create a chain: child -> parent -> grandparent
	parentConfig := createConfigJSON("parent.test", "parent-origin", false, []forward.ForwardRule{
		{
			Hostname: "grandparent.test",
			Rules:    nil,
		},
	})

	childConfig := createConfigJSON("child.test", "child-origin", false, []forward.ForwardRule{
		{
			Hostname: "parent.test",
			Rules:    nil,
		},
	})

	grandparentConfig := createConfigJSON("grandparent.test", "grandparent-origin", false, nil)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"parent.test":      parentConfig,
			"child.test":        childConfig,
			"grandparent.test": grandparentConfig,
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
			},
		},
	}

	// Load configs
	for _, hostname := range []string{"parent.test", "child.test", "grandparent.test"} {
		req := httptest.NewRequest(http.MethodGet, "http://"+hostname+"/", nil)
		req.Host = hostname
		_, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load %s: %v", hostname, err)
		}
	}

	// Test finding related hostnames for parent
	snapshot := cacheSnapshot()
	related := findRelatedHostnames("parent.test", &snapshot)

	// Should find child (forwards to parent) and grandparent (parent forwards to it)
	expected := map[string]bool{
		"child.test":       true,
		"grandparent.test": true,
	}

	for hostname, shouldExist := range expected {
		if shouldExist && !related[hostname] {
			t.Errorf("Expected %s to be in related hostnames", hostname)
		}
	}

	if len(related) != len(expected) {
		t.Errorf("Expected %d related hostnames, got %d", len(expected), len(related))
	}
}

// TestHandleMessage tests the message handling logic
func TestHandleMessage(t *testing.T) {
	resetCache()
	// Stop any existing subscriber from previous tests
	StopOriginCacheRefreshSubscriber()

	testMessenger := NewTestMessenger()
	defer testMessenger.Close()

	mgr := &mockManagerWithMessenger{
		mockManager: &mockManager{
			storage: &mockStorage{
				data: map[string][]byte{
					"test.test": createConfigJSON("test.test", "test-origin", false, nil),
				},
			},
			settings: manager.GlobalSettings{
				OriginLoaderSettings: manager.OriginLoaderSettings{
					MaxOriginForwardDepth: 10,
				},
			},
		},
		messenger: testMessenger,
	}

	// Load config into cache
	req := httptest.NewRequest(http.MethodGet, "http://test.test/", nil)
	req.Host = "test.test"
	_, err := Load(req, mgr)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify cached
	if _, ok := cache.Get("test.test"); !ok {
		t.Fatal("Config should be in cache")
	}

	// Start subscriber
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	topic := "test_topic"
	err = StartOriginCacheRefreshSubscriber(ctx, mgr, topic)
	if err != nil {
		t.Fatalf("Failed to start subscriber: %v", err)
	}

	// Give subscriber time to initialize
	time.Sleep(50 * time.Millisecond)

	// Send message with JSON body
	msg := map[string]interface{}{
		"config_id":       "test-origin",
		"config_hostname": "test.test",
	}
	body, _ := json.Marshal(msg)

	err = testMessenger.Send(ctx, topic, &messenger.Message{
		Body:    body,
		Channel: topic,
		Params:  make(map[string]string),
	})
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// Give message time to be processed
	time.Sleep(200 * time.Millisecond)

	// Verify cache is purged
	if _, ok := cache.Get("test.test"); ok {
		t.Error("Config should be purged from cache")
	}
}

// TestHandleMessage_WithParams tests message handling with params only
func TestHandleMessage_WithParams(t *testing.T) {
	resetCache()
	// Stop any existing subscriber from previous tests
	StopOriginCacheRefreshSubscriber()

	testMessenger := NewTestMessenger()
	defer testMessenger.Close()

	mgr := &mockManagerWithMessenger{
		mockManager: &mockManager{
			storage: &mockStorage{
				data: map[string][]byte{
					"test.test": createConfigJSON("test.test", "test-origin", false, nil),
				},
			},
			settings: manager.GlobalSettings{
				OriginLoaderSettings: manager.OriginLoaderSettings{
					MaxOriginForwardDepth: 10,
				},
			},
		},
		messenger: testMessenger,
	}

	// Load config into cache
	req := httptest.NewRequest(http.MethodGet, "http://test.test/", nil)
	req.Host = "test.test"
	_, err := Load(req, mgr)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Start subscriber
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	topic := "test_topic_params"
	err = StartOriginCacheRefreshSubscriber(ctx, mgr, topic)
	if err != nil {
		t.Fatalf("Failed to start subscriber: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Send message with params only
	err = testMessenger.Send(ctx, topic, &messenger.Message{
		Body:   []byte{},
		Params: map[string]string{"config_id": "test-origin"},
	})
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// Give message time to be processed
	time.Sleep(200 * time.Millisecond)

	// Verify cache is purged (found by config_id)
	if _, ok := cache.Get("test.test"); ok {
		t.Error("Config should be purged from cache")
	}
}

func TestStartOriginCacheRefreshSubscriber_MultipleTopics(t *testing.T) {
	resetCache()
	StopOriginCacheRefreshSubscriber()

	testMessenger := NewTestMessenger()
	defer testMessenger.Close()

	mgr := &mockManagerWithMessenger{
		mockManager: &mockManager{
			storage: &mockStorage{data: map[string][]byte{}},
			settings: manager.GlobalSettings{
				OriginLoaderSettings: manager.OriginLoaderSettings{
					MaxOriginForwardDepth: 10,
				},
			},
		},
		messenger: testMessenger,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := StartOriginCacheRefreshSubscriber(ctx, mgr, "topic-a"); err != nil {
		t.Fatalf("failed to start topic-a subscriber: %v", err)
	}
	if err := StartOriginCacheRefreshSubscriber(ctx, mgr, "topic-b"); err != nil {
		t.Fatalf("failed to start topic-b subscriber: %v", err)
	}

	if len(refreshSubscribers) != 2 {
		t.Fatalf("expected two active refresh subscribers, got %d", len(refreshSubscribers))
	}
}


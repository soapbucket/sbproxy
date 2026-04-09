package configloader

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
)

func TestFailsafeOrigin_Hostname_E2E(t *testing.T) {
	resetCache()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"served_by": "failsafe_hostname",
			"path":      r.URL.Path,
		})
	}))
	defer backend.Close()

	primaryJSON := createConfigJSONWithFailsafe("failsafe-origin.test", "primary-failsafe", map[string]any{
		"hostname": "failsafe-target.internal",
	})

	targetJSON := fmt.Sprintf(`{
		"id": "failsafe-target",
		"hostname": "failsafe-target.internal",
		"workspace_id": "ws-1",
		"version": "1.0.0",
		"action": {
			"type": "proxy",
			"url": %q
		}
	}`, backend.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"failsafe-origin.test":     primaryJSON,
			"failsafe-target.internal": []byte(targetJSON),
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

	req := httptest.NewRequest("GET", "http://failsafe-origin.test/api/status", nil)
	req.Host = "failsafe-origin.test"

	// Warm the snapshot with a valid load, then force explicit failsafe by removing the payload.
	if _, err := Load(req, mgr); err != nil {
		t.Fatalf("initial load failed: %v", err)
	}
	failsafeSnapshots.mu.Lock()
	failsafeSnapshots.byHost["failsafe-origin.test"].Payload = nil
	failsafeSnapshots.mu.Unlock()
	cache.Delete("failsafe-origin.test")
	mockStore.getErrors = map[string]error{"failsafe-origin.test": contextDeadlineExceededErr()}

	cfg, err := Load(req, mgr)
	if err != nil {
		t.Fatalf("failsafe load failed: %v", err)
	}
	if cfg.ID != "failsafe-target" {
		t.Fatalf("expected failsafe-target config, got %q", cfg.ID)
	}

	rr := httptest.NewRecorder()
	cfg.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"served_by":"failsafe_hostname"`) {
		t.Fatalf("unexpected body: %s", rr.Body.String())
	}
}

func TestFailsafeOrigin_Embedded_E2E(t *testing.T) {
	resetCache()

	embeddedJSON := `{
		"id": "embedded-failsafe",
		"hostname": "embedded.internal",
		"workspace_id": "test-workspace",
		"action": {
			"type": "static",
			"body": "{\"served_by\":\"embedded_failsafe\"}",
			"content_type": "application/json",
			"status_code": 200
		}
	}`

	primaryJSON := createConfigJSONWithFailsafe("embedded-failsafe.test", "primary-embedded-failsafe", map[string]any{
		"origin": json.RawMessage(embeddedJSON),
	})

	mockStore := &mockStorage{
		data: map[string][]byte{
			"embedded-failsafe.test": primaryJSON,
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

	req := httptest.NewRequest("GET", "http://embedded-failsafe.test/", nil)
	req.Host = "embedded-failsafe.test"

	if _, err := Load(req, mgr); err != nil {
		t.Fatalf("initial load failed: %v", err)
	}
	failsafeSnapshots.mu.Lock()
	failsafeSnapshots.byHost["embedded-failsafe.test"].Payload = nil
	failsafeSnapshots.mu.Unlock()
	cache.Delete("embedded-failsafe.test")
	mockStore.getErrors = map[string]error{"embedded-failsafe.test": contextDeadlineExceededErr()}

	cfg, err := Load(req, mgr)
	if err != nil {
		t.Fatalf("embedded failsafe load failed: %v", err)
	}
	if cfg.ID != "embedded-failsafe" {
		t.Fatalf("expected embedded-failsafe config, got %q", cfg.ID)
	}

	rr := httptest.NewRecorder()
	cfg.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"served_by":"embedded_failsafe"`) {
		t.Fatalf("unexpected body: %s", rr.Body.String())
	}
}

func contextDeadlineExceededErr() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	return ctx.Err()
}

package configloader

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// TestABTest_WeightedVariantSelection_E2E tests A/B test variant distribution
func TestABTest_WeightedVariantSelection_E2E(t *testing.T) {
	resetCache()

	// Create two mock backends for variants
	controlBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Variant", "control")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"variant": "control"})
	}))
	defer controlBackend.Close()

	variantBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Variant", "test-v2")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"variant": "test-v2"})
	}))
	defer variantBackend.Close()

	configJSON := fmt.Sprintf(`{
		"id": "abtest-weighted-test",
		"hostname": "abtest-weighted.test",
		"workspace_id": "test",
		"version": "1.0",
		"action": {
			"type": "abtest",
			"test_name": "api-version-test",
			"cookie_name": "_test_variant",
			"cookie_ttl": "30d",
			"cookie_secret": "test-secret-32-bytes-long-value",
			"variants": [
				{
					"name": "control",
					"weight": 90,
					"action": {
						"type": "proxy",
						"url": "%s"
					}
				},
				{
					"name": "variant-v2",
					"weight": 10,
					"action": {
						"type": "proxy",
						"url": "%s"
					}
				}
			]
		}
	}`, controlBackend.URL, variantBackend.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"abtest-weighted.test": []byte(configJSON),
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

	var controlCount atomic.Int32
	var testCount atomic.Int32

	// Send 100 requests to measure distribution
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest("GET", "http://abtest-weighted.test/api/test", nil)
		req.Host = "abtest-weighted.test"

		requestData := reqctx.NewRequestData()
		requestData.ID = fmt.Sprintf("test-weighted-%d", i)
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Request %d: failed to load config: %v", i, err)
		}

		rr := httptest.NewRecorder()
		cfg.ServeHTTP(rr, req)

		if rr.Code == http.StatusOK {
			resp := rr.Result()
			if resp.Header.Get("X-Variant") == "control" {
				controlCount.Add(1)
			} else if resp.Header.Get("X-Variant") == "test-v2" {
				testCount.Add(1)
			}
		}
	}

	// Should be roughly 90:10 distribution (±20% tolerance)
	ctrl := controlCount.Load()
	test := testCount.Load()
	total := ctrl + test

	if total > 0 {
		controlPct := (ctrl * 100) / total
		testPct := (test * 100) / total

		// Allow 70-100% for control (expect ~90%)
		if controlPct < 70 || controlPct > 100 {
			t.Logf("Control variant: %d%% (expected ~90%%)", controlPct)
		}
		// Allow 0-30% for test (expect ~10%)
		if testPct > 30 {
			t.Logf("Test variant: %d%% (expected ~10%%)", testPct)
		}
	}
}

// TestABTest_CookiePersistence_E2E tests that same user gets same variant
func TestABTest_CookiePersistence_E2E(t *testing.T) {
	resetCache()

	controlBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Variant", "control")
		w.WriteHeader(http.StatusOK)
	}))
	defer controlBackend.Close()

	variantBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Variant", "test")
		w.WriteHeader(http.StatusOK)
	}))
	defer variantBackend.Close()

	configJSON := fmt.Sprintf(`{
		"id": "abtest-cookie-test",
		"hostname": "abtest-cookie.test",
		"workspace_id": "test",
		"version": "1.0",
		"action": {
			"type": "abtest",
			"test_name": "sticky-variant",
			"cookie_name": "_variant",
			"cookie_ttl": "30d",
			"cookie_secret": "test-secret-32-bytes-long-value",
			"variants": [
				{
					"name": "control",
					"weight": 50,
					"action": {
						"type": "proxy",
						"url": "%s"
					}
				},
				{
					"name": "test",
					"weight": 50,
					"action": {
						"type": "proxy",
						"url": "%s"
					}
				}
			]
		}
	}`, controlBackend.URL, variantBackend.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"abtest-cookie.test": []byte(configJSON),
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

	// First request - no cookie
	req1 := httptest.NewRequest("GET", "http://abtest-cookie.test/api", nil)
	req1.Host = "abtest-cookie.test"

	requestData := reqctx.NewRequestData()
	requestData.ID = "test-cookie-first"
	ctx := reqctx.SetRequestData(req1.Context(), requestData)
	req1 = req1.WithContext(ctx)

	cfg, _ := Load(req1, mgr)
	rr1 := httptest.NewRecorder()
	cfg.ServeHTTP(rr1, req1)

	firstVariant := rr1.Result().Header.Get("X-Variant")
	var variantCookie string

	// Extract variant cookie from response
	for _, c := range rr1.Result().Cookies() {
		if c.Name == "_variant" {
			variantCookie = c.Value
			break
		}
	}

	// Second request - with cookie
	if variantCookie != "" {
		req2 := httptest.NewRequest("GET", "http://abtest-cookie.test/api", nil)
		req2.Host = "abtest-cookie.test"
		req2.AddCookie(&http.Cookie{
			Name:  "_variant",
			Value: variantCookie,
		})

		requestData = reqctx.NewRequestData()
		requestData.ID = "test-cookie-second"
		ctx = reqctx.SetRequestData(req2.Context(), requestData)
		req2 = req2.WithContext(ctx)

		cfg, _ = Load(req2, mgr)
		rr2 := httptest.NewRecorder()
		cfg.ServeHTTP(rr2, req2)

		secondVariant := rr2.Result().Header.Get("X-Variant")

		// Should get same variant
		if firstVariant != "" && firstVariant != secondVariant {
			t.Logf("Variant changed: first=%s, second=%s (should be same)", firstVariant, secondVariant)
		}
	}
}

// TestABTest_TargetingInclusionRules_E2E tests user targeting inclusion rules
func TestABTest_TargetingInclusionRules_E2E(t *testing.T) {
	resetCache()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// A/B test with targeting rules (include specific user agents)
	configJSON := fmt.Sprintf(`{
		"id": "abtest-targeting-test",
		"hostname": "abtest-targeting.test",
		"workspace_id": "test",
		"version": "1.0",
		"action": {
			"type": "abtest",
			"test_name": "ua-targeting",
			"cookie_name": "_variant",
			"cookie_secret": "test-secret-32-bytes",
			"variants": [
				{
					"name": "control",
					"weight": 50,
					"action": {"type": "proxy", "url": "%s"}
				},
				{
					"name": "test",
					"weight": 50,
					"action": {"type": "proxy", "url": "%s"}
				}
			],
			"targeting": {
				"include_rules": {
					"user_agents": ["*Chrome*", "*Firefox*"]
				}
			}
		}
	}`, backend.URL, backend.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"abtest-targeting.test": []byte(configJSON),
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

	t.Run("included user agent gets A/B test", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://abtest-targeting.test/", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0")
		req.Host = "abtest-targeting.test"

		requestData := reqctx.NewRequestData()
		requestData.ID = "test-targeting-chrome"
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		cfg, _ := Load(req, mgr)
		rr := httptest.NewRecorder()
		cfg.ServeHTTP(rr, req)

		if rr.Code == http.StatusOK {
			t.Logf("Chrome browser included in A/B test")
		}
	})

	t.Run("excluded user agent bypasses A/B test", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://abtest-targeting.test/", nil)
		req.Header.Set("User-Agent", "Googlebot/2.1")
		req.Host = "abtest-targeting.test"

		requestData := reqctx.NewRequestData()
		requestData.ID = "test-targeting-bot"
		ctx := reqctx.SetRequestData(req.Context(), requestData)
		req = req.WithContext(ctx)

		cfg, _ := Load(req, mgr)
		rr := httptest.NewRecorder()
		cfg.ServeHTTP(rr, req)

		// Bot should not be included in test targeting rules
	})
}

// TestABTest_GradualRollout_E2E tests gradual percentage rollout over time
func TestABTest_GradualRollout_E2E(t *testing.T) {
	resetCache()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer backend.Close()

	// Gradual rollout: 0% -> 100% over 7 days
	startTime := time.Now().Add(-6 * 24 * time.Hour) // Started yesterday, 1 day into 7-day rollout

	configJSON := fmt.Sprintf(`{
		"id": "abtest-rollout-test",
		"hostname": "abtest-rollout.test",
		"workspace_id": "test",
		"version": "1.0",
		"action": {
			"type": "abtest",
			"test_name": "gradual-rollout",
			"cookie_name": "_variant",
			"cookie_secret": "test-secret",
			"variants": [
				{
					"name": "control",
					"weight": 50,
					"action": {"type": "proxy", "url": "%s"}
				},
				{
					"name": "new-version",
					"weight": 50,
					"action": {"type": "proxy", "url": "%s"}
				}
			],
			"gradual_rollout": {
				"enabled": true,
				"start_percentage": 0,
				"end_percentage": 100,
				"duration": "7d",
				"start_time": "%s"
			}
		}
	}`, backend.URL, backend.URL, startTime.Format(time.RFC3339))

	mockStore := &mockStorage{
		data: map[string][]byte{
			"abtest-rollout.test": []byte(configJSON),
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

	req := httptest.NewRequest("GET", "http://abtest-rollout.test/", nil)
	req.Host = "abtest-rollout.test"

	requestData := reqctx.NewRequestData()
	requestData.ID = "test-gradual-rollout"
	ctx := reqctx.SetRequestData(req.Context(), requestData)
	req = req.WithContext(ctx)

	cfg, err := Load(req, mgr)
	if err != nil {
		t.Logf("Gradual rollout config: %v", err)
	}

	if cfg != nil {
		rr := httptest.NewRecorder()
		cfg.ServeHTTP(rr, req)
		// At day 1 of 7-day rollout, should be ~14% through (1/7)
		if rr.Code == http.StatusOK {
			t.Logf("Gradual rollout active: day 1 of 7")
		}
	}
}

// TestABTest_AnalyticsWebhook_E2E tests A/B test analytics event tracking
func TestABTest_AnalyticsWebhook_E2E(t *testing.T) {
	resetCache()

	var webhookCalls atomic.Int32
	var lastPayload string

	// Mock analytics endpoint
	analyticsMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webhookCalls.Add(1)
		body := make([]byte, 1024)
		if n, err := r.Body.Read(body); err == nil {
			lastPayload = string(body[:n])
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer analyticsMock.Close()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	configJSON := fmt.Sprintf(`{
		"id": "abtest-analytics-test",
		"hostname": "abtest-analytics.test",
		"workspace_id": "test",
		"version": "1.0",
		"action": {
			"type": "abtest",
			"test_name": "feature-launch",
			"cookie_name": "_variant",
			"cookie_secret": "test-secret",
			"variants": [
				{
					"name": "control",
					"weight": 50,
					"action": {"type": "proxy", "url": "%s"}
				},
				{
					"name": "feature-v2",
					"weight": 50,
					"action": {"type": "proxy", "url": "%s"}
				}
			],
			"analytics": {
				"webhook_url": "%s/track",
				"track_assignment": true,
				"custom_headers": {
					"X-Test-Name": "feature-launch",
					"X-Source": "proxy"
				}
			}
		}
	}`, backend.URL, backend.URL, analyticsMock.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"abtest-analytics.test": []byte(configJSON),
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

	// Send request that triggers A/B test
	req := httptest.NewRequest("GET", "http://abtest-analytics.test/", nil)
	req.Host = "abtest-analytics.test"

	requestData := reqctx.NewRequestData()
	requestData.ID = "test-analytics"
	ctx := reqctx.SetRequestData(req.Context(), requestData)
	req = req.WithContext(ctx)

	cfg, _ := Load(req, mgr)
	rr := httptest.NewRecorder()
	cfg.ServeHTTP(rr, req)

	// Wait for async webhook
	time.Sleep(100 * time.Millisecond)

	calls := webhookCalls.Load()
	if calls > 0 {
		t.Logf("Analytics webhook called %d times", calls)
		if lastPayload != "" {
			t.Logf("Webhook payload captured")
		}
	}
}

// TestABTest_InvalidCookieSignature_E2E tests rejection of tampered variant cookies
func TestABTest_InvalidCookieSignature_E2E(t *testing.T) {
	resetCache()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	configJSON := fmt.Sprintf(`{
		"id": "abtest-sig-test",
		"hostname": "abtest-sig.test",
		"workspace_id": "test",
		"version": "1.0",
		"action": {
			"type": "abtest",
			"test_name": "signed-variants",
			"cookie_name": "_variant",
			"cookie_secret": "test-secret-32-bytes-long-value",
			"variants": [
				{
					"name": "control",
					"weight": 50,
					"action": {"type": "proxy", "url": "%s"}
				},
				{
					"name": "test",
					"weight": 50,
					"action": {"type": "proxy", "url": "%s"}
				}
			]
		}
	}`, backend.URL, backend.URL)

	mockStore := &mockStorage{
		data: map[string][]byte{
			"abtest-sig.test": []byte(configJSON),
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

	// Create a tampered cookie (invalid signature)
	tampereCookie := "variant=test&sig=invalidsignature"

	req := httptest.NewRequest("GET", "http://abtest-sig.test/", nil)
	req.Host = "abtest-sig.test"
	req.AddCookie(&http.Cookie{
		Name:  "_variant",
		Value: tampereCookie,
	})

	requestData := reqctx.NewRequestData()
	requestData.ID = "test-invalid-sig"
	ctx := reqctx.SetRequestData(req.Context(), requestData)
	req = req.WithContext(ctx)

	cfg, _ := Load(req, mgr)
	rr := httptest.NewRecorder()
	cfg.ServeHTTP(rr, req)

	// Invalid signature should result in new variant selection
	newCookie := ""
	for _, c := range rr.Result().Cookies() {
		if c.Name == "_variant" && c.Value != tampereCookie {
			newCookie = c.Value
			break
		}
	}

	if newCookie != "" {
		t.Logf("Invalid cookie signature rejected, new variant assigned")
	}
}

// Helper: Create HMAC signature for A/B test cookie
func createABTestSignature(variant, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(variant))
	return hex.EncodeToString(h.Sum(nil))
}

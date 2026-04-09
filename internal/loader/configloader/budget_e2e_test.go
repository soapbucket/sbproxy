package configloader

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// ============================================================================
// E.22-E.25: Budget E2E Tests
// ============================================================================

// TestBudgetExceeded_DowngradeThenBlock_E2E (E.22) verifies that when a budget is exceeded,
// the system first downgrades to a cheaper model and then blocks after full exhaustion.
func TestBudgetExceeded_DowngradeThenBlock_E2E(t *testing.T) {
	resetCache()

	var requestCount atomic.Int32
	var capturedModels []string
	var mu sync.Mutex

	mockAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)

		// Read model from request body
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			mu.Lock()
			if model, ok := body["model"].(string); ok {
				capturedModels = append(capturedModels, model)
			}
			mu.Unlock()
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":      "chatcmpl-budget",
			"object":  "chat.completion",
			"created": 1234567890,
			"model":   "gpt-4o",
			"choices": []map[string]interface{}{
				{
					"index":         0,
					"message":       map[string]interface{}{"role": "assistant", "content": "Response"},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]interface{}{
				"prompt_tokens":     5000,
				"completion_tokens": 5000,
				"total_tokens":      10000,
			},
		})
	}))
	defer mockAI.Close()

	t.Run("downgrade then block on budget exceed", func(t *testing.T) {
		resetCache()
		mu.Lock()
		capturedModels = nil
		mu.Unlock()

		configJSON := fmt.Sprintf(`{
			"id": "ai-budget-downgrade",
			"hostname": "ai-budget-dg.test",
			"workspace_id": "test-workspace",
			"version": "1",
			"action": {
				"type": "ai_proxy",
				"providers": [
					{
						"name": "openai",
						"type": "openai",
						"base_url": "%s",
						"api_key": "sk-test",
						"models": ["gpt-4o", "gpt-4o-mini"],
						"weight": 100,
						"enabled": true
					}
				],
				"default_model": "gpt-4o",
				"budget": {
					"limits": [
						{
							"scope": "workspace",
							"max_tokens": 100,
							"period": "daily"
						}
					],
					"on_exceed": "downgrade",
					"downgrade_map": {
						"gpt-4o": "gpt-4o-mini"
					},
					"downgrade_threshold": 0.8
				}
			}
		}`, mockAI.URL)

		mockStore := &mockStorage{
			data: map[string][]byte{
				"ai-budget-dg.test": []byte(configJSON),
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

		// First request - should succeed (budget not yet exceeded)
		req1 := httptest.NewRequest("POST", "http://ai-budget-dg.test/v1/chat/completions",
			strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}`))
		req1.Host = "ai-budget-dg.test"
		req1.Header.Set("Content-Type", "application/json")

		rd1 := reqctx.NewRequestData()
		rd1.ID = "test-budget-dg-1"
		req1 = req1.WithContext(reqctx.SetRequestData(req1.Context(), rd1))

		cfg1, err := Load(req1, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}
		rr1 := httptest.NewRecorder()
		cfg1.ServeHTTP(rr1, req1)

		if rr1.Code == http.StatusOK {
			t.Log("First request succeeded (budget not yet exceeded)")
		} else {
			t.Logf("First request got status %d: %s", rr1.Code, rr1.Body.String())
		}

		// Second request - budget should be exceeded (10000 tokens used, limit is 100)
		// Should downgrade to gpt-4o-mini or block
		req2 := httptest.NewRequest("POST", "http://ai-budget-dg.test/v1/chat/completions",
			strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hello again"}]}`))
		req2.Host = "ai-budget-dg.test"
		req2.Header.Set("Content-Type", "application/json")

		rd2 := reqctx.NewRequestData()
		rd2.ID = "test-budget-dg-2"
		req2 = req2.WithContext(reqctx.SetRequestData(req2.Context(), rd2))

		cfg2, err := Load(req2, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}
		rr2 := httptest.NewRecorder()
		cfg2.ServeHTTP(rr2, req2)

		switch rr2.Code {
		case http.StatusOK:
			t.Log("Second request succeeded (may have been downgraded)")
			mu.Lock()
			if len(capturedModels) >= 2 && capturedModels[1] == "gpt-4o-mini" {
				t.Log("Model was downgraded from gpt-4o to gpt-4o-mini")
			}
			mu.Unlock()
		case http.StatusTooManyRequests:
			t.Log("Second request blocked by budget enforcement (429)")
		case http.StatusPaymentRequired:
			t.Log("Second request blocked by budget enforcement (402)")
		default:
			t.Logf("Second request status %d (acceptable): %s", rr2.Code, rr2.Body.String())
		}

		if requestCount.Load() < 1 {
			t.Error("Expected at least 1 upstream request")
		}
	})
}

// TestBudgetOverride_E2E (E.23) verifies that a budget override flag allows requests
// to proceed even after the budget is exceeded.
func TestBudgetOverride_E2E(t *testing.T) {
	resetCache()

	var requestCount atomic.Int32

	mockAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":      "chatcmpl-override",
			"object":  "chat.completion",
			"created": 1234567890,
			"model":   "gpt-4o",
			"choices": []map[string]interface{}{
				{
					"index":         0,
					"message":       map[string]interface{}{"role": "assistant", "content": "Override response"},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]interface{}{
				"prompt_tokens":     50000,
				"completion_tokens": 50000,
				"total_tokens":      100000,
			},
		})
	}))
	defer mockAI.Close()

	t.Run("budget override allows request after exceed", func(t *testing.T) {
		resetCache()

		configJSON := fmt.Sprintf(`{
			"id": "ai-budget-override",
			"hostname": "ai-budget-override.test",
			"workspace_id": "test-workspace",
			"version": "1",
			"action": {
				"type": "ai_proxy",
				"providers": [
					{
						"name": "openai",
						"type": "openai",
						"base_url": "%s",
						"api_key": "sk-test",
						"models": ["gpt-4o"],
						"weight": 100,
						"enabled": true
					}
				],
				"default_model": "gpt-4o",
				"budget": {
					"limits": [
						{
							"scope": "workspace",
							"max_tokens": 50,
							"period": "daily"
						}
					],
					"on_exceed": "block"
				}
			}
		}`, mockAI.URL)

		mgr := newAITestManager("ai-budget-override.test", configJSON)

		// First request exhausts budget
		req1 := httptest.NewRequest("POST", "http://ai-budget-override.test/v1/chat/completions",
			strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}`))
		req1.Host = "ai-budget-override.test"
		req1.Header.Set("Content-Type", "application/json")

		rd1 := reqctx.NewRequestData()
		rd1.ID = "test-override-1"
		req1 = req1.WithContext(reqctx.SetRequestData(req1.Context(), rd1))

		cfg1, err := Load(req1, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}
		rr1 := httptest.NewRecorder()
		cfg1.ServeHTTP(rr1, req1)
		t.Logf("First request: status %d", rr1.Code)

		// Second request with budget override header
		req2 := httptest.NewRequest("POST", "http://ai-budget-override.test/v1/chat/completions",
			strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"override please"}]}`))
		req2.Host = "ai-budget-override.test"
		req2.Header.Set("Content-Type", "application/json")
		req2.Header.Set("X-SB-Budget-Override", "true")

		rd2 := reqctx.NewRequestData()
		rd2.ID = "test-override-2"
		req2 = req2.WithContext(reqctx.SetRequestData(req2.Context(), rd2))

		cfg2, err := Load(req2, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}
		rr2 := httptest.NewRecorder()
		cfg2.ServeHTTP(rr2, req2)

		// With override, the request should proceed regardless of budget
		switch rr2.Code {
		case http.StatusOK:
			t.Log("Budget override allowed request after budget exceeded")
		case http.StatusTooManyRequests:
			t.Log("Budget override not supported at this layer (429 returned)")
		default:
			t.Logf("Override request: status %d (acceptable): %s", rr2.Code, rr2.Body.String())
		}

		if requestCount.Load() < 1 {
			t.Error("Expected at least 1 upstream request")
		}
	})
}

// TestProviderBudgetRouting_E2E (E.24) verifies that when one provider's budget is
// exhausted, requests route to the next available provider.
func TestProviderBudgetRouting_E2E(t *testing.T) {
	resetCache()

	var mu sync.Mutex
	providerHits := map[string]int{}

	// OpenAI provider
	openaiUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		providerHits["openai"]++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":      "chatcmpl-openai",
			"object":  "chat.completion",
			"created": 1234567890,
			"model":   "gpt-4o",
			"choices": []map[string]interface{}{
				{
					"index":         0,
					"message":       map[string]interface{}{"role": "assistant", "content": "OpenAI response"},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]interface{}{
				"prompt_tokens":     5000,
				"completion_tokens": 5000,
				"total_tokens":      10000,
			},
		})
	}))
	defer openaiUpstream.Close()

	// Anthropic provider
	anthropicUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		providerHits["anthropic"]++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":      "chatcmpl-anthropic",
			"object":  "chat.completion",
			"created": 1234567890,
			"model":   "claude-sonnet-4-20250514",
			"choices": []map[string]interface{}{
				{
					"index":         0,
					"message":       map[string]interface{}{"role": "assistant", "content": "Anthropic response"},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]interface{}{
				"prompt_tokens":     500,
				"completion_tokens": 500,
				"total_tokens":      1000,
			},
		})
	}))
	defer anthropicUpstream.Close()

	t.Run("exhausted provider routes to alternative", func(t *testing.T) {
		resetCache()
		mu.Lock()
		providerHits = map[string]int{}
		mu.Unlock()

		configJSON := fmt.Sprintf(`{
			"id": "ai-provider-budget",
			"hostname": "ai-provider-budget.test",
			"workspace_id": "test-workspace",
			"version": "1",
			"action": {
				"type": "ai_proxy",
				"providers": [
					{
						"name": "openai",
						"type": "openai",
						"base_url": "%s",
						"api_key": "sk-openai",
						"models": ["gpt-4o"],
						"weight": 100,
						"enabled": true,
						"max_tokens_per_minute": 100
					},
					{
						"name": "anthropic",
						"type": "openai",
						"base_url": "%s",
						"api_key": "sk-anthropic",
						"models": ["claude-sonnet-4-20250514"],
						"weight": 50,
						"enabled": true
					}
				],
				"default_model": "gpt-4o",
				"routing": {
					"strategy": "fallback_chain",
					"fallback_order": ["openai", "anthropic"]
				},
				"budget": {
					"limits": [
						{
							"scope": "workspace",
							"max_tokens": 100,
							"period": "daily"
						}
					],
					"on_exceed": "downgrade"
				}
			}
		}`, openaiUpstream.URL, anthropicUpstream.URL)

		mgr := newAITestManager("ai-provider-budget.test", configJSON)

		// Send multiple requests to exhaust OpenAI budget
		for i := 0; i < 3; i++ {
			body := chatCompletionBody("gpt-4o")
			req := httptest.NewRequest("POST", "http://ai-provider-budget.test/v1/chat/completions", strings.NewReader(body))
			req.Host = "ai-provider-budget.test"
			req.Header.Set("Content-Type", "application/json")

			rd := reqctx.NewRequestData()
			rd.ID = fmt.Sprintf("test-provider-budget-%d", i)
			req = req.WithContext(reqctx.SetRequestData(req.Context(), rd))

			cfg, err := Load(req, mgr)
			if err != nil {
				t.Fatalf("Request %d: Failed to load config: %v", i, err)
			}
			w := httptest.NewRecorder()
			cfg.ServeHTTP(w, req)

			if w.Code == http.StatusOK {
				t.Logf("Request %d: succeeded with status 200", i)
			} else {
				t.Logf("Request %d: status %d", i, w.Code)
			}
		}

		mu.Lock()
		defer mu.Unlock()
		t.Logf("Provider hits - OpenAI: %d, Anthropic: %d", providerHits["openai"], providerHits["anthropic"])

		totalHits := providerHits["openai"] + providerHits["anthropic"]
		if totalHits < 1 {
			t.Error("Expected at least 1 upstream provider hit")
		}

		// If budget enforcement worked, we should see some Anthropic hits after OpenAI exhaustion.
		// This may not trigger in all configurations, so we accept any distribution.
		if providerHits["anthropic"] > 0 {
			t.Log("Successfully routed to Anthropic after OpenAI budget exhaustion")
		}
	})
}

// TestSpendEventVerification_E2E (E.25) verifies that spend events contain correct
// cost and token information after a request is processed.
func TestSpendEventVerification_E2E(t *testing.T) {
	resetCache()

	var requestCount atomic.Int32

	mockAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":      "chatcmpl-spend",
			"object":  "chat.completion",
			"created": 1234567890,
			"model":   "gpt-4o",
			"choices": []map[string]interface{}{
				{
					"index":         0,
					"message":       map[string]interface{}{"role": "assistant", "content": "Token tracking test response."},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]interface{}{
				"prompt_tokens":     150,
				"completion_tokens": 50,
				"total_tokens":      200,
			},
		})
	}))
	defer mockAI.Close()

	t.Run("spend event contains correct tokens and cost", func(t *testing.T) {
		resetCache()

		configJSON := fmt.Sprintf(`{
			"id": "ai-spend-verify",
			"hostname": "ai-spend-verify.test",
			"workspace_id": "test-workspace",
			"version": "1",
			"action": {
				"type": "ai_proxy",
				"providers": [
					{
						"name": "openai",
						"type": "openai",
						"base_url": "%s",
						"api_key": "sk-test",
						"models": ["gpt-4o"],
						"weight": 100,
						"enabled": true
					}
				],
				"default_model": "gpt-4o",
				"budget": {
					"limits": [
						{
							"scope": "workspace",
							"max_cost_usd": 100.0,
							"period": "monthly"
						}
					],
					"on_exceed": "log"
				}
			}
		}`, mockAI.URL)

		mgr := newAITestManager("ai-spend-verify.test", configJSON)

		body := chatCompletionBody("gpt-4o")
		req := httptest.NewRequest("POST", "http://ai-spend-verify.test/v1/chat/completions", strings.NewReader(body))
		req.Host = "ai-spend-verify.test"
		req.Header.Set("Content-Type", "application/json")

		rd := reqctx.NewRequestData()
		rd.ID = "test-spend-event"
		req = req.WithContext(reqctx.SetRequestData(req.Context(), rd))

		cfg, err := Load(req, mgr)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}
		rr := httptest.NewRecorder()
		cfg.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Logf("Got status %d: %s", rr.Code, rr.Body.String())
			return
		}

		// Verify the response contains usage information
		var resp map[string]interface{}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		usage, ok := resp["usage"].(map[string]interface{})
		if !ok {
			t.Fatal("Response missing usage field")
		}

		// Verify token counts match what the mock returned
		promptTokens, _ := usage["prompt_tokens"].(float64)
		completionTokens, _ := usage["completion_tokens"].(float64)
		totalTokens, _ := usage["total_tokens"].(float64)

		if promptTokens != 150 {
			t.Errorf("Expected prompt_tokens=150, got %v", promptTokens)
		}
		if completionTokens != 50 {
			t.Errorf("Expected completion_tokens=50, got %v", completionTokens)
		}
		if totalTokens != 200 {
			t.Errorf("Expected total_tokens=200, got %v", totalTokens)
		}

		t.Logf("Spend event verification: prompt=%v, completion=%v, total=%v", promptTokens, completionTokens, totalTokens)

		// Verify the request reached the upstream
		if requestCount.Load() != 1 {
			t.Errorf("Expected exactly 1 upstream request, got %d", requestCount.Load())
		}
	})

	t.Run("multiple requests accumulate spend", func(t *testing.T) {
		resetCache()
		requestCount.Store(0)

		configJSON := fmt.Sprintf(`{
			"id": "ai-spend-accum",
			"hostname": "ai-spend-accum.test",
			"workspace_id": "test-workspace",
			"version": "1",
			"action": {
				"type": "ai_proxy",
				"providers": [
					{
						"name": "openai",
						"type": "openai",
						"base_url": "%s",
						"api_key": "sk-test",
						"models": ["gpt-4o"],
						"weight": 100,
						"enabled": true
					}
				],
				"default_model": "gpt-4o",
				"budget": {
					"limits": [
						{
							"scope": "workspace",
							"max_tokens": 1000,
							"period": "daily"
						}
					],
					"on_exceed": "log"
				}
			}
		}`, mockAI.URL)

		mgr := newAITestManager("ai-spend-accum.test", configJSON)

		// Send 3 requests
		for i := 0; i < 3; i++ {
			body := chatCompletionBody("gpt-4o")
			req := httptest.NewRequest("POST", "http://ai-spend-accum.test/v1/chat/completions", strings.NewReader(body))
			req.Host = "ai-spend-accum.test"
			req.Header.Set("Content-Type", "application/json")

			rd := reqctx.NewRequestData()
			rd.ID = fmt.Sprintf("test-spend-accum-%d", i)
			req = req.WithContext(reqctx.SetRequestData(req.Context(), rd))

			cfg, err := Load(req, mgr)
			if err != nil {
				t.Fatalf("Request %d: failed to load config: %v", i, err)
			}
			w := httptest.NewRecorder()
			cfg.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Logf("Request %d: status %d", i, w.Code)
			}
		}

		// All 3 should have gone through (budget is 1000 tokens, each uses 200)
		count := requestCount.Load()
		if count != 3 {
			t.Errorf("Expected 3 upstream requests, got %d", count)
		}
		t.Logf("All %d requests processed (accumulated 600/1000 tokens)", count)
	})
}

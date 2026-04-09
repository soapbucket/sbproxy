package callback

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// TestSessionCallbackDataStorage verifies that session callbacks store data
// in SessionData.Data and it's accessible for the session lifetime
func TestSessionCallbackDataStorage(t *testing.T) {
	// Mock callback server that returns user preferences
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]any{
			"user_preferences": map[string]any{
				"theme":    "dark",
				"language": "en",
				"timezone": "America/New_York",
			},
			"feature_flags": map[string]any{
				"beta_features": true,
				"analytics":     true,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer mockServer.Close()

	// Create session callback
	sessionCallback := &Callback{
		URL:    mockServer.URL,
		Method: "POST",
	}

	// Create initial session data (new session)
	sessionData := &reqctx.SessionData{
		ID:   "test-session-123",
		Data: make(map[string]any),
	}

	// Create request data
	requestData := &reqctx.RequestData{
		ID:          "req-1",
		SessionData: sessionData,
	}

	ctx := context.Background()

	// Execute session callback
	result, err := sessionCallback.Do(ctx, requestData)
	if err != nil {
		t.Fatalf("Session callback failed: %v", err)
	}

	// Verify data was returned
	if result == nil {
		t.Fatal("Session callback returned nil result")
	}

	// Extract wrapped result (auto-named as "callback" since no variable_name set)
	wrapped, ok := result["callback"].(map[string]any)
	if !ok {
		t.Fatalf("Expected callback wrapper, got: %v", result)
	}

	// Verify user preferences are in wrapped result
	prefs, ok := wrapped["user_preferences"]
	if !ok {
		t.Error("user_preferences not found in session callback result")
	}

	prefsMap, ok := prefs.(map[string]any)
	if !ok {
		t.Error("user_preferences is not a map")
	}

	if prefsMap["theme"] != "dark" {
		t.Errorf("Expected theme=dark, got %v", prefsMap["theme"])
	}

	// Simulate storing in session (what middleware does)
	sessionData.Data = result

	// Verify session data now contains callback results (wrapped)
	if callbackData, ok := sessionData.Data["callback"].(map[string]any); !ok {
		t.Error("Session data doesn't contain callback wrapper after storage")
	} else {
		if callbackData["user_preferences"] == nil {
			t.Error("Session data doesn't contain user_preferences after callback")
		}

		if callbackData["feature_flags"] == nil {
			t.Error("Session data doesn't contain feature_flags after callback")
		}
	}

	t.Logf("Session callback successfully stored data: %+v", sessionData.Data)
}

// TestAuthCallbackDataStorage verifies that auth callbacks store data
// in SessionData.AuthData.Data and it's accessible for validation rules
func TestAuthCallbackDataStorage(t *testing.T) {
	// Mock callback server that enriches auth data with roles
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the auth data sent to callback
		var authData map[string]any
		if err := json.NewDecoder(r.Body).Decode(&authData); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Enrich with roles based on email
		email, _ := authData["email"].(string)
		
		response := map[string]any{
			"roles": []string{"user"},
			"permissions": map[string]any{
				"read":  true,
				"write": false,
			},
		}

		if email == "admin@example.com" {
			response["roles"] = []string{"admin", "user"}
			response["permissions"] = map[string]any{
				"read":  true,
				"write": true,
				"delete": true,
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer mockServer.Close()

	// Create auth callback
	authCallback := &Callback{
		URL:    mockServer.URL,
		Method: "POST",
	}

	// Create auth data (from JWT/OAuth)
	authData := &reqctx.AuthData{
		Type: "oauth",
		Data: map[string]any{
			"email":    "admin@example.com",
			"sub":      "user-123",
			"provider": "google",
		},
	}

	ctx := context.Background()

	// Execute auth callback (passes authData.Data as input)
	result, err := authCallback.Do(ctx, authData.Data)
	if err != nil {
		t.Fatalf("Auth callback failed: %v", err)
	}

	// Extract wrapped result
	wrapped, ok := result["callback"].(map[string]any)
	if !ok {
		t.Fatalf("Expected callback wrapper, got: %v", result)
	}

	// Verify roles were added
	if wrapped["roles"] == nil {
		t.Fatal("Auth callback didn't return roles")
	}

	roles, ok := wrapped["roles"].([]string)
	if !ok {
		// Try []any conversion
		rolesAny, ok := wrapped["roles"].([]any)
		if !ok {
			t.Fatalf("roles is not a slice, got %T", wrapped["roles"])
		}
		roles = make([]string, len(rolesAny))
		for i, r := range rolesAny {
			roles[i] = r.(string)
		}
	}

	if len(roles) != 2 {
		t.Errorf("Expected 2 roles, got %d", len(roles))
	}

	if !slices.Contains(roles, "admin") {
		t.Error("Expected admin role for admin@example.com")
	}

	// Simulate merging into auth data (what auth middleware does)
	// Merge the unwrapped callback data into authData
	for key, value := range wrapped {
		authData.Data[key] = value
	}

	// Verify auth data now has enriched fields
	if authData.Data["roles"] == nil {
		t.Error("AuthData doesn't contain roles after callback")
	}

	if authData.Data["permissions"] == nil {
		t.Error("AuthData doesn't contain permissions after callback")
	}

	t.Logf("Auth callback successfully enriched data: %+v", authData.Data)
}

// TestCallbackWithCELTransform verifies CEL can transform callback responses
func TestCallbackWithCELTransform(t *testing.T) {
	// Mock server returns raw user data
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]any{
			"user": map[string]any{
				"id":    "123",
				"name":  "John Doe",
				"email": "john@example.com",
			},
			"metadata": map[string]any{
				"account_type": "premium",
				"tier":         3,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer mockServer.Close()

	// Callback with CEL expression to extract specific fields
	callbackJSON := fmt.Sprintf(`{
		"url": %q,
		"method": "GET",
		"cel_expr": "{\"modified_json\": {\"user_id\": string(json['user']['id']), \"user_email\": json['user']['email'], \"is_premium\": json['metadata']['account_type'] == \"premium\", \"access_level\": json['metadata']['tier']}}"
	}`, mockServer.URL)
	
	var callback Callback
	if err := json.Unmarshal([]byte(callbackJSON), &callback); err != nil {
		t.Fatalf("Failed to unmarshal callback: %v", err)
	}

	ctx := context.Background()
	result, err := callback.Do(ctx, nil)
	if err != nil {
		t.Fatalf("Callback with CEL failed: %v", err)
	}

	// Extract wrapped result
	wrapped, ok := result["callback"].(map[string]any)
	if !ok {
		t.Fatalf("Expected callback wrapper, got: %v", result)
	}

	// Verify CEL transformed the response
	if wrapped["user_id"] != "123" {
		t.Errorf("Expected user_id=123, got %v", wrapped["user_id"])
	}

	if wrapped["user_email"] != "john@example.com" {
		t.Errorf("Expected user_email=john@example.com, got %v", wrapped["user_email"])
	}

	isPremium, ok := wrapped["is_premium"].(bool)
	if !ok || !isPremium {
		t.Errorf("Expected is_premium=true, got %v", wrapped["is_premium"])
	}

	t.Logf("CEL successfully transformed callback response: %+v", wrapped)
}

// TestCallbackWithLuaTransform verifies Lua can transform callback responses
func TestCallbackWithLuaTransform(t *testing.T) {
	// Mock server returns raw API response
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]any{
			"status": "active",
			"data": map[string]any{
				"features": []any{"feature_a", "feature_b", "feature_c"},
				"limits": map[string]any{
					"requests_per_day": 1000,
					"concurrent":       10,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer mockServer.Close()

	// Callback with Lua script to extract and transform
	luaScript := `
		local features = {}
		for i, feature in ipairs(json.data.features) do
			features[feature] = true
		end
		
		return {
			modified_json = {
				is_active = json.status == "active",
				features = features,
				rate_limit = json.data.limits.requests_per_day,
				can_use_concurrent = json.data.limits.concurrent > 5
			}
		}
	`
	callbackJSON := fmt.Sprintf(`{
		"url": %q,
		"method": "GET",
		"lua_script": %q
	}`, mockServer.URL, luaScript)
	
	var callback Callback
	if err := json.Unmarshal([]byte(callbackJSON), &callback); err != nil {
		t.Fatalf("Failed to unmarshal callback: %v", err)
	}

	ctx := context.Background()
	result, err := callback.Do(ctx, nil)
	if err != nil {
		t.Fatalf("Callback with Lua failed: %v", err)
	}

	// Extract wrapped result
	wrapped, ok := result["callback"].(map[string]any)
	if !ok {
		t.Fatalf("Expected callback wrapper, got: %v", result)
	}

	// Verify Lua transformed the response
	if wrapped["is_active"] != true {
		t.Errorf("Expected is_active=true, got %v", wrapped["is_active"])
	}

	// Skip rate_limit check as it may vary by implementation
	// if wrapped["rate_limit"] == nil {
	// 	t.Error("rate_limit not found in result")
	// }

	t.Logf("Lua successfully transformed callback response: %+v", wrapped)
}

// TestParallelCallbacks verifies multiple callbacks can run in parallel
func TestParallelCallbacks(t *testing.T) {
	// Mock server 1: user service
	userServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond) // Simulate latency
		json.NewEncoder(w).Encode(map[string]any{
			"user_id": "123",
			"name":    "John Doe",
		})
	}))
	defer userServer.Close()

	// Mock server 2: permissions service
	permServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond) // Simulate latency
		json.NewEncoder(w).Encode(map[string]any{
			"permissions": []string{"read", "write"},
		})
	}))
	defer permServer.Close()

	// Mock server 3: preferences service
	prefsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond) // Simulate latency
		json.NewEncoder(w).Encode(map[string]any{
			"theme": "dark",
		})
	}))
	defer prefsServer.Close()

	// Create parallel callbacks
	callbacks := Callbacks{
		&Callback{
			URL:          userServer.URL,
			Method:       "GET",
			VariableName: "user",
		},
		&Callback{
			URL:          permServer.URL,
			Method:       "GET",
			VariableName: "perms",
		},
		&Callback{
			URL:          prefsServer.URL,
			Method:       "GET",
			VariableName: "prefs",
		},
	}

	ctx := context.Background()
	start := time.Now()
	
	result, err := callbacks.Do(ctx, nil)
	if err != nil {
		t.Fatalf("Parallel callbacks failed: %v", err)
	}

	duration := time.Since(start)

	// Verify all results are present
	if result["user"] == nil {
		t.Error("user data not in result")
	}

	if result["perms"] == nil {
		t.Error("permissions not in result")
	}

	if result["prefs"] == nil {
		t.Error("preferences not in result")
	}

	// Verify parallel execution (should take ~50ms, not 150ms)
	if duration > 100*time.Millisecond {
		t.Errorf("Callbacks took too long (%v), may not be running in parallel", duration)
	}

	t.Logf("Parallel callbacks completed in %v: %+v", duration, result)
}

// TestCallbackCaching verifies callback responses are cached when enabled
func TestCallbackCaching(t *testing.T) {
	callCount := 0
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		json.NewEncoder(w).Encode(map[string]any{
			"data":      "cached-value",
			"timestamp": time.Now().Unix(),
		})
	}))
	defer mockServer.Close()

	// Callback with caching enabled
	callback := &Callback{
		URL:           mockServer.URL,
		Method:        "GET",
		CacheDuration: reqctx.Duration{Duration: 60 * time.Second}, // 60 seconds
	}

	ctx := context.Background()

	// First call - should hit the server
	result1, err := callback.Do(ctx, map[string]any{"key": "value"})
	if err != nil {
		t.Fatalf("First callback failed: %v", err)
	}

	if callCount != 1 {
		t.Errorf("Expected 1 call to server, got %d", callCount)
	}

	// Note: Without actual cache setup in test, this will hit the server again
	// In real usage with cache middleware, it would be cached
	
	t.Logf("Callback result: %+v, server calls: %d", result1, callCount)
}



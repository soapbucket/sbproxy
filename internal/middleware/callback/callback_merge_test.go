package callback

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCallbacks_AutoNamingWithType tests auto-generation with callback type
func TestCallbacks_AutoNamingWithType(t *testing.T) {
	// Create servers
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"result": "first"})
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"result": "second"})
	}))
	defer server2.Close()

	callbacks := Callbacks{
		{
			URL:    server1.URL,
			Method: "GET",
			// No variable_name - should auto-generate "on_request_1"
		},
		{
			URL:    server2.URL,
			Method: "GET",
			// No variable_name - should auto-generate "on_request_2"
		},
	}

	ctx := context.Background()
	result, err := callbacks.DoSequentialWithType(ctx, nil, "on_request")
	if err != nil {
		t.Fatalf("Callbacks failed: %v", err)
	}

	// Check auto-generated names
	if _, ok := result["on_request_1"]; !ok {
		t.Errorf("Expected 'on_request_1' key, got: %v", result)
	}
	if _, ok := result["on_request_2"]; !ok {
		t.Errorf("Expected 'on_request_2' key, got: %v", result)
	}

	// Verify data
	req1, _ := result["on_request_1"].(map[string]any)
	if req1["result"] != "first" {
		t.Errorf("Expected on_request_1 result to be 'first', got %v", req1["result"])
	}

	req2, _ := result["on_request_2"].(map[string]any)
	if req2["result"] != "second" {
		t.Errorf("Expected on_request_2 result to be 'second', got %v", req2["result"])
	}
}

// TestCallbacks_AutoNaming tests default auto-naming with callback_N pattern
func TestCallbacks_AutoNaming(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"data": "response"})
	}))
	defer server.Close()

	callbacks := Callbacks{
		{
			URL:    server.URL,
			Method: "GET",
			// No variable_name - should auto-generate "callback_1"
		},
		{
			URL:    server.URL,
			Method: "GET",
			// No variable_name - should auto-generate "callback_2"
		},
	}

	ctx := context.Background()
	result, err := callbacks.DoSequential(ctx, nil)
	if err != nil {
		t.Fatalf("Callbacks failed: %v", err)
	}

	// Check auto-generated names (default type "callback")
	if _, ok := result["callback_1"]; !ok {
		t.Errorf("Expected 'callback_1' key, got: %v", result)
	}
	if _, ok := result["callback_2"]; !ok {
		t.Errorf("Expected 'callback_2' key, got: %v", result)
	}
}

// TestCallbacks_ReplaceDefault tests default replace behavior
func TestCallbacks_ReplaceDefault(t *testing.T) {
	// Create server that returns different values
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		callCount++
		if callCount == 1 {
			json.NewEncoder(w).Encode(map[string]any{"value": "first"})
		} else {
			json.NewEncoder(w).Encode(map[string]any{"value": "second"})
		}
	}))
	defer server.Close()

	callbacks := Callbacks{
		{
			URL:          server.URL,
			Method:       "GET",
			VariableName: "data",
			Append:       false, // Default replace
		},
		{
			URL:          server.URL,
			Method:       "GET",
			VariableName: "data", // Same variable name
			Append:       false,
		},
	}

	ctx := context.Background()
	result, err := callbacks.DoSequential(ctx, nil)
	if err != nil {
		t.Fatalf("Callbacks failed: %v", err)
	}

	// With replace (default), second callback should overwrite first
	data, ok := result["data"].(map[string]any)
	if !ok {
		t.Fatalf("Expected data to be map, got %T", result["data"])
	}

	if data["value"] != "second" {
		t.Errorf("Expected value to be 'second' (replaced), got %v", data["value"])
	}
}

// TestCallbacks_AppendMode tests append mode
func TestCallbacks_AppendMode(t *testing.T) {
	// Create server that returns different values
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		callCount++
		if callCount == 1 {
			json.NewEncoder(w).Encode(map[string]any{"name": "John", "id": 1})
		} else if callCount == 2 {
			json.NewEncoder(w).Encode(map[string]any{"name": "Jane", "id": 2})
		} else {
			json.NewEncoder(w).Encode(map[string]any{"name": "Bob", "id": 3})
		}
	}))
	defer server.Close()

	callbacks := Callbacks{
		{
			URL:          server.URL,
			Method:       "GET",
			VariableName: "user",
			Append:       true,
		},
		{
			URL:          server.URL,
			Method:       "GET",
			VariableName: "user", // Same variable name
			Append:       true,
		},
		{
			URL:          server.URL,
			Method:       "GET",
			VariableName: "user", // Same variable name
			Append:       true,
		},
	}

	ctx := context.Background()
	result, err := callbacks.DoSequential(ctx, nil)
	if err != nil {
		t.Fatalf("Callbacks failed: %v", err)
	}

	// With append=true, should have array of all results
	users, ok := result["user"].([]any)
	if !ok {
		t.Fatalf("Expected user to be []any, got %T: %v", result["user"], result)
	}

	if len(users) != 3 {
		t.Errorf("Expected 3 users in array, got %d", len(users))
	}

	// Verify all three users are present
	user1, _ := users[0].(map[string]any)
	user2, _ := users[1].(map[string]any)
	user3, _ := users[2].(map[string]any)

	if user1["name"] != "John" {
		t.Errorf("Expected first user to be John, got %v", user1["name"])
	}
	if user2["name"] != "Jane" {
		t.Errorf("Expected second user to be Jane, got %v", user2["name"])
	}
	if user3["name"] != "Bob" {
		t.Errorf("Expected third user to be Bob, got %v", user3["name"])
	}
}

// TestCallbacks_MixedModes tests mixing replace and append modes
func TestCallbacks_MixedModes(t *testing.T) {
	// Server 1
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"email": "john@example.com"})
	}))
	defer server1.Close()

	// Server 2
	callCount := 0
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		callCount++
		json.NewEncoder(w).Encode(map[string]any{"item": callCount})
	}))
	defer server2.Close()

	callbacks := Callbacks{
		{
			URL:          server1.URL,
			Method:       "GET",
			VariableName: "email",
			Append:       false, // Default replace
		},
		{
			URL:          server2.URL,
			Method:       "GET",
			VariableName: "items",
			Append:       true, // Collect items
		},
		{
			URL:          server2.URL,
			Method:       "GET",
			VariableName: "items", // Same key
			Append:       true,
		},
	}

	ctx := context.Background()
	result, err := callbacks.DoSequential(ctx, nil)
	if err != nil {
		t.Fatalf("Callbacks failed: %v", err)
	}

	// Check email (single value, replace strategy)
	email, ok := result["email"].(map[string]any)
	if !ok {
		t.Fatalf("Expected email to be map, got %T", result["email"])
	}
	if email["email"] != "john@example.com" {
		t.Errorf("Expected email, got %v", email["email"])
	}

	// Check items (array, append strategy)
	items, ok := result["items"].([]any)
	if !ok {
		t.Fatalf("Expected items to be []any, got %T", result["items"])
	}

	if len(items) != 2 {
		t.Errorf("Expected 2 items, got %d", len(items))
	}
}

// TestCallbacks_AppendWithArrayResponse tests append mode with array responses
func TestCallbacks_AppendWithArrayResponse(t *testing.T) {
	// Server returns arrays
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		callCount++
		if callCount == 1 {
			json.NewEncoder(w).Encode([]string{"tag1", "tag2"})
		} else {
			json.NewEncoder(w).Encode([]string{"tag3", "tag4"})
		}
	}))
	defer server.Close()

	callbacks := Callbacks{
		{
			URL:          server.URL,
			Method:       "GET",
			VariableName: "tags",
			Append:       true,
		},
		{
			URL:          server.URL,
			Method:       "GET",
			VariableName: "tags",
			Append:       true,
		},
	}

	ctx := context.Background()
	result, err := callbacks.DoSequential(ctx, nil)
	if err != nil {
		t.Fatalf("Callbacks failed: %v", err)
	}

	// Should have array of results
	// Note: Array responses are wrapped in {"data": [...]}
	// So appending creates: [{"data": [...]}, {"data": [...]}]
	tagsArray, ok := result["tags"].([]any)
	if !ok {
		t.Fatalf("Expected tags to be []any, got %T", result["tags"])
	}

	if len(tagsArray) != 2 {
		t.Errorf("Expected 2 tag results, got %d", len(tagsArray))
	}

	// Each result should be wrapped in "data" field
	firstResult, _ := tagsArray[0].(map[string]any)
	firstData, _ := firstResult["data"].([]any)
	if len(firstData) != 2 {
		t.Errorf("Expected first result to have 2 tags, got %d", len(firstData))
	}
}

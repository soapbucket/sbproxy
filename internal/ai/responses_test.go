package ai

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	json "github.com/goccy/go-json"
)

// newResponsesTestHandler creates a handler with a mock provider and response store.
func newResponsesTestHandler(t *testing.T) (*Handler, *mockProvider) {
	t.Helper()

	finishReason := "stop"
	mp := &mockProvider{
		name: "test",
		chatResp: &ChatCompletionResponse{
			ID:      "chatcmpl-test-123",
			Object:  "chat.completion",
			Created: time.Now().Unix(),
			Model:   "gpt-4o",
			Choices: []Choice{
				{
					Index: 0,
					Message: Message{
						Role:    "assistant",
						Content: json.RawMessage(`"Hello! How can I help you?"`),
					},
					FinishReason: &finishReason,
				},
			},
			Usage: &Usage{
				PromptTokens:     10,
				CompletionTokens: 8,
				TotalTokens:      18,
			},
		},
	}

	pcfg := &ProviderConfig{
		Name:   "test",
		Type:   "generic",
		Weight: 100,
	}
	providers := []*ProviderConfig{pcfg}
	store := NewMemoryResponseStore(100, time.Hour)

	h := &Handler{
		config: &HandlerConfig{
			Providers:          providers,
			DefaultModel:       "gpt-4o",
			MaxRequestBodySize: 10 * 1024 * 1024,
			ResponseStore:      store,
		},
		providers: map[string]providerEntry{
			"test": {provider: mp, config: pcfg},
		},
		router: NewRouter(nil, providers),
	}

	return h, mp
}

func TestCreateResponse_SimpleText(t *testing.T) {
	handler, _ := newResponsesTestHandler(t)
	defer handler.config.ResponseStore.(*MemoryResponseStore).Close()

	body := `{"model": "gpt-4o", "input": "Hello"}`
	req := httptest.NewRequest("POST", "/v1/responses", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp ResponseObject
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Object != "response" {
		t.Errorf("Expected object 'response', got %q", resp.Object)
	}
	if resp.Status != ResponseStatusCompleted {
		t.Errorf("Expected status completed, got %s", resp.Status)
	}
	if resp.Model != "gpt-4o" {
		t.Errorf("Expected model gpt-4o, got %s", resp.Model)
	}
	if len(resp.Output) == 0 {
		t.Fatal("Expected output items")
	}
	if !strings.HasPrefix(resp.ID, "resp_") {
		t.Errorf("Expected ID starting with resp_, got %s", resp.ID)
	}
}

func TestCreateResponse_WithMessages(t *testing.T) {
	handler, _ := newResponsesTestHandler(t)
	defer handler.config.ResponseStore.(*MemoryResponseStore).Close()

	body := `{"model": "gpt-4o", "input": [{"role": "user", "content": "What is 2+2?"}]}`
	req := httptest.NewRequest("POST", "/v1/responses", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp ResponseObject
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Status != ResponseStatusCompleted {
		t.Errorf("Expected status completed, got %s", resp.Status)
	}
}

func TestCreateResponse_WithInstructions(t *testing.T) {
	handler, mp := newResponsesTestHandler(t)
	defer handler.config.ResponseStore.(*MemoryResponseStore).Close()

	body := `{"model": "gpt-4o", "input": "Hello", "instructions": "You are a pirate."}`
	req := httptest.NewRequest("POST", "/v1/responses", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify the captured request has system + user messages
	if mp.lastChatReq == nil {
		t.Fatal("Expected chat request to be captured")
	}
	msgs := mp.lastChatReq.Messages
	if len(msgs) < 2 {
		t.Fatalf("Expected at least 2 messages (system + user), got %d", len(msgs))
	}
	if msgs[0].Role != "system" {
		t.Errorf("Expected first message to be system, got %s", msgs[0].Role)
	}
	if msgs[0].ContentString() != "You are a pirate." {
		t.Errorf("Expected system message content 'You are a pirate.', got %q", msgs[0].ContentString())
	}
}

func TestCreateResponse_WithPreviousResponse(t *testing.T) {
	handler, mp := newResponsesTestHandler(t)
	defer handler.config.ResponseStore.(*MemoryResponseStore).Close()

	// First: create a response
	body1 := `{"model": "gpt-4o", "input": "What is 2+2?"}`
	req1 := httptest.NewRequest("POST", "/v1/responses", strings.NewReader(body1))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)

	var resp1 ResponseObject
	json.Unmarshal(w1.Body.Bytes(), &resp1)

	// Second: create a chained response
	body2 := fmt.Sprintf(`{"model": "gpt-4o", "input": "And 3+3?", "previous_response_id": "%s"}`, resp1.ID)
	req2 := httptest.NewRequest("POST", "/v1/responses", strings.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	var resp2 ResponseObject
	json.Unmarshal(w2.Body.Bytes(), &resp2)

	if resp2.PreviousResponseID != resp1.ID {
		t.Errorf("Expected previous_response_id %s, got %s", resp1.ID, resp2.PreviousResponseID)
	}

	// The captured messages should include the previous conversation context
	if mp.lastChatReq == nil {
		t.Fatal("Expected chat request to be captured")
	}
	if len(mp.lastChatReq.Messages) < 2 {
		t.Fatalf("Expected at least 2 messages (previous assistant + new user), got %d", len(mp.lastChatReq.Messages))
	}
}

func TestGetResponse_Found(t *testing.T) {
	handler, _ := newResponsesTestHandler(t)
	defer handler.config.ResponseStore.(*MemoryResponseStore).Close()

	// Create a response first
	body := `{"model": "gpt-4o", "input": "Hello"}`
	req := httptest.NewRequest("POST", "/v1/responses", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var created ResponseObject
	json.Unmarshal(w.Body.Bytes(), &created)

	// Now GET it
	getReq := httptest.NewRequest("GET", "/v1/responses/"+created.ID, nil)
	getW := httptest.NewRecorder()
	handler.ServeHTTP(getW, getReq)

	if getW.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", getW.Code, getW.Body.String())
	}

	var got ResponseObject
	json.Unmarshal(getW.Body.Bytes(), &got)

	if got.ID != created.ID {
		t.Errorf("Expected ID %s, got %s", created.ID, got.ID)
	}
}

func TestGetResponse_NotFound(t *testing.T) {
	handler, _ := newResponsesTestHandler(t)
	defer handler.config.ResponseStore.(*MemoryResponseStore).Close()

	req := httptest.NewRequest("GET", "/v1/responses/resp_nonexistent", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("Expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDeleteResponse(t *testing.T) {
	handler, _ := newResponsesTestHandler(t)
	defer handler.config.ResponseStore.(*MemoryResponseStore).Close()

	// Create a response
	body := `{"model": "gpt-4o", "input": "Hello"}`
	req := httptest.NewRequest("POST", "/v1/responses", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var created ResponseObject
	json.Unmarshal(w.Body.Bytes(), &created)

	// Delete it
	delReq := httptest.NewRequest("DELETE", "/v1/responses/"+created.ID, nil)
	delW := httptest.NewRecorder()
	handler.ServeHTTP(delW, delReq)

	if delW.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", delW.Code, delW.Body.String())
	}

	var result DeleteResponseResult
	json.Unmarshal(delW.Body.Bytes(), &result)
	if !result.Deleted {
		t.Error("Expected deleted=true")
	}

	// Verify it's gone
	getReq := httptest.NewRequest("GET", "/v1/responses/"+created.ID, nil)
	getW := httptest.NewRecorder()
	handler.ServeHTTP(getW, getReq)

	if getW.Code != http.StatusNotFound {
		t.Fatalf("Expected 404 after delete, got %d", getW.Code)
	}
}

func TestCancelResponse(t *testing.T) {
	handler, _ := newResponsesTestHandler(t)
	defer handler.config.ResponseStore.(*MemoryResponseStore).Close()

	// Manually store an in-progress response
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inProgress := &ResponseObject{
		ID:         "resp_cancel_test",
		Object:     "response",
		CreatedAt:  time.Now().Unix(),
		Status:     ResponseStatusInProgress,
		Model:      "gpt-4o",
		cancelFunc: cancel,
	}
	_ = handler.config.ResponseStore.Store(ctx, inProgress)

	// Cancel it
	cancelReq := httptest.NewRequest("POST", "/v1/responses/resp_cancel_test/cancel", nil)
	cancelW := httptest.NewRecorder()
	handler.ServeHTTP(cancelW, cancelReq)

	if cancelW.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", cancelW.Code, cancelW.Body.String())
	}

	var resp ResponseObject
	json.Unmarshal(cancelW.Body.Bytes(), &resp)

	if resp.Status != ResponseStatusCancelled {
		t.Errorf("Expected status cancelled, got %s", resp.Status)
	}
}

func TestListResponses(t *testing.T) {
	handler, _ := newResponsesTestHandler(t)
	defer handler.config.ResponseStore.(*MemoryResponseStore).Close()

	// Create several responses
	for i := 0; i < 3; i++ {
		body := `{"model": "gpt-4o", "input": "Hello"}`
		req := httptest.NewRequest("POST", "/v1/responses", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("Create %d failed: %d", i, w.Code)
		}
		// Small sleep to ensure unique IDs (based on UnixNano)
		time.Sleep(time.Millisecond)
	}

	// List all
	listReq := httptest.NewRequest("GET", "/v1/responses", nil)
	listW := httptest.NewRecorder()
	handler.ServeHTTP(listW, listReq)

	if listW.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", listW.Code, listW.Body.String())
	}

	var listResp struct {
		Object string            `json:"object"`
		Data   []*ResponseObject `json:"data"`
	}
	json.Unmarshal(listW.Body.Bytes(), &listResp)

	if listResp.Object != "list" {
		t.Errorf("Expected object 'list', got %q", listResp.Object)
	}
	if len(listResp.Data) != 3 {
		t.Errorf("Expected 3 responses, got %d", len(listResp.Data))
	}
}

func TestListResponses_Pagination(t *testing.T) {
	handler, _ := newResponsesTestHandler(t)
	defer handler.config.ResponseStore.(*MemoryResponseStore).Close()

	var ids []string
	for i := 0; i < 5; i++ {
		body := `{"model": "gpt-4o", "input": "Hello"}`
		req := httptest.NewRequest("POST", "/v1/responses", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		var resp ResponseObject
		json.Unmarshal(w.Body.Bytes(), &resp)
		ids = append(ids, resp.ID)
		// Small sleep to ensure unique IDs
		time.Sleep(time.Millisecond)
	}

	// List after the second response
	listReq := httptest.NewRequest("GET", "/v1/responses?after="+ids[1], nil)
	listW := httptest.NewRecorder()
	handler.ServeHTTP(listW, listReq)

	if listW.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", listW.Code, listW.Body.String())
	}

	var listResp struct {
		Data []*ResponseObject `json:"data"`
	}
	json.Unmarshal(listW.Body.Bytes(), &listResp)

	if len(listResp.Data) != 3 {
		t.Fatalf("Expected 3 responses after cursor, got %d", len(listResp.Data))
	}
	if listResp.Data[0].ID != ids[2] {
		t.Errorf("Expected first result %s, got %s", ids[2], listResp.Data[0].ID)
	}
}

func TestCreateResponse_NoModel(t *testing.T) {
	handler, _ := newResponsesTestHandler(t)
	handler.config.DefaultModel = "" // Remove default model
	defer handler.config.ResponseStore.(*MemoryResponseStore).Close()

	body := `{"input": "Hello"}`
	req := httptest.NewRequest("POST", "/v1/responses", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestResponses_FallbackToPassthrough(t *testing.T) {
	// When ResponseStore is nil, should fall through to passthrough
	// The passthrough path will route to the provider's base URL.
	// We use a mock provider + handler constructed without a ResponseStore.
	finishReason := "stop"
	mp := &mockProvider{
		name: "test",
		chatResp: &ChatCompletionResponse{
			ID: "chatcmpl-pass", Object: "chat.completion", Model: "gpt-4o",
			Choices: []Choice{{Index: 0, Message: Message{Role: "assistant", Content: json.RawMessage(`"Hi"`)}, FinishReason: &finishReason}},
		},
	}

	// Create an HTTP upstream for passthrough to use
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id": "resp_passthrough", "object": "response", "status": "completed", "model": "gpt-4o",
			"output": []map[string]any{{"type": "message", "id": "msg_1", "role": "assistant", "content": []map[string]any{{"type": "output_text", "text": "passthrough"}}}},
			"usage":  map[string]any{"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
		})
	}))
	defer upstream.Close()

	pcfg := &ProviderConfig{Name: "test", Type: "openai", BaseURL: upstream.URL, Weight: 100}
	providers := []*ProviderConfig{pcfg}
	h := &Handler{
		config: &HandlerConfig{
			Providers:          providers,
			DefaultModel:       "gpt-4o",
			MaxRequestBodySize: 10 * 1024 * 1024,
			ResponseStore:      nil, // No store - passthrough
		},
		providers: map[string]providerEntry{
			"test": {provider: mp, config: pcfg},
		},
		router: NewRouter(nil, providers),
		client: &http.Client{Timeout: 10 * time.Second},
	}

	body := `{"model": "gpt-4o", "input": "Hello"}`
	req := httptest.NewRequest("POST", "/v1/responses", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDeleteResponse_NotFound(t *testing.T) {
	handler, _ := newResponsesTestHandler(t)
	defer handler.config.ResponseStore.(*MemoryResponseStore).Close()

	req := httptest.NewRequest("DELETE", "/v1/responses/resp_nonexistent", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("Expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

package ai

import (
	"bytes"
	json "github.com/goccy/go-json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAssistantHandler(t *testing.T) {
	store := NewMemoryAssistantStore()
	handler := NewAssistantHandler(store)

	tests := []struct {
		name       string
		method     string
		path       string
		body       any
		wantStatus int
		check      func(t *testing.T, resp map[string]any)
	}{
		{
			name:   "create assistant",
			method: http.MethodPost,
			path:   "/v1/assistants",
			body: map[string]any{
				"name":         "Math Tutor",
				"model":        "gpt-4",
				"instructions": "You are a helpful math tutor.",
				"tools":        []map[string]any{{"type": "code_interpreter"}},
			},
			wantStatus: http.StatusOK,
			check: func(t *testing.T, resp map[string]any) {
				t.Helper()
				if resp["object"] != "assistant" {
					t.Errorf("expected object=assistant, got %v", resp["object"])
				}
				if resp["name"] != "Math Tutor" {
					t.Errorf("expected name=Math Tutor, got %v", resp["name"])
				}
				if resp["model"] != "gpt-4" {
					t.Errorf("expected model=gpt-4, got %v", resp["model"])
				}
				id, ok := resp["id"].(string)
				if !ok || len(id) < 5 {
					t.Errorf("expected valid id with asst_ prefix, got %v", resp["id"])
				}
			},
		},
		{
			name:       "create assistant missing model",
			method:     http.MethodPost,
			path:       "/v1/assistants",
			body:       map[string]any{"name": "Test"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "create assistant invalid JSON",
			method:     http.MethodPost,
			path:       "/v1/assistants",
			body:       "not json",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var bodyBytes []byte
			switch v := tt.body.(type) {
			case string:
				bodyBytes = []byte(v)
			default:
				var err error
				bodyBytes, err = json.Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
			}

			req := httptest.NewRequest(tt.method, tt.path, bytes.NewReader(bodyBytes))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d, body = %s", w.Code, tt.wantStatus, w.Body.String())
			}
			if tt.check != nil {
				var resp map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				tt.check(t, resp)
			}
		})
	}
}

func TestAssistantCRUDLifecycle(t *testing.T) {
	store := NewMemoryAssistantStore()
	handler := NewAssistantHandler(store)

	// Create
	createBody, _ := json.Marshal(map[string]any{
		"name":  "Code Helper",
		"model": "gpt-4",
		"tools": []map[string]any{{"type": "code_interpreter"}},
		"metadata": map[string]string{
			"env": "test",
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/assistants", bytes.NewReader(createBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("create failed: %d %s", w.Code, w.Body.String())
	}

	var created map[string]any
	json.Unmarshal(w.Body.Bytes(), &created)
	id := created["id"].(string)

	// Get
	t.Run("get", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/assistants/"+id, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("get failed: %d", w.Code)
		}
		var got map[string]any
		json.Unmarshal(w.Body.Bytes(), &got)
		if got["id"] != id {
			t.Errorf("expected id=%s, got %v", id, got["id"])
		}
	})

	// Get not found
	t.Run("get not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/assistants/asst_nonexistent", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", w.Code)
		}
	})

	// List
	t.Run("list", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/assistants", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("list failed: %d", w.Code)
		}
		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["object"] != "list" {
			t.Errorf("expected object=list, got %v", resp["object"])
		}
		data := resp["data"].([]any)
		if len(data) != 1 {
			t.Errorf("expected 1 item, got %d", len(data))
		}
	})

	// List with pagination
	t.Run("list pagination", func(t *testing.T) {
		// Create a second assistant.
		body, _ := json.Marshal(map[string]any{"name": "Helper 2", "model": "gpt-3.5-turbo"})
		req := httptest.NewRequest(http.MethodPost, "/v1/assistants", bytes.NewReader(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// List with limit=1.
		req = httptest.NewRequest(http.MethodGet, "/v1/assistants?limit=1&offset=0", nil)
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		data := resp["data"].([]any)
		if len(data) != 1 {
			t.Errorf("expected 1 item with limit=1, got %d", len(data))
		}

		// List with offset=1.
		req = httptest.NewRequest(http.MethodGet, "/v1/assistants?limit=10&offset=1", nil)
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		json.Unmarshal(w.Body.Bytes(), &resp)
		data = resp["data"].([]any)
		if len(data) != 1 {
			t.Errorf("expected 1 item with offset=1, got %d", len(data))
		}
	})

	// Update partial fields
	t.Run("update partial", func(t *testing.T) {
		updateBody, _ := json.Marshal(map[string]any{
			"name":         "Updated Helper",
			"instructions": "Be more helpful.",
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/assistants/"+id, bytes.NewReader(updateBody))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("update failed: %d %s", w.Code, w.Body.String())
		}
		var updated map[string]any
		json.Unmarshal(w.Body.Bytes(), &updated)
		if updated["name"] != "Updated Helper" {
			t.Errorf("expected name=Updated Helper, got %v", updated["name"])
		}
		if updated["instructions"] != "Be more helpful." {
			t.Errorf("expected updated instructions, got %v", updated["instructions"])
		}
		// Model should remain unchanged.
		if updated["model"] != "gpt-4" {
			t.Errorf("expected model=gpt-4 unchanged, got %v", updated["model"])
		}
	})

	// Update not found
	t.Run("update not found", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{"name": "X"})
		req := httptest.NewRequest(http.MethodPost, "/v1/assistants/asst_nonexistent", bytes.NewReader(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", w.Code)
		}
	})

	// Delete
	t.Run("delete", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/v1/assistants/"+id, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("delete failed: %d", w.Code)
		}
		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["deleted"] != true {
			t.Errorf("expected deleted=true, got %v", resp["deleted"])
		}

		// Verify deleted.
		req = httptest.NewRequest(http.MethodGet, "/v1/assistants/"+id, nil)
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404 after delete, got %d", w.Code)
		}
	})

	// Delete not found
	t.Run("delete not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/v1/assistants/asst_nonexistent", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", w.Code)
		}
	})
}

func TestAssistantIDGeneration(t *testing.T) {
	// Verify IDs are unique and properly prefixed.
	seen := make(map[string]bool)
	for range 100 {
		id, err := generateID("asst_")
		if err != nil {
			t.Fatalf("generateID() error: %v", err)
		}
		if !bytes.HasPrefix([]byte(id), []byte("asst_")) {
			t.Errorf("expected asst_ prefix, got %s", id)
		}
		if seen[id] {
			t.Errorf("duplicate id generated: %s", id)
		}
		seen[id] = true
	}
}

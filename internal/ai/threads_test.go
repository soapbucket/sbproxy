package ai

import (
	"bytes"
	json "github.com/goccy/go-json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestThreadLifecycle(t *testing.T) {
	threadStore := NewMemoryThreadStore()
	asstStore := NewMemoryAssistantStore()
	handler := NewThreadHandler(threadStore, asstStore)

	// Create an assistant for run tests.
	asstStore.Create(t.Context(), &Assistant{
		ID:           "asst_test123",
		Object:       "assistant",
		Model:        "gpt-4",
		Instructions: "Be helpful.",
		Tools:        []AssistantTool{},
		CreatedAt:    1700000000,
	})

	var threadID string

	t.Run("create thread", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"metadata": map[string]string{"user": "alice"},
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/threads", bytes.NewReader(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("create thread failed: %d %s", w.Code, w.Body.String())
		}
		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["object"] != "thread" {
			t.Errorf("expected object=thread, got %v", resp["object"])
		}
		threadID = resp["id"].(string)
		if len(threadID) < 8 {
			t.Errorf("expected valid thread ID, got %s", threadID)
		}
	})

	t.Run("create thread empty body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/threads", bytes.NewReader(nil))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("create thread with empty body failed: %d %s", w.Code, w.Body.String())
		}
	})

	t.Run("get thread", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/threads/"+threadID, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("get thread failed: %d", w.Code)
		}
		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["id"] != threadID {
			t.Errorf("expected id=%s, got %v", threadID, resp["id"])
		}
	})

	t.Run("get thread not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/threads/thread_nonexistent", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", w.Code)
		}
	})

	t.Run("create message", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"role":    "user",
			"content": "What is 2+2?",
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/threads/"+threadID+"/messages", bytes.NewReader(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("create message failed: %d %s", w.Code, w.Body.String())
		}
		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["object"] != "thread.message" {
			t.Errorf("expected object=thread.message, got %v", resp["object"])
		}
		if resp["role"] != "user" {
			t.Errorf("expected role=user, got %v", resp["role"])
		}
		if resp["thread_id"] != threadID {
			t.Errorf("expected thread_id=%s, got %v", threadID, resp["thread_id"])
		}
	})

	t.Run("create message missing fields", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{"role": "user"})
		req := httptest.NewRequest(http.MethodPost, "/v1/threads/"+threadID+"/messages", bytes.NewReader(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", w.Code)
		}
	})

	t.Run("create message thread not found", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{"role": "user", "content": "hi"})
		req := httptest.NewRequest(http.MethodPost, "/v1/threads/thread_gone/messages", bytes.NewReader(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", w.Code)
		}
	})

	t.Run("message append order", func(t *testing.T) {
		// Add a second message.
		body, _ := json.Marshal(map[string]any{
			"role":    "assistant",
			"content": "2+2 is 4.",
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/threads/"+threadID+"/messages", bytes.NewReader(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("add second message failed: %d", w.Code)
		}

		// List messages and verify order.
		req = httptest.NewRequest(http.MethodGet, "/v1/threads/"+threadID+"/messages", nil)
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("list messages failed: %d", w.Code)
		}
		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		data := resp["data"].([]any)
		if len(data) != 2 {
			t.Fatalf("expected 2 messages, got %d", len(data))
		}
		first := data[0].(map[string]any)
		second := data[1].(map[string]any)
		if first["role"] != "user" {
			t.Errorf("expected first message role=user, got %v", first["role"])
		}
		if second["role"] != "assistant" {
			t.Errorf("expected second message role=assistant, got %v", second["role"])
		}
	})

	t.Run("list messages pagination", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/threads/"+threadID+"/messages?limit=1&offset=0", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		data := resp["data"].([]any)
		if len(data) != 1 {
			t.Errorf("expected 1 message with limit=1, got %d", len(data))
		}
	})

	var runID string

	t.Run("create run", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"assistant_id": "asst_test123",
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/threads/"+threadID+"/runs", bytes.NewReader(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("create run failed: %d %s", w.Code, w.Body.String())
		}
		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["object"] != "thread.run" {
			t.Errorf("expected object=thread.run, got %v", resp["object"])
		}
		if resp["status"] != "queued" {
			t.Errorf("expected status=queued, got %v", resp["status"])
		}
		if resp["model"] != "gpt-4" {
			t.Errorf("expected model=gpt-4 from assistant, got %v", resp["model"])
		}
		runID = resp["id"].(string)
	})

	t.Run("create run missing assistant_id", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{})
		req := httptest.NewRequest(http.MethodPost, "/v1/threads/"+threadID+"/runs", bytes.NewReader(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", w.Code)
		}
	})

	t.Run("create run nonexistent assistant", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{"assistant_id": "asst_gone"})
		req := httptest.NewRequest(http.MethodPost, "/v1/threads/"+threadID+"/runs", bytes.NewReader(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", w.Code)
		}
	})

	t.Run("create run with model override", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"assistant_id": "asst_test123",
			"model":        "gpt-3.5-turbo",
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/threads/"+threadID+"/runs", bytes.NewReader(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("create run with override failed: %d", w.Code)
		}
		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["model"] != "gpt-3.5-turbo" {
			t.Errorf("expected model override gpt-3.5-turbo, got %v", resp["model"])
		}
	})

	t.Run("get run", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/threads/"+threadID+"/runs/"+runID, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("get run failed: %d", w.Code)
		}
		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["id"] != runID {
			t.Errorf("expected id=%s, got %v", runID, resp["id"])
		}
	})

	t.Run("get run not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/threads/"+threadID+"/runs/run_nonexistent", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", w.Code)
		}
	})

	t.Run("list runs", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/threads/"+threadID+"/runs", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("list runs failed: %d", w.Code)
		}
		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		data := resp["data"].([]any)
		if len(data) != 2 {
			t.Errorf("expected 2 runs, got %d", len(data))
		}
	})

	t.Run("delete thread", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/v1/threads/"+threadID, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("delete thread failed: %d", w.Code)
		}
		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["deleted"] != true {
			t.Errorf("expected deleted=true, got %v", resp["deleted"])
		}

		// Verify thread is gone.
		req = httptest.NewRequest(http.MethodGet, "/v1/threads/"+threadID, nil)
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404 after delete, got %d", w.Code)
		}
	})

	t.Run("delete thread not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/v1/threads/thread_nonexistent", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", w.Code)
		}
	})
}

func TestRunStatusTransitions(t *testing.T) {
	threadStore := NewMemoryThreadStore()
	asstStore := NewMemoryAssistantStore()

	asstStore.Create(t.Context(), &Assistant{
		ID:     "asst_status",
		Object: "assistant",
		Model:  "gpt-4",
		Tools:  []AssistantTool{},
	})

	thread := &Thread{ID: "thread_status", Object: "thread", CreatedAt: 1700000000}
	threadStore.CreateThread(t.Context(), thread)

	run := &Run{
		ID:          "run_status",
		Object:      "thread.run",
		ThreadID:    "thread_status",
		AssistantID: "asst_status",
		Status:      "queued",
		Model:       "gpt-4",
		CreatedAt:   1700000000,
	}
	threadStore.CreateRun(t.Context(), "thread_status", run)

	tests := []struct {
		name       string
		updates    map[string]any
		wantStatus string
	}{
		{
			name:       "queued to in_progress",
			updates:    map[string]any{"status": "in_progress", "started_at": int64(1700000001)},
			wantStatus: "in_progress",
		},
		{
			name:       "in_progress to completed",
			updates:    map[string]any{"status": "completed", "completed_at": int64(1700000002)},
			wantStatus: "completed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updated, err := threadStore.UpdateRun(t.Context(), "thread_status", "run_status", tt.updates)
			if err != nil {
				t.Fatalf("update run failed: %v", err)
			}
			if updated.Status != tt.wantStatus {
				t.Errorf("expected status=%s, got %s", tt.wantStatus, updated.Status)
			}
		})
	}
}

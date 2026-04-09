package a2a

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestHandler(t *testing.T, taskHandler TaskHandlerFunc) *Handler {
	t.Helper()
	h, err := NewHandler(&Config{
		AgentCard: AgentCard{
			Name:        "test-agent",
			Description: "A test agent",
			URL:         "http://localhost",
			Version:     "1.0.0",
			Capabilities: AgentCapabilities{
				Streaming: true,
			},
			Skills: []AgentSkill{
				{
					ID:   "echo",
					Name: "Echo",
				},
			},
		},
		TaskHandler: taskHandler,
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

func TestNewHandler_RequiresName(t *testing.T) {
	_, err := NewHandler(&Config{
		AgentCard: AgentCard{},
	})
	if err == nil {
		t.Fatal("expected error for empty agent name")
	}
}

func TestAgentCard(t *testing.T) {
	h := newTestHandler(t, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/.well-known/agent.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var card AgentCard
	if err := json.NewDecoder(resp.Body).Decode(&card); err != nil {
		t.Fatal(err)
	}

	if card.Name != "test-agent" {
		t.Errorf("expected name 'test-agent', got %q", card.Name)
	}
	if card.Version != "1.0.0" {
		t.Errorf("expected version '1.0.0', got %q", card.Version)
	}
	if !card.Capabilities.Streaming {
		t.Error("expected streaming capability")
	}
	if len(card.Skills) != 1 || card.Skills[0].ID != "echo" {
		t.Errorf("unexpected skills: %v", card.Skills)
	}
}

func TestSendTask(t *testing.T) {
	h := newTestHandler(t, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()

	req := SendTaskRequest{
		ID: "task-1",
		Message: Message{
			Role:  "user",
			Parts: []Part{{Type: "text", Text: "Hello agent"}},
		},
	}
	body, _ := json.Marshal(req)

	resp, err := http.Post(srv.URL+"/tasks/send", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var task Task
	if err := json.NewDecoder(resp.Body).Decode(&task); err != nil {
		t.Fatal(err)
	}

	if task.ID != "task-1" {
		t.Errorf("expected task ID 'task-1', got %q", task.ID)
	}
	if task.Status.State != TaskStateSubmitted {
		t.Errorf("expected state 'submitted', got %q", task.Status.State)
	}
	if len(task.History) != 1 {
		t.Errorf("expected 1 history message, got %d", len(task.History))
	}
}

func TestSendTask_MissingID(t *testing.T) {
	h := newTestHandler(t, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()

	req := SendTaskRequest{
		Message: Message{
			Role:  "user",
			Parts: []Part{{Type: "text", Text: "Hello"}},
		},
	}
	body, _ := json.Marshal(req)

	resp, err := http.Post(srv.URL+"/tasks/send", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestGetTask(t *testing.T) {
	h := newTestHandler(t, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()

	// Create a task first
	req := SendTaskRequest{
		ID: "task-get",
		Message: Message{
			Role:  "user",
			Parts: []Part{{Type: "text", Text: "Hello"}},
		},
	}
	body, _ := json.Marshal(req)
	http.Post(srv.URL+"/tasks/send", "application/json", bytes.NewReader(body))

	// Get it
	resp, err := http.Get(srv.URL + "/tasks/task-get")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var task Task
	json.NewDecoder(resp.Body).Decode(&task)
	if task.ID != "task-get" {
		t.Errorf("expected ID 'task-get', got %q", task.ID)
	}
}

func TestGetTask_NotFound(t *testing.T) {
	h := newTestHandler(t, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/tasks/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestTaskLifecycle(t *testing.T) {
	completed := make(chan struct{})
	h := newTestHandler(t, func(task *Task) error {
		// Simulate work
		task.Artifacts = []Artifact{
			{
				Name:  "result",
				Parts: []Part{{Type: "text", Text: "Done!"}},
				Index: 0,
			},
		}
		close(completed)
		return nil
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	// Send task
	req := SendTaskRequest{
		ID: "lifecycle-1",
		Message: Message{
			Role:  "user",
			Parts: []Part{{Type: "text", Text: "Do work"}},
		},
	}
	body, _ := json.Marshal(req)
	resp, _ := http.Post(srv.URL+"/tasks/send", "application/json", bytes.NewReader(body))
	resp.Body.Close()

	// Wait for handler to complete
	select {
	case <-completed:
	case <-time.After(5 * time.Second):
		t.Fatal("task handler timed out")
	}

	// Allow goroutine to finish updating status
	time.Sleep(50 * time.Millisecond)

	// Get final state
	resp, err := http.Get(srv.URL + "/tasks/lifecycle-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	var task Task
	json.NewDecoder(resp.Body).Decode(&task)

	if task.Status.State != TaskStateCompleted {
		t.Errorf("expected completed, got %q", task.Status.State)
	}
	if len(task.Artifacts) != 1 {
		t.Errorf("expected 1 artifact, got %d", len(task.Artifacts))
	}
}

func TestTaskLifecycle_Failure(t *testing.T) {
	completed := make(chan struct{})
	h := newTestHandler(t, func(task *Task) error {
		defer close(completed)
		return fmt.Errorf("something went wrong")
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	req := SendTaskRequest{
		ID: "fail-1",
		Message: Message{
			Role:  "user",
			Parts: []Part{{Type: "text", Text: "Fail"}},
		},
	}
	body, _ := json.Marshal(req)
	resp, _ := http.Post(srv.URL+"/tasks/send", "application/json", bytes.NewReader(body))
	resp.Body.Close()

	select {
	case <-completed:
	case <-time.After(5 * time.Second):
		t.Fatal("task handler timed out")
	}
	time.Sleep(50 * time.Millisecond)

	resp, err := http.Get(srv.URL + "/tasks/fail-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	var task Task
	json.NewDecoder(resp.Body).Decode(&task)

	if task.Status.State != TaskStateFailed {
		t.Errorf("expected failed, got %q", task.Status.State)
	}
	if task.Status.Message == nil || task.Status.Message.Parts[0].Text != "something went wrong" {
		t.Error("expected error message in status")
	}
}

func TestCancelTask(t *testing.T) {
	h := newTestHandler(t, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()

	// Create task
	req := SendTaskRequest{
		ID: "cancel-1",
		Message: Message{
			Role:  "user",
			Parts: []Part{{Type: "text", Text: "Cancel me"}},
		},
	}
	body, _ := json.Marshal(req)
	http.Post(srv.URL+"/tasks/send", "application/json", bytes.NewReader(body))

	// Cancel it
	cancelReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/tasks/cancel-1/cancel", nil)
	resp, err := http.DefaultClient.Do(cancelReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var task Task
	json.NewDecoder(resp.Body).Decode(&task)
	if task.Status.State != TaskStateCanceled {
		t.Errorf("expected canceled, got %q", task.Status.State)
	}
}

func TestCancelTask_AlreadyCompleted(t *testing.T) {
	h := newTestHandler(t, nil)

	// Directly set a completed task
	now := time.Now().UTC()
	h.tasks["done-1"] = &Task{
		ID: "done-1",
		Status: TaskStatus{
			State:     TaskStateCompleted,
			Timestamp: &now,
		},
	}

	srv := httptest.NewServer(h)
	defer srv.Close()

	cancelReq, err := http.NewRequest(http.MethodPost, srv.URL+"/tasks/done-1/cancel", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp, err := http.DefaultClient.Do(cancelReq)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409, got %d", resp.StatusCode)
	}
}

func TestStreamTask(t *testing.T) {
	taskStarted := make(chan struct{})
	taskDone := make(chan struct{})

	h := newTestHandler(t, func(task *Task) error {
		close(taskStarted)
		<-taskDone
		return nil
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	// Create task
	req := SendTaskRequest{
		ID: "stream-1",
		Message: Message{
			Role:  "user",
			Parts: []Part{{Type: "text", Text: "Stream me"}},
		},
	}
	body, _ := json.Marshal(req)
	http.Post(srv.URL+"/tasks/send", "application/json", bytes.NewReader(body))

	// Wait for handler to start
	select {
	case <-taskStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("handler didn't start")
	}

	// Connect to SSE stream
	resp, err := http.Get(srv.URL + "/tasks/stream-1/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Errorf("expected text/event-stream, got %q", resp.Header.Get("Content-Type"))
	}

	// Read first event (current status)
	buf := make([]byte, 4096)
	n, err := resp.Body.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	firstEvent := string(buf[:n])
	if !strings.Contains(firstEvent, "event: status") {
		t.Errorf("expected status event, got: %s", firstEvent)
	}

	// Let the task complete
	close(taskDone)
}

func TestNotFound(t *testing.T) {
	h := newTestHandler(t, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestInvalidRequestBody(t *testing.T) {
	h := newTestHandler(t, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/tasks/send", "application/json", bytes.NewReader([]byte("invalid")))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestExtractTaskID(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/tasks/abc-123", "abc-123"},
		{"/tasks/abc-123/", "abc-123"},
		{"/api/tasks/my-task", "my-task"},
		{"/tasks/", ""},
		{"/other/path", ""},
	}

	for _, tt := range tests {
		got := extractTaskID(tt.path)
		if got != tt.want {
			t.Errorf("extractTaskID(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestStreamTask_AlreadyCompleted(t *testing.T) {
	h := newTestHandler(t, nil)

	now := time.Now().UTC()
	h.tasks["completed-1"] = &Task{
		ID: "completed-1",
		Status: TaskStatus{
			State:     TaskStateCompleted,
			Timestamp: &now,
		},
	}

	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/tasks/completed-1/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Should get the status and close immediately
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "completed") {
		t.Errorf("expected completed status in SSE, got: %s", body)
	}
}

func TestUpdateTaskStatus(t *testing.T) {
	h := newTestHandler(t, nil)

	// Create a task
	now := time.Now().UTC()
	h.tasks["update-1"] = &Task{
		ID: "update-1",
		Status: TaskStatus{
			State:     TaskStateSubmitted,
			Timestamp: &now,
		},
	}

	// Update via public API
	err := h.UpdateTaskStatus("update-1", TaskStateWorking, nil)
	if err != nil {
		t.Fatal(err)
	}

	task, ok := h.GetTask("update-1")
	if !ok {
		t.Fatal("task not found")
	}
	if task.Status.State != TaskStateWorking {
		t.Errorf("expected working, got %q", task.Status.State)
	}

	// Update nonexistent
	err = h.UpdateTaskStatus("nonexistent", TaskStateWorking, nil)
	if err == nil {
		t.Error("expected error for nonexistent task")
	}
}

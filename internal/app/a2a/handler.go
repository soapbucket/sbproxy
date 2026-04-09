// Package a2a implements the Agent-to-Agent (A2A) protocol handler for standardized agent communication.
package a2a

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config defines the A2A handler configuration.
type Config struct {
	// AgentCard served at /.well-known/agent.json
	AgentCard AgentCard `json:"agent_card"`

	// TaskHandler processes incoming tasks. If nil, tasks return 501.
	TaskHandler TaskHandlerFunc `json:"-"`

	// TaskTimeout is the maximum time for a task to complete.
	TaskTimeout time.Duration `json:"task_timeout,omitempty"`
}

// TaskHandlerFunc processes a task and returns the updated task.
type TaskHandlerFunc func(task *Task) error

// Handler implements the A2A protocol as an http.Handler.
type Handler struct {
	config Config
	tasks  map[string]*Task
	mu     sync.RWMutex

	// SSE subscribers per task ID
	subscribers map[string][]chan []byte
	subMu       sync.RWMutex
}

// NewHandler creates a new A2A protocol handler.
func NewHandler(config *Config) (*Handler, error) {
	if config.AgentCard.Name == "" {
		return nil, fmt.Errorf("a2a: agent card name is required")
	}
	if config.AgentCard.URL == "" {
		config.AgentCard.URL = "/"
	}
	if config.TaskTimeout == 0 {
		config.TaskTimeout = 30 * time.Second
	}

	return &Handler{
		config:      *config,
		tasks:       make(map[string]*Task),
		subscribers: make(map[string][]chan []byte),
	}, nil
}

// ServeHTTP routes requests to the appropriate A2A endpoint.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(r.URL.Path, "/")

	switch {
	case path == "/.well-known/agent.json" && r.Method == http.MethodGet:
		h.handleAgentCard(w, r)
	case path == "/tasks/send" && r.Method == http.MethodPost:
		h.handleSendTask(w, r)
	case strings.HasSuffix(path, "/cancel") && r.Method == http.MethodPost:
		h.handleCancelTask(w, r)
	case strings.HasSuffix(path, "/stream") && r.Method == http.MethodGet:
		h.handleStreamTask(w, r)
	case strings.HasPrefix(path, "/tasks/") && r.Method == http.MethodGet:
		h.handleGetTask(w, r)
	default:
		writeError(w, http.StatusNotFound, "endpoint not found")
	}
}

// handleAgentCard serves the agent card at GET /.well-known/agent.json.
func (h *Handler) handleAgentCard(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.config.AgentCard)
}

// handleSendTask processes POST /tasks/send.
func (h *Handler) handleSendTask(w http.ResponseWriter, r *http.Request) {
	var req SendTaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.ID == "" {
		writeError(w, http.StatusBadRequest, "task id is required")
		return
	}

	now := time.Now().UTC()
	task := &Task{
		ID: req.ID,
		Status: TaskStatus{
			State:     TaskStateSubmitted,
			Timestamp: &now,
		},
		History:  []Message{req.Message},
		Metadata: req.Metadata,
	}

	h.mu.Lock()
	h.tasks[req.ID] = task
	h.mu.Unlock()

	// Process task asynchronously if handler is configured
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(task)

	// Process task asynchronously after responding to avoid racing response encoding.
	if h.config.TaskHandler != nil {
		go h.processTask(task)
	}
}

// handleGetTask processes GET /tasks/{id}.
func (h *Handler) handleGetTask(w http.ResponseWriter, r *http.Request) {
	taskID := extractTaskID(r.URL.Path)
	if taskID == "" {
		writeError(w, http.StatusBadRequest, "task id is required")
		return
	}

	h.mu.RLock()
	task, ok := h.tasks[taskID]
	h.mu.RUnlock()

	if !ok {
		writeError(w, http.StatusNotFound, "task not found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(task)
}

// handleCancelTask processes POST /tasks/{id}/cancel.
func (h *Handler) handleCancelTask(w http.ResponseWriter, r *http.Request) {
	// Strip /cancel suffix to get the task path
	path := strings.TrimSuffix(r.URL.Path, "/cancel")
	path = strings.TrimSuffix(path, "/")
	taskID := extractTaskID(path)
	if taskID == "" {
		writeError(w, http.StatusBadRequest, "task id is required")
		return
	}

	h.mu.Lock()
	task, ok := h.tasks[taskID]
	if !ok {
		h.mu.Unlock()
		writeError(w, http.StatusNotFound, "task not found")
		return
	}

	// Can only cancel tasks that are not yet completed/canceled/failed
	switch task.Status.State {
	case TaskStateCompleted, TaskStateCanceled, TaskStateFailed:
		h.mu.Unlock()
		writeError(w, http.StatusConflict, fmt.Sprintf("task is already %s", task.Status.State))
		return
	}

	now := time.Now().UTC()
	task.Status = TaskStatus{
		State:     TaskStateCanceled,
		Timestamp: &now,
	}
	h.mu.Unlock()

	// Notify SSE subscribers
	h.notifySubscribers(taskID, TaskStatusUpdate{
		ID:     taskID,
		Status: task.Status,
		Final:  true,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(task)
}

// handleStreamTask processes GET /tasks/{id}/stream via SSE.
func (h *Handler) handleStreamTask(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(r.URL.Path, "/stream")
	path = strings.TrimSuffix(path, "/")
	taskID := extractTaskID(path)
	if taskID == "" {
		writeError(w, http.StatusBadRequest, "task id is required")
		return
	}

	h.mu.RLock()
	task, ok := h.tasks[taskID]
	h.mu.RUnlock()

	if !ok {
		writeError(w, http.StatusNotFound, "task not found")
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	// Send current status immediately
	h.mu.RLock()
	currentStatus := task.Status
	h.mu.RUnlock()
	data, _ := json.Marshal(TaskStatusUpdate{
		ID:     taskID,
		Status: currentStatus,
	})
	fmt.Fprintf(w, "event: status\ndata: %s\n\n", data)
	flusher.Flush()

	// If task is already in a terminal state, close
	if isTerminalState(currentStatus.State) {
		return
	}

	// Subscribe for updates
	ch := make(chan []byte, 16)
	h.subMu.Lock()
	h.subscribers[taskID] = append(h.subscribers[taskID], ch)
	h.subMu.Unlock()

	defer func() {
		h.subMu.Lock()
		subs := h.subscribers[taskID]
		for i, s := range subs {
			if s == ch {
				h.subscribers[taskID] = append(subs[:i], subs[i+1:]...)
				break
			}
		}
		h.subMu.Unlock()
		close(ch)
	}()

	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "event: status\ndata: %s\n\n", msg)
			flusher.Flush()

			// Check if this was a terminal update
			var update TaskStatusUpdate
			if json.Unmarshal(msg, &update) == nil && update.Final {
				return
			}
		case <-r.Context().Done():
			return
		}
	}
}

// processTask runs the task handler and updates task status.
func (h *Handler) processTask(task *Task) {
	h.mu.Lock()
	now := time.Now().UTC()
	task.Status = TaskStatus{
		State:     TaskStateWorking,
		Timestamp: &now,
	}
	workingStatus := task.Status
	h.mu.Unlock()

	h.notifySubscribers(task.ID, TaskStatusUpdate{
		ID:     task.ID,
		Status: workingStatus,
	})

	err := h.config.TaskHandler(task)

	h.mu.Lock()
	now = time.Now().UTC()
	if err != nil {
		task.Status = TaskStatus{
			State: TaskStateFailed,
			Message: &Message{
				Role:  "agent",
				Parts: []Part{{Type: "text", Text: err.Error()}},
			},
			Timestamp: &now,
		}
	} else if task.Status.State == TaskStateWorking {
		// Only mark completed if handler didn't set a different state
		task.Status = TaskStatus{
			State:     TaskStateCompleted,
			Timestamp: &now,
		}
	}
	finalStatus := task.Status
	h.mu.Unlock()

	h.notifySubscribers(task.ID, TaskStatusUpdate{
		ID:     task.ID,
		Status: finalStatus,
		Final:  true,
	})
}

// notifySubscribers sends an update to all SSE subscribers for a task.
func (h *Handler) notifySubscribers(taskID string, update TaskStatusUpdate) {
	data, err := json.Marshal(update)
	if err != nil {
		return
	}

	h.subMu.RLock()
	subs := h.subscribers[taskID]
	h.subMu.RUnlock()

	for _, ch := range subs {
		select {
		case ch <- data:
		default:
			// Drop if subscriber is slow
		}
	}
}

// GetTask returns a task by ID for external inspection.
func (h *Handler) GetTask(id string) (*Task, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	task, ok := h.tasks[id]
	return task, ok
}

// UpdateTaskStatus allows external code to update a task's status.
func (h *Handler) UpdateTaskStatus(id string, state TaskState, message *Message) error {
	h.mu.Lock()
	task, ok := h.tasks[id]
	if !ok {
		h.mu.Unlock()
		return fmt.Errorf("task %s not found", id)
	}

	now := time.Now().UTC()
	task.Status = TaskStatus{
		State:     state,
		Timestamp: &now,
		Message:   message,
	}
	h.mu.Unlock()

	final := isTerminalState(state)
	h.notifySubscribers(id, TaskStatusUpdate{
		ID:     id,
		Status: task.Status,
		Final:  final,
	})

	return nil
}

// extractTaskID extracts the task ID from a path like /tasks/{id}.
func extractTaskID(path string) string {
	path = strings.TrimSuffix(path, "/")
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if p == "tasks" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func isTerminalState(state TaskState) bool {
	return state == TaskStateCompleted || state == TaskStateCanceled || state == TaskStateFailed
}

func writeError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(ErrorResponse{
		Code:    code,
		Message: message,
	})
}

package ai

import (
	json "github.com/goccy/go-json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Thread represents an OpenAI-compatible thread object.
type Thread struct {
	ID        string            `json:"id"`
	Object    string            `json:"object"`
	CreatedAt int64             `json:"created_at"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// ThreadMessage represents a message within a thread.
type ThreadMessage struct {
	ID        string            `json:"id"`
	Object    string            `json:"object"`
	ThreadID  string            `json:"thread_id"`
	Role      string            `json:"role"`
	Content   []ContentBlock    `json:"content"`
	CreatedAt int64             `json:"created_at"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// ContentBlock is a single content element in a message.
type ContentBlock struct {
	Type string       `json:"type"`
	Text *TextContent `json:"text,omitempty"`
}

// TextContent holds text content and optional annotations.
type TextContent struct {
	Value       string `json:"value"`
	Annotations []any  `json:"annotations"`
}

// Run represents an assistant run on a thread.
type Run struct {
	ID           string    `json:"id"`
	Object       string    `json:"object"`
	ThreadID     string    `json:"thread_id"`
	AssistantID  string    `json:"assistant_id"`
	Status       string    `json:"status"`
	Model        string    `json:"model"`
	Instructions string    `json:"instructions,omitempty"`
	CreatedAt    int64     `json:"created_at"`
	StartedAt    int64     `json:"started_at,omitempty"`
	CompletedAt  int64     `json:"completed_at,omitempty"`
	FailedAt     int64     `json:"failed_at,omitempty"`
	Usage        *RunUsage `json:"usage,omitempty"`
}

// RunUsage tracks token usage for a run.
type RunUsage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}

// ThreadHandler handles HTTP requests for the threads API.
type ThreadHandler struct {
	store      ThreadStore
	assistants AssistantStore
}

// NewThreadHandler creates a new ThreadHandler.
func NewThreadHandler(store ThreadStore, assistants AssistantStore) *ThreadHandler {
	return &ThreadHandler{store: store, assistants: assistants}
}

// ServeHTTP routes thread requests to the appropriate handler.
func (h *ThreadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Strip /v1/threads prefix and trailing slash.
	path := strings.TrimPrefix(r.URL.Path, "/v1/threads")
	path = strings.TrimSuffix(path, "/")

	// POST /v1/threads - create thread
	if path == "" && r.Method == http.MethodPost {
		h.CreateThread(w, r)
		return
	}

	// Parse path segments: /{threadID}, /{threadID}/messages, /{threadID}/runs, /{threadID}/runs/{runID}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")

	if len(parts) == 1 {
		threadID := parts[0]
		switch r.Method {
		case http.MethodGet:
			h.GetThread(w, r, threadID)
		case http.MethodDelete:
			h.DeleteThread(w, r, threadID)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
		return
	}

	if len(parts) == 2 {
		threadID := parts[0]
		sub := parts[1]
		switch sub {
		case "messages":
			switch r.Method {
			case http.MethodPost:
				h.CreateMessage(w, r, threadID)
			case http.MethodGet:
				h.ListMessages(w, r, threadID)
			default:
				writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			}
		case "runs":
			switch r.Method {
			case http.MethodPost:
				h.CreateRun(w, r, threadID)
			case http.MethodGet:
				h.ListRuns(w, r, threadID)
			default:
				writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			}
		default:
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
		return
	}

	if len(parts) == 3 && parts[1] == "runs" {
		threadID := parts[0]
		runID := parts[2]
		if r.Method == http.MethodGet {
			h.GetRun(w, r, threadID, runID)
			return
		}
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
}

// CreateThread handles POST /v1/threads.
func (h *ThreadHandler) CreateThread(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Metadata map[string]string `json:"metadata"`
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}
	// Allow empty body for thread creation.
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
	}

	threadID, err := generateID("thread_")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate ID"})
		return
	}
	t := &Thread{
		ID:        threadID,
		Object:    "thread",
		CreatedAt: time.Now().Unix(),
		Metadata:  req.Metadata,
	}
	if err := h.store.CreateThread(r.Context(), t); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// GetThread handles GET /v1/threads/{id}.
func (h *ThreadHandler) GetThread(w http.ResponseWriter, r *http.Request, threadID string) {
	t, err := h.store.GetThread(r.Context(), threadID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// DeleteThread handles DELETE /v1/threads/{id}.
func (h *ThreadHandler) DeleteThread(w http.ResponseWriter, r *http.Request, threadID string) {
	if err := h.store.DeleteThread(r.Context(), threadID); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      threadID,
		"object":  "thread.deleted",
		"deleted": true,
	})
}

// CreateMessage handles POST /v1/threads/{id}/messages.
func (h *ThreadHandler) CreateMessage(w http.ResponseWriter, r *http.Request, threadID string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}
	var req struct {
		Role     string            `json:"role"`
		Content  string            `json:"content"`
		Metadata map[string]string `json:"metadata"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Role == "" || req.Content == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "role and content are required"})
		return
	}

	msgID, err := generateID("msg_")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate ID"})
		return
	}
	msg := &ThreadMessage{
		ID:       msgID,
		Object:   "thread.message",
		ThreadID: threadID,
		Role:     req.Role,
		Content: []ContentBlock{
			{
				Type: "text",
				Text: &TextContent{
					Value:       req.Content,
					Annotations: []any{},
				},
			},
		},
		CreatedAt: time.Now().Unix(),
		Metadata:  req.Metadata,
	}

	if err := h.store.AddMessage(r.Context(), threadID, msg); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, msg)
}

// ListMessages handles GET /v1/threads/{id}/messages.
func (h *ThreadHandler) ListMessages(w http.ResponseWriter, r *http.Request, threadID string) {
	limit := 20
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	msgs, err := h.store.ListMessages(r.Context(), threadID, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object": "list",
		"data":   msgs,
	})
}

// CreateRun handles POST /v1/threads/{id}/runs.
func (h *ThreadHandler) CreateRun(w http.ResponseWriter, r *http.Request, threadID string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}
	var req struct {
		AssistantID  string `json:"assistant_id"`
		Model        string `json:"model"`
		Instructions string `json:"instructions"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.AssistantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "assistant_id is required"})
		return
	}

	// Verify assistant exists.
	asst, err := h.assistants.Get(r.Context(), req.AssistantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "assistant not found"})
		return
	}

	model := req.Model
	if model == "" {
		model = asst.Model
	}
	instructions := req.Instructions
	if instructions == "" {
		instructions = asst.Instructions
	}

	runID, err := generateID("run_")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate ID"})
		return
	}
	run := &Run{
		ID:           runID,
		Object:       "thread.run",
		ThreadID:     threadID,
		AssistantID:  req.AssistantID,
		Status:       "queued",
		Model:        model,
		Instructions: instructions,
		CreatedAt:    time.Now().Unix(),
	}

	if err := h.store.CreateRun(r.Context(), threadID, run); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// GetRun handles GET /v1/threads/{id}/runs/{run_id}.
func (h *ThreadHandler) GetRun(w http.ResponseWriter, r *http.Request, threadID, runID string) {
	run, err := h.store.GetRun(r.Context(), threadID, runID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// ListRuns handles GET /v1/threads/{id}/runs.
func (h *ThreadHandler) ListRuns(w http.ResponseWriter, r *http.Request, threadID string) {
	limit := 20
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	runs, err := h.store.ListRuns(r.Context(), threadID, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object": "list",
		"data":   runs,
	})
}

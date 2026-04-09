package ai

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	json "github.com/goccy/go-json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Assistant represents an OpenAI-compatible assistant object.
type Assistant struct {
	ID           string            `json:"id"`
	Object       string            `json:"object"`
	Name         string            `json:"name"`
	Description  string            `json:"description,omitempty"`
	Model        string            `json:"model"`
	Instructions string            `json:"instructions,omitempty"`
	Tools        []AssistantTool   `json:"tools"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	CreatedAt    int64             `json:"created_at"`
}

// AssistantTool describes a tool available to an assistant.
type AssistantTool struct {
	Type     string       `json:"type"`
	Function *FunctionDef `json:"function,omitempty"`
}

// FunctionDef describes a function tool definition.
type FunctionDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

// AssistantStore defines CRUD operations for assistants.
type AssistantStore interface {
	Create(ctx context.Context, a *Assistant) error
	Get(ctx context.Context, id string) (*Assistant, error)
	List(ctx context.Context, workspaceID string, limit, offset int) ([]*Assistant, error)
	Update(ctx context.Context, id string, updates map[string]any) (*Assistant, error)
	Delete(ctx context.Context, id string) error
}

// MemoryAssistantStore is an in-memory implementation of AssistantStore.
type MemoryAssistantStore struct {
	mu    sync.RWMutex
	items map[string]*Assistant
	order []string // maintains insertion order for listing
}

// NewMemoryAssistantStore creates a new in-memory assistant store.
func NewMemoryAssistantStore() *MemoryAssistantStore {
	return &MemoryAssistantStore{
		items: make(map[string]*Assistant),
	}
}

func (s *MemoryAssistantStore) Create(_ context.Context, a *Assistant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.items[a.ID]; exists {
		return fmt.Errorf("assistant %s already exists", a.ID)
	}
	s.items[a.ID] = a
	s.order = append(s.order, a.ID)
	return nil
}

func (s *MemoryAssistantStore) Get(_ context.Context, id string) (*Assistant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.items[id]
	if !ok {
		return nil, fmt.Errorf("assistant %s not found", id)
	}
	return a, nil
}

func (s *MemoryAssistantStore) List(_ context.Context, _ string, limit, offset int) ([]*Assistant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total := len(s.order)
	if offset >= total {
		return []*Assistant{}, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	result := make([]*Assistant, 0, end-offset)
	for _, id := range s.order[offset:end] {
		if a, ok := s.items[id]; ok {
			result = append(result, a)
		}
	}
	return result, nil
}

func (s *MemoryAssistantStore) Update(_ context.Context, id string, updates map[string]any) (*Assistant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.items[id]
	if !ok {
		return nil, fmt.Errorf("assistant %s not found", id)
	}
	if v, ok := updates["name"]; ok {
		if s, ok := v.(string); ok {
			a.Name = s
		}
	}
	if v, ok := updates["description"]; ok {
		if s, ok := v.(string); ok {
			a.Description = s
		}
	}
	if v, ok := updates["model"]; ok {
		if s, ok := v.(string); ok {
			a.Model = s
		}
	}
	if v, ok := updates["instructions"]; ok {
		if s, ok := v.(string); ok {
			a.Instructions = s
		}
	}
	if v, ok := updates["metadata"]; ok {
		if m, ok := v.(map[string]string); ok {
			a.Metadata = m
		}
	}
	if v, ok := updates["tools"]; ok {
		if t, ok := v.([]AssistantTool); ok {
			a.Tools = t
		}
	}
	return a, nil
}

func (s *MemoryAssistantStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[id]; !ok {
		return fmt.Errorf("assistant %s not found", id)
	}
	delete(s.items, id)
	for i, oid := range s.order {
		if oid == id {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
	return nil
}

// generateID creates a random ID with the given prefix (e.g. "asst_", "thread_").
func generateID(prefix string) (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand failed: %w", err)
	}
	return prefix + hex.EncodeToString(b), nil
}

// AssistantHandler handles HTTP requests for the assistants API.
type AssistantHandler struct {
	store AssistantStore
}

// NewAssistantHandler creates a new AssistantHandler.
func NewAssistantHandler(store AssistantStore) *AssistantHandler {
	return &AssistantHandler{store: store}
}

// ServeHTTP routes assistant requests to the appropriate handler.
func (h *AssistantHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/assistants")
	path = strings.TrimSuffix(path, "/")

	switch {
	case path == "" && r.Method == http.MethodPost:
		h.CreateAssistant(w, r)
	case path == "" && r.Method == http.MethodGet:
		h.ListAssistants(w, r)
	case path != "" && r.Method == http.MethodGet:
		h.GetAssistant(w, r)
	case path != "" && r.Method == http.MethodPost:
		h.UpdateAssistant(w, r)
	case path != "" && r.Method == http.MethodDelete:
		h.DeleteAssistant(w, r)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// CreateAssistant handles POST /v1/assistants.
func (h *AssistantHandler) CreateAssistant(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}

	var req struct {
		Name         string            `json:"name"`
		Description  string            `json:"description"`
		Model        string            `json:"model"`
		Instructions string            `json:"instructions"`
		Tools        []AssistantTool   `json:"tools"`
		Metadata     map[string]string `json:"metadata"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Model == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "model is required"})
		return
	}

	id, err := generateID("asst_")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate ID"})
		return
	}
	a := &Assistant{
		ID:           id,
		Object:       "assistant",
		Name:         req.Name,
		Description:  req.Description,
		Model:        req.Model,
		Instructions: req.Instructions,
		Tools:        req.Tools,
		Metadata:     req.Metadata,
		CreatedAt:    time.Now().Unix(),
	}
	if a.Tools == nil {
		a.Tools = []AssistantTool{}
	}

	if err := h.store.Create(r.Context(), a); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, a)
}

// GetAssistant handles GET /v1/assistants/{id}.
func (h *AssistantHandler) GetAssistant(w http.ResponseWriter, r *http.Request) {
	id := extractAssistantID(r.URL.Path)
	a, err := h.store.Get(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, a)
}

// ListAssistants handles GET /v1/assistants.
func (h *AssistantHandler) ListAssistants(w http.ResponseWriter, r *http.Request) {
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
	workspaceID := r.URL.Query().Get("workspace_id")
	items, err := h.store.List(r.Context(), workspaceID, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object": "list",
		"data":   items,
	})
}

// UpdateAssistant handles POST /v1/assistants/{id}.
func (h *AssistantHandler) UpdateAssistant(w http.ResponseWriter, r *http.Request) {
	id := extractAssistantID(r.URL.Path)
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	a, err := h.store.Update(r.Context(), id, raw)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, a)
}

// DeleteAssistant handles DELETE /v1/assistants/{id}.
func (h *AssistantHandler) DeleteAssistant(w http.ResponseWriter, r *http.Request) {
	id := extractAssistantID(r.URL.Path)
	if err := h.store.Delete(r.Context(), id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      id,
		"object":  "assistant.deleted",
		"deleted": true,
	})
}

func extractAssistantID(path string) string {
	path = strings.TrimPrefix(path, "/v1/assistants/")
	if idx := strings.Index(path, "/"); idx != -1 {
		path = path[:idx]
	}
	return path
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

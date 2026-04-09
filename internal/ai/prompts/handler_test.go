package prompts

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	json "github.com/goccy/go-json"
)

func setupPromptHandler() *PromptHandler {
	return NewPromptHandler(NewMemoryPromptStore())
}

func doPromptRequest(h *PromptHandler, method, path string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestPromptHandler_CreateAndGet(t *testing.T) {
	h := setupPromptHandler()

	// Create a prompt template.
	w := doPromptRequest(h, http.MethodPost, "/v1/prompts", map[string]any{
		"id":           "tmpl-1",
		"workspace_id": "ws-1",
		"name":         "Greeting",
		"messages": []map[string]any{
			{"role": "system", "content": "You are helpful."},
			{"role": "user", "content": "Hello {{name}}"},
		},
		"variables": []map[string]any{
			{"name": "name", "required": true},
		},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("Create status = %d, want %d, body: %s", w.Code, http.StatusCreated, w.Body.String())
	}

	var created PromptTemplate
	json.NewDecoder(w.Body).Decode(&created)
	if created.ID != "tmpl-1" {
		t.Errorf("ID = %q, want %q", created.ID, "tmpl-1")
	}
	if created.Version != 1 {
		t.Errorf("Version = %d, want 1", created.Version)
	}

	// Get it.
	w = doPromptRequest(h, http.MethodGet, "/v1/prompts/tmpl-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("Get status = %d, body: %s", w.Code, w.Body.String())
	}

	var got PromptTemplate
	json.NewDecoder(w.Body).Decode(&got)
	if got.Name != "Greeting" {
		t.Errorf("Name = %q, want %q", got.Name, "Greeting")
	}
	if len(got.Messages) != 2 {
		t.Errorf("Messages length = %d, want 2", len(got.Messages))
	}
}

func TestPromptHandler_List(t *testing.T) {
	h := setupPromptHandler()

	doPromptRequest(h, http.MethodPost, "/v1/prompts", map[string]any{
		"id": "a", "workspace_id": "ws-1", "name": "Alpha",
		"messages": []map[string]any{{"role": "user", "content": "a"}},
	})
	doPromptRequest(h, http.MethodPost, "/v1/prompts", map[string]any{
		"id": "b", "workspace_id": "ws-1", "name": "Beta",
		"messages": []map[string]any{{"role": "user", "content": "b"}},
	})
	doPromptRequest(h, http.MethodPost, "/v1/prompts", map[string]any{
		"id": "c", "workspace_id": "ws-2", "name": "Charlie",
		"messages": []map[string]any{{"role": "user", "content": "c"}},
	})

	// List all.
	w := doPromptRequest(h, http.MethodGet, "/v1/prompts", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("List status = %d", w.Code)
	}
	var list []*PromptTemplate
	json.NewDecoder(w.Body).Decode(&list)
	if len(list) != 3 {
		t.Errorf("list length = %d, want 3", len(list))
	}

	// List by workspace.
	w = doPromptRequest(h, http.MethodGet, "/v1/prompts?workspace_id=ws-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("List ws-1 status = %d", w.Code)
	}
	json.NewDecoder(w.Body).Decode(&list)
	if len(list) != 2 {
		t.Errorf("ws-1 list length = %d, want 2", len(list))
	}

	// List with pagination.
	w = doPromptRequest(h, http.MethodGet, "/v1/prompts?workspace_id=ws-1&limit=1&offset=0", nil)
	json.NewDecoder(w.Body).Decode(&list)
	if len(list) != 1 {
		t.Errorf("paginated list length = %d, want 1", len(list))
	}
}

func TestPromptHandler_Update(t *testing.T) {
	h := setupPromptHandler()

	doPromptRequest(h, http.MethodPost, "/v1/prompts", map[string]any{
		"id": "upd", "workspace_id": "ws-1", "name": "Original",
		"messages": []map[string]any{{"role": "user", "content": "v1"}},
	})

	// Update (PUT creates a new version).
	w := doPromptRequest(h, http.MethodPut, "/v1/prompts/upd", map[string]any{
		"name":     "Updated",
		"messages": []map[string]any{{"role": "user", "content": "v2"}},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("Update status = %d, body: %s", w.Code, w.Body.String())
	}

	var updated PromptTemplate
	json.NewDecoder(w.Body).Decode(&updated)
	if updated.Version != 2 {
		t.Errorf("Version = %d, want 2", updated.Version)
	}
	if updated.Name != "Updated" {
		t.Errorf("Name = %q, want %q", updated.Name, "Updated")
	}
}

func TestPromptHandler_Delete(t *testing.T) {
	h := setupPromptHandler()

	doPromptRequest(h, http.MethodPost, "/v1/prompts", map[string]any{
		"id": "del", "workspace_id": "ws-1", "name": "Delete",
		"messages": []map[string]any{{"role": "user", "content": "bye"}},
	})

	w := doPromptRequest(h, http.MethodDelete, "/v1/prompts/del", nil)
	if w.Code != http.StatusNoContent {
		t.Errorf("Delete status = %d, want %d", w.Code, http.StatusNoContent)
	}

	w = doPromptRequest(h, http.MethodGet, "/v1/prompts/del", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("Get after delete status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestPromptHandler_Versions(t *testing.T) {
	h := setupPromptHandler()

	doPromptRequest(h, http.MethodPost, "/v1/prompts", map[string]any{
		"id": "ver", "workspace_id": "ws-1", "name": "Versioned",
		"messages": []map[string]any{{"role": "user", "content": "v1"}},
	})
	doPromptRequest(h, http.MethodPut, "/v1/prompts/ver", map[string]any{
		"messages": []map[string]any{{"role": "user", "content": "v2"}},
	})

	// List versions.
	w := doPromptRequest(h, http.MethodGet, "/v1/prompts/ver/versions", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("ListVersions status = %d, body: %s", w.Code, w.Body.String())
	}
	var versions []*PromptVersion
	json.NewDecoder(w.Body).Decode(&versions)
	if len(versions) != 2 {
		t.Errorf("versions length = %d, want 2", len(versions))
	}

	// Get specific version.
	w = doPromptRequest(h, http.MethodGet, "/v1/prompts/ver/versions/1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GetVersion status = %d, body: %s", w.Code, w.Body.String())
	}
	var v1 PromptTemplate
	json.NewDecoder(w.Body).Decode(&v1)
	if v1.Messages[0].Content != "v1" {
		t.Errorf("v1 content = %q, want %q", v1.Messages[0].Content, "v1")
	}
}

func TestPromptHandler_Rollback(t *testing.T) {
	h := setupPromptHandler()

	doPromptRequest(h, http.MethodPost, "/v1/prompts", map[string]any{
		"id": "rb", "workspace_id": "ws-1", "name": "Rollback",
		"messages": []map[string]any{{"role": "user", "content": "original"}},
	})
	doPromptRequest(h, http.MethodPut, "/v1/prompts/rb", map[string]any{
		"messages": []map[string]any{{"role": "user", "content": "changed"}},
	})

	w := doPromptRequest(h, http.MethodPost, "/v1/prompts/rb/rollback", map[string]any{
		"version": 1,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("Rollback status = %d, body: %s", w.Code, w.Body.String())
	}

	var rolled PromptTemplate
	json.NewDecoder(w.Body).Decode(&rolled)
	if rolled.Version != 3 {
		t.Errorf("Version = %d, want 3", rolled.Version)
	}
	if rolled.Messages[0].Content != "original" {
		t.Errorf("Content = %q, want %q", rolled.Messages[0].Content, "original")
	}
}

func TestPromptHandler_Labels(t *testing.T) {
	h := setupPromptHandler()

	doPromptRequest(h, http.MethodPost, "/v1/prompts", map[string]any{
		"id": "lb", "workspace_id": "ws-1", "name": "Labeled",
		"messages": []map[string]any{{"role": "user", "content": "v1"}},
	})
	doPromptRequest(h, http.MethodPut, "/v1/prompts/lb", map[string]any{
		"messages": []map[string]any{{"role": "user", "content": "v2"}},
	})

	w := doPromptRequest(h, http.MethodPost, "/v1/prompts/lb/labels", map[string]any{
		"label":   "production",
		"version": 1,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("SetLabel status = %d, body: %s", w.Code, w.Body.String())
	}

	var labeled PromptTemplate
	json.NewDecoder(w.Body).Decode(&labeled)
	if labeled.Labels["production"] != "1" {
		t.Errorf("production label = %q, want %q", labeled.Labels["production"], "1")
	}
}

func TestPromptHandler_Render(t *testing.T) {
	h := setupPromptHandler()

	doPromptRequest(h, http.MethodPost, "/v1/prompts", map[string]any{
		"id":           "rnd",
		"workspace_id": "ws-1",
		"name":         "Renderable",
		"messages": []map[string]any{
			{"role": "system", "content": "You are a {{role}}."},
			{"role": "user", "content": "Hello {{name}}, tell me about {{topic}}."},
		},
		"variables": []map[string]any{
			{"name": "role", "required": true},
			{"name": "name", "required": true},
			{"name": "topic", "required": false, "default": "the weather"},
		},
	})

	// Render with all variables.
	w := doPromptRequest(h, http.MethodPost, "/v1/prompts/rnd/render", map[string]any{
		"variables": map[string]string{
			"role":  "teacher",
			"name":  "Alice",
			"topic": "math",
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("Render status = %d, body: %s", w.Code, w.Body.String())
	}

	var result struct {
		Messages []RenderedMessage `json:"messages"`
		Template *PromptTemplate   `json:"template"`
	}
	json.NewDecoder(w.Body).Decode(&result)
	if len(result.Messages) != 2 {
		t.Fatalf("messages length = %d, want 2", len(result.Messages))
	}
	if result.Messages[0].Content != "You are a teacher." {
		t.Errorf("system content = %q", result.Messages[0].Content)
	}
	if result.Messages[1].Content != "Hello Alice, tell me about math." {
		t.Errorf("user content = %q", result.Messages[1].Content)
	}

	// Render with default variable.
	w = doPromptRequest(h, http.MethodPost, "/v1/prompts/rnd/render", map[string]any{
		"variables": map[string]string{
			"role": "guide",
			"name": "Bob",
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("Render with defaults status = %d, body: %s", w.Code, w.Body.String())
	}
	json.NewDecoder(w.Body).Decode(&result)
	if result.Messages[1].Content != "Hello Bob, tell me about the weather." {
		t.Errorf("user content with default = %q", result.Messages[1].Content)
	}

	// Render with missing required variable.
	w = doPromptRequest(h, http.MethodPost, "/v1/prompts/rnd/render", map[string]any{
		"variables": map[string]string{"name": "Charlie"},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing required render status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestPromptHandler_Validation(t *testing.T) {
	h := setupPromptHandler()

	tests := []struct {
		name       string
		body       map[string]any
		wantStatus int
	}{
		{
			name:       "missing id",
			body:       map[string]any{"name": "Test"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing name",
			body:       map[string]any{"id": "test"},
			wantStatus: http.StatusBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := doPromptRequest(h, http.MethodPost, "/v1/prompts", tt.body)
			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}

func TestPromptHandler_NotFound(t *testing.T) {
	h := setupPromptHandler()

	tests := []struct {
		name   string
		method string
		path   string
		body   any
	}{
		{name: "get missing", method: http.MethodGet, path: "/v1/prompts/missing"},
		{name: "update missing", method: http.MethodPut, path: "/v1/prompts/missing", body: map[string]any{"name": "X"}},
		{name: "delete missing", method: http.MethodDelete, path: "/v1/prompts/missing"},
		{name: "versions missing", method: http.MethodGet, path: "/v1/prompts/missing/versions"},
		{name: "rollback missing", method: http.MethodPost, path: "/v1/prompts/missing/rollback", body: map[string]any{"version": 1}},
		{name: "label missing", method: http.MethodPost, path: "/v1/prompts/missing/labels", body: map[string]any{"label": "prod", "version": 1}},
		{name: "render missing", method: http.MethodPost, path: "/v1/prompts/missing/render", body: map[string]any{"variables": map[string]string{}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := doPromptRequest(h, tt.method, tt.path, tt.body)
			if w.Code != http.StatusNotFound {
				t.Errorf("status = %d, want %d, body: %s", w.Code, http.StatusNotFound, w.Body.String())
			}
		})
	}
}

func TestPromptHandler_MethodNotAllowed(t *testing.T) {
	h := setupPromptHandler()
	w := doPromptRequest(h, http.MethodPatch, "/v1/prompts", nil)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

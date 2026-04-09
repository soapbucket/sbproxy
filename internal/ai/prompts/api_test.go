package prompts

import (
	"bytes"
	json "github.com/goccy/go-json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func setupHandler() *Handler {
	return NewHandler(NewMemoryStore())
}

func doRequest(h *Handler, method, path string, body any) *httptest.ResponseRecorder {
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

func TestAPI_CreateAndList(t *testing.T) {
	h := setupHandler()

	// Create a prompt.
	w := doRequest(h, http.MethodPost, "/v1/prompts", map[string]any{
		"id":   "test-1",
		"name": "Test One",
		"versions": []map[string]any{
			{"version": 1, "template": "Hello {{name}}"},
		},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("Create status = %d, want %d, body: %s", w.Code, http.StatusCreated, w.Body.String())
	}

	var created Prompt
	json.NewDecoder(w.Body).Decode(&created)
	if created.ID != "test-1" {
		t.Errorf("created ID = %q", created.ID)
	}
	if created.ActiveVersion != 1 {
		t.Errorf("created ActiveVersion = %d, want 1", created.ActiveVersion)
	}

	// List prompts.
	w = doRequest(h, http.MethodGet, "/v1/prompts", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("List status = %d", w.Code)
	}
	var list []*Prompt
	json.NewDecoder(w.Body).Decode(&list)
	if len(list) != 1 {
		t.Errorf("list length = %d, want 1", len(list))
	}
}

func TestAPI_GetPrompt(t *testing.T) {
	h := setupHandler()

	doRequest(h, http.MethodPost, "/v1/prompts", map[string]any{
		"id": "get-1", "name": "Get Test",
		"versions": []map[string]any{{"version": 1, "template": "tmpl"}},
	})

	w := doRequest(h, http.MethodGet, "/v1/prompts/get-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("Get status = %d, body: %s", w.Code, w.Body.String())
	}

	// Not found.
	w = doRequest(h, http.MethodGet, "/v1/prompts/missing", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("Get missing status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestAPI_CreateDuplicate(t *testing.T) {
	h := setupHandler()

	doRequest(h, http.MethodPost, "/v1/prompts", map[string]any{
		"id": "dup", "name": "Dup",
	})
	w := doRequest(h, http.MethodPost, "/v1/prompts", map[string]any{
		"id": "dup", "name": "Dup2",
	})
	if w.Code != http.StatusConflict {
		t.Errorf("duplicate create status = %d, want %d", w.Code, http.StatusConflict)
	}
}

func TestAPI_CreateValidation(t *testing.T) {
	h := setupHandler()

	// Missing ID.
	w := doRequest(h, http.MethodPost, "/v1/prompts", map[string]any{
		"name": "No ID",
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing id status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	// Missing name.
	w = doRequest(h, http.MethodPost, "/v1/prompts", map[string]any{
		"id": "no-name",
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing name status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestAPI_AddVersion(t *testing.T) {
	h := setupHandler()

	doRequest(h, http.MethodPost, "/v1/prompts", map[string]any{
		"id": "av", "name": "Add Version",
		"versions": []map[string]any{{"version": 1, "template": "v1"}},
	})

	w := doRequest(h, http.MethodPost, "/v1/prompts/av/versions", map[string]any{
		"version": 2, "template": "v2", "model": "gpt-4",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("AddVersion status = %d, body: %s", w.Code, w.Body.String())
	}

	var p Prompt
	json.NewDecoder(w.Body).Decode(&p)
	if len(p.Versions) != 2 {
		t.Errorf("versions length = %d, want 2", len(p.Versions))
	}

	// Version 0 should fail validation.
	w = doRequest(h, http.MethodPost, "/v1/prompts/av/versions", map[string]any{
		"version": 0, "template": "bad",
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("version 0 status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	// Missing prompt should fail.
	w = doRequest(h, http.MethodPost, "/v1/prompts/missing/versions", map[string]any{
		"version": 1, "template": "x",
	})
	if w.Code != http.StatusNotFound {
		t.Errorf("missing prompt status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestAPI_UpdateActiveVersion(t *testing.T) {
	h := setupHandler()

	doRequest(h, http.MethodPost, "/v1/prompts", map[string]any{
		"id": "uav", "name": "Update Active",
		"versions": []map[string]any{
			{"version": 1, "template": "v1"},
			{"version": 2, "template": "v2"},
		},
	})

	w := doRequest(h, http.MethodPatch, "/v1/prompts/uav", map[string]any{
		"active_version": 2,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("Patch status = %d, body: %s", w.Code, w.Body.String())
	}

	var p Prompt
	json.NewDecoder(w.Body).Decode(&p)
	if p.ActiveVersion != 2 {
		t.Errorf("ActiveVersion = %d, want 2", p.ActiveVersion)
	}

	// Non-existent version.
	w = doRequest(h, http.MethodPatch, "/v1/prompts/uav", map[string]any{
		"active_version": 99,
	})
	if w.Code != http.StatusNotFound {
		t.Errorf("bad version status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestAPI_Delete(t *testing.T) {
	h := setupHandler()

	doRequest(h, http.MethodPost, "/v1/prompts", map[string]any{
		"id": "del", "name": "Delete Me",
	})

	w := doRequest(h, http.MethodDelete, "/v1/prompts/del", nil)
	if w.Code != http.StatusNoContent {
		t.Errorf("Delete status = %d, want %d", w.Code, http.StatusNoContent)
	}

	// Verify gone.
	w = doRequest(h, http.MethodGet, "/v1/prompts/del", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("Get after delete status = %d, want %d", w.Code, http.StatusNotFound)
	}

	// Delete non-existent.
	w = doRequest(h, http.MethodDelete, "/v1/prompts/del", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("Delete missing status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestAPI_MethodNotAllowed(t *testing.T) {
	h := setupHandler()

	w := doRequest(h, http.MethodPut, "/v1/prompts", nil)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

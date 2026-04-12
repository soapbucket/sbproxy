// api.go provides HTTP handlers for the prompt management REST API.
package prompts

import (
	"context"
	json "github.com/goccy/go-json"
	"net/http"
	"strings"
)

// Handler provides HTTP handlers for prompt management.
type Handler struct {
	store Store
}

// NewHandler creates a new prompt API handler.
func NewHandler(store Store) *Handler {
	return &Handler{store: store}
}

// ServeHTTP routes prompt management requests.
//
// Routes:
//
//	GET    /v1/prompts           - List all prompts
//	POST   /v1/prompts           - Create a new prompt
//	GET    /v1/prompts/:id       - Get prompt with all versions
//	POST   /v1/prompts/:id/versions - Add a new version
//	PATCH  /v1/prompts/:id       - Update active version
//	DELETE /v1/prompts/:id       - Delete prompt
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/prompts")
	rest = strings.TrimPrefix(rest, "/")

	switch {
	case rest == "" && r.Method == http.MethodGet:
		h.listPrompts(w, r)
	case rest == "" && r.Method == http.MethodPost:
		h.createPrompt(w, r)
	case r.Method == http.MethodGet && !strings.Contains(rest, "/"):
		h.getPrompt(w, r, rest)
	case r.Method == http.MethodPatch && !strings.Contains(rest, "/"):
		h.updatePrompt(w, r, rest)
	case r.Method == http.MethodDelete && !strings.Contains(rest, "/"):
		h.deletePrompt(w, r, rest)
	case r.Method == http.MethodPost && strings.HasSuffix(rest, "/versions"):
		id := strings.TrimSuffix(rest, "/versions")
		h.addVersion(w, r, id)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (h *Handler) listPrompts(w http.ResponseWriter, r *http.Request) {
	list, err := h.store.List(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (h *Handler) createPrompt(w http.ResponseWriter, r *http.Request) {
	var p Prompt
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if p.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id is required"})
		return
	}
	if p.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	if err := h.store.Create(r.Context(), &p); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// Re-read to get timestamps set by store.
	created, err := h.store.Get(r.Context(), p.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (h *Handler) getPrompt(w http.ResponseWriter, r *http.Request, id string) {
	p, err := h.store.Get(r.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, p)
}

type updateActiveVersionRequest struct {
	ActiveVersion int `json:"active_version"`
}

func (h *Handler) updatePrompt(w http.ResponseWriter, r *http.Request, id string) {
	var req updateActiveVersionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if err := h.store.SetActiveVersion(r.Context(), id, req.ActiveVersion); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	p, err := h.store.Get(context.Background(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (h *Handler) deletePrompt(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.store.Delete(r.Context(), id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) addVersion(w http.ResponseWriter, r *http.Request, id string) {
	var v LegacyVersion
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if v.Version == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "version number is required"})
		return
	}
	if err := h.store.AddVersion(r.Context(), id, &v); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		if strings.Contains(err.Error(), "already exists") {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	p, err := h.store.Get(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

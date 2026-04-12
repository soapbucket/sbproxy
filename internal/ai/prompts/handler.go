// handler.go provides HTTP handlers for prompt template CRUD and rendering.
package prompts

import (
	"net/http"
	"strconv"
	"strings"

	json "github.com/goccy/go-json"
)

// PromptHandler provides HTTP handlers for prompt template management.
type PromptHandler struct {
	store    PromptStore
	renderer *TemplateRenderer
}

// NewPromptHandler creates a new PromptHandler.
func NewPromptHandler(store PromptStore) *PromptHandler {
	return &PromptHandler{
		store:    store,
		renderer: NewTemplateRenderer(),
	}
}

// ServeHTTP routes prompt management requests.
//
// Routes:
//
//	POST   /v1/prompts                        - Create prompt template
//	GET    /v1/prompts                        - List prompts (query: workspace_id, limit, offset)
//	GET    /v1/prompts/{id}                   - Get prompt
//	PUT    /v1/prompts/{id}                   - Update prompt (creates new version)
//	DELETE /v1/prompts/{id}                   - Delete prompt
//	GET    /v1/prompts/{id}/versions          - List versions
//	GET    /v1/prompts/{id}/versions/{version} - Get specific version
//	POST   /v1/prompts/{id}/rollback          - Rollback to version
//	POST   /v1/prompts/{id}/labels            - Set label
//	POST   /v1/prompts/{id}/render            - Render template with variables
func (h *PromptHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/prompts")
	rest = strings.TrimPrefix(rest, "/")

	switch {
	// Collection routes.
	case rest == "" && r.Method == http.MethodPost:
		h.createTemplate(w, r)
	case rest == "" && r.Method == http.MethodGet:
		h.listTemplates(w, r)

	// Sub-resource routes (must be checked before single-resource routes).
	case r.Method == http.MethodGet && strings.Contains(rest, "/versions/"):
		parts := strings.SplitN(rest, "/versions/", 2)
		h.getVersionRoute(w, r, parts[0], parts[1])
	case r.Method == http.MethodGet && strings.HasSuffix(rest, "/versions"):
		id := strings.TrimSuffix(rest, "/versions")
		h.listVersions(w, r, id)
	case r.Method == http.MethodPost && strings.HasSuffix(rest, "/rollback"):
		id := strings.TrimSuffix(rest, "/rollback")
		h.rollback(w, r, id)
	case r.Method == http.MethodPost && strings.HasSuffix(rest, "/labels"):
		id := strings.TrimSuffix(rest, "/labels")
		h.setLabel(w, r, id)
	case r.Method == http.MethodPost && strings.HasSuffix(rest, "/render"):
		id := strings.TrimSuffix(rest, "/render")
		h.renderTemplate(w, r, id)

	// Single resource routes.
	case r.Method == http.MethodGet && !strings.Contains(rest, "/"):
		h.getTemplate(w, r, rest)
	case r.Method == http.MethodPut && !strings.Contains(rest, "/"):
		h.updateTemplate(w, r, rest)
	case r.Method == http.MethodDelete && !strings.Contains(rest, "/"):
		h.deleteTemplate(w, r, rest)

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (h *PromptHandler) createTemplate(w http.ResponseWriter, r *http.Request) {
	var t PromptTemplate
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if t.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id is required"})
		return
	}
	if t.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	if err := h.store.Create(r.Context(), &t); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	created, err := h.store.Get(r.Context(), t.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (h *PromptHandler) listTemplates(w http.ResponseWriter, r *http.Request) {
	workspaceID := r.URL.Query().Get("workspace_id")
	limit := queryInt(r, "limit", 100)
	offset := queryInt(r, "offset", 0)

	list, err := h.store.List(r.Context(), workspaceID, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if list == nil {
		list = []*PromptTemplate{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (h *PromptHandler) getTemplate(w http.ResponseWriter, r *http.Request, id string) {
	t, err := h.store.Get(r.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (h *PromptHandler) updateTemplate(w http.ResponseWriter, r *http.Request, id string) {
	var t PromptTemplate
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	t.ID = id
	if err := h.store.Update(r.Context(), &t); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	updated, err := h.store.Get(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (h *PromptHandler) deleteTemplate(w http.ResponseWriter, r *http.Request, id string) {
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

func (h *PromptHandler) listVersions(w http.ResponseWriter, r *http.Request, id string) {
	versions, err := h.store.ListVersions(r.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, versions)
}

func (h *PromptHandler) getVersionRoute(w http.ResponseWriter, r *http.Request, id, versionStr string) {
	version, err := strconv.Atoi(versionStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid version number"})
		return
	}
	t, err := h.store.GetVersion(r.Context(), id, version)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, t)
}

type rollbackRequest struct {
	Version int `json:"version"`
}

func (h *PromptHandler) rollback(w http.ResponseWriter, r *http.Request, id string) {
	var req rollbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Version == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "version is required"})
		return
	}
	if err := h.store.Rollback(r.Context(), id, req.Version); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	t, err := h.store.Get(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, t)
}

type setLabelRequest struct {
	Label   string `json:"label"`
	Version int    `json:"version"`
}

func (h *PromptHandler) setLabel(w http.ResponseWriter, r *http.Request, id string) {
	var req setLabelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Label == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "label is required"})
		return
	}
	if req.Version == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "version is required"})
		return
	}
	if err := h.store.SetLabel(r.Context(), id, req.Label, req.Version); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	t, err := h.store.Get(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, t)
}

type renderRequest struct {
	Variables map[string]string `json:"variables"`
}

func (h *PromptHandler) renderTemplate(w http.ResponseWriter, r *http.Request, id string) {
	var req renderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	t, err := h.store.Get(r.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	rendered, err := h.renderer.Render(t, req.Variables)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"messages": rendered,
		"template": t,
	})
}

func queryInt(r *http.Request, key string, defaultVal int) int {
	s := r.URL.Query().Get(key)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return defaultVal
	}
	return v
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}


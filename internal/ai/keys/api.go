package keys

import (
	"io"
	"net/http"
	"strings"
	"time"

	json "github.com/goccy/go-json"
)

// Handler provides HTTP API handlers for virtual key management.
type Handler struct {
	store Store
}

// NewHandler creates a new virtual key API handler.
func NewHandler(store Store) *Handler {
	return &Handler{store: store}
}

// ServeHTTP routes key management requests.
// Expected paths (after stripping any /v1/ prefix):
//   - POST   keys        - create
//   - GET    keys        - list
//   - GET    keys/<id>   - get by id
//   - PATCH  keys/<id>   - update
//   - DELETE keys/<id>   - revoke
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Strip prefix to get sub-path
	path := strings.TrimPrefix(r.URL.Path, "/")
	path = strings.TrimPrefix(path, "v1/")
	path = strings.TrimPrefix(path, "keys")
	path = strings.TrimPrefix(path, "/")

	if path == "" {
		// Collection-level operations
		switch r.Method {
		case http.MethodPost:
			h.handleCreate(w, r)
		case http.MethodGet:
			h.handleList(w, r)
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
		}
		return
	}

	// Resource-level operations: path is the key ID
	id := path
	switch r.Method {
	case http.MethodGet:
		h.handleGet(w, r, id)
	case http.MethodPatch:
		h.handleUpdate(w, r, id)
	case http.MethodDelete:
		h.handleRevoke(w, r, id)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
	}
}

// createKeyRequest is the request body for creating a virtual key.
type createKeyRequest struct {
	Name              string            `json:"name"`
	WorkspaceID       string            `json:"workspace_id"`
	TeamID            string            `json:"team_id,omitempty"`
	ExpiresAt         *time.Time        `json:"expires_at,omitempty"`
	AllowedModels     []string          `json:"allowed_models,omitempty"`
	BlockedModels     []string          `json:"blocked_models,omitempty"`
	AllowedProviders  []string          `json:"allowed_providers,omitempty"`
	MaxTokensPerMin   int               `json:"max_tokens_per_min,omitempty"`
	MaxRequestsPerMin int               `json:"max_requests_per_min,omitempty"`
	MaxBudgetUSD      float64           `json:"max_budget_usd,omitempty"`
	BudgetPeriod      string            `json:"budget_period,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

// createKeyResponse is the response body for key creation - includes the raw key shown once.
type createKeyResponse struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Key       string     `json:"key"` // Raw key, shown only at creation
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Status    string     `json:"status"`
}

// keyDetailResponse is the response body for key details - never includes raw or hashed key.
type keyDetailResponse struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	WorkspaceID       string            `json:"workspace_id"`
	TeamID            string            `json:"team_id,omitempty"`
	CreatedBy         string            `json:"created_by,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
	ExpiresAt         *time.Time        `json:"expires_at,omitempty"`
	Status            string            `json:"status"`
	AllowedModels     []string          `json:"allowed_models,omitempty"`
	BlockedModels     []string          `json:"blocked_models,omitempty"`
	AllowedProviders  []string          `json:"allowed_providers,omitempty"`
	MaxTokensPerMin   int               `json:"max_tokens_per_min,omitempty"`
	MaxRequestsPerMin int               `json:"max_requests_per_min,omitempty"`
	MaxBudgetUSD      float64           `json:"max_budget_usd,omitempty"`
	BudgetPeriod      string            `json:"budget_period,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

func toDetailResponse(vk *VirtualKey) keyDetailResponse {
	return keyDetailResponse{
		ID:                vk.ID,
		Name:              vk.Name,
		WorkspaceID:       vk.WorkspaceID,
		TeamID:            vk.TeamID,
		CreatedBy:         vk.CreatedBy,
		CreatedAt:         vk.CreatedAt,
		ExpiresAt:         vk.ExpiresAt,
		Status:            vk.Status,
		AllowedModels:     vk.AllowedModels,
		BlockedModels:     vk.BlockedModels,
		AllowedProviders:  vk.AllowedProviders,
		MaxTokensPerMin:   vk.MaxTokensPerMin,
		MaxRequestsPerMin: vk.MaxRequestsPerMin,
		MaxBudgetUSD:      vk.MaxBudgetUSD,
		BudgetPeriod:      vk.BudgetPeriod,
		Metadata:          vk.Metadata,
	}
}

func (h *Handler) handleCreate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "Failed to read request body.")
		return
	}
	defer r.Body.Close()

	var req createKeyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "Invalid JSON body.")
		return
	}

	if req.Name == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "name is required.")
		return
	}
	if req.WorkspaceID == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "workspace_id is required.")
		return
	}

	rawKey, hashedKey, err := GenerateKey()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "key_generation_failed", "failed to generate virtual key.")
		return
	}
	now := time.Now().UTC()

	vk := &VirtualKey{
		ID:                "vk-" + now.Format("20060102") + "-" + hashedKey[:12],
		Name:              req.Name,
		HashedKey:         hashedKey,
		WorkspaceID:       req.WorkspaceID,
		TeamID:            req.TeamID,
		CreatedAt:         now,
		ExpiresAt:         req.ExpiresAt,
		Status:            "active",
		AllowedModels:     req.AllowedModels,
		BlockedModels:     req.BlockedModels,
		AllowedProviders:  req.AllowedProviders,
		MaxTokensPerMin:   req.MaxTokensPerMin,
		MaxRequestsPerMin: req.MaxRequestsPerMin,
		MaxBudgetUSD:      req.MaxBudgetUSD,
		BudgetPeriod:      req.BudgetPeriod,
		Metadata:          req.Metadata,
	}

	if err := h.store.Create(r.Context(), vk); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server_error", "Failed to create key.")
		return
	}

	resp := createKeyResponse{
		ID:        vk.ID,
		Name:      vk.Name,
		Key:       rawKey,
		CreatedAt: vk.CreatedAt,
		ExpiresAt: vk.ExpiresAt,
		Status:    vk.Status,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	workspaceID := r.URL.Query().Get("workspace_id")
	if workspaceID == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "workspace_id query parameter is required.")
		return
	}

	opts := ListOpts{
		Status: r.URL.Query().Get("status"),
	}

	keys, err := h.store.List(r.Context(), workspaceID, opts)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server_error", "Failed to list keys.")
		return
	}

	result := make([]keyDetailResponse, 0, len(keys))
	for _, vk := range keys {
		result = append(result, toDetailResponse(vk))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"data": result,
	})
}

func (h *Handler) handleGet(w http.ResponseWriter, r *http.Request, id string) {
	vk, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "not_found", "Key not found.")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toDetailResponse(vk))
}

func (h *Handler) handleUpdate(w http.ResponseWriter, r *http.Request, id string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "Failed to read request body.")
		return
	}
	defer r.Body.Close()

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "Invalid JSON body.")
		return
	}

	// Prevent updating sensitive fields
	delete(raw, "id")
	delete(raw, "hashed_key")
	delete(raw, "created_at")
	delete(raw, "workspace_id")

	if err := h.store.Update(r.Context(), id, raw); err != nil {
		if err == ErrKeyNotFound {
			writeJSONError(w, http.StatusNotFound, "not_found", "Key not found.")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "server_error", "Failed to update key.")
		return
	}

	vk, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server_error", "Failed to retrieve updated key.")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toDetailResponse(vk))
}

func (h *Handler) handleRevoke(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.store.Revoke(r.Context(), id); err != nil {
		if err == ErrKeyNotFound {
			writeJSONError(w, http.StatusNotFound, "not_found", "Key not found.")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "server_error", "Failed to revoke key.")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"id":      id,
		"status":  "revoked",
		"deleted": true,
	})
}

package keys

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	json "github.com/goccy/go-json"
)

func newAPIHandler(t *testing.T) (*Handler, *MemoryStore) {
	t.Helper()
	store := NewMemoryStore()
	return NewHandler(store), store
}

func TestAPI_CreateKey(t *testing.T) {
	h, _ := newAPIHandler(t)

	body := `{"name":"test-key","workspace_id":"ws-1"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/keys", strings.NewReader(body))
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body = %s", rr.Code, http.StatusCreated, rr.Body.String())
	}

	var resp createKeyResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if resp.Key == "" {
		t.Error("response should include raw key")
	}
	if !strings.HasPrefix(resp.Key, KeyPrefix) {
		t.Errorf("key = %q, want prefix %q", resp.Key, KeyPrefix)
	}
	if resp.ID == "" {
		t.Error("response should include ID")
	}
	if resp.Status != "active" {
		t.Errorf("status = %q, want %q", resp.Status, "active")
	}
	if resp.Name != "test-key" {
		t.Errorf("name = %q, want %q", resp.Name, "test-key")
	}
}

func TestAPI_CreateKey_MissingName(t *testing.T) {
	h, _ := newAPIHandler(t)

	body := `{"workspace_id":"ws-1"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/keys", strings.NewReader(body))
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestAPI_CreateKey_MissingWorkspaceID(t *testing.T) {
	h, _ := newAPIHandler(t)

	body := `{"name":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/keys", strings.NewReader(body))
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestAPI_ListKeys(t *testing.T) {
	h, _ := newAPIHandler(t)

	// Create two keys
	for _, name := range []string{"key-1", "key-2"} {
		body := `{"name":"` + name + `","workspace_id":"ws-1"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/keys", strings.NewReader(body))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusCreated {
			t.Fatalf("create %s: status = %d", name, rr.Code)
		}
	}

	// List
	req := httptest.NewRequest(http.MethodGet, "/v1/keys?workspace_id=ws-1", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var result struct {
		Data []keyDetailResponse `json:"data"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if len(result.Data) != 2 {
		t.Errorf("got %d keys, want 2", len(result.Data))
	}
}

func TestAPI_ListKeys_NoRawKey(t *testing.T) {
	h, _ := newAPIHandler(t)

	// Create a key
	body := `{"name":"secret","workspace_id":"ws-1"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/keys", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	// List and verify no raw or hashed key exposed
	req = httptest.NewRequest(http.MethodGet, "/v1/keys?workspace_id=ws-1", nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	responseBody := rr.Body.String()
	if strings.Contains(responseBody, "sk-sb-") {
		t.Error("list response should not contain raw key")
	}
	if strings.Contains(responseBody, "hashed_key") {
		t.Error("list response should not contain hashed_key field")
	}
}

func TestAPI_ListKeys_MissingWorkspaceID(t *testing.T) {
	h, _ := newAPIHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestAPI_GetKey(t *testing.T) {
	h, _ := newAPIHandler(t)

	// Create
	body := `{"name":"get-test","workspace_id":"ws-1"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/keys", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	var created createKeyResponse
	json.NewDecoder(rr.Body).Decode(&created)

	// Get
	req = httptest.NewRequest(http.MethodGet, "/v1/keys/"+created.ID, nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var detail keyDetailResponse
	json.NewDecoder(rr.Body).Decode(&detail)
	if detail.Name != "get-test" {
		t.Errorf("name = %q, want %q", detail.Name, "get-test")
	}
}

func TestAPI_GetKey_NotFound(t *testing.T) {
	h, _ := newAPIHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/keys/nonexistent", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestAPI_UpdateKey(t *testing.T) {
	h, _ := newAPIHandler(t)

	// Create
	body := `{"name":"original","workspace_id":"ws-1"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/keys", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	var created createKeyResponse
	json.NewDecoder(rr.Body).Decode(&created)

	// Update
	updateBody := `{"name":"updated"}`
	req = httptest.NewRequest(http.MethodPatch, "/v1/keys/"+created.ID, bytes.NewBufferString(updateBody))
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var detail keyDetailResponse
	json.NewDecoder(rr.Body).Decode(&detail)
	if detail.Name != "updated" {
		t.Errorf("name = %q, want %q", detail.Name, "updated")
	}
}

func TestAPI_UpdateKey_NotFound(t *testing.T) {
	h, _ := newAPIHandler(t)

	body := `{"name":"x"}`
	req := httptest.NewRequest(http.MethodPatch, "/v1/keys/nonexistent", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestAPI_RevokeKey(t *testing.T) {
	h, _ := newAPIHandler(t)

	// Create
	body := `{"name":"to-revoke","workspace_id":"ws-1"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/keys", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	var created createKeyResponse
	json.NewDecoder(rr.Body).Decode(&created)

	// Delete (revoke)
	req = httptest.NewRequest(http.MethodDelete, "/v1/keys/"+created.ID, nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var result map[string]any
	json.NewDecoder(rr.Body).Decode(&result)
	if result["status"] != "revoked" {
		t.Errorf("status = %v, want %q", result["status"], "revoked")
	}

	// Verify key is revoked
	req = httptest.NewRequest(http.MethodGet, "/v1/keys/"+created.ID, nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	var detail keyDetailResponse
	json.NewDecoder(rr.Body).Decode(&detail)
	if detail.Status != "revoked" {
		t.Errorf("after revoke, status = %q, want %q", detail.Status, "revoked")
	}
}

func TestAPI_RevokeKey_NotFound(t *testing.T) {
	h, _ := newAPIHandler(t)

	req := httptest.NewRequest(http.MethodDelete, "/v1/keys/nonexistent", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestAPI_MethodNotAllowed(t *testing.T) {
	h, _ := newAPIHandler(t)

	// PUT on collection
	req := httptest.NewRequest(http.MethodPut, "/v1/keys", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestAPI_CreateKeyWithOptions(t *testing.T) {
	h, _ := newAPIHandler(t)

	body := `{
		"name": "restricted-key",
		"workspace_id": "ws-1",
		"allowed_models": ["gpt-4"],
		"blocked_models": ["gpt-4-vision"],
		"allowed_providers": ["openai"],
		"max_budget_usd": 100.0,
		"budget_period": "monthly",
		"metadata": {"team": "engineering"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/keys", strings.NewReader(body))
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body = %s", rr.Code, http.StatusCreated, rr.Body.String())
	}

	var created createKeyResponse
	json.NewDecoder(rr.Body).Decode(&created)

	// Verify details via GET
	req = httptest.NewRequest(http.MethodGet, "/v1/keys/"+created.ID, nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	var detail keyDetailResponse
	json.NewDecoder(rr.Body).Decode(&detail)

	if len(detail.AllowedModels) != 1 || detail.AllowedModels[0] != "gpt-4" {
		t.Errorf("allowed_models = %v, want [gpt-4]", detail.AllowedModels)
	}
	if detail.MaxBudgetUSD != 100.0 {
		t.Errorf("max_budget_usd = %v, want 100.0", detail.MaxBudgetUSD)
	}
	if detail.BudgetPeriod != "monthly" {
		t.Errorf("budget_period = %q, want %q", detail.BudgetPeriod, "monthly")
	}
	if detail.Metadata["team"] != "engineering" {
		t.Errorf("metadata[team] = %q, want %q", detail.Metadata["team"], "engineering")
	}
}

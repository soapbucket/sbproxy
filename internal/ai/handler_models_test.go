package ai

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newModelsTestHandler(t *testing.T, providers map[string]providerEntry, cfgs []*ProviderConfig, registry *ModelRegistry, gateway bool) *Handler {
	t.Helper()
	if cfgs == nil {
		cfgs = make([]*ProviderConfig, 0)
		for _, e := range providers {
			cfgs = append(cfgs, e.config)
		}
	}
	h := &Handler{
		config: &HandlerConfig{
			Providers:          cfgs,
			MaxRequestBodySize: 10 * 1024 * 1024,
			Gateway:            gateway,
			ModelRegistry:      registry,
		},
		providers: providers,
		router:    NewRouter(nil, cfgs),
	}
	return h
}

func doModelsRequest(t *testing.T, h *Handler, rd *reqctx.RequestData) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	if rd != nil {
		req = req.WithContext(reqctx.SetRequestData(req.Context(), rd))
	}
	w := httptest.NewRecorder()
	h.handleListModels(w, req)
	return w
}

func TestModels_SingleProviderTwoModels(t *testing.T) {
	mp := &mockProvider{
		name: "openai",
		models: []ModelInfo{
			{ID: "gpt-4", Object: "model", Created: 1686935002, OwnedBy: "openai"},
			{ID: "gpt-3.5-turbo", Object: "model", Created: 1686935002, OwnedBy: "openai"},
		},
	}
	cfg := &ProviderConfig{Name: "openai"}
	providers := map[string]providerEntry{
		"openai": {provider: mp, config: cfg},
	}

	h := newModelsTestHandler(t, providers, []*ProviderConfig{cfg}, nil, false)
	w := doModelsRequest(t, h, nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ModelListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Data, 2)

	// Should be sorted alphabetically.
	assert.Equal(t, "gpt-3.5-turbo", resp.Data[0].ID)
	assert.Equal(t, "gpt-4", resp.Data[1].ID)
}

func TestModels_TwoProvidersOverlappingModelDeduped(t *testing.T) {
	mpOpenAI := &mockProvider{
		name: "openai",
		models: []ModelInfo{
			{ID: "gpt-4", Object: "model", Created: 1686935002, OwnedBy: "openai"},
		},
	}
	mpAzure := &mockProvider{
		name: "azure",
		models: []ModelInfo{
			{ID: "gpt-4", Object: "model", Created: 1700000000, OwnedBy: "azure"},
			{ID: "gpt-4-32k", Object: "model", Created: 1700000000, OwnedBy: "azure"},
		},
	}

	cfgOpenAI := &ProviderConfig{Name: "openai"}
	cfgAzure := &ProviderConfig{Name: "azure"}
	providers := map[string]providerEntry{
		"openai": {provider: mpOpenAI, config: cfgOpenAI},
		"azure":  {provider: mpAzure, config: cfgAzure},
	}

	h := newModelsTestHandler(t, providers, []*ProviderConfig{cfgOpenAI, cfgAzure}, nil, false)
	w := doModelsRequest(t, h, nil)

	var resp ModelListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	// gpt-4 should appear only once (deduped).
	ids := make(map[string]int)
	for _, m := range resp.Data {
		ids[m.ID]++
	}
	assert.Equal(t, 1, ids["gpt-4"], "gpt-4 should appear exactly once")
	assert.Equal(t, 1, ids["gpt-4-32k"], "gpt-4-32k should appear exactly once")
	assert.Len(t, resp.Data, 2)
}

func TestModels_FeatureFlagDisablesModel(t *testing.T) {
	mp := &mockProvider{
		name: "openai",
		models: []ModelInfo{
			{ID: "gpt-4", Object: "model", Created: 1686935002, OwnedBy: "openai"},
			{ID: "gpt-3.5-turbo", Object: "model", Created: 1686935002, OwnedBy: "openai"},
		},
	}
	cfg := &ProviderConfig{Name: "openai"}
	providers := map[string]providerEntry{
		"openai": {provider: mp, config: cfg},
	}

	h := newModelsTestHandler(t, providers, []*ProviderConfig{cfg}, nil, false)

	rd := reqctx.NewRequestData()
	rd.FeatureFlags = map[string]any{
		"ai.models.gpt-4.enabled": false,
	}

	w := doModelsRequest(t, h, rd)

	var resp ModelListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	// gpt-4 should be filtered out.
	assert.Len(t, resp.Data, 1)
	assert.Equal(t, "gpt-3.5-turbo", resp.Data[0].ID)
}

func TestModels_EmptyProviderConfigReturnsEmptyList(t *testing.T) {
	mp := &mockProvider{
		name:   "empty",
		models: nil,
	}
	cfg := &ProviderConfig{Name: "empty"}
	providers := map[string]providerEntry{
		"empty": {provider: mp, config: cfg},
	}

	h := newModelsTestHandler(t, providers, []*ProviderConfig{cfg}, nil, false)
	w := doModelsRequest(t, h, nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ModelListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "list", resp.Object)
	assert.NotNil(t, resp.Data, "data should be an empty array, not null")
	assert.Len(t, resp.Data, 0)
}

func TestModels_ResponseObjectFieldIsList(t *testing.T) {
	mp := &mockProvider{
		name: "openai",
		models: []ModelInfo{
			{ID: "gpt-4", Object: "model", Created: 1686935002, OwnedBy: "openai"},
		},
	}
	cfg := &ProviderConfig{Name: "openai"}
	providers := map[string]providerEntry{
		"openai": {provider: mp, config: cfg},
	}

	h := newModelsTestHandler(t, providers, []*ProviderConfig{cfg}, nil, false)
	w := doModelsRequest(t, h, nil)

	var resp ModelListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "list", resp.Object)
}

func TestModels_EachModelHasRequiredFields(t *testing.T) {
	mp := &mockProvider{
		name: "openai",
		models: []ModelInfo{
			{ID: "gpt-4", Object: "model", Created: 1686935002, OwnedBy: "openai"},
		},
	}
	cfg := &ProviderConfig{Name: "openai"}
	providers := map[string]providerEntry{
		"openai": {provider: mp, config: cfg},
	}

	h := newModelsTestHandler(t, providers, []*ProviderConfig{cfg}, nil, false)
	w := doModelsRequest(t, h, nil)

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))

	var data []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw["data"], &data))
	require.Len(t, data, 1)

	model := data[0]
	assert.Contains(t, model, "id")
	assert.Contains(t, model, "object")
	assert.Contains(t, model, "created")
	assert.Contains(t, model, "owned_by")

	// Verify values.
	var id, object, ownedBy string
	var created int64
	json.Unmarshal(model["id"], &id)
	json.Unmarshal(model["object"], &object)
	json.Unmarshal(model["created"], &created)
	json.Unmarshal(model["owned_by"], &ownedBy)

	assert.Equal(t, "gpt-4", id)
	assert.Equal(t, "model", object)
	assert.Equal(t, int64(1686935002), created)
	assert.Equal(t, "openai", ownedBy)
}

func TestModels_GatewayModelRegistryAddsModels(t *testing.T) {
	mp := &mockProvider{
		name: "openai",
		models: []ModelInfo{
			{ID: "gpt-4", Object: "model", Created: 1686935002, OwnedBy: "openai"},
		},
	}
	cfg := &ProviderConfig{Name: "openai"}
	providers := map[string]providerEntry{
		"openai": {provider: mp, config: cfg},
	}

	registry := NewModelRegistry([]ModelRegistryEntry{
		{ModelPattern: "claude-3-opus", Provider: "anthropic", Priority: 1},
		{ModelPattern: "gpt-4", Provider: "openai", Priority: 2},       // overlaps, should be deduped
		{ModelPattern: "gpt-*", Provider: "openai", Priority: 3},        // glob, should be skipped
	})

	h := newModelsTestHandler(t, providers, []*ProviderConfig{cfg}, registry, true)
	w := doModelsRequest(t, h, nil)

	var resp ModelListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	ids := make(map[string]bool)
	for _, m := range resp.Data {
		ids[m.ID] = true
	}
	// gpt-4 from provider, claude-3-opus from registry, gpt-* glob excluded.
	assert.True(t, ids["gpt-4"], "gpt-4 should be present from provider")
	assert.True(t, ids["claude-3-opus"], "claude-3-opus should be added from registry")
	assert.Len(t, resp.Data, 2)

	// claude-3-opus should be owned by "anthropic" (from registry lookup).
	for _, m := range resp.Data {
		if m.ID == "claude-3-opus" {
			assert.Equal(t, "anthropic", m.OwnedBy)
		}
	}
}

func TestModels_MethodNotAllowed(t *testing.T) {
	mp := &mockProvider{name: "test"}
	cfg := &ProviderConfig{Name: "test"}
	providers := map[string]providerEntry{
		"test": {provider: mp, config: cfg},
	}

	h := newModelsTestHandler(t, providers, []*ProviderConfig{cfg}, nil, false)

	req := httptest.NewRequest(http.MethodPost, "/v1/models", nil)
	w := httptest.NewRecorder()
	h.handleListModels(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestModels_ConfigModelsAddedWhenProviderListEmpty(t *testing.T) {
	// Provider returns no models from ListModels, but config declares models.
	mp := &mockProvider{
		name:   "openai",
		models: nil,
	}
	cfg := &ProviderConfig{
		Name:   "openai",
		Models: []string{"gpt-4o", "gpt-4o-mini"},
	}
	providers := map[string]providerEntry{
		"openai": {provider: mp, config: cfg},
	}

	h := newModelsTestHandler(t, providers, []*ProviderConfig{cfg}, nil, false)
	w := doModelsRequest(t, h, nil)

	var resp ModelListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Data, 2)
	assert.Equal(t, "gpt-4o", resp.Data[0].ID)
	assert.Equal(t, "gpt-4o-mini", resp.Data[1].ID)
}

func TestModels_SortedAlphabetically(t *testing.T) {
	mp := &mockProvider{
		name: "openai",
		models: []ModelInfo{
			{ID: "z-model", Object: "model", Created: 1686935002, OwnedBy: "openai"},
			{ID: "a-model", Object: "model", Created: 1686935002, OwnedBy: "openai"},
			{ID: "m-model", Object: "model", Created: 1686935002, OwnedBy: "openai"},
		},
	}
	cfg := &ProviderConfig{Name: "openai"}
	providers := map[string]providerEntry{
		"openai": {provider: mp, config: cfg},
	}

	h := newModelsTestHandler(t, providers, []*ProviderConfig{cfg}, nil, false)
	w := doModelsRequest(t, h, nil)

	var resp ModelListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Data, 3)
	assert.Equal(t, "a-model", resp.Data[0].ID)
	assert.Equal(t, "m-model", resp.Data[1].ID)
	assert.Equal(t, "z-model", resp.Data[2].ID)
}

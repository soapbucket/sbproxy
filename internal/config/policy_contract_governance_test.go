package config

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getTestSpecPath() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "test", "fixtures", "specs", "petstore.yaml")
}

func loadTestSpec(t *testing.T) []byte {
	t.Helper()
	specPath := getTestSpecPath()
	data, err := os.ReadFile(specPath)
	require.NoError(t, err, "failed to read test spec file: %s", specPath)
	return data
}

func newTestContractPolicy(t *testing.T, enforcement string, validateRequests, validateResponses bool) *ContractGovernancePolicy {
	t.Helper()

	specData := loadTestSpec(t)

	policyJSON := map[string]any{
		"type":               PolicyTypeContractGovernance,
		"spec_from":          "openapi_spec",
		"validate_requests":  validateRequests,
		"validate_responses": validateResponses,
		"enforcement":        enforcement,
		"sample_rate":        1.0,
	}

	data, err := json.Marshal(policyJSON)
	require.NoError(t, err)

	policy, err := LoadContractGovernancePolicy(data)
	require.NoError(t, err)

	cgp := policy.(*ContractGovernancePolicy)

	// Set up config with spec data in Params
	cfg := &Config{
		Hostname: "test.example.com",
		Params: map[string]any{
			"openapi_spec": string(specData),
		},
	}
	cgp.cfg = cfg

	// Load spec
	err = cgp.loadSpec()
	require.NoError(t, err, "failed to load test spec")
	require.True(t, cgp.ready, "spec should be ready after loading")

	return cgp
}

func TestContractGovernance_ValidRequest(t *testing.T) {
	policy := newTestContractPolicy(t, EnforcementReject, true, false)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":1,"name":"Fido"}`))
	})

	handler := policy.Apply(inner)

	// Valid POST /pets with proper body
	body := `{"name":"Fido","tag":"dog"}`
	req := httptest.NewRequest("POST", "/pets", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should pass through successfully
	assert.Equal(t, http.StatusCreated, rr.Code)
	assert.Contains(t, rr.Body.String(), "Fido")
}

func TestContractGovernance_InvalidRequest_Reject(t *testing.T) {
	policy := newTestContractPolicy(t, EnforcementReject, true, false)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":1,"name":"Fido"}`))
	})

	handler := policy.Apply(inner)

	// Invalid POST /pets — missing required "name" field
	body := `{"tag":"dog"}`
	req := httptest.NewRequest("POST", "/pets", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should be rejected with 400
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp struct {
		Error  string   `json:"error"`
		Errors []string `json:"errors"`
	}
	err := json.NewDecoder(rr.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "Contract validation failed", errResp.Error)
	assert.NotEmpty(t, errResp.Errors)
}

func TestContractGovernance_InvalidRequest_Advisory(t *testing.T) {
	policy := newTestContractPolicy(t, EnforcementAdvisory, true, false)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":1,"name":"Fido"}`))
	})

	handler := policy.Apply(inner)

	// Invalid POST /pets — missing required "name" field
	body := `{"tag":"dog"}`
	req := httptest.NewRequest("POST", "/pets", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should pass through (advisory mode) but add violation header
	assert.Equal(t, http.StatusCreated, rr.Code)
	violations := rr.Header().Values("X-Contract-Violation")
	assert.NotEmpty(t, violations, "should have contract violation headers")
}

func TestContractGovernance_ValidGetRequest(t *testing.T) {
	policy := newTestContractPolicy(t, EnforcementReject, true, false)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"id":1,"name":"Fido"}]`))
	})

	handler := policy.Apply(inner)

	// Valid GET /pets
	req := httptest.NewRequest("GET", "/pets?limit=10", nil)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestContractGovernance_PathNotInSpec(t *testing.T) {
	policy := newTestContractPolicy(t, EnforcementReject, true, false)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	handler := policy.Apply(inner)

	// Path not in spec — should pass through without validation
	req := httptest.NewRequest("GET", "/unknown/path", nil)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "ok", rr.Body.String())
}

func TestContractGovernance_ResponseValidation_Advisory(t *testing.T) {
	policy := newTestContractPolicy(t, EnforcementAdvisory, false, true)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Invalid response: missing required "id" field
		w.Write([]byte(`[{"name":"Fido"}]`))
	})

	handler := policy.Apply(inner)

	req := httptest.NewRequest("GET", "/pets", nil)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Advisory mode — response goes through but may have violation headers
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestContractGovernance_ResponseValidation_Reject(t *testing.T) {
	policy := newTestContractPolicy(t, EnforcementReject, false, true)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Invalid response: pets should be an array, not a string
		w.Write([]byte(`"not an array"`))
	})

	handler := policy.Apply(inner)

	req := httptest.NewRequest("GET", "/pets", nil)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Reject mode — should return 502 Bad Gateway
	assert.Equal(t, http.StatusBadGateway, rr.Code)
}

func TestContractGovernance_SpecNotReady(t *testing.T) {
	policyJSON := map[string]any{
		"type":              PolicyTypeContractGovernance,
		"spec_from":         "missing_spec",
		"validate_requests": true,
		"enforcement":       EnforcementReject,
	}

	data, err := json.Marshal(policyJSON)
	require.NoError(t, err)

	policy, err := LoadContractGovernancePolicy(data)
	require.NoError(t, err)

	// Spec not loaded — should pass through
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	handler := policy.Apply(inner)

	req := httptest.NewRequest("GET", "/pets", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "ok", rr.Body.String())
}

func TestContractGovernance_GetPathParam(t *testing.T) {
	policy := newTestContractPolicy(t, EnforcementReject, true, false)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":123,"name":"Fido"}`))
	})

	handler := policy.Apply(inner)

	// GET /pets/123 — valid path parameter
	req := httptest.NewRequest("GET", "/pets/123", nil)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestContractGovernance_SeparateEnforcement(t *testing.T) {
	specData := loadTestSpec(t)

	policyJSON := map[string]any{
		"type":                 PolicyTypeContractGovernance,
		"spec_from":            "openapi_spec",
		"validate_requests":    true,
		"validate_responses":   true,
		"request_enforcement":  "reject",
		"response_enforcement": "advisory",
	}

	data, err := json.Marshal(policyJSON)
	require.NoError(t, err)

	policy, err := LoadContractGovernancePolicy(data)
	require.NoError(t, err)

	cgp := policy.(*ContractGovernancePolicy)
	cgp.cfg = &Config{
		Hostname: "test.example.com",
		Params:   map[string]any{"openapi_spec": string(specData)},
	}

	err = cgp.loadSpec()
	require.NoError(t, err)

	assert.Equal(t, "reject", cgp.getRequestEnforcement())
	assert.Equal(t, "advisory", cgp.getResponseEnforcement())
}

func TestContractGovernance_LoadPolicy(t *testing.T) {
	policyJSON := `{
		"type": "contract_governance",
		"spec_from": "my_spec",
		"validate_requests": true,
		"validate_responses": true,
		"enforcement": "advisory",
		"sample_rate": 0.5
	}`

	policy, err := LoadContractGovernancePolicy([]byte(policyJSON))
	require.NoError(t, err)

	cgp := policy.(*ContractGovernancePolicy)
	assert.Equal(t, "my_spec", cgp.SpecFrom)
	assert.True(t, cgp.ValidateRequests)
	assert.True(t, cgp.ValidateResponses)
	assert.Equal(t, "advisory", cgp.Enforcement)
	assert.Equal(t, 0.5, cgp.SampleRate)
}

func TestContractGovernance_BodySchemaMismatch_FieldPath(t *testing.T) {
	policy := newTestContractPolicy(t, EnforcementReject, true, false)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":1,"name":"Fido"}`))
	})

	handler := policy.Apply(inner)

	// Send a body where "name" is wrong type (integer instead of string)
	// and has an extra invalid field type to trigger field-level error detail
	body := `{"name":12345}`
	req := httptest.NewRequest("POST", "/pets", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp struct {
		Error  string   `json:"error"`
		Errors []string `json:"errors"`
	}
	err := json.NewDecoder(rr.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "Contract validation failed", errResp.Error)
	assert.NotEmpty(t, errResp.Errors)

	// The validation error should reference the field path ("name")
	combined := ""
	for _, e := range errResp.Errors {
		combined += e + " "
	}
	assert.Contains(t, combined, "name", "error should reference the field path 'name'")
}

func TestContractGovernance_MissingRequiredQueryParam(t *testing.T) {
	// The petstore spec has GET /pets with an optional "limit" param.
	// To test required query param validation, we create a custom spec
	// with a required query parameter.
	specJSON := `{
		"openapi": "3.0.0",
		"info": {"title": "Test", "version": "1.0.0"},
		"paths": {
			"/items": {
				"get": {
					"operationId": "listItems",
					"parameters": [
						{
							"name": "page",
							"in": "query",
							"required": true,
							"schema": {"type": "integer"}
						}
					],
					"responses": {
						"200": {
							"description": "OK",
							"content": {
								"application/json": {
									"schema": {"type": "array", "items": {"type": "string"}}
								}
							}
						}
					}
				}
			}
		}
	}`

	policyJSON := map[string]any{
		"type":              PolicyTypeContractGovernance,
		"spec_from":         "spec",
		"validate_requests": true,
		"enforcement":       EnforcementReject,
		"sample_rate":       1.0,
	}

	data, err := json.Marshal(policyJSON)
	require.NoError(t, err)

	policy, err := LoadContractGovernancePolicy(data)
	require.NoError(t, err)

	cgp := policy.(*ContractGovernancePolicy)
	cgp.cfg = &Config{
		Hostname: "test.example.com",
		Params:   map[string]any{"spec": specJSON},
	}
	err = cgp.loadSpec()
	require.NoError(t, err)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`["item1"]`))
	})

	handler := cgp.Apply(inner)

	// Missing required "page" query param
	req := httptest.NewRequest("GET", "/items", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp struct {
		Error  string   `json:"error"`
		Errors []string `json:"errors"`
	}
	err = json.NewDecoder(rr.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "Contract validation failed", errResp.Error)

	// Error should reference the missing "page" parameter
	combined := ""
	for _, e := range errResp.Errors {
		combined += e + " "
	}
	assert.Contains(t, combined, "page", "error should mention the missing 'page' parameter")
}

func TestContractGovernance_RefResolution(t *testing.T) {
	// The petstore fixture uses $ref for Pet and NewPet schemas.
	// This test verifies that $ref schemas are resolved correctly
	// by validating both a request (NewPet via $ref) and response (Pet via $ref).
	policy := newTestContractPolicy(t, EnforcementReject, true, true)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		// Valid Pet response (matches $ref "#/components/schemas/Pet")
		w.Write([]byte(`{"id":42,"name":"Rex","tag":"dog"}`))
	})

	handler := policy.Apply(inner)

	// Valid NewPet body (matches $ref "#/components/schemas/NewPet")
	body := `{"name":"Rex","tag":"dog"}`
	req := httptest.NewRequest("POST", "/pets", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Both request and response should pass validation
	assert.Equal(t, http.StatusCreated, rr.Code)
	assert.Contains(t, rr.Body.String(), "Rex")
	assert.Empty(t, rr.Header().Values("X-Contract-Violation"), "no violations expected for valid request+response")
}

func BenchmarkContractGovernance_ValidRequest(b *testing.B) {
	b.ReportAllocs()
	specPath := getTestSpecPath()
	specData, err := os.ReadFile(specPath)
	if err != nil {
		b.Skip("test spec not found")
	}

	policyJSON, _ := json.Marshal(map[string]any{
		"type":              PolicyTypeContractGovernance,
		"spec_from":         "openapi_spec",
		"validate_requests": true,
		"enforcement":       "reject",
	})

	policy, _ := LoadContractGovernancePolicy(policyJSON)
	cgp := policy.(*ContractGovernancePolicy)
	cgp.cfg = &Config{
		Hostname: "bench.example.com",
		Params:   map[string]any{"openapi_spec": string(specData)},
	}
	cgp.loadSpec()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := cgp.Apply(inner)
	body := `{"name":"BenchPet","tag":"bench"}`

	b.ResetTimer()
	for b.Loop() {
		req := httptest.NewRequest("POST", "/pets", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
	}
}

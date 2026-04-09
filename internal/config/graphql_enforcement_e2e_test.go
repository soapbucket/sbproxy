package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGraphQLEnforcement_E2E_11Aliases_Blocked verifies that a query with 11
// aliases is rejected when max_aliases is set to 10 (the default).
func TestGraphQLEnforcement_E2E_11Aliases_Blocked(t *testing.T) {
	// Backend GraphQL server (should not be reached)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("backend should not be reached for blocked query")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"ok":true}}`)
	}))
	defer backend.Close()

	actionJSON := fmt.Sprintf(`{
		"type": "graphql",
		"url": %q,
		"max_aliases": 10
	}`, backend.URL)

	action, err := NewGraphQLAction([]byte(actionJSON))
	if err != nil {
		t.Fatalf("failed to create GraphQL action: %v", err)
	}

	// Build query with 11 aliases
	var sb strings.Builder
	sb.WriteString(`{"query":"{ `)
	for i := 0; i < 11; i++ {
		if i > 0 {
			sb.WriteString(" ")
		}
		sb.WriteString(fmt.Sprintf("a%d: user { id }", i))
	}
	sb.WriteString(` }"}`)

	req := httptest.NewRequest(http.MethodPost, backend.URL+"/graphql", strings.NewReader(sb.String()))
	req.Header.Set("Content-Type", "application/json")

	transport := action.Transport()
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 400 for 11 aliases (limit 10), got %d, body: %s", resp.StatusCode, string(body))
	}

	// Verify error message mentions aliases
	body, _ := io.ReadAll(resp.Body)
	var gqlResp map[string]interface{}
	if err := json.Unmarshal(body, &gqlResp); err == nil {
		if errs, ok := gqlResp["errors"]; ok {
			errJSON, _ := json.Marshal(errs)
			if !strings.Contains(string(errJSON), "alias") &&
				!strings.Contains(string(errJSON), "ALIAS") &&
				!strings.Contains(string(errJSON), "TOO_MANY_ALIASES") {
				t.Errorf("error response should mention aliases: %s", string(errJSON))
			}
		}
	}
}

// TestGraphQLEnforcement_E2E_5Aliases_Passes verifies that a query with 5
// aliases passes when max_aliases is set to 10.
func TestGraphQLEnforcement_E2E_5Aliases_Passes(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read and verify the request body is forwarded
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("backend failed to read body: %v", err)
		}
		if len(body) == 0 {
			t.Error("backend received empty body")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"a0":{"id":"1"},"a1":{"id":"2"},"a2":{"id":"3"},"a3":{"id":"4"},"a4":{"id":"5"}}}`)
	}))
	defer backend.Close()

	actionJSON := fmt.Sprintf(`{
		"type": "graphql",
		"url": %q,
		"max_aliases": 10
	}`, backend.URL)

	action, err := NewGraphQLAction([]byte(actionJSON))
	if err != nil {
		t.Fatalf("failed to create GraphQL action: %v", err)
	}

	// Build query with 5 aliases (well under limit of 10)
	var sb strings.Builder
	sb.WriteString(`{"query":"{ `)
	for i := 0; i < 5; i++ {
		if i > 0 {
			sb.WriteString(" ")
		}
		sb.WriteString(fmt.Sprintf("a%d: user { id }", i))
	}
	sb.WriteString(` }"}`)

	req := httptest.NewRequest(http.MethodPost, backend.URL+"/graphql", strings.NewReader(sb.String()))
	req.Header.Set("Content-Type", "application/json")

	transport := action.Transport()
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 for 5 aliases (limit 10), got %d, body: %s", resp.StatusCode, string(body))
	}
}

// TestGraphQLEnforcement_E2E_DeeplyNested_Blocked verifies that a query
// exceeding max_depth is blocked.
func TestGraphQLEnforcement_E2E_DeeplyNested_Blocked(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("backend should not be reached for depth-exceeded query")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{}}`)
	}))
	defer backend.Close()

	actionJSON := fmt.Sprintf(`{
		"type": "graphql",
		"url": %q,
		"max_depth": 3
	}`, backend.URL)

	action, err := NewGraphQLAction([]byte(actionJSON))
	if err != nil {
		t.Fatalf("failed to create GraphQL action: %v", err)
	}

	// Build a query with depth 5 (exceeds max_depth of 3)
	query := `{"query":"{ user { posts { comments { author { name } } } } }"}`
	req := httptest.NewRequest(http.MethodPost, backend.URL+"/graphql",
		bytes.NewReader([]byte(query)))
	req.Header.Set("Content-Type", "application/json")

	transport := action.Transport()
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 400 for depth 5 (limit 3), got %d, body: %s", resp.StatusCode, string(body))
	}
}

// TestGraphQLEnforcement_E2E_HighComplexity_Blocked verifies that a query
// exceeding max_complexity is rejected with 400.
func TestGraphQLEnforcement_E2E_HighComplexity_Blocked(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("backend should not be reached for complexity-exceeded query")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{}}`)
	}))
	defer backend.Close()

	// Set max_complexity to 5 so a moderately nested query exceeds it
	actionJSON := fmt.Sprintf(`{
		"type": "graphql",
		"url": %q,
		"max_complexity": 5
	}`, backend.URL)

	action, err := NewGraphQLAction([]byte(actionJSON))
	if err != nil {
		t.Fatalf("failed to create GraphQL action: %v", err)
	}

	// Build a query with many fields that should exceed complexity 5
	query := `{"query":"{ user { id name email posts { id title body comments { id text author { name email } } } } }"}`
	req := httptest.NewRequest(http.MethodPost, backend.URL+"/graphql",
		bytes.NewReader([]byte(query)))
	req.Header.Set("Content-Type", "application/json")

	transport := action.Transport()
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 400 for high-complexity query (limit 5), got %d, body: %s", resp.StatusCode, string(body))
	}

	// Verify the error mentions complexity
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "complexity") && !strings.Contains(string(body), "COMPLEX") {
		t.Errorf("error response should mention complexity: %s", string(body))
	}
}

// TestGraphQLEnforcement_E2E_SimpleQuery_Passes verifies that a simple query
// passes when max_complexity is set to a reasonable limit.
func TestGraphQLEnforcement_E2E_SimpleQuery_Passes(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"user":{"id":"1","name":"Alice"}}}`)
	}))
	defer backend.Close()

	actionJSON := fmt.Sprintf(`{
		"type": "graphql",
		"url": %q,
		"max_complexity": 100
	}`, backend.URL)

	action, err := NewGraphQLAction([]byte(actionJSON))
	if err != nil {
		t.Fatalf("failed to create GraphQL action: %v", err)
	}

	query := `{"query":"{ user { id name } }"}`
	req := httptest.NewRequest(http.MethodPost, backend.URL+"/graphql",
		bytes.NewReader([]byte(query)))
	req.Header.Set("Content-Type", "application/json")

	transport := action.Transport()
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 for simple query (limit 100), got %d, body: %s", resp.StatusCode, string(body))
	}
}

// TestGraphQLEnforcement_E2E_MutationRateLimitedIndependently verifies that
// mutations are rate limited independently from queries. Queries should still
// pass even when the mutation rate limit is exhausted.
func TestGraphQLEnforcement_E2E_MutationRateLimitedIndependently(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"ok":true}}`)
	}))
	defer backend.Close()

	// Allow only 2 mutations per minute, no limit on queries
	actionJSON := fmt.Sprintf(`{
		"type": "graphql",
		"url": %q,
		"mutation_rate_limit": {
			"requests_per_minute": 2
		}
	}`, backend.URL)

	action, err := NewGraphQLAction([]byte(actionJSON))
	if err != nil {
		t.Fatalf("failed to create GraphQL action: %v", err)
	}

	transport := action.Transport()

	// Send 2 mutations (should pass)
	for i := 0; i < 2; i++ {
		query := `{"query":"mutation { createUser(name: \"test\") { id } }"}`
		req := httptest.NewRequest(http.MethodPost, backend.URL+"/graphql",
			bytes.NewReader([]byte(query)))
		req.Header.Set("Content-Type", "application/json")

		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("mutation %d: unexpected transport error: %v", i, err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("mutation %d: expected 200, got %d", i, resp.StatusCode)
		}
	}

	// 3rd mutation should be rate limited (429)
	query := `{"query":"mutation { createUser(name: \"blocked\") { id } }"}`
	req := httptest.NewRequest(http.MethodPost, backend.URL+"/graphql",
		bytes.NewReader([]byte(query)))
	req.Header.Set("Content-Type", "application/json")

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("mutation 3: unexpected transport error: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for 3rd mutation (limit 2/min), got %d", resp.StatusCode)
	}

	// Queries should still pass (independent rate limit)
	queryReq := `{"query":"{ user { id name } }"}`
	req = httptest.NewRequest(http.MethodPost, backend.URL+"/graphql",
		bytes.NewReader([]byte(queryReq)))
	req.Header.Set("Content-Type", "application/json")

	resp, err = transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("query after mutation limit: unexpected transport error: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for query (mutations are rate limited, not queries), got %d", resp.StatusCode)
	}
}

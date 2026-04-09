package config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
)

// TestGraphQLE2EConfig tests the exact config from the E2E test fixtures
// This reproduces the issue where GraphQL returns 404 instead of 200
func TestGraphQLE2EConfig(t *testing.T) {
	// This is the exact config from test/fixtures/origins/12-graphql-proxy.json
	configJSON := `{
		"id": "graphql",
		"hostname": "graphql.test",
		"action": {
			"type": "graphql",
			"url": "http://e2e-test-server:8092/graphql",
			"max_depth": 10,
			"max_complexity": 100,
			"enable_introspection": true,
			"enable_query_batching": true,
			"enable_query_deduplication": true
		}
	}`

	var cfg Config
	err := json.Unmarshal([]byte(configJSON), &cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Verify IsProxy() returns true
	if !cfg.IsProxy() {
		t.Error("IsProxy() should return true for GraphQL")
	}

	// Verify Transport() is not nil
	transport := cfg.Transport()
	if transport == nil {
		t.Error("Transport() should not return nil for GraphQL")
	}

	// Test the Rewrite function with the exact path from the test
	req := httptest.NewRequest("POST", "http://graphql.test/graphql", strings.NewReader(`{"query":"{ __typename }"}`))
	req.Header.Set("Content-Type", "application/json")

	// Create ProxyRequest
	pr := &httputil.ProxyRequest{
		In:  req,
		Out: req.Clone(req.Context()),
	}

	// Get the Rewrite function
	rewriteFn := cfg.Rewrite()
	if rewriteFn == nil {
		t.Fatal("Rewrite() returned nil")
	}

	// Execute the rewrite
	rewriteFn(pr)

	// Verify the URL was set correctly
	// The targetURL is "http://e2e-test-server:8092/graphql"
	expectedURL, _ := url.Parse("http://e2e-test-server:8092/graphql")
	
	if pr.Out.URL.Host != expectedURL.Host {
		t.Errorf("Expected host %s, got %s", expectedURL.Host, pr.Out.URL.Host)
	}

	// This is the key test - the path should be "/graphql" from targetURL, not "/graphql/graphql"
	if pr.Out.URL.Path != expectedURL.Path {
		t.Errorf("Expected path %s, got %s (path should come from targetURL, not be appended)", expectedURL.Path, pr.Out.URL.Path)
		t.Logf("Full URL: %s", pr.Out.URL.String())
	}

	if pr.Out.Method != http.MethodPost {
		t.Errorf("Expected method POST, got %s", pr.Out.Method)
	}

	if pr.Out.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", pr.Out.Header.Get("Content-Type"))
	}
}

// TestGraphQLRewriteWithRootPath tests that requests to "/" are correctly rewritten
// This is what the E2E test does: POST to "/" with Host: graphql.test
func TestGraphQLRewriteWithRootPath(t *testing.T) {
	configJSON := `{
		"type": "graphql",
		"url": "http://e2e-test-server:8092/graphql"
	}`

	action, err := NewGraphQLAction([]byte(configJSON))
	if err != nil {
		t.Fatalf("Failed to create GraphQL action: %v", err)
	}

	gqlAction, ok := action.(*GraphQLAction)
	if !ok {
		t.Fatalf("Expected GraphQLAction, got %T", action)
	}

	// Create a test request to "/" (as the E2E test does)
	req := httptest.NewRequest("POST", "http://graphql.test/", strings.NewReader(`{"query":"{ __typename }"}`))
	req.Header.Set("Content-Type", "application/json")

	// Create ProxyRequest
	pr := &httputil.ProxyRequest{
		In:  req,
		Out: req.Clone(req.Context()),
	}

	// Get the Rewrite function
	rewriteFn := gqlAction.Rewrite()
	rewriteFn(pr)

	// Verify the path is "/graphql" from targetURL, not "/"
	expectedPath := "/graphql"
	if pr.Out.URL.Path != expectedPath {
		t.Errorf("Expected path %s, got %s (should use targetURL path, not incoming path)", expectedPath, pr.Out.URL.Path)
		t.Logf("Full URL: %s", pr.Out.URL.String())
		t.Logf("targetURL: %s", gqlAction.targetURL.String())
	}
}


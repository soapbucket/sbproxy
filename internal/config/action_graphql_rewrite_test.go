package config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
)

// TestGraphQLRewritePath tests that Rewrite() correctly sets the path from targetURL
func TestGraphQLRewritePath(t *testing.T) {
	configJSON := `{
		"type": "graphql",
		"url": "http://backend.example.com:8092/graphql"
	}`

	action, err := NewGraphQLAction([]byte(configJSON))
	if err != nil {
		t.Fatalf("Failed to create GraphQL action: %v", err)
	}

	gqlAction, ok := action.(*GraphQLAction)
	if !ok {
		t.Fatalf("Expected GraphQLAction, got %T", action)
	}

	// Create a test request with a different path
	req := httptest.NewRequest("POST", "http://graphql.test/", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Body = httptest.NewRequest("POST", "http://graphql.test/", nil).Body

	// Create ProxyRequest
	pr := &httputil.ProxyRequest{
		In:  req,
		Out: req.Clone(req.Context()),
	}

	// Get the Rewrite function
	rewriteFn := gqlAction.Rewrite()
	if rewriteFn == nil {
		t.Fatal("Rewrite() returned nil")
	}

	// Execute the rewrite
	rewriteFn(pr)

	// Verify the URL was set correctly
	expectedURL, _ := url.Parse("http://backend.example.com:8092/graphql")
	if pr.Out.URL.Host != expectedURL.Host {
		t.Errorf("Expected host %s, got %s", expectedURL.Host, pr.Out.URL.Host)
	}

	if pr.Out.URL.Path != expectedURL.Path {
		t.Errorf("Expected path %s, got %s", expectedURL.Path, pr.Out.URL.Path)
	}

	if pr.Out.Method != http.MethodPost {
		t.Errorf("Expected method POST, got %s", pr.Out.Method)
	}

	if pr.Out.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", pr.Out.Header.Get("Content-Type"))
	}
}

// TestGraphQLRewriteWithDifferentPath tests that incoming path doesn't override targetURL path
func TestGraphQLRewriteWithDifferentPath(t *testing.T) {
	configJSON := `{
		"type": "graphql",
		"url": "http://backend.example.com:8092/graphql"
	}`

	action, err := NewGraphQLAction([]byte(configJSON))
	if err != nil {
		t.Fatalf("Failed to create GraphQL action: %v", err)
	}

	gqlAction, ok := action.(*GraphQLAction)
	if !ok {
		t.Fatalf("Expected GraphQLAction, got %T", action)
	}

	// Create a test request with a different path (should be ignored)
	req := httptest.NewRequest("POST", "http://graphql.test/api/graphql", nil)
	req.Header.Set("Content-Type", "application/json")

	// Create ProxyRequest
	pr := &httputil.ProxyRequest{
		In:  req,
		Out: req.Clone(req.Context()),
	}

	// Get the Rewrite function
	rewriteFn := gqlAction.Rewrite()
	rewriteFn(pr)

	// Verify the path is from targetURL, not from the incoming request
	expectedPath := "/graphql"
	if pr.Out.URL.Path != expectedPath {
		t.Errorf("Expected path %s, got %s (should use targetURL path, not incoming path)", expectedPath, pr.Out.URL.Path)
	}
}

// TestGraphQLIsProxy tests that GraphQL action is treated as a proxy
func TestGraphQLIsProxy(t *testing.T) {
	configJSON := `{
		"type": "graphql",
		"url": "http://backend.example.com:8092/graphql"
	}`

	action, err := NewGraphQLAction([]byte(configJSON))
	if err != nil {
		t.Fatalf("Failed to create GraphQL action: %v", err)
	}

	gqlAction, ok := action.(*GraphQLAction)
	if !ok {
		t.Fatalf("Expected GraphQLAction, got %T", action)
	}

	// GraphQL should be treated as a proxy (has transport)
	if !gqlAction.IsProxy() {
		t.Error("GraphQL action should return true for IsProxy()")
	}

	// Verify transport is set
	if gqlAction.tr == nil {
		t.Error("GraphQL action should have a transport set")
	}
}

// TestGraphQLConfigIsProxy tests IsProxy() through the Config interface
func TestGraphQLConfigIsProxy(t *testing.T) {
	configJSON := `{
		"id": "test-graphql",
		"hostname": "graphql.test",
		"action": {
			"type": "graphql",
			"url": "http://backend.example.com:8092/graphql"
		}
	}`

	var cfg Config
	err := json.Unmarshal([]byte(configJSON), &cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Config.IsProxy() should return true for GraphQL
	if !cfg.IsProxy() {
		t.Error("Config.IsProxy() should return true for GraphQL")
	}

	// Verify it uses proxy mode (Transport) rather than handler mode
	// GraphQL uses Transport() for proxying, not Handler()
	transport := cfg.Transport()
	if transport == nil {
		t.Error("Transport() should not return nil for GraphQL (should use proxy mode)")
	}

	// Config.Handler() always returns a handler (wraps nil in 404 handler),
	// but GraphQL should use Transport() for actual proxying
	handler := cfg.Handler()
	if handler == nil {
		t.Error("Config.Handler() should not return nil (wraps in 404 handler)")
	}
}


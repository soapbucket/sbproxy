package config

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExecutorSingleStep(t *testing.T) {
	// Create a mock subgraph server.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"product": map[string]interface{}{
					"id":   "1",
					"name": "Widget",
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	subgraphs := map[string]*Subgraph{
		"products": {
			Name: "products",
			URL:  server.URL,
		},
	}

	executor := NewExecutor(subgraphs, server.Client())

	plan := &QueryPlan{
		Steps: []QueryStep{
			{
				Subgraph: "products",
				Query:    `query { product(id: "1") { id name } }`,
			},
		},
	}

	result, err := executor.Execute(context.Background(), plan, nil)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("failed to parse result: %v", err)
	}

	data, ok := parsed["data"].(map[string]interface{})
	if !ok {
		t.Fatal("result missing data field")
	}

	product, ok := data["product"].(map[string]interface{})
	if !ok {
		t.Fatal("result missing product field")
	}

	if product["name"] != "Widget" {
		t.Errorf("product name = %v, want Widget", product["name"])
	}
}

func TestExecutorMultipleSteps(t *testing.T) {
	// Create mock subgraph servers.
	productsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"product": map[string]interface{}{
					"id":   "1",
					"name": "Widget",
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer productsServer.Close()

	reviewsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"reviews": []interface{}{
					map[string]interface{}{
						"id":   "r1",
						"body": "Great product!",
					},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer reviewsServer.Close()

	subgraphs := map[string]*Subgraph{
		"products": {Name: "products", URL: productsServer.URL},
		"reviews":  {Name: "reviews", URL: reviewsServer.URL},
	}

	executor := NewExecutor(subgraphs, nil)

	plan := &QueryPlan{
		Steps: []QueryStep{
			{
				Subgraph: "products",
				Query:    `query { product(id: "1") { id name } }`,
			},
			{
				Subgraph: "reviews",
				Query:    `query { reviews(productId: "1") { id body } }`,
			},
		},
	}

	result, err := executor.Execute(context.Background(), plan, nil)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("failed to parse result: %v", err)
	}

	data, ok := parsed["data"].(map[string]interface{})
	if !ok {
		t.Fatal("result missing data field")
	}

	// Both product and reviews should be in the merged result.
	if _, ok := data["product"]; !ok {
		t.Error("merged result missing product field")
	}
	if _, ok := data["reviews"]; !ok {
		t.Error("merged result missing reviews field")
	}
}

func TestExecutorWithVariables(t *testing.T) {
	var receivedVars map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)

		if vars, ok := body["variables"]; ok {
			receivedVars, _ = vars.(map[string]interface{})
		}

		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"product": map[string]interface{}{"id": "1"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	subgraphs := map[string]*Subgraph{
		"products": {Name: "products", URL: server.URL},
	}

	executor := NewExecutor(subgraphs, server.Client())

	plan := &QueryPlan{
		Steps: []QueryStep{
			{Subgraph: "products", Query: `query($id: ID!) { product(id: $id) { id } }`},
		},
	}

	variables := json.RawMessage(`{"id": "42"}`)
	_, err := executor.Execute(context.Background(), plan, variables)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if receivedVars == nil {
		t.Fatal("subgraph did not receive variables")
	}
	if receivedVars["id"] != "42" {
		t.Errorf("variable id = %v, want 42", receivedVars["id"])
	}
}

func TestExecutorEmptyPlan(t *testing.T) {
	executor := NewExecutor(map[string]*Subgraph{}, nil)

	_, err := executor.Execute(context.Background(), nil, nil)
	if err == nil {
		t.Error("Execute() should fail with nil plan")
	}

	_, err = executor.Execute(context.Background(), &QueryPlan{}, nil)
	if err == nil {
		t.Error("Execute() should fail with empty plan")
	}
}

func TestExecutorSubgraphNotFound(t *testing.T) {
	executor := NewExecutor(map[string]*Subgraph{}, nil)

	plan := &QueryPlan{
		Steps: []QueryStep{
			{Subgraph: "nonexistent", Query: `{ hello }`},
		},
	}

	_, err := executor.Execute(context.Background(), plan, nil)
	if err == nil {
		t.Error("Execute() should fail when subgraph is not found")
	}
}

func TestExecutorSubgraphError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	subgraphs := map[string]*Subgraph{
		"broken": {Name: "broken", URL: server.URL},
	}

	executor := NewExecutor(subgraphs, server.Client())

	plan := &QueryPlan{
		Steps: []QueryStep{
			{Subgraph: "broken", Query: `{ hello }`},
		},
	}

	_, err := executor.Execute(context.Background(), plan, nil)
	if err == nil {
		t.Error("Execute() should fail when subgraph returns error status")
	}
}

func TestExecutorDependentStepFailure(t *testing.T) {
	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"data": map[string]interface{}{"ok": true},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer goodServer.Close()

	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("bad gateway"))
	}))
	defer badServer.Close()

	subgraphs := map[string]*Subgraph{
		"good": {Name: "good", URL: goodServer.URL},
		"bad":  {Name: "bad", URL: badServer.URL},
	}

	executor := NewExecutor(subgraphs, nil)

	plan := &QueryPlan{
		Steps: []QueryStep{
			{Subgraph: "good", Query: `{ ok }`},
			{Subgraph: "bad", Query: `{ fail }`, DependsOn: []int{0}},
		},
	}

	_, err := executor.Execute(context.Background(), plan, nil)
	if err == nil {
		t.Error("Execute() should fail when a dependent step fails")
	}
}

func TestExecutorSubgraphHeaders(t *testing.T) {
	var receivedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"data": map[string]interface{}{"ok": true},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	subgraphs := map[string]*Subgraph{
		"auth": {
			Name: "auth",
			URL:  server.URL,
			Headers: map[string]string{
				"Authorization": "Bearer secret-token",
				"X-Custom":      "custom-value",
			},
		},
	}

	executor := NewExecutor(subgraphs, server.Client())

	plan := &QueryPlan{
		Steps: []QueryStep{
			{Subgraph: "auth", Query: `{ me { id } }`},
		},
	}

	_, err := executor.Execute(context.Background(), plan, nil)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if receivedHeaders.Get("Authorization") != "Bearer secret-token" {
		t.Errorf("Authorization header = %q, want Bearer secret-token", receivedHeaders.Get("Authorization"))
	}
	if receivedHeaders.Get("X-Custom") != "custom-value" {
		t.Errorf("X-Custom header = %q, want custom-value", receivedHeaders.Get("X-Custom"))
	}
}

func TestMergeResults(t *testing.T) {
	t.Run("single result", func(t *testing.T) {
		input := []json.RawMessage{
			json.RawMessage(`{"data":{"product":{"id":"1"}}}`),
		}
		result, err := mergeResults(input)
		if err != nil {
			t.Fatalf("mergeResults() error = %v", err)
		}

		var parsed map[string]interface{}
		json.Unmarshal(result, &parsed)
		data := parsed["data"].(map[string]interface{})
		if _, ok := data["product"]; !ok {
			t.Error("result missing product field")
		}
	})

	t.Run("multiple results merged", func(t *testing.T) {
		input := []json.RawMessage{
			json.RawMessage(`{"data":{"product":{"id":"1","name":"Widget"}}}`),
			json.RawMessage(`{"data":{"reviews":[{"id":"r1"}]}}`),
		}
		result, err := mergeResults(input)
		if err != nil {
			t.Fatalf("mergeResults() error = %v", err)
		}

		var parsed map[string]interface{}
		json.Unmarshal(result, &parsed)
		data := parsed["data"].(map[string]interface{})
		if _, ok := data["product"]; !ok {
			t.Error("merged result missing product")
		}
		if _, ok := data["reviews"]; !ok {
			t.Error("merged result missing reviews")
		}
	})

	t.Run("errors collected", func(t *testing.T) {
		input := []json.RawMessage{
			json.RawMessage(`{"data":{"product":null},"errors":[{"message":"not found"}]}`),
		}
		result, err := mergeResults(input)
		if err != nil {
			t.Fatalf("mergeResults() error = %v", err)
		}

		var parsed map[string]interface{}
		json.Unmarshal(result, &parsed)
		errs, ok := parsed["errors"].([]interface{})
		if !ok || len(errs) == 0 {
			t.Error("merged result should contain errors")
		}
	})

	t.Run("empty results", func(t *testing.T) {
		_, err := mergeResults(nil)
		if err == nil {
			t.Error("mergeResults() should fail with empty input")
		}
	})
}

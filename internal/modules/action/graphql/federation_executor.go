// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package graphql

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Executor executes a query plan against subgraphs.
type Executor struct {
	subgraphs map[string]*Subgraph
	client    *http.Client
}

// NewExecutor creates a new Executor.
func NewExecutor(subgraphs map[string]*Subgraph, client *http.Client) *Executor {
	if client == nil {
		client = &http.Client{
			Timeout: 30 * time.Second,
		}
	}
	return &Executor{
		subgraphs: subgraphs,
		client:    client,
	}
}

// Execute runs a query plan and merges results.
func (e *Executor) Execute(ctx context.Context, plan *QueryPlan, variables json.RawMessage) (json.RawMessage, error) {
	if plan == nil || len(plan.Steps) == 0 {
		return nil, fmt.Errorf("federation executor: empty query plan")
	}

	results := make([]json.RawMessage, len(plan.Steps))
	errors := make([]error, len(plan.Steps))

	// Build dependency graph: steps with no dependencies can run concurrently.
	// Steps with dependencies wait for their prerequisite steps.
	ready := make([]bool, len(plan.Steps))
	for i, step := range plan.Steps {
		ready[i] = len(step.DependsOn) == 0
	}

	// Execute ready steps concurrently.
	var wg sync.WaitGroup
	var mu sync.Mutex

	// First pass: execute all steps with no dependencies.
	for i, step := range plan.Steps {
		if !ready[i] {
			continue
		}
		wg.Add(1)
		go func(idx int, s QueryStep) {
			defer wg.Done()
			result, err := e.executeStep(ctx, &s, variables)
			mu.Lock()
			results[idx] = result
			errors[idx] = err
			mu.Unlock()
		}(i, step)
	}
	wg.Wait()

	// Check for errors in the first pass.
	for i, err := range errors {
		if ready[i] && err != nil {
			return nil, fmt.Errorf("federation executor: step %d (%s) failed: %w", i, plan.Steps[i].Subgraph, err)
		}
	}

	// Second pass: execute dependent steps.
	for i, step := range plan.Steps {
		if ready[i] {
			continue
		}

		// Verify dependencies completed.
		for _, dep := range step.DependsOn {
			if errors[dep] != nil {
				return nil, fmt.Errorf("federation executor: step %d depends on failed step %d: %w", i, dep, errors[dep])
			}
		}

		result, err := e.executeStep(ctx, &step, variables)
		results[i] = result
		errors[i] = err
		if err != nil {
			return nil, fmt.Errorf("federation executor: step %d (%s) failed: %w", i, step.Subgraph, err)
		}
	}

	// Merge results from all steps.
	merged, err := mergeResults(results)
	if err != nil {
		return nil, fmt.Errorf("federation executor: merge failed: %w", err)
	}

	return merged, nil
}

// executeStep sends a GraphQL query to a subgraph and returns the result.
func (e *Executor) executeStep(ctx context.Context, step *QueryStep, variables json.RawMessage) (json.RawMessage, error) {
	sg, ok := e.subgraphs[step.Subgraph]
	if !ok {
		return nil, fmt.Errorf("subgraph %q not found", step.Subgraph)
	}

	// Build the GraphQL request body.
	reqBody := map[string]interface{}{
		"query": step.Query,
	}
	if variables != nil {
		var vars interface{}
		if err := json.Unmarshal(variables, &vars); err == nil {
			reqBody["variables"] = vars
		}
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sg.URL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Apply subgraph-specific headers.
	for k, v := range sg.Headers {
		req.Header.Set(k, v)
	}

	slog.Debug("federation: executing step", "subgraph", step.Subgraph, "url", sg.URL)

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request to subgraph %q failed: %w", step.Subgraph, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response from subgraph %q: %w", step.Subgraph, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("subgraph %q returned status %d: %s", step.Subgraph, resp.StatusCode, string(respBody))
	}

	return json.RawMessage(respBody), nil
}

// mergeResults combines results from multiple subgraph responses into a single response.
func mergeResults(results []json.RawMessage) (json.RawMessage, error) {
	if len(results) == 0 {
		return nil, fmt.Errorf("no results to merge")
	}

	// If only one result, return it directly.
	if len(results) == 1 {
		return results[0], nil
	}

	// Merge data fields from all results.
	merged := make(map[string]interface{})
	var mergedErrors []interface{}

	for _, raw := range results {
		if raw == nil {
			continue
		}

		var result map[string]interface{}
		if err := json.Unmarshal(raw, &result); err != nil {
			return nil, fmt.Errorf("failed to parse subgraph result: %w", err)
		}

		// Merge data.
		if data, ok := result["data"].(map[string]interface{}); ok {
			if _, exists := merged["data"]; !exists {
				merged["data"] = make(map[string]interface{})
			}
			mergedData := merged["data"].(map[string]interface{})
			for k, v := range data {
				mergedData[k] = v
			}
		}

		// Collect errors.
		if errs, ok := result["errors"].([]interface{}); ok {
			mergedErrors = append(mergedErrors, errs...)
		}
	}

	if len(mergedErrors) > 0 {
		merged["errors"] = mergedErrors
	}

	return json.Marshal(merged)
}

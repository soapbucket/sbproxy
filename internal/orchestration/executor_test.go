package orchestration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/config/callback"
)

// newTestCallback creates a callback pointing at the given URL
func newTestCallback(url, method string) *callback.Callback {
	if method == "" {
		method = "GET"
	}
	return &callback.Callback{
		URL:    url,
		Method: method,
	}
}

// newTestServer returns an httptest.Server that responds with the given JSON body
func newTestServer(statusCode int, body map[string]any) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		json.NewEncoder(w).Encode(body)
	}))
}

// newDelayedTestServer responds after a configurable delay
func newDelayedTestServer(delay time.Duration, body map[string]any) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(body)
	}))
}

// newCountingServer tracks how many requests it has received
func newCountingServer(counter *atomic.Int32, body map[string]any) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counter.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(body)
	}))
}

// newFailThenSucceedServer fails the first N requests, then succeeds
func newFailThenSucceedServer(failCount *atomic.Int32, body map[string]any) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remaining := failCount.Add(-1)
		if remaining >= 0 {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "temporary failure"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(body)
	}))
}

// TestExecutor_SingleStep tests executing a single step
func TestExecutor_SingleStep(t *testing.T) {
	srv := newTestServer(200, map[string]any{"name": "Alice", "id": 1})
	defer srv.Close()

	executor, err := NewBuilder().
		WithSteps([]Step{
			BuildStepFromCallback("get_user", newTestCallback(srv.URL, "GET"), nil, "", nil, nil),
		}).
		WithResponseBuilder(BuildResponseBuilder(
			`{"user": "ok", "duration": {{ total_duration }}}`,
			"application/json", 200, nil,
		)).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := executor.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if len(body) == 0 {
		t.Error("Response body should not be empty")
	}
}

// TestExecutor_SequentialSteps tests executing multiple steps sequentially
func TestExecutor_SequentialSteps(t *testing.T) {
	srv1 := newTestServer(200, map[string]any{"name": "Alice"})
	defer srv1.Close()
	srv2 := newTestServer(200, map[string]any{"items": []string{"a", "b"}})
	defer srv2.Close()

	executor, err := NewBuilder().
		WithSteps([]Step{
			BuildStepFromCallback("step1", newTestCallback(srv1.URL, "GET"), nil, "", nil, nil),
			BuildStepFromCallback("step2", newTestCallback(srv2.URL, "GET"), []string{"step1"}, "", nil, nil),
		}).
		WithResponseBuilder(BuildResponseBuilder(
			`{"status": "complete"}`,
			"application/json", 200, nil,
		)).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := executor.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

// TestExecutor_ParallelSteps tests that independent steps run in parallel
func TestExecutor_ParallelSteps(t *testing.T) {
	delay := 100 * time.Millisecond

	srv1 := newDelayedTestServer(delay, map[string]any{"source": "api1"})
	defer srv1.Close()
	srv2 := newDelayedTestServer(delay, map[string]any{"source": "api2"})
	defer srv2.Close()
	srv3 := newDelayedTestServer(delay, map[string]any{"source": "api3"})
	defer srv3.Close()

	executor, err := NewBuilder().
		WithSteps([]Step{
			BuildStepFromCallback("api1", newTestCallback(srv1.URL, "GET"), nil, "", nil, nil),
			BuildStepFromCallback("api2", newTestCallback(srv2.URL, "GET"), nil, "", nil, nil),
			BuildStepFromCallback("api3", newTestCallback(srv3.URL, "GET"), nil, "", nil, nil),
		}).
		WithParallel(true).
		WithResponseBuilder(BuildResponseBuilder(
			`{"status": "ok"}`,
			"application/json", 200, nil,
		)).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	start := time.Now()
	resp, err := executor.Execute(context.Background(), req)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// In parallel, 3 steps of 100ms each should complete in ~100ms, not ~300ms
	// Use generous threshold to avoid flaky tests
	if elapsed > 250*time.Millisecond {
		t.Errorf("Parallel execution took %v, expected less than 250ms (3 x 100ms steps should overlap)", elapsed)
	}
}

// TestExecutor_DependencyOrder tests that dependencies are respected
func TestExecutor_DependencyOrder(t *testing.T) {
	var callOrder []string
	var orderMu = &atomic.Int32{}

	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		orderMu.Add(1)
		callOrder = append(callOrder, "a")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"step": "a"})
	}))
	defer srvA.Close()

	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		orderMu.Add(1)
		callOrder = append(callOrder, "b")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"step": "b"})
	}))
	defer srvB.Close()

	srvC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		orderMu.Add(1)
		callOrder = append(callOrder, "c")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"step": "c"})
	}))
	defer srvC.Close()

	executor, err := NewBuilder().
		WithSteps([]Step{
			BuildStepFromCallback("a", newTestCallback(srvA.URL, "GET"), nil, "", nil, nil),
			BuildStepFromCallback("b", newTestCallback(srvB.URL, "GET"), []string{"a"}, "", nil, nil),
			BuildStepFromCallback("c", newTestCallback(srvC.URL, "GET"), []string{"b"}, "", nil, nil),
		}).
		WithResponseBuilder(BuildResponseBuilder(
			`{"done": true}`,
			"application/json", 200, nil,
		)).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	_, err = executor.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Sequential: a must come before b, b before c
	if len(callOrder) != 3 {
		t.Fatalf("Expected 3 calls, got %d", len(callOrder))
	}

	aIdx, bIdx, cIdx := -1, -1, -1
	for i, name := range callOrder {
		switch name {
		case "a":
			aIdx = i
		case "b":
			bIdx = i
		case "c":
			cIdx = i
		}
	}

	if aIdx >= bIdx || bIdx >= cIdx {
		t.Errorf("Expected order a < b < c, got: %v", callOrder)
	}
}

// TestExecutor_Timeout tests that workflow timeout is enforced
func TestExecutor_Timeout(t *testing.T) {
	srv := newDelayedTestServer(500*time.Millisecond, map[string]any{"slow": true})
	defer srv.Close()

	executor, err := NewBuilder().
		WithSteps([]Step{
			BuildStepFromCallback("slow_step", newTestCallback(srv.URL, "GET"), nil, "", nil, nil),
		}).
		WithTimeout(100 * time.Millisecond).
		WithResponseBuilder(BuildResponseBuilder(
			`{"status": "ok"}`,
			"application/json", 200, nil,
		)).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	_, err = executor.Execute(context.Background(), req)
	if err == nil {
		t.Fatal("Expected timeout error, got nil")
	}
}

// TestExecutor_ContinueOnError tests that continue_on_error works
func TestExecutor_ContinueOnError(t *testing.T) {
	srvGood := newTestServer(200, map[string]any{"ok": true})
	defer srvGood.Close()

	// Server that always fails
	srvBad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "server error"}`))
	}))
	defer srvBad.Close()

	t.Run("StopOnError", func(t *testing.T) {
		executor, err := NewBuilder().
			WithSteps([]Step{
				BuildStepFromCallback("fail_step", newTestCallback(srvBad.URL, "GET"), nil, "", nil, nil),
				BuildStepFromCallback("good_step", newTestCallback(srvGood.URL, "GET"), nil, "", nil, nil),
			}).
			WithContinueOnError(false).
			WithResponseBuilder(BuildResponseBuilder(
				`{"status": "ok"}`,
				"application/json", 200, nil,
			)).
			Build()

		if err != nil {
			t.Fatalf("Build failed: %v", err)
		}

		req := httptest.NewRequest("GET", "/test", nil)
		_, err = executor.Execute(context.Background(), req)
		if err == nil {
			t.Error("Expected error when continue_on_error is false")
		}
	})

	t.Run("ContinueOnError", func(t *testing.T) {
		executor, err := NewBuilder().
			WithSteps([]Step{
				BuildStepFromCallback("fail_step", newTestCallback(srvBad.URL, "GET"), nil, "", nil, nil),
				BuildStepFromCallback("good_step", newTestCallback(srvGood.URL, "GET"), nil, "", nil, nil),
			}).
			WithContinueOnError(true).
			WithResponseBuilder(BuildResponseBuilder(
				`{"error_count": {{ error_count }}}`,
				"application/json", 200, nil,
			)).
			Build()

		if err != nil {
			t.Fatalf("Build failed: %v", err)
		}

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := executor.Execute(context.Background(), req)
		if err != nil {
			t.Fatalf("Execute should not return error when continue_on_error is true, got: %v", err)
		}

		if resp.StatusCode != 200 {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})
}

// TestExecutor_StepLevelContinueOnError tests per-step continue_on_error override
func TestExecutor_StepLevelContinueOnError(t *testing.T) {
	srvGood := newTestServer(200, map[string]any{"ok": true})
	defer srvGood.Close()

	srvBad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "server error"}`))
	}))
	defer srvBad.Close()

	// Orchestration-level: stop on error
	// But the failing step overrides to continue
	continueTrue := true
	executor, err := NewBuilder().
		WithSteps([]Step{
			BuildStepFromCallback("optional_fail", newTestCallback(srvBad.URL, "GET"), nil, "", &continueTrue, nil),
			BuildStepFromCallback("must_succeed", newTestCallback(srvGood.URL, "GET"), nil, "", nil, nil),
		}).
		WithContinueOnError(false).
		WithResponseBuilder(BuildResponseBuilder(
			`{"status": "ok"}`,
			"application/json", 200, nil,
		)).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := executor.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute should succeed because step-level continue_on_error=true: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

// TestExecutor_Condition tests conditional step execution
func TestExecutor_Condition(t *testing.T) {
	var counter atomic.Int32

	srv := newCountingServer(&counter, map[string]any{"ok": true})
	defer srv.Close()

	t.Run("ConditionTrue", func(t *testing.T) {
		counter.Store(0)

		executor, err := NewBuilder().
			WithSteps([]Step{
				BuildStepFromCallback("always", newTestCallback(srv.URL, "GET"), nil, "", nil, nil),
				BuildStepFromCallback("conditional", newTestCallback(srv.URL, "GET"), nil, "true", nil, nil),
			}).
			WithResponseBuilder(BuildResponseBuilder(
				`{"ok": true}`,
				"application/json", 200, nil,
			)).
			Build()

		if err != nil {
			t.Fatalf("Build failed: %v", err)
		}

		req := httptest.NewRequest("GET", "/test", nil)
		_, err = executor.Execute(context.Background(), req)
		if err != nil {
			t.Fatalf("Execute failed: %v", err)
		}

		if counter.Load() != 2 {
			t.Errorf("Expected 2 calls (both steps), got %d", counter.Load())
		}
	})

	t.Run("ConditionFalse", func(t *testing.T) {
		counter.Store(0)

		executor, err := NewBuilder().
			WithSteps([]Step{
				BuildStepFromCallback("always", newTestCallback(srv.URL, "GET"), nil, "", nil, nil),
				BuildStepFromCallback("skipped", newTestCallback(srv.URL, "GET"), nil, "false", nil, nil),
			}).
			WithResponseBuilder(BuildResponseBuilder(
				`{"ok": true}`,
				"application/json", 200, nil,
			)).
			Build()

		if err != nil {
			t.Fatalf("Build failed: %v", err)
		}

		req := httptest.NewRequest("GET", "/test", nil)
		_, err = executor.Execute(context.Background(), req)
		if err != nil {
			t.Fatalf("Execute failed: %v", err)
		}

		if counter.Load() != 1 {
			t.Errorf("Expected 1 call (conditional step should be skipped), got %d", counter.Load())
		}
	})
}

// TestExecutor_ResponseBuilder tests custom response building
func TestExecutor_ResponseBuilder(t *testing.T) {
	srv := newTestServer(200, map[string]any{"name": "Alice", "age": 30})
	defer srv.Close()

	executor, err := NewBuilder().
		WithSteps([]Step{
			BuildStepFromCallback("get_user", newTestCallback(srv.URL, "GET"), nil, "", nil, nil),
		}).
		WithResponseBuilder(BuildResponseBuilder(
			`{"fetched": true}`,
			"text/plain",
			201,
			map[string]string{"X-Custom": "orchestrated"},
		)).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := executor.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if resp.StatusCode != 201 {
		t.Errorf("Expected status 201, got %d", resp.StatusCode)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "text/plain" {
		t.Errorf("Expected Content-Type text/plain, got %s", ct)
	}

	if custom := resp.Header.Get("X-Custom"); custom != "orchestrated" {
		t.Errorf("Expected X-Custom=orchestrated, got %s", custom)
	}
}

// TestExecutor_RetryOnFailure tests step retry with exponential backoff
func TestExecutor_RetryOnFailure(t *testing.T) {
	var failCount atomic.Int32
	failCount.Store(2) // Fail first 2 requests

	srv := newFailThenSucceedServer(&failCount, map[string]any{"recovered": true})
	defer srv.Close()

	retryConfig := BuildRetryConfig(3, "exponential", 10*time.Millisecond, 100*time.Millisecond)

	executor, err := NewBuilder().
		WithSteps([]Step{
			BuildStepFromCallback("retry_step", newTestCallback(srv.URL, "GET"), nil, "", nil, retryConfig),
		}).
		WithResponseBuilder(BuildResponseBuilder(
			`{"status": "ok"}`,
			"application/json", 200, nil,
		)).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := executor.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute failed (should have recovered after retries): %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

// TestExecutor_RetryExhausted tests that exhausted retries produce an error
func TestExecutor_RetryExhausted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "always fails"}`))
	}))
	defer srv.Close()

	retryConfig := BuildRetryConfig(2, "fixed", 10*time.Millisecond, 10*time.Millisecond)

	executor, err := NewBuilder().
		WithSteps([]Step{
			BuildStepFromCallback("doomed", newTestCallback(srv.URL, "GET"), nil, "", nil, retryConfig),
		}).
		WithResponseBuilder(BuildResponseBuilder(
			`{"status": "ok"}`,
			"application/json", 200, nil,
		)).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	_, err = executor.Execute(context.Background(), req)
	if err == nil {
		t.Fatal("Expected error after exhausting retries")
	}
}

// TestExecutor_ContextCancellation tests that cancelled context stops execution
func TestExecutor_ContextCancellation(t *testing.T) {
	srv := newDelayedTestServer(1*time.Second, map[string]any{"slow": true})
	defer srv.Close()

	executor, err := NewBuilder().
		WithSteps([]Step{
			BuildStepFromCallback("slow", newTestCallback(srv.URL, "GET"), nil, "", nil, nil),
		}).
		WithResponseBuilder(BuildResponseBuilder(
			`{"ok": true}`,
			"application/json", 200, nil,
		)).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	req := httptest.NewRequest("GET", "/test", nil).WithContext(ctx)
	_, err = executor.Execute(ctx, req)
	if err == nil {
		t.Fatal("Expected context cancellation error")
	}
}

// TestBuilder_Validation tests builder validation
func TestBuilder_Validation(t *testing.T) {
	t.Run("NoSteps", func(t *testing.T) {
		_, err := NewBuilder().
			WithResponseBuilder(BuildResponseBuilder(`{}`, "", 200, nil)).
			Build()

		if err == nil {
			t.Error("Expected error for empty steps")
		}
	})

	t.Run("NoResponseBuilder", func(t *testing.T) {
		_, err := NewBuilder().
			WithSteps([]Step{
				BuildStepFromCallback("a", newTestCallback("http://example.com", "GET"), nil, "", nil, nil),
			}).
			Build()

		if err == nil {
			t.Error("Expected error for missing response builder")
		}
	})

	t.Run("DuplicateStepNames", func(t *testing.T) {
		_, err := NewBuilder().
			WithSteps([]Step{
				BuildStepFromCallback("dup", newTestCallback("http://example.com", "GET"), nil, "", nil, nil),
				BuildStepFromCallback("dup", newTestCallback("http://example.com", "GET"), nil, "", nil, nil),
			}).
			WithResponseBuilder(BuildResponseBuilder(`{}`, "", 200, nil)).
			Build()

		if err == nil {
			t.Error("Expected error for duplicate step names")
		}
	})

	t.Run("EmptyStepName", func(t *testing.T) {
		_, err := NewBuilder().
			WithSteps([]Step{
				BuildStepFromCallback("", newTestCallback("http://example.com", "GET"), nil, "", nil, nil),
			}).
			WithResponseBuilder(BuildResponseBuilder(`{}`, "", 200, nil)).
			Build()

		if err == nil {
			t.Error("Expected error for empty step name")
		}
	})

	t.Run("CircularDependency", func(t *testing.T) {
		_, err := NewBuilder().
			WithSteps([]Step{
				BuildStepFromCallback("a", newTestCallback("http://example.com", "GET"), []string{"b"}, "", nil, nil),
				BuildStepFromCallback("b", newTestCallback("http://example.com", "GET"), []string{"a"}, "", nil, nil),
			}).
			WithResponseBuilder(BuildResponseBuilder(`{}`, "", 200, nil)).
			Build()

		if err == nil {
			t.Error("Expected error for circular dependency")
		}
	})

	t.Run("UnknownDependency", func(t *testing.T) {
		_, err := NewBuilder().
			WithSteps([]Step{
				BuildStepFromCallback("a", newTestCallback("http://example.com", "GET"), []string{"nonexistent"}, "", nil, nil),
			}).
			WithResponseBuilder(BuildResponseBuilder(`{}`, "", 200, nil)).
			Build()

		if err == nil {
			t.Error("Expected error for unknown dependency")
		}
	})
}

// TestBuildRetryConfig tests retry config builder defaults
func TestBuildRetryConfig(t *testing.T) {
	t.Run("Defaults", func(t *testing.T) {
		rc := BuildRetryConfig(0, "", 0, 0)
		if rc.maxAttempts != 3 {
			t.Errorf("Default maxAttempts should be 3, got %d", rc.maxAttempts)
		}
		if rc.backoff != "exponential" {
			t.Errorf("Default backoff should be 'exponential', got '%s'", rc.backoff)
		}
		if rc.initialDelay != 100*time.Millisecond {
			t.Errorf("Default initialDelay should be 100ms, got %v", rc.initialDelay)
		}
		if rc.maxDelay != 10*time.Second {
			t.Errorf("Default maxDelay should be 10s, got %v", rc.maxDelay)
		}
	})

	t.Run("CustomValues", func(t *testing.T) {
		rc := BuildRetryConfig(5, "fixed", 200*time.Millisecond, 5*time.Second)
		if rc.maxAttempts != 5 {
			t.Errorf("Expected maxAttempts=5, got %d", rc.maxAttempts)
		}
		if rc.backoff != "fixed" {
			t.Errorf("Expected backoff='fixed', got '%s'", rc.backoff)
		}
		if rc.initialDelay != 200*time.Millisecond {
			t.Errorf("Expected initialDelay=200ms, got %v", rc.initialDelay)
		}
		if rc.maxDelay != 5*time.Second {
			t.Errorf("Expected maxDelay=5s, got %v", rc.maxDelay)
		}
	})
}

// TestCalculateRetryDelay tests retry delay calculation
func TestCalculateRetryDelay(t *testing.T) {
	executor := &Executor{}

	t.Run("NilRetry", func(t *testing.T) {
		step := Step{name: "test"}
		delay := executor.calculateRetryDelay(step, 1)
		if delay != 100*time.Millisecond {
			t.Errorf("Expected 100ms default delay, got %v", delay)
		}
	})

	t.Run("ExponentialBackoff", func(t *testing.T) {
		step := Step{
			name: "test",
			retry: &RetryConfig{
				maxAttempts:  5,
				backoff:      "exponential",
				initialDelay: 100 * time.Millisecond,
				maxDelay:     10 * time.Second,
			},
		}

		delay1 := executor.calculateRetryDelay(step, 1)
		delay2 := executor.calculateRetryDelay(step, 2)
		delay3 := executor.calculateRetryDelay(step, 3)

		if delay1 != 100*time.Millisecond {
			t.Errorf("Attempt 1: expected 100ms, got %v", delay1)
		}
		if delay2 != 200*time.Millisecond {
			t.Errorf("Attempt 2: expected 200ms, got %v", delay2)
		}
		if delay3 != 400*time.Millisecond {
			t.Errorf("Attempt 3: expected 400ms, got %v", delay3)
		}
	})

	t.Run("FixedBackoff", func(t *testing.T) {
		step := Step{
			name: "test",
			retry: &RetryConfig{
				maxAttempts:  3,
				backoff:      "fixed",
				initialDelay: 500 * time.Millisecond,
				maxDelay:     10 * time.Second,
			},
		}

		delay1 := executor.calculateRetryDelay(step, 1)
		delay2 := executor.calculateRetryDelay(step, 2)

		// Fixed backoff: delay should not increase
		if delay1 != 500*time.Millisecond {
			t.Errorf("Attempt 1: expected 500ms, got %v", delay1)
		}
		if delay2 != 500*time.Millisecond {
			t.Errorf("Attempt 2: expected 500ms, got %v", delay2)
		}
	})

	t.Run("MaxDelayCap", func(t *testing.T) {
		step := Step{
			name: "test",
			retry: &RetryConfig{
				maxAttempts:  10,
				backoff:      "exponential",
				initialDelay: 1 * time.Second,
				maxDelay:     5 * time.Second,
			},
		}

		delay := executor.calculateRetryDelay(step, 5)
		if delay > 5*time.Second {
			t.Errorf("Delay should be capped at maxDelay (5s), got %v", delay)
		}
	})
}

// TestExecutor_ParallelWithDependencies tests parallel mode with a diamond dependency pattern
func TestExecutor_ParallelWithDependencies(t *testing.T) {
	delay := 50 * time.Millisecond

	srvA := newDelayedTestServer(delay, map[string]any{"step": "a"})
	defer srvA.Close()
	srvB := newDelayedTestServer(delay, map[string]any{"step": "b"})
	defer srvB.Close()
	srvC := newDelayedTestServer(delay, map[string]any{"step": "c"})
	defer srvC.Close()
	srvD := newDelayedTestServer(delay, map[string]any{"step": "d"})
	defer srvD.Close()

	// Diamond: A -> B, A -> C, B+C -> D
	executor, err := NewBuilder().
		WithSteps([]Step{
			BuildStepFromCallback("a", newTestCallback(srvA.URL, "GET"), nil, "", nil, nil),
			BuildStepFromCallback("b", newTestCallback(srvB.URL, "GET"), []string{"a"}, "", nil, nil),
			BuildStepFromCallback("c", newTestCallback(srvC.URL, "GET"), []string{"a"}, "", nil, nil),
			BuildStepFromCallback("d", newTestCallback(srvD.URL, "GET"), []string{"b", "c"}, "", nil, nil),
		}).
		WithParallel(true).
		WithResponseBuilder(BuildResponseBuilder(
			`{"done": true}`,
			"application/json", 200, nil,
		)).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	start := time.Now()
	resp, err := executor.Execute(context.Background(), req)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Diamond pattern with 50ms per step:
	// Level 0: A (50ms)
	// Level 1: B, C in parallel (50ms)
	// Level 2: D (50ms)
	// Total: ~150ms, not ~200ms (which would be fully sequential)
	if elapsed > 300*time.Millisecond {
		t.Errorf("Diamond pattern took %v, expected less than 300ms", elapsed)
	}

	fmt.Printf("Diamond dependency pattern completed in %v\n", elapsed)
}

// TestExecutor_EmptyConditionAlwaysRuns confirms empty condition means always execute
func TestExecutor_EmptyConditionAlwaysRuns(t *testing.T) {
	var counter atomic.Int32
	srv := newCountingServer(&counter, map[string]any{"ok": true})
	defer srv.Close()

	executor, err := NewBuilder().
		WithSteps([]Step{
			BuildStepFromCallback("no_condition", newTestCallback(srv.URL, "GET"), nil, "", nil, nil),
		}).
		WithResponseBuilder(BuildResponseBuilder(`{"ok": true}`, "application/json", 200, nil)).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	_, err = executor.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if counter.Load() != 1 {
		t.Errorf("Step with no condition should always run, got %d calls", counter.Load())
	}
}

// TestExecutor_ResponseHTTPFields tests that buildResponse returns a complete HTTP response
func TestExecutor_ResponseHTTPFields(t *testing.T) {
	srv := newTestServer(200, map[string]any{"ok": true})
	defer srv.Close()

	executor, err := NewBuilder().
		WithSteps([]Step{
			BuildStepFromCallback("step", newTestCallback(srv.URL, "GET"), nil, "", nil, nil),
		}).
		WithResponseBuilder(BuildResponseBuilder(`{"result": "ok"}`, "application/json", 201, nil)).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := executor.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if resp.StatusCode != 201 {
		t.Errorf("StatusCode = %d, want 201", resp.StatusCode)
	}
	if resp.Status != "201 Created" {
		t.Errorf("Status = %q, want %q", resp.Status, "201 Created")
	}
	if resp.Proto != "HTTP/1.1" {
		t.Errorf("Proto = %q, want %q", resp.Proto, "HTTP/1.1")
	}
	if resp.ProtoMajor != 1 {
		t.Errorf("ProtoMajor = %d, want 1", resp.ProtoMajor)
	}
	if resp.ProtoMinor != 1 {
		t.Errorf("ProtoMinor = %d, want 1", resp.ProtoMinor)
	}

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.ContentLength != int64(len(body)) {
		t.Errorf("ContentLength = %d, want %d", resp.ContentLength, len(body))
	}
}

// TestExecutor_ResponseWithToJSON tests response_json in response templates
func TestExecutor_ResponseWithToJSON(t *testing.T) {
	srv := newTestServer(200, map[string]any{"name": "Alice", "role": "admin"})
	defer srv.Close()

	executor, err := NewBuilder().
		WithSteps([]Step{
			BuildStepFromCallback("get_user", newTestCallback(srv.URL, "GET"), nil, "", nil, nil),
		}).
		WithResponseBuilder(BuildResponseBuilder(
			`{"user": {{steps.get_user.response_json}}}`,
			"application/json", 200, nil,
		)).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := executor.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	bodyStr := string(body)
	if !strings.Contains(bodyStr, `"name"`) || !strings.Contains(bodyStr, `"Alice"`) {
		t.Errorf("Response should contain user data serialized via tojson, got: %s", bodyStr)
	}
}

// TestExecutor_DefaultResponseValues tests default status code and content type
func TestExecutor_DefaultResponseValues(t *testing.T) {
	srv := newTestServer(200, map[string]any{"ok": true})
	defer srv.Close()

	executor, err := NewBuilder().
		WithSteps([]Step{
			BuildStepFromCallback("step", newTestCallback(srv.URL, "GET"), nil, "", nil, nil),
		}).
		WithResponseBuilder(BuildResponseBuilder(`{}`, "", 0, nil)).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := executor.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Default status code is 200
	if resp.StatusCode != 200 {
		t.Errorf("Default status should be 200, got %d", resp.StatusCode)
	}

	// Default content type is application/json
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Default Content-Type should be application/json, got %s", ct)
	}
}

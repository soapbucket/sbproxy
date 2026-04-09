package config

import (
	"context"
	"math/rand"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func TestLoadLoadBalancerConfig(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid loadbalancer with single target",
			input: `{
				"type": "loadbalancer",
				"targets": [
					{
						"url": "https://backend1.example.com"
					}
				]
			}`,
			expectError: false,
		},
		{
			name: "valid loadbalancer with multiple targets",
			input: `{
				"type": "loadbalancer",
				"targets": [
					{
						"url": "https://backend1.example.com",
						"weight": 3
					},
					{
						"url": "https://backend2.example.com",
						"weight": 1
					}
				]
			}`,
			expectError: false,
		},
		{
			name: "loadbalancer with round robin",
			input: `{
				"type": "loadbalancer",
				"round_robin": true,
				"targets": [
					{
						"url": "https://backend1.example.com"
					},
					{
						"url": "https://backend2.example.com"
					}
				]
			}`,
			expectError: false,
		},
		{
			name: "loadbalancer with least connections",
			input: `{
				"type": "loadbalancer",
				"least_connections": true,
				"targets": [
					{
						"url": "https://backend1.example.com"
					},
					{
						"url": "https://backend2.example.com"
					}
				]
			}`,
			expectError: false,
		},
		{
			name: "loadbalancer with health checks",
			input: `{
				"type": "loadbalancer",
				"targets": [
					{
						"url": "https://backend1.example.com",
						"health_check": {
							"enabled": true,
							"interval": "10s",
							"timeout": "5s",
							"path": "/health",
							"method": "GET",
							"expected_status": [200, 204],
							"healthy_threshold": 2,
							"unhealthy_threshold": 3
						}
					}
				]
			}`,
			expectError: false,
		},
		{
			name: "loadbalancer with circuit breaker",
			input: `{
				"type": "loadbalancer",
				"targets": [
					{
						"url": "https://backend1.example.com",
						"circuit_breaker": {
							"enabled": true,
							"failure_threshold": 5,
							"success_threshold": 2,
							"timeout": "30s",
							"error_rate_threshold": 0.5
						}
					}
				]
			}`,
			expectError: false,
		},
		{
			name: "loadbalancer with sticky sessions disabled",
			input: `{
				"type": "loadbalancer",
				"disable_sticky": true,
				"targets": [
					{
						"url": "https://backend1.example.com"
					}
				]
			}`,
			expectError: false,
		},
		{
			name: "loadbalancer with custom sticky cookie",
			input: `{
				"type": "loadbalancer",
				"sticky_cookie_name": "_custom_sticky",
				"targets": [
					{
						"url": "https://backend1.example.com"
					}
				]
			}`,
			expectError: false,
		},
		{
			name: "no targets",
			input: `{
				"type": "loadbalancer",
				"targets": []
			}`,
			expectError: true,
			errorMsg:    "no load balancer targets",
		},
		{
			name: "invalid target url",
			input: `{
				"type": "loadbalancer",
				"targets": [
					{
						"url": "not a valid url"
					}
				]
			}`,
			expectError: true,
			errorMsg:    "invalid target URL",
		},
		{
			name: "invalid json",
			input: `{
				"type": "loadbalancer",
				"targets": "invalid"
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadLoadBalancerConfig([]byte(tt.input))
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if cfg == nil {
				t.Fatal("expected config but got nil")
			}

			if cfg.GetType() != TypeLoadBalancer {
				t.Errorf("expected type %s, got %s", TypeLoadBalancer, cfg.GetType())
			}

			lbCfg, ok := cfg.(*LoadBalancerTypedConfig)
			if !ok {
				t.Fatal("expected LoadBalancerTypedConfig")
			}

			if len(lbCfg.compiledTargets) == 0 {
				t.Error("expected compiled targets")
			}
		})
	}
}

func TestCompileTarget(t *testing.T) {
	tests := []struct {
		name        string
		target      *Target
		expectError bool
	}{
		{
			name: "valid target",
			target: &Target{
				URL: "https://backend.example.com",
			},
			expectError: false,
		},
		{
			name: "target with weight",
			target: &Target{
				URL:    "https://backend.example.com",
				Weight: 5,
			},
			expectError: false,
		},
		{
			name: "target with health check",
			target: &Target{
				URL: "https://backend.example.com",
				HealthCheck: &HealthCheckConfig{
					Enabled:  true,
					Interval: reqctx.Duration{Duration: 10 * time.Second},
					Timeout:  reqctx.Duration{Duration: 5 * time.Second},
				},
			},
			expectError: false,
		},
		{
			name: "target with circuit breaker",
			target: &Target{
				URL: "https://backend.example.com",
				CircuitBreaker: &CircuitBreakerConfig{
					Enabled:          true,
					FailureThreshold: 5,
				},
			},
			expectError: false,
		},
		{
			name: "empty url",
			target: &Target{
				URL: "",
			},
			expectError: true,
		},
		{
			name: "invalid url",
			target: &Target{
				URL: "not a valid url",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiled, err := compileTarget(tt.target, 0)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if compiled == nil {
				t.Fatal("expected compiled target")
			}

			if compiled.Transport == nil {
				t.Error("expected transport to be set")
			}

			if compiled.health == nil {
				t.Error("expected health status to be initialized")
			}

			// Health should start as healthy
			if !compiled.health.isHealthy() {
				t.Error("expected target to start healthy")
			}

			// Circuit breaker should be initialized if configured
			if tt.target.CircuitBreaker != nil && tt.target.CircuitBreaker.Enabled {
				if compiled.circuitBreaker == nil {
					t.Error("expected circuit breaker to be initialized")
				}
			}
		})
	}
}

func TestSignAndVerifyTargetIndex(t *testing.T) {
	tests := []struct {
		name        string
		targetIndex int
		secret      string
		maxTargets  int
		shouldVerify bool
	}{
		{
			name:         "with secret",
			targetIndex:  2,
			secret:       "mysecret123",
			maxTargets:   5,
			shouldVerify: true,
		},
		{
			name:         "without secret",
			targetIndex:  1,
			secret:       "",
			maxTargets:   3,
			shouldVerify: true,
		},
		{
			name:         "index 0",
			targetIndex:  0,
			secret:       "secret",
			maxTargets:   10,
			shouldVerify: true,
		},
		{
			name:         "large index",
			targetIndex:  99,
			secret:       "secret",
			maxTargets:   100,
			shouldVerify: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signed := signTargetIndex(tt.targetIndex, tt.secret)
			if signed == "" {
				t.Fatal("expected non-empty signed value")
			}

			index, valid := verifyAndExtractTargetIndex(signed, tt.secret, tt.maxTargets)
			if valid != tt.shouldVerify {
				t.Errorf("expected verification=%v, got %v", tt.shouldVerify, valid)
			}

			if valid && index != tt.targetIndex {
				t.Errorf("expected index %d, got %d", tt.targetIndex, index)
			}
		})
	}
}

func TestVerifyTargetIndex_Invalid(t *testing.T) {
	tests := []struct {
		name        string
		cookieValue string
		secret      string
		maxTargets  int
	}{
		{
			name:        "empty cookie",
			cookieValue: "",
			secret:      "secret",
			maxTargets:  5,
		},
		{
			name:        "invalid format",
			cookieValue: "invalid",
			secret:      "secret",
			maxTargets:  5,
		},
		{
			name:        "index out of range",
			cookieValue: "10",
			secret:      "",
			maxTargets:  5,
		},
		{
			name:        "tampered signature",
			cookieValue: "2.tampered",
			secret:      "secret",
			maxTargets:  5,
		},
		{
			name:        "wrong secret",
			cookieValue: signTargetIndex(2, "secret1"),
			secret:      "secret2",
			maxTargets:  5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, valid := verifyAndExtractTargetIndex(tt.cookieValue, tt.secret, tt.maxTargets)
			if valid {
				t.Error("expected verification to fail")
			}
		})
	}
}

func TestCircuitBreaker(t *testing.T) {
	t.Run("circuit breaker starts closed", func(t *testing.T) {
		config := &CircuitBreakerConfig{
			Enabled:          true,
			FailureThreshold: 3,
		}
		cb := newCircuitBreaker(config, "http://backend.com", "0")

		if cb.getState() != CircuitBreakerStateClosed {
			t.Errorf("expected closed state, got %s", cb.getState())
		}

		if cb.isOpen() {
			t.Error("expected circuit to not be open")
		}
	})

	t.Run("circuit breaker opens after failures", func(t *testing.T) {
		config := &CircuitBreakerConfig{
			Enabled:                true,
			FailureThreshold:       3,
			RequestVolumeThreshold: 1,
		}
		cb := newCircuitBreaker(config, "http://backend.com", "0")

		// Record failures
		for i := 0; i < 3; i++ {
			cb.recordFailure()
		}

		if cb.getState() != CircuitBreakerStateOpen {
			t.Errorf("expected open state, got %s", cb.getState())
		}

		if !cb.isOpen() {
			t.Error("expected circuit to be open")
		}
	})

	t.Run("circuit breaker transitions to half-open", func(t *testing.T) {
		config := &CircuitBreakerConfig{
			Enabled:                true,
			FailureThreshold:       2,
			RequestVolumeThreshold: 2, // Set to match failure threshold
			Timeout:                reqctx.Duration{Duration: 100 * time.Millisecond},
		}
		cb := newCircuitBreaker(config, "http://backend.com", "0")

		// Open the circuit
		cb.recordFailure()
		cb.recordFailure()

		if cb.getState() != CircuitBreakerStateOpen {
			t.Errorf("expected open state, got %s", cb.getState())
		}

		// Wait for timeout
		time.Sleep(150 * time.Millisecond)

		// Check if open - should transition to half-open
		if cb.isOpen() {
			t.Error("expected circuit to transition to half-open")
		}

		if cb.getState() != CircuitBreakerStateHalfOpen {
			t.Errorf("expected half-open state, got %s", cb.getState())
		}
	})

	t.Run("circuit breaker closes from half-open after successes", func(t *testing.T) {
		config := &CircuitBreakerConfig{
			Enabled:          true,
			SuccessThreshold: 2,
		}
		cb := newCircuitBreaker(config, "http://backend.com", "0")

		// Manually set to half-open
		cb.transitionTo(CircuitBreakerStateHalfOpen)

		// Record successes
		cb.recordSuccess()
		cb.recordSuccess()

		if cb.getState() != CircuitBreakerStateClosed {
			t.Errorf("expected closed state, got %s", cb.getState())
		}
	})

	t.Run("circuit breaker opens from half-open on failure", func(t *testing.T) {
		config := &CircuitBreakerConfig{
			Enabled: true,
		}
		cb := newCircuitBreaker(config, "http://backend.com", "0")

		// Manually set to half-open
		cb.transitionTo(CircuitBreakerStateHalfOpen)

		// Record failure
		cb.recordFailure()

		if cb.getState() != CircuitBreakerStateOpen {
			t.Errorf("expected open state, got %s", cb.getState())
		}
	})

	t.Run("nil circuit breaker", func(t *testing.T) {
		var cb *circuitBreaker

		if cb.getState() != CircuitBreakerStateClosed {
			t.Error("expected nil circuit breaker to be closed")
		}

		if cb.isOpen() {
			t.Error("expected nil circuit breaker to not be open")
		}

		// Should not panic
		cb.recordSuccess()
		cb.recordFailure()
	})
}

func TestHealthStatus(t *testing.T) {
	t.Run("health status starts healthy", func(t *testing.T) {
		h := &healthStatus{}
		h.healthy.Store(true)

		if !h.isHealthy() {
			t.Error("expected health status to be healthy")
		}
	})

	t.Run("mark unhealthy", func(t *testing.T) {
		h := &healthStatus{}
		h.healthy.Store(true)

		h.markUnhealthy("origin1", "http://backend.com", "0", "connection refused")

		if h.isHealthy() {
			t.Error("expected health status to be unhealthy")
		}

		healthy, successes, failures, _, lastError := h.getStatus()
		if healthy {
			t.Error("expected healthy=false")
		}
		if successes != 0 {
			t.Errorf("expected 0 successes, got %d", successes)
		}
		if failures != 1 {
			t.Errorf("expected 1 failure, got %d", failures)
		}
		if lastError != "connection refused" {
			t.Errorf("expected error message, got %q", lastError)
		}
	})

	t.Run("mark healthy", func(t *testing.T) {
		h := &healthStatus{}
		h.healthy.Store(false)

		h.markHealthy("origin1", "http://backend.com", "0")

		if !h.isHealthy() {
			t.Error("expected health status to be healthy")
		}

		healthy, successes, failures, _, lastError := h.getStatus()
		if !healthy {
			t.Error("expected healthy=true")
		}
		if successes != 1 {
			t.Errorf("expected 1 success, got %d", successes)
		}
		if failures != 0 {
			t.Errorf("expected 0 failures, got %d", failures)
		}
		if lastError != "" {
			t.Errorf("expected empty error message, got %q", lastError)
		}
	})
}

func TestLoadBalancerSelectTarget(t *testing.T) {
	t.Run("single target", func(t *testing.T) {
		target := &compiledTarget{
			Config: &Target{URL: "http://backend1.com"},
			health: &healthStatus{},
		}
		target.health.healthy.Store(true)

		lb := &loadBalancerTransport{
			targets: []*compiledTarget{target},
		}

		req := httptest.NewRequest("GET", "http://example.com", nil)
		index := lb.selectTarget(req)

		if index != 0 {
			t.Errorf("expected index 0, got %d", index)
		}
	})

	t.Run("algorithm field selects least_connections", func(t *testing.T) {
		targets := []*compiledTarget{
			{
				Config:            &Target{URL: "http://backend1.com", Weight: 1},
				health:            &healthStatus{},
				activeConnections: 10, // high
			},
			{
				Config:            &Target{URL: "http://backend2.com", Weight: 1},
				health:            &healthStatus{},
				activeConnections: 2, // low
			},
		}
		for _, t := range targets {
			t.health.healthy.Store(true)
		}

		lb := &loadBalancerTransport{
			targets:   targets,
			algorithm: AlgorithmLeastConnections,
			random:    rand.New(rand.NewSource(time.Now().UnixNano())),
		}

		req := httptest.NewRequest("GET", "http://example.com", nil)
		index := lb.selectTarget(req)

		if index != 1 {
			t.Errorf("expected target 1 (fewer connections), got %d", index)
		}
	})

	t.Run("weighted round robin distributes proportional to weight", func(t *testing.T) {
		targets := []*compiledTarget{
			{
				Config: &Target{URL: "http://backend1.com", Weight: 3},
				health: &healthStatus{},
			},
			{
				Config: &Target{URL: "http://backend2.com", Weight: 1},
				health: &healthStatus{},
			},
		}
		for _, t := range targets {
			t.health.healthy.Store(true)
		}

		lb := &loadBalancerTransport{
			targets:   targets,
			algorithm: AlgorithmWeightedRoundRobin,
			random:    rand.New(rand.NewSource(time.Now().UnixNano())),
			// wrrIndex starts at 0, wrrCounter starts at 0
		}

		req := httptest.NewRequest("GET", "http://example.com", nil)

		// Over 8 requests (2 full cycles of weight 3+1=4), we expect:
		// target 1 gets 3, target 0 gets 1, target 1 gets 3, target 0 gets 1
		counts := make(map[int]int)
		for i := 0; i < 8; i++ {
			index := lb.selectTarget(req)
			counts[index]++
		}

		// With weights 3:1, over 8 requests we expect 6:2
		if counts[0] != 6 {
			t.Errorf("expected target 0 (weight 3) to get 6 requests, got %d (distribution: %v)", counts[0], counts)
		}
		if counts[1] != 2 {
			t.Errorf("expected target 1 (weight 1) to get 2 requests, got %d (distribution: %v)", counts[1], counts)
		}
	})

	t.Run("algorithm field with invalid value rejected", func(t *testing.T) {
		input := `{
			"type": "loadbalancer",
			"algorithm": "invalid_algo",
			"targets": [{"url": "https://backend.example.com"}]
		}`
		_, err := LoadLoadBalancerConfig([]byte(input))
		if err == nil {
			t.Fatal("expected error for invalid algorithm, got nil")
		}
		if !strings.Contains(err.Error(), "invalid load balancer algorithm") {
			t.Errorf("expected algorithm validation error, got: %v", err)
		}
	})

	t.Run("algorithm field parses from JSON", func(t *testing.T) {
		input := `{
			"type": "loadbalancer",
			"algorithm": "weighted_round_robin",
			"targets": [{"url": "https://backend.example.com"}]
		}`
		cfg, err := LoadLoadBalancerConfig([]byte(input))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		typed, ok := cfg.(*LoadBalancerTypedConfig)
		if !ok {
			t.Fatalf("expected *LoadBalancerTypedConfig, got %T", cfg)
		}
		if typed.Algorithm != AlgorithmWeightedRoundRobin {
			t.Errorf("expected algorithm %q, got %q", AlgorithmWeightedRoundRobin, typed.Algorithm)
		}
	})

	t.Run("weighted random selection", func(t *testing.T) {
		targets := []*compiledTarget{
			{
				Config:          &Target{URL: "http://backend1.com", Weight: 1},
				health:          &healthStatus{},
				RequestMatchers: nil, // Explicitly nil to skip matcher-based routing
			},
			{
				Config:          &Target{URL: "http://backend2.com", Weight: 9},
				health:          &healthStatus{},
				RequestMatchers: nil, // Explicitly nil to skip matcher-based routing
			},
		}
		for _, t := range targets {
			t.health.healthy.Store(true)
		}

		lb := &loadBalancerTransport{
			targets: targets,
			random:  rand.New(rand.NewSource(time.Now().UnixNano())),
		}

		req := httptest.NewRequest("GET", "http://example.com", nil)

		// Run multiple times and check distribution (target 2 should be selected more often)
		counts := make(map[int]int)
		for i := 0; i < 1000; i++ { // Increase iterations for more reliable statistics
			index := lb.selectTarget(req)
			counts[index]++
		}

		// With weights 1:9, we expect roughly 10% vs 90% distribution
		// Allow for randomness - just check target 1 is selected more
		if counts[1] <= counts[0] {
			t.Errorf("expected target 1 (weight 9) to be selected more than target 0 (weight 1), got %v", counts)
		}
	})
}

func TestLoadBalancerAllTargetsUnhealthy(t *testing.T) {
	// Test that selectTarget returns -1 when all targets are unhealthy
	t.Run("all targets unhealthy returns negative index", func(t *testing.T) {
		health1 := &healthStatus{}
		health1.healthy.Store(false)
		health2 := &healthStatus{}
		health2.healthy.Store(false)

		lb := &loadBalancerTransport{
			targets: []*compiledTarget{
				{
					Config: &Target{URL: "https://backend1.example.com", Weight: 1},
					health: health1,
				},
				{
					Config: &Target{URL: "https://backend2.example.com", Weight: 1},
					health: health2,
				},
			},
			random:    rand.New(rand.NewSource(42)),
			algorithm: AlgorithmWeightedRandom,
		}

		req := httptest.NewRequest("GET", "http://example.com/", nil)
		idx := lb.selectTarget(req)
		if idx >= 0 {
			t.Errorf("expected negative index when all targets unhealthy, got %d", idx)
		}
	})

	t.Run("round robin all unhealthy returns negative index", func(t *testing.T) {
		health1 := &healthStatus{}
		health1.healthy.Store(false)
		health2 := &healthStatus{}
		health2.healthy.Store(false)

		lb := &loadBalancerTransport{
			targets: []*compiledTarget{
				{
					Config: &Target{URL: "https://backend1.example.com", Weight: 1},
					health: health1,
				},
				{
					Config: &Target{URL: "https://backend2.example.com", Weight: 1},
					health: health2,
				},
			},
			random:    rand.New(rand.NewSource(42)),
			algorithm: AlgorithmRoundRobin,
		}

		req := httptest.NewRequest("GET", "http://example.com/", nil)
		idx := lb.selectTarget(req)
		if idx >= 0 {
			t.Errorf("expected negative index when all targets unhealthy, got %d", idx)
		}
	})

	t.Run("least connections all unhealthy returns negative index", func(t *testing.T) {
		health1 := &healthStatus{}
		health1.healthy.Store(false)
		health2 := &healthStatus{}
		health2.healthy.Store(false)

		lb := &loadBalancerTransport{
			targets: []*compiledTarget{
				{
					Config: &Target{URL: "https://backend1.example.com", Weight: 1},
					health: health1,
				},
				{
					Config: &Target{URL: "https://backend2.example.com", Weight: 1},
					health: health2,
				},
			},
			random:    rand.New(rand.NewSource(42)),
			algorithm: AlgorithmLeastConnections,
		}

		req := httptest.NewRequest("GET", "http://example.com/", nil)
		idx := lb.selectTarget(req)
		if idx >= 0 {
			t.Errorf("expected negative index when all targets unhealthy, got %d", idx)
		}
	})

	t.Run("weighted round robin all unhealthy returns negative index", func(t *testing.T) {
		health1 := &healthStatus{}
		health1.healthy.Store(false)
		health2 := &healthStatus{}
		health2.healthy.Store(false)

		lb := &loadBalancerTransport{
			targets: []*compiledTarget{
				{
					Config: &Target{URL: "https://backend1.example.com", Weight: 3},
					health: health1,
				},
				{
					Config: &Target{URL: "https://backend2.example.com", Weight: 1},
					health: health2,
				},
			},
			random:    rand.New(rand.NewSource(42)),
			algorithm: AlgorithmWeightedRoundRobin,
		}

		req := httptest.NewRequest("GET", "http://example.com/", nil)
		idx := lb.selectTarget(req)
		if idx >= 0 {
			t.Errorf("expected negative index when all targets unhealthy, got %d", idx)
		}
	})

	t.Run("healthy target selected when one is healthy", func(t *testing.T) {
		health1 := &healthStatus{}
		health1.healthy.Store(false)
		health2 := &healthStatus{}
		health2.healthy.Store(true)

		lb := &loadBalancerTransport{
			targets: []*compiledTarget{
				{
					Config: &Target{URL: "https://backend1.example.com", Weight: 1},
					health: health1,
				},
				{
					Config: &Target{URL: "https://backend2.example.com", Weight: 1},
					health: health2,
				},
			},
			random:    rand.New(rand.NewSource(42)),
			algorithm: AlgorithmWeightedRandom,
		}

		req := httptest.NewRequest("GET", "http://example.com/", nil)
		idx := lb.selectTarget(req)
		if idx != 1 {
			t.Errorf("expected target 1 (the healthy one), got %d", idx)
		}
	})

	t.Run("RoundTrip returns ErrAllTargetsUnhealthy", func(t *testing.T) {
		health1 := &healthStatus{}
		health1.healthy.Store(false)
		health2 := &healthStatus{}
		health2.healthy.Store(false)

		lb := &loadBalancerTransport{
			targets: []*compiledTarget{
				{
					Config: &Target{URL: "https://backend1.example.com", Weight: 1},
					health: health1,
				},
				{
					Config: &Target{URL: "https://backend2.example.com", Weight: 1},
					health: health2,
				},
			},
			random:           rand.New(rand.NewSource(42)),
			algorithm:        AlgorithmWeightedRandom,
			stickyCookieName: "sb_sticky",
			disableSticky:    true,
		}

		req := httptest.NewRequest("GET", "http://example.com/", nil)
		_, err := lb.RoundTrip(req)
		if err == nil {
			t.Fatal("expected error when all targets unhealthy")
		}
		if err != ErrAllTargetsUnhealthy {
			t.Errorf("expected ErrAllTargetsUnhealthy, got %v", err)
		}
	})
}

func TestLoadBalancerClose(t *testing.T) {
	// Test that Close cancels the health check context
	healthCtx, healthCancel := context.WithCancel(context.Background())

	lb := &loadBalancerTransport{
		healthCheckCtx:    healthCtx,
		healthCheckCancel: healthCancel,
	}

	lbTyped := &LoadBalancerTypedConfig{}
	lbTyped.setTransport(lb)

	// Verify context is not cancelled yet
	select {
	case <-healthCtx.Done():
		t.Fatal("health check context should not be cancelled yet")
	default:
		// expected
	}

	// Close should cancel the context
	lbTyped.Close()

	// Verify context is cancelled
	select {
	case <-healthCtx.Done():
		// expected
	default:
		t.Fatal("health check context should be cancelled after Close()")
	}
}


package ai

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func defaultCanaryConfig() CanaryConfig {
	return CanaryConfig{
		Enabled:         true,
		Name:            "test-canary",
		Control:         CanaryVariant{Name: "control-v1", Provider: "openai", Model: "gpt-4o"},
		Experiment:      CanaryVariant{Name: "experiment-v2", Provider: "anthropic", Model: "claude-sonnet-4-20250514"},
		TrafficPercent:  10.0,
		MaxErrorRate:    0.05,
		MaxLatencyRatio: 2.0,
		MinRequests:     10,
		EvalInterval:    100 * time.Millisecond,
	}
}

func TestCanary_Route_InitialSplit(t *testing.T) {
	cfg := defaultCanaryConfig()
	cfg.TrafficPercent = 20.0
	ce := NewCanaryExperiment(cfg)
	defer ce.Stop()

	controlCount := 0
	experimentCount := 0
	total := 10000

	for i := 0; i < total; i++ {
		variant, _ := ce.Route()
		if variant == cfg.Control.Name {
			controlCount++
		} else {
			experimentCount++
		}
	}

	// With 20% traffic, experiment should get roughly 15-25% of requests.
	expPct := float64(experimentCount) / float64(total) * 100.0
	if expPct < 15.0 || expPct > 25.0 {
		t.Errorf("Expected ~20%% experiment traffic, got %.1f%% (%d/%d)", expPct, experimentCount, total)
	}
}

func TestCanary_Route_ControlOnly(t *testing.T) {
	cfg := defaultCanaryConfig()
	cfg.TrafficPercent = 0.0
	cfg.RampSteps = nil
	ce := NewCanaryExperiment(cfg)
	defer ce.Stop()

	for i := 0; i < 1000; i++ {
		variant, v := ce.Route()
		if variant != cfg.Control.Name {
			t.Fatalf("Expected all traffic to control, got %s", variant)
		}
		if v.Provider != cfg.Control.Provider {
			t.Fatalf("Expected control provider %s, got %s", cfg.Control.Provider, v.Provider)
		}
	}
}

func TestCanary_Route_ExperimentOnly(t *testing.T) {
	cfg := defaultCanaryConfig()
	cfg.TrafficPercent = 100.0
	cfg.RampSteps = nil
	ce := NewCanaryExperiment(cfg)
	defer ce.Stop()

	for i := 0; i < 1000; i++ {
		variant, v := ce.Route()
		if variant != cfg.Experiment.Name {
			t.Fatalf("Expected all traffic to experiment, got %s", variant)
		}
		if v.Provider != cfg.Experiment.Provider {
			t.Fatalf("Expected experiment provider %s, got %s", cfg.Experiment.Provider, v.Provider)
		}
	}
}

func TestCanary_RecordResult(t *testing.T) {
	cfg := defaultCanaryConfig()
	ce := NewCanaryExperiment(cfg)
	defer ce.Stop()

	// Record some control results.
	ce.RecordResult(cfg.Control.Name, 50*time.Millisecond, 100, nil)
	ce.RecordResult(cfg.Control.Name, 60*time.Millisecond, 120, nil)
	ce.RecordResult(cfg.Control.Name, 70*time.Millisecond, 80, errors.New("timeout"))

	// Record some experiment results.
	ce.RecordResult(cfg.Experiment.Name, 40*time.Millisecond, 90, nil)
	ce.RecordResult(cfg.Experiment.Name, 45*time.Millisecond, 110, nil)

	ctrl, exp := ce.Metrics()

	if ctrl.Requests != 3 {
		t.Errorf("Expected 3 control requests, got %d", ctrl.Requests)
	}
	if ctrl.Errors != 1 {
		t.Errorf("Expected 1 control error, got %d", ctrl.Errors)
	}
	if ctrl.TotalTokens != 300 {
		t.Errorf("Expected 300 control tokens, got %d", ctrl.TotalTokens)
	}

	if exp.Requests != 2 {
		t.Errorf("Expected 2 experiment requests, got %d", exp.Requests)
	}
	if exp.Errors != 0 {
		t.Errorf("Expected 0 experiment errors, got %d", exp.Errors)
	}
	if exp.TotalTokens != 200 {
		t.Errorf("Expected 200 experiment tokens, got %d", exp.TotalTokens)
	}
}

func TestCanary_Evaluate_Promote(t *testing.T) {
	cfg := defaultCanaryConfig()
	cfg.MinRequests = 5
	cfg.RampSteps = nil // No ramp steps, promotes directly.
	ce := NewCanaryExperiment(cfg)
	defer ce.Stop()

	// Record good control metrics.
	for i := 0; i < 10; i++ {
		ce.RecordResult(cfg.Control.Name, 50*time.Millisecond, 100, nil)
	}
	// Record good experiment metrics.
	for i := 0; i < 10; i++ {
		ce.RecordResult(cfg.Experiment.Name, 45*time.Millisecond, 90, nil)
	}

	status := ce.Evaluate()
	if status != CanaryStatusPromoted {
		t.Errorf("Expected promoted, got %s", status)
	}
	if ce.CurrentTrafficPercent() != 100 {
		t.Errorf("Expected 100%% traffic after promotion, got %.1f%%", ce.CurrentTrafficPercent())
	}
}

func TestCanary_Evaluate_Rollback_ErrorRate(t *testing.T) {
	cfg := defaultCanaryConfig()
	cfg.MinRequests = 5
	cfg.MaxErrorRate = 0.10
	ce := NewCanaryExperiment(cfg)
	defer ce.Stop()

	// Record control metrics (all successful).
	for i := 0; i < 10; i++ {
		ce.RecordResult(cfg.Control.Name, 50*time.Millisecond, 100, nil)
	}
	// Record experiment metrics with 20% error rate (above 10% threshold).
	for i := 0; i < 8; i++ {
		ce.RecordResult(cfg.Experiment.Name, 45*time.Millisecond, 90, nil)
	}
	for i := 0; i < 2; i++ {
		ce.RecordResult(cfg.Experiment.Name, 45*time.Millisecond, 0, errors.New("provider error"))
	}

	status := ce.Evaluate()
	if status != CanaryStatusRolledBack {
		t.Errorf("Expected rolled_back due to error rate, got %s", status)
	}
	if ce.CurrentTrafficPercent() != 0 {
		t.Errorf("Expected 0%% traffic after rollback, got %.1f%%", ce.CurrentTrafficPercent())
	}
}

func TestCanary_Evaluate_Rollback_Latency(t *testing.T) {
	cfg := defaultCanaryConfig()
	cfg.MinRequests = 5
	cfg.MaxLatencyRatio = 1.5
	ce := NewCanaryExperiment(cfg)
	defer ce.Stop()

	// Control: average 50ms.
	for i := 0; i < 10; i++ {
		ce.RecordResult(cfg.Control.Name, 50*time.Millisecond, 100, nil)
	}
	// Experiment: average 100ms (2x control, exceeds 1.5x ratio).
	for i := 0; i < 10; i++ {
		ce.RecordResult(cfg.Experiment.Name, 100*time.Millisecond, 90, nil)
	}

	status := ce.Evaluate()
	if status != CanaryStatusRolledBack {
		t.Errorf("Expected rolled_back due to latency, got %s", status)
	}
}

func TestCanary_Evaluate_InsufficientData(t *testing.T) {
	cfg := defaultCanaryConfig()
	cfg.MinRequests = 100
	ce := NewCanaryExperiment(cfg)
	defer ce.Stop()

	// Only record a few requests (below MinRequests).
	for i := 0; i < 5; i++ {
		ce.RecordResult(cfg.Experiment.Name, 45*time.Millisecond, 90, nil)
	}

	status := ce.Evaluate()
	if status != CanaryStatusRunning {
		t.Errorf("Expected running (insufficient data), got %s", status)
	}
}

func TestCanary_Ramp(t *testing.T) {
	cfg := defaultCanaryConfig()
	cfg.RampSteps = []float64{5, 10, 25, 50, 100}
	ce := NewCanaryExperiment(cfg)
	defer ce.Stop()

	if ce.CurrentTrafficPercent() != 5.0 {
		t.Errorf("Expected initial ramp step 5%%, got %.1f%%", ce.CurrentTrafficPercent())
	}

	if !ce.Ramp() {
		t.Error("Expected Ramp to return true")
	}
	if ce.CurrentTrafficPercent() != 10.0 {
		t.Errorf("Expected 10%% after first ramp, got %.1f%%", ce.CurrentTrafficPercent())
	}

	if !ce.Ramp() {
		t.Error("Expected Ramp to return true")
	}
	if ce.CurrentTrafficPercent() != 25.0 {
		t.Errorf("Expected 25%% after second ramp, got %.1f%%", ce.CurrentTrafficPercent())
	}

	if !ce.Ramp() {
		t.Error("Expected Ramp to return true")
	}
	if ce.CurrentTrafficPercent() != 50.0 {
		t.Errorf("Expected 50%% after third ramp, got %.1f%%", ce.CurrentTrafficPercent())
	}

	if !ce.Ramp() {
		t.Error("Expected Ramp to return true")
	}
	if ce.CurrentTrafficPercent() != 100.0 {
		t.Errorf("Expected 100%% after fourth ramp, got %.1f%%", ce.CurrentTrafficPercent())
	}

	// No more steps.
	if ce.Ramp() {
		t.Error("Expected Ramp to return false when no more steps")
	}
}

func TestCanary_RampSteps(t *testing.T) {
	cfg := defaultCanaryConfig()
	cfg.MinRequests = 3
	cfg.RampSteps = []float64{5, 25, 50, 100}
	ce := NewCanaryExperiment(cfg)
	defer ce.Stop()

	// Simulate good metrics and evaluate to auto-ramp through all steps.
	// Each Evaluate call advances to the next ramp step. After reaching the last
	// step (100%), one more Evaluate is needed to trigger promotion.
	totalEvals := len(cfg.RampSteps) // steps 0->1, 1->2, 2->3, then 3->promote
	for step := 0; step < totalEvals; step++ {
		// Record enough good metrics for both variants.
		for i := 0; i < 5; i++ {
			ce.RecordResult(cfg.Control.Name, 50*time.Millisecond, 100, nil)
			ce.RecordResult(cfg.Experiment.Name, 45*time.Millisecond, 90, nil)
		}

		status := ce.Evaluate()
		if step < totalEvals-1 {
			if status != CanaryStatusRunning {
				t.Errorf("Step %d: expected running, got %s", step, status)
			}
			expected := cfg.RampSteps[step+1]
			if ce.CurrentTrafficPercent() != expected {
				t.Errorf("Step %d: expected %.0f%%, got %.1f%%", step, expected, ce.CurrentTrafficPercent())
			}
		} else {
			// Final evaluate after reaching last ramp step should promote.
			if status != CanaryStatusPromoted {
				t.Errorf("Final step: expected promoted, got %s", status)
			}
		}
	}
}

func TestCanary_Rollback(t *testing.T) {
	cfg := defaultCanaryConfig()
	ce := NewCanaryExperiment(cfg)
	defer ce.Stop()

	ce.Rollback()

	if ce.Status() != CanaryStatusRolledBack {
		t.Errorf("Expected rolled_back, got %s", ce.Status())
	}
	if ce.CurrentTrafficPercent() != 0 {
		t.Errorf("Expected 0%% after rollback, got %.1f%%", ce.CurrentTrafficPercent())
	}

	// After rollback, all traffic should go to control.
	for i := 0; i < 100; i++ {
		variant, _ := ce.Route()
		if variant != cfg.Control.Name {
			t.Fatalf("Expected control after rollback, got %s", variant)
		}
	}
}

func TestCanary_Promote(t *testing.T) {
	cfg := defaultCanaryConfig()
	ce := NewCanaryExperiment(cfg)
	defer ce.Stop()

	ce.Promote()

	if ce.Status() != CanaryStatusPromoted {
		t.Errorf("Expected promoted, got %s", ce.Status())
	}
	if ce.CurrentTrafficPercent() != 100 {
		t.Errorf("Expected 100%% after promotion, got %.1f%%", ce.CurrentTrafficPercent())
	}

	// After promotion, all traffic should go to experiment.
	for i := 0; i < 100; i++ {
		variant, _ := ce.Route()
		if variant != cfg.Experiment.Name {
			t.Fatalf("Expected experiment after promotion, got %s", variant)
		}
	}
}

func TestCanary_Metrics(t *testing.T) {
	cfg := defaultCanaryConfig()
	ce := NewCanaryExperiment(cfg)
	defer ce.Stop()

	// Record varying latencies.
	ce.RecordResult(cfg.Control.Name, 10*time.Millisecond, 50, nil)
	ce.RecordResult(cfg.Control.Name, 20*time.Millisecond, 60, nil)
	ce.RecordResult(cfg.Control.Name, 30*time.Millisecond, 70, errors.New("err"))

	ce.RecordResult(cfg.Experiment.Name, 5*time.Millisecond, 40, nil)
	ce.RecordResult(cfg.Experiment.Name, 15*time.Millisecond, 80, nil)

	ctrl, exp := ce.Metrics()

	if ctrl.Requests != 3 {
		t.Errorf("Control requests: expected 3, got %d", ctrl.Requests)
	}
	if ctrl.Errors != 1 {
		t.Errorf("Control errors: expected 1, got %d", ctrl.Errors)
	}
	// Error rate should be 1/3 ~ 0.333.
	if ctrl.ErrorRate < 0.3 || ctrl.ErrorRate > 0.4 {
		t.Errorf("Control error rate: expected ~0.33, got %.3f", ctrl.ErrorRate)
	}
	// Average latency: (10+20+30)/3 = 20ms.
	if ctrl.AvgLatencyMs < 19.0 || ctrl.AvgLatencyMs > 21.0 {
		t.Errorf("Control avg latency: expected ~20ms, got %.1fms", ctrl.AvgLatencyMs)
	}
	if ctrl.TotalTokens != 180 {
		t.Errorf("Control tokens: expected 180, got %d", ctrl.TotalTokens)
	}

	if exp.Requests != 2 {
		t.Errorf("Experiment requests: expected 2, got %d", exp.Requests)
	}
	if exp.Errors != 0 {
		t.Errorf("Experiment errors: expected 0, got %d", exp.Errors)
	}
	// Average latency: (5+15)/2 = 10ms.
	if exp.AvgLatencyMs < 9.0 || exp.AvgLatencyMs > 11.0 {
		t.Errorf("Experiment avg latency: expected ~10ms, got %.1fms", exp.AvgLatencyMs)
	}
}

func TestCanary_ConcurrentAccess(t *testing.T) {
	cfg := defaultCanaryConfig()
	cfg.TrafficPercent = 50.0
	cfg.MinRequests = 100
	ce := NewCanaryExperiment(cfg)
	defer ce.Stop()

	var wg sync.WaitGroup
	errCh := make(chan error, 100)

	// Concurrent routing and recording.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				variant, _ := ce.Route()
				ce.RecordResult(variant, time.Duration(j)*time.Millisecond, j*10, nil)
			}
		}()
	}

	// Concurrent evaluations.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				ce.Evaluate()
			}
		}()
	}

	// Concurrent metric reads.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				ce.Metrics()
				ce.Status()
				ce.CurrentTrafficPercent()
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("Concurrent access error: %v", err)
	}

	// Verify metrics are consistent.
	ctrl, exp := ce.Metrics()
	totalRequests := ctrl.Requests + exp.Requests
	if totalRequests != 50*200 {
		t.Errorf("Expected %d total requests, got %d", 50*200, totalRequests)
	}
}

func TestCanary_Status(t *testing.T) {
	cfg := defaultCanaryConfig()
	ce := NewCanaryExperiment(cfg)
	defer ce.Stop()

	if ce.Status() != CanaryStatusRunning {
		t.Errorf("Initial status should be running, got %s", ce.Status())
	}

	ce.Rollback()
	if ce.Status() != CanaryStatusRolledBack {
		t.Errorf("Expected rolled_back, got %s", ce.Status())
	}

	// Create a new experiment and promote it.
	ce2 := NewCanaryExperiment(cfg)
	defer ce2.Stop()
	ce2.Promote()
	if ce2.Status() != CanaryStatusPromoted {
		t.Errorf("Expected promoted, got %s", ce2.Status())
	}
}

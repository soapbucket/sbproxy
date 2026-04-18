package metric

import (
	"fmt"
	"sync"
	"testing"
)

func TestNewCardinalityLimiter(t *testing.T) {
	t.Run("uses provided max values", func(t *testing.T) {
		cl := NewCardinalityLimiter(500)
		if cl.maxValues != 500 {
			t.Errorf("expected maxValues=500, got %d", cl.maxValues)
		}
	})

	t.Run("uses default for zero", func(t *testing.T) {
		cl := NewCardinalityLimiter(0)
		if cl.maxValues != DefaultMaxCardinalityValues {
			t.Errorf("expected maxValues=%d, got %d", DefaultMaxCardinalityValues, cl.maxValues)
		}
	})

	t.Run("uses default for negative", func(t *testing.T) {
		cl := NewCardinalityLimiter(-1)
		if cl.maxValues != DefaultMaxCardinalityValues {
			t.Errorf("expected maxValues=%d, got %d", DefaultMaxCardinalityValues, cl.maxValues)
		}
	})
}

func TestCardinalityLimiter_Limit(t *testing.T) {
	t.Run("allows values under the cap", func(t *testing.T) {
		cl := NewCardinalityLimiter(3)

		for i := 0; i < 3; i++ {
			val := fmt.Sprintf("value_%d", i)
			got := cl.Limit("test_metric", val)
			if got != val {
				t.Errorf("expected %q, got %q", val, got)
			}
		}
	})

	t.Run("demotes values at the cap", func(t *testing.T) {
		cl := NewCardinalityLimiter(2)

		cl.Limit("test_metric", "a")
		cl.Limit("test_metric", "b")

		got := cl.Limit("test_metric", "c")
		if got != DemotedLabelValue {
			t.Errorf("expected %q, got %q", DemotedLabelValue, got)
		}
	})

	t.Run("allows previously seen values after cap", func(t *testing.T) {
		cl := NewCardinalityLimiter(2)

		cl.Limit("test_metric", "a")
		cl.Limit("test_metric", "b")
		// Cap reached, "c" should be demoted.
		cl.Limit("test_metric", "c")

		// "a" was seen before cap, should still pass.
		got := cl.Limit("test_metric", "a")
		if got != "a" {
			t.Errorf("expected 'a', got %q", got)
		}
	})

	t.Run("tracks metrics independently", func(t *testing.T) {
		cl := NewCardinalityLimiter(1)

		got1 := cl.Limit("metric_1", "val_a")
		got2 := cl.Limit("metric_2", "val_b")

		if got1 != "val_a" {
			t.Errorf("metric_1: expected 'val_a', got %q", got1)
		}
		if got2 != "val_b" {
			t.Errorf("metric_2: expected 'val_b', got %q", got2)
		}

		// Second value on each metric should be demoted.
		if got := cl.Limit("metric_1", "val_c"); got != DemotedLabelValue {
			t.Errorf("metric_1 overflow: expected %q, got %q", DemotedLabelValue, got)
		}
		if got := cl.Limit("metric_2", "val_d"); got != DemotedLabelValue {
			t.Errorf("metric_2 overflow: expected %q, got %q", DemotedLabelValue, got)
		}
	})

	t.Run("same value is idempotent", func(t *testing.T) {
		cl := NewCardinalityLimiter(1)

		for i := 0; i < 100; i++ {
			got := cl.Limit("test_metric", "same_value")
			if got != "same_value" {
				t.Fatalf("iteration %d: expected 'same_value', got %q", i, got)
			}
		}

		stats := cl.Stats()
		if stats["test_metric"] != 1 {
			t.Errorf("expected cardinality 1, got %d", stats["test_metric"])
		}
	})
}

func TestCardinalityLimiter_Reset(t *testing.T) {
	cl := NewCardinalityLimiter(2)
	cl.Limit("m", "a")
	cl.Limit("m", "b")

	// At cap, next should be demoted.
	if got := cl.Limit("m", "c"); got != DemotedLabelValue {
		t.Errorf("before reset: expected %q, got %q", DemotedLabelValue, got)
	}

	cl.Reset()

	// After reset, "c" should be allowed.
	if got := cl.Limit("m", "c"); got != "c" {
		t.Errorf("after reset: expected 'c', got %q", got)
	}
}

func TestCardinalityLimiter_Stats(t *testing.T) {
	cl := NewCardinalityLimiter(100)
	cl.Limit("alpha", "1")
	cl.Limit("alpha", "2")
	cl.Limit("alpha", "3")
	cl.Limit("beta", "x")

	stats := cl.Stats()
	if stats["alpha"] != 3 {
		t.Errorf("alpha: expected 3, got %d", stats["alpha"])
	}
	if stats["beta"] != 1 {
		t.Errorf("beta: expected 1, got %d", stats["beta"])
	}
}

func TestCardinalityLimiter_Concurrent(t *testing.T) {
	cl := NewCardinalityLimiter(50)

	var wg sync.WaitGroup
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(goroutine int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				val := fmt.Sprintf("g%d_v%d", goroutine, i)
				result := cl.Limit("concurrent_metric", val)
				if result != val && result != DemotedLabelValue {
					t.Errorf("unexpected result: %q", result)
				}
			}
		}(g)
	}
	wg.Wait()

	stats := cl.Stats()
	if stats["concurrent_metric"] > 50 {
		t.Errorf("cardinality exceeded cap: got %d, max 50", stats["concurrent_metric"])
	}
}

func TestDemotionLogger_WarnOnce(t *testing.T) {
	dl := newDemotionLogger()

	// Should not panic and should mark as warned.
	dl.WarnOnce("test_metric", 1000, 1000)

	dl.mu.Lock()
	warned := dl.warned["test_metric"]
	dl.mu.Unlock()

	if !warned {
		t.Error("expected metric to be marked as warned")
	}
}

func TestDemotionLogger_OnlyWarnsOnce(t *testing.T) {
	dl := newDemotionLogger()

	// Call multiple times; should not panic.
	for i := 0; i < 10; i++ {
		dl.WarnOnce("test_metric", 1000, 1000)
	}

	dl.mu.Lock()
	count := len(dl.warned)
	dl.mu.Unlock()

	if count != 1 {
		t.Errorf("expected 1 warned metric, got %d", count)
	}
}

func TestDemotionLogger_Reset(t *testing.T) {
	dl := newDemotionLogger()
	dl.WarnOnce("metric_a", 100, 100)

	dl.Reset()

	dl.mu.Lock()
	warned := dl.warned["metric_a"]
	dl.mu.Unlock()

	if warned {
		t.Error("expected warned state to be cleared after reset")
	}
}

func TestDefaultCardinalityLimiter(t *testing.T) {
	limiter := DefaultCardinalityLimiter()
	if limiter == nil {
		t.Fatal("default limiter should not be nil")
	}
	if limiter.maxValues != DefaultMaxCardinalityValues {
		t.Errorf("expected maxValues=%d, got %d", DefaultMaxCardinalityValues, limiter.maxValues)
	}
}

func TestLimitCardinality(t *testing.T) {
	// Reset state to avoid interference from other tests.
	ResetCardinality()

	got := LimitCardinality("pkg_test_metric", "test_value")
	if got != "test_value" {
		t.Errorf("expected 'test_value', got %q", got)
	}

	stats := CardinalityStats()
	if stats["pkg_test_metric"] != 1 {
		t.Errorf("expected cardinality 1, got %d", stats["pkg_test_metric"])
	}
}

func BenchmarkCardinalityLimiter_Limit_HitPath(b *testing.B) {
	cl := NewCardinalityLimiter(1000)
	// Pre-populate with one value so all lookups hit the fast path.
	cl.Limit("bench_metric", "existing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cl.Limit("bench_metric", "existing")
	}
}

func BenchmarkCardinalityLimiter_Limit_MissPath(b *testing.B) {
	cl := NewCardinalityLimiter(b.N + 1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cl.Limit("bench_metric", fmt.Sprintf("val_%d", i))
	}
}

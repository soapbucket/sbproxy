package policy

import (
	"sync"
	"testing"
	"time"
)

func TestTPMLimiter_Check_WithinLimit(t *testing.T) {
	tpm := NewTPMLimiter()
	if !tpm.Check("user-1", 500, 1000) {
		t.Error("expected check to pass for 500/1000")
	}
}

func TestTPMLimiter_Check_ExceedsLimit(t *testing.T) {
	tpm := NewTPMLimiter()
	tpm.Record("user-1", 800)

	if tpm.Check("user-1", 300, 1000) {
		t.Error("expected check to fail for 800+300 > 1000")
	}
}

func TestTPMLimiter_Record(t *testing.T) {
	tpm := NewTPMLimiter()
	tpm.Record("user-1", 100)
	tpm.Record("user-1", 200)

	usage := tpm.Usage("user-1")
	if usage != 300 {
		t.Errorf("expected usage=300, got %d", usage)
	}
}

func TestTPMLimiter_SlidingWindow(t *testing.T) {
	tpm := NewTPMLimiter()
	tpm.Record("user-1", 500)

	usage := tpm.Usage("user-1")
	if usage != 500 {
		t.Errorf("expected usage=500 initially, got %d", usage)
	}

	// Simulate time passing by manipulating the window directly.
	shard := tpm.shardFor("user-1")
	shard.mu.Lock()
	w := shard.windows["user-1"]
	// Move lastUpdate back by 61 seconds so all buckets expire.
	w.lastUpdate = time.Now().Add(-61 * time.Second)
	shard.mu.Unlock()

	usage = tpm.Usage("user-1")
	if usage != 0 {
		t.Errorf("expected usage=0 after window expiry, got %d", usage)
	}
}

func TestTPMLimiter_ConcurrentAccess(t *testing.T) {
	tpm := NewTPMLimiter()
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tpm.Record("user-1", 10)
			tpm.Check("user-1", 10, 100000)
			tpm.Usage("user-1")
		}()
	}

	wg.Wait()

	usage := tpm.Usage("user-1")
	if usage != 1000 {
		t.Errorf("expected usage=1000 after 100 concurrent records of 10, got %d", usage)
	}
}

func TestTPMLimiter_Usage(t *testing.T) {
	tpm := NewTPMLimiter()

	// No usage yet.
	if usage := tpm.Usage("nonexistent"); usage != 0 {
		t.Errorf("expected 0 for nonexistent key, got %d", usage)
	}

	tpm.Record("user-1", 42)
	if usage := tpm.Usage("user-1"); usage != 42 {
		t.Errorf("expected usage=42, got %d", usage)
	}
}

func TestTPMLimiter_MultipleKeys(t *testing.T) {
	tpm := NewTPMLimiter()
	tpm.Record("user-1", 100)
	tpm.Record("user-2", 200)

	if usage := tpm.Usage("user-1"); usage != 100 {
		t.Errorf("expected user-1 usage=100, got %d", usage)
	}
	if usage := tpm.Usage("user-2"); usage != 200 {
		t.Errorf("expected user-2 usage=200, got %d", usage)
	}
}

package keys

import (
	"testing"

	cacher "github.com/soapbucket/sbproxy/internal/cache/store"
)

func newMemoryCacher(t *testing.T) cacher.Cacher {
	t.Helper()
	c, err := cacher.NewMemoryCacher(cacher.Settings{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRedisUsageTracker_Record(t *testing.T) {
	c := newMemoryCacher(t)
	defer c.Close()
	tracker := NewRedisUsageTracker(c)

	tracker.Record("vk-1", 100, 50, 0.01, false)
	usage := tracker.GetUsage("vk-1")

	if usage.Requests != 1 {
		t.Fatalf("expected 1 request, got %d", usage.Requests)
	}
	if usage.InputTokens != 100 {
		t.Fatalf("expected 100 input tokens, got %d", usage.InputTokens)
	}
	if usage.OutputTokens != 50 {
		t.Fatalf("expected 50 output tokens, got %d", usage.OutputTokens)
	}
	if usage.TotalTokens != 150 {
		t.Fatalf("expected 150 total tokens, got %d", usage.TotalTokens)
	}
}

func TestRedisUsageTracker_MultipleRecords(t *testing.T) {
	c := newMemoryCacher(t)
	defer c.Close()
	tracker := NewRedisUsageTracker(c)

	tracker.Record("vk-1", 100, 50, 0.01, false)
	tracker.Record("vk-1", 200, 100, 0.02, false)
	tracker.Record("vk-1", 50, 25, 0.005, true)

	usage := tracker.GetUsage("vk-1")
	if usage.Requests != 3 {
		t.Fatalf("expected 3 requests, got %d", usage.Requests)
	}
	if usage.TotalTokens != 525 {
		t.Fatalf("expected 525 total tokens, got %d", usage.TotalTokens)
	}
	if usage.Errors != 1 {
		t.Fatalf("expected 1 error, got %d", usage.Errors)
	}
}

func TestRedisUsageTracker_CheckTokenBudget(t *testing.T) {
	c := newMemoryCacher(t)
	defer c.Close()
	tracker := NewRedisUsageTracker(c)

	// No usage yet - within budget
	if !tracker.CheckTokenBudget("vk-1", 1000) {
		t.Fatal("expected within budget with no usage")
	}

	// Record some usage
	tracker.Record("vk-1", 400, 200, 0, false)

	// Still within budget (600 < 1000)
	if !tracker.CheckTokenBudget("vk-1", 1000) {
		t.Fatal("expected within budget at 600/1000")
	}

	// Record more to exceed
	tracker.Record("vk-1", 300, 200, 0, false)

	// Now exceeded (1100 >= 1000)
	if tracker.CheckTokenBudget("vk-1", 1000) {
		t.Fatal("expected budget exceeded at 1100/1000")
	}

	// No limit = always within budget
	if !tracker.CheckTokenBudget("vk-1", 0) {
		t.Fatal("expected within budget with no limit")
	}
}

func TestRedisUsageTracker_CheckTokenRate(t *testing.T) {
	c := newMemoryCacher(t)
	defer c.Close()
	tracker := NewRedisUsageTracker(c)

	tracker.Record("vk-1", 5000, 3000, 0, false)

	if !tracker.CheckTokenRate("vk-1", 10000) {
		t.Fatal("expected within rate at 8000/10000")
	}

	tracker.Record("vk-1", 3000, 0, 0, false)

	if tracker.CheckTokenRate("vk-1", 10000) {
		t.Fatal("expected rate exceeded at 11000/10000")
	}
}

func TestRedisUsageTracker_TokenUtilization(t *testing.T) {
	c := newMemoryCacher(t)
	defer c.Close()
	tracker := NewRedisUsageTracker(c)

	// No usage
	if u := tracker.TokenUtilization("vk-1", 1000); u != 0 {
		t.Fatalf("expected 0 utilization, got %f", u)
	}

	tracker.Record("vk-1", 300, 200, 0, false)

	u := tracker.TokenUtilization("vk-1", 1000)
	if u < 0.49 || u > 0.51 {
		t.Fatalf("expected ~0.5 utilization, got %f", u)
	}
}

func TestRedisUsageTracker_CheckBudget(t *testing.T) {
	c := newMemoryCacher(t)
	defer c.Close()
	tracker := NewRedisUsageTracker(c)

	tracker.Record("vk-1", 0, 0, 5.0, false)

	if !tracker.CheckBudget("vk-1", 10.0, "daily") {
		t.Fatal("expected within budget at $5/$10")
	}

	tracker.Record("vk-1", 0, 0, 6.0, false)

	if tracker.CheckBudget("vk-1", 10.0, "daily") {
		t.Fatal("expected budget exceeded at $11/$10")
	}
}

func TestRedisUsageTracker_IsolatedKeys(t *testing.T) {
	c := newMemoryCacher(t)
	defer c.Close()
	tracker := NewRedisUsageTracker(c)

	tracker.Record("vk-1", 100, 50, 0, false)
	tracker.Record("vk-2", 200, 100, 0, false)

	u1 := tracker.GetUsage("vk-1")
	u2 := tracker.GetUsage("vk-2")

	if u1.TotalTokens != 150 {
		t.Fatalf("vk-1 expected 150 tokens, got %d", u1.TotalTokens)
	}
	if u2.TotalTokens != 300 {
		t.Fatalf("vk-2 expected 300 tokens, got %d", u2.TotalTokens)
	}
}

func TestRedisUsageTracker_ImplementsInterface(t *testing.T) {
	c := newMemoryCacher(t)
	defer c.Close()

	// Verify both trackers satisfy the UsageStore interface
	var _ UsageStore = NewUsageTracker()
	var _ UsageStore = NewRedisUsageTracker(c)
}

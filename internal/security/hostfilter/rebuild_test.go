package hostfilter

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

type countingKeyLister struct {
	keys      []string
	callCount atomic.Int32
}

func (c *countingKeyLister) ListKeys(ctx context.Context) ([]string, error) {
	c.callCount.Add(1)
	return c.keys, nil
}

func (c *countingKeyLister) ListKeysByWorkspace(ctx context.Context, workspaceID string) ([]string, error) {
	return nil, nil
}

func TestScheduleDebouncedRebuild_CollapsesCalls(t *testing.T) {
	mock := &countingKeyLister{keys: []string{"a.com", "b.com"}}
	hf := New(100, 0.001)
	hf.storage = mock

	ctx := context.Background()

	// Schedule multiple rebuilds rapidly - they should collapse into one
	for i := 0; i < 5; i++ {
		hf.ScheduleDebouncedRebuild(ctx)
	}

	// Wait for debounce window + processing time
	time.Sleep(7 * time.Second)

	count := mock.callCount.Load()
	if count != 1 {
		t.Errorf("expected 1 rebuild call (debounced), got %d", count)
	}
}

func TestStop_CancelsRebuild(t *testing.T) {
	mock := &countingKeyLister{keys: []string{"a.com"}}
	hf := New(100, 0.001)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start with very short interval
	hf.StartPeriodicRebuild(ctx, mock, 100*time.Millisecond, 0.01)

	// Let it run a bit
	time.Sleep(300 * time.Millisecond)

	// Stop
	hf.Stop()

	countBefore := mock.callCount.Load()

	// Wait to verify no more rebuilds happen
	time.Sleep(300 * time.Millisecond)

	countAfter := mock.callCount.Load()
	if countAfter > countBefore+1 {
		t.Errorf("expected rebuild to stop, but count increased from %d to %d", countBefore, countAfter)
	}
}

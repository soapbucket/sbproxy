package ai

import (
	"context"
	"fmt"
	"testing"
	"time"
)

var benchTime = time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)

func BenchmarkTokenTrackerCheck(b *testing.B) {
	tracker := NewTokenTracker(nil)
	ctx := context.Background()

	key := "user=user-1:model=gpt-4o:day:20260313"
	tracker.Record(ctx, key, "day", 100, 50)

	limit := &HierarchicalLimit{
		TotalTokenLimit: 100000,
		Period:          "day",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = tracker.Check(ctx, key, limit)
	}
}

func BenchmarkTokenTrackerRecord(b *testing.B) {
	tracker := NewTokenTracker(nil)
	ctx := context.Background()

	key := "user=user-1:model=gpt-4o:day:20260313"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tracker.Record(ctx, key, "day", 10, 5)
	}
}

func BenchmarkBuildKey(b *testing.B) {
	scopes := map[string]string{
		"user":      "user-1",
		"model":     "gpt-4o",
		"workspace": "ws-123",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BuildKeyAt(scopes, "day", benchTime)
	}
}

func BenchmarkTokenTrackerParallel(b *testing.B) {
	tracker := NewTokenTracker(nil)
	ctx := context.Background()

	// Pre-populate some keys
	for i := 0; i < 100; i++ {
		key := fmt.Sprintf("user=user-%d:day:20260313", i)
		tracker.Record(ctx, key, "day", 100, 50)
	}

	limit := &HierarchicalLimit{
		TotalTokenLimit: 100000,
		Period:          "day",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("user=user-%d:day:20260313", i%100)
			if i%2 == 0 {
				_, _, _ = tracker.Check(ctx, key, limit)
			} else {
				tracker.Record(ctx, key, "day", 10, 5)
			}
			i++
		}
	})
}

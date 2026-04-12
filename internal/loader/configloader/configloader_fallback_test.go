package configloader

import (
	"context"
	"testing"
)

func TestGetFallbackDepth(t *testing.T) {
	// Default context has depth 0
	ctx := context.Background()
	if got := GetFallbackDepth(ctx); got != 0 {
		t.Errorf("GetFallbackDepth(background) = %d, want 0", got)
	}

	// Set depth to 1
	ctx = WithFallbackDepth(ctx, 1)
	if got := GetFallbackDepth(ctx); got != 1 {
		t.Errorf("GetFallbackDepth(depth=1) = %d, want 1", got)
	}

	// Increment depth
	ctx = WithFallbackDepth(ctx, 2)
	if got := GetFallbackDepth(ctx); got != 2 {
		t.Errorf("GetFallbackDepth(depth=2) = %d, want 2", got)
	}
}

func TestWithFallbackDepth_Independent(t *testing.T) {
	ctx := context.Background()
	ctx1 := WithFallbackDepth(ctx, 1)
	ctx2 := WithFallbackDepth(ctx, 5)

	// Each context should have its own depth
	if got := GetFallbackDepth(ctx1); got != 1 {
		t.Errorf("ctx1 depth = %d, want 1", got)
	}
	if got := GetFallbackDepth(ctx2); got != 5 {
		t.Errorf("ctx2 depth = %d, want 5", got)
	}
	// Original context unchanged
	if got := GetFallbackDepth(ctx); got != 0 {
		t.Errorf("original ctx depth = %d, want 0", got)
	}
}

func BenchmarkGetFallbackDepth(b *testing.B) {
	b.ReportAllocs()
	ctx := WithFallbackDepth(context.Background(), 3)
	for i := 0; i < b.N; i++ {
		_ = GetFallbackDepth(ctx)
	}
}

func BenchmarkWithFallbackDepth(b *testing.B) {
	b.ReportAllocs()
	ctx := context.Background()
	for i := 0; i < b.N; i++ {
		_ = WithFallbackDepth(ctx, i)
	}
}

package rag

import (
	"testing"
)

func TestDefaultQueryOptions(t *testing.T) {
	t.Parallel()

	opts := DefaultQueryOptions()

	if opts.TopK != 5 {
		t.Errorf("TopK: got %d, want 5", opts.TopK)
	}
	if opts.Threshold != 0.7 {
		t.Errorf("Threshold: got %f, want 0.7", opts.Threshold)
	}
	if opts.Temperature != 0.1 {
		t.Errorf("Temperature: got %f, want 0.1", opts.Temperature)
	}
	if opts.Model != "" {
		t.Errorf("Model: got %q, want empty", opts.Model)
	}
	if opts.MaxTokens != 0 {
		t.Errorf("MaxTokens: got %d, want 0", opts.MaxTokens)
	}
	if opts.Filter != nil {
		t.Errorf("Filter: got %v, want nil", opts.Filter)
	}
	if opts.Namespace != "" {
		t.Errorf("Namespace: got %q, want empty", opts.Namespace)
	}
	if opts.Stream {
		t.Error("Stream: got true, want false")
	}
}

func TestApplyOptions_NoOpts(t *testing.T) {
	t.Parallel()

	opts := ApplyOptions(nil)
	defaults := DefaultQueryOptions()

	if opts.TopK != defaults.TopK {
		t.Errorf("TopK: got %d, want %d", opts.TopK, defaults.TopK)
	}
	if opts.Threshold != defaults.Threshold {
		t.Errorf("Threshold: got %f, want %f", opts.Threshold, defaults.Threshold)
	}
	if opts.Temperature != defaults.Temperature {
		t.Errorf("Temperature: got %f, want %f", opts.Temperature, defaults.Temperature)
	}
}

func TestWithTopK(t *testing.T) {
	t.Parallel()

	opts := ApplyOptions([]QueryOption{WithTopK(10)})
	if opts.TopK != 10 {
		t.Errorf("TopK: got %d, want 10", opts.TopK)
	}
	// Other defaults should remain unchanged.
	if opts.Threshold != 0.7 {
		t.Errorf("Threshold: got %f, want 0.7", opts.Threshold)
	}
}

func TestWithThreshold(t *testing.T) {
	t.Parallel()

	opts := ApplyOptions([]QueryOption{WithThreshold(0.9)})
	if opts.Threshold != 0.9 {
		t.Errorf("Threshold: got %f, want 0.9", opts.Threshold)
	}
}

func TestWithModel(t *testing.T) {
	t.Parallel()

	opts := ApplyOptions([]QueryOption{WithModel("gpt-4o")})
	if opts.Model != "gpt-4o" {
		t.Errorf("Model: got %q, want %q", opts.Model, "gpt-4o")
	}
}

func TestWithMaxTokens(t *testing.T) {
	t.Parallel()

	opts := ApplyOptions([]QueryOption{WithMaxTokens(512)})
	if opts.MaxTokens != 512 {
		t.Errorf("MaxTokens: got %d, want 512", opts.MaxTokens)
	}
}

func TestWithTemperature(t *testing.T) {
	t.Parallel()

	opts := ApplyOptions([]QueryOption{WithTemperature(0.8)})
	if opts.Temperature != 0.8 {
		t.Errorf("Temperature: got %f, want 0.8", opts.Temperature)
	}
}

func TestWithFilter(t *testing.T) {
	t.Parallel()

	filter := map[string]string{"source": "docs", "lang": "en"}
	opts := ApplyOptions([]QueryOption{WithFilter(filter)})
	if opts.Filter == nil {
		t.Fatal("Filter: got nil")
	}
	if opts.Filter["source"] != "docs" {
		t.Errorf("Filter[source]: got %q, want %q", opts.Filter["source"], "docs")
	}
	if opts.Filter["lang"] != "en" {
		t.Errorf("Filter[lang]: got %q, want %q", opts.Filter["lang"], "en")
	}
}

func TestWithNamespace(t *testing.T) {
	t.Parallel()

	opts := ApplyOptions([]QueryOption{WithNamespace("workspace-42")})
	if opts.Namespace != "workspace-42" {
		t.Errorf("Namespace: got %q, want %q", opts.Namespace, "workspace-42")
	}
}

func TestWithStream(t *testing.T) {
	t.Parallel()

	opts := ApplyOptions([]QueryOption{WithStream(true)})
	if !opts.Stream {
		t.Error("Stream: got false, want true")
	}

	opts2 := ApplyOptions([]QueryOption{WithStream(false)})
	if opts2.Stream {
		t.Error("Stream: got true, want false")
	}
}

func TestApplyOptions_MultipleOptions(t *testing.T) {
	t.Parallel()

	opts := ApplyOptions([]QueryOption{
		WithTopK(20),
		WithThreshold(0.5),
		WithModel("claude-3"),
		WithMaxTokens(1024),
		WithTemperature(0.7),
		WithFilter(map[string]string{"type": "pdf"}),
		WithNamespace("tenant-1"),
		WithStream(true),
	})

	if opts.TopK != 20 {
		t.Errorf("TopK: got %d, want 20", opts.TopK)
	}
	if opts.Threshold != 0.5 {
		t.Errorf("Threshold: got %f, want 0.5", opts.Threshold)
	}
	if opts.Model != "claude-3" {
		t.Errorf("Model: got %q, want %q", opts.Model, "claude-3")
	}
	if opts.MaxTokens != 1024 {
		t.Errorf("MaxTokens: got %d, want 1024", opts.MaxTokens)
	}
	if opts.Temperature != 0.7 {
		t.Errorf("Temperature: got %f, want 0.7", opts.Temperature)
	}
	if opts.Filter["type"] != "pdf" {
		t.Errorf("Filter[type]: got %q, want %q", opts.Filter["type"], "pdf")
	}
	if opts.Namespace != "tenant-1" {
		t.Errorf("Namespace: got %q, want %q", opts.Namespace, "tenant-1")
	}
	if !opts.Stream {
		t.Error("Stream: got false, want true")
	}
}

func TestApplyOptions_LastOptionWins(t *testing.T) {
	t.Parallel()

	opts := ApplyOptions([]QueryOption{
		WithTopK(5),
		WithTopK(10),
		WithTopK(15),
	})
	if opts.TopK != 15 {
		t.Errorf("TopK: got %d, want 15 (last option should win)", opts.TopK)
	}
}

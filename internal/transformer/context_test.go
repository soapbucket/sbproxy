package transformer

import (
	"context"
	"sync"
	"testing"
)

func TestNewTransformContext(t *testing.T) {
	tc := NewTransformContext(5, "application/json", 1024)
	if tc.Total != 5 {
		t.Errorf("Total = %d, want 5", tc.Total)
	}
	if tc.ContentType != "application/json" {
		t.Errorf("ContentType = %q, want %q", tc.ContentType, "application/json")
	}
	if tc.OriginalSize != 1024 {
		t.Errorf("OriginalSize = %d, want 1024", tc.OriginalSize)
	}
	if tc.Index != 0 {
		t.Errorf("Index = %d, want 0", tc.Index)
	}
}

func TestTransformContext_Metadata(t *testing.T) {
	tc := NewTransformContext(1, "", 0)

	// Key not found
	if _, ok := tc.GetMetadata("missing"); ok {
		t.Error("expected missing key to return false")
	}

	// Set and get
	tc.SetMetadata("format", "gzip")
	val, ok := tc.GetMetadata("format")
	if !ok {
		t.Fatal("expected key to exist")
	}
	if val != "gzip" {
		t.Errorf("expected 'gzip', got %v", val)
	}

	// Overwrite
	tc.SetMetadata("format", "br")
	val, _ = tc.GetMetadata("format")
	if val != "br" {
		t.Errorf("expected 'br', got %v", val)
	}
}

func TestTransformContext_Errors(t *testing.T) {
	tc := NewTransformContext(3, "", 0)

	if tc.HasErrors() {
		t.Error("new context should have no errors")
	}
	if errs := tc.Errors(); errs != nil {
		t.Errorf("expected nil errors, got %v", errs)
	}

	tc.Index = 1
	tc.RecordError("json", "invalid syntax")

	if !tc.HasErrors() {
		t.Error("expected HasErrors() to be true")
	}

	errs := tc.Errors()
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d", len(errs))
	}
	if errs[0].Index != 1 {
		t.Errorf("error index = %d, want 1", errs[0].Index)
	}
	if errs[0].Type != "json" {
		t.Errorf("error type = %q, want 'json'", errs[0].Type)
	}
	if errs[0].Message != "invalid syntax" {
		t.Errorf("error message = %q, want 'invalid syntax'", errs[0].Message)
	}

	// Verify returned slice is a copy
	errs[0].Message = "mutated"
	originalErrs := tc.Errors()
	if originalErrs[0].Message == "mutated" {
		t.Error("Errors() should return a copy, not a reference")
	}
}

func TestTransformContext_ConcurrentAccess(t *testing.T) {
	tc := NewTransformContext(10, "", 0)
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			tc.SetMetadata("key", n)
			tc.GetMetadata("key")
			tc.RecordError("test", "concurrent error")
			tc.HasErrors()
			tc.Errors()
		}(i)
	}
	wg.Wait()

	if !tc.HasErrors() {
		t.Error("expected errors after concurrent writes")
	}
}

func TestWithTransformContext_RoundTrip(t *testing.T) {
	tc := NewTransformContext(3, "text/html", 512)
	ctx := WithTransformContext(context.Background(), tc)

	retrieved := GetTransformContext(ctx)
	if retrieved == nil {
		t.Fatal("expected non-nil TransformContext")
	}
	if retrieved != tc {
		t.Error("expected same pointer")
	}
	if retrieved.Total != 3 {
		t.Errorf("Total = %d, want 3", retrieved.Total)
	}
}

func TestGetTransformContext_NilWhenMissing(t *testing.T) {
	tc := GetTransformContext(context.Background())
	if tc != nil {
		t.Errorf("expected nil, got %v", tc)
	}
}

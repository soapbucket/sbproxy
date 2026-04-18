package telemetry

import (
	"sync"
	"testing"
	"time"
)

func TestStartPipelineSpanReturnsCorrectType(t *testing.T) {
	span := StartPipelineSpan("test", nil)
	// Ensure the return type is *Span (compile-time check)
	var _ *Span = span
	if span == nil {
		t.Fatal("expected non-nil Span")
	}
}

func TestStartPipelineSpanWithParent(t *testing.T) {
	parent := &TraceContext{
		TraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:  "00f067aa0ba902b7",
		Sampled: true,
	}

	span := StartPipelineSpan("auth", parent)
	if span == nil {
		t.Fatal("expected non-nil span")
	}
	if span.Name != "auth" {
		t.Errorf("Name = %q, want %q", span.Name, "auth")
	}
	if span.TraceID != parent.TraceID {
		t.Errorf("TraceID = %q, want parent's %q", span.TraceID, parent.TraceID)
	}
	if span.ParentID != parent.SpanID {
		t.Errorf("ParentID = %q, want parent's SpanID %q", span.ParentID, parent.SpanID)
	}
	if len(span.SpanID) != 16 {
		t.Errorf("SpanID should be 16 chars, got %d", len(span.SpanID))
	}
	if span.SpanID == parent.SpanID {
		t.Error("Span should have its own SpanID, not parent's")
	}
	if span.StartTime.IsZero() {
		t.Error("StartTime should be set")
	}
}

func TestStartPipelineSpanWithoutParent(t *testing.T) {
	span := StartPipelineSpan("request", nil)
	if span == nil {
		t.Fatal("expected non-nil span")
	}
	if len(span.TraceID) != 32 {
		t.Errorf("TraceID should be 32 chars when no parent, got %d", len(span.TraceID))
	}
	if span.ParentID != "" {
		t.Errorf("ParentID should be empty without parent, got %q", span.ParentID)
	}
}

func TestSpanEnd(t *testing.T) {
	span := StartPipelineSpan("test", nil)
	if !span.EndTime.IsZero() {
		t.Error("EndTime should be zero before End()")
	}

	time.Sleep(time.Millisecond)
	span.End()

	if span.EndTime.IsZero() {
		t.Error("EndTime should be set after End()")
	}
	if !span.EndTime.After(span.StartTime) {
		t.Error("EndTime should be after StartTime")
	}
}

func TestSpanDuration(t *testing.T) {
	span := StartPipelineSpan("test", nil)
	time.Sleep(5 * time.Millisecond)
	span.End()

	d := span.Duration()
	if d < 5*time.Millisecond {
		t.Errorf("Duration = %v, expected >= 5ms", d)
	}
}

func TestSpanDurationBeforeEnd(t *testing.T) {
	span := StartPipelineSpan("test", nil)
	time.Sleep(2 * time.Millisecond)

	d := span.Duration()
	if d < 2*time.Millisecond {
		t.Errorf("Duration before End = %v, expected >= 2ms", d)
	}
}

func TestSpanSetAttr(t *testing.T) {
	span := StartPipelineSpan("test", nil)
	span.SetAttr("http.method", "GET")
	span.SetAttr("http.status_code", "200")

	val, ok := span.GetAttr("http.method")
	if !ok || val != "GET" {
		t.Errorf("GetAttr(http.method) = %q, %v, want %q, true", val, ok, "GET")
	}

	val, ok = span.GetAttr("http.status_code")
	if !ok || val != "200" {
		t.Errorf("GetAttr(http.status_code) = %q, %v, want %q, true", val, ok, "200")
	}

	_, ok = span.GetAttr("missing")
	if ok {
		t.Error("GetAttr should return false for missing key")
	}
}

func TestSpanSetAttrOverwrite(t *testing.T) {
	span := StartPipelineSpan("test", nil)
	span.SetAttr("key", "value1")
	span.SetAttr("key", "value2")

	val, ok := span.GetAttr("key")
	if !ok || val != "value2" {
		t.Errorf("GetAttr after overwrite = %q, want %q", val, "value2")
	}
}

func TestSpanAttrs(t *testing.T) {
	span := StartPipelineSpan("test", nil)
	span.SetAttr("a", "1")
	span.SetAttr("b", "2")

	attrs := span.Attrs()
	if len(attrs) != 2 {
		t.Errorf("Attrs() returned %d entries, want 2", len(attrs))
	}
	if attrs["a"] != "1" || attrs["b"] != "2" {
		t.Errorf("Attrs() = %v, want map[a:1 b:2]", attrs)
	}

	// Verify it is a copy
	attrs["c"] = "3"
	attrs2 := span.Attrs()
	if len(attrs2) != 2 {
		t.Error("Attrs() should return a copy, not a reference")
	}
}

func TestSpanAttrsConcurrent(t *testing.T) {
	span := StartPipelineSpan("test", nil)
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			span.SetAttr("key", "value")
			span.GetAttr("key")
			span.Attrs()
		}(i)
	}

	wg.Wait()
}

func TestSpanToTraceContext(t *testing.T) {
	parent := &TraceContext{
		TraceID: GenerateTraceID(),
		SpanID:  GenerateSpanID(),
		Sampled: true,
	}

	span := StartPipelineSpan("middleware", parent)
	ctx := span.ToTraceContext()

	if ctx.TraceID != span.TraceID {
		t.Errorf("TraceID = %q, want %q", ctx.TraceID, span.TraceID)
	}
	if ctx.SpanID != span.SpanID {
		t.Errorf("SpanID = %q, want %q", ctx.SpanID, span.SpanID)
	}
	if !ctx.Sampled {
		t.Error("Sampled should be true")
	}
}

func TestSpanChaining(t *testing.T) {
	// Simulate a pipeline: request -> auth -> proxy
	root := StartPipelineSpan("request", nil)
	rootCtx := root.ToTraceContext()

	auth := StartPipelineSpan("auth", rootCtx)
	authCtx := auth.ToTraceContext()

	proxy := StartPipelineSpan("proxy", authCtx)

	// All should share the same trace ID
	if root.TraceID != auth.TraceID || auth.TraceID != proxy.TraceID {
		t.Errorf("Trace IDs should match: root=%q, auth=%q, proxy=%q",
			root.TraceID, auth.TraceID, proxy.TraceID)
	}

	// Parent chain should be correct
	if auth.ParentID != root.SpanID {
		t.Errorf("auth.ParentID = %q, want root.SpanID = %q", auth.ParentID, root.SpanID)
	}
	if proxy.ParentID != auth.SpanID {
		t.Errorf("proxy.ParentID = %q, want auth.SpanID = %q", proxy.ParentID, auth.SpanID)
	}

	// All span IDs should be unique
	ids := map[string]bool{root.SpanID: true, auth.SpanID: true, proxy.SpanID: true}
	if len(ids) != 3 {
		t.Error("All span IDs should be unique")
	}
}

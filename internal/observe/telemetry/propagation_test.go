package telemetry

import (
	"net/http"
	"testing"
)

func TestExtractW3C(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		wantNil  bool
		traceID  string
		spanID   string
		sampled  bool
		state    string
	}{
		{
			name:    "valid traceparent sampled",
			headers: map[string]string{"Traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
			traceID: "4bf92f3577b34da6a3ce929d0e0e4736",
			spanID:  "00f067aa0ba902b7",
			sampled: true,
		},
		{
			name:    "valid traceparent not sampled",
			headers: map[string]string{"Traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"},
			traceID: "4bf92f3577b34da6a3ce929d0e0e4736",
			spanID:  "00f067aa0ba902b7",
			sampled: false,
		},
		{
			name: "with tracestate",
			headers: map[string]string{
				"Traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
				"Tracestate":  "congo=t61rcWkgMzE",
			},
			traceID: "4bf92f3577b34da6a3ce929d0e0e4736",
			spanID:  "00f067aa0ba902b7",
			sampled: true,
			state:   "congo=t61rcWkgMzE",
		},
		{
			name:    "missing header",
			headers: map[string]string{},
			wantNil: true,
		},
		{
			name:    "too few parts",
			headers: map[string]string{"Traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736"},
			wantNil: true,
		},
		{
			name:    "invalid trace ID length",
			headers: map[string]string{"Traceparent": "00-4bf92f35-00f067aa0ba902b7-01"},
			wantNil: true,
		},
		{
			name:    "all-zero trace ID",
			headers: map[string]string{"Traceparent": "00-00000000000000000000000000000000-00f067aa0ba902b7-01"},
			wantNil: true,
		},
		{
			name:    "all-zero span ID",
			headers: map[string]string{"Traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01"},
			wantNil: true,
		},
		{
			name:    "invalid hex in trace ID",
			headers: map[string]string{"Traceparent": "00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-00f067aa0ba902b7-01"},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			for k, v := range tt.headers {
				h.Set(k, v)
			}

			ctx := ExtractW3C(h)
			if tt.wantNil {
				if ctx != nil {
					t.Fatalf("expected nil, got %+v", ctx)
				}
				return
			}
			if ctx == nil {
				t.Fatal("expected non-nil TraceContext")
			}
			if ctx.TraceID != tt.traceID {
				t.Errorf("TraceID = %q, want %q", ctx.TraceID, tt.traceID)
			}
			if ctx.SpanID != tt.spanID {
				t.Errorf("SpanID = %q, want %q", ctx.SpanID, tt.spanID)
			}
			if ctx.Sampled != tt.sampled {
				t.Errorf("Sampled = %v, want %v", ctx.Sampled, tt.sampled)
			}
			if ctx.TraceState != tt.state {
				t.Errorf("TraceState = %q, want %q", ctx.TraceState, tt.state)
			}
		})
	}
}

func TestInjectW3C(t *testing.T) {
	ctx := &TraceContext{
		TraceID:    "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:     "00f067aa0ba902b7",
		Sampled:    true,
		TraceState: "congo=t61rcWkgMzE",
	}

	h := http.Header{}
	InjectW3C(ctx, h)

	expected := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	if got := h.Get("Traceparent"); got != expected {
		t.Errorf("Traceparent = %q, want %q", got, expected)
	}
	if got := h.Get("Tracestate"); got != "congo=t61rcWkgMzE" {
		t.Errorf("Tracestate = %q, want %q", got, "congo=t61rcWkgMzE")
	}
}

func TestInjectW3CNotSampled(t *testing.T) {
	ctx := &TraceContext{
		TraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:  "00f067aa0ba902b7",
		Sampled: false,
	}

	h := http.Header{}
	InjectW3C(ctx, h)

	expected := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"
	if got := h.Get("Traceparent"); got != expected {
		t.Errorf("Traceparent = %q, want %q", got, expected)
	}
	if got := h.Get("Tracestate"); got != "" {
		t.Errorf("Tracestate should be empty, got %q", got)
	}
}

func TestInjectW3CNil(t *testing.T) {
	h := http.Header{}
	InjectW3C(nil, h)
	if got := h.Get("Traceparent"); got != "" {
		t.Errorf("Expected empty header for nil context, got %q", got)
	}
}

func TestExtractB3Multi(t *testing.T) {
	h := http.Header{}
	h.Set("X-B3-TraceId", "463ac35c9f6413ad48485a3953bb6124")
	h.Set("X-B3-SpanId", "0020000000000001")
	h.Set("X-B3-ParentSpanId", "0000000000000000")
	h.Set("X-B3-Sampled", "1")

	ctx := ExtractB3(h)
	if ctx == nil {
		t.Fatal("expected non-nil TraceContext")
	}
	if ctx.TraceID != "463ac35c9f6413ad48485a3953bb6124" {
		t.Errorf("TraceID = %q, want %q", ctx.TraceID, "463ac35c9f6413ad48485a3953bb6124")
	}
	if ctx.SpanID != "0020000000000001" {
		t.Errorf("SpanID = %q, want %q", ctx.SpanID, "0020000000000001")
	}
	if ctx.ParentID != "0000000000000000" {
		t.Errorf("ParentID = %q, want %q", ctx.ParentID, "0000000000000000")
	}
	if !ctx.Sampled {
		t.Error("Expected Sampled = true")
	}
}

func TestExtractB3Multi64BitTraceID(t *testing.T) {
	h := http.Header{}
	h.Set("X-B3-TraceId", "463ac35c9f6413ad")
	h.Set("X-B3-SpanId", "0020000000000001")

	ctx := ExtractB3(h)
	if ctx == nil {
		t.Fatal("expected non-nil TraceContext")
	}
	// 64-bit trace IDs should be padded to 128-bit
	if ctx.TraceID != "0000000000000000463ac35c9f6413ad" {
		t.Errorf("TraceID = %q, want padded 128-bit", ctx.TraceID)
	}
}

func TestExtractB3Single(t *testing.T) {
	tests := []struct {
		name     string
		b3       string
		wantNil  bool
		traceID  string
		spanID   string
		parentID string
		sampled  bool
	}{
		{
			name:    "full format",
			b3:      "463ac35c9f6413ad48485a3953bb6124-0020000000000001-1-0000000000000002",
			traceID: "463ac35c9f6413ad48485a3953bb6124",
			spanID:  "0020000000000001",
			parentID: "0000000000000002",
			sampled: true,
		},
		{
			name:    "without parent",
			b3:      "463ac35c9f6413ad48485a3953bb6124-0020000000000001-0",
			traceID: "463ac35c9f6413ad48485a3953bb6124",
			spanID:  "0020000000000001",
			sampled: false,
		},
		{
			name:    "minimal",
			b3:      "463ac35c9f6413ad48485a3953bb6124-0020000000000001",
			traceID: "463ac35c9f6413ad48485a3953bb6124",
			spanID:  "0020000000000001",
			sampled: true, // default
		},
		{
			name:    "64-bit trace ID",
			b3:      "463ac35c9f6413ad-0020000000000001-1",
			traceID: "0000000000000000463ac35c9f6413ad",
			spanID:  "0020000000000001",
			sampled: true,
		},
		{
			name:    "deny shorthand",
			b3:      "0",
			traceID: "",
			sampled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			h.Set("B3", tt.b3)

			ctx := ExtractB3(h)
			if tt.wantNil {
				if ctx != nil {
					t.Fatalf("expected nil, got %+v", ctx)
				}
				return
			}
			if ctx == nil {
				t.Fatal("expected non-nil TraceContext")
			}
			if ctx.TraceID != tt.traceID {
				t.Errorf("TraceID = %q, want %q", ctx.TraceID, tt.traceID)
			}
			if tt.spanID != "" && ctx.SpanID != tt.spanID {
				t.Errorf("SpanID = %q, want %q", ctx.SpanID, tt.spanID)
			}
			if ctx.ParentID != tt.parentID {
				t.Errorf("ParentID = %q, want %q", ctx.ParentID, tt.parentID)
			}
			if ctx.Sampled != tt.sampled {
				t.Errorf("Sampled = %v, want %v", ctx.Sampled, tt.sampled)
			}
		})
	}
}

func TestInjectB3(t *testing.T) {
	ctx := &TraceContext{
		TraceID:  "463ac35c9f6413ad48485a3953bb6124",
		SpanID:   "0020000000000001",
		ParentID: "0000000000000002",
		Sampled:  true,
	}

	h := http.Header{}
	InjectB3(ctx, h)

	if got := h.Get("X-B3-TraceId"); got != ctx.TraceID {
		t.Errorf("X-B3-TraceId = %q, want %q", got, ctx.TraceID)
	}
	if got := h.Get("X-B3-SpanId"); got != ctx.SpanID {
		t.Errorf("X-B3-SpanId = %q, want %q", got, ctx.SpanID)
	}
	if got := h.Get("X-B3-ParentSpanId"); got != ctx.ParentID {
		t.Errorf("X-B3-ParentSpanId = %q, want %q", got, ctx.ParentID)
	}
	if got := h.Get("X-B3-Sampled"); got != "1" {
		t.Errorf("X-B3-Sampled = %q, want %q", got, "1")
	}
}

func TestInjectB3Nil(t *testing.T) {
	h := http.Header{}
	InjectB3(nil, h)
	if got := h.Get("X-B3-TraceId"); got != "" {
		t.Errorf("Expected empty header for nil context, got %q", got)
	}
}

func TestInjectB3NoParent(t *testing.T) {
	ctx := &TraceContext{
		TraceID: "463ac35c9f6413ad48485a3953bb6124",
		SpanID:  "0020000000000001",
		Sampled: false,
	}

	h := http.Header{}
	InjectB3(ctx, h)

	if got := h.Get("X-B3-ParentSpanId"); got != "" {
		t.Errorf("Expected no ParentSpanId header, got %q", got)
	}
	if got := h.Get("X-B3-Sampled"); got != "0" {
		t.Errorf("X-B3-Sampled = %q, want %q", got, "0")
	}
}

func TestExtractPrefersW3C(t *testing.T) {
	h := http.Header{}
	h.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	h.Set("X-B3-TraceId", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
	h.Set("X-B3-SpanId", "bbbbbbbbbbbbbbbb")

	ctx := Extract(h)
	if ctx == nil {
		t.Fatal("expected non-nil")
	}
	// Should use W3C trace ID, not B3
	if ctx.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("Expected W3C trace ID, got %q", ctx.TraceID)
	}
}

func TestExtractFallsBackToB3(t *testing.T) {
	h := http.Header{}
	h.Set("X-B3-TraceId", "463ac35c9f6413ad48485a3953bb6124")
	h.Set("X-B3-SpanId", "0020000000000001")

	ctx := Extract(h)
	if ctx == nil {
		t.Fatal("expected non-nil")
	}
	if ctx.TraceID != "463ac35c9f6413ad48485a3953bb6124" {
		t.Errorf("Expected B3 trace ID, got %q", ctx.TraceID)
	}
}

func TestExtractNoHeaders(t *testing.T) {
	h := http.Header{}
	ctx := Extract(h)
	if ctx != nil {
		t.Errorf("Expected nil for no trace headers, got %+v", ctx)
	}
}

func TestGenerateTraceID(t *testing.T) {
	id := GenerateTraceID()
	if len(id) != 32 {
		t.Errorf("Expected 32-char trace ID, got %d chars: %q", len(id), id)
	}
	if !isHex(id) {
		t.Errorf("Trace ID contains non-hex chars: %q", id)
	}

	// Two generated IDs should be different
	id2 := GenerateTraceID()
	if id == id2 {
		t.Error("Expected unique trace IDs")
	}
}

func TestGenerateSpanID(t *testing.T) {
	id := GenerateSpanID()
	if len(id) != 16 {
		t.Errorf("Expected 16-char span ID, got %d chars: %q", len(id), id)
	}
	if !isHex(id) {
		t.Errorf("Span ID contains non-hex chars: %q", id)
	}

	id2 := GenerateSpanID()
	if id == id2 {
		t.Error("Expected unique span IDs")
	}
}

func TestW3CRoundTrip(t *testing.T) {
	original := &TraceContext{
		TraceID:    GenerateTraceID(),
		SpanID:     GenerateSpanID(),
		Sampled:    true,
		TraceState: "vendor=value",
	}

	h := http.Header{}
	InjectW3C(original, h)

	extracted := ExtractW3C(h)
	if extracted == nil {
		t.Fatal("expected non-nil after round trip")
	}
	if extracted.TraceID != original.TraceID {
		t.Errorf("TraceID mismatch: %q != %q", extracted.TraceID, original.TraceID)
	}
	if extracted.SpanID != original.SpanID {
		t.Errorf("SpanID mismatch: %q != %q", extracted.SpanID, original.SpanID)
	}
	if extracted.Sampled != original.Sampled {
		t.Errorf("Sampled mismatch: %v != %v", extracted.Sampled, original.Sampled)
	}
	if extracted.TraceState != original.TraceState {
		t.Errorf("TraceState mismatch: %q != %q", extracted.TraceState, original.TraceState)
	}
}

func TestB3RoundTrip(t *testing.T) {
	original := &TraceContext{
		TraceID:  GenerateTraceID(),
		SpanID:   GenerateSpanID(),
		ParentID: GenerateSpanID(),
		Sampled:  true,
	}

	h := http.Header{}
	InjectB3(original, h)

	extracted := ExtractB3(h)
	if extracted == nil {
		t.Fatal("expected non-nil after round trip")
	}
	if extracted.TraceID != original.TraceID {
		t.Errorf("TraceID mismatch: %q != %q", extracted.TraceID, original.TraceID)
	}
	if extracted.SpanID != original.SpanID {
		t.Errorf("SpanID mismatch: %q != %q", extracted.SpanID, original.SpanID)
	}
	if extracted.ParentID != original.ParentID {
		t.Errorf("ParentID mismatch: %q != %q", extracted.ParentID, original.ParentID)
	}
	if extracted.Sampled != original.Sampled {
		t.Errorf("Sampled mismatch: %v != %v", extracted.Sampled, original.Sampled)
	}
}

func TestIsHex(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"0123456789abcdef", true},
		{"ABCDEF", true},
		{"0", true},
		{"", false},
		{"xyz", false},
		{"12g4", false},
	}

	for _, tt := range tests {
		got := isHex(tt.input)
		if got != tt.want {
			t.Errorf("isHex(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

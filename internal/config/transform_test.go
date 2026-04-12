package config

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/transformer"
)

// mockTransform records whether Modify was called.
type mockTransform struct {
	called bool
}

func (m *mockTransform) Modify(resp *http.Response) error {
	m.called = true
	return nil
}

func newTestTransform(maxBodySize int64) (*BaseTransform, *mockTransform) {
	mock := &mockTransform{}
	bt := &BaseTransform{
		TransformType: "test",
		MaxBodySize:   maxBodySize,
		tr:            mock,
	}
	return bt, mock
}

func newTestResponse(contentLength int64) *http.Response {
	return &http.Response{
		StatusCode:    200,
		ContentLength: contentLength,
		Header:        http.Header{"Content-Type": []string{"text/html"}},
		Body:          io.NopCloser(strings.NewReader("hello")),
	}
}

func TestTransformApply_SkipsLargeBody(t *testing.T) {
	bt, mock := newTestTransform(1024) // 1KB limit
	resp := newTestResponse(2048)      // 2KB body

	err := bt.Apply(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.called {
		t.Error("expected transform to be skipped for body exceeding max_body_size")
	}
}

func TestTransformApply_AllowsBodyUnderLimit(t *testing.T) {
	bt, mock := newTestTransform(1024) // 1KB limit
	resp := newTestResponse(512)       // 512B body

	err := bt.Apply(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mock.called {
		t.Error("expected transform to run for body under max_body_size")
	}
}

func TestTransformApply_AllowsBodyAtExactLimit(t *testing.T) {
	bt, mock := newTestTransform(1024) // 1KB limit
	resp := newTestResponse(1024)      // exactly at limit

	err := bt.Apply(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mock.called {
		t.Error("expected transform to run for body at exactly max_body_size")
	}
}

func TestTransformApply_DefaultMaxBodySize(t *testing.T) {
	bt, mock := newTestTransform(0)                                        // 0 = use default
	resp := newTestResponse(int64(httputil.DefaultTransformThreshold) + 1) // just over 10MB

	err := bt.Apply(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.called {
		t.Error("expected transform to be skipped: body exceeds default 10MB threshold")
	}
}

func TestTransformApply_DefaultAllowsUnder10MB(t *testing.T) {
	bt, mock := newTestTransform(0)                                        // 0 = use default
	resp := newTestResponse(int64(httputil.DefaultTransformThreshold) - 1) // just under 10MB

	err := bt.Apply(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mock.called {
		t.Error("expected transform to run for body under default 10MB threshold")
	}
}

func TestTransformApply_UnlimitedMaxBodySize(t *testing.T) {
	bt, mock := newTestTransform(-1)           // -1 = unlimited
	resp := newTestResponse(500 * 1024 * 1024) // 500MB

	err := bt.Apply(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mock.called {
		t.Error("expected transform to run with unlimited max_body_size (-1)")
	}
}

func TestTransformApply_NoContentLength(t *testing.T) {
	bt, mock := newTestTransform(1024) // 1KB limit
	resp := newTestResponse(-1)        // unknown Content-Length (chunked)

	err := bt.Apply(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mock.called {
		t.Error("expected transform to run when Content-Length is unknown (-1)")
	}
}

func TestTransformApply_ZeroContentLength(t *testing.T) {
	bt, mock := newTestTransform(1024) // 1KB limit
	resp := newTestResponse(0)         // empty body

	err := bt.Apply(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mock.called {
		t.Error("expected transform to run for empty body (Content-Length 0)")
	}
}

func TestEffectiveMaxBodySize(t *testing.T) {
	tests := []struct {
		name     string
		input    int64
		expected int64
	}{
		{"zero uses default", 0, int64(httputil.DefaultTransformThreshold)},
		{"positive uses configured", 5000, 5000},
		{"negative one means unlimited", -1, -1},
		{"large value preserved", 100 * 1024 * 1024, 100 * 1024 * 1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bt := &BaseTransform{MaxBodySize: tt.input}
			got := bt.effectiveMaxBodySize()
			if got != tt.expected {
				t.Errorf("effectiveMaxBodySize() = %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestTransformApply_DisabledSkipsEvenSmallBody(t *testing.T) {
	mock := &mockTransform{}
	bt := &BaseTransform{
		TransformType: "test",
		Disabled:      true,
		tr:            mock,
	}
	resp := newTestResponse(100)

	err := bt.Apply(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.called {
		t.Error("expected disabled transform to be skipped")
	}
}

// Ensure the unused import is referenced
var _ = transformer.Func(nil)

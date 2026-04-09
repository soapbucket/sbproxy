package transformer

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func makeResponse(body string) *http.Response {
	return &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Content-Type": []string{"text/html"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       &http.Request{Header: http.Header{}},
	}
}

func TestInstrumentedPipeline_Execution(t *testing.T) {
	var order []string

	stageA := NamedTransform{
		Name: "alpha",
		Transformer: Func(func(resp *http.Response) error {
			order = append(order, "alpha")
			return nil
		}),
	}
	stageB := NamedTransform{
		Name: "beta",
		Transformer: Func(func(resp *http.Response) error {
			order = append(order, "beta")
			return nil
		}),
	}

	pipeline := NewInstrumentedPipeline(stageA, stageB)
	resp := makeResponse("hello world")

	if err := pipeline.Modify(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(order) != 2 || order[0] != "alpha" || order[1] != "beta" {
		t.Fatalf("stages executed out of order: %v", order)
	}

	result := pipeline.Result()
	if result == nil {
		t.Fatal("result should not be nil after Modify")
	}
	if len(result.Stages) != 2 {
		t.Fatalf("expected 2 stages, got %d", len(result.Stages))
	}
	if result.Stages[0].Name != "alpha" {
		t.Errorf("expected stage 0 name 'alpha', got %q", result.Stages[0].Name)
	}
	if result.Stages[1].Name != "beta" {
		t.Errorf("expected stage 1 name 'beta', got %q", result.Stages[1].Name)
	}
	if result.TotalDuration <= 0 {
		t.Error("total duration should be positive")
	}
	if result.Error != "" {
		t.Errorf("expected no error, got %q", result.Error)
	}

	// Each stage should have recorded timing.
	for i, s := range result.Stages {
		if s.Duration < 0 {
			t.Errorf("stage %d duration should be non-negative, got %v", i, s.Duration)
		}
	}
}

func TestInstrumentedPipeline_VisualizationHeader(t *testing.T) {
	stageA := NamedTransform{
		Name:      "encoding",
		Transformer: Func(func(*http.Response) error { return nil }),
	}
	stageB := NamedTransform{
		Name:      "html",
		Transformer: Func(func(*http.Response) error { return nil }),
	}

	pipeline := NewInstrumentedPipeline(stageA, stageB)

	// Before execution, visualization should be empty.
	if v := pipeline.VisualizationHeader(); v != "" {
		t.Errorf("expected empty visualization before Modify, got %q", v)
	}

	resp := makeResponse("test")
	if err := pipeline.Modify(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	viz := pipeline.VisualizationHeader()
	if !strings.Contains(viz, "encoding(") {
		t.Errorf("visualization should contain 'encoding(', got %q", viz)
	}
	if !strings.Contains(viz, " > ") {
		t.Errorf("visualization should contain ' > ' separator, got %q", viz)
	}
	if !strings.Contains(viz, "html(") {
		t.Errorf("visualization should contain 'html(', got %q", viz)
	}

	// Test InjectHeader.
	resp2 := makeResponse("test")
	pipeline.InjectHeader(resp2, "X-Sb-Transforms")
	if resp2.Header.Get("X-Sb-Transforms") != viz {
		t.Errorf("injected header mismatch: got %q, want %q", resp2.Header.Get("X-Sb-Transforms"), viz)
	}
}

func TestInstrumentedPipeline_ErrorStopsExecution(t *testing.T) {
	errTest := errors.New("stage failed")
	var executed []string

	stageA := NamedTransform{
		Name: "first",
		Transformer: Func(func(*http.Response) error {
			executed = append(executed, "first")
			return nil
		}),
	}
	stageB := NamedTransform{
		Name: "failing",
		Transformer: Func(func(*http.Response) error {
			executed = append(executed, "failing")
			return errTest
		}),
	}
	stageC := NamedTransform{
		Name: "third",
		Transformer: Func(func(*http.Response) error {
			executed = append(executed, "third")
			return nil
		}),
	}

	pipeline := NewInstrumentedPipeline(stageA, stageB, stageC)
	resp := makeResponse("test")

	err := pipeline.Modify(resp)
	if err == nil {
		t.Fatal("expected error from pipeline")
	}
	if !errors.Is(err, errTest) {
		t.Errorf("expected errTest, got %v", err)
	}

	if len(executed) != 2 || executed[0] != "first" || executed[1] != "failing" {
		t.Fatalf("expected [first, failing], got %v", executed)
	}

	result := pipeline.Result()
	if result == nil {
		t.Fatal("result should not be nil after error")
	}
	if len(result.Stages) != 2 {
		t.Fatalf("expected 2 stages recorded, got %d", len(result.Stages))
	}
	if result.Stages[1].Error == "" {
		t.Error("failing stage should have error recorded")
	}
	if result.Error == "" {
		t.Error("pipeline result should have error set")
	}
}

func TestInstrumentedPipeline_EmptyPipeline(t *testing.T) {
	pipeline := NewInstrumentedPipeline()
	resp := makeResponse("unchanged")

	if err := pipeline.Modify(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := pipeline.Result()
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if len(result.Stages) != 0 {
		t.Errorf("expected 0 stages, got %d", len(result.Stages))
	}
	if result.Error != "" {
		t.Errorf("expected no error, got %q", result.Error)
	}

	if viz := pipeline.VisualizationHeader(); viz != "" {
		t.Errorf("expected empty visualization for empty pipeline, got %q", viz)
	}
}

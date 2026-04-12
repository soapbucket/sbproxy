package transformer

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func BenchmarkInstrumentedPipeline_ThreeStages(b *testing.B) {
	b.ReportAllocs()
	stages := []NamedTransform{
		{Name: "upper", Transformer: Func(func(resp *http.Response) error { return nil })},
		{Name: "trim", Transformer: Func(func(resp *http.Response) error { return nil })},
		{Name: "encode", Transformer: Func(func(resp *http.Response) error { return nil })},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := &http.Response{Body: io.NopCloser(strings.NewReader("test body")), Header: http.Header{}}
		p := NewInstrumentedPipeline(stages...)
		p.Modify(resp)
	}
}

func BenchmarkInstrumentedPipeline_SingleStage(b *testing.B) {
	b.ReportAllocs()
	stages := []NamedTransform{
		{Name: "noop", Transformer: Func(func(resp *http.Response) error { return nil })},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := &http.Response{Body: io.NopCloser(strings.NewReader("x")), Header: http.Header{}}
		p := NewInstrumentedPipeline(stages...)
		p.Modify(resp)
	}
}

func BenchmarkCostTracker_Record(b *testing.B) {
	b.ReportAllocs()
	ct := NewCostTracker()
	// Pre-create entry to benchmark steady-state.
	ct.Record("html", "origin-1", 5*time.Millisecond, 1024, 2048, nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ct.Record("html", "origin-1", 5*time.Millisecond, 1024, 2048, nil)
	}
}

func BenchmarkCostTracker_Snapshot(b *testing.B) {
	b.ReportAllocs()
	ct := NewCostTracker()
	names := []string{"html", "css", "js", "json", "xml"}
	for _, name := range names {
		for j := 0; j < 100; j++ {
			ct.Record(name, "origin-1", time.Duration(j)*time.Millisecond, 512, 1024, nil)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ct.Snapshot()
	}
}

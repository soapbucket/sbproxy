// Package telemetry collects and exports distributed tracing and observability data.
package telemetry

import (
	"sync"
	"time"
)

// Span represents a timed phase in the request pipeline. It tracks timing,
// trace context, and arbitrary string attributes. It is used both for
// lightweight pipeline phase tracking and as the span type consumed by the
// OTLPExporter.
type Span struct {
	Name      string
	TraceID   string
	SpanID    string
	ParentID  string
	StartTime time.Time
	EndTime   time.Time

	mu    sync.RWMutex
	attrs map[string]string
}

// StartPipelineSpan begins a new span for a pipeline phase. If parent is
// non-nil the span inherits its TraceID and uses the parent SpanID as its
// ParentID. If parent is nil a new TraceID is generated.
func StartPipelineSpan(name string, parent *TraceContext) *Span {
	s := &Span{
		Name:      name,
		SpanID:    GenerateSpanID(),
		StartTime: time.Now(),
		attrs:     make(map[string]string),
	}

	if parent != nil {
		s.TraceID = parent.TraceID
		s.ParentID = parent.SpanID
	} else {
		s.TraceID = GenerateTraceID()
	}

	return s
}

// End marks the span as complete by recording the end time.
func (s *Span) End() {
	s.EndTime = time.Now()
}

// Duration returns the span duration. If End has not been called it returns the
// elapsed time since the span was started.
func (s *Span) Duration() time.Duration {
	end := s.EndTime
	if end.IsZero() {
		end = time.Now()
	}
	return end.Sub(s.StartTime)
}

// SetAttr sets a span attribute. It is safe for concurrent use.
func (s *Span) SetAttr(key, value string) {
	s.mu.Lock()
	s.attrs[key] = value
	s.mu.Unlock()
}

// GetAttr returns a span attribute value. It is safe for concurrent use.
func (s *Span) GetAttr(key string) (string, bool) {
	s.mu.RLock()
	v, ok := s.attrs[key]
	s.mu.RUnlock()
	return v, ok
}

// Attrs returns a copy of all span attributes.
func (s *Span) Attrs() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make(map[string]string, len(s.attrs))
	for k, v := range s.attrs {
		cp[k] = v
	}
	return cp
}

// ToTraceContext converts the span into a TraceContext suitable for passing
// to child spans or injecting into outgoing headers.
func (s *Span) ToTraceContext() *TraceContext {
	return &TraceContext{
		TraceID: s.TraceID,
		SpanID:  s.SpanID,
		Sampled: true,
	}
}

// Package transform applies content transformations to HTTP request and response bodies.
package transformer

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// PipelineStage represents a single stage in the transform pipeline with timing.
type PipelineStage struct {
	Name     string        `json:"name"`
	Duration time.Duration `json:"duration"`
	Error    string        `json:"error,omitempty"`
	SizeIn   int           `json:"size_in"`
	SizeOut  int           `json:"size_out"`
}

// PipelineResult holds the full pipeline execution result.
type PipelineResult struct {
	Stages        []PipelineStage `json:"stages"`
	TotalDuration time.Duration   `json:"total_duration"`
	Error         string          `json:"error,omitempty"`
}

// NamedTransform wraps a Transformerer with a name for pipeline tracking.
type NamedTransform struct {
	Name      string
	Transformer Transformer
}

// InstrumentedPipeline executes transforms with per-stage timing.
type InstrumentedPipeline struct {
	stages []NamedTransform
	result *PipelineResult
}

// NewInstrumentedPipeline creates a new pipeline with the given named stages.
func NewInstrumentedPipeline(stages ...NamedTransform) *InstrumentedPipeline {
	return &InstrumentedPipeline{
		stages: stages,
	}
}

// Modify implements the Transformer interface, executing each stage with timing.
func (p *InstrumentedPipeline) Modify(resp *http.Response) error {
	result := &PipelineResult{
		Stages: make([]PipelineStage, 0, len(p.stages)),
	}

	totalStart := time.Now()

	for _, stage := range p.stages {
		ps := PipelineStage{
			Name: stage.Name,
		}

		// Measure body size before transform.
		ps.SizeIn = bodySize(resp)

		start := time.Now()
		err := stage.Transformer.Modify(resp)
		ps.Duration = time.Since(start)

		// Measure body size after transform.
		ps.SizeOut = bodySize(resp)

		if err != nil {
			ps.Error = err.Error()
			result.Stages = append(result.Stages, ps)
			result.TotalDuration = time.Since(totalStart)
			result.Error = fmt.Sprintf("stage %q failed: %s", stage.Name, err.Error())
			p.result = result
			return err
		}

		result.Stages = append(result.Stages, ps)
	}

	result.TotalDuration = time.Since(totalStart)
	p.result = result
	return nil
}

// Result returns the pipeline execution result. Returns nil if Modify has not been called.
func (p *InstrumentedPipeline) Result() *PipelineResult {
	return p.result
}

// VisualizationHeader returns a formatted string summarizing stage execution times,
// for example: "encoding(2ms) > html(5ms) > replace(1ms)".
func (p *InstrumentedPipeline) VisualizationHeader() string {
	if p.result == nil || len(p.result.Stages) == 0 {
		return ""
	}

	parts := make([]string, 0, len(p.result.Stages))
	for _, s := range p.result.Stages {
		dur := s.Duration.Round(time.Millisecond)
		if dur == 0 {
			dur = s.Duration.Round(time.Microsecond)
		}
		parts = append(parts, fmt.Sprintf("%s(%s)", s.Name, dur))
	}

	return strings.Join(parts, " > ")
}

// InjectHeader adds the pipeline visualization to the response as the specified header.
func (p *InstrumentedPipeline) InjectHeader(resp *http.Response, headerName string) {
	viz := p.VisualizationHeader()
	if viz == "" {
		return
	}
	resp.Header.Set(headerName, viz)
}

// bodySize returns the current response body size if the body supports Len or
// ContentLength is set. Returns -1 if unknown.
func bodySize(resp *http.Response) int {
	if resp.Body == nil {
		return 0
	}
	if resp.ContentLength >= 0 {
		return int(resp.ContentLength)
	}
	// Try to peek at body length via a known interface.
	type lenner interface {
		Len() int
	}
	if l, ok := resp.Body.(lenner); ok {
		return l.Len()
	}
	// Try reading the body to measure it.
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return -1
	}
	resp.Body = NewTransformReader(strings.NewReader(string(data)), nil)
	resp.ContentLength = int64(len(data))
	return len(data)
}

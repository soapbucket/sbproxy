// Package logging handles structured request logging to multiple backends (stdout, ClickHouse, file).
package logging

import (
	"strconv"
	"time"

	"go.uber.org/zap"
)

// TraceStep records a single step in the request processing pipeline.
type TraceStep struct {
	Name     string
	Duration time.Duration
	Error    error
	Fields   []zap.Field
}

// RequestTrace provides per-step diagnostic logging for a single request.
// Only active when debug is enabled. Zero cost when disabled.
type RequestTrace struct {
	enabled       bool
	requestID     string
	logger        *zap.Logger
	slowThreshold time.Duration
	steps         []TraceStep
}

// NewRequestTrace creates a new request trace. When enabled is false, all
// methods are no-ops (single boolean check, branch-predicted away).
func NewRequestTrace(logger *zap.Logger, requestID string, enabled bool, slowThreshold time.Duration) *RequestTrace {
	return &RequestTrace{
		enabled:       enabled,
		requestID:     requestID,
		logger:        logger,
		slowThreshold: slowThreshold,
	}
}

// Step records a processing step with its duration and optional fields.
func (t *RequestTrace) Step(name string, duration time.Duration, fields ...zap.Field) {
	if !t.enabled {
		return
	}
	t.steps = append(t.steps, TraceStep{Name: name, Duration: duration, Fields: fields})
	t.logger.Debug("request trace step",
		zap.String("request_id", t.requestID),
		zap.String("step", name),
		zap.Int64("step_duration_us", duration.Microseconds()),
	)
}

// StepError records a processing step that resulted in an error.
func (t *RequestTrace) StepError(name string, duration time.Duration, err error, fields ...zap.Field) {
	if !t.enabled {
		return
	}
	t.steps = append(t.steps, TraceStep{Name: name, Duration: duration, Error: err, Fields: fields})
	t.logger.Debug("request trace step error",
		zap.String("request_id", t.requestID),
		zap.String("step", name),
		zap.Int64("step_duration_us", duration.Microseconds()),
		zap.Error(err),
	)
}

// Summary logs all steps at once for slow requests or errors.
// Should be called at the end of request processing.
func (t *RequestTrace) Summary(totalDuration time.Duration, statusCode int) {
	if !t.enabled {
		return
	}
	if statusCode < 500 && totalDuration <= t.slowThreshold {
		return
	}

	fields := make([]zap.Field, 0, len(t.steps)*3+4)
	fields = append(fields,
		zap.String("request_id", t.requestID),
		zap.Int("status_code", statusCode),
		zap.Float64("total_duration_ms", float64(totalDuration.Microseconds())/1000.0),
		zap.Int("step_count", len(t.steps)),
	)
	for _, step := range t.steps {
		fields = append(fields,
			zap.String("step_"+step.Name+"_duration_us",
				strconv.FormatInt(step.Duration.Microseconds(), 10)),
		)
		if step.Error != nil {
			fields = append(fields, zap.NamedError("step_"+step.Name+"_error", step.Error))
		}
	}
	t.logger.Warn("request trace summary", fields...)
}

// Steps returns the collected trace steps (for embedding in log output).
func (t *RequestTrace) Steps() []TraceStep {
	if !t.enabled {
		return nil
	}
	return t.steps
}

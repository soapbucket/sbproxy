// Package orchestration coordinates multi-step request processing workflows and action sequencing.
package orchestration

import (
	"fmt"
	"time"

	"github.com/soapbucket/sbproxy/internal/config/callback"
)

// Builder builds an Executor from configuration
type Builder struct {
	steps           []Step
	parallel        bool
	timeout         time.Duration
	responseBuilder *ResponseBuilder
	continueOnError bool
}

// NewBuilder creates a new orchestration builder
func NewBuilder() *Builder {
	return &Builder{
		steps: make([]Step, 0),
	}
}

// WithSteps adds steps to the builder
func (b *Builder) WithSteps(steps []Step) *Builder {
	b.steps = steps
	return b
}

// WithParallel sets the parallel execution mode
func (b *Builder) WithParallel(parallel bool) *Builder {
	b.parallel = parallel
	return b
}

// WithTimeout sets the orchestration timeout
func (b *Builder) WithTimeout(timeout time.Duration) *Builder {
	b.timeout = timeout
	return b
}

// WithResponseBuilder sets the response builder
func (b *Builder) WithResponseBuilder(rb *ResponseBuilder) *Builder {
	b.responseBuilder = rb
	return b
}

// WithContinueOnError sets the continue on error flag
func (b *Builder) WithContinueOnError(continueOnError bool) *Builder {
	b.continueOnError = continueOnError
	return b
}

// Build creates the Executor
func (b *Builder) Build() (*Executor, error) {
	if len(b.steps) == 0 {
		return nil, fmt.Errorf("orchestration must have at least one step")
	}

	if b.responseBuilder == nil {
		return nil, fmt.Errorf("orchestration must have a response builder")
	}

	// Validate step names are unique
	names := make(map[string]bool)
	for _, step := range b.steps {
		if step.name == "" {
			return nil, fmt.Errorf("step name cannot be empty")
		}
		if names[step.name] {
			return nil, fmt.Errorf("duplicate step name: %s", step.name)
		}
		names[step.name] = true
	}

	// Build and validate dependency graph
	graph, err := buildDependencyGraph(b.steps)
	if err != nil {
		return nil, fmt.Errorf("failed to build dependency graph: %w", err)
	}

	if err := graph.Validate(); err != nil {
		return nil, fmt.Errorf("dependency graph validation failed: %w", err)
	}

	executor := &Executor{
		steps:           b.steps,
		parallel:        b.parallel,
		timeout:         b.timeout,
		responseBuilder: b.responseBuilder,
		continueOnError: b.continueOnError,
	}

	return executor, nil
}

// BuildStepFromCallback creates a Step from a callback configuration
func BuildStepFromCallback(name string, cb *callback.Callback, dependsOn []string, condition string, continueOnError *bool, retry *RetryConfig) Step {
	return Step{
		name:            name,
		callback:        cb,
		condition:       condition,
		dependsOn:       dependsOn,
		continueOnError: continueOnError,
		retry:           retry,
	}
}

// BuildResponseBuilder creates a ResponseBuilder from configuration
func BuildResponseBuilder(template, contentType string, statusCode int, headers map[string]string) *ResponseBuilder {
	return &ResponseBuilder{
		template:    template,
		contentType: contentType,
		statusCode:  statusCode,
		headers:     headers,
	}
}

// BuildRetryConfig creates a RetryConfig from configuration values
func BuildRetryConfig(maxAttempts int, backoff string, initialDelay, maxDelay time.Duration) *RetryConfig {
	if backoff == "" {
		backoff = "exponential"
	}
	if maxAttempts == 0 {
		maxAttempts = 3
	}
	if initialDelay == 0 {
		initialDelay = 100 * time.Millisecond
	}
	if maxDelay == 0 {
		maxDelay = 10 * time.Second
	}

	return &RetryConfig{
		maxAttempts:  maxAttempts,
		backoff:      backoff,
		initialDelay: initialDelay,
		maxDelay:     maxDelay,
	}
}


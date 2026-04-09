// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/config/callback"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/orchestration"
)

func init() {
	loaderFns[TypeOrchestration] = LoadOrchestration
}

var _ ActionConfig = (*Orchestration)(nil)

// Orchestration represents an orchestration action that executes multiple steps
type Orchestration struct {
	OrchestrationConfig
	
	executor *orchestration.Executor `json:"-"`
}

// OrchestrationConfig defines the configuration for orchestration workflows
type OrchestrationConfig struct {
	BaseAction

	// Steps to execute (can be sequential or parallel based on dependencies)
	Steps []OrchestrationStep `json:"steps"`

	// Parallel controls default execution mode when no dependencies exist
	// - false (default): Execute sequentially
	// - true: Execute in parallel where possible
	Parallel bool `json:"parallel,omitempty"`

	// Timeout for the entire orchestration workflow
	Timeout reqctx.Duration `json:"timeout,omitempty" validate:"max_value=5m,default_value=30s"`

	// ResponseBuilder defines how to build the final response from step results
	ResponseBuilder *ResponseBuilderConfig `json:"response_builder,omitempty"`

	// ContinueOnError controls whether to continue executing remaining steps if a step fails
	// - false (default): Stop execution on first error
	// - true: Continue executing remaining steps, collect all errors
	ContinueOnError bool `json:"continue_on_error,omitempty"`
}

// OrchestrationStep represents a single step in the orchestration workflow
type OrchestrationStep struct {
	// Name uniquely identifies this step (required)
	Name string `json:"name"`

	// Callback to execute for this step
	Callback *callback.Callback `json:"callback,omitempty"`

	// Condition determines if this step should execute (Mustache template that evaluates to boolean)
	// Has access to: request, original, config, request_data, session, auth, secrets, steps (previous results)
	// Examples:
	//   "{{#steps.fetch_user.response.active}}true{{/steps.fetch_user.response.active}}"
	//   "{{steps.validate.response.valid}}"
	Condition string `json:"condition,omitempty"`

	// DependsOn lists step names that must complete before this step executes
	// Used for building dependency graph and determining execution order
	DependsOn []string `json:"depends_on,omitempty"`

	// ContinueOnError controls whether to continue if this specific step fails
	// Overrides orchestration-level setting for this step
	ContinueOnError *bool `json:"continue_on_error,omitempty"`

	// Retry configuration for this step
	Retry *StepRetryConfig `json:"retry,omitempty"`
}

// StepRetryConfig defines retry behavior for a step
type StepRetryConfig struct {
	MaxAttempts int             `json:"max_attempts,omitempty" validate:"max_value=10,default_value=3"` // Max retry attempts (default: 3, max: 10)
	Backoff     string          `json:"backoff,omitempty"`                                              // "fixed", "exponential" (default: "exponential")
	InitialDelay reqctx.Duration `json:"initial_delay,omitempty" validate:"max_value=1m,default_value=100ms"` // Initial delay (default: 100ms)
	MaxDelay     reqctx.Duration `json:"max_delay,omitempty" validate:"max_value=1m,default_value=10s"`      // Max delay (default: 10s)
}

// ResponseBuilderConfig defines how to build the final response
type ResponseBuilderConfig struct {
	// Template uses Mustache to build response body
	// Has access to: request, original, config, request_data, session, auth, secrets, steps
	// steps contains all step results: steps.step_name.response, steps.step_name.duration, etc.
	Template string `json:"template"`

	// ContentType for the response (default: application/json)
	ContentType string `json:"content_type,omitempty"`

	// StatusCode for the response (default: 200)
	StatusCode int `json:"status_code,omitempty"`

	// Headers to add to the response
	Headers map[string]string `json:"headers,omitempty"`
}

// LoadOrchestration loads an orchestration action from JSON
func LoadOrchestration(data []byte) (ActionConfig, error) {
	var config OrchestrationConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	orch := &Orchestration{
		OrchestrationConfig: config,
	}

	return orch, nil
}

// Init implements ActionConfig interface
// Builds the executor from the configuration
func (o *Orchestration) Init(cfg *Config) error {
	o.cfg = cfg

	// Build executor
	executor, err := o.buildExecutor()
	if err != nil {
		return fmt.Errorf("failed to build orchestration executor: %w", err)
	}

	o.executor = executor

	// Set transport so IsProxy() returns true and the streaming proxy handler is used
	o.tr = TransportFn(func(req *http.Request) (*http.Response, error) {
		return o.execute(req)
	})

	return nil
}

// buildExecutor creates an executor from the orchestration configuration
func (o *Orchestration) buildExecutor() (*orchestration.Executor, error) {
	builder := orchestration.NewBuilder()

	// Convert config steps to executor steps
	steps := make([]orchestration.Step, len(o.Steps))
	for i, stepConfig := range o.Steps {
		// Build retry config if specified
		var retry *orchestration.RetryConfig
		if stepConfig.Retry != nil {
			retry = orchestration.BuildRetryConfig(
				stepConfig.Retry.MaxAttempts,
				stepConfig.Retry.Backoff,
				stepConfig.Retry.InitialDelay.Duration,
				stepConfig.Retry.MaxDelay.Duration,
			)
		}

		steps[i] = orchestration.BuildStepFromCallback(
			stepConfig.Name,
			stepConfig.Callback,
			stepConfig.DependsOn,
			stepConfig.Condition,
			stepConfig.ContinueOnError,
			retry,
		)
	}

	// Build response builder
	var responseBuilder *orchestration.ResponseBuilder
	if o.ResponseBuilder != nil {
		responseBuilder = orchestration.BuildResponseBuilder(
			o.ResponseBuilder.Template,
			o.ResponseBuilder.ContentType,
			o.ResponseBuilder.StatusCode,
			o.ResponseBuilder.Headers,
		)
	} else {
		return nil, fmt.Errorf("response_builder is required")
	}

	// Configure builder
	builder.WithSteps(steps).
		WithParallel(o.Parallel).
		WithTimeout(o.Timeout.Duration).
		WithResponseBuilder(responseBuilder).
		WithContinueOnError(o.ContinueOnError)

	return builder.Build()
}

// GetType implements ActionConfig interface
func (o *Orchestration) GetType() string {
	return TypeOrchestration
}

// Rewrite implements ActionConfig interface
func (o *Orchestration) Rewrite() RewriteFn {
	// Orchestration doesn't rewrite the request - it builds a response
	return nil
}

// Transport implements ActionConfig interface
func (o *Orchestration) Transport() TransportFn {
	return TransportFn(func(req *http.Request) (*http.Response, error) {
		return o.execute(req)
	})
}

// Handler implements ActionConfig interface
func (o *Orchestration) Handler() http.Handler {
	return nil
}

// execute performs the orchestration workflow
func (o *Orchestration) execute(req *http.Request) (*http.Response, error) {
	if o.executor == nil {
		return nil, fmt.Errorf("orchestration executor not initialized")
	}

	ctx := req.Context()
	return o.executor.Execute(ctx, req)
}


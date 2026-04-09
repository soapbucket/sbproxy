package ai

import "fmt"

// ContextWindowError is returned when input exceeds a model's context window.
type ContextWindowError struct {
	Model           string
	ContextWindow   int
	EstimatedInput  int
	RequestedOutput int
}

func (e *ContextWindowError) Error() string {
	return fmt.Sprintf(
		"input too large for model %s: estimated %d input tokens + %d max output tokens = %d, context window is %d",
		e.Model, e.EstimatedInput, e.RequestedOutput,
		e.EstimatedInput+e.RequestedOutput, e.ContextWindow,
	)
}

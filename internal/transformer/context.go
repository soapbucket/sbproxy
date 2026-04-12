// Package transformer applies content transformations to HTTP request and response bodies.
package transformer

import (
	"context"
	"sync"
)

// transformContextKey is the context key type for TransformContext.
type transformContextKey struct{}

// TransformError records a non-fatal error from a specific transform.
type TransformError struct {
	Index   int    // Transform position in chain (0-based)
	Type    string // Transform type name
	Message string // Error description
}

// TransformContext carries metadata through a transform chain,
// enabling cross-transform data sharing, error tracking, and position awareness.
type TransformContext struct {
	ContentType  string // Detected content type of the response
	OriginalSize int64  // Original response body size (-1 if unknown)
	Index        int    // Current position in chain (0-based)
	Total        int    // Total transforms in chain

	mu       sync.RWMutex
	metadata map[string]interface{}
	errors   []TransformError
}

// NewTransformContext creates a context for a transform chain.
func NewTransformContext(total int, contentType string, originalSize int64) *TransformContext {
	return &TransformContext{
		ContentType:  contentType,
		OriginalSize: originalSize,
		Total:        total,
		metadata:     make(map[string]interface{}),
	}
}

// SetMetadata stores a value accessible by subsequent transforms.
func (tc *TransformContext) SetMetadata(key string, value interface{}) {
	tc.mu.Lock()
	tc.metadata[key] = value
	tc.mu.Unlock()
}

// GetMetadata retrieves a value set by a previous transform.
// Returns the value and true if found, or nil and false if the key does not exist.
func (tc *TransformContext) GetMetadata(key string) (interface{}, bool) {
	tc.mu.RLock()
	v, ok := tc.metadata[key]
	tc.mu.RUnlock()
	return v, ok
}

// RecordError records a non-fatal error without stopping the chain.
// The error is associated with the current transform index and the given type name.
func (tc *TransformContext) RecordError(transformType string, msg string) {
	tc.mu.Lock()
	tc.errors = append(tc.errors, TransformError{
		Index:   tc.Index,
		Type:    transformType,
		Message: msg,
	})
	tc.mu.Unlock()
}

// Errors returns a copy of all recorded non-fatal errors.
func (tc *TransformContext) Errors() []TransformError {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	if len(tc.errors) == 0 {
		return nil
	}
	out := make([]TransformError, len(tc.errors))
	copy(out, tc.errors)
	return out
}

// HasErrors returns true if any non-fatal errors have been recorded.
func (tc *TransformContext) HasErrors() bool {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return len(tc.errors) > 0
}

// WithTransformContext returns a new context.Context carrying the given TransformContext.
func WithTransformContext(ctx context.Context, tc *TransformContext) context.Context {
	return context.WithValue(ctx, transformContextKey{}, tc)
}

// GetTransformContext retrieves the TransformContext from the given context.Context.
// Returns nil if no TransformContext is stored.
func GetTransformContext(ctx context.Context) *TransformContext {
	tc, _ := ctx.Value(transformContextKey{}).(*TransformContext)
	return tc
}

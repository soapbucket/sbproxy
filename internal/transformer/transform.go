// Package transformer applies content transformations to HTTP request and response bodies.
package transformer

import (
	"net/http"
)

const (
	logSender = "transform"
)

// Transformer defines the interface for response transformation operations.
type Transformer interface {
	// Modify takes an http.Response and transforms it in place.
	Modify(*http.Response) error
}

// Func is a function type that implements the Transformer interface.
type Func func(*http.Response) error

// Modify performs the modify operation on the Func.
func (fn Func) Modify(resp *http.Response) error {
	return fn(resp)
}

// Wrap chains multiple Transformers into a single Transformer.
func Wrap(transforms ...Transformer) Transformer {
	return Func(func(resp *http.Response) error {
		for _, tr := range transforms {
			if err := tr.Modify(resp); err != nil {
				return err
			}
		}
		return nil
	})
}

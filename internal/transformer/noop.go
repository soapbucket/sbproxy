// Package transform applies content transformations to HTTP request and response bodies.
package transformer

import "net/http"

// Noop is a variable for noop.
var Noop = Func(func(*http.Response) error {
	return nil
})

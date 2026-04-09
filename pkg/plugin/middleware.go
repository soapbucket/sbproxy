package plugin

import "net/http"

// MiddlewareRegistration describes a middleware plugin with ordering constraints.
type MiddlewareRegistration struct {
	Name     string
	Priority int
	After    []string
	Before   []string
	Factory  func() func(http.Handler) http.Handler
}

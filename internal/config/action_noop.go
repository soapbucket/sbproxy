// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import "net/http"

// NoopAction is a variable for noop action.
var NoopAction ActionConfig = &noopAction{BaseAction: BaseAction{ActionType: TypeNoop}}

type noopAction struct {
	BaseAction
}

// Handler returns a handler that responds with 204 No Content.
func (n *noopAction) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
}

// LoadNoop performs the load noop operation.
func LoadNoop([]byte) (ActionConfig, error) {
	return NoopAction, nil
}

func init() {
	loaderFns[TypeNoop] = LoadNoop
	loaderFns[TypeNone] = LoadNoop
}

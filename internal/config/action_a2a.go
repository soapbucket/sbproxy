// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/app/a2a"
)

func init() {
	loaderFns[TypeA2A] = LoadA2A
}

var _ ActionConfig = (*A2AAction)(nil)

// A2AAction implements the Google Agent-to-Agent protocol.
// Endpoints:
//
//	GET  /.well-known/agent.json -> Agent Card
//	POST /tasks/send             -> Send task
//	GET  /tasks/{id}             -> Get task status
//	POST /tasks/{id}/cancel      -> Cancel task
//	GET  /tasks/{id}/stream      -> SSE task updates
type A2AAction struct {
	A2AActionConfig

	handler *a2a.Handler `json:"-"`
}

// A2AActionConfig defines the configuration for A2A server endpoints.
type A2AActionConfig struct {
	BaseAction

	// AgentCard defines the agent's metadata and capabilities.
	AgentCard a2a.AgentCard `json:"agent_card"`

	// TaskTimeout for task processing.
	TaskTimeout reqctx.Duration `json:"task_timeout,omitempty" validate:"max_value=5m,default_value=30s"`
}

// LoadA2A loads an A2A action from JSON configuration.
func LoadA2A(data []byte) (ActionConfig, error) {
	var config A2AActionConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal a2a config: %w", err)
	}

	if config.AgentCard.Name == "" {
		return nil, fmt.Errorf("a2a: agent_card.name is required")
	}

	action := &A2AAction{
		A2AActionConfig: config,
	}

	return action, nil
}

// Init implements ActionConfig interface.
func (a *A2AAction) Init(cfg *Config) error {
	a.cfg = cfg

	a2aCfg := &a2a.Config{
		AgentCard: a.AgentCard,
	}

	if a.TaskTimeout.Duration > 0 {
		a2aCfg.TaskTimeout = a.TaskTimeout.Duration
	}

	handler, err := a2a.NewHandler(a2aCfg)
	if err != nil {
		return fmt.Errorf("failed to create A2A handler: %w", err)
	}

	a.handler = handler
	return nil
}

// GetType implements ActionConfig interface.
func (a *A2AAction) GetType() string {
	return TypeA2A
}

// Rewrite implements ActionConfig interface.
func (a *A2AAction) Rewrite() RewriteFn {
	return nil
}

// Transport implements ActionConfig interface.
func (a *A2AAction) Transport() TransportFn {
	return nil
}

// Handler implements ActionConfig interface.
func (a *A2AAction) Handler() http.Handler {
	return a.handler
}

// ModifyResponse implements ActionConfig interface.
func (a *A2AAction) ModifyResponse() ModifyResponseFn {
	return nil
}

// ErrorHandler implements ActionConfig interface.
func (a *A2AAction) ErrorHandler() ErrorHandlerFn {
	return nil
}

// IsProxy implements ActionConfig interface.
func (a *A2AAction) IsProxy() bool {
	return false
}

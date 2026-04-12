// Package a2a provides an Agent-to-Agent (A2A) protocol action module.
// It implements the Google A2A protocol, exposing endpoints for agent discovery,
// task submission, status polling, cancellation, and SSE streaming.
// Registers under "a2a".
package a2a

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/soapbucket/sbproxy/internal/app/a2a"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterAction("a2a", New)
}

// Config holds the A2A action configuration.
type Config struct {
	AgentCard   a2a.AgentCard `json:"agent_card"`
	TaskTimeout string        `json:"task_timeout,omitempty"`
}

// Handler is the A2A action handler.
type Handler struct {
	delegate *a2a.Handler
}

// New is the ActionFactory for the a2a module.
func New(raw json.RawMessage) (plugin.ActionHandler, error) {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("a2a: parse config: %w", err)
	}

	if cfg.AgentCard.Name == "" {
		return nil, fmt.Errorf("a2a: agent_card.name is required")
	}

	a2aCfg := &a2a.Config{
		AgentCard: cfg.AgentCard,
	}

	if cfg.TaskTimeout != "" {
		d, err := time.ParseDuration(cfg.TaskTimeout)
		if err != nil {
			return nil, fmt.Errorf("a2a: invalid task_timeout %q: %w", cfg.TaskTimeout, err)
		}
		a2aCfg.TaskTimeout = d
	}

	delegate, err := a2a.NewHandler(a2aCfg)
	if err != nil {
		return nil, fmt.Errorf("a2a: create handler: %w", err)
	}

	slog.Debug("a2a action loaded", "agent_name", cfg.AgentCard.Name)
	return &Handler{delegate: delegate}, nil
}

// Type returns the action type name.
func (h *Handler) Type() string { return "a2a" }

// ServeHTTP delegates all A2A protocol requests to the internal handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.delegate.ServeHTTP(w, r)
}

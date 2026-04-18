// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"net/http"

	json "github.com/goccy/go-json"
)

// AgentCard is the .well-known/agent.json metadata for A2A discovery.
type AgentCard struct {
	Name         string   `json:"name"`
	Description  string   `json:"description,omitempty"`
	URL          string   `json:"url"`
	Version      string   `json:"version,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Provider     string   `json:"provider,omitempty"`
	Skills       []Skill  `json:"skills,omitempty"`
}

// Skill describes a capability the agent supports.
type Skill struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// AgentCardHandler serves .well-known/agent.json responses.
type AgentCardHandler struct {
	card     AgentCard
	cardJSON []byte
}

// NewAgentCardHandler creates a handler that serves the given agent card.
// The card is pre-serialized at construction time so ServeHTTP does no allocation.
func NewAgentCardHandler(card AgentCard) *AgentCardHandler {
	data, err := json.Marshal(card)
	if err != nil {
		// AgentCard contains only basic types; marshal failure should never happen.
		data = []byte(`{"name":"unknown"}`)
	}
	return &AgentCardHandler{card: card, cardJSON: data}
}

// ServeHTTP writes the agent card as JSON. Only GET and HEAD are allowed.
func (h *AgentCardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(h.cardJSON)
	}
}

// Card returns the agent card metadata.
func (h *AgentCardHandler) Card() AgentCard {
	return h.card
}

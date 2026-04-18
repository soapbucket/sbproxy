// Package action contains action-level traffic management handlers.
package action

import (
	"sync/atomic"
)

// BlueGreenConfig configures blue-green routing.
type BlueGreenConfig struct {
	Blue   UpstreamGroup `json:"blue" yaml:"blue"`
	Green  UpstreamGroup `json:"green" yaml:"green"`
	Active string        `json:"active" yaml:"active"` // "blue" or "green"
}

// UpstreamGroup defines a set of upstream targets.
type UpstreamGroup struct {
	URL  string `json:"url" yaml:"url"`
	Name string `json:"name,omitempty" yaml:"name"`
}

// BlueGreenHandler routes 100% traffic to the active group.
type BlueGreenHandler struct {
	config BlueGreenConfig
	active atomic.Value // stores string "blue" or "green"
}

// NewBlueGreenHandler creates a BlueGreenHandler with the specified config.
// If the Active field is empty or invalid, it defaults to "blue".
func NewBlueGreenHandler(cfg BlueGreenConfig) *BlueGreenHandler {
	h := &BlueGreenHandler{
		config: cfg,
	}
	active := cfg.Active
	if active != "blue" && active != "green" {
		active = "blue"
	}
	h.active.Store(active)
	return h
}

// ActiveGroup returns the currently active group name ("blue" or "green").
func (h *BlueGreenHandler) ActiveGroup() string {
	v, ok := h.active.Load().(string)
	if !ok {
		return "blue"
	}
	return v
}

// Switch toggles the active group from blue to green or vice versa.
func (h *BlueGreenHandler) Switch() {
	if h.ActiveGroup() == "blue" {
		h.active.Store("green")
	} else {
		h.active.Store("blue")
	}
}

// ActiveURL returns the URL of the currently active upstream group.
func (h *BlueGreenHandler) ActiveURL() string {
	if h.ActiveGroup() == "green" {
		return h.config.Green.URL
	}
	return h.config.Blue.URL
}

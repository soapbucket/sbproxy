package config

import (
	"encoding/json"
	"time"
)

// Origin represents a proxy origin configuration (pure data, no behavior).
type Origin struct {
	ID                string            `json:"id"`
	Hostname          string            `json:"hostname"`
	WorkspaceID       string            `json:"workspace_id"`
	Version           string            `json:"version"`
	Environment       string            `json:"environment"`
	Tags              []string          `json:"tags,omitempty"`
	Disabled          bool              `json:"disabled,omitempty"`
	Action            json.RawMessage   `json:"action"`
	Auth              json.RawMessage   `json:"authentication,omitempty"`
	Policies          []json.RawMessage `json:"policies,omitempty"`
	Transforms        []json.RawMessage `json:"transforms,omitempty"`
	RequestModifiers  json.RawMessage   `json:"request_modifiers,omitempty"`
	ResponseModifiers json.RawMessage   `json:"response_modifiers,omitempty"`
	ForwardRules      json.RawMessage   `json:"forward_rules,omitempty"`
	ResponseCache     json.RawMessage   `json:"response_cache,omitempty"`
	SessionConfig     json.RawMessage   `json:"session_config,omitempty"`
	Variables         map[string]any    `json:"variables,omitempty"`
	Events            []string          `json:"events,omitempty"`
	FailureMode       string            `json:"failure_mode,omitempty"`
	FailureOverrides  map[string]string `json:"failure_overrides,omitempty"`
}

// Duration wraps time.Duration for JSON marshaling.
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = dur
	return nil
}

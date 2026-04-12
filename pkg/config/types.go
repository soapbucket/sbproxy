// Package config provides the public configuration types used by sbproxy.
//
// These types are pure data structures with no dependencies on internal packages.
// They serve as the contract between configuration sources (YAML files, APIs, databases)
// and the proxy engine that consumes them.
package config

import (
	"encoding/json"
	"time"
)

// Origin represents a single proxy origin configuration. An origin defines how
// the proxy handles requests for a specific hostname, including which action to
// take (reverse proxy, redirect, static response, etc.), what authentication and
// policies to apply, and how to transform responses.
//
// Most fields use [json.RawMessage] instead of concrete types so that the config
// package remains decoupled from plugin implementations. Each plugin is responsible
// for unmarshaling its own configuration from the raw JSON. This allows new plugin
// types to be added without modifying this struct.
type Origin struct {
	// ID is the unique identifier for this origin, typically assigned by the
	// management backend or derived from the configuration file.
	ID string `json:"id"`

	// Hostname is the public hostname that this origin handles (e.g., "api.example.com").
	// The proxy uses this to route incoming requests to the correct origin configuration.
	Hostname string `json:"hostname"`

	// WorkspaceID identifies the tenant workspace that owns this origin.
	// Used for multi-tenant isolation of caches, metrics, and rate limits.
	WorkspaceID string `json:"workspace_id"`

	// Version is an opaque version string used to detect configuration changes.
	// When the version changes, the proxy reloads this origin's pipeline.
	Version string `json:"version"`

	// Environment is a label such as "production", "staging", or "development"
	// that can be used for conditional behavior or filtering.
	Environment string `json:"environment"`

	// Tags are arbitrary labels attached to this origin for grouping and filtering.
	Tags []string `json:"tags,omitempty"`

	// Disabled, when true, causes the proxy to reject requests for this origin
	// with a 503 Service Unavailable response.
	Disabled bool `json:"disabled,omitempty"`

	// Action is the raw JSON configuration for the primary action handler (e.g., reverse
	// proxy, redirect, static response, load balancer). This is the core of what the
	// origin does with a request after authentication and policies have passed.
	Action json.RawMessage `json:"action"`

	// Auth is the raw JSON configuration for the authentication provider (e.g., basic_auth,
	// api_keys, OAuth). Authentication runs before policies in the request lifecycle.
	Auth json.RawMessage `json:"authentication,omitempty"`

	// Policies is a list of raw JSON configurations for policy enforcers (e.g., rate
	// limiting, IP filtering, WAF). Policies run after authentication but before the action.
	Policies []json.RawMessage `json:"policies,omitempty"`

	// Transforms is a list of raw JSON configurations for response transformers (e.g.,
	// JSON projection, header injection). Transforms run on the response body after the
	// upstream has replied.
	Transforms []json.RawMessage `json:"transforms,omitempty"`

	// RequestModifiers is the raw JSON configuration for modifying inbound requests
	// before they reach the action handler (e.g., adding headers, rewriting paths).
	RequestModifiers json.RawMessage `json:"request_modifiers,omitempty"`

	// ResponseModifiers is the raw JSON configuration for modifying outbound responses
	// before they are sent to the client (e.g., injecting CORS headers, removing headers).
	ResponseModifiers json.RawMessage `json:"response_modifiers,omitempty"`

	// ForwardRules is the raw JSON configuration for path-based routing rules that
	// can delegate specific request paths to different inline origins.
	ForwardRules json.RawMessage `json:"forward_rules,omitempty"`

	// ResponseCache is the raw JSON configuration for the response caching layer,
	// including TTL, cache key templates, and stale-while-revalidate settings.
	ResponseCache json.RawMessage `json:"response_cache,omitempty"`

	// SessionConfig is the raw JSON configuration for session management,
	// including cookie names, TTLs, and encryption settings.
	SessionConfig json.RawMessage `json:"session_config,omitempty"`

	// Variables is a map of user-defined template variables that can be interpolated
	// into other configuration fields using the {{ .var_name }} syntax. Common uses
	// include storing API keys, upstream URLs, and feature flags.
	Variables map[string]any `json:"variables,omitempty"`

	// Events lists the event types this origin subscribes to (e.g., "request.blocked",
	// "policy.triggered"). Only listed event types will be published to the event bus.
	Events []string `json:"events,omitempty"`

	// FailureMode controls how the proxy behaves when a component in the pipeline
	// fails. Common values are "fail_open" (serve a degraded response) and "fail_closed"
	// (return an error to the client).
	FailureMode string `json:"failure_mode,omitempty"`

	// FailureOverrides maps specific error conditions to custom behavior, allowing
	// fine-grained control over failure handling per error type.
	FailureOverrides map[string]string `json:"failure_overrides,omitempty"`
}

// Duration wraps [time.Duration] to support JSON unmarshaling from human-readable
// duration strings (e.g., "30s", "5m", "1h30m"). The standard time.Duration type
// only marshals as integer nanoseconds, which is not user-friendly in configuration
// files.
type Duration struct {
	time.Duration
}

// UnmarshalJSON parses a JSON string as a Go duration using [time.ParseDuration].
// The input must be a quoted string like "10s" or "2m30s".
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

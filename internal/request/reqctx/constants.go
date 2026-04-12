// Package models defines shared data types, constants, and request/response models used across packages.
package reqctx

type contextKey string

const (
	// RequestDataKey is a constant for request data key.
	RequestDataKey contextKey = "request_data"
	// ManagerKey is a constant for manager key.
	ManagerKey contextKey = "manager"
)

// Typed context keys for request-scoped values.
// Using the unexported contextKey type prevents collisions with bare string keys
// from other packages and ensures type safety at compile time.
const (
	// ContextKeyProviderName stores the AI provider name (string) in the request context.
	ContextKeyProviderName contextKey = "provider_name"
	// ContextKeyCacheHit stores whether the response was served from cache (bool) in the request context.
	ContextKeyCacheHit contextKey = "cache_hit"
	// ContextKeyErrorStatusCode stores the HTTP error status code (int) in the request context.
	ContextKeyErrorStatusCode contextKey = "error_status_code"
	// ContextKeyMaxBodySize stores the maximum request body size (int64) in the request context.
	ContextKeyMaxBodySize contextKey = "max_body_size"
)

// Config parameter keys used in RequestData.Config
const (
	// ConfigParamID is a constant for config param id.
	ConfigParamID = "config_id"
	// ConfigParamHostname is a constant for config param hostname.
	ConfigParamHostname = "config_hostname"
	// ConfigParamParentID is a constant for config param parent id.
	ConfigParamParentID = "parent_config_id"
	// ConfigParamParentHostname is a constant for config param parent hostname.
	ConfigParamParentHostname = "parent_config_hostname"
	// ConfigParamWorkspaceID is a constant for config param workspace id.
	ConfigParamWorkspaceID = "workspace_id"
	// ConfigParamVersion is a constant for config param version.
	ConfigParamVersion = "version"
	// ConfigParamRevision is a constant for config param revision.
	ConfigParamRevision = "revision"
	// ConfigParamParentVersion is a constant for config param parent version.
	ConfigParamParentVersion = "parent_version"
	// ConfigParamEnvironment is a constant for config param environment.
	ConfigParamEnvironment = "environment"
	// ConfigParamTags is a constant for config param tags.
	ConfigParamTags = "tags"
	// ConfigParamEvents is a constant for config param events.
	ConfigParamEvents = "events"
	// ConfigParamMode is a constant for config param mode.
	ConfigParamMode = "config_mode"
	// ConfigParamReason is a constant for config param reason.
	ConfigParamReason = "config_reason"
)

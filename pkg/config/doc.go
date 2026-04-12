// Package config defines pure configuration types for proxy origins.
//
// These types represent the public, serializable configuration structures
// that external consumers use to describe proxy origins, actions, and
// policies. They contain no behavior, only data and validation helpers.
//
// The [Origin] struct is the primary type. It uses [json.RawMessage] for
// plugin-specific fields (action, authentication, policies, transforms,
// request_modifiers, response_modifiers, forward_rules, response_cache,
// session_config, error_pages, message_signatures, compression, cors, hsts,
// and callback hooks). This keeps the config package decoupled from plugin
// implementations and allows new plugin types to be added without modifying
// these structs.
//
// The JSON struct tags on these types are the canonical field names for sb.yml
// configuration files. When in doubt about a YAML field name, read the Go
// struct tag rather than documentation.
//
// This package has zero imports from internal/. It is safe to import from
// external programs for config generation, validation tools, or SDKs.
package config

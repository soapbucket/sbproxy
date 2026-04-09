// Package config loads, parses, and validates proxy configuration from YAML.
//
// This is the internal configuration package that defines the full Config
// struct with all action types, authentication schemes, policies, transforms,
// forward rules, vault integration, variables, and session management. The
// JSON struct tags are the canonical field names for sb.yml files.
package config

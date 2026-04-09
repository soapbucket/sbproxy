// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/soapbucket/sbproxy/internal/transformer"
)

func init() {
	transformLoaderFns[TransformLuaJSON] = NewLuaJSONTransformConfig
}

// LuaJSONTransformConfig wraps LuaJSONTransform for the transform config interface.
type LuaJSONTransformConfig struct {
	LuaJSONTransform
}

// NewLuaJSONTransformConfig creates a new Lua JSON transform configuration.
// This transform uses a Lua script to transform JSON response bodies.
//
// Configuration example:
//
//	{
//	  "type": "lua_json",
//	  "lua_script": "function modify_json(data, ctx)\n  return data\nend",
//	  "timeout": "100ms",
//	  "content_types": ["application/json"]
//	}
func NewLuaJSONTransformConfig(data []byte) (TransformConfig, error) {
	config := &LuaJSONTransformConfig{}
	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("lua_json: failed to unmarshal config: %w", err)
	}

	// Validate that lua_script is provided
	if config.LuaScript == "" {
		return nil, fmt.Errorf("lua_json: lua_script is required")
	}

	// Apply default content types if not set
	if config.ContentTypes == nil {
		config.ContentTypes = JSONContentTypes
	}

	// Parse timeout with default of 100ms
	timeout := 100 * time.Millisecond
	if config.Timeout.Duration > 0 {
		timeout = config.Timeout.Duration
	}

	// Create the transform function
	tr, err := transformer.TransformLuaJSON(config.LuaScript, timeout)
	if err != nil {
		return nil, fmt.Errorf("lua_json: failed to create transform: %w", err)
	}

	config.tr = tr
	return config, nil
}

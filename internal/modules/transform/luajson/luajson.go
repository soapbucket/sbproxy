// Package luajson registers the lua_json transform.
package luajson

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/transformer"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterTransform("lua_json", New)
}

// Config holds configuration for the lua_json transform.
type Config struct {
	Type         string          `json:"type"`
	LuaScript    string          `json:"lua_script"`
	Timeout      reqctx.Duration `json:"timeout,omitempty"`
	ContentTypes []string        `json:"content_types,omitempty"`
}

// luaJSONTransform implements plugin.TransformHandler.
type luaJSONTransform struct {
	tr transformer.Transformer
}

// New creates a new lua_json transform.
func New(data json.RawMessage) (plugin.TransformHandler, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("lua_json: failed to unmarshal config: %w", err)
	}

	if cfg.LuaScript == "" {
		return nil, fmt.Errorf("lua_json: lua_script is required")
	}

	timeout := 100 * time.Millisecond
	if cfg.Timeout.Duration > 0 {
		timeout = cfg.Timeout.Duration
	}

	tr, err := transformer.TransformLuaJSON(cfg.LuaScript, timeout)
	if err != nil {
		return nil, fmt.Errorf("lua_json: failed to create transform: %w", err)
	}

	return &luaJSONTransform{tr: tr}, nil
}

func (l *luaJSONTransform) Type() string                    { return "lua_json" }
func (l *luaJSONTransform) Apply(resp *http.Response) error { return l.tr.Modify(resp) }

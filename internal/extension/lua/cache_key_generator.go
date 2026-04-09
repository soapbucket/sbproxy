// Package lua provides Lua scripting support for dynamic request/response processing.
package lua

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	lua "github.com/yuin/gopher-lua"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

// CacheKeyGenerator generates cache keys for response caching using Lua scripts.
type CacheKeyGenerator interface {
	// GenerateCacheKey generates a cache key from an HTTP request.
	GenerateCacheKey(*http.Request) (string, error)
}

type cacheKeyGenerator struct {
	script  string
	timeout time.Duration
}

// GenerateCacheKey generates a cache key using the Lua script.
// The script must define a function: function generate_cache_key(req, ctx)
// that returns a string cache key.
func (g *cacheKeyGenerator) GenerateCacheKey(req *http.Request) (string, error) {
	L := newSandboxedState()
	defer L.Close()

	// Set up timeout context
	ctx, cancel := context.WithTimeout(context.Background(), g.timeout)
	defer cancel()
	L.SetContext(ctx)

	// Measure Lua execution time
	startTime := time.Now()

	// Load the script
	if err := L.DoString(g.script); err != nil {
		duration := time.Since(startTime).Seconds()

		origin := "unknown"
		if req != nil {
			requestData := reqctx.GetRequestData(req.Context())
			if requestData != nil && requestData.Config != nil {
				if id := reqctx.ConfigParams(requestData.Config).GetConfigID(); id != "" {
					origin = id
				}
			}
		}

		metric.LuaExecutionTime(origin, "cache_key_generator", duration)
		slog.Debug("error loading cache key generator script", "error", err)
		return "", err
	}

	// Get the generate_cache_key function
	genFn := L.GetGlobal("generate_cache_key")
	if genFn.Type() != lua.LTFunction {
		duration := time.Since(startTime).Seconds()
		origin := "unknown"
		if req != nil {
			requestData := reqctx.GetRequestData(req.Context())
			if requestData != nil && requestData.Config != nil {
				if id := reqctx.ConfigParams(requestData.Config).GetConfigID(); id != "" {
					origin = id
				}
			}
		}
		metric.LuaExecutionTime(origin, "cache_key_generator", duration)
		slog.Debug("generate_cache_key function not found")
		return "", fmt.Errorf("lua: missing required function 'generate_cache_key' in cache key script")
	}

	// Build request context and tables
	rc := NewRequestContext(req)
	reqTable := createRequestTable(L, req)
	ctxTable := rc.BuildContextTable(L)

	// Call the generate_cache_key function
	L.Push(genFn)
	L.Push(reqTable)
	L.Push(ctxTable)

	if err := L.PCall(2, 1, nil); err != nil {
		duration := time.Since(startTime).Seconds()
		origin := "unknown"
		if req != nil {
			requestData := reqctx.GetRequestData(req.Context())
			if requestData != nil && requestData.Config != nil {
				if id := reqctx.ConfigParams(requestData.Config).GetConfigID(); id != "" {
					origin = id
				}
			}
		}
		metric.LuaExecutionTime(origin, "cache_key_generator", duration)
		slog.Debug("error calling generate_cache_key", "error", err)
		return "", err
	}

	duration := time.Since(startTime).Seconds()
	origin := "unknown"
	if req != nil {
		requestData := reqctx.GetRequestData(req.Context())
		if requestData != nil && requestData.Config != nil {
			if id := reqctx.ConfigParams(requestData.Config).GetConfigID(); id != "" {
				origin = id
			}
		}
	}
	metric.LuaExecutionTime(origin, "cache_key_generator", duration)

	// Get the return value
	if L.GetTop() == 0 {
		slog.Debug("generate_cache_key did not return a value")
		return "", fmt.Errorf("lua: generate_cache_key did not return a value")
	}

	ret := L.Get(-1)
	L.Pop(1)

	// Check if it's a string
	if strVal, ok := ret.(lua.LString); ok {
		return string(strVal), nil
	}

	slog.Debug("generate_cache_key did not return a string", "got_type", ret.Type())
	return "", fmt.Errorf("lua: generate_cache_key must return a string, got %s", ret.Type())
}

// NewCacheKeyGenerator creates a new cache key generator with the default timeout.
func NewCacheKeyGenerator(script string) (CacheKeyGenerator, error) {
	return NewCacheKeyGeneratorWithTimeout(script, DefaultTimeout)
}

// NewCacheKeyGeneratorWithTimeout creates a new cache key generator with a custom timeout.
func NewCacheKeyGeneratorWithTimeout(script string, timeout time.Duration) (CacheKeyGenerator, error) {
	// Validate the script
	L := newSandboxedState()
	defer L.Close()

	if err := L.DoString(script); err != nil {
		return nil, fmt.Errorf("lua: script compilation error: %w", err)
	}

	// Validate that generate_cache_key function exists
	genFn := L.GetGlobal("generate_cache_key")
	if genFn.Type() != lua.LTFunction {
		return nil, fmt.Errorf("lua: missing required function 'generate_cache_key' in cache key script")
	}

	return &cacheKeyGenerator{
		script:  script,
		timeout: timeout,
	}, nil
}

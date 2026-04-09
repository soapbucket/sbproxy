// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"fmt"
	"sync"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// builtinServerKeys are server variable keys populated automatically at startup.
// Operator-defined custom variables from sb.yml cannot collide with these.
var builtinServerKeys = map[string]bool{
	"instance_id": true,
	"version":     true,
	"build_hash":  true,
	"start_time":  true,
	"hostname":    true,
	"environment": true,
}

// serverVariables holds the module-level singleton, set once at startup.
var (
	serverVarsMu   sync.RWMutex
	serverVarsData map[string]any
	serverCtx      *reqctx.ServerContext
)

// SetServerVariables stores the server variables singleton (called once at startup).
func SetServerVariables(vars map[string]any) {
	serverVarsMu.Lock()
	defer serverVarsMu.Unlock()
	serverVarsData = vars
}

// GetServerVariables returns the server variables map (thread-safe read).
func GetServerVariables() map[string]any {
	serverVarsMu.RLock()
	defer serverVarsMu.RUnlock()
	return serverVarsData
}

// BuildServerVariables constructs the server variables map from built-in values
// and operator-defined custom entries. Returns an error if a custom key collides
// with a built-in key.
func BuildServerVariables(
	instanceID, version, buildHash, startTime, hostname, environment string,
	custom map[string]string,
) (map[string]any, error) {
	vars := map[string]any{
		"instance_id": instanceID,
		"version":     version,
		"build_hash":  buildHash,
		"start_time":  startTime,
		"hostname":    hostname,
		"environment": environment,
	}

	for k, v := range custom {
		if builtinServerKeys[k] {
			return nil, fmt.Errorf("custom server variable %q collides with built-in key", k)
		}
		vars[k] = v
	}

	return vars, nil
}

// BuildServerContext constructs a ServerContext from the same inputs as BuildServerVariables.
// Called once at startup alongside BuildServerVariables.
func BuildServerContext(
	instanceID, version, buildHash, startTime, hostname, environment string,
	custom map[string]string,
) (*reqctx.ServerContext, error) {
	// Validate no custom key collisions
	for k := range custom {
		if builtinServerKeys[k] {
			return nil, fmt.Errorf("custom server variable %q collides with built-in key", k)
		}
	}

	return &reqctx.ServerContext{
		InstanceID:  instanceID,
		Version:     version,
		BuildHash:   buildHash,
		StartTime:   startTime,
		Hostname:    hostname,
		Environment: environment,
		Custom:      custom,
	}, nil
}

// SetServerContext stores the ServerContext singleton (called once at startup).
func SetServerContext(sc *reqctx.ServerContext) {
	serverVarsMu.Lock()
	defer serverVarsMu.Unlock()
	serverCtx = sc
}

// GetServerContext returns the ServerContext singleton (thread-safe read).
func GetServerContext() *reqctx.ServerContext {
	serverVarsMu.RLock()
	defer serverVarsMu.RUnlock()
	return serverCtx
}

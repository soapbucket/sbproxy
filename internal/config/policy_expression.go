// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/extension/cel"
	"github.com/soapbucket/sbproxy/internal/extension/lua"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func init() {
	policyLoaderFns[PolicyTypeExpression] = NewExpressionPolicy
}

// ExpressionPolicyConfig implements PolicyConfig for custom CEL/Lua expressions
type ExpressionPolicyConfig struct {
	ExpressionPolicy

	// Internal
	config      *Config
	celMatcher  cel.Matcher
	luaMatcher  lua.Matcher
}

// NewExpressionPolicy creates a new expression policy config
func NewExpressionPolicy(data []byte) (PolicyConfig, error) {
	cfg := &ExpressionPolicyConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	// Compile CEL expression if provided
	// Expression should return true to ALLOW the request, false to BLOCK
	if cfg.CELExpr != "" {
		matcher, err := cel.NewMatcher(cfg.CELExpr)
		if err != nil {
			return nil, fmt.Errorf("failed to compile CEL expression: %w", err)
		}
		cfg.celMatcher = matcher
	}

	// Compile Lua script if provided
	// Script should return true to ALLOW the request, false to BLOCK
	if cfg.LuaScript != "" {
		matcher, err := lua.NewMatcher(cfg.LuaScript)
		if err != nil {
			return nil, fmt.Errorf("failed to compile Lua script: %w", err)
		}
		cfg.luaMatcher = matcher
	}

	// Validate that at least one expression is provided
	if cfg.CELExpr == "" && cfg.LuaScript == "" {
		return nil, fmt.Errorf("expression policy requires either cel_expr or lua_script")
	}

	return cfg, nil
}

// Init initializes the policy config
func (p *ExpressionPolicyConfig) Init(config *Config) error {
	p.config = config
	return nil
}

// Apply implements the middleware pattern for expression-based policies
// CEL/Lua expressions should return true to ALLOW, false to BLOCK the request
func (p *ExpressionPolicyConfig) Apply(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.Disabled {
			next.ServeHTTP(w, r)
			return
		}

		// Evaluate CEL expression if provided
		// Expression returns true = allow, false = block
		if p.celMatcher != nil {
			if !p.celMatcher.Match(r) {
				// Policy violation - block request
				// Use 401 (Unauthorized) for authentication-related failures, 403 (Forbidden) for authorization
				// Since expression policies are often used for auth checks, default to 401
				statusCode := http.StatusUnauthorized
				if p.StatusCode > 0 {
					statusCode = p.StatusCode
				}
				reqctx.RecordPolicyViolation(r.Context(), "expression", "Request blocked by CEL expression policy")
				http.Error(w, "Request blocked by CEL expression policy", statusCode)
				return
			}
		}

		// Evaluate Lua script if provided
		// Script returns true = allow, false = block
		if p.luaMatcher != nil {
			if !p.luaMatcher.Match(r) {
				// Policy violation - block request
				// Use 401 (Unauthorized) for authentication-related failures, 403 (Forbidden) for authorization
				// Since expression policies are often used for auth checks, default to 401
				statusCode := http.StatusUnauthorized
				if p.StatusCode > 0 {
					statusCode = p.StatusCode
				}
				reqctx.RecordPolicyViolation(r.Context(), "expression", "Request blocked by Lua script policy")
				http.Error(w, "Request blocked by Lua script policy", statusCode)
				return
			}
		}

		// All checks passed, continue to next handler
		next.ServeHTTP(w, r)
	})
}


// Package expression registers the expression (CEL/Lua) policy.
package expression

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/soapbucket/sbproxy/internal/extension/cel"
	"github.com/soapbucket/sbproxy/internal/extension/lua"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterPolicy("expression", New)
}

// RequestAssertion defines a named assertion that evaluates a CEL/Lua expression
// against the incoming request. Block assertions short-circuit with a custom
// status code and message; flag assertions log and continue.
type RequestAssertion struct {
	Name       string `json:"name"`
	CELExpr    string `json:"cel_expr,omitempty"`
	LuaScript  string `json:"lua_script,omitempty"`
	Action     string `json:"action,omitempty"`      // "block" (default) or "flag"
	StatusCode int    `json:"status_code,omitempty"` // default 403
	Message    string `json:"message,omitempty"`
}

// compiledAssertion holds a compiled request assertion with its matchers.
type compiledAssertion struct {
	RequestAssertion
	celMatcher cel.Matcher
	luaMatcher lua.Matcher
}

// Config holds configuration for the expression policy.
type Config struct {
	Type       string             `json:"type"`
	Disabled   bool               `json:"disabled,omitempty"`
	CELExpr    string             `json:"cel_expr,omitempty"`
	LuaScript  string             `json:"lua_script,omitempty"`
	StatusCode int                `json:"status_code,omitempty"`
	Assertions []RequestAssertion `json:"assertions,omitempty"`
}

// New creates a new expression policy enforcer.
func New(data json.RawMessage) (plugin.PolicyEnforcer, error) {
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	p := &expressionPolicy{cfg: cfg}

	// Compile legacy top-level CEL expression
	if cfg.CELExpr != "" {
		matcher, err := cel.NewMatcher(cfg.CELExpr)
		if err != nil {
			return nil, fmt.Errorf("failed to compile CEL expression: %w", err)
		}
		p.celMatcher = matcher
	}

	// Compile legacy top-level Lua script
	if cfg.LuaScript != "" {
		matcher, err := lua.NewMatcher(cfg.LuaScript)
		if err != nil {
			return nil, fmt.Errorf("failed to compile Lua script: %w", err)
		}
		p.luaMatcher = matcher
	}

	// Compile named assertions
	for i, a := range cfg.Assertions {
		ca := compiledAssertion{RequestAssertion: a}

		if a.CELExpr == "" && a.LuaScript == "" {
			return nil, fmt.Errorf("assertion[%d] %q requires either cel_expr or lua_script", i, a.Name)
		}

		if a.CELExpr != "" {
			matcher, err := cel.NewMatcher(a.CELExpr)
			if err != nil {
				return nil, fmt.Errorf("assertion[%d] %q: failed to compile CEL expression: %w", i, a.Name, err)
			}
			ca.celMatcher = matcher
		}

		if a.LuaScript != "" {
			matcher, err := lua.NewMatcher(a.LuaScript)
			if err != nil {
				return nil, fmt.Errorf("assertion[%d] %q: failed to compile Lua script: %w", i, a.Name, err)
			}
			ca.luaMatcher = matcher
		}

		if ca.Action == "" {
			ca.Action = "block"
		}

		p.compiledAssertions = append(p.compiledAssertions, ca)
	}

	// Validate: at least one expression or assertion must be provided
	if cfg.CELExpr == "" && cfg.LuaScript == "" && len(cfg.Assertions) == 0 {
		return nil, fmt.Errorf("expression policy requires either cel_expr, lua_script, or assertions")
	}

	return p, nil
}

type expressionPolicy struct {
	cfg                *Config
	celMatcher         cel.Matcher
	luaMatcher         lua.Matcher
	compiledAssertions []compiledAssertion
}

func (p *expressionPolicy) Type() string { return "expression" }

func (p *expressionPolicy) Enforce(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.cfg.Disabled {
			next.ServeHTTP(w, r)
			return
		}

		// Evaluate legacy top-level CEL expression (backward compatible)
		if p.celMatcher != nil {
			if !p.celMatcher.Match(r) {
				statusCode := http.StatusUnauthorized
				if p.cfg.StatusCode > 0 {
					statusCode = p.cfg.StatusCode
				}
				reqctx.RecordPolicyViolation(r.Context(), "expression", "Request blocked by CEL expression policy")
				http.Error(w, "Request blocked by CEL expression policy", statusCode)
				return
			}
		}

		// Evaluate legacy top-level Lua script (backward compatible)
		if p.luaMatcher != nil {
			if !p.luaMatcher.Match(r) {
				statusCode := http.StatusUnauthorized
				if p.cfg.StatusCode > 0 {
					statusCode = p.cfg.StatusCode
				}
				reqctx.RecordPolicyViolation(r.Context(), "expression", "Request blocked by Lua script policy")
				http.Error(w, "Request blocked by Lua script policy", statusCode)
				return
			}
		}

		// Evaluate named assertions in order. First blocking failure short-circuits.
		for _, a := range p.compiledAssertions {
			passed := true

			if a.celMatcher != nil && !a.celMatcher.Match(r) {
				passed = false
			}
			if passed && a.luaMatcher != nil && !a.luaMatcher.Match(r) {
				passed = false
			}

			if !passed {
				violationMsg := fmt.Sprintf("Request assertion %q failed", a.Name)
				if a.Message != "" {
					violationMsg = a.Message
				}

				reqctx.RecordPolicyViolation(r.Context(), "expression", violationMsg)

				if a.Action == "flag" {
					slog.Warn("request assertion flagged",
						"assertion", a.Name,
						"path", r.URL.Path,
						"message", violationMsg)
					continue
				}

				// Block action (default)
				statusCode := http.StatusForbidden
				if a.StatusCode > 0 {
					statusCode = a.StatusCode
				}
				http.Error(w, violationMsg, statusCode)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

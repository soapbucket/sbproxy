// Package cel provides Common Expression Language (CEL) evaluation for dynamic request matching and filtering.
package cel

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// ErrWrongType is returned when a CEL expression does not return a boolean type.
var ErrWrongType = errors.New("cel: wrong type")

// Matcher evaluates CEL expressions against HTTP requests.
type Matcher interface {
	// Match evaluates the CEL expression against the given HTTP request.
	// Returns true if the expression evaluates to true, false otherwise.
	// If evaluation fails, returns false and logs the error.
	Match(*http.Request) bool
}

type matcher struct {
	cel.Program
}

// Match performs the match operation on the matcher.
func (m *matcher) Match(req *http.Request) bool {
	rc := GetRequestContext(req)
	vars := rc.ToVars()

	// Measure CEL execution time
	startTime := time.Now()
	out, _, err := m.Eval(vars)
	duration := time.Since(startTime).Seconds()

	// Get origin from config context
	origin := "unknown"
	if req != nil {
		requestData := reqctx.GetRequestData(req.Context())
		if requestData != nil && requestData.Config != nil {
			if id := reqctx.ConfigParams(requestData.Config).GetConfigID(); id != "" {
				origin = id
			}
		}
		// Fallback to hostname if config_id not available
		if origin == "unknown" && req.Host != "" {
			origin = req.Host
		}
	}

	// Record CEL execution time
	metric.CELExecutionTime(origin, "matcher", duration)

	if err != nil {
		slog.Debug("error evaluating expression", "url", req.URL, "error", err)
		return false
	}
	if outBool, ok := out.Value().(bool); ok {
		return outBool
	}
	return false

}

// NewMatcher creates and initializes a new Matcher.
func NewMatcher(expr string) (Matcher, error) {
	env, err := getRequestEnv()
	if err != nil {
		return nil, err
	}
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	if ast == nil {
		return nil, errors.New("cel: compilation produced nil AST")
	}
	if ast.OutputType() != cel.BoolType {
		return nil, ErrWrongType
	}

	program, err := env.Program(ast)
	if err != nil {
		return nil, err
	}
	return &matcher{Program: program}, nil
}

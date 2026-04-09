// Package cel provides Common Expression Language (CEL) evaluation for dynamic request matching and filtering.
package cel

import (
	"fmt"

	celgo "github.com/google/cel-go/cel"
)

// CompileAndCache compiles a CEL expression using the request environment and
// stores the resulting program in the provided cache. This is used by the
// cache warmer to pre-compile expressions before they are needed at request time.
func CompileAndCache(expression string, version string, cache *ExpressionCache) (celgo.Program, error) {
	env, err := getRequestEnv()
	if err != nil {
		return nil, fmt.Errorf("failed to get CEL environment: %w", err)
	}

	ast, iss := env.Compile(expression)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("CEL compilation error: %w", iss.Err())
	}
	if ast == nil {
		return nil, fmt.Errorf("CEL compilation produced nil AST")
	}

	program, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("CEL program creation error: %w", err)
	}

	// Store in cache
	if cache != nil {
		cache.Put(expression, version, program)
	}

	return program, nil
}

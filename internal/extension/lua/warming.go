// Package lua provides Lua scripting support for dynamic request/response processing.
package lua

import (
	"fmt"
	"strings"

	luago "github.com/yuin/gopher-lua"
	"github.com/yuin/gopher-lua/parse"
)

// CompileAndCache parses and compiles a Lua script, storing the result in the
// provided cache. This is used by the cache warmer to pre-compile scripts
// before they are needed at request time. A temporary Lua state is created
// for compilation and closed after the function returns.
func CompileAndCache(script string, version string, cache *ScriptCache) (*luago.LFunction, error) {
	// Parse the script to validate syntax (no state needed)
	chunk, parseErr := parse.Parse(strings.NewReader(script), "<warming>")
	if parseErr != nil {
		return nil, fmt.Errorf("Lua parse error: %w", parseErr)
	}

	// Compile the parsed chunk into a function prototype using a temporary state
	L := luago.NewState()
	defer L.Close()

	proto, compileErr := luago.Compile(chunk, "<warming>")
	if compileErr != nil {
		return nil, fmt.Errorf("Lua compile error: %w", compileErr)
	}

	fn := L.NewFunctionFromProto(proto)

	// Store in cache
	if cache != nil {
		cache.Put(script, version, fn)
	}

	return fn, nil
}

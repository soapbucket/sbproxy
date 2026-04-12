// Package transform applies content transformations to HTTP request and response bodies.
package transformer

import (
	"net/http"
	"time"

	"github.com/soapbucket/sbproxy/internal/extension/lua"
)

// TransformLuaJSON creates a transform function that applies Lua-based JSON transformation.
// The script must define a function modify_json(data, ctx) that receives the parsed JSON body
// as a Lua table and returns the transformed data structure.
//
// Example usage:
//
//	script := `
//	function modify_json(data, ctx)
//	  -- Convert country codes
//	  local country_map = {GERMANY = 'DE', FRANCE = 'FR', SPAIN = 'ES'}
//	  if data.country and country_map[data.country] then
//	    data.country = country_map[data.country]
//	  end
//	  return data
//	end
//	`
//	tr, err := TransformLuaJSON(script, 100*time.Millisecond)
func TransformLuaJSON(script string, timeout time.Duration) (Func, error) {
	transformer, err := lua.NewJSONTransformerWithTimeout(script, timeout)
	if err != nil {
		return nil, err
	}

	return Func(func(resp *http.Response) error {
		return transformer.TransformResponse(resp)
	}), nil
}

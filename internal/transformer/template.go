// Package transform applies content transformations to HTTP request and response bodies.
package transformer

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	templateresolver "github.com/soapbucket/sbproxy/internal/template"
)

// ApplyTemplate performs the apply template operation.
func ApplyTemplate(tmpl string, data interface{}) Func {
	return Func(func(resp *http.Response) error {
		// Read response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		resp.Body.Close()

		// Parse response body as JSON
		var bodyJSON interface{}
		if len(body) > 0 {
			if err := json.Unmarshal(body, &bodyJSON); err != nil {
				// If body is not valid JSON, use it as a string
				bodyJSON = string(body)
			}
		} else {
			bodyJSON = ""
		}

		// Build template context using unified resolver
		// This gives access to: request, original, config, request_data, session, auth, secrets
		ctx := map[string]any{
			"response": bodyJSON,
		}

		// Add all request context variables if response has request
		if resp.Request != nil {
			requestCtx := templateresolver.BuildContext(resp.Request)
			for k, v := range requestCtx {
				if k != "response" {
					ctx[k] = v
				}
			}
		}

		// Merge provided data (custom transform data)
		if dataMap, ok := data.(map[string]interface{}); ok {
			for key, value := range dataMap {
				ctx[key] = value
			}
		} else if dataSlice, ok := data.([]interface{}); ok {
			ctx["data"] = dataSlice
		} else if data != nil {
			ctx["data"] = data
		}

		// Execute template
		rendered, err := templateresolver.ResolveWithContext(tmpl, ctx)
		if err != nil {
			return err
		}

		// Replace response body with rendered template
		resp.Body = io.NopCloser(strings.NewReader(rendered))

		return nil
	})
}

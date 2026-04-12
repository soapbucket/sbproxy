// Package callback executes HTTP callbacks to external services during request processing with retry and caching support.
package callback

import (
	"bytes"
	json "github.com/goccy/go-json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"sort"
	"strings"

	templateresolver "github.com/soapbucket/sbproxy/internal/template"
)

// buildRequestBody builds the request body and content type based on callback configuration.
// Priority: FormFields > Body template > JSON-marshal of obj (default behavior).
// Returns the body reader, content type to set, and any error.
func (c *Callback) buildRequestBody(obj any) (io.Reader, string, error) {
	method := strings.ToUpper(c.Method)
	if method == "" {
		method = http.MethodPost
	}

	// GET and DELETE never send a body
	if method == http.MethodGet || method == http.MethodDelete {
		return http.NoBody, "", nil
	}

	ctx := objToTemplateContext(obj)

	// Priority 1: FormFields — auto-build form body
	if len(c.FormFields) > 0 {
		return c.buildFormBody(ctx)
	}

	// Priority 2: Body template — render and use as body
	if c.Body != "" {
		rendered, err := renderBodyTemplate(c.Body, ctx)
		if err != nil {
			return nil, "", fmt.Errorf("failed to render body template: %w", err)
		}
		contentType := c.ContentType
		if contentType == "" {
			contentType = "application/json"
		}
		return strings.NewReader(rendered), contentType, nil
	}

	// Priority 3: Default — JSON-marshal obj
	if obj != nil {
		body, err := json.Marshal(obj)
		if err != nil {
			return nil, "", fmt.Errorf("failed to marshal object: %w", err)
		}
		contentType := c.ContentType
		if contentType == "" {
			contentType = "application/json"
		}
		return bytes.NewReader(body), contentType, nil
	}

	return http.NoBody, "", nil
}

// objToTemplateContext converts the obj parameter to a map[string]any for template rendering.
// - map[string]any: keys become top-level template variables
// - nil: empty context
// - anything else: wrapped under a "data" key
func objToTemplateContext(obj any) map[string]any {
	if obj == nil {
		return map[string]any{}
	}
	if m, ok := obj.(map[string]any); ok {
		ctx := make(map[string]any, len(m))
		for k, v := range m {
			ctx[k] = v
		}
		return ctx
	}
	return map[string]any{"data": obj}
}

// renderBodyTemplate renders a template string with the given context using the Jet resolver.
func renderBodyTemplate(templateStr string, ctx map[string]any) (string, error) {
	return templateresolver.ResolveWithContext(templateStr, ctx)
}

// buildFormBody builds a form body from FormFields, rendering each value as a template.
// If ContentType is "multipart/form-data", builds a multipart body with proper boundaries.
// Otherwise, builds a URL-encoded body (application/x-www-form-urlencoded).
func (c *Callback) buildFormBody(ctx map[string]any) (io.Reader, string, error) {
	// Render all field value templates
	renderedFields := make(map[string]string, len(c.FormFields))
	for key, valueTpl := range c.FormFields {
		rendered, err := renderBodyTemplate(valueTpl, ctx)
		if err != nil {
			return nil, "", fmt.Errorf("failed to render form field %q: %w", key, err)
		}
		renderedFields[key] = rendered
	}

	if strings.EqualFold(c.ContentType, "multipart/form-data") {
		return buildMultipartBody(renderedFields)
	}

	return buildURLEncodedBody(renderedFields)
}

// sortedKeys returns the keys of a map sorted alphabetically.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// buildMultipartBody creates a multipart/form-data body from key-value pairs.
// Returns the body reader and the full content type (including boundary).
func buildMultipartBody(fields map[string]string) (io.Reader, string, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	for _, key := range sortedKeys(fields) {
		if err := writer.WriteField(key, fields[key]); err != nil {
			return nil, "", fmt.Errorf("failed to write multipart field %q: %w", key, err)
		}
	}

	if err := writer.Close(); err != nil {
		return nil, "", fmt.Errorf("failed to close multipart writer: %w", err)
	}

	return &buf, writer.FormDataContentType(), nil
}

// buildURLEncodedBody creates an application/x-www-form-urlencoded body from key-value pairs.
func buildURLEncodedBody(fields map[string]string) (io.Reader, string, error) {
	values := url.Values{}

	for _, key := range sortedKeys(fields) {
		values.Set(key, fields[key])
	}

	return strings.NewReader(values.Encode()), "application/x-www-form-urlencoded", nil
}

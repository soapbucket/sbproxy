// Package modifier provides request and response modification capabilities for header, body, and URL transformations.
package modifier

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"net/url"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/config/rule"
	"github.com/soapbucket/sbproxy/internal/extension/lua"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/template"
)

// RequestModifier represents a request modifier.
type RequestModifier struct {
	URL    *URLModifications `json:"url,omitempty"`
	Method string            `json:"method,omitempty"`

	Headers *HeaderModifications `json:"headers,omitempty"`
	Query   *QueryModifications  `json:"query,omitempty"`
	Body    *BodyModifications   `json:"body,omitempty"`
	Form    *FormModifications   `json:"form,omitempty"`

	JSONTransform *JSONTransformConfig `json:"json_transform,omitempty"`

	AISchemaValidation *AISchemaValidationConfig `json:"ai_schema_validation,omitempty"`
	TokenEstimation    *TokenEstimationConfig    `json:"token_estimation,omitempty"`

	Rules rule.RequestRules `json:"rules,omitempty"`

	LuaScript string `json:"lua_script,omitempty"`

	luamodifier     lua.Modifier       `json:"-"`
	jsonTransformer lua.JSONTransformer `json:"-"`
}

// JSONTransformConfig configures Lua-based JSON body transformation for requests.
// The Lua script must define: function modify_json(data, ctx) ... return data end
type JSONTransformConfig struct {
	LuaScript    string          `json:"lua_script"`
	Timeout      reqctx.Duration `json:"timeout,omitempty"`
	ContentTypes []string        `json:"content_types,omitempty"`
	MaxBodySize  int64           `json:"max_body_size,omitempty"`
}

// URLModifications provides fine-grained control over URL components
type URLModifications struct {
	Set      string              `json:"set,omitempty"`      // Set entire URL (replaces all components)
	Scheme   string              `json:"scheme,omitempty"`   // Modify scheme (http, https, etc.)
	Host     string              `json:"host,omitempty"`     // Modify host (including port if needed)
	Path     *PathModifications  `json:"path,omitempty"`     // Modify path
	Query    *QueryModifications `json:"query,omitempty"`    // Modify query parameters
	Fragment string              `json:"fragment,omitempty"` // Modify fragment
}

// PathModifications provides control over path modifications
type PathModifications struct {
	Set     string       `json:"set,omitempty"`     // Set exact path (replaces entire path)
	Prefix  string       `json:"prefix,omitempty"`  // Add prefix to path
	Suffix  string       `json:"suffix,omitempty"`  // Add suffix to path
	Replace *PathReplace `json:"replace,omitempty"` // Replace substring in path
}

// PathReplace specifies a path replacement
type PathReplace struct {
	Old string `json:"old"` // Substring to replace
	New string `json:"new"` // Replacement string
}

// QueryModifications provides control over query parameter modifications
type QueryModifications struct {
	Set    map[string]string `json:"set,omitempty"`    // Set query parameter (overwrites existing)
	Add    map[string]string `json:"add,omitempty"`    // Add query parameter (appends if exists, creates if not)
	Delete []string          `json:"delete,omitempty"` // Delete query parameters by name
}

// HeaderModifications provides control over header modifications
type HeaderModifications struct {
	Set    map[string]string `json:"set,omitempty"`    // Set header to value (overwrites existing)
	Add    map[string]string `json:"add,omitempty"`    // Add header value (appends to existing or creates new)
	Delete []string          `json:"delete,omitempty"` // Delete headers by name
}

// BodyModifications provides control over body modifications
type BodyModifications struct {
	Remove        bool            `json:"remove,omitempty"`         // Remove body (set to empty)
	Replace       string          `json:"replace,omitempty"`        // Replace body with string value
	ReplaceJSON   json.RawMessage `json:"replace_json,omitempty"`   // Replace body with JSON value (validates JSON and sets Content-Type)
	ReplaceBase64 string          `json:"replace_base64,omitempty"` // Replace body with base64-decoded value
}

// FormModifications provides control over form parameter modifications
type FormModifications struct {
	Set    map[string]string `json:"set,omitempty"`    // Set form parameter (overwrites existing)
	Add    map[string]string `json:"add,omitempty"`    // Add form parameter (appends if exists, creates if not)
	Delete []string          `json:"delete,omitempty"` // Delete form parameters by name
}

// UnmarshalJSON implements the json.Unmarshaler interface for RequestModifier.
func (m *RequestModifier) UnmarshalJSON(data []byte) error {
	// Check for deprecated cel_expr field
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err == nil {
		if _, hasCEL := raw["cel_expr"]; hasCEL {
			return fmt.Errorf("cel_expr is no longer supported in request modifiers; use lua_script instead")
		}
	}

	type Alias RequestModifier
	alias := (*Alias)(m)
	if err := json.Unmarshal(data, alias); err != nil {
		return err
	}

	if m.LuaScript != "" {
		luamodifier, err := lua.NewModifier(m.LuaScript)
		if err != nil {
			return err
		}
		m.luamodifier = luamodifier
	}

	if m.JSONTransform != nil {
		if m.JSONTransform.LuaScript == "" {
			return fmt.Errorf("json_transform: lua_script is required")
		}
		timeout := 100 * time.Millisecond
		if m.JSONTransform.Timeout.Duration > 0 {
			timeout = m.JSONTransform.Timeout.Duration
		}
		if m.JSONTransform.ContentTypes == nil {
			m.JSONTransform.ContentTypes = []string{"application/json"}
		}
		if m.JSONTransform.MaxBodySize == 0 {
			m.JSONTransform.MaxBodySize = 10 * 1024 * 1024 // 10MB default
		}
		transformer, err := lua.NewJSONTransformerWithTimeout(m.JSONTransform.LuaScript, timeout)
		if err != nil {
			return fmt.Errorf("json_transform: %w", err)
		}
		m.jsonTransformer = transformer
	}

	return nil
}

// Match performs the match operation on the RequestModifier.
func (m *RequestModifier) Match(req *http.Request) bool {
	if len(m.Rules) == 0 || m.Rules.Match(req) {
		return true
	}

	return false
}

// Apply performs the apply operation on the RequestModifier.
func (m *RequestModifier) Apply(req *http.Request) error {
	if !m.Match(req) {
		return nil
	}

	// Apply Lua modifier (if present)
	if m.luamodifier != nil {
		modifiedReq, err := m.luamodifier.Modify(req)
		if err != nil {
			slog.Debug("Lua modifier error", "error", err)
			// No-op on error - continue processing
		} else if modifiedReq != nil {
			// Update req with the modified request
			*req = *modifiedReq
		}
	}

	// Modify URL
	if m.URL != nil {
		if err := applyURLModifications(req, m.URL); err != nil {
			return err
		}
	}

	// Modify method
	if m.Method != "" {
		req.Method = strings.ToUpper(m.Method)
	}

	// Modify headers
	if m.Headers != nil {
		applyHeaderModificationsWithRequest(req.Header, m.Headers, req)
	}

	// Modify query parameters (if not already modified via URL)
	if m.Query != nil && (m.URL == nil || m.URL.Query == nil) {
		applyQueryModifications(req.URL, m.Query)
	}

	// Modify form parameters
	if m.Form != nil {
		if err := applyFormModifications(req, m.Form); err != nil {
			return err
		}
	}

	// JSON body transform (runs before declarative body mods)
	if m.jsonTransformer != nil {
		if err := applyJSONTransform(req, m.JSONTransform, m.jsonTransformer); err != nil {
			slog.Error("json_transform failed", "error", err)
			return err
		}
	}

	// AI schema validation (request-side)
	if m.AISchemaValidation != nil {
		if err := applyAISchemaValidation(req, m.AISchemaValidation); err != nil {
			return err
		}
	}

	// Token estimation (request-side)
	if m.TokenEstimation != nil {
		if err := applyTokenEstimation(req, m.TokenEstimation); err != nil {
			return err
		}
	}

	// Modify body
	if m.Body != nil {
		if err := applyBodyModifications(req, m.Body); err != nil {
			return err
		}
	}

	return nil
}

func applyURLModifications(req *http.Request, mods *URLModifications) error {
	// If Set is provided, replace entire URL
	if mods.Set != "" {
		newURL, err := url.Parse(mods.Set)
		if err != nil {
			return err
		}
		*req.URL = *newURL
		return nil
	}

	// Modify individual URL components
	if mods.Scheme != "" {
		req.URL.Scheme = mods.Scheme
	}

	if mods.Host != "" {
		req.URL.Host = mods.Host
	}

	if mods.Path != nil {
		applyPathModifications(req.URL, mods.Path)
	}

	if mods.Query != nil {
		applyQueryModifications(req.URL, mods.Query)
	}

	if mods.Fragment != "" {
		req.URL.Fragment = mods.Fragment
	}

	return nil
}

func applyPathModifications(u *url.URL, mods *PathModifications) {
	if mods.Set != "" {
		u.Path = mods.Set
		return
	}

	currentPath := u.Path

	if mods.Replace != nil && mods.Replace.Old != "" {
		currentPath = strings.ReplaceAll(currentPath, mods.Replace.Old, mods.Replace.New)
	}

	if mods.Prefix != "" {
		currentPath = mods.Prefix + currentPath
	}

	if mods.Suffix != "" {
		currentPath = currentPath + mods.Suffix
	}

	u.Path = currentPath
}

func applyQueryModifications(u *url.URL, mods *QueryModifications) {
	query := u.Query()

	// Delete query parameters first
	for _, name := range mods.Delete {
		query.Del(name)
	}

	// Set query parameters (overwrites existing)
	for name, value := range mods.Set {
		query.Set(name, value)
	}

	// Add query parameters (appends to existing or creates new)
	for name, value := range mods.Add {
		query.Add(name, value)
	}

	u.RawQuery = query.Encode()
}

// Template resolution now uses unified Mustache resolver

func applyHeaderModificationsWithRequest(header http.Header, mods *HeaderModifications, req *http.Request) {
	// Delete headers first
	for _, name := range mods.Delete {
		header.Del(name)
	}

	// Set headers (overwrites existing)
	for name, value := range mods.Set {
		resolvedValue := resolveTemplateVariables(value, req)
		header.Set(name, resolvedValue)
	}

	// Add headers (appends to existing or creates new)
	for name, value := range mods.Add {
		resolvedValue := resolveTemplateVariables(value, req)
		header.Add(name, resolvedValue)
	}
}

// resolveTemplateVariables resolves Mustache template variables in header/query values.
// Uses unified Mustache resolver with caching for performance.
func resolveTemplateVariables(value string, req *http.Request) string {
	if req == nil {
		return value
	}

	// Use unified Mustache template resolver
	resolved, err := template.Resolve(value, req)
	if err != nil {
		// Log error but return original value to avoid breaking request
		slog.Error("template resolution failed in modifier",
			"template", value,
			"error", err)
		return value
	}
	
	return resolved
}

// Note: Legacy regex-based template resolution has been removed.
// All template resolution now uses the unified Mustache resolver.
// Variables: {{request.id}}, {{config.key}}, {{secrets.key}}, etc.
// Sections: {{#condition}}...{{/condition}}, {{^falsy}}...{{/falsy}}
// Iteration: {{#items}}{{name}}{{/items}}

func applyBodyModifications(req *http.Request, mods *BodyModifications) error {
	// Read existing body if present
	var bodyBytes []byte
	if req.Body != nil {
		// Close body to ensure cleanup (even on error)
		defer req.Body.Close()

		var err error
		if req.ContentLength > 0 {
			bodyBytes = make([]byte, req.ContentLength)
			_, err = io.ReadFull(req.Body, bodyBytes)
		} else {
			bodyBytes, err = io.ReadAll(req.Body)
		}
		if err != nil {
			return err
		}
	}

	// Apply modifications (priority: ReplaceBase64 > ReplaceJSON > Replace > Remove)
	if mods.ReplaceBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(mods.ReplaceBase64)
		if err != nil {
			return err
		}
		bodyBytes = decoded
	} else if len(mods.ReplaceJSON) > 0 {
		// Validate JSON (json.RawMessage should already be valid, but we verify)
		if !json.Valid(mods.ReplaceJSON) {
			return fmt.Errorf("invalid JSON")
		}
		// Use the raw message directly (it's already validated JSON)
		bodyBytes = mods.ReplaceJSON
		// Set Content-Type header for JSON
		if req.Header == nil {
			req.Header = make(http.Header)
		}
		req.Header.Set("Content-Type", "application/json")
	} else if mods.Replace != "" {
		// Resolve template variables in body replacement
		resolvedBody := resolveTemplateVariables(mods.Replace, req)
		bodyBytes = []byte(resolvedBody)
	} else if mods.Remove {
		bodyBytes = []byte{}
	}

	// Replace body
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	req.ContentLength = int64(len(bodyBytes))

	// Update Content-Length header
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	if len(bodyBytes) == 0 {
		req.Header.Del("Content-Length")
	} else {
		req.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
	}

	return nil
}

// parseMediaType extracts the media type from a Content-Type header value
// without the allocation overhead of mime.ParseMediaType.
// Returns the media type portion (e.g. "application/json" from "application/json; charset=utf-8").
func parseMediaType(contentType string) string {
	if i := strings.IndexByte(contentType, ';'); i >= 0 {
		contentType = contentType[:i]
	}
	return strings.TrimSpace(contentType)
}

func applyJSONTransform(req *http.Request, cfg *JSONTransformConfig, transformer lua.JSONTransformer) error {
	if req.Body == nil || req.ContentLength == 0 {
		return nil
	}

	// Check content type — lightweight parse avoids mime.ParseMediaType allocs
	contentType := parseMediaType(req.Header.Get("Content-Type"))
	matched := false
	for _, ct := range cfg.ContentTypes {
		if ct == contentType {
			matched = true
			break
		}
	}
	if !matched {
		return nil
	}

	// Check body size limit
	if cfg.MaxBodySize > 0 && req.ContentLength > 0 && req.ContentLength > cfg.MaxBodySize {
		slog.Warn("skipping json_transform: request body exceeds max_body_size",
			"content_length", req.ContentLength,
			"max_body_size", cfg.MaxBodySize)
		return nil
	}

	// Read body — pre-allocate buffer when ContentLength is known
	var bodyBytes []byte
	var err error
	if req.ContentLength > 0 {
		bodyBytes = make([]byte, req.ContentLength)
		_, err = io.ReadFull(req.Body, bodyBytes)
	} else {
		bodyBytes, err = io.ReadAll(req.Body)
	}
	req.Body.Close()
	if err != nil {
		return fmt.Errorf("json_transform: failed to read request body: %w", err)
	}

	if len(bodyBytes) == 0 {
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return nil
	}

	// Parse JSON
	var jsonData interface{}
	if err := json.Unmarshal(bodyBytes, &jsonData); err != nil {
		// Not valid JSON — restore body unchanged
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return nil
	}

	// Transform via Lua with request context
	transformedData, err := transformer.TransformRequestData(jsonData, req)
	if err != nil {
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return err
	}

	// Marshal back to JSON
	transformedBytes, err := json.Marshal(transformedData)
	if err != nil {
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return fmt.Errorf("json_transform: failed to marshal transformed data: %w", err)
	}

	// Update request
	req.Body = io.NopCloser(bytes.NewReader(transformedBytes))
	req.ContentLength = int64(len(transformedBytes))
	req.Header.Set("Content-Length", strconv.Itoa(len(transformedBytes)))

	return nil
}

func applyFormModifications(req *http.Request, mods *FormModifications) error {
	// Parse form if Content-Type is application/x-www-form-urlencoded
	contentType := req.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		// If not form-encoded, set content type and create new form
		if req.Header == nil {
			req.Header = make(http.Header)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	// Read existing body if present
	var bodyBytes []byte
	if req.Body != nil {
		// Close body to ensure cleanup (even on error)
		defer req.Body.Close()

		var err error
		if req.ContentLength > 0 {
			bodyBytes = make([]byte, req.ContentLength)
			_, err = io.ReadFull(req.Body, bodyBytes)
		} else {
			bodyBytes, err = io.ReadAll(req.Body)
		}
		if err != nil {
			return err
		}

		// Restore body temporarily for parsing
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// Parse existing form
	var form url.Values
	if len(bodyBytes) > 0 {
		// Parse the form data
		parsedForm, err := url.ParseQuery(string(bodyBytes))
		if err != nil {
			// If parsing fails, start with empty form
			form = make(url.Values)
		} else {
			form = parsedForm
		}
	} else {
		form = make(url.Values)
	}

	// Delete form parameters first
	for _, name := range mods.Delete {
		form.Del(name)
	}

	// Set form parameters (overwrites existing)
	for name, value := range mods.Set {
		form.Set(name, value)
	}

	// Add form parameters (appends to existing or creates new)
	for name, value := range mods.Add {
		form.Add(name, value)
	}

	// Encode form and update body
	encoded := form.Encode()
	newBodyBytes := []byte(encoded)
	req.Body = io.NopCloser(bytes.NewReader(newBodyBytes))
	req.ContentLength = int64(len(newBodyBytes))

	// Update Content-Length header
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("Content-Length", strconv.Itoa(len(newBodyBytes)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return nil
}

// RequestModifiers is a slice type for request modifiers.
type RequestModifiers []RequestModifier

// Apply performs the apply operation on the RequestModifiers.
func (m RequestModifiers) Apply(req *http.Request) error {
	for _, modifier := range m {
		if err := modifier.Apply(req); err != nil {
			return err
		}
	}
	return nil
}

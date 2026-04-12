// Package cel provides Common Expression Language (CEL) evaluation for dynamic request matching and filtering.
package cel

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	json "github.com/goccy/go-json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// ErrNoModifications is returned when a CEL expression produces no modifications.
var ErrNoModifications = errors.New("cel: no modifications returned")

// ModificationResult represents the modifications to be applied to a request.
type ModificationResult struct {
	// SetHeaders contains headers to set (replaces existing values)
	SetHeaders map[string]string
	// AddHeaders contains headers to add (appends to existing values)
	AddHeaders map[string]string
	// DeleteHeaders contains header names to delete
	DeleteHeaders []string

	// URL modifications
	Scheme   string // URL scheme (http, https)
	Host     string // URL host (including port if needed)
	Path     string // Full path replacement
	Fragment string // URL fragment

	// Path modifications (applied if Path is empty)
	PathPrefix  string            // Prefix to add to path
	PathSuffix  string            // Suffix to add to path
	PathReplace map[string]string // Replace old substring with new (map of old->new)

	// Method is the new HTTP method to set (if not empty)
	Method string

	// Query parameter modifications
	SetQuery    map[string]string // Query params to set (overwrites)
	AddQuery    map[string]string // Query params to add (appends)
	DeleteQuery []string          // Query param names to delete

	// Form parameter modifications
	SetForm    map[string]string // Form params to set (overwrites)
	AddForm    map[string]string // Form params to add (appends)
	DeleteForm []string          // Form param names to delete

	// Body modifications
	BodyRemove        bool   // Remove body entirely
	BodyReplace       string // Replace body with string
	BodyReplaceJSON   string // Replace body with JSON (validates and sets Content-Type)
	BodyReplaceBase64 string // Replace body with base64-decoded content
}

// Modifier modifies HTTP requests based on CEL expressions.
type Modifier interface {
	// Modify evaluates the CEL expression and applies the modifications to the request.
	// Returns the modified request and any error that occurred.
	Modify(*http.Request) (*http.Request, error)
}

type modifier struct {
	cel.Program
}

// Modify evaluates the CEL expression and applies modifications to the request
func (m *modifier) Modify(req *http.Request) (*http.Request, error) {
	vars := getModifierRequestVar(req)

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
	metric.CELExecutionTime(origin, "modifier", duration)

	if err != nil {
		slog.Debug("error evaluating expression", "url", req.URL, "error", err)
		return req, err
	}

	// Extract the modifications from the CEL result
	modifications, err := extractModifications(out)
	if err != nil {
		slog.Debug("error extracting modifications", "url", req.URL, "error", err)
		return req, err
	}

	// Apply modifications to the request
	modifiedReq, err := applyModifications(req, modifications)
	if err != nil {
		slog.Debug("error applying modifications", "url", req.URL, "error", err)
		return req, err
	}

	return modifiedReq, nil
}

// getModifierRequestVar creates CEL variables from an HTTP request for the modifier.
// This returns a simplified map-based representation instead of protobuf types.
func getModifierRequestVar(req *http.Request) map[string]interface{} {
	rc := GetRequestContext(req)

	// Create a simple map representation of the request for easier access in CEL
	reqMap := make(map[string]interface{})
	reqMap["method"] = rc.req.Method
	reqMap["path"] = rc.req.Path
	reqMap["scheme"] = rc.req.Scheme
	reqMap["query"] = rc.req.Query
	reqMap["protocol"] = rc.req.Protocol
	reqMap["size"] = rc.req.Size

	// Convert headers to map[string]interface{}
	headers := make(map[string]interface{})
	for k, v := range rc.req.Headers {
		headers[k] = v
	}
	reqMap["headers"] = headers

	// Add request ID if available
	if requestData := reqctx.GetRequestData(req.Context()); requestData != nil {
		reqMap["id"] = requestData.ID
		// Add request.data field pointing to RequestData.Data
		if requestData.Data != nil {
			reqMap["data"] = requestData.Data
		} else {
			reqMap["data"] = make(map[string]interface{})
		}
	} else {
		reqMap["id"] = ""
		reqMap["data"] = make(map[string]interface{})
	}

	vars := map[string]interface{}{
		"request": reqMap,
		"session": rc.sessionData,
	}

	// Add new namespace variables from RequestData bridge fields
	vars["origin"] = rc.buildOriginVars()
	vars["server"] = rc.buildServerVars()
	vars["vars"] = rc.buildVarsNamespace()
	vars["features"] = rc.buildFeaturesVars()
	vars["client"] = rc.buildClientVars()
	vars["ctx"] = rc.buildCtxVars()

	return vars
}

// NewModifier creates a new CEL modifier for HTTP requests.
// The expression must return a map with modification instructions.
//
// The expression has access to the 9-namespace model:
//   - request, origin, server, vars, features, session, client, ctx, cache
//
// The expression must return a map with the following optional keys:
//   - set_headers: map[string]string - Headers to set (replaces existing)
//   - add_headers: map[string]string - Headers to add (appends to existing)
//   - delete_headers: []string - Header names to delete
//   - path: string - New path to set
//   - method: string - New HTTP method to set
//   - add_query: map[string]string - Query parameters to add
//   - delete_query: []string - Query parameter names to delete
//
// Example expressions:
//
//	{
//	  "set_headers": {"X-Custom": "value"},
//	  "path": "/new/path"
//	}
//
//	{
//	  "add_headers": {"X-Country": client.location['country_code']},
//	  "add_query": {"source": "proxy"}
//	}
//
//	{
//	  "set_headers": {"X-Browser": client.user_agent['family']},
//	  "delete_headers": ["X-Old-Header"]
//	}
func NewModifier(expr string) (Modifier, error) {
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

	// The output type should be a map or dynamic type for flexibility
	// We'll validate the actual return value at runtime

	program, err := env.Program(ast)
	if err != nil {
		return nil, err
	}
	return &modifier{Program: program}, nil
}

// extractModifications extracts ModificationResult from the CEL evaluation result
func extractModifications(out interface{ Value() interface{} }) (*ModificationResult, error) {
	// Convert CEL value to native Go types
	refVal, ok := out.(ref.Val)
	if !ok {
		return nil, fmt.Errorf("cel: expected ref.Val, got %T", out)
	}

	// Use reflection to get the native value
	nativeMap, err := refVal.ConvertToNative(reflect.TypeOf(map[string]interface{}{}))
	if err != nil {
		return nil, fmt.Errorf("cel: failed to convert to native: %w", err)
	}

	resultMap, err := toStringKeyMap(nativeMap)
	if err != nil {
		return nil, err
	}

	result := &ModificationResult{
		SetHeaders:    make(map[string]string),
		AddHeaders:    make(map[string]string),
		DeleteHeaders: []string{},
		PathReplace:   make(map[string]string),
		SetQuery:      make(map[string]string),
		AddQuery:      make(map[string]string),
		DeleteQuery:   []string{},
		SetForm:       make(map[string]string),
		AddForm:       make(map[string]string),
		DeleteForm:    []string{},
	}

	// Extract headers
	// Normalize header names to lowercase for consistency (http.Header is case-insensitive, but normalization ensures consistency)
	if setHeadersVal, ok := resultMap["set_headers"]; ok && setHeadersVal != nil {
		result.SetHeaders = normalizeHeaderMap(convertToStringMap(setHeadersVal))
	}
	if addHeadersVal, ok := resultMap["add_headers"]; ok && addHeadersVal != nil {
		result.AddHeaders = normalizeHeaderMap(convertToStringMap(addHeadersVal))
	}
	if deleteHeadersVal, ok := resultMap["delete_headers"]; ok && deleteHeadersVal != nil {
		result.DeleteHeaders = normalizeHeaderSlice(convertToStringSlice(deleteHeadersVal))
	}

	// Extract URL modifications
	if schemeVal, ok := resultMap["scheme"]; ok && schemeVal != nil {
		if scheme, ok := schemeVal.(string); ok {
			result.Scheme = scheme
		}
	}
	if hostVal, ok := resultMap["host"]; ok && hostVal != nil {
		if host, ok := hostVal.(string); ok {
			result.Host = host
		}
	}
	if pathVal, ok := resultMap["path"]; ok && pathVal != nil {
		if path, ok := pathVal.(string); ok {
			result.Path = path
		}
	}
	if fragmentVal, ok := resultMap["fragment"]; ok && fragmentVal != nil {
		if fragment, ok := fragmentVal.(string); ok {
			result.Fragment = fragment
		}
	}

	// Extract path modifications
	if pathPrefixVal, ok := resultMap["path_prefix"]; ok && pathPrefixVal != nil {
		if pathPrefix, ok := pathPrefixVal.(string); ok {
			result.PathPrefix = pathPrefix
		}
	}
	if pathSuffixVal, ok := resultMap["path_suffix"]; ok && pathSuffixVal != nil {
		if pathSuffix, ok := pathSuffixVal.(string); ok {
			result.PathSuffix = pathSuffix
		}
	}
	if pathReplaceVal, ok := resultMap["path_replace"]; ok && pathReplaceVal != nil {
		result.PathReplace = convertToStringMap(pathReplaceVal)
	}

	// Extract method
	if methodVal, ok := resultMap["method"]; ok && methodVal != nil {
		if method, ok := methodVal.(string); ok {
			result.Method = method
		}
	}

	// Extract query modifications
	if setQueryVal, ok := resultMap["set_query"]; ok && setQueryVal != nil {
		result.SetQuery = convertToStringMap(setQueryVal)
	}
	if addQueryVal, ok := resultMap["add_query"]; ok && addQueryVal != nil {
		result.AddQuery = convertToStringMap(addQueryVal)
	}
	if deleteQueryVal, ok := resultMap["delete_query"]; ok && deleteQueryVal != nil {
		result.DeleteQuery = convertToStringSlice(deleteQueryVal)
	}

	// Extract form modifications
	if setFormVal, ok := resultMap["set_form"]; ok && setFormVal != nil {
		result.SetForm = convertToStringMap(setFormVal)
	}
	if addFormVal, ok := resultMap["add_form"]; ok && addFormVal != nil {
		result.AddForm = convertToStringMap(addFormVal)
	}
	if deleteFormVal, ok := resultMap["delete_form"]; ok && deleteFormVal != nil {
		result.DeleteForm = convertToStringSlice(deleteFormVal)
	}

	// Extract body modifications
	if bodyRemoveVal, ok := resultMap["body_remove"]; ok && bodyRemoveVal != nil {
		if bodyRemove, ok := bodyRemoveVal.(bool); ok {
			result.BodyRemove = bodyRemove
		}
	}
	if bodyReplaceVal, ok := resultMap["body_replace"]; ok && bodyReplaceVal != nil {
		if bodyReplace, ok := bodyReplaceVal.(string); ok {
			result.BodyReplace = bodyReplace
		}
	}
	if bodyReplaceJSONVal, ok := resultMap["body_replace_json"]; ok && bodyReplaceJSONVal != nil {
		if bodyReplaceJSON, ok := bodyReplaceJSONVal.(string); ok {
			result.BodyReplaceJSON = bodyReplaceJSON
		}
	}
	if bodyReplaceBase64Val, ok := resultMap["body_replace_base64"]; ok && bodyReplaceBase64Val != nil {
		if bodyReplaceBase64, ok := bodyReplaceBase64Val.(string); ok {
			result.BodyReplaceBase64 = bodyReplaceBase64
		}
	}

	return result, nil
}

// convertToStringMap converts a value to map[string]string
func convertToStringMap(val interface{}) map[string]string {
	result := make(map[string]string)

	// Try direct conversion first
	if m, ok := val.(map[string]string); ok {
		return m
	}

	// Handle map[ref.Val]ref.Val (CEL native map type)
	if refMap, ok := val.(map[ref.Val]ref.Val); ok {
		for k, v := range refMap {
			// Convert key to string
			kNative, err := k.ConvertToNative(reflect.TypeOf(""))
			if err != nil {
				continue
			}
			kStr, ok := kNative.(string)
			if !ok {
				continue
			}

			// Convert value to string
			vNative, err := v.ConvertToNative(reflect.TypeOf(""))
			if err != nil {
				continue
			}
			vStr, ok := vNative.(string)
			if !ok {
				continue
			}

			result[kStr] = vStr
		}
		return result
	}

	// Try map[string]interface{}
	if m, ok := val.(map[string]interface{}); ok {
		for k, v := range m {
			result[k] = fmt.Sprintf("%v", v)
		}
		return result
	}

	// Handle map[interface{}]interface{} (cel-go 0.28+)
	if m, ok := val.(map[interface{}]interface{}); ok {
		for k, v := range m {
			result[fmt.Sprintf("%v", k)] = fmt.Sprintf("%v", v)
		}
		return result
	}

	// Try ref.Val (CEL type)
	if refVal, ok := val.(ref.Val); ok {
		if nativeMap, err := refVal.ConvertToNative(reflect.TypeOf(map[string]interface{}{})); err == nil {
			if m, ok := nativeMap.(map[string]interface{}); ok {
				for k, v := range m {
					// Handle string values
					if vStr, ok := v.(string); ok {
						result[k] = vStr
						continue
					}
					// Handle ref.Val wrapped strings
					if vRef, ok := v.(ref.Val); ok {
						if vNative, err := vRef.ConvertToNative(reflect.TypeOf("")); err == nil {
							if vStr, ok := vNative.(string); ok {
								result[k] = vStr
							}
						}
					}
				}
			}
		}
	}

	return result
}

// normalizeHeaderMap normalizes header names to lowercase for consistency
// http.Header is case-insensitive, but normalization ensures consistency across the codebase
func normalizeHeaderMap(headers map[string]string) map[string]string {
	normalized := make(map[string]string, len(headers))
	for k, v := range headers {
		normalized[strings.ToLower(k)] = v
	}
	return normalized
}

// normalizeHeaderSlice normalizes header names to lowercase for consistency
func normalizeHeaderSlice(headers []string) []string {
	normalized := make([]string, len(headers))
	for i, h := range headers {
		normalized[i] = strings.ToLower(h)
	}
	return normalized
}

// convertToStringSlice converts a value to []string
func convertToStringSlice(val interface{}) []string {
	result := []string{}

	// Try direct conversion first
	if s, ok := val.([]string); ok {
		return s
	}

	// Handle []ref.Val (CEL native list type)
	if refSlice, ok := val.([]ref.Val); ok {
		for _, v := range refSlice {
			vNative, err := v.ConvertToNative(reflect.TypeOf(""))
			if err != nil {
				continue
			}
			vStr, ok := vNative.(string)
			if !ok {
				continue
			}
			result = append(result, vStr)
		}
		return result
	}

	// Try []interface{}
	if s, ok := val.([]interface{}); ok {
		for _, v := range s {
			// Handle string values
			if vStr, ok := v.(string); ok {
				result = append(result, vStr)
				continue
			}
			// Handle ref.Val wrapped strings
			if vRef, ok := v.(ref.Val); ok {
				if vNative, err := vRef.ConvertToNative(reflect.TypeOf("")); err == nil {
					if vStr, ok := vNative.(string); ok {
						result = append(result, vStr)
					}
				}
			}
		}
		return result
	}

	// Try ref.Val (CEL type)
	if refVal, ok := val.(ref.Val); ok {
		if nativeSlice, err := refVal.ConvertToNative(reflect.TypeOf([]interface{}{})); err == nil {
			if s, ok := nativeSlice.([]interface{}); ok {
				for _, v := range s {
					// Handle string values
					if vStr, ok := v.(string); ok {
						result = append(result, vStr)
						continue
					}
					// Handle ref.Val wrapped strings
					if vRef, ok := v.(ref.Val); ok {
						if vNative, err := vRef.ConvertToNative(reflect.TypeOf("")); err == nil {
							if vStr, ok := vNative.(string); ok {
								result = append(result, vStr)
							}
						}
					}
				}
			}
		}
	}

	return result
}

// applyModifications applies the modifications to the request and returns a new request
func applyModifications(req *http.Request, mods *ModificationResult) (*http.Request, error) {
	// Clone the request to avoid modifying the original
	modifiedReq := req.Clone(req.Context())

	// Ensure we have a proper header map
	if modifiedReq.Header == nil {
		modifiedReq.Header = make(http.Header)
	}

	// Apply URL scheme modification
	if mods.Scheme != "" {
		modifiedReq.URL.Scheme = mods.Scheme
	}

	// Apply URL host modification
	if mods.Host != "" {
		modifiedReq.URL.Host = mods.Host
		modifiedReq.Host = mods.Host
	}

	// Apply path modifications
	if mods.Path != "" {
		// Full path replacement
		modifiedReq.URL.Path = mods.Path
	} else {
		// Apply path transformations if no full replacement
		currentPath := modifiedReq.URL.Path

		// Apply path replace operations
		for old, new := range mods.PathReplace {
			if old != "" {
				currentPath = strings.ReplaceAll(currentPath, old, new)
			}
		}

		// Apply prefix
		if mods.PathPrefix != "" {
			currentPath = mods.PathPrefix + currentPath
		}

		// Apply suffix
		if mods.PathSuffix != "" {
			currentPath = currentPath + mods.PathSuffix
		}

		modifiedReq.URL.Path = currentPath
	}

	// Apply URL fragment modification
	if mods.Fragment != "" {
		modifiedReq.URL.Fragment = mods.Fragment
	}

	// Apply method modification
	if mods.Method != "" {
		modifiedReq.Method = strings.ToUpper(mods.Method)
	}

	// Apply header modifications
	for _, headerName := range mods.DeleteHeaders {
		modifiedReq.Header.Del(headerName)
	}
	for k, v := range mods.SetHeaders {
		modifiedReq.Header.Set(k, v)
	}
	for k, v := range mods.AddHeaders {
		modifiedReq.Header.Add(k, v)
	}

	// Apply query parameter modifications
	if len(mods.SetQuery) > 0 || len(mods.AddQuery) > 0 || len(mods.DeleteQuery) > 0 {
		query := modifiedReq.URL.Query()

		// Delete first
		for _, param := range mods.DeleteQuery {
			query.Del(param)
		}

		// Then set (overwrites)
		for k, v := range mods.SetQuery {
			query.Set(k, v)
		}

		// Then add (appends)
		for k, v := range mods.AddQuery {
			query.Add(k, v)
		}

		modifiedReq.URL.RawQuery = query.Encode()
	}

	// Apply form parameter modifications
	if len(mods.SetForm) > 0 || len(mods.AddForm) > 0 || len(mods.DeleteForm) > 0 {
		if err := applyFormModifications(modifiedReq, mods); err != nil {
			return nil, fmt.Errorf("failed to apply form modifications: %w", err)
		}
	}

	// Apply body modifications
	if mods.BodyRemove || mods.BodyReplace != "" || mods.BodyReplaceJSON != "" || mods.BodyReplaceBase64 != "" {
		if err := applyBodyModifications(modifiedReq, mods); err != nil {
			return nil, fmt.Errorf("failed to apply body modifications: %w", err)
		}
	}

	return modifiedReq, nil
}

// applyFormModifications applies form parameter modifications to the request
func applyFormModifications(req *http.Request, mods *ModificationResult) error {
	// Set content type if not already set
	contentType := req.Header.Get("Content-Type")
	if contentType == "" || !strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	// Read existing body if present
	var bodyBytes []byte
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("failed to read body: %w", err)
		}
		req.Body.Close()
		bodyBytes = body
	}

	// Parse existing form data
	var form url.Values
	if len(bodyBytes) > 0 {
		parsedForm, err := url.ParseQuery(string(bodyBytes))
		if err != nil {
			form = make(url.Values)
		} else {
			form = parsedForm
		}
	} else {
		form = make(url.Values)
	}

	// Apply modifications: delete, set, add
	for _, name := range mods.DeleteForm {
		form.Del(name)
	}
	for name, value := range mods.SetForm {
		form.Set(name, value)
	}
	for name, value := range mods.AddForm {
		form.Add(name, value)
	}

	// Encode form and update body
	encoded := form.Encode()
	newBodyBytes := []byte(encoded)
	req.Body = io.NopCloser(bytes.NewReader(newBodyBytes))
	req.ContentLength = int64(len(newBodyBytes))
	req.Header.Set("Content-Length", strconv.FormatInt(int64(len(newBodyBytes)), 10))

	return nil
}

// applyBodyModifications applies body modifications to the request
func applyBodyModifications(req *http.Request, mods *ModificationResult) error {
	var bodyBytes []byte

	// Priority: BodyReplaceBase64 > BodyReplaceJSON > BodyReplace > BodyRemove
	if mods.BodyReplaceBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(mods.BodyReplaceBase64)
		if err != nil {
			return fmt.Errorf("failed to decode base64 body: %w", err)
		}
		bodyBytes = decoded
	} else if mods.BodyReplaceJSON != "" {
		// Validate JSON
		if !json.Valid([]byte(mods.BodyReplaceJSON)) {
			return fmt.Errorf("invalid JSON body")
		}
		bodyBytes = []byte(mods.BodyReplaceJSON)
		req.Header.Set("Content-Type", "application/json")
	} else if mods.BodyReplace != "" {
		bodyBytes = []byte(mods.BodyReplace)
	} else if mods.BodyRemove {
		bodyBytes = []byte{}
	}

	// Update request body
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	req.ContentLength = int64(len(bodyBytes))

	if len(bodyBytes) == 0 {
		req.Header.Del("Content-Length")
	} else {
		req.Header.Set("Content-Length", strconv.FormatInt(int64(len(bodyBytes)), 10))
	}

	return nil
}

// ApplyModifications is a helper function that applies ModificationResult to a request
func ApplyModifications(req *http.Request, mods *ModificationResult) (*http.Request, error) {
	return applyModifications(req, mods)
}

// ParseModificationExpression parses a CEL expression and returns a Modifier
func ParseModificationExpression(expr string) (Modifier, error) {
	return NewModifier(expr)
}

// ModifyRequest is a convenience function that creates a modifier and applies it to a request
func ModifyRequest(req *http.Request, expr string) (*http.Request, error) {
	modifier, err := NewModifier(expr)
	if err != nil {
		return req, fmt.Errorf("failed to create modifier: %w", err)
	}
	return modifier.Modify(req)
}

// Package cel provides Common Expression Language (CEL) evaluation for dynamic request matching and filtering.
package cel

import (
	"github.com/soapbucket/sbproxy/internal/cache/store"
	"bytes"
	"encoding/base64"
	json "github.com/goccy/go-json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

// ErrNoResponseModifications is returned when a CEL expression produces no modifications.
var ErrNoResponseModifications = errors.New("cel: no response modifications returned")

// ResponseModificationResult represents the modifications to be applied to a response.
type ResponseModificationResult struct {
	// SetHeaders contains headers to set (replaces existing values)
	SetHeaders map[string]string
	// AddHeaders contains headers to add (appends to existing values)
	AddHeaders map[string]string
	// DeleteHeaders contains header names to delete
	DeleteHeaders []string
	
	// Status modifications
	StatusCode int    // New status code to set (if not 0)
	StatusText string // Custom status text (overrides default for status code)
	
	// Body modifications
	Body              string // Simple body replacement (deprecated, use BodyReplace)
	BodyRemove        bool   // Remove body entirely
	BodyReplace       string // Replace body with string
	BodyReplaceJSON   string // Replace body with JSON (validates and sets Content-Type)
	BodyReplaceBase64 string // Replace body with base64-decoded content
}

// ResponseModifier modifies HTTP responses based on CEL expressions.
type ResponseModifier interface {
	// ModifyResponse evaluates the CEL expression and applies the modifications to the response.
	// Returns the modified response and any error that occurred.
	ModifyResponse(*http.Response) error
}

type responseModifier struct {
	cel.Program
}

// ModifyResponse evaluates the CEL expression and applies modifications to the response
func (m *responseModifier) ModifyResponse(resp *http.Response) error {
	vars := getResponseModifierVars(resp)
	
	// Measure CEL execution time
	startTime := time.Now()
	out, _, err := m.Eval(vars)
	duration := time.Since(startTime).Seconds()
	
	// Get origin from config context
	origin := "unknown"
	if resp != nil && resp.Request != nil {
		requestData := reqctx.GetRequestData(resp.Request.Context())
		if requestData != nil && requestData.Config != nil {
			if id := reqctx.ConfigParams(requestData.Config).GetConfigID(); id != "" {
				origin = id
			}
		}
		// Fallback to hostname if config_id not available
		if origin == "unknown" && resp.Request.Host != "" {
			origin = resp.Request.Host
		}
	}
	
	// Record CEL execution time
	metric.CELExecutionTime(origin, "response_modifier", duration)
	
	if err != nil {
		slog.Debug("error evaluating response expression", "url", resp.Request.URL, "error", err)
		return err
	}

	// Extract the modifications from the CEL result
	modifications, err := extractResponseModifications(out)
	if err != nil {
		slog.Debug("error extracting response modifications", "url", resp.Request.URL, "error", err)
		return err
	}

	// Apply modifications to the response
	err = applyResponseModifications(resp, modifications)
	if err != nil {
		slog.Debug("error applying response modifications", "url", resp.Request.URL, "error", err)
		return err
	}

	return nil
}

// getResponseModifierVars creates CEL variables from an HTTP response and request for the modifier.
func getResponseModifierVars(resp *http.Response) map[string]interface{} {
	// Get request variables
	var requestVars map[string]interface{}
	var rc *RequestContext
	if resp.Request != nil && resp.Request.URL != nil {
		rc = GetRequestContext(resp.Request)
		reqMap := make(map[string]interface{})
		reqMap["method"] = rc.req.Method
		reqMap["path"] = rc.req.Path
		reqMap["host"] = rc.req.Host
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
		requestVars = reqMap
	}

	// Create response map
	respMap := make(map[string]interface{})
	respMap["status_code"] = resp.StatusCode
	respMap["status"] = resp.Status

	// Convert response headers to map[string]interface{}
	// Normalize headers to lowercase with hyphens converted to underscores for consistent access
	respHeaders := make(map[string]interface{})
	for k, v := range resp.Header {
		if len(v) > 0 {
			headerKey := strings.ToLower(k)
			headerKey = strings.ReplaceAll(headerKey, "-", "_")
			respHeaders[headerKey] = v[0]
		}
	}
	respMap["headers"] = respHeaders

	// Read response body (we'll need to restore it after)
	var bodyString string
	if resp.Body != nil {
		bodyBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err == nil {
			bodyString = string(bodyBytes)
			// Restore the body for later use
			resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
	}
	respMap["body"] = bodyString

	vars := map[string]interface{}{
		"response": respMap,
	}

	// Add request if available
	if requestVars != nil {
		vars["request"] = requestVars
	}

	// Add namespace variables
	if rc != nil {
		vars["session"] = rc.sessionData
		vars["origin"] = rc.buildOriginVars()
		vars["server"] = rc.buildServerVars()
		vars["vars"] = rc.buildVarsNamespace()
		vars["features"] = rc.buildFeaturesVars()
		vars["client"] = rc.buildClientVars()
		vars["ctx"] = rc.buildCtxVars()
	} else {
		vars["session"] = map[string]interface{}{}
		vars["origin"] = map[string]interface{}{}
		vars["server"] = map[string]interface{}{}
		vars["vars"] = map[string]interface{}{}
		vars["features"] = map[string]interface{}{}
		vars["client"] = map[string]interface{}{}
		vars["ctx"] = map[string]interface{}{}
	}

	return vars
}

// NewResponseModifier creates a new CEL response modifier for HTTP responses.
// The expression must return a map with modification instructions.
//
// The expression has access to:
//   - request: HTTP request fields (same as request modifier)
//   - response: HTTP response fields
//   - status_code: int - HTTP status code
//   - status: string - HTTP status text
//   - headers: map[string]string - Response headers
//   - body: string - Response body content
//
// The expression must return a map with the following optional keys:
//   - set_headers: map[string]string - Headers to set (replaces existing)
//   - add_headers: map[string]string - Headers to add (appends to existing)
//   - delete_headers: []string - Header names to delete
//   - status_code: int - New status code to set
//   - body: string - New body content to set
//
// Example expressions:
//
//	{
//	  "set_headers": {"X-Custom": "value"},
//	  "status_code": 200
//	}
//
//	{
//	  "add_headers": {"X-Modified": "true"},
//	  "body": "{\"status\": \"success\"}"
//	}
//
//	{
//	  "set_headers": {"Content-Type": "application/json"},
//	  "body": "{\"error\": \"not found\"}",
//	  "status_code": 404
//	}
//
//	{
//	  "body": response.body + " [modified]"
//	}
func NewResponseModifier(expr string) (ResponseModifier, error) {
	env, err := GetResponseEnv()
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

	program, err := env.Program(ast)
	if err != nil {
		return nil, err
	}
	return &responseModifier{Program: program}, nil
}

// extractResponseModifications extracts ResponseModificationResult from the CEL evaluation result
func extractResponseModifications(out interface{ Value() interface{} }) (*ResponseModificationResult, error) {
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

	result := &ResponseModificationResult{
		SetHeaders:    make(map[string]string),
		AddHeaders:    make(map[string]string),
		DeleteHeaders: []string{},
	}

	// Extract set_headers
	// Normalize header names to lowercase for consistency (http.Header is case-insensitive, but normalization ensures consistency)
	if setHeadersVal, ok := resultMap["set_headers"]; ok && setHeadersVal != nil {
		setHeaders := normalizeHeaderMap(convertToStringMap(setHeadersVal))
		for k, v := range setHeaders {
			result.SetHeaders[k] = v
		}
	}

	// Extract add_headers
	if addHeadersVal, ok := resultMap["add_headers"]; ok && addHeadersVal != nil {
		addHeaders := normalizeHeaderMap(convertToStringMap(addHeadersVal))
		for k, v := range addHeaders {
			result.AddHeaders[k] = v
		}
	}

	// Extract delete_headers
	if deleteHeadersVal, ok := resultMap["delete_headers"]; ok && deleteHeadersVal != nil {
		deleteHeaders := normalizeHeaderSlice(convertToStringSlice(deleteHeadersVal))
		result.DeleteHeaders = deleteHeaders
	}

	// Extract status_code
	if statusCodeVal, ok := resultMap["status_code"]; ok && statusCodeVal != nil {
		// Handle different numeric types
		switch v := statusCodeVal.(type) {
		case int:
			result.StatusCode = v
		case int64:
			result.StatusCode = int(v)
		case float64:
			result.StatusCode = int(v)
		}
	}

	// Extract status_text
	if statusTextVal, ok := resultMap["status_text"]; ok && statusTextVal != nil {
		if statusText, ok := statusTextVal.(string); ok {
			result.StatusText = statusText
		}
	}

	// Extract body (deprecated, but still supported)
	if bodyVal, ok := resultMap["body"]; ok && bodyVal != nil {
		if body, ok := bodyVal.(string); ok {
			result.Body = body
		}
	}

	// Extract body_remove
	if bodyRemoveVal, ok := resultMap["body_remove"]; ok && bodyRemoveVal != nil {
		if bodyRemove, ok := bodyRemoveVal.(bool); ok {
			result.BodyRemove = bodyRemove
		}
	}

	// Extract body_replace
	if bodyReplaceVal, ok := resultMap["body_replace"]; ok && bodyReplaceVal != nil {
		if bodyReplace, ok := bodyReplaceVal.(string); ok {
			result.BodyReplace = bodyReplace
		}
	}

	// Extract body_replace_json
	if bodyReplaceJSONVal, ok := resultMap["body_replace_json"]; ok && bodyReplaceJSONVal != nil {
		if bodyReplaceJSON, ok := bodyReplaceJSONVal.(string); ok {
			result.BodyReplaceJSON = bodyReplaceJSON
		}
	}

	// Extract body_replace_base64
	if bodyReplaceBase64Val, ok := resultMap["body_replace_base64"]; ok && bodyReplaceBase64Val != nil {
		if bodyReplaceBase64, ok := bodyReplaceBase64Val.(string); ok {
			result.BodyReplaceBase64 = bodyReplaceBase64
		}
	}

	return result, nil
}

// applyResponseModifications applies the modifications to the response
func applyResponseModifications(resp *http.Response, mods *ResponseModificationResult) error {
	// Ensure we have a proper header map
	if resp.Header == nil {
		resp.Header = make(http.Header)
	}

	// Apply header modifications
	for _, headerName := range mods.DeleteHeaders {
		resp.Header.Del(headerName)
	}
	for k, v := range mods.SetHeaders {
		resp.Header.Set(k, v)
	}
	for k, v := range mods.AddHeaders {
		resp.Header.Add(k, v)
	}

	// Apply status code and text modifications
	if mods.StatusCode != 0 {
		resp.StatusCode = mods.StatusCode
		if mods.StatusText != "" {
			// Use custom status text - optimized with strings.Builder from pool
			sb := cacher.GetBuilderWithSize(8 + len(mods.StatusText)) // Estimate: status code (3) + space (1) + text
			sb.WriteString(strconv.Itoa(mods.StatusCode))
			sb.WriteByte(' ')
			sb.WriteString(mods.StatusText)
			resp.Status = sb.String()
			cacher.PutBuilder(sb)
		} else {
			// Use default status text
			resp.Status = http.StatusText(mods.StatusCode)
			if resp.Status == "" {
				// No default status text, use just the code
				resp.Status = strconv.Itoa(mods.StatusCode)
			} else {
				// Combine code with default text - optimized with strings.Builder from pool
				sb := cacher.GetBuilderWithSize(8 + len(resp.Status)) // Estimate: status code (3) + space (1) + text
				sb.WriteString(strconv.Itoa(mods.StatusCode))
				sb.WriteByte(' ')
				sb.WriteString(resp.Status)
				resp.Status = sb.String()
				cacher.PutBuilder(sb)
			}
		}
	} else if mods.StatusText != "" {
		// Only status text provided, keep existing status code - optimized with strings.Builder from pool
		sb := cacher.GetBuilderWithSize(8 + len(mods.StatusText)) // Estimate: status code (3) + space (1) + text
		sb.WriteString(strconv.Itoa(resp.StatusCode))
		sb.WriteByte(' ')
		sb.WriteString(mods.StatusText)
		resp.Status = sb.String()
		cacher.PutBuilder(sb)
	}

	// Apply body modifications
	// Priority: BodyReplaceBase64 > BodyReplaceJSON > BodyReplace > Body (deprecated) > BodyRemove
	if mods.BodyReplaceBase64 != "" || mods.BodyReplaceJSON != "" || 
	   mods.BodyReplace != "" || mods.Body != "" || mods.BodyRemove {
		var bodyBytes []byte
		var err error

		if mods.BodyReplaceBase64 != "" {
			bodyBytes, err = base64.StdEncoding.DecodeString(mods.BodyReplaceBase64)
			if err != nil {
				return fmt.Errorf("failed to decode base64 body: %w", err)
			}
		} else if mods.BodyReplaceJSON != "" {
			// Validate JSON
			if !json.Valid([]byte(mods.BodyReplaceJSON)) {
				return fmt.Errorf("invalid JSON body")
			}
			bodyBytes = []byte(mods.BodyReplaceJSON)
			resp.Header.Set("Content-Type", "application/json")
		} else if mods.BodyReplace != "" {
			bodyBytes = []byte(mods.BodyReplace)
		} else if mods.Body != "" {
			// Support deprecated 'body' field
			bodyBytes = []byte(mods.Body)
		} else if mods.BodyRemove {
			bodyBytes = []byte{}
		}

		// Update response body
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		resp.ContentLength = int64(len(bodyBytes))

		if len(bodyBytes) == 0 {
			resp.Header.Del("Content-Length")
		} else {
			resp.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
		}
	}

	return nil
}

// ApplyResponseModifications is a helper function that applies ResponseModificationResult to a response
func ApplyResponseModifications(resp *http.Response, mods *ResponseModificationResult) error {
	return applyResponseModifications(resp, mods)
}

// ParseResponseModificationExpression parses a CEL expression and returns a ResponseModifier
func ParseResponseModificationExpression(expr string) (ResponseModifier, error) {
	return NewResponseModifier(expr)
}

// ModifyResponseWithExpression is a convenience function that creates a modifier and applies it to a response
func ModifyResponseWithExpression(resp *http.Response, expr string) error {
	modifier, err := NewResponseModifier(expr)
	if err != nil {
		return fmt.Errorf("failed to create response modifier: %w", err)
	}
	return modifier.ModifyResponse(resp)
}

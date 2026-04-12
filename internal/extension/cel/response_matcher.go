// Package cel provides Common Expression Language (CEL) evaluation for dynamic request matching and filtering.
package cel

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/cel-go/cel"
)

// ResponseMatcher evaluates CEL expressions against HTTP responses.
type ResponseMatcher interface {
	// Match evaluates the CEL expression against the given HTTP response.
	// Returns true if the expression evaluates to true, false otherwise.
	// If evaluation fails, returns false and logs the error.
	Match(*http.Response) bool
}

type responseMatcher struct {
	cel.Program
}

// Match performs the match operation on the responseMatcher.
func (m *responseMatcher) Match(resp *http.Response) bool {
	vars := getResponseMatcherVars(resp)
	out, _, err := m.Eval(vars)
	if err != nil {
		slog.Debug("error evaluating response expression", "url", resp.Request.URL, "error", err)
		return false
	}
	if outBool, ok := out.Value().(bool); ok {
		return outBool
	}
	return false
}

// getResponseMatcherVars creates CEL variables from an HTTP response for matching.
func getResponseMatcherVars(resp *http.Response) map[string]interface{} {
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

	// Store response headers under lowercase keys only
	respHeaders := make(map[string]interface{})
	for k, v := range resp.Header {
		if len(v) > 0 {
			respHeaders[strings.ToLower(k)] = v[0]
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
		vars["oauth_user"] = rc.oauthUser
		vars["origin"] = rc.buildOriginVars()
		vars["server"] = rc.buildServerVars()
		vars["vars"] = rc.buildVarsNamespace()
		vars["features"] = rc.buildFeaturesVars()
		vars["client"] = rc.buildClientVars()
		vars["ctx"] = rc.buildCtxVars()
	} else {
		vars["session"] = map[string]interface{}{}
		vars["oauth_user"] = map[string]interface{}{}
		vars["origin"] = map[string]interface{}{}
		vars["server"] = map[string]interface{}{}
		vars["vars"] = map[string]interface{}{}
		vars["features"] = map[string]interface{}{}
		vars["client"] = map[string]interface{}{}
		vars["ctx"] = map[string]interface{}{}
	}

	return vars
}

// NewResponseMatcher creates a new CEL response matcher for HTTP responses.
// The expression must return a boolean value and can access response properties
// through the 'response' object which has the following fields:
//   - status_code: int (HTTP status code)
//   - status: string (HTTP status text, e.g., "200 OK")
//   - headers: map<string, string> (response headers)
//   - body: string (response body content)
//
// The expression can also access request properties through the 'request' object:
//   - path: string
//   - method: string
//   - host: string
//   - protocol: string
//   - scheme: string
//   - query: string (URL-encoded query string)
//   - size: int (content length)
//   - headers: map<string, string>
//
// Context namespaces are also available:
//   - origin, server, vars, features, session, client, ctx
//   - oauth_user: map<string, any>
//
// Example expressions:
//
//	response.status_code == 200
//	response.status_code >= 400 && response.status_code < 500
//	response.headers["content-type"].contains("application/json")
//	response.body.contains("error")
//	response.status_code == 404 && request.path.startsWith("/api/")
//	response.status_code == 200 && response.body.contains("success") && client.location["country_code"] == "US"
func NewResponseMatcher(expr string) (ResponseMatcher, error) {
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
	if ast.OutputType() != cel.BoolType {
		return nil, ErrWrongType
	}

	program, err := env.Program(ast)
	if err != nil {
		return nil, err
	}
	return &responseMatcher{Program: program}, nil
}

// Package assertion registers the response_assertion policy module.
// Unlike the expression policy (which evaluates requests), this module
// evaluates assertions against backend RESPONSES. It captures the response
// using a buffered ResponseWriter, evaluates assertions, and either forwards
// the original response or replaces it with a blocking error.
package assertion

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/soapbucket/sbproxy/internal/extension/cel"
	"github.com/soapbucket/sbproxy/internal/extension/lua"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterPolicy("response_assertion", New)
}

// ResponseAssertion defines a named assertion evaluated against an HTTP response.
type ResponseAssertion struct {
	Name       string `json:"name"`
	CELExpr    string `json:"cel_expr,omitempty"`
	LuaScript  string `json:"lua_script,omitempty"`
	Action     string `json:"action"`                // "block" or "flag"
	StatusCode int    `json:"status_code,omitempty"` // default 403
	Message    string `json:"message,omitempty"`
}

// compiledResponseAssertion holds a single assertion with its compiled matchers.
type compiledResponseAssertion struct {
	ResponseAssertion
	celMatcher cel.ResponseMatcher
	luaMatcher lua.ResponseMatcher
}

// Config holds configuration for the response_assertion policy.
type Config struct {
	Type       string              `json:"type"`
	Disabled   bool                `json:"disabled,omitempty"`
	Assertions []ResponseAssertion `json:"assertions"`
}

// AssertionResult contains the outcome of evaluating a single response assertion.
type AssertionResult struct {
	Blocked       bool
	Flagged       bool
	StatusCode    int
	Message       string
	AssertionName string
}

type responseAssertionPolicy struct {
	cfg        *Config
	assertions []compiledResponseAssertion
}

// New creates a new response assertion policy from raw JSON configuration.
func New(data json.RawMessage) (plugin.PolicyEnforcer, error) {
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	if len(cfg.Assertions) == 0 {
		return nil, fmt.Errorf("response_assertion policy requires at least one assertion")
	}

	p := &responseAssertionPolicy{cfg: cfg}
	p.assertions = make([]compiledResponseAssertion, 0, len(cfg.Assertions))

	for i, a := range cfg.Assertions {
		compiled := compiledResponseAssertion{ResponseAssertion: a}

		if a.CELExpr == "" && a.LuaScript == "" {
			return nil, fmt.Errorf("response_assertion[%d] (%s): requires either cel_expr or lua_script", i, a.Name)
		}

		if a.Action != "block" && a.Action != "flag" {
			return nil, fmt.Errorf("response_assertion[%d] (%s): action must be \"block\" or \"flag\", got %q", i, a.Name, a.Action)
		}

		if a.CELExpr != "" {
			matcher, err := cel.NewResponseMatcher(a.CELExpr)
			if err != nil {
				return nil, fmt.Errorf("response_assertion[%d] (%s): failed to compile CEL: %w", i, a.Name, err)
			}
			compiled.celMatcher = matcher
		}

		if a.LuaScript != "" {
			matcher, err := lua.NewResponseMatcher(a.LuaScript)
			if err != nil {
				return nil, fmt.Errorf("response_assertion[%d] (%s): failed to compile Lua: %w", i, a.Name, err)
			}
			compiled.luaMatcher = matcher
		}

		p.assertions = append(p.assertions, compiled)
	}

	return p, nil
}

func (p *responseAssertionPolicy) Type() string { return "response_assertion" }

// Enforce wraps the handler to intercept the backend response and evaluate
// assertions against it. The response is captured with a buffered ResponseWriter.
// If any blocking assertion triggers, the original response is replaced.
func (p *responseAssertionPolicy) Enforce(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.cfg.Disabled {
			next.ServeHTTP(w, r)
			return
		}

		// Capture the response from downstream handlers
		rec := &bufferedResponseWriter{
			header: make(http.Header),
		}
		next.ServeHTTP(rec, r)

		// Build a synthetic http.Response for assertion evaluation
		resp := rec.toHTTPResponse(r)

		// Evaluate assertions
		result := p.evaluateResponse(resp, r)

		if result != nil && result.Blocked {
			// Write blocking response instead of the captured one
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(result.StatusCode)
			_, _ = io.WriteString(w, result.Message)
			return
		}

		// Forward the original captured response
		rec.writeTo(w)
	})
}

// evaluateResponse runs all assertions against the given HTTP response.
// Returns an AssertionResult if a blocking assertion triggers, nil otherwise.
func (p *responseAssertionPolicy) evaluateResponse(resp *http.Response, r *http.Request) *AssertionResult {
	// Buffer body once for all assertions
	if resp.Body == nil {
		return nil
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		slog.Error("response_assertion: failed to read response body", "error", err)
		return nil
	}

	for _, a := range p.assertions {
		// Reset body for each assertion
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		passed := p.evaluateAssertion(a, resp)
		if passed {
			continue
		}

		// Assertion failed
		statusCode := a.StatusCode
		if statusCode == 0 {
			statusCode = http.StatusForbidden
		}
		message := a.Message
		if message == "" {
			message = fmt.Sprintf("Response blocked by assertion: %s", a.Name)
		}

		if a.Action == "block" {
			reqctx.RecordPolicyViolation(r.Context(), "response_assertion", message)
			return &AssertionResult{
				Blocked:       true,
				StatusCode:    statusCode,
				Message:       message,
				AssertionName: a.Name,
			}
		}

		// Flag action: log and continue
		reqctx.RecordPolicyViolation(r.Context(), "response_assertion", message)
		slog.Warn("response assertion flagged",
			"assertion", a.Name,
			"status_code", resp.StatusCode,
			"message", message)
	}

	// Restore body for downstream use
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return nil
}

// evaluateAssertion runs a single assertion's CEL and/or Lua matchers.
// Returns true if the assertion passes, false if it triggers.
func (p *responseAssertionPolicy) evaluateAssertion(a compiledResponseAssertion, resp *http.Response) bool {
	if a.celMatcher != nil {
		if !a.celMatcher.Match(resp) {
			return false
		}
	}
	if a.luaMatcher != nil {
		if !a.luaMatcher.Match(resp) {
			return false
		}
	}
	return true
}

// bufferedResponseWriter captures a handler's response (status, headers, body)
// so the response_assertion policy can inspect it before forwarding.
type bufferedResponseWriter struct {
	header     http.Header
	body       bytes.Buffer
	statusCode int
}

func (w *bufferedResponseWriter) Header() http.Header {
	return w.header
}

func (w *bufferedResponseWriter) Write(b []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	return w.body.Write(b)
}

func (w *bufferedResponseWriter) WriteHeader(code int) {
	w.statusCode = code
}

// toHTTPResponse converts the buffered response to an *http.Response for
// assertion evaluation. The body is set to a fresh reader of the buffered data.
func (w *bufferedResponseWriter) toHTTPResponse(r *http.Request) *http.Response {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	bodyBytes := w.body.Bytes()
	return &http.Response{
		StatusCode:    w.statusCode,
		Status:        strconv.Itoa(w.statusCode) + " " + http.StatusText(w.statusCode),
		Header:        w.header.Clone(),
		Body:          io.NopCloser(bytes.NewReader(bodyBytes)),
		ContentLength: int64(len(bodyBytes)),
		Request:       r,
	}
}

// writeTo forwards the captured response to the real ResponseWriter.
func (w *bufferedResponseWriter) writeTo(dst http.ResponseWriter) {
	// Copy headers
	for k, vals := range w.header {
		for _, v := range vals {
			dst.Header().Add(k, v)
		}
	}

	// Remove Content-Length if present; let net/http recompute it
	dst.Header().Del("Content-Length")

	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	dst.WriteHeader(w.statusCode)
	_, _ = dst.Write(w.body.Bytes())
}

// formatFlaggedAssertions builds a log-friendly string from flagged assertion names.
func formatFlaggedAssertions(names []string) string {
	return strings.Join(names, ", ")
}

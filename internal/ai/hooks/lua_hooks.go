// lua_hooks.go implements Lua-based request and response modification hooks
// for the AI gateway.
//
// Operators write Lua scripts that define modify_request(req, ctx) and/or
// modify_response(resp, ctx) functions. Scripts run in a sandboxed Lua VM
// (no filesystem, network, or OS access) with a configurable execution
// timeout. Data flows through JSON round-trips: Go struct -> map -> Lua
// table -> map -> Go struct. Post-execution validation enforces message
// count and byte size limits to prevent runaway scripts from producing
// oversized requests.
//
// Streaming mode controls on_response behavior for SSE responses:
//   - "skip" (default): on_response is not called for streaming responses
//   - "buffer" and "chunk": reserved for future streaming hook support
package hooks

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	json "github.com/goccy/go-json"
	lua "github.com/yuin/gopher-lua"

	"github.com/soapbucket/sbproxy/internal/ai"
	luaext "github.com/soapbucket/sbproxy/internal/extension/lua"
	"github.com/soapbucket/sbproxy/internal/extension/scripting"
)

const (
	// DefaultMaxMessages is the default maximum number of messages allowed after Lua modification.
	DefaultMaxMessages = 500
	// DefaultMaxRequestBytes is the default maximum request size in bytes after Lua modification (10MB).
	DefaultMaxRequestBytes = 10 * 1024 * 1024
	// DefaultLuaHookTimeout is the default execution timeout for Lua hook scripts.
	DefaultLuaHookTimeout = 100 * time.Millisecond
)

// LuaHookConfig holds the configuration for Lua request/response hooks.
type LuaHookConfig struct {
	// OnRequestLua is the Lua script for request modification.
	// Must define: function modify_request(req, ctx) ... return req end
	OnRequestLua string `json:"on_request_lua,omitempty" yaml:"on_request_lua,omitempty"`
	// OnResponseLua is the Lua script for response modification.
	// Must define: function modify_response(resp, ctx) ... return resp end
	OnResponseLua string `json:"on_response_lua,omitempty" yaml:"on_response_lua,omitempty"`
	// StreamingMode controls how on_response behaves for streaming requests.
	// "skip" (default): on_response is not called for streaming responses.
	// "buffer" and "chunk" are reserved for future use.
	StreamingMode string `json:"streaming_mode,omitempty" yaml:"streaming_mode,omitempty"`
	// MaxMessages is the post-execution validation limit for message count.
	MaxMessages int `json:"max_messages,omitempty" yaml:"max_messages,omitempty"`
	// MaxRequestBytes is the post-execution size limit in bytes.
	MaxRequestBytes int `json:"max_request_bytes,omitempty" yaml:"max_request_bytes,omitempty"`
	// Timeout overrides the default Lua execution timeout.
	Timeout time.Duration `json:"timeout,omitempty" yaml:"timeout,omitempty"`
}

// LuaHooks manages compiled Lua scripts for AI request/response modification.
type LuaHooks struct {
	onRequestScript  string
	onResponseScript string
	streamingMode    string
	maxMessages      int
	maxRequestBytes  int
	timeout          time.Duration
}

// NewLuaHooks creates a new LuaHooks from the given configuration.
// It validates and compiles both request and response scripts at construction time.
func NewLuaHooks(config LuaHookConfig) (*LuaHooks, error) {
	h := &LuaHooks{
		streamingMode:   config.StreamingMode,
		maxMessages:     config.MaxMessages,
		maxRequestBytes: config.MaxRequestBytes,
		timeout:         config.Timeout,
	}

	// Apply defaults
	if h.streamingMode == "" {
		h.streamingMode = "skip"
	}
	if h.maxMessages <= 0 {
		h.maxMessages = DefaultMaxMessages
	}
	if h.maxRequestBytes <= 0 {
		h.maxRequestBytes = DefaultMaxRequestBytes
	}
	if h.timeout <= 0 {
		h.timeout = DefaultLuaHookTimeout
	}

	// Validate streaming mode
	switch h.streamingMode {
	case "skip":
		// OK
	case "buffer", "chunk":
		return nil, fmt.Errorf("lua_hooks: streaming mode %q is not yet supported", h.streamingMode)
	default:
		return nil, fmt.Errorf("lua_hooks: unknown streaming mode %q", h.streamingMode)
	}

	// Validate and store on_request script
	if config.OnRequestLua != "" {
		script := wrapAIRequestScript(config.OnRequestLua)
		if err := validateLuaScript(script, "modify_request"); err != nil {
			return nil, fmt.Errorf("lua_hooks: on_request script error: %w", err)
		}
		h.onRequestScript = script
	}

	// Validate and store on_response script
	if config.OnResponseLua != "" {
		script := wrapAIResponseScript(config.OnResponseLua)
		if err := validateLuaScript(script, "modify_response"); err != nil {
			return nil, fmt.Errorf("lua_hooks: on_response script error: %w", err)
		}
		h.onResponseScript = script
	}

	return h, nil
}

// ModifyRequest runs the on_request Lua hook against the ChatCompletionRequest.
// If no on_request hook is configured, the request is returned unmodified.
// The ctx parameter provides the 9-namespace scripting context to the Lua script.
func (h *LuaHooks) ModifyRequest(req *ai.ChatCompletionRequest, sc *scripting.ScriptContext) (*ai.ChatCompletionRequest, error) {
	if h == nil || h.onRequestScript == "" || req == nil {
		return req, nil
	}

	// Convert request to generic map for Lua
	reqMap, err := structToMap(req)
	if err != nil {
		return req, fmt.Errorf("lua_hooks: failed to marshal request for Lua: %w", err)
	}

	// Execute Lua
	resultMap, err := h.executeLuaHook(h.onRequestScript, "modify_request", reqMap, sc)
	if err != nil {
		return req, fmt.Errorf("lua_hooks: on_request failed: %w", err)
	}

	// Convert result back to ChatCompletionRequest
	modified, err := mapToStruct[ai.ChatCompletionRequest](resultMap)
	if err != nil {
		return req, fmt.Errorf("lua_hooks: failed to unmarshal modified request: %w", err)
	}

	// Post-execution validation
	if len(modified.Messages) > h.maxMessages {
		return req, fmt.Errorf("lua_hooks: modified request has %d messages, exceeds limit of %d", len(modified.Messages), h.maxMessages)
	}

	estimatedSize, err := estimateJSONSize(modified)
	if err != nil {
		return req, fmt.Errorf("lua_hooks: failed to estimate modified request size: %w", err)
	}
	if estimatedSize > h.maxRequestBytes {
		return req, fmt.Errorf("lua_hooks: modified request size %d bytes exceeds limit of %d bytes", estimatedSize, h.maxRequestBytes)
	}

	return modified, nil
}

// ModifyResponse runs the on_response Lua hook against the ChatCompletionResponse.
// If no on_response hook is configured, or if streaming mode is "skip" and the
// request was streaming, the response is returned unmodified.
func (h *LuaHooks) ModifyResponse(resp *ai.ChatCompletionResponse, sc *scripting.ScriptContext, streaming bool) (*ai.ChatCompletionResponse, error) {
	if h == nil || h.onResponseScript == "" || resp == nil {
		return resp, nil
	}

	// Skip for streaming responses when mode is "skip"
	if streaming && h.streamingMode == "skip" {
		return resp, nil
	}

	// Convert response to generic map for Lua
	respMap, err := structToMap(resp)
	if err != nil {
		return resp, fmt.Errorf("lua_hooks: failed to marshal response for Lua: %w", err)
	}

	// Execute Lua
	resultMap, err := h.executeLuaHook(h.onResponseScript, "modify_response", respMap, sc)
	if err != nil {
		return resp, fmt.Errorf("lua_hooks: on_response failed: %w", err)
	}

	// Convert result back to ChatCompletionResponse
	modified, err := mapToStruct[ai.ChatCompletionResponse](resultMap)
	if err != nil {
		return resp, fmt.Errorf("lua_hooks: failed to unmarshal modified response: %w", err)
	}

	return modified, nil
}

// executeLuaHook runs a Lua script with the given function name, data, and context.
func (h *LuaHooks) executeLuaHook(script, funcName string, data map[string]interface{}, sc *scripting.ScriptContext) (map[string]interface{}, error) {
	L := luaext.NewSandboxedState()
	defer L.Close()

	ctx, cancel := context.WithTimeout(context.Background(), h.timeout)
	defer cancel()
	L.SetContext(ctx)

	startTime := time.Now()

	// Load the script
	if err := L.DoString(script); err != nil {
		slog.Debug("lua_hooks: script compilation error", "func", funcName, "error", err)
		return nil, fmt.Errorf("script compilation: %w", err)
	}

	// Get the target function
	fn := L.GetGlobal(funcName)
	if fn.Type() != lua.LTFunction {
		return nil, fmt.Errorf("function %q not found in script", funcName)
	}

	// Convert Go data to Lua table
	dataTable := luaext.ConvertGoToLua(L, data)

	// Build context table from ScriptContext
	ctxTable := scripting.BuildContextTable(L, sc)

	// Call the function
	L.Push(fn)
	L.Push(dataTable)
	L.Push(ctxTable)
	if err := L.PCall(2, 1, nil); err != nil {
		duration := time.Since(startTime)
		slog.Debug("lua_hooks: execution error", "func", funcName, "duration", duration, "error", err)
		return nil, fmt.Errorf("execution: %w", err)
	}

	duration := time.Since(startTime)
	slog.Debug("lua_hooks: executed", "func", funcName, "duration", duration)

	// Get return value
	if L.GetTop() == 0 {
		return nil, fmt.Errorf("function %q did not return a value", funcName)
	}

	ret := L.Get(-1)
	L.Pop(1)

	if ret == lua.LNil {
		return data, nil // Return original data if Lua returned nil
	}

	// Convert Lua result back to Go map
	goResult := luaext.ConvertLuaToGo(L, ret)
	resultMap, ok := goResult.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("function %q must return a table, got %T", funcName, goResult)
	}

	return resultMap, nil
}

// wrapAIRequestScript ensures the script defines a modify_request function.
func wrapAIRequestScript(script string) string {
	if script == "" {
		return ""
	}
	// If the script already contains the function definition, use as-is
	if containsFunction(script, "modify_request") {
		return script
	}
	// Wrap bare code in a function
	return "function modify_request(req, ctx)\n" + script + "\nreturn req\nend"
}

// wrapAIResponseScript ensures the script defines a modify_response function.
func wrapAIResponseScript(script string) string {
	if script == "" {
		return ""
	}
	if containsFunction(script, "modify_response") {
		return script
	}
	return "function modify_response(resp, ctx)\n" + script + "\nreturn resp\nend"
}

// containsFunction checks if a script contains a function definition.
func containsFunction(script, name string) bool {
	return len(script) > 0 && strings.Contains(script, "function "+name)
}

// validateLuaScript compiles a Lua script and checks that the named function exists.
func validateLuaScript(script, funcName string) error {
	L := luaext.NewSandboxedState()
	defer L.Close()

	if err := L.DoString(script); err != nil {
		return fmt.Errorf("compilation: %w", err)
	}

	fn := L.GetGlobal(funcName)
	if fn.Type() != lua.LTFunction {
		return fmt.Errorf("missing required function %q", funcName)
	}

	return nil
}

// structToMap converts a struct to map[string]interface{} via JSON round-trip.
func structToMap(v interface{}) (map[string]interface{}, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// mapToStruct converts a map[string]interface{} back to a typed struct via JSON round-trip.
func mapToStruct[T any](m map[string]interface{}) (*T, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// estimateJSONSize returns the JSON-encoded byte size of the value.
func estimateJSONSize(v interface{}) (int, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return 0, err
	}
	return len(data), nil
}

// Package hooks provides CEL selectors, Lua hooks, and CEL guardrails for AI request processing.
package hooks

import (
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	celgo "github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"github.com/soapbucket/sbproxy/internal/ai/keys"

	ai "github.com/soapbucket/sbproxy/internal/ai"
)

// selectorEnv is the shared CEL environment for AI selector expressions.
// It exposes: request, headers, key, workspace, timestamp.
var (
	selectorEnvOnce sync.Once
	selectorEnvVal  *celgo.Env
	selectorEnvErr  error
)

// getSelectorEnv returns the shared CEL environment for selector expressions.
// This environment is distinct from the AI routing env and the proxy request env.
func getSelectorEnv() (*celgo.Env, error) {
	selectorEnvOnce.Do(func() {
		selectorEnvVal, selectorEnvErr = celgo.NewEnv(
			celgo.Variable("request", celgo.MapType(celgo.StringType, celgo.DynType)),
			celgo.Variable("headers", celgo.MapType(celgo.StringType, celgo.StringType)),
			celgo.Variable("key", celgo.MapType(celgo.StringType, celgo.DynType)),
			celgo.Variable("workspace", celgo.StringType),
			celgo.Variable("timestamp", celgo.MapType(celgo.StringType, celgo.DynType)),
			ext.Strings(),
			ext.Encoders(),
		)
	})
	return selectorEnvVal, selectorEnvErr
}

// CELSelectorConfig holds the raw CEL expressions for routing selectors.
type CELSelectorConfig struct {
	// ModelSelector returns a string (model name) to override the request model.
	ModelSelector string `json:"model_selector,omitempty"`
	// ProviderSelector returns a string (provider name) to prefer. Empty means normal routing.
	ProviderSelector string `json:"provider_selector,omitempty"`
	// CacheBypass returns a bool. When true, the semantic cache is skipped.
	CacheBypass string `json:"cache_bypass,omitempty"`
	// DynamicRPM returns an int to override the per-model RPM limit.
	DynamicRPM string `json:"dynamic_rpm,omitempty"`
	// FailOpen controls behavior on CEL evaluation errors.
	// When true (default), errors log a warning and return zero/empty values.
	// When false, errors are propagated to the caller.
	FailOpen *bool `json:"fail_open,omitempty"`
}

// CELSelector holds pre-compiled CEL programs for routing decisions.
// Expressions are compiled once at config load time; evaluation is per-request.
type CELSelector struct {
	modelExpr    celgo.Program // Returns string (model name)
	providerExpr celgo.Program // Returns string (provider name)
	cacheExpr    celgo.Program // Returns bool (skip cache?)
	rpmExpr      celgo.Program // Returns int (override RPM)
	failOpen     bool          // Fail-open on eval errors
}

// AIRequestCELContext holds per-request data exposed to CEL selector expressions.
type AIRequestCELContext struct {
	// Request holds model, messages, temperature, max_tokens, tools, stream fields.
	Request map[string]any
	// Headers holds normalized HTTP request headers.
	Headers map[string]string
	// Key holds virtual key metadata: key_id, key_name, allowed_models, tags.
	Key map[string]any
	// Workspace is the workspace identifier.
	Workspace string
	// Timestamp holds time components: hour, minute, day_of_week, date.
	Timestamp map[string]any
}

// BuildAIRequestCELContext constructs the CEL context from the current request state.
func BuildAIRequestCELContext(req *ai.ChatCompletionRequest, r *http.Request, workspaceID string) *AIRequestCELContext {
	ctx := &AIRequestCELContext{
		Workspace: workspaceID,
	}

	// Build request map
	reqMap := map[string]any{
		"model":  req.Model,
		"stream": req.IsStreaming(),
	}
	// Messages as list of maps
	msgs := make([]any, 0, len(req.Messages))
	for _, m := range req.Messages {
		msgs = append(msgs, map[string]any{
			"role":    m.Role,
			"content": m.ContentString(),
		})
	}
	reqMap["messages"] = msgs

	if req.Temperature != nil {
		reqMap["temperature"] = *req.Temperature
	} else {
		reqMap["temperature"] = 0.0
	}
	if req.MaxTokens != nil {
		reqMap["max_tokens"] = int64(*req.MaxTokens)
	} else {
		reqMap["max_tokens"] = int64(0)
	}
	reqMap["tools"] = len(req.Tools) > 0
	ctx.Request = reqMap

	// Build headers map
	hdrs := make(map[string]string)
	if r != nil {
		for k := range r.Header {
			hdrs[http.CanonicalHeaderKey(k)] = r.Header.Get(k)
		}
	}
	ctx.Headers = hdrs

	// Build key map from virtual key context
	keyMap := map[string]any{
		"key_id":         "",
		"key_name":       "",
		"allowed_models": []any{},
		"tags":           map[string]any{},
	}
	if r != nil {
		if vk, ok := keys.FromContext(r.Context()); ok {
			keyMap["key_id"] = vk.ID
			keyMap["key_name"] = vk.Name
			models := make([]any, 0, len(vk.AllowedModels))
			for _, m := range vk.AllowedModels {
				models = append(models, m)
			}
			keyMap["allowed_models"] = models
			tags := make(map[string]any)
			for k, v := range vk.Metadata {
				tags[k] = v
			}
			keyMap["tags"] = tags
		}
	}
	ctx.Key = keyMap

	// Build timestamp map
	now := time.Now()
	ctx.Timestamp = map[string]any{
		"hour":        int64(now.Hour()),
		"minute":      int64(now.Minute()),
		"day_of_week": now.Weekday().String(),
		"date":        now.Format("2006-01-02"),
	}

	return ctx
}

// activation converts the context into the CEL activation map.
func (c *AIRequestCELContext) activation() map[string]any {
	if c == nil {
		return map[string]any{
			"request":   map[string]any{},
			"headers":   map[string]string{},
			"key":       map[string]any{},
			"workspace": "",
			"timestamp": map[string]any{},
		}
	}
	return map[string]any{
		"request":   c.Request,
		"headers":   c.Headers,
		"key":       c.Key,
		"workspace": c.Workspace,
		"timestamp": c.Timestamp,
	}
}

// NewCELSelector compiles all non-empty CEL expressions and returns a ready-to-use selector.
// Returns nil if all expressions are empty (no selectors configured).
// Compilation errors are returned immediately so that invalid expressions are caught at config load time.
func NewCELSelector(config CELSelectorConfig) (*CELSelector, error) {
	if config.ModelSelector == "" && config.ProviderSelector == "" &&
		config.CacheBypass == "" && config.DynamicRPM == "" {
		return nil, nil
	}

	env, err := getSelectorEnv()
	if err != nil {
		return nil, err
	}

	failOpen := true
	if config.FailOpen != nil {
		failOpen = *config.FailOpen
	}

	s := &CELSelector{failOpen: failOpen}

	if config.ModelSelector != "" {
		prog, err := compileSelector(env, config.ModelSelector, celgo.StringType, "model_selector")
		if err != nil {
			return nil, err
		}
		s.modelExpr = prog
	}

	if config.ProviderSelector != "" {
		prog, err := compileSelector(env, config.ProviderSelector, celgo.StringType, "provider_selector")
		if err != nil {
			return nil, err
		}
		s.providerExpr = prog
	}

	if config.CacheBypass != "" {
		prog, err := compileSelector(env, config.CacheBypass, celgo.BoolType, "cache_bypass")
		if err != nil {
			return nil, err
		}
		s.cacheExpr = prog
	}

	if config.DynamicRPM != "" {
		prog, err := compileSelector(env, config.DynamicRPM, celgo.IntType, "dynamic_rpm")
		if err != nil {
			return nil, err
		}
		s.rpmExpr = prog
	}

	return s, nil
}

// compileSelector compiles a single CEL expression and verifies its output type.
func compileSelector(env *celgo.Env, expr string, expectedType *celgo.Type, name string) (celgo.Program, error) {
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, errors.New("cel_selector: " + name + " compile error: " + iss.Err().Error())
	}
	if ast == nil {
		return nil, errors.New("cel_selector: " + name + " produced nil AST")
	}
	if ast.OutputType() != expectedType {
		return nil, errors.New("cel_selector: " + name + " must return " + expectedType.String() + ", got " + ast.OutputType().String())
	}
	prog, err := env.Program(ast)
	if err != nil {
		return nil, errors.New("cel_selector: " + name + " program error: " + err.Error())
	}
	return prog, nil
}

// SelectModel evaluates the model_selector expression and returns the model name override.
// Returns empty string if no model_selector is configured or on fail-open error.
func (s *CELSelector) SelectModel(ctx *AIRequestCELContext) (string, error) {
	if s == nil || s.modelExpr == nil {
		return "", nil
	}
	out, _, err := s.modelExpr.Eval(ctx.activation())
	if err != nil {
		if s.failOpen {
			slog.Warn("cel_selector: model_selector eval error, using default", "error", err)
			return "", nil
		}
		return "", errors.New("cel_selector: model_selector eval error: " + err.Error())
	}
	result, ok := out.Value().(string)
	if !ok {
		if s.failOpen {
			slog.Warn("cel_selector: model_selector returned non-string", "type", out.Type())
			return "", nil
		}
		return "", errors.New("cel_selector: model_selector returned non-string: " + string(out.Type().TypeName()))
	}
	return result, nil
}

// SelectProvider evaluates the provider_selector expression and returns the preferred provider name.
// Returns empty string if no provider_selector is configured, on fail-open error, or when the
// expression explicitly returns empty (meaning normal routing should proceed).
func (s *CELSelector) SelectProvider(ctx *AIRequestCELContext) (string, error) {
	if s == nil || s.providerExpr == nil {
		return "", nil
	}
	out, _, err := s.providerExpr.Eval(ctx.activation())
	if err != nil {
		if s.failOpen {
			slog.Warn("cel_selector: provider_selector eval error, using default", "error", err)
			return "", nil
		}
		return "", errors.New("cel_selector: provider_selector eval error: " + err.Error())
	}
	result, ok := out.Value().(string)
	if !ok {
		if s.failOpen {
			slog.Warn("cel_selector: provider_selector returned non-string", "type", out.Type())
			return "", nil
		}
		return "", errors.New("cel_selector: provider_selector returned non-string: " + string(out.Type().TypeName()))
	}
	return result, nil
}

// ShouldBypassCache evaluates the cache_bypass expression and returns true when the cache should be skipped.
// Returns false if no cache_bypass is configured or on fail-open error.
func (s *CELSelector) ShouldBypassCache(ctx *AIRequestCELContext) (bool, error) {
	if s == nil || s.cacheExpr == nil {
		return false, nil
	}
	out, _, err := s.cacheExpr.Eval(ctx.activation())
	if err != nil {
		if s.failOpen {
			slog.Warn("cel_selector: cache_bypass eval error, using default", "error", err)
			return false, nil
		}
		return false, errors.New("cel_selector: cache_bypass eval error: " + err.Error())
	}
	result, ok := out.Value().(bool)
	if !ok {
		if s.failOpen {
			slog.Warn("cel_selector: cache_bypass returned non-bool", "type", out.Type())
			return false, nil
		}
		return false, errors.New("cel_selector: cache_bypass returned non-bool: " + string(out.Type().TypeName()))
	}
	return result, nil
}

// DynamicRPM evaluates the dynamic_rpm expression and returns the RPM override.
// Returns 0 if no dynamic_rpm is configured or on fail-open error.
func (s *CELSelector) DynamicRPM(ctx *AIRequestCELContext) (int, error) {
	if s == nil || s.rpmExpr == nil {
		return 0, nil
	}
	out, _, err := s.rpmExpr.Eval(ctx.activation())
	if err != nil {
		if s.failOpen {
			slog.Warn("cel_selector: dynamic_rpm eval error, using default", "error", err)
			return 0, nil
		}
		return 0, errors.New("cel_selector: dynamic_rpm eval error: " + err.Error())
	}
	result, ok := out.Value().(int64)
	if !ok {
		if s.failOpen {
			slog.Warn("cel_selector: dynamic_rpm returned non-int", "type", out.Type())
			return 0, nil
		}
		return 0, errors.New("cel_selector: dynamic_rpm returned non-int: " + string(out.Type().TypeName()))
	}
	return int(result), nil
}

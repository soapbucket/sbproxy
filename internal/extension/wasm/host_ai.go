package wasm

import (
	"context"
	"sync"

	json "github.com/goccy/go-json"
)

// AIHostContext holds AI-specific request state that WASM host functions read from and write to.
// It is stored in the context and accessed by AI host functions during module execution.
type AIHostContext struct {
	// Read-only fields (set before WASM execution).
	Model           string   `json:"model"`
	Messages        []byte   `json:"messages"`         // JSON-encoded messages
	TokenCount      int64    `json:"token_count"`
	PrincipalID     string   `json:"principal_id"`
	PrincipalGroups []string `json:"principal_groups"`
	BudgetRemaining int64    `json:"budget_remaining"`

	// Writable fields (set by WASM module via host functions).
	ModifiedModel    string `json:"modified_model,omitempty"`
	ModifiedMessages []byte `json:"modified_messages,omitempty"`
	GuardrailAction  int32  `json:"guardrail_action"` // 0=pass, 1=block, 2=flag, 3=redact

	mu sync.RWMutex
}

// NewAIHostContext creates a new AIHostContext with the given initial state.
func NewAIHostContext(model string, messages []byte, tokenCount int64, principalID string, principalGroups []string, budgetRemaining int64) *AIHostContext {
	return &AIHostContext{
		Model:           model,
		Messages:        messages,
		TokenCount:      tokenCount,
		PrincipalID:     principalID,
		PrincipalGroups: principalGroups,
		BudgetRemaining: budgetRemaining,
	}
}

// GetModel returns the current model name.
func (ac *AIHostContext) GetModel() string {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	return ac.Model
}

// GetMessages returns the current messages JSON bytes.
func (ac *AIHostContext) GetMessages() []byte {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	return ac.Messages
}

// GetTokenCount returns the estimated token count.
func (ac *AIHostContext) GetTokenCount() int64 {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	return ac.TokenCount
}

// GetPrincipalID returns the principal ID.
func (ac *AIHostContext) GetPrincipalID() string {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	return ac.PrincipalID
}

// GetPrincipalGroups returns the principal groups as a JSON-encoded byte slice.
func (ac *AIHostContext) GetPrincipalGroups() []byte {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	data, err := json.Marshal(ac.PrincipalGroups)
	if err != nil {
		return []byte("[]")
	}
	return data
}

// GetBudgetRemaining returns the remaining token budget.
func (ac *AIHostContext) GetBudgetRemaining() int64 {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	return ac.BudgetRemaining
}

// SetModifiedModel sets the overridden model name.
func (ac *AIHostContext) SetModifiedModel(model string) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.ModifiedModel = model
}

// GetModifiedModel returns the overridden model name.
func (ac *AIHostContext) GetModifiedModel() string {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	return ac.ModifiedModel
}

// SetModifiedMessages sets the modified messages.
func (ac *AIHostContext) SetModifiedMessages(messages []byte) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.ModifiedMessages = make([]byte, len(messages))
	copy(ac.ModifiedMessages, messages)
}

// GetModifiedMessages returns the modified messages.
func (ac *AIHostContext) GetModifiedMessages() []byte {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	return ac.ModifiedMessages
}

// SetGuardrailAction sets the guardrail action (0=pass, 1=block, 2=flag, 3=redact).
func (ac *AIHostContext) SetGuardrailAction(action int32) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.GuardrailAction = action
}

// GetGuardrailAction returns the guardrail action.
func (ac *AIHostContext) GetGuardrailAction() int32 {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	return ac.GuardrailAction
}

// aiContextKey is an unexported type for the AI context key.
type aiContextKey struct{}

// aiCtxKey is the context key for AIHostContext.
var aiCtxKey = aiContextKey{}

// WithAIHostContext returns a new context with the given AIHostContext.
func WithAIHostContext(ctx context.Context, ac *AIHostContext) context.Context {
	return context.WithValue(ctx, aiCtxKey, ac)
}

// AIHostContextFromContext extracts the AIHostContext from a context.
func AIHostContextFromContext(ctx context.Context) *AIHostContext {
	ac, _ := ctx.Value(aiCtxKey).(*AIHostContext)
	return ac
}

// RegisterAIHostFunctions registers all AI-specific host functions on the given module builder.
// These functions allow WASM guest modules to interact with AI request/response data.
func RegisterAIHostFunctions(builder HostModuleBuilder) HostModuleBuilder {
	return builder.
		// get_ai_model(ptr, len) -> (ptr, len)
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetAIModel), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{ValueTypeI32, ValueTypeI32}).
		WithParameterNames("ptr", "len").
		Export("sb_get_ai_model").
		// get_ai_messages(ptr, len) -> (ptr, len)
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetAIMessages), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{ValueTypeI32, ValueTypeI32}).
		WithParameterNames("ptr", "len").
		Export("sb_get_ai_messages").
		// get_ai_token_count() -> i64
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetAITokenCount), []ValueType{}, []ValueType{ValueTypeI64}).
		Export("sb_get_ai_token_count").
		// get_principal_id(ptr, len) -> (ptr, len)
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetPrincipalID), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{ValueTypeI32, ValueTypeI32}).
		WithParameterNames("ptr", "len").
		Export("sb_get_principal_id").
		// get_principal_groups(ptr, len) -> (ptr, len)
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetPrincipalGroups), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{ValueTypeI32, ValueTypeI32}).
		WithParameterNames("ptr", "len").
		Export("sb_get_principal_groups").
		// get_budget_remaining() -> i64
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostGetBudgetRemaining), []ValueType{}, []ValueType{ValueTypeI64}).
		Export("sb_get_budget_remaining").
		// set_ai_model(ptr, len)
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostSetAIModel), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{}).
		WithParameterNames("ptr", "len").
		Export("sb_set_ai_model").
		// set_ai_messages(ptr, len)
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostSetAIMessages), []ValueType{ValueTypeI32, ValueTypeI32}, []ValueType{}).
		WithParameterNames("ptr", "len").
		Export("sb_set_ai_messages").
		// set_guardrail_action(action i32)
		NewFunctionBuilder().
		WithGoModuleFunction(GoModuleFunc(hostSetGuardrailAction), []ValueType{ValueTypeI32}, []ValueType{}).
		WithParameterNames("action").
		Export("sb_set_guardrail_action")
}

// hostGetAIModel implements sb_get_ai_model(ptr, len) -> (ptr, len)
func hostGetAIModel(ctx context.Context, mod WasmModule, stack []uint64) {
	ac := AIHostContextFromContext(ctx)
	if ac == nil {
		stack[0] = 0
		stack[1] = 0
		return
	}

	model := ac.GetModel()
	if model == "" {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, []byte(model))
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostGetAIMessages implements sb_get_ai_messages(ptr, len) -> (ptr, len)
func hostGetAIMessages(ctx context.Context, mod WasmModule, stack []uint64) {
	ac := AIHostContextFromContext(ctx)
	if ac == nil {
		stack[0] = 0
		stack[1] = 0
		return
	}

	messages := ac.GetMessages()
	if len(messages) == 0 {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, messages)
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostGetAITokenCount implements sb_get_ai_token_count() -> i64
func hostGetAITokenCount(ctx context.Context, _ WasmModule, stack []uint64) {
	ac := AIHostContextFromContext(ctx)
	if ac == nil {
		stack[0] = 0
		return
	}

	stack[0] = uint64(ac.GetTokenCount())
}

// hostGetPrincipalID implements sb_get_principal_id(ptr, len) -> (ptr, len)
func hostGetPrincipalID(ctx context.Context, mod WasmModule, stack []uint64) {
	ac := AIHostContextFromContext(ctx)
	if ac == nil {
		stack[0] = 0
		stack[1] = 0
		return
	}

	pid := ac.GetPrincipalID()
	if pid == "" {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, []byte(pid))
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostGetPrincipalGroups implements sb_get_principal_groups(ptr, len) -> (ptr, len)
func hostGetPrincipalGroups(ctx context.Context, mod WasmModule, stack []uint64) {
	ac := AIHostContextFromContext(ctx)
	if ac == nil {
		stack[0] = 0
		stack[1] = 0
		return
	}

	groups := ac.GetPrincipalGroups()
	if len(groups) == 0 {
		stack[0] = 0
		stack[1] = 0
		return
	}

	ptr, length := writeToGuest(ctx, mod, groups)
	stack[0] = uint64(ptr)
	stack[1] = uint64(length)
}

// hostGetBudgetRemaining implements sb_get_budget_remaining() -> i64
func hostGetBudgetRemaining(ctx context.Context, _ WasmModule, stack []uint64) {
	ac := AIHostContextFromContext(ctx)
	if ac == nil {
		stack[0] = 0
		return
	}

	stack[0] = uint64(ac.GetBudgetRemaining())
}

// hostSetAIModel implements sb_set_ai_model(ptr, len)
func hostSetAIModel(ctx context.Context, mod WasmModule, stack []uint64) {
	ptr := uint32(stack[0])
	length := uint32(stack[1])

	ac := AIHostContextFromContext(ctx)
	if ac == nil {
		return
	}

	model, ok := readString(mod, ptr, length)
	if !ok {
		return
	}

	ac.SetModifiedModel(model)
}

// hostSetAIMessages implements sb_set_ai_messages(ptr, len)
func hostSetAIMessages(ctx context.Context, mod WasmModule, stack []uint64) {
	ptr := uint32(stack[0])
	length := uint32(stack[1])

	ac := AIHostContextFromContext(ctx)
	if ac == nil {
		return
	}

	data, ok := mod.Memory().Read(ptr, length)
	if !ok {
		return
	}

	// Copy to avoid holding reference to WASM memory.
	ac.SetModifiedMessages(data)
}

// hostSetGuardrailAction implements sb_set_guardrail_action(action i32)
func hostSetGuardrailAction(ctx context.Context, _ WasmModule, stack []uint64) {
	action := int32(stack[0])

	ac := AIHostContextFromContext(ctx)
	if ac == nil {
		return
	}

	// Clamp to valid range [0, 3].
	if action < 0 {
		action = 0
	}
	if action > 3 {
		action = 3
	}

	ac.SetGuardrailAction(action)
}

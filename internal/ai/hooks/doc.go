// Package hooks provides CEL selectors, Lua hooks, and CEL guardrails
// for AI request processing in the sbproxy AI gateway.
//
// # CEL Selectors
//
// CEL selectors (cel_selectors.go) evaluate Google CEL expressions against
// per-request context to make dynamic routing decisions. There are four
// selector types: model_selector (returns a model name override),
// provider_selector (returns a preferred provider), cache_bypass (returns
// a bool to skip the semantic cache), and dynamic_rpm (returns an int RPM
// override). Expressions are compiled once at config load time and evaluated
// per-request. The CEL context includes request (model, messages, temperature,
// max_tokens, tools, stream), headers, key (virtual key metadata), workspace,
// and timestamp (hour, minute, day_of_week, date).
//
// # Lua Hooks
//
// Lua hooks (lua_hooks.go) execute user-supplied Lua scripts to modify AI
// requests and responses. on_request hooks run before the request is sent
// to the provider, and on_response hooks run after the response is received.
// Scripts execute in a sandboxed Lua VM with resource limits (execution
// timeout, max messages, max request bytes). Streaming mode controls whether
// on_response runs for streaming responses: "skip" (default) disables it,
// while "buffer" and "chunk" are reserved for future use.
//
// # CEL Guardrails
//
// CEL guardrails (cel_guardrails.go) evaluate safety rules against AI
// requests and responses. Each guardrail has a phase (input or output),
// a CEL condition that returns a bool, and an action (block or flag).
// Input guardrails run before the provider call and can block harmful
// prompts. Output guardrails run after the provider call and can block
// or flag problematic responses. Block actions reject the request
// immediately, while flag actions record the violation for audit without
// stopping the request.
package hooks

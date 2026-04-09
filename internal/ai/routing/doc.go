// Package routing provides context window validation, automatic fallback,
// and parameter management for AI request routing in the sbproxy AI gateway.
//
// # Context Window Validation
//
// [ContextWindowValidator] checks whether a request's estimated token count
// fits within the target model's context window before the provider call.
// A configurable safety margin (default 5%) prevents edge-case overflows.
// Token estimation uses a ~4 chars/token heuristic when tiktoken is
// unavailable.
//
// # Context Fallback
//
// [ContextFallbackMap] finds a model with a larger context window when
// the current model cannot fit the request. It checks explicit user-configured
// mappings first, then auto-generates candidates from the same provider
// in the registry, picking the smallest sufficient window to avoid
// unnecessary cost escalation.
//
// # Parameter Dropping
//
// [ParamDropper] removes unsupported parameters from requests based on
// model capabilities (vision, tool calling, structured output, reasoning).
// Dropping unsupported parameters is better than erroring, because it
// allows cross-provider compatibility without requiring callers to know
// each provider's exact feature set.
package routing

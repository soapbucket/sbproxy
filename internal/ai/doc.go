// Package ai implements the AI gateway handler for LLM provider routing.
//
// It provides a unified endpoint that normalizes requests across OpenAI,
// Anthropic, and other providers, with support for streaming, fallback
// chains, cost tracking, budget enforcement, and guardrails evaluation.
package ai

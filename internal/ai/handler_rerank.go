// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

// handleRerank is defined in handler_modalities.go. This file exists as a
// documented entry point for the /v1/rerank endpoint.
//
// The endpoint accepts POST requests with a RerankRequest body containing:
//   - model: the reranking model to use (required)
//   - query: the query string to rank documents against (required)
//   - documents: array of document strings to rerank (required)
//   - top_n: optional limit on returned results
//   - return_documents: whether to include document text in response
//
// The handler validates the request, checks budget limits, routes to the
// appropriate provider (Cohere native format, Jina, or generic), translates
// the request/response format, and returns a RerankResponse with results
// sorted by relevance_score.
//
// Route: POST /v1/rerank
// Provider support: Cohere (native), Jina, generic passthrough

//! End-to-end coverage for AI gateway SSE streaming.
//!
//! `examples/16-ai-streaming/sb.yml` documents the contract: a
//! `stream: true` request to `/v1/chat/completions` yields
//! `text/event-stream` chunks forwarded from the upstream provider
//! verbatim. The OSS [`MockUpstream`] in `sbproxy-e2e/src/lib.rs`
//! returns one canned JSON body per request and closes the
//! connection. It cannot drip-feed multiple `data:` SSE chunks, so
//! a faithful streaming test would need a chunked-aware mock.
//!
//! TODO: when a chunked-encoded mock provider lands in
//! `sbproxy-e2e`, the placeholders below should:
//!   1. Spin up an upstream that emits `text/event-stream` plus
//!      three `data: { ... }` chunks separated by short delays.
//!   2. Configure an `ai_proxy` origin pointing `base_url` at the
//!      mock provider via `provider_type: openai`.
//!   3. POST `/v1/chat/completions` with `stream: true` and verify
//!      the proxy forwards each chunk to the client without
//!      reassembling them into a single body.

#[test]
#[ignore = "needs a chunked-encoding mock provider on sbproxy-e2e to assert SSE pass-through"]
fn sse_chunks_pass_through_in_order() {
    // Placeholder. See module docs for the missing harness piece.
}

#[test]
#[ignore = "needs a chunked-encoding mock provider on sbproxy-e2e to assert SSE pass-through"]
fn streaming_response_uses_event_stream_content_type() {
    // Placeholder. See module docs for the missing harness piece.
}

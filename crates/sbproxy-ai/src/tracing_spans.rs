//! AI-specific tracing span helpers.
//!
//! Provides thin wrappers around `tracing::info_span!` for the spans
//! that are most useful when profiling the AI gateway pipeline.
//! Callers enter the returned span with `.entered()` or pass it to
//! `Instrument::instrument`.
//!
//! # Field naming convention
//!
//! Field names follow the **OpenTelemetry GenAI** semantic conventions
//! (`gen_ai.*`) as defined in:
//!
//! - <https://opentelemetry.io/docs/specs/semconv/gen-ai/>
//!
//! Where appropriate they also emit **OpenInference** (`llm.*`)
//! fields so dashboards built for Arize Phoenix, Langfuse, or
//! Honeycomb pick the data up without manual remapping:
//!
//! - <https://github.com/Arize-ai/openinference/blob/main/spec/semantic_conventions.md>
//!
//! Stable field names used by this module:
//!
//! | Concept                  | OTel GenAI                          | OpenInference                  |
//! |--------------------------|-------------------------------------|--------------------------------|
//! | Provider label           | `gen_ai.system`                     | `llm.provider`                 |
//! | Requested model          | `gen_ai.request.model`              | `llm.model_name`               |
//! | Response model           | `gen_ai.response.model`             | n/a                            |
//! | Operation                | `gen_ai.operation.name`             | n/a                            |
//! | Response identifier      | `gen_ai.response.id`                | n/a                            |
//! | Input tokens             | `gen_ai.usage.input_tokens`         | `llm.token_count.prompt`       |
//! | Output tokens            | `gen_ai.usage.output_tokens`        | `llm.token_count.completion`   |
//! | Total tokens             | n/a                                 | `llm.token_count.total`        |
//! | Finish reasons (joined)  | `gen_ai.response.finish_reasons`    | n/a                            |
//! | Temperature              | `gen_ai.request.temperature`        | n/a                            |
//! | Max tokens               | `gen_ai.request.max_tokens`         | n/a                            |
//! | Top-p                    | `gen_ai.request.top_p`              | n/a                            |
//!
//! sbproxy-internal context (routing surface, guardrail category)
//! lives under the `sbproxy.ai.*` namespace so it does not clash with
//! upstream conventions.
//!
//! ## Backwards compatibility
//!
//! These helpers replaced an earlier ad-hoc field naming
//! (`surface`, `method`, `provider`, `model`, `category`). The old
//! names had no external consumers inside this workspace, so they
//! were renamed without aliasing. Anything outside this repo that
//! parsed those raw field names must move to the conventions above.

use tracing::{field::Empty, Span};

/// Operation name recorded on the top-level AI request span when no
/// more specific operation has been classified yet. Mirrors the value
/// the OpenTelemetry GenAI conventions recommend for chat completion
/// style endpoints.
pub const OP_CHAT: &str = "chat";

/// Operation name for embedding requests.
pub const OP_EMBEDDINGS: &str = "embeddings";

/// Operation name for image generation requests.
pub const OP_IMAGE_GENERATION: &str = "image_generation";

/// Operation name for audio (transcription, translation, TTS) requests.
pub const OP_AUDIO: &str = "audio";

/// Create the top-level span for an AI request.
///
/// Opened at the entry of `handle_ai_proxy`. Records:
///
/// - `gen_ai.operation.name` defaulted to `surface` so traces are
///   pre-bucketed by the classified surface (chat_completions,
///   embeddings, image_generation, audio, assistants, etc.). The
///   field is also emitted as `sbproxy.ai.surface` for any internal
///   tooling that prefers the original label.
/// - `http.request.method` mirrors the OpenTelemetry HTTP semantic
///   convention for HTTP method.
/// - Empty placeholders for `sbproxy.tenant_id`, `gen_ai.system`,
///   `gen_ai.request.model`, `gen_ai.response.model`,
///   `gen_ai.response.id`, `gen_ai.usage.input_tokens`,
///   `gen_ai.usage.output_tokens`, and `gen_ai.response.finish_reasons`
///   so downstream code can fill them in once the routing and upstream
///   call complete (a `tracing::field::Empty` field becomes a settable
///   slot on the live span). The tenant slot is populated from
///   `RequestContext.tenant_id` at dispatch entry (WOR-1098).
pub fn ai_request_span(surface: &str, method: &str) -> Span {
    tracing::info_span!(
        "ai.request",
        "gen_ai.operation.name" = surface,
        "sbproxy.ai.surface" = surface,
        "http.request.method" = method,
        // WOR-1098: tenant attribution. Left Empty here and filled in
        // by the dispatch path from `RequestContext.tenant_id` once the
        // origin match has resolved the tenant, so exported request
        // spans can be filtered by tenant downstream without parsing
        // the event payload.
        "sbproxy.tenant_id" = Empty,
        "gen_ai.system" = Empty,
        "gen_ai.request.model" = Empty,
        "gen_ai.response.model" = Empty,
        "gen_ai.response.id" = Empty,
        "gen_ai.usage.input_tokens" = Empty,
        "gen_ai.usage.output_tokens" = Empty,
        // WOR-1084 capture completeness: per-dimension token
        // counts that the Capture layer of the Token-to-Value
        // Ledger expects. Zero on providers that do not report
        // them; downstream callers record the populated split via
        // `Span::record` from the usage parser's snapshot.
        "gen_ai.usage.cache_read_tokens" = Empty,
        "gen_ai.usage.cache_write_tokens" = Empty,
        "gen_ai.usage.reasoning_tokens" = Empty,
        // WOR-1084: pricing-catalog revision used to derive USD
        // cost from the token counts. A re-price against a newer
        // catalog reads this field to re-run the math against the
        // original token snapshot; without it, the spend record
        // is not reproducible past a pricing-table edit.
        "sbproxy.ai.pricing_version" = Empty,
        // WOR-1229: derived USD cost for the request, so trace backends
        // (Phoenix, Langfuse, Tempo) show spend per generation alongside
        // tokens. Recorded at the billing choke point via
        // `record_cost_usd`. Both the OpenInference and gen_ai keys are
        // stamped so either backend vocabulary renders it.
        "gen_ai.usage.cost" = Empty,
        "llm.usage.total_cost" = Empty,
        "gen_ai.response.finish_reasons" = Empty,
        "llm.provider" = Empty,
        "llm.model_name" = Empty,
        "llm.token_count.prompt" = Empty,
        "llm.token_count.completion" = Empty,
        "llm.token_count.total" = Empty,
    )
}

/// Create a span for provider selection.
///
/// Records the provider label as `gen_ai.system` and the chosen
/// model as `gen_ai.request.model`, mirroring the OpenTelemetry
/// GenAI conventions. The same values are also emitted as
/// `llm.provider` / `llm.model_name` for OpenInference consumers.
pub fn provider_selection_span(provider: &str, model: &str) -> Span {
    tracing::info_span!(
        "ai.provider_selection",
        "gen_ai.system" = provider,
        "gen_ai.request.model" = model,
        "llm.provider" = provider,
        "llm.model_name" = model,
    )
}

/// Create a span for guardrail evaluation.
///
/// `category` identifies which guardrail rule set is being
/// evaluated (for example `"content_policy"` or `"pii_detection"`).
/// Recorded as `sbproxy.ai.guardrail.category` because the GenAI
/// and OpenInference conventions do not currently cover guardrail
/// shape; using the sbproxy namespace keeps the field
/// unambiguous.
pub fn guardrail_eval_span(category: &str) -> Span {
    tracing::info_span!(
        "ai.guardrail_eval",
        "sbproxy.ai.guardrail.category" = category,
    )
}

/// Create a span for streaming accumulation.
///
/// Covers the window from the first SSE chunk received until the
/// stream is closed. Records `gen_ai.system`, `gen_ai.request.model`,
/// and a default `gen_ai.operation.name = "chat"` (the streaming
/// pipeline is currently only used for chat-style completions; if a
/// future caller streams embeddings or audio the operation name slot
/// can be overwritten with `Span::record`). Leaves
/// `gen_ai.response.finish_reasons`, `gen_ai.usage.*`, and
/// `gen_ai.response.id` as empty placeholders so the accumulator can
/// fill them in once the final chunk arrives.
pub fn streaming_span(provider: &str, model: &str) -> Span {
    tracing::info_span!(
        "ai.streaming",
        "gen_ai.system" = provider,
        "gen_ai.request.model" = model,
        "gen_ai.operation.name" = OP_CHAT,
        "llm.provider" = provider,
        "llm.model_name" = model,
        "gen_ai.response.id" = Empty,
        "gen_ai.response.model" = Empty,
        "gen_ai.usage.input_tokens" = Empty,
        "gen_ai.usage.output_tokens" = Empty,
        "gen_ai.response.finish_reasons" = Empty,
        "llm.token_count.prompt" = Empty,
        "llm.token_count.completion" = Empty,
        "llm.token_count.total" = Empty,
    )
}

/// Stamp token usage onto the currently active AI span.
///
/// Sets both the OpenTelemetry GenAI fields
/// (`gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`) and
/// the OpenInference equivalents (`llm.token_count.prompt`,
/// `llm.token_count.completion`, `llm.token_count.total`) so
/// dashboards built for either convention pick the data up.
///
/// Call this from the response path once token counts are known
/// (either from the provider's `usage` object or estimated from the
/// request and response bodies). The values are recorded on the
/// active span; the caller is responsible for entering an
/// appropriate span first (typically the one returned by
/// [`ai_request_span`] or [`streaming_span`]).
pub fn record_token_usage(span: &Span, input_tokens: u64, output_tokens: u64) {
    span.record("gen_ai.usage.input_tokens", input_tokens);
    span.record("gen_ai.usage.output_tokens", output_tokens);
    span.record("llm.token_count.prompt", input_tokens);
    span.record("llm.token_count.completion", output_tokens);
    span.record(
        "llm.token_count.total",
        input_tokens.saturating_add(output_tokens),
    );
}

/// WOR-1084: stamp the full token-kind split onto an active AI
/// span. Sibling of [`record_token_usage`] for callers that have
/// the per-dimension counts from a [`crate::usage_parser::UsageTokens`]
/// snapshot.
///
/// Sets the OTel GenAI cache + reasoning attributes plus the
/// updated total (the `llm.token_count.total` field includes
/// every dimension so a downstream dashboard sums tokens against
/// a single field).
pub fn record_token_usage_split(
    span: &Span,
    input_tokens: u64,
    output_tokens: u64,
    cache_read_tokens: u64,
    cache_write_tokens: u64,
    reasoning_tokens: u64,
) {
    span.record("gen_ai.usage.input_tokens", input_tokens);
    span.record("gen_ai.usage.output_tokens", output_tokens);
    span.record("gen_ai.usage.cache_read_tokens", cache_read_tokens);
    span.record("gen_ai.usage.cache_write_tokens", cache_write_tokens);
    span.record("gen_ai.usage.reasoning_tokens", reasoning_tokens);
    span.record("llm.token_count.prompt", input_tokens);
    span.record("llm.token_count.completion", output_tokens);
    let total = input_tokens
        .saturating_add(output_tokens)
        .saturating_add(cache_read_tokens)
        .saturating_add(cache_write_tokens)
        .saturating_add(reasoning_tokens);
    span.record("llm.token_count.total", total);
}

/// WOR-1084: stamp the pricing-catalog revision the gateway used
/// to derive USD cost from the token counts. Without this stamp,
/// a re-price against a newer catalog cannot reproduce the
/// historical cost from the original token snapshot.
///
/// `version` is the pricing-catalog identifier: today the
/// catalog's file content hash; future revisions may switch to a
/// monotonic version tag.
pub fn record_pricing_version(span: &Span, version: &str) {
    span.record("sbproxy.ai.pricing_version", version);
}

/// Stamp the derived USD cost of the request onto an AI span (WOR-1229).
///
/// Records `gen_ai.usage.cost` (gen_ai vocabulary) and
/// `llm.usage.total_cost` (OpenInference vocabulary) so both trace-backend
/// conventions render spend per generation. `cost_usd` is the same value
/// the FinOps cost metric uses, derived from the token counts and the
/// pricing catalog stamped via [`record_pricing_version`].
pub fn record_cost_usd(span: &Span, cost_usd: f64) {
    span.record("gen_ai.usage.cost", cost_usd);
    span.record("llm.usage.total_cost", cost_usd);
}

/// Stamp the response model and identifier onto an AI span.
///
/// `model` becomes `gen_ai.response.model`; `response_id` becomes
/// `gen_ai.response.id`. Either may be empty if the provider did
/// not return it; pass an empty string in that case rather than
/// skipping the call so the field remains a stable slot for
/// downstream consumers.
pub fn record_response_identity(span: &Span, model: &str, response_id: &str) {
    span.record("gen_ai.response.model", model);
    span.record("gen_ai.response.id", response_id);
}

/// Stamp finish reasons onto an AI span.
///
/// The OpenTelemetry GenAI conventions define
/// `gen_ai.response.finish_reasons` as an array of strings. Until
/// the `tracing` crate gains first-class array fields the canonical
/// rendering is a comma-separated list; backends that read structured
/// trace data (Langfuse, Phoenix, Honeycomb) all accept the joined
/// form as well as the array form.
pub fn record_finish_reasons(span: &Span, reasons: &[&str]) {
    let joined = reasons.join(",");
    span.record("gen_ai.response.finish_reasons", joined.as_str());
}

/// Stamp request-side sampling parameters onto an AI span.
///
/// Pass `None` for any parameter the caller did not configure; the
/// corresponding field is left untouched on the span.
pub fn record_request_params(
    span: &Span,
    temperature: Option<f64>,
    max_tokens: Option<u64>,
    top_p: Option<f64>,
) {
    if let Some(t) = temperature {
        span.record("gen_ai.request.temperature", t);
    }
    if let Some(m) = max_tokens {
        span.record("gen_ai.request.max_tokens", m);
    }
    if let Some(p) = top_p {
        span.record("gen_ai.request.top_p", p);
    }
}

/// Emit an OpenInference input-message event on the current span.
///
/// OpenInference encodes per-message data as numerically indexed
/// fields (`llm.input_messages.0.message.role`,
/// `llm.input_messages.0.message.content`, ...). Because the
/// `tracing` macro family requires statically known field names,
/// these are emitted as a structured `info!` event rather than as
/// span fields. Trace backends collapse events back onto the parent
/// span when they render the trace, so the visual result is the
/// same as if the fields had been attached directly.
///
/// `index` is the zero-based message position. `role` is the
/// conversation role (`system`, `user`, `assistant`, `tool`).
/// `content` is the textual message body; callers are responsible
/// for redaction before logging if their compliance posture
/// requires it.
pub fn record_input_message(index: usize, role: &str, content: &str) {
    tracing::info!(
        "llm.input_messages.index" = index,
        "llm.input_messages.message.role" = role,
        "llm.input_messages.message.content" = content,
        "ai.input_message"
    );
}

/// Emit an OpenInference output-message event on the current span.
///
/// Mirror of [`record_input_message`] for the response side.
pub fn record_output_message(index: usize, role: &str, content: &str) {
    tracing::info!(
        "llm.output_messages.index" = index,
        "llm.output_messages.message.role" = role,
        "llm.output_messages.message.content" = content,
        "ai.output_message"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Subscriber};
    use tracing_subscriber::layer::{Context, Layer};
    use tracing_subscriber::registry::LookupSpan;

    /// Captured span: name plus a flat field name to string-value map.
    /// Numeric values are stringified for assertion convenience.
    #[derive(Debug, Default, Clone)]
    struct CapturedSpan {
        name: String,
        fields: HashMap<String, String>,
    }

    /// Captured event: the field name to value map.
    #[derive(Debug, Default, Clone)]
    struct CapturedEvent {
        fields: HashMap<String, String>,
    }

    #[derive(Default)]
    struct CaptureState {
        spans: HashMap<u64, CapturedSpan>,
        events: Vec<CapturedEvent>,
    }

    #[derive(Clone, Default)]
    struct CaptureLayer {
        state: Arc<Mutex<CaptureState>>,
    }

    struct MapVisitor<'a> {
        out: &'a mut HashMap<String, String>,
    }

    impl<'a> Visit for MapVisitor<'a> {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.out
                .insert(field.name().to_string(), format!("{:?}", value));
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            self.out.insert(field.name().to_string(), value.to_string());
        }

        fn record_i64(&mut self, field: &Field, value: i64) {
            self.out.insert(field.name().to_string(), value.to_string());
        }

        fn record_u64(&mut self, field: &Field, value: u64) {
            self.out.insert(field.name().to_string(), value.to_string());
        }

        fn record_f64(&mut self, field: &Field, value: f64) {
            self.out.insert(field.name().to_string(), value.to_string());
        }

        fn record_bool(&mut self, field: &Field, value: bool) {
            self.out.insert(field.name().to_string(), value.to_string());
        }
    }

    impl<S> Layer<S> for CaptureLayer
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, _ctx: Context<'_, S>) {
            let mut fields = HashMap::new();
            attrs.record(&mut MapVisitor { out: &mut fields });
            let span = CapturedSpan {
                name: attrs.metadata().name().to_string(),
                fields,
            };
            self.state
                .lock()
                .expect("capture state mutex poisoned")
                .spans
                .insert(id.into_u64(), span);
        }

        fn on_record(&self, id: &Id, values: &Record<'_>, _ctx: Context<'_, S>) {
            let mut guard = self.state.lock().expect("capture state mutex poisoned");
            if let Some(span) = guard.spans.get_mut(&id.into_u64()) {
                values.record(&mut MapVisitor {
                    out: &mut span.fields,
                });
            }
        }

        fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
            let mut fields = HashMap::new();
            event.record(&mut MapVisitor { out: &mut fields });
            self.state
                .lock()
                .expect("capture state mutex poisoned")
                .events
                .push(CapturedEvent { fields });
        }
    }

    /// Snapshot all captured spans.
    fn snapshot_spans(layer: &CaptureLayer) -> Vec<CapturedSpan> {
        layer
            .state
            .lock()
            .expect("capture state mutex poisoned")
            .spans
            .values()
            .cloned()
            .collect()
    }

    /// Snapshot all captured events.
    fn snapshot_events(layer: &CaptureLayer) -> Vec<CapturedEvent> {
        layer
            .state
            .lock()
            .expect("capture state mutex poisoned")
            .events
            .clone()
    }

    /// Find a span by its tracing name.
    fn find_span<'a>(spans: &'a [CapturedSpan], name: &str) -> &'a CapturedSpan {
        spans
            .iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("expected captured span named {name:?}"))
    }

    fn assert_field(span: &CapturedSpan, field: &str, expected: &str) {
        let actual = span
            .fields
            .get(field)
            .unwrap_or_else(|| panic!("span {:?} missing field {field:?}", span.name));
        assert_eq!(actual, expected, "field {field}");
    }

    #[test]
    fn ai_request_span_uses_genai_operation_and_http_method() {
        use tracing_subscriber::prelude::*;
        let layer = CaptureLayer::default();
        let subscriber = tracing_subscriber::registry().with(layer.clone());
        tracing::subscriber::with_default(subscriber, || {
            let _s = ai_request_span("chat_completions", "POST");
        });

        let spans = snapshot_spans(&layer);
        let span = find_span(&spans, "ai.request");
        assert_field(span, "gen_ai.operation.name", "chat_completions");
        assert_field(span, "sbproxy.ai.surface", "chat_completions");
        assert_field(span, "http.request.method", "POST");
    }

    #[test]
    fn ai_request_span_records_tenant_id() {
        // WOR-1098: the dispatch path stamps `sbproxy.tenant_id` from
        // `RequestContext.tenant_id` so exported request spans can be
        // filtered by tenant. The slot starts Empty and is filled via
        // `Span::record`, mirroring what `handle_ai_proxy` does.
        use tracing_subscriber::prelude::*;
        let layer = CaptureLayer::default();
        let subscriber = tracing_subscriber::registry().with(layer.clone());
        tracing::subscriber::with_default(subscriber, || {
            let span = ai_request_span("chat_completions", "POST");
            span.record("sbproxy.tenant_id", "acme");
        });

        let spans = snapshot_spans(&layer);
        let span = find_span(&spans, "ai.request");
        assert_field(span, "sbproxy.tenant_id", "acme");
    }

    #[test]
    fn chat_completion_span_records_system_model_and_token_usage() {
        use tracing_subscriber::prelude::*;
        let layer = CaptureLayer::default();
        let subscriber = tracing_subscriber::registry().with(layer.clone());
        tracing::subscriber::with_default(subscriber, || {
            let span = ai_request_span("chat_completions", "POST");
            let _entered = span.clone().entered();
            // Routing layer would normally do this once the provider
            // is resolved. We mimic the same calls here.
            span.record("gen_ai.system", "openai");
            span.record("gen_ai.request.model", "gpt-4o");
            span.record("llm.provider", "openai");
            span.record("llm.model_name", "gpt-4o");
            record_token_usage(&span, 17, 42);
        });

        let spans = snapshot_spans(&layer);
        let span = find_span(&spans, "ai.request");
        assert_field(span, "gen_ai.system", "openai");
        assert_field(span, "gen_ai.request.model", "gpt-4o");
        assert_field(span, "gen_ai.usage.input_tokens", "17");
        assert_field(span, "gen_ai.usage.output_tokens", "42");
        // OpenInference dual-emit.
        assert_field(span, "llm.provider", "openai");
        assert_field(span, "llm.model_name", "gpt-4o");
        assert_field(span, "llm.token_count.prompt", "17");
        assert_field(span, "llm.token_count.completion", "42");
        assert_field(span, "llm.token_count.total", "59");
    }

    /// WOR-1084: the cache + reasoning split lands on
    /// `gen_ai.usage.*` and the total includes every dimension.
    #[test]
    fn record_token_usage_split_stamps_all_dimensions() {
        use tracing_subscriber::prelude::*;
        let layer = CaptureLayer::default();
        let subscriber = tracing_subscriber::registry().with(layer.clone());
        tracing::subscriber::with_default(subscriber, || {
            let span = ai_request_span("chat", "POST");
            // input 100, output 50, cache_read 20, cache_write 5, reasoning 30
            record_token_usage_split(&span, 100, 50, 20, 5, 30);
            record_pricing_version(&span, "catalog-2026-06-01");
        });

        let spans = snapshot_spans(&layer);
        let span = find_span(&spans, "ai.request");
        assert_field(span, "gen_ai.usage.input_tokens", "100");
        assert_field(span, "gen_ai.usage.output_tokens", "50");
        assert_field(span, "gen_ai.usage.cache_read_tokens", "20");
        assert_field(span, "gen_ai.usage.cache_write_tokens", "5");
        assert_field(span, "gen_ai.usage.reasoning_tokens", "30");
        // Total is the sum of every dimension.
        assert_field(span, "llm.token_count.total", "205");
        assert_field(span, "sbproxy.ai.pricing_version", "catalog-2026-06-01");
    }

    /// WOR-1229: derived USD cost lands on both the gen_ai and
    /// OpenInference cost keys so either trace backend renders spend.
    #[test]
    fn record_cost_usd_stamps_both_vocabularies() {
        use tracing_subscriber::prelude::*;
        let layer = CaptureLayer::default();
        let subscriber = tracing_subscriber::registry().with(layer.clone());
        tracing::subscriber::with_default(subscriber, || {
            let span = ai_request_span("chat", "POST");
            record_cost_usd(&span, 0.001234);
        });
        let spans = snapshot_spans(&layer);
        let span = find_span(&spans, "ai.request");
        assert_field(span, "gen_ai.usage.cost", "0.001234");
        assert_field(span, "llm.usage.total_cost", "0.001234");
    }

    /// `UsageTokens::total()` (WOR-1084) sums every dimension,
    /// not just prompt + completion. Pinned so a downstream
    /// dashboard's "total tokens" math stays consistent.
    #[test]
    fn usage_tokens_total_includes_all_dimensions() {
        use crate::usage_parser::UsageTokens;
        let u = UsageTokens {
            prompt_tokens: 100,
            completion_tokens: 50,
            cache_read_tokens: 20,
            cache_write_tokens: 5,
            reasoning_tokens: 30,
        };
        assert_eq!(u.total(), 205);
    }

    #[test]
    fn provider_selection_span_dual_emits_genai_and_openinference() {
        use tracing_subscriber::prelude::*;
        let layer = CaptureLayer::default();
        let subscriber = tracing_subscriber::registry().with(layer.clone());
        tracing::subscriber::with_default(subscriber, || {
            let _s = provider_selection_span("anthropic", "claude-3-5-sonnet");
        });

        let spans = snapshot_spans(&layer);
        let span = find_span(&spans, "ai.provider_selection");
        assert_field(span, "gen_ai.system", "anthropic");
        assert_field(span, "gen_ai.request.model", "claude-3-5-sonnet");
        assert_field(span, "llm.provider", "anthropic");
        assert_field(span, "llm.model_name", "claude-3-5-sonnet");
    }

    #[test]
    fn guardrail_eval_span_uses_sbproxy_namespace() {
        use tracing_subscriber::prelude::*;
        let layer = CaptureLayer::default();
        let subscriber = tracing_subscriber::registry().with(layer.clone());
        tracing::subscriber::with_default(subscriber, || {
            let _s = guardrail_eval_span("content_policy");
        });

        let spans = snapshot_spans(&layer);
        let span = find_span(&spans, "ai.guardrail_eval");
        assert_field(span, "sbproxy.ai.guardrail.category", "content_policy");
    }

    #[test]
    fn streaming_span_records_operation_and_finish_reasons() {
        use tracing_subscriber::prelude::*;
        let layer = CaptureLayer::default();
        let subscriber = tracing_subscriber::registry().with(layer.clone());
        tracing::subscriber::with_default(subscriber, || {
            let span = streaming_span("openai", "gpt-4o-mini");
            let _entered = span.clone().entered();
            record_finish_reasons(&span, &["stop", "length"]);
            record_response_identity(&span, "gpt-4o-mini-2024-07-18", "chatcmpl-abc123");
        });

        let spans = snapshot_spans(&layer);
        let span = find_span(&spans, "ai.streaming");
        assert_field(span, "gen_ai.operation.name", OP_CHAT);
        assert_field(span, "gen_ai.system", "openai");
        assert_field(span, "gen_ai.request.model", "gpt-4o-mini");
        assert_field(span, "gen_ai.response.finish_reasons", "stop,length");
        assert_field(span, "gen_ai.response.model", "gpt-4o-mini-2024-07-18");
        assert_field(span, "gen_ai.response.id", "chatcmpl-abc123");
    }

    #[test]
    fn record_request_params_skips_none_values() {
        use tracing_subscriber::prelude::*;
        let layer = CaptureLayer::default();
        let subscriber = tracing_subscriber::registry().with(layer.clone());
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!(
                "ai.test_params",
                "gen_ai.request.temperature" = tracing::field::Empty,
                "gen_ai.request.max_tokens" = tracing::field::Empty,
                "gen_ai.request.top_p" = tracing::field::Empty,
            );
            record_request_params(&span, Some(0.7), Some(512), None);
        });

        let spans = snapshot_spans(&layer);
        let span = find_span(&spans, "ai.test_params");
        assert_field(span, "gen_ai.request.temperature", "0.7");
        assert_field(span, "gen_ai.request.max_tokens", "512");
        // top_p was None so the field stays at its placeholder; the
        // captured value will be the empty-field rendering, which the
        // tracing crate represents as "?". We only assert that no
        // numeric value sneaks in.
        let top_p = span.fields.get("gen_ai.request.top_p").map(String::as_str);
        assert!(
            matches!(top_p, None | Some("?")),
            "top_p should be unset, got {top_p:?}"
        );
    }

    #[test]
    fn input_and_output_messages_emit_openinference_events() {
        use tracing_subscriber::prelude::*;
        let layer = CaptureLayer::default();
        let subscriber = tracing_subscriber::registry().with(layer.clone());
        tracing::subscriber::with_default(subscriber, || {
            let span = ai_request_span("chat_completions", "POST");
            let _entered = span.entered();
            record_input_message(0, "system", "You are a helpful assistant.");
            record_input_message(1, "user", "Hello!");
            record_output_message(0, "assistant", "Hi there.");
        });

        let events = snapshot_events(&layer);
        assert!(
            events.iter().any(|e| e
                .fields
                .get("llm.input_messages.message.role")
                .map(String::as_str)
                == Some("system")
                && e.fields
                    .get("llm.input_messages.message.content")
                    .map(String::as_str)
                    == Some("You are a helpful assistant.")),
            "expected an input message event with role=system, got {events:?}"
        );
        assert!(
            events.iter().any(|e| e
                .fields
                .get("llm.input_messages.message.role")
                .map(String::as_str)
                == Some("user")
                && e.fields.get("llm.input_messages.index").map(String::as_str) == Some("1")),
            "expected an input message event with role=user index=1, got {events:?}"
        );
        assert!(
            events.iter().any(|e| e
                .fields
                .get("llm.output_messages.message.role")
                .map(String::as_str)
                == Some("assistant")
                && e.fields
                    .get("llm.output_messages.message.content")
                    .map(String::as_str)
                    == Some("Hi there.")),
            "expected an output message event with role=assistant, got {events:?}"
        );
    }

    #[test]
    fn spans_can_be_entered_without_subscriber() {
        // Sanity check: span construction does not depend on a
        // subscriber being installed. Mirrors the original test that
        // shipped with this module.
        let span = provider_selection_span("cohere", "command-r");
        let _guard = span.entered();
    }
}

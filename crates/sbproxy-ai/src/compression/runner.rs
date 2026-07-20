//! Sequential asynchronous compression execution.

use crate::compression::outcome::{
    FailureReason, LeverKind, LeverOutcome, LeverResult, RequestOutcome, SkipReason,
};
use crate::compression::CompressionBackend;
use crate::TokenCountPrecision;
use async_trait::async_trait;
use serde_json::Value;
use std::fmt;
use std::sync::Arc;
use std::time::Instant;

/// Request-shape controls that affect safe compression eligibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionRequestControls {
    /// The request uses the supported chat message-array shape.
    pub supported_chat: bool,
    /// A top-level tool declaration is present.
    pub has_tools: bool,
    /// A legacy top-level function declaration is present.
    pub has_functions: bool,
    /// A structured response format is present.
    pub has_response_format: bool,
    /// A top-level output schema is present.
    pub has_schema: bool,
}

impl CompressionRequestControls {
    /// Whether any top-level structured-output or tool control is present.
    pub const fn has_structured_top_level_fields(self) -> bool {
        self.has_tools || self.has_functions || self.has_response_format || self.has_schema
    }
}

impl Default for CompressionRequestControls {
    fn default() -> Self {
        Self {
            supported_chat: true,
            has_tools: false,
            has_functions: false,
            has_response_format: false,
            has_schema: false,
        }
    }
}

/// Immutable request data shared by every lever in one pipeline run.
#[derive(Clone, Copy)]
pub struct CompressionRequest<'a> {
    model: &'a str,
    tenant_id: Option<&'a str>,
    api_key_id: Option<&'a str>,
    origin: Option<&'a str>,
    session_id: Option<[u8; 16]>,
    controls: CompressionRequestControls,
    now_unix_ms: u64,
    writer_node: &'a str,
}

impl fmt::Debug for CompressionRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompressionRequest")
            .field("model", &self.model)
            .field("tenant_id", &self.tenant_id)
            .field("api_key_id", &self.api_key_id)
            .field("origin", &self.origin)
            .field("session_id", &self.session_id.map(|_| "<redacted>"))
            .field("controls", &self.controls)
            .field("now_unix_ms", &self.now_unix_ms)
            .field("writer_node", &self.writer_node)
            .finish()
    }
}

impl<'a> CompressionRequest<'a> {
    /// Construct request context for one resolved target model.
    pub const fn new(model: &'a str) -> Self {
        Self {
            model,
            tenant_id: None,
            api_key_id: None,
            origin: None,
            session_id: None,
            controls: CompressionRequestControls {
                supported_chat: true,
                has_tools: false,
                has_functions: false,
                has_response_format: false,
                has_schema: false,
            },
            now_unix_ms: 0,
            writer_node: "",
        }
    }

    /// Resolved target model used for all token comparisons.
    pub const fn model(&self) -> &'a str {
        self.model
    }

    /// Add the captured session identity and its isolation boundaries.
    pub const fn with_session_context(
        mut self,
        tenant_id: &'a str,
        api_key_id: Option<&'a str>,
        origin: &'a str,
        session_id: [u8; 16],
    ) -> Self {
        self.tenant_id = Some(tenant_id);
        self.api_key_id = api_key_id;
        self.origin = Some(origin);
        self.session_id = Some(session_id);
        self
    }

    /// Set request-shape controls captured before body transformation.
    pub const fn with_controls(mut self, controls: CompressionRequestControls) -> Self {
        self.controls = controls;
        self
    }

    /// Set the deterministic request clock and stable writer identity.
    pub const fn with_clock_and_writer(mut self, now_unix_ms: u64, writer_node: &'a str) -> Self {
        self.now_unix_ms = now_unix_ms;
        self.writer_node = writer_node;
        self
    }

    /// Tenant boundary, available only when a session was captured.
    pub const fn tenant_id(&self) -> Option<&'a str> {
        self.tenant_id
    }

    /// Sanitized API-key identifier used for internal admission and metrics.
    pub const fn api_key_id(&self) -> Option<&'a str> {
        self.api_key_id
    }

    /// AI handler origin included in the opaque record identity.
    pub const fn origin(&self) -> Option<&'a str> {
        self.origin
    }

    /// Captured request session bytes. The compression layer never generates one.
    pub const fn session_id(&self) -> Option<[u8; 16]> {
        self.session_id
    }

    /// Request-shape controls used by stateful lever eligibility checks.
    pub const fn controls(&self) -> CompressionRequestControls {
        self.controls
    }

    /// Request-time Unix timestamp in milliseconds.
    pub const fn now_unix_ms(&self) -> u64 {
        self.now_unix_ms
    }

    /// Stable process or mesh node identity, never a credential.
    pub const fn writer_node(&self) -> &'a str {
        self.writer_node
    }
}

/// Backend-neutral result returned by a lever before runner validation.
#[derive(Clone, PartialEq)]
pub enum CompressionDecision {
    /// Complete candidate replacement to validate and possibly commit.
    Candidate {
        /// Full replacement message list.
        messages: Vec<Value>,
    },
    /// Expected ineligibility or no-op.
    Skipped {
        /// Closed reason code.
        reason: SkipReason,
    },
    /// Sanitized runtime failure that preserves the working list.
    Failed {
        /// Closed failure code.
        reason: FailureReason,
    },
}

impl fmt::Debug for CompressionDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Candidate { messages } => formatter
                .debug_struct("Candidate")
                .field("message_count", &messages.len())
                .finish(),
            Self::Skipped { reason } => formatter
                .debug_struct("Skipped")
                .field("reason", reason)
                .finish(),
            Self::Failed { reason } => formatter
                .debug_struct("Failed")
                .field("reason", reason)
                .finish(),
        }
    }
}

/// Token-accounting rule a lever's candidate must satisfy before commit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CompressionCommitRule {
    /// Commit only candidates with a smaller target-model token estimate.
    #[default]
    StrictReduction,
    /// Commit changed candidates whose target-model estimate does not grow.
    NonExpanding,
}

/// One asynchronous compression transformation.
#[async_trait]
pub trait CompressionLever: Send + Sync {
    /// Stable lever identifier.
    fn kind(&self) -> LeverKind;

    /// External state backend, if the lever is stateful.
    fn backend(&self) -> Option<CompressionBackend>;

    /// Candidate commit rule used by the shared runner.
    fn commit_rule(&self) -> CompressionCommitRule {
        CompressionCommitRule::StrictReduction
    }

    /// Produce a complete candidate, skip, or fail without mutating the input.
    async fn compress(
        &self,
        request: &CompressionRequest<'_>,
        messages: &[Value],
    ) -> CompressionDecision;
}

/// Model-aware estimated-token counting used to validate every candidate.
pub trait TokenCounter: Send + Sync {
    /// Count tokens for a complete raw JSON message list.
    fn count(&self, model: &str, messages: &[Value]) -> u64;

    /// Precision signal for this counter and target model.
    fn precision(&self, _model: &str) -> TokenCountPrecision {
        TokenCountPrecision::Heuristic
    }
}

/// Production model-aware estimated-token counter.
#[derive(Debug, Default)]
pub struct ModelTokenCounter;

impl TokenCounter for ModelTokenCounter {
    fn count(&self, model: &str, messages: &[Value]) -> u64 {
        crate::token_estimate::estimate_json_message_tokens(model, messages)
    }

    fn precision(&self, model: &str) -> TokenCountPrecision {
        crate::token_estimate::token_count_precision(model)
    }
}

/// Completed ordered compression run and estimator-relative token accounting.
#[derive(Clone, PartialEq)]
pub struct CompressionRun {
    /// Final committed message list.
    pub messages: Vec<Value>,
    /// Model-aware token estimate before the first lever.
    pub initial_tokens: u64,
    /// Model-aware token estimate after the last committed lever.
    pub final_tokens: u64,
    /// Initial-to-final reduction in the shared estimate, counted once.
    pub tokens_saved: u64,
    /// Target-model tokenizer path used for every token value in this run.
    pub token_count_precision: TokenCountPrecision,
    /// Ordered result for every lever that ran.
    pub lever_results: Vec<LeverResult>,
}

impl fmt::Debug for CompressionRun {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompressionRun")
            .field("message_count", &self.messages.len())
            .field("initial_tokens", &self.initial_tokens)
            .field("final_tokens", &self.final_tokens)
            .field("tokens_saved", &self.tokens_saved)
            .field("token_count_precision", &self.token_count_precision)
            .field("lever_results", &self.lever_results)
            .finish()
    }
}

impl CompressionRun {
    /// Return failure-first request outcome semantics.
    pub fn outcome(&self) -> RequestOutcome {
        if self
            .lever_results
            .iter()
            .any(|result| matches!(result.outcome, LeverOutcome::Failed { .. }))
        {
            return RequestOutcome::Failed;
        }
        if self
            .lever_results
            .iter()
            .any(|result| matches!(result.outcome, LeverOutcome::Applied))
        {
            return RequestOutcome::Applied;
        }
        RequestOutcome::Skipped
    }

    /// Sum committed per-lever savings for invariant and telemetry checks.
    pub fn applied_tokens_saved(&self) -> u64 {
        self.lever_results
            .iter()
            .filter(|result| matches!(result.outcome, LeverOutcome::Applied))
            .map(|result| result.tokens_saved)
            .sum()
    }
}

/// Sequential compression runner with one shared token-accounting strategy.
pub struct CompressionRunner {
    levers: Vec<Arc<dyn CompressionLever>>,
    token_counter: Arc<dyn TokenCounter>,
}

impl CompressionRunner {
    /// Construct a runner from ordered levers and a shared counter.
    pub fn new(
        levers: Vec<Arc<dyn CompressionLever>>,
        token_counter: Arc<dyn TokenCounter>,
    ) -> Self {
        Self {
            levers,
            token_counter,
        }
    }

    /// Construct a runner using the production target-model counter.
    pub fn with_model_counter(levers: Vec<Arc<dyn CompressionLever>>) -> Self {
        Self::new(levers, Arc::new(ModelTokenCounter))
    }

    /// Whether the explicit/effective pipeline contains no levers.
    pub fn is_empty(&self) -> bool {
        self.levers.is_empty()
    }

    /// Run every lever in order and enforce each candidate's commit rule.
    pub async fn run(
        &self,
        request: &CompressionRequest<'_>,
        messages: &[Value],
    ) -> CompressionRun {
        let mut working = messages.to_vec();
        let initial_tokens = self.token_counter.count(request.model(), &working);
        let mut working_tokens = initial_tokens;
        let mut lever_results = Vec::with_capacity(self.levers.len());

        for lever in &self.levers {
            let started = Instant::now();
            let before_tokens = working_tokens;
            let decision = lever.compress(request, &working).await;
            let (outcome, after_tokens, tokens_saved) = match decision {
                CompressionDecision::Candidate {
                    messages: candidate,
                } => {
                    let candidate_tokens = self.token_counter.count(request.model(), &candidate);
                    let changed = candidate != working;
                    let commit_rule = lever.commit_rule();
                    let applies = match commit_rule {
                        CompressionCommitRule::StrictReduction => candidate_tokens < working_tokens,
                        CompressionCommitRule::NonExpanding => {
                            changed && candidate_tokens <= working_tokens
                        }
                    };
                    if applies {
                        let saved = working_tokens.saturating_sub(candidate_tokens);
                        working = candidate;
                        working_tokens = candidate_tokens;
                        (LeverOutcome::Applied, candidate_tokens, saved)
                    } else {
                        let reason = if commit_rule == CompressionCommitRule::NonExpanding
                            && !changed
                            && candidate_tokens == working_tokens
                        {
                            SkipReason::NotNeeded
                        } else {
                            SkipReason::NoSavings
                        };
                        (LeverOutcome::Skipped { reason }, working_tokens, 0)
                    }
                }
                CompressionDecision::Skipped { reason } => {
                    (LeverOutcome::Skipped { reason }, working_tokens, 0)
                }
                CompressionDecision::Failed { reason } => {
                    (LeverOutcome::Failed { reason }, working_tokens, 0)
                }
            };
            lever_results.push(LeverResult {
                lever: lever.kind(),
                backend: lever.backend(),
                outcome,
                before_tokens,
                after_tokens,
                tokens_saved,
                duration: started.elapsed(),
            });
        }

        let tokens_saved = initial_tokens - working_tokens;
        let run = CompressionRun {
            messages: working,
            initial_tokens,
            final_tokens: working_tokens,
            tokens_saved,
            token_count_precision: self.token_counter.precision(request.model()),
            lever_results,
        };
        debug_assert_eq!(run.applied_tokens_saved(), run.tokens_saved);
        run
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CompressionCommitRule, CompressionDecision, CompressionLever, CompressionRequest,
        CompressionRequestControls, CompressionRunner, TokenCounter,
    };
    use crate::compression::outcome::{
        FailureReason, LeverKind, LeverOutcome, RequestOutcome, SkipReason,
    };
    use crate::compression::{
        inspect_marked_context, CompressionBackend, PositionReorderConfig, PositionReorderLever,
        RetrievalRanking,
    };
    use crate::TokenCountPrecision;
    use async_trait::async_trait;
    use serde_json::{json, Value};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct FieldTokenCounter {
        models: Mutex<Vec<String>>,
    }

    impl TokenCounter for FieldTokenCounter {
        fn count(&self, model: &str, messages: &[Value]) -> u64 {
            self.models.lock().unwrap().push(model.to_string());
            messages
                .iter()
                .filter_map(|message| message.get("tokens").and_then(Value::as_u64))
                .sum()
        }
    }

    struct ScriptedLever {
        kind: LeverKind,
        backend: Option<CompressionBackend>,
        commit_rule: CompressionCommitRule,
        decision: CompressionDecision,
        seen_tokens: Arc<Mutex<Vec<u64>>>,
    }

    impl ScriptedLever {
        fn new(kind: LeverKind, decision: CompressionDecision) -> (Self, Arc<Mutex<Vec<u64>>>) {
            let seen_tokens = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    kind,
                    backend: None,
                    commit_rule: CompressionCommitRule::StrictReduction,
                    decision,
                    seen_tokens: seen_tokens.clone(),
                },
                seen_tokens,
            )
        }

        fn with_commit_rule(mut self, commit_rule: CompressionCommitRule) -> Self {
            self.commit_rule = commit_rule;
            self
        }
    }

    #[async_trait]
    impl CompressionLever for ScriptedLever {
        fn kind(&self) -> LeverKind {
            self.kind
        }

        fn backend(&self) -> Option<CompressionBackend> {
            self.backend
        }

        fn commit_rule(&self) -> CompressionCommitRule {
            self.commit_rule
        }

        async fn compress(
            &self,
            _request: &CompressionRequest<'_>,
            messages: &[Value],
        ) -> CompressionDecision {
            let tokens = messages
                .iter()
                .filter_map(|message| message.get("tokens").and_then(Value::as_u64))
                .sum();
            self.seen_tokens.lock().unwrap().push(tokens);
            self.decision.clone()
        }
    }

    fn messages(tokens: u64, label: &str) -> Vec<Value> {
        vec![json!({"role": "user", "content": label, "tokens": tokens})]
    }

    fn candidate(tokens: u64, label: &str) -> CompressionDecision {
        CompressionDecision::Candidate {
            messages: messages(tokens, label),
        }
    }

    fn marked_chunk(id: &str, score: &str) -> String {
        format!(
            "<sbproxy-chunk id=\"{id}\" score=\"{score}\" format=\"text\">\nbody-{id}\n</sbproxy-chunk>"
        )
    }

    fn marked_block(chunks: &[String]) -> String {
        let mut rendered =
            String::from("<sbproxy-retrieval>\n<sbproxy-query>\nquery\n</sbproxy-query>\n");
        for chunk in chunks {
            rendered.push_str(chunk);
            rendered.push('\n');
        }
        rendered.push_str("</sbproxy-retrieval>");
        rendered
    }

    #[test]
    fn request_context_defaults_are_safe_and_session_context_is_explicit() {
        let bare = CompressionRequest::new("gpt-target");
        assert_eq!(bare.model(), "gpt-target");
        assert_eq!(bare.tenant_id(), None);
        assert_eq!(bare.api_key_id(), None);
        assert_eq!(bare.origin(), None);
        assert_eq!(bare.session_id(), None);
        assert!(bare.controls().supported_chat);
        assert!(!bare.controls().has_structured_top_level_fields());

        let controls = CompressionRequestControls {
            supported_chat: true,
            has_tools: true,
            ..CompressionRequestControls::default()
        };
        let contextual = CompressionRequest::new("gpt-target")
            .with_session_context("tenant-a", Some("key-a"), "API.Example.COM.", [7; 16])
            .with_controls(controls)
            .with_clock_and_writer(12_345, "node-a");

        assert_eq!(contextual.tenant_id(), Some("tenant-a"));
        assert_eq!(contextual.api_key_id(), Some("key-a"));
        assert_eq!(contextual.origin(), Some("API.Example.COM."));
        assert_eq!(contextual.session_id(), Some([7; 16]));
        assert!(contextual.controls().has_structured_top_level_fields());
        assert_eq!(contextual.now_unix_ms(), 12_345);
        assert_eq!(contextual.writer_node(), "node-a");
        let request_debug = format!("{contextual:?}");
        assert!(!request_debug.contains("[7, 7"));
        assert!(request_debug.contains("<redacted>"));

        let decision = candidate(1, "sensitive prompt text");
        let decision_debug = format!("{decision:?}");
        assert!(!decision_debug.contains("sensitive prompt text"));
        assert!(decision_debug.contains("message_count"));
    }

    #[tokio::test]
    async fn applies_levers_in_order_and_later_levers_see_committed_output() {
        let (first, first_seen) =
            ScriptedLever::new(LeverKind::SummaryBuffer, candidate(70, "first"));
        let (second, second_seen) =
            ScriptedLever::new(LeverKind::WindowFit, candidate(40, "second"));
        let counter = Arc::new(FieldTokenCounter::default());
        let runner =
            CompressionRunner::new(vec![Arc::new(first), Arc::new(second)], counter.clone());
        let original = messages(100, "original");
        let untouched = original.clone();

        let run = runner
            .run(&CompressionRequest::new("gpt-target"), &original)
            .await;

        assert_eq!(original, untouched, "the caller's body is immutable");
        assert_eq!(*first_seen.lock().unwrap(), vec![100]);
        assert_eq!(*second_seen.lock().unwrap(), vec![70]);
        assert_eq!(run.messages, messages(40, "second"));
        assert_eq!(run.initial_tokens, 100);
        assert_eq!(run.final_tokens, 40);
        assert_eq!(run.tokens_saved, 60);
        assert_eq!(run.token_count_precision, TokenCountPrecision::Heuristic);
        assert_eq!(run.outcome(), RequestOutcome::Applied);
        assert_eq!(run.lever_results.len(), 2);
        assert_eq!(run.lever_results[0].before_tokens, 100);
        assert_eq!(run.lever_results[0].after_tokens, 70);
        assert_eq!(run.lever_results[0].tokens_saved, 30);
        assert_eq!(run.lever_results[1].before_tokens, 70);
        assert_eq!(run.lever_results[1].after_tokens, 40);
        assert_eq!(run.lever_results[1].tokens_saved, 30);
        assert_eq!(run.applied_tokens_saved(), 60);
        assert!(run
            .lever_results
            .iter()
            .all(|result| matches!(result.outcome, LeverOutcome::Applied)));
        assert!(counter
            .models
            .lock()
            .unwrap()
            .iter()
            .all(|model| model == "gpt-target"));
    }

    #[tokio::test]
    async fn discards_equal_and_larger_candidates_as_no_savings() {
        assert_eq!(
            CompressionCommitRule::default(),
            CompressionCommitRule::StrictReduction
        );
        let (equal, _) = ScriptedLever::new(LeverKind::SummaryBuffer, candidate(100, "equal"));
        let (larger, seen) = ScriptedLever::new(LeverKind::WindowFit, candidate(120, "larger"));
        let runner = CompressionRunner::new(
            vec![Arc::new(equal), Arc::new(larger)],
            Arc::new(FieldTokenCounter::default()),
        );
        let original = messages(100, "original");

        let run = runner
            .run(&CompressionRequest::new("gpt-target"), &original)
            .await;

        assert_eq!(*seen.lock().unwrap(), vec![100]);
        assert_eq!(run.messages, original);
        assert_eq!(run.initial_tokens, 100);
        assert_eq!(run.final_tokens, 100);
        assert_eq!(run.tokens_saved, 0);
        assert_eq!(run.applied_tokens_saved(), 0);
        assert_eq!(run.outcome(), RequestOutcome::Skipped);
        for result in run.lever_results {
            assert_eq!(result.before_tokens, 100);
            assert_eq!(result.after_tokens, 100);
            assert_eq!(result.tokens_saved, 0);
            assert_eq!(
                result.outcome,
                LeverOutcome::Skipped {
                    reason: SkipReason::NoSavings
                }
            );
        }
    }

    #[tokio::test]
    async fn non_expanding_changed_equal_candidate_applies_with_zero_savings() {
        let (lever, _) =
            ScriptedLever::new(LeverKind::PositionReorder, candidate(100, "reordered"));
        let runner = CompressionRunner::new(
            vec![Arc::new(
                lever.with_commit_rule(CompressionCommitRule::NonExpanding),
            )],
            Arc::new(FieldTokenCounter::default()),
        );

        let run = runner
            .run(
                &CompressionRequest::new("gpt-target"),
                &messages(100, "original"),
            )
            .await;

        assert_eq!(run.messages, messages(100, "reordered"));
        assert_eq!(run.initial_tokens, 100);
        assert_eq!(run.final_tokens, 100);
        assert_eq!(run.tokens_saved, 0);
        assert_eq!(run.lever_results[0].outcome, LeverOutcome::Applied);
        assert_eq!(run.lever_results[0].tokens_saved, 0);
        assert_eq!(run.outcome(), RequestOutcome::Applied);
    }

    #[tokio::test]
    async fn position_reorder_applies_with_zero_savings_through_production_runner() {
        let source = marked_block(&[
            marked_chunk("1", "1"),
            marked_chunk("2", "0.8"),
            marked_chunk("3", "0.6"),
            marked_chunk("4", "0.4"),
        ]);
        let original = vec![json!({"role": "user", "content": source, "tokens": 100})];
        let lever = PositionReorderLever::new(PositionReorderConfig {
            ranking: RetrievalRanking::Supplied,
        });
        let runner = CompressionRunner::new(
            vec![Arc::new(lever)],
            Arc::new(FieldTokenCounter::default()),
        );

        let run = runner
            .run(&CompressionRequest::new("gpt-target"), &original)
            .await;

        let snapshot = inspect_marked_context(&run.messages)
            .expect("valid marked context")
            .expect("marked context present");
        let ids = snapshot.blocks[0]
            .chunks
            .iter()
            .map(|chunk| chunk.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, ["1", "3", "4", "2"]);
        assert_eq!(run.initial_tokens, 100);
        assert_eq!(run.final_tokens, 100);
        assert_eq!(run.tokens_saved, 0);
        assert_eq!(run.applied_tokens_saved(), 0);
        assert_eq!(run.lever_results[0].lever, LeverKind::PositionReorder);
        assert_eq!(run.lever_results[0].outcome, LeverOutcome::Applied);
        assert_eq!(run.lever_results[0].tokens_saved, 0);
        assert_eq!(run.outcome(), RequestOutcome::Applied);
    }

    #[tokio::test]
    async fn non_expanding_unchanged_equal_candidate_skips_as_not_needed() {
        let original = messages(100, "original");
        let (lever, _) = ScriptedLever::new(
            LeverKind::PositionReorder,
            CompressionDecision::Candidate {
                messages: original.clone(),
            },
        );
        let runner = CompressionRunner::new(
            vec![Arc::new(
                lever.with_commit_rule(CompressionCommitRule::NonExpanding),
            )],
            Arc::new(FieldTokenCounter::default()),
        );

        let run = runner
            .run(&CompressionRequest::new("gpt-target"), &original)
            .await;

        assert_eq!(run.messages, original);
        assert_eq!(
            run.lever_results[0].outcome,
            LeverOutcome::Skipped {
                reason: SkipReason::NotNeeded
            }
        );
        assert_eq!(run.outcome(), RequestOutcome::Skipped);
    }

    #[tokio::test]
    async fn position_reorder_non_expanding_rule_rejects_artificial_expansion() {
        let (lever, _) = ScriptedLever::new(LeverKind::PositionReorder, candidate(120, "expanded"));
        let runner = CompressionRunner::new(
            vec![Arc::new(
                lever.with_commit_rule(CompressionCommitRule::NonExpanding),
            )],
            Arc::new(FieldTokenCounter::default()),
        );
        let original = messages(100, "original");

        let run = runner
            .run(&CompressionRequest::new("gpt-target"), &original)
            .await;

        assert_eq!(run.messages, original);
        assert_eq!(
            run.lever_results[0].outcome,
            LeverOutcome::Skipped {
                reason: SkipReason::NoSavings
            }
        );
        assert_eq!(run.outcome(), RequestOutcome::Skipped);
    }

    #[tokio::test]
    async fn zero_saving_apply_preserves_request_savings_invariant() {
        let (reordered, _) =
            ScriptedLever::new(LeverKind::PositionReorder, candidate(100, "reordered"));
        let (reduced, seen) = ScriptedLever::new(LeverKind::WindowFit, candidate(70, "reduced"));
        let runner = CompressionRunner::new(
            vec![
                Arc::new(reordered.with_commit_rule(CompressionCommitRule::NonExpanding)),
                Arc::new(reduced),
            ],
            Arc::new(FieldTokenCounter::default()),
        );

        let run = runner
            .run(
                &CompressionRequest::new("gpt-target"),
                &messages(100, "original"),
            )
            .await;

        assert_eq!(*seen.lock().unwrap(), vec![100]);
        assert_eq!(run.lever_results[0].outcome, LeverOutcome::Applied);
        assert_eq!(run.lever_results[0].tokens_saved, 0);
        assert_eq!(run.lever_results[1].outcome, LeverOutcome::Applied);
        assert_eq!(run.lever_results[1].tokens_saved, 30);
        assert_eq!(run.tokens_saved, 30);
        assert_eq!(run.applied_tokens_saved(), 30);
    }

    #[tokio::test]
    async fn discarded_candidate_cannot_inflate_request_savings() {
        let (larger, _) = ScriptedLever::new(LeverKind::SummaryBuffer, candidate(140, "discarded"));
        let (applied, _) = ScriptedLever::new(LeverKind::WindowFit, candidate(80, "applied"));
        let runner = CompressionRunner::new(
            vec![Arc::new(larger), Arc::new(applied)],
            Arc::new(FieldTokenCounter::default()),
        );

        let run = runner
            .run(
                &CompressionRequest::new("gpt-target"),
                &messages(100, "original"),
            )
            .await;

        assert_eq!(run.initial_tokens, 100);
        assert_eq!(run.final_tokens, 80);
        assert_eq!(run.tokens_saved, 20);
        assert_eq!(run.applied_tokens_saved(), 20);
        assert_eq!(run.lever_results[0].tokens_saved, 0);
        assert_eq!(run.lever_results[1].tokens_saved, 20);
    }

    #[tokio::test]
    async fn skip_and_failure_preserve_working_messages_but_later_lever_runs() {
        let (skipped, _) = ScriptedLever::new(
            LeverKind::SummaryBuffer,
            CompressionDecision::Skipped {
                reason: SkipReason::NotEligible,
            },
        );
        let (failed, _) = ScriptedLever::new(
            LeverKind::SummaryBuffer,
            CompressionDecision::Failed {
                reason: FailureReason::StateUnavailable,
            },
        );
        let (applied, seen) = ScriptedLever::new(LeverKind::WindowFit, candidate(60, "fallback"));
        let runner = CompressionRunner::new(
            vec![Arc::new(skipped), Arc::new(failed), Arc::new(applied)],
            Arc::new(FieldTokenCounter::default()),
        );

        let run = runner
            .run(
                &CompressionRequest::new("gpt-target"),
                &messages(100, "original"),
            )
            .await;

        assert_eq!(*seen.lock().unwrap(), vec![100]);
        assert_eq!(run.messages, messages(60, "fallback"));
        assert_eq!(run.tokens_saved, 40);
        assert_eq!(run.lever_results[0].tokens_saved, 0);
        assert_eq!(run.lever_results[1].tokens_saved, 0);
        assert_eq!(run.outcome(), RequestOutcome::Failed);
    }

    #[tokio::test]
    async fn empty_pipeline_is_a_silent_noop_record() {
        let runner = CompressionRunner::new(vec![], Arc::new(FieldTokenCounter::default()));
        let original = messages(42, "original");

        let run = runner
            .run(&CompressionRequest::new("gpt-target"), &original)
            .await;

        assert!(run.lever_results.is_empty());
        assert_eq!(run.messages, original);
        assert_eq!(run.initial_tokens, 42);
        assert_eq!(run.final_tokens, 42);
        assert_eq!(run.tokens_saved, 0);
        assert_eq!(run.outcome(), RequestOutcome::Skipped);
    }

    #[tokio::test]
    async fn production_counter_stamps_its_target_model_precision_on_the_run() {
        let runner = CompressionRunner::with_model_counter(vec![]);

        let tokenizer = runner.run(&CompressionRequest::new("gpt-4o"), &[]).await;
        let heuristic = runner
            .run(&CompressionRequest::new("self-hosted-model"), &[])
            .await;

        assert_eq!(
            tokenizer.token_count_precision,
            TokenCountPrecision::ModelTokenizer
        );
        assert_eq!(
            heuristic.token_count_precision,
            TokenCountPrecision::Heuristic
        );
    }
}

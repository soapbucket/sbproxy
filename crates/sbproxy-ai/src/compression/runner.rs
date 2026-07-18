//! Sequential asynchronous compression execution.

use crate::compression::outcome::{
    FailureReason, LeverKind, LeverOutcome, LeverResult, RequestOutcome, SkipReason,
};
use crate::compression::CompressionBackend;
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;
use std::time::Instant;

/// Immutable request data shared by every lever in one pipeline run.
#[derive(Debug, Clone, Copy)]
pub struct CompressionRequest<'a> {
    model: &'a str,
}

impl<'a> CompressionRequest<'a> {
    /// Construct request context for one resolved target model.
    pub const fn new(model: &'a str) -> Self {
        Self { model }
    }

    /// Resolved target model used for all token comparisons.
    pub const fn model(&self) -> &'a str {
        self.model
    }
}

/// Backend-neutral result returned by a lever before runner validation.
#[derive(Debug, Clone, PartialEq)]
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

/// One asynchronous compression transformation.
#[async_trait]
pub trait CompressionLever: Send + Sync {
    /// Stable lever identifier.
    fn kind(&self) -> LeverKind;

    /// External state backend, if the lever is stateful.
    fn backend(&self) -> Option<CompressionBackend>;

    /// Produce a complete candidate, skip, or fail without mutating the input.
    async fn compress(
        &self,
        request: &CompressionRequest<'_>,
        messages: &[Value],
    ) -> CompressionDecision;
}

/// Target-model token counting used to validate every candidate consistently.
pub trait TokenCounter: Send + Sync {
    /// Count tokens for a complete raw JSON message list.
    fn count(&self, model: &str, messages: &[Value]) -> u64;
}

/// Production target-model token counter.
#[derive(Debug, Default)]
pub struct ModelTokenCounter;

impl TokenCounter for ModelTokenCounter {
    fn count(&self, model: &str, messages: &[Value]) -> u64 {
        crate::token_estimate::estimate_json_message_tokens(model, messages)
    }
}

/// Completed ordered compression run and exact token accounting.
#[derive(Debug, Clone, PartialEq)]
pub struct CompressionRun {
    /// Final committed message list.
    pub messages: Vec<Value>,
    /// Target-model token count before the first lever.
    pub initial_tokens: u64,
    /// Target-model token count after the last committed lever.
    pub final_tokens: u64,
    /// Exact initial-to-final reduction, counted once.
    pub tokens_saved: u64,
    /// Ordered result for every lever that ran.
    pub lever_results: Vec<LeverResult>,
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

    /// Run every lever in order and commit only strictly reducing candidates.
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
                    if candidate_tokens < working_tokens {
                        let saved = working_tokens - candidate_tokens;
                        working = candidate;
                        working_tokens = candidate_tokens;
                        (LeverOutcome::Applied, candidate_tokens, saved)
                    } else {
                        (
                            LeverOutcome::Skipped {
                                reason: SkipReason::NoSavings,
                            },
                            working_tokens,
                            0,
                        )
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
            lever_results,
        };
        debug_assert_eq!(run.applied_tokens_saved(), run.tokens_saved);
        run
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CompressionDecision, CompressionLever, CompressionRequest, CompressionRunner, TokenCounter,
    };
    use crate::compression::outcome::{
        FailureReason, LeverKind, LeverOutcome, RequestOutcome, SkipReason,
    };
    use crate::compression::CompressionBackend;
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
                    decision,
                    seen_tokens: seen_tokens.clone(),
                },
                seen_tokens,
            )
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
}

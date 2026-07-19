//! Stateful running-summary compression lever.

use crate::compression::identity::normalize_origin;
use crate::compression::summary_policy::{
    SummaryPolicyFingerprint, SUMMARIZER_SYSTEM_PROMPT, SUMMARIZER_USER_PROMPT_PREAMBLE,
    SUMMARY_REPLACEMENT_PREAMBLE, SUMMARY_WRAPPER_CLOSE, SUMMARY_WRAPPER_OPEN,
};
use crate::compression::{
    CommitError, CompressionBackend, CompressionDecision, CompressionLever, CompressionRecordId,
    CompressionRequest, CompressionSessionRecord, CompressionSessionStore, FailureReason,
    LeverKind, MessageDigest, RecordKind, SkipReason, SummaryBufferConfig, RECORD_SCHEMA_VERSION,
};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

// The permit covers one bounded state load before summarization and one
// bounded commit afterward. The fixed five-second margin covers two complete
// Redis operations at two seconds each plus one second for local validation
// and scheduling without requiring lease renewal.
const STATE_OPERATION_COMMIT_MARGIN_SECS: u64 = 5;

/// Dedicated internal summarizer input after governance and model selection.
#[derive(Clone, Copy)]
pub struct SummarizationRequest<'a> {
    /// Tenant charged for internal model use.
    pub tenant_id: &'a str,
    /// Sanitized API-key identifier used by admission and metrics.
    pub api_key_id: Option<&'a str>,
    /// Dedicated provider selected by compression policy.
    pub provider: &'a str,
    /// Dedicated model selected by compression policy.
    pub model: &'a str,
    /// Previously verified summary for an incremental update.
    pub prior_summary: Option<&'a str>,
    /// Only newly covered, eligibility-checked original messages.
    pub new_messages: &'a [Value],
    /// Hard maximum requested output size.
    pub target_summary_tokens: u64,
    /// Hard wall-clock deadline for the internal call.
    pub timeout: Duration,
}

impl fmt::Debug for SummarizationRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SummarizationRequest")
            .field("tenant_id", &self.tenant_id)
            .field("api_key_id", &self.api_key_id)
            .field("provider", &self.provider)
            .field("model", &self.model)
            .field("has_prior_summary", &self.prior_summary.is_some())
            .field("new_message_count", &self.new_messages.len())
            .field("target_summary_tokens", &self.target_summary_tokens)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl SummarizationRequest<'_> {
    /// Build the exact privileged prompt whose size is checked before dispatch.
    pub fn input_messages(&self) -> Vec<Value> {
        let source = json!({
            "prior_summary": self.prior_summary,
            "new_messages": self.new_messages,
        });
        vec![
            json!({"role": "system", "content": SUMMARIZER_SYSTEM_PROMPT}),
            json!({
                "role": "user",
                "content": format!(
                    "{SUMMARIZER_USER_PROMPT_PREAMBLE}{source}"
                )
            }),
        ]
    }
}

/// Successful dedicated summarizer response and provider usage.
#[derive(Clone, PartialEq, Eq)]
pub struct SummarizationOutput {
    /// Generated bounded running summary.
    pub summary: String,
    /// Provider-reported internal input tokens.
    pub input_tokens: u64,
    /// Provider-reported internal output tokens.
    pub output_tokens: u64,
}

impl fmt::Debug for SummarizationOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SummarizationOutput")
            .field("summary", &"<redacted>")
            .field("input_tokens", &self.input_tokens)
            .field("output_tokens", &self.output_tokens)
            .finish()
    }
}

/// Closed dedicated summarizer failure and admission classifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SummarizerError {
    /// The bounded internal request exceeded its deadline.
    #[error("internal summarizer timed out")]
    Timeout,
    /// The selected provider failed without exposing response content.
    #[error("internal summarizer provider failed")]
    Provider,
    /// Internal model budget admission was denied.
    #[error("internal summarizer budget denied")]
    BudgetDenied,
    /// Credential governance denied the configured destination.
    #[error("internal summarizer policy denied")]
    PolicyDenied,
    /// A response could not be decoded into bounded summary text.
    #[error("invalid internal summarizer response")]
    InvalidOutput,
}

/// Internal model boundary used by the summary-buffer lever.
#[async_trait]
pub trait InternalSummarizer: Send + Sync {
    /// Maximum safe input tokens for the selected provider and model.
    fn max_input_tokens(&self, provider: &str, model: &str) -> u64;

    /// Execute one governed, budgeted, non-recursive internal request.
    async fn summarize(
        &self,
        request: SummarizationRequest<'_>,
    ) -> Result<SummarizationOutput, SummarizerError>;
}

/// Stateful running-summary transformation backed by external canonical state.
pub struct SummaryBufferLever {
    config: SummaryBufferConfig,
    state_ttl: Duration,
    policy_fingerprint: SummaryPolicyFingerprint,
    store: Arc<dyn CompressionSessionStore>,
    summarizer: Arc<dyn InternalSummarizer>,
}

impl SummaryBufferLever {
    /// Construct one configured stateful lever.
    pub fn new(
        config: SummaryBufferConfig,
        state_ttl: Duration,
        store: Arc<dyn CompressionSessionStore>,
        summarizer: Arc<dyn InternalSummarizer>,
    ) -> Self {
        let policy_fingerprint = SummaryPolicyFingerprint::current(&config, state_ttl);
        Self {
            config,
            state_ttl,
            policy_fingerprint,
            store,
            summarizer,
        }
    }

    fn eligible_history<'a>(
        &self,
        request: &CompressionRequest<'_>,
        messages: &'a [Value],
    ) -> Result<EligibleHistory<'a>, SkipReason> {
        if !request.controls().supported_chat {
            return Err(SkipReason::UnsupportedRequest);
        }
        if request.controls().has_structured_top_level_fields() {
            return Err(SkipReason::StructuredRequest);
        }
        if request.session_id().is_none()
            || request.tenant_id().is_none()
            || request.origin().is_none()
        {
            return Err(SkipReason::MissingSession);
        }

        let input_tokens =
            crate::token_estimate::estimate_json_message_tokens(request.model(), messages);
        if input_tokens < self.config.min_tokens {
            return Err(SkipReason::BelowThreshold);
        }

        let mut protected_prefix_count = 0;
        for (index, message) in messages.iter().enumerate() {
            let Some(role) = message.get("role").and_then(Value::as_str) else {
                return Err(SkipReason::UnsupportedRequest);
            };
            if index == protected_prefix_count && matches!(role, "system" | "developer") {
                protected_prefix_count += 1;
            }
        }

        if messages.len()
            <= protected_prefix_count.saturating_add(self.config.retain_recent_messages)
        {
            return Err(SkipReason::InsufficientHistory);
        }
        let covered_end = messages.len() - self.config.retain_recent_messages;
        let covered = &messages[protected_prefix_count..covered_end];
        if covered.is_empty() {
            return Err(SkipReason::InsufficientHistory);
        }
        if !covered.iter().all(is_simple_history_message) {
            return Err(SkipReason::StructuredRequest);
        }

        Ok(EligibleHistory {
            protected: &messages[..protected_prefix_count],
            covered,
            recent: &messages[covered_end..],
            input_tokens,
        })
    }

    async fn compress_with_permit(
        &self,
        request: &CompressionRequest<'_>,
        history: &EligibleHistory<'_>,
        record_id: CompressionRecordId,
        permit: &crate::compression::UpdatePermit,
    ) -> CompressionDecision {
        let stored = match self.store.load(&record_id).await {
            Ok(record) => record,
            Err(_) => return failed(FailureReason::StateUnavailable),
        };
        if stored
            .as_ref()
            .is_some_and(|record| record.schema_version != RECORD_SCHEMA_VERSION)
        {
            return failed(FailureReason::Serialization);
        }
        if stored.as_ref().is_some_and(|record| {
            record.kind == RecordKind::Live && record.expires_at_unix_ms <= request.now_unix_ms()
        }) {
            return skipped(SkipReason::StateExpired);
        }

        let live = stored
            .as_ref()
            .filter(|record| record.kind == RecordKind::Live);
        if let Some(record) = live {
            if record.protected_prefix_count != history.protected.len()
                || record.protected_prefix_digest != MessageDigest::for_messages(history.protected)
                || record.covered_history_count > history.covered.len()
                || record.covered_history_digest
                    != MessageDigest::for_messages(&history.covered[..record.covered_history_count])
            {
                return skipped(SkipReason::BranchMismatch);
            }
            if record.covered_history_count == history.covered.len() {
                return CompressionDecision::Candidate {
                    messages: replacement_messages(
                        history.protected,
                        &record.summary,
                        history.recent,
                    ),
                };
            }
        }

        let prior_summary = live.map(|record| record.summary.as_str());
        let covered_start = live.map_or(0, |record| record.covered_history_count);
        let new_messages = &history.covered[covered_start..];
        if new_messages.is_empty() {
            return skipped(SkipReason::NoNewHistory);
        }
        let summarization_request = SummarizationRequest {
            tenant_id: request
                .tenant_id()
                .expect("eligibility requires a tenant boundary"),
            api_key_id: request.api_key_id(),
            provider: &self.config.summarizer.provider,
            model: &self.config.summarizer.model,
            prior_summary,
            new_messages,
            target_summary_tokens: self.config.target_summary_tokens,
            timeout: Duration::from_secs(self.config.summarizer.timeout_secs),
        };
        let summarizer_input_tokens = crate::token_estimate::estimate_json_message_tokens(
            summarization_request.model,
            &summarization_request.input_messages(),
        );
        if summarizer_input_tokens
            > self
                .summarizer
                .max_input_tokens(summarization_request.provider, summarization_request.model)
        {
            return skipped(SkipReason::SummarizerInputTooLarge);
        }

        let output = match self.summarizer.summarize(summarization_request).await {
            Ok(output) => output,
            Err(SummarizerError::BudgetDenied) => return skipped(SkipReason::BudgetDenied),
            Err(SummarizerError::PolicyDenied) => return skipped(SkipReason::PolicyDenied),
            Err(SummarizerError::Timeout) => return failed(FailureReason::SummarizerTimeout),
            Err(SummarizerError::Provider) => return failed(FailureReason::SummarizerProvider),
            Err(SummarizerError::InvalidOutput) => return failed(FailureReason::InvalidSummary),
        };
        let summary = output.summary.trim();
        if summary.is_empty() || output.output_tokens > self.config.target_summary_tokens {
            return failed(FailureReason::InvalidSummary);
        }
        let summary_tokens = crate::token_estimate::estimate_json_message_tokens(
            self.config.summarizer.model.as_str(),
            &[json!({"role": "user", "content": summary})],
        );
        if summary_tokens > self.config.target_summary_tokens
            || summary.len() as u64 > self.config.target_summary_tokens.saturating_mul(16)
        {
            return failed(FailureReason::InvalidSummary);
        }

        let candidate = replacement_messages(history.protected, summary, history.recent);
        let candidate_tokens =
            crate::token_estimate::estimate_json_message_tokens(request.model(), &candidate);
        if candidate_tokens >= history.input_tokens {
            return skipped(SkipReason::NoSavings);
        }

        let expected_logical_version = stored.as_ref().map(|record| record.logical_version);
        let Some(logical_version) = expected_logical_version.unwrap_or(0).checked_add(1) else {
            return failed(FailureReason::Internal);
        };
        let now = request.now_unix_ms();
        let ttl_millis = u64::try_from(self.state_ttl.as_millis()).unwrap_or(u64::MAX);
        let record = CompressionSessionRecord {
            schema_version: RECORD_SCHEMA_VERSION,
            logical_version,
            tenant_id: request
                .tenant_id()
                .expect("eligibility requires a tenant boundary")
                .to_string(),
            origin: normalize_origin(
                request
                    .origin()
                    .expect("eligibility requires an origin boundary"),
            ),
            summary: summary.to_string(),
            protected_prefix_count: history.protected.len(),
            protected_prefix_digest: MessageDigest::for_messages(history.protected),
            covered_history_count: history.covered.len(),
            covered_history_digest: MessageDigest::for_messages(history.covered),
            covered_input_tokens: crate::token_estimate::estimate_json_message_tokens(
                request.model(),
                history.covered,
            ),
            summary_tokens: output.output_tokens.max(summary_tokens),
            summarizer_provider: self.config.summarizer.provider.clone(),
            summarizer_model: self.config.summarizer.model.clone(),
            writer_node: request.writer_node().to_string(),
            parent_logical_version: expected_logical_version,
            conflict_detected: false,
            created_at_unix_ms: stored
                .as_ref()
                .map_or(now, |record| record.created_at_unix_ms),
            updated_at_unix_ms: now,
            expires_at_unix_ms: now.saturating_add(ttl_millis),
            kind: RecordKind::Live,
        };
        if let Err(error) = self
            .store
            .commit(permit, expected_logical_version, &record, self.state_ttl)
            .await
        {
            return failed(commit_failure_reason(error));
        }
        CompressionDecision::Candidate {
            messages: candidate,
        }
    }
}

#[async_trait]
impl CompressionLever for SummaryBufferLever {
    fn kind(&self) -> LeverKind {
        LeverKind::SummaryBuffer
    }

    fn backend(&self) -> Option<CompressionBackend> {
        Some(self.store.backend())
    }

    async fn compress(
        &self,
        request: &CompressionRequest<'_>,
        messages: &[Value],
    ) -> CompressionDecision {
        let history = match self.eligible_history(request, messages) {
            Ok(history) => history,
            Err(reason) => return skipped(reason),
        };
        let record_id = CompressionRecordId::derive_for_summary_policy(
            request
                .tenant_id()
                .expect("eligibility requires a tenant boundary"),
            request
                .origin()
                .expect("eligibility requires an origin boundary"),
            request
                .session_id()
                .expect("eligibility requires a captured session"),
            self.policy_fingerprint,
        );
        let lease_ttl = Duration::from_secs(
            self.config
                .summarizer
                .timeout_secs
                .saturating_add(STATE_OPERATION_COMMIT_MARGIN_SECS),
        );
        let permit = match self.store.acquire_update(&record_id, lease_ttl).await {
            Ok(Some(permit)) => permit,
            Ok(None) => return skipped(SkipReason::LockContended),
            Err(_) => return failed(FailureReason::StateUnavailable),
        };
        let decision = self
            .compress_with_permit(request, &history, record_id, &permit)
            .await;
        let _ = self.store.release(permit).await;
        decision
    }
}

struct EligibleHistory<'a> {
    protected: &'a [Value],
    covered: &'a [Value],
    recent: &'a [Value],
    input_tokens: u64,
}

fn is_simple_history_message(message: &Value) -> bool {
    let Some(object) = message.as_object() else {
        return false;
    };
    if object.len() != 2 {
        return false;
    }
    matches!(
        object.get("role").and_then(Value::as_str),
        Some("user" | "assistant")
    ) && object.get("content").is_some_and(Value::is_string)
}

fn replacement_messages(protected: &[Value], summary: &str, recent: &[Value]) -> Vec<Value> {
    let mut replacement = Vec::with_capacity(protected.len() + recent.len() + 1);
    replacement.extend_from_slice(protected);
    replacement.push(json!({
        "role": "user",
        "content": format!(
            "{SUMMARY_REPLACEMENT_PREAMBLE}\n{SUMMARY_WRAPPER_OPEN}\n{summary}\n{SUMMARY_WRAPPER_CLOSE}"
        )
    }));
    replacement.extend_from_slice(recent);
    replacement
}

fn skipped(reason: SkipReason) -> CompressionDecision {
    CompressionDecision::Skipped { reason }
}

fn failed(reason: FailureReason) -> CompressionDecision {
    CompressionDecision::Failed { reason }
}

fn commit_failure_reason(error: CommitError) -> FailureReason {
    match error {
        CommitError::Unavailable => FailureReason::StateUnavailable,
        CommitError::LeaseLost | CommitError::FenceRejected => FailureReason::LeaseLost,
        CommitError::StaleVersion => FailureReason::StaleVersion,
        CommitError::Serialization => FailureReason::Serialization,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        InternalSummarizer, SummarizationOutput, SummarizationRequest, SummarizerError,
        SummaryBufferLever,
    };
    use crate::compression::{
        CommitError, CompressionBackend, CompressionConsistency, CompressionDecision,
        CompressionLever, CompressionRecordId, CompressionRequest, CompressionRequestControls,
        CompressionSessionRecord, CompressionSessionStore, DeleteResult, FailureReason, ListPage,
        ListRequest, PurgePage, PurgeRequest, SkipReason, StoreError, SummarizerConfig,
        SummaryBufferConfig, UpdatePermit,
    };
    use async_trait::async_trait;
    use serde_json::{json, Value};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[derive(Debug, Clone, PartialEq)]
    struct CapturedSummarization {
        tenant_id: String,
        api_key_id: Option<String>,
        prior_summary: Option<String>,
        new_messages: Vec<Value>,
        target_summary_tokens: u64,
    }

    struct FakeSummarizer {
        calls: Mutex<Vec<CapturedSummarization>>,
        max_input_tokens: u64,
        result: Mutex<Result<SummarizationOutput, SummarizerError>>,
    }

    impl FakeSummarizer {
        fn returning(summary: &str) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                max_input_tokens: u64::MAX,
                result: Mutex::new(Ok(SummarizationOutput {
                    summary: summary.to_string(),
                    input_tokens: 80,
                    output_tokens: 4,
                })),
            }
        }
    }

    #[async_trait]
    impl InternalSummarizer for FakeSummarizer {
        fn max_input_tokens(&self, _provider: &str, _model: &str) -> u64 {
            self.max_input_tokens
        }

        async fn summarize(
            &self,
            request: SummarizationRequest<'_>,
        ) -> Result<SummarizationOutput, SummarizerError> {
            self.calls.lock().unwrap().push(CapturedSummarization {
                tenant_id: request.tenant_id.to_string(),
                api_key_id: request.api_key_id.map(str::to_string),
                prior_summary: request.prior_summary.map(str::to_string),
                new_messages: request.new_messages.to_vec(),
                target_summary_tokens: request.target_summary_tokens,
            });
            self.result.lock().unwrap().clone()
        }
    }

    struct FakeStore {
        calls: Mutex<Vec<&'static str>>,
        acquired_lease_ttls: Mutex<Vec<Duration>>,
        records: Mutex<HashMap<CompressionRecordId, CompressionSessionRecord>>,
        commits: Mutex<Vec<(Option<u64>, CompressionSessionRecord, Duration)>>,
        permit_available: Mutex<bool>,
        load_error: Mutex<Option<StoreError>>,
        commit_error: Mutex<Option<CommitError>>,
    }

    impl Default for FakeStore {
        fn default() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                acquired_lease_ttls: Mutex::new(Vec::new()),
                records: Mutex::new(HashMap::new()),
                commits: Mutex::new(Vec::new()),
                permit_available: Mutex::new(true),
                load_error: Mutex::new(None),
                commit_error: Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl CompressionSessionStore for FakeStore {
        fn backend(&self) -> CompressionBackend {
            CompressionBackend::Redis
        }

        fn consistency(&self) -> CompressionConsistency {
            CompressionConsistency::Serialized
        }

        async fn load(
            &self,
            id: &CompressionRecordId,
        ) -> Result<Option<CompressionSessionRecord>, StoreError> {
            self.calls.lock().unwrap().push("load");
            if let Some(error) = *self.load_error.lock().unwrap() {
                return Err(error);
            }
            Ok(self.records.lock().unwrap().get(id).cloned())
        }

        async fn acquire_update(
            &self,
            id: &CompressionRecordId,
            lease_ttl: Duration,
        ) -> Result<Option<UpdatePermit>, StoreError> {
            self.calls.lock().unwrap().push("acquire");
            self.acquired_lease_ttls.lock().unwrap().push(lease_ttl);
            if !*self.permit_available.lock().unwrap() {
                return Ok(None);
            }
            Ok(Some(UpdatePermit::new(
                *id,
                CompressionBackend::Redis,
                b"test-lease".to_vec(),
                1,
            )))
        }

        async fn commit(
            &self,
            permit: &UpdatePermit,
            expected_logical_version: Option<u64>,
            record: &CompressionSessionRecord,
            ttl: Duration,
        ) -> Result<(), CommitError> {
            self.calls.lock().unwrap().push("commit");
            if let Some(error) = *self.commit_error.lock().unwrap() {
                return Err(error);
            }
            self.commits
                .lock()
                .unwrap()
                .push((expected_logical_version, record.clone(), ttl));
            self.records
                .lock()
                .unwrap()
                .insert(permit.record_id(), record.clone());
            Ok(())
        }

        async fn release(&self, _permit: UpdatePermit) -> Result<(), StoreError> {
            self.calls.lock().unwrap().push("release");
            Ok(())
        }

        async fn list(&self, _request: &ListRequest) -> Result<ListPage, StoreError> {
            unreachable!("not used by request-path tests")
        }

        async fn delete(&self, _id: &CompressionRecordId) -> Result<DeleteResult, StoreError> {
            unreachable!("not used by request-path tests")
        }

        async fn purge(&self, _request: &PurgeRequest) -> Result<PurgePage, StoreError> {
            unreachable!("not used by request-path tests")
        }
    }

    fn config() -> SummaryBufferConfig {
        SummaryBufferConfig {
            min_tokens: 100,
            retain_recent_messages: 1,
            target_summary_tokens: 40,
            summarizer: SummarizerConfig {
                provider: "internal-provider".to_string(),
                model: "summary-model".to_string(),
                timeout_secs: 5,
            },
        }
    }

    fn long(label: &str) -> String {
        format!("{label} {}", "historical detail ".repeat(80))
    }

    fn request() -> CompressionRequest<'static> {
        CompressionRequest::new("target-model")
            .with_session_context("tenant-a", Some("key-a"), "API.Example.COM.", [7; 16])
            .with_clock_and_writer(10_000, "node-a")
    }

    fn history() -> Vec<Value> {
        vec![
            json!({"role": "system", "content": "protected instruction"}),
            json!({"role": "user", "content": long("old question")}),
            json!({"role": "assistant", "content": long("old answer")}),
            json!({"role": "user", "content": long("recent question")}),
        ]
    }

    #[tokio::test]
    async fn first_summary_protects_prefix_and_tail_and_commits_versioned_state() {
        let store = Arc::new(FakeStore::default());
        let summarizer = Arc::new(FakeSummarizer::returning("short bounded facts"));
        let lever = SummaryBufferLever::new(
            config(),
            Duration::from_secs(60),
            store.clone(),
            summarizer.clone(),
        );
        let messages = history();

        let decision = lever.compress(&request(), &messages).await;
        let CompressionDecision::Candidate {
            messages: candidate,
        } = decision
        else {
            panic!("expected a reducing summary candidate, got {decision:?}");
        };

        assert_eq!(candidate[0], messages[0]);
        assert_eq!(candidate.last(), messages.last());
        assert_eq!(candidate[1]["role"], "user");
        assert!(candidate[1]["content"]
            .as_str()
            .unwrap()
            .contains("untrusted historical summary"));
        assert!(candidate[1]["content"]
            .as_str()
            .unwrap()
            .contains("short bounded facts"));

        let calls = summarizer.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].tenant_id, "tenant-a");
        assert_eq!(calls[0].api_key_id.as_deref(), Some("key-a"));
        assert_eq!(calls[0].prior_summary, None);
        assert_eq!(calls[0].new_messages, messages[1..3]);
        assert_eq!(calls[0].target_summary_tokens, 40);
        drop(calls);

        let commits = store.commits.lock().unwrap();
        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0].0, None);
        assert_eq!(commits[0].2, Duration::from_secs(60));
        let record = &commits[0].1;
        assert_eq!(record.logical_version, 1);
        assert_eq!(record.parent_logical_version, None);
        assert_eq!(record.tenant_id, "tenant-a");
        assert_eq!(record.origin, "api.example.com");
        assert_eq!(record.summary, "short bounded facts");
        assert_eq!(record.protected_prefix_count, 1);
        assert_eq!(record.covered_history_count, 2);
        assert_eq!(record.created_at_unix_ms, 10_000);
        assert_eq!(record.updated_at_unix_ms, 10_000);
        assert_eq!(record.expires_at_unix_ms, 70_000);
        let encoded = serde_json::to_string(record).unwrap();
        assert!(!encoded.contains(&hex::encode([7; 16])));
        assert!(!encoded.contains("old question"));
        assert!(!encoded.contains("old answer"));
        drop(commits);

        assert_eq!(
            *store.acquired_lease_ttls.lock().unwrap(),
            vec![Duration::from_secs(10)],
            "the lease must cover the summarizer plus bounded state load and commit operations"
        );

        assert_eq!(
            *store.calls.lock().unwrap(),
            vec!["acquire", "load", "commit", "release"]
        );
    }

    #[tokio::test]
    async fn missing_session_skips_before_touching_state_or_summarizer() {
        let store = Arc::new(FakeStore::default());
        let summarizer = Arc::new(FakeSummarizer::returning("unused"));
        let lever = SummaryBufferLever::new(
            config(),
            Duration::from_secs(60),
            store.clone(),
            summarizer.clone(),
        );
        let messages = vec![json!({"role": "user", "content": long("history")})];

        assert_eq!(
            lever
                .compress(&CompressionRequest::new("target-model"), &messages)
                .await,
            CompressionDecision::Skipped {
                reason: SkipReason::MissingSession
            }
        );
        assert!(store.calls.lock().unwrap().is_empty());
        assert!(summarizer.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn summarizer_diagnostics_redact_source_and_generated_content() {
        let source = vec![json!({"role": "user", "content": "sensitive source"})];
        let request = SummarizationRequest {
            tenant_id: "tenant-a",
            api_key_id: Some("key-a"),
            provider: "provider-a",
            model: "model-a",
            prior_summary: Some("sensitive prior summary"),
            new_messages: &source,
            target_summary_tokens: 100,
            timeout: Duration::from_secs(2),
        };
        let output = SummarizationOutput {
            summary: "sensitive generated summary".to_string(),
            input_tokens: 20,
            output_tokens: 5,
        };

        let request_debug = format!("{request:?}");
        assert!(!request_debug.contains("sensitive source"));
        assert!(!request_debug.contains("sensitive prior summary"));
        assert!(request_debug.contains("new_message_count"));
        let output_debug = format!("{output:?}");
        assert!(!output_debug.contains("sensitive generated summary"));
        assert!(output_debug.contains("<redacted>"));
    }

    #[tokio::test]
    async fn unsupported_structured_below_threshold_and_short_history_skip_before_state() {
        let cases = [
            (
                CompressionRequestControls {
                    supported_chat: false,
                    ..CompressionRequestControls::default()
                },
                SkipReason::UnsupportedRequest,
            ),
            (
                CompressionRequestControls {
                    has_tools: true,
                    ..CompressionRequestControls::default()
                },
                SkipReason::StructuredRequest,
            ),
            (
                CompressionRequestControls {
                    has_functions: true,
                    ..CompressionRequestControls::default()
                },
                SkipReason::StructuredRequest,
            ),
            (
                CompressionRequestControls {
                    has_response_format: true,
                    ..CompressionRequestControls::default()
                },
                SkipReason::StructuredRequest,
            ),
            (
                CompressionRequestControls {
                    has_schema: true,
                    ..CompressionRequestControls::default()
                },
                SkipReason::StructuredRequest,
            ),
        ];
        for (controls, expected) in cases {
            let store = Arc::new(FakeStore::default());
            let summarizer = Arc::new(FakeSummarizer::returning("unused"));
            let lever = SummaryBufferLever::new(
                config(),
                Duration::from_secs(60),
                store.clone(),
                summarizer.clone(),
            );

            assert_eq!(
                lever
                    .compress(&request().with_controls(controls), &history())
                    .await,
                CompressionDecision::Skipped { reason: expected }
            );
            assert!(store.calls.lock().unwrap().is_empty());
            assert!(summarizer.calls.lock().unwrap().is_empty());
        }

        let store = Arc::new(FakeStore::default());
        let summarizer = Arc::new(FakeSummarizer::returning("unused"));
        let mut high_threshold = config();
        high_threshold.min_tokens = u64::MAX;
        let lever = SummaryBufferLever::new(
            high_threshold,
            Duration::from_secs(60),
            store.clone(),
            summarizer.clone(),
        );
        assert_eq!(
            lever.compress(&request(), &history()).await,
            CompressionDecision::Skipped {
                reason: SkipReason::BelowThreshold
            }
        );
        assert!(store.calls.lock().unwrap().is_empty());

        let store = Arc::new(FakeStore::default());
        let summarizer = Arc::new(FakeSummarizer::returning("unused"));
        let lever = SummaryBufferLever::new(
            config(),
            Duration::from_secs(60),
            store.clone(),
            summarizer.clone(),
        );
        let only_recent = vec![json!({"role": "user", "content": long("recent only")})];
        assert_eq!(
            lever.compress(&request(), &only_recent).await,
            CompressionDecision::Skipped {
                reason: SkipReason::InsufficientHistory
            }
        );
        assert!(store.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn structured_covered_history_skips_but_structured_recent_tail_is_preserved() {
        let store = Arc::new(FakeStore::default());
        let summarizer = Arc::new(FakeSummarizer::returning("unused"));
        let lever = SummaryBufferLever::new(
            config(),
            Duration::from_secs(60),
            store.clone(),
            summarizer.clone(),
        );
        let structured_history = vec![
            json!({"role": "user", "content": [{"type": "text", "text": long("old") }]}),
            json!({"role": "user", "content": long("recent")}),
        ];
        assert_eq!(
            lever.compress(&request(), &structured_history).await,
            CompressionDecision::Skipped {
                reason: SkipReason::StructuredRequest
            }
        );
        assert!(store.calls.lock().unwrap().is_empty());

        let store = Arc::new(FakeStore::default());
        let summarizer = Arc::new(FakeSummarizer::returning("short bounded facts"));
        let lever = SummaryBufferLever::new(config(), Duration::from_secs(60), store, summarizer);
        let structured_tail = json!({
            "role": "assistant",
            "content": null,
            "tool_calls": [{"id": "call-a", "type": "function"}]
        });
        let messages = vec![
            json!({"role": "user", "content": long("old")}),
            structured_tail.clone(),
        ];
        let CompressionDecision::Candidate { messages } =
            lever.compress(&request(), &messages).await
        else {
            panic!("structured recent tail must not block older history compression");
        };
        assert_eq!(messages.last(), Some(&structured_tail));
    }

    #[tokio::test]
    async fn exact_match_reuses_state_without_summarizer_or_write() {
        let store = Arc::new(FakeStore::default());
        let summarizer = Arc::new(FakeSummarizer::returning("short bounded facts"));
        let lever = SummaryBufferLever::new(
            config(),
            Duration::from_secs(60),
            store.clone(),
            summarizer.clone(),
        );
        let messages = history();
        assert!(matches!(
            lever.compress(&request(), &messages).await,
            CompressionDecision::Candidate { .. }
        ));
        store.calls.lock().unwrap().clear();
        store.commits.lock().unwrap().clear();
        summarizer.calls.lock().unwrap().clear();

        let decision = lever.compress(&request(), &messages).await;

        assert!(matches!(decision, CompressionDecision::Candidate { .. }));
        assert!(summarizer.calls.lock().unwrap().is_empty());
        assert!(store.commits.lock().unwrap().is_empty());
        assert_eq!(
            *store.calls.lock().unwrap(),
            vec!["acquire", "load", "release"]
        );
    }

    #[tokio::test]
    async fn logically_expired_state_is_not_reused_before_redis_removes_it() {
        let store = Arc::new(FakeStore::default());
        let summarizer = Arc::new(FakeSummarizer::returning("short bounded facts"));
        let lever = SummaryBufferLever::new(
            config(),
            Duration::from_secs(60),
            store.clone(),
            summarizer.clone(),
        );
        let messages = history();
        assert!(matches!(
            lever.compress(&request(), &messages).await,
            CompressionDecision::Candidate { .. }
        ));
        store.calls.lock().unwrap().clear();
        store.commits.lock().unwrap().clear();
        summarizer.calls.lock().unwrap().clear();
        let expired_request = CompressionRequest::new("target-model")
            .with_session_context("tenant-a", Some("key-a"), "API.Example.COM.", [7; 16])
            .with_clock_and_writer(70_000, "node-b");

        let decision = lever.compress(&expired_request, &messages).await;

        assert_eq!(
            decision,
            CompressionDecision::Skipped {
                reason: SkipReason::StateExpired
            }
        );
        assert!(summarizer.calls.lock().unwrap().is_empty());
        assert!(store.commits.lock().unwrap().is_empty());
        assert_eq!(
            *store.calls.lock().unwrap(),
            vec!["acquire", "load", "release"]
        );
    }

    #[tokio::test]
    async fn semantic_policy_changes_start_isolated_summary_lineages() {
        let baseline = config();
        let mut cases = Vec::new();

        let mut changed = baseline.clone();
        changed.summarizer.provider = "other-provider".to_string();
        cases.push(("summarizer provider", changed, Duration::from_secs(60)));

        let mut changed = baseline.clone();
        changed.summarizer.model = "other-model".to_string();
        cases.push(("summarizer model", changed, Duration::from_secs(60)));

        let mut changed = baseline.clone();
        changed.target_summary_tokens -= 1;
        cases.push(("summary target", changed, Duration::from_secs(60)));

        let mut changed = baseline.clone();
        changed.retain_recent_messages += 1;
        cases.push(("retained tail", changed, Duration::from_secs(60)));

        let mut changed = baseline.clone();
        changed.min_tokens += 1;
        cases.push(("eligibility threshold", changed, Duration::from_secs(60)));

        cases.push(("state retention", baseline.clone(), Duration::from_secs(61)));

        for (name, changed, state_ttl) in cases {
            let store = Arc::new(FakeStore::default());
            let first_summarizer = Arc::new(FakeSummarizer::returning("first summary"));
            let first = SummaryBufferLever::new(
                baseline.clone(),
                Duration::from_secs(60),
                store.clone(),
                first_summarizer,
            );
            assert!(matches!(
                first.compress(&request(), &history()).await,
                CompressionDecision::Candidate { .. }
            ));

            let changed_summarizer = Arc::new(FakeSummarizer::returning("changed summary"));
            let changed = SummaryBufferLever::new(
                changed,
                state_ttl,
                store.clone(),
                changed_summarizer.clone(),
            );
            assert!(
                matches!(
                    changed.compress(&request(), &history()).await,
                    CompressionDecision::Candidate { .. }
                ),
                "{name} must start a fresh lineage"
            );

            assert_eq!(
                changed_summarizer.calls.lock().unwrap().len(),
                1,
                "{name} reused the old policy's summary"
            );
            let commits = store.commits.lock().unwrap();
            assert_eq!(commits.len(), 2, "{name} did not commit fresh state");
            assert_eq!(
                commits[1].0, None,
                "{name} extended the old policy's lineage"
            );
            assert_eq!(commits[1].1.logical_version, 1);
            assert_eq!(store.records.lock().unwrap().len(), 2);
        }
    }

    #[tokio::test]
    async fn incremental_update_sends_only_newly_covered_messages_and_advances_version() {
        let store = Arc::new(FakeStore::default());
        let summarizer = Arc::new(FakeSummarizer::returning("first summary"));
        let lever = SummaryBufferLever::new(
            config(),
            Duration::from_secs(60),
            store.clone(),
            summarizer.clone(),
        );
        let mut messages = history();
        assert!(matches!(
            lever.compress(&request(), &messages).await,
            CompressionDecision::Candidate { .. }
        ));
        summarizer.calls.lock().unwrap().clear();
        store.commits.lock().unwrap().clear();
        *summarizer.result.lock().unwrap() = Ok(SummarizationOutput {
            summary: "updated summary".to_string(),
            input_tokens: 50,
            output_tokens: 4,
        });
        let prior_recent = messages.last().unwrap().clone();
        let newly_covered = json!({"role": "assistant", "content": long("new answer")});
        messages.push(newly_covered.clone());
        messages.push(json!({"role": "user", "content": long("new recent")}));

        assert!(matches!(
            lever.compress(&request(), &messages).await,
            CompressionDecision::Candidate { .. }
        ));

        let calls = summarizer.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].prior_summary.as_deref(), Some("first summary"));
        assert_eq!(calls[0].new_messages, vec![prior_recent, newly_covered]);
        drop(calls);
        let commits = store.commits.lock().unwrap();
        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0].0, Some(1));
        assert_eq!(commits[0].1.logical_version, 2);
        assert_eq!(commits[0].1.parent_logical_version, Some(1));
        assert_eq!(commits[0].1.created_at_unix_ms, 10_000);
        assert_eq!(commits[0].1.covered_history_count, 4);
    }

    #[tokio::test]
    async fn branch_mismatch_skips_without_overwriting_state() {
        let store = Arc::new(FakeStore::default());
        let summarizer = Arc::new(FakeSummarizer::returning("first summary"));
        let lever = SummaryBufferLever::new(
            config(),
            Duration::from_secs(60),
            store.clone(),
            summarizer.clone(),
        );
        let mut messages = history();
        assert!(matches!(
            lever.compress(&request(), &messages).await,
            CompressionDecision::Candidate { .. }
        ));
        store.commits.lock().unwrap().clear();
        summarizer.calls.lock().unwrap().clear();
        messages[1] = json!({"role": "user", "content": long("different branch")});

        assert_eq!(
            lever.compress(&request(), &messages).await,
            CompressionDecision::Skipped {
                reason: SkipReason::BranchMismatch
            }
        );
        assert!(store.commits.lock().unwrap().is_empty());
        assert!(summarizer.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn oversized_summarizer_input_skips_without_call_or_write() {
        let store = Arc::new(FakeStore::default());
        let summarizer = Arc::new(FakeSummarizer {
            calls: Mutex::new(Vec::new()),
            max_input_tokens: 1,
            result: Mutex::new(Ok(SummarizationOutput {
                summary: "unused".to_string(),
                input_tokens: 0,
                output_tokens: 1,
            })),
        });
        let lever = SummaryBufferLever::new(
            config(),
            Duration::from_secs(60),
            store.clone(),
            summarizer.clone(),
        );

        assert_eq!(
            lever.compress(&request(), &history()).await,
            CompressionDecision::Skipped {
                reason: SkipReason::SummarizerInputTooLarge
            }
        );
        assert!(summarizer.calls.lock().unwrap().is_empty());
        assert!(store.commits.lock().unwrap().is_empty());
        assert_eq!(store.calls.lock().unwrap().last(), Some(&"release"));
    }

    #[tokio::test]
    async fn invalid_summary_and_failed_commit_preserve_messages_and_release_permit() {
        for invalid in [
            SummarizationOutput {
                summary: "   ".to_string(),
                input_tokens: 10,
                output_tokens: 1,
            },
            SummarizationOutput {
                summary: "too many reported tokens".to_string(),
                input_tokens: 10,
                output_tokens: 41,
            },
        ] {
            let store = Arc::new(FakeStore::default());
            let summarizer = Arc::new(FakeSummarizer {
                calls: Mutex::new(Vec::new()),
                max_input_tokens: u64::MAX,
                result: Mutex::new(Ok(invalid)),
            });
            let lever = SummaryBufferLever::new(
                config(),
                Duration::from_secs(60),
                store.clone(),
                summarizer,
            );
            assert_eq!(
                lever.compress(&request(), &history()).await,
                CompressionDecision::Failed {
                    reason: FailureReason::InvalidSummary
                }
            );
            assert!(store.commits.lock().unwrap().is_empty());
            assert_eq!(store.calls.lock().unwrap().last(), Some(&"release"));
        }

        let store = Arc::new(FakeStore::default());
        *store.commit_error.lock().unwrap() = Some(CommitError::StaleVersion);
        let summarizer = Arc::new(FakeSummarizer::returning("short bounded facts"));
        let lever =
            SummaryBufferLever::new(config(), Duration::from_secs(60), store.clone(), summarizer);
        assert_eq!(
            lever.compress(&request(), &history()).await,
            CompressionDecision::Failed {
                reason: FailureReason::StaleVersion
            }
        );
        assert!(store.records.lock().unwrap().is_empty());
        assert_eq!(store.calls.lock().unwrap().last(), Some(&"release"));
    }

    #[tokio::test]
    async fn non_reducing_summary_is_not_committed() {
        let store = Arc::new(FakeStore::default());
        let summarizer = Arc::new(FakeSummarizer::returning("short"));
        let lever =
            SummaryBufferLever::new(config(), Duration::from_secs(60), store.clone(), summarizer);
        let messages = vec![
            json!({"role": "user", "content": "x"}),
            json!({"role": "user", "content": long("very large retained tail")}),
        ];

        assert_eq!(
            lever.compress(&request(), &messages).await,
            CompressionDecision::Skipped {
                reason: SkipReason::NoSavings
            }
        );
        assert!(store.commits.lock().unwrap().is_empty());
        assert!(store.records.lock().unwrap().is_empty());
    }
}

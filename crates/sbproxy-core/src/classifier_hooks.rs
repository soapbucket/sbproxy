//! A real [`crate::hooks::IntentDetectionHook`] backed by the classifier
//! sidecar (WOR-2661/WOR-2665), closing the gap
//! `crate::intent_detection`'s module doc used to call out: "no
//! sidecar-backed implementation ships in this OSS tree today."
//!
//! [`crate::classifier_hooks::ClassifierIntentHook`] wraps
//! [`sbproxy_classifier_client::FallbackClassifier`], the WOR-2665
//! optional-degrade client, so it inherits its exact three-case contract:
//!
//! - No sidecar configured (`sidecar: None`): every call runs the local
//!   keyword heuristic ([`crate::intent_detection::detect_intent_heuristic`]).
//!   No connection is ever attempted.
//! - A sidecar is configured but unreachable, times out, or errors: the
//!   call degrades to the heuristic for that request.
//! - A sidecar is configured and healthy: its classification is used, and
//!   the heuristic is not run at all.
//!
//! # What the sidecar has to return
//!
//! The sidecar's generic `Classify` RPC returns a label plus a confidence
//! score; it has no built-in notion of "intent". This hook maps the
//! top label back to [`crate::hooks::IntentCategory`] by exact,
//! lowercase name (`"coding"`, `"vision"`, `"analysis"`,
//! `"summarization"`, `"general"`), so it only produces a useful result
//! when the sidecar's tenant is configured with a label set that matches
//! those five names. A label outside that set degrades to `None`, which
//! is a real "the hook declined" per
//! [`crate::hooks::IntentDetectionHook::detect`]'s contract, not a bug:
//! [`crate::intent_detection::detect_intent_with_source`] runs the
//! heuristic on `None` the same as it would for a missing hook.
//!
//! Stock proxy configuration can install both intent and provider-quality
//! hooks. Intent maps a classifier model's top label to the five categories
//! above. Quality maps each provider to a classifier model plus the exact
//! positive label whose score represents suitability for the current prompt.
//! This deliberately uses `Classify`, not the rich sidecar's completed-text
//! `Quality` RPC: provider routing happens before any provider has produced a
//! response. Every configured candidate must answer inside one shared
//! deadline or the request preserves its configured routing order.

use async_trait::async_trait;
use sbproxy_classifier_client::{
    ClassifierClient, ClassifierClientAuthenticationConfig, ClassifierClientError,
    ClassifierClientIdentityConfig, ClassifierClientSecurityConfig, ClassifierClientTlsConfig,
    ClassifyResponse, FallbackClassifier, InProcessClassifier, Verdict,
};
use sbproxy_security::egress::EgressAuthorizer;
use std::collections::HashMap;
#[cfg(test)]
use std::collections::HashSet;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::Notify;

use crate::hooks::{
    Hooks, IntentCategory, IntentDetectionHook, QualityRequest, QualityScore, QualityScoringHook,
};
use crate::intent_detection::detect_intent_heuristic;

#[cfg(test)]
tokio::task_local! {
    static QUALITY_PROMPT_STORAGE: std::cell::RefCell<Vec<usize>>;
}

const QUALITY_FANOUT_MAX_CONCURRENT_CALLS: usize = 8;
const QUALITY_FANOUT_MAX_LIVE_PROMPT_BYTES: usize = 1024 * 1024;
const QUALITY_FANOUT_MAX_PROMPT_BYTES: usize = 1024 * 1024;
const CLASSIFIER_HOOK_MAX_AUTH_BYTES: usize = 256;
const CLASSIFIER_HOOK_MAX_PEM_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct QualityFanoutLimits {
    max_concurrent_calls: usize,
    max_live_prompt_bytes: usize,
    max_prompt_bytes: usize,
}

impl QualityFanoutLimits {
    pub(crate) const fn max_concurrent_calls(self) -> usize {
        self.max_concurrent_calls
    }

    pub(crate) const fn max_live_prompt_bytes(self) -> usize {
        self.max_live_prompt_bytes
    }

    pub(crate) const fn max_prompt_bytes(self) -> usize {
        self.max_prompt_bytes
    }
}

pub(crate) const fn quality_fanout_limits() -> QualityFanoutLimits {
    QualityFanoutLimits {
        max_concurrent_calls: QUALITY_FANOUT_MAX_CONCURRENT_CALLS,
        max_live_prompt_bytes: QUALITY_FANOUT_MAX_LIVE_PROMPT_BYTES,
        max_prompt_bytes: QUALITY_FANOUT_MAX_PROMPT_BYTES,
    }
}

fn resolve_classifier_hook_secret_reference(
    reference: &str,
    field: &str,
    max_bytes: usize,
) -> anyhow::Result<String> {
    crate::config_source::resolve_secret_reference_bounded(reference, field, max_bytes)
}

struct QualityFanoutRuntime {
    byte_notify: Notify,
    state: Mutex<QualityFanoutState>,
    #[cfg(test)]
    owner_fingerprint: usize,
}

#[derive(Default)]
struct QualityFanoutState {
    leased_prompt_bytes: usize,
    current_call_leases: usize,
    #[cfg(test)]
    peak_leased_prompt_bytes: usize,
    #[cfg(test)]
    live_owned_prompt_bytes: usize,
    #[cfg(test)]
    peak_owned_prompt_bytes: usize,
    #[cfg(test)]
    total_weighted_leases: usize,
    #[cfg(test)]
    total_weighted_lease_releases: usize,
    #[cfg(test)]
    total_prompt_owners: usize,
    #[cfg(test)]
    total_prompt_owner_releases: usize,
    #[cfg(test)]
    prompt_owners_without_prior_lease: usize,
    #[cfg(test)]
    dials_without_prompt_lease: usize,
    #[cfg(test)]
    byte_budget_blocks_by_origin: HashMap<String, usize>,
    #[cfg(test)]
    dials_by_origin: HashMap<String, usize>,
    #[cfg(test)]
    total_prompt_owners_by_origin: HashMap<String, usize>,
    #[cfg(test)]
    live_leases_by_origin: HashMap<String, usize>,
    #[cfg(test)]
    distinct_budget_owner_ids: HashSet<usize>,
}

impl QualityFanoutRuntime {
    fn shared() -> &'static Self {
        static RUNTIME: OnceLock<QualityFanoutRuntime> = OnceLock::new();
        RUNTIME.get_or_init(|| Self {
            byte_notify: Notify::new(),
            state: Mutex::new(QualityFanoutState::default()),
            #[cfg(test)]
            owner_fingerprint: 1,
        })
    }

    async fn acquire(
        &'static self,
        prompt_bytes: usize,
        #[cfg(test)] origin: String,
    ) -> Option<QualityFanoutLease> {
        if prompt_bytes > quality_fanout_limits().max_prompt_bytes() {
            return None;
        }

        loop {
            let notified = self.byte_notify.notified();
            {
                // Poison recovery is deliberate: this lock guards request-path
                // admission, and inheriting a panicking writer's poison would
                // turn one bug into a standing outage for every quality-scored
                // request until restart. The counters the writer may have left
                // behind only over-count, which admission tolerates.
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if state.current_call_leases < quality_fanout_limits().max_concurrent_calls()
                    && state.leased_prompt_bytes + prompt_bytes
                        <= quality_fanout_limits().max_live_prompt_bytes()
                {
                    state.leased_prompt_bytes += prompt_bytes;
                    state.current_call_leases += 1;
                    #[cfg(test)]
                    {
                        state.peak_leased_prompt_bytes = state
                            .peak_leased_prompt_bytes
                            .max(state.leased_prompt_bytes);
                        state.total_weighted_leases += 1;
                        *state
                            .live_leases_by_origin
                            .entry(origin.clone())
                            .or_insert(0) += 1;
                        state
                            .distinct_budget_owner_ids
                            .insert(self.owner_fingerprint);
                    }
                    return Some(QualityFanoutLease {
                        runtime: self,
                        #[cfg(test)]
                        origin,
                        prompt_bytes,
                    });
                }
                #[cfg(test)]
                {
                    if state.leased_prompt_bytes + prompt_bytes
                        > quality_fanout_limits().max_live_prompt_bytes()
                    {
                        *state
                            .byte_budget_blocks_by_origin
                            .entry(origin.clone())
                            .or_insert(0) += 1;
                    }
                }
            }
            notified.await;
        }
    }

    fn release_weighted_lease(&self, prompt_bytes: usize, #[cfg(test)] origin: &str) {
        {
            // Runs from `Drop`. A panic here while holding the lock would
            // poison request-path admission, so recover the lock and treat an
            // underflow (a would-be double release) as a loud invariant report
            // rather than a poisoning panic.
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Deliberately no `debug_assert!`. It is live in every non-release
            // profile, so it would put a panic back on the exact path this
            // saturation exists to keep panic-free: a drop running during
            // another panic's unwind would abort the process instead of
            // reaching the report below.
            if state.leased_prompt_bytes < prompt_bytes || state.current_call_leases == 0 {
                static UNDERFLOW_REPORTED: std::sync::Once = std::sync::Once::new();
                UNDERFLOW_REPORTED.call_once(|| {
                    tracing::error!(
                        target: "sbproxy::classifier_hooks",
                        "weighted quality-fanout lease underflow: a lease was released twice; \
                         admission accounting saturates instead of poisoning the request path"
                    );
                });
            }
            state.leased_prompt_bytes = state.leased_prompt_bytes.saturating_sub(prompt_bytes);
            state.current_call_leases = state.current_call_leases.saturating_sub(1);
            #[cfg(test)]
            {
                state.total_weighted_lease_releases += 1;
                let remaining = state
                    .live_leases_by_origin
                    .get_mut(origin)
                    .expect("missing origin lease count");
                *remaining = remaining.checked_sub(1).expect("origin lease underflow");
                if *remaining == 0 {
                    state.live_leases_by_origin.remove(origin);
                }
            }
        }
        self.byte_notify.notify_waiters();
    }

    #[cfg(test)]
    fn begin_owned_prompt(&self, origin: &str, prompt_bytes: usize) -> QualityOwnedPromptGuard<'_> {
        let mut state = self.state.lock().expect("quality fanout state poisoned");
        if state
            .live_leases_by_origin
            .get(origin)
            .copied()
            .unwrap_or_default()
            == 0
        {
            state.prompt_owners_without_prior_lease += 1;
        }
        state.total_prompt_owners += 1;
        *state
            .total_prompt_owners_by_origin
            .entry(origin.to_string())
            .or_insert(0) += 1;
        state.live_owned_prompt_bytes += prompt_bytes;
        state.peak_owned_prompt_bytes = state
            .peak_owned_prompt_bytes
            .max(state.live_owned_prompt_bytes);
        drop(state);
        QualityOwnedPromptGuard {
            runtime: self,
            prompt_bytes,
        }
    }

    #[cfg(test)]
    fn finish_owned_prompt(&self, prompt_bytes: usize) {
        let mut state = self.state.lock().expect("quality fanout state poisoned");
        state.live_owned_prompt_bytes = state
            .live_owned_prompt_bytes
            .checked_sub(prompt_bytes)
            .expect("owned prompt lease underflow");
        state.total_prompt_owner_releases += 1;
    }

    #[cfg(test)]
    fn note_dial(&self, origin: &str) {
        let mut state = self.state.lock().expect("quality fanout state poisoned");
        if state
            .live_leases_by_origin
            .get(origin)
            .copied()
            .unwrap_or_default()
            == 0
        {
            state.dials_without_prompt_lease += 1;
        }
        *state.dials_by_origin.entry(origin.to_string()).or_insert(0) += 1;
    }

    #[cfg(test)]
    fn reset_for_test(&self) {
        *self.state.lock().expect("quality fanout state poisoned") = QualityFanoutState::default();
        self.byte_notify.notify_waiters();
    }
}

struct QualityFanoutLease {
    runtime: &'static QualityFanoutRuntime,
    #[cfg(test)]
    origin: String,
    prompt_bytes: usize,
}

impl Drop for QualityFanoutLease {
    fn drop(&mut self) {
        self.runtime.release_weighted_lease(
            self.prompt_bytes,
            #[cfg(test)]
            &self.origin,
        );
    }
}

#[cfg(test)]
struct QualityOwnedPromptGuard<'a> {
    runtime: &'a QualityFanoutRuntime,
    prompt_bytes: usize,
}

#[cfg(test)]
impl Drop for QualityOwnedPromptGuard<'_> {
    fn drop(&mut self) {
        self.runtime.finish_owned_prompt(self.prompt_bytes);
    }
}

#[cfg(test)]
struct QualityFanoutProbe {
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

#[cfg(test)]
impl QualityFanoutProbe {
    async fn acquire_unique() -> Self {
        static TEST_GUARD: OnceLock<Arc<tokio::sync::Mutex<()>>> = OnceLock::new();
        let guard = TEST_GUARD
            .get_or_init(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
            .lock_owned()
            .await;
        QualityFanoutRuntime::shared().reset_for_test();
        Self { _guard: guard }
    }

    fn total_prompt_owners(&self) -> usize {
        QualityFanoutRuntime::shared()
            .state
            .lock()
            .expect("quality fanout state poisoned")
            .total_prompt_owners
    }

    fn total_prompt_owners_for_origin(&self, origin: &str) -> usize {
        QualityFanoutRuntime::shared()
            .state
            .lock()
            .expect("quality fanout state poisoned")
            .total_prompt_owners_by_origin
            .get(origin)
            .copied()
            .unwrap_or_default()
    }

    fn dials_for_origin(&self, origin: &str) -> usize {
        QualityFanoutRuntime::shared()
            .state
            .lock()
            .expect("quality fanout state poisoned")
            .dials_by_origin
            .get(origin)
            .copied()
            .unwrap_or_default()
    }

    fn reset_high_water(&self) {
        let mut state = QualityFanoutRuntime::shared()
            .state
            .lock()
            .expect("quality fanout state poisoned");
        state.peak_leased_prompt_bytes = state.leased_prompt_bytes;
        state.peak_owned_prompt_bytes = state.live_owned_prompt_bytes;
    }

    async fn wait_for_origin_blocked_on_byte_budget(
        &self,
        origin: &str,
        within: Duration,
    ) -> Result<(), ()> {
        self.wait_for_origin_byte_budget_blocks(origin, 1, within)
            .await
    }

    fn byte_budget_blocks_for_origin(&self, origin: &str) -> usize {
        QualityFanoutRuntime::shared()
            .state
            .lock()
            .expect("quality fanout state poisoned")
            .byte_budget_blocks_by_origin
            .get(origin)
            .copied()
            .unwrap_or_default()
    }

    async fn wait_for_origin_byte_budget_blocks(
        &self,
        origin: &str,
        minimum: usize,
        within: Duration,
    ) -> Result<(), ()> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            if self.byte_budget_blocks_for_origin(origin) >= minimum {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn distinct_budget_owner_ids(&self) -> usize {
        QualityFanoutRuntime::shared()
            .state
            .lock()
            .expect("quality fanout state poisoned")
            .distinct_budget_owner_ids
            .len()
    }

    fn prompt_owners_without_prior_lease(&self) -> usize {
        QualityFanoutRuntime::shared()
            .state
            .lock()
            .expect("quality fanout state poisoned")
            .prompt_owners_without_prior_lease
    }

    fn dials_without_prompt_lease(&self) -> usize {
        QualityFanoutRuntime::shared()
            .state
            .lock()
            .expect("quality fanout state poisoned")
            .dials_without_prompt_lease
    }

    fn peak_leased_prompt_bytes(&self) -> usize {
        QualityFanoutRuntime::shared()
            .state
            .lock()
            .expect("quality fanout state poisoned")
            .peak_leased_prompt_bytes
    }

    fn peak_owned_prompt_bytes(&self) -> usize {
        QualityFanoutRuntime::shared()
            .state
            .lock()
            .expect("quality fanout state poisoned")
            .peak_owned_prompt_bytes
    }

    fn current_leased_prompt_bytes(&self) -> usize {
        QualityFanoutRuntime::shared()
            .state
            .lock()
            .expect("quality fanout state poisoned")
            .leased_prompt_bytes
    }

    fn current_owned_prompt_bytes(&self) -> usize {
        QualityFanoutRuntime::shared()
            .state
            .lock()
            .expect("quality fanout state poisoned")
            .live_owned_prompt_bytes
    }

    fn current_call_leases(&self) -> usize {
        QualityFanoutRuntime::shared()
            .state
            .lock()
            .expect("quality fanout state poisoned")
            .current_call_leases
    }

    fn available_call_permits(&self) -> usize {
        quality_fanout_limits().max_concurrent_calls() - self.current_call_leases()
    }

    fn available_prompt_bytes(&self) -> usize {
        quality_fanout_limits().max_live_prompt_bytes() - self.current_leased_prompt_bytes()
    }

    async fn wait_for_no_live_leases(&self, within: Duration) -> Result<(), ()> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            if self.current_call_leases() == 0
                && self.current_leased_prompt_bytes() == 0
                && self.current_owned_prompt_bytes() == 0
            {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn assert_every_owner_released_exactly_once(&self) {
        let state = QualityFanoutRuntime::shared()
            .state
            .lock()
            .expect("quality fanout state poisoned");
        assert_eq!(state.total_prompt_owners, state.total_prompt_owner_releases);
        assert_eq!(state.live_owned_prompt_bytes, 0);
    }

    fn assert_every_weighted_lease_released_exactly_once(&self) {
        let state = QualityFanoutRuntime::shared()
            .state
            .lock()
            .expect("quality fanout state poisoned");
        assert_eq!(
            state.total_weighted_leases,
            state.total_weighted_lease_releases
        );
        assert_eq!(state.leased_prompt_bytes, 0);
        assert_eq!(state.current_call_leases, 0);
    }
}

/// Adapts [`detect_intent_heuristic`] to [`InProcessClassifier`] so
/// [`FallbackClassifier`] can degrade to it without a network round trip.
struct IntentHeuristic;

impl InProcessClassifier for IntentHeuristic {
    fn classify(&self, text: &str) -> Verdict {
        let category: IntentCategory = detect_intent_heuristic(text).into();
        Verdict {
            label: intent_label(category).to_string(),
            // The heuristic does not produce a confidence score; 1.0
            // marks "this categorical rule fired", not a calibrated
            // probability. `ClassifierIntentHook::detect` never reads
            // this field, only `label`.
            score: 1.0,
        }
    }
}

/// Canonical lowercase label [`ClassifierIntentHook`] expects the sidecar
/// (or the in-process heuristic fallback) to use for each category.
fn intent_label(category: IntentCategory) -> &'static str {
    match category {
        IntentCategory::Coding => "coding",
        IntentCategory::Vision => "vision",
        IntentCategory::Analysis => "analysis",
        IntentCategory::Summarization => "summarization",
        IntentCategory::General => "general",
    }
}

/// The inverse of [`intent_label`]. Returns `None` for any label the
/// sidecar returns that this hook does not recognize, which the caller
/// treats as "declined to decide" per the hook's fail-open contract.
fn category_from_label(label: &str) -> Option<IntentCategory> {
    match label {
        "coding" => Some(IntentCategory::Coding),
        "vision" => Some(IntentCategory::Vision),
        "analysis" => Some(IntentCategory::Analysis),
        "summarization" => Some(IntentCategory::Summarization),
        "general" => Some(IntentCategory::General),
        _ => None,
    }
}

/// [`IntentDetectionHook`] backed by the classifier sidecar, degrading to
/// the local keyword heuristic per [`FallbackClassifier`]'s contract. See
/// the module docs for the label contract and why `QualityScoringHook` is
/// not built the same way.
pub struct ClassifierIntentHook {
    inner: FallbackClassifier<IntentHeuristic>,
}

impl ClassifierIntentHook {
    /// Build a hook that classifies through `sidecar` (`None` runs the
    /// heuristic on every call, the common OSS case: no sidecar deployed
    /// at all) using `model` as the sidecar's logical model id for the
    /// `Classify` RPC (empty selects the sidecar's default).
    pub fn new(sidecar: Option<ClassifierClient>, model: impl Into<String>) -> Self {
        Self {
            inner: FallbackClassifier::new(sidecar, model, IntentHeuristic),
        }
    }

    /// True when a sidecar is configured (whether or not it is currently
    /// reachable). Exposed for callers that want to log or report which
    /// mode a request ran in without duplicating the `Option` check.
    pub fn has_sidecar_configured(&self) -> bool {
        self.inner.has_sidecar_configured()
    }
}

#[async_trait]
impl IntentDetectionHook for ClassifierIntentHook {
    async fn detect(&self, prompt: &str) -> Option<IntentCategory> {
        let verdict = self.inner.classify(prompt).await;
        category_from_label(&verdict.label)
    }
}

/// One lazily constructed channel shared by the stock intent and quality
/// hooks. Pipeline compilation is synchronous and may run without a Tokio
/// runtime, so only URI validation happens there. The channel is constructed
/// on the first request-path call, inside the runtime, and then reused.
struct LazyClassifierClient {
    endpoint: String,
    timeout: Duration,
    egress: Option<EgressAuthorizer>,
    security: Option<ClassifierClientSecurityConfig>,
    client: tokio::sync::OnceCell<ClassifierClient>,
}

impl LazyClassifierClient {
    fn new(
        endpoint: String,
        timeout: Duration,
        egress: Option<EgressAuthorizer>,
        security: Option<ClassifierClientSecurityConfig>,
    ) -> Self {
        Self {
            endpoint,
            timeout,
            egress,
            security,
            client: tokio::sync::OnceCell::new(),
        }
    }

    async fn client(&self) -> Result<&ClassifierClient, ClassifierClientError> {
        self.client
            .get_or_try_init(|| async {
                match self.egress.clone() {
                    Some(egress) => ClassifierClient::connect_governed_lazy_with_security(
                        &self.endpoint,
                        self.timeout,
                        egress,
                        self.security.clone(),
                    ),
                    None => ClassifierClient::connect_lazy_with_security(
                        &self.endpoint,
                        self.timeout,
                        self.security.clone(),
                    ),
                }
            })
            .await
    }

    async fn classify(
        &self,
        model: &str,
        text: &str,
    ) -> Result<ClassifyResponse, ClassifierClientError> {
        #[cfg(test)]
        let _ = QUALITY_PROMPT_STORAGE.try_with(|pointers| {
            pointers.borrow_mut().push(text.as_ptr() as usize);
        });
        let client = self.client().await?;
        client.classify(model, text).await
    }

    async fn classify_owned(
        &self,
        model: &str,
        text: String,
        #[cfg(test)] origin: &str,
    ) -> Result<ClassifyResponse, ClassifierClientError> {
        let client = self.client().await?;
        #[cfg(test)]
        let runtime = QualityFanoutRuntime::shared();
        #[cfg(test)]
        let _owned_prompt = runtime.begin_owned_prompt(origin, text.len());
        #[cfg(test)]
        runtime.note_dial(origin);
        client.classify_owned(model, text).await
    }
}

/// Stock sidecar intent hook. Unlike [`ClassifierIntentHook`], it returns
/// `None` when the configured sidecar fails so the shared dispatcher can
/// report `heuristic_degraded` separately from unconfigured heuristic mode.
struct StockClassifierIntentHook {
    client: Arc<LazyClassifierClient>,
    model: String,
}

#[async_trait]
impl IntentDetectionHook for StockClassifierIntentHook {
    async fn detect(&self, prompt: &str) -> Option<IntentCategory> {
        match self.client.classify(&self.model, prompt).await {
            Ok(response) => response
                .labels
                .first()
                .and_then(|label| category_from_label(&label.name)),
            Err(error) => {
                tracing::debug!(
                    error = %error,
                    "configured intent classifier unavailable; using heuristic fallback"
                );
                None
            }
        }
    }
}

/// Stock prompt-aware provider scorer backed by per-provider classifier
/// contracts from `proxy.classifier_hooks.quality.provider_models`.
struct ClassifierQualityHook {
    client: Arc<LazyClassifierClient>,
    timeout: Duration,
    minimum_score: f64,
    provider_models: HashMap<String, sbproxy_config::ClassifierProviderModelConfig>,
}

#[async_trait]
impl QualityScoringHook for ClassifierQualityHook {
    fn minimum_score(&self) -> f64 {
        self.minimum_score
    }

    async fn score_providers(&self, req: &QualityRequest) -> Option<Vec<QualityScore>> {
        const MAX_CANDIDATES: usize = 64;
        if req.candidate_providers.len() > MAX_CANDIDATES {
            tracing::warn!(
                candidates = req.candidate_providers.len(),
                maximum = MAX_CANDIDATES,
                "quality classifier candidate limit exceeded; preserving configured routing"
            );
            return None;
        }
        if req.prompt.len() > quality_fanout_limits().max_prompt_bytes() {
            tracing::warn!(
                prompt_bytes = req.prompt.len(),
                maximum = quality_fanout_limits().max_prompt_bytes(),
                "quality classifier prompt limit exceeded; preserving configured routing"
            );
            return None;
        }

        let contracts = req
            .candidate_providers
            .iter()
            .map(|provider| {
                self.provider_models
                    .get(provider)
                    .cloned()
                    .map(|contract| (provider.clone(), contract))
            })
            .collect::<Option<Vec<_>>>()?;

        let prompt = req.prompt.as_str();
        #[cfg(test)]
        let origin = req.origin.clone();
        let calls = contracts.into_iter().map(move |(provider, contract)| {
            let client = Arc::clone(&self.client);
            #[cfg(test)]
            let origin = origin.clone();
            async move {
                #[cfg(test)]
                let _ = QUALITY_PROMPT_STORAGE.try_with(|pointers| {
                    pointers.borrow_mut().push(prompt.as_ptr() as usize);
                });
                let Some(_lease) = QualityFanoutRuntime::shared()
                    .acquire(
                        prompt.len(),
                        #[cfg(test)]
                        origin.clone(),
                    )
                    .await
                else {
                    return (
                        provider,
                        contract.label,
                        Err(ClassifierClientError::InvalidRequest(
                            "quality prompt exceeds fanout byte budget".to_string(),
                        )),
                    );
                };
                let response = client
                    .classify_owned(
                        &contract.model,
                        prompt.to_string(),
                        #[cfg(test)]
                        &origin,
                    )
                    .await;
                (provider, contract.label, response)
            }
        });
        // Arm the shared deadline before any candidate starts. Individual
        // classifier RPCs use the same configured timeout, so a regular
        // `timeout(join_all(...))` can poll newly completed inner timeouts
        // first and admit queued candidates at the outer deadline. Deadline
        // precedence prevents new prompt ownership once the shared fanout
        // budget has expired.
        let deadline = tokio::time::sleep(self.timeout);
        tokio::pin!(deadline);
        let results = tokio::select! {
            biased;
            () = &mut deadline => return None,
            results = futures::future::join_all(calls) => results,
        };

        let mut scores = Vec::with_capacity(results.len());
        for (provider, positive_label, response) in results {
            let response = match response {
                Ok(response) => response,
                Err(error) => {
                    tracing::debug!(
                        error = %error,
                        provider,
                        "configured quality classifier unavailable; preserving configured routing"
                    );
                    return None;
                }
            };
            let score = response
                .labels
                .iter()
                .find(|label| label.name == positive_label)
                .map(|label| label.score)?;
            scores.push(QualityScore { provider, score });
        }
        Some(scores)
    }
}

fn classifier_hook_security_config(
    config: &sbproxy_config::ClassifierHooksConfig,
) -> anyhow::Result<Option<ClassifierClientSecurityConfig>> {
    let tls = config
        .tls
        .as_ref()
        .map(|tls| {
            let ca_pem = tls
                .ca_pem
                .as_deref()
                .map(|reference| {
                    resolve_classifier_hook_secret_reference(
                        reference,
                        "proxy.classifier_hooks.tls.ca_pem",
                        CLASSIFIER_HOOK_MAX_PEM_BYTES,
                    )
                })
                .transpose()?;
            let client_identity = tls
                .client_identity
                .as_ref()
                .map(|identity| {
                    Ok::<_, anyhow::Error>(ClassifierClientIdentityConfig {
                        cert_pem: resolve_classifier_hook_secret_reference(
                            &identity.cert_pem,
                            "proxy.classifier_hooks.tls.client_identity.cert_pem",
                            CLASSIFIER_HOOK_MAX_PEM_BYTES,
                        )?,
                        key_pem: resolve_classifier_hook_secret_reference(
                            &identity.key_pem,
                            "proxy.classifier_hooks.tls.client_identity.key_pem",
                            CLASSIFIER_HOOK_MAX_PEM_BYTES,
                        )?,
                    })
                })
                .transpose()?;
            Ok::<_, anyhow::Error>(ClassifierClientTlsConfig {
                ca_pem,
                server_name: tls.server_name.clone(),
                client_identity,
            })
        })
        .transpose()?;
    let authentication = config
        .authentication
        .as_ref()
        .map(|authentication| -> anyhow::Result<_> {
            match authentication {
                sbproxy_config::ClassifierHooksAuthenticationConfig::Bearer {
                    credential,
                    header,
                    scheme,
                } => Ok(ClassifierClientAuthenticationConfig::Bearer {
                    credential: resolve_classifier_hook_secret_reference(
                        credential,
                        "proxy.classifier_hooks.authentication.credential",
                        CLASSIFIER_HOOK_MAX_AUTH_BYTES,
                    )?,
                    header: header.clone(),
                    scheme: scheme.clone(),
                }),
            }
        })
        .transpose()?;
    if tls.is_none() && authentication.is_none() {
        return Ok(None);
    }
    Ok(Some(ClassifierClientSecurityConfig {
        tls,
        authentication,
    }))
}

/// Compile stock classifier hooks from operator configuration without
/// dialing the sidecar. URI and resource-bound validation is eager; network
/// availability remains fail-open on each request.
pub(crate) fn hooks_from_config(
    config: Option<&sbproxy_config::ClassifierHooksConfig>,
    egress: Option<&EgressAuthorizer>,
) -> anyhow::Result<Hooks> {
    let Some(config) = config else {
        return Ok(Hooks::default());
    };
    config.validate()?;
    ClassifierClient::validate_endpoint(&config.endpoint)
        .map_err(|error| anyhow::anyhow!("proxy.classifier_hooks.endpoint: {error}"))?;

    let timeout = Duration::from_millis(config.timeout_ms);
    let security = classifier_hook_security_config(config)?;
    let client = Arc::new(LazyClassifierClient::new(
        config.endpoint.clone(),
        timeout,
        egress.cloned(),
        security,
    ));
    let intent_detection = config.intent.as_ref().map(|intent| {
        Arc::new(StockClassifierIntentHook {
            client: Arc::clone(&client),
            model: intent.model.clone(),
        }) as Arc<dyn IntentDetectionHook>
    });
    let quality_scoring = config.quality.as_ref().map(|quality| {
        Arc::new(ClassifierQualityHook {
            client,
            timeout,
            minimum_score: quality.minimum_score,
            provider_models: quality.provider_models.clone(),
        }) as Arc<dyn QualityScoringHook>
    });

    Ok(Hooks {
        intent_detection,
        quality_scoring,
        ..Hooks::default()
    })
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn no_sidecar_configured_runs_heuristic_directly() {
        let hook = ClassifierIntentHook::new(None, "intent");
        assert!(!hook.has_sidecar_configured());
        assert_eq!(
            hook.detect("please help me debug this function").await,
            Some(IntentCategory::Coding)
        );
        assert_eq!(
            hook.detect("what is the capital of France?").await,
            Some(IntentCategory::General)
        );
    }

    /// A configured-but-unreachable sidecar (a refused connection on a
    /// dead loopback port, exactly the fallback.rs pattern this hook
    /// wraps) degrades to the heuristic rather than returning `None`
    /// outright, so a broken sidecar makes intent detection revert to
    /// the OSS default instead of going silent.
    #[tokio::test]
    async fn unreachable_sidecar_degrades_to_heuristic() {
        // Port 1 is a privileged port nothing in a test sandbox is
        // listening on; `connect_lazy` never dials until the first RPC,
        // so building the client here cannot itself fail.
        let dead_client =
            ClassifierClient::connect_lazy("http://127.0.0.1:1", Duration::from_millis(200))
                .expect("lazy client construction does not dial");
        let hook = ClassifierIntentHook::new(Some(dead_client), "intent");
        assert!(hook.has_sidecar_configured());
        assert_eq!(
            hook.detect("please implement a binary search").await,
            Some(IntentCategory::Coding)
        );
    }

    #[test]
    fn label_round_trips_every_category() {
        for category in [
            IntentCategory::Coding,
            IntentCategory::Vision,
            IntentCategory::Analysis,
            IntentCategory::Summarization,
            IntentCategory::General,
        ] {
            assert_eq!(category_from_label(intent_label(category)), Some(category));
        }
    }

    #[test]
    fn unrecognized_label_declines_rather_than_guessing() {
        assert_eq!(category_from_label("spam"), None);
        assert_eq!(category_from_label(""), None);
    }

    #[test]
    fn heuristic_adapter_produces_a_recognized_label() {
        let verdict = IntentHeuristic.classify("summarize this article for me");
        assert_eq!(verdict.label, "summarization");
        assert_eq!(
            category_from_label(&verdict.label),
            Some(IntentCategory::Summarization)
        );
    }

    /// The counting-in-process pattern from
    /// `sbproxy-classifier-client/src/fallback.rs`'s own tests, applied
    /// at this hook's level rather than `FallbackClassifier`'s: proves
    /// the degrade path actually runs the heuristic exactly once per
    /// call when the sidecar is unreachable, rather than merely
    /// returning a plausible-looking category.
    #[tokio::test]
    async fn degrade_path_invokes_heuristic_exactly_once() {
        struct CountingHeuristic(Arc<AtomicUsize>);
        impl InProcessClassifier for CountingHeuristic {
            fn classify(&self, text: &str) -> Verdict {
                self.0.fetch_add(1, Ordering::SeqCst);
                let category: IntentCategory = detect_intent_heuristic(text).into();
                Verdict {
                    label: intent_label(category).to_string(),
                    score: 1.0,
                }
            }
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let dead_client =
            ClassifierClient::connect_lazy("http://127.0.0.1:1", Duration::from_millis(200))
                .expect("lazy client construction does not dial");
        let inner = FallbackClassifier::new(
            Some(dead_client),
            "intent",
            CountingHeuristic(Arc::clone(&calls)),
        );
        let verdict = inner.classify("describe this screenshot").await;
        assert_eq!(verdict.label, "vision");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    fn quality_only_config() -> sbproxy_config::ClassifierHooksConfig {
        sbproxy_config::ClassifierHooksConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            timeout_ms: 100,
            tls: None,
            authentication: None,
            intent: None,
            quality: Some(sbproxy_config::ClassifierQualityHookConfig {
                minimum_score: 0.75,
                provider_models: HashMap::new(),
            }),
        }
    }

    fn assert_secret_limit_error(error: anyhow::Error, field: &str, maximum: usize) {
        let message = format!("{error:#}");
        assert!(message.contains(field), "{message}");
        assert!(
            message.contains(&format!("{maximum}-byte limit")),
            "{message}"
        );
    }

    #[test]
    fn classifier_hook_security_config_bounds_auth_credentials_from_env() {
        let variable = "SBPROXY_CLASSIFIER_HOOK_TOKEN_BOUND";
        let exact = "t".repeat(CLASSIFIER_HOOK_MAX_AUTH_BYTES);
        let mut config = quality_only_config();
        config.authentication = Some(
            sbproxy_config::ClassifierHooksAuthenticationConfig::Bearer {
                credential: format!("env:{variable}"),
                header: "authorization".to_string(),
                scheme: "Bearer".to_string(),
            },
        );
        {
            let _env = crate::test_env::EnvVarGuard::set(&[(variable, Some(exact.as_str()))]);
            let security = classifier_hook_security_config(&config)
                .expect("exact token bound must be accepted");
            let Some(ClassifierClientSecurityConfig {
                authentication:
                    Some(ClassifierClientAuthenticationConfig::Bearer { credential, .. }),
                ..
            }) = security
            else {
                panic!("expected bearer authentication");
            };
            assert_eq!(credential.len(), CLASSIFIER_HOOK_MAX_AUTH_BYTES);
        }

        let oversized = "t".repeat(CLASSIFIER_HOOK_MAX_AUTH_BYTES + 1);
        let _env = crate::test_env::EnvVarGuard::set(&[(variable, Some(oversized.as_str()))]);
        let error = classifier_hook_security_config(&config).unwrap_err();
        assert_secret_limit_error(
            error,
            "proxy.classifier_hooks.authentication.credential",
            CLASSIFIER_HOOK_MAX_AUTH_BYTES,
        );
    }

    #[test]
    fn classifier_hook_security_config_bounds_auth_credentials_from_file_and_provider() {
        let exact_file = tempfile::NamedTempFile::new().expect("temp token file");
        std::fs::write(
            exact_file.path(),
            "f".repeat(CLASSIFIER_HOOK_MAX_AUTH_BYTES),
        )
        .expect("write exact token file");
        let mut config = quality_only_config();
        config.authentication = Some(
            sbproxy_config::ClassifierHooksAuthenticationConfig::Bearer {
                credential: format!("file:{}", exact_file.path().display()),
                header: "authorization".to_string(),
                scheme: "Bearer".to_string(),
            },
        );
        classifier_hook_security_config(&config).expect("exact file token bound must be accepted");

        let over_file = tempfile::NamedTempFile::new().expect("temp oversized token file");
        std::fs::write(
            over_file.path(),
            "f".repeat(CLASSIFIER_HOOK_MAX_AUTH_BYTES + 1),
        )
        .expect("write oversized token file");
        config.authentication = Some(
            sbproxy_config::ClassifierHooksAuthenticationConfig::Bearer {
                credential: format!("file:{}", over_file.path().display()),
                header: "authorization".to_string(),
                scheme: "Bearer".to_string(),
            },
        );
        let error = classifier_hook_security_config(&config).unwrap_err();
        assert_secret_limit_error(
            error,
            "proxy.classifier_hooks.authentication.credential",
            CLASSIFIER_HOOK_MAX_AUTH_BYTES,
        );

        sbproxy_vault::reset_process_resolver_for_test();
        let vault = sbproxy_vault::LocalVault::new();
        vault
            .set_secret("token", &"p".repeat(CLASSIFIER_HOOK_MAX_AUTH_BYTES))
            .expect("store exact provider token");
        let mut manager = sbproxy_vault::VaultManager::new();
        manager.register("fixture", Box::new(vault));
        sbproxy_vault::install_process_resolver(Arc::new(
            sbproxy_vault::SecretResolver::new().with_manager(Arc::new(manager)),
        ));
        config.authentication = Some(
            sbproxy_config::ClassifierHooksAuthenticationConfig::Bearer {
                credential: "secret://fixture/token".to_string(),
                header: "authorization".to_string(),
                scheme: "Bearer".to_string(),
            },
        );
        classifier_hook_security_config(&config)
            .expect("exact provider token bound must be accepted");
        sbproxy_vault::reset_process_resolver_for_test();

        let vault = sbproxy_vault::LocalVault::new();
        vault
            .set_secret("token", &"p".repeat(CLASSIFIER_HOOK_MAX_AUTH_BYTES + 1))
            .expect("store oversized provider token");
        let mut manager = sbproxy_vault::VaultManager::new();
        manager.register("fixture", Box::new(vault));
        sbproxy_vault::install_process_resolver(Arc::new(
            sbproxy_vault::SecretResolver::new().with_manager(Arc::new(manager)),
        ));
        let error = classifier_hook_security_config(&config).unwrap_err();
        assert_secret_limit_error(
            error,
            "proxy.classifier_hooks.authentication.credential",
            CLASSIFIER_HOOK_MAX_AUTH_BYTES,
        );
        sbproxy_vault::reset_process_resolver_for_test();
    }

    #[test]
    fn classifier_hook_security_config_bounds_tls_pem_material() {
        let exact_pem = tempfile::NamedTempFile::new().expect("temp pem file");
        exact_pem
            .as_file()
            .write_all(&vec![b'c'; CLASSIFIER_HOOK_MAX_PEM_BYTES])
            .expect("write exact pem file");
        let mut config = quality_only_config();
        config.tls = Some(sbproxy_config::ClassifierHooksTlsConfig {
            ca_pem: Some(format!("file:{}", exact_pem.path().display())),
            server_name: None,
            client_identity: None,
        });
        classifier_hook_security_config(&config).expect("exact PEM bound must be accepted");

        let over_pem = tempfile::NamedTempFile::new().expect("temp oversized pem file");
        over_pem
            .as_file()
            .write_all(&vec![b'c'; CLASSIFIER_HOOK_MAX_PEM_BYTES + 1])
            .expect("write oversized pem file");
        config.tls = Some(sbproxy_config::ClassifierHooksTlsConfig {
            ca_pem: Some(format!("file:{}", over_pem.path().display())),
            server_name: None,
            client_identity: None,
        });
        let error = classifier_hook_security_config(&config).unwrap_err();
        assert_secret_limit_error(
            error,
            "proxy.classifier_hooks.tls.ca_pem",
            CLASSIFIER_HOOK_MAX_PEM_BYTES,
        );
    }

    #[tokio::test]
    async fn quality_hook_shares_pre_rpc_prompt_storage_across_candidates() {
        let _fanout_probe = QualityFanoutProbe::acquire_unique().await;
        const CANDIDATES: usize = 16;
        let mut provider_models = HashMap::new();
        let candidate_providers = (0..CANDIDATES)
            .map(|index| {
                let provider = format!("provider-{index}");
                provider_models.insert(
                    provider.clone(),
                    sbproxy_config::ClassifierProviderModelConfig {
                        model: format!("quality-{index}"),
                        label: "suitable".to_string(),
                    },
                );
                provider
            })
            .collect();
        let config = sbproxy_config::ClassifierHooksConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            timeout_ms: 100,
            tls: None,
            authentication: None,
            intent: None,
            quality: Some(sbproxy_config::ClassifierQualityHookConfig {
                minimum_score: 0.75,
                provider_models,
            }),
        };
        let hook = hooks_from_config(Some(&config), None)
            .unwrap()
            .quality_scoring
            .expect("quality hook configured");
        let request = QualityRequest {
            origin: "ai.example".to_string(),
            model_id: Some("model-a".to_string()),
            prompt: "large prompt ".repeat(64 * 1024),
            candidate_providers,
        };

        let pointers = QUALITY_PROMPT_STORAGE
            .scope(std::cell::RefCell::new(Vec::new()), async {
                let result = hook.score_providers(&request).await;
                assert!(
                    result.is_none(),
                    "dead sidecar must preserve configured routing"
                );
                QUALITY_PROMPT_STORAGE.with(|seen| seen.borrow().clone())
            })
            .await;
        assert_eq!(pointers.len(), CANDIDATES);
        let distinct: HashSet<_> = pointers.into_iter().collect();
        assert_eq!(
            distinct.len(),
            1,
            "quality candidates must borrow or share one full prompt allocation"
        );
    }

    struct HoldingInferenceState {
        active: AtomicUsize,
        peak_active: AtomicUsize,
        live_prompt_bytes: AtomicUsize,
        peak_prompt_bytes: AtomicUsize,
        total_calls: AtomicUsize,
        small_release: tokio::sync::Semaphore,
        large_release: tokio::sync::Semaphore,
    }

    impl HoldingInferenceState {
        fn new() -> Self {
            Self {
                active: AtomicUsize::new(0),
                peak_active: AtomicUsize::new(0),
                live_prompt_bytes: AtomicUsize::new(0),
                peak_prompt_bytes: AtomicUsize::new(0),
                total_calls: AtomicUsize::new(0),
                small_release: tokio::sync::Semaphore::new(0),
                large_release: tokio::sync::Semaphore::new(0),
            }
        }

        fn hold(self: &Arc<Self>, text: String) -> HeldProtoRequest {
            let bytes = text.len();
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak_active.fetch_max(active, Ordering::SeqCst);
            let live_bytes = self.live_prompt_bytes.fetch_add(bytes, Ordering::SeqCst) + bytes;
            self.peak_prompt_bytes
                .fetch_max(live_bytes, Ordering::SeqCst);
            self.total_calls.fetch_add(1, Ordering::SeqCst);
            HeldProtoRequest {
                state: Arc::clone(self),
                text,
            }
        }

        async fn wait_for_active(&self, expected: usize, within: Duration) -> Result<(), ()> {
            let deadline = tokio::time::Instant::now() + within;
            loop {
                if self.active.load(Ordering::SeqCst) == expected {
                    return Ok(());
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(());
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }

        async fn wait_for_total_calls_at_least(
            &self,
            expected: usize,
            within: Duration,
        ) -> Result<(), ()> {
            let deadline = tokio::time::Instant::now() + within;
            loop {
                if self.total_calls.load(Ordering::SeqCst) >= expected {
                    return Ok(());
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(());
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }

    struct HeldProtoRequest {
        state: Arc<HoldingInferenceState>,
        text: String,
    }

    impl Drop for HeldProtoRequest {
        fn drop(&mut self) {
            self.state.active.fetch_sub(1, Ordering::SeqCst);
            self.state
                .live_prompt_bytes
                .fetch_sub(self.text.len(), Ordering::SeqCst);
        }
    }

    #[derive(Clone)]
    struct HoldingInference(Arc<HoldingInferenceState>);

    #[tonic::async_trait]
    impl sbproxy_classifier_proto::InferenceService for HoldingInference {
        async fn classify(
            &self,
            request: tonic::Request<sbproxy_classifier_proto::ClassifyRequest>,
        ) -> Result<tonic::Response<sbproxy_classifier_proto::ClassifyResponse>, tonic::Status>
        {
            let request = request.into_inner();
            let score = request
                .model
                .strip_prefix("quality-")
                .and_then(|index| index.parse::<usize>().ok())
                .map(|index| 0.5 + index as f64 / 100.0)
                .unwrap_or(0.5);
            let held = self.0.hold(request.text);
            let release = if held.text.len() <= 384 * 1024 {
                &self.0.small_release
            } else {
                &self.0.large_release
            };
            let permit = release
                .acquire()
                .await
                .map_err(|_| tonic::Status::unavailable("test release closed"))?;
            permit.forget();
            drop(held);
            Ok(tonic::Response::new(
                sbproxy_classifier_proto::ClassifyResponse {
                    labels: vec![sbproxy_classifier_proto::Label {
                        name: "suitable".to_string(),
                        score,
                    }],
                    latency_us: 1,
                },
            ))
        }

        async fn embed(
            &self,
            _request: tonic::Request<sbproxy_classifier_proto::EmbedRequest>,
        ) -> Result<tonic::Response<sbproxy_classifier_proto::EmbedResponse>, tonic::Status>
        {
            Err(tonic::Status::unimplemented("not used by quality test"))
        }

        async fn compress(
            &self,
            _request: tonic::Request<sbproxy_classifier_proto::CompressRequest>,
        ) -> Result<tonic::Response<sbproxy_classifier_proto::CompressResponse>, tonic::Status>
        {
            Err(tonic::Status::unimplemented("not used by quality test"))
        }

        async fn model_info(
            &self,
            _request: tonic::Request<sbproxy_classifier_proto::ModelInfoRequest>,
        ) -> Result<tonic::Response<sbproxy_classifier_proto::ModelInfoResponse>, tonic::Status>
        {
            Err(tonic::Status::unimplemented("not used by quality test"))
        }

        async fn version(
            &self,
            _request: tonic::Request<sbproxy_classifier_proto::VersionRequest>,
        ) -> Result<tonic::Response<sbproxy_classifier_proto::VersionResponse>, tonic::Status>
        {
            Err(tonic::Status::unimplemented("not used by quality test"))
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quality_hook_bounds_real_downstream_protobuf_prompt_high_water() {
        const CANDIDATES_PER_HOOK: usize = 6;
        const TOTAL_CANDIDATES: usize = 2 * CANDIDATES_PER_HOOK;
        const MAX_CALLS: usize = 8;
        const MAX_LIVE_COPIES: usize = 4;
        const FANOUT_BYTE_BUDGET: usize = 1024 * 1024;
        const LARGE_PROMPT_BYTES: usize = 768 * 1024;
        const SMALL_PROMPT_BYTES: usize = 384 * 1024;
        const MAX_PROMPT_BYTES: usize = 1024 * 1024;
        assert_eq!(quality_fanout_limits().max_concurrent_calls(), MAX_CALLS);
        assert_eq!(
            quality_fanout_limits().max_live_prompt_bytes(),
            FANOUT_BYTE_BUDGET
        );
        assert_eq!(quality_fanout_limits().max_prompt_bytes(), MAX_PROMPT_BYTES);

        // This production probe attaches to the constructor that creates the
        // leased `ClassifyRequest.text`, not to the earlier borrowed prompt.
        // It observes the actual lease -> ownership -> dial sequence without
        // supplying an alternate handler/client path.
        let ownership_probe = QualityFanoutProbe::acquire_unique().await;
        let state = Arc::new(HoldingInferenceState::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_state = Arc::clone(&state);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(sbproxy_classifier_proto::InferenceServiceServer::new(
                    HoldingInference(server_state),
                ))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async move {
                        let _ = shutdown_rx.await;
                    },
                )
                .await
        });

        let mut provider_models = HashMap::new();
        let candidate_providers = (0..TOTAL_CANDIDATES)
            .map(|index| {
                let provider = format!("provider-{index}");
                provider_models.insert(
                    provider.clone(),
                    sbproxy_config::ClassifierProviderModelConfig {
                        model: format!("quality-{index}"),
                        label: "suitable".to_string(),
                    },
                );
                provider
            })
            .collect::<Vec<_>>();
        let config = sbproxy_config::ClassifierHooksConfig {
            endpoint: format!("http://{address}"),
            timeout_ms: 5_000,
            tls: None,
            authentication: None,
            intent: None,
            quality: Some(sbproxy_config::ClassifierQualityHookConfig {
                minimum_score: 0.75,
                provider_models,
            }),
        };
        let first_hook = hooks_from_config(Some(&config), None)
            .unwrap()
            .quality_scoring
            .expect("first quality hook configured");
        let second_hook = hooks_from_config(Some(&config), None)
            .unwrap()
            .quality_scoring
            .expect("second quality hook configured");

        let calls_before_oversize = state.total_calls.load(Ordering::SeqCst);
        let allocations_before_oversize = ownership_probe.total_prompt_owners();
        let oversized_result = tokio::time::timeout(
            Duration::from_secs(3),
            first_hook.score_providers(&QualityRequest {
                origin: "oversized.example".to_string(),
                model_id: Some("model-a".to_string()),
                prompt: "o".repeat(MAX_PROMPT_BYTES + 1),
                candidate_providers: candidate_providers[..CANDIDATES_PER_HOOK].to_vec(),
            }),
        )
        .await
        .expect("oversized fanout refusal is bounded");
        assert!(oversized_result.is_none(), "oversized fanout fails open");
        assert_eq!(
            state.total_calls.load(Ordering::SeqCst),
            calls_before_oversize
        );
        assert_eq!(
            ownership_probe.total_prompt_owners(),
            allocations_before_oversize,
            "oversized input is rejected before protobuf ownership"
        );
        assert_eq!(
            ownership_probe.dials_for_origin("oversized.example"),
            0,
            "oversized input must not dial the sidecar"
        );

        ownership_probe.reset_high_water();
        let first_providers = candidate_providers[..CANDIDATES_PER_HOOK].to_vec();
        let second_providers = candidate_providers[CANDIDATES_PER_HOOK..].to_vec();
        let expected_first = first_providers.clone();
        let expected_second = second_providers.clone();
        let second_score_task = tokio::spawn(async move {
            second_hook
                .score_providers(&QualityRequest {
                    origin: "second.example".to_string(),
                    model_id: Some("model-a".to_string()),
                    prompt: "q".repeat(SMALL_PROMPT_BYTES),
                    candidate_providers: second_providers,
                })
                .await
        });

        state
            .wait_for_active(2, Duration::from_secs(3))
            .await
            .expect("two 384 KiB protobuf requests fit concurrently in the one MiB owner");
        assert_eq!(
            state.live_prompt_bytes.load(Ordering::SeqCst),
            2 * SMALL_PROMPT_BYTES,
            "the accepted small-request control must exercise byte weighting, not count-one serialization"
        );

        let first_score_task = tokio::spawn(async move {
            first_hook
                .score_providers(&QualityRequest {
                    origin: "first.example".to_string(),
                    model_id: Some("model-a".to_string()),
                    prompt: "p".repeat(LARGE_PROMPT_BYTES),
                    candidate_providers: first_providers,
                })
                .await
        });
        ownership_probe
            .wait_for_origin_blocked_on_byte_budget("first.example", Duration::from_secs(3))
            .await
            .expect("a 768 KiB request cannot consume the 256 KiB remainder");
        let first_blocks_before_drain =
            ownership_probe.byte_budget_blocks_for_origin("first.example");
        assert_eq!(
            ownership_probe.dials_for_origin("first.example"),
            0,
            "the large request remains before allocation and dial while only 256 KiB is free"
        );
        let peak_active = state.peak_active.load(Ordering::SeqCst);
        let peak_prompt_bytes = state.peak_prompt_bytes.load(Ordering::SeqCst);
        assert_eq!(peak_active, 2);
        assert_eq!(peak_prompt_bytes, 2 * SMALL_PROMPT_BYTES);
        assert_eq!(
            ownership_probe.distinct_budget_owner_ids(),
            1,
            "independently built hooks share the same process fanout owner"
        );
        assert_eq!(
            ownership_probe.prompt_owners_without_prior_lease(),
            0,
            "the byte lease precedes every real ClassifyRequest.text allocation"
        );
        assert_eq!(
            ownership_probe.dials_without_prompt_lease(),
            0,
            "every dial remains inside the weighted prompt lease"
        );
        assert!(
            ownership_probe.peak_leased_prompt_bytes() <= FANOUT_BYTE_BUDGET,
            "weighted lease high-water exceeded its process budget"
        );
        assert!(
            ownership_probe.peak_owned_prompt_bytes() <= FANOUT_BYTE_BUDGET,
            "protobuf strings were allocated ahead of the weighted gate"
        );
        // Keep one small request live while admitting each queued small
        // candidate. If both initial requests are released together, the
        // intentionally non-FIFO weighted gate may admit a large request
        // first and this test would wait on the wrong release semaphore.
        for expected_total_calls in 3..=CANDIDATES_PER_HOOK {
            state.small_release.add_permits(1);
            state
                .wait_for_total_calls_at_least(expected_total_calls, Duration::from_secs(3))
                .await
                .expect("the next small candidate is admitted before releasing another");
        }
        state.small_release.add_permits(2);
        let second_scores = tokio::time::timeout(Duration::from_secs(3), second_score_task)
            .await
            .expect("all small-prompt candidate calls finish")
            .unwrap()
            .expect("every small-prompt classifier response is accepted");
        state
            .wait_for_active(1, Duration::from_secs(3))
            .await
            .expect("after the small origin drains exactly one 768 KiB protobuf body is live");
        assert_eq!(
            state.live_prompt_bytes.load(Ordering::SeqCst),
            LARGE_PROMPT_BYTES,
            "a global count-two mutation would hold two large bodies and exceed one MiB"
        );
        ownership_probe
            .wait_for_origin_byte_budget_blocks(
                "first.example",
                first_blocks_before_drain + 1,
                Duration::from_secs(3),
            )
            .await
            .expect("the next large candidate remains pre-allocation behind the first");
        state.large_release.add_permits(CANDIDATES_PER_HOOK);
        let first_scores = tokio::time::timeout(Duration::from_secs(3), first_score_task)
            .await
            .expect("all large-prompt candidate calls finish")
            .unwrap()
            .expect("every large-prompt classifier response is accepted");
        let total_calls = state.total_calls.load(Ordering::SeqCst);
        let final_peak_active = state.peak_active.load(Ordering::SeqCst);
        let final_peak_prompt_bytes = state.peak_prompt_bytes.load(Ordering::SeqCst);
        let final_peak_leased_prompt_bytes = ownership_probe.peak_leased_prompt_bytes();
        let final_peak_owned_prompt_bytes = ownership_probe.peak_owned_prompt_bytes();

        state
            .wait_for_active(0, Duration::from_secs(3))
            .await
            .expect("all downstream response children exit before listener cleanup");
        assert_eq!(state.live_prompt_bytes.load(Ordering::SeqCst), 0);
        assert!(
            !server.is_finished(),
            "local downstream listener exited before explicit cleanup"
        );
        shutdown_tx
            .send(())
            .expect("local downstream shutdown receiver remains owned");
        let server_join = tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .expect("local downstream server joins before its cleanup deadline")
            .expect("local downstream listener task must not panic");
        server_join.expect("local downstream listener reports clean graceful shutdown");

        assert_eq!(total_calls, TOTAL_CANDIDATES);
        assert_eq!(
            first_scores
                .iter()
                .map(|score| score.provider.as_str())
                .collect::<Vec<_>>(),
            expected_first
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            "bounded unordered execution must restore first-hook candidate order"
        );
        assert_eq!(
            second_scores
                .iter()
                .map(|score| score.provider.as_str())
                .collect::<Vec<_>>(),
            expected_second
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            "bounded unordered execution must restore second-hook candidate order"
        );
        assert!(
            final_peak_active <= MAX_LIVE_COPIES,
            "{final_peak_active} decoded protobuf prompt copies were live; maximum is {MAX_LIVE_COPIES}"
        );
        assert!(
            final_peak_prompt_bytes <= FANOUT_BYTE_BUDGET,
            "{final_peak_prompt_bytes} unequal live prompt bytes exceeded the weighted downstream budget"
        );
        assert!(final_peak_leased_prompt_bytes <= FANOUT_BYTE_BUDGET);
        assert!(final_peak_owned_prompt_bytes <= FANOUT_BYTE_BUDGET);
        assert_eq!(ownership_probe.total_prompt_owners(), TOTAL_CANDIDATES);
        assert_eq!(
            ownership_probe.total_prompt_owners_for_origin("first.example"),
            CANDIDATES_PER_HOOK
        );
        assert_eq!(
            ownership_probe.total_prompt_owners_for_origin("second.example"),
            CANDIDATES_PER_HOOK
        );
        ownership_probe.assert_every_owner_released_exactly_once();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quality_fanout_admits_feasible_calls_without_cross_resource_hold_and_wait() {
        const LARGE_PROMPT_BYTES: usize = 768 * 1024;
        const SMALL_PROMPT_BYTES: usize = 256 * 1024;
        const BLOCKED_LARGE_CALLS: usize = 7;

        let ownership_probe = QualityFanoutProbe::acquire_unique().await;
        let runtime = QualityFanoutRuntime::shared();
        let large_lease = runtime
            .acquire(LARGE_PROMPT_BYTES, "large-owner.example".to_string())
            .await
            .expect("the first large prompt fits");

        let mut blocked = Vec::with_capacity(BLOCKED_LARGE_CALLS);
        for _ in 0..BLOCKED_LARGE_CALLS {
            blocked.push(tokio::spawn(async {
                QualityFanoutRuntime::shared()
                    .acquire(LARGE_PROMPT_BYTES, "large-waiters.example".to_string())
                    .await
            }));
        }
        ownership_probe
            .wait_for_origin_byte_budget_blocks(
                "large-waiters.example",
                BLOCKED_LARGE_CALLS,
                Duration::from_secs(3),
            )
            .await
            .expect("every additional large call waits on bytes without owning call capacity");

        let small_lease = tokio::time::timeout(
            Duration::from_secs(3),
            runtime.acquire(SMALL_PROMPT_BYTES, "small-owner.example".to_string()),
        )
        .await
        .expect("a feasible small call is not starved by byte waiters")
        .expect("the small prompt fits exactly in the remaining budget");
        assert_eq!(
            ownership_probe.current_leased_prompt_bytes(),
            quality_fanout_limits().max_live_prompt_bytes()
        );
        assert_eq!(ownership_probe.current_call_leases(), 2);

        for waiter in blocked {
            waiter.abort();
            match waiter.await {
                Err(error) => assert!(error.is_cancelled()),
                Ok(_) => panic!("cancelled byte waiter must not acquire a lease"),
            }
        }
        drop(small_lease);
        drop(large_lease);
        ownership_probe
            .wait_for_no_live_leases(Duration::from_secs(3))
            .await
            .expect("mixed-size admission returns all capacity");
        ownership_probe.assert_every_weighted_lease_released_exactly_once();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quality_hook_timeout_returns_weighted_leases_and_full_capacity_recovers() {
        const CANDIDATES: usize = 6;
        const FANOUT_BYTE_BUDGET: usize = 1024 * 1024;
        const MAX_CALLS: usize = 8;
        const MAX_RECOVERY_ACTIVE_CALLS: usize = 4;
        const TIMED_PROMPT_BYTES: usize = 384 * 1024;
        const RECOVERY_PROMPT_BYTES: usize = 256 * 1024;

        fn config(
            endpoint: String,
            timeout_ms: u64,
            candidate_providers: &[String],
        ) -> sbproxy_config::ClassifierHooksConfig {
            let provider_models = candidate_providers
                .iter()
                .enumerate()
                .map(|(index, provider)| {
                    (
                        provider.clone(),
                        sbproxy_config::ClassifierProviderModelConfig {
                            model: format!("quality-{index}"),
                            label: "suitable".to_string(),
                        },
                    )
                })
                .collect();
            sbproxy_config::ClassifierHooksConfig {
                endpoint,
                timeout_ms,
                tls: None,
                authentication: None,
                intent: None,
                quality: Some(sbproxy_config::ClassifierQualityHookConfig {
                    minimum_score: 0.75,
                    provider_models,
                }),
            }
        }

        let ownership_probe = QualityFanoutProbe::acquire_unique().await;
        let state = Arc::new(HoldingInferenceState::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_state = Arc::clone(&state);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(sbproxy_classifier_proto::InferenceServiceServer::new(
                    HoldingInference(server_state),
                ))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async move {
                        let _ = shutdown_rx.await;
                    },
                )
                .await
        });
        let candidate_providers = (0..CANDIDATES)
            .map(|index| format!("provider-{index}"))
            .collect::<Vec<_>>();

        let timeout_hook = hooks_from_config(
            Some(&config(
                format!("http://{address}"),
                5_000,
                &candidate_providers,
            )),
            None,
        )
        .unwrap()
        .quality_scoring
        .unwrap();
        let timed_candidates = candidate_providers.clone();
        let timed = tokio::spawn(async move {
            timeout_hook
                .score_providers(&QualityRequest {
                    origin: "timeout.example".to_string(),
                    model_id: Some("model-a".to_string()),
                    prompt: "t".repeat(TIMED_PROMPT_BYTES),
                    candidate_providers: timed_candidates,
                })
                .await
        });
        state
            .wait_for_active(2, Duration::from_secs(3))
            .await
            .expect("two weighted requests are live beyond the shared hook timeout");
        assert_eq!(
            state.live_prompt_bytes.load(Ordering::SeqCst),
            2 * TIMED_PROMPT_BYTES
        );
        assert_eq!(
            ownership_probe.current_leased_prompt_bytes(),
            2 * TIMED_PROMPT_BYTES
        );
        assert_eq!(
            ownership_probe.current_owned_prompt_bytes(),
            2 * TIMED_PROMPT_BYTES
        );

        let timed_result = tokio::time::timeout(Duration::from_secs(7), timed)
            .await
            .expect("the shared quality-hook timeout has one outer deadline")
            .expect("the timed quality task does not panic");
        assert!(
            timed_result.is_none(),
            "quality timeout preserves fail-open policy"
        );
        state
            .wait_for_active(0, Duration::from_secs(3))
            .await
            .expect("cancelling the timed hook drops every real downstream handler");
        ownership_probe
            .wait_for_no_live_leases(Duration::from_secs(3))
            .await
            .expect("timeout cancellation returns every weighted process lease");
        assert_eq!(ownership_probe.current_leased_prompt_bytes(), 0);
        assert_eq!(ownership_probe.current_owned_prompt_bytes(), 0);
        assert_eq!(ownership_probe.current_call_leases(), 0);
        assert_eq!(ownership_probe.available_call_permits(), MAX_CALLS);
        assert_eq!(ownership_probe.available_prompt_bytes(), FANOUT_BYTE_BUDGET);
        assert_eq!(
            ownership_probe.total_prompt_owners_for_origin("timeout.example"),
            2,
            "blocked candidates must be cancelled before protobuf ownership"
        );

        let recovery_hook = hooks_from_config(
            Some(&config(
                format!("http://{address}"),
                10_000,
                &candidate_providers,
            )),
            None,
        )
        .unwrap()
        .quality_scoring
        .unwrap();
        let recovery_candidates = candidate_providers.clone();
        let recovery = tokio::spawn(async move {
            recovery_hook
                .score_providers(&QualityRequest {
                    origin: "recovery.example".to_string(),
                    model_id: Some("model-a".to_string()),
                    prompt: "r".repeat(RECOVERY_PROMPT_BYTES),
                    candidate_providers: recovery_candidates,
                })
                .await
        });
        state
            .wait_for_active(MAX_RECOVERY_ACTIVE_CALLS, Duration::from_secs(3))
            .await
            .expect("the next hook reuses the full one-MiB byte budget without shrinking the global call budget");
        assert_eq!(
            state.live_prompt_bytes.load(Ordering::SeqCst),
            FANOUT_BYTE_BUDGET
        );
        assert_eq!(
            ownership_probe.current_leased_prompt_bytes(),
            FANOUT_BYTE_BUDGET
        );
        state.small_release.add_permits(CANDIDATES);
        let recovered = tokio::time::timeout(Duration::from_secs(3), recovery)
            .await
            .expect("post-timeout full-capacity hook has one outer deadline")
            .expect("post-timeout quality task does not panic")
            .expect("post-timeout hook evaluates every candidate");
        assert_eq!(recovered.len(), CANDIDATES);
        state
            .wait_for_active(0, Duration::from_secs(3))
            .await
            .expect("every recovered downstream response child exits");
        ownership_probe
            .wait_for_no_live_leases(Duration::from_secs(3))
            .await
            .expect("recovery also returns every weighted lease");
        assert_eq!(ownership_probe.available_call_permits(), MAX_CALLS);
        assert_eq!(ownership_probe.available_prompt_bytes(), FANOUT_BYTE_BUDGET);
        assert_eq!(
            ownership_probe.total_prompt_owners_for_origin("recovery.example"),
            CANDIDATES
        );
        ownership_probe.assert_every_owner_released_exactly_once();
        ownership_probe.assert_every_weighted_lease_released_exactly_once();
        assert_eq!(state.live_prompt_bytes.load(Ordering::SeqCst), 0);
        assert!(
            !server.is_finished(),
            "timeout fixture listener exited before explicit cleanup"
        );
        shutdown_tx
            .send(())
            .expect("timeout fixture shutdown receiver remains owned");
        let join = tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .expect("timeout fixture listener joins before cleanup deadline")
            .expect("timeout fixture listener task must not panic");
        join.expect("timeout fixture listener reports clean graceful shutdown");
    }

    // --- Weighted-lease accounting under a double release and a poisoned lock ---

    #[derive(Clone)]
    struct CapturedErrors(Arc<Mutex<Vec<u8>>>);

    struct CapturedErrorsGuard(Arc<Mutex<Vec<u8>>>);

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedErrors {
        type Writer = CapturedErrorsGuard;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedErrorsGuard(Arc::clone(&self.0))
        }
    }

    impl Write for CapturedErrorsGuard {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Run `body` with a local subscriber and return the `ERROR` lines it
    /// emitted, so a once-only report can be counted rather than eyeballed.
    fn capture_error_lines(body: impl FnOnce()) -> Vec<String> {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::ERROR)
            .with_writer(CapturedErrors(Arc::clone(&captured)))
            .finish();
        tracing::subscriber::with_default(subscriber, body);
        let bytes = captured
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        String::from_utf8(bytes)
            .expect("captured log is UTF-8")
            .lines()
            .filter(|line| line.contains("quality-fanout lease underflow"))
            .map(str::to_string)
            .collect()
    }

    /// A runtime of this test's own.
    ///
    /// `QualityFanoutRuntime::shared()` is a process-wide `OnceLock` whose
    /// mutex, once poisoned, stays poisoned for every later test in the
    /// binary. `release_weighted_lease` takes `&self` rather than
    /// `&'static self`, so these tests can drive it on an instance nobody
    /// else can see.
    fn isolated_runtime() -> QualityFanoutRuntime {
        QualityFanoutRuntime {
            byte_notify: Notify::new(),
            state: Mutex::new(QualityFanoutState::default()),
            owner_fingerprint: 0,
        }
    }

    /// Seed the production counters for exactly one live lease of
    /// `prompt_bytes`, with enough per-origin headroom that the test-only
    /// ledger survives a second release and leaves the production counters
    /// as the thing under test.
    fn seed_one_live_lease(runtime: &QualityFanoutRuntime, prompt_bytes: usize, origin: &str) {
        let mut state = runtime
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.leased_prompt_bytes = prompt_bytes;
        state.current_call_leases = 1;
        state.live_leases_by_origin.insert(origin.to_string(), 8);
    }

    #[test]
    fn releasing_a_weighted_lease_twice_saturates_instead_of_panicking() {
        // Pins two remedies at once. Restoring the
        // `.checked_sub(..).expect(..)` this replaced makes the second
        // release panic; so does putting the `debug_assert!` back, because
        // debug assertions are live in every non-release profile and this
        // path runs from `Drop`.
        const PROMPT_BYTES: usize = 64;
        let runtime = isolated_runtime();
        seed_one_live_lease(&runtime, PROMPT_BYTES, "origin-a");

        runtime.release_weighted_lease(PROMPT_BYTES, "origin-a");
        runtime.release_weighted_lease(PROMPT_BYTES, "origin-a");

        let state = runtime
            .state
            .lock()
            .expect("a saturating release must not poison the admission lock");
        assert_eq!(
            state.leased_prompt_bytes, 0,
            "byte accounting saturates at zero rather than underflowing"
        );
        assert_eq!(
            state.current_call_leases, 0,
            "lease accounting saturates at zero rather than underflowing"
        );
    }

    #[test]
    fn a_lease_underflow_reports_once_and_then_stays_quiet() {
        const PROMPT_BYTES: usize = 64;
        let runtime = isolated_runtime();
        seed_one_live_lease(&runtime, PROMPT_BYTES, "origin-a");
        runtime.release_weighted_lease(PROMPT_BYTES, "origin-a");

        // The `Once` behind the report is process-wide, so whether this
        // first underflow is the one that speaks depends on what else ran
        // in this binary. Bound it rather than pin it.
        let first =
            capture_error_lines(|| runtime.release_weighted_lease(PROMPT_BYTES, "origin-a"));
        assert!(
            first.len() <= 1,
            "the underflow report is once-only, saw {first:?}"
        );

        // By here the `Once` is spent no matter what ran before, so a
        // further underflow has to be silent. This is the half that fails
        // if the report is ever moved out from behind its `Once` and starts
        // writing a line per release on a hot path.
        let second =
            capture_error_lines(|| runtime.release_weighted_lease(PROMPT_BYTES, "origin-a"));
        assert!(
            second.is_empty(),
            "the once-only underflow report must not repeat, saw {second:?}"
        );
    }

    #[test]
    fn a_poisoned_admission_lock_is_recovered_rather_than_propagated() {
        const PROMPT_BYTES: usize = 64;
        let runtime = isolated_runtime();
        seed_one_live_lease(&runtime, PROMPT_BYTES, "origin-a");

        // Poison the lock the way a panicking writer on the request path
        // would. The hook swap keeps the deliberate panic from printing a
        // backtrace that reads like a failure; it is restored immediately.
        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = runtime
                .state
                .lock()
                .expect("a fresh runtime's lock is unpoisoned");
            panic!("simulated panic while holding the admission lock");
        }));
        std::panic::set_hook(previous_hook);

        assert!(panicked.is_err(), "the fixture must actually panic");
        // Bound and released explicitly: the poisoned `Err` still carries a
        // live guard, and holding it across the release below would deadlock
        // rather than fail.
        let poison_probe = runtime.state.lock();
        let is_poisoned = poison_probe.is_err();
        drop(poison_probe);
        assert!(
            is_poisoned,
            "the lock must really be poisoned or this test proves nothing"
        );

        // Admission recovers instead of inheriting the poison: one bug must
        // not become a standing outage for every quality-scored request.
        runtime.release_weighted_lease(PROMPT_BYTES, "origin-a");

        let state = runtime
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(
            state.leased_prompt_bytes, 0,
            "the recovered writer still returns the leased bytes"
        );
        assert_eq!(
            state.current_call_leases, 0,
            "the recovered writer still returns the lease slot"
        );
    }
}

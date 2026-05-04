// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Soap Bucket LLC

//! Identity, classification, and anomaly hook trait surface.
//!
//! These three traits are the seam between the request / response
//! filter chain and out-of-tree wiring (KYA verifier, ML agent
//! classifier, anomaly detector). The pipeline holds the per-request
//! inputs; registered hooks run inference / verification and write
//! verdicts back through these traits.
//!
//! ## Why a separate trait surface
//!
//! [`crate::traits`] owns the third-party plugin trait surface
//! ([`crate::traits::AuthProvider`], [`crate::traits::PolicyEnforcer`],
//! [`crate::traits::ActionHandler`], ...). Those traits speak to fields
//! the pipeline already exposes and are invoked by name through the
//! compiled handler chain. Identity / classifier / anomaly hooks are
//! different in two ways:
//!
//! 1. They run at fixed phases of the pipeline (resolver step 1.5,
//!    pre-policy, response phase) rather than being addressed by name
//!    from a YAML config block.
//! 2. They consume a curated snapshot of the per-request context
//!    rather than the raw `http::Request`, so the pipeline code that
//!    constructs the snapshot can keep this crate free of any
//!    cross-crate type dependency.
//!
//! Hook impls register through `inventory::submit!` or through the
//! runtime-installable slots below. The pipeline iterates registered
//! hooks at the matching phase; the first impl returning `Some(_)`
//! writes its verdict back to the per-request context, and the
//! iteration short-circuits.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// --- View types ---

/// Stable label describing where a resolver step's verdict came from.
///
/// Hook impls return one of:
///
/// - `"bot_auth"` - Web Bot Auth (cryptographic key-id).
/// - `"kya"` - Skyfire KYA token.
/// - `"rdns"` - Forward-confirmed reverse DNS.
/// - `"user_agent"` - User-Agent regex match.
/// - `"anonymous_bot_auth"` - Bot-auth signature with unknown keyid.
/// - `"tls_fingerprint"` - JA4-based headless detector.
/// - `"ml_override"` - ML classifier overrode the rule-based verdict.
/// - `"fallback"` - generic crawler / human fallback.
pub type AgentIdSourceLabel = &'static str;

/// Resolver verdict returned by an [`IdentityResolverHook`].
#[derive(Debug, Clone, Default)]
pub struct IdentityVerdict {
    /// Resolved agent identifier (`openai-gptbot`, `human`, ...).
    /// Empty string means "the hook ran but produced no agent_id";
    /// the pipeline iteration does NOT short-circuit on an empty
    /// `agent_id`, so a later resolver step can still match. The hook
    /// may still populate the diagnostic side-fields below
    /// (`kya_verdict`) so scripting layers (CEL / Lua / JS / WASM)
    /// can branch on them.
    pub agent_id: String,
    /// Stable source label to stamp into the per-request context's
    /// `agent_id_source` field. Empty when `agent_id` is also empty.
    pub agent_id_source: AgentIdSourceLabel,
    /// Optional KYA verdict label exposed to scripting under
    /// `request.kya.verdict`. The KYA verifier hook fills this even
    /// when `agent_id` is empty (e.g. `"missing"`, `"expired"`) so the
    /// operator's policy can branch on the verdict before any
    /// resolver step matches. `None` for non-KYA hooks.
    pub kya_verdict: Option<AgentIdSourceLabel>,
    /// Optional KYA agent vendor (e.g. `"skyfire"`) exposed to
    /// scripting under `request.kya.vendor`. Filled by the KYA
    /// verifier when a token verifies; `None` otherwise.
    pub kya_vendor: Option<String>,
    /// Optional KYA-token version (e.g. `"v1"`) exposed to scripting
    /// under `request.kya.kya_version`. Filled by the KYA verifier
    /// when a token verifies; `None` otherwise.
    pub kya_version: Option<String>,
    /// Optional KYAB advisory balance (smallest unit) exposed to
    /// scripting under `request.kya.kyab_balance`. The proxy itself
    /// does not act on this; CEL gates may. `None` when the token
    /// does not carry a balance.
    pub kya_kyab_balance: Option<u64>,
}

/// Per-request input the [`IdentityResolverHook`] reads.
///
/// Owned-borrow shape so the call site can construct one without
/// cloning the underlying request context. Hook impls hold the borrow
/// only for the duration of `resolve` and never escape it across an
/// await point that outlives the request.
pub struct IdentityRequest<'a> {
    /// Indirection over the request header bag. Used by verifiers
    /// that need a specific header (e.g. `X-Skyfire-KYA` for the KYA
    /// verifier).
    pub headers: &'a dyn IdentityHeaderLookup,
    /// Hostname the request targets (without port). Used by the KYA
    /// verifier's audience check.
    pub hostname: &'a str,
    /// `agent_id` already produced by an earlier resolver step (e.g.
    /// the bot-auth step). `None` when no earlier step matched.
    /// Hook impls use this to apply conflict-resolution rules
    /// (bot-auth wins over disagreeing KYA, etc.).
    pub prior_agent_id: Option<&'a str>,
}

/// Indirection over the request header bag so the trait stays free of
/// any concrete header-map type. The pipeline's request context
/// exposes its headers through this trait at the call site.
pub trait IdentityHeaderLookup: Send + Sync {
    /// Return the (first) value of the named header. Lookup is
    /// case-sensitive; callers normalise to lowercase on the way in.
    /// Returns `None` when the header is absent or the value is not
    /// valid UTF-8.
    fn get(&self, name: &str) -> Option<&str>;
}

/// Read-only view over the per-request context exposed to hooks that
/// run after the resolver chain (ML classifier, anomaly detector).
///
/// Constructed at the call site so this crate stays decoupled from
/// the pipeline's request-context type. New hooks add fields by
/// extending this struct, not by widening trait signatures.
pub struct RequestContextView<'a> {
    /// Hostname of the request.
    pub hostname: &'a str,
    /// HTTP method as `&str` (`"GET"`, `"POST"`, ...).
    pub method: &'a str,
    /// Request path component (no scheme/host/query).
    pub path: &'a str,
    /// Query string after `?`, or empty string when absent.
    pub query: &'a str,
    /// Resolved agent identifier from the rule-based chain. `None`
    /// when no chain has run yet.
    pub agent_id: Option<&'a str>,
    /// Source label stamped by the rule-based chain.
    pub agent_id_source: Option<&'a str>,
    /// JA4 fingerprint string, when captured.
    pub ja4_fingerprint: Option<&'a str>,
    /// Whether the gateway treats the JA4 as trustworthy (not behind
    /// a CDN that re-terminates TLS).
    pub ja4_trustworthy: bool,
    /// Headless library label (e.g. `"puppeteer"`) when the headless
    /// detector returned `Detected`. `None` otherwise.
    pub headless_library: Option<&'a str>,
    /// Client IP address.
    pub client_ip: Option<std::net::IpAddr>,
}

/// Snapshot of the per-request signals the [`MlClassifierHook`] reads
/// before inference. Owned strings here because the snapshot may
/// cross `tokio::spawn_blocking` for async-mode dispatch.
#[derive(Debug, Clone, Default)]
pub struct RequestSnapshotView<'a> {
    /// HTTP method, e.g. `"GET"`.
    pub method: &'a str,
    /// Request path component (no scheme/host).
    pub path: &'a str,
    /// Query string after `?`, or empty.
    pub query: &'a str,
    /// Number of request headers (case-insensitive count).
    pub header_count: usize,
    /// Length of the request body in bytes, when known.
    pub body_size_bytes: Option<usize>,
    /// Value of the `Accept` header.
    pub accept_header: &'a str,
    /// Value of the `User-Agent` header.
    pub user_agent: &'a str,
    /// Whether a `Cookie` header is present.
    pub cookie_present: bool,
    /// JA4 fingerprint, when captured.
    pub ja4_fingerprint: Option<&'a str>,
    /// Whether the JA4 is trustworthy.
    pub ja4_trustworthy: bool,
    /// Whether the JA4 matches a known headless library.
    pub known_headless: bool,
    /// Diagnostic source label from the rule-based resolver
    /// (`"bot_auth"`, `"user_agent"`, ...). `None` when the chain has
    /// not run yet.
    pub agent_id_source: Option<&'a str>,
    /// Client IP, used to look up per-IP behavioural counters.
    pub client_ip: Option<std::net::IpAddr>,
}

/// ML classifier verdict returned by an [`MlClassifierHook`].
#[derive(Debug, Clone)]
pub struct MlClassificationResult {
    /// Class label as a stable string: `"human"`, `"scraper"`,
    /// `"llm_agent"`, `"unknown"`. The call site maps this back to the
    /// closed enum on the consumer side.
    pub class: &'static str,
    /// Confidence in `[0.0, 1.0]`.
    pub confidence: f32,
    /// Model version string (e.g. `"agent-classifier-v1.2"`).
    pub model_version: &'static str,
    /// Feature schema version pinned by the model.
    pub feature_schema_version: u32,
    /// Wall-clock latency the inference took. Used by the
    /// `sbproxy_ml_classifier_latency_seconds` metric.
    pub inference_latency: Duration,
}

/// Anomaly verdict returned by an [`AnomalyDetectorHook`].
#[derive(Debug, Clone)]
pub struct AnomalyVerdict {
    /// Stable kind label: `"ja4_outlier"`, `"ml_inconsistency"`,
    /// `"headless_library"`, `"request_rate_spike"`. Hook impls
    /// guarantee one of these strings.
    pub kind: &'static str,
    /// Stable severity label: `"info"`, `"warn"`, `"critical"`.
    pub severity: &'static str,
    /// Optional human-readable reason for diagnostic emission.
    pub reason: String,
}

// --- Hook traits ---

/// Identity resolver hook called at the resolver step between Web Bot
/// Auth and forward-confirmed reverse DNS.
///
/// Implementations look at `req.headers` (e.g. `X-Skyfire-KYA`),
/// possibly reconcile with `req.prior_agent_id`, and return a verdict
/// when the step produced an identity. Returning `None` falls through
/// to the next resolver step in the chain.
///
/// The trait returns a pinned future so verifiers can await JWKS or
/// denylist fetches when a cache misses; sync implementations just
/// wrap their result in `async move { ... }`.
pub trait IdentityResolverHook: Send + Sync + 'static {
    /// Resolve the request's identity.
    fn resolve<'a>(
        &'a self,
        req: &'a IdentityRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = Option<IdentityVerdict>> + Send + 'a>>;
}

/// ML classifier hook called pre-policy.
///
/// Runs after the rule-based resolver chain has stamped its verdict so
/// the snapshot's `agent_id_source` field reflects the rule-based
/// outcome. Returning `Some` writes the verdict back to the
/// per-request context's `ml_classification` field; the pipeline then
/// applies the configured human-override rule. Returning `None` means
/// "did not run / no model registered" and the rule-based verdict
/// survives.
///
/// The trait returns a future so async-mode dispatch can offload
/// inference to the tokio blocking pool without blocking the
/// request-filter task.
pub trait MlClassifierHook: Send + Sync + 'static {
    /// Classify the request snapshot. Implementations should respect
    /// the configured sync vs async dispatch mode internally.
    fn classify<'a>(
        &'a self,
        snapshot: &'a RequestSnapshotView<'a>,
    ) -> Pin<Box<dyn Future<Output = Option<MlClassificationResult>> + Send + 'a>>;
}

/// Anomaly detector hook called at the response phase.
///
/// Runs after every per-request signal is populated (TLS fingerprint,
/// ML classification, headless detection, request rate). The detector
/// tallies the signals against the rolling per-`agent_class`
/// histogram and returns every flagged verdict. The pipeline forwards
/// verdicts to the reputation updater (when wired) and emits the
/// `sbproxy_anomaly_detected_total` metric.
///
/// The trait returns a future so the alert sink can route verdicts
/// through the audit pipeline asynchronously.
pub trait AnomalyDetectorHook: Send + Sync + 'static {
    /// Analyse the per-request context and return any flagged
    /// verdicts. An empty `Vec` means "nothing flagged"; this is the
    /// common case.
    fn analyze<'a>(
        &'a self,
        ctx: &'a RequestContextView<'a>,
    ) -> Pin<Box<dyn Future<Output = Vec<AnomalyVerdict>> + Send + 'a>>;
}

// --- Process-wide registry ---
//
// Hook impls that need to be installed at runtime (rather than picked
// up at link time via `inventory::submit!`) register through these
// slots. Tests that need to install specific impls without touching
// the inventory feed call `register_*_hook` directly.

static IDENTITY_HOOKS: Mutex<Vec<Arc<dyn IdentityResolverHook>>> = Mutex::new(Vec::new());
static ML_CLASSIFIER_HOOKS: Mutex<Vec<Arc<dyn MlClassifierHook>>> = Mutex::new(Vec::new());
static ANOMALY_HOOKS: Mutex<Vec<Arc<dyn AnomalyDetectorHook>>> = Mutex::new(Vec::new());

/// Register an [`IdentityResolverHook`] at runtime.
///
/// Each call appends a new impl, so the iteration runs all registered
/// impls in registration order. Tests use this instead of
/// `inventory::submit!` because inventory entries cannot be removed
/// for cleanup.
pub fn register_identity_hook(hook: Arc<dyn IdentityResolverHook>) {
    IDENTITY_HOOKS
        .lock()
        .expect("identity hook registry poisoned")
        .push(hook);
}

/// Register an [`MlClassifierHook`] at runtime. See
/// [`register_identity_hook`] for the contract.
pub fn register_ml_classifier_hook(hook: Arc<dyn MlClassifierHook>) {
    ML_CLASSIFIER_HOOKS
        .lock()
        .expect("ml classifier hook registry poisoned")
        .push(hook);
}

/// Register an [`AnomalyDetectorHook`] at runtime. See
/// [`register_identity_hook`] for the contract.
pub fn register_anomaly_hook(hook: Arc<dyn AnomalyDetectorHook>) {
    ANOMALY_HOOKS
        .lock()
        .expect("anomaly hook registry poisoned")
        .push(hook);
}

/// Snapshot all registered identity resolver hooks.
///
/// Returns owned `Arc`s so the iteration stays valid even if the
/// registry is modified concurrently.
pub fn identity_hooks() -> Vec<Arc<dyn IdentityResolverHook>> {
    IDENTITY_HOOKS
        .lock()
        .expect("identity hook registry poisoned")
        .clone()
}

/// Snapshot all registered ML classifier hooks. See [`identity_hooks`]
/// for the contract.
pub fn ml_classifier_hooks() -> Vec<Arc<dyn MlClassifierHook>> {
    ML_CLASSIFIER_HOOKS
        .lock()
        .expect("ml classifier hook registry poisoned")
        .clone()
}

/// Snapshot all registered anomaly detector hooks. See
/// [`identity_hooks`] for the contract.
pub fn anomaly_hooks() -> Vec<Arc<dyn AnomalyDetectorHook>> {
    ANOMALY_HOOKS
        .lock()
        .expect("anomaly hook registry poisoned")
        .clone()
}

#[cfg(test)]
#[allow(clippy::mutex_atomic)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    // --- Test helpers ---

    struct MapHeaders {
        inner: HashMap<String, String>,
    }
    impl IdentityHeaderLookup for MapHeaders {
        fn get(&self, name: &str) -> Option<&str> {
            self.inner.get(name).map(|s| s.as_str())
        }
    }

    struct CountingIdentityHook {
        calls: Arc<StdMutex<u32>>,
        verdict: Option<IdentityVerdict>,
    }
    impl IdentityResolverHook for CountingIdentityHook {
        fn resolve<'a>(
            &'a self,
            _req: &'a IdentityRequest<'a>,
        ) -> Pin<Box<dyn Future<Output = Option<IdentityVerdict>> + Send + 'a>> {
            *self.calls.lock().unwrap() += 1;
            let v = self.verdict.clone();
            Box::pin(async move { v })
        }
    }

    struct CountingMlHook {
        calls: Arc<StdMutex<u32>>,
        verdict: Option<MlClassificationResult>,
    }
    impl MlClassifierHook for CountingMlHook {
        fn classify<'a>(
            &'a self,
            _snap: &'a RequestSnapshotView<'a>,
        ) -> Pin<Box<dyn Future<Output = Option<MlClassificationResult>> + Send + 'a>> {
            *self.calls.lock().unwrap() += 1;
            let v = self.verdict.clone();
            Box::pin(async move { v })
        }
    }

    struct CountingAnomalyHook {
        calls: Arc<StdMutex<u32>>,
        verdicts: Vec<AnomalyVerdict>,
    }
    impl AnomalyDetectorHook for CountingAnomalyHook {
        fn analyze<'a>(
            &'a self,
            _ctx: &'a RequestContextView<'a>,
        ) -> Pin<Box<dyn Future<Output = Vec<AnomalyVerdict>> + Send + 'a>> {
            *self.calls.lock().unwrap() += 1;
            let v = self.verdicts.clone();
            Box::pin(async move { v })
        }
    }

    // --- Tests ---

    #[tokio::test]
    async fn registered_identity_hook_is_returned_by_iter() {
        let calls = Arc::new(StdMutex::new(0));
        let hook = Arc::new(CountingIdentityHook {
            calls: calls.clone(),
            verdict: Some(IdentityVerdict {
                agent_id: "openai-gptbot".into(),
                agent_id_source: "kya",
                ..Default::default()
            }),
        });
        register_identity_hook(hook);

        let headers = MapHeaders {
            inner: HashMap::new(),
        };
        let req = IdentityRequest {
            headers: &headers,
            hostname: "news.example.com",
            prior_agent_id: None,
        };

        // At least one hook is registered. Iterate; the first
        // matching hook wins per the pipeline contract; we just check
        // that our hook ran at least once.
        let mut saw_verdict = false;
        for h in identity_hooks() {
            if let Some(v) = h.resolve(&req).await {
                assert_eq!(v.agent_id_source, "kya");
                assert_eq!(v.agent_id, "openai-gptbot");
                saw_verdict = true;
            }
        }
        assert!(saw_verdict, "registered hook must produce a verdict");
        assert!(*calls.lock().unwrap() >= 1);
    }

    #[tokio::test]
    async fn multiple_identity_hooks_run_in_registration_order() {
        let order = Arc::new(StdMutex::new(Vec::<u32>::new()));

        struct OrderedHook {
            tag: u32,
            order: Arc<StdMutex<Vec<u32>>>,
        }
        impl IdentityResolverHook for OrderedHook {
            fn resolve<'a>(
                &'a self,
                _req: &'a IdentityRequest<'a>,
            ) -> Pin<Box<dyn Future<Output = Option<IdentityVerdict>> + Send + 'a>> {
                self.order.lock().unwrap().push(self.tag);
                Box::pin(async move { None })
            }
        }

        let snapshot_before = identity_hooks().len();

        register_identity_hook(Arc::new(OrderedHook {
            tag: 100,
            order: order.clone(),
        }));
        register_identity_hook(Arc::new(OrderedHook {
            tag: 200,
            order: order.clone(),
        }));

        let headers = MapHeaders {
            inner: HashMap::new(),
        };
        let req = IdentityRequest {
            headers: &headers,
            hostname: "h.example.com",
            prior_agent_id: None,
        };
        for h in identity_hooks() {
            let _ = h.resolve(&req).await;
        }

        let observed = order.lock().unwrap().clone();
        // Find the position of our tags in the call order; tag 100
        // must appear before tag 200.
        let p100 = observed.iter().position(|x| *x == 100);
        let p200 = observed.iter().position(|x| *x == 200);
        assert!(p100.is_some());
        assert!(p200.is_some());
        assert!(p100.unwrap() < p200.unwrap());
        assert!(identity_hooks().len() >= snapshot_before + 2);
    }

    #[tokio::test]
    async fn ml_classifier_hook_round_trips_verdict() {
        let calls = Arc::new(StdMutex::new(0));
        let hook = Arc::new(CountingMlHook {
            calls: calls.clone(),
            verdict: Some(MlClassificationResult {
                class: "human",
                confidence: 0.95,
                model_version: "test-v1",
                feature_schema_version: 1,
                inference_latency: Duration::from_millis(2),
            }),
        });
        register_ml_classifier_hook(hook);

        let snap = RequestSnapshotView {
            method: "GET",
            path: "/",
            query: "",
            header_count: 4,
            body_size_bytes: None,
            accept_header: "text/html",
            user_agent: "Mozilla/5.0",
            cookie_present: false,
            ja4_fingerprint: None,
            ja4_trustworthy: false,
            known_headless: false,
            agent_id_source: Some("user_agent"),
            client_ip: None,
        };
        let mut saw_verdict = false;
        for h in ml_classifier_hooks() {
            if let Some(v) = h.classify(&snap).await {
                if v.class == "human" {
                    assert!((v.confidence - 0.95).abs() < f32::EPSILON);
                    saw_verdict = true;
                }
            }
        }
        assert!(saw_verdict);
        assert!(*calls.lock().unwrap() >= 1);
    }

    #[tokio::test]
    async fn anomaly_hook_returns_zero_or_more_verdicts() {
        let calls = Arc::new(StdMutex::new(0));
        let hook = Arc::new(CountingAnomalyHook {
            calls: calls.clone(),
            verdicts: vec![AnomalyVerdict {
                kind: "ja4_outlier",
                severity: "warn",
                reason: "novel JA4 against strong baseline".into(),
            }],
        });
        register_anomaly_hook(hook);

        let view = RequestContextView {
            hostname: "h.example.com",
            method: "GET",
            path: "/",
            query: "",
            agent_id: Some("openai-gptbot"),
            agent_id_source: Some("user_agent"),
            ja4_fingerprint: Some("t13d_NOVEL"),
            ja4_trustworthy: true,
            headless_library: None,
            client_ip: None,
        };

        let mut total: usize = 0;
        for h in anomaly_hooks() {
            total += h.analyze(&view).await.len();
        }
        assert!(total >= 1);
        assert!(*calls.lock().unwrap() >= 1);
    }

    #[test]
    fn unregistered_kinds_yield_empty_iter() {
        // We can't reset the registry between tests, but we can pin
        // the contract: iter never panics, and an absent registration
        // simply means an empty Vec or no impl matches.
        // Run the iteration to prove no panic.
        let _ = identity_hooks();
        let _ = ml_classifier_hooks();
        let _ = anomaly_hooks();
    }

    #[test]
    fn header_lookup_is_case_sensitive_by_caller() {
        // Pin the contract: the trait is intentionally case-preserving.
        // Callers normalise to lowercase on the way in (the call site
        // does this when constructing the MapHeaders). The trait
        // itself does not lower-case; this test pins that.
        let mut map = HashMap::new();
        map.insert("x-skyfire-kya".to_string(), "tok".to_string());
        let h = MapHeaders { inner: map };
        assert_eq!(h.get("x-skyfire-kya"), Some("tok"));
        assert_eq!(h.get("X-Skyfire-KYA"), None);
    }
}

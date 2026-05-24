//! Hot-reload support via ArcSwap with connection draining.
//!
//! The compiled pipeline is stored in a global `ArcSwap<CompiledPipeline>` so
//! that all request-handling threads can read the current config without locks.
//! Reloading replaces the pointer atomically; in-flight requests continue
//! using their snapshot until they finish.
//!
//! Connection draining: an atomic counter tracks active in-flight requests.
//! Callers should call `increment_active()` when a request starts and
//! `decrement_active()` when it completes. During a reload, `is_draining()`
//! returns true while any requests are still in-flight, allowing a graceful
//! shutdown sequence.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwap;

use crate::pipeline::CompiledPipeline;
use sbproxy_tls::challenges::Http01ChallengeStore;

// --- Connection draining ---

const DRAINING_BIT: u64 = 1 << 63;
const ACTIVE_COUNT_MASK: u64 = !DRAINING_BIT;

/// Global drain state. The high bit records whether a drain is active;
/// the remaining bits record active in-flight requests. Keeping both in
/// one atomic gives readers a coherent snapshot.
static DRAIN_STATE: AtomicU64 = AtomicU64::new(0);

/// Increment the active request counter. Call when a request begins.
pub fn increment_active() {
    DRAIN_STATE
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
            let active = state & ACTIVE_COUNT_MASK;
            assert!(
                active < ACTIVE_COUNT_MASK,
                "active request counter overflow"
            );
            Some((state & DRAINING_BIT) | (active + 1))
        })
        .expect("increment update cannot fail");
}

/// Decrement the active request counter. Call when a request completes.
///
/// If draining is active and the count reaches zero, draining is automatically
/// cleared.
pub fn decrement_active() {
    DRAIN_STATE
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
            let active = state & ACTIVE_COUNT_MASK;
            assert!(active > 0, "active request counter underflow");
            let next_active = active - 1;
            let next_draining = if next_active == 0 {
                0
            } else {
                state & DRAINING_BIT
            };
            Some(next_draining | next_active)
        })
        .expect("decrement update cannot fail");
}

/// Return the current number of active in-flight requests.
pub fn active_count() -> u64 {
    DRAIN_STATE.load(Ordering::Acquire) & ACTIVE_COUNT_MASK
}

/// Check whether the server is currently draining connections.
///
/// Returns `true` when a reload is pending (draining flag is set) and there
/// is at least one in-flight request still in progress. Once `active_count()`
/// drops to zero, `is_draining()` returns `false`.
pub fn is_draining() -> bool {
    let state = DRAIN_STATE.load(Ordering::Acquire);
    (state & DRAINING_BIT) != 0 && (state & ACTIVE_COUNT_MASK) > 0
}

/// Signal that a reload has been triggered and connection draining should begin.
///
/// Sets the draining flag; `is_draining()` will return `true` until all
/// in-flight requests complete.
pub fn begin_drain() {
    DRAIN_STATE
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
            if (state & ACTIVE_COUNT_MASK) == 0 {
                Some(0)
            } else {
                Some(state | DRAINING_BIT)
            }
        })
        .expect("begin drain update cannot fail");
}

/// Global pipeline store. Initialized lazily on first access with an empty default.
static PIPELINE: OnceLock<ArcSwap<CompiledPipeline>> = OnceLock::new();

/// Global ACME challenge store for HTTP-01 interception.
static CHALLENGE_STORE: OnceLock<Arc<Http01ChallengeStore>> = OnceLock::new();

/// Global Alt-Svc header value for HTTP/3 advertisement.
/// Empty string means H3 is not enabled.
static ALT_SVC: OnceLock<ArcSwap<String>> = OnceLock::new();

/// Get a reference to the global pipeline ArcSwap.
///
/// Initializes with `CompiledPipeline::default()` on first call.
fn pipeline_store() -> &'static ArcSwap<CompiledPipeline> {
    PIPELINE.get_or_init(|| ArcSwap::from_pointee(CompiledPipeline::default()))
}

/// Atomically replace the current pipeline with a new snapshot.
///
/// In-flight requests that already loaded the old pipeline will continue
/// using it until they complete.
///
/// Also re-renders the Wave 4 / G4.5..G4.10 policy-graph projections
/// (`robots.txt`, `llms.txt`, `llms-full.txt`, `/licenses.xml`,
/// `/.well-known/tdmrep.json`) and atomically swaps the projection
/// cache before returning. The two atomics happen back-to-back: a
/// reader that observes the new pipeline may briefly see the old
/// projection cache and vice versa, but per A4.1 the projections are
/// derived from the pipeline's compiled config so any reader on the
/// new path sees consistent data within sub-microsecond skew.
pub fn load_pipeline(new_pipeline: CompiledPipeline) {
    // --- Wave 4 / G4.10 wire: projection cache refresh ---
    //
    // Compute projections before storing the pipeline so the cache is
    // hot for the first request that observes the new pipeline. The
    // config_version is derived from the pipeline-store epoch counter
    // (incremented per swap); A4.1 leaves the exact version-source
    // unspecified so an in-process counter is sufficient for the
    // hot-path freshness check. Cross-process verification (Wave 6
    // signed batch) re-derives the version from the config bytes.
    let config_version = next_config_version();
    let docs = sbproxy_modules::projections::render_projections_with_listings(
        &new_pipeline.config,
        &new_pipeline.listings,
        config_version,
    );
    sbproxy_modules::projections::install_projections(docs);
    pipeline_store().store(Arc::new(new_pipeline));
}

/// Monotonically increasing counter used as the projection cache's
/// `config_version` stamp. Wraps after `2^64` reloads (effectively
/// never).
static CONFIG_VERSION_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_config_version() -> u64 {
    CONFIG_VERSION_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Load a read guard to the current pipeline.
///
/// The returned guard holds an `Arc<CompiledPipeline>` that is valid
/// even if a reload happens while the guard is alive.
pub fn current_pipeline() -> arc_swap::Guard<Arc<CompiledPipeline>> {
    pipeline_store().load()
}

/// Set the global ACME challenge store (called once during TLS init).
pub fn set_challenge_store(store: Arc<Http01ChallengeStore>) {
    let _ = CHALLENGE_STORE.set(store);
}

/// Get the global ACME challenge store.
pub fn challenge_store() -> Option<&'static Arc<Http01ChallengeStore>> {
    CHALLENGE_STORE.get()
}

/// Set the global Alt-Svc header value for HTTP/3 advertisement.
pub fn set_alt_svc(value: String) {
    let store = ALT_SVC.get_or_init(|| ArcSwap::from_pointee(String::new()));
    store.store(Arc::new(value));
}

/// Get the current Alt-Svc header value. Returns empty string if H3 is not enabled.
pub fn alt_svc_value() -> arc_swap::Guard<Arc<String>> {
    ALT_SVC
        .get_or_init(|| ArcSwap::from_pointee(String::new()))
        .load()
}

// --- Wave 3 / G1.4 wire: agent-class resolver singleton ---
//
// The binary builds the resolver once during `run()` from the parsed
// `agent_classes:` config block (or from `AgentClassCatalog::defaults()`
// when the block is absent). The request pipeline reads it from this
// slot in `request_filter` and feeds it to `core::agent_class::stamp_request_context`.
//
// One process-wide resolver is sufficient: the catalog is shared, the
// rDNS verdict cache is process-local, and per-origin overrides land on
// the per-policy `AgentClassPolicy` block (a follow-up wave). A config
// hot reload that flips the `agent_classes:` block keeps the existing
// resolver; rebuilding the resolver across reloads is reserved for a
// later wave (the catalog source is rarely live-tuned).

/// Global agent-class resolver, populated once at startup. `None` when
/// the binary is built without the `agent-class` feature; otherwise
/// always `Some(_)` after `install_agent_class_resolver` runs.
#[cfg(feature = "agent-class")]
static AGENT_CLASS_RESOLVER: OnceLock<
    Arc<sbproxy_modules::policy::agent_class::AgentClassResolver>,
> = OnceLock::new();

/// Install the process-wide agent-class resolver. Idempotent: a second
/// call after the first wins is silently ignored (config hot-reload
/// keeps the original resolver).
#[cfg(feature = "agent-class")]
pub fn set_agent_class_resolver(
    resolver: Arc<sbproxy_modules::policy::agent_class::AgentClassResolver>,
) {
    let _ = AGENT_CLASS_RESOLVER.set(resolver);
}

/// Borrow the global agent-class resolver, when one has been installed.
///
/// Returns `None` before `set_agent_class_resolver` runs (e.g. very
/// early in startup, or in tests that bypass the binary entrypoint).
/// Callers in `request_filter` short-circuit on `None`.
#[cfg(feature = "agent-class")]
pub fn agent_class_resolver(
) -> Option<&'static Arc<sbproxy_modules::policy::agent_class::AgentClassResolver>> {
    AGENT_CLASS_RESOLVER.get()
}

// --- Wave 5 / G5.4 wire: TLS fingerprint catalogue singleton ---
//
// The binary loads the catalogue once from the embedded JSON (or from
// an operator-supplied path) at startup. The headless detector and
// the `tls_fingerprint_matches` CEL function read from this slot in
// `request_filter` and during script evaluation respectively. A
// config hot reload that flips `tls_fingerprint.catalog_path` rebuilds
// the slot via `set_tls_fingerprint_catalog`; the singleton is
// `RwLock`-wrapped (rather than `OnceLock`) so reloads see the new
// data without a process restart.

/// Global TLS-fingerprint catalogue, populated at startup. `None`
/// before `set_tls_fingerprint_catalog` runs or when the
/// `tls-fingerprint` feature is off.
#[cfg(feature = "tls-fingerprint")]
static TLS_FINGERPRINT_CATALOG: OnceLock<
    arc_swap::ArcSwap<sbproxy_security::TlsFingerprintCatalog>,
> = OnceLock::new();

/// Install (or replace) the process-wide TLS-fingerprint catalogue.
/// Idempotent across reloads: every call atomically swaps the live
/// catalogue without dropping in-flight detector reads.
#[cfg(feature = "tls-fingerprint")]
pub fn set_tls_fingerprint_catalog(catalog: sbproxy_security::TlsFingerprintCatalog) {
    let arc = Arc::new(catalog);
    match TLS_FINGERPRINT_CATALOG.get() {
        Some(swap) => swap.store(arc),
        None => {
            let _ = TLS_FINGERPRINT_CATALOG.set(arc_swap::ArcSwap::from(arc));
        }
    }
}

/// Borrow the live TLS-fingerprint catalogue, when one has been
/// installed.
///
/// Returns `None` before `set_tls_fingerprint_catalog` runs. The
/// returned guard implements `Deref<Target = TlsFingerprintCatalog>`
/// so callers can pass it where `&TlsFingerprintCatalog` is expected.
#[cfg(feature = "tls-fingerprint")]
pub fn tls_fingerprint_catalog(
) -> Option<arc_swap::Guard<Arc<sbproxy_security::TlsFingerprintCatalog>>> {
    TLS_FINGERPRINT_CATALOG.get().map(|swap| swap.load())
}

// --- Agent-detect rule-pack loader singleton ---
//
// The binary loads the ADRF rule pack once at startup from
// `proxy.extensions.agent_detect.rule_pack_path` and installs the loader
// here. `request_filter` reads the compiled pack via the loader when
// agent detection is enabled. The loader owns its own `ArcSwap`, so a
// SIGHUP reload swaps the pack contents in place without replacing this
// slot; that is why the slot is `OnceLock` rather than `RwLock`.

/// Global agent-detect rule-pack loader, populated at startup when
/// `proxy.extensions.agent_detect.rule_pack_path` is set. `None`
/// otherwise; `request_filter` short-circuits on `None`.
static AGENT_DETECT_LOADER: OnceLock<Arc<sbproxy_agent_detect::RulePackLoader>> = OnceLock::new();

/// Install the process-wide agent-detect rule-pack loader. Idempotent: a
/// later call after the first wins is ignored, so a config hot-reload of
/// the rule-pack *path* keeps the original loader. The pack *contents*
/// still hot-reload through the loader's own `ArcSwap` via `reload()`.
pub fn set_agent_detect_loader(loader: sbproxy_agent_detect::RulePackLoader) {
    let _ = AGENT_DETECT_LOADER.set(Arc::new(loader));
}

/// Borrow the global agent-detect rule-pack loader, when one is installed.
/// Returns `None` before `set_agent_detect_loader` runs (e.g. when the
/// rule-pack path is unset or in tests that bypass the binary entrypoint).
pub fn agent_detect_loader() -> Option<&'static Arc<sbproxy_agent_detect::RulePackLoader>> {
    AGENT_DETECT_LOADER.get()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use compact_str::CompactString;
    use sbproxy_config::CompiledConfig;

    use super::*;

    // --- Connection draining tests ---
    // Note: these tests manipulate global atomics and are marked with
    // `#[ignore]` to avoid interference in parallel test runs. Run with
    // `cargo test -- --ignored drain` to execute them individually.

    fn reset_drain_state() {
        DRAIN_STATE.store(0, Ordering::SeqCst);
    }

    #[test]
    #[ignore = "manipulates global atomics; run in isolation"]
    fn active_count_increments_and_decrements() {
        // Reset state.
        reset_drain_state();

        assert_eq!(active_count(), 0);
        increment_active();
        assert_eq!(active_count(), 1);
        increment_active();
        assert_eq!(active_count(), 2);
        decrement_active();
        assert_eq!(active_count(), 1);
        decrement_active();
        assert_eq!(active_count(), 0);
    }

    #[test]
    #[ignore = "manipulates global atomics; run in isolation"]
    fn is_draining_true_when_draining_and_active() {
        DRAIN_STATE.store(DRAINING_BIT | 2, Ordering::SeqCst);

        assert!(is_draining());
    }

    #[test]
    #[ignore = "manipulates global atomics; run in isolation"]
    fn is_draining_false_when_no_active_requests() {
        DRAIN_STATE.store(DRAINING_BIT, Ordering::SeqCst);

        assert!(!is_draining(), "no active requests means not draining");
        reset_drain_state();
    }

    #[test]
    #[ignore = "manipulates global atomics; run in isolation"]
    fn drain_clears_when_last_request_finishes() {
        DRAIN_STATE.store(DRAINING_BIT | 1, Ordering::SeqCst);

        assert!(is_draining());

        // Finish the last in-flight request.
        decrement_active();

        assert_eq!(active_count(), 0);
        assert!(
            !is_draining(),
            "draining should clear when all requests finish"
        );
    }

    #[test]
    #[ignore = "manipulates global atomics; run in isolation"]
    fn begin_drain_sets_draining_flag() {
        DRAIN_STATE.store(3, Ordering::SeqCst);

        assert!(!is_draining());
        begin_drain();
        assert!(is_draining());

        // Clean up.
        reset_drain_state();
    }

    #[test]
    fn loom_drain_state_clears_when_last_request_finishes() {
        loom::model(|| {
            use loom::sync::atomic::{AtomicU64 as LoomAtomicU64, Ordering as LoomOrdering};
            use loom::sync::Arc as LoomArc;
            use loom::thread;

            let state = LoomArc::new(LoomAtomicU64::new(1));

            let begin_state = state.clone();
            let begin = thread::spawn(move || {
                begin_state
                    .fetch_update(LoomOrdering::AcqRel, LoomOrdering::Acquire, |current| {
                        if (current & ACTIVE_COUNT_MASK) == 0 {
                            Some(0)
                        } else {
                            Some(current | DRAINING_BIT)
                        }
                    })
                    .expect("begin drain update cannot fail");
            });

            let finish_state = state.clone();
            let finish = thread::spawn(move || {
                finish_state
                    .fetch_update(LoomOrdering::AcqRel, LoomOrdering::Acquire, |current| {
                        let active = current & ACTIVE_COUNT_MASK;
                        if active == 0 {
                            return Some(current);
                        }
                        let next_active = active - 1;
                        let next_draining = if next_active == 0 {
                            0
                        } else {
                            current & DRAINING_BIT
                        };
                        Some(next_draining | next_active)
                    })
                    .expect("decrement update cannot fail");
            });

            begin.join().unwrap();
            finish.join().unwrap();

            let snapshot = state.load(LoomOrdering::Acquire);
            assert_eq!(snapshot & ACTIVE_COUNT_MASK, 0);
            assert_eq!(
                snapshot & DRAINING_BIT,
                0,
                "draining flag must clear when active count reaches zero"
            );
        });
    }

    fn make_config(hostname: &str) -> CompiledConfig {
        let mut host_map = HashMap::new();
        host_map.insert(CompactString::new(hostname), 0);
        CompiledConfig {
            origins: vec![sbproxy_config::CompiledOrigin {
                hostname: CompactString::new(hostname),
                origin_id: CompactString::new(hostname),
                workspace_id: CompactString::default(),
                action_config: serde_json::json!({"type": "proxy", "url": "http://127.0.0.1:9000"}),
                auth_config: None,
                policy_configs: Vec::new(),
                transform_configs: Vec::new(),
                cors: None,
                hsts: None,
                compression: None,
                session: None,
                properties: None,
                sessions: None,
                user: None,
                force_ssl: false,
                allowed_methods: smallvec::smallvec![],
                request_modifiers: smallvec::smallvec![],
                response_modifiers: smallvec::smallvec![],
                variables: None,
                forward_rules: Vec::new(),
                fallback_origin: None,
                error_pages: None,
                problem_details: None,
                proxy_status: None,
                message_signatures: None,
                idempotency: None,
                bot_detection: None,
                threat_protection: None,
                on_request: Vec::new(),
                on_response: Vec::new(),
                response_cache: None,
                mirror: None,
                extensions: HashMap::new(),
                expose_openapi: false,
                stream_safety: Vec::new(),
                rate_limits: None,
                auto_content_negotiate: None,
                content_signal: None,
                token_bytes_ratio: None,
                agent_skills: Vec::new(),
                agents_md: None,
                ai_txt: None,
            }],
            host_map,
            server: sbproxy_config::ProxyServerConfig::default(),
            l2_store: None,
            messenger: None,
            mesh: None,
            access_log: None,
            agent_classes: None,
        }
    }

    #[test]
    fn default_pipeline_is_empty() {
        let pipeline = CompiledPipeline::default();
        assert!(pipeline.config.origins.is_empty());
        assert!(pipeline.actions.is_empty());
    }

    #[test]
    fn load_and_reload_pipeline() {
        // Load first pipeline
        let cfg1 = make_config("old.example.com");
        let pipeline1 = CompiledPipeline::from_config(cfg1).unwrap();
        load_pipeline(pipeline1);

        let guard1 = current_pipeline();
        assert!(guard1.resolve_origin("old.example.com").is_some());
        assert_eq!(guard1.actions.len(), 1);
        drop(guard1);

        // Load second pipeline
        let cfg2 = make_config("new.example.com");
        let pipeline2 = CompiledPipeline::from_config(cfg2).unwrap();
        load_pipeline(pipeline2);

        let guard2 = current_pipeline();
        assert_eq!(guard2.config.origins.len(), 1);
        assert!(guard2.resolve_origin("new.example.com").is_some());
        assert!(guard2.resolve_origin("old.example.com").is_none());
    }
}

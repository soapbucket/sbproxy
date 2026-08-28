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
use std::sync::{Arc, OnceLock, RwLock};

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

#[cfg(test)]
pub(crate) static FEATURE_FLAG_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

fn feature_flag_store(
    config: &sbproxy_config::CompiledConfig,
) -> Arc<sbproxy_extension::flags::FlagStore> {
    use sbproxy_extension::flags::{FlagConfig, FlagRule, FlagStore};

    let flags = config.flags.iter().map(|flag| FlagConfig {
        name: flag.name.clone(),
        default: flag.default,
        rules: FlagRule {
            allow_list: flag.rules.allow_list.iter().cloned().collect(),
            block_list: flag.rules.block_list.iter().cloned().collect(),
            rollout_percent: flag.rules.rollout_percent,
            // The shipped CEL helper intentionally has two arguments
            // (`name`, `key`), so top-level YAML rejects `segments`
            // instead of accepting a rule no request could exercise.
            segments: std::collections::HashSet::new(),
        },
    });
    Arc::new(FlagStore::from_configs(flags))
}

/// Atomically replace the current pipeline with a new snapshot.
///
/// In-flight requests that already loaded the old pipeline will continue
/// using it until they complete.
///
/// Also re-renders the policy-graph projections
/// (`robots.txt`, `llms.txt`, `llms-full.txt`, `/licenses.xml`,
/// `/.well-known/tdmrep.json`) and atomically swaps the projection
/// cache before returning. The two atomics happen back-to-back: a
/// reader that observes the new pipeline may briefly see the old
/// projection cache and vice versa, but the projections are
/// derived from the pipeline's compiled config so any reader on the
/// new path sees consistent data within sub-microsecond skew.
pub fn load_pipeline(new_pipeline: CompiledPipeline) {
    // The one seam every install goes through, boot and reload alike, so
    // it is where a gauge describing the running document belongs.
    // `compile_config` is not that seam: it also validates candidate
    // documents, and an authority payload can never carry
    // `origin_sources` because the path is denied to it, so publishing
    // from there zeroed every series on each publish (WOR-2432
    // re-review N1).
    for (tier, pinned, unpinned) in new_pipeline.config.origin_source_entries.rows() {
        sbproxy_observe::metrics::set_origin_source_entries(tier.as_str(), true, pinned as i64);
        sbproxy_observe::metrics::set_origin_source_entries(tier.as_str(), false, unpinned as i64);
    }
    let next_feature_flags = feature_flag_store(&new_pipeline.config);
    let previous_cache_reserve_health = current_pipeline_full().cache_reserve_health.clone();
    // --- Wave 4 / G4.10 wire: projection cache refresh ---
    //
    // Compute projections before storing the pipeline so the cache is
    // hot for the first request that observes the new pipeline. The
    // config_version is derived from the pipeline-store epoch counter;
    // A4.1 leaves the exact version-source unspecified so an in-process
    // counter is sufficient for the hot-path freshness check.
    // Cross-process verification (Wave 6 signed batch) re-derives the
    // version from the config bytes.
    //
    // Read here, advanced only inside the store closure below. The
    // generation must never be observable before the pipeline it
    // names: `render_openapi` reads generation-then-pipeline and keys
    // its cache on the pair, so a bump that precedes the store lets a
    // request cache the old document under the new generation and
    // serve it until the reload after this one (WOR-2602 review).
    let config_version = staged_config_version();
    let docs = sbproxy_modules::projections::render_projections_with_listings(
        &new_pipeline.config,
        &new_pipeline.listings,
        config_version,
    );
    sbproxy_modules::projections::install_projections(docs);
    // Serve-preflight: warn (never fail) when the config declares
    // local model serving but this host is missing a prerequisite,
    // so the gap surfaces at load time instead of on the first
    // request that quietly fails over.
    crate::server::model_host::preflight_serve_warnings(&new_pipeline.actions);
    // WOR-2560: point the `sbproxy_target_health_state` gauge at the
    // live pipeline walk. The installed closure resolves
    // `current_pipeline()` at scrape time, so installing before the
    // swap below is fine; doing it at every publication (rather than
    // once at startup) keeps the seam installed for library embedders
    // that never run the binary's startup path.
    crate::admin::install_target_health_metrics_source();
    // WOR-2289: the structured-log redactor's bundle field-key denylist
    // belongs to whichever extension registry is serving, so it moves
    // here and nowhere else. Loading a bundle candidate used to install
    // it, which meant every validate-only load (a `/config/publish` dry
    // run, doctor, the empty registry `CompiledPipeline::from_config`
    // builds) reprogrammed the redactor for a candidate that was then
    // dropped, leaving the still-serving config logging its own
    // `secret_vars` in cleartext. Installing at the publication boundary
    // makes the denylist as durable as the pipeline it describes.
    //
    // The union goes in before the swap and the adopted set after it,
    // because neither ordering is safe on its own. Installing only
    // before would un-redact a dropped bundle's field names for the
    // generation still serving, which is a narrower version of the bug
    // this moved to fix; installing only after would leave a newly
    // added bundle's names in cleartext until the swap lands. Redacting
    // the union across the boundary is the one direction with no window
    // in it, and it costs an over-redacted field for a few microseconds
    // on a reload.
    let bundle_secret_fields = new_pipeline
        .extension_registry()
        .secret_field_names()
        .to_vec();
    let mut across_the_swap = sbproxy_observe::logging::bundle_secret_field_names().to_vec();
    across_the_swap.extend_from_slice(&bundle_secret_fields);
    sbproxy_observe::logging::set_bundle_secret_field_names(across_the_swap);
    // WOR-2587 review: the same fix, for the same reason, for the MCP
    // Cedar policy hook. `McpAction::from_config` used to install a
    // `CedarMcpHook` into `sbproxy_plugin::mcp`'s registry
    // unconditionally at compile time -- the identical bug class the
    // redactor fix above closed: a validate-only load (a
    // `/config/publish` dry run, `doctor`) or a hot-reload candidate
    // this function's caller goes on to reject (see
    // `hooks::PipelineLifecycleHook::on_reload`'s doc comment)
    // installed a live hook for a config nobody ever served, and the
    // registry was append-only, so a successful reload piled a fresh
    // hook on top of the previous generation's rather than replacing
    // it -- federation dispatch takes the first non-Allow verdict, so
    // a stale hook from a config already rolled back would keep
    // denying calls for the rest of the process's life. The hook is
    // compiled onto the `McpAction` instead now (see
    // `McpAction::cedar_policy_hook`) and only reaches the registry
    // here, at the publication boundary.
    //
    // Same union-before / narrow-after shape as the redactor fix, for
    // the same reason: installing only before the swap would drop a
    // generation's hook the moment a request lands between the swap
    // and the narrowing below; installing only after would leave a
    // newly added hook not yet governing calls until the swap lands.
    // Unioning across the boundary is the direction with no window in
    // it, and for a policy gate "briefly more restrictive" is the safe
    // side to err on, unlike the redactor's "briefly over-redacted."
    let cedar_hooks: Vec<Arc<dyn sbproxy_plugin::mcp::McpPolicyHook>> = new_pipeline
        .actions
        .iter()
        .filter_map(|action| match action {
            sbproxy_modules::Action::Mcp(mcp) => mcp.cedar_policy_hook(),
            _ => None,
        })
        .collect();
    let mut cedar_hooks_across_the_swap = sbproxy_plugin::mcp::pipeline_mcp_policy_hooks();
    cedar_hooks_across_the_swap.extend(cedar_hooks.iter().cloned());
    sbproxy_plugin::mcp::set_pipeline_mcp_policy_hooks(cedar_hooks_across_the_swap);
    // This is the only pipeline publisher. Hold the flag-store write lock
    // while the pipeline pointer is swapped, then install its matching flag
    // snapshot before CEL readers can resume. Direct/library callers therefore
    // cannot publish flag-bearing config without seeding `flag_enabled`.
    // Activate generation-owned tasks here as well: construction may still be
    // rejected by a lifecycle hook, while every successful startup and reload
    // converges on this publication boundary.
    new_pipeline.activate_background_tasks();
    previous_cache_reserve_health.retire();
    let cache_reserve_audit_enabled = new_pipeline.config.decision_audit.publishes(
        sbproxy_observe::decision::DecisionEvent::CacheReserveHealth.as_label(),
        None,
        None,
    );
    new_pipeline
        .cache_reserve_health
        .activate(cache_reserve_audit_enabled);
    sbproxy_extension::flags::replace_global_store_after(next_feature_flags, || {
        pipeline_store().store(Arc::new(new_pipeline));
        advance_config_version();
    });
    // Narrow the denylist from the union back to what the generation
    // now serving actually declares, so a reload that drops a bundle
    // also drops its names rather than leaking them forward forever.
    sbproxy_observe::logging::set_bundle_secret_field_names(bundle_secret_fields);
    // Narrow the Cedar hook registry the same way: from the union back
    // to exactly what the generation now serving declares, so a reload
    // that drops or edits a `cedar_policies:` block retires the old
    // hook rather than leaving it denying calls forever.
    sbproxy_plugin::mcp::set_pipeline_mcp_policy_hooks(cedar_hooks);
}

/// Monotonically increasing counter used as the projection cache's
/// `config_version` stamp. Wraps after `2^64` reloads (effectively
/// never).
static CONFIG_VERSION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The version stamp the next publication will serve under.
///
/// Read-only: `load_pipeline` stamps its projections with this value
/// and advances the counter only after the pipeline store swap, via
/// [`advance_config_version`].
fn staged_config_version() -> u64 {
    // Relaxed is enough here: only the publisher thread calls this,
    // and it reads its own prior `advance_config_version` writes.
    CONFIG_VERSION_COUNTER.load(Ordering::Relaxed)
}

/// Advance the pipeline generation.
///
/// Called in exactly one place: the publication closure in
/// `load_pipeline`, strictly after the pipeline store swap. Keeping
/// the bump behind the swap is what makes `pipeline_generation` safe
/// to read before `current_pipeline`: a reader racing a reload can
/// only see the newer pipeline under the older generation, which the
/// next request re-renders, never the older pipeline under the newer
/// generation, which would be served until the following reload.
fn advance_config_version() {
    // Release pairs with the Acquire in `pipeline_generation`: a
    // reader that observes the bump must also observe the pipeline
    // swap sequenced before it, or the stale-document-under-new-
    // generation window reopens as a reordering on weakly ordered
    // hardware.
    CONFIG_VERSION_COUNTER.fetch_add(1, Ordering::Release);
}

/// The current pipeline generation.
///
/// Moves once per swap, whatever changed inside the pipeline. Anything
/// caching a value derived from the compiled config should key on this
/// rather than on `config_revision`: the revision is an origin-set
/// identity hash, so it deliberately does not move when a policy, an
/// auth block, a forward rule or a port does, and a cache keyed on it
/// serves the pre-reload answer for the life of the process.
pub(crate) fn pipeline_generation() -> u64 {
    // Acquire pairs with the Release bump in `advance_config_version`;
    // see the comment there.
    CONFIG_VERSION_COUNTER.load(Ordering::Acquire)
}

/// Load a read guard to the current pipeline.
///
/// The returned guard holds an `Arc<CompiledPipeline>` that is valid
/// even if a reload happens while the guard is alive.
pub fn current_pipeline() -> arc_swap::Guard<Arc<CompiledPipeline>> {
    pipeline_store().load()
}

/// Load an owned `Arc` to the current pipeline snapshot.
///
/// Unlike [`current_pipeline`], this returns a full `Arc` (not a
/// borrow-scoped guard), so it can be stashed on the per-request
/// [`RequestContext`](crate::context::RequestContext) at request start
/// and read by every later Pingora phase. Pinning one snapshot per
/// request means a request finishes on the config it began with: a hot
/// reload that swaps or removes origins mid-request can no longer make a
/// later phase index a fresh pipeline with a stale `origin_idx`.
pub fn current_pipeline_full() -> Arc<CompiledPipeline> {
    pipeline_store().load_full()
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

/// Global agent-class resolver, populated at startup and refreshed on
/// every hot reload. `None` when the binary is built without the
/// `agent-class` feature; otherwise `Some(_)` after the first
/// `install_agent_class_resolver` runs. ArcSwap-backed so a reload that
/// rebuilt the resolver from a changed `agent_classes:` block (or the
/// resolver flags) swaps it live without dropping in-flight reads.
#[cfg(feature = "agent-class")]
static AGENT_CLASS_RESOLVER: OnceLock<
    arc_swap::ArcSwap<sbproxy_modules::policy::agent_class::AgentClassResolver>,
> = OnceLock::new();

/// Install (or replace) the process-wide agent-class resolver.
/// Idempotent across reloads: every call atomically swaps the live
/// resolver, so a SIGHUP / file reload that changed the `agent_classes:`
/// block or the `resolver.rdns_enabled` / `bot_auth_keyid_enabled` flags
/// takes effect without a process restart (WOR-1164).
#[cfg(feature = "agent-class")]
pub fn set_agent_class_resolver(
    resolver: Arc<sbproxy_modules::policy::agent_class::AgentClassResolver>,
) {
    match AGENT_CLASS_RESOLVER.get() {
        Some(swap) => swap.store(resolver),
        None => {
            let _ = AGENT_CLASS_RESOLVER.set(arc_swap::ArcSwap::from(resolver));
        }
    }
}

/// Borrow the live agent-class resolver, when one has been installed.
///
/// Returns `None` before `set_agent_class_resolver` runs (e.g. very
/// early in startup, or in tests that bypass the binary entrypoint).
/// Callers in `request_filter` short-circuit on `None`. The returned
/// guard derefs to `AgentClassResolver`.
#[cfg(feature = "agent-class")]
pub fn agent_class_resolver(
) -> Option<arc_swap::Guard<Arc<sbproxy_modules::policy::agent_class::AgentClassResolver>>> {
    AGENT_CLASS_RESOLVER.get().map(|swap| swap.load())
}

// --- Wave 5 / G5.4 wire: TLS fingerprint catalogue singleton ---
//
// The binary loads the catalogue once from the embedded JSON (or from
// an operator-supplied path) at startup. The headless detector and
// the `tls_fingerprint_matches` CEL function read from this slot in
// `request_filter` and during script evaluation respectively. The
// catalogue is sourced from the embedded JSON (`default_embedded`);
// there is no operator `catalog_path` override today. A hot reload
// re-installs it via `set_tls_fingerprint_catalog`, which atomically
// swaps the `ArcSwap` so reads never tear and no restart is needed.

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
// The binary loads the ADRF rule pack at startup from
// `proxy.extensions.agent_detect.rule_pack_path` and installs the loader
// here. `request_filter` reads the compiled pack via the loader when
// agent detection is enabled. The slot is ArcSwap-backed so a reload
// that repoints `rule_pack_path` at a different file swaps the loader
// live (WOR-1164); the loader also owns its own `ArcSwap`, so a
// same-path content change hot-reloads through `reload()`.

/// Global agent-detect rule-pack loader, populated at startup when
/// `proxy.extensions.agent_detect.rule_pack_path` is set and refreshed
/// on reload. `None` otherwise; `request_filter` short-circuits on
/// `None`.
static AGENT_DETECT_LOADER: OnceLock<arc_swap::ArcSwap<sbproxy_agent_detect::RulePackLoader>> =
    OnceLock::new();

/// Install (or replace) the process-wide agent-detect rule-pack loader.
/// Idempotent across reloads: every call atomically swaps the live
/// loader, so a reload that repoints `agent_detect.rule_pack_path` at a
/// different file takes effect without a restart (WOR-1164). A same-path
/// content change also hot-reloads through the loader's own `ArcSwap`.
pub fn set_agent_detect_loader(loader: sbproxy_agent_detect::RulePackLoader) {
    set_agent_detect_loader_arc(Arc::new(loader));
}

/// Install a shared rule-pack loader. Startup uses this when the same
/// loader allocation also needs to back the trait-object scorer.
pub fn set_agent_detect_loader_arc(loader: Arc<sbproxy_agent_detect::RulePackLoader>) {
    match AGENT_DETECT_LOADER.get() {
        Some(swap) => swap.store(loader),
        None => {
            let _ = AGENT_DETECT_LOADER.set(arc_swap::ArcSwap::from(loader));
        }
    }
}

/// Borrow the live agent-detect rule-pack loader, when one is installed.
/// Returns `None` before `set_agent_detect_loader` runs (e.g. when the
/// rule-pack path is unset or in tests that bypass the binary entrypoint).
/// The returned guard derefs to `RulePackLoader`.
pub fn agent_detect_loader() -> Option<arc_swap::Guard<Arc<sbproxy_agent_detect::RulePackLoader>>> {
    AGENT_DETECT_LOADER.get().map(|swap| swap.load())
}

/// Global agent-detect scorer, populated at startup when
/// `proxy.extensions.agent_detect` installs a rule pack, an ONNX model,
/// or both. Stored behind an `RwLock<Option<Arc<_>>>` because scorer
/// replacement happens only on startup/reload; the hot path clones the
/// current `Arc` and then runs without holding the lock.
type AgentDetectScorer = Arc<dyn sbproxy_agent_detect::AgentScorer>;
type AgentDetectScorerSlot = RwLock<Option<AgentDetectScorer>>;

static AGENT_DETECT_SCORER: OnceLock<AgentDetectScorerSlot> = OnceLock::new();

fn agent_detect_scorer_slot() -> &'static AgentDetectScorerSlot {
    AGENT_DETECT_SCORER.get_or_init(|| RwLock::new(None))
}

/// Install or replace the process-wide agent-detect scorer.
pub fn set_agent_detect_scorer(scorer: AgentDetectScorer) {
    let mut guard = agent_detect_scorer_slot()
        .write()
        .expect("agent-detect scorer lock poisoned");
    *guard = Some(scorer);
}

/// Clear the process-wide agent-detect scorer.
pub fn clear_agent_detect_scorer() {
    let mut guard = agent_detect_scorer_slot()
        .write()
        .expect("agent-detect scorer lock poisoned");
    *guard = None;
}

/// Clone the live agent-detect scorer, when configured.
pub fn agent_detect_scorer() -> Option<AgentDetectScorer> {
    agent_detect_scorer_slot()
        .read()
        .expect("agent-detect scorer lock poisoned")
        .clone()
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
            origin_source_entries: Default::default(),
            extension_bundles: Default::default(),
            origins: vec![sbproxy_config::CompiledOrigin {
                hostname: CompactString::new(hostname),
                origin_id: CompactString::new(hostname),
                cache_config_fingerprint: CompactString::default(),
                workspace_id: CompactString::default(),
                tenant_id: compact_str::CompactString::const_new("__default__"),
                action_config: serde_json::json!({"type": "proxy", "url": "http://127.0.0.1:9000"}),
                auth_config: None,
                policy_configs: Vec::new(),
                transform_configs: Vec::new(),
                filters: Vec::new(),
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
                deprecation: None,
                message_signatures: None,
                olp: None,
                comp: None,
                web_bot_auth_publish: None,
                idempotency: None,
                timeouts: sbproxy_config::UpstreamTimeouts::default(),
                bot_detection: None,
                threat_protection: None,
                on_request: Vec::new(),
                on_response: Vec::new(),
                response_cache: None,
                mirror: None,
                extensions: HashMap::new(),
                expose_openapi: false,
                stream_safety: Vec::new(),
                auto_content_negotiate: None,
                content_signal: None,
                token_bytes_ratio: None,
                agent_skills: Vec::new(),
                agents_md: None,
                ai_txt: None,
                agents_json: None,
                outbound_credential: None,
                outbound_web_bot_auth: false,
                observability: None,
                attestation: None,
                owasp_pack_manifest: None,
            }],
            host_map,
            server: sbproxy_config::ProxyServerConfig::default(),
            l2_store: None,
            mesh: None,
            access_log: None,
            decision_audit: Default::default(),
            agent_classes: None,
            rate_limits: None,
            audit: None,
            session_ledger: None,
            request_events: None,
            events: None,
            flags: Vec::new(),
            egress: Default::default(),
        }
    }

    /// [`make_config`] with the origin's action replaced by an `mcp`
    /// gateway action, optionally carrying a `cedar_policies:` block.
    fn make_mcp_config(hostname: &str, cedar_policies: Option<&str>) -> CompiledConfig {
        let mut config = make_config(hostname);
        let mut action = serde_json::json!({
            "type": "mcp",
            "mode": "gateway",
            "server_info": {"name": "reload-cedar-fixture", "version": "1.0.0"},
            "federated_servers": [{
                "origin": "http://127.0.0.1:1/mcp",
                "prefix": "reload-cedar-fixture-server"
            }]
        });
        if let Some(policies) = cedar_policies {
            action["cedar_policies"] = serde_json::json!({"policies": policies});
        }
        config.origins[0].action_config = action;
        config
    }

    /// WOR-2587 review: `McpAction::from_config` used to install a
    /// `CedarMcpHook` into `sbproxy_plugin::mcp`'s global registry
    /// unconditionally at compile time, so a validation-only compile
    /// and a runtime candidate that is never handed to
    /// [`load_pipeline`] both installed a live hook for a config
    /// nobody ever served, and the registry was append-only, so a
    /// successful reload piled a fresh hook on top of the previous
    /// generation's rather than retiring it. This pins the fix: the
    /// hook only reaches the registry from [`load_pipeline`], for a
    /// pipeline that actually goes live, and a later reload that drops
    /// `cedar_policies:` retires the hook rather than leaving it
    /// registered forever.
    #[test]
    fn cedar_hook_installed_only_at_publication_and_retired_on_reload() {
        const POLICIES: &str = "permit(principal, action, resource);";

        // A validation-only compile must never touch the registry.
        let validation_cfg = make_mcp_config("cedar-reload-validate.example.com", Some(POLICIES));
        CompiledPipeline::from_config_for_validation(validation_cfg)
            .expect("validation-mode mcp+cedar_policies config compiles");
        assert!(
            sbproxy_plugin::mcp::pipeline_mcp_policy_hooks().is_empty(),
            "a validation-only compile must never install a live Cedar hook"
        );

        // Neither must a Runtime-mode candidate that compiles cleanly
        // but is simply never passed to `load_pipeline` -- the shape
        // of a hot-reload candidate a lifecycle hook goes on to
        // reject.
        let candidate_cfg = make_mcp_config("cedar-reload-candidate.example.com", Some(POLICIES));
        CompiledPipeline::from_config(candidate_cfg)
            .expect("runtime-mode mcp+cedar_policies config compiles");
        assert!(
            sbproxy_plugin::mcp::pipeline_mcp_policy_hooks().is_empty(),
            "compiling a runtime candidate must not install a hook until load_pipeline runs"
        );

        // Publishing DOES install it.
        let live_cfg = make_mcp_config("cedar-reload-live.example.com", Some(POLICIES));
        let live_pipeline = CompiledPipeline::from_config(live_cfg)
            .expect("runtime-mode mcp+cedar_policies config compiles");
        load_pipeline(live_pipeline);
        assert_eq!(
            sbproxy_plugin::mcp::pipeline_mcp_policy_hooks().len(),
            1,
            "load_pipeline must install exactly the live generation's Cedar hook"
        );

        // A later reload to a config with no `cedar_policies:` must
        // retire the previous generation's hook rather than leaving it
        // registered forever -- the monotonic-registry half of the
        // bug this fix closes.
        let next_cfg = make_config("cedar-reload-live.example.com");
        let next_pipeline =
            CompiledPipeline::from_config(next_cfg).expect("plain proxy config compiles");
        load_pipeline(next_pipeline);
        assert!(
            sbproxy_plugin::mcp::pipeline_mcp_policy_hooks().is_empty(),
            "a reload that drops cedar_policies must retire the old hook, not leave it \
             denying calls forever"
        );
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

    #[test]
    fn canonical_pipeline_publish_installs_compiled_flags_for_cel() {
        let _guard = FEATURE_FLAG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let previous = sbproxy_extension::flags::set_global_store(Arc::new(
            sbproxy_extension::flags::FlagStore::new(),
        ));
        let config = sbproxy_config::compile_config(
            r#"
flags:
  - name: canonical-publisher
    default: true
"#,
        )
        .expect("flag config compiles");
        let pipeline = CompiledPipeline::from_config(config).expect("pipeline compiles");

        load_pipeline(pipeline);

        let engine = sbproxy_extension::cel::CelEngine::new();
        let context = sbproxy_extension::cel::CelContext::new();
        assert!(engine
            .eval_bool_source(
                r#"flag_enabled("canonical-publisher", "request-key")"#,
                &context,
            )
            .expect("CEL flag evaluates"));
        sbproxy_extension::flags::set_global_store(previous);
    }

    /// WOR-1164 regression: a second `set_agent_detect_loader` (e.g. a
    /// hot reload that repointed `rule_pack_path`) must atomically swap
    /// the live loader, not silently no-op the way the old `OnceLock`
    /// slot did. We prove the swap by Arc-pointer identity: the first
    /// guard pins the old allocation alive, so a real swap yields a
    /// distinct pointer while a no-op would yield the same one.
    #[test]
    fn agent_detect_loader_swaps_on_reinstall() {
        use sbproxy_agent_detect::rules::CompiledRulePack;
        use sbproxy_agent_detect::RulePackLoader;

        let pack_a =
            CompiledRulePack::from_yaml_str("version: 0\nagents: []\n").expect("pack a parses");
        let pack_b =
            CompiledRulePack::from_yaml_str("version: 0\nagents: []\n").expect("pack b parses");

        set_agent_detect_loader(RulePackLoader::from_pack(pack_a, "/nonexistent/a.yaml"));
        let first = agent_detect_loader().expect("loader installed after first set");
        let first_ptr = Arc::as_ptr(&first);

        set_agent_detect_loader(RulePackLoader::from_pack(pack_b, "/nonexistent/b.yaml"));
        let second = agent_detect_loader().expect("loader still installed after reload");
        let second_ptr = Arc::as_ptr(&second);

        assert!(
            !std::ptr::eq(first_ptr, second_ptr),
            "reload must swap the agent-detect loader, not no-op the second install"
        );
    }

    #[test]
    fn agent_detect_scorer_installs_and_clears() {
        clear_agent_detect_scorer();
        assert!(agent_detect_scorer().is_none());

        set_agent_detect_scorer(Arc::new(sbproxy_agent_detect::DefaultScorer));
        assert!(agent_detect_scorer().is_some());

        clear_agent_detect_scorer();
        assert!(agent_detect_scorer().is_none());
    }

    /// Write a bundle whose one hook declares `billing_key` as a
    /// `secret_var`, so a pipeline built over it has a non-empty
    /// redactor denylist.
    fn write_secret_var_bundle(root: &std::path::Path) {
        let bundle = root.join("bundles").join("billing");
        std::fs::create_dir_all(&bundle).expect("create bundle directory");
        std::fs::write(bundle.join("entry.js"), "export function run() {}\n")
            .expect("write bundle artifact");
        std::fs::write(
            bundle.join("bundle.yaml"),
            r#"apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: billing
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: policy
    type: billing_policy
    export: run
    config_schema:
      type: object
      properties:
        billing_key:
          type: string
    secret_vars: [billing_key]
"#,
        )
        .expect("write bundle manifest");
    }

    /// WOR-2289 regression: the structured-log redactor's bundle
    /// field-key denylist moves at publication and only at publication.
    ///
    /// The clobber this pins: `Candidate::finish` used to install the
    /// names itself, so a validate-only load (a `/config/publish` dry
    /// run with no `extensions:` block, doctor, or any
    /// `CompiledPipeline::from_config` with its empty registry) replaced
    /// the live denylist with its own and the config still serving began
    /// logging its `secret_vars` in cleartext. Half of this test is
    /// therefore the publish wiring (`load_pipeline` installs) and half
    /// is the absence of the clobber (a dropped candidate does not).
    #[test]
    fn publishing_a_pipeline_owns_the_bundle_redactor_denylist() {
        sbproxy_observe::logging::set_bundle_secret_field_names(Vec::new());

        let directory = tempfile::TempDir::new().expect("temporary config directory");
        write_secret_var_bundle(directory.path());
        let mut config = make_config("billing.example.com");
        config.extension_bundles.bundles_dir = Some("bundles".to_owned());
        let pipeline = CompiledPipeline::from_config_at(config, directory.path())
            .expect("a pipeline over the bundle compiles");

        load_pipeline(pipeline);

        let live = sbproxy_observe::logging::bundle_secret_field_names();
        assert!(
            live.iter().any(|name| name == "billing_key"),
            "publication must install the adopted registry's secret field names: {live:?}"
        );

        // A candidate that is built and dropped, which is what a
        // validate-only publish of a payload carrying no `extensions:`
        // block does, must leave the serving generation's denylist alone.
        let candidate = CompiledPipeline::from_config(make_config("candidate.example.com"))
            .expect("the validate-only candidate compiles");
        let candidate_names = candidate.extension_registry().secret_field_names();
        assert!(candidate_names.is_empty(), "{candidate_names:?}");
        drop(candidate);

        let live = sbproxy_observe::logging::bundle_secret_field_names();
        assert!(
            live.iter().any(|name| name == "billing_key"),
            "a dropped candidate must not disarm the serving config's redactor: {live:?}"
        );

        // Publishing a generation that drops the bundle drops its
        // names too. Without the narrowing step after the swap, the
        // union installed across the boundary would leak forward and
        // the denylist would only ever grow.
        let successor = CompiledPipeline::from_config(make_config("successor.example.com"))
            .expect("the bundle-free successor compiles");
        load_pipeline(successor);
        let live = sbproxy_observe::logging::bundle_secret_field_names();
        assert!(
            !live.iter().any(|name| name == "billing_key"),
            "a reload that drops a bundle must drop the names it declared: {live:?}"
        );

        sbproxy_observe::logging::set_bundle_secret_field_names(Vec::new());
    }
}

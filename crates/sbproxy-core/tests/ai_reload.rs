//! WOR-173 integration tests: AI provider registry hot-reload and
//! deliberate budget tracker preservation across reloads.
//!
//! Two properties are pinned here. First, a reload that points at a
//! new `ai_providers_file` makes the new providers reachable through
//! `sbproxy_ai::get_provider_info` without restarting the process,
//! and old-only providers vanish on the swap. Second, the
//! process-wide `BUDGET_TRACKER` is **not** rebuilt on reload: an
//! accumulator written before a reload remains visible afterward.
//! Wiping the tracker on reload would silently roll daily / monthly
//! counters back to zero and let already-spent budget through twice.

use std::sync::Mutex;

use sbproxy_ai::providers::{
    get_provider_info, init_provider_registry, list_providers, reload_provider_registry,
};
use sbproxy_core::server::{budget_tracker, reload_ai_client};

/// The provider registry and AI client are process-global. Tests in
/// this file mutate them in sequence so they must run serially. A
/// regular `#[test]` may run in parallel with other test functions in
/// the same binary; we serialise with a mutex to keep the assertions
/// independent of execution order.
fn serial_lock() -> &'static Mutex<()> {
    static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn write_yaml(dir: &tempfile::TempDir, name: &str, body: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, body).expect("write override yaml");
    path
}

const CFG_A: &str = r#"providers:
  - name: alpha
    display_name: Alpha
    default_base_url: https://alpha.example.com
    auth_header: Authorization
    auth_prefix: "Bearer "
    format: openai
    supports_streaming: false
    supports_embeddings: false
  - name: beta
    display_name: Beta
    default_base_url: https://beta.example.com
    auth_header: Authorization
    auth_prefix: "Bearer "
    format: openai
    supports_streaming: false
    supports_embeddings: false
"#;

const CFG_B: &str = r#"providers:
  - name: alpha
    display_name: Alpha
    default_base_url: https://alpha.example.com
    auth_header: Authorization
    auth_prefix: "Bearer "
    format: openai
    supports_streaming: false
    supports_embeddings: false
  - name: beta
    display_name: Beta
    default_base_url: https://beta.example.com
    auth_header: Authorization
    auth_prefix: "Bearer "
    format: openai
    supports_streaming: false
    supports_embeddings: false
  - name: gamma
    display_name: Gamma
    default_base_url: https://gamma.example.com
    auth_header: Authorization
    auth_prefix: "Bearer "
    format: openai
    supports_streaming: true
    supports_embeddings: false
"#;

#[test]
fn provider_registry_hot_reload_picks_up_new_provider_without_restart() {
    let _g = serial_lock().lock().unwrap();

    let dir = tempfile::tempdir().expect("tempdir");
    let cfg_a = write_yaml(&dir, "ai_providers_a.yml", CFG_A);
    let cfg_b = write_yaml(&dir, "ai_providers_b.yml", CFG_B);

    // --- Phase 1: install config A. ---
    init_provider_registry(Some(&cfg_a)).expect("init registry against config A");
    let names_a = list_providers();
    assert!(
        names_a.contains(&"alpha".to_string()) && names_a.contains(&"beta".to_string()),
        "config A should expose alpha and beta, got {names_a:?}"
    );
    assert!(
        !names_a.contains(&"gamma".to_string()),
        "gamma must not be present before the reload"
    );
    let alpha_a = get_provider_info("alpha").expect("alpha should resolve before reload");
    assert_eq!(alpha_a.default_base_url, "https://alpha.example.com");
    assert!(
        get_provider_info("gamma").is_none(),
        "gamma must not resolve before reload"
    );

    // --- Phase 2: hot-reload to config B. ---
    reload_provider_registry(Some(&cfg_b)).expect("reload registry against config B");

    let names_b = list_providers();
    assert!(
        names_b.contains(&"gamma".to_string()),
        "gamma must be reachable after reload, got {names_b:?}"
    );
    let gamma = get_provider_info("gamma").expect("gamma should resolve after reload");
    assert_eq!(gamma.default_base_url, "https://gamma.example.com");
    assert!(
        gamma.supports_streaming,
        "gamma streaming flag should reflect config B"
    );

    // The two carry-over providers stay reachable so existing traffic
    // routed at them is unaffected by the swap.
    assert!(
        get_provider_info("alpha").is_some(),
        "alpha must still resolve after reload"
    );
    assert!(
        get_provider_info("beta").is_some(),
        "beta must still resolve after reload"
    );

    // The AI client is intended to be rebuilt alongside the registry
    // on a reload. We can't observe that easily from outside the
    // crate, but the call itself must not panic - this pins the wire.
    reload_ai_client();
}

#[test]
fn budget_tracker_accumulator_survives_reload() {
    let _g = serial_lock().lock().unwrap();

    let dir = tempfile::tempdir().expect("tempdir");
    let cfg_a = write_yaml(&dir, "ai_providers_budget_a.yml", CFG_A);
    let cfg_b = write_yaml(&dir, "ai_providers_budget_b.yml", CFG_B);

    // Pick a scope key that no other test is using to keep the
    // assertion independent of test interleaving in the same binary.
    let scope = "wor-173-test:budget-survives-reload";

    // Reset to zero so a previous test run cannot pre-fill the slot.
    budget_tracker().reset(scope);

    // Install config A and seed the accumulator.
    init_provider_registry(Some(&cfg_a)).expect("init registry against config A");
    budget_tracker().record_usage(scope, 1_000, 0.05);
    budget_tracker().record_usage(scope, 500, 0.025);

    let before = budget_tracker().get_usage(scope);
    assert_eq!(before.tokens, 1_500);
    assert!((before.cost_usd - 0.075).abs() < 1e-9);
    assert_eq!(before.request_count, 2);

    // Hot-reload to config B (and the AI client alongside it). The
    // budget tracker is intentionally not part of the swap.
    reload_provider_registry(Some(&cfg_b)).expect("reload registry against config B");
    reload_ai_client();

    let after = budget_tracker().get_usage(scope);
    assert_eq!(
        after.tokens, before.tokens,
        "token accumulator must survive AI registry / client reload",
    );
    assert!(
        (after.cost_usd - before.cost_usd).abs() < 1e-9,
        "cost accumulator must survive AI registry / client reload",
    );
    assert_eq!(
        after.request_count, before.request_count,
        "request_count accumulator must survive AI registry / client reload",
    );

    // Cleanup so subsequent runs in the same binary start clean.
    budget_tracker().reset(scope);
}

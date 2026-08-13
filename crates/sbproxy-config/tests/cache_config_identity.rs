//! Per-origin cache config fingerprint (WOR-2407).
//!
//! A shared cache store is one flat key space across every node in a
//! mesh. The fingerprint is what keeps a node from reading an entry
//! that a differently-configured node wrote, so these tests pin both
//! halves of the contract: config that changes the upstream
//! representation must move the fingerprint, and config that cannot
//! must leave it alone.
//!
//! The second half is not a nicety. A fingerprint that moved on every
//! edit would cold-start the whole fleet's cache on an unrelated
//! deploy, which is the reason this is a narrow projection rather than
//! a hash of the whole document.

use sbproxy_config::compile_config;

/// Compile `yaml` and return the fingerprint of the `cached.local`
/// origin.
fn fingerprint(yaml: &str) -> String {
    let compiled = compile_config(yaml).expect("config should compile");
    compiled
        .origins
        .iter()
        .find(|origin| origin.hostname == "cached.local")
        .expect("the cached.local origin should compile")
        .cache_config_fingerprint
        .to_string()
}

/// The baseline config every test below perturbs one piece of.
fn baseline() -> String {
    config_with("https://test.sbproxy.dev", "", "")
}

/// `upstream` is the cached origin's proxy target, `origin_extra` is
/// spliced into that origin's block, and `proxy_extra` into the
/// top-level `proxy:` block.
fn config_with(upstream: &str, origin_extra: &str, proxy_extra: &str) -> String {
    format!(
        "proxy:\n  http_bind_port: 8080\n{proxy_extra}\
         origins:\n  \"cached.local\":\n    action:\n      type: proxy\n      url: {upstream}\n\
         {origin_extra}\
         \n    response_cache:\n      enabled: true\n      ttl_secs: 60\n"
    )
}

// --- config that must move the fingerprint ---

#[test]
fn two_origins_differing_only_in_upstream_do_not_share_a_fingerprint() {
    // The failure this prevents: node A proxies cached.local to the old
    // upstream, node B to the new one, and a shared Redis hands B's
    // response to A's clients under an identical key.
    assert_ne!(
        fingerprint(&config_with("https://test.sbproxy.dev", "", "")),
        fingerprint(&config_with("https://other.sbproxy.dev", "", "")),
        "a repointed upstream must not inherit the old upstream's entries"
    );
}

#[test]
fn a_request_modifier_moves_the_fingerprint() {
    // Request modifiers change what the upstream sees, so they change
    // what it returns for an otherwise identical cache key.
    let modified = config_with(
        "https://test.sbproxy.dev",
        "    request_modifiers:\n      - headers:\n          set:\n            X-Tier: gold\n",
        "",
    );
    assert_ne!(
        fingerprint(&baseline()),
        fingerprint(&modified),
        "a request modifier changes the upstream representation"
    );
}

#[test]
fn the_response_cache_block_itself_moves_the_fingerprint() {
    let longer_ttl = config_with("https://test.sbproxy.dev", "", "").replace("ttl_secs: 60", "ttl_secs: 120");
    assert_ne!(
        fingerprint(&baseline()),
        fingerprint(&longer_ttl),
        "the response_cache block is part of its own identity"
    );
}

#[test]
fn bumping_the_epoch_moves_the_fingerprint() {
    // The operator escape hatch, for a change the projection cannot
    // see: an upstream that changed its response shape with no sbproxy
    // config change at all.
    let bumped = config_with("https://test.sbproxy.dev", "", "").replace(
        "      ttl_secs: 60\n",
        "      ttl_secs: 60\n      epoch: 1\n",
    );
    assert_ne!(
        fingerprint(&baseline()),
        fingerprint(&bumped),
        "bumping the epoch must rotate this origin's entries"
    );
}

// --- config that must not move the fingerprint ---

#[test]
fn an_unrelated_origin_leaves_the_fingerprint_untouched() {
    // The whole reason this is a per-origin projection rather than a
    // hash of the document: adding an origin must not cold-start every
    // other origin's cache.
    let with_neighbor = format!(
        "{}\n  \"other.local\":\n    action:\n      type: proxy\n      url: https://elsewhere.sbproxy.dev\n",
        baseline()
    );
    assert_eq!(
        fingerprint(&baseline()),
        fingerprint(&with_neighbor),
        "an unrelated origin must not rotate this origin's cache"
    );
}

#[test]
fn a_response_modifier_leaves_the_fingerprint_untouched() {
    // Response modifiers run downstream of the cache write. The stored
    // representation is the raw upstream one, so they cannot change it.
    let modified = config_with(
        "https://test.sbproxy.dev",
        "    response_modifiers:\n      - headers:\n          set:\n            X-Served-By: sbproxy\n",
        "",
    );
    assert_eq!(
        fingerprint(&baseline()),
        fingerprint(&modified),
        "response-side config is outside the cache boundary"
    );
}

#[test]
fn a_cors_block_leaves_the_fingerprint_untouched() {
    let with_cors = config_with(
        "https://test.sbproxy.dev",
        "    cors:\n      allow_origins: [\"https://example.com\"]\n",
        "",
    );
    assert_eq!(
        fingerprint(&baseline()),
        fingerprint(&with_cors),
        "CORS is a response-side concern and must not rotate the cache"
    );
}

#[test]
fn the_fingerprint_is_stable_across_recompiles() {
    // Any nondeterminism here (map iteration order, a timestamp) would
    // partition a single node from its own entries on every restart.
    assert_eq!(
        fingerprint(&baseline()),
        fingerprint(&baseline()),
        "the fingerprint must be a pure function of the config"
    );
}

#[test]
fn the_fingerprint_is_lowercase_hex_and_bounded() {
    let fp = fingerprint(&baseline());
    assert_eq!(fp.len(), 16, "expected 16 hex chars, got {fp:?}");
    assert!(
        fp.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "the fingerprint reaches a cache key and a Redis glob, so it must \
         stay lowercase hex: {fp:?}"
    );
}

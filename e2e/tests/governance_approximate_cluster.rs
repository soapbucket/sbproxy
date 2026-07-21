//! Multi-process approximate-governance acceptance coverage (WOR-1835).
//!
//! `key_management.governance.consistency: approximate` (the default) is
//! deliberately NOT cluster-coherent the way `strict` is: each gateway
//! counts governed-key usage in its own process-local `InMemoryGovernanceStore`
//! and only learns about other nodes' usage through a periodic CRDT
//! dissemination loop over the cluster mesh
//! (`crates/sbproxy-core/src/governance_cluster.rs`, spawned by
//! `start_governance_dissemination` in `crates/sbproxy-core/src/cluster.rs`).
//! That loop's cadence is hardcoded to 15 seconds
//! (`governance_cluster::run_loop(handle.clone(), store, 15)`), with each
//! published contribution TTLed at 3x that (45s). There is no config knob
//! for it today.
//!
//! This is the honest tradeoff the approximate tier makes for not needing
//! Redis: a request admitted on one node can be invisible to a sibling node
//! for up to one dissemination interval, so the *cluster-wide* limit can be
//! oversubscribed by whatever a peer node's own local window admits during
//! that gap. That gap is this test's "rounding unit" - a bounded amount of
//! slack, not an unbounded leak, and it disappears once dissemination has
//! ticked at least once.
//!
//! Local only; never added to the required CI gate (project e2e policy).
//! No Redis dependency; this exercises the no-backend approximate path.

use std::net::{TcpListener, UdpSocket};
use std::time::{Duration, Instant};

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::{json, Value};

const CLUSTER_ID: &str = "governance-approx-e2e";
const CLUSTER_SECRET: &str = "governance-approx-development-secret-123456";

/// Shared per-key request budget. Kept small so the two "waves" below (one
/// full window on node A, one just-under-full window on node B) finish in a
/// handful of requests each.
const LIMIT: u64 = 6;
/// Fired on node B immediately after node A's wave, before any
/// dissemination tick can possibly have landed. This is intentionally
/// `LIMIT - 1`, not `LIMIT`: it leaves node B's own local counter one
/// request short of its (locally-visible) ceiling, so the later assertion
/// that a merged peer view - not node B's own count - is what finally
/// blocks admission is unambiguous.
const WAVE_TWO_COUNT: u64 = LIMIT - 1;

/// The dissemination loop's hardcoded cadence
/// (`crates/sbproxy-core/src/governance_cluster.rs::run_loop`). Polling
/// waits comfortably past this rather than sleeping a fixed amount, so the
/// test is not flaky on a slow CI-less local box but also does not wait
/// longer than it has to.
const DISSEMINATION_INTERVAL_SECS: u64 = 15;

fn reserve_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve TCP port")
        .local_addr()
        .expect("reserved TCP address")
        .port()
}

fn reserve_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .expect("reserve UDP port")
        .local_addr()
        .expect("reserved UDP address")
        .port()
}

#[allow(clippy::too_many_arguments)]
fn config(
    admin_port: u16,
    node_id: &str,
    gossip_port: u16,
    transport_port: u16,
    seeds: &str,
    state_dir: &str,
    store_path: &str,
    upstream_base: &str,
    key_id: &str,
    secret: &str,
) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  admin:
    enabled: true
    port: {admin_port}
    username: admin
    password: secret
    # Headroom over the 60/min default. This suite polls the admin
    # surface from one client IP for membership, health, and usage
    # merges; at the default cap those polls exhaust the per-IP budget
    # mid-wait, and a 429-stalled poll loop outlives the governed
    # key's one-minute fixed window, so usage reads decay to 0 before
    # a merge can ever be observed.
    rate_limit_per_minute: 600
  cluster:
    cluster_id: {CLUSTER_ID}
    node_id: {node_id}
    roles: [gateway]
    seeds: {seeds}
    gossip_port: {gossip_port}
    transport_port: {transport_port}
    advertise_addr: 127.0.0.1:{gossip_port}
    transport_advertise_addr: 127.0.0.1:{transport_port}
    state_dir: "{state_dir}"
    security:
      mode: shared_key
      development: true
      shared_key: {CLUSTER_SECRET}
    snapshot_ttl_secs: 10
    publish_interval_secs: 1
    dead_peer_gc_secs: 5
  key_management:
    enabled: true
    store:
      backend: embedded
      path: "{store_path}"
    cache:
      ttl_secs: 60
    crypto:
      pepper: governance-approx-e2e-pepper
      master_key: governance-approx-e2e-master
    governance:
      consistency: approximate
      lease_ttl_secs: 30
      terminal_retention_secs: 60
    seed:
      keys:
        - key_id: {key_id}
          secret: {secret}
          name: approx-shared-budget
          max_requests_per_minute: {LIMIT}
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      require_governed_key: true
      providers:
        - name: openai
          api_key: sk-dummy
          base_url: "{upstream_base}"
          allow_private_base_url: true
          default_model: gpt-4o-mini
          models: [gpt-4o-mini]
"#
    )
}

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("HTTP client")
}

/// Send one governed chat request and return the HTTP status.
fn chat(base_url: &str, token: &str) -> u16 {
    client()
        .post(format!("{base_url}/v1/chat/completions"))
        .header("host", "ai.localhost")
        .header("authorization", format!("Bearer {token}"))
        .json(&json!({
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "approximate admission"}],
            "max_tokens": 1
        }))
        .send()
        .expect("governed chat request")
        .status()
        .as_u16()
}

fn admin_get(admin_port: u16, path: &str) -> Value {
    // The admin surface rate limits per client IP. Convergence polling in
    // this suite can exhaust that budget on slow runners, and a 429 means
    // "alive but throttled", not a failure, so back off and retry rather
    // than panicking mid-wait.
    for _ in 0..30 {
        let response = client()
            .get(format!("http://127.0.0.1:{admin_port}{path}"))
            .basic_auth("admin", Some("secret"))
            .send()
            .expect("admin request");
        if response.status().as_u16() == 429 {
            std::thread::sleep(Duration::from_secs(2));
            continue;
        }
        return response
            .error_for_status()
            .expect("admin status")
            .json::<Value>()
            .expect("admin JSON");
    }
    panic!("admin endpoint {path} still rate limited after 60s of backoff");
}

/// Poll `/admin/cluster/status` until this node sees `expected` total nodes,
/// all healthy. Bounded polling rather than a fixed sleep: gossip
/// convergence on loopback is normally sub-second, and this only needs to
/// wait long enough for that, not for the (much slower) governance
/// dissemination cadence tested later.
fn wait_for_cluster_size(admin_port: u16, expected: u64, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let status = admin_get(admin_port, "/admin/cluster/status");
        let total = status["summary"]["total_nodes"].as_u64().unwrap_or(0);
        // This helper waits on gossip membership only: every expected
        // node present and alive. Aggregate health converges slightly
        // later (snapshot collection lags membership by up to a publish
        // interval) and is asserted separately by
        // `wait_for_all_nodes_healthy` after this returns.
        let alive = status["nodes"]
            .as_array()
            .map(|nodes| {
                nodes
                    .iter()
                    .filter(|node| node["membership_state"] == "alive")
                    .count() as u64
            })
            .unwrap_or(0);
        if total >= expected && alive >= expected {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "admin port {admin_port} did not converge to {expected} alive cluster \
                 nodes within {timeout:?}; last status: {status}"
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Poll `/admin/cluster/status` until `summary.healthy_nodes` equals the
/// full node count. This cluster is gateway-only: nodes without the
/// worker role run no model plane, so an unavailable model plane must
/// not grade them degraded. Every node in a converged gateway-only
/// cluster therefore has to report healthy; anything less is the
/// role-blind grading defect resurfacing.
fn wait_for_all_nodes_healthy(admin_port: u16, expected: u64, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let status = admin_get(admin_port, "/admin/cluster/status");
        let healthy = status["summary"]["healthy_nodes"].as_u64().unwrap_or(0);
        if healthy == expected {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "admin port {admin_port} never reported summary.healthy_nodes == {expected} \
                 for its gateway-only cluster within {timeout:?} (last saw {healthy}); \
                 gateway-only nodes must not be graded on the model plane; last status: {status}"
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Read the current (locally merged) `requests_per_window.used` counter for
/// a governed key from one node's admin surface. Once a peer's contribution
/// has been disseminated and merged, this value includes that peer's usage,
/// not just this node's own.
fn requests_used(admin_port: u16, key_id: &str) -> u64 {
    let usage = admin_get(admin_port, &format!("/admin/keys/{key_id}/usage"));
    usage["usage"]["requests_per_window"]["used"]
        .as_u64()
        .unwrap_or(0)
}

/// Poll one node's usage view until it reflects at least `at_least`
/// requests, i.e. until a peer's contribution has been merged in. The
/// deadline deliberately exceeds `DISSEMINATION_INTERVAL_SECS` with margin:
/// this is the one place in the test that has to wait out the real
/// dissemination cadence, since there is no way to force an early tick.
fn wait_for_peer_merge(admin_port: u16, key_id: &str, at_least: u64, timeout: Duration) -> u64 {
    let deadline = Instant::now() + timeout;
    loop {
        let used = requests_used(admin_port, key_id);
        if used >= at_least {
            return used;
        }
        if Instant::now() >= deadline {
            panic!(
                "admin port {admin_port} never observed a merged peer contribution for {key_id} \
                 (want used >= {at_least}, last saw {used}) within {timeout:?}; the cross-node \
                 governance CRDT dissemination loop ticks every {DISSEMINATION_INTERVAL_SECS}s \
                 (crates/sbproxy-core/src/cluster.rs::start_governance_dissemination), so this \
                 deadline must comfortably exceed that cadence"
            );
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

#[test]
fn approximate_cluster_bounds_admission_to_one_dissemination_intervals_slack() {
    let suffix = std::process::id();
    let key_id = format!("approxgov{suffix}");
    let secret = "shared-approximate-secret";
    let token = format!("sk-{key_id}-{secret}");

    let root = tempfile::tempdir().expect("scratch workspace");
    let store_a = root.path().join("store-a.redb");
    let store_b = root.path().join("store-b.redb");
    let state_a = root.path().join("state-a");
    let state_b = root.path().join("state-b");
    std::fs::create_dir_all(&state_a).expect("state dir a");
    std::fs::create_dir_all(&state_b).expect("state dir b");

    let upstream = MockUpstream::start(json!({
        "id": "chatcmpl-governed",
        "object": "chat.completion",
        "model": "gpt-4o-mini",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "ok"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    }))
    .expect("mock upstream");

    let admin_a = reserve_tcp_port();
    let admin_b = reserve_tcp_port();
    let gossip_a = reserve_udp_port();
    let gossip_b = reserve_udp_port();
    let transport_a = reserve_tcp_port();
    let transport_b = reserve_tcp_port();

    let proxy_a = ProxyHarness::start_with_yaml(&config(
        admin_a,
        "node-a",
        gossip_a,
        transport_a,
        "[]",
        &state_a.display().to_string(),
        &store_a.display().to_string(),
        &upstream.base_url(),
        &key_id,
        secret,
    ))
    .expect("start gateway A");
    let proxy_b = ProxyHarness::start_with_yaml(&config(
        admin_b,
        "node-b",
        gossip_b,
        transport_b,
        &format!("[127.0.0.1:{gossip_a}]"),
        &state_b.display().to_string(),
        &store_b.display().to_string(),
        &upstream.base_url(),
        &key_id,
        secret,
    ))
    .expect("start gateway B");
    ProxyHarness::wait_for_port(admin_a, Duration::from_secs(10)).expect("admin A ready");
    ProxyHarness::wait_for_port(admin_b, Duration::from_secs(10)).expect("admin B ready");

    // Let gossip membership converge before touching governance at all;
    // this is unrelated to (and much faster than) the dissemination
    // cadence under test below.
    wait_for_cluster_size(admin_a, 2, Duration::from_secs(30));
    wait_for_cluster_size(admin_b, 2, Duration::from_secs(30));

    // With membership converged, both gateway-only nodes must grade
    // healthy: role-aware health means model_plane_unavailable neither
    // degrades a non-worker nor appears in its unhealthy_reasons.
    wait_for_all_nodes_healthy(admin_a, 2, Duration::from_secs(30));
    wait_for_all_nodes_healthy(admin_b, 2, Duration::from_secs(30));

    let base_a = proxy_a.base_url();
    let base_b = proxy_b.base_url();

    // Wave 1: exhaust the shared limit entirely on node A. Approximate
    // governance is exact within one process, so this must land exactly on
    // the limit with zero denials.
    let mut wave_one = Vec::new();
    for _ in 0..LIMIT {
        wave_one.push(chat(&base_a, &token));
    }
    assert!(
        wave_one.iter().all(|status| *status == 200),
        "node A alone must exactly admit up to its own local view of the limit: {wave_one:?}"
    );

    // Wave 2: fired on node B immediately, with no wait. Node B has not
    // received any dissemination tick yet (the loop's first tick is
    // DISSEMINATION_INTERVAL_SECS after boot), so it only sees its own
    // (empty) local counters and independently admits its own requests.
    // This is the documented gap: cluster-wide true usage after this wave
    // is LIMIT + WAVE_TWO_COUNT (2*LIMIT - 1), well past the shared limit,
    // purely because node B has not yet learned about node A's spend.
    let mut wave_two = Vec::new();
    for _ in 0..WAVE_TWO_COUNT {
        wave_two.push(chat(&base_b, &token));
    }
    assert!(
        wave_two.iter().all(|status| *status == 200),
        "node B must admit its own under-the-local-limit requests before dissemination \
         has had a chance to inform it about node A's usage: {wave_two:?}"
    );

    let accepted_before_dissemination = wave_one.len() + wave_two.len();
    assert_eq!(
        accepted_before_dissemination as u64,
        LIMIT + WAVE_TWO_COUNT,
        "the pre-dissemination slack is bounded: at most one full local window on a peer \
         node (here WAVE_TWO_COUNT = LIMIT - 1) can be admitted beyond the shared limit \
         before the next CRDT tick merges cross-node usage; this is the approximate tier's \
         rounding unit, sized by the dissemination interval, not an unbounded leak"
    );

    // Now wait out the real dissemination cadence: poll node B until its
    // merged view includes node A's contribution. The deadline is set with
    // real margin over DISSEMINATION_INTERVAL_SECS because loopback gossip
    // publish/read round trips add latency on top of the raw tick.
    let merged_used = wait_for_peer_merge(
        admin_b,
        &key_id,
        LIMIT + WAVE_TWO_COUNT,
        Duration::from_secs(DISSEMINATION_INTERVAL_SECS * 3),
    );
    assert!(
        merged_used >= LIMIT + WAVE_TWO_COUNT,
        "node B's merged usage view must include node A's disseminated contribution: {merged_used}"
    );

    // Once dissemination has landed, the slack is gone: further requests on
    // either node must be denied, because each node's reserve() call now
    // adds its own local count to the merged peer view before checking the
    // limit (crates/sbproxy-ai/src/governance.rs::reserve_units). Node B in
    // particular still has local headroom under ITS OWN counter alone
    // (WAVE_TWO_COUNT < LIMIT), so a denial here can only come from the
    // merged peer view, not node B's own count.
    let post_dissemination_b = chat(&base_b, &token);
    assert_eq!(
        post_dissemination_b, 429,
        "node B must deny once it has merged node A's usage, even though node B's own \
         local counter alone still has headroom"
    );
    let post_dissemination_a = chat(&base_a, &token);
    assert_eq!(
        post_dissemination_a, 429,
        "node A must keep denying once its own local counter has hit the limit"
    );

    // Repeat a couple more times on each node to make sure the bound holds
    // firmly rather than being a one-shot fluke of timing.
    for _ in 0..2 {
        assert_eq!(
            chat(&base_b, &token),
            429,
            "node B must stay denied after convergence"
        );
        assert_eq!(
            chat(&base_a, &token),
            429,
            "node A must stay denied after convergence"
        );
    }

    // No denied request should ever have reached the upstream: only the
    // admitted wave-1 + wave-2 requests may have dispatched.
    assert_eq!(
        upstream.captured().len() as u64,
        LIMIT + WAVE_TWO_COUNT,
        "denied requests (before or after dissemination) must never reach the upstream"
    );
}

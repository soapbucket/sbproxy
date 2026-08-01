//! Attested consumption metering, end to end (WOR-2145).
//!
//! Every layer of the meter shipped across eight PRs and none of it ran on
//! a request, so these tests exist to hold the seam rather than the parts.
//! They assert against the file on disk and against the proxy's own verify
//! route, never against an internal type, because the thing being promised
//! is that a buyer with the ledger and the published key can check the bill
//! without asking the seller for anything.
//!
//! # What is deliberately not tested here
//!
//! A forced append failure on a chain that opened successfully. There is no
//! way to make an already-open append file descriptor fail from outside the
//! process, so the signed gap marker is covered by unit tests in
//! `sbproxy-core/src/meter_runtime.rs`, which can inject the failure. What
//! is reachable from out here is the other half of the same posture: a
//! chain that could not be opened at all, which is what a full or unwritable
//! disk actually looks like, and which the tests below do cover under every
//! failure mode.

use std::net::TcpListener;
use std::path::{Path, PathBuf};

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

/// Ed25519 seed the proxy signs receipts with. A fixed test value: the
/// receipt chain's signature is derived from it, so a random seed would
/// make a failure unreproducible.
const SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

/// The genesis digest every chain starts from.
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn pick_admin_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("local addr").port()
}

/// A complete `proxy.attestation` block, parameterised on the two things
/// each test varies.
///
/// `cache_hit` is a parameter because it is the one billing answer that is
/// a commercial position rather than a technical fact, and both positions
/// have to be exercised.
fn config_yaml(
    admin_port: u16,
    ledger: &Path,
    queue: &Path,
    upstream_url: &str,
    failure_mode: &str,
    cache_hit: &str,
) -> String {
    // Single-quoted paths: a Windows path contains backslashes, and YAML
    // treats those as escapes inside double quotes.
    format!(
        r#"
proxy:
  http_bind_port: 0
  admin:
    enabled: true
    port: {admin_port}
    username: admin
    password: secret
  web_bot_auth:
    key_id: acme-prod-1
    ed25519_seed_hex: {SEED_HEX}
  attestation:
    role: receipt
    failure_mode: {failure_mode}
    sign_with: proxy.web_bot_auth
    queue:
      path: '{queue}'
      max_entries: 1000
    ledger:
      path: '{ledger}'
    billable:
      delivered: "yes"
      client_disconnected: "partial"
      origin_4xx: "no"
      origin_5xx: "no"
      policy_blocked: "no"
      rate_limited: "no"
      cache_hit: "{cache_hit}"
      retry: "collapse"
    measured:
      - name: egress_kib
        quantity: bytes_out
        per: 1024
      - name: api_call
        quantity: requests
    route_weights:
      - name: search_call
        path: /search
        weight: 5
    origin_headers:
      - name: result_row
        header: X-Rows-Returned
origins:
  "meter.localhost":
    action:
      type: proxy
      url: "{upstream_url}"
    attestation:
      agreement_id: acme-2026
    response_cache:
      enabled: true
      ttl: 60
      cacheable_methods: [GET]
      cacheable_status: [200]
"#,
        queue = queue.display(),
        ledger = ledger.display(),
    )
}

/// Read the chain file and return one parsed entry per line.
fn read_chain(ledger: &Path) -> Vec<serde_json::Value> {
    let body = std::fs::read_to_string(ledger)
        .unwrap_or_else(|error| panic!("read chain {}: {error}", ledger.display()));
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("chain line is not JSON: {error}: {line}"))
        })
        .collect()
}

/// Poll until the chain has at least `want` entries, or fail.
///
/// The receipt is cut in the proxy's `logging` phase, which runs after the
/// response has been written to the client, so a test that read the file
/// the instant its HTTP call returned would be racing the writer.
fn wait_for_entries(ledger: &Path, want: usize) -> Vec<serde_json::Value> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if ledger.exists() {
            let entries = read_chain(ledger);
            if entries.len() >= want {
                return entries;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "chain at {} did not reach {want} entries within five seconds",
            ledger.display()
        );
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}

/// Poll until the chain carries an entry with `outcome`, and return it.
///
/// Waiting on an entry count instead would be waiting for the wrong thing.
/// The receipt is cut after the response has been written, so the number of
/// entries reaches any given total before the interesting one has
/// necessarily been appended, and a test that counted would read an
/// incomplete chain and report a missing outcome that was merely late.
fn wait_for_outcome(ledger: &Path, outcome: &str) -> serde_json::Value {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if ledger.exists() {
            if let Some(entry) = read_chain(ledger)
                .into_iter()
                .find(|entry| entry["event"]["outcome"] == outcome)
            {
                return entry;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no entry with outcome {outcome} appeared in {} within ten seconds; chain was {:?}",
            ledger.display(),
            ledger.exists().then(|| read_chain(ledger)),
        );
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}

/// Drive requests until the response cache serves one, and return it.
fn wait_for_cache_hit(proxy: &ProxyHarness) -> sbproxy_e2e::Response {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let response = proxy.get("/cached", "meter.localhost").expect("cache poll");
        if response
            .headers
            .get("x-sbproxy-cache")
            .is_some_and(|value| value == "HIT")
        {
            return response;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the response cache never served a hit; last response: {response:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

fn admin_request(port: u16, method: &str, path: &str) -> (u16, String) {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("client");
    let url = format!("http://127.0.0.1:{port}{path}");
    let builder = match method {
        "POST" => client.post(url),
        _ => client.get(url),
    };
    let response = builder
        .basic_auth("admin", Some("secret"))
        .send()
        .expect("admin request");
    let status = response.status().as_u16();
    (status, response.text().unwrap_or_default())
}

/// A temp dir plus the two state paths inside it.
struct StateDir {
    dir: tempfile::TempDir,
}

impl StateDir {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("temp dir"),
        }
    }

    fn ledger(&self) -> PathBuf {
        self.dir.path().join("state").join("receipts.ndjson")
    }

    fn queue(&self) -> PathBuf {
        self.dir.path().join("state").join("claims.q")
    }

    /// Make the ledger path unopenable while leaving its parent intact.
    ///
    /// A directory where the chain expects a file. `ensure_state_dir`
    /// still creates the parent, so boot proceeds and the failure lands
    /// exactly where a full or unwritable disk would put it: on the open,
    /// at the moment the first receipt is owed.
    fn break_the_ledger(&self) {
        let ledger = self.ledger();
        std::fs::create_dir_all(&ledger).expect("occupy the ledger path with a directory");
    }
}

#[test]
fn a_metered_request_writes_one_verifiable_receipt() {
    let state = StateDir::new();
    let admin_port = pick_admin_port();
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let proxy = ProxyHarness::start_with_yaml(&config_yaml(
        admin_port,
        &state.ledger(),
        &state.queue(),
        &upstream.base_url(),
        "degraded",
        "yes",
    ))
    .expect("start proxy");
    ProxyHarness::wait_for_port(admin_port, std::time::Duration::from_secs(5))
        .expect("admin port to bind");

    let response = proxy
        .get("/search", "meter.localhost")
        .expect("GET /search");
    assert_eq!(response.status, 200);

    let entries = wait_for_entries(&state.ledger(), 1);
    assert_eq!(entries.len(), 1, "one request, one receipt");
    let entry = &entries[0];

    // The chain half: position, linkage, and a signature over the digest.
    assert_eq!(entry["seq"], 0);
    assert_eq!(entry["prev_hash"], GENESIS);
    assert!(
        entry["signature"].is_string(),
        "the chain is signed with the web_bot_auth seed the role names: {entry}"
    );

    // The receipt half. `seq` and `prev` inside the claims must agree with
    // the entry that carries them, or the signed document describes a
    // position in a chain other than the one it is in.
    let receipt = &entry["event"];
    assert_eq!(receipt["seq"], 0);
    assert_eq!(receipt["prev"], GENESIS);
    assert_eq!(receipt["outcome"], "delivered");
    assert_eq!(receipt["agreement_id"], "acme-2026");
    assert_eq!(receipt["route"], "/search");
    assert!(
        receipt["config_revision"]
            .as_str()
            .is_some_and(|revision| revision.len() == 12),
        "config_revision is the 12 hex char content hash: {receipt}"
    );
    assert!(
        receipt.get("request_digest").is_none(),
        "no request body was buffered, so claiming a digest over one would be a lie: {receipt}"
    );

    // And the proxy's own verifier agrees. The route reports a verdict as
    // `outcome` plus the sequence it broke at, rather than a bare boolean,
    // so that a caller learns where a chain stopped verifying and not only
    // that it did.
    let (status, body) = admin_request(admin_port, "POST", "/api/meter/verify");
    assert_eq!(status, 200, "verify route: {body}");
    let verdict: serde_json::Value = serde_json::from_str(&body).expect("verify JSON");
    assert_eq!(verdict["outcome"], "ok", "chain must verify: {verdict}");
    assert!(
        verdict["broken_seq"].is_null(),
        "a verifying chain has no broken link: {verdict}"
    );
    assert_eq!(verdict["entries"], 1, "one request, one entry: {verdict}");
}

#[test]
fn three_resolvers_produce_three_lines_and_never_their_sum() {
    let state = StateDir::new();
    let admin_port = pick_admin_port();
    let upstream = MockUpstream::start_with_response_headers(
        json!({"ok": true}),
        vec![("x-rows-returned".to_string(), "47".to_string())],
    )
    .expect("upstream");
    let proxy = ProxyHarness::start_with_yaml(&config_yaml(
        admin_port,
        &state.ledger(),
        &state.queue(),
        &upstream.base_url(),
        "degraded",
        "yes",
    ))
    .expect("start proxy");

    let response = proxy
        .get("/search", "meter.localhost")
        .expect("GET /search");
    assert_eq!(response.status, 200);

    let entries = wait_for_entries(&state.ledger(), 1);
    let units = entries[0]["event"]["units"]
        .as_array()
        .expect("units is an array")
        .clone();

    let sources: Vec<&str> = units
        .iter()
        .map(|unit| unit["source"].as_str().expect("source is a string"))
        .collect();
    assert!(
        sources.contains(&"measured")
            && sources.contains(&"route_weight")
            && sources.contains(&"origin_header"),
        "all three provenances stay separate lines: {units:?}"
    );

    // The origin's claim is recorded as the origin's claim, never
    // laundered into something the proxy vouches for, and its raw value
    // survives verbatim.
    let claimed = units
        .iter()
        .find(|unit| unit["source"] == "origin_header")
        .expect("an origin_header line");
    assert_eq!(claimed["count"], 47);
    assert_eq!(claimed["evidence"]["raw"], "47");
    assert_eq!(claimed["evidence"]["header"], "X-Rows-Returned");

    let weighted = units
        .iter()
        .find(|unit| unit["source"] == "route_weight")
        .expect("a route_weight line");
    assert_eq!(weighted["count"], 5);
    assert!(
        weighted["evidence"]["config_revision"].is_string(),
        "a weight has to name the document that set it: {weighted}"
    );

    // The defect this design exists to prevent: one number nobody can take
    // apart. No line may equal the total.
    let total: u64 = units
        .iter()
        .map(|unit| unit["count"].as_u64().expect("count is a number"))
        .sum();
    assert!(
        units
            .iter()
            .all(|unit| unit["count"].as_u64() != Some(total)),
        "units must never be summed into one unfalsifiable figure: {units:?}"
    );
}

#[test]
fn a_cache_hit_bills_when_the_table_says_yes() {
    let state = StateDir::new();
    let admin_port = pick_admin_port();
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let proxy = ProxyHarness::start_with_yaml(&config_yaml(
        admin_port,
        &state.ledger(),
        &state.queue(),
        &upstream.base_url(),
        "degraded",
        "yes",
    ))
    .expect("start proxy");

    // Warm, then hit.
    proxy.get("/cached", "meter.localhost").expect("warm");
    let hit = wait_for_cache_hit(&proxy);
    assert_eq!(hit.status, 200);

    let cached = wait_for_outcome(&state.ledger(), "cache_hit");
    let units = cached["event"]["units"]
        .as_array()
        .expect("units is an array");
    assert!(
        !units.is_empty(),
        "the table says cache_hit bills, so the receipt carries billed units: {cached}"
    );
}

#[test]
fn a_cache_hit_bills_nothing_when_the_table_says_no() {
    let state = StateDir::new();
    let admin_port = pick_admin_port();
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let proxy = ProxyHarness::start_with_yaml(&config_yaml(
        admin_port,
        &state.ledger(),
        &state.queue(),
        &upstream.base_url(),
        "degraded",
        "no",
    ))
    .expect("start proxy");

    proxy.get("/cached", "meter.localhost").expect("warm");
    wait_for_cache_hit(&proxy);

    let cached = wait_for_outcome(&state.ledger(), "cache_hit");

    // Recorded, and billed nothing. Omitting the receipt entirely would
    // leave the chain unreconcilable against a request log, which is the
    // other half of what the chain is for.
    assert_eq!(
        cached["event"]["units"]
            .as_array()
            .expect("units is an array")
            .len(),
        0,
        "the table says cache_hit is free, so no unit may be billed: {cached}"
    );
}

#[test]
fn closed_refuses_when_the_chain_cannot_be_written() {
    let state = StateDir::new();
    state.break_the_ledger();
    let admin_port = pick_admin_port();
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let proxy = ProxyHarness::start_with_yaml(&config_yaml(
        admin_port,
        &state.ledger(),
        &state.queue(),
        &upstream.base_url(),
        "closed",
        "yes",
    ))
    .expect("start proxy");

    let response = proxy
        .get("/search", "meter.localhost")
        .expect("GET /search");
    assert_eq!(
        response.status, 503,
        "closed means the seller does not deliver value it cannot bill for: {response:?}"
    );
}

#[test]
fn degraded_admits_and_counts_the_gap_it_left() {
    let state = StateDir::new();
    state.break_the_ledger();
    let admin_port = pick_admin_port();
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let proxy = ProxyHarness::start_with_yaml(&config_yaml(
        admin_port,
        &state.ledger(),
        &state.queue(),
        &upstream.base_url(),
        "degraded",
        "yes",
    ))
    .expect("start proxy");

    let response = proxy
        .get("/search", "meter.localhost")
        .expect("GET /search");
    assert_eq!(
        response.status, 200,
        "billing is not a security boundary; a full disk must not take the API down"
    );

    // The hole is countable, which is what makes admitting defensible.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let metrics = proxy
            .get("/metrics", "meter.localhost")
            .expect("GET /metrics");
        let body = metrics.text().unwrap_or_default();
        if body
            .lines()
            .any(|line| line.starts_with("sbproxy_meter_chain_gap_total") && !line.ends_with(" 0"))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "sbproxy_meter_chain_gap_total never moved; an unbillable request left no trace"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

#[test]
fn observe_never_changes_a_response() {
    let state = StateDir::new();
    state.break_the_ledger();
    let admin_port = pick_admin_port();
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let proxy = ProxyHarness::start_with_yaml(&config_yaml(
        admin_port,
        &state.ledger(),
        &state.queue(),
        &upstream.base_url(),
        "observe",
        "yes",
    ))
    .expect("start proxy");

    // The chain is unopenable and the meter cannot record a thing, which
    // is precisely the situation in which the rollout posture must stay
    // invisible to a caller.
    let response = proxy
        .get("/search", "meter.localhost")
        .expect("GET /search");
    assert_eq!(response.status, 200);
    let body = response.text().expect("body");
    assert!(
        body.contains("\"ok\""),
        "observe must not alter the body it observed: {body}"
    );
}

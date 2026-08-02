//! Multi-process strict-governance acceptance coverage (WOR-1835).
//!
//! Two independent proxy processes share one governed key and one Redis
//! governance backend (`key_management.governance.consistency: strict`).
//! The whole point of strict consistency is that admission is a
//! cluster-wide atomic reservation, not a per-process counter: firing a
//! burst of concurrent requests split across both gateways must never let
//! the combined accepted count exceed the key's shared limit, even though
//! neither gateway can see the other's in-memory state.
//!
//! Requires `redis-server` on PATH (the test spawns and owns its own
//! instance; no external Redis is touched) and a prebuilt `sbproxy`
//! binary. Ordinary local runs skip with a message when `redis-server`
//! is unavailable. Set `SBPROXY_E2E_REQUIRE_REDIS=1` in CI or other
//! dependency-complete environments to make a missing Redis executable
//! fail instead. This test is not part of the required PR CI gate.

use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::{json, Value};

/// Shared per-key request budget. Small on purpose: the assertion is exact
/// (`accepted <= LIMIT`), so a tight limit makes any race in the reserve
/// path show up as a clear over-admission rather than noise.
const LIMIT: u64 = 10;
/// Roughly 2x the limit, split across both gateways, fired concurrently.
const REQUESTS: usize = 20;

/// Shared per-key lifetime token budget for the token-dimension load
/// test. Sized so the reservation ceiling for the fixture prompt (a
/// dozen or so `o200k_base` tokens) fits several times over but cannot
/// cover twenty requests, so the burst is guaranteed to produce both
/// admissions and governance denials no matter how the two gateways
/// interleave.
const TOKEN_LIMIT: u64 = 24;
/// Total tokens the mock upstream reports for every response, and
/// therefore the amount each admitted request settles. Deliberately far
/// below the reservation ceiling, which is what makes the accepted total
/// exact rather than approximate: settled usage never exceeds the units
/// the reserve already held, so the documented rounding unit for this
/// case is zero. See `docs/key-management.md`.
const SETTLED_TOKENS_PER_REQUEST: u64 = 2;

fn pick_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("ephemeral address")
        .port()
}

/// A private `redis-server` child, killed on drop. Mirrors
/// `e2e/tests/key_replicas.rs::RedisGuard`.
struct RedisGuard {
    child: Child,
    port: u16,
}

impl RedisGuard {
    /// Spawn `redis-server` on an ephemeral port with persistence disabled.
    /// Returns `None` when the binary is not installed.
    fn spawn() -> Option<Self> {
        let port = pick_port();
        let child = match Command::new("redis-server")
            .args([
                "--port",
                &port.to_string(),
                "--save",
                "",
                "--appendonly",
                "no",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if std::env::var_os("SBPROXY_E2E_REQUIRE_REDIS").as_deref()
                    == Some(std::ffi::OsStr::new("1"))
                {
                    panic!(
                        "SBPROXY_E2E_REQUIRE_REDIS=1 but redis-server was not found on PATH; \
                         install redis-server before running governance_strict"
                    );
                }
                return None;
            }
            Err(e) => panic!("spawn redis-server: {e}"),
        };
        let guard = Self { child, port };
        guard.wait_ready(Duration::from_secs(10));
        Some(guard)
    }

    fn url(&self) -> String {
        format!("redis://127.0.0.1:{}", self.port)
    }

    /// Block until the server accepts TCP connections.
    fn wait_ready(&self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if TcpStream::connect(format!("127.0.0.1:{}", self.port)).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!(
            "redis-server did not accept connections on port {}",
            self.port
        );
    }
}

impl Drop for RedisGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One gateway's config: its own embedded key store (so minting is purely
/// local/declarative via `seed.keys`), but the SAME Redis governance
/// backend as every other gateway, so admission accounting is coherent
/// cluster-wide even though the key *records* are not shared.
fn config(
    admin_port: u16,
    store_path: &str,
    redis_url: &str,
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
  key_management:
    enabled: true
    store:
      backend: embedded
      path: "{store_path}"
    cache:
      ttl_secs: 60
    crypto:
      pepper: governance-strict-e2e-pepper
      master_key: governance-strict-e2e-master
    governance:
      consistency: strict
      backend:
        type: redis
        url: "{redis_url}"
      lease_ttl_secs: 30
      terminal_retention_secs: 60
      failure_mode: closed
    seed:
      keys:
        - key_id: {key_id}
          secret: {secret}
          name: strict-shared-budget
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

/// Same two-gateway strict shape as [`config`], but the governed key
/// carries a lifetime token budget instead of a request-per-minute
/// limit, so admission is decided on the token dimension.
fn token_budget_config(
    admin_port: u16,
    store_path: &str,
    redis_url: &str,
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
  key_management:
    enabled: true
    store:
      backend: embedded
      path: "{store_path}"
    cache:
      ttl_secs: 60
    crypto:
      pepper: governance-strict-tokens-e2e-pepper
      master_key: governance-strict-tokens-e2e-master
    governance:
      consistency: strict
      backend:
        type: redis
        url: "{redis_url}"
      lease_ttl_secs: 30
      terminal_retention_secs: 60
      failure_posture: closed
    seed:
      keys:
        - key_id: {key_id}
          secret: {secret}
          name: strict-shared-token-budget
          max_budget_tokens: {TOKEN_LIMIT}
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
          default_model: gpt-4o
          models: [gpt-4o]
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
            "messages": [{"role": "user", "content": "strict admission"}],
            "max_tokens": 1
        }))
        .send()
        .expect("governed chat request")
        .status()
        .as_u16()
}

/// Send one governed chat request against the token-budget fixture and
/// return the HTTP status. The prompt is short on purpose: the reserve
/// holds a conservative ceiling derived from it, and a short prompt
/// keeps that ceiling well inside [`TOKEN_LIMIT`].
fn chat_tokens(base_url: &str, token: &str) -> u16 {
    client()
        .post(format!("{base_url}/v1/chat/completions"))
        .header("host", "ai.localhost")
        .header("authorization", format!("Bearer {token}"))
        .json(&json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "budget"}],
            "max_tokens": 1
        }))
        .send()
        .expect("governed chat request")
        .status()
        .as_u16()
}

fn admin_usage(admin_port: u16, key_id: &str) -> Value {
    client()
        .get(format!(
            "http://127.0.0.1:{admin_port}/admin/keys/{key_id}/usage"
        ))
        .basic_auth("admin", Some("secret"))
        .send()
        .expect("admin usage request")
        .error_for_status()
        .expect("admin usage status")
        .json::<Value>()
        .expect("admin usage JSON")
}

#[test]
fn required_redis_mode_fails_when_redis_server_is_unavailable() {
    let test_binary = std::env::current_exe().expect("current governance_strict test binary");
    let output = Command::new(test_binary)
        .args([
            "--exact",
            "two_gateways_never_admit_more_than_the_shared_strict_request_limit",
            "--nocapture",
        ])
        .env("PATH", "/sbproxy-e2e-intentionally-missing")
        .env("SBPROXY_E2E_REQUIRE_REDIS", "1")
        .output()
        .expect("run governance_strict in Redis-required mode");

    assert!(
        !output.status.success(),
        "Redis-required mode must fail instead of reporting a successful skip; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("SBPROXY_E2E_REQUIRE_REDIS=1 but redis-server was not found on PATH"),
        "failure must explain how to satisfy the Redis dependency; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn two_gateways_never_admit_more_than_the_shared_strict_request_limit() {
    let Some(redis) = RedisGuard::spawn() else {
        eprintln!(
            "SKIP governance_strict::two_gateways_never_admit_more_than_the_shared_strict_request_limit: \
             redis-server not found on PATH (optional for local runs; set \
             SBPROXY_E2E_REQUIRE_REDIS=1 to require it)"
        );
        return;
    };

    let suffix = std::process::id();
    let key_id = format!("strictgov{suffix}");
    let secret = "shared-strict-secret";
    let token = format!("sk-{key_id}-{secret}");

    let store_a = format!(
        "{}/sbproxy_e2e_governance_strict_a_{suffix}.redb",
        std::env::temp_dir().display()
    );
    let store_b = format!(
        "{}/sbproxy_e2e_governance_strict_b_{suffix}.redb",
        std::env::temp_dir().display()
    );
    let _ = std::fs::remove_file(&store_a);
    let _ = std::fs::remove_file(&store_b);

    // A single shared mock upstream is fine: both gateways only need to
    // observe whether a request reached dispatch at all, not per-gateway
    // provider isolation.
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

    let admin_a = pick_port();
    let admin_b = pick_port();
    let redis_url = redis.url();

    let proxy_a = ProxyHarness::start_with_yaml(&config(
        admin_a,
        &store_a,
        &redis_url,
        &upstream.base_url(),
        &key_id,
        secret,
    ))
    .expect("start gateway A");
    let proxy_b = ProxyHarness::start_with_yaml(&config(
        admin_b,
        &store_b,
        &redis_url,
        &upstream.base_url(),
        &key_id,
        secret,
    ))
    .expect("start gateway B");
    ProxyHarness::wait_for_port(admin_a, Duration::from_secs(10)).expect("admin A ready");
    ProxyHarness::wait_for_port(admin_b, Duration::from_secs(10)).expect("admin B ready");

    // Fire ~2x the limit, alternating gateways, all released from a
    // barrier at once so the two processes race each other against the
    // one shared Redis reservation.
    let bases = [proxy_a.base_url(), proxy_b.base_url()];
    let barrier = Arc::new(Barrier::new(REQUESTS + 1));
    let mut workers = Vec::with_capacity(REQUESTS);
    for index in 0..REQUESTS {
        let base = bases[index % bases.len()].clone();
        let token = token.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            chat(&base, &token)
        }));
    }
    barrier.wait();
    let statuses: Vec<u16> = workers
        .into_iter()
        .map(|worker| worker.join().expect("request worker"))
        .collect();

    let accepted = statuses.iter().filter(|status| **status == 200).count();
    let denied = statuses.iter().filter(|status| **status == 429).count();
    assert_eq!(
        accepted + denied,
        REQUESTS,
        "every response must be either admitted or governance-denied: {statuses:?}"
    );
    assert!(
        accepted > 0,
        "sanity: at least some requests under the limit must be admitted: {statuses:?}"
    );
    assert!(
        accepted as u64 <= LIMIT,
        "strict Redis reservation must never let two gateways jointly admit more than \
         the shared limit ({LIMIT}); accepted={accepted} statuses={statuses:?}"
    );

    // Denied requests must never reach the upstream: the reserve() call
    // happens before dispatch, so a 429 short-circuits before any provider
    // I/O.
    assert_eq!(
        upstream.captured().len(),
        accepted,
        "only admitted requests may reach the upstream"
    );

    // Cross-check the admin-visible ledger agrees with what the request
    // path actually admitted. The governance store settles synchronously
    // before each response is written, so by the time every worker thread
    // above has joined, all `accepted` reservations must already be
    // settled (reserved == 0) rather than still outstanding.
    let usage = admin_usage(admin_a, &key_id)["usage"].clone();
    assert_eq!(usage["requests_per_window"]["limit"], LIMIT);
    assert_eq!(usage["requests_per_window"]["used"], accepted as u64);
    assert_eq!(
        usage["requests_per_window"]["reserved"], 0,
        "every reservation must be settled once its HTTP response has been sent"
    );
    assert_eq!(usage["backend"]["consistency"], "strict");
    assert_eq!(usage["backend"]["status"], "healthy");
}

/// The token half of the same guarantee, which is the one that actually
/// decides whether a spend budget means anything.
///
/// A request limit is trivially exact: every admission costs one unit
/// and the unit is known before dispatch. A token budget is not, because
/// the size of the response is unknown at reserve time. Strict mode
/// closes that by holding a conservative ceiling and replacing it with
/// reported usage at settlement, so the ledger can only ever move by the
/// amount really consumed.
///
/// The property under test: with one shared token budget and two
/// gateways racing a burst, the settled total is exactly
/// `accepted * SETTLED_TOKENS_PER_REQUEST` and never passes
/// `TOKEN_LIMIT`. The documented rounding unit here is zero, because
/// every response settles less than its reserve already held. A response
/// that settles more than it reserved (an unbounded completion against a
/// short prompt) can overshoot by that excess, which the store records
/// per reservation as `tokens_exceeded_reservation`; see
/// `docs/key-management.md`.
#[test]
fn two_gateways_never_settle_more_than_the_shared_strict_token_budget() {
    let Some(redis) = RedisGuard::spawn() else {
        eprintln!(
            "SKIP governance_strict::two_gateways_never_settle_more_than_the_shared_strict_token_budget: \
             redis-server not found on PATH (optional for local runs; set \
             SBPROXY_E2E_REQUIRE_REDIS=1 to require it)"
        );
        return;
    };

    let suffix = std::process::id();
    let key_id = format!("stricttok{suffix}");
    let secret = "shared-strict-token-secret";
    let token = format!("sk-{key_id}-{secret}");

    let store_a = format!(
        "{}/sbproxy_e2e_governance_tokens_a_{suffix}.redb",
        std::env::temp_dir().display()
    );
    let store_b = format!(
        "{}/sbproxy_e2e_governance_tokens_b_{suffix}.redb",
        std::env::temp_dir().display()
    );
    let _ = std::fs::remove_file(&store_a);
    let _ = std::fs::remove_file(&store_b);

    let upstream = MockUpstream::start(json!({
        "id": "chatcmpl-token-governed",
        "object": "chat.completion",
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "ok"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    }))
    .expect("mock upstream");

    let admin_a = pick_port();
    let admin_b = pick_port();
    let redis_url = redis.url();

    let proxy_a = ProxyHarness::start_with_yaml(&token_budget_config(
        admin_a,
        &store_a,
        &redis_url,
        &upstream.base_url(),
        &key_id,
        secret,
    ))
    .expect("start token-budget gateway A");
    let proxy_b = ProxyHarness::start_with_yaml(&token_budget_config(
        admin_b,
        &store_b,
        &redis_url,
        &upstream.base_url(),
        &key_id,
        secret,
    ))
    .expect("start token-budget gateway B");
    ProxyHarness::wait_for_port(admin_a, Duration::from_secs(10)).expect("admin A ready");
    ProxyHarness::wait_for_port(admin_b, Duration::from_secs(10)).expect("admin B ready");

    let bases = [proxy_a.base_url(), proxy_b.base_url()];
    let barrier = Arc::new(Barrier::new(REQUESTS + 1));
    let mut workers = Vec::with_capacity(REQUESTS);
    for index in 0..REQUESTS {
        let base = bases[index % bases.len()].clone();
        let token = token.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            chat_tokens(&base, &token)
        }));
    }
    barrier.wait();
    let statuses: Vec<u16> = workers
        .into_iter()
        .map(|worker| worker.join().expect("request worker"))
        .collect();

    let accepted = statuses.iter().filter(|status| **status == 200).count();
    let denied = statuses.iter().filter(|status| **status == 429).count();
    assert_eq!(
        accepted + denied,
        REQUESTS,
        "every response must be either admitted or governance-denied: {statuses:?}"
    );
    assert!(
        accepted > 0,
        "sanity: the budget covers several requests, so some must be admitted. Zero \
         admissions means the reservation ceiling for the fixture prompt outgrew \
         TOKEN_LIMIT ({TOKEN_LIMIT}); statuses={statuses:?}"
    );
    assert!(
        denied > 0,
        "sanity: twenty requests cannot fit a {TOKEN_LIMIT}-token budget, so the limit \
         must bite; statuses={statuses:?}"
    );
    assert_eq!(
        upstream.captured().len(),
        accepted,
        "only admitted requests may reach the upstream"
    );

    let usage = admin_usage(admin_a, &key_id)["usage"].clone();
    let settled = usage["total_tokens"]["used"]
        .as_u64()
        .expect("settled token total");
    assert_eq!(usage["total_tokens"]["limit"], TOKEN_LIMIT);
    assert_eq!(
        settled,
        accepted as u64 * SETTLED_TOKENS_PER_REQUEST,
        "the ledger must account for exactly the usage the admitted requests reported"
    );
    assert!(
        settled <= TOKEN_LIMIT,
        "two gateways jointly settled {settled} tokens against a shared {TOKEN_LIMIT}-token \
         budget; statuses={statuses:?}"
    );
    assert_eq!(
        usage["total_tokens"]["reserved"], 0,
        "every reservation must be settled once its HTTP response has been sent"
    );
    assert_eq!(usage["backend"]["consistency"], "strict");
    assert_eq!(usage["backend"]["status"], "healthy");
}

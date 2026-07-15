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
//! instance; no external Redis is touched) and a prebuilt release
//! `sbproxy` binary. Skips with a message instead of failing when
//! `redis-server` is not installed, mirroring `e2e/tests/key_replicas.rs`.
//! Local only; never added to the required CI gate (project e2e policy).

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
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
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
      failure_mode_allow: false
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
fn two_gateways_never_admit_more_than_the_shared_strict_request_limit() {
    let Some(redis) = RedisGuard::spawn() else {
        eprintln!(
            "SKIP governance_strict::two_gateways_never_admit_more_than_the_shared_strict_request_limit: \
             redis-server not found on PATH"
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

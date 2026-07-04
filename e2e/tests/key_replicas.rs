//! Cross-replica key invalidation over the Redis backend (WOR-1560).
//!
//! Local only; never added to the required CI gate (project e2e policy).
//! Spawns a private `redis-server` on an ephemeral port, boots TWO proxy
//! replicas that share it as the key store, and proves the revoke contract
//! across the fleet: a key minted through replica A's admin API works on both
//! replicas, and revoking it on A propagates to B through the pub/sub
//! invalidation channel well before B's local cache TTL (pinned at 300 s here,
//! so a pass can only come from invalidation, never TTL expiry).
//!
//! Requires `redis-server` on PATH (the test spawns and owns its own instance;
//! no external Redis is touched). When the binary is missing the test skips
//! with a message instead of failing, since machines without Redis cannot run
//! this scenario at all.
//!
//! The AI origin's upstream is a dead loopback port, so a request that passes
//! the virtual-key gate fails later at the upstream (5xx) while a denied key
//! is a 401/403 before the upstream is ever dialed.

use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use sbproxy_e2e::ProxyHarness;

fn pick_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A private redis-server child, killed on drop.
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

/// Replica config: shared Redis store, long local cache TTL (invalidation, not
/// expiry, must carry the revoke), shared pepper so both replicas verify the
/// same hashes.
fn replica_config(admin_port: u16, dead_port: u16, redis_url: &str) -> String {
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
      backend: redis
      url: "{redis_url}"
    cache:
      ttl_secs: 300
    crypto:
      pepper: e2e-replica-pepper
      master_key: e2e-replica-master
    failure_mode_allow: false
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: sk-dummy
          base_url: "http://127.0.0.1:{dead_port}"
          allow_private_base_url: true
          default_model: gpt-4o-mini
          models:
            - gpt-4o-mini
"#
    )
}

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

fn admin_post(port: u16, path: &str, auth: &str, body: Option<&str>) -> (u16, String) {
    let mut req = client()
        .post(format!("http://127.0.0.1:{port}{path}"))
        .header("authorization", auth);
    if let Some(b) = body {
        req = req
            .header("content-type", "application/json")
            .body(b.to_string());
    }
    let resp = req.send().expect("admin POST");
    (resp.status().as_u16(), resp.text().unwrap_or_default())
}

/// Send an AI request carrying `token` and return the HTTP status.
fn ai_request(base_url: &str, token: &str) -> u16 {
    client()
        .post(format!("{base_url}/v1/chat/completions"))
        .header("host", "ai.localhost")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}"#)
        .send()
        .expect("ai request")
        .status()
        .as_u16()
}

fn denied(status: u16) -> bool {
    status == 401 || status == 403
}

#[test]
fn revoke_on_replica_a_invalidates_replica_b() {
    let Some(redis) = RedisGuard::spawn() else {
        eprintln!(
            "SKIP key_replicas::revoke_on_replica_a_invalidates_replica_b: \
             redis-server not found on PATH"
        );
        return;
    };

    let admin_a = pick_port();
    let admin_b = pick_port();
    let dead_port = pick_port();

    let replica_a =
        ProxyHarness::start_with_yaml(&replica_config(admin_a, dead_port, &redis.url()))
            .expect("start replica A");
    let replica_b =
        ProxyHarness::start_with_yaml(&replica_config(admin_b, dead_port, &redis.url()))
            .expect("start replica B");
    ProxyHarness::wait_for_port(admin_a, Duration::from_secs(5)).expect("admin A to bind");
    ProxyHarness::wait_for_port(admin_b, Duration::from_secs(5)).expect("admin B to bind");
    let auth = format!("Basic {}", base64_encode("admin:secret"));
    let base_a = replica_a.base_url();
    let base_b = replica_b.base_url();

    // Mint through replica A; the record lands in the shared Redis store.
    let (status, body) = admin_post(admin_a, "/admin/keys", &auth, Some(r#"{"name":"fleet"}"#));
    assert_eq!(status, 201, "mint key on A: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let token = v["token"].as_str().unwrap().to_string();
    let key_id = v["key"]["key_id"].as_str().unwrap().to_string();

    // The key authenticates on BOTH replicas. B resolves it from the shared
    // store on first use and caches it locally (TTL 300 s).
    assert!(
        !denied(ai_request(&base_a, &token)),
        "the minted key must pass auth on replica A"
    );
    assert!(
        !denied(ai_request(&base_b, &token)),
        "the minted key must pass auth on replica B via the shared store"
    );

    // Revoke through replica A. A's own cache is invalidated synchronously by
    // the admin mutation, so A denies immediately.
    let (status, body) = admin_post(
        admin_a,
        &format!("/admin/keys/{key_id}/revoke"),
        &auth,
        None,
    );
    assert_eq!(status, 200, "revoke on A: {body}");
    assert_eq!(
        ai_request(&base_a, &token),
        403,
        "replica A must deny the revoked key on the next request"
    );

    // Replica B holds the record in its local cache with 295+ s of TTL left,
    // so only the pub/sub invalidation can make it deny. Give delivery a
    // bounded window; each pass through the loop re-asks B.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last = 0;
    while Instant::now() < deadline {
        last = ai_request(&base_b, &token);
        if last == 403 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        last, 403,
        "replica B must deny the revoked key within the invalidation window \
         (cache TTL is 300 s, so this can only come from pub/sub invalidation)"
    );
}

/// Minimal standard base64 (avoids a crate dep), matching admin_endpoints.rs.
fn base64_encode(input: &str) -> String {
    const ALPH: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i] as u32;
        let b1 = if i + 1 < bytes.len() {
            bytes[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < bytes.len() {
            bytes[i + 2] as u32
        } else {
            0
        };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPH[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPH[((triple >> 12) & 0x3F) as usize] as char);
        if i + 1 < bytes.len() {
            out.push(ALPH[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < bytes.len() {
            out.push(ALPH[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

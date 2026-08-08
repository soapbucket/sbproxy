//! Certification drills for config distribution: real binaries, real
//! sockets, real boots.
//!
//! Everything else in this feature is covered by unit and integration tests
//! that run one side against a stub in one process. These drills are the only
//! place a subscriber is a separate operating-system process reading
//! configuration over a socket, and the only place a boot-time refusal can
//! show up at all. Two previous epics in this repository shipped features
//! certified by unit tests alone that did not work when a real process tried
//! them, which is why this ticket exists.
//!
//! Deliberately outside the required CI gate, like the rest of
//! `sbproxy-e2e`, and marked `#[ignore]` so an ordinary e2e run does not pay
//! for them. See `docs/config-authority-drills.md` to run them by hand. e2e
//! runs the **release** binary, so `cargo build --release -p sbproxy` comes
//! first.
//!
//! ## Two kinds of authority, on purpose
//!
//! Drills 1, 6, 7, and 8 run the shipped authority binary, because what they
//! test is the real publish path and the real boot path.
//!
//! Drills 2, 3, 4, and 5 run a stub authority built from the shipped bundle
//! types, because what they test is a subscriber's reaction to a bundle no
//! real authority would ever send: an older revision, a mutated payload, a
//! signature from a retired key, or no answer at all. Asking the real
//! authority to misbehave would mean adding a misbehave switch to production
//! code, and the interesting half is the subscriber's refusal either way. The
//! stub signs with `ConfigBundleSigner` and serves the real wire format, so
//! the subscriber cannot tell the difference until it looks at the contents.

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use sbproxy_config::{BundleMode, ConfigBundle, ConfigBundleSigner, SignedConfigBundle};
use sbproxy_e2e::{proxy_binary_path, ProxyHarness};

const ADMIN_USER: &str = "admin";
const ADMIN_PASSWORD: &str = "drill-password-not-the-default";
const AUTHORITY_ID: &str = "control-plane-drill";
const KEY_ID: &str = "drill-key-1";
const ROTATED_KEY_ID: &str = "drill-key-2";
const SUBSCRIBER_ID: &str = "edge-01";
const BUNDLE_PATH: &str = "/config-authority/v1/bundle";
/// The configured floor. `poll_interval` is validated to be between 5s and
/// 86400s, so a drill cannot poll faster than this no matter how much it
/// would like to, and every convergence window below is a multiple of it.
const POLL_INTERVAL: &str = "5s";
/// Generous, because these are process starts and network round trips on a
/// machine that may be running a compile at the same time. At a 5s poll this
/// is roughly nine chances to converge.
const CONVERGE: Duration = Duration::from_secs(45);

/// How long a refusal has to hold before it counts.
///
/// Sized in poll intervals, not in round numbers. A single look cannot tell
/// "refused" from "has not polled yet", so this has to span several polls;
/// three is enough to be sure the subscriber saw the bad bundle and declined
/// it rather than simply not having fetched.
const REFUSAL_WINDOW: Duration = Duration::from_secs(18);

fn pick_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_millis() as u64
}

fn basic_auth() -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{ADMIN_USER}:{ADMIN_PASSWORD}"))
    )
}

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("build client")
}

struct AdminReply {
    status: u16,
    body: String,
}

impl AdminReply {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|e| panic!("admin reply was not JSON ({e}): {}", self.body))
    }
}

fn admin_get(port: u16, path: &str) -> AdminReply {
    let resp = client()
        .get(format!("http://127.0.0.1:{port}{path}"))
        .header("authorization", basic_auth())
        .send()
        .expect("admin GET");
    AdminReply {
        status: resp.status().as_u16(),
        body: resp.text().unwrap_or_default(),
    }
}

fn admin_send(method: &str, port: u16, path: &str, body: Vec<u8>) -> AdminReply {
    let url = format!("http://127.0.0.1:{port}{path}");
    let request = match method {
        "POST" => client().post(url),
        "PUT" => client().put(url),
        other => panic!("unsupported method {other}"),
    };
    let resp = request
        .header("authorization", basic_auth())
        .header("content-type", "application/yaml")
        .body(body)
        .send()
        .expect("admin request");
    AdminReply {
        status: resp.status().as_u16(),
        body: resp.text().unwrap_or_default(),
    }
}

/// Poll until `check` passes or the deadline expires.
///
/// Drills are timing-dependent by nature. A poll with a deadline expresses
/// "converges within" honestly; a fixed sleep is either flaky or slow.
fn converges<F: FnMut() -> bool>(timeout: Duration, mut check: F) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if check() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Whether `check` stays false for the whole window.
///
/// Needed for the refusal drills. "The subscriber did not apply the bad
/// bundle" cannot be proven by one look, because the poll may not have
/// happened yet; it has to hold across several poll intervals.
fn stays_false<F: FnMut() -> bool>(window: Duration, mut check: F) -> bool {
    let deadline = Instant::now() + window;
    while Instant::now() < deadline {
        if check() {
            return false;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    true
}

/// Start a proxy with its child log captured.
///
/// `start_with_workspace` rather than `start_with_yaml` for one reason: the
/// latter sends the child's stdout to /dev/null, sbproxy logs there, and every
/// drill failure therefore printed an empty log exactly when the refusal
/// reason was the thing worth reading. No sibling files are needed, so the
/// workspace is empty.
fn start_proxy(yaml: &str) -> anyhow::Result<ProxyHarness> {
    ProxyHarness::start_with_workspace(yaml, &[])
}

/// The child's tracing output, which is on stdout, plus stderr.
///
/// A drill whose failure prints nothing is not worth having, and that is what
/// `stderr_contents` alone produced: `start_with_yaml` sends stdout to
/// /dev/null and sbproxy logs there, so every refusal reason was discarded
/// exactly when it was needed.
fn child_log(proxy: &ProxyHarness) -> String {
    format!(
        "--- stdout ---\n{}\n--- stderr ---\n{}",
        proxy.stdout_contents(),
        proxy.stderr_contents()
    )
}

fn serves(proxy: &ProxyHarness, host: &str, expected: &str) -> bool {
    match proxy.get("/", host) {
        Ok(resp) => resp.status == 200 && resp.text().map(|t| t == expected).unwrap_or(false),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// The real authority
// ---------------------------------------------------------------------------

struct LiveAuthority {
    _harness: ProxyHarness,
    admin_port: u16,
    bundle_port: u16,
    verifying_keys: PathBuf,
}

/// Run `sbproxy config authority init` and return the two files it wrote.
///
/// Uses the shipped CLI rather than generating a keypair in the test, because
/// the documented setup path is itself something these drills should prove.
fn init_authority_keys(dir: &Path, key_id: &str) -> (PathBuf, PathBuf) {
    let output = Command::new(proxy_binary_path())
        .args([
            "config",
            "authority",
            "init",
            "--dir",
            dir.to_str().expect("utf8 dir"),
            "--key-id",
            key_id,
            "--authority-id",
            AUTHORITY_ID,
        ])
        .output()
        .expect("run authority init");
    assert!(
        output.status.success(),
        "authority init failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let signing = dir.join("authority-signing.key");
    let verifying = dir.join("authority-keys.json");
    assert!(signing.exists(), "init did not write the signing key");
    assert!(verifying.exists(), "init did not write the verifying keys");
    (signing, verifying)
}

fn authority_yaml(
    admin_port: u16,
    bundle_port: u16,
    signing_key: &Path,
    store_dir: &Path,
) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  admin:
    enabled: true
    bind: 127.0.0.1
    port: {admin_port}
    username: {ADMIN_USER}
    password: {ADMIN_PASSWORD}
  config_authority:
    publish:
      authority_id: {AUTHORITY_ID}
      key_id: {KEY_ID}
      signing_key_file: {signing}
      store_dir: {store}
      bind: 127.0.0.1:{bundle_port}
origins:
  "authority.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "authority-serves-its-own-traffic"
"#,
        signing = signing_key.display(),
        store = store_dir.display(),
    )
}

fn start_live_authority(dir: &Path) -> LiveAuthority {
    let (signing_key, verifying_keys) = init_authority_keys(dir, KEY_ID);
    let store_dir = dir.join("store");
    std::fs::create_dir_all(&store_dir).expect("create store dir");
    let admin_port = pick_port();
    let bundle_port = pick_port();
    let harness = start_proxy(&authority_yaml(
        admin_port,
        bundle_port,
        &signing_key,
        &store_dir,
    ))
    .expect("start authority");
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(20))
        .expect("authority admin port never bound");
    ProxyHarness::wait_for_port(bundle_port, Duration::from_secs(20))
        .expect("authority bundle listener never bound");
    LiveAuthority {
        _harness: harness,
        admin_port,
        bundle_port,
        verifying_keys,
    }
}

/// Register a subscriber and write its credential to a file.
///
/// A file rather than an environment variable, because the harness starts the
/// proxy without a custom environment and `credential: file:` is a supported
/// spelling. An inline literal is refused by the loader, correctly: a token in
/// a config file is a token in every copy of that file.
fn register_subscriber(admin_port: u16, dir: &Path) -> PathBuf {
    let reply = admin_send(
        "POST",
        admin_port,
        "/admin/config-authority/subscribers",
        format!(r#"{{"subscriber_id":"{SUBSCRIBER_ID}"}}"#).into_bytes(),
    );
    assert_eq!(reply.status, 200, "register subscriber: {}", reply.body);
    let credential = reply.json()["credential"]
        .as_str()
        .expect("credential in reply")
        .to_string();
    let path = dir.join("subscriber.token");
    std::fs::write(&path, credential.as_bytes()).expect("write token");
    path
}

fn publish(admin_port: u16, payload: &str, mode: &str) -> AdminReply {
    admin_send(
        "POST",
        admin_port,
        &format!("/admin/config-authority/publish?mode={mode}"),
        payload.as_bytes().to_vec(),
    )
}

// ---------------------------------------------------------------------------
// The stub authority
// ---------------------------------------------------------------------------

/// A minimal bundle server whose reply the test controls.
///
/// Speaks the same wire contract as the real authority (one GET, a JSON
/// signed envelope, an ETag) using the shipped `ConfigBundleSigner`, so a
/// subscriber's refusal is a refusal of contents rather than of format.
struct StubAuthority {
    port: u16,
    /// Exact bytes to serve, so a drill can hand over a mutated envelope.
    body: Arc<Mutex<Vec<u8>>>,
    /// When set, the listener answers nothing, simulating an outage.
    down: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    signing: SigningKey,
    verifying_keys: PathBuf,
}

impl StubAuthority {
    fn start(dir: &Path, key_id: &str) -> Self {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_keys = dir.join("stub-keys.json");
        Self::write_key_file(&verifying_keys, &[(key_id, &signing)]);

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let port = listener.local_addr().expect("addr").port();
        listener
            .set_nonblocking(true)
            .expect("nonblocking so the accept loop can notice the stop flag");

        let body = Arc::new(Mutex::new(Vec::new()));
        let down = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));

        let (loop_body, loop_down, loop_stop) = (body.clone(), down.clone(), stop.clone());
        std::thread::spawn(move || {
            while !loop_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if loop_down.load(Ordering::Relaxed) {
                            // Drop the connection unanswered, which is what a
                            // dead authority looks like to a client that
                            // already has a route to the host.
                            drop(stream);
                            continue;
                        }
                        let payload = loop_body.lock().expect("stub body").clone();
                        let _ = Self::answer(stream, &payload);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            port,
            body,
            down,
            stop,
            signing,
            verifying_keys,
        }
    }

    fn write_key_file(path: &Path, keys: &[(&str, &SigningKey)]) {
        use base64::Engine as _;
        let mut map = serde_json::Map::new();
        for (id, key) in keys {
            map.insert(
                (*id).to_string(),
                serde_json::json!({
                    "algorithm": "ed25519",
                    "key": base64::engine::general_purpose::STANDARD
                        .encode(key.verifying_key().to_bytes()),
                }),
            );
        }
        std::fs::write(
            path,
            serde_json::to_vec_pretty(&serde_json::Value::Object(map)).expect("serialize keys"),
        )
        .expect("write verifying keys");
    }

    fn answer(mut stream: TcpStream, payload: &[u8]) -> std::io::Result<()> {
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf);
        let request = String::from_utf8_lossy(&buf);
        if !request.contains(BUNDLE_PATH) {
            let head = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            stream.write_all(head)?;
            return stream.flush();
        }
        if payload.is_empty() {
            let head = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            stream.write_all(head)?;
            return stream.flush();
        }
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            payload.len()
        );
        stream.write_all(head.as_bytes())?;
        stream.write_all(payload)?;
        stream.flush()
    }

    /// Sign a bundle with `key_id` and serve it from now on.
    fn serve(&self, key_id: &str, revision: u64, mode: BundleMode, config_yaml: &str) {
        let signed = self.sign(key_id, revision, mode, config_yaml);
        self.serve_bytes(serde_json::to_vec(&signed).expect("serialize envelope"));
    }

    fn sign(
        &self,
        key_id: &str,
        revision: u64,
        mode: BundleMode,
        config_yaml: &str,
    ) -> SignedConfigBundle {
        let bundle = ConfigBundle::new(AUTHORITY_ID, revision, mode, config_yaml, now_ms(), None)
            .expect("build bundle");
        ConfigBundleSigner::ed25519(key_id, self.signing.clone())
            .expect("signer")
            .sign(bundle)
            .expect("sign bundle")
    }

    fn serve_bytes(&self, bytes: Vec<u8>) {
        *self.body.lock().expect("stub body") = bytes;
    }

    fn set_down(&self, down: bool) {
        self.down.store(down, Ordering::Relaxed);
    }
}

impl Drop for StubAuthority {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Subscriber
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn subscriber_yaml(
    bundle_port: u16,
    token_file: &Path,
    verifying_keys: &Path,
    cache_path: &Path,
    admin_port: u16,
    mode: &str,
    extra_upstream: &str,
) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  admin:
    enabled: true
    bind: 127.0.0.1
    port: {admin_port}
    username: {ADMIN_USER}
    password: {ADMIN_PASSWORD}
  config_authority:
    upstream:
      url: http://127.0.0.1:{bundle_port}
      mode: {mode}
      subscriber_id: {SUBSCRIBER_ID}
      credential: file:{token}
      verifying_keys_file: {keys}
      poll_interval: {POLL_INTERVAL}
      cache_path: {cache}
      # The subscriber refuses a plaintext authority URL without this, which
      # is the right default: the credential and the whole configuration
      # would otherwise cross the wire in the clear. These drills bind
      # loopback and issue no certificates, so the opt-in is what makes them
      # runnable. A production subscriber uses https and never sets it, and
      # the runbook says so.
      allow_insecure_http: true
{extra_upstream}
origins:
  "local.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "local-only-origin"
"#,
        token = token_file.display(),
        keys = verifying_keys.display(),
        cache = cache_path.display(),
    )
}

/// A payload that adds one origin, so "did it apply" is a `GET` away.
fn fleet_payload(body: &str) -> String {
    format!(
        r#"
origins:
  "fleet.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "{body}"
"#
    )
}

fn write_token(dir: &Path) -> PathBuf {
    // The stub does not check credentials, but the subscriber refuses to
    // start without one, so it gets a syntactically valid token.
    let path = dir.join("stub.token");
    std::fs::write(
        &path,
        "sbca1.0000000000000000.0000000000000000000000000000000000000000000",
    )
    .expect("write stub token");
    path
}

// ---------------------------------------------------------------------------
// Drill 1: happy path, real authority
// ---------------------------------------------------------------------------

#[test]
#[ignore = "certification drill: run with --ignored against release binaries"]
fn drill_1_published_config_reaches_a_subscriber_and_serves() {
    let dir = tempfile::tempdir().expect("tempdir");
    let authority = start_live_authority(dir.path());
    let token = register_subscriber(authority.admin_port, dir.path());

    let published = publish(
        authority.admin_port,
        &fleet_payload("from-the-authority"),
        "overlay",
    );
    assert_eq!(published.status, 200, "publish: {}", published.body);
    let body = published.json();
    let revision = body["revision"].as_u64().expect("revision");
    let digest = body["content_digest"]
        .as_str()
        .expect("content_digest")
        .to_string();
    assert_eq!(revision, 1, "the first publish should be revision 1");

    let cache = dir.path().join("bundle-cache.json");
    let sub_admin = pick_port();
    let subscriber = start_proxy(&subscriber_yaml(
        authority.bundle_port,
        &token,
        &authority.verifying_keys,
        &cache,
        sub_admin,
        "overlay",
        "",
    ))
    .expect("start subscriber");
    ProxyHarness::wait_for_port(sub_admin, Duration::from_secs(20)).expect("subscriber admin");

    assert!(
        converges(CONVERGE, || serves(
            &subscriber,
            "fleet.localhost",
            "from-the-authority"
        )),
        "the authority's origin never started serving.\nsubscriber stderr:\n{}",
        child_log(&subscriber)
    );

    // An overlay keeps what the node already had.
    assert!(
        serves(&subscriber, "local.localhost", "local-only-origin"),
        "an overlay must not discard the node's own origins"
    );

    // Both sides agree on the numbers, which is what an operator checks
    // during a rollout.
    let status = admin_get(authority.admin_port, "/admin/config-authority/status").json();
    assert_eq!(status["current_revision"].as_u64(), Some(revision));
    assert_eq!(
        status["current_content_digest"].as_str(),
        Some(digest.as_str()),
        "status: {status}"
    );
    assert!(
        converges(CONVERGE, || {
            let s = admin_get(authority.admin_port, "/admin/config-authority/status").json();
            s["subscribers"][0]["last_seen_revision"].as_u64() == Some(revision)
        }),
        "the authority never recorded the subscriber at revision {revision}"
    );

    // And the subscriber names the authority as the owner of what it took.
    let effective = admin_get(sub_admin, "/admin/config/effective").json();
    assert_eq!(effective["locally_owned"].as_bool(), Some(false));
    assert_eq!(
        effective["layers"]["authority"]["revision"].as_u64(),
        Some(revision)
    );
}

// ---------------------------------------------------------------------------
// Drill 2: key rotation
// ---------------------------------------------------------------------------

#[test]
#[ignore = "certification drill: run with --ignored against release binaries"]
fn drill_2_a_rotated_key_verifies_and_a_retired_one_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let stub = StubAuthority::start(dir.path(), KEY_ID);
    let token = write_token(dir.path());
    let cache = dir.path().join("cache.json");
    let sub_admin = pick_port();

    stub.serve(
        KEY_ID,
        1,
        BundleMode::Overlay,
        &fleet_payload("under-key-1"),
    );
    let subscriber = start_proxy(&subscriber_yaml(
        stub.port,
        &token,
        &stub.verifying_keys,
        &cache,
        sub_admin,
        "overlay",
        "",
    ))
    .expect("start subscriber");
    assert!(
        converges(CONVERGE, || serves(
            &subscriber,
            "fleet.localhost",
            "under-key-1"
        )),
        "the first key's bundle never applied:\n{}",
        child_log(&subscriber)
    );

    // Trust both ids: the additive window is the whole point of rotation.
    StubAuthority::write_key_file(
        &stub.verifying_keys,
        &[(KEY_ID, &stub.signing), (ROTATED_KEY_ID, &stub.signing)],
    );
    stub.serve(
        ROTATED_KEY_ID,
        2,
        BundleMode::Overlay,
        &fleet_payload("under-key-2"),
    );
    assert!(
        converges(CONVERGE, || serves(
            &subscriber,
            "fleet.localhost",
            "under-key-2"
        )),
        "a bundle under the rotated key id never applied:\n{}",
        child_log(&subscriber)
    );

    // Retire the first id. A bundle signed under it is now unverifiable, and
    // the previously applied configuration keeps serving.
    StubAuthority::write_key_file(&stub.verifying_keys, &[(ROTATED_KEY_ID, &stub.signing)]);
    stub.serve(
        KEY_ID,
        3,
        BundleMode::Overlay,
        &fleet_payload("signed-by-a-retired-key"),
    );
    assert!(
        stays_false(REFUSAL_WINDOW, || serves(
            &subscriber,
            "fleet.localhost",
            "signed-by-a-retired-key"
        )),
        "a bundle signed by a retired key was applied:\n{}",
        child_log(&subscriber)
    );
    assert!(
        serves(&subscriber, "fleet.localhost", "under-key-2"),
        "the last good configuration must keep serving"
    );
}

// ---------------------------------------------------------------------------
// Drill 3: replay
// ---------------------------------------------------------------------------

#[test]
#[ignore = "certification drill: run with --ignored against release binaries"]
fn drill_3_an_older_revision_is_refused_and_stays_refused_after_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let stub = StubAuthority::start(dir.path(), KEY_ID);
    let token = write_token(dir.path());
    let cache = dir.path().join("cache.json");
    let sub_admin = pick_port();
    let yaml = subscriber_yaml(
        stub.port,
        &token,
        &stub.verifying_keys,
        &cache,
        sub_admin,
        "overlay",
        "",
    );

    stub.serve(KEY_ID, 5, BundleMode::Overlay, &fleet_payload("revision-5"));
    let subscriber = start_proxy(&yaml).expect("start subscriber");
    assert!(
        converges(CONVERGE, || serves(
            &subscriber,
            "fleet.localhost",
            "revision-5"
        )),
        "revision 5 never applied:\n{}",
        child_log(&subscriber)
    );

    // Serve a valid, correctly signed, strictly older revision. Everything
    // about it verifies; only the cursor refuses it.
    stub.serve(KEY_ID, 4, BundleMode::Overlay, &fleet_payload("revision-4"));
    assert!(
        stays_false(REFUSAL_WINDOW, || serves(
            &subscriber,
            "fleet.localhost",
            "revision-4"
        )),
        "a replayed older revision was applied:\n{}",
        child_log(&subscriber)
    );
    assert!(serves(&subscriber, "fleet.localhost", "revision-5"));

    // The cursor is durable: a restarted node still refuses it. Without
    // persistence, a restart would be all an attacker needs.
    drop(subscriber);
    let restarted = start_proxy(&yaml).expect("restart subscriber");
    assert!(
        stays_false(REFUSAL_WINDOW, || serves(
            &restarted,
            "fleet.localhost",
            "revision-4"
        )),
        "the replay was accepted after a restart, so the cursor did not persist:\n{}",
        child_log(&restarted)
    );
    assert!(
        converges(CONVERGE, || serves(
            &restarted,
            "fleet.localhost",
            "revision-5"
        )),
        "the restarted node should boot on the cached revision 5:\n{}",
        child_log(&restarted)
    );
}

// ---------------------------------------------------------------------------
// Drill 4: tamper
// ---------------------------------------------------------------------------

#[test]
#[ignore = "certification drill: run with --ignored against release binaries"]
fn drill_4_a_tampered_bundle_is_refused_and_the_previous_config_keeps_serving() {
    let dir = tempfile::tempdir().expect("tempdir");
    let stub = StubAuthority::start(dir.path(), KEY_ID);
    let token = write_token(dir.path());
    let cache = dir.path().join("cache.json");
    let sub_admin = pick_port();

    stub.serve(
        KEY_ID,
        1,
        BundleMode::Overlay,
        &fleet_payload("good-config"),
    );
    let subscriber = start_proxy(&subscriber_yaml(
        stub.port,
        &token,
        &stub.verifying_keys,
        &cache,
        sub_admin,
        "overlay",
        "",
    ))
    .expect("start subscriber");
    assert!(
        converges(CONVERGE, || serves(
            &subscriber,
            "fleet.localhost",
            "good-config"
        )),
        "the good bundle never applied:\n{}",
        child_log(&subscriber)
    );

    // Mutate the payload, leaving the signature field untouched. The digest
    // and the signature both now disagree with the bytes.
    let mut signed = stub.sign(
        KEY_ID,
        2,
        BundleMode::Overlay,
        &fleet_payload("tampered-payload"),
    );
    signed.bundle.config_yaml = fleet_payload("attacker-payload");
    stub.serve_bytes(serde_json::to_vec(&signed).expect("serialize"));
    assert!(
        stays_false(REFUSAL_WINDOW, || serves(
            &subscriber,
            "fleet.localhost",
            "attacker-payload"
        )),
        "a bundle whose payload was swapped after signing was applied:\n{}",
        child_log(&subscriber)
    );
    assert!(
        serves(&subscriber, "fleet.localhost", "good-config"),
        "the last good configuration must keep serving through a tampered fetch"
    );

    // Mutate the signature instead, leaving the payload intact.
    let mut signed = stub.sign(
        KEY_ID,
        3,
        BundleMode::Overlay,
        &fleet_payload("signature-swapped"),
    );
    let mut sig = signed.signature.clone().into_bytes();
    // Flip a byte in the middle of the base64 rather than truncating, so this
    // is a wrong signature and not a malformed field.
    let middle = sig.len() / 2;
    sig[middle] = if sig[middle] == b'A' { b'B' } else { b'A' };
    signed.signature = String::from_utf8(sig).expect("still utf8");
    stub.serve_bytes(serde_json::to_vec(&signed).expect("serialize"));
    assert!(
        stays_false(REFUSAL_WINDOW, || serves(
            &subscriber,
            "fleet.localhost",
            "signature-swapped"
        )),
        "a bundle with a mutated signature was applied:\n{}",
        child_log(&subscriber)
    );
    assert!(
        serves(&subscriber, "fleet.localhost", "good-config"),
        "the last good configuration must keep serving through a bad signature"
    );
}

// ---------------------------------------------------------------------------
// Drill 5: authority outage
// ---------------------------------------------------------------------------

#[test]
#[ignore = "certification drill: run with --ignored against release binaries"]
fn drill_5_an_outage_keeps_serving_and_converges_without_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let stub = StubAuthority::start(dir.path(), KEY_ID);
    let token = write_token(dir.path());
    let cache = dir.path().join("cache.json");
    let sub_admin = pick_port();

    stub.serve(
        KEY_ID,
        1,
        BundleMode::Overlay,
        &fleet_payload("before-outage"),
    );
    let subscriber = start_proxy(&subscriber_yaml(
        stub.port,
        &token,
        &stub.verifying_keys,
        &cache,
        sub_admin,
        "overlay",
        "",
    ))
    .expect("start subscriber");
    assert!(
        converges(CONVERGE, || serves(
            &subscriber,
            "fleet.localhost",
            "before-outage"
        )),
        "the first bundle never applied:\n{}",
        child_log(&subscriber)
    );

    // The authority stops answering. A control-plane outage must not take
    // down a data plane that does not depend on it.
    stub.set_down(true);
    assert!(
        stays_false(REFUSAL_WINDOW, || !serves(
            &subscriber,
            "fleet.localhost",
            "before-outage"
        )),
        "the subscriber stopped serving during an authority outage:\n{}",
        child_log(&subscriber)
    );

    // The staleness gauge climbs while the authority is away, which is what
    // an operator alerts on. `/metrics` is on the admin listener.
    let metrics = admin_get(sub_admin, "/metrics").body;
    assert!(
        metrics.contains("sbproxy_config_bundle_age_seconds"),
        "the bundle age gauge should be published on a subscriber"
    );

    // The authority returns and the node converges with no restart.
    stub.serve(
        KEY_ID,
        2,
        BundleMode::Overlay,
        &fleet_payload("after-outage"),
    );
    stub.set_down(false);
    assert!(
        converges(CONVERGE, || serves(
            &subscriber,
            "fleet.localhost",
            "after-outage"
        )),
        "the subscriber never converged after the authority returned:\n{}",
        child_log(&subscriber)
    );
}

// ---------------------------------------------------------------------------
// Drill 6: denied path, at both gates
// ---------------------------------------------------------------------------

#[test]
#[ignore = "certification drill: run with --ignored against release binaries"]
fn drill_6_a_denied_path_is_refused_at_publish_and_again_at_the_subscriber() {
    let dir = tempfile::tempdir().expect("tempdir");
    let authority = start_live_authority(dir.path());

    // Gate one: the authority refuses to sign it at all.
    let denied = r#"
proxy:
  admin:
    port: 1
origins: {}
"#;
    let reply = publish(authority.admin_port, denied, "overlay");
    assert_eq!(reply.status, 400, "publish should refuse: {}", reply.body);
    let body = reply.json();
    assert_eq!(body["code"].as_str(), Some("denied_path"));
    assert_eq!(
        body["revision_consumed"].as_bool(),
        Some(false),
        "a refused publish must not spend a revision: {}",
        reply.body
    );
    assert!(
        reply.body.contains("proxy.admin"),
        "the refusal should name the path: {}",
        reply.body
    );

    // The counter really did not move: the next good publish is revision 1.
    let good = publish(
        authority.admin_port,
        &fleet_payload("first-real-revision"),
        "overlay",
    );
    assert_eq!(good.status, 200, "{}", good.body);
    assert_eq!(good.json()["revision"].as_u64(), Some(1));

    // Gate two, independently: a hand-signed bundle that never went through
    // the publish path is still refused by the subscriber. Two gates rather
    // than one gate twice, which is the property worth proving.
    let stub = StubAuthority::start(dir.path(), KEY_ID);
    let token = write_token(dir.path());
    let cache = dir.path().join("cache.json");
    let sub_admin = pick_port();
    stub.serve(KEY_ID, 1, BundleMode::Overlay, &fleet_payload("legitimate"));
    let subscriber = start_proxy(&subscriber_yaml(
        stub.port,
        &token,
        &stub.verifying_keys,
        &cache,
        sub_admin,
        "overlay",
        "",
    ))
    .expect("start subscriber");
    assert!(
        converges(CONVERGE, || serves(
            &subscriber,
            "fleet.localhost",
            "legitimate"
        )),
        "the legitimate bundle never applied:\n{}",
        child_log(&subscriber)
    );

    let hostile = format!(
        "{}\nproxy:\n  admin:\n    port: 1\n",
        fleet_payload("hostile")
    );
    stub.serve(KEY_ID, 2, BundleMode::Overlay, &hostile);
    assert!(
        stays_false(REFUSAL_WINDOW, || serves(
            &subscriber,
            "fleet.localhost",
            "hostile"
        )),
        "a signed bundle naming a subscriber-owned path was applied:\n{}",
        child_log(&subscriber)
    );
    assert!(
        serves(&subscriber, "fleet.localhost", "legitimate"),
        "the whole bundle is refused, so the previous config keeps serving"
    );
    // The admin listener is still on the port this node chose, which is the
    // thing the deny list exists to protect.
    assert_eq!(
        admin_get(sub_admin, "/admin/config/effective").status,
        200,
        "the node's own admin listener must survive a hostile bundle"
    );
}

// ---------------------------------------------------------------------------
// Drill 7: editor lock
// ---------------------------------------------------------------------------

#[test]
#[ignore = "certification drill: run with --ignored against release binaries"]
fn drill_7_a_write_to_an_authority_owned_path_is_refused_with_409() {
    let dir = tempfile::tempdir().expect("tempdir");
    let stub = StubAuthority::start(dir.path(), KEY_ID);
    let token = write_token(dir.path());
    let cache = dir.path().join("cache.json");
    let sub_admin = pick_port();

    // The authority owns the local origin's body, so an edit to it is the
    // write that would look applied and then vanish at the next poll.
    stub.serve(
        KEY_ID,
        1,
        BundleMode::Overlay,
        "origins:\n  \"local.localhost\":\n    action:\n      type: static\n      status_code: 200\n      content_type: text/plain\n      body: \"authority-owns-this\"\n",
    );
    let sub_yaml = subscriber_yaml(
        stub.port,
        &token,
        &stub.verifying_keys,
        &cache,
        sub_admin,
        "overlay",
        "",
    );
    let subscriber = start_proxy(&sub_yaml).expect("start subscriber");
    assert!(
        converges(CONVERGE, || serves(
            &subscriber,
            "local.localhost",
            "authority-owns-this"
        )),
        "the bundle never applied:\n{}",
        child_log(&subscriber)
    );

    let before = admin_get(sub_admin, "/admin/config").json()["yaml"]
        .as_str()
        .expect("yaml in config read")
        .to_string();
    assert!(
        before.contains("local-only-origin"),
        "the local file should still hold its own value: {before}"
    );
    // WOR-2316: the read is redacted, so the inlined admin password must
    // not come back. That also means the GET body is no longer a valid
    // edit base; the drill edits the text it wrote to disk instead.
    assert!(
        !before.contains(ADMIN_PASSWORD),
        "the config read must not echo the inlined admin password: {before}"
    );

    // Edit the value the authority overrides.
    let proposed = sub_yaml.replace("local-only-origin", "operator-tried-this");
    let reply = admin_send("PUT", sub_admin, "/admin/config", proposed.into_bytes());
    assert_eq!(
        reply.status, 409,
        "a write the authority would swallow must be refused: {}",
        reply.body
    );
    let body = reply.json();
    assert_eq!(body["code"].as_str(), Some("config_not_locally_owned"));
    assert!(
        body["conflicts"][0]["path"]
            .as_str()
            .unwrap_or_default()
            .contains("local.localhost"),
        "the refusal should name the path: {}",
        reply.body
    );
    assert!(
        body["remedy"]
            .as_str()
            .unwrap_or_default()
            .contains(AUTHORITY_ID),
        "the remedy should name the authority: {}",
        reply.body
    );

    // Neither the running configuration nor the file changed.
    assert!(
        serves(&subscriber, "local.localhost", "authority-owns-this"),
        "the refused write must not have taken effect"
    );
    let after = admin_get(sub_admin, "/admin/config").json()["yaml"]
        .as_str()
        .expect("yaml")
        .to_string();
    assert_eq!(before, after, "the refused write must not touch the file");

    // A write confined to a path the authority does not set still works, so
    // the guard is per-setting rather than a blanket lock.
    let allowed = format!("{sub_yaml}\n  \"second.localhost\":\n    action:\n      type: static\n      status_code: 200\n      content_type: text/plain\n      body: \"node-owns-this\"\n");
    let reply = admin_send("PUT", sub_admin, "/admin/config", allowed.into_bytes());
    assert_eq!(
        reply.status, 200,
        "a write to a path the authority does not set must succeed: {}",
        reply.body
    );
    assert!(
        converges(CONVERGE, || serves(
            &subscriber,
            "second.localhost",
            "node-owns-this"
        )),
        "the accepted write never took effect:\n{}",
        child_log(&subscriber)
    );
}

// ---------------------------------------------------------------------------
// Drill 8: cold boot
// ---------------------------------------------------------------------------

#[test]
#[ignore = "certification drill: run with --ignored against release binaries"]
fn drill_8_replace_with_no_cache_refuses_to_start_and_overlay_boots_local() {
    let dir = tempfile::tempdir().expect("tempdir");
    let stub = StubAuthority::start(dir.path(), KEY_ID);
    let token = write_token(dir.path());
    // The stub answers 503 with an empty body, so there is nothing to cache.
    stub.set_down(true);

    // Overlay with no cache and an unreachable authority boots on the local
    // file. A control plane that is not answering must not stop a data plane
    // that does not depend on it.
    let overlay_admin = pick_port();
    let overlay = start_proxy(&subscriber_yaml(
        stub.port,
        &token,
        &stub.verifying_keys,
        &dir.path().join("overlay-cache.json"),
        overlay_admin,
        "overlay",
        "",
    ))
    .expect("overlay mode should boot with no cached bundle");
    assert!(
        serves(&overlay, "local.localhost", "local-only-origin"),
        "overlay with no bundle should serve the local file:\n{}",
        child_log(&overlay)
    );
    drop(overlay);

    // Replace with no cache refuses to start: the local file is not a
    // servable configuration on its own under replace, so booting anyway
    // would serve a configuration nobody wrote.
    let replace_admin = pick_port();
    let started = start_proxy(&subscriber_yaml(
        stub.port,
        &token,
        &stub.verifying_keys,
        &dir.path().join("replace-cache.json"),
        replace_admin,
        "replace",
        "",
    ));
    assert!(
        started.is_err(),
        "replace mode with no cached bundle and no reachable authority must refuse to start"
    );
}

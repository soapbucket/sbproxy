//! Two project repositories, one aggregator, one subscriber node
//! serving traffic.
//!
//! The ticket that proves the aggregation epic. Every part of it passes
//! its own unit tests and still does not have to compose into a working
//! system, and a green gate plus green CI has previously proved nothing
//! for integration work in this repository.
//!
//! Deliberately outside the required CI gate, like the rest of
//! `sbproxy-e2e`. The scheduled lane runs `cargo test -p sbproxy-e2e`,
//! so this file is in it by being here.
//!
//! # The git server
//!
//! Each project repository is a real bare git repository served over
//! plain HTTP by a static file server this file starts, which is git's
//! "dumb" transport. That is enough for both halves of what the
//! aggregator does: `git ls-remote` reads `info/refs`, and the targeted
//! shallow fetch is refused by a dumb server and falls back to the full
//! fetch the production code already carries for exactly this case. A
//! smart-HTTP server would need `git http-backend` behind CGI and would
//! exercise strictly less of that fallback.
//!
//! # Serialization
//!
//! Every test binds real sockets and spawns real processes. The
//! scheduled lane runs `--test-threads=1`; this file additionally holds
//! a file-scoped mutex so running this target alone is safe.

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use sbproxy_e2e::{proxy_binary_path, ProxyHarness};

const ADMIN_USER: &str = "admin";
const ADMIN_PASSWORD: &str = "aggregation-e2e-not-the-default";
const AUTHORITY_ID: &str = "control-plane-aggregation";
const KEY_ID: &str = "aggregation-key-1";
const SUBSCRIBER_ID: &str = "edge-01";
/// The configured floor: `poll_interval` is validated between 5s and a
/// day, so no test can converge faster than this.
const POLL_INTERVAL: &str = "5s";
/// Generous: process starts and git fetches on a machine that may be
/// compiling. At a 5s poll this is a dozen chances to converge.
const CONVERGE: Duration = Duration::from_secs(75);

const CHECKOUT_HOST: &str = "checkout.example.com";
const HOOKS_HOST: &str = "hooks.example.com";
const BILLING_HOST: &str = "billing.example.com";

/// A value exported to the aggregator process and to nothing else. No
/// composed document, published bundle, or response may ever carry it.
const AGGREGATOR_ONLY_SECRET: &str = "aggregator-env-must-never-leak-9f2c";

fn suite_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn pick_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
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
        .timeout(Duration::from_secs(20))
        .build()
        .expect("build client")
}

struct Reply {
    status: u16,
    body: String,
}

impl Reply {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|error| panic!("reply was not JSON ({error}): {}", self.body))
    }
}

fn admin(port: u16, method: &str, path: &str) -> Reply {
    let url = format!("http://127.0.0.1:{port}{path}");
    let request = match method {
        "GET" => client().get(url),
        "POST" => client().post(url),
        other => panic!("unsupported method {other}"),
    };
    let response = request
        .header("authorization", basic_auth())
        .send()
        .expect("admin request");
    Reply {
        status: response.status().as_u16(),
        body: response.text().unwrap_or_default(),
    }
}

/// Wait for something to accept a TCP connection on `port`.
///
/// Weaker than the harness's HTTP probe on purpose: a TLS listener
/// cannot answer one, and a kernel-accepted connection with no accept
/// loop behind it would still connect. The caller follows this with a
/// real request, which is the assertion that matters.
fn wait_for_tcp(port: u16, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("nothing accepting TCP on 127.0.0.1:{port} within {timeout:?}");
}

fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + CONVERGE;
    while Instant::now() < deadline {
        if condition() {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("timed out waiting for {what}");
}

// ---------------------------------------------------------------------------
// A stub upstream and a static file server for the git repositories
// ---------------------------------------------------------------------------

struct LoopbackServer {
    port: u16,
    shutdown: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for LoopbackServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Serve every request with `200 OK` and a body naming the `Host` the
/// proxy forwarded, so a test can tell which origin answered.
fn start_stub_upstream() -> LoopbackServer {
    serve(move |request| {
        let host = request
            .lines()
            .find_map(|line| line.strip_prefix("host: ").or(line.strip_prefix("Host: ")))
            .unwrap_or("?")
            .trim()
            .to_string();
        let body = format!("upstream-for:{host}");
        Some(("200 OK", "text/plain".to_string(), body.into_bytes()))
    })
}

/// Serve `root` as static files, which is git's dumb HTTP transport.
fn start_git_server(root: PathBuf) -> LoopbackServer {
    serve(move |request| {
        let target = request.split_whitespace().nth(1)?;
        let target = target.split('?').next().unwrap_or(target);
        // No `..` ever reaches the filesystem: the components are
        // filtered rather than canonicalized, so a traversal cannot
        // depend on the shape of the temp path.
        let mut path = root.clone();
        for part in target.split('/').filter(|part| !part.is_empty()) {
            if part == ".." || part == "." {
                return None;
            }
            path.push(part);
        }
        let body = std::fs::read(&path).ok()?;
        Some(("200 OK", "application/octet-stream".to_string(), body))
    })
}

/// One loopback HTTP/1.1 server. `answer` returns the status, content
/// type, and body for one request head, or `None` for a `404`.
fn serve(
    answer: impl Fn(&str) -> Option<(&'static str, String, Vec<u8>)> + Send + 'static,
) -> LoopbackServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback server");
    let port = listener.local_addr().expect("addr").port();
    listener.set_nonblocking(true).expect("non-blocking");
    let shutdown = Arc::new(AtomicBool::new(false));
    let stop = Arc::clone(&shutdown);
    let handle = std::thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut socket, _)) => {
                    socket.set_nonblocking(false).ok();
                    socket
                        .set_read_timeout(Some(Duration::from_millis(1_000)))
                        .ok();
                    let mut head = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                        match socket.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(read) => head.extend_from_slice(&buf[..read]),
                        }
                        if head.len() > 64 * 1024 {
                            break;
                        }
                    }
                    let request = String::from_utf8_lossy(&head).to_string();
                    let response = match answer(&request) {
                        Some((status, content_type, body)) => {
                            let mut out = format!(
                                "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\n\
                                 content-length: {}\r\nconnection: close\r\n\r\n",
                                body.len(),
                            )
                            .into_bytes();
                            out.extend_from_slice(&body);
                            out
                        }
                        None => b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\
                                  connection: close\r\n\r\n"
                            .to_vec(),
                    };
                    let _ = socket.write_all(&response);
                    let _ = socket.flush();
                }
                Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    LoopbackServer {
        port,
        shutdown,
        handle: Some(handle),
    }
}

// ---------------------------------------------------------------------------
// Project repositories
// ---------------------------------------------------------------------------

fn git(args: &[&str], cwd: &Path) {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env("GIT_AUTHOR_NAME", "e2e")
        .env("GIT_AUTHOR_EMAIL", "e2e@example.invalid")
        .env("GIT_COMMITTER_NAME", "e2e")
        .env("GIT_COMMITTER_EMAIL", "e2e@example.invalid")
        .output()
        .unwrap_or_else(|error| panic!("run git {args:?}: {error}"));
    assert!(
        output.status.success(),
        "git {args:?} in {} failed:\nstdout: {}\nstderr: {}",
        cwd.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// One project repository: a working tree the test edits, and a bare
/// clone the git server publishes.
struct ProjectRepo {
    work: PathBuf,
    bare: PathBuf,
    name: String,
}

impl ProjectRepo {
    fn create(root: &Path, serve_root: &Path, name: &str, profile: &str) -> Self {
        let work = root.join(format!("{name}-work"));
        std::fs::create_dir_all(work.join("sbproxy")).expect("create work tree");
        std::fs::write(work.join("sbproxy/origin.yaml"), profile).expect("write profile");
        git(&["init", "--quiet", "-b", "main", "."], &work);
        git(&["add", "-A"], &work);
        git(&["commit", "--quiet", "-m", "initial profile"], &work);

        let bare = serve_root.join(format!("{name}.git"));
        git(
            &[
                "clone",
                "--quiet",
                "--bare",
                work.to_str().expect("utf8"),
                bare.to_str().expect("utf8"),
            ],
            root,
        );
        git(&["update-server-info"], &bare);
        Self {
            work,
            bare,
            name: name.to_string(),
        }
    }

    /// Commit a new profile and publish it, the way a merge to `main`
    /// would.
    fn merge(&self, profile: &str) {
        std::fs::write(self.work.join("sbproxy/origin.yaml"), profile).expect("rewrite profile");
        git(&["add", "-A"], &self.work);
        git(&["commit", "--quiet", "-m", "update profile"], &self.work);
        git(
            &["fetch", "--quiet", "origin", "+refs/heads/*:refs/heads/*"],
            &self.bare,
        );
        git(&["update-server-info"], &self.bare);
    }

    fn url(&self, git_port: u16) -> String {
        format!("http://127.0.0.1:{git_port}/{}.git", self.name)
    }
}

// ---------------------------------------------------------------------------
// Fixture documents
// ---------------------------------------------------------------------------

/// The checkout team's profile. No hostname anywhere in it.
fn checkout_profile(rate_limit: u32) -> String {
    format!(
        r#"name: checkout
inputs:
  - name: upstream_host
    description: the regional upstream this deployment sends to
spec:
  api:
    base:
      action:
        type: proxy
        url: "http://{{{{vars.upstream_host}}}}"
      policies:
        - name: rate_limit
          requests_per_minute: {rate_limit}
        - name: checkout_request_limit
          type: request_limit
          max_body_size: 1048576
          max_url_length: 2048
  webhooks:
    base:
      action:
        type: proxy
        url: "http://{{{{vars.upstream_host}}}}"
"#
    )
}

/// The billing team's profile. One origin, one added policy.
fn billing_profile() -> String {
    r#"name: billing
inputs:
  - name: upstream_host
    description: the regional upstream this deployment sends to
spec:
  api:
    base:
      action:
        type: proxy
        url: "http://{{vars.upstream_host}}"
      policies:
        - name: billing_request_limit
          type: request_limit
          max_body_size: 524288
          max_url_length: 1024
"#
    .to_string()
}

/// The platform's runtime document: the floor, and which repositories
/// to pull. No `origins:` block: every origin below is composed.
fn runtime_yaml(
    checkout: &ProjectRepo,
    billing: &ProjectRepo,
    git_port: u16,
    upstream: &str,
    platform_rate_limit: u32,
    extra_entries: &str,
) -> String {
    format!(
        r#"proxy:
  http_bind_port: 0
  extensions:
    upstream:
      allow_private_cidrs:
        - '127.0.0.1/32'

origin_defaults:
  policies:
    - name: platform_headers_lock
      type: security_headers
      hsts: true
      locked: true
    - name: rate_limit
      type: rate_limiting
      requests_per_minute: {platform_rate_limit}
      burst: 100

origin_sources:
  tier: development
  aggregator:
    poll_interval_secs: 5
    debounce_secs: 1
    max_deferral_secs: 10
    concurrency: 2
    deadline_secs: 120
  entries:
    - name: checkout
      repo: {checkout_url}
      revision: refs/heads/main
      path: sbproxy/origin.yaml
      timeout_secs: 60
      hosts:
        api:
          - {CHECKOUT_HOST}
        webhooks:
          - {HOOKS_HOST}
      inputs:
        upstream_host: {upstream}
    - name: billing
      repo: {billing_url}
      revision: refs/heads/main
      path: sbproxy/origin.yaml
      timeout_secs: 60
      hosts:
        api:
          - {BILLING_HOST}
      inputs:
        upstream_host: {upstream}
{extra_entries}"#,
        checkout_url = checkout.url(git_port),
        billing_url = billing.url(git_port),
    )
}

// ---------------------------------------------------------------------------
// The aggregator, run as the shipped binary
// ---------------------------------------------------------------------------

struct AggregateRun {
    success: bool,
    stdout: String,
    stderr: String,
}

impl AggregateRun {
    fn combined(&self) -> String {
        format!(
            "--- stdout ---\n{}\n--- stderr ---\n{}",
            self.stdout, self.stderr
        )
    }
}

/// Run one `sbproxy aggregate` round with `AGGREGATOR_ONLY_SECRET`
/// exported, so every test in this file is also a test that a project
/// profile cannot read the aggregator's environment.
fn aggregate(args: &[&str]) -> AggregateRun {
    let output = Command::new(proxy_binary_path())
        .arg("aggregate")
        .args(args)
        .env("SOME_SECRET", AGGREGATOR_ONLY_SECRET)
        .env("AGGREGATOR_ONLY", AGGREGATOR_ONLY_SECRET)
        .output()
        .expect("run sbproxy aggregate");
    AggregateRun {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

fn publish_round(runtime: &Path, authority_admin: u16) -> AggregateRun {
    aggregate(&[
        runtime.to_str().expect("utf8"),
        "--admin-url",
        &format!("http://127.0.0.1:{authority_admin}"),
        "--username",
        ADMIN_USER,
        "--password",
        ADMIN_PASSWORD,
        "--format",
        "json",
    ])
}

// ---------------------------------------------------------------------------
// The authority and the subscriber node
// ---------------------------------------------------------------------------

struct LiveAuthority {
    _harness: ProxyHarness,
    admin_port: u16,
    bundle_port: u16,
    verifying_keys: PathBuf,
    /// The CA a subscriber has to trust when the bundle listener runs
    /// TLS, or `None` when it is plaintext loopback.
    ca_file: Option<PathBuf>,
}

/// Mint a self-signed leaf for `127.0.0.1` and write the PEM pair.
///
/// TLS on the bundle listener is the one thing in this feature that can
/// only break at startup, in a separate process, with real sockets:
/// nothing in the unit or integration tiers binds a rustls acceptor.
/// `rcgen` is already an `e2e` dependency and three other suites mint
/// certificates with it the same way.
fn write_self_signed(dir: &Path) -> (PathBuf, PathBuf) {
    let key = rcgen::KeyPair::generate().expect("rcgen keypair");
    let mut params =
        rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).expect("rcgen params");
    params.subject_alt_names.push(rcgen::SanType::IpAddress(
        "127.0.0.1".parse().expect("loopback literal"),
    ));
    let cert = params.self_signed(&key).expect("self-signed cert");
    let cert_file = dir.join("authority-tls.pem");
    let key_file = dir.join("authority-tls-key.pem");
    std::fs::write(&cert_file, cert.pem()).expect("write cert");
    std::fs::write(&key_file, key.serialize_pem()).expect("write key");
    (cert_file, key_file)
}

fn init_authority_keys(dir: &Path) -> (PathBuf, PathBuf) {
    let output = Command::new(proxy_binary_path())
        .args([
            "config",
            "authority",
            "init",
            "--dir",
            dir.to_str().expect("utf8"),
            "--key-id",
            KEY_ID,
            "--authority-id",
            AUTHORITY_ID,
        ])
        .output()
        .expect("run authority init");
    assert!(
        output.status.success(),
        "authority init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    (
        dir.join("authority-signing.key"),
        dir.join("authority-keys.json"),
    )
}

fn start_authority(dir: &Path) -> LiveAuthority {
    start_authority_with_tls(dir, false)
}

fn start_authority_with_tls(dir: &Path, tls: bool) -> LiveAuthority {
    let (signing_key, verifying_keys) = init_authority_keys(dir);
    let store_dir = dir.join("authority-store");
    std::fs::create_dir_all(&store_dir).expect("create store dir");
    let admin_port = pick_port();
    let bundle_port = pick_port();
    let (tls_block, ca_file) = if tls {
        let (cert_file, key_file) = write_self_signed(dir);
        (
            format!(
                "\n      tls:\n        cert_file: {}\n        key_file: {}",
                cert_file.display(),
                key_file.display(),
            ),
            Some(cert_file),
        )
    } else {
        (String::new(), None)
    };
    let yaml = format!(
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
      archive_keep: 10{tls_block}
origins:
  "authority.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "authority"
"#,
        signing = signing_key.display(),
        store = store_dir.display(),
    );
    let harness = ProxyHarness::start_with_workspace(&yaml, &[]).expect("start authority");
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(30))
        .expect("authority admin port never bound");
    if ca_file.is_some() {
        // `ProxyHarness::wait_for_port` is an HTTP-level probe, by
        // design, and it cannot complete against a TLS listener. Wait
        // for the accept loop at the TCP level here; the handshake in
        // the test itself is what proves the acceptor really built.
        wait_for_tcp(bundle_port, Duration::from_secs(30));
    } else {
        ProxyHarness::wait_for_port(bundle_port, Duration::from_secs(30))
            .expect("authority bundle listener never bound");
    }
    LiveAuthority {
        _harness: harness,
        admin_port,
        bundle_port,
        verifying_keys,
        ca_file,
    }
}

fn register_subscriber(admin_port: u16, dir: &Path) -> PathBuf {
    let url = format!("http://127.0.0.1:{admin_port}/admin/config-authority/subscribers");
    let response = client()
        .post(url)
        .header("authorization", basic_auth())
        .header("content-type", "application/json")
        .body(format!(r#"{{"subscriber_id":"{SUBSCRIBER_ID}"}}"#))
        .send()
        .expect("register subscriber");
    let body: serde_json::Value = response.json().expect("registration json");
    let credential = body["credential"]
        .as_str()
        .expect("a credential")
        .to_string();
    let path = dir.join("subscriber.token");
    std::fs::write(&path, credential.as_bytes()).expect("write token");
    path
}

/// A node with **no `origins:` block of its own**. Everything it serves
/// comes from the bundle the aggregator composed.
fn subscriber_yaml(
    bundle_port: u16,
    token_file: &Path,
    verifying_keys: &Path,
    cache_path: &Path,
    admin_port: u16,
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
  extensions:
    upstream:
      allow_private_cidrs:
        - '127.0.0.1/32'
  config_authority:
    upstream:
      url: http://127.0.0.1:{bundle_port}
      mode: overlay
      subscriber_id: {SUBSCRIBER_ID}
      credential: file:{token}
      verifying_keys_file: {keys}
      poll_interval: {POLL_INTERVAL}
      cache_path: {cache}
      allow_insecure_http: true
"#,
        token = token_file.display(),
        keys = verifying_keys.display(),
        cache = cache_path.display(),
    )
}

/// The `requests_per_minute` the node's composed `origins:` map carries
/// for `host`, or `None` when nothing composed for it yet.
///
/// Read out of `GET /admin/config/effective`'s `yaml` field rather than
/// by substring, because the same number is the right answer for one
/// host and the wrong one for another: the floor is 600 and only
/// checkout overrides it.
fn composed_rate_limit(admin_port: u16, host: &str) -> Option<u64> {
    let effective = admin(admin_port, "GET", "/admin/config/effective");
    if effective.status != 200 {
        return None;
    }
    let document = effective.json();
    let yaml = document["yaml"].as_str()?;
    let parsed: serde_yaml::Value = serde_yaml::from_str(yaml).ok()?;
    parsed
        .get("origins")?
        .get(host)?
        .get("policies")?
        .as_sequence()?
        .iter()
        .find(|policy| {
            policy.get("type").and_then(serde_yaml::Value::as_str) == Some("rate_limiting")
        })?
        .get("requests_per_minute")?
        .as_u64()
}

/// Every policy `type` the node composed for `host`.
fn composed_policy_types(admin_port: u16, host: &str) -> Vec<String> {
    let effective = admin(admin_port, "GET", "/admin/config/effective");
    let document = effective.json();
    let Some(yaml) = document["yaml"].as_str() else {
        return Vec::new();
    };
    let Ok(parsed) = serde_yaml::from_str::<serde_yaml::Value>(yaml) else {
        return Vec::new();
    };
    parsed
        .get("origins")
        .and_then(|origins| origins.get(host))
        .and_then(|origin| origin.get("policies"))
        .and_then(serde_yaml::Value::as_sequence)
        .map(|policies| {
            policies
                .iter()
                .filter_map(|policy| {
                    policy
                        .get("type")
                        .and_then(serde_yaml::Value::as_str)
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// What the node answers for `host`, as `(status, body)`.
fn node_get(node: &ProxyHarness, host: &str) -> (u16, String) {
    match node.get("/", host) {
        Ok(response) => (response.status, response.text().unwrap_or_default()),
        Err(_) => (0, String::new()),
    }
}

// ---------------------------------------------------------------------------
// The arc
// ---------------------------------------------------------------------------

#[test]
fn two_project_repos_one_aggregator_and_a_node_that_was_handed_no_origins() {
    let _guard = suite_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = tempfile::tempdir().expect("temp dir");
    let serve_root = dir.path().join("git");
    std::fs::create_dir_all(&serve_root).expect("create git root");

    let checkout =
        ProjectRepo::create(dir.path(), &serve_root, "checkout", &checkout_profile(1200));
    let billing = ProjectRepo::create(dir.path(), &serve_root, "billing", &billing_profile());
    let git_server = start_git_server(serve_root.clone());
    let upstream = start_stub_upstream();
    let upstream_target = format!("127.0.0.1:{}", upstream.port);

    let runtime = dir.path().join("runtime.yml");
    std::fs::write(
        &runtime,
        runtime_yaml(
            &checkout,
            &billing,
            git_server.port,
            &upstream_target,
            600,
            "",
        ),
    )
    .expect("write runtime config");

    let authority = start_authority(dir.path());
    let token = register_subscriber(authority.admin_port, dir.path());
    let cache = dir.path().join("bundle-cache.json");
    let node_admin = pick_port();

    // --- The aggregator composes and publishes.
    let published = publish_round(&runtime, authority.admin_port);
    assert!(published.success, "first publish: {}", published.combined());

    let node = ProxyHarness::start_with_workspace(
        &subscriber_yaml(
            authority.bundle_port,
            &token,
            &authority.verifying_keys,
            &cache,
            node_admin,
        ),
        &[],
    )
    .expect("start subscriber node");
    ProxyHarness::wait_for_port(node_admin, Duration::from_secs(30))
        .expect("node admin port never bound");

    // --- The node serves both projects' hosts, having been handed no
    // `origins:` block of its own.
    wait_until("the node to serve the checkout host", || {
        node_get(&node, CHECKOUT_HOST).0 == 200
    });
    for host in [CHECKOUT_HOST, HOOKS_HOST, BILLING_HOST] {
        let (status, body) = node_get(&node, host);
        assert_eq!(
            status, 200,
            "{host} should be served by the composed bundle"
        );
        assert!(
            body.starts_with("upstream-for:"),
            "{host} reached the stub upstream: {body}",
        );
    }

    // --- The composed behavior is the three-layer answer.
    let effective = admin(node_admin, "GET", "/admin/config/effective");
    assert_eq!(effective.status, 200, "{}", effective.body);
    let document = effective.body;
    // Asserted on the parsed document rather than by substring:
    // composition strips `name`, `locked` and `disabled` before it
    // emits, because the modules these lists feed reject unknown keys,
    // and the floor's 600 is the *right* answer for the two hosts that
    // never overrode it.
    let checkout_policies = composed_policy_types(node_admin, CHECKOUT_HOST);
    assert!(
        checkout_policies.contains(&"security_headers".to_string()),
        "the platform's locked policy reached the node: {checkout_policies:?}\n{document}",
    );
    assert!(
        checkout_policies.contains(&"request_limit".to_string()),
        "the project's own added policy reached the node: {checkout_policies:?}",
    );
    assert_eq!(
        composed_rate_limit(node_admin, CHECKOUT_HOST),
        Some(1200),
        "the project's override of the unlocked default is at the project's value",
    );
    assert_eq!(
        composed_rate_limit(node_admin, BILLING_HOST),
        Some(600),
        "and a project that never overrode it stays on the platform's floor",
    );

    // --- A project merges a change to its own repository. One
    // aggregator round later the node's behavior changes, with no edit
    // to the runtime document and no node restart.
    checkout.merge(&checkout_profile(2400));
    let second = publish_round(&runtime, authority.admin_port);
    assert!(second.success, "second publish: {}", second.combined());
    wait_until("the node to take the project's merged change", || {
        composed_rate_limit(node_admin, CHECKOUT_HOST) == Some(2400)
    });

    // --- The platform raises a default in the runtime document. Both
    // hosts pick it up; billing never overrode it, so it moves.
    std::fs::write(
        &runtime,
        runtime_yaml(
            &checkout,
            &billing,
            git_server.port,
            &upstream_target,
            900,
            "",
        ),
    )
    .expect("raise the floor");
    let third = publish_round(&runtime, authority.admin_port);
    assert!(third.success, "third publish: {}", third.combined());
    wait_until("the node to take the platform's raised floor", || {
        composed_rate_limit(node_admin, BILLING_HOST) == Some(900)
            && composed_rate_limit(node_admin, HOOKS_HOST) == Some(900)
    });

    // --- Nothing the aggregator could read from its own environment
    // ever reached the node.
    let served = admin(node_admin, "GET", "/admin/config/effective").body;
    assert!(
        !served.contains(AGGREGATOR_ONLY_SECRET),
        "the aggregator's environment must not reach a subscriber",
    );

    // --- A bad configuration that did get published is undone by
    // `config-authority rollback`, and the node returns to the previous
    // behavior.
    assert_eq!(composed_rate_limit(node_admin, BILLING_HOST), Some(900));
    let status = admin(
        authority.admin_port,
        "GET",
        "/admin/config-authority/status",
    )
    .json();
    let archived: Vec<u64> = status["archived_revisions"]
        .as_array()
        .expect("the archive ring")
        .iter()
        .filter_map(serde_json::Value::as_u64)
        .collect();
    assert!(
        archived.len() >= 3,
        "three publishes are in the archive: {archived:?}",
    );
    let rollback = Command::new(proxy_binary_path())
        .args([
            "config",
            "authority",
            "rollback",
            "--to-revision",
            "1",
            "--admin-url",
            &format!("http://127.0.0.1:{}", authority.admin_port),
            "--username",
            ADMIN_USER,
            "--password",
            ADMIN_PASSWORD,
        ])
        .output()
        .expect("run rollback");
    assert!(
        rollback.status.success(),
        "rollback: {}",
        String::from_utf8_lossy(&rollback.stderr),
    );
    wait_until("the node to converge on the rolled-back revision", || {
        composed_rate_limit(node_admin, CHECKOUT_HOST) == Some(1200)
            && composed_rate_limit(node_admin, BILLING_HOST) == Some(600)
    });
    assert_eq!(
        node_get(&node, CHECKOUT_HOST).0,
        200,
        "and it is still serving traffic on the restored document",
    );
}

/// The bundle listener with TLS on, which is the one thing in this
/// feature that can only break at startup, in a separate process, on a
/// real socket.
///
/// Nothing in the unit or integration tiers binds a rustls acceptor, so
/// a TLS block that the config accepts and the listener cannot start on
/// would ship green. Asserted three ways: the port binds, it completes a
/// real TLS handshake, and a plaintext request to it does not get an
/// HTTP response.
///
/// The subscriber half stays on plaintext loopback, because
/// `proxy.config_authority.upstream` has no `ca_file` key: a subscriber
/// trusts the system store, and a self-signed leaf minted in a temp
/// directory is not in it. What this covers is the listener's own
/// startup, which is what has shipped broken before.
#[test]
fn the_bundle_listener_starts_and_serves_tls() {
    let _guard = suite_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = tempfile::tempdir().expect("temp dir");
    let authority = start_authority_with_tls(dir.path(), true);
    assert!(
        authority.ca_file.is_some(),
        "the fixture really did configure TLS",
    );

    // A real handshake, not a port probe. `start_authority_with_tls`
    // already waited for the port, and a listener that bound and then
    // failed to build its acceptor would pass that and fail here.
    let client = reqwest::blocking::Client::builder()
        // The leaf is self-signed and minted for this run; the point is
        // that a TLS session establishes at all, not that a public CA
        // vouches for it.
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(15))
        .build()
        .expect("build a TLS client");
    let response = client
        .get(format!(
            "https://127.0.0.1:{}/config-authority/v1/bundle",
            authority.bundle_port
        ))
        .send()
        .expect("the bundle listener completes a TLS handshake");
    assert_eq!(
        response.status().as_u16(),
        401,
        "an unauthenticated fetch is refused, which is an answer over TLS",
    );

    // And it is really TLS: a plaintext request must not get an HTTP
    // response out of it.
    let plaintext = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build a plaintext client")
        .get(format!(
            "http://127.0.0.1:{}/config-authority/v1/bundle",
            authority.bundle_port
        ))
        .send();
    assert!(
        plaintext.is_err(),
        "a TLS listener must not answer a plaintext request: {plaintext:?}",
    );
}

/// The node boots with its cached bundle and no aggregator or authority
/// reachable, and serves both hosts.
#[test]
fn a_node_boots_from_its_cached_bundle_with_the_authority_gone() {
    let _guard = suite_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = tempfile::tempdir().expect("temp dir");
    let serve_root = dir.path().join("git");
    std::fs::create_dir_all(&serve_root).expect("create git root");
    let checkout =
        ProjectRepo::create(dir.path(), &serve_root, "checkout", &checkout_profile(1200));
    let billing = ProjectRepo::create(dir.path(), &serve_root, "billing", &billing_profile());
    let git_server = start_git_server(serve_root.clone());
    let upstream = start_stub_upstream();
    let upstream_target = format!("127.0.0.1:{}", upstream.port);

    let runtime = dir.path().join("runtime.yml");
    std::fs::write(
        &runtime,
        runtime_yaml(
            &checkout,
            &billing,
            git_server.port,
            &upstream_target,
            600,
            "",
        ),
    )
    .expect("write runtime config");

    let cache = dir.path().join("bundle-cache.json");
    let token;
    let verifying_keys;
    let bundle_port;
    let node_admin = pick_port();
    {
        let authority = start_authority(dir.path());
        token = register_subscriber(authority.admin_port, dir.path());
        verifying_keys = authority.verifying_keys.clone();
        bundle_port = authority.bundle_port;
        let published = publish_round(&runtime, authority.admin_port);
        assert!(published.success, "publish: {}", published.combined());

        let node = ProxyHarness::start_with_workspace(
            &subscriber_yaml(bundle_port, &token, &verifying_keys, &cache, node_admin),
            &[],
        )
        .expect("start subscriber node");
        ProxyHarness::wait_for_port(node_admin, Duration::from_secs(30)).expect("node admin");
        wait_until("the node to cache the bundle", || {
            node_get(&node, CHECKOUT_HOST).0 == 200 && cache.is_file()
        });
        // The authority process and the node both go away here.
    }

    // Nothing is listening on the authority's bundle port any more.
    let cold_admin = pick_port();
    let cold = ProxyHarness::start_with_workspace(
        &subscriber_yaml(bundle_port, &token, &verifying_keys, &cache, cold_admin),
        &[],
    )
    .expect("a node with no authority reachable must still boot");
    ProxyHarness::wait_for_port(cold_admin, Duration::from_secs(30)).expect("cold node admin");
    for host in [CHECKOUT_HOST, HOOKS_HOST, BILLING_HOST] {
        let (status, _) = node_get(&cold, host);
        assert_eq!(
            status, 200,
            "{host} must be served from the cached bundle with no authority reachable",
        );
    }
}

// ---------------------------------------------------------------------------
// The refusals, offline: `--out` needs no authority and publishes nothing
// ---------------------------------------------------------------------------

/// Compose to a file and return the run plus whether the file exists.
fn compose_offline(runtime: &Path, out: &Path) -> (AggregateRun, bool) {
    let run = aggregate(&[
        runtime.to_str().expect("utf8"),
        "--out",
        out.to_str().expect("utf8"),
    ]);
    (run, out.is_file())
}

struct OfflineFixture {
    _dir: tempfile::TempDir,
    _git_server: LoopbackServer,
    _upstream: LoopbackServer,
    checkout: ProjectRepo,
    billing: ProjectRepo,
    git_port: u16,
    upstream_target: String,
    root: PathBuf,
}

fn offline_fixture() -> OfflineFixture {
    let dir = tempfile::tempdir().expect("temp dir");
    let serve_root = dir.path().join("git");
    std::fs::create_dir_all(&serve_root).expect("create git root");
    let checkout =
        ProjectRepo::create(dir.path(), &serve_root, "checkout", &checkout_profile(1200));
    let billing = ProjectRepo::create(dir.path(), &serve_root, "billing", &billing_profile());
    let git_server = start_git_server(serve_root);
    let upstream = start_stub_upstream();
    let upstream_target = format!("127.0.0.1:{}", upstream.port);
    let root = dir.path().to_path_buf();
    OfflineFixture {
        _dir: dir,
        git_port: git_server.port,
        _git_server: git_server,
        _upstream: upstream,
        checkout,
        billing,
        upstream_target,
        root,
    }
}

impl OfflineFixture {
    fn runtime(&self, platform_rate_limit: u32, extra_entries: &str) -> PathBuf {
        let path = self.root.join("runtime.yml");
        std::fs::write(
            &path,
            runtime_yaml(
                &self.checkout,
                &self.billing,
                self.git_port,
                &self.upstream_target,
                platform_rate_limit,
                extra_entries,
            ),
        )
        .expect("write runtime config");
        path
    }
}

#[test]
fn a_profile_that_touches_a_locked_default_fails_the_compose_and_names_the_project() {
    let _guard = suite_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fixture = offline_fixture();
    let runtime = fixture.runtime(600, "");
    let out = fixture.root.join("composed.yml");

    // The good round first, so the failure below is a change and not the
    // starting state.
    let (good, wrote) = compose_offline(&runtime, &out);
    assert!(
        good.success && wrote,
        "baseline compose: {}",
        good.combined()
    );
    let baseline = std::fs::read_to_string(&out).expect("read composed");

    fixture.checkout.merge(
        r#"name: checkout
inputs:
  - name: upstream_host
    description: the regional upstream this deployment sends to
spec:
  api:
    base:
      action:
        type: proxy
        url: "http://{{vars.upstream_host}}"
      policies:
        - name: platform_headers_lock
          hsts: false
  webhooks:
    base:
      action:
        type: proxy
        url: "http://{{vars.upstream_host}}"
"#,
    );
    let (refused, _) = compose_offline(&runtime, &out);
    assert!(
        !refused.success,
        "a profile that touches a locked default must fail the compose: {}",
        refused.combined(),
    );
    assert!(
        refused.combined().contains("checkout"),
        "the error names the project: {}",
        refused.combined(),
    );
    assert_eq!(
        std::fs::read_to_string(&out).expect("read composed"),
        baseline,
        "nothing was written, so a node reading this file keeps the previous composition",
    );
}

#[test]
fn a_profile_that_does_not_compile_is_attributed_to_its_entry() {
    let _guard = suite_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fixture = offline_fixture();
    let runtime = fixture.runtime(600, "");
    let out = fixture.root.join("composed.yml");

    fixture
        .billing
        .merge("name: billing\nspec:\n  api:\n    base:\n      action:\n  \t- not yaml\n");
    let (refused, wrote) = compose_offline(&runtime, &out);
    assert!(
        !refused.success,
        "a profile that does not parse must fail the round: {}",
        refused.combined(),
    );
    assert!(
        !wrote,
        "and it must write nothing at all on a first-ever composition",
    );
    assert!(
        refused.combined().contains("billing"),
        "the failure is attributed to the entry rather than reported as an unattributed \
         parse error: {}",
        refused.combined(),
    );
}

#[test]
fn a_second_entry_claiming_a_taken_host_fails_the_compose_by_name() {
    let _guard = suite_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fixture = offline_fixture();
    let clash = format!(
        r#"    - name: clashing
      repo: {url}
      revision: refs/heads/main
      path: sbproxy/origin.yaml
      timeout_secs: 60
      hosts:
        api:
          - {CHECKOUT_HOST}
      inputs:
        upstream_host: {upstream}
"#,
        url = fixture.billing.url(fixture.git_port),
        upstream = fixture.upstream_target,
    );
    let runtime = fixture.runtime(600, &clash);
    let out = fixture.root.join("composed.yml");
    let (refused, wrote) = compose_offline(&runtime, &out);
    assert!(
        !refused.success,
        "two entries cannot both claim one host: {}",
        refused.combined(),
    );
    assert!(
        !wrote,
        "and nothing is written before the clash is resolved"
    );
    let message = refused.combined();
    assert!(
        message.contains(CHECKOUT_HOST),
        "the refusal names the host: {message}",
    );
    assert!(
        message.contains("clashing") || message.contains("checkout"),
        "and the entries fighting over it: {message}",
    );
}

/// A project profile is a confined document. `${VAR}` inside one is
/// refused rather than resolved, so the aggregator's environment can
/// never reach a composed document, a published bundle, or a response.
#[test]
fn a_profile_referencing_a_variable_never_reads_the_aggregators_environment() {
    let _guard = suite_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // The variable really is in the aggregator's environment: without
    // this the test would pass on a build that resolved it, because
    // there would be nothing to resolve.
    assert_eq!(
        std::env::var("SOME_SECRET").ok().as_deref(),
        None,
        "the value is exported to the aggregator child, not to this process",
    );

    let fixture = offline_fixture();
    let runtime = fixture.runtime(600, "");
    let out = fixture.root.join("composed.yml");

    fixture.checkout.merge(
        r#"name: checkout
inputs:
  - name: upstream_host
    description: the regional upstream this deployment sends to
spec:
  api:
    base:
      action:
        type: proxy
        url: "http://{{vars.upstream_host}}"
      request_modifiers:
        - name: leak
          headers:
            set:
              X-Leak: "${SOME_SECRET}"
  webhooks:
    base:
      action:
        type: proxy
        url: "http://{{vars.upstream_host}}"
"#,
    );
    let (run, wrote) = compose_offline(&runtime, &out);
    let output = run.combined();
    assert!(
        !output.contains(AGGREGATOR_ONLY_SECRET),
        "the aggregator's environment must not appear in its own output either: {output}",
    );
    if wrote {
        let composed = std::fs::read_to_string(&out).expect("read composed");
        assert!(
            !composed.contains(AGGREGATOR_ONLY_SECRET),
            "the composed document must never carry a value only the aggregator could read",
        );
    }
    assert!(
        !run.success,
        "a confined document refuses a host-backed reference rather than resolving it: {output}",
    );
}

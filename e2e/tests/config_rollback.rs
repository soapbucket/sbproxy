//! A bad config pushed, soaked, reverted, restarted, and rolled forward.
//!
//! Every other child of the config-rollback epic is unit and integration
//! tested inside its own crate. None of them spawns a real proxy on real
//! ports and kills it. This one does, because two epics in this
//! repository have shipped green with every child merged and the
//! assembled behavior broken.
//!
//! Deliberately outside the required CI gate, like the rest of
//! `sbproxy-e2e`. The scheduled lane runs `cargo test -p sbproxy-e2e`,
//! so this file is in it by being here; it is not `#[ignore]`d, because
//! the arc it covers is the epic's acceptance criterion rather than a
//! certification drill somebody opts into.
//!
//! # No sleep-and-hope
//!
//! Every wait below is a poll against an observable condition with a
//! bounded timeout: a ring entry reaching a state, a gauge reaching a
//! value, a body changing. A `sleep` that is not a poll appears exactly
//! twice, both times to prove a *negative* (the pipeline did not move
//! while the watcher was suspended), where waiting out a fixed window is
//! the only way to give the thing under test a chance to misbehave.
//!
//! # Serialization
//!
//! Every test here binds real sockets and restarts processes. The
//! scheduled lane runs `--test-threads=1`; this file additionally holds
//! a file-scoped mutex so a local `cargo test -p sbproxy-e2e
//! --test config_rollback` is safe on its own.

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use sbproxy_e2e::{proxy_binary_path, ProxyHarness};

const ADMIN_USER: &str = "admin";
const ADMIN_PASSWORD: &str = "rollback-e2e-not-the-default";

/// Long enough for a process start plus a soak window on a machine that
/// may be compiling at the same time.
const CONVERGE: Duration = Duration::from_secs(60);

/// The soak window every node in this file runs. Short on purpose; the
/// production default is 120 seconds.
const SOAK_WINDOW_SECS: u64 = 4;

/// How long a negative assertion waits before it counts. Sized at more
/// than three watcher debounce intervals plus a soak window, so "the
/// pipeline did not move" means it had every chance to.
const QUIET_WINDOW: Duration = Duration::from_secs(12);

/// Serializes the whole file. See the module docs.
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
        .timeout(Duration::from_secs(15))
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

fn admin(port: u16, method: &str, path: &str, body: Option<&str>) -> Reply {
    let url = format!("http://127.0.0.1:{port}{path}");
    let mut request = match method {
        "GET" => client().get(url),
        "POST" => client().post(url),
        "DELETE" => client().delete(url),
        other => panic!("unsupported method {other}"),
    }
    .header("authorization", basic_auth());
    if let Some(body) = body {
        request = request
            .header("content-type", "application/json")
            .body(body.to_string());
    }
    let response = request.send().expect("admin request");
    Reply {
        status: response.status().as_u16(),
        body: response.text().unwrap_or_default(),
    }
}

// ---------------------------------------------------------------------------
// A stub upstream and a stub that refuses to listen
// ---------------------------------------------------------------------------

/// A loopback HTTP server answering every request with `body`.
struct StubUpstream {
    port: u16,
    shutdown: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl StubUpstream {
    fn start(body: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub upstream");
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
                            .set_read_timeout(Some(Duration::from_millis(500)))
                            .ok();
                        let mut buf = [0u8; 4096];
                        let _ = socket.read(&mut buf);
                        let response = format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\
                             content-length: {}\r\nconnection: close\r\n\r\n{body}",
                            body.len(),
                        );
                        let _ = socket.write_all(response.as_bytes());
                        let _ = socket.flush();
                    }
                    Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            port,
            shutdown,
            handle: Some(handle),
        }
    }
}

impl Drop for StubUpstream {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// A port nothing listens on. Bound, noted, released: the point is a
/// destination that refuses a connection rather than one that hangs.
fn closed_port() -> u16 {
    pick_port()
}

// ---------------------------------------------------------------------------
// A node this test owns, rather than the shared harness
// ---------------------------------------------------------------------------

/// One `sbproxy` process, spawned directly so the test owns its config
/// path across a restart and can add `--config-fallback`.
///
/// `ProxyHarness` owns its own temp config and cannot be restarted
/// against a file the test has since corrupted, which is step 4.
struct Node {
    child: Option<Child>,
    http_port: u16,
    admin_port: u16,
    config_path: PathBuf,
    stdout: PathBuf,
    stderr: PathBuf,
}

impl Node {
    fn start(
        config_path: &Path,
        http_port: u16,
        admin_port: u16,
        args: &[&str],
        dir: &Path,
    ) -> Self {
        Self::start_with_env(config_path, http_port, admin_port, args, dir, &[])
    }

    /// [`Self::start`] with extra environment for the child.
    ///
    /// Scoped to the child, so two nodes in one test can differ in what
    /// a `${VAR}` in a published bundle resolves to. That divergence is
    /// how the fleet arc below gets one subscriber to refuse a bundle
    /// its sibling applies, with no misbehave switch in production code.
    fn start_with_env(
        config_path: &Path,
        http_port: u16,
        admin_port: u16,
        args: &[&str],
        dir: &Path,
        env: &[(&str, &str)],
    ) -> Self {
        let stdout = dir.join(format!("node-{admin_port}.out"));
        let stderr = dir.join(format!("node-{admin_port}.err"));
        let mut command = Command::new(proxy_binary_path());
        for (name, value) in env {
            command.env(name, value);
        }
        let child = command
            .arg("--config")
            .arg(config_path)
            .args(args)
            .stdout(Stdio::from(
                std::fs::File::create(&stdout).expect("create stdout capture"),
            ))
            .stderr(Stdio::from(
                std::fs::File::create(&stderr).expect("create stderr capture"),
            ))
            .spawn()
            .expect("spawn sbproxy");
        let node = Self {
            child: Some(child),
            http_port,
            admin_port,
            config_path: config_path.to_path_buf(),
            stdout,
            stderr,
        };
        ProxyHarness::wait_for_port(admin_port, CONVERGE).unwrap_or_else(|error| {
            panic!("admin port never bound: {error}\n{}", node.log());
        });
        node
    }

    fn log(&self) -> String {
        format!(
            "--- stdout ---\n{}\n--- stderr ---\n{}",
            std::fs::read_to_string(&self.stdout).unwrap_or_default(),
            std::fs::read_to_string(&self.stderr).unwrap_or_default(),
        )
    }

    fn admin(&self, method: &str, path: &str, body: Option<&str>) -> Reply {
        admin(self.admin_port, method, path, body)
    }

    fn history(&self) -> serde_json::Value {
        let reply = self.admin("GET", "/admin/config/history", None);
        assert_eq!(reply.status, 200, "history: {}", reply.body);
        reply.json()
    }

    fn metrics(&self) -> String {
        self.admin("GET", "/metrics", None).body
    }

    /// The gauge's current value, or `None` when the family is absent.
    fn gauge(&self, name: &str) -> Option<f64> {
        self.metrics()
            .lines()
            .find(|line| line.starts_with(name) && !line.starts_with('#'))
            .and_then(|line| line.split_whitespace().nth(1)?.parse().ok())
    }

    /// The value of one labeled counter sample, or `0.0` when the
    /// series does not exist yet.
    ///
    /// A counter that has never been incremented has no series at all,
    /// so "absent" and "zero" are the same answer to the question these
    /// assertions ask.
    fn counter(&self, series: &str) -> f64 {
        self.metrics()
            .lines()
            .find(|line| line.starts_with(series))
            .and_then(|line| line.split_whitespace().last()?.parse().ok())
            .unwrap_or(0.0)
    }

    /// The body this node serves for `host`, or `None` when it did not
    /// answer 200.
    fn serves(&self, host: &str) -> Option<String> {
        let response = client()
            .get(format!("http://127.0.0.1:{}/", self.http_port))
            .header("host", host)
            .send()
            .ok()?;
        if response.status() != 200 {
            return None;
        }
        response.text().ok()
    }

    fn rewrite_config(&self, yaml: &str) {
        std::fs::write(&self.config_path, yaml).expect("rewrite config");
    }

    fn reload(&self) -> Reply {
        self.admin("POST", "/admin/reload", None)
    }

    fn kill(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        // The port has to be free before a restart binds it again.
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", self.admin_port)).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("admin port {} still accepting after kill", self.admin_port);
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// The status this node answers for `api.local`, or `0` when the
/// request did not complete.
fn node_error_status(node: &Node) -> u16 {
    client()
        .get(format!("http://127.0.0.1:{}/", node.http_port))
        .header("host", "api.local")
        .send()
        .map_or(0, |response| response.status().as_u16())
}

/// Poll `condition` until it is true or `CONVERGE` elapses.
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
// Configuration fixtures
// ---------------------------------------------------------------------------

/// One node with a load-balanced origin pointed at `upstream_port`, a
/// health check on it, and a short soak window.
///
/// `load_balancer` rather than `proxy` on purpose: the soak's
/// upstream-health signal reads per-target health checks, circuit
/// breakers, and outlier ejections, and an origin declaring none of the
/// three abstains rather than reporting health it never looked for.
fn node_yaml(
    http_port: u16,
    admin_port: u16,
    history_dir: &Path,
    upstream_port: u16,
    auto_revert: bool,
    require_upstream_health: bool,
) -> String {
    format!(
        r#"proxy:
  http_bind_port: {http_port}
  admin:
    enabled: true
    bind: 127.0.0.1
    port: {admin_port}
    username: {ADMIN_USER}
    password: {ADMIN_PASSWORD}
    # This suite polls the admin API to observe ring state, and the
    # shipped 240-per-minute limit is a rate a poll loop reaches in
    # seconds. Raised here rather than slowed down there, so a wait
    # stays responsive enough to catch a transition.
    rate_limit_per_minute: 100000
  extensions:
    upstream:
      allow_private_cidrs:
        - '127.0.0.1/32'
  config_history:
    enabled: true
    dir: {history}
    keep: 20
    keep_rejected: 5
    soak:
      window_secs: {SOAK_WINDOW_SECS}
      min_requests: 1
      require_upstream_health: {require_upstream_health}
      auto_revert: {auto_revert}
      probe:
        url: http://127.0.0.1:{admin_port}/healthz
        expect_status: 200
        interval_secs: 1
    boot:
      fallback: 'off'
      max_attempts: 3
      success_secs: 2
origins:
  "api.local":
    action:
      type: load_balancer
      algorithm: round_robin
      targets:
        - url: http://127.0.0.1:{upstream_port}
          health_check:
            path: /
            interval_secs: 1
            timeout_ms: 500
            unhealthy_threshold: 2
            healthy_threshold: 1
"#,
        history = history_dir.display(),
    )
}

// ---------------------------------------------------------------------------
// The node-side arc: seven steps against one real binary
// ---------------------------------------------------------------------------

#[test]
fn a_bad_config_soaks_reverts_survives_a_restart_and_rolls_forward() {
    let _guard = suite_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let upstream = StubUpstream::start("good-upstream");
    let dir = tempfile::tempdir().expect("temp dir");
    let history = dir.path().join("config-history");
    let config_path = dir.path().join("sb.yml");
    let http_port = pick_port();
    let admin_port = pick_port();

    let good = node_yaml(http_port, admin_port, &history, upstream.port, true, true);
    std::fs::write(&config_path, &good).expect("write config");

    // --- 1. Boot on a good config, serve, and watch the soak promote it.
    let mut node = Node::start(&config_path, http_port, admin_port, &[], dir.path());
    wait_until("the good config to serve traffic", || {
        node.serves("api.local").as_deref() == Some("good-upstream")
    });
    let history_now = node.history();
    assert_eq!(
        history_now["entries"].as_array().map(Vec::len),
        Some(1),
        "one applied revision after boot: {history_now}",
    );
    wait_until("revision 1 to promote to last known good", || {
        node.history()["lkg_revision"] == serde_json::json!(1)
    });
    assert_eq!(
        node.history()["entries"][0]["state"],
        "good",
        "the soak promoted it rather than leaving it applied",
    );

    // --- 2. A config that compiles cleanly and breaks traffic.
    let dead = closed_port();
    let broken = node_yaml(http_port, admin_port, &history, dead, true, true);
    node.rewrite_config(&broken);
    let reloaded = node.reload();
    assert_eq!(
        reloaded.status, 200,
        "the broken config compiles: {}",
        reloaded.body
    );
    wait_until("the broken revision to be recorded", || {
        node.history()["entries"].as_array().map(Vec::len) >= Some(2)
    });
    assert_eq!(
        node_error_status(&node),
        502,
        "the broken document really did break traffic:\n{}",
        node.log(),
    );

    // The soak fails, and it fails on the upstream-health signal
    // specifically. The ring's own rows carry the state rather than the
    // verdict, so the signal comes off the metric that names it, which
    // is also the series an operator alerts on.
    let failing_signal = concat!(
        "sbproxy_config_soak_verdict_total{signal=\"upstream_health\",",
        "verdict=\"failed\"}",
    );
    wait_until("the soak to fail on the upstream-health signal", || {
        node.counter(failing_signal) >= 1.0
    });
    let after_soak = node.history();
    assert_eq!(
        after_soak["lkg_revision"],
        serde_json::json!(1),
        "a failed soak must not advance last known good: {after_soak}",
    );

    // --- 3. auto_revert is armed, so the node goes back and serves again.
    wait_until("the node to revert to the last known good", || {
        node.serves("api.local").as_deref() == Some("good-upstream")
    });
    wait_until("revision 2 to be recorded as reverted", || {
        node.history()["entries"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row["revision"] == 2))
            .is_some_and(|row| row["state"] == "reverted")
    });

    // --- 4. Kill, corrupt the file, restart on the ring.
    node.kill();
    // Break the origin, not the `proxy:` block. The ring's directory is
    // named by the very document that is broken, so a lenient partial
    // parse has to be able to recover `proxy.config_history` out of it;
    // a document whose `proxy:` block is unparseable falls back to the
    // packaged default directory, which on a real node is
    // /var/lib/sbproxy and is not the ring this node has been writing.
    //
    // The break is a **construct-only** failure on purpose. An unknown
    // action type compiles cleanly and fails when the module is built,
    // which is where most operator typos land. That class used to walk
    // straight past the fallback: the pre-check stopped at
    // `compile_config`, the primary document's early return skipped the
    // ring walk entirely, and the process exited
    // `Fatal: unknown action type: load_balancerr` with no pin, no boot
    // counter and no walk, on every restart. Step 4 is the end-to-end
    // proof that it does not any more.
    std::fs::write(
        &config_path,
        good.replace("type: load_balancer\n", "type: load_balancerr\n"),
    )
    .expect("corrupt the config");
    // Prove the corruption is the class this step means to cover, and
    // that it really is refused. A "corruption" the parser shrugs at
    // would leave the rest of this arc testing an ordinary restart, and
    // a *compile* failure would not exercise the construct check at
    // all. `validate` prints the two apart, so assert on which one.
    let refused = Command::new(proxy_binary_path())
        .arg("validate")
        .arg("-f")
        .arg(&config_path)
        .output()
        .expect("run validate");
    let validate_says = format!(
        "{}{}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr),
    );
    assert!(
        validate_says.contains("a module failed to construct"),
        "step 4 covers the construct-only class, not a parse error: {validate_says}",
    );
    assert!(
        validate_says.contains("unknown action type: load_balancerr"),
        "and the failure is the one this step planted: {validate_says}",
    );
    let rescued = Node::start(
        &config_path,
        http_port,
        admin_port,
        &["--config-fallback", "last-known-good"],
        dir.path(),
    );
    wait_until("the rescued node to serve traffic", || {
        rescued.serves("api.local").as_deref() == Some("good-upstream")
    });
    assert_eq!(
        rescued.gauge("sbproxy_config_fallback_active"),
        Some(1.0),
        "a node serving a rescued config says so loudly:\n{}",
        rescued.log(),
    );
    let pin = rescued.admin("GET", "/admin/config/fallback", None).json();
    assert_eq!(pin["active"], true, "{pin}");
    assert!(
        pin["reason"]
            .as_str()
            .is_some_and(|why| why.contains("unknown action type: load_balancerr")),
        "the pin names why the configured document failed, in the words the proxy used: {pin}",
    );

    // --- 5. The watcher is suspended, so touching the directory moves
    // nothing. The property most likely to regress, and the difference
    // between a working rescue and a crash loop.
    let second_upstream = StubUpstream::start("would-have-been-applied");
    let tempting = node_yaml(
        http_port,
        admin_port,
        &history,
        second_upstream.port,
        true,
        true,
    );
    let entries_before = rescued.history()["entries"]
        .as_array()
        .map(Vec::len)
        .expect("entries");
    rescued.rewrite_config(&tempting);
    // A fixed wait, deliberately: this is a negative, and the only way
    // to give the watcher a chance to misbehave is to let its debounce
    // and its poll interval both elapse.
    std::thread::sleep(QUIET_WINDOW);
    assert_eq!(
        rescued.serves("api.local").as_deref(),
        Some("good-upstream"),
        "a suspended watcher must not apply the file it is pinned away from:\n{}",
        rescued.log(),
    );
    assert_eq!(
        rescued.history()["entries"].as_array().map(Vec::len),
        Some(entries_before),
        "and it must not append a revision either",
    );
    assert_eq!(
        rescued.admin("GET", "/admin/config/fallback", None).json()["active"],
        true,
        "the pin is still in place",
    );

    // --- 6. Clear the pin. The file that was sitting there applies.
    let cleared = rescued.admin("DELETE", "/admin/config/fallback", None);
    assert_eq!(cleared.status, 200, "clear the pin: {}", cleared.body);
    assert_eq!(cleared.json()["cleared"], true);
    wait_until("the fixed config to apply once the pin is cleared", || {
        rescued.serves("api.local").as_deref() == Some("would-have-been-applied")
    });
    assert_eq!(
        rescued.gauge("sbproxy_config_fallback_active"),
        Some(0.0),
        "the gauge goes back to zero with the pin",
    );
    let promoted_revision = rescued.history()["entries"]
        .as_array()
        .and_then(|rows| rows.last())
        .and_then(|row| row["revision"].as_u64())
        .expect("a newest revision");
    wait_until("the fixed config to promote", || {
        rescued.history()["lkg_revision"] == serde_json::json!(promoted_revision)
    });

    // --- 7. Roll back to a named earlier revision through the admin API.
    let rollback = rescued.admin("POST", "/admin/config/rollback", Some(r#"{"revision":1}"#));
    assert_eq!(rollback.status, 200, "rollback: {}", rollback.body);
    let rolled = rollback.json();
    assert_eq!(rolled["rolled_back"], true, "{rolled}");
    assert_eq!(rolled["restored_revision"], 1);
    assert!(
        rolled["appended_revision"].as_u64().is_some(),
        "history is append-only, so a rollback is itself in the history: {rolled}",
    );
    wait_until("the rolled-back document to serve", || {
        rescued.serves("api.local").as_deref() == Some("good-upstream")
    });
    let appended = rolled["appended_revision"].as_u64().expect("appended");
    assert!(
        rescued.history()["entries"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|row| row["revision"] == appended)),
        "the appended revision is in the ring",
    );
}

/// The discriminator for step 2. Without it, the assertion that a
/// broken config fails its soak proves nothing: a node that failed
/// every soak would pass it too.
///
/// Same broken config, same node, `require_upstream_health: false`.
/// The signal that caught it is switched off, nothing else changes,
/// and the revision promotes.
#[test]
fn the_same_broken_config_promotes_once_the_upstream_signal_is_switched_off() {
    let _guard = suite_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let upstream = StubUpstream::start("good-upstream");
    let dir = tempfile::tempdir().expect("temp dir");
    let history = dir.path().join("config-history");
    let config_path = dir.path().join("sb.yml");
    let http_port = pick_port();
    let admin_port = pick_port();

    std::fs::write(
        &config_path,
        node_yaml(http_port, admin_port, &history, upstream.port, false, false),
    )
    .expect("write config");
    let node = Node::start(&config_path, http_port, admin_port, &[], dir.path());
    wait_until("the first revision to promote", || {
        node.history()["lkg_revision"] == serde_json::json!(1)
    });

    let dead = closed_port();
    node.rewrite_config(&node_yaml(
        http_port, admin_port, &history, dead, false, false,
    ));
    let reloaded = node.reload();
    assert_eq!(reloaded.status, 200, "{}", reloaded.body);

    wait_until("the broken revision to promote anyway", || {
        node.history()["lkg_revision"] == serde_json::json!(2)
    });
    let entries = node.history();
    let second = entries["entries"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["revision"] == 2))
        .expect("revision 2");
    assert_eq!(
        second["state"], "good",
        "with the upstream signal off the same document promotes: {entries}",
    );
    assert_eq!(
        node.counter(concat!(
            "sbproxy_config_soak_verdict_total{signal=\"upstream_health\",",
            "verdict=\"failed\"}",
        )),
        0.0,
        "and the signal that caught it in the sibling test never reported: {entries}",
    );
}

// ---------------------------------------------------------------------------
// The fleet arc: a real authority, two subscribers, one of which refuses
// ---------------------------------------------------------------------------

/// Publish, watch one subscriber refuse, read the refusal off the status
/// page, roll back to a named revision, and watch both converge.
///
/// The node-side arc above proves one process. This proves the fleet
/// half of the same feature: that a refusal is visible to the operator
/// who has to decide, and that `rollback --to-revision N` is what
/// resolves it.
///
/// One subscriber refuses because the published payload names a `${VAR}`
/// that resolves on one node and not on the other. That is the shipped
/// refusal path (a subscriber that cannot resolve a reference refuses
/// the bundle rather than applying the literal text), reached by giving
/// two child processes different environments rather than by adding a
/// misbehave switch to production code.
#[test]
fn a_fleet_refusal_is_reported_and_a_named_rollback_converges_every_subscriber() {
    let _guard = suite_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = tempfile::tempdir().expect("temp dir");
    let upstream = StubUpstream::start("fleet-upstream");

    // --- The authority.
    let (signing_key, verifying_keys) = init_authority_keys(dir.path());
    let store_dir = dir.path().join("authority-store");
    std::fs::create_dir_all(&store_dir).expect("create store dir");
    let authority_admin = pick_port();
    let bundle_port = pick_port();
    let authority_config = dir.path().join("authority.yml");
    std::fs::write(
        &authority_config,
        authority_yaml(authority_admin, bundle_port, &signing_key, &store_dir),
    )
    .expect("write authority config");
    let _authority = Node::start(
        &authority_config,
        pick_port(),
        authority_admin,
        &[],
        dir.path(),
    );
    ProxyHarness::wait_for_port(bundle_port, CONVERGE).expect("bundle listener never bound");

    // --- Two subscribers. Only one can resolve ${FLEET_BODY}.
    let mut nodes = Vec::new();
    for (index, env) in [
        vec![("FLEET_BODY", "resolved-on-both")],
        // The second node is not given the variable at all.
        vec![],
    ]
    .into_iter()
    .enumerate()
    {
        let subscriber_id = format!("edge-{index}");
        let token = register_fleet_subscriber(authority_admin, dir.path(), &subscriber_id);
        let http_port = pick_port();
        let admin_port = pick_port();
        let config = dir.path().join(format!("subscriber-{index}.yml"));
        std::fs::write(
            &config,
            subscriber_yaml(
                http_port,
                admin_port,
                bundle_port,
                &token,
                &verifying_keys,
                &dir.path().join(format!("cache-{index}.json")),
                &subscriber_id,
            ),
        )
        .expect("write subscriber config");
        nodes.push(Node::start_with_env(
            &config,
            http_port,
            admin_port,
            &[],
            dir.path(),
            &env,
        ));
    }

    // --- A first publication both nodes can apply, so the refusal below
    // is a change and not the starting state.
    publish(
        authority_admin,
        &fleet_payload(upstream.port, "everyone-applies"),
    );
    for node in &nodes {
        wait_until("both subscribers to take the first revision", || {
            node.serves("fleet.local").as_deref() == Some("everyone-applies")
        });
    }
    let good_revision = authority_status(authority_admin)["current_revision"]
        .as_u64()
        .expect("a current revision");

    // --- A payload only one node can resolve.
    publish(
        authority_admin,
        &fleet_payload(upstream.port, "${FLEET_BODY}"),
    );

    // The node that has the variable applies it.
    wait_until("the node that can resolve it to apply", || {
        nodes[0].serves("fleet.local").as_deref() == Some("resolved-on-both")
    });

    // The other refuses, and the authority's status page says so with a
    // reason. That is the half an operator reads before deciding.
    wait_until(
        "the authority to report the refusal with its reason",
        || {
            let status = authority_status(authority_admin);
            status["subscribers"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|row| {
                    row["subscriber_id"] == "edge-1"
                        && row["apply_status"] == "failed"
                        && row["apply_error"].as_str().is_some_and(|e| !e.is_empty())
                })
        },
    );
    let status = authority_status(authority_admin);
    assert_eq!(
        status["apply_failed_count"], 1,
        "exactly one subscriber refused: {status}",
    );
    let refusal = status["subscribers"]
        .as_array()
        .expect("subscribers")
        .iter()
        .find(|row| row["subscriber_id"] == "edge-1")
        .expect("edge-1 on the status page")
        .clone();
    let reason = refusal["apply_error"].as_str().expect("a reason");
    assert!(
        reason.contains("FLEET_BODY") || reason.to_lowercase().contains("resolve"),
        "the refusal names what could not be resolved: {reason}",
    );
    assert_eq!(
        nodes[1].serves("fleet.local").as_deref(),
        Some("everyone-applies"),
        "and the refusing node keeps serving the revision it did apply",
    );

    // --- Roll back to the named revision. Both converge.
    let rollback = Command::new(proxy_binary_path())
        .args([
            "config",
            "authority",
            "rollback",
            "--to-revision",
            &good_revision.to_string(),
            "--admin-url",
            &format!("http://127.0.0.1:{authority_admin}"),
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

    for (index, node) in nodes.iter().enumerate() {
        wait_until(&format!("subscriber edge-{index} to converge"), || {
            node.serves("fleet.local").as_deref() == Some("everyone-applies")
        });
    }
    wait_until("the authority to report both subscribers applied", || {
        let status = authority_status(authority_admin);
        status["apply_failed_count"] == serde_json::json!(0)
            && status["applied_current_count"] == serde_json::json!(2)
    });
}

fn authority_yaml(
    admin_port: u16,
    bundle_port: u16,
    signing_key: &Path,
    store_dir: &Path,
) -> String {
    format!(
        r#"proxy:
  http_bind_port: 0
  admin:
    enabled: true
    bind: 127.0.0.1
    port: {admin_port}
    username: {ADMIN_USER}
    password: {ADMIN_PASSWORD}
    rate_limit_per_minute: 100000
  config_authority:
    publish:
      authority_id: fleet-authority
      key_id: fleet-key-1
      signing_key_file: {signing}
      store_dir: {store}
      bind: 127.0.0.1:{bundle_port}
      archive_keep: 10
origins:
  "authority.local":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: authority
"#,
        signing = signing_key.display(),
        store = store_dir.display(),
    )
}

#[allow(clippy::too_many_arguments)]
fn subscriber_yaml(
    http_port: u16,
    admin_port: u16,
    bundle_port: u16,
    token_file: &Path,
    verifying_keys: &Path,
    cache_path: &Path,
    subscriber_id: &str,
) -> String {
    format!(
        r#"proxy:
  http_bind_port: {http_port}
  admin:
    enabled: true
    bind: 127.0.0.1
    port: {admin_port}
    username: {ADMIN_USER}
    password: {ADMIN_PASSWORD}
    rate_limit_per_minute: 100000
  extensions:
    upstream:
      allow_private_cidrs:
        - '127.0.0.1/32'
  config_authority:
    upstream:
      url: http://127.0.0.1:{bundle_port}
      mode: overlay
      subscriber_id: {subscriber_id}
      credential: file:{token}
      verifying_keys_file: {keys}
      poll_interval: 5s
      cache_path: {cache}
      allow_insecure_http: true
"#,
        token = token_file.display(),
        keys = verifying_keys.display(),
        cache = cache_path.display(),
    )
}

/// A payload whose body is `body`, which may be a `${VAR}` reference.
fn fleet_payload(upstream_port: u16, body: &str) -> String {
    let _ = upstream_port;
    format!(
        r#"origins:
  "fleet.local":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "{body}"
"#
    )
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
            "fleet-key-1",
            "--authority-id",
            "fleet-authority",
        ])
        .output()
        .expect("run authority init");
    assert!(
        output.status.success(),
        "authority init failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    (
        dir.join("authority-signing.key"),
        dir.join("authority-keys.json"),
    )
}

fn register_fleet_subscriber(admin_port: u16, dir: &Path, subscriber_id: &str) -> PathBuf {
    let reply = admin(
        admin_port,
        "POST",
        "/admin/config-authority/subscribers",
        Some(&format!(r#"{{"subscriber_id":"{subscriber_id}"}}"#)),
    );
    assert_eq!(
        reply.status, 200,
        "register {subscriber_id}: {}",
        reply.body
    );
    let credential = reply.json()["credential"]
        .as_str()
        .expect("a credential")
        .to_string();
    let path = dir.join(format!("{subscriber_id}.token"));
    std::fs::write(&path, credential.as_bytes()).expect("write token");
    path
}

fn publish(admin_port: u16, payload: &str) {
    let url = format!("http://127.0.0.1:{admin_port}/admin/config-authority/publish");
    let response = client()
        .post(url)
        .header("authorization", basic_auth())
        .header("content-type", "application/yaml")
        .body(payload.to_string())
        .send()
        .expect("publish");
    let status = response.status().as_u16();
    let body = response.text().unwrap_or_default();
    assert_eq!(status, 200, "publish: {body}");
}

fn authority_status(admin_port: u16) -> serde_json::Value {
    let reply = admin(admin_port, "GET", "/admin/config-authority/status", None);
    assert_eq!(reply.status, 200, "status: {}", reply.body);
    reply.json()
}

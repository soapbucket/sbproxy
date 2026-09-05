// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! `sbproxy config authority *` and `sbproxy config pull --dry-run`.
//!
//! Two properties get most of the attention here, because both have been got
//! wrong before in this binary.
//!
//! The first is that a command which changes fleet state talks to the admin
//! API and reports what the server said. `apply` used to call the in-process
//! reload primitive inside the short-lived CLI, swap that process's own
//! pipeline, print success, and exit without contacting the proxy, which made
//! its exit code meaningless. So the tests below assert on exit codes against
//! a fixture that answers, a fixture that refuses, and a port where nothing
//! listens.
//!
//! The second is that `config pull --dry-run` applies nothing. It is checked
//! by the absence of the two files a real cycle would write (the bundle cache
//! and the replay cursor) rather than by reading the output, because output
//! is what a broken implementation would still get right.
//!
//! The fixtures are hand-rolled `TcpListener`s for the same reason the
//! config-authority tests in `sbproxy-core` are: a mock-HTTP dependency here
//! would mean a new entry in every nested `Cargo.lock` in the repo, and the
//! contract under test is one request and one response.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use sbproxy_config::config_bundle::{BundleMode, ConfigBundle, ConfigBundleSigner};

/// Admin password every fixture expects. Asserted absent from every byte of
/// output, in every test that supplies it.
const PASSWORD: &str = "fixture-admin-password";

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_sbproxy")
}

fn unique() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos()
}

fn temp_dir(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "sbproxy-authority-cli-{label}-{}-{}",
        std::process::id(),
        unique()
    ));
    std::fs::create_dir_all(&path).expect("create test directory");
    path
}

fn run(args: &[&str]) -> Output {
    Command::new(binary())
        .args(args)
        .env("SB_ADMIN_PASSWORD", PASSWORD)
        // Cleared so a developer's own environment cannot point a test at a
        // real proxy or a real config.
        .env_remove("SB_ADMIN_URL")
        .env_remove("SB_CONFIG_FILE")
        .output()
        .expect("run sbproxy")
}

fn code(output: &Output) -> i32 {
    output.status.code().expect("the process exited normally")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Assert the admin password reached neither stream.
///
/// The hand-written `Debug` impls exist so a panic or a `{args:?}` cannot
/// print it; this is the end-to-end form of the same check.
fn assert_no_password(output: &Output) {
    assert!(
        !stdout(output).contains(PASSWORD),
        "the admin password reached stdout: {}",
        stdout(output)
    );
    assert!(
        !stderr(output).contains(PASSWORD),
        "the admin password reached stderr: {}",
        stderr(output)
    );
}

/// A port nothing is listening on: bound, noted, released.
fn closed_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").expect("probe bind");
    let port = probe.local_addr().expect("probe address").port();
    drop(probe);
    port
}

/// One request a fixture received.
struct Captured {
    /// Request line and headers, verbatim.
    head: String,
    /// Request body, verbatim.
    body: Vec<u8>,
}

/// Read one complete HTTP request from `stream`, honoring `Content-Length`.
fn read_request(stream: &mut std::net::TcpStream) -> Captured {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .expect("read timeout");
    let mut raw = Vec::new();
    let mut buffer = [0u8; 4096];
    let mut expected_len = None;
    loop {
        let read = stream.read(&mut buffer).expect("read request");
        assert!(read > 0, "client closed before the request completed");
        raw.extend_from_slice(&buffer[..read]);
        let Some(header_end) = raw.windows(4).position(|bytes| bytes == b"\r\n\r\n") else {
            continue;
        };
        if expected_len.is_none() {
            let headers = String::from_utf8_lossy(&raw[..header_end]);
            let content_length = headers.lines().find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
            });
            expected_len = Some(header_end + 4 + content_length.unwrap_or(0));
        }
        if expected_len.is_some_and(|length| raw.len() >= length) {
            let header_end = raw
                .windows(4)
                .position(|bytes| bytes == b"\r\n\r\n")
                .expect("headers");
            return Captured {
                head: String::from_utf8_lossy(&raw[..header_end]).into_owned(),
                body: raw[header_end + 4..].to_vec(),
            };
        }
    }
}

/// How long a fixture waits for the CLI to connect before giving up.
///
/// Bounded rather than a blocking `accept`: a command that refuses locally
/// never connects, and a fixture that waits forever for it would hang the
/// whole test binary instead of failing one test with a legible message.
const FIXTURE_ACCEPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Accept one connection, or panic once [`FIXTURE_ACCEPT_TIMEOUT`] passes.
fn accept_within_timeout(listener: &TcpListener) -> std::net::TcpStream {
    listener
        .set_nonblocking(true)
        .expect("fixture non-blocking accept");
    let deadline = std::time::Instant::now() + FIXTURE_ACCEPT_TIMEOUT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .expect("fixture blocking reads");
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "no request reached the fixture within {FIXTURE_ACCEPT_TIMEOUT:?}; the \
                     command under test never contacted it"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => panic!("fixture accept failed: {error}"),
        }
    }
}

/// Serve exactly one request, answering with `status` and `body`, and return
/// what arrived.
fn one_shot_fixture(
    status: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
    extra_headers: Vec<String>,
) -> (String, std::thread::JoinHandle<Captured>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("fixture bind");
    let address = listener.local_addr().expect("fixture address");
    let handle = std::thread::spawn(move || {
        let mut stream = accept_within_timeout(&listener);
        let captured = read_request(&mut stream);
        let mut head = format!(
            "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\n",
            body.len()
        );
        for header in &extra_headers {
            head.push_str(header);
            head.push_str("\r\n");
        }
        head.push_str("connection: close\r\n\r\n");
        stream.write_all(head.as_bytes()).expect("response head");
        stream.write_all(&body).expect("response body");
        captured
    });
    (format!("http://{address}"), handle)
}

/// A one-shot admin fixture answering with a JSON document.
fn admin_fixture(
    status: &'static str,
    body: &serde_json::Value,
) -> (String, std::thread::JoinHandle<Captured>) {
    one_shot_fixture(
        status,
        "application/json",
        body.to_string().into_bytes(),
        Vec::new(),
    )
}

/// The basic-auth header value for `admin:PASSWORD`, as the CLI sends it.
fn assert_basic_auth(captured: &Captured) {
    let header = captured
        .head
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("authorization:"))
        .expect("the CLI must authenticate to the admin API");
    assert!(
        header.contains("Basic "),
        "admin auth must be Basic: {header}"
    );
}

/// The permission bits on a generated file.
#[cfg(unix)]
fn file_mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::metadata(path)
        .expect("stat the generated file")
        .permissions()
        .mode()
        & 0o777
}

/// Windows has no mode bits, so the assertion is vacuous there rather than
/// wrong.
#[cfg(not(unix))]
fn file_mode(_path: &Path) -> u32 {
    0o600
}

// --- init -------------------------------------------------------------

#[test]
fn authority_init_writes_owner_only_key_material_and_refuses_to_clobber_it() {
    let root = temp_dir("init");
    let directory = root.join("authority");
    let directory_arg = directory.to_string_lossy().into_owned();

    let first = run(&[
        "config",
        "authority",
        "init",
        "--dir",
        &directory_arg,
        "--authority-id",
        "control-plane-test",
        "--format",
        "json",
    ]);
    assert_eq!(code(&first), 0, "{}", stderr(&first));
    let generated: serde_json::Value =
        serde_json::from_slice(&first.stdout).expect("init emits one JSON object");
    let key_id = generated["key_id"].as_str().expect("a key id").to_string();
    assert!(
        key_id.starts_with("authority-"),
        "the default key id names the key: {key_id}"
    );
    assert_eq!(generated["algorithm"], "ed25519");
    assert_eq!(generated["authority_id"], "control-plane-test");
    assert_eq!(generated["rotated"], false);

    let key_path = directory.join("authority-signing.key");
    let keys_path = directory.join("authority-keys.json");
    assert!(key_path.is_file(), "the signing key must exist");
    assert!(keys_path.is_file(), "the verifying-key file must exist");
    assert_eq!(
        file_mode(&key_path),
        0o600,
        "a signing key that mints configuration for a fleet must be owner-only, and the loader \
         refuses one that is not"
    );

    // The seed itself appears in no output, in either stream. It is the one
    // secret this command produces.
    let seed_body = std::fs::read_to_string(&key_path).expect("read the signing key");
    let seed_body = seed_body.trim().to_string();
    assert!(!seed_body.is_empty());
    assert!(
        !stdout(&first).contains(&seed_body) && !stderr(&first).contains(&seed_body),
        "init must never print the signing seed"
    );

    // The verifying-key file is the shape a subscriber parses, keyed on the
    // key id the authority will stamp into every bundle.
    let keys: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&keys_path).expect("read the key map"))
            .expect("the verifying-key file is JSON");
    assert_eq!(keys[&key_id]["algorithm"], "ed25519");
    assert_eq!(keys[&key_id]["key"], generated["verifying_material"]);

    // A second run refuses rather than silently invalidating every bundle
    // the first key signed.
    let clobber = run(&[
        "config",
        "authority",
        "init",
        "--dir",
        &directory_arg,
        "--format",
        "json",
    ]);
    assert_eq!(code(&clobber), 3, "{}", stderr(&clobber));
    assert!(
        stderr(&clobber).contains("--force"),
        "the refusal must name the way past it: {}",
        stderr(&clobber)
    );
    assert_eq!(
        std::fs::read_to_string(&key_path).expect("read the signing key"),
        format!("{seed_body}\n"),
        "a refused init must leave the existing key exactly as it was"
    );

    // `--force` rotates: a new key, a new id, and the old verifying key kept
    // so subscribers that have not been updated yet keep verifying.
    let rotated = run(&[
        "config",
        "authority",
        "init",
        "--dir",
        &directory_arg,
        "--force",
        "--format",
        "json",
    ]);
    assert_eq!(code(&rotated), 0, "{}", stderr(&rotated));
    let rotated_json: serde_json::Value =
        serde_json::from_slice(&rotated.stdout).expect("init emits one JSON object");
    let rotated_key_id = rotated_json["key_id"].as_str().expect("a key id");
    assert_ne!(
        rotated_key_id, key_id,
        "a derived key id must change with the key, or an additive rotation would collide"
    );
    assert_eq!(rotated_json["rotated"], true);
    assert_ne!(
        std::fs::read_to_string(&key_path)
            .expect("read the signing key")
            .trim(),
        seed_body,
        "--force must actually replace the key"
    );
    let keys: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&keys_path).expect("read the key map"))
            .expect("the verifying-key file is JSON");
    assert!(
        keys.get(&key_id).is_some() && keys.get(rotated_key_id).is_some(),
        "rotation is additive: both keys must verify until the old entry is dropped, or the old \
         key's trust is withdrawn at the instant the new key starts signing: {keys}"
    );
}

#[test]
fn authority_init_text_output_names_what_to_copy_where() {
    let root = temp_dir("init-text");
    let directory = root.join("authority");
    let output = run(&[
        "config",
        "authority",
        "init",
        "--dir",
        &directory.to_string_lossy(),
    ]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let printed = stdout(&output);
    for expected in [
        "signing_key_file",
        "verifying_keys_file",
        "authority-keys.json",
        "Never copy",
        "subscriber add",
    ] {
        assert!(
            printed.contains(expected),
            "init's next steps must mention {expected}: {printed}"
        );
    }
}

// --- publish ----------------------------------------------------------

/// A payload the authority would accept: it compiles, it constructs, and it
/// names no path a subscriber owns.
const VALID_PAYLOAD: &str = r#"origins:
  "fleet.test":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: from-the-authority
"#;

/// The same shape, as the document a bundle carries.
const BUNDLE_PAYLOAD: &str = r#"origins:
  "authority.test":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: from-the-authority
"#;

/// A payload `compile_config` accepts and the module constructors do not:
/// the typo is inside an opaque `policies:` entry.
const TYPO_PAYLOAD: &str = r#"origins:
  "fleet.test":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: broken
    policies:
      - type: no_such_policy_type
"#;

fn valid_payload(root: &Path) -> PathBuf {
    let path = root.join("payload.yml");
    std::fs::write(&path, VALID_PAYLOAD).expect("write payload");
    path
}

#[test]
fn authority_publish_refuses_a_bad_payload_before_a_revision_can_be_spent() {
    let root = temp_dir("publish-invalid");
    // Nothing listens here. A command that reached the network would exit 7,
    // so exit 3 is the evidence that the refusal happened locally, which is
    // the whole point: a rejected payload must not cost a revision number.
    let unreachable = format!("http://127.0.0.1:{}", closed_port());

    // A path every subscriber owns outright. Refused whole, not partially.
    let denied = root.join("denied.yml");
    std::fs::write(&denied, "proxy:\n  admin:\n    enabled: true\n").expect("write payload");
    let output = run(&[
        "config",
        "authority",
        "publish",
        "-f",
        &denied.to_string_lossy(),
        "--admin-url",
        &unreachable,
    ]);
    assert_eq!(
        code(&output),
        3,
        "a denied path must be refused locally: {}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("no revision was consumed"),
        "the refusal must say the counter did not move: {}",
        stderr(&output)
    );

    // The case publish-side validation exists for: a typo inside an opaque
    // `policies:` entry, which `compile_config` alone accepts and every
    // subscriber would then refuse at boot.
    let typo = root.join("typo.yml");
    std::fs::write(&typo, TYPO_PAYLOAD).expect("write payload");
    let output = run(&[
        "config",
        "authority",
        "publish",
        "-f",
        &typo.to_string_lossy(),
        "--admin-url",
        &unreachable,
    ]);
    assert_eq!(
        code(&output),
        3,
        "a policy that cannot construct must be refused locally: {}",
        stderr(&output)
    );

    // And the same payload under --validate-only, which is the CI form: it
    // never contacts anything, so the closed port is irrelevant to it.
    let output = run(&[
        "config",
        "authority",
        "publish",
        "-f",
        &valid_payload(&root).to_string_lossy(),
        "--validate-only",
    ]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        stdout(&output).contains("Nothing was published"),
        "--validate-only must say it published nothing: {}",
        stdout(&output)
    );
}

#[test]
fn authority_publish_sends_the_payload_verbatim_and_reports_what_the_server_assigned() {
    let root = temp_dir("publish-ok");
    let payload = valid_payload(&root);
    let payload_bytes = std::fs::read(&payload).expect("read payload");
    let (url, fixture) = admin_fixture(
        "200 OK",
        &serde_json::json!({
            "schema_version": 1,
            "authority_id": "control-plane-test",
            "key_id": "authority-abc123",
            "revision": 8,
            "content_digest": "sha256:fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9",
            "etag": "\"8-sha256:fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9\"",
            "mode": "replace",
            "issued_at_unix_ms": 1_753_401_600_000_u64,
        }),
    );
    let output = run(&[
        "config",
        "authority",
        "publish",
        "-f",
        &payload.to_string_lossy(),
        "--mode",
        "replace",
        "--admin-url",
        &url,
    ]);
    let captured = fixture.join().expect("fixture");
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        captured
            .head
            .starts_with("POST /admin/config-authority/publish?mode=replace "),
        "publish must post to the admin route with the mode in the query: {}",
        captured.head
    );
    assert_basic_auth(&captured);
    assert!(
        captured
            .head
            .to_ascii_lowercase()
            .contains("content-type: application/yaml"),
        "{}",
        captured.head
    );
    assert_eq!(
        captured.body, payload_bytes,
        "the bytes that get signed must be the bytes the operator wrote"
    );
    let printed = stdout(&output);
    assert!(
        printed.contains("revision 8") && printed.contains("authority-abc123"),
        "publish must report what the server assigned: {printed}"
    );
    assert_no_password(&output);
}

#[test]
fn authority_publish_separates_a_refusal_from_an_unreachable_authority() {
    let root = temp_dir("publish-codes");
    let payload = valid_payload(&root);

    let (url, fixture) = admin_fixture(
        "500 Internal Server Error",
        &serde_json::json!({
            "error": "config authority publish failed at the store: no space left on device",
            "code": "store_failed",
            "revision_consumed": false,
        }),
    );
    let refused = run(&[
        "config",
        "authority",
        "publish",
        "-f",
        &payload.to_string_lossy(),
        "--admin-url",
        &url,
    ]);
    fixture.join().expect("fixture");
    assert_eq!(
        code(&refused),
        4,
        "an authority that answered and refused is exit 4: {}",
        stderr(&refused)
    );
    assert!(
        stderr(&refused).contains("store_failed"),
        "the refusal must carry the server's own code: {}",
        stderr(&refused)
    );

    let unreachable = run(&[
        "config",
        "authority",
        "publish",
        "-f",
        &payload.to_string_lossy(),
        "--admin-url",
        &format!("http://127.0.0.1:{}", closed_port()),
    ]);
    assert_eq!(
        code(&unreachable),
        7,
        "an authority that never answered is exit 7, never a local success: {}",
        stderr(&unreachable)
    );
    assert!(
        stderr(&unreachable).contains("nothing was changed"),
        "{}",
        stderr(&unreachable)
    );
    assert_no_password(&unreachable);
}

// --- status, rollback, subscribers ------------------------------------

fn status_document() -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "authority_id": "control-plane-test",
        "key_id": "authority-abc123",
        "algorithm": "ed25519",
        "verifying_material": "3p8Q0mB1yV4kX7wR2tL6nS9cF5jH0dA8gZ2eK4uY1oM=",
        "current_revision": 8,
        "current_content_digest": "sha256:fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9",
        "previous_revision": 7,
        "high_water_revision": 9,
        "subscriber_count": 2,
        "live_subscriber_count": 2,
        "subscribers": [
            {
                "subscriber_id": "edge-01",
                "credential_id": "0lJ8kQ2vTn5mAqRt",
                "revoked": false,
                "last_seen_revision": 8,
                "up_to_date": true,
            },
            {
                "subscriber_id": "edge-02",
                "credential_id": "9pQx7Yb2ZmKd3Lw8",
                "revoked": false,
                "last_seen_revision": 7,
                "up_to_date": false,
            },
        ],
    })
}

#[test]
fn authority_status_shows_the_rollout_and_prints_no_secret() {
    let (url, fixture) = admin_fixture("200 OK", &status_document());
    let output = run(&[
        "config",
        "authority",
        "status",
        "--admin-url",
        &url,
        "--username",
        "admin",
    ]);
    let captured = fixture.join().expect("fixture");
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        captured
            .head
            .starts_with("GET /admin/config-authority/status "),
        "{}",
        captured.head
    );
    assert_basic_auth(&captured);
    let printed = stdout(&output);
    for expected in [
        "authority-abc123",
        "revision: 8",
        "highest reserved 9",
        "edge-01",
        "current",
        "edge-02",
        "behind",
    ] {
        assert!(
            printed.contains(expected),
            "status must show {expected}: {printed}"
        );
    }
    assert_no_password(&output);
}

#[test]
fn authority_rollback_reports_the_revision_it_restored_and_the_one_it_replaced() {
    let (url, fixture) = admin_fixture(
        "200 OK",
        &serde_json::json!({
            "schema_version": 1,
            "authority_id": "control-plane-test",
            "key_id": "authority-abc123",
            "revision": 9,
            "restored_from_revision": 7,
            "replaced_revision": 8,
            "content_digest": "sha256:2c26b46b68ffc68ff99b453c1d3041341340d0d0d0d0d0d0d0d0d0d0d0d0d0d0",
            "mode": "overlay",
        }),
    );
    let output = run(&["config", "authority", "rollback", "--admin-url", &url]);
    let captured = fixture.join().expect("fixture");
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        captured
            .head
            .starts_with("POST /admin/config-authority/rollback "),
        "{}",
        captured.head
    );
    let printed = stdout(&output);
    assert!(
        printed.contains("revision 7's payload as revision 9") && printed.contains("replacing"),
        "rollback must name both ends of what it did: {printed}"
    );

    let (url, fixture) = admin_fixture(
        "400 Bad Request",
        &serde_json::json!({
            "error": "config authority rollback rejected: no previous revision is stored",
            "code": "no_previous_revision",
            "revision_consumed": false,
        }),
    );
    let refused = run(&["config", "authority", "rollback", "--admin-url", &url]);
    fixture.join().expect("fixture");
    assert_eq!(code(&refused), 4, "{}", stderr(&refused));
    assert!(
        stderr(&refused).contains("no_previous_revision"),
        "{}",
        stderr(&refused)
    );
}

#[test]
fn authority_rollback_to_revision_sends_the_named_target_and_relays_the_refusal() {
    // WOR-2463: the flag has to reach the wire. A `--to-revision` that got
    // dropped on the way would run the one-step rollback and report
    // success, rolling the fleet to a document the operator did not name.
    let (url, fixture) = admin_fixture(
        "200 OK",
        &serde_json::json!({
            "schema_version": 1,
            "authority_id": "control-plane-test",
            "key_id": "authority-abc123",
            "revision": 12,
            "restored_from_revision": 4,
            "replaced_revision": 11,
            "content_digest": "sha256:2c26b46b68ffc68ff99b453c1d3041341340d0d0d0d0d0d0d0d0d0d0d0d0d0d0",
            "mode": "overlay",
        }),
    );
    let output = run(&[
        "config",
        "authority",
        "rollback",
        "--to-revision",
        "4",
        "--admin-url",
        &url,
    ]);
    let captured = fixture.join().expect("fixture");
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        captured
            .head
            .starts_with("POST /admin/config-authority/rollback "),
        "{}",
        captured.head
    );
    let sent = String::from_utf8_lossy(&captured.body).to_string();
    assert!(
        sent.contains("\"to_revision\"") && sent.contains('4'),
        "the named revision must reach the authority: {sent:?}",
    );
    assert!(
        stdout(&output).contains("revision 4's payload as revision 12"),
        "{}",
        stdout(&output)
    );

    // A refusal names the revisions that are available, so the next
    // attempt is informed rather than another guess.
    let (url, fixture) = admin_fixture(
        "400 Bad Request",
        &serde_json::json!({
            "error": "config authority rollback rejected: revision 4 is not in the archive; \
                      available revisions are 9, 10, 11",
            "code": "revision_not_archived",
            "revision_consumed": false,
            "archived_revisions": [9, 10, 11],
        }),
    );
    let refused = run(&[
        "config",
        "authority",
        "rollback",
        "--to-revision",
        "4",
        "--admin-url",
        &url,
    ]);
    fixture.join().expect("fixture");
    assert_eq!(code(&refused), 4, "{}", stderr(&refused));
    assert!(
        stderr(&refused).contains("revision_not_archived")
            && stderr(&refused).contains("available revisions are 9, 10, 11"),
        "{}",
        stderr(&refused)
    );
}

#[test]
fn subscriber_add_prints_the_credential_once_on_stdout_and_says_so_on_stderr() {
    let credential = "sbca1.0lJ8kQ2vTn5mAqRt.9pQx7Yb2ZmKd3Lw8Rn6Tf1Vc4Hs0Jg5Ee2Aa8Bb1Cc";
    let (url, fixture) = admin_fixture(
        "200 OK",
        &serde_json::json!({
            "schema_version": 1,
            "subscriber_id": "edge-01",
            "credential_id": "0lJ8kQ2vTn5mAqRt",
            "credential": credential,
        }),
    );
    let output = run(&[
        "config",
        "authority",
        "subscriber",
        "add",
        "edge-01",
        "--admin-url",
        &url,
    ]);
    let captured = fixture.join().expect("fixture");
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        captured
            .head
            .starts_with("POST /admin/config-authority/subscribers "),
        "{}",
        captured.head
    );
    assert!(
        String::from_utf8_lossy(&captured.body).contains("edge-01"),
        "the request must name the subscriber: {}",
        String::from_utf8_lossy(&captured.body)
    );
    // Alone on stdout, the way `cluster token create` prints a token, so
    // `export TOKEN="$(...)"` captures the credential and not the prose.
    assert_eq!(stdout(&output).trim(), credential);
    let guidance = stderr(&output);
    assert!(
        guidance.contains("shown once"),
        "the operator has to be told this is the only copy: {guidance}"
    );
    assert!(
        !guidance.contains(credential),
        "the note must not repeat the credential onto the other stream: {guidance}"
    );
    assert_no_password(&output);
}

#[test]
fn subscriber_list_and_revoke_report_what_the_authority_returned() {
    let (url, fixture) = admin_fixture(
        "200 OK",
        &serde_json::json!({
            "schema_version": 1,
            "subscriber_count": 1,
            "live_subscriber_count": 1,
            "subscribers": [{
                "subscriber_id": "edge-01",
                "credential_id": "0lJ8kQ2vTn5mAqRt",
                "revoked": false,
                "last_seen_revision": 8,
                "up_to_date": true,
            }],
        }),
    );
    let listed = run(&[
        "config",
        "authority",
        "subscriber",
        "list",
        "--admin-url",
        &url,
    ]);
    let captured = fixture.join().expect("fixture");
    assert_eq!(code(&listed), 0, "{}", stderr(&listed));
    assert!(
        captured
            .head
            .starts_with("GET /admin/config-authority/subscribers "),
        "{}",
        captured.head
    );
    assert!(
        stdout(&listed).contains("edge-01") && stdout(&listed).contains("last_seen_revision=8"),
        "{}",
        stdout(&listed)
    );

    let (url, fixture) = admin_fixture(
        "200 OK",
        &serde_json::json!({
            "schema_version": 1,
            "credential_id": "0lJ8kQ2vTn5mAqRt",
            "revoked": true,
        }),
    );
    let revoked = run(&[
        "config",
        "authority",
        "subscriber",
        "revoke",
        "--credential-id",
        "0lJ8kQ2vTn5mAqRt",
        "--admin-url",
        &url,
    ]);
    let captured = fixture.join().expect("fixture");
    assert_eq!(code(&revoked), 0, "{}", stderr(&revoked));
    assert!(
        captured
            .head
            .starts_with("POST /admin/config-authority/subscribers/revoke "),
        "{}",
        captured.head
    );
    assert!(stdout(&revoked).contains("revoked"), "{}", stdout(&revoked));

    // Naming neither selector is a usage error, not a request that revokes
    // something unspecified.
    let neither = run(&[
        "config",
        "authority",
        "subscriber",
        "revoke",
        "--admin-url",
        &format!("http://127.0.0.1:{}", closed_port()),
    ]);
    assert_eq!(code(&neither), 1, "{}", stderr(&neither));
    assert!(
        stderr(&neither).contains("--credential-id")
            && stderr(&neither).contains("--subscriber-id"),
        "{}",
        stderr(&neither)
    );
}

// --- config pull --dry-run --------------------------------------------

/// Generate an authority key pair through the CLI itself, and return the key
/// id, the signing key path, and the verifying-key file path.
fn generated_key(directory: &Path) -> (String, PathBuf, PathBuf) {
    let output = run(&[
        "config",
        "authority",
        "init",
        "--dir",
        &directory.to_string_lossy(),
        "--format",
        "json",
    ]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let generated: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("init emits JSON");
    (
        generated["key_id"].as_str().expect("key id").to_string(),
        PathBuf::from(
            generated["signing_key_file"]
                .as_str()
                .expect("signing key path"),
        ),
        PathBuf::from(
            generated["verifying_keys_file"]
                .as_str()
                .expect("verifying keys path"),
        ),
    )
}

/// Sign one bundle with the generated key, and return its JSON body and ETag.
fn signed_bundle(
    key_id: &str,
    signing_key_file: &Path,
    revision: u64,
    payload: &str,
) -> (Vec<u8>, String) {
    let signer = ConfigBundleSigner::ed25519_from_seed_file(key_id, signing_key_file)
        .expect("load the generated signing key");
    let now_unix_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("a clock inside u64");
    let bundle = ConfigBundle::new(
        "control-plane-test",
        revision,
        BundleMode::Overlay,
        payload,
        now_unix_ms,
        None,
    )
    .expect("build the bundle");
    let etag = format!("\"{revision}-{}\"", bundle.content_digest);
    let signed = signer.sign(bundle).expect("sign the bundle");
    (signed.to_json().expect("encode the bundle"), etag)
}

/// Write a subscriber config pointing at `authority_url`.
///
/// The two paths are single-quoted: a Windows temp path carries backslashes,
/// and a double-quoted YAML scalar would read those as escapes.
fn subscriber_config(root: &Path, authority_url: &str, verifying_keys_file: &Path) -> PathBuf {
    let path = root.join("sb.yml");
    let body = format!(
        r#"proxy:
  http_bind_port: 0
  config_authority:
    upstream:
      url: '{authority_url}'
      mode: overlay
      subscriber_id: edge-01
      credential: env:SB_TEST_CONFIG_CREDENTIAL
      verifying_keys_file: '{keys}'
      cache_path: '{cache}'
      allow_insecure_http: true
origins:
  "local.test":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: local
"#,
        keys = verifying_keys_file.display(),
        cache = root.join("config-bundle.json").display(),
    );
    std::fs::write(&path, body).expect("write subscriber config");
    path
}

fn run_pull(args: &[&str]) -> Output {
    Command::new(binary())
        .args(args)
        .env("SB_TEST_CONFIG_CREDENTIAL", "sbca1.fixture.credential")
        .env_remove("SB_CONFIG_FILE")
        .env_remove("SB_ADMIN_URL")
        .output()
        .expect("run sbproxy")
}

#[test]
fn config_pull_dry_run_previews_the_merge_and_writes_nothing() {
    let root = temp_dir("pull");
    let (key_id, signing_key_file, verifying_keys_file) = generated_key(&root.join("authority"));
    let (body, etag) = signed_bundle(&key_id, &signing_key_file, 4, BUNDLE_PAYLOAD);
    let (url, fixture) = one_shot_fixture(
        "200 OK",
        "application/json",
        body,
        vec![
            format!("etag: {etag}"),
            "cache-control: no-store".to_string(),
        ],
    );
    let config = subscriber_config(&root, &url, &verifying_keys_file);
    let config_arg = config.to_string_lossy().into_owned();
    let config_before = std::fs::read(&config).expect("read the config");

    let output = run_pull(&["config", "pull", &config_arg, "--dry-run"]);
    let captured = fixture.join().expect("fixture");
    assert_eq!(
        code(&output),
        2,
        "an offered bundle that changes the document is exit 2, matching `plan`: {}",
        stderr(&output)
    );
    assert!(
        captured
            .head
            .starts_with("GET /config-authority/v1/bundle "),
        "the dry run must use the real subscriber transport: {}",
        captured.head
    );
    assert!(
        captured
            .head
            .to_ascii_lowercase()
            .contains("x-sbproxy-subscriber-id: edge-01"),
        "{}",
        captured.head
    );

    let printed = stdout(&output);
    assert!(
        printed.contains("offers revision 4"),
        "the preview must name the revision it would apply: {printed}"
    );
    assert!(
        printed.contains("authority.test"),
        "the preview must show the diff: {printed}"
    );
    assert!(
        printed.contains("nothing was applied"),
        "a dry run has to say plainly that it applied nothing: {printed}"
    );

    // The properties that matter, checked by absence rather than by output.
    // A real cycle writes the cache and the cursor and reloads; this must do
    // none of the three.
    assert!(
        !root.join("config-bundle.json").exists(),
        "a dry run must not write the bundle cache"
    );
    assert!(
        !root.join("config-bundle.json.cursor").exists(),
        "a dry run must not advance the replay cursor"
    );
    assert_eq!(
        std::fs::read(&config).expect("read the config"),
        config_before,
        "a dry run must not rewrite the local document"
    );
}

#[test]
fn config_pull_dry_run_json_reports_that_it_applied_nothing() {
    let root = temp_dir("pull-json");
    let (key_id, signing_key_file, verifying_keys_file) = generated_key(&root.join("authority"));
    let (body, etag) = signed_bundle(&key_id, &signing_key_file, 11, BUNDLE_PAYLOAD);
    let (url, fixture) = one_shot_fixture(
        "200 OK",
        "application/json",
        body,
        vec![format!("etag: {etag}")],
    );
    let config = subscriber_config(&root, &url, &verifying_keys_file);

    // Exercised through the global `-f`, which is the flag the help text
    // points at and which a subcommand cannot see from its own args struct.
    let output = run_pull(&[
        "config",
        "pull",
        "-f",
        &config.to_string_lossy(),
        "--dry-run",
        "--format",
        "json",
    ]);
    fixture.join().expect("fixture");
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    let reported: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("pull emits one JSON object");
    assert_eq!(reported["command"], "config.pull");
    assert_eq!(reported["applied"], false);
    assert_eq!(reported["dry_run"], true);
    assert_eq!(reported["offered_revision"], 11);
    assert_eq!(reported["applied_revision"], 0);
    assert!(
        reported["plan"].is_object(),
        "the preview carries the plan envelope: {reported}"
    );
}

#[test]
fn config_pull_requires_dry_run_and_reports_an_unreachable_authority() {
    let root = temp_dir("pull-guards");
    let (_, _, verifying_keys_file) = generated_key(&root.join("authority"));
    let config = subscriber_config(
        &root,
        &format!("http://127.0.0.1:{}", closed_port()),
        &verifying_keys_file,
    );
    let config_arg = config.to_string_lossy().into_owned();

    // There is no local apply, and the refusal has to say why rather than
    // quietly doing something process-local that looks like success.
    let no_flag = run_pull(&["config", "pull", &config_arg]);
    assert_eq!(code(&no_flag), 1, "{}", stderr(&no_flag));
    assert!(
        stderr(&no_flag).contains("--dry-run"),
        "{}",
        stderr(&no_flag)
    );

    let unreachable = run_pull(&["config", "pull", &config_arg, "--dry-run"]);
    assert_eq!(
        code(&unreachable),
        7,
        "an authority that never answered is exit 7: {}",
        stderr(&unreachable)
    );
    assert!(
        stderr(&unreachable).contains("nothing was applied"),
        "{}",
        stderr(&unreachable)
    );
}

#[test]
fn config_pull_refuses_a_bundle_signed_by_a_key_the_node_does_not_trust() {
    let root = temp_dir("pull-untrusted");
    // Two authorities: the bundle is signed by the first, and the subscriber
    // trusts only the second.
    let (key_id, signing_key_file, _) = generated_key(&root.join("signer"));
    let (_, _, trusted_keys_file) = generated_key(&root.join("trusted"));
    let (body, etag) = signed_bundle(&key_id, &signing_key_file, 2, BUNDLE_PAYLOAD);
    let (url, fixture) = one_shot_fixture(
        "200 OK",
        "application/json",
        body,
        vec![format!("etag: {etag}")],
    );
    let config = subscriber_config(&root, &url, &trusted_keys_file);

    let output = run_pull(&["config", "pull", &config.to_string_lossy(), "--dry-run"]);
    fixture.join().expect("fixture");
    assert_eq!(
        code(&output),
        3,
        "a bundle this node would refuse must be reported as refused, not previewed: {}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("verify_failed"),
        "the refusal must name which check fired: {}",
        stderr(&output)
    );
    assert!(
        !root.join("config-bundle.json").exists(),
        "a refused bundle must not be cached"
    );
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Config-authority publisher, end to end.
//!
//! The listener is a real `tokio` listener and the client is a hand-rolled
//! request over `TcpStream`, for the same reason the subscriber tests do
//! it that way: a mock-HTTP dependency here means refreshing every nested
//! `Cargo.lock` in the repo, and the contract under test is one
//! conditional GET.
//!
//! The test that matters most is
//! [`the_real_subscriber_applies_what_the_real_authority_publishes`].
//! Everything else in the config-authority story so far has run against a
//! hand-rolled stub on one side or the other, so nothing had proven the two
//! halves agree on the wire. If the ETag or the header names disagree, that
//! is the test that fails.
//!
//! Tests that drive the process-wide reload transaction, or the
//! process-global authority handle, run one at a time behind [`SERIAL`].

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, LazyLock};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use sbproxy_config::config_bundle::{BundleMode, SignedConfigBundle, VerifyingKeySet};
use sbproxy_config::types::{
    ConfigAuthorityConfig, ConfigAuthorityPublishConfig, ConfigAuthorityPublishTlsConfig,
    ConfigAuthorityUpstreamConfig,
};
use sbproxy_core::config_authority::{BundleFetch, BundleListener, ConfigAuthority};
use sbproxy_core::config_subscriber::{ConfigSubscriber, CycleResult, BUNDLE_ENDPOINT_PATH};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// Serializes the tests that touch process-wide state: the live pipeline,
/// the reload transaction, and the installed authority handle.
static SERIAL: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

/// The Ed25519 seed every fixture authority signs with. Fixed so a
/// signature is reproducible across a "restart" in the same test.
const SEED: [u8; 32] = [7u8; 32];

const AUTHORITY_ID: &str = "control-plane-test";
const KEY_ID: &str = "authority-2026-07";

// --- fixtures ---------------------------------------------------------

/// A payload that compiles, constructs, and names no denied path.
fn payload(host: &str, body: &str) -> String {
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

/// A minimal local document: one static origin, nothing to bind.
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

/// Write the owner-only signing key file the authority loads.
fn write_signing_key(dir: &Path) -> String {
    let path = dir.join("authority-signing.key");
    std::fs::write(&path, BASE64.encode(SEED)).expect("write signing key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("tighten signing key permissions");
    }
    path.display().to_string()
}

/// A free loopback port. Bound, noted, released: the schema refuses port
/// `0` (a listener whose address moves every restart is one no subscriber
/// URL can point at), so a test has to name a port it believes is free.
fn free_port() -> u16 {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe bind");
    let port = probe.local_addr().expect("probe addr").port();
    drop(probe);
    port
}

/// The publish block under test. Built as a struct literal so a new field
/// cannot be added without this file deciding what it means.
fn publish_config(dir: &Path, port: u16) -> ConfigAuthorityPublishConfig {
    let publish = ConfigAuthorityPublishConfig {
        authority_id: AUTHORITY_ID.to_string(),
        key_id: KEY_ID.to_string(),
        signing_key_file: write_signing_key(dir),
        store_dir: dir.join("authority-store").display().to_string(),
        bind: format!("127.0.0.1:{port}"),
        // Loopback, so TLS is optional. The non-loopback rule has its own
        // tests below.
        tls: None,
        rate_limit_per_subscriber_per_minute: 1_000,
        rate_limit_total_per_minute: 1_000,
        archive_keep: sbproxy_config::config_authority::DEFAULT_ARCHIVE_KEEP,
    };
    // Every fixture must be a block an operator could actually write, so
    // the same validation `sbproxy validate` runs applies here.
    publish.validate().expect("fixture publish validates");
    publish
}

fn authority(dir: &Path) -> ConfigAuthority {
    ConfigAuthority::from_config(&publish_config(dir, free_port())).expect("authority")
}

/// The trusted-key set a subscriber would install for `authority`.
fn key_set(authority: &ConfigAuthority) -> VerifyingKeySet {
    VerifyingKeySet::from_json(
        authority
            .verifying_key_file_json()
            .expect("render key file")
            .as_bytes(),
    )
    .expect("parse key file")
}

/// A fetch with a credential and nothing else set.
fn fetch<'a>(credential: &'a str, if_none_match: Option<&'a str>) -> BundleFetch<'a> {
    BundleFetch {
        path: BUNDLE_ENDPOINT_PATH,
        method: "GET",
        credential: Some(credential),
        subscriber_id: None,
        if_none_match,
        peer: "127.0.0.1",
        apply_report: None,
    }
}

// --- raw HTTP client --------------------------------------------------

/// One raw HTTP/1.1 response, split into the parts a test asserts on.
struct RawResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl RawResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Send one GET over plain TCP and read the response to EOF.
///
/// The listener answers `Connection: close`, so reading to EOF is the
/// whole response and no framing logic is needed here.
async fn raw_get(addr: SocketAddr, target: &str, headers: &[(&str, &str)]) -> RawResponse {
    let mut socket = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to the authority");
    let mut request = format!("GET {target} HTTP/1.1\r\nHost: authority.test\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    socket
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    socket.flush().await.expect("flush request");
    let mut raw = Vec::new();
    socket
        .read_to_end(&mut raw)
        .await
        .expect("read the response");

    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("the response must carry a complete head");
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let body = raw[split + 4..].to_vec();
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .expect("the status line must carry a code");
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
        .collect();
    RawResponse {
        status,
        headers,
        body,
    }
}

/// Bind the authority's listener and serve it for the rest of the test.
async fn serve(
    authority: Arc<ConfigAuthority>,
    publish: &ConfigAuthorityPublishConfig,
) -> SocketAddr {
    let listener = BundleListener::bind(authority, publish)
        .await
        .expect("bind the bundle listener");
    assert!(
        !listener.is_tls(),
        "a loopback fixture listener is deliberately plaintext",
    );
    let addr = listener.local_addr().expect("listener address");
    tokio::spawn(listener.run());
    addr
}

// --- publish and fetch ------------------------------------------------

#[test]
fn publish_then_fetch_round_trips_a_verifiable_bundle() {
    let temp = tempfile::tempdir().expect("temp dir");
    let authority = authority(temp.path());
    let keys = key_set(&authority);

    assert_eq!(authority.current_revision(), 0);
    let credential = authority
        .register_subscriber("edge-01")
        .expect("register")
        .into_token();

    // Nothing published yet, so a fetch is a 404 rather than an empty 200.
    let empty = authority.serve_bundle(&fetch(&credential, None));
    assert_eq!(empty.status, 404);
    assert_eq!(empty.reason, "no_bundle_published");

    let outcome = authority
        .publish(&payload("api.test", "authority"), BundleMode::Overlay)
        .expect("publish");
    assert_eq!(outcome.revision, 1);
    assert_eq!(outcome.mode, BundleMode::Overlay);
    assert_eq!(authority.current_revision(), 1);

    let reply = authority.serve_bundle(&fetch(&credential, None));
    assert_eq!(reply.status, 200);
    assert_eq!(reply.revision, Some(1));
    assert_eq!(reply.etag.as_deref(), Some(outcome.etag.as_str()));

    // The body is a bundle that verifies under the key an operator would
    // hand a subscriber, which is the whole point of signing it.
    let signed = SignedConfigBundle::from_json(&reply.body).expect("decode the served bundle");
    let verified = signed.verify(&keys).expect("the served bundle must verify");
    assert_eq!(verified.revision, 1);
    assert_eq!(verified.authority_id, AUTHORITY_ID);
    assert_eq!(verified.mode, BundleMode::Overlay);
    assert!(verified.config_yaml.contains("api.test"));
    assert_eq!(signed.key_id, KEY_ID);
    assert_eq!(verified.content_digest, outcome.content_digest);

    // The ETag names the revision and the digest, which is what lets a
    // same-revision content change be visible rather than a silent 304.
    let etag = outcome.etag;
    assert_eq!(etag, format!("\"1-{}\"", verified.content_digest));

    // The rollout view records who took it.
    let status = authority.status();
    assert_eq!(status["current_revision"], 1);
    assert_eq!(status["subscriber_count"], 1);
    let subscriber = &status["subscribers"][0];
    assert_eq!(subscriber["subscriber_id"], "edge-01");
    assert_eq!(subscriber["last_seen_revision"], 1);
    assert_eq!(subscriber["up_to_date"], true);
}

#[test]
fn an_unchanged_etag_answers_304_with_no_body() {
    let temp = tempfile::tempdir().expect("temp dir");
    let authority = authority(temp.path());
    let credential = authority
        .register_subscriber("edge-01")
        .expect("register")
        .into_token();
    let first = authority
        .publish(&payload("api.test", "one"), BundleMode::Overlay)
        .expect("publish");

    let unchanged = authority.serve_bundle(&fetch(&credential, Some(first.etag.as_str())));
    assert_eq!(unchanged.status, 304);
    assert!(unchanged.body.is_empty(), "a 304 carries no body");
    assert_eq!(unchanged.etag.as_deref(), Some(first.etag.as_str()));

    // A stale ETag gets the current bundle.
    let stale = authority.serve_bundle(&fetch(&credential, Some("\"0-sha256:none\"")));
    assert_eq!(stale.status, 200);

    // A new publication makes the previously matching ETag stale, because
    // both the revision and the digest changed.
    let second = authority
        .publish(&payload("api.test", "two"), BundleMode::Overlay)
        .expect("publish");
    assert_ne!(second.etag, first.etag);
    assert_eq!(
        authority
            .serve_bundle(&fetch(&credential, Some(first.etag.as_str())))
            .status,
        200,
    );
    assert_eq!(
        authority
            .serve_bundle(&fetch(&credential, Some(second.etag.as_str())))
            .status,
        304,
    );
}

#[test]
fn an_unauthenticated_fetch_is_rejected() {
    let temp = tempfile::tempdir().expect("temp dir");
    let authority = authority(temp.path());
    authority
        .publish(&payload("api.test", "authority"), BundleMode::Overlay)
        .expect("publish");

    let anonymous = authority.serve_bundle(&BundleFetch {
        path: BUNDLE_ENDPOINT_PATH,
        method: "GET",
        credential: None,
        subscriber_id: None,
        if_none_match: None,
        peer: "127.0.0.1",
        apply_report: None,
    });
    assert_eq!(anonymous.status, 401);
    assert_eq!(anonymous.reason, "missing_credential");

    // A token that was never issued is refused, and is not
    // distinguishable from a malformed one: a caller must not be able to
    // learn which credential IDs exist.
    for bogus in [
        "not-a-token",
        "sbca1.unknown.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        let reply = authority.serve_bundle(&fetch(bogus, None));
        assert_eq!(reply.status, 401, "{bogus}");
        assert_eq!(reply.reason, "invalid_credential", "{bogus}");
    }

    // The registered credential works, which pins the refusals above on
    // the credential rather than on the fixture.
    let credential = authority
        .register_subscriber("edge-01")
        .expect("register")
        .into_token();
    assert_eq!(
        authority.serve_bundle(&fetch(&credential, None)).status,
        200
    );
}

#[test]
fn a_revoked_subscriber_is_rejected() {
    let temp = tempfile::tempdir().expect("temp dir");
    let authority = authority(temp.path());
    authority
        .publish(&payload("api.test", "authority"), BundleMode::Overlay)
        .expect("publish");
    let issued = authority.register_subscriber("edge-01").expect("register");
    let credential_id = issued.record().credential_id().to_string();
    let credential = issued.into_token();
    assert_eq!(
        authority.serve_bundle(&fetch(&credential, None)).status,
        200
    );

    assert!(authority.revoke_credential(&credential_id).expect("revoke"));
    let reply = authority.serve_bundle(&fetch(&credential, None));
    assert_eq!(reply.status, 403);
    assert_eq!(
        reply.reason, "revoked_credential",
        "a revoked credential is reported as revoked, not merely invalid: reaching that \
         branch already required holding the token",
    );

    // Revoking by subscriber id retires every credential that node holds.
    let other = authority
        .register_subscriber("edge-02")
        .expect("register")
        .into_token();
    assert_eq!(authority.serve_bundle(&fetch(&other, None)).status, 200);
    assert_eq!(authority.revoke_subscriber("edge-02").expect("revoke"), 1);
    assert_eq!(authority.serve_bundle(&fetch(&other, None)).status, 403);
}

#[test]
fn a_subscriber_id_header_that_disagrees_with_the_credential_is_refused() {
    let temp = tempfile::tempdir().expect("temp dir");
    let authority = authority(temp.path());
    authority
        .publish(&payload("api.test", "authority"), BundleMode::Overlay)
        .expect("publish");
    let credential = authority
        .register_subscriber("edge-01")
        .expect("register")
        .into_token();

    let mut mismatched = fetch(&credential, None);
    mismatched.subscriber_id = Some("edge-99");
    let reply = authority.serve_bundle(&mismatched);
    assert_eq!(reply.status, 403);
    assert_eq!(reply.reason, "subscriber_id_mismatch");

    // The registered id is accepted, and so is no header at all: the
    // credential is the identity and the header is a claim about it.
    let mut matching = fetch(&credential, None);
    matching.subscriber_id = Some("edge-01");
    assert_eq!(authority.serve_bundle(&matching).status, 200);
    assert_eq!(
        authority.serve_bundle(&fetch(&credential, None)).status,
        200
    );
}

// --- validation -------------------------------------------------------

#[test]
fn an_invalid_config_is_rejected_without_consuming_a_revision() {
    let temp = tempfile::tempdir().expect("temp dir");
    let authority = authority(temp.path());
    authority
        .publish(&payload("api.test", "one"), BundleMode::Overlay)
        .expect("publish");
    assert_eq!(authority.current_revision(), 1);

    // The case the publish-side validation exists for: a typo inside an
    // opaque `policies:` entry. `compile_config` leaves policies as JSON,
    // so it accepts this happily, and every subscriber would then refuse
    // it at boot. A fleet-wide outage from a validation gap.
    let typo = r#"
origins:
  "api.test":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: broken
    policies:
      - type: no_such_policy_type
"#;
    assert!(
        sbproxy_config::compile_config(typo).is_ok(),
        "the premise of this test is that compile_config alone does not catch it",
    );
    let error = authority
        .publish(typo, BundleMode::Overlay)
        .expect_err("a policy that cannot be constructed must not publish");
    assert_eq!(error.code(), "construct_failed", "{error}");
    assert!(error.is_payload_fault());
    assert!(
        error.to_string().contains("every subscriber"),
        "the message must name who would be hurt: {error}"
    );

    // A payload that does not even parse is refused at the compile step.
    let broken = "proxy:\n  http2_cleartextt: true\n";
    assert_eq!(
        authority
            .publish(broken, BundleMode::Overlay)
            .expect_err("a misspelled key must not publish")
            .code(),
        "compile_failed",
    );
    // An empty payload is refused rather than published as an empty
    // document that would blank a `replace` subscriber.
    assert_eq!(
        authority
            .publish("   \n", BundleMode::Overlay)
            .expect_err("an empty payload must not publish")
            .code(),
        "invalid_payload",
    );

    // None of the three consumed a number: the next publication is 2, and
    // the durable high-water mark never moved either.
    assert_eq!(authority.status()["high_water_revision"], 1);
    let next = authority
        .publish(&payload("api.test", "two"), BundleMode::Overlay)
        .expect("publish");
    assert_eq!(
        next.revision, 2,
        "a rejected payload must not burn a revision, or an operator fixing a typo would \
         watch the counter climb for nothing",
    );
}

#[test]
fn rollback_republishes_the_previous_payload_as_a_new_revision() {
    let temp = tempfile::tempdir().expect("temp dir");
    let authority = authority(temp.path());

    // Nothing published: there is nothing to go back to, and saying so is
    // better than inventing an empty document.
    let error = authority
        .rollback()
        .expect_err("a rollback with no history must be refused");
    assert_eq!(error.code(), "no_previous_revision", "{error}");
    assert!(error.is_request_fault());

    authority
        .publish(&payload("api.test", "good"), BundleMode::Overlay)
        .expect("publish the good revision");
    // One revision is still not enough: rolling back from 1 would leave
    // nothing serving.
    assert_eq!(
        authority
            .rollback()
            .expect_err("one revision is not a history")
            .code(),
        "no_previous_revision",
    );

    authority
        .publish(&payload("api.test", "regrettable"), BundleMode::Overlay)
        .expect("publish the regrettable revision");
    assert_eq!(authority.current_revision(), 2);

    let rolled_back = authority.rollback().expect("rollback");
    assert_eq!(rolled_back.restored_from_revision, 1);
    assert_eq!(rolled_back.replaced_revision, 2);
    assert_eq!(
        rolled_back.outcome.revision, 3,
        "a rollback must move forward: a subscriber's cursor refuses any revision that is not \
         greater than the one it applied, so re-serving revision 1 would reach nobody who had \
         already taken 2",
    );
    assert_eq!(authority.current_revision(), 3);

    // The content really is revision 1's, byte for byte, which is what makes
    // the digest comparison below meaningful rather than incidental.
    let digest_of_good = sbproxy_config::config_bundle::ConfigBundle::content_digest_of(&payload(
        "api.test", "good",
    ));
    assert_eq!(rolled_back.outcome.content_digest, digest_of_good);
    assert_eq!(
        authority.status()["current_content_digest"],
        serde_json::json!(digest_of_good),
    );
    assert_eq!(authority.status()["previous_revision"], 2);
}

// --- WOR-2463: the archive ring and rollback to a named revision -------

/// Publish `count` distinct payloads and hand back the authority.
fn published_series(dir: &Path, count: u64) -> ConfigAuthority {
    let authority = authority(dir);
    for revision in 1..=count {
        let outcome = authority
            .publish(
                &payload("api.test", &format!("body-{revision}")),
                BundleMode::Overlay,
            )
            .expect("publish");
        assert_eq!(outcome.revision, revision);
    }
    authority
}

#[test]
fn rollback_to_an_archived_revision_republishes_it_above_the_current_one() {
    let temp = tempfile::tempdir().expect("temp dir");
    let authority = published_series(temp.path(), 4);
    let keys = key_set(&authority);
    let credential = authority
        .register_subscriber("edge-01")
        .expect("register")
        .into_token();

    let status = authority.status();
    assert_eq!(
        status["archived_revisions"],
        serde_json::json!([1, 2, 3, 4]),
        "the status page names what a rollback may target",
    );
    assert_eq!(
        status["archive_keep"],
        serde_json::json!(sbproxy_config::config_authority::DEFAULT_ARCHIVE_KEEP),
    );

    // Three publishes ago, which `previous.json` alone cannot reach.
    let rolled_back = authority.rollback_to(2).expect("rollback to revision 2");
    assert_eq!(rolled_back.restored_from_revision, 2);
    assert_eq!(rolled_back.replaced_revision, 4);
    assert_eq!(
        rolled_back.outcome.revision, 5,
        "an archive rollback moves forward for the same anti-replay reason the one-step \
         rollback does",
    );
    let digest_of_two = sbproxy_config::config_bundle::ConfigBundle::content_digest_of(&payload(
        "api.test", "body-2",
    ));
    assert_eq!(rolled_back.outcome.content_digest, digest_of_two);

    // A real subscriber takes it, which is the half that proves the
    // republication is a bundle and not just a bookkeeping entry.
    let reply = authority.serve_bundle(&fetch(&credential, None));
    assert_eq!(reply.status, 200);
    assert_eq!(reply.revision, Some(5));
    let signed = SignedConfigBundle::from_json(&reply.body).expect("decode");
    let verified = signed.verify(&keys).expect("the served bundle verifies");
    assert_eq!(verified.revision, 5);
    assert!(
        verified.config_yaml.contains("body-2"),
        "the payload is revision 2's: {}",
        verified.config_yaml,
    );
    // And the republication itself is archived, so the next rollback can
    // name it too.
    assert_eq!(
        authority.status()["archived_revisions"],
        serde_json::json!([1, 2, 3, 4, 5]),
    );
}

/// The wire half of `revision_consumed`: the refusal an operator
/// actually reads carries the computed value. The per-variant
/// classification is pinned in the module's own tests, where the
/// private method is reachable.
#[test]
fn revision_consumed_tells_a_validation_refusal_from_a_spent_number() {
    let temp = tempfile::tempdir().expect("temp dir");
    let authority = std::sync::Arc::new(published_series(temp.path(), 2));
    sbproxy_core::config_authority::install_process_authority(std::sync::Arc::clone(&authority));
    let (status, refused) = {
        let (status, _content_type, body) = sbproxy_core::config_authority::dispatch(
            "POST",
            "/admin/config-authority/publish",
            Some("proxy:\n  admin:\n    enabled: true\n"),
        )
        .expect("the route must be owned by this dispatcher");
        (
            status,
            serde_json::from_str::<serde_json::Value>(&body).expect("a JSON body"),
        )
    };
    assert_eq!(status, 400, "{refused}");
    assert_eq!(
        refused["revision_consumed"], false,
        "a denied path is caught before the reservation: {refused}",
    );
    sbproxy_core::config_authority::clear_process_authority();
}

/// The other direction, which is the one that was never asserted.
///
/// Without this the wire value could be hardcoded `false` again and every
/// test in the tree would stay green: the refusal above is the direction
/// the old code already gave. So this drives a real failure *after*
/// `reserve_revision` has returned and asserts the operator is told the
/// number is gone.
#[test]
fn a_store_failure_after_the_reservation_reports_the_number_as_spent() {
    use std::os::unix::fs::PermissionsExt as _;

    let temp = tempfile::tempdir().expect("temp dir");
    let authority = std::sync::Arc::new(published_series(temp.path(), 2));

    // The archive write is the first write `commit` makes, and `commit`
    // runs after the reservation has already persisted the new
    // high-water mark. Making that directory read-and-traverse only is
    // the shape ENOSPC and EACCES both present to `write_atomically`.
    let archive_dir = temp
        .path()
        .join("authority-store")
        .join("revisions")
        .join("archive");
    let original = std::fs::metadata(&archive_dir)
        .expect("archive dir")
        .permissions();
    std::fs::set_permissions(&archive_dir, std::fs::Permissions::from_mode(0o500))
        .expect("make the archive unwritable");

    // Root bypasses the mode bits, and so do some filesystems. Skipping
    // is honest; asserting a refusal that never happened is not.
    let probe = archive_dir.join(".writability-probe");
    if std::fs::write(&probe, b"x").is_ok() {
        let _ = std::fs::remove_file(&probe);
        std::fs::set_permissions(&archive_dir, original).expect("restore permissions");
        return;
    }

    sbproxy_core::config_authority::install_process_authority(std::sync::Arc::clone(&authority));
    let (status, refused) = {
        let (status, _content_type, body) = sbproxy_core::config_authority::dispatch(
            "POST",
            "/admin/config-authority/publish",
            Some(&payload("api.test", "body-3")),
        )
        .expect("the route must be owned by this dispatcher");
        (
            status,
            serde_json::from_str::<serde_json::Value>(&body).expect("a JSON body"),
        )
    };
    sbproxy_core::config_authority::clear_process_authority();
    std::fs::set_permissions(&archive_dir, original).expect("restore permissions");

    assert_eq!(
        status, 500,
        "the authority is at fault, not the payload: {refused}"
    );
    assert_eq!(refused["code"], "store_failed", "{refused}");
    assert_eq!(
        refused["revision_consumed"], true,
        "the reservation returned before the store failed, so the number is gone: {refused}",
    );

    // And it really is gone: the next publication takes the number after
    // the one that failed, rather than reusing it.
    let next = authority
        .publish(&payload("api.test", "body-4"), BundleMode::Overlay)
        .expect("the store is writable again");
    assert_eq!(
        next.revision, 4,
        "revision 3 was reserved and never reissued, which is what revision_consumed reports",
    );
}

/// The rollback route's own `revision_consumed`, which the publish test
/// above does not witness.
///
/// The criterion was both wire sites. Reverting only the rollback site to
/// a hardcoded `false` left the whole suite green, because every existing
/// rollback refusal here is a request fault that answers `false` anyway.
/// A rollback republishes, so it reserves a number and can fail after it
/// the same way a publish can, and that is the case nothing covered.
#[test]
fn a_rollback_that_fails_after_its_reservation_reports_the_number_as_spent() {
    use std::os::unix::fs::PermissionsExt as _;

    let temp = tempfile::tempdir().expect("temp dir");
    let authority = std::sync::Arc::new(published_series(temp.path(), 2));

    let archive_dir = temp
        .path()
        .join("authority-store")
        .join("revisions")
        .join("archive");
    let original = std::fs::metadata(&archive_dir)
        .expect("archive dir")
        .permissions();
    std::fs::set_permissions(&archive_dir, std::fs::Permissions::from_mode(0o500))
        .expect("make the archive unwritable");

    // Root and mode-ignoring filesystems: skip honestly rather than
    // assert a refusal that never happened.
    let probe = archive_dir.join(".writability-probe");
    if std::fs::write(&probe, b"x").is_ok() {
        let _ = std::fs::remove_file(&probe);
        std::fs::set_permissions(&archive_dir, original).expect("restore permissions");
        return;
    }

    sbproxy_core::config_authority::install_process_authority(std::sync::Arc::clone(&authority));
    let (status, refused) = {
        let (status, _content_type, body) = sbproxy_core::config_authority::dispatch(
            "POST",
            "/admin/config-authority/rollback",
            None,
        )
        .expect("the route must be owned by this dispatcher");
        (
            status,
            serde_json::from_str::<serde_json::Value>(&body).expect("a JSON body"),
        )
    };
    sbproxy_core::config_authority::clear_process_authority();
    std::fs::set_permissions(&archive_dir, original).expect("restore permissions");

    assert_eq!(
        status, 500,
        "the store failed, which is the authority's fault, not the request's: {refused}",
    );
    assert_eq!(refused["code"], "store_failed", "{refused}");
    assert_eq!(
        refused["revision_consumed"], true,
        "the republication reserved a number before the store failed: {refused}",
    );

    // The number really is gone, independently of what the wire said.
    let next = authority
        .publish(&payload("api.test", "body-after"), BundleMode::Overlay)
        .expect("the store is writable again");
    assert_eq!(
        next.revision, 4,
        "the rollback reserved 3 and the counter never reissues it",
    );
}

#[test]
fn a_rollback_to_a_revision_the_archive_does_not_hold_is_refused_by_name() {
    let temp = tempfile::tempdir().expect("temp dir");
    let authority = published_series(temp.path(), 2);
    let error = authority
        .rollback_to(9)
        .expect_err("revision 9 was never published");
    assert_eq!(error.code(), "revision_not_archived", "{error}");
    assert!(error.is_request_fault(), "{error}");
    let message = error.to_string();
    assert!(
        message.contains("revision 9 is not in the archive"),
        "{message}"
    );
    assert!(
        message.contains("available revisions are 1, 2"),
        "the refusal lists what an operator may pick instead: {message}",
    );
    assert_eq!(
        authority.current_revision(),
        2,
        "a refused rollback publishes nothing and burns no number",
    );
}

#[test]
fn an_archived_payload_that_no_longer_validates_is_refused_with_its_validation_error() {
    let temp = tempfile::tempdir().expect("temp dir");
    let authority = published_series(temp.path(), 2);
    // Stand in for "this payload stopped constructing after a binary
    // upgrade" by rewriting the archived bundle's payload to one the
    // current binary refuses. The file is the authority's own, signed by
    // its own key, so nothing but the validation pass can reject it, which
    // is exactly the property under test: a rollback revalidates rather
    // than trusting that a payload which published once still publishes.
    let archive = temp
        .path()
        .join("authority-store")
        .join("revisions")
        .join("archive")
        .join("1.json");
    let signed: sbproxy_config::SignedConfigBundle =
        sbproxy_config::SignedConfigBundle::from_json(&std::fs::read(&archive).expect("read"))
            .expect("decode");
    let signer = sbproxy_config::ConfigBundleSigner::ed25519_from_seed_file(
        KEY_ID,
        write_signing_key(temp.path()),
    )
    .expect("signer");
    let denied = signer
        .sign(
            sbproxy_config::ConfigBundle::new(
                AUTHORITY_ID,
                signed.bundle.revision,
                signed.bundle.mode,
                "proxy:\n  admin:\n    enabled: true\n",
                signed.bundle.issued_at_unix_ms,
                None,
            )
            .expect("bundle"),
        )
        .expect("sign");
    std::fs::write(&archive, denied.to_json().expect("encode")).expect("rewrite archive");

    let error = authority
        .rollback_to(1)
        .expect_err("an archived payload this binary refuses must not reach the fleet");
    assert_eq!(error.code(), "denied_path", "{error}");
    assert!(
        error.is_request_fault(),
        "the stored payload is at fault, not the authority: {error}",
    );
    assert_eq!(
        authority.current_revision(),
        2,
        "nothing was published, so the fleet is still on revision 2",
    );
}

#[test]
fn the_rollback_route_takes_an_optional_to_revision_and_refuses_a_malformed_one() {
    fn call(body: Option<&str>) -> (u16, serde_json::Value) {
        let (status, _content_type, body) = sbproxy_core::config_authority::dispatch(
            "POST",
            "/admin/config-authority/rollback",
            body,
        )
        .expect("the route must be owned by this dispatcher");
        (
            status,
            serde_json::from_str::<serde_json::Value>(&body).expect("a JSON body"),
        )
    }

    let temp = tempfile::tempdir().expect("temp dir");
    let authority = std::sync::Arc::new(published_series(temp.path(), 3));
    sbproxy_core::config_authority::install_process_authority(std::sync::Arc::clone(&authority));

    // No body is the one-step rollback it has always been.
    let (status, one_step) = call(None);
    assert_eq!(status, 200, "{one_step}");
    assert_eq!(one_step["restored_from_revision"], 2);
    assert_eq!(one_step["revision"], 4);

    // An empty object is the same thing: `to_revision` is optional.
    let (status, still_one_step) = call(Some("{}"));
    assert_eq!(status, 200, "{still_one_step}");
    assert_eq!(still_one_step["restored_from_revision"], 3);

    // Naming a revision reaches past the one-step window.
    let (status, named) = call(Some(r#"{"to_revision":1}"#));
    assert_eq!(status, 200, "{named}");
    assert_eq!(named["restored_from_revision"], 1);
    assert_eq!(named["revision"], 6);

    // A revision the ring does not hold is a 400 that lists the choices,
    // in the body as well as in the sentence.
    let (status, refused) = call(Some(r#"{"to_revision":99}"#));
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["code"], "revision_not_archived");
    assert_eq!(refused["revision_consumed"], false);
    assert_eq!(
        refused["archived_revisions"],
        serde_json::json!([1, 2, 3, 4, 5, 6]),
    );

    // The query-string spelling is refused rather than discarded. The
    // sibling publish route on this prefix takes `?mode=`, so
    // `?to_revision=` is the spelling an operator reaches for, and
    // silently running the one-step rollback with a 200 is the exact
    // outcome the malformed-body 400 exists to prevent.
    let before = authority.current_revision();
    let (status, by_query) = {
        let (status, _content_type, body) = sbproxy_core::config_authority::dispatch(
            "POST",
            "/admin/config-authority/rollback?to_revision=1",
            None,
        )
        .expect("the route must be owned by this dispatcher");
        (
            status,
            serde_json::from_str::<serde_json::Value>(&body).expect("a JSON body"),
        )
    };
    assert_eq!(status, 400, "{by_query}");
    assert_eq!(by_query["code"], "invalid_to_revision");
    assert!(
        by_query["error"]
            .as_str()
            .is_some_and(|error| error.contains("not a query parameter")),
        "the refusal says where the field belongs: {by_query}",
    );
    assert_eq!(
        authority.current_revision(),
        before,
        "and nothing was published",
    );

    // A body that is present but unusable is refused rather than silently
    // treated as the one-step rollback, which would roll the fleet to a
    // document the operator did not name.
    for (body, code) in [
        ("not json", "invalid_body"),
        ("[1]", "invalid_body"),
        (r#"{"to_revision":0}"#, "invalid_to_revision"),
        (r#"{"to_revision":"3"}"#, "invalid_to_revision"),
        (r#"{"to_revision":-1}"#, "invalid_to_revision"),
    ] {
        let (status, answer) = call(Some(body));
        assert_eq!(status, 400, "{body}: {answer}");
        assert_eq!(answer["code"], code, "{body}");
    }

    sbproxy_core::config_authority::clear_process_authority();
}

#[test]
fn a_zero_archive_keep_leaves_the_one_step_rollback_and_refuses_a_named_one() {
    let temp = tempfile::tempdir().expect("temp dir");
    let mut publish = publish_config(temp.path(), free_port());
    publish.archive_keep = 0;
    publish.validate().expect("archive_keep of zero validates");
    let authority = ConfigAuthority::from_config(&publish).expect("authority");
    for revision in 1..=2u64 {
        authority
            .publish(
                &payload("api.test", &format!("body-{revision}")),
                BundleMode::Overlay,
            )
            .expect("publish");
    }
    assert!(authority.archived_revisions().is_empty());
    // The behavior that predates the ring is untouched.
    assert_eq!(
        authority
            .rollback()
            .expect("one-step rollback")
            .restored_from_revision,
        1,
    );
    assert_eq!(
        authority
            .rollback_to(1)
            .expect_err("nothing is archived")
            .code(),
        "revision_not_archived",
    );
}

#[test]
fn a_deny_listed_path_is_rejected_at_publish() {
    let temp = tempfile::tempdir().expect("temp dir");
    let authority = authority(temp.path());

    // Every path the subscriber owns outright, rejected here rather than
    // left for the whole fleet to discover at once.
    for path in sbproxy_config::AUTHORITY_DENIED_PATHS {
        let segments: Vec<&str> = path.split('.').collect();
        let mut yaml = String::new();
        for (depth, segment) in segments.iter().enumerate() {
            yaml.push_str(&"  ".repeat(depth));
            yaml.push_str(segment);
            if depth + 1 == segments.len() {
                yaml.push_str(": {}\n");
            } else {
                yaml.push_str(":\n");
            }
        }
        let error = match authority.publish(&yaml, BundleMode::Overlay) {
            Ok(outcome) => panic!(
                "{path} published as revision {}; a path every subscriber owns must be refused \
                 here rather than left for the whole fleet to refuse at once",
                outcome.revision
            ),
            Err(error) => error,
        };
        if *path == "source" {
            // `source` is the one deny-listed path that is legitimate in a
            // *submitted* payload: that is how a git-backed authority points
            // at the repository it publishes from. The deny-list applies to
            // the *resolved* document, so this submission is read as a
            // pointer and refused for being a malformed one rather than for
            // naming a denied path. Refusal either way, but for the accurate
            // reason. The resolved-document case is covered by
            // `an_authority_bundle_carrying_source_is_rejected` in
            // sbproxy-config's config_source_git tests.
            assert_eq!(error.code(), "invalid_payload", "{path}: {error}");
            continue;
        }
        assert_eq!(error.code(), "denied_path", "{path}: {error}");
        assert!(error.to_string().contains(path), "{path}: {error}");
    }
    assert_eq!(
        authority.current_revision(),
        0,
        "no denied payload may consume a revision",
    );
}

/// WOR-2436: `origin_defaults` is authority-writable and its sibling
/// `origin_sources` is not, so the distinction is deliberate rather than
/// an accident of what happens to be on the deny list.
///
/// The negative half is covered by `a_deny_listed_path_is_rejected_at_publish`
/// above, which walks the whole list. This is the positive half: the
/// platform raising a security floor across the fleet is exactly what
/// this channel exists for, and a refusal here would mean the block
/// could never be distributed.
#[test]
fn an_authority_bundle_setting_origin_defaults_is_accepted() {
    let temp = tempfile::tempdir().expect("temp dir");
    let authority = authority(temp.path());

    let yaml = format!(
        "{}\norigin_defaults:\n  policies:\n    - name: waf\n      type: waf\n      \
         mode: block\n      locked: true\n",
        payload("api.test", "ok")
    );
    let outcome = authority
        .publish(&yaml, BundleMode::Overlay)
        .expect("the platform floor must publish through the authority");
    assert_eq!(outcome.revision, 1);
}

/// The published example payload really publishes.
///
/// `validate_examples` only runs the example files through
/// `compile_config`, which by design cannot see a typo inside an opaque
/// `policies:` entry. This runs the shipped `bundle.yml` through the whole
/// publish path, so a reader following the example's README cannot be the
/// one who discovers it does not work.
#[test]
fn the_shipped_example_payload_publishes() {
    let temp = tempfile::tempdir().expect("temp dir");
    let authority = authority(temp.path());
    let example = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .parent()
        .expect("workspace root")
        .join("examples/config-authority/bundle.yml");
    let yaml = std::fs::read_to_string(&example)
        .unwrap_or_else(|error| panic!("{}: read failed: {error}", example.display()));
    let outcome = authority
        .publish(&yaml, BundleMode::Overlay)
        .unwrap_or_else(|error| {
            panic!(
                "{} must publish through the real validation path: {error}",
                example.display()
            )
        });
    assert_eq!(outcome.revision, 1);
    assert_eq!(outcome.mode, BundleMode::Overlay);
}

#[test]
fn revisions_stay_monotonic_across_a_restart() {
    let temp = tempfile::tempdir().expect("temp dir");
    let port = free_port();
    let publish = publish_config(temp.path(), port);

    let first_digest = {
        let authority = ConfigAuthority::from_config(&publish).expect("authority");
        authority
            .publish(&payload("api.test", "one"), BundleMode::Overlay)
            .expect("publish");
        let second = authority
            .publish(&payload("api.test", "two"), BundleMode::Overlay)
            .expect("publish");
        assert_eq!(second.revision, 2);
        second.content_digest
    };

    // Same store directory, brand-new authority: the restart.
    let restarted = ConfigAuthority::from_config(&publish).expect("authority");
    assert_eq!(
        restarted.current_revision(),
        2,
        "the published revision has to survive a restart, or a subscriber's cursor would \
         refuse the next bundle as a rollback",
    );
    let credential = restarted
        .register_subscriber("edge-01")
        .expect("register")
        .into_token();
    let served = restarted.serve_bundle(&fetch(&credential, None));
    assert_eq!(served.status, 200);
    let signed = SignedConfigBundle::from_json(&served.body).expect("decode");
    assert_eq!(signed.bundle.revision, 2);
    assert_eq!(
        signed.bundle.content_digest, first_digest,
        "the restarted authority serves the same bytes it published, not a re-signed \
         approximation of them",
    );

    let next = restarted
        .publish(&payload("api.test", "three"), BundleMode::Overlay)
        .expect("publish");
    assert_eq!(
        next.revision, 3,
        "a restart must never reissue a number a subscriber may already hold",
    );
}

#[test]
fn the_rate_limit_is_enforced_per_subscriber_and_fleet_wide() {
    let temp = tempfile::tempdir().expect("temp dir");
    let mut publish = publish_config(temp.path(), free_port());
    publish.rate_limit_per_subscriber_per_minute = 2;
    publish.rate_limit_total_per_minute = 3;
    publish.validate().expect("fixture validates");
    let authority = ConfigAuthority::from_config(&publish).expect("authority");
    authority
        .publish(&payload("api.test", "authority"), BundleMode::Overlay)
        .expect("publish");
    let first = authority
        .register_subscriber("edge-01")
        .expect("register")
        .into_token();
    let second = authority
        .register_subscriber("edge-02")
        .expect("register")
        .into_token();

    // Two requests each is the per-subscriber budget.
    assert_eq!(authority.serve_bundle(&fetch(&first, None)).status, 200);
    assert_eq!(authority.serve_bundle(&fetch(&first, None)).status, 200);
    let throttled = authority.serve_bundle(&fetch(&first, None));
    assert_eq!(throttled.status, 429);
    assert_eq!(throttled.reason, "rate_limited");

    // The second subscriber has its own budget, so one noisy node does not
    // starve a quiet one. It also runs into the fleet-wide cap, which is
    // what keeps a restart storm from taking the authority down rather
    // than merely slowing it.
    assert_eq!(authority.serve_bundle(&fetch(&second, None)).status, 200);
    assert_eq!(
        authority.serve_bundle(&fetch(&second, None)).status,
        429,
        "the fleet-wide cap of 3 is reached even though this subscriber's own budget is not",
    );
}

// --- the listener -----------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_authority_listener_serves_only_the_bundle_path() {
    let temp = tempfile::tempdir().expect("temp dir");
    let publish = publish_config(temp.path(), free_port());
    let authority = Arc::new(ConfigAuthority::from_config(&publish).expect("authority"));
    authority
        .publish(&payload("api.test", "authority"), BundleMode::Overlay)
        .expect("publish");
    let credential = authority
        .register_subscriber("edge-01")
        .expect("register")
        .into_token();
    let addr = serve(Arc::clone(&authority), &publish).await;

    let bearer = format!("Bearer {credential}");
    let authorized = [("Authorization", bearer.as_str())];

    // The one path this listener owns.
    let bundle = raw_get(addr, BUNDLE_ENDPOINT_PATH, &authorized).await;
    assert_eq!(bundle.status, 200);
    assert_eq!(bundle.header("Content-Type"), Some("application/json"));
    assert_eq!(bundle.header("Cache-Control"), Some("no-store"));
    let etag = bundle.header("ETag").expect("an ETag").to_string();
    assert!(SignedConfigBundle::from_json(&bundle.body).is_ok());

    // Nothing else is here. Not the admin surface that would let a
    // subscriber's credential reach operator routes, not the metrics
    // endpoint, not the UI.
    for target in [
        "/admin/config-authority/status",
        "/admin/config-authority/publish",
        "/admin/config-authority/subscribers",
        "/admin/reload",
        "/admin/ui/",
        "/metrics",
        "/healthz",
        "/",
    ] {
        let response = raw_get(addr, target, &authorized).await;
        assert_eq!(
            response.status, 404,
            "{target} must not be reachable on the bundle listener",
        );
    }

    // The conditional request works over the wire too, which is the half
    // the in-process tests cannot prove.
    let conditional = raw_get(
        addr,
        BUNDLE_ENDPOINT_PATH,
        &[
            ("Authorization", bearer.as_str()),
            ("If-None-Match", etag.as_str()),
        ],
    )
    .await;
    assert_eq!(conditional.status, 304);
    assert!(conditional.body.is_empty());
    assert_eq!(conditional.header("ETag"), Some(etag.as_str()));
    assert_eq!(
        conditional.header("Content-Length"),
        None,
        "a 304 sends no Content-Length",
    );

    // And an unauthenticated request over the wire is a 401 that names the
    // scheme, so a client knows what to present.
    let anonymous = raw_get(addr, BUNDLE_ENDPOINT_PATH, &[]).await;
    assert_eq!(anonymous.status, 401);
    assert!(
        anonymous
            .header("WWW-Authenticate")
            .is_some_and(|value| value.contains("Bearer")),
        "{:?}",
        anonymous.header("WWW-Authenticate"),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_non_loopback_bind_without_tls_refuses_to_start() {
    let temp = tempfile::tempdir().expect("temp dir");
    let publish = publish_config(temp.path(), free_port());
    let authority = Arc::new(ConfigAuthority::from_config(&publish).expect("authority"));

    // The listener refuses it in its own right, not only because the
    // schema does. The listener is the thing that would leak, so it does
    // not rely on something upstream having checked.
    let mut remote = publish.clone();
    remote.bind = format!("0.0.0.0:{}", free_port());
    remote.tls = None;
    let error = BundleListener::bind(Arc::clone(&authority), &remote)
        .await
        .expect_err("a remote bundle listener must not serve plaintext");
    let message = format!("{error:#}");
    assert!(message.contains("refusing to start"), "{message}");
    assert!(message.contains("fleet credential"), "{message}");

    // TLS material that cannot be read is also a refusal, never a
    // plaintext fall back.
    let mut missing_cert = remote.clone();
    missing_cert.tls = Some(ConfigAuthorityPublishTlsConfig {
        cert_file: temp.path().join("absent.pem").display().to_string(),
        key_file: temp.path().join("absent-key.pem").display().to_string(),
    });
    let error = BundleListener::bind(Arc::clone(&authority), &missing_cert)
        .await
        .expect_err("an unreadable certificate must not fall back to plaintext");
    assert!(
        format!("{error:#}").contains("TLS certificate"),
        "{error:#}"
    );

    // The same remote bind with usable TLS starts and terminates TLS.
    let (cert_pem, key_pem) = self_signed();
    let cert_file = temp.path().join("authority.pem");
    let key_file = temp.path().join("authority-key.pem");
    std::fs::write(&cert_file, cert_pem).expect("write cert");
    std::fs::write(&key_file, key_pem).expect("write key");
    let mut secured = remote;
    secured.bind = format!("127.0.0.1:{}", free_port());
    secured.tls = Some(ConfigAuthorityPublishTlsConfig {
        cert_file: cert_file.display().to_string(),
        key_file: key_file.display().to_string(),
    });
    let listener = BundleListener::bind(authority, &secured)
        .await
        .expect("a listener with usable TLS binds");
    assert!(listener.is_tls());
}

/// A throwaway self-signed certificate for `localhost`.
fn self_signed() -> (String, String) {
    let key = rcgen::KeyPair::generate().expect("generate key");
    let certificate = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .expect("certificate params")
        .self_signed(&key)
        .expect("self-sign");
    (certificate.pem(), key.serialize_pem())
}

// --- boot-time validation --------------------------------------------

#[test]
fn compile_config_refuses_a_publishing_node_that_would_be_unsafe() {
    let temp = tempfile::tempdir().expect("temp dir");
    let signing_key_file = write_signing_key(temp.path());
    let store_dir = temp.path().join("store").display().to_string();
    let full = |publish_extra: &str, admin: &str| {
        format!(
            r#"
proxy:
  http_bind_port: 0
{admin}  config_authority:
    publish:
      authority_id: control-plane-test
      key_id: authority-2026-07
      signing_key_file: {signing_key_file}
      store_dir: {store_dir}
{publish_extra}
origins:
  "api.test":
    action:
      type: static
      status_code: 200
"#
        )
    };
    let loopback = "      bind: 127.0.0.1:9443\n";
    let no_admin = "";
    let real_password = "  admin:\n    enabled: true\n    password: a-real-password\n";

    // The baseline compiles, so every refusal below is about the thing it
    // names and not about the fixture.
    sbproxy_config::compile_config(&full(loopback, no_admin)).expect("the baseline compiles");
    sbproxy_config::compile_config(&full(loopback, real_password))
        .expect("a real admin password compiles");

    // A remote bind with no TLS block.
    // `err().expect()` rather than `expect_err`: the latter needs Debug on
    // the Ok type, and CompiledConfig does not implement it.
    let error = sbproxy_config::compile_config(&full("      bind: 0.0.0.0:9443\n", no_admin))
        .err()
        .expect("a remote bundle listener must not serve plaintext");
    let message = format!("{error:#}");
    assert!(message.contains("not a loopback address"), "{message}");
    assert!(message.contains("tls"), "{message}");

    // The shipped default admin password, on loopback. Refused anyway,
    // which is the one place a publishing node is stricter than an
    // ordinary one: the blast radius is the fleet, not the box.
    let default_password = "  admin:\n    enabled: true\n    bind: 127.0.0.1\n";
    let error = sbproxy_config::compile_config(&full(loopback, default_password))
        .err()
        .expect("a publishing node must not carry the shipped default admin password");
    let message = format!("{error:#}");
    assert!(message.contains("changeme"), "{message}");
    assert!(
        message.contains("loopback does not make this acceptable"),
        "{message}"
    );
    // The same admin block without a publish block is fine, which pins the
    // refusal on the combination.
    sbproxy_config::compile_config(
        r#"
proxy:
  http_bind_port: 0
  admin:
    enabled: true
    bind: 127.0.0.1
origins:
  "api.test":
    action:
      type: static
      status_code: 200
"#,
    )
    .expect("loopback admin with the default password is the first-run path");

    // A signing key that is not there.
    let absent = temp.path().join("absent.key").display().to_string();
    let error = sbproxy_config::compile_config(&full(loopback, no_admin).replace(
        &format!("signing_key_file: {signing_key_file}"),
        &format!("signing_key_file: {absent}"),
    ))
    .err()
    .expect("an authority that cannot sign cannot serve");
    let message = format!("{error:#}");
    assert!(message.contains("not a usable signing key"), "{message}");
    assert!(
        message.contains("/dev/urandom"),
        "the message must say how to make one: {message}"
    );
}

#[test]
fn upstream_plus_publish_fails_validation_through_compile_config() {
    let temp = tempfile::tempdir().expect("temp dir");
    let signing_key_file = write_signing_key(temp.path());
    let store_dir = temp.path().join("store").display().to_string();
    let both = format!(
        r#"
proxy:
  http_bind_port: 0
  config_authority:
    upstream:
      url: https://control.example.com
      mode: overlay
      subscriber_id: edge-01
      verifying_keys_file: /etc/sbproxy/authority-keys.json
      cache_path: /var/lib/sbproxy/config-bundle.json
    publish:
      authority_id: control-plane-test
      key_id: authority-2026-07
      signing_key_file: {signing_key_file}
      store_dir: {store_dir}
      bind: 127.0.0.1:9443
origins:
  "api.test":
    action:
      type: static
      status_code: 200
"#
    );
    let error = sbproxy_config::compile_config(&both)
        .err()
        .expect("one node cannot both subscribe to an authority and publish to subscribers");
    let message = format!("{error:#}");
    assert!(message.contains("both"), "{message}");
    assert!(message.contains("provenance"), "{message}");

    // And the assertion the seam was left with is now the live answer.
    let publish_only: ConfigAuthorityConfig = serde_yaml::from_str(&format!(
        r#"
publish:
  authority_id: control-plane-test
  key_id: authority-2026-07
  signing_key_file: {signing_key_file}
  store_dir: {store_dir}
  bind: 127.0.0.1:9443
"#
    ))
    .expect("parse");
    assert!(publish_only.publishes_bundles());
    publish_only.validate().expect("publish alone validates");
}

// --- the test that matters most ---------------------------------------

/// Point the real subscriber at the real authority, in process, and prove
/// a published configuration reaches it and applies.
///
/// Everything else in this story has run against a hand-rolled stub on one
/// side or the other. This is the only test where both halves are the
/// shipped code, so it is where an ETag or header-name disagreement shows
/// up rather than in production.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_real_subscriber_applies_what_the_real_authority_publishes() {
    let _serial = SERIAL.lock().await;
    let temp = tempfile::tempdir().expect("temp dir");
    let dir = temp.path();

    // --- the authority side ---
    let publish = publish_config(dir, free_port());
    let authority = Arc::new(ConfigAuthority::from_config(&publish).expect("authority"));
    let issued = authority
        .register_subscriber("edge-01")
        .expect("register a subscriber");
    let credential_id = issued.record().credential_id().to_string();
    let credential = issued.into_token();
    let addr = serve(Arc::clone(&authority), &publish).await;
    let first = authority
        .publish(
            &payload("wire-authority.test", "authority"),
            BundleMode::Overlay,
        )
        .expect("publish");

    // --- the subscriber side ---
    // The verifying-key file the authority generates is what the
    // subscriber installs, so a key-ID typo cannot creep in between them.
    let keys_file = dir.join("authority-keys.json");
    std::fs::write(
        &keys_file,
        authority
            .verifying_key_file_json()
            .expect("render the key file"),
    )
    .expect("write the key file");
    let config_path = dir.join("sb.yml");
    let local = local_config("wire-local.test");
    std::fs::write(&config_path, &local).expect("write the local document");

    // The credential is a secret reference, not an inline literal, because
    // that is the only shape the schema accepts. A `file:` reference keeps
    // this test from mutating the process environment (WOR-646); the
    // `env:` spelling has its own unit coverage in config_subscriber.rs.
    let credential_path = dir.join("authority-credential");
    std::fs::write(&credential_path, &credential).expect("write the credential file");
    let upstream = ConfigAuthorityUpstreamConfig {
        url: format!("http://{addr}"),
        mode: BundleMode::Overlay,
        subscriber_id: "edge-01".to_string(),
        credential: Some(format!("file:{}", credential_path.display())),
        verifying_keys_file: keys_file.display().to_string(),
        poll_interval_secs: 5,
        cache_path: dir.join("config-bundle.json").display().to_string(),
        max_staleness_secs: 86_400,
        require_bundle_on_boot: None,
        // The fixture listener is loopback plaintext; the signature is
        // what protects the payload either way.
        allow_insecure_http: true,
        allow_shared_secret_keys: false,
    };
    upstream.validate().expect("the fixture upstream validates");
    let mut subscriber =
        ConfigSubscriber::new(config_path.to_str().expect("utf-8 path"), &upstream)
            .expect("subscriber");
    assert!(
        subscriber.has_keys(),
        "the subscriber must trust the key the authority generated",
    );

    // --- one full cycle over the wire ---
    assert_eq!(
        subscriber.poll_once().await,
        CycleResult::Applied,
        "the real subscriber must accept what the real authority serves",
    );
    assert_eq!(subscriber.revision(), first.revision);
    assert_eq!(
        subscriber.cursor().content_digest,
        first.content_digest,
        "the cursor must land on the digest the authority published",
    );
    let serving: Vec<String> = sbproxy_core::reload::current_pipeline()
        .config
        .origins
        .iter()
        .map(|origin| origin.hostname.to_string())
        .collect();
    assert!(
        serving.iter().any(|host| host == "wire-authority.test"),
        "the authority's origin must be live: {serving:?}",
    );
    assert!(
        serving.iter().any(|host| host == "wire-local.test"),
        "an overlay must keep the local origin: {serving:?}",
    );

    // The authority recorded who took it, under the subscriber id the
    // subscriber sent in its header.
    let status = authority.status();
    let record = status["subscribers"]
        .as_array()
        .expect("a roster")
        .iter()
        .find(|entry| entry["credential_id"] == credential_id.as_str())
        .expect("the registered credential");
    assert_eq!(record["subscriber_id"], "edge-01");
    assert_eq!(record["last_seen_revision"], first.revision);
    assert_eq!(record["up_to_date"], true);

    // --- the conditional request ---
    // A second cycle sends the cursor as `If-None-Match` and the authority
    // answers 304. This is the assertion that fails if the two sides ever
    // render the entity tag differently.
    assert_eq!(
        subscriber.poll_once().await,
        CycleResult::NotModified,
        "the authority's ETag and the subscriber's If-None-Match have to be the same bytes",
    );
    assert_eq!(subscriber.revision(), first.revision);

    // --- a second publication reaches the same subscriber ---
    let second = authority
        .publish(
            &payload("wire-second.test", "authority-second"),
            BundleMode::Overlay,
        )
        .expect("publish");
    assert_eq!(second.revision, first.revision + 1);
    assert_eq!(subscriber.poll_once().await, CycleResult::Applied);
    assert_eq!(subscriber.revision(), second.revision);
    let serving: Vec<String> = sbproxy_core::reload::current_pipeline()
        .config
        .origins
        .iter()
        .map(|origin| origin.hostname.to_string())
        .collect();
    assert!(
        serving.iter().any(|host| host == "wire-second.test"),
        "the second publication must reach the live pipeline: {serving:?}",
    );

    // --- revocation stops the fleet ---
    authority.revoke_credential(&credential_id).expect("revoke");
    authority
        .publish(&payload("wire-third.test", "never"), BundleMode::Overlay)
        .expect("publish");
    assert_eq!(
        subscriber.poll_once().await,
        CycleResult::Unreachable,
        "a revoked subscriber sees the authority as unreachable (403) and keeps serving what \
         it already applied, rather than losing its configuration",
    );
    assert_eq!(
        subscriber.revision(),
        second.revision,
        "the cursor must not move on a refused fetch",
    );
}

// --- the admin surface ------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_admin_routes_publish_register_revoke_and_report() {
    let _serial = SERIAL.lock().await;
    let temp = tempfile::tempdir().expect("temp dir");
    let publish = publish_config(temp.path(), free_port());
    let authority = Arc::new(ConfigAuthority::from_config(&publish).expect("authority"));
    sbproxy_core::config_authority::install_process_authority(Arc::clone(&authority));

    /// A plain `fn` rather than a closure: a closure over `&str`
    /// parameters gets one inferred lifetime, and this is called with both
    /// literals and temporaries.
    fn call(method: &str, path: &str, body: Option<&str>) -> (u16, serde_json::Value) {
        let (status, content_type, body) =
            sbproxy_core::config_authority::dispatch(method, path, body)
                .expect("the route must be owned by this dispatcher");
        assert_eq!(content_type, "application/json");
        (
            status,
            serde_json::from_str::<serde_json::Value>(&body).expect("a JSON body"),
        )
    }

    // Publish takes the YAML as the request body and the mode as a query
    // parameter.
    let (status, published) = call(
        "POST",
        "/admin/config-authority/publish",
        Some(&payload("admin-api.test", "published")),
    );
    assert_eq!(status, 200, "{published}");
    assert_eq!(published["revision"], 1);
    assert_eq!(published["mode"], "overlay");
    assert_eq!(published["key_id"], KEY_ID);

    let (status, replaced) = call(
        "POST",
        "/admin/config-authority/publish?mode=replace",
        Some(&payload("admin-api.test", "replaced")),
    );
    assert_eq!(status, 200, "{replaced}");
    assert_eq!(replaced["revision"], 2);
    assert_eq!(replaced["mode"], "replace");

    // A rejected payload says so, and says the counter did not move.
    let (status, rejected) = call(
        "POST",
        "/admin/config-authority/publish",
        Some("proxy:\n  admin:\n    enabled: true\n"),
    );
    assert_eq!(status, 400);
    assert_eq!(rejected["code"], "denied_path");
    assert_eq!(rejected["revision_consumed"], false);

    // Register, list, revoke.
    let (status, registered) = call(
        "POST",
        "/admin/config-authority/subscribers",
        Some(r#"{"subscriber_id":"edge-01"}"#),
    );
    assert_eq!(status, 200, "{registered}");
    let token = registered["credential"]
        .as_str()
        .expect("the clear credential, shown once")
        .to_string();
    assert!(token.starts_with("sbca1."), "{token}");
    let credential_id = registered["credential_id"]
        .as_str()
        .expect("a credential id")
        .to_string();
    // The token really works against the running authority.
    assert_eq!(authority.serve_bundle(&fetch(&token, None)).status, 200);

    let (status, listed) = call("GET", "/admin/config-authority/subscribers", None);
    assert_eq!(status, 200);
    assert_eq!(listed["subscriber_count"], 1);
    assert_eq!(listed["subscribers"][0]["subscriber_id"], "edge-01");

    let (status, status_body) = call("GET", "/admin/config-authority/status", None);
    assert_eq!(status, 200);
    assert_eq!(status_body["authority_id"], AUTHORITY_ID);
    assert_eq!(status_body["current_revision"], 2);
    assert_eq!(status_body["previous_revision"], 1);
    assert_eq!(status_body["algorithm"], "ed25519");
    assert_eq!(status_body["bundle_endpoint"], BUNDLE_ENDPOINT_PATH);
    assert!(
        status_body["verifying_keys_file"]
            .as_str()
            .is_some_and(|file| file.contains(KEY_ID)),
        "status must hand the operator the key file subscribers install: {status_body}",
    );
    // The clear credential is never echoed back anywhere.
    assert!(
        !status_body.to_string().contains(&token),
        "no admin response may repeat a minted credential",
    );

    let (status, revoked) = call(
        "POST",
        "/admin/config-authority/subscribers/revoke",
        Some(&format!(r#"{{"credential_id":"{credential_id}"}}"#)),
    );
    assert_eq!(status, 200, "{revoked}");
    assert_eq!(revoked["revoked"], true);
    assert_eq!(authority.serve_bundle(&fetch(&token, None)).status, 403);

    // Rollback republishes revision 1's payload as revision 3, and says
    // where it came from.
    let (status, rolled_back) = call("POST", "/admin/config-authority/rollback", None);
    assert_eq!(status, 200, "{rolled_back}");
    assert_eq!(rolled_back["revision"], 3);
    assert_eq!(rolled_back["restored_from_revision"], 1);
    assert_eq!(rolled_back["replaced_revision"], 2);
    assert_eq!(rolled_back["key_id"], KEY_ID);

    // Method and shape errors are named rather than silently accepted.
    assert_eq!(call("GET", "/admin/config-authority/publish", None).0, 405);
    assert_eq!(call("GET", "/admin/config-authority/rollback", None).0, 405);
    assert_eq!(
        call("POST", "/admin/config-authority/publish", None).1["code"],
        "invalid_payload",
    );
    assert_eq!(
        call(
            "POST",
            "/admin/config-authority/publish?mode=sideways",
            Some("proxy: {}\n"),
        )
        .1["code"],
        "invalid_mode",
    );
    assert_eq!(
        call("POST", "/admin/config-authority/subscribers", Some("{}")).0,
        400,
    );
    assert_eq!(
        call(
            "POST",
            "/admin/config-authority/subscribers/revoke",
            Some("{}")
        )
        .0,
        400,
    );

    sbproxy_core::config_authority::clear_process_authority();

    // With no authority installed, every route says so rather than
    // pretending to work.
    for (method, path) in [
        ("GET", "/admin/config-authority/status"),
        ("GET", "/admin/config-authority/subscribers"),
        ("POST", "/admin/config-authority/publish"),
        ("POST", "/admin/config-authority/rollback"),
    ] {
        let (status, body) = call(method, path, Some("proxy: {}\n"));
        assert_eq!(status, 404, "{path}: {body}");
        assert_eq!(body["code"], "publish_not_configured", "{path}");
    }
}

// --- WOR-2464: subscribers report what they applied -------------------

/// The apply-report headers a subscriber sends, as wire strings.
///
/// Driven over the real listener rather than through `serve_bundle`
/// directly, deliberately: the header names are a contract between two
/// files in two crates, and a test that hands the parsed struct straight
/// to the decision function would keep passing if the listener stopped
/// reading one of them off the wire.
fn apply_headers<'a>(
    status: &'a str,
    revision: &'a str,
    hash: &'a str,
    error: Option<&'a str>,
) -> Vec<(&'a str, &'a str)> {
    let mut headers = vec![
        ("x-sbproxy-config-status", status),
        ("x-sbproxy-applied-revision", revision),
        ("x-sbproxy-applied-hash", hash),
        ("x-sbproxy-fallback-active", "false"),
    ];
    if let Some(error) = error {
        headers.push(("x-sbproxy-config-error", error));
    }
    headers
}

/// One subscriber row out of the status page.
fn subscriber_row(status: &serde_json::Value, id: &str) -> serde_json::Value {
    status["subscribers"]
        .as_array()
        .expect("subscribers")
        .iter()
        .find(|record| record["subscriber_id"] == id)
        .cloned()
        .unwrap_or_else(|| panic!("subscriber {id} is listed"))
}

/// WOR-2464. The authority status endpoint tracked per-subscriber
/// last-**seen** revision, and seen is not applied: a fleet where three
/// nodes fetched r42, refused it, and kept serving r41 looked identical
/// from here to a fleet that applied it cleanly. All four report states
/// in one test, over the real listener, because the page's value is in
/// telling them apart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_status_page_tells_applied_from_fetched_for_every_report_state() {
    let temp = tempfile::tempdir().expect("temp");
    let publish = publish_config(temp.path(), free_port());
    let authority = Arc::new(ConfigAuthority::from_config(&publish).expect("authority"));
    authority
        .publish(&payload("api.test", "authority"), BundleMode::Overlay)
        .expect("publish");
    let addr = serve(Arc::clone(&authority), &publish).await;

    let token = |id: &str| {
        authority
            .register_subscriber(id)
            .expect("register")
            .into_token()
    };
    let clean = token("edge-clean");
    let degraded = token("edge-degraded");
    let refused = token("edge-refused");
    let silent = token("edge-old-build");

    for (credential, headers) in [
        (&clean, apply_headers("applied", "1", "sha-clean", None)),
        (
            &degraded,
            apply_headers("applied_degraded", "1", "sha-clean", None),
        ),
        (
            &refused,
            apply_headers("failed", "0", "", Some("unknown policy type `waf_v3`")),
        ),
    ] {
        let mut sent = vec![("authorization", format!("Bearer {credential}"))];
        sent.extend(
            headers
                .into_iter()
                .map(|(name, value)| (name, value.to_string())),
        );
        let borrowed: Vec<(&str, &str)> = sent
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        let reply = raw_get(addr, BUNDLE_ENDPOINT_PATH, &borrowed).await;
        assert_eq!(reply.status, 200, "the bundle is still served");
    }
    // The old build fetches without any of the new headers. It must be
    // served, and it must not be rendered as having applied anything.
    let reply = raw_get(
        addr,
        BUNDLE_ENDPOINT_PATH,
        &[("authorization", &format!("Bearer {silent}"))],
    )
    .await;
    assert_eq!(reply.status, 200);

    let status = authority.status();

    let clean = subscriber_row(&status, "edge-clean");
    assert_eq!(clean["apply_status"], "applied");
    assert_eq!(clean["applied_revision"], 1);
    assert_eq!(clean["applied_config_hash"], "sha-clean");
    assert_eq!(clean["applied_up_to_date"], true);
    assert_eq!(clean["poll_state"], "recent");

    assert_eq!(
        subscriber_row(&status, "edge-degraded")["apply_status"],
        "applied_degraded",
        "a degraded apply must stay distinguishable from a clean one on the trip upstream",
    );

    let refused = subscriber_row(&status, "edge-refused");
    assert_eq!(refused["apply_status"], "failed");
    assert_eq!(
        refused["applied_revision"], 0,
        "a refusing node keeps naming the revision it is serving, not the one it refused",
    );
    assert_eq!(refused["apply_error"], "unknown policy type `waf_v3`");
    assert_eq!(refused["applied_up_to_date"], false);
    // It was still served, so its *seen* revision moved. That is exactly
    // the pair of facts the ticket exists to separate.
    assert_eq!(refused["last_seen_revision"], 1);

    let silent = subscriber_row(&status, "edge-old-build");
    assert_eq!(
        silent["apply_status"], "unknown",
        "an old subscriber is handled without error and rendered as unknown, never as applied",
    );
    assert!(silent["applied_revision"].is_null());
    assert_eq!(silent["last_seen_revision"], 1, "it was still served");

    // The three numbers that turn a fleet rollback into a decision.
    assert_eq!(status["applied_current_count"], 2);
    assert_eq!(status["apply_failed_count"], 1);
    assert_eq!(status["apply_unknown_count"], 1);
}

/// WOR-2464. A subscriber cannot report a revision higher than the
/// authority has published. That would let one compromised node make the
/// fleet view say a rollout is complete, which is the one answer an
/// operator acts on without checking.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_subscriber_cannot_claim_a_revision_the_authority_never_published() {
    let temp = tempfile::tempdir().expect("temp");
    let publish = publish_config(temp.path(), free_port());
    let authority = Arc::new(ConfigAuthority::from_config(&publish).expect("authority"));
    authority
        .publish(&payload("api.test", "authority"), BundleMode::Overlay)
        .expect("publish");
    let addr = serve(Arc::clone(&authority), &publish).await;
    let credential = authority
        .register_subscriber("edge-liar")
        .expect("register")
        .into_token();

    let bearer = format!("Bearer {credential}");
    let mut headers = vec![("authorization", bearer.as_str())];
    headers.extend(apply_headers("applied", "9999", "sha-forged", None));
    let reply = raw_get(addr, BUNDLE_ENDPOINT_PATH, &headers).await;
    assert_eq!(
        reply.status, 200,
        "the node is still served: the report is discarded, not the bundle",
    );

    let status = authority.status();
    assert_eq!(
        subscriber_row(&status, "edge-liar")["apply_status"],
        "unknown",
        "an over-claim leaves the record as it was rather than poisoning the fleet view",
    );
    assert_eq!(status["applied_current_count"], 0);
    assert_eq!(status["apply_unknown_count"], 1);
}

/// WOR-2464. The report rides the existing bundle fetch, so it carries
/// the existing subscriber credential and adds no new auth surface. An
/// unauthenticated or forged request cannot plant one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_apply_report_needs_the_subscriber_credential_like_the_fetch_it_rides_on() {
    let temp = tempfile::tempdir().expect("temp");
    let publish = publish_config(temp.path(), free_port());
    let authority = Arc::new(ConfigAuthority::from_config(&publish).expect("authority"));
    authority
        .publish(&payload("api.test", "authority"), BundleMode::Overlay)
        .expect("publish");
    let addr = serve(Arc::clone(&authority), &publish).await;
    let credential = authority
        .register_subscriber("edge-01")
        .expect("register")
        .into_token();

    let anonymous = raw_get(
        addr,
        BUNDLE_ENDPOINT_PATH,
        &apply_headers("applied", "1", "sha-forged", None),
    )
    .await;
    assert_eq!(
        anonymous.status, 401,
        "no credential, no fetch and no report",
    );

    let mut forged = vec![("authorization", "Bearer sbca1.not.a.real.token")];
    forged.extend(apply_headers("applied", "1", "sha-forged", None));
    assert_eq!(
        raw_get(addr, BUNDLE_ENDPOINT_PATH, &forged).await.status,
        401
    );

    assert_eq!(
        subscriber_row(&authority.status(), "edge-01")["apply_status"],
        "unknown",
        "neither refused request may have planted a report against the registered subscriber",
    );

    // And the credential that is real still works, which proves the two
    // refusals above were about the credential rather than the headers.
    let bearer = format!("Bearer {credential}");
    let mut real = vec![("authorization", bearer.as_str())];
    real.extend(apply_headers("applied", "1", "sha-real", None));
    assert_eq!(raw_get(addr, BUNDLE_ENDPOINT_PATH, &real).await.status, 200);
    assert_eq!(authority.status()["applied_current_count"], 1);
}

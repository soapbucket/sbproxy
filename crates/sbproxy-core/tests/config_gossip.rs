// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The gossip accelerator, end to end: an authority announces a revision
//! into typed cluster state, mesh-member subscribers pull on the hint, and a
//! non-mesh subscriber converges on polling alone.
//!
//! # How three nodes fit in one process
//!
//! Three `MeshNode`s built in one process do not gossip with each other:
//! each owns its own typed-state store and its own hash ring, so a value
//! published through one is invisible to the others. Standing up real
//! transports and letting SWIM converge would take sockets, ports, and
//! seconds, and would test the mesh rather than this module. So the three
//! handles share one store, which is the state a converged cluster arrives
//! at, and the only property any case here depends on. Cross-node routing of
//! typed state has its own coverage in `sbproxy-mesh`.
//!
//! # What is deliberately not asserted
//!
//! Nothing here proves gossip is *required*, because it must not be. Every
//! case that applies a bundle applies it through the ordinary HTTP fetch and
//! the ordinary verify-merge-compile path; gossip only decides when that
//! happens.
//!
//! Every test here runs one at a time behind [`SERIAL`]. Some drive the
//! process-wide reload transaction, and all of them assert on deltas of
//! process-global Prometheus counters, which two concurrent cases would
//! observe in each other.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use sbproxy_config::config_bundle::{BundleMode, ConfigBundle, ConfigBundleSigner};
use sbproxy_config::types::{ConfigAuthorityConfig, ConfigAuthorityUpstreamConfig};
use sbproxy_core::config_gossip::{
    self, AnnounceOutcome, ConfigGossipWatcher, CycleTrigger, GossipProbe, RevisionAnnouncement,
    ANNOUNCEMENT_KEY, ANNOUNCEMENT_NAMESPACE, ANNOUNCEMENT_SCHEMA_VERSION, ANNOUNCEMENT_TTL,
};
use sbproxy_core::config_subscriber::{ConfigSubscriber, CycleResult};
use sbproxy_mesh::{ClusterHandle, ClusterIdentity, ClusterNodeRole, ClusterStateRead, MeshNode};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

/// Serializes every test in this binary: the reload transaction and the
/// default Prometheus registry are both process-wide.
static SERIAL: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

/// Shared secret behind every fixture bundle. Shared-secret signing keeps
/// this file free of a crate the package does not already depend on, and the
/// Ed25519 path is covered in `sbproxy-config`.
const SECRET: [u8; 32] = [9u8; 32];

/// Key ID every fixture bundle is signed under.
const KEY_ID: &str = "lab-shared";

/// Probe cadence the cases use, so a hint lands in milliseconds rather than
/// the production two seconds.
const FAST_PROBE: Duration = Duration::from_millis(100);

// --- cluster fixtures -------------------------------------------------

fn identity(node_id: &str, role: ClusterNodeRole) -> ClusterIdentity {
    let identity = ClusterIdentity {
        cluster_id: "config-gossip-test".to_string(),
        node_id: node_id.to_string(),
        roles: BTreeSet::from([role]),
        labels: BTreeMap::new(),
        peer_address: None,
        model_endpoint: None,
    };
    identity.validate().expect("fixture identity validates");
    identity
}

/// One authority handle and two gateway handles that share a typed-state
/// store. See the module docs for why they share rather than gossip.
fn meshed() -> [ClusterHandle; 3] {
    let authority_node = MeshNode::new("authority-a".to_string(), Vec::new(), 32);
    let shared = authority_node.distributed_cache();

    let mut gateway_a = MeshNode::new("gateway-a".to_string(), Vec::new(), 32);
    gateway_a.distributed_cache = Arc::clone(&shared);
    let mut gateway_b = MeshNode::new("gateway-b".to_string(), Vec::new(), 32);
    gateway_b.distributed_cache = Arc::clone(&shared);

    [
        ClusterHandle::distributed(
            identity("authority-a", ClusterNodeRole::Authority),
            Arc::new(authority_node),
        )
        .expect("authority handle"),
        ClusterHandle::distributed(
            identity("gateway-a", ClusterNodeRole::Gateway),
            Arc::new(gateway_a),
        )
        .expect("gateway-a handle"),
        ClusterHandle::distributed(
            identity("gateway-b", ClusterNodeRole::Gateway),
            Arc::new(gateway_b),
        )
        .expect("gateway-b handle"),
    ]
}

fn watcher(handle: &ClusterHandle) -> ConfigGossipWatcher {
    ConfigGossipWatcher::from_handle(handle.clone())
        .expect("a mesh member has a watcher")
        .with_probe_interval(FAST_PROBE)
}

// --- bundle fixtures --------------------------------------------------

fn now_unix_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after the epoch")
            .as_millis(),
    )
    .expect("unix millis fit u64")
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

/// An authority payload adding one origin, so an applied overlay is visible
/// in the live pipeline.
fn bundle_payload(host: &str) -> String {
    format!(
        r#"
origins:
  "{host}":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: authority
"#
    )
}

fn sign(revision: u64, payload: &str) -> sbproxy_config::SignedConfigBundle {
    let signer = ConfigBundleSigner::shared_secret(KEY_ID, SECRET.to_vec()).expect("signer");
    let bundle = ConfigBundle::new(
        "authority-test",
        revision,
        BundleMode::Overlay,
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
    std::fs::write(
        &path,
        format!(
            r#"{{"{KEY_ID}": {{"algorithm": "hmac_sha256", "key": "{}"}}}}"#,
            BASE64.encode(SECRET),
        ),
    )
    .expect("write keys");
    path
}

/// The upstream block under test. Built as a struct literal so a new field
/// cannot be added without this file deciding what it means.
fn upstream(
    url: &str,
    dir: &Path,
    keys: &Path,
    poll_interval_secs: u64,
) -> ConfigAuthorityUpstreamConfig {
    let upstream = ConfigAuthorityUpstreamConfig {
        url: url.to_string(),
        mode: BundleMode::Overlay,
        subscriber_id: "edge-01".to_string(),
        credential: None,
        verifying_keys_file: keys.display().to_string(),
        poll_interval_secs,
        cache_path: dir.join("config-bundle.json").display().to_string(),
        // Must be at least the poll interval, and the long-interval cases use
        // the largest interval the schema accepts.
        max_staleness_secs: sbproxy_config::types::MAX_CONFIG_AUTHORITY_STALENESS_SECS,
        require_bundle_on_boot: None,
        // The stub authority speaks plaintext, and the signature is what
        // actually protects the payload.
        allow_insecure_http: true,
        allow_shared_secret_keys: true,
    };
    upstream.validate().expect("fixture upstream validates");
    ConfigAuthorityConfig {
        upstream: Some(upstream.clone()),
        publish: None,
    }
    .validate()
    .expect("fixture block validates");
    upstream
}

// --- stub authority ---------------------------------------------------

struct StubState {
    body: Vec<u8>,
    requests: usize,
}

/// A stub config authority: one conditional GET, one response. Hand-rolled
/// for the same reason the subscriber tests hand-roll theirs, and it counts
/// requests so a case can prove a cycle did not fetch.
struct StubAuthority {
    url: String,
    state: Arc<Mutex<StubState>>,
}

impl StubAuthority {
    async fn start(body: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stub");
        let addr: SocketAddr = listener.local_addr().expect("stub addr");
        let state = Arc::new(Mutex::new(StubState { body, requests: 0 }));
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
                    let body = {
                        let mut state = state.lock().expect("stub state");
                        state.requests += 1;
                        state.body.clone()
                    };
                    let head = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: \
                         {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = socket.write_all(head.as_bytes()).await;
                    let _ = socket.write_all(&body).await;
                    let _ = socket.flush().await;
                });
            }
        });
        Self {
            url: format!("http://{addr}"),
            state,
        }
    }

    fn requests(&self) -> usize {
        self.state.lock().expect("stub state").requests
    }
}

// --- observation ------------------------------------------------------

fn serves(host: &str) -> bool {
    sbproxy_core::reload::current_pipeline()
        .config
        .origins
        .iter()
        .any(|origin| origin.hostname == host)
}

fn gossip_total(outcome: &str) -> u64 {
    metric_value("sbproxy_config_bundle_gossip_total", ("outcome", outcome))
}

fn announce_total(result: &str) -> u64 {
    metric_value(
        "sbproxy_config_authority_announce_total",
        ("result", result),
    )
}

/// One `{label}` series off the default registry, so a case can prove the
/// metric is incremented at the point of use rather than merely declared.
fn metric_value(name: &str, label: (&str, &str)) -> u64 {
    for family in prometheus::gather() {
        if family.name() != name {
            continue;
        }
        for metric in family.get_metric() {
            let matches = metric
                .get_label()
                .iter()
                .any(|pair| pair.name() == label.0 && pair.value() == label.1);
            if matches {
                return metric.get_counter().value() as u64;
            }
        }
    }
    0
}

/// A subscriber pointed at `stub`, with a fresh cursor.
fn subscriber(dir: &Path, stub: &StubAuthority, poll_interval_secs: u64) -> ConfigSubscriber {
    let config_path = dir.join("sb.yml");
    std::fs::write(&config_path, local_config("local.test")).expect("write local config");
    let keys = write_keys(dir);
    ConfigSubscriber::new(
        config_path.to_str().expect("utf-8 path"),
        &upstream(&stub.url, dir, &keys, poll_interval_secs),
    )
    .expect("subscriber")
}

// --- tests ------------------------------------------------------------

#[tokio::test]
async fn an_announcement_round_trips_and_carries_no_config_body() {
    let _serial = SERIAL.lock().await;
    let [authority, gateway, _] = meshed();
    let signed = sign(42, &bundle_payload("bundle.test"));
    let announcement = RevisionAnnouncement {
        revision: 42,
        content_digest: signed.bundle.content_digest.clone(),
        authority_id: "acme-prod".to_string(),
    };

    let published = announce_total("published");
    assert_eq!(
        config_gossip::announce_on(&authority, &announcement).await,
        AnnounceOutcome::Published,
    );
    assert_eq!(
        announce_total("published"),
        published + 1,
        "the announce counter has to move at the point of use",
    );

    // A peer classifies the same announcement against its own cursor.
    let watcher = watcher(&gateway);
    assert_eq!(watcher.probe(41).await, GossipProbe::Hint);
    assert_eq!(watcher.probe(42).await, GossipProbe::Stale);
    assert_eq!(watcher.probe(43).await, GossipProbe::Stale);

    // The envelope carries three scalars. Not the bundle, not the YAML: the
    // size of a fleet's configuration must never become the size of a gossip
    // message.
    let ClusterStateRead::Present(record) = gateway
        .read_state::<serde_json::Value>(
            ANNOUNCEMENT_NAMESPACE,
            ANNOUNCEMENT_KEY,
            ANNOUNCEMENT_SCHEMA_VERSION,
        )
        .await
    else {
        panic!("the announcement must be readable by a peer");
    };
    let mut keys: Vec<&str> = record
        .payload
        .as_object()
        .expect("the payload is a JSON object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["authority_id", "content_digest", "revision"]);
    assert_eq!(record.generation, 42, "the revision fences the write");

    // Bounded expiry, so a dead authority's revision does not sit in cluster
    // state describing itself as current forever.
    let lifetime = record.expires_at_unix_ms - record.published_at_unix_ms;
    assert!(lifetime > 0);
    assert!(
        lifetime <= u64::try_from(ANNOUNCEMENT_TTL.as_millis()).expect("TTL fits u64") + 1_000,
        "announcement lifetime {lifetime}ms exceeds the declared TTL",
    );
}

#[tokio::test]
async fn a_local_handle_is_not_a_mesh_member_so_it_neither_watches_nor_announces() {
    let _serial = SERIAL.lock().await;
    let local =
        ClusterHandle::local(identity("solo", ClusterNodeRole::Gateway)).expect("local handle");

    // This is the whole of the non-mesh gate: no watcher, so a subscriber on
    // such a node runs the plain interval sleep and nothing else.
    assert!(ConfigGossipWatcher::from_handle(local.clone()).is_none());

    let not_clustered = announce_total("not_clustered");
    let announcement = RevisionAnnouncement {
        revision: 7,
        content_digest: format!("sha256:{}", "a".repeat(64)),
        authority_id: "acme-prod".to_string(),
    };
    assert_eq!(
        config_gossip::announce_on(&local, &announcement).await,
        AnnounceOutcome::NotClustered,
    );
    assert_eq!(announce_total("not_clustered"), not_clustered + 1);

    // Nothing was written: a local handle's typed state reaches this process
    // and nobody else, so spending a generation on it would tell us only
    // what we already knew.
    assert!(matches!(
        local
            .read_state::<RevisionAnnouncement>(
                ANNOUNCEMENT_NAMESPACE,
                ANNOUNCEMENT_KEY,
                ANNOUNCEMENT_SCHEMA_VERSION,
            )
            .await,
        ClusterStateRead::Missing
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stale_gossiped_revision_causes_no_fetch() {
    let _serial = SERIAL.lock().await;
    let dir = tempfile::tempdir().expect("temp dir");
    let signed = sign(5, &bundle_payload("bundle.test"));
    let stub = StubAuthority::start(signed.to_json().expect("encode")).await;
    let mut subscriber = subscriber(dir.path(), &stub, 5);

    // Apply revision 5, so the cursor sits exactly where the announcement
    // will point.
    assert_eq!(subscriber.poll_once().await, CycleResult::Applied);
    let fetched_once = stub.requests();
    assert_eq!(subscriber.cursor().revision, 5);

    let [authority, gateway, _] = meshed();
    assert_eq!(
        config_gossip::announce_on(
            &authority,
            &RevisionAnnouncement {
                revision: 5,
                content_digest: signed.bundle.content_digest.clone(),
                authority_id: "acme-prod".to_string(),
            },
        )
        .await,
        AnnounceOutcome::Published,
    );
    subscriber.attach_gossip(watcher(&gateway));

    // The wait must run to its own end rather than being cut short, so the
    // timeout expiring is the assertion. With a 100ms probe cadence that is
    // roughly a dozen probes, every one of them classified stale.
    let stale_before = gossip_total("stale");
    let cut_short =
        tokio::time::timeout(Duration::from_millis(1_200), subscriber.await_next_cycle()).await;
    assert!(
        cut_short.is_err(),
        "an announcement at the local cursor must not shorten the interval",
    );
    assert!(
        gossip_total("stale") > stale_before,
        "the probes did happen; they were classified stale",
    );
    assert_eq!(
        stub.requests(),
        fetched_once,
        "a stale announcement must cost no fetch at all",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hint_the_pull_cannot_satisfy_buys_exactly_one_extra_fetch() {
    let _serial = SERIAL.lock().await;
    // The stub serves revision 3 while a peer announces revision 99. The hint
    // is genuine, the pull that follows it is honest, and it lands the cursor
    // on 3, so the announcement is still above the cursor on the next probe.
    // Nothing about that is fixable from here: only one extra fetch is
    // allowed to come of it, and then this node is back on its interval.
    let dir = tempfile::tempdir().expect("temp dir");
    let signed = sign(3, &bundle_payload("bundle.test"));
    let stub = StubAuthority::start(signed.to_json().expect("encode")).await;
    let mut subscriber = subscriber(dir.path(), &stub, 5);

    assert_eq!(subscriber.poll_once().await, CycleResult::Applied);
    assert_eq!(subscriber.cursor().revision, 3);
    let fetches = stub.requests();

    let [authority, gateway, _] = meshed();
    assert_eq!(
        config_gossip::announce_on(
            &authority,
            &RevisionAnnouncement {
                revision: 99,
                content_digest: format!("sha256:{}", "b".repeat(64)),
                authority_id: "acme-prod".to_string(),
            },
        )
        .await,
        AnnounceOutcome::Published,
    );
    subscriber.attach_gossip(watcher(&gateway));

    // First hint: acted on, one extra fetch, and the authority still has
    // nothing newer than revision 3 to give.
    assert_eq!(
        subscriber.await_next_cycle().await,
        CycleTrigger::Gossip,
        "the first hint above the cursor has to be acted on",
    );
    assert_eq!(subscriber.poll_once().await, CycleResult::NotModified);
    assert_eq!(subscriber.cursor().revision, 3);
    assert_eq!(stub.requests(), fetches + 1);

    // Second wait: the same hint is still there, and it is now ignored, so
    // the wait runs to the end of the interval rather than the probe cadence.
    let cut_short =
        tokio::time::timeout(Duration::from_millis(1_200), subscriber.await_next_cycle()).await;
    assert!(
        cut_short.is_err(),
        "a hint that already failed to move the cursor must not shorten the interval again",
    );
    assert_eq!(
        stub.requests(),
        fetches + 1,
        "the accelerator must not turn the probe cadence into the fetch cadence",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_mesh_subscribers_beat_the_interval_and_a_non_mesh_one_converges_on_polling() {
    let _serial = SERIAL.lock().await;
    let signed = sign(9, &bundle_payload("bundle.test"));
    let stub = StubAuthority::start(signed.to_json().expect("encode")).await;

    let [authority, gateway_a, gateway_b] = meshed();
    assert_eq!(
        config_gossip::announce_on(
            &authority,
            &RevisionAnnouncement {
                revision: 9,
                content_digest: signed.bundle.content_digest.clone(),
                authority_id: "acme-prod".to_string(),
            },
        )
        .await,
        AnnounceOutcome::Published,
    );

    // Both mesh members poll on the longest interval the schema accepts, so
    // an apply inside a few seconds can only have come from the hint.
    let long_interval = sbproxy_config::types::MAX_CONFIG_AUTHORITY_POLL_SECS;
    let hints_before = gossip_total("hint");
    for (label, member) in [("gateway-a", &gateway_a), ("gateway-b", &gateway_b)] {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut member_subscriber = subscriber(dir.path(), &stub, long_interval);
        member_subscriber.attach_gossip(watcher(member));
        assert!(member_subscriber.is_gossip_accelerated(), "{label}");

        let started = Instant::now();
        assert_eq!(
            member_subscriber.await_next_cycle().await,
            CycleTrigger::Gossip,
            "{label} must wake on the hint, not the interval",
        );
        let waited = started.elapsed();
        assert!(
            waited < Duration::from_secs(5),
            "{label} waited {waited:?}; the hint must land in seconds, not in the {long_interval}s \
             interval",
        );

        // The pull is the ordinary cycle: fetched over HTTP, verified,
        // merged, compiled, and applied. The hint decided when, not what.
        assert_eq!(
            member_subscriber.poll_once().await,
            CycleResult::Applied,
            "{label}"
        );
        assert_eq!(member_subscriber.cursor().revision, 9, "{label}");
        assert!(serves("bundle.test"), "{label}");
        assert!(
            serves("local.test"),
            "{label} overlay must keep the local origin"
        );
    }
    assert!(
        gossip_total("hint") >= hints_before + 2,
        "each mesh member's early pull has to be counted",
    );

    // The third node is in no cluster at all: no watcher, no cluster read,
    // and it still converges. This is the required path, and it is the one
    // every managed-service subscriber is on.
    //
    // This wait is the reason the test runs for about five seconds, and it is
    // load-bearing. `MIN_CONFIG_AUTHORITY_POLL_SECS` is 5 and `upstream()`
    // validates every fixture against the real schema, so a shorter interval
    // would mean either weakening that fixture guard or lowering a shipped
    // config bound to suit a test. Neither is worth under a second, so the test
    // sits at the schema minimum and waits.
    const OUTSIDER_INTERVAL_SECS: u64 = sbproxy_config::types::MIN_CONFIG_AUTHORITY_POLL_SECS;
    let dir = tempfile::tempdir().expect("temp dir");
    let mut outsider = subscriber(dir.path(), &stub, OUTSIDER_INTERVAL_SECS);
    assert!(
        !outsider.is_gossip_accelerated(),
        "a non-mesh subscriber must hold no watcher",
    );

    let started = Instant::now();
    assert_eq!(outsider.await_next_cycle().await, CycleTrigger::Interval);
    let waited = started.elapsed();
    // Four fifths of the interval: the jitter subtracts up to a fifth, so this
    // is the same relationship the 5s form asserted with its floor of 4s.
    assert!(
        waited >= Duration::from_secs(OUTSIDER_INTERVAL_SECS) * 4 / 5,
        "the non-mesh subscriber waited only {waited:?}; it must sit out its jittered interval",
    );
    assert_eq!(outsider.poll_once().await, CycleResult::Applied);
    assert_eq!(outsider.cursor().revision, 9);
    assert!(serves("bundle.test"));
}

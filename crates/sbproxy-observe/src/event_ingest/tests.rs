//! The ingest sinks, driven against an in-process NATS server that speaks
//! the real protocol.
//!
//! A fake transport would prove the batching and leave the wire format
//! untested, and the wire format is the part with no library behind it. So
//! the server here is a socket that reads `CONNECT`, `PING`, and `PUB`
//! exactly as the protocol specifies them, and every assertion is about
//! what actually went down the wire.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use sbproxy_platform::storage::EmbeddedKvStore;

use super::*;
use crate::events::EventType;
use crate::request_event::RequestEvent;

#[test]
fn nats_worker_does_not_initialize_an_http_client() {
    let target = IngestTarget::Nats {
        address: "127.0.0.1:4222".into(),
        subject_prefix: "events".into(),
        token: None,
    };
    assert!(http_client_for_target(&target).is_none());
}

/// What the fake broker saw.
#[derive(Debug, Default)]
struct Observed {
    connect: Option<String>,
    published: Vec<(String, String)>,
    pings: usize,
}

/// A NATS server that speaks enough of the core protocol to be worth
/// testing against: the `INFO` greeting, `CONNECT`, `PING`/`PONG`, and
/// `PUB` with its length-prefixed payload.
struct FakeNats {
    address: String,
    observed: Arc<Mutex<Observed>>,
}

/// How the fake broker answers a `PING`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PingBehavior {
    /// Answer every ping with `PONG`.
    Pong,
    /// Answer every ping with `-ERR`, which is what a rejected `CONNECT`
    /// looks like.
    Refuse,
    /// Answer the `CONNECT` ping and then go silent, which is what a broker
    /// that took the publishes and then stalled looks like.
    PongThenSilent,
}

impl FakeNats {
    async fn start(refuse: bool) -> Self {
        Self::start_with(
            if refuse {
                PingBehavior::Refuse
            } else {
                PingBehavior::Pong
            },
            r#"{"server_id":"fake","version":"2.10.0"}"#,
        )
        .await
    }

    /// Start a broker whose `INFO` greeting is exactly `info`, so a test can
    /// say what the server advertises.
    async fn start_with_info(refuse: bool, info: &'static str) -> Self {
        Self::start_with(
            if refuse {
                PingBehavior::Refuse
            } else {
                PingBehavior::Pong
            },
            info,
        )
        .await
    }

    async fn start_with(refuse: PingBehavior, info: &'static str) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("addr").to_string();
        let observed = Arc::new(Mutex::new(Observed::default()));
        let server_observed = Arc::clone(&observed);
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let observed = Arc::clone(&server_observed);
                tokio::spawn(async move {
                    serve(socket, observed, refuse, info).await;
                });
            }
        });
        Self { address, observed }
    }

    fn observed(&self) -> Observed {
        let guard = self.observed.lock().unwrap_or_else(|e| e.into_inner());
        Observed {
            connect: guard.connect.clone(),
            published: guard.published.clone(),
            pings: guard.pings,
        }
    }
}

async fn serve(
    mut socket: tokio::net::TcpStream,
    observed: Arc<Mutex<Observed>>,
    refuse: PingBehavior,
    info: &'static str,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    if socket
        .write_all(format!("INFO {info}\r\n").as_bytes())
        .await
        .is_err()
    {
        return;
    }

    let mut buffer: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut pings_on_this_connection = 0usize;
    loop {
        // Consume whole protocol messages out of `buffer`.
        while let Some(index) = buffer.windows(2).position(|window| window == b"\r\n") {
            let line = String::from_utf8_lossy(&buffer[..index]).to_string();
            let consumed = index + 2;
            let mut parts = line.split_whitespace();
            match parts.next().unwrap_or("") {
                "CONNECT" => {
                    buffer.drain(..consumed);
                    observed.lock().unwrap_or_else(|e| e.into_inner()).connect =
                        Some(line.trim_start_matches("CONNECT ").to_string());
                }
                "PING" => {
                    buffer.drain(..consumed);
                    observed.lock().unwrap_or_else(|e| e.into_inner()).pings += 1;
                    pings_on_this_connection += 1;
                    let answer: Option<&[u8]> = match refuse {
                        PingBehavior::Refuse => Some(b"-ERR 'Authorization Violation'\r\n"),
                        PingBehavior::Pong => Some(b"PONG\r\n"),
                        // Counted per connection, not per process: a redial
                        // has to get its `CONNECT` answered, or the resend
                        // this test is watching for never gets to happen and
                        // the test would pass for the wrong reason.
                        PingBehavior::PongThenSilent if pings_on_this_connection == 1 => {
                            Some(b"PONG\r\n")
                        }
                        PingBehavior::PongThenSilent => None,
                    };
                    if let Some(answer) = answer {
                        if socket.write_all(answer).await.is_err() {
                            return;
                        }
                    }
                }
                "PUB" => {
                    let subject = parts.next().unwrap_or("").to_string();
                    let length: usize = parts.next().and_then(|n| n.parse().ok()).unwrap_or(0);
                    // The payload plus its own trailing CRLF has to be
                    // present before this message can be consumed.
                    if buffer.len() < consumed + length + 2 {
                        break;
                    }
                    let payload =
                        String::from_utf8_lossy(&buffer[consumed..consumed + length]).to_string();
                    buffer.drain(..consumed + length + 2);
                    observed
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .published
                        .push((subject, payload));
                }
                _ => {
                    buffer.drain(..consumed);
                }
            }
        }
        match socket.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
        }
    }
}

fn temp_path() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}/sbproxy_ingest_test_{}_{}.redb",
        std::env::temp_dir().display(),
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

fn event(workspace: &str) -> RequestEvent {
    let mut event = RequestEvent::new_started(
        "example.com".to_string(),
        ulid::Ulid::new(),
        workspace.to_string(),
    );
    event.event_type = EventType::RequestCompleted;
    event
}

async fn eventually(mut check: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if check() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    check()
}

/// The wire format, end to end, against a server that parses it the way
/// the protocol specifies rather than the way this code writes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_batch_reaches_a_real_nats_socket_as_pub_frames() {
    let broker = FakeNats::start(false).await;
    let sink = EventIngest::start(
        IngestTarget::Nats {
            address: broker.address.clone(),
            subject_prefix: "sb.events".into(),
            token: Some("s3cret".into()),
        },
        16,
        None,
    )
    .expect("sink");

    sink.publish(event("acme"));
    sink.publish(event("globex"));

    assert!(
        eventually(|| broker.observed().published.len() >= 2).await,
        "both events should have reached the broker"
    );
    let observed = broker.observed();
    let subjects: Vec<&str> = observed
        .published
        .iter()
        .map(|(subject, _)| subject.as_str())
        .collect();
    assert!(subjects.contains(&"sb.events.acme.request_completed"));
    assert!(subjects.contains(&"sb.events.globex.request_completed"));
    assert!(
        observed.published[0].1.contains("\"workspace_id\""),
        "the payload is the serialized request event"
    );
    assert!(
        observed
            .connect
            .as_deref()
            .is_some_and(|c| c.contains("s3cret")),
        "the token has to reach CONNECT, or an authenticated broker refuses"
    );
    assert!(
        observed.pings >= 2,
        "one ping confirms the connect and one flushes the batch"
    );

    drop(sink);
}

/// The subject tree is the only place a caller-influenced value reaches a
/// routing decision. A workspace id carrying a dot would create a subject
/// one level deeper than intended, and one carrying `>` would name a
/// wildcard, so a subscriber filtering `sb.events.acme.>` would receive
/// another workspace's traffic.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hostile_workspace_id_cannot_reshape_the_subject_tree() {
    let broker = FakeNats::start(false).await;
    let sink = EventIngest::start(
        IngestTarget::Nats {
            address: broker.address.clone(),
            subject_prefix: "sb.events".into(),
            token: None,
        },
        16,
        None,
    )
    .expect("sink");

    sink.publish(event("acme.internal.>"));
    sink.publish(event("has space*"));

    assert!(eventually(|| broker.observed().published.len() >= 2).await);
    for (subject, _) in broker.observed().published {
        let tokens: Vec<&str> = subject.split('.').collect();
        assert_eq!(
            tokens.len(),
            4,
            "prefix plus exactly one workspace token plus one type token: {subject}"
        );
        assert!(
            !subject.contains('>') && !subject.contains('*') && !subject.contains(' '),
            "no wildcard or separator may survive into the subject: {subject}"
        );
    }

    drop(sink);
}

/// A broker that refuses the connect must be a counted failure rather than
/// a socket the sink keeps writing into. Without the ping round trip on
/// connect, a rejected `CONNECT` looks identical to a good one until the
/// server closes the socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_connect_is_a_failure_rather_than_a_silent_hole() {
    let broker = FakeNats::start(true).await;
    let sink = EventIngest::start(
        IngestTarget::Nats {
            address: broker.address.clone(),
            subject_prefix: "sb.events".into(),
            token: Some("wrong".into()),
        },
        16,
        None,
    )
    .expect("sink");

    sink.publish(event("acme"));
    assert!(
        eventually(|| broker.observed().pings >= 1).await,
        "the connect ping should have been sent"
    );
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        broker.observed().published.is_empty(),
        "nothing may be published over a connection the server refused"
    );

    drop(sink);
}

/// The checkpoint that replaces the Postgres watermark table. An operator
/// reconciling their warehouse needs a position that survives a restart,
/// and one row is not a reason to run a database.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_delivery_watermark_survives_a_restart() {
    let path = temp_path();
    let broker = FakeNats::start(false).await;

    {
        let store: Arc<dyn PersistentKv> =
            Arc::new(EmbeddedKvStore::open(&path, "event_ingest").expect("open"));
        let sink = EventIngest::start(
            IngestTarget::Nats {
                address: broker.address.clone(),
                subject_prefix: "sb.events".into(),
                token: None,
            },
            16,
            Some(store),
        )
        .expect("sink");
        sink.publish(event("acme"));
        assert!(eventually(|| !broker.observed().published.is_empty()).await);
        drop(sink);
    }

    let store = EmbeddedKvStore::open(&path, "event_ingest").expect("reopen");
    let namespace = sbproxy_platform::storage::KvNamespace::new(WATERMARK_NAMESPACE).expect("ns");
    let entry = store
        .get(&namespace, WATERMARK_KEY)
        .await
        .expect("read")
        .expect("a watermark was written");
    let watermark: Watermark = serde_json::from_slice(&entry.value).expect("decode");
    assert_eq!(watermark.target, "nats");
    assert_eq!(watermark.delivered_total, 1);
    assert!(watermark.last_timestamp_ms > 0);
    assert!(!watermark.last_request_id.is_empty());

    std::fs::remove_file(&path).ok();
}

/// NATS answers a `PUB` past `max_payload` with `-ERR` and then closes the
/// connection, so one oversized event used to cost the 255 healthy events
/// sharing its batch, then cost them again on the resend, then again on the
/// next batch carrying a neighbor like it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_oversized_event_is_skipped_rather_than_killing_its_batch() {
    let broker = FakeNats::start_with_info(
        false,
        r#"{"server_id":"fake","version":"2.10.0","max_payload":512}"#,
    )
    .await;

    let sink = EventIngest::start(
        IngestTarget::Nats {
            address: broker.address.clone(),
            subject_prefix: "sb.events".into(),
            token: None,
        },
        16,
        None,
    )
    .expect("sink");

    let mut oversized = event("acme");
    oversized.error_class = Some("x".repeat(4096));
    sink.publish(oversized);
    sink.publish(event("acme"));

    assert!(
        eventually(|| broker.observed().published.len() == 1).await,
        "the healthy event has to land"
    );
    let published = broker.observed().published;
    assert_eq!(
        published.len(),
        1,
        "and the oversized one has to be skipped"
    );
    assert!(published[0].1.len() <= 512);

    drop(sink);
}

/// `docs/event-ingest.md` says out loud that this is at-most-once, and the
/// window that made it false is a batch whose write completed and whose
/// acknowledgement did not: NATS processes commands in order, so the server
/// already has the publishes, and resending them is how 256 events become
/// 512 rows in a warehouse with no dedup.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_batch_the_broker_took_is_not_resent_when_its_acknowledgement_is_lost() {
    let broker = FakeNats::start_with(
        PingBehavior::PongThenSilent,
        r#"{"server_id":"fake","version":"2.10.0"}"#,
    )
    .await;

    // The connection is built here rather than through `EventIngest::start`
    // so the flush window can be shortened on the connection this test
    // owns. Waiting out the real five-second window would put the only
    // multi-second sleep in the crate on every run of the lane, and a
    // process-global override would hand a concurrently running test the
    // short window under any runner that shares a process.
    let mut connection = Some(
        NatsConnection::connect(&broker.address, None)
            .await
            .expect("the stub answers the CONNECT ping"),
    );
    if let Some(live) = connection.as_mut() {
        live.flush_timeout = std::time::Duration::from_millis(150);
    }
    let mut dialed = true;

    // The stub goes silent after the CONNECT ping, so the publishes land
    // and the acknowledgement never does.
    let delivered = publish_to_nats(
        &mut connection,
        &mut dialed,
        &broker.address,
        "sb.events",
        None,
        &[event("acme")],
    )
    .await;

    assert!(
        delivered,
        "a batch the server took is delivered, not an error, even with no acknowledgement"
    );
    assert_eq!(
        broker.observed().published.len(),
        1,
        "a batch the broker already took must not be resent"
    );
    assert!(
        connection.is_none(),
        "the connection is dropped, so the next batch redials"
    );
}

/// `docs/event-ingest.md` and `docs/metrics-stability.md` both sell
/// `reconnected` as the broker-cycling signal. The version this replaces
/// held "have we dialed" in a local of `publish_to_nats`, reset on every
/// call, so the common case (enter with a stale connection, fail on
/// iteration 0, redial on iteration 1) never counted and the series read
/// zero for exactly the event it names.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_redial_between_batches_counts_as_a_reconnect() {
    let broker = FakeNats::start(false).await;
    let mut connection: Option<NatsConnection> = None;
    let mut dialed = false;

    let connected = ingest_ops("nats", "connected");
    let reconnected = ingest_ops("nats", "reconnected");

    assert!(
        publish_to_nats(
            &mut connection,
            &mut dialed,
            &broker.address,
            "sb.events",
            None,
            &[event("acme")],
        )
        .await
    );
    assert_eq!(
        ingest_ops("nats", "connected"),
        connected + 1,
        "the first dial is a connect, not a reconnect"
    );
    assert_eq!(ingest_ops("nats", "reconnected"), reconnected);

    // The broker went away between batches: the worker enters the next call
    // holding a connection that is no longer usable.
    drop(connection.take());
    assert!(
        publish_to_nats(
            &mut connection,
            &mut dialed,
            &broker.address,
            "sb.events",
            None,
            &[event("acme")],
        )
        .await
    );
    assert_eq!(
        ingest_ops("nats", "reconnected"),
        reconnected + 1,
        "a dial on a later batch is the reconnect the docs point operators at"
    );
    assert_eq!(ingest_ops("nats", "connected"), connected + 1);
}

/// One `sbproxy_event_ingest_events_total` series off the default registry.
fn ingest_ops(target: &str, outcome: &str) -> u64 {
    for family in prometheus::gather() {
        if family.name() != "sbproxy_event_ingest_events_total" {
            continue;
        }
        for metric in family.get_metric() {
            let labels = metric.get_label();
            let has = |name: &str, want: &str| {
                labels
                    .iter()
                    .any(|pair| pair.name() == name && pair.value() == want)
            };
            if has("target", target) && has("outcome", outcome) {
                return metric.get_counter().value() as u64;
            }
        }
    }
    0
}

/// A broker that advertises `tls_required` expects a handshake next. This
/// client speaks plain TCP and its `CONNECT` carries the operator's
/// vault-resolved token, so writing it would put the credential on the wire
/// in the clear, once per batch, forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tls_required_broker_never_sees_the_token() {
    let broker = FakeNats::start_with_info(
        false,
        r#"{"server_id":"fake","version":"2.10.0","tls_required":true}"#,
    )
    .await;

    let sink = EventIngest::start(
        IngestTarget::Nats {
            address: broker.address.clone(),
            subject_prefix: "sb.events".into(),
            token: Some("super-secret-token".into()),
        },
        16,
        None,
    )
    .expect("sink");
    sink.publish(event("acme"));

    // Give the worker room to do the wrong thing before asserting it did
    // not.
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert!(
        broker.observed().connect.is_none(),
        "no CONNECT, and therefore no token, may reach a tls_required broker"
    );
    assert!(broker.observed().published.is_empty());

    drop(sink);
}

/// `timestamp_ms` is request start, so a `request_completed` for a long
/// request is emitted after one for a short request that began later.
/// Storing the last element of a batch therefore made the checkpoint move
/// backwards, and an operator running `WHERE timestamp_ms > :checkpoint`
/// re-read rows they had already reconciled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_watermark_records_the_newest_event_rather_than_the_last_one() {
    let path = temp_path();
    let store: Arc<dyn PersistentKv> =
        Arc::new(EmbeddedKvStore::open(&path, "event_ingest").expect("open"));
    let mut watermark = WatermarkStore::new(Arc::clone(&store), "nats").expect("store");

    let mut newest = event("acme");
    newest.timestamp_ms = 2_000;
    let mut older = event("acme");
    older.timestamp_ms = 1_000;
    let newest_id = newest.request_id.to_string();

    // Queue order puts the older request last, which is exactly what a
    // long-running request does.
    watermark.advance(&[newest, older], 2).await;

    let namespace = sbproxy_platform::storage::KvNamespace::new(WATERMARK_NAMESPACE).expect("ns");
    let stored: Watermark = serde_json::from_slice(
        &store
            .get(&namespace, WATERMARK_KEY)
            .await
            .expect("read")
            .expect("written")
            .value,
    )
    .expect("decode");
    assert_eq!(stored.last_timestamp_ms, 2_000);
    assert_eq!(stored.last_request_id, newest_id);
    assert_eq!(stored.delivered_total, 2);

    // A whole batch older than the checkpoint moves the count and not the
    // position.
    let mut stale = event("acme");
    stale.timestamp_ms = 500;
    watermark.advance(&[stale], 1).await;
    let stored: Watermark = serde_json::from_slice(
        &store
            .get(&namespace, WATERMARK_KEY)
            .await
            .expect("read")
            .expect("written")
            .value,
    )
    .expect("decode");
    assert_eq!(
        stored.last_timestamp_ms, 2_000,
        "the position never regresses"
    );

    std::fs::remove_file(&path).ok();
}

/// A checkpoint written for one destination is not this destination's
/// position. Reading it as such would tell an operator that a ClickHouse
/// table they have never written to is caught up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_watermark_from_another_target_is_not_adopted() {
    let path = temp_path();
    let store: Arc<dyn PersistentKv> =
        Arc::new(EmbeddedKvStore::open(&path, "event_ingest").expect("open"));
    let namespace = sbproxy_platform::storage::KvNamespace::new(WATERMARK_NAMESPACE).expect("ns");
    let foreign = Watermark {
        target: "clickhouse".into(),
        last_request_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
        last_timestamp_ms: 1_700_000_000_000,
        delivered_total: 999,
    };
    store
        .put(
            &namespace,
            WATERMARK_KEY,
            &serde_json::to_vec(&foreign).expect("encode"),
        )
        .await
        .expect("seed");

    let mut watermark = WatermarkStore::new(Arc::clone(&store), "nats").expect("store");
    assert!(
        watermark.load().await.is_none(),
        "a nats sink must not adopt a clickhouse checkpoint"
    );
    assert_eq!(watermark.delivered_total, 0);

    std::fs::remove_file(&path).ok();
}

#[test]
fn a_malformed_target_is_refused_before_a_worker_starts() {
    assert!(
        IngestTarget::Nats {
            address: "nats://broker:4222".into(),
            subject_prefix: "sb.events".into(),
            token: None,
        }
        .validate()
        .is_err(),
        "a URL is not a host:port"
    );

    assert!(
        IngestTarget::Nats {
            address: "broker".into(),
            subject_prefix: "sb.events".into(),
            token: None,
        }
        .validate()
        .is_err(),
        "a port is required"
    );

    assert!(
        IngestTarget::Nats {
            address: "broker:4222".into(),
            subject_prefix: "sb.events.>".into(),
            token: None,
        }
        .validate()
        .is_err(),
        "a wildcard prefix would publish into somebody's filter"
    );

    assert!(
        IngestTarget::ClickHouse {
            url: "clickhouse://host:9000".into(),
            database: "sbproxy".into(),
            table: "events".into(),
            user: None,
            password: None,
        }
        .validate()
        .is_err(),
        "the HTTP interface is the one this sink speaks"
    );

    // The database and table names are interpolated into a statement, so
    // anything outside the identifier charset is refused rather than
    // escaped.
    assert!(IngestTarget::ClickHouse {
        url: "http://host:8123".into(),
        database: "sbproxy".into(),
        table: "events; DROP TABLE x".into(),
        user: None,
        password: None,
    }
    .validate()
    .is_err());

    assert!(IngestTarget::ClickHouse {
        url: "http://host:8123".into(),
        database: "sbproxy".into(),
        table: "events".into(),
        user: None,
        password: None,
    }
    .validate()
    .is_ok());
}

/// What the fake warehouse saw.
#[derive(Debug, Default, Clone)]
struct ClickHouseRequest {
    target: String,
    user: Option<String>,
    key: Option<String>,
    content_type: Option<String>,
    body: String,
}

/// A ClickHouse that speaks enough HTTP to check the half of this sink the
/// `FakeNats` server does not cover: the query string, the two credential
/// headers, and the NDJSON body.
///
/// The NATS half got a real in-process server because the wire format is
/// hand written and a fake transport would have left it untested. The same
/// argument applies here: the statement, the headers, and the row framing
/// are all built by hand in this module.
struct FakeClickHouse {
    url: String,
    seen: Arc<Mutex<Vec<ClickHouseRequest>>>,
}

impl FakeClickHouse {
    async fn start(status: u16, body: &'static str) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("addr");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let server_seen = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let seen = Arc::clone(&server_seen);
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buffer = Vec::new();
                    let mut chunk = [0u8; 8192];
                    // Read until the body is complete, which the
                    // Content-Length header tells us.
                    loop {
                        let read = match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(read) => read,
                        };
                        buffer.extend_from_slice(&chunk[..read]);
                        let text = String::from_utf8_lossy(&buffer).to_string();
                        let Some(head_end) = text.find("\r\n\r\n") else {
                            continue;
                        };
                        let head = &text[..head_end];
                        let header = |name: &str| {
                            head.lines()
                                .find(|line| {
                                    line.to_ascii_lowercase().starts_with(&format!("{name}:"))
                                })
                                .and_then(|line| line.split_once(':'))
                                .map(|(_, value)| value.trim().to_string())
                        };
                        let length: usize = header("content-length")
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(0);
                        if text.len() < head_end + 4 + length {
                            continue;
                        }
                        seen.lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push(ClickHouseRequest {
                                target: head.lines().next().unwrap_or("").to_string(),
                                user: header("x-clickhouse-user"),
                                key: header("x-clickhouse-key"),
                                content_type: header("content-type"),
                                body: text[head_end + 4..head_end + 4 + length].to_string(),
                            });
                        let response = format!(
                            "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                        let _ = socket.flush().await;
                        break;
                    }
                });
            }
        });
        Self {
            url: format!("http://{address}"),
            seen,
        }
    }

    fn seen(&self) -> Vec<ClickHouseRequest> {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// The statement, the headers, and the row framing are all built by hand in
/// this module and none of them had a test. `docs/event-ingest.md` documents
/// every one of them as an operator-visible contract.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_clickhouse_insert_carries_the_documented_statement_headers_and_rows() {
    let warehouse = FakeClickHouse::start(200, "").await;
    let client = http_client_for_target(&IngestTarget::ClickHouse {
        url: warehouse.url.clone(),
        database: "sbproxy".into(),
        table: "request_events".into(),
        user: Some("writer".into()),
        password: Some("hunter2".into()),
    })
    .expect("ClickHouse requires an HTTP client");

    let landed = insert_into_clickhouse(
        &client,
        &warehouse.url,
        "sbproxy",
        "request_events",
        Some("writer"),
        Some("hunter2"),
        &[event("acme"), event("globex")],
    )
    .await;
    assert!(landed, "a 200 is a delivered batch");

    let seen = warehouse.seen();
    assert_eq!(seen.len(), 1, "one POST per batch");
    let request = &seen[0];
    assert!(request.target.starts_with("POST "), "{}", request.target);
    assert!(
        request
            .target
            .contains("query=INSERT+INTO+sbproxy.request_events+FORMAT+JSONEachRow")
            || request
                .target
                .contains("query=INSERT%20INTO%20sbproxy.request_events%20FORMAT%20JSONEachRow"),
        "{}",
        request.target
    );
    assert_eq!(request.user.as_deref(), Some("writer"));
    assert_eq!(request.key.as_deref(), Some("hunter2"));
    assert_eq!(
        request.content_type.as_deref(),
        Some("application/x-ndjson")
    );

    let rows: Vec<&str> = request.body.trim_end().split('\n').collect();
    assert_eq!(rows.len(), 2, "one newline-delimited row per event");
    for row in rows {
        let parsed: serde_json::Value = serde_json::from_str(row).expect("each row is JSON");
        assert!(parsed.get("request_id").is_some());
    }
}

/// A warehouse that refuses is a dropped batch, counted as an error rather
/// than swallowed as a success. The refusal body is where ClickHouse says
/// which of the two failures it was, so the sink has to read it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_clickhouse_refusal_is_a_failure_rather_than_a_silent_success() {
    let warehouse = FakeClickHouse::start(
        400,
        "Code: 60. DB::Exception: Table sbproxy.request_events does not exist.",
    )
    .await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");

    let landed = insert_into_clickhouse(
        &client,
        &warehouse.url,
        "sbproxy",
        "request_events",
        None,
        None,
        &[event("acme")],
    )
    .await;
    assert!(!landed, "a 4xx must not report the batch as delivered");
    assert_eq!(warehouse.seen().len(), 1);
    assert!(
        warehouse.seen()[0].user.is_none(),
        "no credential header is sent when none is configured"
    );
}

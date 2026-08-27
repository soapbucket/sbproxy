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

impl FakeNats {
    async fn start(refuse: bool) -> Self {
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
                    serve(socket, observed, refuse).await;
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

async fn serve(mut socket: tokio::net::TcpStream, observed: Arc<Mutex<Observed>>, refuse: bool) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    if socket
        .write_all(b"INFO {\"server_id\":\"fake\",\"version\":\"2.10.0\"}\r\n")
        .await
        .is_err()
    {
        return;
    }

    let mut buffer: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
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
                    let answer: &[u8] = if refuse {
                        b"-ERR 'Authorization Violation'\r\n"
                    } else {
                        b"PONG\r\n"
                    };
                    if socket.write_all(answer).await.is_err() {
                        return;
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

/// A `Debug` that prints a token is a token in a boot log.
#[test]
fn the_debug_impl_never_prints_a_credential() {
    let nats = format!(
        "{:?}",
        IngestTarget::Nats {
            address: "broker:4222".into(),
            subject_prefix: "sb.events".into(),
            token: Some("s3cret".into()),
        }
    );
    assert!(!nats.contains("s3cret"));
    assert!(nats.contains("authenticated: true"));

    let clickhouse = format!(
        "{:?}",
        IngestTarget::ClickHouse {
            url: "http://host:8123".into(),
            database: "sbproxy".into(),
            table: "events".into(),
            user: Some("writer".into()),
            password: Some("hunter2".into()),
        }
    );
    assert!(!clickhouse.contains("hunter2"));
    assert!(clickhouse.contains("authenticated: true"));
}

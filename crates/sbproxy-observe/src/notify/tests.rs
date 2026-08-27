//! The notifier's behavior, driven through a fake transport.
//!
//! Every test here goes through the real [`Notifier`], the real worker
//! thread, and the real embedded store. Only the socket is replaced, which
//! is the one part whose behavior these tests are not about: what they are
//! about is which subscriptions get a delivery, how many attempts a failure
//! gets, what lands in the deadletter queue, and whether a replay carries
//! the same event id.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use sbproxy_platform::storage::EmbeddedKvStore;

use super::*;
use crate::events::EventType;

/// One recorded attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Recorded {
    url: String,
    event_id: String,
    attempt: String,
    signature: Option<String>,
}

/// A transport that answers from a script and records what it was asked to
/// send.
struct FakeTransport {
    /// Outcomes, consumed in order. The last one repeats once exhausted, so
    /// a test that wants "always fails" writes one entry.
    script: Mutex<Vec<AttemptOutcome>>,
    seen: Mutex<Vec<Recorded>>,
}

impl FakeTransport {
    fn new(script: Vec<AttemptOutcome>) -> Arc<Self> {
        Arc::new(Self {
            script: Mutex::new(script),
            seen: Mutex::new(Vec::new()),
        })
    }

    fn seen(&self) -> Vec<Recorded> {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

#[async_trait::async_trait]
impl DeliveryTransport for FakeTransport {
    async fn attempt(
        &self,
        url: &str,
        headers: Vec<(&'static str, String)>,
        _body: Vec<u8>,
    ) -> AttemptOutcome {
        let header = |name: &str| {
            headers
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.clone())
        };
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(Recorded {
                url: url.to_string(),
                event_id: header("X-Sbproxy-Event-Id").unwrap_or_default(),
                attempt: header("X-Sbproxy-Attempt").unwrap_or_default(),
                signature: header("X-Sbproxy-Signature"),
            });
        let mut script = self.script.lock().unwrap_or_else(|e| e.into_inner());
        if script.len() > 1 {
            script.remove(0)
        } else {
            script
                .first()
                .cloned()
                .unwrap_or(AttemptOutcome::Delivered { status: 200 })
        }
    }
}

/// A transport that refuses immediately until `stall` is set, and parks
/// afterwards until the test releases it, so one test can produce a
/// deadletter and then jam the delivery path without a timed sleep that
/// would still be running at teardown.
struct FailThenStall {
    stall: std::sync::atomic::AtomicBool,
    /// Zero permits, so an acquire parks. Closing it wakes every waiter at
    /// once, which is how the test lets the worker finish.
    gate: tokio::sync::Semaphore,
}

impl FailThenStall {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            stall: std::sync::atomic::AtomicBool::new(false),
            gate: tokio::sync::Semaphore::new(0),
        })
    }
}

#[async_trait::async_trait]
impl DeliveryTransport for FailThenStall {
    async fn attempt(
        &self,
        _url: &str,
        _headers: Vec<(&'static str, String)>,
        _body: Vec<u8>,
    ) -> AttemptOutcome {
        if self.stall.load(std::sync::atomic::Ordering::Relaxed) {
            let _ = self.gate.acquire().await;
        }
        AttemptOutcome::Permanent {
            status: Some(400),
            reason: "http_rejected",
        }
    }
}

/// A transport that never answers for one host and answers instantly for
/// every other, so a test can tell head-of-line blocking from concurrency.
struct SlowForOneHost {
    slow_host: String,
    seen: Mutex<Vec<String>>,
    /// Zero permits. The slow host parks here until the test closes it.
    gate: tokio::sync::Semaphore,
}

#[async_trait::async_trait]
impl DeliveryTransport for SlowForOneHost {
    async fn attempt(
        &self,
        url: &str,
        _headers: Vec<(&'static str, String)>,
        _body: Vec<u8>,
    ) -> AttemptOutcome {
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(url.to_string());
        if url == self.slow_host {
            let _ = self.gate.acquire().await;
        }
        AttemptOutcome::Delivered { status: 200 }
    }
}

fn temp_path() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}/sbproxy_notify_test_{}_{}.redb",
        std::env::temp_dir().display(),
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

fn store(path: &str) -> Arc<dyn PersistentKv> {
    Arc::new(EmbeddedKvStore::open(path, "notifications").expect("open store"))
}

fn event(event_type: EventType) -> ProxyEvent {
    ProxyEvent::new(
        event_type,
        "example.com".to_string(),
        "acme".to_string(),
        serde_json::json!({"note": "test"}),
    )
}

/// Wait until `check` holds or the deadline passes, so a test does not race
/// the worker thread. Polling rather than a channel because the worker's
/// completion is observable through the store and the transport, and
/// wiring a second signal only for tests would be a shape production does
/// not have.
async fn eventually(mut check: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if check() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    check()
}

/// The seam: an event reaches exactly the subscriptions whose filter
/// selects it, and no others. A fan-out that ignores filters is the failure
/// that sends one customer another customer's events.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_event_reaches_only_the_subscriptions_that_selected_it() {
    let path = temp_path();
    let transport = FakeTransport::new(vec![AttemptOutcome::Delivered { status: 200 }]);
    let notifier = Notifier::start_with_transport(store(&path), 16, transport.clone())
        .await
        .expect("notifier");

    notifier
        .create_subscription("https://all.example/hook".into(), vec!["*".into()], true)
        .await
        .expect("wildcard subscription");
    notifier
        .create_subscription(
            "https://keys.example/hook".into(),
            vec!["key_minted".into()],
            false,
        )
        .await
        .expect("exact subscription");
    notifier
        .create_subscription(
            "https://other.example/hook".into(),
            vec!["policy_denied".into()],
            false,
        )
        .await
        .expect("unrelated subscription");

    assert!(notifier.wants("key_minted"));
    notifier.offer(event(EventType::KeyMinted));

    assert!(
        eventually(|| transport.seen().len() >= 2).await,
        "both selecting subscriptions should have been attempted"
    );
    let urls: std::collections::BTreeSet<String> =
        transport.seen().into_iter().map(|r| r.url).collect();
    assert!(urls.contains("https://all.example/hook"));
    assert!(urls.contains("https://keys.example/hook"));
    assert!(
        !urls.contains("https://other.example/hook"),
        "a subscription that did not select this type must not receive it"
    );

    drop(notifier);
    std::fs::remove_file(&path).ok();
}

/// An inactive subscription is kept but not delivered to. Deleting it
/// instead would lose its filters and its id, which is why pausing exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_inactive_subscription_receives_nothing() {
    let path = temp_path();
    let transport = FakeTransport::new(vec![AttemptOutcome::Delivered { status: 200 }]);
    let notifier = Notifier::start_with_transport(store(&path), 16, transport.clone())
        .await
        .expect("notifier");

    let (view, _) = notifier
        .create_subscription("https://paused.example/hook".into(), vec!["*".into()], true)
        .await
        .expect("subscription");
    notifier
        .update_subscription(&view.subscription_id, None, None, Some(false), None)
        .await
        .expect("pause");
    assert!(!notifier.wants("key_minted"));

    notifier.offer(event(EventType::KeyMinted));
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(transport.seen().is_empty());

    // Reactivating it starts delivery again without a new id.
    let resumed = notifier
        .update_subscription(&view.subscription_id, None, None, Some(true), None)
        .await
        .expect("resume");
    assert_eq!(resumed.subscription_id, view.subscription_id);
    notifier.offer(event(EventType::KeyMinted));
    assert!(eventually(|| !transport.seen().is_empty()).await);

    drop(notifier);
    std::fs::remove_file(&path).ok();
}

/// The retry-and-deadletter contract: a receiver that keeps failing gets
/// exactly `MAX_ATTEMPTS` attempts, all under one event id, and what is
/// left lands in the queue.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_receiver_is_retried_then_deadlettered_under_one_event_id() {
    let path = temp_path();
    let transport = FakeTransport::new(vec![AttemptOutcome::Retryable {
        status: Some(503),
        reason: "http_error",
    }]);
    let notifier = Notifier::start_with_transport(store(&path), 16, transport.clone())
        .await
        .expect("notifier");
    notifier
        .create_subscription("https://down.example/hook".into(), vec!["*".into()], true)
        .await
        .expect("subscription");

    notifier.offer(event(EventType::KeyMinted));

    assert!(
        eventually(|| transport.seen().len() as u32 >= MAX_ATTEMPTS).await,
        "the delivery should have used its whole attempt budget"
    );
    let seen = transport.seen();
    assert_eq!(seen.len() as u32, MAX_ATTEMPTS, "and no more than that");
    let ids: std::collections::BTreeSet<&str> = seen.iter().map(|r| r.event_id.as_str()).collect();
    assert_eq!(ids.len(), 1, "every attempt carries the same event id");
    let attempts: Vec<&str> = seen.iter().map(|r| r.attempt.as_str()).collect();
    assert_eq!(attempts, vec!["1", "2", "3"], "and a per-attempt counter");
    assert!(
        seen.iter().all(|r| r.signature.is_some()),
        "every attempt is signed"
    );

    let queued = eventually_deadletters(&notifier, 1).await;
    assert_eq!(queued.len(), 1);
    assert_eq!(
        queued[0].attempts as usize,
        seen.len(),
        "the record has to carry the attempts that were actually made"
    );
    assert_eq!(queued[0].last_status, Some(503));
    assert_eq!(queued[0].event_id, seen[0].event_id);

    drop(notifier);
    std::fs::remove_file(&path).ok();
}

/// A 400 will be a 400 next time. Spending the retry budget on it delays
/// every delivery behind it and changes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_permanent_refusal_is_not_retried() {
    let path = temp_path();
    let transport = FakeTransport::new(vec![AttemptOutcome::Permanent {
        status: Some(400),
        reason: "http_rejected",
    }]);
    let notifier = Notifier::start_with_transport(store(&path), 16, transport.clone())
        .await
        .expect("notifier");
    notifier
        .create_subscription("https://picky.example/hook".into(), vec!["*".into()], true)
        .await
        .expect("subscription");

    notifier.offer(event(EventType::KeyMinted));
    let queued = eventually_deadletters(&notifier, 1).await;
    assert_eq!(
        transport.seen().len(),
        1,
        "a permanent refusal costs exactly one attempt"
    );
    assert_eq!(
        queued[0].attempts, 1,
        "and the record says one, not the budget"
    );
    assert_eq!(queued[0].last_status, Some(400));
    assert_eq!(queued[0].last_reason, "http_rejected");

    drop(notifier);
    std::fs::remove_file(&path).ok();
}

/// Replay is the recoverable half of the bounded retry budget. It has to
/// re-send under the original event id, and it has to take the record out
/// of the queue, or an operator draining one watches it refuse to shrink.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replay_resends_under_the_original_event_id_and_empties_the_queue() {
    let path = temp_path();
    // 422 rather than 500: `GovernedTransport` classifies every 5xx as
    // retryable, so a scripted `Permanent { 500 }` is a shape production
    // cannot produce and a fixture that cannot happen proves nothing.
    let transport = FakeTransport::new(vec![
        AttemptOutcome::Permanent {
            status: Some(422),
            reason: "http_rejected",
        },
        AttemptOutcome::Delivered { status: 200 },
    ]);
    let notifier = Notifier::start_with_transport(store(&path), 16, transport.clone())
        .await
        .expect("notifier");
    notifier
        .create_subscription("https://flaky.example/hook".into(), vec!["*".into()], true)
        .await
        .expect("subscription");

    notifier.offer(event(EventType::KeyMinted));
    let queued = eventually_deadletters(&notifier, 1).await;
    let original_event_id = queued[0].event_id.clone();

    let replayed = notifier
        .replay(&queued[0].delivery_id)
        .await
        .expect("replay");
    assert_eq!(replayed, original_event_id);

    assert!(
        eventually(|| transport.seen().len() >= 2).await,
        "the replay should have been attempted"
    );
    assert_eq!(
        transport.seen()[1].event_id,
        original_event_id,
        "a replay carries the id the receiver may already have seen"
    );
    assert!(
        eventually_empty(&notifier).await,
        "a replayed record leaves the queue"
    );

    // Replaying an id that is gone is a 404 rather than a silent success.
    assert!(matches!(
        notifier.replay(&queued[0].delivery_id).await,
        Err(NotifyError::NotFound(_))
    ));

    drop(notifier);
    std::fs::remove_file(&path).ok();
}

/// The deadletter queue is the one durable structure this feature exists
/// to provide, and the drain `docs/notifications.md` recommends is what
/// used to destroy it: `replay` deleted the record and then offered the
/// delivery, so once the queue filled, every further replay deleted a
/// record, dropped the delivery, and answered `202 replayed: true`. The
/// queue shrank to zero, which is exactly the signal the operator was told
/// to watch for.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replay_a_full_queue_cannot_take_keeps_its_record() {
    let path = temp_path();
    let transport = FailThenStall::new();
    let notifier = Notifier::start_with_transport(store(&path), 1, transport.clone())
        .await
        .expect("notifier");
    notifier
        .create_subscription("https://down.example/hook".into(), vec!["*".into()], true)
        .await
        .expect("subscription");

    notifier.offer(event(EventType::KeyMinted));
    let queued = eventually_deadletters(&notifier, 1).await;
    let delivery_id = queued[0].delivery_id.clone();

    // Every delivery from here on parks, so the in-flight bound fills, the
    // worker stops receiving, and the queue stays full. Offering with a
    // yield rather than in a tight loop, because a tight loop outruns the
    // worker and most offers would be dropped before it had taken enough
    // to exhaust its permits.
    transport
        .stall
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let mut full = false;
    for _ in 0..2_000 {
        if notifier
            .offer_delivery(QueuedDelivery {
                event_id: store::mint_event_id(),
                event: event(EventType::KeyMinted),
            })
            .is_err()
        {
            full = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    assert!(
        full,
        "the queue has to reach its bound for this test to mean anything"
    );

    assert!(
        matches!(
            notifier.replay(&delivery_id).await,
            Err(NotifyError::QueueFull)
        ),
        "a full queue has to refuse rather than accept"
    );
    assert!(
        notifier.get_deadletter(&delivery_id).await.is_ok(),
        "a refused replay must leave the record where it was"
    );

    // The refusal is a 429 carrying `replayed: false`, so a drain loop
    // reading the flag backs off instead of shredding the queue.
    let refusal = crate::notify::admin::dispatch(
        &notifier,
        "POST",
        &format!("/admin/notifications/deadletters/{delivery_id}/replay"),
        None,
    )
    .await
    .expect("route exists");
    assert_eq!(refusal.status, 429);
    assert!(
        refusal.body.contains("\"replayed\":false"),
        "{}",
        refusal.body
    );

    transport.gate.close();
    drop(notifier);
    std::fs::remove_file(&path).ok();
}

/// One customer's dead receiver used to throttle every other customer's
/// feed: the worker awaited one event's whole fan-out before receiving the
/// next, so a subscription timing out cost three attempts across up to
/// fifteen seconds and everybody else waited behind it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stalled_receiver_does_not_hold_up_a_healthy_one() {
    let path = temp_path();
    let transport = Arc::new(SlowForOneHost {
        slow_host: "https://slow.example/hook".to_string(),
        seen: Mutex::new(Vec::new()),
        gate: tokio::sync::Semaphore::new(0),
    });
    let notifier = Notifier::start_with_transport(store(&path), 64, transport.clone())
        .await
        .expect("notifier");
    notifier
        .create_subscription("https://slow.example/hook".into(), vec!["*".into()], true)
        .await
        .expect("slow subscription");
    notifier
        .create_subscription("https://fast.example/hook".into(), vec!["*".into()], true)
        .await
        .expect("fast subscription");

    // Two events. Under the serial worker the second event's healthy
    // delivery cannot start until the first event's stalled one finishes.
    notifier.offer(event(EventType::KeyMinted));
    notifier.offer(event(EventType::KeyRevoked));

    assert!(
        eventually(|| {
            transport
                .seen
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .filter(|url| url.as_str() == "https://fast.example/hook")
                .count()
                >= 2
        })
        .await,
        "the healthy receiver must get both events while the other is stalled"
    );

    transport.gate.close();
    drop(notifier);
    std::fs::remove_file(&path).ok();
}

/// Subscriptions are the operator's configuration of who hears about what.
/// A restart that forgot them stops telling every customer anything, with
/// no error anywhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscriptions_and_deadletters_survive_a_restart() {
    let path = temp_path();
    let subscription_id = {
        let transport = FakeTransport::new(vec![AttemptOutcome::Permanent {
            status: Some(410),
            reason: "http_rejected",
        }]);
        let notifier = Notifier::start_with_transport(store(&path), 16, transport)
            .await
            .expect("notifier");
        let (view, secret) = notifier
            .create_subscription(
                "https://gone.example/hook".into(),
                vec!["key_minted".into()],
                false,
            )
            .await
            .expect("subscription");
        assert_eq!(secret.len(), 64);
        notifier.offer(event(EventType::KeyMinted));
        eventually_deadletters(&notifier, 1).await;
        drop(notifier);
        view.subscription_id
    };

    let transport = FakeTransport::new(vec![AttemptOutcome::Delivered { status: 200 }]);
    let notifier = Notifier::start_with_transport(store(&path), 16, transport)
        .await
        .expect("reopened notifier");
    let restored = notifier.list_subscriptions().await.expect("list");
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].subscription_id, subscription_id);
    assert_eq!(restored[0].event_types, vec!["key_minted".to_string()]);
    assert_eq!(
        deadletters(&notifier).await.len(),
        1,
        "a deadletter is a record of what a receiver missed and has to survive"
    );

    drop(notifier);
    std::fs::remove_file(&path).ok();
}

/// A read path that can carry a secret eventually does. This one cannot:
/// the type has no field for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_read_path_returns_the_signing_secret() {
    let path = temp_path();
    let transport = FakeTransport::new(vec![AttemptOutcome::Delivered { status: 200 }]);
    let notifier = Notifier::start_with_transport(store(&path), 16, transport)
        .await
        .expect("notifier");
    let (view, secret) = notifier
        .create_subscription(
            "https://receiver.example/hook".into(),
            vec!["*".into()],
            true,
        )
        .await
        .expect("subscription");

    let listed = serde_json::to_string(&notifier.list_subscriptions().await.expect("list"))
        .expect("serialize");
    assert!(!listed.contains(&secret));
    assert!(!listed.contains("signing_secret"));
    assert!(listed.contains(&view.signing_key_id));

    // Rotating mints a different secret and a different key id.
    let (rotated, new_secret) = notifier
        .rotate_signing_key(&view.subscription_id)
        .await
        .expect("rotate");
    assert_ne!(new_secret, secret);
    assert_ne!(rotated.signing_key_id, view.signing_key_id);

    drop(notifier);
    std::fs::remove_file(&path).ok();
}

async fn deadletters(notifier: &Notifier) -> Vec<DeadLetterSummary> {
    notifier
        .page_deadletters(None, MAX_DEADLETTER_PAGE)
        .await
        .map(|(items, _)| items)
        .unwrap_or_default()
}

async fn eventually_deadletters(notifier: &Notifier, want: usize) -> Vec<DeadLetterSummary> {
    for _ in 0..200 {
        let records = deadletters(notifier).await;
        if records.len() >= want {
            return records;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    deadletters(notifier).await
}

async fn eventually_empty(notifier: &Notifier) -> bool {
    for _ in 0..200 {
        if deadletters(notifier).await.is_empty() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    false
}

/// The seam that makes the notifier a feature rather than a library: an
/// event published through the ordinary `publish_proxy_event` path reaches
/// an installed notifier even when no `events:` egress is configured.
///
/// Before this, `publish_proxy_event` returned early unless the egress
/// wanted the event, so a deployment with subscriptions and no `events:`
/// block would have delivered nothing, with no error anywhere. Coverage of
/// `Notifier::offer` proves nothing about that; this drives the call site.
///
/// The subscription filters on one event type no other test in this binary
/// publishes, because `install` sets a process-global and a wildcard filter
/// would make this test's assertions depend on what else ran.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_installed_notifier_receives_events_with_no_events_egress_configured() {
    let path = temp_path();
    let transport = FakeTransport::new(vec![AttemptOutcome::Delivered { status: 200 }]);
    let notifier = Arc::new(
        Notifier::start_with_transport(store(&path), 16, transport.clone())
            .await
            .expect("notifier"),
    );
    notifier
        .create_subscription(
            "https://seam.example/hook".into(),
            vec!["agent_registration_decided".into()],
            false,
        )
        .await
        .expect("subscription");

    // `install` is set-once per process. This repository runs its test
    // lane under nextest, which gives every test its own process, so the
    // set-once global is this test's alone. Asserting it rather than
    // returning early is deliberate: the version this replaces returned
    // without asserting anything when it lost the race, so a seam that
    // stopped working would have shown as a green test under any
    // shared-process runner.
    assert!(
        crate::notify::install(Arc::clone(&notifier)),
        "no other notifier may be installed in this process; run the test lane under nextest"
    );

    crate::event_sink::publish_proxy_event(EventType::AgentRegistrationDecided, || {
        event(EventType::AgentRegistrationDecided)
    });

    assert!(
        eventually(|| !transport.seen().is_empty()).await,
        "an installed notifier must receive a published event with no events: egress configured"
    );
    assert_eq!(transport.seen()[0].url, "https://seam.example/hook");

    // The installed notifier is a process-global that is never dropped, so
    // the store file stays open for the rest of the run. Leaving the file
    // is the honest cost of testing a set-once global.
}

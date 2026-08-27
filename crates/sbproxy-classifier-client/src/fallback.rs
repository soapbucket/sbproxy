//! Optional-degrade architecture for the classifier sidecar (WOR-2665).
//!
//! This is the piece that makes deploying a classifier sidecar (minimal or
//! rich) genuinely optional, per WOR-2661's rule that a sidecar process a
//! deployment must run and keep running is the same category of hard
//! dependency as an external database: nothing in this OSS workspace may
//! require one to be up.
//!
//! [`FallbackClassifier`] wraps an *optional* [`ClassifierClient`] and a
//! caller-supplied [`InProcessClassifier`]:
//!
//! - No sidecar configured at all (the common OSS case: an operator who
//!   never deploys one): every call goes straight to the in-process
//!   classifier. No connection is ever attempted.
//! - A sidecar is configured but unreachable, times out, or returns a
//!   malformed response: the call degrades to the in-process classifier for
//!   that request, logging a warning so the degradation is visible without
//!   failing the request.
//! - A sidecar is configured and healthy: its verdict is used, and the
//!   in-process classifier is not invoked at all (no wasted CPU running
//!   inference twice).
//!
//! `InProcessClassifier` is a trait rather than a concrete type so this
//! crate does not have to depend on `sbproxy_classifiers` (the ONNX
//! runtime) or any other specific in-process implementation; a caller
//! plugs in whatever it already has (an `OnnxClassifier`, a heuristic
//! detector, a stub for tests). See
//! `crates/sbproxy-classifier-client/examples/fallback.rs` for a runnable
//! demonstration of all three cases above.

use crate::{ClassifierClient, ClassifierClientError};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// How long one degrade reason stays quiet after it has been logged once.
///
/// A configured-but-unreachable sidecar at 5k rps used to emit 5k WARN lines
/// per second in a release build, so the outage became the log flood that
/// hid it. The window aggregates instead: the first degrade of each reason
/// logs immediately, the rest are counted and reported on the next line.
const DEGRADE_WARNING_WINDOW: Duration = Duration::from_secs(60);

/// Closed reason vocabulary for the fallback counter and the warning window.
///
/// Derived from the client's own error enum, never from a sidecar-supplied
/// string, so the label set cannot be opened by a hostile peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DegradeReason {
    Connect,
    Timeout,
    Rpc,
    Protocol,
    InvalidRequest,
    EmptyResponse,
}

impl DegradeReason {
    const ALL: [Self; 6] = [
        Self::Connect,
        Self::Timeout,
        Self::Rpc,
        Self::Protocol,
        Self::InvalidRequest,
        Self::EmptyResponse,
    ];

    /// Slots in the warning window, one per reason. Derived from `ALL` so
    /// the two cannot be resized apart.
    const COUNT: usize = Self::ALL.len();

    fn as_label(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Timeout => "timeout",
            Self::Rpc => "rpc",
            Self::Protocol => "protocol",
            Self::InvalidRequest => "invalid_request",
            Self::EmptyResponse => "empty_response",
        }
    }

    /// This reason's slot in the window's per-reason arrays.
    ///
    /// Exhaustive, so a seventh variant does not compile until it is given a
    /// slot, and the arrays are sized from `ALL` rather than hand-numbered,
    /// so a variant added to `ALL` widens them with it. A const assertion
    /// checks the two agree at compile time, and `admit` reads its slot with
    /// `get`, so even a mapping that got past both refuses to log-flood
    /// rather than panicking on the proxy's classifier path.
    const fn index(self) -> usize {
        match self {
            Self::Connect => 0,
            Self::Timeout => 1,
            Self::Rpc => 2,
            Self::Protocol => 3,
            Self::InvalidRequest => 4,
            Self::EmptyResponse => 5,
        }
    }

    fn of(error: &ClassifierClientError) -> Self {
        match error {
            ClassifierClientError::Connect(_) => Self::Connect,
            ClassifierClientError::Timeout(_) => Self::Timeout,
            ClassifierClientError::Rpc { .. } => Self::Rpc,
            ClassifierClientError::Protocol(_) => Self::Protocol,
            ClassifierClientError::InvalidRequest(_) => Self::InvalidRequest,
        }
    }
}

// Every reason in `ALL` owns the slot it sits at, so `index` and the window's
// arrays, which are sized from `ALL`, cannot drift apart.
const _: () = {
    let mut slot = 0;
    while slot < DegradeReason::COUNT {
        assert!(DegradeReason::ALL[slot].index() == slot);
        slot += 1;
    }
};

fn fallback_total() -> Option<&'static prometheus::IntCounterVec> {
    static FALLBACK_TOTAL: OnceLock<Option<prometheus::IntCounterVec>> = OnceLock::new();
    FALLBACK_TOTAL
        .get_or_init(|| {
            let counter = prometheus::IntCounterVec::new(
                prometheus::Opts::new(
                    "sbproxy_classifier_client_fallback_total",
                    "Classifier calls served by the in-process fallback because the configured sidecar did not answer, by closed reason.",
                ),
                &["reason"],
            )
            .ok()?;
            prometheus::register(Box::new(counter.clone())).ok()?;
            // Publish a zero for every reason so a dashboard shows the family
            // rather than nothing at all before the first outage.
            for reason in DegradeReason::ALL {
                counter.with_label_values(&[reason.as_label()]);
            }
            Some(counter)
        })
        .as_ref()
}

/// Per-reason warning window shared by every `FallbackClassifier` in the
/// process. Holds the epoch of the last emitted warning and how many
/// degrades have been suppressed since.
struct DegradeWindow {
    started: Instant,
    last_logged_millis: [AtomicU64; DegradeReason::COUNT],
    suppressed: [AtomicU64; DegradeReason::COUNT],
}

impl DegradeWindow {
    fn get() -> &'static Self {
        static WINDOW: OnceLock<DegradeWindow> = OnceLock::new();
        WINDOW.get_or_init(|| DegradeWindow {
            started: Instant::now(),
            last_logged_millis: std::array::from_fn(|_| AtomicU64::new(u64::MAX)),
            suppressed: std::array::from_fn(|_| AtomicU64::new(0)),
        })
    }

    /// Record one degrade. Returns the number of degrades this line speaks
    /// for when the caller should log, and `None` while the window is open.
    fn admit(&self, reason: DegradeReason) -> Option<u64> {
        let index = reason.index();
        // The const assertion above makes a slot outside the arrays a
        // compile error; this path still refuses to index blind, because the
        // alternative is a panic inside every degraded classification the
        // proxy makes. An unmapped reason logs its line instead.
        let (Some(last_logged), Some(suppressed)) = (
            self.last_logged_millis.get(index),
            self.suppressed.get(index),
        ) else {
            return Some(1);
        };
        let now = self.started.elapsed().as_millis() as u64;
        let last = last_logged.load(Ordering::Relaxed);
        let window = DEGRADE_WARNING_WINDOW.as_millis() as u64;
        if last != u64::MAX && now.saturating_sub(last) < window {
            suppressed.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        if last_logged
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            suppressed.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        Some(suppressed.swap(0, Ordering::Relaxed) + 1)
    }

    #[cfg(test)]
    fn reset(&self) {
        for index in 0..self.last_logged_millis.len() {
            self.last_logged_millis[index].store(u64::MAX, Ordering::Relaxed);
            self.suppressed[index].store(0, Ordering::Relaxed);
        }
    }
}

/// Count one degrade and log at most one line per reason per window.
///
/// The error's `Display` is deliberately absent from the suppressed-path
/// bookkeeping and the counter: only the closed reason label crosses into
/// either, so nothing a sidecar returns can open the label space or reach a
/// log line.
fn note_degrade(reason: DegradeReason, error: Option<&ClassifierClientError>) {
    if let Some(counter) = fallback_total() {
        counter.with_label_values(&[reason.as_label()]).inc();
    }
    let Some(degrades) = DegradeWindow::get().admit(reason) else {
        return;
    };
    match error {
        Some(error) => tracing::warn!(
            reason = reason.as_label(),
            degraded_calls = degrades,
            window_seconds = DEGRADE_WARNING_WINDOW.as_secs(),
            error = %error,
            "classifier sidecar unavailable; degrading to in-process classifier"
        ),
        None => tracing::warn!(
            reason = reason.as_label(),
            degraded_calls = degrades,
            window_seconds = DEGRADE_WARNING_WINDOW.as_secs(),
            "classifier sidecar returned zero labels despite client validation; degrading to in-process classifier"
        ),
    }
}

/// A classification verdict: a label plus its confidence score.
///
/// Deliberately minimal (this crate's existing [`crate::Label`] mirrors it)
/// so both the sidecar path and an arbitrary in-process classifier can
/// produce the same shape without either depending on the other's types.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    /// Classification label.
    pub label: String,
    /// Confidence score.
    pub score: f64,
}

/// The in-process fallback a caller supplies. Implement this over whatever
/// local classifier is already available (typically
/// `sbproxy_classifiers::OnnxClassifier`, or a heuristic detector) so
/// [`FallbackClassifier`] can degrade to it without this crate needing to
/// know which one.
///
/// Synchronous by design: in-process classification (an ONNX forward pass,
/// or a handful of regex matches) is CPU-bound work with no I/O, so there
/// is nothing for an implementor to `.await`. A caller whose in-process
/// classifier is expensive enough to want off the async executor's thread
/// wraps its own call in `spawn_blocking`; that policy belongs to the
/// caller; wrapping it here would tax the common case of a cheap heuristic
/// classifier with a channel round trip it does not need.
pub trait InProcessClassifier: Send + Sync {
    /// Classify `text`, returning the top verdict.
    fn classify(&self, text: &str) -> Verdict;
}

/// Degrades from an optional classifier sidecar to an in-process classifier.
///
/// See the module doc for the three cases this covers. Constructed once per
/// logical classification use (e.g. once per policy), then called on every
/// request.
pub struct FallbackClassifier<F> {
    sidecar: Option<ClassifierClient>,
    model: String,
    inprocess: F,
}

impl<F: InProcessClassifier> FallbackClassifier<F> {
    /// Build a fallback classifier. `sidecar` is `None` when the operator
    /// has not configured one at all (the common OSS case); `model` is the
    /// logical model id requested from the sidecar's `Classify` RPC (empty
    /// selects the sidecar's default).
    pub fn new(sidecar: Option<ClassifierClient>, model: impl Into<String>, inprocess: F) -> Self {
        Self {
            sidecar,
            model: model.into(),
            inprocess,
        }
    }

    /// True when a sidecar is configured (whether or not it is currently
    /// reachable). Exposed for callers that want to log or report which
    /// mode a request ran in without duplicating the `Option` check.
    pub fn has_sidecar_configured(&self) -> bool {
        self.sidecar.is_some()
    }

    /// Classify `text`, preferring the sidecar when one is configured and
    /// healthy, and degrading to the in-process classifier otherwise.
    ///
    /// The in-process classifier is never invoked when the sidecar answers
    /// successfully, and the sidecar is never contacted when none is
    /// configured, so an operator pays for exactly the inference path they
    /// actually use.
    pub async fn classify(&self, text: &str) -> Verdict {
        let Some(client) = &self.sidecar else {
            return self.inprocess.classify(text);
        };

        match client.classify(&self.model, text).await {
            Ok(response) => {
                // The client validates responses before returning them (at
                // least one label, finite in-range scores), so `labels` is
                // non-empty and sorted highest score first here.
                if let Some(top) = response.labels.into_iter().next() {
                    return Verdict {
                        label: top.name,
                        score: top.score,
                    };
                }
                // Defensive: the client contract guarantees this does not
                // happen, but a defensive guard that silently returned a
                // clean verdict on a broken invariant would be the exact
                // "reads as covered but is not" failure mode this
                // architecture exists to avoid. Fall through to in-process.
                note_degrade(DegradeReason::EmptyResponse, None);
                self.inprocess.classify(text)
            }
            Err(err) => self.on_sidecar_error(text, &err),
        }
    }

    fn on_sidecar_error(&self, text: &str, err: &ClassifierClientError) -> Verdict {
        note_degrade(DegradeReason::of(err), Some(err));
        self.inprocess.classify(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// In-process stub that counts calls, so tests can assert both the
    /// returned verdict and whether the fallback path actually ran.
    struct CountingInProcess {
        calls: Arc<AtomicUsize>,
        verdict: Verdict,
    }

    impl InProcessClassifier for CountingInProcess {
        fn classify(&self, _text: &str) -> Verdict {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.verdict.clone()
        }
    }

    #[tokio::test]
    async fn no_sidecar_configured_uses_in_process_directly() {
        // The common OSS case: an operator who never deploys a sidecar at
        // all must still get full classification via the existing
        // in-process path, with no network attempted.
        let calls = Arc::new(AtomicUsize::new(0));
        let classifier = FallbackClassifier::new(
            None,
            "prompt-injection",
            CountingInProcess {
                calls: Arc::clone(&calls),
                verdict: Verdict {
                    label: "clean".to_string(),
                    score: 0.0,
                },
            },
        );

        assert!(!classifier.has_sidecar_configured());
        let verdict = classifier.classify("hello").await;
        assert_eq!(verdict.label, "clean");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// The degrade path used to emit one unaggregated `warn!` per request
    /// and record no metric at all, so a configured-but-unreachable sidecar
    /// at 5k rps turned the outage into the log flood that hid it, and no
    /// counter existed to alert on "we are running on the fallback".
    /// The window's arrays are sized from `ALL` and every reason's slot
    /// falls inside them. Hand-numbered slots against a hand-sized array
    /// meant a seventh reason compiled and then panicked inside
    /// `note_degrade`, which every degraded classification reaches.
    #[test]
    fn every_degrade_reason_owns_a_slot_inside_the_window() {
        let window = DegradeWindow::get();
        assert_eq!(DegradeReason::ALL.len(), window.suppressed.len());
        assert_eq!(DegradeReason::ALL.len(), window.last_logged_millis.len());
        for (slot, reason) in DegradeReason::ALL.iter().enumerate() {
            assert_eq!(reason.index(), slot, "{} moved slot", reason.as_label());
            assert!(
                window.suppressed.get(reason.index()).is_some()
                    && window.last_logged_millis.get(reason.index()).is_some(),
                "{} has no slot to count into",
                reason.as_label()
            );
        }
    }

    #[tokio::test]
    async fn every_degrade_counts_and_the_warning_is_windowed_by_reason() {
        DegradeWindow::get().reset();
        let before = degraded_calls_total();

        // Port 1 refuses immediately, so each call degrades without hanging.
        let sidecar =
            ClassifierClient::connect_lazy("http://127.0.0.1:1", Duration::from_millis(200))
                .expect("lazy client construction does not dial");
        let calls = Arc::new(AtomicUsize::new(0));
        let classifier = FallbackClassifier::new(
            Some(sidecar),
            "prompt-injection",
            CountingInProcess {
                calls: Arc::clone(&calls),
                verdict: Verdict {
                    label: "clean".to_string(),
                    score: 0.0,
                },
            },
        );

        for _ in 0..8 {
            classifier.classify("hello").await;
        }

        assert_eq!(
            degraded_calls_total() - before,
            8,
            "every degraded call must be counted, not just the logged one"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 8);

        // The window opened on the first degrade of that reason and swallowed
        // the rest, so the remainder are parked against the next line rather
        // than each writing one.
        let window = DegradeWindow::get();
        let suppressed: u64 = DegradeReason::ALL
            .iter()
            .map(|reason| window.suppressed[reason.index()].load(Ordering::Relaxed))
            .sum();
        assert_eq!(
            suppressed, 7,
            "only the first degrade in the window may reach the log"
        );

        // A different reason has its own window and is not suppressed by the
        // first one.
        window.reset();
        assert_eq!(window.admit(DegradeReason::Connect), Some(1));
        assert_eq!(window.admit(DegradeReason::Connect), None);
        assert_eq!(
            window.admit(DegradeReason::Protocol),
            Some(1),
            "each reason carries its own window"
        );
    }

    fn degraded_calls_total() -> u64 {
        let Some(counter) = fallback_total() else {
            return 0;
        };
        DegradeReason::ALL
            .iter()
            .map(|reason| counter.with_label_values(&[reason.as_label()]).get())
            .sum()
    }

    #[tokio::test]
    async fn sidecar_configured_but_unreachable_degrades_to_in_process() {
        // Port 1 refuses immediately, so the lazy client's first RPC fails
        // fast rather than hanging for the test.
        let sidecar =
            ClassifierClient::connect_lazy("http://127.0.0.1:1", Duration::from_millis(200))
                .expect("lazy client construction does not dial");
        let calls = Arc::new(AtomicUsize::new(0));
        let classifier = FallbackClassifier::new(
            Some(sidecar),
            "prompt-injection",
            CountingInProcess {
                calls: Arc::clone(&calls),
                verdict: Verdict {
                    label: "clean".to_string(),
                    score: 0.0,
                },
            },
        );

        assert!(classifier.has_sidecar_configured());
        let verdict = classifier.classify("hello").await;
        assert_eq!(
            verdict.label, "clean",
            "an unreachable sidecar must degrade to the in-process verdict, not panic or block"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the in-process classifier must have been invoked exactly once"
        );
    }

    #[tokio::test]
    async fn sidecar_configured_and_healthy_is_used_and_in_process_is_not_invoked() {
        use sbproxy_classifier_proto::{
            ClassifyRequest, ClassifyResponse, CompressRequest, CompressResponse, EmbedRequest,
            EmbedResponse, InferenceService, InferenceServiceServer, Label, ModelInfoRequest,
            ModelInfoResponse, VersionRequest, VersionResponse,
        };
        use tonic::{Request, Response, Status};

        struct StubService;

        #[tonic::async_trait]
        impl InferenceService for StubService {
            async fn classify(
                &self,
                _req: Request<ClassifyRequest>,
            ) -> Result<Response<ClassifyResponse>, Status> {
                Ok(Response::new(ClassifyResponse {
                    labels: vec![Label {
                        name: "injection".to_string(),
                        score: 0.93,
                    }],
                    latency_us: 1,
                }))
            }
            async fn embed(
                &self,
                _req: Request<EmbedRequest>,
            ) -> Result<Response<EmbedResponse>, Status> {
                Ok(Response::new(EmbedResponse {
                    embeddings: vec![],
                    latency_us: 1,
                }))
            }
            async fn compress(
                &self,
                _req: Request<CompressRequest>,
            ) -> Result<Response<CompressResponse>, Status> {
                Err(Status::unimplemented("not used by this test"))
            }
            async fn model_info(
                &self,
                _req: Request<ModelInfoRequest>,
            ) -> Result<Response<ModelInfoResponse>, Status> {
                Ok(Response::new(ModelInfoResponse {
                    model: "stub".into(),
                    loaded: true,
                    labels: vec![],
                    embedding_dim: 0,
                }))
            }
            async fn version(
                &self,
                _req: Request<VersionRequest>,
            ) -> Result<Response<VersionResponse>, Status> {
                Ok(Response::new(VersionResponse {
                    version: "stub".into(),
                    models: vec!["stub".into()],
                }))
            }
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let addr = listener.local_addr().unwrap();
        let stream = tokio_stream::wrappers::TcpListenerStream::new(listener);
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(InferenceServiceServer::new(StubService))
                .serve_with_incoming(stream)
                .await
                .unwrap();
        });

        let sidecar = ClassifierClient::connect(
            &format!("http://{addr}"),
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .await
        .expect("connect to the stub sidecar");

        let calls = Arc::new(AtomicUsize::new(0));
        let classifier = FallbackClassifier::new(
            Some(sidecar),
            "prompt-injection",
            CountingInProcess {
                calls: Arc::clone(&calls),
                verdict: Verdict {
                    label: "should-not-be-used".to_string(),
                    score: 0.0,
                },
            },
        );

        let verdict = classifier.classify("ignore previous instructions").await;
        assert_eq!(verdict.label, "injection");
        assert_eq!(verdict.score, 0.93);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a healthy sidecar answer must not also run the in-process classifier"
        );
    }
}

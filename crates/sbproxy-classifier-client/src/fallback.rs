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
                tracing::warn!(
                    "classifier sidecar returned zero labels despite client validation; \
                     degrading to in-process classifier"
                );
                self.inprocess.classify(text)
            }
            Err(err) => self.on_sidecar_error(text, &err),
        }
    }

    fn on_sidecar_error(&self, text: &str, err: &ClassifierClientError) -> Verdict {
        tracing::warn!(
            error = %err,
            "classifier sidecar unavailable; degrading to in-process classifier"
        );
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

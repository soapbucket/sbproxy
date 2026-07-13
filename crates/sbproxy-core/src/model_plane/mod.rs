//! Authenticated private model-plane request primitives.

mod client;
mod envelope;
mod execution;
mod replay;
mod server;

pub use client::{ModelPlaneClient, ModelPlaneClientSecurity, ModelPlaneResponse};
pub use envelope::{
    body_sha256_hex, DispatchAuthProof, DispatchEnvelope, DispatchEnvelopeError, DispatchSigner,
    DispatchVerifier, SignedDispatchEnvelope, VerifiedDispatch, DISPATCH_ENVELOPE_SCHEMA_VERSION,
    DISPATCH_PROOF_CONTEXT, MAX_SIGNED_DISPATCH_ENVELOPE_BYTES,
};
pub use execution::{PreparedWorkerExecution, WorkerModelExecution};
pub use replay::DispatchReplayFence;
pub use server::{
    ModelPlaneServer, ModelPlaneServerConfig, ModelPlaneServerHandle, ModelPlaneServerSecurity,
    MODEL_PLANE_DISPATCH_PATH, MODEL_PLANE_PATH_PREFIX,
};

/// Stable private model-plane failure taxonomy.
#[derive(Debug, thiserror::Error)]
pub enum ModelPlaneError {
    /// The dispatch named a generation no longer assigned to this worker.
    #[error("stale managed deployment generation")]
    StaleDeploymentGeneration,
    /// The deployment is not assigned to this worker.
    #[error("managed deployment is not assigned to this worker")]
    DeploymentNotAssigned,
    /// Bounded worker admission rejected the request.
    #[error(transparent)]
    Admission(#[from] sbproxy_model_host::AdmissionRejection),
    /// Worker lifecycle or engine preparation failed.
    #[error(transparent)]
    Runtime(#[from] sbproxy_model_host::RuntimeManagerError),
    /// Signed dispatch validation or authentication failed.
    #[error(transparent)]
    Envelope(#[from] DispatchEnvelopeError),
    /// Request or response bytes exceeded the configured bound.
    #[error("model-plane body exceeds its configured bound")]
    BodyTooLarge,
    /// Internal model-plane request shape was invalid.
    #[error("invalid model-plane request")]
    InvalidRequest,
    /// Listener or client configuration was invalid.
    #[error("invalid model-plane configuration: {0}")]
    InvalidConfiguration(String),
    /// TLS setup or negotiation failed.
    #[error("model-plane TLS failed: {0}")]
    Tls(String),
    /// HTTP/2 connection or stream transport failed before output.
    #[error("model-plane transport failed: {0}")]
    Transport(String),
    /// The local engine upstream failed before or during response streaming.
    #[error("managed engine upstream failed: {0}")]
    Upstream(String),
    /// The remote worker returned a stable internal failure.
    #[error("remote model-plane dispatch failed: {code}")]
    Remote {
        /// Stable remote error code.
        code: String,
        /// Whether another current replica may be attempted before output.
        retryable: bool,
    },
    /// The listener stopped accepting or cancelled outstanding work.
    #[error("model-plane listener is shutting down")]
    Shutdown,
}

impl ModelPlaneError {
    /// Stable machine-readable error code.
    pub fn code(&self) -> &str {
        match self {
            Self::StaleDeploymentGeneration => "stale_deployment_generation",
            Self::DeploymentNotAssigned => "deployment_not_assigned",
            Self::Admission(error) => error.reason.as_str(),
            Self::Runtime(error) => error.reason_code(),
            Self::Envelope(error) => error.code(),
            Self::BodyTooLarge => "body_too_large",
            Self::InvalidRequest => "invalid_request",
            Self::InvalidConfiguration(_) => "invalid_configuration",
            Self::Tls(_) => "tls_failed",
            Self::Transport(_) => "transport_failed",
            Self::Upstream(_) => "upstream_failed",
            Self::Remote { code, .. } => code,
            Self::Shutdown => "listener_shutdown",
        }
    }

    /// Whether a different current replica may safely be attempted before output.
    pub fn retryable(&self) -> bool {
        match self {
            Self::StaleDeploymentGeneration
            | Self::DeploymentNotAssigned
            | Self::Transport(_)
            | Self::Upstream(_)
            | Self::Shutdown => true,
            Self::Admission(error) => error.retryable,
            Self::Runtime(sbproxy_model_host::RuntimeManagerError::Admission(error)) => {
                error.retryable
            }
            Self::Runtime(error) => matches!(
                error,
                sbproxy_model_host::RuntimeManagerError::PrepareInfrastructure(_)
                    | sbproxy_model_host::RuntimeManagerError::Engine(_)
                    | sbproxy_model_host::RuntimeManagerError::Draining(_)
            ),
            Self::Remote { retryable, .. } => *retryable,
            Self::Envelope(_)
            | Self::BodyTooLarge
            | Self::InvalidRequest
            | Self::InvalidConfiguration(_)
            | Self::Tls(_) => false,
        }
    }
}

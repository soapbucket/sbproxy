//! Authenticated private model-plane request primitives.

mod envelope;
mod replay;

pub use envelope::{
    body_sha256_hex, DispatchAuthProof, DispatchEnvelope, DispatchEnvelopeError, DispatchSigner,
    DispatchVerifier, SignedDispatchEnvelope, VerifiedDispatch, DISPATCH_ENVELOPE_SCHEMA_VERSION,
    DISPATCH_PROOF_CONTEXT,
};
pub use replay::DispatchReplayFence;

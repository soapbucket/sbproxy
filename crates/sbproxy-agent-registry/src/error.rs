//! The closed error set this crate refuses with.
//!
//! Every variant carries what the caller needs to act rather than a
//! formatted string it would have to parse: an admin handler maps a variant
//! onto an HTTP status and a stable `code`, and the metrics recorder maps
//! the same variant onto a bounded `outcome` label. Adding a variant is
//! therefore a deliberate act in three places at once, which is the point.

use thiserror::Error;

/// Anything this crate refuses.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RegistryError {
    /// The body did not parse, or a field was outside its documented range.
    #[error("invalid {field}: {detail}")]
    Invalid {
        /// Which field was wrong. A fixed vocabulary, safe as a metric label.
        field: &'static str,
        /// What was wrong with it. Never echoes a secret.
        detail: String,
    },

    /// A signed document did not verify against the key it names.
    #[error("signature verification failed: {0}")]
    Signature(String),

    /// The feed named a signing key the directory does not vouch for, or
    /// vouches for only in its revoked list.
    #[error("unknown or revoked signing key: {0}")]
    UnknownKey(String),

    /// The feed is past its `expires_at`, plus whatever stale grace the
    /// operator allowed.
    #[error("feed expired at {expired_at}, past the configured stale grace")]
    FeedExpired {
        /// The envelope's own expiry, in RFC 3339.
        expired_at: String,
    },

    /// The document declares a `format_version` this build does not
    /// understand. Refusing forward is deliberate: a newer publisher may
    /// have added a field whose absence changes meaning.
    #[error("feed format_version {found} is newer than the supported {supported}")]
    UnsupportedFormatVersion {
        /// What the document declared.
        found: u32,
        /// The newest version this build accepts.
        supported: u32,
    },

    /// A submission repeated metadata a reviewer has already refused or
    /// withdrawn. Terminal: the decision is durable and keyed on the
    /// metadata fingerprint, so resubmitting the same description gets the
    /// same answer forever rather than a fresh queue slot and a second
    /// reviewer.
    #[error("this registration was already {decision} as {agent_id} and cannot be resubmitted")]
    MetadataBurned {
        /// The registration that carries the decision.
        agent_id: String,
        /// What was decided. A fixed vocabulary, safe as a metric label.
        decision: &'static str,
    },

    /// A submission repeated metadata that is already live: an approved
    /// agent, or another submission inside the duplicate-detection window.
    #[error("a registration with identical metadata already exists as {0}")]
    DuplicateMetadata(String),

    /// The pending queue is at its cap.
    ///
    /// A queue with no bound is a disk-exhaustion primitive handed to
    /// whoever can reach the submission route, and the operator fronting it
    /// for public self-service (see `docs/agent-registry.md`) is exactly the
    /// deployment where that reach is a stranger's. Refusing is recoverable:
    /// a reviewer working the queue down makes room, and the submitter can
    /// try again.
    #[error("the pending registration queue is at its limit of {limit}; try again once a reviewer has worked it down")]
    QueueFull {
        /// The cap that was reached.
        limit: usize,
    },

    /// No registration under that id.
    #[error("no registration {0}")]
    NotFound(String),

    /// The caller did not present the registration access token this
    /// registration was issued with. The message never says whether the
    /// registration exists, so a wrong token and a wrong id are
    /// indistinguishable to the caller.
    #[error("registration access token rejected")]
    Unauthorized,

    /// The requested transition is not one the state machine allows.
    #[error("cannot {action} a registration in state {state}")]
    InvalidTransition {
        /// What was attempted. Fixed vocabulary.
        action: &'static str,
        /// The state it was attempted from. Fixed vocabulary.
        state: &'static str,
    },

    /// Another writer changed the record between the read and the write.
    /// The caller re-reads and retries; nothing was clobbered.
    #[error("registration {0} changed while the decision was being applied")]
    Conflict(String),

    /// The embedded store, the filesystem, or the hasher failed.
    #[error("agent registry backend: {0}")]
    Backend(String),
}

impl RegistryError {
    /// Stable, low-cardinality label this refusal is counted under on
    /// `sbproxy_agent_registry_operations_total`.
    pub fn outcome(&self) -> &'static str {
        match self {
            Self::Invalid { .. } => "invalid",
            Self::Signature(_) => "bad_signature",
            Self::UnknownKey(_) => "unknown_key",
            Self::FeedExpired { .. } => "expired",
            Self::UnsupportedFormatVersion { .. } => "unsupported_version",
            Self::MetadataBurned { .. } => "burned",
            Self::QueueFull { .. } => "queue_full",
            Self::DuplicateMetadata(_) => "duplicate",
            Self::NotFound(_) => "not_found",
            Self::Unauthorized => "unauthorized",
            Self::InvalidTransition { .. } => "invalid_transition",
            Self::Conflict(_) => "conflict",
            Self::Backend(_) => "error",
        }
    }

    /// HTTP status an admin handler answers this refusal with.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::Invalid { .. }
            | Self::Signature(_)
            | Self::UnknownKey(_)
            | Self::FeedExpired { .. }
            | Self::UnsupportedFormatVersion { .. } => 400,
            Self::Unauthorized => 401,
            Self::MetadataBurned { .. } | Self::DuplicateMetadata(_) | Self::Conflict(_) => 409,
            // 429 rather than 503: the refusal is about how much is
            // already queued, not about the registry being unavailable,
            // and a submitter reading Retry-After semantics into it is
            // reading it right.
            Self::QueueFull { .. } => 429,
            Self::NotFound(_) => 404,
            Self::InvalidTransition { .. } => 422,
            Self::Backend(_) => 500,
        }
    }
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, RegistryError>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Both mappings are exhaustive by construction (the compiler proves
    /// that), but the values themselves are a contract: the outcome label
    /// set is what the dashboard queries and the status is what an operator
    /// scripts against. Pinning a representative of each class here means a
    /// silent reclassification is a test failure.
    #[test]
    fn refusals_map_to_stable_outcomes_and_statuses() {
        let cases: Vec<(RegistryError, &str, u16)> = vec![
            (
                RegistryError::Invalid {
                    field: "vendor",
                    detail: "too long".into(),
                },
                "invalid",
                400,
            ),
            (RegistryError::Signature("bad".into()), "bad_signature", 400),
            (
                RegistryError::MetadataBurned {
                    agent_id: "acme-1".into(),
                    decision: "rejected",
                },
                "burned",
                409,
            ),
            (
                RegistryError::DuplicateMetadata("acme-1".into()),
                "duplicate",
                409,
            ),
            (RegistryError::QueueFull { limit: 5_000 }, "queue_full", 429),
            (RegistryError::NotFound("acme-1".into()), "not_found", 404),
            (RegistryError::Unauthorized, "unauthorized", 401),
            (
                RegistryError::InvalidTransition {
                    action: "approve",
                    state: "rejected",
                },
                "invalid_transition",
                422,
            ),
            (RegistryError::Conflict("acme-1".into()), "conflict", 409),
            (RegistryError::Backend("redb".into()), "error", 500),
        ];
        for (error, outcome, status) in cases {
            assert_eq!(error.outcome(), outcome, "{error}");
            assert_eq!(error.http_status(), status, "{error}");
        }
    }
}

//! Error types shared across this crate's key management, revocation,
//! and CoMP marketplace modules.
//!
//! The set is scoped to what this crate can actually produce. OLP
//! license-token *verification* (expiry, audience, route-glob,
//! license-URN mismatch) is not one of them: that check already runs
//! OSS-side against the CAP-protected request path (see
//! `docs/glossary.md`'s OLP entry and `crates/sbproxy-modules/src/olp.rs`),
//! and this crate only ever mints tokens in that same wire format, it
//! never verifies one. A variant this crate cannot construct would be
//! a guard narrower than its name.

use thiserror::Error;

/// Closed error set for the licensing crate.
#[derive(Debug, Error)]
pub enum LicensingError {
    // --- Token / message shape ---
    /// Message shape is wrong (missing dots, header decode fails,
    /// claim decode fails, bad base64).
    #[error("malformed message: {0}")]
    Malformed(String),

    /// A signing key id could not be resolved against the active or
    /// retained verifier set.
    #[error("unknown signing key id: {0}")]
    UnknownKey(String),

    /// A presented signature used an algorithm this crate does not
    /// support (only Ed25519 / `EdDSA` is accepted anywhere here).
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlg(String),

    /// A message declared a protocol version, or a JWS `typ`, this
    /// crate does not recognize.
    #[error("unsupported type: {0}")]
    UnsupportedType(String),

    /// Signature did not validate against the resolved public key.
    #[error("signature invalid")]
    SignatureInvalid,

    /// A CoMP request named a `tier_id` this publisher's manifest does
    /// not declare.
    ///
    /// Its own variant rather than an [`Self::Encode`] the HTTP layer
    /// substring-matches: the status this maps to is 404, and matching
    /// on message text means rewording the message silently turns that
    /// 404 into a 500.
    #[error("unknown tier_id: {0}")]
    UnknownTier(String),

    /// A quote was requested while the issued-quote ledger was full.
    ///
    /// The ledger is bounded because `POST /quote` is unauthenticated
    /// and, on the proxy, returns before the policy chain where rate
    /// limits live: an unbounded map there is an OOM one client can
    /// drive. Its own variant rather than [`Self::Encode`] so the HTTP
    /// layer can answer 429 and an operator can tell "we are being
    /// flooded" from "something broke".
    #[error("quote ledger is full (capacity {capacity})")]
    QuoteLedgerFull {
        /// Row cap the ledger was configured with.
        capacity: usize,
    },

    /// A redeem named a `quote_id` that was already redeemed.
    ///
    /// A quote is single-use. The buyer signature covers the request
    /// body with its own value cleared, so replaying costs a buyer
    /// nothing; without this the same purchase mints a fresh license
    /// token per call for the whole quote validity window.
    #[error("quote already redeemed: {0}")]
    AlreadyRedeemed(String),

    /// A redeem named a `quote_id` this process never issued.
    ///
    /// Its own variant rather than [`Self::Expired`]: an expired quote
    /// is one this bridge signed and can name a `valid_until` for,
    /// while an unknown one is a claim about a quote nothing here has
    /// ever seen. They map to the same 403 but they are different
    /// operator problems, and only one of them means someone is
    /// fabricating quote ids.
    #[error("unknown quote_id: {0}")]
    UnknownQuote(String),

    /// A time-bounded object (a CoMP quote) is being redeemed after
    /// its `valid_until` has passed.
    #[error("expired (exp={exp}, now={now})")]
    Expired {
        /// The object's expiry, unix seconds.
        exp: u64,
        /// Wall clock at check time, unix seconds.
        now: u64,
    },

    // --- Revocation ---
    /// The referenced id (a license `jti` or a CoMP `quote_id`) has
    /// been revoked.
    #[error("revoked: {0}")]
    Revoked(String),

    /// The revocation backend itself returned an error, distinct from
    /// [`Self::Revoked`] so a caller can choose fail-open vs
    /// fail-closed independently of "yes, definitely revoked".
    #[error("revocation backend error: {0}")]
    RevocationBackend(String),

    // --- Generic ---
    /// Internal encode/decode failure, or a marketplace-level lookup
    /// failure (e.g. an unknown `tier_id`). Should not occur in the
    /// steady state; treated as an invariant violation upstream.
    #[error("encode error: {0}")]
    Encode(String),
}

impl From<serde_json::Error> for LicensingError {
    fn from(err: serde_json::Error) -> Self {
        Self::Encode(err.to_string())
    }
}

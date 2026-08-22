//! Errors raised by the federation crate. Each variant maps onto a
//! specific failure surface so an operator sees the failure category
//! rather than a free-text message.

use thiserror::Error;

/// Failure modes for entity statement sign / verify / parse paths.
#[derive(Debug, Error)]
pub enum FederationError {
    /// The configured signing key did not parse as a recognised PEM
    /// shape (PKCS#8 EC private key, RSA private key, or Ed25519).
    #[error("federation signing key did not parse: {0}")]
    InvalidSigningKey(String),
    /// The configured algorithm slug was outside the OIDF-recommended
    /// set (ES256/ES384/RS256/RS384/RS512/PS256/PS384/PS512/EdDSA).
    /// Symmetric algorithms are intentionally rejected: an entity
    /// statement MUST be verifiable by any peer holding the issuer's
    /// public key.
    #[error("algorithm `{0}` not in the OIDF allowlist")]
    AlgorithmNotAllowed(String),
    /// JWS encode failed: usually a downstream `jsonwebtoken` error
    /// surfaced verbatim. Carries the inner string so a `tracing::warn!`
    /// emits the actionable bit.
    #[error("JWS encode failed: {0}")]
    EncodeFailed(String),
    /// JWS decode / signature verification failed. Catch-all for
    /// `jsonwebtoken::errors::Error`: the verifier deliberately does
    /// not leak which step rejected the token (alg, kid, signature,
    /// claims) to avoid feeding an attacker.
    #[error("JWS decode or verification failed")]
    VerificationFailed,
    /// The JWS header did not carry `typ = "entity-statement+jwt"`.
    /// Per §3, every entity statement MUST advertise this typ so a
    /// downstream verifier can refuse an arbitrary access token that
    /// was mis-routed into the federation surface.
    #[error("JWS typ is not `entity-statement+jwt` (got: {0:?})")]
    WrongTyp(Option<String>),
    /// The JWS header was missing a `kid` (key id). The OIDF spec
    /// makes `kid` mandatory so the verifier can pick the right
    /// public key from the issuer's `jwks`.
    #[error("JWS header is missing `kid`")]
    MissingKid,
    /// The JWS header `kid` did not match any key in the resolved
    /// issuer's `jwks`. Either the issuer rotated keys without
    /// republishing or the verifier was fed a forged statement.
    #[error("JWS `kid` `{0}` does not match any key in the issuer's jwks")]
    UnknownKid(String),
    /// The decoded claims were missing a required field. Per §3 the
    /// required fields are `iss`, `sub`, `iat`, `exp`, `jwks`.
    #[error("entity statement is missing required claim `{0}`")]
    MissingClaim(&'static str),
    /// The JWK in `jwks` could not be lifted to a verifier key. Some
    /// JWK shapes (oct / unsupported curves) are intentionally
    /// rejected; OIDF requires asymmetric keys only.
    #[error("JWK `{kid}` of kty `{kty}` is not supported as a federation key")]
    UnsupportedJwk {
        /// `kid` of the offending JWK so the operator can find it.
        kid: String,
        /// Key-type slug (`EC` / `RSA` / `OKP` / `oct`).
        kty: String,
    },
    /// The trust-chain resolver was handed an empty chain. Either
    /// the caller forgot to fetch the leaf's own configuration or
    /// the fetcher failed silently.
    #[error("trust chain is empty")]
    ChainEmpty,
    /// The supplied chain exceeded the configured depth cap. The cap
    /// is a denial-of-service defence: a runaway chain forces N
    /// signature checks per resolve call.
    #[error("trust chain length {got} exceeds max_depth {max}")]
    ChainTooLong {
        /// Actual chain length the resolver was handed.
        got: usize,
        /// Configured maximum.
        max: usize,
    },
    /// A leaf Entity Configuration MUST have `iss == sub` (§9). When
    /// the validator sees a leaf with mismatched `iss` / `sub`, the
    /// caller probably handed it a Subordinate Statement by mistake.
    #[error("leaf entity statement is not self-signed (iss != sub)")]
    LeafNotSelfSigned,
    /// A trust anchor MUST be self-signed: an entity configuration
    /// served at the anchor's own well-known endpoint. A non-self-
    /// signed tail cannot be the chain's terminal authority.
    #[error("trust-anchor entity statement is not self-signed (iss != sub)")]
    AnchorNotSelfSigned,
    /// The chain's tail entity URL is not in the configured trust
    /// anchor store. Either the operator forgot to pin this anchor
    /// or the chain is reaching for an untrusted authority.
    #[error("chain ends at `{entity_id}` which is not a configured trust anchor")]
    UnknownTrustAnchor {
        /// Entity URL the tail of the chain claims to be.
        entity_id: String,
    },
    /// Two adjacent steps in the chain do not link: the §9.2
    /// algorithm expects the next statement's `sub` to identify the
    /// entity that signed the prior statement. A mismatch means the
    /// chain was forged, mis-ordered, or built from statements
    /// fetched out of the right authority_hints walk.
    #[error("chain link broken: expected sub `{expected_sub}`, got `{actual_sub}`")]
    ChainLinkBroken {
        /// The `sub` the validator expected at this step (the prior
        /// step's `iss`).
        expected_sub: String,
        /// The `sub` actually carried by the statement at this step.
        actual_sub: String,
    },
    /// The chain visits the same entity URL twice. A forged chain
    /// may loop back to an earlier entity to evade the depth cap.
    #[error("chain contains a cycle through entity `{entity_id}`")]
    ChainCycle {
        /// Entity URL that appeared more than once in the chain.
        entity_id: String,
    },
    /// A `metadata_policy` claim was structurally malformed (the
    /// outer container, the per-field operator map, or a specific
    /// operator's value was not the JSON shape the spec defines).
    #[error("metadata_policy shape error: {0}")]
    PolicyShape(String),
    /// `essential = true` was set on a field the leaf did not
    /// publish. Per §6.1 the policy applicator MUST reject the
    /// resolved metadata in this case.
    #[error("metadata_policy `essential` field `{field}` is missing from the leaf")]
    PolicyEssentialMissing {
        /// Name of the policy-essential field that was absent.
        field: String,
    },
    /// `one_of` was set on a field and the leaf's value was not in
    /// the allowed set.
    #[error("metadata_policy `one_of` violated for field `{field}`")]
    PolicyOneOfViolated {
        /// Name of the field whose value was outside the allowed set.
        field: String,
    },
    /// `subset_of` was set on a field and the leaf's array carried
    /// an element outside the allowed set.
    #[error("metadata_policy `subset_of` violated for field `{field}` (value {offending_value})")]
    PolicySubsetViolated {
        /// Name of the field whose array was not a subset.
        field: String,
        /// Stringified offending value the leaf published.
        offending_value: String,
    },
    /// `superset_of` was set on a field and the leaf's array did
    /// not include a required element.
    #[error(
        "metadata_policy `superset_of` violated for field `{field}` (missing {missing_value})"
    )]
    PolicySupersetViolated {
        /// Name of the field whose array was not a superset.
        field: String,
        /// Stringified required value the leaf failed to include.
        missing_value: String,
    },
    /// An HTTP fetch against a federation endpoint failed. Carries
    /// the original message so an operator's logs surface the
    /// actionable bit (DNS error, status code, malformed URL).
    #[error("federation HTTP fetch failed: {0}")]
    FetchFailed(String),
    /// The chain composer walked every `authority_hints` path from
    /// the leaf and none ended at a configured trust anchor before
    /// the depth cap fired.
    #[error("no configured trust anchor reachable from entity `{entity_id}`")]
    ChainNoAnchorFound {
        /// Entity URL the walk started from.
        entity_id: String,
    },
    /// A superior fetched during the chain walk did not advertise a
    /// `federation_fetch_endpoint` in its `federation_entity`
    /// metadata block, so the composer cannot pull the next
    /// Subordinate Statement.
    #[error("superior `{entity_id}` is missing federation_fetch_endpoint metadata")]
    SuperiorMissingFetchEndpoint {
        /// Entity URL of the superior that lacked the endpoint.
        entity_id: String,
    },
}

/// Convenience alias the crate's public functions return.
pub type FederationResult<T> = Result<T, FederationError>;

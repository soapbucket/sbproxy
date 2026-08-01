// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Receipt-token JWS signer and verifier: the sibling of the quote token.
//!
//! A quote token proves what a call was going to cost. A receipt proves what
//! was actually consumed. Neither is an invoice on its own: a price with no
//! quantity is a rate card, and a quantity with no price is a log line.
//! Together they are one invoice line, which is why they are signed by the
//! same key family and published through the same JWKS. A buyer settling a
//! bill fetches one key set and checks both halves of the line with it,
//! instead of discovering a second key-distribution problem at the moment
//! they were ready to pay.
//!
//! ## Wire shape
//!
//! Compact JWS (RFC 7515) with `alg=EdDSA`, `typ=sbproxy-receipt+jws`, and a
//! `kid` selecting the JWKS entry that verifies the signature. That is the
//! quote token's shape ([`quote_token`](super::quote_token)) with exactly one
//! field changed, and the sameness is deliberate: a verifier that already
//! knows how to check one has nothing new to learn, and the single differing
//! field is what keeps the two from being mistaken for each other.
//! [`ReceiptTokenVerifier::verify`] rejects a quote token on `typ` before it
//! touches the signature, and the quote verifier does the same to a receipt.
//!
//! ## The claim types are wire types, and drift is a compile error
//!
//! [`ReceiptSubject`], [`ReceiptUnit`], and [`ReceiptEvidence`] mirror the
//! metering vocabulary [`sbproxy_meter`] defines for internal use, as
//! separate types rather than re-exports, and every closed set arrives here
//! as a `String`.
//!
//! That is not laziness about types, it is the correct shape for a signed
//! artifact that strangers parse. A buyer's verifier is compiled once and
//! then has to keep working. If the wire carried a closed Rust enum, adding a
//! fourth unit source next quarter would turn every receipt written after
//! that date into an unparseable document for every verifier written before
//! it, and a receipt nobody outside this repository can read is not evidence
//! of anything. Internally the enums are exactly right, because in here a new
//! variant *should* stop the build until somebody handles it. The two
//! requirements are opposites, so they get two types.
//!
//! Two types that must agree is how formats drift, so agreement is enforced
//! by the compiler rather than by a convention or a test. The `From` impls
//! on the three wire types, and [`outcome_wire_name`], match exhaustively
//! with no wildcard arm and destructure with no `..`. Add a variant to
//! [`UnitSource`], [`Evidence`], or [`BillableOutcome`], or a field to
//! [`Subject`] or [`Unit`], and this crate stops compiling until the wire
//! format is updated on purpose. A test can be deleted or marked ignored; a
//! non-exhaustive match cannot.
//!
//! ## A receipt is not single-use
//!
//! The quote verifier makes a nonce store structurally mandatory and burns
//! the nonce as the last step of every verification, because a quote that
//! redeems twice is a call that was paid for once and served twice. None of
//! that reasoning transfers. A receipt is a statement about something that
//! already happened, and a buyer who reconciles their invoice in March and
//! again in August must get the same answer both times. So a receipt carries
//! no nonce, and [`ReceiptTokenVerifier::verify`] consumes nothing.
//!
//! A store can still be injected (see
//! [`ReceiptTokenVerifier::with_nonce_store`]) for an embedder that wants
//! at-most-once *settlement*, which is a different question from whether the
//! signature checks out. Settlement is then an explicit call at the call
//! site rather than a side effect of verifying, and it defaults to absent.
//!
//! ## Key rotation is not implemented here
//!
//! [`ReceiptTokenVerifier::with_keys`] accepts a map because the JWKS shape
//! is a map, not because anything rotates keys today. Nothing in this
//! workspace adds a second key or retires a first one, so there is no
//! rotation window to describe and this module does not pretend to offer
//! one. Rotation for the shared quote and receipt key family is tracked as
//! WOR-2135.

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sbproxy_meter::{BillableOutcome, Evidence, Subject, Unit, UnitSource};
use serde::{Deserialize, Serialize};

use super::quote_token::NonceStore;

/// The `typ` header value that marks a compact JWS as a receipt.
///
/// Vendor-specific on purpose. An ordinary application JWT, and in
/// particular a quote token minted by the same key, is rejected on this
/// field before any signature work happens.
pub const RECEIPT_JWS_TYP: &str = "sbproxy-receipt+jws";

// --- Public claim types ---

/// Decoded JWS payload for a receipt token.
///
/// The field order below is the wire order: the signature covers
/// `serde_json`'s output for this struct, and `serde_json` emits fields in
/// declaration order. Reordering a field changes the bytes that were signed
/// and invalidates every receipt already issued. Treat the order as frozen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptClaims {
    /// Zero-based position of this receipt in its node's chain.
    ///
    /// A signature on each receipt says nothing about receipts that were
    /// never written, which is the half of a billing dispute that reads "I
    /// made calls you never credited". `seq` and [`ReceiptClaims::prev`]
    /// together are what make a gap visible.
    pub seq: u64,
    /// Hex digest of the preceding receipt in the same chain, or the
    /// all-zero genesis digest for the first one.
    pub prev: String,
    /// Identifier of the node that wrote this receipt.
    ///
    /// Chains are per node. Two nodes serving the same tenant each write
    /// their own sequence, so a `seq` is only meaningful next to the
    /// `node_id` it was counted under.
    pub node_id: String,
    /// Groups every attempt at one unit of work under a single invoice line.
    ///
    /// A ULID string. Retries of the same call share it, which is what lets
    /// a settlement pass charge four attempts once instead of four times.
    pub claim_id: String,
    /// The commercial agreement the units are billed under.
    ///
    /// Names which price list applied. Without it a receipt says how much
    /// was consumed but not which contract turns that into money.
    pub agreement_id: String,
    /// Who the consumption is charged to.
    pub subject: ReceiptSubject,
    /// The route that matched, as the operator named it in config.
    pub route: String,
    /// Digest of the request bytes, when a complete body was available to
    /// hash.
    ///
    /// Optional, and that is a statement about this proxy rather than a
    /// hedge. The wired RFC 9421 egress signer covers `@authority`,
    /// `@method`, and `@path` over an empty body and emits no
    /// `Content-Digest` on the request path at all, because the auth phase
    /// does not buffer the request body. There is therefore no request-side
    /// digest to reuse, and computing one here would mean buffering bodies
    /// that nothing else in the request path buffers.
    ///
    /// Present when a body was actually available and hashed in full; absent
    /// otherwise. Never a digest over a partial body: a digest that claims
    /// to cover bytes it does not cover is worse than no digest, because it
    /// reads as proof right up until somebody checks it. See
    /// [`receipt_content_digest`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_digest: Option<String>,
    /// Digest of the response bytes, when there was a complete response.
    ///
    /// Absent when there was not. A blocked, rate-limited, or cut-short
    /// request produced no complete response, and the same rule applies as
    /// for [`ReceiptClaims::request_digest`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_digest: Option<String>,
    /// Everything billable this pass accrued.
    ///
    /// On a cut-short response this is what accrued before the cut, not what
    /// would have accrued had it finished.
    pub units: Vec<ReceiptUnit>,
    /// What happened, in the terms a billing rule cares about.
    ///
    /// Carries the metering vocabulary's snake-case outcome name
    /// (`delivered`, `client_disconnected`, `origin_4xx`, `origin_5xx`,
    /// `policy_blocked`, `rate_limited`, `cache_hit`, `retry`). A `String`
    /// rather than an enum on the wire type for the same reason the quote
    /// token keeps `rail` and `shape` as strings: a verifier built against
    /// today's set must still parse a receipt written after the set grows.
    pub outcome: String,
    /// Which configuration priced this call.
    ///
    /// A content hash rather than a number: the first 12 hex characters of
    /// the SHA-256 of the serialized config, which is what this codebase
    /// already stamps on webhook envelopes and admin responses. There is no
    /// numeric config generation anywhere in this workspace, and a content
    /// hash is the better primitive regardless. Two nodes running the same
    /// config stamp the same value, whereas a per-process counter would have
    /// them disagree about a config they both loaded from one file.
    ///
    /// This is the field that answers "you priced my call under a config I
    /// never agreed to".
    pub config_revision: String,
}

/// Who the consumption is charged to.
///
/// Three fields rather than one opaque account id, because a dispute is
/// usually about a slice rather than the whole bill. An operator who can
/// only say "your account used 40,000 units" cannot answer "which key, and
/// which agent" without going back to raw logs, and raw logs are what the
/// receipt was meant to replace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptSubject {
    /// The billing account the units are charged to. Always present: a unit
    /// with nobody to charge is not a metering event, it is a bug.
    pub tenant: String,
    /// Identifier of the credential that authenticated the call.
    ///
    /// An identifier, never key material. Absent when the route admits
    /// unauthenticated traffic that is still metered against a tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// The calling agent, when one identified itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
}

/// One billable quantity on a receipt.
///
/// A count on its own is unfalsifiable, and an unfalsifiable receipt is
/// worthless in a dispute, so every unit carries where its number came from
/// and the raw material behind it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptUnit {
    /// Operator-chosen unit name, for example `search_call` or `egress_kib`.
    /// This is the name that appears on the invoice line.
    pub name: String,
    /// How many of the unit were consumed.
    pub count: u64,
    /// Which mechanism produced [`ReceiptUnit::count`].
    ///
    /// Carries the metering vocabulary's snake-case source name
    /// (`measured`, `route_weight`, `origin_header`). A `String` on the wire
    /// type for the same reason [`ReceiptClaims::outcome`] is one.
    pub source: String,
    /// The raw material [`ReceiptUnit::count`] was derived from.
    pub evidence: ReceiptEvidence,
}

/// The raw material a unit count was derived from.
///
/// One variant per unit source, carrying whatever a person auditing the
/// receipt needs in order to redo the arithmetic. Serialized untagged,
/// because the sibling [`ReceiptUnit::source`] already names the variant and
/// repeating it would let the two disagree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ReceiptEvidence {
    /// What the proxy observed on the wire. Backs the `measured` source.
    Measured {
        /// Request bytes received from the client.
        bytes_in: u64,
        /// Response bytes written to the client. On a connection that was
        /// cut this is what actually crossed, not what was intended.
        bytes_out: u64,
        /// Wall-clock milliseconds the request was in flight.
        duration_ms: u64,
    },
    /// The config generation that supplied the weight. Backs the
    /// `route_weight` source.
    RouteWeight {
        /// Generation of the configuration that was live when the weight was
        /// read.
        config_gen: u64,
    },
    /// What the origin claimed, verbatim. Backs the `origin_header` source.
    OriginHeader {
        /// Name of the response header the count was read from.
        header: String,
        /// The header value exactly as the origin sent it, never trimmed and
        /// never re-serialized from the parsed number. The disagreement may
        /// be about the parse rather than the number.
        raw: String,
    },
}

// --- Conversions from the metering vocabulary ---
//
// Every conversion below matches exhaustively over the meter's types with no
// wildcard arm and no `..` in any struct pattern. That is the only reason
// this crate depends on `sbproxy-meter` at all: adding a variant or a field
// over there must stop this crate compiling, so that somebody has to decide
// what the new thing means on a signed document that third parties parse.
// See the module documentation.

impl From<&Subject> for ReceiptSubject {
    /// Convert the internal subject into its wire form.
    ///
    /// The destructuring below is load-bearing. It lists every field with no
    /// `..`, so adding a field to the meter's `Subject` breaks this build
    /// rather than silently dropping that field from every receipt the proxy
    /// signs. A dropped field is invisible: the receipt still verifies, and
    /// the missing dimension only surfaces when somebody tries to dispute a
    /// bill with it. Never add `..` here.
    fn from(subject: &Subject) -> Self {
        let Subject {
            tenant,
            key_id,
            agent,
        } = subject;
        Self {
            tenant: tenant.clone(),
            key_id: key_id.clone(),
            agent: agent.clone(),
        }
    }
}

impl From<&Unit> for ReceiptUnit {
    /// Convert one internal billable quantity into its wire form.
    ///
    /// Destructured with no `..` for the same reason as [`ReceiptSubject`]:
    /// a new field on the meter's `Unit` is a new thing a buyer may need in
    /// order to check the arithmetic, and dropping it silently is worse than
    /// failing to build. Never add `..` here.
    fn from(unit: &Unit) -> Self {
        let Unit {
            name,
            count,
            source,
            evidence,
        } = unit;
        Self {
            name: name.clone(),
            count: *count,
            source: unit_source_wire_name(*source),
            evidence: ReceiptEvidence::from(evidence),
        }
    }
}

impl From<&Evidence> for ReceiptEvidence {
    /// Convert the raw material behind a count into its wire form.
    ///
    /// The `match` is exhaustive with no wildcard arm, and each variant is
    /// destructured with no `..`. A new `Evidence` variant is a new class of
    /// proof, and a wildcard arm would have to invent a wire encoding for a
    /// kind of evidence nobody had designed one for, which means either
    /// losing the proof or mislabelling it. Failing the build is the correct
    /// outcome. Never add `_ =>` here.
    fn from(evidence: &Evidence) -> Self {
        match evidence {
            Evidence::Measured {
                bytes_in,
                bytes_out,
                duration_ms,
            } => Self::Measured {
                bytes_in: *bytes_in,
                bytes_out: *bytes_out,
                duration_ms: *duration_ms,
            },
            Evidence::RouteWeight { config_gen } => Self::RouteWeight {
                config_gen: *config_gen,
            },
            Evidence::OriginHeader { header, raw } => Self::OriginHeader {
                header: header.clone(),
                raw: raw.clone(),
            },
        }
    }
}

/// The wire spelling of a billable outcome, for [`ReceiptClaims::outcome`].
///
/// A free function rather than a `From` impl because both types are foreign
/// to this crate and the orphan rule forbids it.
///
/// The `match` is exhaustive with no wildcard arm, and that is load-bearing.
/// A new [`BillableOutcome`] is a new commercial situation the operator has
/// to price, so a wildcard arm mapping it to something plausible would put a
/// word on a signed invoice line that nobody chose. Never add `_ =>` here.
///
/// The literals are written out rather than delegated to the meter's own
/// accessor so that this crate, and not the meter, owns what appears on the
/// wire. `outcome_wire_names_match_the_metering_vocabulary` pins them to
/// agree, which covers the one case the exhaustive match cannot see: an
/// existing variant being renamed rather than a new one being added.
pub fn outcome_wire_name(outcome: BillableOutcome) -> String {
    match outcome {
        BillableOutcome::Delivered => "delivered",
        BillableOutcome::ClientDisconnected => "client_disconnected",
        BillableOutcome::Origin4xx => "origin_4xx",
        BillableOutcome::Origin5xx => "origin_5xx",
        BillableOutcome::PolicyBlocked => "policy_blocked",
        BillableOutcome::RateLimited => "rate_limited",
        BillableOutcome::CacheHit => "cache_hit",
        BillableOutcome::Retry => "retry",
    }
    .to_string()
}

/// The wire spelling of a unit source, for [`ReceiptUnit::source`].
///
/// Exhaustive with no wildcard arm, for the same reason as
/// [`outcome_wire_name`]: a new source is a new provenance claim, and a
/// receipt that labelled it as one of the existing three would be asserting
/// something untrue about where a number came from. Never add `_ =>` here.
fn unit_source_wire_name(source: UnitSource) -> String {
    match source {
        UnitSource::Measured => "measured",
        UnitSource::RouteWeight => "route_weight",
        UnitSource::OriginHeader => "origin_header",
    }
    .to_string()
}

/// JWS protected header for a receipt token.
///
/// A sibling of the quote token's private header struct rather than a shared
/// type, with the same three fields in the same order. Sharing it would make
/// one struct with a `typ` that means two things, which is precisely the
/// confusion the field exists to prevent.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReceiptHeader {
    /// Algorithm; always `"EdDSA"`.
    pub alg: String,
    /// Type tag; always [`RECEIPT_JWS_TYP`].
    pub typ: String,
    /// Key id selecting which JWKS entry verifies this signature.
    pub kid: String,
}

// --- Error types ---

/// Errors returned by [`ReceiptTokenSigner::sign`].
#[derive(Debug, thiserror::Error)]
pub enum ReceiptSignError {
    /// JSON encoding of the header or payload failed.
    #[error("encode error: {0}")]
    Encode(#[from] serde_json::Error),
}

/// Errors returned by [`ReceiptTokenVerifier::verify`].
///
/// Shorter than the quote token's error set, and the absences are the
/// interesting part: no expiry, no clock skew, and no replay. A receipt has
/// no TTL to run out and no nonce to burn.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReceiptVerifyError {
    /// Token shape is wrong (missing segments, or a segment that will not
    /// decode).
    #[error("malformed token: {0}")]
    Malformed(String),
    /// Header `kid` does not match any public key in the JWKS.
    #[error("unknown signing key id: {0}")]
    UnknownKey(String),
    /// Header `alg` is not `EdDSA`.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlg(String),
    /// Header `typ` is not [`RECEIPT_JWS_TYP`]. A quote token presented as a
    /// receipt lands here.
    #[error("unsupported token type: {0}")]
    UnsupportedType(String),
    /// Signature did not validate against the resolved public key.
    #[error("signature invalid")]
    SignatureInvalid,
}

// --- Signer ---

/// Sync signer that produces compact-JWS receipt tokens.
///
/// Holds a key and a key id and nothing else. There is deliberately no
/// `issue()` convenience of the kind the quote signer has: every field of
/// [`ReceiptClaims`] is a fact about something that already happened, owned
/// by the chain (`seq`, `prev`), the pipeline (the digests, the config
/// revision), or the metering pass (the units). A signer filling any of them
/// in would be inventing them.
pub struct ReceiptTokenSigner {
    /// Private key. Never logged; see the [`std::fmt::Debug`] impl.
    signing_key: SigningKey,
    /// `kid` stamped into the JWS header. The verifier looks up the matching
    /// public key in the JWKS by this id.
    key_id: String,
}

impl std::fmt::Debug for ReceiptTokenSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never log the private key bytes; the kid is the safe identifier.
        f.debug_struct("ReceiptTokenSigner")
            .field("kid", &self.key_id)
            .finish()
    }
}

impl ReceiptTokenSigner {
    /// Build a signer from an Ed25519 signing key plus the `kid` that
    /// selects its public half in the JWKS.
    pub fn new(signing_key: SigningKey, key_id: impl Into<String>) -> Self {
        Self {
            signing_key,
            key_id: key_id.into(),
        }
    }

    /// Build a signer from a 32-byte Ed25519 private key seed (raw bytes).
    ///
    /// Pass the same seed the quote signer was built from to put both
    /// tokens on one key family, which is the arrangement the module
    /// documentation describes.
    pub fn from_seed_bytes(seed: &[u8; 32], key_id: impl Into<String>) -> Self {
        Self::new(SigningKey::from_bytes(seed), key_id)
    }

    /// Active signing key id.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The matching public key. Use this to seed a
    /// [`ReceiptTokenVerifier`] in single-host deployments where signer and
    /// verifier coexist.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Sign a fully-populated [`ReceiptClaims`].
    ///
    /// The signed bytes are the ASCII of `<header_b64>`, one `.`, and
    /// `<payload_b64>`. Nothing else is covered and nothing else may be
    /// added.
    pub fn sign(&self, claims: &ReceiptClaims) -> Result<String, ReceiptSignError> {
        let header = ReceiptHeader {
            alg: "EdDSA".to_string(),
            typ: RECEIPT_JWS_TYP.to_string(),
            kid: self.key_id.clone(),
        };
        // Compact `serde_json` output in struct declaration order, NOT RFC
        // 8785 JCS. This repository contains both conventions, so the choice
        // is worth stating: the receipt is the quote token's sibling and
        // matching it byte-for-byte is the whole point, since a verifier
        // that can check one can check the other. Switching to JCS here
        // would sort the keys, change the signed bytes, and invalidate every
        // receipt already issued. Do not "fix" this.
        let header_json = serde_json::to_vec(&header)?;
        let payload_json = serde_json::to_vec(claims)?;
        let header_b64 = base64_url_encode(&header_json);
        let payload_b64 = base64_url_encode(&payload_json);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = self.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = base64_url_encode(&signature.to_bytes());
        Ok(format!("{header_b64}.{payload_b64}.{sig_b64}"))
    }
}

// --- Verifier ---

/// Stateless verifier for compact-JWS receipt tokens.
///
/// Holds the JWKS (kid to public key) and, optionally, a settlement store
/// that [`ReceiptTokenVerifier::verify`] never touches. Verification is pure:
/// the same token verifies the same way forever, from any process, with no
/// state anywhere.
pub struct ReceiptTokenVerifier {
    /// Trusted public keys by `kid`.
    public_keys: HashMap<String, VerifyingKey>,
    /// Optional settlement store. Absent by default, and absent is the
    /// normal case: checking a receipt's signature and deciding whether its
    /// claim has already been paid are different questions asked by
    /// different callers at different times. Nothing in this type consults
    /// it; see [`ReceiptTokenVerifier::nonce_store()`].
    nonce_store: Option<Arc<dyn NonceStore>>,
}

impl std::fmt::Debug for ReceiptTokenVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut kids: Vec<&String> = self.public_keys.keys().collect();
        kids.sort();
        f.debug_struct("ReceiptTokenVerifier")
            .field("kids", &kids)
            .field("settlement_store", &self.nonce_store.is_some())
            .finish()
    }
}

impl ReceiptTokenVerifier {
    /// Build a verifier with a single trusted key.
    ///
    /// Note what this constructor does not ask for. The quote verifier
    /// cannot be built without a nonce store, to the point that publishing
    /// its JWKS requires handing it a throwaway one. A receipt verifier
    /// needs no such prop.
    pub fn single_key(kid: impl Into<String>, public_key: VerifyingKey) -> Self {
        let mut keys = HashMap::with_capacity(1);
        keys.insert(kid.into(), public_key);
        Self {
            public_keys: keys,
            nonce_store: None,
        }
    }

    /// Build a verifier from a JWKS-shaped map of `kid` to public key.
    pub fn with_keys(keys: HashMap<String, VerifyingKey>) -> Self {
        Self {
            public_keys: keys,
            nonce_store: None,
        }
    }

    /// Inject a settlement store.
    ///
    /// Optional and off by default, following the same shape the Web Bot
    /// Auth provider uses for its own optional store. It exists for an
    /// embedder building an at-most-once settlement pass on top of verified
    /// receipts, keyed on [`ReceiptClaims::claim_id`]. Consuming a claim
    /// stays an explicit call at that call site;
    /// [`ReceiptTokenVerifier::verify`] never consumes anything, so a
    /// receipt verified during reconciliation does not quietly become
    /// unverifiable afterwards.
    pub fn with_nonce_store(mut self, store: Arc<dyn NonceStore>) -> Self {
        self.nonce_store = Some(store);
        self
    }

    /// The injected settlement store, if any.
    ///
    /// Handing the store back rather than wrapping it in a `settle()` method
    /// keeps the burn visible in the caller's code. A settlement pass that
    /// consumes a claim should read as consuming a claim.
    pub fn nonce_store(&self) -> Option<&Arc<dyn NonceStore>> {
        self.nonce_store.as_ref()
    }

    /// Verify a compact JWS receipt token.
    ///
    /// 1. Split and decode the three segments.
    /// 2. Reject an `alg` that is not `EdDSA` and a `typ` that is not
    ///    [`RECEIPT_JWS_TYP`], both before any key or signature work.
    /// 3. Resolve `kid` against the JWKS.
    /// 4. Verify the Ed25519 signature over the original textual segments.
    /// 5. Decode the claims.
    ///
    /// There is no step 6. No expiry check, no skew check, and nothing
    /// consumed: this method is a pure function of the token and the key
    /// set, and calling it twice returns the same answer twice.
    pub fn verify(&self, token: &str) -> Result<ReceiptClaims, ReceiptVerifyError> {
        // --- Parse JWS ---
        let mut parts = token.split('.');
        let header_b64 = parts
            .next()
            .ok_or_else(|| ReceiptVerifyError::Malformed("missing header".into()))?;
        let payload_b64 = parts
            .next()
            .ok_or_else(|| ReceiptVerifyError::Malformed("missing payload".into()))?;
        let signature_b64 = parts
            .next()
            .ok_or_else(|| ReceiptVerifyError::Malformed("missing signature".into()))?;
        if parts.next().is_some() {
            return Err(ReceiptVerifyError::Malformed("too many segments".into()));
        }

        let header_bytes = base64_url_decode(header_b64)
            .map_err(|e| ReceiptVerifyError::Malformed(format!("header b64: {e}")))?;
        let payload_bytes = base64_url_decode(payload_b64)
            .map_err(|e| ReceiptVerifyError::Malformed(format!("payload b64: {e}")))?;
        let signature_bytes = base64_url_decode(signature_b64)
            .map_err(|e| ReceiptVerifyError::Malformed(format!("signature b64: {e}")))?;

        let header: ReceiptHeader = serde_json::from_slice(&header_bytes)
            .map_err(|e| ReceiptVerifyError::Malformed(format!("header decode: {e}")))?;

        if header.alg != "EdDSA" {
            return Err(ReceiptVerifyError::UnsupportedAlg(header.alg));
        }
        // Before the key lookup and before the signature check, so a quote
        // token minted by this very key is turned away for being the wrong
        // kind of document rather than accepted for being correctly signed.
        if header.typ != RECEIPT_JWS_TYP {
            return Err(ReceiptVerifyError::UnsupportedType(header.typ));
        }

        // --- Resolve key ---
        let key = self
            .public_keys
            .get(&header.kid)
            .ok_or_else(|| ReceiptVerifyError::UnknownKey(header.kid.clone()))?;

        // --- Verify signature ---
        let sig_arr: [u8; 64] = signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ReceiptVerifyError::SignatureInvalid)?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
        // Rebuilt from the original textual segments, never from re-encoded
        // JSON. Re-serializing the decoded claims would verify a signature
        // over bytes this process just produced instead of over the bytes
        // that arrived, and any encoder difference at all (key order, number
        // formatting, escaping) would then either pass a forgery or fail a
        // genuine receipt.
        let signing_input = format!("{header_b64}.{payload_b64}");
        key.verify(signing_input.as_bytes(), &signature)
            .map_err(|_| ReceiptVerifyError::SignatureInvalid)?;

        // --- Decode claims ---
        let claims: ReceiptClaims = serde_json::from_slice(&payload_bytes)
            .map_err(|e| ReceiptVerifyError::Malformed(format!("claims decode: {e}")))?;

        Ok(claims)
    }

    /// JWKS publication shape: a JSON object with a `keys` array, each entry
    /// a JWK-ish record `{ "kty": "OKP", "crv": "Ed25519", "kid": "...",
    /// "x": "<base64url public key>" }`.
    ///
    /// Byte-identical to the quote verifier's output for the same key, which
    /// is the mechanical statement of the one-key-family claim: an operator
    /// serving both tokens serves one document, and a buyer fetches it once.
    pub fn jwks_json(&self) -> serde_json::Value {
        let keys: Vec<serde_json::Value> = self
            .public_keys
            .iter()
            .map(|(kid, vk)| {
                serde_json::json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "use": "sig",
                    "alg": "EdDSA",
                    "kid": kid,
                    "x": base64_url_encode(vk.as_bytes()),
                })
            })
            .collect();
        serde_json::json!({ "keys": keys })
    }
}

// --- Helpers ---

/// Compute the `Content-Digest` value a receipt carries for a body that was
/// available in full.
///
/// Call this only with the complete body. A partial body has no honest
/// digest, and the right receipt for one is a receipt with no digest field
/// at all.
///
/// The returned string is the RFC 9530 header value, for example
/// `sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:`. That inner
/// base64 is STANDARD and padded, which is a different alphabet from the
/// URL-safe unpadded base64 the three JWS segments use. Both are correct and
/// the nesting is deliberate: the digest is an RFC 9530 structured-fields
/// Byte Sequence and keeps that spelling, so the value on a receipt is the
/// same string the RFC 9421 egress signer covers, character for character. A
/// receipt that re-spelled it would be a second value that a buyer could not
/// compare against the signed one.
pub fn receipt_content_digest(body: &[u8]) -> String {
    sbproxy_middleware::digest::compute_content_digest(
        sbproxy_middleware::digest::Algorithm::Sha256,
        body,
    )
}

/// The same URL-safe unpadded base64 the quote token uses on all three
/// segments. Re-declared here rather than reached for across the module
/// boundary, so the receipt module does not depend on a sibling's privates.
fn base64_url_encode(input: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
}

fn base64_url_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input)
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ai_crawl::{ContentShape, Money};
    use crate::policy::quote_token::{
        InMemoryNonceStore, NonceCheck, QuoteTokenSigner, QuoteTokenVerifier, VerifyError,
    };
    use std::time::Duration;

    /// The seed both signers share in these tests. One key family is the
    /// point, so the quote signer and the receipt signer are built from the
    /// same bytes on purpose.
    const SEED: [u8; 32] = [
        7, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];

    const KID: &str = "kid-current";

    fn receipt_signer() -> ReceiptTokenSigner {
        ReceiptTokenSigner::from_seed_bytes(&SEED, KID)
    }

    fn quote_signer() -> QuoteTokenSigner {
        QuoteTokenSigner::from_seed_bytes(
            &SEED,
            KID,
            "https://api.example.com",
            Duration::from_secs(300),
        )
    }

    fn sample_claims() -> ReceiptClaims {
        ReceiptClaims {
            seq: 41,
            prev: "9a3f".repeat(16),
            node_id: "node-a".to_string(),
            claim_id: ulid::Ulid::new().to_string(),
            agreement_id: "agr-2026-04".to_string(),
            subject: ReceiptSubject {
                tenant: "acme".to_string(),
                key_id: Some("key_7".to_string()),
                agent: None,
            },
            route: "search".to_string(),
            request_digest: None,
            response_digest: Some(receipt_content_digest(b"{\"rows\":3}")),
            units: vec![
                ReceiptUnit {
                    name: "api_call".to_string(),
                    count: 1,
                    source: "measured".to_string(),
                    evidence: ReceiptEvidence::Measured {
                        bytes_in: 512,
                        bytes_out: 12_043,
                        duration_ms: 91,
                    },
                },
                ReceiptUnit {
                    name: "result_row".to_string(),
                    count: 47,
                    source: "origin_header".to_string(),
                    evidence: ReceiptEvidence::OriginHeader {
                        header: "X-Rows-Returned".to_string(),
                        raw: " 47 ".to_string(),
                    },
                },
            ],
            outcome: "delivered".to_string(),
            config_revision: "3f9a1c7d0b42".to_string(),
        }
    }

    #[test]
    fn receipt_round_trips_through_sign_and_verify() {
        let signer = receipt_signer();
        let claims = sample_claims();
        let token = signer.sign(&claims).expect("sign");

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "compact JWS has three segments");

        let header_bytes = base64_url_decode(parts[0]).expect("header b64");
        let header: ReceiptHeader = serde_json::from_slice(&header_bytes).expect("header decode");
        assert_eq!(header.alg, "EdDSA");
        assert_eq!(header.typ, "sbproxy-receipt+jws");
        assert_eq!(header.kid, KID);

        let verifier = ReceiptTokenVerifier::single_key(KID, signer.verifying_key());
        let back = verifier.verify(&token).expect("verify");
        assert_eq!(back, claims, "every claim survives the round trip");
    }

    #[test]
    fn the_signed_bytes_are_the_header_a_dot_and_the_payload_and_nothing_else() {
        // The wire format is frozen, so it gets a test that fails if anyone
        // widens or narrows what the signature covers.
        let signer = receipt_signer();
        let token = signer.sign(&sample_claims()).expect("sign");
        let parts: Vec<&str> = token.split('.').collect();

        let mut expected = Vec::new();
        expected.extend_from_slice(parts[0].as_bytes());
        expected.push(0x2E);
        expected.extend_from_slice(parts[1].as_bytes());

        let signature_bytes = base64_url_decode(parts[2]).expect("signature b64");
        let sig_arr: [u8; 64] = signature_bytes.as_slice().try_into().expect("64 bytes");
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
        signer
            .verifying_key()
            .verify(&expected, &signature)
            .expect("signature covers exactly header + 0x2E + payload");
    }

    #[test]
    fn a_quote_token_presented_as_a_receipt_is_rejected_on_typ() {
        // Signed by the same key under the same kid, so the signature would
        // check out. Only `typ` stands between the two documents, which is
        // exactly why it is checked before any signature work.
        let quote = quote_signer();
        let issued = quote
            .issue(
                "agent-1",
                "/articles/foo",
                ContentShape::Markdown,
                Money {
                    amount_micros: 5_000,
                    currency: "USD".to_string(),
                },
                "x402",
                None,
                None,
            )
            .expect("issue quote");

        let verifier = ReceiptTokenVerifier::single_key(KID, quote.verifying_key());
        let err = verifier
            .verify(&issued.token)
            .expect_err("a quote is not a receipt");
        assert_eq!(
            err,
            ReceiptVerifyError::UnsupportedType("sbproxy-quote+jws".to_string()),
            "rejected for what it is, not for how it was signed"
        );
    }

    #[test]
    fn a_receipt_presented_as_a_quote_is_rejected_on_typ() {
        let signer = receipt_signer();
        let token = signer.sign(&sample_claims()).expect("sign");

        let store = Arc::new(InMemoryNonceStore::new()) as Arc<dyn NonceStore>;
        let quote_verifier = QuoteTokenVerifier::single_key(KID, signer.verifying_key(), store);
        let err = quote_verifier
            .verify(&token, "search", ContentShape::Markdown)
            .expect_err("a receipt is not a quote");
        assert!(
            matches!(err, VerifyError::UnsupportedType(ref t) if t == RECEIPT_JWS_TYP),
            "{err:?}"
        );
    }

    #[test]
    fn verifying_the_same_receipt_twice_both_succeed() {
        // The test that proves the nonce coupling is gone. A settlement
        // store is injected precisely so that a leftover burn would show up
        // here rather than in production six months after issue.
        let signer = receipt_signer();
        let claims = sample_claims();
        let token = signer.sign(&claims).expect("sign");

        let store = Arc::new(InMemoryNonceStore::new());
        let verifier = ReceiptTokenVerifier::single_key(KID, signer.verifying_key())
            .with_nonce_store(Arc::clone(&store) as Arc<dyn NonceStore>);

        let first = verifier.verify(&token).expect("first verify");
        let second = verifier.verify(&token).expect("second verify");
        assert_eq!(first, second, "a receipt reads the same every time");

        // And the store is untouched: the claim is still fresh, so nothing
        // in the verify path consumed it.
        assert_eq!(
            store.check_and_consume(&claims.claim_id).expect("store ok"),
            NonceCheck::Fresh,
            "verify must not have burned the claim"
        );
    }

    #[test]
    fn an_external_verifier_checks_a_receipt_from_the_published_jwks() {
        // The two lines below are the only ones that touch signer state.
        // Everything after them uses nothing but the published token and the
        // published JWKS document, which is all a buyer ever has.
        let (token, published) = {
            let signer = receipt_signer();
            let token = signer.sign(&sample_claims()).expect("sign");
            let jwks = ReceiptTokenVerifier::single_key(KID, signer.verifying_key()).jwks_json();
            (token, jwks)
        };

        let entry = &published["keys"][0];
        assert_eq!(entry["kty"], "OKP");
        assert_eq!(entry["crv"], "Ed25519");
        assert_eq!(entry["alg"], "EdDSA");
        let kid = entry["kid"].as_str().expect("kid");
        let x = entry["x"].as_str().expect("x");

        let key_bytes: [u8; 32] = base64_url_decode(x)
            .expect("x decodes as base64url")
            .as_slice()
            .try_into()
            .expect("Ed25519 public keys are 32 bytes");
        let public_key = VerifyingKey::from_bytes(&key_bytes).expect("valid Ed25519 point");

        let external = ReceiptTokenVerifier::single_key(kid, public_key);
        let claims = external.verify(&token).expect("verify from JWKS alone");
        assert_eq!(claims.outcome, "delivered");
        assert_eq!(claims.units.len(), 2);
    }

    #[test]
    fn the_receipt_and_the_quote_publish_one_key_family() {
        let receipt = receipt_signer();
        let quote = quote_signer();

        let store = Arc::new(InMemoryNonceStore::new()) as Arc<dyn NonceStore>;
        let mut quote_keys = HashMap::new();
        quote_keys.insert(KID.to_string(), quote.verifying_key());

        assert_eq!(
            ReceiptTokenVerifier::single_key(KID, receipt.verifying_key()).jwks_json(),
            QuoteTokenVerifier::with_keys(quote_keys, store).jwks_json(),
            "one JWKS fetch has to serve both halves of the invoice line"
        );
    }

    #[test]
    fn a_tampered_payload_fails() {
        let signer = receipt_signer();
        let claims = sample_claims();
        let token = signer.sign(&claims).expect("sign");
        let parts: Vec<&str> = token.split('.').collect();

        // The edit a dishonest seller would actually make.
        let mut inflated = claims.clone();
        inflated.units[1].count = 9_999;
        let payload_b64 = base64_url_encode(&serde_json::to_vec(&inflated).expect("encode"));
        assert_ne!(payload_b64, parts[1], "the edit landed");
        let tampered = format!("{}.{}.{}", parts[0], payload_b64, parts[2]);

        let verifier = ReceiptTokenVerifier::single_key(KID, signer.verifying_key());
        assert_eq!(
            verifier.verify(&tampered).expect_err("tampered"),
            ReceiptVerifyError::SignatureInvalid
        );
    }

    #[test]
    fn an_unknown_kid_fails() {
        let signer = receipt_signer();
        let token = signer.sign(&sample_claims()).expect("sign");

        let other = ReceiptTokenSigner::from_seed_bytes(&[99u8; 32], "kid-other");
        let verifier = ReceiptTokenVerifier::single_key("kid-other", other.verifying_key());
        assert_eq!(
            verifier.verify(&token).expect_err("unknown kid"),
            ReceiptVerifyError::UnknownKey(KID.to_string())
        );
    }

    #[test]
    fn an_unsupported_alg_is_rejected_before_the_key_lookup() {
        // Hand-built header so the token is well formed in every respect
        // except `alg`. The verifier holds no key at all, so reaching the
        // lookup would report UnknownKey instead.
        let signer = receipt_signer();
        let header = ReceiptHeader {
            alg: "RS256".to_string(),
            typ: RECEIPT_JWS_TYP.to_string(),
            kid: KID.to_string(),
        };
        let claims = sample_claims();
        let header_b64 = base64_url_encode(&serde_json::to_vec(&header).expect("encode"));
        let payload_b64 = base64_url_encode(&serde_json::to_vec(&claims).expect("encode"));
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = signer.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = base64_url_encode(&signature.to_bytes());
        let token = format!("{signing_input}.{sig_b64}");

        let verifier = ReceiptTokenVerifier::with_keys(HashMap::new());
        assert_eq!(
            verifier.verify(&token).expect_err("bad alg"),
            ReceiptVerifyError::UnsupportedAlg("RS256".to_string())
        );
    }

    #[test]
    fn rejects_malformed_tokens() {
        let signer = receipt_signer();
        let verifier = ReceiptTokenVerifier::single_key(KID, signer.verifying_key());
        for bad in &["", "no-dots", "a.b", "a.b.c.d"] {
            let err = verifier
                .verify(bad)
                .expect_err(&format!("malformed: {bad}"));
            assert!(matches!(err, ReceiptVerifyError::Malformed(_)), "{err:?}");
        }
    }

    // --- Conversions ---
    //
    // The exhaustive matches already stop the build when the metering
    // vocabulary grows. These pin the other half: that the wire spelling of
    // what is already there does not quietly change. Each one compares the
    // serialized wire type against the serialized internal type, so a renamed
    // field or a changed serde attribute on either side fails here.

    #[test]
    fn a_subject_converts_to_the_same_json_the_meter_writes() {
        for subject in [
            Subject {
                tenant: "acme".to_string(),
                key_id: Some("key_7".to_string()),
                agent: Some("crawler-3".to_string()),
            },
            // The absent-field case, which is where a `skip_serializing_if`
            // mismatch between the two types would show up.
            Subject {
                tenant: "acme".to_string(),
                key_id: None,
                agent: None,
            },
        ] {
            let wire = ReceiptSubject::from(&subject);
            assert_eq!(
                serde_json::to_value(&wire).expect("wire subject serializes"),
                serde_json::to_value(&subject).expect("meter subject serializes"),
                "the receipt's subject must be the meter's subject, byte for byte"
            );
        }
    }

    #[test]
    fn a_unit_converts_to_the_same_json_the_meter_writes() {
        // One unit per evidence variant, so every arm of the conversion is
        // exercised and every variant's field names are pinned.
        let units = [
            Unit::new(
                "egress_kib",
                12,
                Evidence::Measured {
                    bytes_in: 512,
                    bytes_out: 12_043,
                    duration_ms: 91,
                },
            ),
            Unit::new("api_call", 1, Evidence::RouteWeight { config_gen: 7 }),
            Unit::new(
                "result_row",
                47,
                Evidence::OriginHeader {
                    header: "X-Rows-Returned".to_string(),
                    raw: " 47 ".to_string(),
                },
            ),
        ];

        for unit in &units {
            let wire = ReceiptUnit::from(unit);
            assert_eq!(
                serde_json::to_value(&wire).expect("wire unit serializes"),
                serde_json::to_value(unit).expect("meter unit serializes"),
                "the receipt's unit must be the meter's unit, byte for byte"
            );
        }
    }

    #[test]
    fn evidence_converts_to_the_same_json_the_meter_writes() {
        for evidence in [
            Evidence::Measured {
                bytes_in: 512,
                bytes_out: 12_043,
                duration_ms: 91,
            },
            Evidence::RouteWeight { config_gen: 7 },
            Evidence::OriginHeader {
                header: "X-Rows-Returned".to_string(),
                raw: " 47 ".to_string(),
            },
        ] {
            let wire = ReceiptEvidence::from(&evidence);
            assert_eq!(
                serde_json::to_value(&wire).expect("wire evidence serializes"),
                serde_json::to_value(&evidence).expect("meter evidence serializes"),
                "untagged evidence must carry identical keys on both sides"
            );
        }
    }

    #[test]
    fn outcome_wire_names_match_the_metering_vocabulary() {
        // Covers the case the exhaustive match cannot see: an existing
        // variant renamed rather than a new one added. `ALL` is the meter's
        // own list, so a variant added there lands here without this test
        // being edited.
        for outcome in BillableOutcome::ALL {
            assert_eq!(
                outcome_wire_name(outcome),
                outcome.as_str(),
                "receipt and meter must spell an outcome the same way"
            );
            assert_eq!(
                serde_json::to_value(outcome).expect("outcome serializes"),
                serde_json::Value::String(outcome_wire_name(outcome)),
                "and both must match what serde puts on the wire"
            );
        }
    }

    #[test]
    fn unit_source_wire_names_match_the_metering_vocabulary() {
        for source in [
            UnitSource::Measured,
            UnitSource::RouteWeight,
            UnitSource::OriginHeader,
        ] {
            assert_eq!(
                unit_source_wire_name(source),
                source.as_str(),
                "receipt and meter must spell a unit source the same way"
            );
        }
    }

    #[test]
    fn a_converted_unit_survives_the_signing_round_trip() {
        // The end-to-end statement: a unit that came out of the meter is
        // still the same unit after it has been signed, transmitted, and
        // verified by somebody holding only the public key.
        let unit = Unit::new(
            "result_row",
            47,
            Evidence::OriginHeader {
                header: "X-Rows-Returned".to_string(),
                raw: " 47 ".to_string(),
            },
        );
        let signer = receipt_signer();
        let mut claims = sample_claims();
        claims.units = vec![ReceiptUnit::from(&unit)];
        claims.outcome = outcome_wire_name(BillableOutcome::Delivered);
        let token = signer.sign(&claims).expect("sign");

        let verifier = ReceiptTokenVerifier::single_key(KID, signer.verifying_key());
        let back = verifier.verify(&token).expect("verify");
        assert_eq!(back.units, vec![ReceiptUnit::from(&unit)]);
        assert_eq!(back.units[0].source, "origin_header");
        assert_eq!(back.outcome, "delivered");
        assert_eq!(
            back.units[0].evidence,
            ReceiptEvidence::OriginHeader {
                header: "X-Rows-Returned".to_string(),
                raw: " 47 ".to_string(),
            },
            "the origin's bytes survive verbatim, whitespace included"
        );
    }

    #[test]
    fn an_absent_request_digest_is_omitted_from_the_wire_entirely() {
        // A receipt with no request digest must not carry `"request_digest":
        // null`. Absent and "we hashed nothing" are the same statement, and
        // a partial-body digest is neither.
        let signer = receipt_signer();
        let claims = sample_claims();
        assert!(
            claims.request_digest.is_none(),
            "fixture has no request body"
        );
        let token = signer.sign(&claims).expect("sign");
        let payload = base64_url_decode(token.split('.').nth(1).expect("payload")).expect("b64");
        let value: serde_json::Value = serde_json::from_slice(&payload).expect("json");

        assert!(
            value.get("request_digest").is_none(),
            "a digest over a request that was never buffered is a claim about nothing"
        );
        assert_eq!(
            value["response_digest"]
                .as_str()
                .expect("response digest present"),
            receipt_content_digest(b"{\"rows\":3}"),
            "the receipt carries the RFC 9530 spelling verbatim"
        );
        assert!(
            value["response_digest"]
                .as_str()
                .expect("str")
                .starts_with("sha-256=:"),
            "padded standard base64 inside the structured-fields wrapper"
        );
    }
}

//! IAB CoMP v1.0 wire types.
//!
//! Each struct mirrors a JSON envelope from the IAB Content
//! Authorization Marketplace Protocol spec; `serde_json` round-trips
//! without renaming. The request/response shapes are split into
//! manifest, quote, and redeem groups for clarity.
//!
//! [`CompAuthorization::Cap`] and [`CompAuthorization::Olp`] name the
//! two credential types a tier can require. Both already have a full
//! OSS implementation elsewhere in the workspace: CAP verification in
//! `crates/sbproxy-modules/src/auth/cap.rs`, OLP issuance and
//! verification in `crates/sbproxy-modules/src/olp.rs`. This crate
//! does not re-implement either; a tier tagged `Cap` is manifest
//! metadata telling the buyer which credential to present elsewhere,
//! and a tier tagged `Olp` is the one [`super::marketplace::CompMarketplace::redeem`]
//! can actually mint a token for, via [`super::olp_bridge::OlpBridgeSigner`].

use serde::{Deserialize, Serialize};

/// CoMP protocol version this crate implements.
pub const COMP_VERSION: &str = "1.0";

/// Wire constant for the manifest response.
pub const COMP_MANIFEST_CONTENT_TYPE: &str = "application/iab-comp+json";

/// Wire constant for the quote response.
pub const COMP_QUOTE_CONTENT_TYPE: &str = "application/iab-comp-quote+json";

/// Cache header for the manifest. 5 minutes per the spec.
pub const COMP_MANIFEST_CACHE_CONTROL: &str = "public, max-age=300";

/// Cache header for the quote and redeem responses. Both are
/// per-buyer credentials and must never be cached cross-buyer.
pub const COMP_NO_STORE_CACHE_CONTROL: &str = "no-store";

// --- Manifest (Endpoint 1) ---

/// Top-level CoMP manifest envelope returned from
/// `GET /.well-known/iab-comp/manifest.json`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompManifest {
    /// Protocol version. Always `"1.0"`.
    pub comp_version: String,
    /// Publisher metadata.
    pub publisher: CompPublisher,
    /// Content tiers the publisher exposes.
    pub tiers: Vec<CompTier>,
    /// Endpoint URLs the buyer needs.
    pub endpoints: CompEndpoints,
    /// Convenience pointer at the publisher's robots.txt.
    pub robots_url: String,
    /// Convenience pointer at the publisher's llms.txt.
    pub llms_url: String,
    /// Convenience pointer at the publisher's RSL catalog.
    pub rsl_url: String,
    /// Manifest assembly timestamp (UTC, RFC 3339).
    pub generated_at: String,
    /// Integrity hash of the manifest: the SHA-256 of this manifest's
    /// JSON with the field itself cleared, in `sha256:<hex>` form.
    ///
    /// [`compute_manifest_hash`] produces it and the proxy stamps it on
    /// the manifest it serves. Nothing verifies it on the way in: a
    /// manifest handed to [`CompManifest`] from anywhere but that path
    /// carries whatever its author wrote. Read the ordering contract on
    /// [`compute_manifest_hash`] before recomputing it in another
    /// language.
    pub manifest_hash: String,
}

/// Compute a manifest's `manifest_hash`.
///
/// The SHA-256 of `serde_json`'s rendering of the manifest with
/// `manifest_hash` cleared to the empty string, rendered as
/// `sha256:<lowercase hex>`.
///
/// # Ordering contract
///
/// The bytes hashed are this crate's `serde` rendering, so field order
/// is the declaration order of [`CompManifest`] and its nested types,
/// not sorted-key canonical JSON (RFC 8785 JCS). That is the same
/// contract `canonical_quote_signing_input` documents for quote
/// signatures, and for the same reason: moving to JCS is a wire break
/// for every client that has already implemented against this. A
/// non-Rust client that wants to recompute this value has to reproduce
/// the declaration order.
///
/// # Errors
///
/// Returns [`crate::LicensingError::Encode`] when the manifest cannot
/// be serialized, which cannot happen for a manifest built from config.
pub fn compute_manifest_hash(manifest: &CompManifest) -> Result<String, crate::LicensingError> {
    use sha2::{Digest, Sha256};

    let mut bare = manifest.clone();
    bare.manifest_hash = String::new();
    let bytes = serde_json::to_vec(&bare)
        .map_err(|error| crate::LicensingError::Encode(format!("manifest hash: {error}")))?;
    let digest = Sha256::digest(&bytes);
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!("sha256:{hex}"))
}

/// Publisher block of the manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompPublisher {
    /// Operator-supplied display name.
    pub name: String,
    /// Primary domain.
    pub domain: String,
    /// Licensing contact email.
    pub contact: String,
    /// KYC verification timestamp (RFC 3339), empty for unverified.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub verified_at: Option<String>,
}

/// Acquisition flow a tier requires.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CompAuthorization {
    /// Public access. No token required.
    Public,
    /// CAP token required. Verified OSS-side; see module docs.
    Cap,
    /// OLP license token required. This is the only variant
    /// [`super::marketplace::CompMarketplace::redeem`] can currently
    /// mint a token for.
    Olp,
}

/// Pricing model for a tier.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompPricingModel {
    /// Tier is free.
    Free,
    /// Per-request charge.
    PerRequest,
    /// Flat-rate purchase.
    FlatRate,
}

/// Tier pricing block.
///
/// `amount` is used for `Free` and `FlatRate`; `amount_micros` is used
/// for `PerRequest`. The fields are mutually exclusive at the schema
/// level but both are optional in the type to mirror the wire shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompPricing {
    /// Pricing model.
    pub model: CompPricingModel,
    /// ISO 4217 currency code.
    pub currency: String,
    /// Whole-unit amount (free or flat rate).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub amount: Option<u64>,
    /// Micro-unit amount (per-request).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub amount_micros: Option<u64>,
}

/// Per-tier rate ceiling for CAP-authorized tiers.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompRateCaps {
    /// Maximum requests per second.
    pub max_rps: f64,
    /// Maximum bytes per UTC day.
    pub max_bytes_per_day: u64,
}

/// One tier entry in the manifest.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompTier {
    /// Stable tier identifier.
    pub id: String,
    /// Operator-set display name.
    pub name: String,
    /// Operator-set description.
    pub description: String,
    /// License URN that governs this tier.
    pub license: String,
    /// Content shape (`html`, `json-envelope`, `bulk-archive`).
    pub shape: String,
    /// Pricing block.
    pub pricing: CompPricing,
    /// Acquisition flow.
    pub authorization: CompAuthorization,
    /// Rate caps (CAP tiers only).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub rate_caps: Option<CompRateCaps>,
    /// Route allow-list as a glob. Echoed to the buyer for
    /// convenience; this crate does not itself enforce it against
    /// request paths.
    pub route_glob: String,
}

/// Endpoints block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompEndpoints {
    /// Manifest URL.
    pub manifest: String,
    /// Quote URL.
    pub quote: String,
    /// Redeem URL.
    pub redeem: String,
}

// --- Quote (Endpoint 2) ---

/// Body of a quote request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompQuoteRequest {
    /// Protocol version. Verifier rejects mismatch.
    pub comp_version: String,
    /// Buyer identity block.
    pub buyer: CompBuyer,
    /// Tier the buyer wants to quote.
    pub tier_id: String,
    /// Requested volume.
    pub requested_volume: CompRequestedVolume,
    /// Audience host the resulting token will bind to.
    pub audience: String,
}

/// Buyer block in a quote request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompBuyer {
    /// Stable agent identifier.
    pub agent_id: String,
    /// Buyer organization name.
    pub organization: String,
}

/// Requested volume block in a quote request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompRequestedVolume {
    /// Pricing model the buyer is requesting against.
    pub model: CompPricingModel,
    /// Expected request count over the duration.
    pub expected_count: u64,
    /// Token validity window in days.
    pub duration_days: u32,
}

/// Body of a quote response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompQuoteResponse {
    /// Protocol version.
    pub comp_version: String,
    /// Stable quote identifier (ULID).
    pub quote_id: String,
    /// Tier the quote covers.
    pub tier_id: String,
    /// License URN that will be minted on redeem.
    pub license: String,
    /// Quote pricing block.
    pub pricing: CompQuotePricing,
    /// Acquisition pointer for the buyer.
    pub acquisition: CompAcquisition,
    /// RFC 3339 expiry. Buyer must redeem before this.
    pub valid_until: String,
    /// Quote signature (Ed25519).
    pub signature: CompSignature,
}

/// Pricing block on a quote response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompQuotePricing {
    /// ISO 4217 currency code.
    pub currency: String,
    /// Total quote amount in micros.
    pub amount_micros: u64,
    /// Human-readable unit description.
    pub unit: String,
}

/// Acquisition pointer for the buyer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompAcquisition {
    /// Redeem URL the buyer POSTs to.
    pub url: String,
    /// Acquisition method. Always `"redeem"` for v1.
    pub method: String,
}

/// Detached Ed25519 signature shared by quote and redeem flows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompSignature {
    /// Signature algorithm. Always `"ed25519"` for v1.
    pub alg: String,
    /// Signing key id (`comp-<rotation_id>`).
    pub kid: String,
    /// Base64-encoded signature.
    pub value: String,
}

// --- Redeem (Endpoint 3) ---

/// Body of a redeem request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompRedeemRequest {
    /// Protocol version.
    pub comp_version: String,
    /// Quote being redeemed.
    pub quote_id: String,
    /// Buyer's signature over the canonical-JSON request body with
    /// `buyer_signature.value` cleared.
    pub buyer_signature: CompSignature,
    /// Buyer-side acceptance terms.
    pub buyer_acceptance: CompAcceptance,
    /// Payment proof block.
    pub payment_proof: CompPaymentProof,
}

/// Acceptance attestation submitted with the redeem request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompAcceptance {
    /// SHA-256 of the canonical-JSON of the original quote.
    pub accepted_quote_hash: String,
    /// RFC 3339 timestamp.
    pub accepted_at: String,
    /// Buyer's legal entity name (for the audit log).
    pub buyer_legal_entity: String,
}

/// Payment proof block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompPaymentProof {
    /// Payment rail (`x402`, `mpp`, `stripe`).
    pub rail: String,
    /// Transaction hash for on-chain rails.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub txhash: Option<String>,
    /// Chain identifier for on-chain rails (e.g. `base`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub chain: Option<String>,
    /// Off-chain receipt id (e.g. Stripe payment_intent).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub receipt_id: Option<String>,
}

/// Body of a redeem response. Wraps a bridged OLP license token (see
/// [`super::olp_bridge`]).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompRedeemResponse {
    /// Compact JWS license token.
    pub license_token: String,
    /// Always `"Bearer"`.
    pub token_type: String,
    /// Token TTL in seconds.
    pub expires_in: u64,
    /// License URN.
    pub license: String,
    /// Agent identifier the token was minted for.
    pub agent_id: String,
    /// Route allow-list glob, echoed from the redeemed tier.
    pub route_glob: String,
}

/// Redacted `Debug` (WOR-2673). `license_token` is a bearer
/// credential: every reader of a log line, a panic message, or a
/// `dbg!` that printed it would hold the licensed access it grants for
/// the whole of its TTL. Everything else here is what an operator
/// reconciles revenue against and none of it authorizes anything, so
/// it stays. Curated and `finish_non_exhaustive`, so a
/// credential-shaped field added later is absent rather than printed.
impl std::fmt::Debug for CompRedeemResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompRedeemResponse")
            .field("license_token", &"[REDACTED]")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("license", &self.license)
            .field("agent_id", &self.agent_id)
            .field("route_glob", &self.route_glob)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WOR-2673, and the entry this type has in
    /// `scripts/secret-debug-registry.txt`. `license_token` is a bearer
    /// credential: a `{:?}` that printed it would hand every reader of
    /// a log line, a `dbg!`, or a panic message the licensed access it
    /// grants for the whole of its TTL.
    #[test]
    fn a_redeem_response_does_not_print_its_token() {
        const SENTINEL: &str = "SENTINEL-LICENSE-TOKEN-4c1a";

        let response = CompRedeemResponse {
            license_token: SENTINEL.into(),
            token_type: "Bearer".into(),
            expires_in: 3600,
            license: "urn:rsl:pay-per-inference:default".into(),
            agent_id: "agent_9f2c1b".into(),
            route_glob: "/api/v1/inference/**".into(),
        };
        let rendered = format!("{response:?}");
        assert!(
            !rendered.contains(SENTINEL),
            "the minted license token reached Debug: {rendered}"
        );
        assert!(
            rendered.contains("agent_9f2c1b")
                && rendered.contains("urn:rsl:pay-per-inference:default"),
            "the agent id and the license URN must survive: they are what an operator \
             reconciles a mint against, and neither authorizes anything: {rendered}"
        );
    }

    #[test]
    fn manifest_round_trips() {
        let manifest = CompManifest {
            comp_version: COMP_VERSION.into(),
            publisher: CompPublisher {
                name: "Example Publishing Co.".into(),
                domain: "example.com".into(),
                contact: "licensing@example.com".into(),
                verified_at: Some("2026-05-02T00:00:00Z".into()),
            },
            tiers: vec![CompTier {
                id: "tier_free_search".into(),
                name: "Search indexing, free".into(),
                description: "Indexing for traditional search engines.".into(),
                license: "urn:rsl:search-index:default".into(),
                shape: "html".into(),
                pricing: CompPricing {
                    model: CompPricingModel::Free,
                    currency: "USD".into(),
                    amount: Some(0),
                    amount_micros: None,
                },
                authorization: CompAuthorization::Cap,
                rate_caps: Some(CompRateCaps {
                    max_rps: 1.0,
                    max_bytes_per_day: 1_073_741_824,
                }),
                route_glob: "/**".into(),
            }],
            endpoints: CompEndpoints {
                manifest: "https://example.com/.well-known/iab-comp/manifest.json".into(),
                quote: "https://example.com/.well-known/iab-comp/quote".into(),
                redeem: "https://example.com/.well-known/iab-comp/redeem".into(),
            },
            robots_url: "https://example.com/robots.txt".into(),
            llms_url: "https://example.com/llms.txt".into(),
            rsl_url: "https://example.com/licenses.xml".into(),
            generated_at: "2026-05-02T14:00:00Z".into(),
            manifest_hash: "sha256:placeholder".into(),
        };
        let s = serde_json::to_string(&manifest).unwrap();
        let back: CompManifest = serde_json::from_str(&s).unwrap();
        assert_eq!(manifest, back);
        // Authorization serializes lowercase per the spec.
        assert!(s.contains("\"authorization\":\"cap\""));
        // Pricing model is snake_case (here `free`).
        assert!(s.contains("\"model\":\"free\""));
    }

    #[test]
    fn quote_request_parses() {
        let body = r#"{
            "comp_version": "1.0",
            "buyer": { "agent_id": "agent_acme_001", "organization": "Acme AI Inc." },
            "tier_id": "tier_ai_inference",
            "requested_volume": {
                "model": "per_request",
                "expected_count": 100000,
                "duration_days": 30
            },
            "audience": "api.example.com"
        }"#;
        let parsed: CompQuoteRequest = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.tier_id, "tier_ai_inference");
        assert_eq!(parsed.requested_volume.expected_count, 100_000);
        assert!(matches!(
            parsed.requested_volume.model,
            CompPricingModel::PerRequest
        ));
    }

    #[test]
    fn redeem_request_parses_with_x402_proof() {
        let body = r#"{
            "comp_version": "1.0",
            "quote_id": "01J7HZ8X9R3",
            "buyer_signature": { "alg": "ed25519", "kid": "buyer-1", "value": "AAAA" },
            "buyer_acceptance": {
                "accepted_quote_hash": "sha256:base64x",
                "accepted_at": "2026-05-02T14:35:00Z",
                "buyer_legal_entity": "Acme AI Inc."
            },
            "payment_proof": { "rail": "x402", "txhash": "0xabc", "chain": "base" }
        }"#;
        let parsed: CompRedeemRequest = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.payment_proof.rail, "x402");
        assert_eq!(parsed.payment_proof.txhash.as_deref(), Some("0xabc"));
        assert_eq!(parsed.payment_proof.chain.as_deref(), Some("base"));
    }
}

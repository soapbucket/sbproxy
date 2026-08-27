//! CoMP marketplace bridge.
//!
//! The bridge object that owns the manifest, signs quotes, and
//! converts a redeemed quote into an OLP-wire-compatible license
//! token via [`super::olp_bridge::OlpBridgeSigner`]. Signature work on
//! the quote itself uses this crate's `comp-...` kid namespace (see
//! [`crate::keys`]); redeem hands off to the OLP bridge, which mints
//! under whichever `kid` the operator configured there.
//!
//! Buyer-key resolution is pluggable via [`BuyerKeyRegistry`]. The
//! production implementation reads from wherever the deployment keeps
//! its agent registry; the in-tree [`InMemoryBuyerKeyRegistry`] backs
//! unit and integration tests.

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use ed25519_dalek::{Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::LicensingError;
use crate::keys::KeyManager;
use crate::revocation::Revocation;

use super::olp_bridge::OlpBridgeSigner;
use super::types::{
    CompAcceptance, CompAcquisition, CompManifest, CompPricingModel, CompQuotePricing,
    CompQuoteRequest, CompQuoteResponse, CompRedeemRequest, CompRedeemResponse, CompSignature,
    CompTier, COMP_VERSION,
};

/// Maximum quote validity window. One hour.
pub const COMP_QUOTE_VALIDITY_SECS: u64 = 3600;

// --- Buyer-key registry ---

/// Resolves a buyer kid to a verifying key for redeem-time signature
/// verification.
#[async_trait]
pub trait BuyerKeyRegistry: Send + Sync {
    /// Resolve `kid` to a buyer verifying key. Returns
    /// [`LicensingError::UnknownKey`] for an unrecognised kid.
    async fn resolve(&self, kid: &str) -> Result<VerifyingKey, LicensingError>;
}

/// In-memory buyer-key registry. Suitable for unit tests and
/// single-tenant deployments where buyer keys are managed out of band.
///
/// A poisoned registry is recovered with
/// [`PoisonError::into_inner`] rather than unwrapped: the guarded
/// state is a plain `kid -> key` map written one whole entry at a
/// time, so a panic elsewhere cannot leave a partial key behind, and
/// an unknown kid is already answered with
/// [`LicensingError::UnknownKey`] rather than a panic.
#[derive(Default)]
pub struct InMemoryBuyerKeyRegistry {
    keys: RwLock<HashMap<String, VerifyingKey>>,
}

impl InMemoryBuyerKeyRegistry {
    /// Build an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a buyer key under `kid`.
    pub fn insert(&self, kid: impl Into<String>, key: VerifyingKey) {
        self.keys
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(kid.into(), key);
    }
}

#[async_trait]
impl BuyerKeyRegistry for InMemoryBuyerKeyRegistry {
    async fn resolve(&self, kid: &str) -> Result<VerifyingKey, LicensingError> {
        self.keys
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(kid)
            .copied()
            .ok_or_else(|| LicensingError::UnknownKey(kid.to_string()))
    }
}

// --- Marketplace ---

/// CoMP marketplace bridge: owns the manifest, signs quotes, and
/// converts redeemed quotes into OLP-wire-compatible license tokens.
pub struct CompMarketplace {
    keys: Arc<KeyManager>,
    manifest: Arc<CompManifest>,
    revocation: Arc<dyn Revocation>,
    olp_bridge: Arc<OlpBridgeSigner>,
    buyer_keys: Arc<dyn BuyerKeyRegistry>,
    /// Same-process quote-expiry ledger: `quote_id -> valid_until`
    /// (unix seconds), written at `quote()` time. A redeem for a
    /// quote_id this ledger still holds and whose `valid_until` has
    /// passed is rejected as [`LicensingError::Expired`]. A quote_id
    /// this ledger does not hold (an older quote from before a
    /// restart, matching this crate's no-external-store default) is
    /// not rejected on that basis alone; the revocation check below
    /// is the durable-enough backstop an operator who needs
    /// restart-survival should reach for via [`crate::revocation::RedisRevocation`].
    ///
    /// Poisoning is recovered with [`PoisonError::into_inner`]: the
    /// ledger is advisory (a quote_id it does not hold is not rejected
    /// on that basis alone) and every write is one `insert` or
    /// `retain`, so reading a map that survived another thread's panic
    /// is strictly better than refusing every redeem from here on.
    issued_quotes: std::sync::Mutex<HashMap<String, IssuedQuote>>,
}

/// How long an expired quote stays in the ledger as a tombstone.
///
/// The row has to outlive the quote, or the only thing that removes it
/// is the next `quote()` call and an expired quote becomes redeemable
/// again the moment any buyer asks for a new one. Twenty-four hours is
/// far past any quote lifetime a publisher configures and bounds the
/// map the same way the old sweep did.
const QUOTE_TOMBSTONE_SECS: u64 = 24 * 60 * 60;

/// One issued quote, as the ledger remembers it.
#[derive(Clone, Debug)]
struct IssuedQuote {
    /// Unix seconds the quote stops being redeemable.
    valid_until: u64,
    /// `sha256:<hex>` over the canonical signing bytes of the quote
    /// this process issued. The redeem request carries the buyer's copy
    /// in `buyer_acceptance.accepted_quote_hash`; comparing the two is
    /// what binds a redeem to a quote at all.
    quote_hash: String,
}

/// The `accepted_quote_hash` a buyer puts in its redeem request.
///
/// A redeem is bound to a quote by this value, so a buyer client has to
/// be able to compute it from the quote it received. It is the SHA-256
/// of the same canonical bytes the quote's own signature covers, in
/// `sha256:<hex>` form, and the ordering contract on
/// [`canonical_quote_signing_input`] applies to it too.
///
/// # Errors
///
/// Returns an error when the quote cannot be serialized, which cannot
/// happen for a quote this crate produced.
pub fn quote_acceptance_hash(quote: &CompQuoteResponse) -> Result<String, LicensingError> {
    Ok(quote_hash(&canonical_quote_signing_input(quote)?))
}

/// Hash a quote's canonical signing bytes the way the acceptance
/// attestation is specified to.
fn quote_hash(signing_input: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(signing_input);
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("sha256:{hex}")
}

impl CompMarketplace {
    /// Build a marketplace from its collaborators.
    pub fn new(
        keys: Arc<KeyManager>,
        manifest: Arc<CompManifest>,
        revocation: Arc<dyn Revocation>,
        olp_bridge: Arc<OlpBridgeSigner>,
        buyer_keys: Arc<dyn BuyerKeyRegistry>,
    ) -> Self {
        Self {
            keys,
            manifest,
            revocation,
            olp_bridge,
            buyer_keys,
            issued_quotes: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// The pinned manifest. Cloned cheaply via `Arc`.
    pub fn manifest(&self) -> Arc<CompManifest> {
        Arc::clone(&self.manifest)
    }

    // --- Quote ---

    /// Validate a quote request and return a signed quote.
    pub fn quote(&self, request: CompQuoteRequest) -> Result<CompQuoteResponse, LicensingError> {
        if request.comp_version != COMP_VERSION {
            return Err(LicensingError::UnsupportedType(format!(
                "comp_version {} not supported",
                request.comp_version
            )));
        }
        let tier = self.find_tier(&request.tier_id)?;

        let amount_micros = compute_amount(&tier.pricing, &request.requested_volume)?;
        let unit = format_unit(&request.requested_volume);

        let now = unix_now();
        let valid_until_unix = now.saturating_add(COMP_QUOTE_VALIDITY_SECS);
        let valid_until = format_rfc3339(valid_until_unix);
        let quote_id = ulid::Ulid::new().to_string();

        let acquisition = CompAcquisition {
            url: self.manifest.endpoints.redeem.clone(),
            method: "redeem".into(),
        };

        let mut response = CompQuoteResponse {
            comp_version: COMP_VERSION.into(),
            quote_id: quote_id.clone(),
            tier_id: tier.id.clone(),
            license: tier.license.clone(),
            pricing: CompQuotePricing {
                currency: tier.pricing.currency.clone(),
                amount_micros,
                unit,
            },
            acquisition,
            valid_until,
            signature: CompSignature {
                alg: "ed25519".into(),
                kid: String::new(),
                value: String::new(),
            },
        };

        let signing_input = canonical_quote_signing_input(&response)?;
        let (kid, sig) = self.keys.sign(&signing_input)?;
        response.signature.kid = kid;
        response.signature.value = B64URL.encode(sig);

        {
            let mut ledger = self
                .issued_quotes
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            // Keep expired rows as tombstones. Sweeping them at expiry
            // is what made the expiry check unreachable: the only code
            // that removed a row was this sweep, and once removed the id
            // fell into the "unknown to this process" branch, which
            // proceeds. Any buyer could trigger the sweep by asking for
            // a new quote, so the window in which the check fired was
            // close to zero.
            ledger
                .retain(|_, issued| issued.valid_until.saturating_add(QUOTE_TOMBSTONE_SECS) > now);
            ledger.insert(
                quote_id,
                IssuedQuote {
                    valid_until: valid_until_unix,
                    quote_hash: quote_hash(&signing_input),
                },
            );
        }

        Ok(response)
    }

    // --- Redeem ---

    /// Validate a redeem request and mint a bridged OLP license token.
    pub async fn redeem(
        &self,
        request: CompRedeemRequest,
    ) -> Result<CompRedeemResponse, LicensingError> {
        if request.comp_version != COMP_VERSION {
            return Err(LicensingError::UnsupportedType(format!(
                "comp_version {} not supported",
                request.comp_version
            )));
        }

        let buyer_sig = &request.buyer_signature;
        if buyer_sig.alg != "ed25519" {
            return Err(LicensingError::UnsupportedAlg(buyer_sig.alg.clone()));
        }
        let buyer_key = self.buyer_keys.resolve(&buyer_sig.kid).await?;
        let signing_input = canonical_redeem_signing_input(&request)?;
        let sig_bytes = B64URL
            .decode(&buyer_sig.value)
            .map_err(|e| LicensingError::Malformed(format!("buyer signature b64: {e}")))?;
        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| LicensingError::SignatureInvalid)?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
        buyer_key
            .verify(&signing_input, &signature)
            .map_err(|_| LicensingError::SignatureInvalid)?;

        if self.revocation.is_revoked(&request.quote_id).await? {
            return Err(LicensingError::Revoked(request.quote_id.clone()));
        }

        let now = unix_now();
        let issued = self
            .issued_quotes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&request.quote_id)
            .cloned();
        if let Some(issued) = issued {
            if issued.valid_until <= now {
                return Err(LicensingError::Expired {
                    exp: issued.valid_until,
                    now,
                });
            }
            // Bind the redeem to the quote. Without this the whole
            // request reduces to a syntactically valid body with a
            // fabricated quote_id and a fabricated hash, redeemable on
            // a loop by any onboarded buyer key.
            if request.buyer_acceptance.accepted_quote_hash != issued.quote_hash {
                return Err(LicensingError::Malformed(
                    "buyer_acceptance.accepted_quote_hash does not match the quote this \
                     publisher issued for that quote_id"
                        .to_string(),
                ));
            }
        }

        verify_payment_proof(&request.payment_proof)?;

        let acceptance = &request.buyer_acceptance;
        let buyer_kid = buyer_sig.kid.clone();
        let agent_id = derive_agent_id(&buyer_kid, acceptance);

        let tier = self.tier_for_acceptance(acceptance)?;
        let token =
            self.olp_bridge
                .mint(&agent_id, &self.manifest.publisher.domain, &tier.license)?;
        let expires_in = expires_in_of(&token)?;

        Ok(CompRedeemResponse {
            license_token: token,
            token_type: "Bearer".into(),
            expires_in,
            license: tier.license.clone(),
            agent_id,
            route_glob: tier.route_glob.clone(),
        })
    }

    // --- Helpers ---

    fn find_tier(&self, tier_id: &str) -> Result<&CompTier, LicensingError> {
        self.manifest
            .tiers
            .iter()
            .find(|t| t.id == tier_id)
            .ok_or_else(|| LicensingError::UnknownTier(tier_id.to_string()))
    }

    fn tier_for_acceptance(
        &self,
        _acceptance: &CompAcceptance,
    ) -> Result<&CompTier, LicensingError> {
        // v1: redeem runs against a single-tier manifest in the
        // common case; pick the first OLP-authorised tier. A
        // production composer keys on quote_id once a quote-to-tier
        // store lands as separate scope.
        self.manifest
            .tiers
            .iter()
            .find(|t| matches!(t.authorization, super::types::CompAuthorization::Olp))
            .ok_or_else(|| LicensingError::Encode("no OLP-authorised tier in manifest".into()))
    }
}

/// Decode `expires_in` (exp - iat) from a just-minted bridged token
/// without re-deriving the signer's private configuration. Kept free
/// so it can be unit-tested against the wire format directly.
fn expires_in_of(token: &str) -> Result<u64, LicensingError> {
    let mut parts = token.split('.');
    let _header = parts
        .next()
        .ok_or_else(|| LicensingError::Malformed("missing header".into()))?;
    let payload_b64 = parts
        .next()
        .ok_or_else(|| LicensingError::Malformed("missing payload".into()))?;
    let payload = B64URL
        .decode(payload_b64)
        .map_err(|e| LicensingError::Malformed(format!("payload b64: {e}")))?;
    let claims: super::olp_bridge::OlpBridgeClaims = serde_json::from_slice(&payload)
        .map_err(|e| LicensingError::Malformed(format!("claims decode: {e}")))?;
    Ok(claims.exp.saturating_sub(claims.iat))
}

// --- Pricing ---

fn compute_amount(
    pricing: &super::types::CompPricing,
    volume: &super::types::CompRequestedVolume,
) -> Result<u64, LicensingError> {
    match pricing.model {
        CompPricingModel::Free => Ok(0),
        CompPricingModel::FlatRate => {
            let amount = pricing.amount.unwrap_or(0);
            Ok(amount.saturating_mul(1_000_000))
        }
        CompPricingModel::PerRequest => {
            let unit = pricing.amount_micros.unwrap_or(0);
            Ok(unit.saturating_mul(volume.expected_count))
        }
    }
}

fn format_unit(volume: &super::types::CompRequestedVolume) -> String {
    format!(
        "{} requests over {} days",
        volume.expected_count, volume.duration_days
    )
}

// --- Canonical signing inputs ---

/// The bytes a CoMP quote signature covers.
///
/// "Canonical" here means `serde_json` over this Rust struct with the
/// signature `kid` and `value` cleared, which fixes the byte order as
/// the struct's field declaration order. A non-Rust client that signs
/// or verifies has to reproduce that order exactly; this is not JCS.
/// `docs/comp-marketplace.md` states the ordering contract for anyone
/// writing a client.
fn canonical_quote_signing_input(quote: &CompQuoteResponse) -> Result<Vec<u8>, LicensingError> {
    let mut clone = quote.clone();
    // Strip kid + value so signer and verifier compute identical bytes.
    clone.signature.kid = String::new();
    clone.signature.value = String::new();
    serde_json::to_vec(&clone).map_err(LicensingError::from)
}

/// The bytes a CoMP redeem signature covers. Same ordering contract as
/// [`canonical_quote_signing_input`].
fn canonical_redeem_signing_input(req: &CompRedeemRequest) -> Result<Vec<u8>, LicensingError> {
    let mut clone = req.clone();
    clone.buyer_signature.value = String::new();
    serde_json::to_vec(&clone).map_err(LicensingError::from)
}

// --- Payment-proof bridge ---

fn verify_payment_proof(proof: &super::types::CompPaymentProof) -> Result<(), LicensingError> {
    // v1: per-rail integration is deferred; this accepts any proof
    // whose rail is recognised and whose receipt fields are
    // populated. Real verification (x402 facilitator query, MPP
    // receipt resolution, Stripe payment_intent lookup) is separate
    // scope, tracked against the workspace's existing payment rails
    // rather than reimplemented here.
    match proof.rail.as_str() {
        "x402" => {
            if proof.txhash.as_deref().unwrap_or("").is_empty()
                || proof.chain.as_deref().unwrap_or("").is_empty()
            {
                return Err(LicensingError::Malformed(
                    "x402 proof missing txhash or chain".into(),
                ));
            }
        }
        "mpp" | "stripe" => {
            if proof.receipt_id.as_deref().unwrap_or("").is_empty() {
                return Err(LicensingError::Malformed(format!(
                    "{} proof missing receipt_id",
                    proof.rail
                )));
            }
        }
        other => {
            return Err(LicensingError::UnsupportedType(format!(
                "unsupported payment rail {other}"
            )));
        }
    }
    Ok(())
}

fn derive_agent_id(buyer_kid: &str, acceptance: &CompAcceptance) -> String {
    // Stable id derived from the buyer kid + legal entity; the audit
    // log entry uses this so two buyers signing under the same kid
    // remain distinguishable by their declared legal entity.
    let mut hasher = Sha256::new();
    hasher.update(buyer_kid.as_bytes());
    hasher.update(b":");
    hasher.update(acceptance.buyer_legal_entity.as_bytes());
    let digest = hasher.finalize();
    format!("agent_{}", hex::encode(&digest[..8]))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn format_rfc3339(unix: u64) -> String {
    // Hand-rolled to avoid pulling chrono into this crate; the format
    // is a simplified RFC 3339 stamp suitable for the marketplace
    // wire surface.
    let secs = unix as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hh = rem / 3600;
    let mm = (rem % 3600) / 60;
    let ss = rem % 60;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

fn days_to_ymd(mut days: i64) -> (i32, u32, u32) {
    days += 719_468;
    let era = days.div_euclid(146_097);
    let doe = days - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comp::types::{
        CompAuthorization, CompBuyer, CompEndpoints, CompPaymentProof, CompPricing, CompPublisher,
        CompRequestedVolume,
    };
    use crate::keys::MasterKey;
    use crate::revocation::InMemoryRevocation;
    use ed25519_dalek::{Signer, SigningKey};

    fn build_manifest() -> Arc<CompManifest> {
        Arc::new(CompManifest {
            comp_version: COMP_VERSION.into(),
            publisher: CompPublisher {
                name: "Example".into(),
                domain: "api.example.com".into(),
                contact: "licensing@example.com".into(),
                verified_at: None,
            },
            tiers: vec![CompTier {
                id: "tier_ai_inference".into(),
                name: "AI inference".into(),
                description: "Per-request inference".into(),
                license: "urn:rsl:pay-per-inference:default".into(),
                shape: "json-envelope".into(),
                pricing: CompPricing {
                    model: CompPricingModel::PerRequest,
                    currency: "USD".into(),
                    amount: None,
                    amount_micros: Some(2500),
                },
                authorization: CompAuthorization::Olp,
                rate_caps: None,
                route_glob: "/api/v1/inference/**".into(),
            }],
            endpoints: CompEndpoints {
                manifest: "https://api.example.com/.well-known/iab-comp/manifest.json".into(),
                quote: "https://api.example.com/.well-known/iab-comp/quote".into(),
                redeem: "https://api.example.com/.well-known/iab-comp/redeem".into(),
            },
            robots_url: "https://api.example.com/robots.txt".into(),
            llms_url: "https://api.example.com/llms.txt".into(),
            rsl_url: "https://api.example.com/licenses.xml".into(),
            generated_at: "2026-05-02T14:00:00Z".into(),
            manifest_hash: "sha256:placeholder".into(),
        })
    }

    fn build_marketplace() -> (
        Arc<CompMarketplace>,
        Arc<InMemoryBuyerKeyRegistry>,
        SigningKey,
    ) {
        let mgr = KeyManager::new(MasterKey::new(vec![0x33u8; 32]).unwrap());
        mgr.set_active("2026-q2-001").unwrap();
        let bridge = Arc::new(OlpBridgeSigner::new(
            [0x44u8; 32],
            "olp-2026-q2-001",
            "https://api.example.com",
            "ai-input",
            3600,
        ));
        let revocation: Arc<dyn Revocation> = Arc::new(InMemoryRevocation::new());
        let buyer_keys = Arc::new(InMemoryBuyerKeyRegistry::new());
        let buyer_signing = SigningKey::from_bytes(&[0x55u8; 32]);
        buyer_keys.insert("buyer-1", buyer_signing.verifying_key());
        let mp = Arc::new(CompMarketplace::new(
            mgr,
            build_manifest(),
            revocation,
            bridge,
            buyer_keys.clone(),
        ));
        (mp, buyer_keys, buyer_signing)
    }

    fn quote_request() -> CompQuoteRequest {
        CompQuoteRequest {
            comp_version: COMP_VERSION.into(),
            buyer: CompBuyer {
                agent_id: "agent_acme_001".into(),
                organization: "Acme AI".into(),
            },
            tier_id: "tier_ai_inference".into(),
            requested_volume: CompRequestedVolume {
                model: CompPricingModel::PerRequest,
                expected_count: 100,
                duration_days: 30,
            },
            audience: "api.example.com".into(),
        }
    }

    /// Build a redeem carrying the quote hash a buyer who actually held
    /// the quote would compute.
    fn build_redeem_for(quote: &CompQuoteResponse, signer: &SigningKey) -> CompRedeemRequest {
        let hash = quote_hash(&canonical_quote_signing_input(quote).unwrap());
        build_redeem_with_hash(quote.quote_id.clone(), &hash, signer)
    }

    fn build_redeem(quote_id: String, signer: &SigningKey) -> CompRedeemRequest {
        build_redeem_with_hash(quote_id, "sha256:placeholder", signer)
    }

    fn build_redeem_with_hash(
        quote_id: String,
        accepted_quote_hash: &str,
        signer: &SigningKey,
    ) -> CompRedeemRequest {
        let mut req = CompRedeemRequest {
            comp_version: COMP_VERSION.into(),
            quote_id,
            buyer_signature: CompSignature {
                alg: "ed25519".into(),
                kid: "buyer-1".into(),
                value: String::new(),
            },
            buyer_acceptance: CompAcceptance {
                accepted_quote_hash: accepted_quote_hash.into(),
                accepted_at: "2026-05-02T14:35:00Z".into(),
                buyer_legal_entity: "Acme AI Inc.".into(),
            },
            payment_proof: CompPaymentProof {
                rail: "x402".into(),
                txhash: Some("0xabc".into()),
                chain: Some("base".into()),
                receipt_id: None,
            },
        };
        let signing_input = canonical_redeem_signing_input(&req).unwrap();
        let sig = signer.sign(&signing_input);
        req.buyer_signature.value = B64URL.encode(sig.to_bytes());
        req
    }

    #[test]
    fn quote_happy_path_signs_quote() {
        let (mp, _, _) = build_marketplace();
        let res = mp.quote(quote_request()).unwrap();
        assert_eq!(res.tier_id, "tier_ai_inference");
        assert_eq!(res.pricing.amount_micros, 250_000);
        assert!(res.signature.kid.starts_with("comp-"));
        assert!(!res.signature.value.is_empty());
        // Verify the signature with the kid's verifying key.
        let key = mp.keys.lookup(&res.signature.kid).unwrap();
        let signing_input = canonical_quote_signing_input(&res).unwrap();
        let sig_bytes = B64URL.decode(&res.signature.value).unwrap();
        let arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&arr);
        key.verify(&signing_input, &sig).unwrap();
    }

    #[test]
    fn quote_rejects_unknown_tier() {
        let (mp, _, _) = build_marketplace();
        let mut req = quote_request();
        req.tier_id = "tier_does_not_exist".into();
        let err = mp.quote(req).unwrap_err();
        assert!(matches!(err, LicensingError::UnknownTier(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn redeem_happy_path_returns_bridged_token() {
        let (mp, _, signer) = build_marketplace();
        let quote = mp.quote(quote_request()).unwrap();
        let redeem = build_redeem_for(&quote, &signer);
        let res = mp.redeem(redeem).await.unwrap();
        assert_eq!(res.token_type, "Bearer");
        assert_eq!(res.license, "urn:rsl:pay-per-inference:default");
        assert_eq!(res.route_glob, "/api/v1/inference/**");
        // Token shape: three b64url segments separated by dots, and
        // decodes to the expected TTL via the OSS-format claim names.
        assert_eq!(res.license_token.split('.').count(), 3);
        assert_eq!(expires_in_of(&res.license_token).unwrap(), 3600);
    }

    #[tokio::test]
    async fn redeem_rejects_bad_buyer_signature() {
        let (mp, _, signer) = build_marketplace();
        let quote = mp.quote(quote_request()).unwrap();
        let mut redeem = build_redeem(quote.quote_id, &signer);
        // Flip a bit in the signature.
        let mut sig_bytes = B64URL.decode(&redeem.buyer_signature.value).unwrap();
        sig_bytes[0] ^= 0x01;
        redeem.buyer_signature.value = B64URL.encode(sig_bytes);
        let err = mp.redeem(redeem).await.unwrap_err();
        assert!(matches!(err, LicensingError::SignatureInvalid));
    }

    #[tokio::test]
    async fn redeem_rejects_after_revocation() {
        let (mp, _, signer) = build_marketplace();
        let quote = mp.quote(quote_request()).unwrap();
        // Revoke the quote_id before redeem.
        mp.revocation
            .revoke(&quote.quote_id, unix_now() + 3600)
            .await
            .unwrap();
        let redeem = build_redeem(quote.quote_id, &signer);
        let err = mp.redeem(redeem).await.unwrap_err();
        assert!(matches!(err, LicensingError::Revoked(_)));
    }

    #[tokio::test]
    async fn redeem_rejects_after_quote_expiry() {
        let (mp, _, signer) = build_marketplace();
        let quote = mp.quote(quote_request()).unwrap();
        // Force the in-process ledger's entry into the past without
        // waiting a real hour.
        let hash = quote_hash(&canonical_quote_signing_input(&quote).unwrap());
        mp.issued_quotes.lock().unwrap().insert(
            quote.quote_id.clone(),
            IssuedQuote {
                valid_until: unix_now().saturating_sub(1),
                quote_hash: hash,
            },
        );
        let redeem = build_redeem_for(&quote, &signer);
        let err = mp.redeem(redeem).await.unwrap_err();
        assert!(matches!(err, LicensingError::Expired { .. }));
    }

    #[tokio::test]
    async fn an_expired_quote_stays_refusable_after_a_later_quote_request() {
        // The interaction the two tests either side of this one hid
        // from each other: quote, expire, quote again, redeem the first.
        // The second quote's sweep used to remove the expired row, and
        // the redeem then fell into the "unknown to this process"
        // branch and minted a token.
        let (mp, _, signer) = build_marketplace();
        let first = mp.quote(quote_request()).unwrap();
        let hash = quote_hash(&canonical_quote_signing_input(&first).unwrap());
        mp.issued_quotes.lock().unwrap().insert(
            first.quote_id.clone(),
            IssuedQuote {
                valid_until: unix_now().saturating_sub(1),
                quote_hash: hash,
            },
        );
        // Anyone can trigger this: /quote is unauthenticated.
        let _second = mp.quote(quote_request()).unwrap();
        let redeem = build_redeem_for(&first, &signer);
        let err = mp.redeem(redeem).await.unwrap_err();
        assert!(matches!(err, LicensingError::Expired { .. }), "got {err:?}");
    }

    #[tokio::test]
    async fn redeem_rejects_an_acceptance_hash_that_is_not_the_issued_quote() {
        // Without this the redeem is bound to nothing: the quote_id and
        // the acceptance hash are both free-form strings the buyer
        // writes, and an onboarded key could mint a license per call
        // forever without ever asking for a quote.
        let (mp, _, signer) = build_marketplace();
        let quote = mp.quote(quote_request()).unwrap();
        let redeem = build_redeem(quote.quote_id, &signer);
        let err = mp.redeem(redeem).await.unwrap_err();
        assert!(
            matches!(err, LicensingError::Malformed(ref message) if message.contains("accepted_quote_hash")),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn redeem_allows_quote_unknown_to_this_process() {
        // A quote_id the in-process ledger never saw (e.g. minted
        // before a restart) is not rejected on expiry grounds alone;
        // this crate's no-external-store default cannot know its
        // real expiry, so it falls through to the other redeem
        // checks rather than failing closed on missing bookkeeping.
        let (mp, _, signer) = build_marketplace();
        let redeem = build_redeem("01JUNKNOWNQUOTEID000000000".into(), &signer);
        let res = mp.redeem(redeem).await.unwrap();
        assert_eq!(res.token_type, "Bearer");
    }
}

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

/// Rows one bridge's issued-quote ledger holds before it starts
/// refusing.
///
/// **Per bridge, so per origin.** Each `origins.<host>.comp` block
/// builds its own `CompMarketplace` with its own ledger, so a process
/// serving N origins with a bridge bounds at `N x
/// COMP_QUOTE_LEDGER_CAPACITY` rows, roughly `N x 10 MB`. That is the
/// number to size against, not this one. Ten bridged origins is about
/// 100 MB of worst case, which is a bound a proxy can hold; a
/// deployment with hundreds of bridged origins on one process should
/// know it is choosing that ceiling.
///
/// `POST /quote` is unauthenticated, and on the proxy it answers and
/// returns before bot detection, threat protection, authentication, and
/// the policy chain where an origin's own rate limits live. So the
/// origin's limits never see it and this map is the only thing standing
/// between one looping client and an OOM that takes every other origin
/// on the process with it.
///
/// Fifty thousand rows is roughly ten megabytes at about 200 bytes per
/// row (a 26-character ULID key, a 71-character `sha256:` hash, two
/// integers, a bool, and map overhead), which is a bound a proxy can
/// hold without thinking about it and far past any real publisher's
/// concurrent outstanding quotes.
///
/// Refusing rather than evicting the oldest row is deliberate: eviction
/// would let a flood push a paying buyer's quote out of the ledger,
/// turning a denial-of-service into a denial-of-purchase. Refusing
/// costs new quotes during a flood and leaves every issued one
/// redeemable.
pub const COMP_QUOTE_LEDGER_CAPACITY: usize = 50_000;

/// How far ahead of this bridge's clock a buyer's `accepted_at` may
/// sit before the acceptance is refused.
///
/// Five minutes, the same allowance JWT verifiers conventionally give
/// `nbf` and `iat`, and for the same reason: a buyer whose clock runs a
/// minute fast is a normal deployment, not an attack. Anything past the
/// window is refused rather than clamped, because the whole point of
/// reading the field is that it bounds when the acceptance was made.
pub const COMP_ACCEPTANCE_SKEW_SECS: u64 = 300;

// --- Buyer-key registry ---

/// Resolves a buyer kid to a verifying key for redeem-time signature
/// verification.
#[async_trait]
pub trait BuyerKeyRegistry: Send + Sync {
    /// Resolve `kid` to a buyer verifying key. Returns
    /// [`LicensingError::UnknownKey`] for an unrecognized kid.
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

    /// Register a buyer key from its base64url-without-padding
    /// encoding, the form `origins.<host>.comp.buyer_keys[].public_key`
    /// carries.
    ///
    /// Exists so a host that only has the config string does not have
    /// to take its own `ed25519-dalek` dependency to hand this registry
    /// a key. Every refusal an operator can cause is a typed error
    /// here: the wrong alphabet, the wrong length, and a 32-byte value
    /// that is not a point on the curve are three different mistakes
    /// and read as three different messages.
    ///
    /// # Errors
    ///
    /// [`LicensingError::Malformed`] when the value is not
    /// base64url-without-padding, does not decode to 32 bytes, or is
    /// not a valid Ed25519 public key.
    pub fn insert_base64url(
        &self,
        kid: impl Into<String>,
        public_key: &str,
    ) -> Result<(), LicensingError> {
        let kid = kid.into();
        let decoded = B64URL.decode(public_key.trim()).map_err(|error| {
            LicensingError::Malformed(format!(
                "buyer key '{kid}' is not base64url without padding: {error}"
            ))
        })?;
        let bytes: [u8; 32] = decoded.as_slice().try_into().map_err(|_| {
            LicensingError::Malformed(format!(
                "buyer key '{kid}' decoded to {} bytes; an Ed25519 public key is 32",
                decoded.len()
            ))
        })?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|error| {
            LicensingError::Malformed(format!(
                "buyer key '{kid}' is not a valid Ed25519 point: {error}"
            ))
        })?;
        self.insert(kid, key);
        Ok(())
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
    /// Whether a redeem for a `quote_id` this process never issued is
    /// honored (WOR-2673).
    ///
    /// `false` by default, which is the fail-closed reading: an
    /// onboarded buyer key plus a fabricated id would otherwise mint a
    /// token per call with no quote and no price behind it, and the
    /// publisher's reconciliation would show no quote for the revenue.
    ///
    /// The cost of the default is real and worth stating: the ledger is
    /// in memory, so a restart forgets every quote this bridge signed,
    /// and a buyer holding a quote from thirty seconds ago is refused.
    /// A single long-lived bridge that would rather absorb the
    /// fabrication risk than the restart refusals sets this true; see
    /// `origins.<host>.comp.allow_unknown_quotes`.
    allow_unknown_quotes: bool,
    /// Row cap for [`Self::issued_quotes`]. See
    /// [`COMP_QUOTE_LEDGER_CAPACITY`] for why one exists.
    quote_ledger_capacity: usize,
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
    /// Whether this quote has already been redeemed.
    ///
    /// A quote is single-use. Set under the same guard that reads the
    /// row, before any minting, so two concurrent redeems of one quote
    /// cannot both pass the check.
    redeemed: bool,
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
/// `canonical_quote_signing_input` applies to it too.
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
            allow_unknown_quotes: false,
            quote_ledger_capacity: COMP_QUOTE_LEDGER_CAPACITY,
        }
    }

    /// Override the issued-quote ledger's row cap.
    ///
    /// Test-only on purpose. [`COMP_QUOTE_LEDGER_CAPACITY`] is not
    /// operator-configurable: a cap an operator can raise is a cap an
    /// operator can raise until it stops bounding anything, and the
    /// number that matters to them is the refusal it produces, which
    /// the counter and `docs/comp-marketplace.md` both name. This
    /// exists so the bound is testable without issuing fifty thousand
    /// quotes. Make it `pub` when a caller outside these tests has a
    /// reason, not before.
    #[cfg(test)]
    #[must_use]
    fn with_quote_ledger_capacity(mut self, capacity: usize) -> Self {
        self.quote_ledger_capacity = capacity.max(1);
        self
    }

    /// Move every ledger row this many seconds into the past, so a test
    /// can reach the tombstone sweep without sleeping.
    #[cfg(test)]
    fn age_ledger_for_test(&self, seconds: u64) {
        let mut ledger = self
            .issued_quotes
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for issued in ledger.values_mut() {
            issued.valid_until = issued.valid_until.saturating_sub(seconds);
        }
    }

    /// Honor a redeem whose `quote_id` this process never issued.
    ///
    /// The opt-out from the fail-closed default. What it buys: a buyer
    /// holding a quote this bridge signed before a reload is honored
    /// rather than refused, since the ledger is in memory and a reload
    /// forgets it. What it costs: an onboarded buyer key plus a
    /// fabricated `quote_id`, a fabricated `accepted_quote_hash`, and a
    /// shape-valid payment proof then mints a license token per call
    /// with no quote and no price behind it. A deployment that reaches for this should also be running
    /// [`crate::revocation::RedisRevocation`], since the revocation
    /// check is then the only durable thing standing between a
    /// fabricated id and a token.
    #[must_use]
    pub fn allowing_unknown_quotes(mut self) -> Self {
        self.allow_unknown_quotes = true;
        self
    }

    /// The pinned manifest. Cloned cheaply via `Arc`.
    pub fn manifest(&self) -> Arc<CompManifest> {
        Arc::clone(&self.manifest)
    }

    /// The kid quotes are currently signed under, or `None` when no
    /// rotation has been activated (every quote request fails closed
    /// until one is).
    ///
    /// A read-only projection rather than an accessor for the
    /// [`KeyManager`] itself: the manager can sign, and an operator
    /// surface that only needs to answer "which key is live" should
    /// not be handed the thing that mints signatures.
    pub fn active_signing_kid(&self) -> Option<String> {
        self.keys.active_kid()
    }

    /// How many CoMP kids currently verify: the active one plus any
    /// rotation-window keys still trusted.
    pub fn trusted_kid_count(&self) -> usize {
        self.keys.jwks().len()
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

        // Sweep and check the cap *before* signing (WOR-2673 re-review
        // N6). The signature is the expensive part of this function, and
        // a flood at capacity is exactly when it is worth not paying:
        // checking first makes every refused request cost a map sweep
        // instead of a sweep plus an Ed25519 signature.
        //
        // The sweep has to run under the same guard as the check, or the
        // cap would be a lifetime one rather than a live-row one:
        // keeping expired rows as tombstones is what makes the redeem
        // expiry check reachable at all, and dropping them at expiry is
        // what made it unreachable before.
        {
            let mut ledger = self
                .issued_quotes
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            ledger
                .retain(|_, issued| issued.valid_until.saturating_add(QUOTE_TOMBSTONE_SECS) > now);
            if ledger.len() >= self.quote_ledger_capacity {
                return Err(LicensingError::QuoteLedgerFull {
                    capacity: self.quote_ledger_capacity,
                });
            }
        }

        let signing_input = canonical_quote_signing_input(&response)?;
        let (kid, sig) = self.keys.sign(&signing_input)?;
        response.signature.kid = kid;
        response.signature.value = B64URL.encode(sig);

        {
            let mut ledger = self
                .issued_quotes
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            // Re-check under the second guard. The lock was released
            // across the signature, so concurrent quoters could have
            // filled the ledger in the window. Without this the cap
            // would be exceeded by up to the number of threads signing
            // at once; with it a signature is wasted only in that race,
            // never during a sustained flood, because the check above
            // already refused those before signing.
            //
            // Refusing here discards a quote this bridge signed and
            // never returned, which is the right direction: returning a
            // signed quote the ledger does not hold would send the
            // buyer's redeem into the unknown-quote branch.
            if ledger.len() >= self.quote_ledger_capacity {
                return Err(LicensingError::QuoteLedgerFull {
                    capacity: self.quote_ledger_capacity,
                });
            }
            ledger.insert(
                quote_id,
                IssuedQuote {
                    redeemed: false,
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
        // The acceptance's own timestamp, checked before the ledger so
        // the refusal is the same whether or not this process still
        // holds the quote. Unparseable is a refusal rather than a
        // fallback to `now`: reading a value this bridge cannot read as
        // the current time turns a bounded window into no window.
        let accepted_at =
            parse_rfc3339_to_unix(&request.buyer_acceptance.accepted_at).ok_or_else(|| {
                LicensingError::Malformed(
                    "buyer_acceptance.accepted_at is not an RFC 3339 timestamp".to_string(),
                )
            })?;
        if accepted_at > now.saturating_add(COMP_ACCEPTANCE_SKEW_SECS) {
            return Err(LicensingError::Expired {
                exp: now.saturating_add(COMP_ACCEPTANCE_SKEW_SECS),
                now: accepted_at,
            });
        }
        // An acceptance older than a quote's whole validity window
        // cannot be an acceptance of a live quote: no quote this bridge
        // would still honor existed when it was signed.
        if accepted_at < now.saturating_sub(COMP_QUOTE_VALIDITY_SECS + COMP_ACCEPTANCE_SKEW_SECS) {
            return Err(LicensingError::Expired {
                exp: accepted_at,
                now,
            });
        }

        // Check and consume under one guard (WOR-2673 review M1). A
        // quote is single-use, and the buyer signature covers the body
        // with its own value cleared, so a replay is a resend of
        // identical bytes and costs the buyer nothing. Marking the row
        // here rather than after the mint is what makes two concurrent
        // redeems of one quote mint once: the guard is the only thing
        // both of them have to pass through.
        //
        // Consuming before the mint means a quote is spent even if the
        // signing that follows fails. That is the fail-closed
        // direction: the alternative leaves a window in which a buyer
        // who can make minting fail keeps redeeming.
        {
            let mut ledger = self
                .issued_quotes
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            match ledger.get_mut(&request.quote_id) {
                Some(issued) => {
                    if issued.redeemed {
                        return Err(LicensingError::AlreadyRedeemed(request.quote_id.clone()));
                    }
                    if issued.valid_until <= now {
                        return Err(LicensingError::Expired {
                            exp: issued.valid_until,
                            now,
                        });
                    }
                    // Bind the redeem to the quote. Without this the
                    // whole request reduces to a syntactically valid
                    // body with a fabricated quote_id and a fabricated
                    // hash, redeemable on a loop by any onboarded buyer
                    // key.
                    if request.buyer_acceptance.accepted_quote_hash != issued.quote_hash {
                        return Err(LicensingError::Malformed(
                            "buyer_acceptance.accepted_quote_hash does not match the quote this \
                             publisher issued for that quote_id"
                                .to_string(),
                        ));
                    }
                    issued.redeemed = true;
                }
                // No row, and the operator has not opted out. Refused
                // for the reason on `allow_unknown_quotes`.
                None if !self.allow_unknown_quotes => {
                    return Err(LicensingError::UnknownQuote(request.quote_id.clone()));
                }
                // The opt-out. Note what it also gives up: with no row
                // there is nothing to mark, so single-use protection
                // does not apply to a quote this process does not hold.
                // `docs/comp-marketplace.md` says so.
                None => {}
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

    /// Resolve the tier a redeem mints for.
    ///
    /// Nothing in a redeem request names a tier: the buyer sends a
    /// `quote_id`, and this bridge keeps no durable quote-to-tier
    /// mapping (that store is separate scope). So the manifest has to
    /// carry exactly one redeemable tier for the answer to be
    /// unambiguous, and it does: `validate_comp_marketplace` refuses a
    /// catalog with zero or with two.
    ///
    /// This function re-checks that rather than trusting it, because
    /// the compiler is not the only way a `CompMarketplace` is built.
    /// A host constructing one in memory gets the same refusal instead
    /// of silently minting the wrong tier's license (WOR-2673 review
    /// B2).
    fn tier_for_acceptance(
        &self,
        _acceptance: &CompAcceptance,
    ) -> Result<&CompTier, LicensingError> {
        let mut olp = self
            .manifest
            .tiers
            .iter()
            .filter(|t| matches!(t.authorization, super::types::CompAuthorization::Olp));
        let first = olp
            .next()
            .ok_or_else(|| LicensingError::Encode("no OLP-authorized tier in manifest".into()))?;
        if let Some(second) = olp.next() {
            return Err(LicensingError::Encode(format!(
                "manifest carries more than one OLP-authorized tier ('{}' and '{}'); a redeem \
                 names no tier, so it cannot tell them apart",
                first.id, second.id
            )));
        }
        Ok(first)
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
    // whose rail is recognized and whose receipt fields are
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

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

pub(crate) fn format_rfc3339(unix: u64) -> String {
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

/// Parse a strict RFC 3339 timestamp into unix seconds.
///
/// Accepts `YYYY-MM-DDTHH:MM:SS` with an optional fractional-second
/// part, followed by `Z`, `z`, or a `+HH:MM` / `-HH:MM` offset. `T` may
/// be lowercase or a space, which RFC 3339 s5.6 permits.
///
/// Hand-rolled for the same reason [`format_rfc3339`] is: this crate
/// carries no `chrono`, and a date library is a large dependency for
/// one field. Deliberately strict rather than lenient. Every shape it
/// does not accept is answered with a refusal by the one caller, so a
/// parser that guessed would be a parser that let a bad timestamp
/// through, which is the failure this check exists to prevent.
///
/// Returns `None` for anything it cannot read exactly, including
/// out-of-range month, day, hour, minute, or second values and any
/// timestamp before the unix epoch.
fn parse_rfc3339_to_unix(value: &str) -> Option<u64> {
    let value = value.trim();
    let bytes = value.as_bytes();
    if bytes.len() < 19 {
        return None;
    }
    let digits = |range: std::ops::Range<usize>| -> Option<i64> {
        let slice = value.get(range)?;
        if !slice.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        slice.parse::<i64>().ok()
    };
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    if !matches!(bytes[10], b'T' | b't' | b' ') {
        return None;
    }
    if bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    let year = digits(0..4)?;
    let month = digits(5..7)?;
    let day = digits(8..10)?;
    let hour = digits(11..13)?;
    let minute = digits(14..16)?;
    let second = digits(17..19)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // 60 for a leap second, which RFC 3339 s5.7 allows; it lands on the
    // following minute, which is close enough for a skew window.
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    let mut rest = value.get(19..)?;
    if let Some(stripped) = rest.strip_prefix('.') {
        let fraction_len = stripped.bytes().take_while(u8::is_ascii_digit).count();
        if fraction_len == 0 {
            return None;
        }
        rest = stripped.get(fraction_len..)?;
    }
    let offset_secs: i64 = match rest.as_bytes() {
        [b'Z'] | [b'z'] => 0,
        [sign @ (b'+' | b'-'), rest_bytes @ ..] if rest_bytes.len() == 5 => {
            let text = std::str::from_utf8(rest_bytes).ok()?;
            if text.as_bytes()[2] != b':' {
                return None;
            }
            let hours: i64 = text.get(0..2)?.parse().ok()?;
            let minutes: i64 = text.get(3..5)?.parse().ok()?;
            if hours > 23 || minutes > 59 {
                return None;
            }
            let magnitude = hours * 3600 + minutes * 60;
            if *sign == b'+' {
                magnitude
            } else {
                -magnitude
            }
        }
        _ => return None,
    };

    let days = ymd_to_days(year, month as u32, day as u32)?;
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(hour * 3600 + minute * 60 + second)?
        .checked_sub(offset_secs)?;
    u64::try_from(seconds).ok()
}

/// Days since the unix epoch for a proleptic Gregorian date. The
/// inverse of [`days_to_ymd`], and it rejects a day past the month's
/// real length so `2026-02-30` is refused rather than rolled forward.
fn ymd_to_days(year: i64, month: u32, day: u32) -> Option<i64> {
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_length = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if day == 0 || day > month_length {
        return None;
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
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

    /// The same marketplace with a small ledger cap, so the bound is
    /// testable without issuing fifty thousand quotes.
    fn build_marketplace_with_ledger_capacity(
        capacity: usize,
    ) -> (
        Arc<CompMarketplace>,
        Arc<InMemoryBuyerKeyRegistry>,
        SigningKey,
    ) {
        let (mp, keys, signer) = build_marketplace();
        let mp = Arc::new(
            Arc::try_unwrap(mp)
                .unwrap_or_else(|_| panic!("the fixture holds the only reference"))
                .with_quote_ledger_capacity(capacity),
        );
        (mp, keys, signer)
    }

    /// The same marketplace with the restart-survival opt-out on.
    fn build_marketplace_allowing_unknown_quotes() -> (
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
        let mp = Arc::new(
            CompMarketplace::new(
                mgr,
                build_manifest(),
                revocation,
                bridge,
                buyer_keys.clone(),
            )
            .allowing_unknown_quotes(),
        );
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
                // Stamped from the clock rather than frozen. A frozen
                // date would have gone stale the moment the acceptance
                // freshness window landed, and every redeem test would
                // then be passing or failing for the wrong reason.
                accepted_at: format_rfc3339(unix_now()),
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

    /// WOR-2673 review B1: the quote ledger is bounded.
    ///
    /// `POST /quote` is unauthenticated and returns from the request
    /// path before bot detection, threat protection, auth, and the
    /// policy chain where rate limits live, so the origin's own limits
    /// never see it. Every accepted quote writes a row that survives
    /// its own expiry by a 24-hour tombstone. Without a cap, one client
    /// looping the endpoint grows the map until the process is
    /// OOM-killed, taking every other origin on the proxy with it.
    #[test]
    fn the_quote_ledger_refuses_rather_than_growing_without_bound() {
        let (mp, _, _) = build_marketplace_with_ledger_capacity(4);
        for index in 0..4 {
            mp.quote(quote_request())
                .unwrap_or_else(|error| panic!("quote {index} must be issued: {error}"));
        }
        let error = mp
            .quote(quote_request())
            .expect_err("the fifth quote must be refused rather than grow the ledger");
        assert!(
            matches!(error, LicensingError::QuoteLedgerFull { .. }),
            "got {error:?}"
        );
    }

    /// The cap is a live-row cap, not a lifetime one: rows that have
    /// aged past their tombstone are swept on the way in, so a bridge
    /// that has been up for a month is not permanently refusing.
    #[test]
    fn a_swept_ledger_accepts_quotes_again() {
        let (mp, _, _) = build_marketplace_with_ledger_capacity(2);
        mp.quote(quote_request()).expect("first quote");
        mp.quote(quote_request()).expect("second quote");
        assert!(mp.quote(quote_request()).is_err(), "the cap holds");
        // Age every row past its expiry plus the tombstone window.
        mp.age_ledger_for_test(COMP_QUOTE_VALIDITY_SECS + QUOTE_TOMBSTONE_SECS + 1);
        mp.quote(quote_request())
            .expect("a swept ledger has room again");
    }

    /// WOR-2673 review M1: a redeem is single-use.
    ///
    /// The buyer signature covers the body with `buyer_signature.value`
    /// cleared, so replaying costs nothing: resend the identical bytes.
    /// Without consumption one purchase mints a fresh 24-hour license
    /// token per call for the whole quote validity window, and the
    /// publisher's reconciliation shows one quote for N licenses.
    #[tokio::test]
    async fn a_quote_redeems_once_and_the_replay_is_refused() {
        let (mp, _, signer) = build_marketplace();
        let quote = mp.quote(quote_request()).unwrap();
        let redeem = build_redeem_for(&quote, &signer);

        mp.redeem(redeem.clone())
            .await
            .expect("the first redeem mints");
        let error = mp
            .redeem(redeem)
            .await
            .expect_err("the identical body must not mint a second token");
        assert!(
            matches!(error, LicensingError::AlreadyRedeemed(ref id) if *id == quote.quote_id),
            "got {error:?}"
        );
    }

    /// Consumption happens under the same guard that reads the row, so
    /// concurrent redeems of one quote cannot both pass the check and
    /// both mint.
    ///
    /// Multi-threaded and spawned rather than `tokio::join!` on the
    /// current-thread runtime (WOR-2673 re-review N5). Neither `.await`
    /// inside `redeem` yields, so a joined pair runs to completion one
    /// after the other and passes just as well if the row were marked
    /// *after* the mint, which is the ordering this test exists to
    /// discriminate. Eight tasks on four threads race the guard for
    /// real.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_redeems_of_one_quote_mint_once() {
        let (mp, _, signer) = build_marketplace();
        let quote = mp.quote(quote_request()).unwrap();
        let redeem = build_redeem_for(&quote, &signer);

        let mut tasks = Vec::new();
        for _ in 0..8 {
            let mp = Arc::clone(&mp);
            let redeem = redeem.clone();
            tasks.push(tokio::spawn(async move { mp.redeem(redeem).await.is_ok() }));
        }
        let mut minted = 0usize;
        for task in tasks {
            if task.await.expect("no redeem task panics") {
                minted += 1;
            }
        }
        assert_eq!(
            minted, 1,
            "exactly one of eight concurrent redeems of one quote may mint"
        );
    }

    /// WOR-2673 fail-closed: an acceptance stamped in the future.
    ///
    /// `accepted_at` is the buyer's own attestation of when it agreed
    /// to the price, and it is the only timestamp in the redeem body.
    /// Unchecked, a buyer with one onboarded key can stamp an
    /// acceptance years ahead and keep the same body redeemable past
    /// every window this bridge has, because nothing else in the
    /// request goes stale.
    #[tokio::test]
    async fn an_acceptance_stamped_in_the_future_is_refused() {
        let (mp, _, signer) = build_marketplace();
        let quote = mp.quote(quote_request()).unwrap();
        let hash = quote_hash(&canonical_quote_signing_input(&quote).unwrap());
        let mut redeem = build_redeem_with_hash(quote.quote_id.clone(), &hash, &signer);
        redeem.buyer_acceptance.accepted_at = format_rfc3339(unix_now() + 86_400);
        resign(&mut redeem, &signer);
        let error = mp
            .redeem(redeem)
            .await
            .expect_err("an acceptance a day ahead of this clock must be refused");
        assert!(
            matches!(error, LicensingError::Expired { .. }),
            "got {error:?}"
        );
    }

    /// A small skew allowance is deliberate, so a buyer whose clock
    /// runs a minute fast is not refused. The window is bounded.
    #[tokio::test]
    async fn an_acceptance_inside_the_skew_allowance_still_redeems() {
        let (mp, _, signer) = build_marketplace();
        let quote = mp.quote(quote_request()).unwrap();
        let hash = quote_hash(&canonical_quote_signing_input(&quote).unwrap());
        let mut redeem = build_redeem_with_hash(quote.quote_id.clone(), &hash, &signer);
        redeem.buyer_acceptance.accepted_at =
            format_rfc3339(unix_now() + COMP_ACCEPTANCE_SKEW_SECS / 2);
        resign(&mut redeem, &signer);
        mp.redeem(redeem)
            .await
            .expect("a clock a couple of minutes fast is not an attack");
    }

    /// An acceptance older than the quote's own validity window cannot
    /// be an acceptance of that quote: the quote did not exist yet.
    #[tokio::test]
    async fn an_acceptance_older_than_the_quote_window_is_refused() {
        let (mp, _, signer) = build_marketplace();
        let quote = mp.quote(quote_request()).unwrap();
        let hash = quote_hash(&canonical_quote_signing_input(&quote).unwrap());
        let mut redeem = build_redeem_with_hash(quote.quote_id.clone(), &hash, &signer);
        redeem.buyer_acceptance.accepted_at =
            format_rfc3339(unix_now() - COMP_QUOTE_VALIDITY_SECS - 3_600);
        resign(&mut redeem, &signer);
        let error = mp
            .redeem(redeem)
            .await
            .expect_err("an acceptance predating the quote must be refused");
        assert!(
            matches!(error, LicensingError::Expired { .. }),
            "got {error:?}"
        );
    }

    /// A timestamp this bridge cannot read is refused rather than
    /// treated as "now". Reading an unparseable value as the current
    /// time is what turns a strict window into no window at all.
    #[tokio::test]
    async fn an_unparseable_acceptance_timestamp_is_refused() {
        let (mp, _, signer) = build_marketplace();
        let quote = mp.quote(quote_request()).unwrap();
        let hash = quote_hash(&canonical_quote_signing_input(&quote).unwrap());
        for stamp in ["", "yesterday", "2026-05-02", "2026-13-02T14:35:00Z"] {
            let mut redeem = build_redeem_with_hash(quote.quote_id.clone(), &hash, &signer);
            redeem.buyer_acceptance.accepted_at = stamp.to_string();
            resign(&mut redeem, &signer);
            let error = mp
                .redeem(redeem)
                .await
                .expect_err("an unreadable timestamp must be refused");
            assert!(
                matches!(error, LicensingError::Malformed(_)),
                "'{stamp}' got {error:?}"
            );
        }
    }

    /// WOR-2673 re-review N4: the runtime half of the single-OLP-tier
    /// invariant, which only the config compiler had a test for.
    ///
    /// `validate_comp_marketplace` refuses a catalog with two, so a
    /// config-loaded proxy never reaches this. A host building a
    /// `CompMarketplace` in memory does, and the review's own rule is
    /// that a detector has to be as wide as its enforcer: without this
    /// the runtime re-check could be deleted and every test would stay
    /// green while a buyer who quoted the cheap tier received the
    /// expensive tier's license.
    #[tokio::test]
    async fn a_manifest_with_two_olp_tiers_refuses_a_redeem_rather_than_guessing() {
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

        // The manifest the compiler would have refused: two redeemable
        // tiers, so a redeem naming only a quote_id cannot say which.
        let mut manifest = (*build_manifest()).clone();
        let mut second = manifest.tiers[0].clone();
        second.id = "tier_bulk_archive".into();
        second.license = "urn:rsl:bulk-archive:default".into();
        manifest.tiers.push(second);
        let mp = Arc::new(CompMarketplace::new(
            mgr,
            Arc::new(manifest),
            revocation,
            bridge,
            buyer_keys,
        ));

        let quote = mp.quote(quote_request()).unwrap();
        let redeem = build_redeem_for(&quote, &buyer_signing);
        let error = mp
            .redeem(redeem)
            .await
            .expect_err("an ambiguous catalog must refuse rather than pick one");
        let message = error.to_string();
        assert!(
            message.contains("tier_ai_inference") && message.contains("tier_bulk_archive"),
            "the refusal must name both tiers: {message}"
        );
    }

    /// WOR-2673 fail-closed: a `quote_id` this process never issued.
    ///
    /// The ledger lives in memory, so a restart forgets every quote it
    /// signed. Accepting an unknown id was the restart-survival answer,
    /// and it is also a hole a buyer can drive through: an onboarded
    /// key plus a fabricated id mints a token per call with no quote
    /// and no price behind it. Refusing is the default; an operator who
    /// runs one long-lived bridge and would rather lose the refusal
    /// than the in-flight quotes sets `allow_unknown_quotes`.
    #[tokio::test]
    async fn a_quote_id_this_process_never_issued_is_refused_by_default() {
        let (mp, _, signer) = build_marketplace();
        let redeem = build_redeem("01JQFABRICATEDQUOTEID000000".to_string(), &signer);
        let error = mp
            .redeem(redeem)
            .await
            .expect_err("a fabricated quote_id must not mint a token");
        assert!(
            matches!(error, LicensingError::UnknownQuote(_)),
            "got {error:?}"
        );
    }

    /// The opt-out, for a deployment that would rather honor quotes it
    /// issued before a restart. Same test, opposite expectation, so the
    /// switch cannot silently stop switching anything.
    #[tokio::test]
    async fn allow_unknown_quotes_restores_the_restart_survival_behavior() {
        let (mp, _, signer) = build_marketplace_allowing_unknown_quotes();
        let redeem = build_redeem("01JQFABRICATEDQUOTEID000000".to_string(), &signer);
        mp.redeem(redeem)
            .await
            .expect("the opt-out honors a quote_id this process does not hold");
    }

    /// Re-sign a redeem after mutating it, so the buyer signature still
    /// covers the body under test. Without this every mutation above
    /// would be refused as `SignatureInvalid` and prove nothing about
    /// the check it is aimed at.
    fn resign(request: &mut CompRedeemRequest, signer: &SigningKey) {
        request.buyer_signature.value = String::new();
        let signing_input = canonical_redeem_signing_input(request).unwrap();
        let sig = signer.sign(&signing_input);
        request.buyer_signature.value = B64URL.encode(sig.to_bytes());
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
                redeemed: false,
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
                redeemed: false,
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
    async fn redeem_allows_quote_unknown_to_this_process_when_opted_in() {
        // A quote_id the in-process ledger never saw (minted before a
        // restart, say) falls through to the other redeem checks
        // rather than failing closed on missing bookkeeping. That was
        // the unconditional behavior until WOR-2673 wired this bridge
        // into the proxy, where an onboarded buyer key plus a
        // fabricated id minted a token per call with no quote behind
        // it. It is now what `allow_unknown_quotes` buys, and the
        // property it protects (a buyer holding a real quote across a
        // restart is not refused) is unchanged where it is on.
        let (mp, _, signer) = build_marketplace_allowing_unknown_quotes();
        let redeem = build_redeem("01JUNKNOWNQUOTEID000000000".into(), &signer);
        let res = mp.redeem(redeem).await.unwrap();
        assert_eq!(res.token_type, "Bearer");
    }

    /// The parser the acceptance window depends on, at its edges. A
    /// lenient parser here would quietly widen every refusal above.
    #[test]
    fn the_rfc3339_parser_reads_exactly_what_it_claims_to() {
        assert_eq!(parse_rfc3339_to_unix("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339_to_unix("2026-05-02T14:35:00Z"),
            Some(1_777_732_500)
        );
        // Offsets move the instant, they do not decorate it.
        assert_eq!(
            parse_rfc3339_to_unix("2026-05-02T16:35:00+02:00"),
            Some(1_777_732_500)
        );
        assert_eq!(
            parse_rfc3339_to_unix("2026-05-02T12:35:00-02:00"),
            Some(1_777_732_500)
        );
        // Fractional seconds are accepted and truncated.
        assert_eq!(
            parse_rfc3339_to_unix("2026-05-02T14:35:00.250Z"),
            Some(1_777_732_500)
        );
        // A lowercase separator and a lowercase zone, both RFC 3339 5.6.
        assert_eq!(
            parse_rfc3339_to_unix("2026-05-02t14:35:00z"),
            Some(1_777_732_500)
        );
        for bad in [
            "",
            "2026-05-02",
            "2026-05-02T14:35Z",
            "2026-13-02T14:35:00Z",
            "2026-02-30T14:35:00Z",
            "2026-05-02T24:00:00Z",
            "2026-05-02T14:35:00",
            "2026-05-02T14:35:00+0200",
            "2026-05-02T14:35:00.Z",
            "not a timestamp at all",
            "1969-12-31T23:59:59Z",
        ] {
            assert_eq!(parse_rfc3339_to_unix(bad), None, "'{bad}' must not parse");
        }
    }

    /// A minted token is a bearer credential. Its `Debug` must not
    /// carry it, or a `dbg!`, a panic message, or a `?response` in a
    /// tracing macro hands it to every reader of the log.
    #[tokio::test]
    async fn a_minted_response_does_not_print_its_token() {
        let (mp, _, signer) = build_marketplace();
        let quote = mp.quote(quote_request()).unwrap();
        let redeem = build_redeem_for(&quote, &signer);
        let response = mp.redeem(redeem).await.unwrap();
        let rendered = format!("{response:?}");
        assert!(
            !rendered.contains(&response.license_token),
            "the token must not appear in Debug output: {rendered}"
        );
        assert!(rendered.contains("[REDACTED]"), "{rendered}");
        // The fields an operator reconciles against are still there.
        assert!(rendered.contains(&response.agent_id), "{rendered}");
        assert!(rendered.contains(&response.license), "{rendered}");
    }
}

//! Signing a payment requirement into the existing quote JWS.
//!
//! The billing crate never sees key material. It hands a finalized
//! requirement to a [`RequirementSigner`] and gets back an opaque token, and
//! this is the implementation that turns that into the quote JWS the crawl
//! policy already issues. One signing key, one token format, one JWKS
//! endpoint, whether or not settlement is enabled.
//!
//! # What the signature is over
//!
//! The token binds three identifiers a payer cannot forge apart: the
//! requirement id, the digest of the immutable draft, and the digest of the
//! complete final requirement. The last of those covers the provider handle,
//! so a Stripe PaymentIntent id or a Lightning payment hash is inside the
//! signature rather than beside it.
//!
//! Both digests are carried because direct Stripe mode has to commit before
//! its PaymentIntent exists: an identifier cannot be part of its own create
//! request. That mode's metadata binds the draft digest, and the final quote
//! binds the draft digest and the returned identifier together, so the two
//! halves can be checked against each other later.
//!
//! # Verification does not consume
//!
//! [`Self::verify`] authenticates and checks bindings. It never touches the
//! nonce store. Single use belongs to the durable intent and proof
//! transaction, which is the only place that can tell a replay apart from a
//! resumed retry, and burning the quote during signature parsing would leave
//! an interrupted payment unresumable: the payer would hold a settled charge
//! and a quote this proxy would no longer read.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use sbproxy_billing::error::BillingError;
use sbproxy_billing::service::RequirementSigner;
use sbproxy_billing::types::{
    AdvertisedRail, PaymentRequirement, RequirementTerms, SignedPaymentRequirement,
};
use sbproxy_modules::policy::ai_crawl::Money;
use sbproxy_modules::policy::quote_token::{QuoteClaims, QuoteTokenSigner, QuoteTokenVerifier};

/// The `shape` claim a settlement quote carries.
///
/// Settlement quotes are not content-shape negotiated, and this value is not
/// a shape any negotiation can produce. That is deliberate: it means a
/// settlement quote can never satisfy the legacy
/// [`QuoteTokenVerifier::verify`] path, which matches `shape` exactly and
/// consumes the nonce. A token minted for a payment cannot be spent as a
/// token minted for a free content negotiation.
const SETTLEMENT_SHAPE: &str = "payment-requirement";

/// The audience every quote carries.
const QUOTE_AUDIENCE: &str = "ledger";

/// Signs and verifies payment requirements as quote JWS tokens.
pub struct QuoteRequirementSigner {
    signer: QuoteTokenSigner,
    verifier: QuoteTokenVerifier,
}

impl QuoteRequirementSigner {
    /// Builds a signer over one key pair and its verifier.
    #[must_use]
    pub const fn new(signer: QuoteTokenSigner, verifier: QuoteTokenVerifier) -> Self {
        Self { signer, verifier }
    }

    /// The JWKS the admin surface publishes for these tokens.
    #[must_use]
    pub fn jwks_json(&self) -> serde_json::Value {
        self.verifier.jwks_json()
    }
}

impl std::fmt::Debug for QuoteRequirementSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QuoteRequirementSigner")
            .field("issuer", &self.signer.issuer())
            .field("key_id", &self.signer.key_id())
            .finish()
    }
}

impl RequirementSigner for QuoteRequirementSigner {
    fn sign(
        &self,
        requirement: &PaymentRequirement,
        requirement_digest: &[u8; 32],
    ) -> Result<String, BillingError> {
        let draft = &requirement.draft;
        let draft_digest = draft.digest()?;

        let claims = QuoteClaims {
            iss: self.signer.issuer().to_string(),
            // The tenant is who owes the money. The crawl policy's agent
            // identity describes who is asking, which is a different
            // question and one that cannot be authenticated at settlement
            // time from durable state alone.
            sub: draft.tenant_id.clone(),
            aud: QUOTE_AUDIENCE.to_string(),
            iat: unix_seconds_now(),
            // Milliseconds to seconds, rounding down, so the token never
            // outlives the challenge it prices.
            exp: u64::try_from(draft.expires_at_ms.max(0) / 1_000).unwrap_or(0),
            // One requirement, one nonce. The durable intent enforces that a
            // nonce binds to exactly one requirement and proof digest, so
            // deriving it from the requirement id rather than minting a
            // fresh ULID means re-signing the same requirement cannot
            // produce a second spendable quote.
            nonce: draft.requirement_id.clone(),
            quote_id: draft.quote_id.clone(),
            route: draft.route.clone(),
            shape: SETTLEMENT_SHAPE.to_string(),
            price: Money {
                amount_micros: draft.amount.amount_micros,
                currency: draft.amount.currency.clone(),
            },
            rail: advertised_name(draft.advertised_rail).to_string(),
            facilitator: facilitator_url(&draft.terms),
            requirement_id: Some(draft.requirement_id.clone()),
            draft_digest: Some(URL_SAFE_NO_PAD.encode(draft_digest)),
            requirement_digest: Some(URL_SAFE_NO_PAD.encode(requirement_digest)),
        };

        self.signer
            .sign(&claims)
            // The signing failure is dropped rather than wrapped: it can
            // name the key, and this text reaches an operator's logs.
            .map_err(|_| BillingError::Storage("quote token could not be signed"))
    }

    fn verify(&self, signed: &SignedPaymentRequirement) -> Result<(), BillingError> {
        let claims = self
            .verifier
            .verify_authenticity(&signed.quote_token)
            .map_err(|_| BillingError::InvalidProof)?;

        let draft = &signed.requirement.draft;
        let draft_digest = draft.digest()?;

        // Every check is exact equality against durable state. A claim that
        // is merely present is not a claim that matches.
        let bindings_hold = claims.requirement_id.as_deref() == Some(draft.requirement_id.as_str())
            && claims.draft_digest.as_deref()
                == Some(URL_SAFE_NO_PAD.encode(draft_digest).as_str())
            && claims.requirement_digest.as_deref()
                == Some(URL_SAFE_NO_PAD.encode(signed.requirement_digest).as_str())
            && claims.quote_id == draft.quote_id
            && claims.route == draft.route
            && claims.shape == SETTLEMENT_SHAPE
            && claims.aud == QUOTE_AUDIENCE
            && claims.nonce == draft.requirement_id
            && claims.rail == advertised_name(draft.advertised_rail)
            && claims.price.amount_micros == draft.amount.amount_micros
            && claims
                .price
                .currency
                .eq_ignore_ascii_case(&draft.amount.currency)
            && claims.facilitator == facilitator_url(&draft.terms);

        if bindings_hold {
            Ok(())
        } else {
            Err(BillingError::RequirementMismatch)
        }
    }
}

/// The facilitator a requirement's terms select, for rails that have one.
///
/// Projected into the quote so the legacy claim keeps meaning what it meant,
/// and checked on the way back so a payer cannot present a quote for one
/// facilitator against a requirement naming another.
fn facilitator_url(terms: &RequirementTerms) -> Option<String> {
    match terms {
        RequirementTerms::X402Exact {
            facilitator_url, ..
        } => Some(facilitator_url.clone()),
        _ => None,
    }
}

/// The wire name of an advertised rail.
const fn advertised_name(rail: AdvertisedRail) -> &'static str {
    match rail {
        AdvertisedRail::X402 => "x402",
        AdvertisedRail::Mpp => "mpp",
        AdvertisedRail::Stripe => "stripe",
        AdvertisedRail::Lightning => "lightning",
    }
}

/// Wall clock in unix seconds.
fn unix_seconds_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use sbproxy_billing::types::{
        PaymentProtocol, PaymentRequirementDraft, SettlementRail, SignedPaymentRequirement,
    };
    use sbproxy_billing::Money as BillingMoney;
    use sbproxy_modules::policy::quote_token::{InMemoryNonceStore, NonceStore};

    use super::*;

    /// A fixed seed, so a failure is reproducible.
    const SEED: [u8; 32] = [7_u8; 32];

    fn signer() -> QuoteRequirementSigner {
        let quote_signer = QuoteTokenSigner::from_seed_bytes(
            &SEED,
            "kid-test",
            "https://proxy.example",
            Duration::from_secs(600),
        );
        let verifying = quote_signer.verifying_key();
        let store = Arc::new(InMemoryNonceStore::new()) as Arc<dyn NonceStore>;
        let verifier = QuoteTokenVerifier::single_key("kid-test", verifying, store);
        QuoteRequirementSigner::new(quote_signer, verifier)
    }

    fn draft() -> PaymentRequirementDraft {
        let expires = i64::try_from(unix_seconds_now()).expect("clock fits") * 1_000 + 300_000;
        let mut draft = PaymentRequirementDraft {
            requirement_id: "req-0123456789abcdef".to_string(),
            protocol: PaymentProtocol::X402V2,
            advertised_rail: AdvertisedRail::X402,
            settlement_rail: SettlementRail::X402,
            method: "exact".to_string(),
            intent: "exact".to_string(),
            network: Some("eip155:84532".to_string()),
            asset: Some("0x036CbD53842c5426634e7929541eC2318f3dCF7e".to_string()),
            pay_to: Some("0x1111111111111111111111111111111111111111".to_string()),
            amount: BillingMoney {
                amount_micros: 10_000,
                currency: "USD".to_string(),
            },
            settlement_amount: "10000".to_string(),
            settlement_decimals: 6,
            terms: RequirementTerms::X402Exact {
                facilitator_url: "https://facilitator.example/api".to_string(),
                max_timeout_seconds: 60,
                extra: std::collections::BTreeMap::new(),
            },
            quote_id: "quote-1".to_string(),
            tenant_id: "tenant-1".to_string(),
            origin_id: "origin-1".to_string(),
            route: "/paid".to_string(),
            expires_at_ms: expires,
            request_digest: None,
        };
        draft.canonicalize().expect("draft canonicalizes");
        draft
    }

    fn sign_requirement(signer: &QuoteRequirementSigner) -> SignedPaymentRequirement {
        let draft = draft();
        let draft_digest = draft.digest().expect("draft digest");
        let requirement = PaymentRequirement {
            draft,
            provider_handle: None,
        };
        let requirement_digest = requirement.digest().expect("requirement digest");
        let quote_token = signer
            .sign(&requirement, &requirement_digest)
            .expect("sign requirement");
        SignedPaymentRequirement {
            requirement,
            draft_digest,
            requirement_digest,
            quote_token,
        }
    }

    #[test]
    fn a_signed_requirement_verifies_against_itself() {
        let signer = signer();
        let signed = sign_requirement(&signer);
        signer.verify(&signed).expect("the signature binds");
    }

    /// Verification is a read, so the same quote answers the same way twice.
    ///
    /// This is the property the settlement path depends on: a paid retry is
    /// parsed before the store has decided whether it is a first redemption
    /// or a resumption, and a verify that consumed the nonce would make the
    /// second read fail and strand a payment that already settled.
    #[test]
    fn verifying_twice_succeeds_twice() {
        let signer = signer();
        let signed = sign_requirement(&signer);
        signer.verify(&signed).expect("first read");
        signer.verify(&signed).expect("second read");
    }

    #[test]
    fn a_changed_requirement_digest_is_refused() {
        let signer = signer();
        let mut signed = sign_requirement(&signer);
        signed.requirement_digest[0] ^= 0xff;
        assert!(
            matches!(
                signer.verify(&signed),
                Err(BillingError::RequirementMismatch)
            ),
            "a digest the token does not sign must not verify",
        );
    }

    #[test]
    fn a_changed_amount_is_refused() {
        let signer = signer();
        let mut signed = sign_requirement(&signer);
        // The token still signs the original digest, but the requirement
        // now claims a different price. Re-deriving the digest is not
        // enough either, because the token's own digest claim would then
        // disagree.
        signed.requirement.draft.amount.amount_micros = 1;
        assert!(
            matches!(
                signer.verify(&signed),
                Err(BillingError::RequirementMismatch)
            ),
            "a price the token does not sign must not verify",
        );
    }

    #[test]
    fn a_changed_facilitator_is_refused() {
        let signer = signer();
        let mut signed = sign_requirement(&signer);
        signed.requirement.draft.terms = RequirementTerms::X402Exact {
            facilitator_url: "https://attacker.example/api".to_string(),
            max_timeout_seconds: 60,
            extra: std::collections::BTreeMap::new(),
        };
        assert!(
            matches!(
                signer.verify(&signed),
                Err(BillingError::RequirementMismatch)
            ),
            "a payer must not redirect settlement to another facilitator",
        );
    }

    /// A settlement quote cannot be spent on the free content path.
    #[test]
    fn a_settlement_quote_is_not_a_content_quote() {
        let signer = signer();
        let signed = sign_requirement(&signer);
        let claims = signer
            .verifier
            .verify_authenticity(&signed.quote_token)
            .expect("authentic");
        assert_eq!(claims.shape, SETTLEMENT_SHAPE);
        assert_ne!(claims.shape, "html");
        assert_ne!(claims.shape, "markdown");
    }
}

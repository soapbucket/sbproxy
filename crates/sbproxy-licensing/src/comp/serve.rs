//! Transport-neutral CoMP endpoint bodies (WOR-2673).
//!
//! Every CoMP response, its status, its headers, its
//! [`crate::metrics`] counter, and its decision-event log line come
//! from exactly one place: the three functions here. Two surfaces call
//! them. [`super::router`] wraps them for a host that mounts this
//! crate's axum router, and the sbproxy request path wraps them for a
//! host that serves the same URLs off Pingora, where no axum router is
//! ever mounted.
//!
//! One body rather than two, because the alternative already went
//! wrong once in this workspace. The OpenID Federation well-known
//! endpoint was hand-rolled a second time in the proxy's request path,
//! and the result was every `sbproxy_federation_*` family reading flat
//! on the only binary that shipped the crate, plus a missing
//! `Cache-Control` header that no peer could see was missing. A
//! response type the caller only has to write out keeps that from
//! being possible here: a transport that forgets a header fails to
//! compile, not silently in production.

use super::marketplace::CompMarketplace;
use super::types::{
    CompQuoteRequest, CompRedeemRequest, COMP_MANIFEST_CACHE_CONTROL, COMP_MANIFEST_CONTENT_TYPE,
    COMP_NO_STORE_CACHE_CONTROL, COMP_QUOTE_CONTENT_TYPE, COMP_VERSION,
};
use crate::error::LicensingError;
use crate::metrics;

/// A rendered CoMP response, ready for any transport to write out.
#[derive(Debug, Clone)]
pub struct CompResponse {
    /// HTTP status code.
    pub status: u16,
    /// `Content-Type` value.
    pub content_type: &'static str,
    /// `Cache-Control` value. Never absent: a quote and a redeem are
    /// both `no-store`, and a manifest carries a real max-age, so a
    /// caller that had to remember to set it would eventually not.
    pub cache_control: &'static str,
    /// Protocol version header value, when the endpoint advertises
    /// one. Only the manifest does.
    pub comp_version: Option<&'static str>,
    /// Response body.
    pub body: Vec<u8>,
}

impl CompResponse {
    /// The `{"error": "<code>"}` body every refusal answers with.
    fn error(status: u16, code: &'static str) -> Self {
        Self {
            status,
            content_type: "application/json",
            cache_control: COMP_NO_STORE_CACHE_CONTROL,
            comp_version: None,
            body: serde_json::json!({ "error": code })
                .to_string()
                .into_bytes(),
        }
    }
}

/// Make a caller-supplied string safe to put in a log line.
///
/// `tier_id`, `quote_id`, and the error text derived from them come
/// out of a POST body on an unauthenticated endpoint. A newline in one
/// of them forges a whole log line in any collector that reads
/// newline-delimited records, which is how a fabricated "quoted"
/// decision gets into an audit trail. Control characters go, and the
/// value is capped so one request cannot write a megabyte into the log.
///
/// This is a deliberate duplicate of `sbproxy_observe::log_safe`, which
/// is what the federation peer-trust decision calls for the same
/// reason. This crate depends on `sbproxy-storage` and nothing else in
/// the workspace, so pulling in `sbproxy-observe` for ten lines would
/// be the larger mistake. If a third caller appears, move this to a
/// crate all three already depend on rather than adding a fourth copy.
/// The two implementations are kept byte-identical on purpose.
pub(crate) fn log_safe(value: &str) -> String {
    const MAX: usize = 200;
    let mut out: String = value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX)
        .collect();
    if value.chars().count() > MAX {
        out.push_str("...");
    }
    out
}

/// `GET /.well-known/iab-comp/manifest.json`.
pub fn serve_manifest(marketplace: &CompMarketplace) -> CompResponse {
    match serde_json::to_vec(&*marketplace.manifest()) {
        Ok(body) => {
            metrics::record_manifest_serve("ok");
            CompResponse {
                status: 200,
                content_type: COMP_MANIFEST_CONTENT_TYPE,
                cache_control: COMP_MANIFEST_CACHE_CONTROL,
                comp_version: Some(COMP_VERSION),
                body,
            }
        }
        Err(error) => {
            tracing::warn!(error = %error, "comp.manifest.encode_failed");
            metrics::record_manifest_serve("error");
            CompResponse::error(500, "encode_failed")
        }
    }
}

/// `POST /.well-known/iab-comp/quote`, from the raw request body.
///
/// A body that does not parse is a refusal counted under the same
/// `rejected` label as a tier that does not exist: from the operator's
/// side both are "a buyer asked for a quote and did not get one", and
/// the decision-event line carries which.
pub fn serve_quote(marketplace: &CompMarketplace, body: &[u8]) -> CompResponse {
    let request: CompQuoteRequest = match serde_json::from_slice(body) {
        Ok(request) => request,
        Err(error) => {
            tracing::info!(
                event = "comp_quote_decision",
                outcome = "rejected",
                reason = %log_safe(&error.to_string()),
                "comp.quote.rejected"
            );
            metrics::record_quote("rejected");
            return CompResponse::error(400, "malformed");
        }
    };
    let tier_id = request.tier_id.clone();
    match marketplace.quote(request) {
        Ok(response) => {
            tracing::info!(
                event = "comp_quote_decision",
                outcome = "quoted",
                tier_id = %log_safe(&tier_id),
                quote_id = %log_safe(&response.quote_id),
                amount_micros = response.pricing.amount_micros,
                "comp.quote.issued"
            );
            metrics::record_quote("ok");
            match serde_json::to_vec(&response) {
                Ok(body) => CompResponse {
                    status: 200,
                    content_type: COMP_QUOTE_CONTENT_TYPE,
                    cache_control: COMP_NO_STORE_CACHE_CONTROL,
                    comp_version: None,
                    body,
                },
                Err(error) => {
                    tracing::warn!(error = %error, "comp.quote.encode_failed");
                    CompResponse::error(500, "encode_failed")
                }
            }
        }
        Err(error) => {
            tracing::info!(
                event = "comp_quote_decision",
                outcome = "rejected",
                tier_id = %log_safe(&tier_id),
                reason = %log_safe(&error.to_string()),
                "comp.quote.rejected"
            );
            metrics::record_quote("rejected");
            map_error(error)
        }
    }
}

/// `POST /.well-known/iab-comp/redeem`, from the raw request body.
pub async fn serve_redeem(marketplace: &CompMarketplace, body: &[u8]) -> CompResponse {
    let request: CompRedeemRequest = match serde_json::from_slice(body) {
        Ok(request) => request,
        Err(error) => {
            tracing::info!(
                event = "comp_redeem_decision",
                outcome = "rejected",
                reason = %log_safe(&error.to_string()),
                "comp.redeem.rejected"
            );
            metrics::record_redeem("rejected");
            return CompResponse::error(400, "malformed");
        }
    };
    let quote_id = request.quote_id.clone();
    match marketplace.redeem(request).await {
        Ok(response) => {
            // `license_token` is deliberately absent. It is a bearer
            // credential: a log line carrying it hands every reader of
            // the log the licensed access it grants, for its whole TTL.
            // The `license` URN, the `quote_id`, and the derived
            // `agent_id` are what an operator reconciles revenue
            // against, and none of them authorizes anything.
            tracing::info!(
                event = "comp_redeem_decision",
                outcome = "minted",
                quote_id = %log_safe(&quote_id),
                license = %response.license,
                agent_id = %response.agent_id,
                "comp.redeem.minted"
            );
            metrics::record_redeem("ok");
            match serde_json::to_vec(&response) {
                Ok(body) => CompResponse {
                    status: 200,
                    content_type: "application/json",
                    cache_control: COMP_NO_STORE_CACHE_CONTROL,
                    comp_version: None,
                    body,
                },
                Err(error) => {
                    tracing::warn!(error = %error, "comp.redeem.encode_failed");
                    CompResponse::error(500, "encode_failed")
                }
            }
        }
        Err(error) => {
            tracing::info!(
                event = "comp_redeem_decision",
                outcome = "rejected",
                quote_id = %log_safe(&quote_id),
                reason = %log_safe(&error.to_string()),
                "comp.redeem.rejected"
            );
            metrics::record_redeem("rejected");
            map_error(error)
        }
    }
}

/// Map a [`LicensingError`] onto its HTTP status and stable error code.
fn map_error(error: LicensingError) -> CompResponse {
    let (status, code) = match &error {
        LicensingError::Malformed(_) => (400, "malformed"),
        LicensingError::UnsupportedAlg(_) => (400, "unsupported_alg"),
        LicensingError::UnsupportedType(_) => (400, "unsupported_type"),
        LicensingError::SignatureInvalid => (401, "signature_invalid"),
        LicensingError::UnknownKey(_) => (401, "unknown_key"),
        LicensingError::Expired { .. } => (403, "expired"),
        LicensingError::Revoked(_) => (403, "revoked"),
        LicensingError::UnknownQuote(_) => (403, "unknown_quote"),
        LicensingError::RevocationBackend(_) => (500, "revocation_backend"),
        LicensingError::UnknownTier(_) => (404, "unknown_tier"),
        LicensingError::Encode(_) => (500, "encode_error"),
    };
    tracing::warn!(
        error = %log_safe(&error.to_string()),
        code = %code,
        status = %status,
        "comp.error"
    );
    CompResponse::error(status, code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comp::marketplace::InMemoryBuyerKeyRegistry;
    use crate::comp::olp_bridge::OlpBridgeSigner;
    use crate::comp::types::{CompEndpoints, CompManifest, CompPublisher};
    use crate::keys::{KeyManager, MasterKey};
    use crate::revocation::{InMemoryRevocation, Revocation};
    use std::sync::Arc;

    fn marketplace() -> CompMarketplace {
        let keys = KeyManager::new(MasterKey::new(vec![0x31u8; 32]).expect("32-byte key"));
        keys.set_active("2026-q3-001").expect("derive");
        let manifest = Arc::new(CompManifest {
            comp_version: COMP_VERSION.into(),
            publisher: CompPublisher {
                name: "Example".into(),
                domain: "api.example.com".into(),
                contact: "licensing@example.com".into(),
                verified_at: None,
            },
            tiers: Vec::new(),
            endpoints: CompEndpoints {
                manifest: "https://api.example.com/.well-known/iab-comp/manifest.json".into(),
                quote: "https://api.example.com/.well-known/iab-comp/quote".into(),
                redeem: "https://api.example.com/.well-known/iab-comp/redeem".into(),
            },
            robots_url: "https://api.example.com/robots.txt".into(),
            llms_url: "https://api.example.com/llms.txt".into(),
            rsl_url: "https://api.example.com/licenses.xml".into(),
            generated_at: "2026-08-28T00:00:00Z".into(),
            manifest_hash: "sha256:placeholder".into(),
        });
        let revocation: Arc<dyn Revocation> = Arc::new(InMemoryRevocation::new());
        let bridge = Arc::new(OlpBridgeSigner::new(
            [0x32u8; 32],
            "olp-2026-q3-001",
            "https://api.example.com",
            "ai-input",
            3600,
        ));
        CompMarketplace::new(
            keys,
            manifest,
            revocation,
            bridge,
            Arc::new(InMemoryBuyerKeyRegistry::new()),
        )
    }

    /// The manifest response carries the headers a buyer's cache and
    /// version negotiation need, from the one body that writes them.
    #[test]
    fn the_manifest_carries_its_cache_control_and_version() {
        let response = serve_manifest(&marketplace());
        assert_eq!(response.status, 200);
        assert_eq!(response.content_type, COMP_MANIFEST_CONTENT_TYPE);
        assert_eq!(response.cache_control, COMP_MANIFEST_CACHE_CONTROL);
        assert_eq!(response.comp_version, Some(COMP_VERSION));
    }

    /// A body that is not JSON is a 400 with the same shape every other
    /// refusal has, not a panic and not a 500.
    #[test]
    fn a_body_that_is_not_json_is_a_typed_refusal() {
        let response = serve_quote(&marketplace(), b"{not json");
        assert_eq!(response.status, 400);
        let body: serde_json::Value =
            serde_json::from_slice(&response.body).expect("the refusal body is JSON");
        assert_eq!(body["error"], "malformed");
        assert_eq!(response.cache_control, COMP_NO_STORE_CACHE_CONTROL);
    }

    /// A quote for a tier this publisher does not sell is a 404 with a
    /// typed code, not a 500 from a message-text match.
    #[test]
    fn an_unknown_tier_is_a_typed_404() {
        let body = serde_json::json!({
            "comp_version": COMP_VERSION,
            "buyer": { "agent_id": "agent_a", "organization": "A" },
            "tier_id": "tier_that_does_not_exist",
            "requested_volume": {
                "model": "per_request", "expected_count": 1, "duration_days": 1
            },
            "audience": "api.example.com",
        })
        .to_string();
        let response = serve_quote(&marketplace(), body.as_bytes());
        assert_eq!(response.status, 404);
        let parsed: serde_json::Value =
            serde_json::from_slice(&response.body).expect("the refusal body is JSON");
        assert_eq!(parsed["error"], "unknown_tier");
    }

    /// Log-forging defense, on the field that reaches `tracing` from an
    /// unauthenticated POST body.
    #[test]
    fn a_newline_in_a_buyer_supplied_field_cannot_forge_a_log_line() {
        let forged = log_safe("tier\ninfo comp_quote_decision outcome=quoted");
        assert!(!forged.contains('\n'), "{forged}");
        assert_eq!(log_safe(&"x".repeat(500)).chars().count(), 203);
    }
}

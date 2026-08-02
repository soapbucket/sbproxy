//! Request-context adapter for the module-owned trust-tier combiner.
//!
//! The pure combiner lives in `sbproxy-modules`. This adapter translates
//! the typed request evidence already collected by the proxy into its
//! compact signal bag and records the resulting closed metric label.

use crate::context::{HeadlessSignal, RequestContext};

/// Minimum confidence at which an advisory detector may contribute
/// load-bearing trust evidence. Trusted catalogue hits are at least 0.85;
/// untrustworthy proxy/CDN observations are capped at 0.5.
const LOAD_BEARING_CONFIDENCE: f32 = 0.8;

/// Derive the request's conservative trust tier from available evidence.
///
/// `deny_observed` is supplied by the authentication call site because a
/// denied result returns before it can be stored as `ctx.auth_result`.
pub(crate) fn derive(
    ctx: &RequestContext,
    deny_observed: bool,
) -> sbproxy_modules::auth::TrustTier {
    derive_with_bot_auth(ctx, deny_observed, true)
}

fn derive_with_bot_auth(
    ctx: &RequestContext,
    deny_observed: bool,
    include_bot_auth: bool,
) -> sbproxy_modules::auth::TrustTier {
    let detection = ctx.agent_detection.as_ref();
    let named_agent = detection.and_then(|d| {
        (d.provenance != sbproxy_agent_detect::AgentProvenance::UnsignedAnonymous
            && d.confidence >= LOAD_BEARING_CONFIDENCE)
            .then_some(d.agent_id.as_deref())
            .flatten()
    });
    let agent_score = detection.map_or(0, |d| d.score);
    let credential_signed = matches!(ctx.principal.source, sbproxy_plugin::PrincipalSource::Cap)
        || (include_bot_auth
            && matches!(
                ctx.principal.source,
                sbproxy_plugin::PrincipalSource::BotAuth
            ));
    let trustworthy_tls = ctx
        .tls_fingerprint
        .as_ref()
        .is_some_and(|fingerprint| fingerprint.trustworthy);
    let headless_deny = trustworthy_tls
        && matches!(
            ctx.headless_signal,
            Some(HeadlessSignal::Detected { confidence, .. })
                if confidence >= LOAD_BEARING_CONFIDENCE
        );

    #[cfg(feature = "agent-class")]
    let identity_deny = matches!(ctx.kya_verdict, Some("expired" | "revoked" | "invalid"));
    #[cfg(not(feature = "agent-class"))]
    let identity_deny = false;

    #[cfg(feature = "agent-class")]
    let identity_signed = ctx.kya_verdict == Some("verified");
    #[cfg(not(feature = "agent-class"))]
    let identity_signed = false;

    sbproxy_modules::auth::compute_trust_tier(&sbproxy_modules::auth::TrustSignals {
        // The rule-pack scorer is driven by attacker-controlled HTTP/TLS
        // observations. Its `provenance` label may name traffic, but only
        // verifier-backed principal/KYA evidence can grant Strong.
        signed: credential_signed || identity_signed,
        named_agent,
        agent_score,
        deny_observed: deny_observed || identity_deny || headless_deny,
    })
}

/// Store and meter the request's derived tier.
pub(crate) fn finalize(ctx: &mut RequestContext, deny_observed: bool) {
    if ctx.trust_tier_metric_recorded {
        return;
    }
    let tier = derive(ctx, deny_observed);
    let body_proof_pending =
        ctx.bot_auth_digest_check_required && !ctx.content_digest_verified && !deny_observed;
    if body_proof_pending && tier == sbproxy_modules::auth::TrustTier::Strong {
        ctx.trust_tier = derive_with_bot_auth(ctx, false, false);
        return;
    }
    ctx.trust_tier = tier;
    sbproxy_observe::metrics::record_trust_tier(tier.as_str());
    ctx.trust_tier_metric_recorded = true;
}

/// Verify a body-bound Web Bot Auth proof and finalize the request's tier.
///
/// Header verification happens before the body is available, so a signature
/// that covers `content-digest` is provisional until this function sees the
/// complete pre-transform body. The final metric observation is emitted here,
/// once, for either the verified or failed proof.
pub(crate) fn verify_and_finalize_body_proof(
    ctx: &mut RequestContext,
    headers: &http::HeaderMap,
    body: &[u8],
) -> bool {
    if !ctx.bot_auth_digest_check_required {
        return true;
    }

    let header_value = headers
        .get("content-digest")
        .or_else(|| headers.get("repr-digest"))
        .and_then(|value| value.to_str().ok());
    let verified = header_value
        .is_some_and(|value| sbproxy_middleware::digest::verify_content_digest(value, body));
    if verified {
        ctx.content_digest_verified = true;
    }
    finalize(ctx, !verified);
    verified
}

/// Close a provisional body-bound proof when the request ends before the body
/// verifier runs.
///
/// This can happen on a policy or middleware short circuit. The unverified
/// BotAuth credential is removed from the evidence bag while independent KYA
/// or named-agent evidence is retained, then the conservative result is
/// recorded exactly once.
pub(crate) fn finalize_pending_body_proof_at_request_end(ctx: &mut RequestContext) {
    if ctx.trust_tier_metric_recorded
        || !ctx.bot_auth_digest_check_required
        || ctx.content_digest_verified
    {
        return;
    }

    let tier = derive_with_bot_auth(ctx, false, false);
    ctx.trust_tier = tier;
    sbproxy_observe::metrics::record_trust_tier(tier.as_str());
    ctx.trust_tier_metric_recorded = true;
}

#[cfg(test)]
mod tests {
    use super::*;

    static METRIC_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn detection(
        provenance: sbproxy_agent_detect::AgentProvenance,
        agent_id: Option<&str>,
        score: u8,
    ) -> sbproxy_agent_detect::AgentDetection {
        sbproxy_agent_detect::AgentDetection {
            score,
            agent_id: agent_id.map(str::to_string),
            provenance,
            confidence: 1.0,
            signals_used: Vec::new(),
            headless_score: 0,
            headless_indicators: Vec::new(),
        }
    }

    #[test]
    fn absent_signals_are_anonymous() {
        assert_eq!(
            derive(&RequestContext::new(), false),
            sbproxy_modules::auth::TrustTier::Anonymous
        );
    }

    #[test]
    fn verified_web_bot_auth_is_strong_not_named() {
        let mut ctx = RequestContext::new();
        ctx.principal.source = sbproxy_plugin::PrincipalSource::BotAuth;
        assert_eq!(
            derive(&ctx, false),
            sbproxy_modules::auth::TrustTier::Strong
        );
    }

    #[test]
    fn rule_pack_signed_label_cannot_grant_cryptographic_trust() {
        let mut ctx = RequestContext::new();
        ctx.agent_detection = Some(detection(
            sbproxy_agent_detect::AgentProvenance::Signed,
            Some("spoofable-rule"),
            100,
        ));

        assert_eq!(
            derive(&ctx, false),
            sbproxy_modules::auth::TrustTier::Named,
            "a UA/header/JA4 rule may name traffic but cannot prove a signature"
        );
    }

    #[test]
    fn unsigned_named_detection_uses_the_existing_score_threshold() {
        let mut ctx = RequestContext::new();
        ctx.agent_detection = Some(detection(
            sbproxy_agent_detect::AgentProvenance::UnsignedNamed,
            Some("claude-code"),
            sbproxy_modules::auth::NAMED_AGENT_SCORE_THRESHOLD,
        ));
        assert_eq!(derive(&ctx, false), sbproxy_modules::auth::TrustTier::Named);

        ctx.agent_detection.as_mut().unwrap().score =
            sbproxy_modules::auth::NAMED_AGENT_SCORE_THRESHOLD - 1;
        assert_eq!(
            derive(&ctx, false),
            sbproxy_modules::auth::TrustTier::Anonymous
        );
    }

    #[test]
    fn low_confidence_named_detection_remains_anonymous() {
        let mut ctx = RequestContext::new();
        let mut low_confidence = detection(
            sbproxy_agent_detect::AgentProvenance::UnsignedNamed,
            Some("spoofable-rule"),
            100,
        );
        low_confidence.confidence = 0.4;
        ctx.agent_detection = Some(low_confidence);

        assert_eq!(
            derive(&ctx, false),
            sbproxy_modules::auth::TrustTier::Anonymous,
            "a high score with low classifier confidence is not verified named-agent evidence"
        );
    }

    #[test]
    fn explicit_deny_wins_over_a_verified_signature() {
        let mut ctx = RequestContext::new();
        ctx.principal.source = sbproxy_plugin::PrincipalSource::BotAuth;
        assert_eq!(
            derive(&ctx, true),
            sbproxy_modules::auth::TrustTier::Suspicious
        );
    }

    #[test]
    fn suspicious_headless_classification_is_suspicious() {
        let mut ctx = RequestContext::new();
        ctx.tls_fingerprint = Some(sbproxy_tls::TlsFingerprint {
            trustworthy: true,
            ..Default::default()
        });
        ctx.headless_signal = Some(HeadlessSignal::Detected {
            library: "playwright".to_string(),
            confidence: 0.99,
        });
        assert_eq!(
            derive(&ctx, false),
            sbproxy_modules::auth::TrustTier::Suspicious
        );
    }

    #[test]
    fn advisory_headless_classification_is_not_load_bearing() {
        let mut ctx = RequestContext::new();
        ctx.tls_fingerprint = Some(sbproxy_tls::TlsFingerprint {
            trustworthy: false,
            ..Default::default()
        });
        ctx.headless_signal = Some(HeadlessSignal::Detected {
            library: "playwright".to_string(),
            confidence: 0.475,
        });

        assert_eq!(
            derive(&ctx, false),
            sbproxy_modules::auth::TrustTier::Anonymous,
            "an untrustworthy CDN/sidecar fingerprint is advisory only"
        );
    }

    #[test]
    fn pending_body_proof_is_not_published_before_body_verification() {
        let mut ctx = RequestContext::new();
        ctx.principal.source = sbproxy_plugin::PrincipalSource::BotAuth;
        ctx.bot_auth_digest_check_required = true;

        finalize(&mut ctx, false);

        assert_eq!(
            ctx.trust_tier,
            sbproxy_modules::auth::TrustTier::Anonymous,
            "header verification alone must not publish Strong before the body digest verifies"
        );
    }

    #[test]
    fn pending_body_proof_records_only_the_final_failed_verdict() {
        let _guard = METRIC_TEST_LOCK.lock().unwrap();
        let mut ctx = RequestContext::new();
        ctx.principal.source = sbproxy_plugin::PrincipalSource::BotAuth;
        ctx.bot_auth_digest_check_required = true;
        let strong_before = sbproxy_observe::metrics::metrics()
            .trust_tier_requests
            .with_label_values(&["strong"])
            .get();
        let suspicious_before = sbproxy_observe::metrics::metrics()
            .trust_tier_requests
            .with_label_values(&["suspicious"])
            .get();

        finalize(&mut ctx, false);
        finalize(&mut ctx, true);

        assert_eq!(ctx.trust_tier, sbproxy_modules::auth::TrustTier::Suspicious);
        assert_eq!(
            sbproxy_observe::metrics::metrics()
                .trust_tier_requests
                .with_label_values(&["strong"])
                .get(),
            strong_before,
            "the provisional signature must not be metered as final"
        );
        assert_eq!(
            sbproxy_observe::metrics::metrics()
                .trust_tier_requests
                .with_label_values(&["suspicious"])
                .get(),
            suspicious_before + 1,
            "the final failed body proof is the one observation"
        );
    }

    #[test]
    fn completed_body_proof_records_strong_exactly_once() {
        let _guard = METRIC_TEST_LOCK.lock().unwrap();
        let mut ctx = RequestContext::new();
        ctx.principal.source = sbproxy_plugin::PrincipalSource::BotAuth;
        ctx.bot_auth_digest_check_required = true;
        let strong_before = sbproxy_observe::metrics::metrics()
            .trust_tier_requests
            .with_label_values(&["strong"])
            .get();

        finalize(&mut ctx, false);
        ctx.content_digest_verified = true;
        finalize(&mut ctx, false);
        finalize(&mut ctx, false);

        assert_eq!(ctx.trust_tier, sbproxy_modules::auth::TrustTier::Strong);
        assert_eq!(
            sbproxy_observe::metrics::metrics()
                .trust_tier_requests
                .with_label_values(&["strong"])
                .get(),
            strong_before + 1,
            "late success must emit one final observation"
        );
    }

    #[test]
    fn finalized_trust_tier_cannot_be_overwritten() {
        let _guard = METRIC_TEST_LOCK.lock().unwrap();
        let mut ctx = RequestContext::new();
        ctx.principal.source = sbproxy_plugin::PrincipalSource::BotAuth;

        finalize(&mut ctx, false);
        finalize(&mut ctx, true);

        assert_eq!(
            ctx.trust_tier,
            sbproxy_modules::auth::TrustTier::Strong,
            "a final tier must remain stable after its metric observation is emitted"
        );
    }

    #[test]
    fn unfinished_body_proof_falls_back_without_bot_auth_at_request_end() {
        let _guard = METRIC_TEST_LOCK.lock().unwrap();
        let mut ctx = RequestContext::new();
        ctx.principal.source = sbproxy_plugin::PrincipalSource::BotAuth;
        ctx.bot_auth_digest_check_required = true;
        ctx.agent_detection = Some(detection(
            sbproxy_agent_detect::AgentProvenance::UnsignedNamed,
            Some("named-rule"),
            sbproxy_modules::auth::NAMED_AGENT_SCORE_THRESHOLD,
        ));
        let strong_before = sbproxy_observe::metrics::metrics()
            .trust_tier_requests
            .with_label_values(&["strong"])
            .get();
        let named_before = sbproxy_observe::metrics::metrics()
            .trust_tier_requests
            .with_label_values(&["named"])
            .get();

        finalize(&mut ctx, false);
        finalize_pending_body_proof_at_request_end(&mut ctx);
        finalize_pending_body_proof_at_request_end(&mut ctx);

        assert_eq!(ctx.trust_tier, sbproxy_modules::auth::TrustTier::Named);
        assert_eq!(
            sbproxy_observe::metrics::metrics()
                .trust_tier_requests
                .with_label_values(&["strong"])
                .get(),
            strong_before,
            "an unverified body-bound signature must not survive request end"
        );
        assert_eq!(
            sbproxy_observe::metrics::metrics()
                .trust_tier_requests
                .with_label_values(&["named"])
                .get(),
            named_before + 1,
            "request-end fallback must record once"
        );
    }

    #[cfg(feature = "agent-class")]
    #[test]
    fn rejected_kya_is_suspicious_and_missing_kya_is_neutral() {
        let mut ctx = RequestContext::new();
        ctx.kya_verdict = Some("revoked");
        assert_eq!(
            derive(&ctx, false),
            sbproxy_modules::auth::TrustTier::Suspicious
        );

        ctx.kya_verdict = Some("missing");
        assert_eq!(
            derive(&ctx, false),
            sbproxy_modules::auth::TrustTier::Anonymous
        );
    }

    #[cfg(feature = "agent-class")]
    #[test]
    fn kya_directory_unavailable_is_not_caller_suspicion() {
        let mut ctx = RequestContext::new();
        ctx.kya_verdict = Some("directory_unavailable");

        assert_eq!(
            derive(&ctx, false),
            sbproxy_modules::auth::TrustTier::Anonymous,
            "a verifier-directory outage carries no adversarial caller evidence"
        );
    }
}

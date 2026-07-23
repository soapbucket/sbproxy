//! Request-context adapter for the module-owned trust-tier combiner.
//!
//! The pure combiner lives in `sbproxy-modules`. This adapter translates
//! the typed request evidence already collected by the proxy into its
//! compact signal bag and records the resulting closed metric label.

use crate::context::{HeadlessSignal, RequestContext};

/// Derive the request's conservative trust tier from available evidence.
///
/// `deny_observed` is supplied by the authentication call site because a
/// denied result returns before it can be stored as `ctx.auth_result`.
pub(crate) fn derive(
    ctx: &RequestContext,
    deny_observed: bool,
) -> sbproxy_modules::auth::TrustTier {
    let detection = ctx.agent_detection.as_ref();
    let detection_signed =
        detection.is_some_and(|d| d.provenance == sbproxy_agent_detect::AgentProvenance::Signed);
    let named_agent = detection.and_then(|d| {
        (d.provenance == sbproxy_agent_detect::AgentProvenance::UnsignedNamed)
            .then_some(d.agent_id.as_deref())
            .flatten()
    });
    let agent_score = detection.map_or(0, |d| d.score);
    let credential_signed = matches!(
        ctx.principal.source,
        sbproxy_plugin::PrincipalSource::BotAuth | sbproxy_plugin::PrincipalSource::Cap
    );
    let headless_deny = matches!(ctx.headless_signal, Some(HeadlessSignal::Detected { .. }));

    #[cfg(feature = "agent-class")]
    let identity_deny = matches!(
        ctx.kya_verdict,
        Some("expired" | "revoked" | "invalid" | "directory_unavailable")
    );
    #[cfg(not(feature = "agent-class"))]
    let identity_deny = false;

    #[cfg(feature = "agent-class")]
    let identity_signed = ctx.kya_verdict == Some("verified");
    #[cfg(not(feature = "agent-class"))]
    let identity_signed = false;

    sbproxy_modules::auth::compute_trust_tier(&sbproxy_modules::auth::TrustSignals {
        signed: credential_signed || identity_signed || detection_signed,
        named_agent,
        agent_score,
        deny_observed: deny_observed || identity_deny || headless_deny,
    })
}

/// Store and meter the request's derived tier.
pub(crate) fn finalize(ctx: &mut RequestContext, deny_observed: bool) {
    let tier = derive(ctx, deny_observed);
    ctx.trust_tier = tier;
    sbproxy_observe::metrics::record_trust_tier(tier.as_str());
}

#[cfg(test)]
mod tests {
    use super::*;

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
        ctx.headless_signal = Some(HeadlessSignal::Detected {
            library: "playwright".to_string(),
            confidence: 0.99,
        });
        assert_eq!(
            derive(&ctx, false),
            sbproxy_modules::auth::TrustTier::Suspicious
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
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Agent-class capture wired into the request pipeline.
//!
//! Companion to `sbproxy-modules::policy::agent_class`. The resolver
//! itself is pure; this module is the seam between the resolver and
//! [`crate::context::RequestContext`]. The binary owns the resolver
//! instance (catalog + DNS resolver + verdict cache); the request
//! pipeline calls `stamp_request_context` from `request_filter`
//! immediately after the trust-boundary header strip and the bot-auth
//! verifier (when configured).
//!
//! Feature-gated: when `agent-class` is off, the helpers compile to
//! no-ops and the context fields don't exist. The binary's default
//! feature set turns it on.

#![cfg(feature = "agent-class")]

use std::net::IpAddr;

use sbproxy_modules::policy::agent_class::{AgentClassResolver, ResolveInputs};

use crate::context::RequestContext;

/// Resolve the agent class and stamp every relevant field on `ctx`.
///
/// `bot_auth_keyid` is `Some(_)` only when the bot-auth provider has
/// already cryptographically verified the signature; the resolver
/// trusts the keyid implicitly (per the ADR's "highest confidence"
/// language for step 1).
///
/// `anonymous_bot_auth` should be `true` when a Web Bot Auth
/// signature was present and structurally valid but advertised a
/// `keyid` no catalog entry recognises.
pub fn stamp_request_context(
    ctx: &mut RequestContext,
    resolver: &AgentClassResolver,
    bot_auth_keyid: Option<&str>,
    anonymous_bot_auth: bool,
    client_ip: Option<IpAddr>,
    user_agent: Option<&str>,
) {
    let inputs = ResolveInputs {
        bot_auth_keyid,
        anonymous_bot_auth,
        client_ip,
        user_agent,
    };
    let resolved = resolver.resolve(&inputs);
    ctx.agent_id = Some(resolved.agent_id);
    ctx.agent_vendor = Some(resolved.vendor);
    ctx.agent_purpose = Some(resolved.purpose);
    ctx.agent_id_source = Some(resolved.source);
    ctx.agent_rdns_hostname = resolved.rdns_hostname;
}

/// Compute the CAP `sub`-binding target for this request (WOR-1149
/// follow-up).
///
/// The agent-class resolver always stamps *some* `agent_id`: when no
/// signal matches it falls through to the `human` sentinel with
/// [`sbproxy_classifiers::AgentIdSource::Fallback`]. Binding the CAP
/// token's `sub` against `ctx.agent_id` unconditionally would therefore
/// reject every CAP token whose `sub` is not literally `"human"`, even on
/// origins that never configured agent classes, because the resolver is
/// installed with the built-in catalog by default. The binding is only
/// meaningful when the resolver *genuinely* identified an agent, so the
/// fallback / `human` verdict yields `None` and the CAP verifier falls
/// through to its "no resolved agent -> skip" branch.
///
/// Compiled out unless the `agent-class` feature is enabled.
pub fn cap_binding_agent_id(ctx: &RequestContext) -> Option<&str> {
    use sbproxy_classifiers::{AgentId, AgentIdSource};
    if matches!(ctx.agent_id_source, Some(AgentIdSource::Fallback)) {
        return None;
    }
    let id = ctx.agent_id.as_ref()?.as_str();
    if id == AgentId::HUMAN {
        return None;
    }
    Some(id)
}

/// Apply the headless-detection override § "Worked example:
/// headless Puppeteer detection".
///
/// When the headless detector returned `HeadlessSignal::Detected` AND
/// the rule-based resolver chain fell through to its `Fallback`
/// verdict (i.e. no higher-confidence signal matched), overwrite
/// `ctx.agent_id` / `agent_vendor` / `agent_purpose` with the catalog
/// entry whose `id` matches `headless-{library}` (or the generic
/// `headless-browser` entry on lookup miss). The source stamp becomes
/// `AgentIdSource::TlsFingerprint`.
///
/// Any non-`Fallback` source survives untouched: bot-auth, KYA, rDNS,
/// and UA-regex matches outrank the headless detector.
///
/// `library` comes from the detector's verdict label (e.g.
/// `"puppeteer"`, `"playwright"`). The function returns `true` when
/// the override fires so callers can emit a metric / log line.
///
/// Compiled out unless the `agent-class` feature is enabled.
pub fn apply_headless_override(
    ctx: &mut RequestContext,
    library: &str,
    catalog: &sbproxy_classifiers::AgentClassCatalog,
) -> bool {
    use sbproxy_classifiers::{AgentId, AgentIdSource, AgentPurpose};
    if !matches!(ctx.agent_id_source, Some(AgentIdSource::Fallback)) {
        return false;
    }
    let candidate_id = format!("headless-{library}");
    let entry = catalog
        .get(&candidate_id)
        .or_else(|| catalog.get("headless-browser"));
    match entry {
        Some(e) => {
            ctx.agent_id = Some(AgentId(e.id.clone()));
            ctx.agent_vendor = Some(e.vendor.clone());
            ctx.agent_purpose = Some(e.purpose);
            ctx.agent_id_source = Some(AgentIdSource::TlsFingerprint);
        }
        None => {
            ctx.agent_id = Some(AgentId(candidate_id));
            ctx.agent_vendor = Some("Unknown".to_string());
            ctx.agent_purpose = Some(AgentPurpose::Unknown);
            ctx.agent_id_source = Some(AgentIdSource::TlsFingerprint);
        }
    }
    true
}

/// Apply the ML override.
///
/// When the ML classifier verdict is [`MlClass::Human`] at confidence
/// 0.9 or above, the rule-based resolver verdict is overwritten with
/// the `human` sentinel and the source stamp is changed to
/// [`AgentIdSource::MlOverride`]. Every other case is a no-op: the
/// rule-based verdict (bot-auth, KYA, rDNS, UA, fallback) stays
/// authoritative.
///
/// Logs at `info` whenever the override fires so operators can audit
/// false-positive 402 challenges that the ML classifier reverses.
///
/// Compiled out unless both the `agent-class` and `agent-classifier`
/// features are enabled.
#[cfg(feature = "agent-classifier")]
pub fn apply_ml_override(ctx: &mut RequestContext) {
    use sbproxy_classifiers::{AgentId, AgentIdSource, AgentPurpose, MlClass};

    let Some(verdict) = ctx.ml_classification.as_ref() else {
        return;
    };
    if !matches!(verdict.class, MlClass::Human) || verdict.confidence < 0.9 {
        return;
    }

    let prior_id = ctx
        .agent_id
        .as_ref()
        .map(|a| a.as_str().to_string())
        .unwrap_or_else(|| "<unset>".to_string());
    let prior_source = ctx.agent_id_source;

    ctx.agent_id = Some(AgentId::human());
    ctx.agent_vendor = Some("unknown".to_string());
    ctx.agent_purpose = Some(AgentPurpose::Unknown);
    ctx.agent_id_source = Some(AgentIdSource::MlOverride);
    ctx.agent_rdns_hostname = None;

    tracing::info!(
        ml_class = %verdict.class,
        ml_confidence = verdict.confidence,
        ml_model_version = verdict.model_version,
        prior_agent_id = %prior_id,
        ?prior_source,
        "ml classifier overrode agent_id with `human`",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_classifiers::{AgentClassCatalog, AgentIdSource};
    use sbproxy_security::agent_verify::StubResolver;
    use std::sync::Arc;

    fn build_resolver() -> AgentClassResolver {
        AgentClassResolver::new(
            Arc::new(AgentClassCatalog::defaults()),
            Arc::new(StubResolver::new()),
            16,
            true,
            true,
        )
    }

    #[test]
    fn stamps_human_for_browser_ua() {
        let mut ctx = RequestContext::new();
        let resolver = build_resolver();
        stamp_request_context(
            &mut ctx,
            &resolver,
            None,
            false,
            None,
            Some("Mozilla/5.0 Chrome/123.0"),
        );
        assert_eq!(ctx.agent_id.as_ref().unwrap().as_str(), "human");
        assert_eq!(ctx.agent_id_source, Some(AgentIdSource::Fallback));
    }

    #[test]
    fn stamps_known_bot_for_gptbot_ua() {
        let mut ctx = RequestContext::new();
        let resolver = build_resolver();
        stamp_request_context(
            &mut ctx,
            &resolver,
            None,
            false,
            None,
            Some("Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)"),
        );
        assert_eq!(ctx.agent_id.as_ref().unwrap().as_str(), "openai-gptbot");
        assert_eq!(ctx.agent_vendor.as_deref(), Some("OpenAI"));
        assert_eq!(ctx.agent_id_source, Some(AgentIdSource::UserAgent));
    }

    // --- WOR-1149 follow-up: CAP `sub`-binding target gating ---

    #[test]
    fn cap_binding_skips_fallback_human() {
        let mut ctx = RequestContext::new();
        let resolver = build_resolver();
        // Browser UA -> Fallback `human` verdict; not a resolved agent.
        stamp_request_context(
            &mut ctx,
            &resolver,
            None,
            false,
            None,
            Some("Mozilla/5.0 Chrome/123.0"),
        );
        assert_eq!(ctx.agent_id_source, Some(AgentIdSource::Fallback));
        assert_eq!(
            cap_binding_agent_id(&ctx),
            None,
            "a fallback/human verdict must not bind the CAP `sub`"
        );
    }

    #[test]
    fn cap_binding_uses_genuinely_resolved_agent() {
        let mut ctx = RequestContext::new();
        let resolver = build_resolver();
        // GPTBot UA -> UserAgent source with a real catalog id.
        stamp_request_context(
            &mut ctx,
            &resolver,
            None,
            false,
            None,
            Some("Mozilla/5.0 (compatible; GPTBot/1.0)"),
        );
        assert_eq!(cap_binding_agent_id(&ctx), Some("openai-gptbot"));
    }

    #[test]
    fn cap_binding_none_when_resolver_never_ran() {
        // No resolver stamped the context (feature on but no request
        // passed through the resolver yet).
        let ctx = RequestContext::new();
        assert_eq!(cap_binding_agent_id(&ctx), None);
    }

    // --- A5.1 headless-override tests ---

    fn build_catalog() -> sbproxy_classifiers::AgentClassCatalog {
        sbproxy_classifiers::AgentClassCatalog::defaults()
    }

    #[test]
    fn headless_override_fires_on_fallback_with_known_library() {
        let mut ctx = RequestContext::new();
        let resolver = build_resolver();
        // Generic browser UA -> Fallback `human` verdict.
        stamp_request_context(
            &mut ctx,
            &resolver,
            None,
            false,
            None,
            Some("Mozilla/5.0 Chrome/123.0"),
        );
        assert_eq!(ctx.agent_id_source, Some(AgentIdSource::Fallback));

        let catalog = build_catalog();
        let fired = apply_headless_override(&mut ctx, "puppeteer", &catalog);
        assert!(fired, "override must fire on Fallback + known library");
        assert_eq!(
            ctx.agent_id.as_ref().unwrap().as_str(),
            "headless-puppeteer"
        );
        assert_eq!(ctx.agent_id_source, Some(AgentIdSource::TlsFingerprint));
        assert_eq!(ctx.agent_vendor.as_deref(), Some("Puppeteer"));
    }

    #[test]
    fn headless_override_falls_back_to_generic_for_unknown_library() {
        let mut ctx = RequestContext::new();
        let resolver = build_resolver();
        stamp_request_context(
            &mut ctx,
            &resolver,
            None,
            false,
            None,
            Some("Mozilla/5.0 Firefox/120.0"),
        );
        let catalog = build_catalog();
        let fired = apply_headless_override(&mut ctx, "fictitious-bot", &catalog);
        assert!(fired);
        // No `headless-fictitious-bot` entry -> falls back to the
        // generic `headless-browser` entry.
        assert_eq!(ctx.agent_id.as_ref().unwrap().as_str(), "headless-browser");
        assert_eq!(ctx.agent_id_source, Some(AgentIdSource::TlsFingerprint));
    }

    #[test]
    fn headless_override_does_not_fire_when_chain_resolved_to_known_bot() {
        let mut ctx = RequestContext::new();
        let resolver = build_resolver();
        // GPTBot UA -> UserAgent source, not Fallback.
        stamp_request_context(
            &mut ctx,
            &resolver,
            None,
            false,
            None,
            Some("Mozilla/5.0 (compatible; GPTBot/1.0)"),
        );
        assert_eq!(ctx.agent_id_source, Some(AgentIdSource::UserAgent));
        let prior_id = ctx.agent_id.clone();

        let catalog = build_catalog();
        let fired = apply_headless_override(&mut ctx, "puppeteer", &catalog);
        assert!(
            !fired,
            "override must skip when chain produced a non-Fallback verdict"
        );
        assert_eq!(ctx.agent_id, prior_id);
        assert_eq!(ctx.agent_id_source, Some(AgentIdSource::UserAgent));
    }

    // --- A5.2 ML override tests ---

    #[cfg(feature = "agent-classifier")]
    mod ml_override_tests {
        use super::*;
        use sbproxy_classifiers::{MlClass, MlClassification};

        fn run_with_verdict(class: MlClass, confidence: f32) -> RequestContext {
            // Resolver-stamps a non-human verdict, then ML override runs.
            let mut ctx = RequestContext::new();
            let resolver = build_resolver();
            stamp_request_context(
                &mut ctx,
                &resolver,
                None,
                false,
                None,
                Some("Mozilla/5.0 (compatible; GPTBot/1.0)"),
            );
            ctx.ml_classification = Some(MlClassification {
                class,
                confidence,
                model_version: "test-v1",
                feature_schema_version: 1,
            });
            apply_ml_override(&mut ctx);
            ctx
        }

        #[test]
        fn human_at_high_confidence_overrides_resolver() {
            let ctx = run_with_verdict(MlClass::Human, 0.95);
            assert_eq!(ctx.agent_id.as_ref().unwrap().as_str(), "human");
            assert_eq!(ctx.agent_id_source, Some(AgentIdSource::MlOverride));
        }

        #[test]
        fn human_at_low_confidence_does_not_override() {
            let ctx = run_with_verdict(MlClass::Human, 0.85);
            // Resolver-stamped verdict survives unchanged.
            assert_eq!(ctx.agent_id.as_ref().unwrap().as_str(), "openai-gptbot");
            assert_eq!(ctx.agent_id_source, Some(AgentIdSource::UserAgent));
        }

        #[test]
        fn scraper_at_any_confidence_does_not_override() {
            for conf in [0.5_f32, 0.95, 0.99] {
                let ctx = run_with_verdict(MlClass::Scraper, conf);
                assert_eq!(ctx.agent_id.as_ref().unwrap().as_str(), "openai-gptbot");
                assert_eq!(ctx.agent_id_source, Some(AgentIdSource::UserAgent));
            }
        }

        #[test]
        fn llm_agent_does_not_override() {
            let ctx = run_with_verdict(MlClass::LlmAgent, 0.99);
            assert_eq!(ctx.agent_id.as_ref().unwrap().as_str(), "openai-gptbot");
            assert_eq!(ctx.agent_id_source, Some(AgentIdSource::UserAgent));
        }

        #[test]
        fn no_verdict_is_no_op() {
            let mut ctx = RequestContext::new();
            let resolver = build_resolver();
            stamp_request_context(
                &mut ctx,
                &resolver,
                None,
                false,
                None,
                Some("Mozilla/5.0 (compatible; GPTBot/1.0)"),
            );
            assert!(ctx.ml_classification.is_none());
            apply_ml_override(&mut ctx);
            assert_eq!(ctx.agent_id.as_ref().unwrap().as_str(), "openai-gptbot");
            assert_eq!(ctx.agent_id_source, Some(AgentIdSource::UserAgent));
        }
    }
}

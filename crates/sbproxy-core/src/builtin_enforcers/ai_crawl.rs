//! Newtype wrapper enforcer for the
//! `Policy::AiCrawl` variant.
//!
//! Lifts the body of the `Policy::AiCrawl(p)` arm that lived in
//! `crate::server::check_policies` into a
//! [`sbproxy_plugin::PolicyEnforcer`] impl. The policy emits four
//! distinct deny shapes (Charge / MultiRail / NoAcceptableRail /
//! LedgerUnavailable); each carries a different per-deny-reason
//! label so the response handler routes the correct response.
//!
//! Per-deny-reason labels:
//!
//! - `"ai_crawl_payment"` for the 402 Charge.
//! - `"ai_crawl_multi_rail"` for the 402 MultiRail.
//! - `"ai_crawl_no_acceptable_rail"` for the 406 NoAcceptableRail.
//! - `"ai_crawl_ledger_unavailable"` for the 503 LedgerUnavailable.
//! - `"ai_crawl_signal_blocked"` for the 403 SignalBlocked (a Content
//!   Signal the operator declared `=no` for this crawler's purpose).
//!
//! Cfg-gated on `agent-class` for the resolved-agent-id thread-
//! through to the quote-token signer. Without the feature the
//! policy still works; the JWS `sub` claim falls back to `""`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use sbproxy_modules::policy::AiCrawlControlPolicy;
use sbproxy_modules::AiCrawlDecision;
use sbproxy_modules::RateLimitInfo;
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use crate::context::RequestContext;

/// Newtype wrapper that adapts [`AiCrawlControlPolicy`] to the
/// [`PolicyEnforcer`] trait surface.
pub struct AiCrawlEnforcer(pub Arc<AiCrawlControlPolicy>);

impl PolicyEnforcer for AiCrawlEnforcer {
    fn policy_type(&self) -> &'static str {
        "ai_crawl_control"
    }

    fn enforce(
        &self,
        req: &http::Request<Bytes>,
        ctx: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn Future<Output = sbproxy_plugin::PluginResult<PolicyDecision>> + Send + '_>>
    {
        let policy = Arc::clone(&self.0);
        let ctx = match ctx.downcast_mut::<RequestContext>() {
            Some(c) => c,
            None => {
                return Box::pin(async move {
                    Ok(PolicyDecision::Deny {
                        status: 500,
                        message: "ai_crawl enforcer: bad context".to_string(),
                    })
                });
            }
        };
        let method = req.method().as_str();
        let path = req.uri().path();

        // G1.4 -> G3.6 thread: pass the resolved agent identifier
        // through to the quote-token signer so the JWS `sub` claim
        // is the resolved id, not the Wave 1 `"unknown"` placeholder.
        // Feature-gated because `agent_id` only exists on the
        // context when the `agent-class` feature is enabled.
        #[cfg(feature = "agent-class")]
        let agent_id_str: Option<String> =
            ctx.agent_id.as_ref().map(|aid| aid.as_str().to_string());
        #[cfg(feature = "agent-class")]
        let agent_id_param: Option<&str> = agent_id_str.as_deref();
        #[cfg(not(feature = "agent-class"))]
        let agent_id_param: Option<&str> = None;
        #[cfg(feature = "agent-class")]
        let agent_id_for_tier = agent_id_param.unwrap_or("");
        #[cfg(not(feature = "agent-class"))]
        let agent_id_for_tier = "";

        // G4.4 + G4.10: stamp citation_required onto the context so
        // downstream transforms read a single source of truth.
        {
            let accept = req
                .headers()
                .get(http::header::ACCEPT)
                .and_then(|v| v.to_str().ok());
            if let Some(tier) = policy.matched_tier_for_request(path, agent_id_for_tier, accept) {
                ctx.citation_required = Some(tier.citation_required);
            }
        }

        let hostname = ctx.hostname.to_string();
        let decision = policy.check(method, &hostname, path, req.headers(), agent_id_param);
        match decision {
            AiCrawlDecision::Allow => Box::pin(async move { Ok(PolicyDecision::Allow) }),
            AiCrawlDecision::AllowCharged { charged_header } => {
                // WOR-803: Cloudflare Pay Per Crawl settled this request
                // through the ledger. Stash the `crawler-charged` value
                // so the served-response path stamps it on the 2xx, then
                // allow the request through to the origin.
                ctx.crawl_charged = Some(charged_header);
                Box::pin(async move { Ok(PolicyDecision::Allow) })
            }
            AiCrawlDecision::CloudflareCharge { price_header, body } => {
                // WOR-803: Cloudflare Pay Per Crawl 402. Carry the
                // `crawler-price` header through the same challenge slot
                // the single-rail path uses; the 402 response handler
                // stamps the literal header name `crawler-price`.
                ctx.crawl_challenge = Some(("crawler-price".to_string(), price_header, body));
                ctx.deny_policy_type = Some("ai_crawl_payment");
                Box::pin(async move {
                    Ok(PolicyDecision::Deny {
                        status: 402,
                        message: "payment required".to_string(),
                    })
                })
            }
            AiCrawlDecision::Charge { body, challenge } => {
                ctx.crawl_challenge = Some((policy.header_name().to_string(), challenge, body));
                ctx.deny_policy_type = Some("ai_crawl_payment");
                Box::pin(async move {
                    Ok(PolicyDecision::Deny {
                        status: 402,
                        message: "payment required".to_string(),
                    })
                })
            }
            AiCrawlDecision::MultiRail { body, content_type } => {
                ctx.crawl_challenge =
                    Some(("Content-Type".to_string(), content_type.to_string(), body));
                ctx.deny_policy_type = Some("ai_crawl_multi_rail");
                Box::pin(async move {
                    Ok(PolicyDecision::Deny {
                        status: 402,
                        message: "payment required".to_string(),
                    })
                })
            }
            AiCrawlDecision::NoAcceptableRail { body } => {
                ctx.crawl_challenge = Some((
                    "Content-Type".to_string(),
                    "application/json".to_string(),
                    body,
                ));
                ctx.deny_policy_type = Some("ai_crawl_no_acceptable_rail");
                Box::pin(async move {
                    Ok(PolicyDecision::Deny {
                        status: 406,
                        message: "no acceptable rail".to_string(),
                    })
                })
            }
            AiCrawlDecision::SignalBlocked { body } => {
                // WOR-804: the crawler's purpose maps to a Content
                // Signal the operator declared as disallowed (`=no`).
                // Block with 403 and carry the JSON explanation through
                // the same challenge slot the other deny shapes use.
                ctx.crawl_challenge = Some((
                    "Content-Type".to_string(),
                    "application/json".to_string(),
                    body,
                ));
                ctx.deny_policy_type = Some("ai_crawl_signal_blocked");
                Box::pin(async move {
                    Ok(PolicyDecision::Deny {
                        status: 403,
                        message: "content signal disallows this crawler".to_string(),
                    })
                })
            }
            AiCrawlDecision::Tarpit { body } => {
                // WOR-810: short-circuit with a 200 + the maze HTML. The
                // request-phase short-circuit renderer serves
                // `short_circuit_body` with this status + content-type
                // without contacting the upstream; we return Allow so the
                // enforcer chain does not deny the request out from under
                // the short-circuit.
                ctx.short_circuit_status = Some(200);
                ctx.short_circuit_body = Some(bytes::Bytes::from(body));
                ctx.short_circuit_content_type = Some("text/html; charset=utf-8".to_string());
                Box::pin(async move { Ok(PolicyDecision::Allow) })
            }
            AiCrawlDecision::LedgerUnavailable {
                body,
                retry_after_seconds,
            } => {
                ctx.crawl_challenge = Some((policy.header_name().to_string(), String::new(), body));
                ctx.rate_limit_info = Some(RateLimitInfo {
                    allowed: false,
                    limit: 0,
                    remaining: 0,
                    reset_secs: retry_after_seconds as u64,
                    headers_enabled: false,
                    include_retry_after: true,
                });
                ctx.deny_policy_type = Some("ai_crawl_ledger_unavailable");
                Box::pin(async move {
                    Ok(PolicyDecision::Deny {
                        status: 503,
                        message: "ledger unavailable".to_string(),
                    })
                })
            }
        }
    }
}

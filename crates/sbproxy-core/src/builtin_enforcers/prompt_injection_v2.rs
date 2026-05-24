//! Newtype wrapper enforcer for the
//! `Policy::PromptInjectionV2` variant.
//!
//! Lifts the body of the `Policy::PromptInjectionV2(p)` arm that
//! lived in `crate::server::check_policies` into a
//! [`sbproxy_plugin::PolicyEnforcer`] impl. The detector runs at
//! request_filter time on the request-line text + non-credential
//! headers so the tag-action path can stamp trust headers before
//! `upstream_request_filter` builds the upstream request.
//! Body-aware detection (the prompt usually lives in the JSON
//! body) lands with the ONNX classifier follow-up; for now the
//! heuristic detector still fires on injection vocabulary present
//! in the URL or in custom headers.
//!
//! Auth-class headers (Authorization / Cookie / Set-Cookie) are
//! skipped so tokens carried by design do not self-flag, mirroring
//! DLP.
//!
//! Per-deny-reason label: `"prompt_injection"`. Block action only;
//! Tag and Log do not deny.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use sbproxy_modules::policy::PromptInjectionV2Policy;
use sbproxy_modules::{PromptInjectionAction, PromptInjectionV2Outcome};
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use crate::context::RequestContext;

/// Newtype wrapper that adapts [`PromptInjectionV2Policy`] to the
/// [`PolicyEnforcer`] trait surface.
pub struct PromptInjectionV2Enforcer(pub Arc<PromptInjectionV2Policy>);

impl PolicyEnforcer for PromptInjectionV2Enforcer {
    fn policy_type(&self) -> &'static str {
        "prompt_injection_v2"
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
                        message: "prompt_injection_v2 enforcer: bad context".to_string(),
                    })
                });
            }
        };
        let mut prompt = req.uri().to_string();
        for (name, value) in req.headers().iter() {
            let n = name.as_str();
            if n == "authorization" || n == "cookie" || n == "set-cookie" {
                continue;
            }
            if let Ok(v) = value.to_str() {
                prompt.push('\n');
                prompt.push_str(v);
            }
        }
        if let PromptInjectionV2Outcome::Hit { result } = policy.evaluate(&prompt) {
            match policy.action() {
                PromptInjectionAction::Block => {
                    tracing::warn!(
                        target: "sbproxy::prompt_injection_v2",
                        detector = %policy.detector_name(),
                        score = %result.score,
                        label = %result.label,
                        reason = ?result.reason,
                        "blocked: detector matched"
                    );
                    ctx.deny_policy_type = Some("prompt_injection");
                    let message = policy.block_body().to_string();
                    return Box::pin(async move {
                        Ok(PolicyDecision::Deny {
                            status: 403,
                            message,
                        })
                    });
                }
                PromptInjectionAction::Tag => {
                    let score_entry = (
                        policy.score_header().to_string(),
                        format!("{:.3}", result.score),
                    );
                    let label_entry = (
                        policy.label_header().to_string(),
                        result.label.as_str().to_string(),
                    );
                    match ctx.trust_headers.as_mut() {
                        Some(v) => {
                            v.push(score_entry);
                            v.push(label_entry);
                        }
                        None => {
                            ctx.trust_headers = Some(vec![score_entry, label_entry]);
                        }
                    }
                }
                PromptInjectionAction::Log => {
                    tracing::warn!(
                        target: "sbproxy::prompt_injection_v2",
                        detector = %policy.detector_name(),
                        score = %result.score,
                        label = %result.label,
                        reason = ?result.reason,
                        "prompt injection detected (log mode)"
                    );
                }
            }
        }
        Box::pin(async move { Ok(PolicyDecision::Allow) })
    }
}

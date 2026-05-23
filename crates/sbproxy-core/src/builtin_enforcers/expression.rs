//! WOR-201 PR 1c.1: newtype wrapper enforcer for the
//! `Policy::Expression` variant.
//!
//! Lifts the body of the `Policy::Expression(p)` arm that lived
//! in `crate::server::check_policies` into a
//! [`sbproxy_plugin::PolicyEnforcer`] impl. Builds the
//! [`sbproxy_modules::ExpressionViews`] bundle from the live
//! [`RequestContext`] (aipref signal, optional KYA verifier
//! verdict under the `agent-class` feature, optional ML
//! classifier verdict under the `agent-classifier` feature, and
//! the `x-sb-flags` parsed feature flags) and dispatches into
//! [`sbproxy_modules::policy::ExpressionPolicy::evaluate_with_views`].
//!
//! Per-deny-reason label: `"expression"`. The denial status and
//! body are operator-configurable on the policy itself; the
//! wrapper forwards them verbatim into the
//! [`PolicyDecision::Deny`] payload so the response handler
//! reproduces today's byte-identical body.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use sbproxy_modules::policy::ExpressionPolicy;
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use crate::context::RequestContext;

/// Newtype wrapper that adapts [`ExpressionPolicy`] to the
/// [`PolicyEnforcer`] trait surface.
pub struct ExpressionEnforcer(pub Arc<ExpressionPolicy>);

impl PolicyEnforcer for ExpressionEnforcer {
    fn policy_type(&self) -> &'static str {
        "expression"
    }

    fn enforce(
        &self,
        req: &http::Request<Bytes>,
        ctx: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn Future<Output = sbproxy_plugin::PluginResult<PolicyDecision>> + Send + '_>>
    {
        let policy = Arc::clone(&self.0);
        // Pull the typed RequestContext out of the trait's
        // `&mut dyn Any` carrier. Fail closed if the carrier is
        // unexpectedly something else.
        let ctx = match ctx.downcast_mut::<RequestContext>() {
            Some(c) => c,
            None => {
                return Box::pin(async move {
                    Ok(PolicyDecision::Deny {
                        status: 500,
                        message: "expression enforcer: bad context".to_string(),
                    })
                });
            }
        };

        // Snapshot every input the CEL evaluator needs so the
        // future does not borrow `req` or `ctx`.
        let method = req.method().as_str().to_string();
        let path = req
            .uri()
            .path_and_query()
            .map(|pq| pq.path().to_string())
            .unwrap_or_else(|| "/".to_string());
        let query = req
            .uri()
            .path_and_query()
            .and_then(|pq| pq.query().map(|q| q.to_string()));
        let headers = req.headers().clone();
        let client_ip_str = ctx.client_ip.map(|ip| ip.to_string());
        let hostname = ctx.hostname.to_string();

        // Build the Wave 4 / Wave 5 view bundle. Each view borrows
        // from the live ctx, so populate it inside this function
        // before producing the future. The CEL evaluation
        // (`evaluate_with_views`) is synchronous; the async block
        // only carries the boolean result.
        #[cfg(feature = "agent-class")]
        let kya_view = Some(sbproxy_extension::cel::context::KyaVerdictView {
            verdict: ctx.kya_verdict,
            agent_id: ctx.agent_id.as_ref().map(|id| id.as_str()),
            vendor: ctx.kya_vendor.as_deref(),
            kya_version: ctx.kya_version.as_deref(),
            kyab_balance: ctx.kya_kyab_balance,
        });
        #[cfg(not(feature = "agent-class"))]
        let kya_view: Option<sbproxy_extension::cel::context::KyaVerdictView<'_>> = None;

        #[cfg(feature = "agent-classifier")]
        let ml_view = ctx.ml_classification.as_ref().map(|m| {
            sbproxy_extension::cel::context::MlClassificationView {
                class: Some(m.class.as_str()),
                confidence: Some(m.confidence),
                model_version: Some(m.model_version),
                feature_schema_version: Some(m.feature_schema_version),
            }
        });
        #[cfg(not(feature = "agent-classifier"))]
        let ml_view: Option<sbproxy_extension::cel::context::MlClassificationView<'_>> = None;

        let features_view = sbproxy_extension::cel::context::FeatureFlagsView {
            debug: ctx.flags.debug,
            trace: ctx.flags.trace,
            no_cache: ctx.flags.no_cache,
            extra: &ctx.flags.extra,
        };
        // WOR-589: expose the agent-detection verdict (WOR-706 stamps it
        // on ctx when proxy.extensions.agent_detect is enabled) so CEL
        // policies can branch on `request.agent.score` etc.
        let agent_detect_view = ctx.agent_detection.as_ref().map(|ad| {
            sbproxy_extension::cel::context::AgentDetectView {
                score: ad.score,
                agent_id: ad.agent_id.as_deref(),
                provenance: ad.provenance.as_str(),
                confidence: ad.confidence,
                signals_used: &ad.signals_used,
            }
        });
        let views = sbproxy_modules::ExpressionViews {
            aipref: ctx.aipref.as_ref(),
            kya: kya_view,
            ml: ml_view,
            features: Some(features_view),
            agent_detect: agent_detect_view,
        };

        let allowed = policy.evaluate_with_views(
            &method,
            &path,
            &headers,
            query.as_deref(),
            client_ip_str.as_deref(),
            &hostname,
            views,
        );
        if !allowed {
            // Forward the configured deny shape verbatim. The
            // response handler keys on `deny_policy_type`
            // independently of the status / message, so callers
            // that override the status (e.g. 401) still land in
            // the standard deny-emit path.
            ctx.deny_policy_type = Some("expression");
            let status = policy.deny_status;
            let message = policy.deny_message.clone();
            return Box::pin(async move { Ok(PolicyDecision::Deny { status, message }) });
        }
        Box::pin(async move { Ok(PolicyDecision::Allow) })
    }
}

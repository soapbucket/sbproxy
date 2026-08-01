//! Newtype wrapper enforcer for the `Policy::A2A`
//! variant.
//!
//! Lifts the body of the `Policy::A2A(p)` arm that lived in
//! `crate::server::check_policies` into a
//! [`sbproxy_plugin::PolicyEnforcer`] impl. Reads the inbound
//! agent-to-agent envelope from `RequestContext::a2a` and runs the
//! per-hop checks (chain depth, cycle detection, callee allowlist,
//! caller deny). Emits per-hop metrics regardless of verdict.
//!
//! Per-deny-reason labels (one per refusal class):
//!
//! - `"a2a_chain_depth_exceeded"`
//! - `"a2a_cycle_detected"`
//! - `"a2a_callee_not_allowed"`
//! - `"a2a_caller_denied"`
//! - `"a2a_undetected"`
//! - `"a2a"` (catch-all for any future variant)
//!
//! A request the policy cannot identify as A2A is routed by the
//! policy's failure posture rather than being allowed unconditionally.
//! The default is `open`, which is what shipped before the knob
//! existed, so an existing config behaves identically. See
//! `A2APolicyConfig::failure_posture` for why the default is `open`
//! here and closed almost everywhere else.
//!
//! # What this enforcer does not do
//!
//! Everything here runs on headers and the resolved principal, because
//! that is all the request-filter surface can see: the
//! `http::Request<Bytes>` it is handed always has an empty body.
//! Body-dependent A2A governance (the push-notification SSRF check, the
//! prompt-injection scan of message parts) lives in
//! `crate::server::a2a_body_phase`, which is private, so this is a
//! plain reference rather than an intra-doc link. This enforcer's job for those is
//! to set `RequestContext::validate_request_body` so the body is
//! buffered, and to publish the envelope it resolved on
//! `RequestContext::a2a` so the body phase sees the same one.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use sbproxy_modules::policy::{A2APolicy, A2APolicyDecision};
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use crate::context::RequestContext;

/// Newtype wrapper that adapts [`A2APolicy`] to the
/// [`PolicyEnforcer`] trait surface.
pub struct A2AEnforcer(pub Arc<A2APolicy>);

impl PolicyEnforcer for A2AEnforcer {
    fn policy_type(&self) -> &'static str {
        "a2a"
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
                        message: "a2a enforcer: bad context".to_string(),
                    })
                });
            }
        };
        // WOR-2120: the request filter detects on caller-supplied
        // signals only (`Content-Type`, `MCP-Method`), because the
        // operator's `route_glob` is per-policy and not reachable from
        // there. Consult it here, where the compiled policy is in hand,
        // so a route the operator declared as A2A is governed even when
        // the caller sends nothing that looks like A2A. Without this the
        // policy is opt-in for the attacker: omit one header, skip every
        // check.
        let mut a2a_ctx = match ctx.a2a.clone() {
            Some(c) => c,
            None => match policy.governs(req.headers(), req.uri().path()) {
                // Operator-declared route, no envelope stamped upstream.
                // Evaluate against the zero-default envelope so route
                // limits still apply; `identity_verified` stays false.
                Some(spec) => sbproxy_modules::A2AContext::empty(spec.to_spec()),
                None => {
                    // WOR-2120 AC5: the policy is configured on this
                    // route but did not engage. Record it either way:
                    // an unbroken stream of allows from a policy that
                    // never runs is indistinguishable from a healthy
                    // one, which is how a bypass stays invisible on a
                    // dashboard.
                    //
                    // The posture decides what happens to the request.
                    // Each posture gets its own `decision` value, so
                    // "ungoverned by default", "would have been
                    // refused", and "refused" are three series rather
                    // than one, and `open` keeps the string it always
                    // emitted.
                    let posture = policy.failure_posture();
                    let label = policy.undetected_decision_label();
                    sbproxy_observe::metrics::record_a2a_hop(ctx.hostname.as_ref(), "none", label);
                    if posture.admits() {
                        // `observe` promises more than a distinct metric
                        // series: it admits the request AND records the
                        // decision the control would otherwise have
                        // taken. A counter alone cannot say which
                        // requests those were, so an operator sizing the
                        // blast radius of flipping this route to
                        // `closed` would have a number and no way to
                        // audit it. Emit the counterfactual per request,
                        // carrying the 403 that `closed` would have
                        // returned rather than the 200 actually served.
                        if posture.records_counterfactual() {
                            let counterfactual = A2APolicyDecision::Undetected;
                            sbproxy_observe::SecurityAuditEntry::policy_violation(
                                "a2a_undetected_observed",
                                "route carries an a2a policy but the request did not identify \
                                 itself as A2A; admitted because failure_posture is observe, \
                                 and closed would have refused it",
                                counterfactual.http_status(),
                                Some(ctx.hostname.to_string()),
                                ctx.client_ip,
                                Some(ctx.request_id.to_string()),
                                Some(req.method().as_str().to_string()),
                            )
                            .emit();
                        }
                        return Box::pin(async move { Ok(PolicyDecision::Allow) });
                    }
                    // Closed. The origin serves A2A and nothing else,
                    // and this request did not identify itself as A2A.
                    let decision = A2APolicyDecision::Undetected;
                    sbproxy_observe::metrics::record_a2a_denied(
                        ctx.hostname.as_ref(),
                        decision.reason_label(),
                    );
                    let body = decision.json_body();
                    let status = decision.http_status();
                    ctx.a2a_denial_body = Some(body.clone());
                    ctx.deny_policy_type = Some("a2a_undetected");
                    return Box::pin(async move {
                        Ok(PolicyDecision::Deny {
                            status,
                            message: body,
                        })
                    });
                }
            },
        };

        // WOR-2120: a signed token outranks the transport. The header
        // envelope is forgeable in the direction that matters, since a
        // caller asserting depth 1 (or omitting the header) clears any
        // cap. An `act` chain cannot be flattened that way, so when the
        // verified principal carries one it replaces the claimed depth
        // and chain before evaluation.
        if let Some(claims) = ctx.principal.attrs.claims.as_ref() {
            sbproxy_modules::apply_verified_act_chain(&mut a2a_ctx, claims);
        }
        let a2a_ctx = a2a_ctx;
        let route = ctx.hostname.to_string();
        let spec_label = a2a_ctx.spec.as_label();
        let callable_endpoint = req.uri().path().to_string();

        // WOR-2118: publish the envelope this enforcer actually resolved.
        // Two things happen above that the stamped `ctx.a2a` does not
        // know about: a route matched by the operator's `route_glob`
        // produces an envelope where detection stamped none, and a
        // verified `act` chain replaces the depth and chain the
        // transport claimed. The body phase decides on delegation depth,
        // so it has to read the post-overlay value or it would enforce
        // against exactly the forgeable number the overlay exists to
        // discard.
        ctx.a2a = Some(a2a_ctx.clone());

        // WOR-2116 / WOR-2118: on ratified 1.0, the JSON-RPC body has to
        // be inspected for a push-notification registration before it
        // reaches the upstream agent. A2A lets a caller hand the agent a
        // URL to POST task artifacts to, so an unchecked registration
        // turns an authenticated backend into a confused deputy aimed at
        // whatever the caller names.
        //
        // That check cannot run here. `req` comes from
        // `build_plugin_request_snapshot`, whose body is always empty,
        // so the `!req.body().is_empty()` guard this code used to carry
        // was never true and the check never ran once. Ask for the body
        // instead: setting this flag makes `request_body_filter` buffer
        // the request, and `server::a2a_body_phase` runs the check there
        // against bytes that exist.
        //
        // Only for the 1.0 spec. The v0 drafts have no push-notification
        // surface, so buffering their bodies would buy nothing and cost
        // a hold on every hop.
        if a2a_ctx.spec == sbproxy_modules::A2ASpec::V1_0 {
            ctx.validate_request_body = true;
        }

        let decision = policy.evaluate(&a2a_ctx, &callable_endpoint);
        sbproxy_observe::metrics::record_a2a_chain_depth(&route, spec_label, a2a_ctx.chain_depth);
        let decision_label = decision.metric_label(a2a_ctx.identity_verified);
        if decision.is_allow() {
            sbproxy_observe::metrics::record_a2a_hop(&route, spec_label, &decision_label);
            return Box::pin(async move { Ok(PolicyDecision::Allow) });
        }
        let reason = decision.reason_label();
        sbproxy_observe::metrics::record_a2a_hop(&route, spec_label, &decision_label);
        sbproxy_observe::metrics::record_a2a_denied(&route, reason);
        let body = decision.json_body();
        let status = decision.http_status();
        ctx.a2a_denial_body = Some(body.clone());
        let policy_type: &'static str = match reason {
            "depth" => "a2a_chain_depth_exceeded",
            "cycle" => "a2a_cycle_detected",
            "callee_not_allowed" => "a2a_callee_not_allowed",
            "caller_denied" => "a2a_caller_denied",
            "undetected" => "a2a_undetected",
            _ => "a2a",
        };
        ctx.deny_policy_type = Some(policy_type);
        Box::pin(async move {
            Ok(PolicyDecision::Deny {
                status,
                message: body,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_modules::policy::{A2APolicy, A2APolicyConfig};
    use sbproxy_modules::{A2AContext, A2ASpec};

    fn enforce(policy: A2APolicy, ctx: &mut RequestContext, path: &str) -> PolicyDecision {
        let enforcer = A2AEnforcer(Arc::new(policy));
        let req = http::Request::builder()
            .method("POST")
            .uri(path)
            .body(Bytes::new())
            .expect("request builds");
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime builds");
        rt.block_on(enforcer.enforce(&req, ctx))
            .expect("enforce runs")
    }

    #[test]
    fn a_ratified_hop_asks_for_the_request_body() {
        // The half of the fix that lives in the request filter. Without
        // this flag `request_body_filter` never buffers, the body phase
        // never sees the JSON-RPC envelope, and the push-notification
        // check has nothing to inspect. The check being correct is not
        // enough if nothing ever hands it bytes.
        let mut ctx = RequestContext::new();
        ctx.a2a = Some(A2AContext::empty(A2ASpec::V1_0));
        assert!(
            !ctx.validate_request_body,
            "precondition: nothing has asked for the body yet"
        );

        let decision = enforce(
            A2APolicy::with_config(A2APolicyConfig::default()),
            &mut ctx,
            "/a2a",
        );

        assert!(matches!(decision, PolicyDecision::Allow));
        assert!(
            ctx.validate_request_body,
            "a ratified 1.0 hop must request body buffering so the body \
             phase can run the push-notification check"
        );
    }

    #[test]
    fn a_draft_hop_does_not_ask_for_the_request_body() {
        // The v0 drafts have no push-notification surface. Buffering
        // their bodies would hold every hop for nothing, and this is an
        // east-west path where a fan-out multiplies the request count.
        let mut ctx = RequestContext::new();
        ctx.a2a = Some(A2AContext::empty(A2ASpec::GoogleV0));

        let _ = enforce(
            A2APolicy::with_config(A2APolicyConfig::default()),
            &mut ctx,
            "/a2a",
        );

        assert!(!ctx.validate_request_body);
    }

    #[test]
    fn an_operator_declared_route_publishes_an_envelope_the_body_phase_can_read() {
        // Detection stamps nothing when the caller sends no A2A-shaped
        // headers, so `ctx.a2a` arrives as None and the enforcer builds
        // the envelope from `route_glob`. If it does not publish that
        // envelope, the body phase sees None and its depth rule never
        // engages on exactly the routes the operator declared.
        let mut ctx = RequestContext::new();
        assert!(ctx.a2a.is_none(), "precondition: detection found nothing");

        let _ = enforce(
            A2APolicy::with_config(A2APolicyConfig {
                route_glob: Some("/agents/**".to_string()),
                ..A2APolicyConfig::default()
            }),
            &mut ctx,
            "/agents/invoke",
        );

        assert!(ctx.a2a.is_some(), "the resolved envelope must be published");
    }

    #[test]
    fn a_verified_act_chain_is_published_not_just_evaluated() {
        // The overlay replaces a forgeable claimed depth with the one the
        // signed token proves. It used to be applied to a local clone
        // that was dropped at the end of the call, so anything reading
        // `ctx.a2a` later got the caller's number back.
        let mut ctx = RequestContext::new();
        ctx.a2a = Some(A2AContext::empty(A2ASpec::V1_0));
        let claims = match serde_json::json!({
            "sub": "user-1",
            "act": { "sub": "worker", "act": { "sub": "orchestrator" } }
        }) {
            serde_json::Value::Object(m) => m,
            _ => unreachable!(),
        };
        ctx.principal.attrs.claims = Some(claims);

        let _ = enforce(
            A2APolicy::with_config(A2APolicyConfig::default()),
            &mut ctx,
            "/a2a",
        );

        let published = ctx.a2a.expect("envelope published");
        assert_eq!(published.chain_depth, 3, "two actors plus this hop");
        assert_eq!(
            published.delegation_depth(),
            2,
            "the body phase reads delegation depth, which is one less"
        );
        assert!(published.identity_verified);
    }
}

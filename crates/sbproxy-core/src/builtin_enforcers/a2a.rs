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

        // WOR-2116: on ratified 1.0, inspect the JSON-RPC body for a
        // push-notification registration and validate its target before
        // it reaches the upstream agent. A2A lets a caller hand the
        // agent a URL to POST task artifacts to, so an unchecked
        // registration turns an authenticated backend into a confused
        // deputy aimed at whatever the caller names.
        //
        // Only parsed for the 1.0 spec: the v0 drafts have no
        // push-notification surface, so there is nothing to check and no
        // reason to spend a JSON parse on their bodies.
        if a2a_ctx.spec == sbproxy_modules::A2ASpec::V1_0 && !req.body().is_empty() {
            if let Some(parsed) = sbproxy_modules::a2a_v1::parse_request(req.body()) {
                // Method-level visibility, from the closed enum rather
                // than the caller-supplied wire string: eleven bounded
                // values instead of an unbounded label. The type is
                // named rather than inferred so the label's cardinality
                // bound is legible at the call site.
                let method: Option<sbproxy_modules::a2a_v1::V1Method> = parsed.method;
                if let Some(method) = method {
                    sbproxy_observe::metrics::record_a2a_method(&route, method.as_label());
                }
                let push = policy.check_push_notification(&parsed);
                if !push.is_allow() {
                    let reason = push.reason_label();
                    sbproxy_observe::metrics::record_a2a_hop(
                        &route,
                        spec_label,
                        &push.metric_label(a2a_ctx.identity_verified),
                    );
                    sbproxy_observe::metrics::record_a2a_denied(&route, reason);
                    let body = push.json_body();
                    let status = push.http_status();
                    ctx.a2a_denial_body = Some(body.clone());
                    ctx.deny_policy_type = Some("a2a_push_target_blocked");
                    return Box::pin(async move {
                        Ok(PolicyDecision::Deny {
                            status,
                            message: body,
                        })
                    });
                }
            }
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

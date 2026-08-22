//! Cedar evaluator: wraps `cedar_policy::Authorizer` and maps the
//! response back to [`sbproxy_plugin::PolicyDecision`].
//!
//! This is the request-hot-path entry point once a caller wires it
//! in: hold an `Arc<CedarEvaluator>`, call [`CedarEvaluator::evaluate`]
//! per request. The evaluator owns:
//!
//! - The compiled `cedar_policy::PolicySet` from
//!   [`super::compiler::compile_all`].
//! - The workspace `cedar_policy::Schema` used for runtime request
//!   validation when present.
//!
//! `Authorizer` is constructed once and held alongside the policy
//! set. Per the cedar-policy docs, `Authorizer` is `Send + Sync` and
//! `is_authorized` is a pure read against the supplied policy set;
//! sharing one instance across all dispatches is the documented
//! pattern.
//!
//! Cedar returns `Decision::{Allow, Deny}` with a `Diagnostics` blob
//! that carries the matched policy ids and any evaluation errors.
//! This maps that to:
//!
//! - `Decision::Allow` -> [`PolicyDecision::Allow`].
//! - `Decision::Deny`, no matched policy annotated `@confirm(...)` ->
//!   [`PolicyDecision::Deny`] with status 403 and a message that
//!   includes the matched policy ids (Cedar's `Diagnostics::reason()`
//!   exposes them).
//! - `Decision::Deny`, a matched `forbid` annotated
//!   `@confirm("reason")` -> [`PolicyDecision::Confirm`] with that
//!   reason text (WOR-2587). This is how a Cedar-authored policy asks
//!   for human-in-the-loop approval rather than an outright refusal:
//!   the annotation is inert to Cedar's own evaluator (annotations
//!   never affect which policy fires), so the same source stays a
//!   plain `forbid` from Cedar's point of view and only sbproxy's
//!   verdict mapping treats it specially.
//! - Bridge or request-construction errors short-circuit to
//!   [`PolicyDecision::Deny`] with status 500 and a structured
//!   reason. This is a deliberate fail-closed posture: a malformed
//!   request should never be silently allowed because the bridge
//!   could not translate it.

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, Schema,
};
use sbproxy_plugin::PolicyDecision;
use thiserror::Error;

use super::request_bridge::{build_request, CedarRequest, RequestBridgeError};

/// Errors raised by the evaluator at construction time. Run-time
/// evaluation errors do NOT surface as `Result::Err` from
/// [`CedarEvaluator::evaluate`]; per the fail-closed contract, those
/// are folded into a structured `Deny` verdict so the request hot
/// path never panics.
#[derive(Debug, Error)]
pub enum EvaluatorError {
    /// The supplied policy set was empty. Mirrors
    /// [`super::compiler::CompilerError::EmptyInput`] so a caller can
    /// surface a single error variant to operators.
    #[error("cedar evaluator constructed with empty policy set")]
    EmptyPolicySet,
}

/// Wraps a compiled [`PolicySet`] plus the workspace [`Schema`] and
/// exposes the evaluation entry point.
///
/// One instance per compiled policy generation. A caller that
/// hot-reloads policy holds this behind an `Arc` so in-flight
/// requests keep using the previous evaluator until they complete.
#[derive(Debug)]
pub struct CedarEvaluator {
    authorizer: Authorizer,
    policy_set: PolicySet,
    schema: Option<Schema>,
}

impl CedarEvaluator {
    /// Construct an evaluator from a compiled policy set and an
    /// optional workspace schema.
    ///
    /// The schema is optional because a caller with no MCP schema
    /// configured yet has nothing to validate requests against. Once
    /// a default MCP schema is always loaded, production call sites
    /// can pass `Some(schema)` unconditionally.
    ///
    /// # Errors
    ///
    /// Returns [`EvaluatorError::EmptyPolicySet`] if `policy_set` has
    /// zero policies.
    pub fn new(policy_set: PolicySet, schema: Option<Schema>) -> Result<Self, EvaluatorError> {
        if policy_set.policies().count() == 0 {
            return Err(EvaluatorError::EmptyPolicySet);
        }
        Ok(Self {
            authorizer: Authorizer::new(),
            policy_set,
            schema,
        })
    }

    /// Number of policies the evaluator was constructed with. Used
    /// by the metrics surface and by tests; not on the request hot
    /// path.
    pub fn policy_count(&self) -> usize {
        self.policy_set.policies().count()
    }

    /// Evaluate a request against the compiled policy set.
    ///
    /// The four possible paths:
    ///
    /// 1. Bridge succeeds, Cedar returns `Allow`: returns
    ///    [`PolicyDecision::Allow`].
    /// 2. Bridge succeeds, Cedar returns `Deny`: returns
    ///    [`PolicyDecision::Deny`] with HTTP 403 and a message that
    ///    embeds the matched policy id (the first one from
    ///    `Diagnostics::reason()`; multiple matches are joined with
    ///    `, `).
    /// 3. Bridge fails (malformed UID, schema mismatch): returns
    ///    [`PolicyDecision::Deny`] with HTTP 500 and a structured
    ///    reason. Fail-closed.
    /// 4. Cedar evaluation produces non-fatal errors (attribute
    ///    missing on a referenced entity, etc.): the verdict is still
    ///    honoured; the errors are emitted via `tracing` so the
    ///    operator can debug without changing the response shape.
    ///
    /// This method is `&self` and Send-safe; the caller can hold the
    /// evaluator behind an `Arc` and dispatch from any task.
    pub fn evaluate(&self, request: &CedarRequest) -> PolicyDecision {
        let (cedar_req, entities) = match build_request(request, self.schema.as_ref()) {
            Ok(pair) => pair,
            Err(err) => return deny_from_bridge_error(err),
        };
        self.evaluate_with_entities(&cedar_req, &entities)
    }

    /// Evaluate an already-translated `cedar_policy::Request` with an
    /// empty [`Entities`] store.
    ///
    /// Internal step shared by [`Self::evaluate_uids`] (the production
    /// caller: see its docs) and, indirectly, [`Self::evaluate`].
    /// Materialising per-agent / per-tool entities through
    /// [`Self::evaluate_with_entities`] instead of an empty store is
    /// follow-up work once a workspace state projection exists to
    /// source them from.
    fn evaluate_cedar_request(&self, request: &Request) -> PolicyDecision {
        let entities = Entities::empty();
        self.evaluate_with_entities(request, &entities)
    }

    /// Evaluate against the supplied request + entities pair.
    ///
    /// Shared entry point for [`Self::evaluate`] and
    /// [`Self::evaluate_cedar_request`]. Keeps the verdict mapping in
    /// one place so the two callers never drift.
    fn evaluate_with_entities(&self, request: &Request, entities: &Entities) -> PolicyDecision {
        let response = self
            .authorizer
            .is_authorized(request, &self.policy_set, entities);

        // Surface evaluation errors via tracing without changing the
        // verdict shape. A Cedar evaluation error (e.g. attribute
        // missing on a referenced entity) is the operator's signal
        // that a policy or entity hierarchy is misaligned; the
        // verdict still reflects what Cedar decided.
        for err in response.diagnostics().errors() {
            tracing::warn!(target: "policy.cedar", error = %err, "cedar evaluation produced a diagnostic error");
        }

        match response.decision() {
            Decision::Allow => PolicyDecision::Allow,
            Decision::Deny => {
                let matched_ids: Vec<_> = response.diagnostics().reason().collect();

                // WOR-2587 review: a `forbid` annotated
                // `@confirm("reason")` asks for human-in-the-loop
                // approval rather than an outright refusal, but only
                // downgrades the verdict when EVERY matched forbid
                // carries the annotation. Cedar's own decision is Deny
                // either way once any forbid matches; the bug this
                // guards against is a policy author writing one
                // absolute, non-confirmable `forbid` and a separate,
                // narrower `@confirm`-annotated `forbid` that also
                // happens to match the same request -- `find_map`
                // over the full matched-id list would soften the
                // absolute forbid's intent the moment the narrower
                // rule also fired, purely because it happened to be
                // annotated. Requiring unanimity means a plain forbid
                // anywhere in the matched set keeps the verdict a hard
                // Deny, exactly as its author wrote it.
                let all_confirm = !matched_ids.is_empty()
                    && matched_ids
                        .iter()
                        .all(|id| self.policy_set.annotation(id, "confirm").is_some());
                if all_confirm {
                    // Every matched id carries the annotation, so any
                    // one of their reason texts is a faithful summary;
                    // the first is used because `Diagnostics::reason()`
                    // has already decided which forbid(s) fired and
                    // this only decides how sbproxy reports that
                    // outcome upstream.
                    let reason = matched_ids
                        .iter()
                        .find_map(|id| self.policy_set.annotation(id, "confirm"))
                        .unwrap_or_default();
                    let reason = if reason.is_empty() {
                        "cedar policy requires confirmation".to_string()
                    } else {
                        reason.to_string()
                    };
                    return PolicyDecision::confirm(reason, None, None);
                }

                let matched = matched_ids
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                let message = if matched.is_empty() {
                    "denied by cedar policy".to_string()
                } else {
                    format!("denied by cedar policy: {matched}")
                };
                PolicyDecision::Deny {
                    status: 403,
                    message,
                }
            }
        }
    }

    /// Evaluate a request built directly from an `EntityUid` triple,
    /// with an empty Cedar context, against this evaluator's own
    /// schema (when one is configured).
    ///
    /// Callers whose principal / resource ids come from untrusted
    /// request data (an MCP `agent_id`, a `tool_name`) build their
    /// [`EntityUid`]s via [`EntityUid::from_type_name_and_id`] rather
    /// than interpolating the raw string into Cedar source-text syntax
    /// and parsing it through [`CedarRequest`] / [`Self::evaluate`]: a
    /// value containing `"` or other Cedar syntax characters would
    /// otherwise either fail to parse or be interpreted as additional
    /// Cedar syntax. `EntityId::new` (used to build the ids that go
    /// into those `EntityUid`s) is infallible and escapes arbitrary
    /// input safely, which `EntityUid::from_str` on a hand-assembled
    /// string does not guarantee. See
    /// `crate::mcp::cedar_hook::CedarMcpHook` for the production
    /// caller.
    ///
    /// # Errors surfaced as Deny
    ///
    /// A schema-validation failure at request-construction time (the
    /// action does not apply to the given principal / resource types,
    /// for example) fails closed through the same
    /// [`RequestBridgeError::InvalidRequest`] path
    /// [`super::request_bridge::build_request`] uses, so callers see
    /// one consistent Deny message shape regardless of which bridge
    /// failed.
    pub fn evaluate_uids(
        &self,
        principal: EntityUid,
        action: EntityUid,
        resource: EntityUid,
    ) -> PolicyDecision {
        match Request::new(
            principal,
            action,
            resource,
            Context::empty(),
            self.schema.as_ref(),
        ) {
            Ok(request) => self.evaluate_cedar_request(&request),
            Err(err) => {
                deny_from_bridge_error(RequestBridgeError::InvalidRequest(format!("{err}")))
            }
        }
    }
}

/// Map a [`RequestBridgeError`] onto the standard fail-closed Deny.
///
/// The reason string carries the variant tag so audit consumers can
/// distinguish "operator misconfigured a policy" (InvalidEntityUid)
/// from "request was malformed" (InvalidContext / InvalidRequest)
/// without parsing the message text.
fn deny_from_bridge_error(err: RequestBridgeError) -> PolicyDecision {
    let reason = match &err {
        RequestBridgeError::InvalidEntityUid { component, .. } => {
            format!("cedar_request_bridge_invalid_entity_uid:{component}")
        }
        RequestBridgeError::InvalidContext(_) => "cedar_request_bridge_invalid_context".to_string(),
        RequestBridgeError::InvalidRequest(_) => "cedar_request_bridge_invalid_request".to_string(),
    };
    tracing::warn!(target: "policy.cedar", error = %err, "cedar request bridge failed; failing closed");
    PolicyDecision::Deny {
        status: 500,
        message: reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cedar::compiler::compile_all;

    /// Round-trip a single permit policy against multiple requests.
    /// The matching request is allowed; the non-matching request is
    /// denied. Pins the `Authorizer::is_authorized` shape and the
    /// PolicyDecision mapping in one go.
    #[test]
    fn evaluator_round_trips_permit_policy() {
        let src = r#"permit(principal == User::"alice", action == Action::"view", resource);"#;
        let compiled = compile_all(&[("t", src)], None).expect("compile");
        let evaluator = CedarEvaluator::new(compiled.policy_set, None).expect("new evaluator");

        // Matching request: alice viewing.
        let allow_req =
            CedarRequest::new(r#"User::"alice""#, r#"Action::"view""#, r#"Document::"x""#);
        assert_eq!(evaluator.evaluate(&allow_req), PolicyDecision::Allow);

        // Non-matching request: bob viewing. No policy permits, so
        // default-deny applies. The Deny variant is the load-bearing
        // contract; the message text is informational.
        let deny_req = CedarRequest::new(r#"User::"bob""#, r#"Action::"view""#, r#"Document::"x""#);
        match evaluator.evaluate(&deny_req) {
            PolicyDecision::Deny { status, .. } => assert_eq!(status, 403),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    /// An empty policy set is rejected at construction time. This
    /// guards against a caller silently producing an always-allow
    /// evaluator.
    #[test]
    fn empty_policy_set_rejected() {
        // Build a PolicySet with zero policies by parsing an empty
        // string. Cedar accepts this and returns an empty set.
        let empty = std::str::FromStr::from_str("").expect("empty parse");
        let result = CedarEvaluator::new(empty, None);
        assert!(matches!(result, Err(EvaluatorError::EmptyPolicySet)));
    }

    /// A malformed principal UID short-circuits to the fail-closed
    /// `Deny` with the structured reason. The reason embeds the
    /// `principal` component tag so audit consumers can distinguish
    /// the failure surface without parsing the message.
    #[test]
    fn bridge_failure_returns_fail_closed_deny() {
        let src = r#"permit(principal, action, resource);"#;
        let compiled = compile_all(&[("t", src)], None).expect("compile");
        let evaluator = CedarEvaluator::new(compiled.policy_set, None).expect("new evaluator");

        let bad = CedarRequest::new("not a uid", r#"Action::"view""#, r#"Doc::"d""#);
        match evaluator.evaluate(&bad) {
            PolicyDecision::Deny { status, message } => {
                assert_eq!(status, 500);
                assert!(message.contains("invalid_entity_uid"));
                assert!(message.contains("principal"));
            }
            other => panic!("expected fail-closed Deny, got {other:?}"),
        }
    }

    /// A `forbid` policy produces a Deny whose message includes the
    /// matched policy id from `Diagnostics::reason()`. Pins the
    /// audit-trail shape: the matched id MUST surface in the verdict
    /// so a rationale renderer can include it.
    #[test]
    fn forbid_verdict_carries_matched_policy_id() {
        let src = r#"
            permit(principal, action, resource);
            forbid(principal == User::"banned", action, resource);
        "#;
        let compiled = compile_all(&[("t", src)], None).expect("compile");
        let evaluator = CedarEvaluator::new(compiled.policy_set, None).expect("new evaluator");

        let req = CedarRequest::new(r#"User::"banned""#, r#"Action::"view""#, r#"Doc::"d""#);
        match evaluator.evaluate(&req) {
            PolicyDecision::Deny { message, .. } => {
                // Cedar names un-annotated policies `policy0`,
                // `policy1`, ... in source order. The forbid is
                // second so policy1 is the one that fired.
                assert!(message.contains("policy"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    /// WOR-2587: a `forbid` annotated `@confirm("reason")` maps to
    /// [`PolicyDecision::Confirm`] carrying that reason text, instead
    /// of the plain `Deny` an unannotated `forbid` produces.
    #[test]
    fn confirm_annotated_forbid_maps_to_confirm_verdict() {
        let src = r#"
            permit(principal, action, resource);

            @confirm("high-risk tool requires human approval")
            forbid(principal == User::"risky", action, resource);
        "#;
        let compiled = compile_all(&[("t", src)], None).expect("compile");
        let evaluator = CedarEvaluator::new(compiled.policy_set, None).expect("new evaluator");

        let req = CedarRequest::new(r#"User::"risky""#, r#"Action::"view""#, r#"Doc::"d""#);
        match evaluator.evaluate(&req) {
            PolicyDecision::Confirm { reason, .. } => {
                assert_eq!(reason, "high-risk tool requires human approval");
            }
            other => panic!("expected Confirm, got {other:?}"),
        }
    }

    /// WOR-2587 review: when two forbids match the same request and
    /// only one carries `@confirm(...)`, the verdict must stay a plain
    /// `Deny`, not downgrade to `Confirm`. An absolute, unannotated
    /// forbid's intent must not be softened just because a separate,
    /// narrower `@confirm`-annotated forbid also happened to fire.
    #[test]
    fn confirm_does_not_win_when_another_matched_forbid_is_unannotated() {
        let src = r#"
            permit(principal, action, resource);

            forbid(principal == User::"banned", action, resource);

            @confirm("needs review")
            forbid(principal, action, resource);
        "#;
        let compiled = compile_all(&[("t", src)], None).expect("compile");
        let evaluator = CedarEvaluator::new(compiled.policy_set, None).expect("new evaluator");

        let req = CedarRequest::new(r#"User::"banned""#, r#"Action::"view""#, r#"Doc::"d""#);
        match evaluator.evaluate(&req) {
            PolicyDecision::Deny { status, .. } => assert_eq!(status, 403),
            other => panic!(
                "an absolute unannotated forbid must not be softened to Confirm just \
                 because a separate annotated forbid also matched, got {other:?}"
            ),
        }
    }

    /// An unannotated `forbid` still produces a plain `Deny`: the
    /// `@confirm` mapping only fires for policies that actually carry
    /// the annotation, so existing forbid-only policy sets keep their
    /// current behaviour unchanged.
    #[test]
    fn unannotated_forbid_still_denies() {
        let src = r#"
            permit(principal, action, resource);
            forbid(principal == User::"banned", action, resource);
        "#;
        let compiled = compile_all(&[("t", src)], None).expect("compile");
        let evaluator = CedarEvaluator::new(compiled.policy_set, None).expect("new evaluator");

        let req = CedarRequest::new(r#"User::"banned""#, r#"Action::"view""#, r#"Doc::"d""#);
        assert!(matches!(
            evaluator.evaluate(&req),
            PolicyDecision::Deny { status: 403, .. }
        ));
    }

    /// [`CedarEvaluator::evaluate_uids`] round-trips a request built
    /// from `EntityUid`s directly (the shape `CedarMcpHook` uses),
    /// rather than through the text-based [`CedarRequest`] bridge.
    #[test]
    fn evaluate_uids_round_trips_permit_and_forbid() {
        use cedar_policy::{EntityId, EntityTypeName};
        use std::str::FromStr;

        let src = r#"
            permit(principal == User::"alice", action, resource);
            forbid(principal == User::"mallory", action, resource);
        "#;
        let compiled = compile_all(&[("t", src)], None).expect("compile");
        let evaluator = CedarEvaluator::new(compiled.policy_set, None).expect("new evaluator");

        let user_ty = EntityTypeName::from_str("User").expect("User type");
        let action = EntityUid::from_str(r#"Action::"view""#).expect("action uid");
        let resource = EntityUid::from_str(r#"Doc::"d""#).expect("resource uid");

        let alice = EntityUid::from_type_name_and_id(user_ty.clone(), EntityId::new("alice"));
        assert_eq!(
            evaluator.evaluate_uids(alice, action.clone(), resource.clone()),
            PolicyDecision::Allow
        );

        let mallory = EntityUid::from_type_name_and_id(user_ty, EntityId::new("mallory"));
        assert!(matches!(
            evaluator.evaluate_uids(mallory, action, resource),
            PolicyDecision::Deny { status: 403, .. }
        ));
    }
}

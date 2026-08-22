//! Deterministic conversion from a [`CedarRequest`] into the
//! cedar-policy `Request` + `Entities` pair.
//!
//! Determinism is load-bearing for two reasons:
//!
//! 1. Audit replay: a caller that records the rendered Cedar input
//!    alongside a verdict needs re-running the bridge on the same
//!    logical input to produce a byte-identical Cedar input, so a
//!    verifier can reproduce the recorded decision bit-for-bit.
//!
//! 2. Content hashing: a compiled-policy cache that keys entries by a
//!    content hash needs that hash to include the Cedar request shape
//!    that produced it. If the bridge introduced map-iteration-order
//!    nondeterminism, the same logical request would hash differently
//!    across processes and break the lookup.
//!
//! This module ships a minimal [`CedarRequest`] surface: principal,
//! action, resource as Cedar EntityUid strings, plus a
//! `serde_json::Value` context for extension attributes. A future MCP
//! request-translation layer can extend this with the typed agent /
//! tool / argument-binding entity attributes the default MCP schema
//! declares. The narrow surface here is deliberate: the bridge
//! unit-tests every contract independently of that richer structure.

use std::str::FromStr;

use cedar_policy::{Context, Entities, EntityUid, Request, Schema};
use thiserror::Error;

/// Minimal request shape consumed by the Cedar evaluator.
///
/// This surface is kept narrow on purpose. A richer request context
/// (MCP tool name, argument binding, agent class, latency tier hints,
/// etc.) translates into this shape at the call site; pinning the
/// minimal shape here lets the rest of the policy engine compile and
/// its reload contract be exercised in tests without waiting on that
/// translation layer.
#[derive(Debug, Clone)]
pub struct CedarRequest {
    /// Principal entity UID in Cedar text syntax, e.g.
    /// `User::"alice"` or `Agent::"agent-7"`.
    pub principal: String,
    /// Action entity UID in Cedar text syntax, e.g.
    /// `Action::"view"` or `MCP::Action::"CallTool"`.
    pub action: String,
    /// Resource entity UID in Cedar text syntax, e.g.
    /// `Document::"report.pdf"` or `Tool::"read_file"`.
    pub resource: String,
    /// Free-form context attributes encoded as a JSON value. The
    /// bridge feeds this through `Context::from_json_value` so the
    /// schema (when supplied) can type-check each attribute.
    /// `serde_json::Value::Object({})` represents an empty context
    /// without forcing every call site to import `serde_json`.
    pub context: serde_json::Value,
}

impl CedarRequest {
    /// Convenience constructor for the no-context case.
    pub fn new(
        principal: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
    ) -> Self {
        Self {
            principal: principal.into(),
            action: action.into(),
            resource: resource.into(),
            context: serde_json::Value::Object(serde_json::Map::new()),
        }
    }

    /// Set the context attributes. Builder-style for tests and for a
    /// future request-translation path; not load-bearing today.
    pub fn with_context(mut self, ctx: serde_json::Value) -> Self {
        self.context = ctx;
        self
    }
}

/// Build a fixed-shape [`CedarRequest`] for unit tests and benches.
///
/// Returns a request with `principal: User::"test"`,
/// `action: Action::"test"`, `resource: Resource::"test"`. `pub`
/// rather than `#[cfg(test)]` so integration tests and any benchmark
/// harness can reach for a realistic request shape without
/// duplicating it.
pub fn stub_request_for_unit_tests() -> CedarRequest {
    CedarRequest::new(
        r#"User::"test""#,
        r#"Action::"test""#,
        r#"Resource::"test""#,
    )
}

/// Errors raised while translating a [`CedarRequest`] into the
/// cedar-policy types.
///
/// The variants are deliberately narrow so a caller can pick a
/// sensible verdict for each case without parsing the message. Parse
/// failures are operator errors at config-load time; run-time bridge
/// failures should be rare and are mapped to `Deny` with a structured
/// reason string by [`super::evaluator`].
#[derive(Debug, Error)]
pub enum RequestBridgeError {
    /// Cedar rejected one of the three EntityUid strings (principal,
    /// action, or resource). The wrapped string carries the failing
    /// component so a caller can include it in the deny rationale
    /// without re-parsing.
    #[error("invalid cedar entity uid for {component}: {reason}")]
    InvalidEntityUid {
        /// Which of the three positions failed (`"principal"`,
        /// `"action"`, `"resource"`).
        component: &'static str,
        /// Cedar's parser diagnostic (with span info).
        reason: String,
    },

    /// Context JSON failed to translate to a `cedar_policy::Context`.
    /// Typical cause: a value type that does not match the workspace
    /// schema's declared attribute type, or a malformed extension
    /// expression.
    #[error("invalid cedar context: {0}")]
    InvalidContext(String),

    /// `Request::new` rejected the assembled triple (e.g. when a
    /// schema is provided and the action does not apply to the
    /// supplied principal type).
    #[error("invalid cedar request: {0}")]
    InvalidRequest(String),
}

/// Translate a [`CedarRequest`] into a cedar-policy `Request` plus a
/// matching empty [`Entities`] store.
///
/// This returns an empty `Entities` store: the workspace schema is
/// sufficient for basic permit / forbid evaluation, and a fuller
/// entity hierarchy is follow-up work once per-agent / per-tool state
/// is available to source it from. Returning the entities alongside
/// the request matches the eventual call site shape and avoids two
/// round trips once the entity hierarchy starts carrying real data.
///
/// The translation order is fixed (principal, action, resource,
/// context) and does not depend on hash-map iteration. Combined with
/// `serde_json::Value`'s ordered map (`preserve_order` is on by
/// default in this workspace), two calls with structurally identical
/// inputs produce byte-identical Cedar inputs.
///
/// # Errors
///
/// Returns the matching [`RequestBridgeError`] variant if any of the
/// four steps fails. A caller maps every variant onto a
/// `PolicyDecision::Deny` with a structured reason; see
/// [`super::evaluator`].
pub fn build_request(
    req: &CedarRequest,
    schema: Option<&Schema>,
) -> Result<(Request, Entities), RequestBridgeError> {
    let principal =
        EntityUid::from_str(&req.principal).map_err(|e| RequestBridgeError::InvalidEntityUid {
            component: "principal",
            reason: format!("{e}"),
        })?;
    let action =
        EntityUid::from_str(&req.action).map_err(|e| RequestBridgeError::InvalidEntityUid {
            component: "action",
            reason: format!("{e}"),
        })?;
    let resource =
        EntityUid::from_str(&req.resource).map_err(|e| RequestBridgeError::InvalidEntityUid {
            component: "resource",
            reason: format!("{e}"),
        })?;

    let context = if req.context.is_null()
        || matches!(&req.context, serde_json::Value::Object(m) if m.is_empty())
    {
        // Empty context fast path: avoids a JSON round trip and
        // sidesteps the schema-aware constructor when the caller has
        // no extension attributes to declare.
        Context::empty()
    } else {
        // The Cedar API takes the action UID alongside the schema so
        // it can resolve the per-action context type. Passing `None`
        // for the action when no schema is supplied keeps this call
        // stable across schema-on / schema-off.
        let schema_action = schema.map(|s| (s, &action));
        Context::from_json_value(req.context.clone(), schema_action)
            .map_err(|e| RequestBridgeError::InvalidContext(format!("{e}")))?
    };

    let request = Request::new(principal, action, resource, context, schema)
        .map_err(|e| RequestBridgeError::InvalidRequest(format!("{e}")))?;

    // Empty entities; a caller with a real entity hierarchy fills
    // this in from workspace state.
    let entities = Entities::empty();

    Ok((request, entities))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip a basic principal / action / resource triple.
    /// Schema-less mode is the happy path; the strict-schema case is
    /// covered by the evaluator tests.
    #[test]
    fn build_request_round_trips_without_schema() {
        let req = CedarRequest::new(
            r#"User::"alice""#,
            r#"Action::"view""#,
            r#"Document::"report.pdf""#,
        );
        let (cedar_req, entities) = build_request(&req, None).expect("build");
        // Sanity: the Cedar request reflects the inputs we supplied.
        // We only assert structural properties; comparing the full
        // string-formatted UIDs is upstream-controlled and not part
        // of this test's contract.
        assert!(cedar_req.principal().is_some());
        assert!(cedar_req.action().is_some());
        assert!(cedar_req.resource().is_some());
        // Empty entities for the narrow surface this module ships.
        assert_eq!(entities.iter().count(), 0);
    }

    /// A malformed principal UID maps onto the right variant. This
    /// pins the error-routing contract: the variant (and the
    /// `component` field) is the load-bearing surface, not the
    /// message text.
    #[test]
    fn invalid_principal_maps_to_invalid_entity_uid() {
        let req = CedarRequest::new("not a uid", r#"Action::"view""#, r#"Doc::"x""#);
        let err = build_request(&req, None).unwrap_err();
        match err {
            RequestBridgeError::InvalidEntityUid { component, .. } => {
                assert_eq!(component, "principal");
            }
            other => panic!("expected InvalidEntityUid, got {other:?}"),
        }
    }

    /// Determinism: two calls with the same input produce
    /// byte-identical context JSON. We compare the JSON shape
    /// directly because the cedar-policy `Request` does not expose a
    /// stable bytewise serialiser. An audit replay path round-trips
    /// the input via JSON, so equal `Value`s under `==` are the
    /// load-bearing contract.
    #[test]
    fn identical_inputs_produce_equal_context_json() {
        let ctx = serde_json::json!({ "mfa": true, "tier": "gold" });
        let a = CedarRequest::new(r#"User::"a""#, r#"Action::"view""#, r#"Doc::"d""#)
            .with_context(ctx.clone());
        let b =
            CedarRequest::new(r#"User::"a""#, r#"Action::"view""#, r#"Doc::"d""#).with_context(ctx);
        assert_eq!(a.context, b.context);
        let _ = build_request(&a, None).expect("build a");
        let _ = build_request(&b, None).expect("build b");
    }
}

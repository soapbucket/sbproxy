//! A2A protocol envelope.
//!
//! The module exposes the shared `A2AContext` populated by the
//! request filter and the detection function that runs before
//! either spec parser. Parsers live behind feature flags so the
//! default OSS build compiles detection only and treats matched
//! requests as plain POSTs.

#[cfg(feature = "a2a-anthropic")]
pub mod anthropic;
#[cfg(feature = "a2a-google")]
pub mod google;

use serde::{Deserialize, Serialize};

/// Closed enum of the A2A specs the proxy understands.
///
/// New variants extend the wire envelope (closed-enum
/// amendment rules). Today both variants carry the `v0` designation
/// because the upstream drafts are unstable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum A2ASpec {
    /// Anthropic A2A draft (`draft-anthropic-a2a-v0`). Modeled as an
    /// MCP method (`agents.invoke`).
    AnthropicV0,
    /// Google A2A draft (`draft-google-a2a-v0`). Dedicated content
    /// type `application/a2a+json`.
    GoogleV0,
}

impl A2ASpec {
    /// Stable label used in metrics and audit events.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::AnthropicV0 => "anthropic-v0",
            Self::GoogleV0 => "google-v0",
        }
    }
}

/// One hop in the A2A call chain. The chain is ordered oldest first
/// so `chain[0]` is the chain root and `chain[chain_depth - 1]` is
/// the immediate caller of this hop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainHop {
    /// Resolved agent identifier of the hop. The string form mirrors
    /// the catalog `id` values produced by the agent-class resolver.
    pub agent_id: String,
    /// Per-hop request id (the request id of the hop, not the parent).
    pub request_id: String,
    /// Wall-clock timestamp the hop was observed, in milliseconds since
    /// the unix epoch. Zero when the wire envelope omits it; downstream
    /// pipelines treat zero as `unknown`.
    pub timestamp_ms: u64,
}

/// Per-request A2A envelope, populated once in the request filter.
///
/// Fields use zero / empty defaults when the wire envelope omits them
/// so the policy module can run on partial data; the request filter
/// records an audit event when fields are missing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2AContext {
    /// Which spec this envelope was decoded under.
    pub spec: A2ASpec,
    /// Resolved agent id of the caller (the agent that initiated the
    /// hop). String form mirrors the agent-class resolver output.
    pub caller_agent_id: String,
    /// Resolved agent id of the callee, when the parser could
    /// determine it from the envelope. None when the callee is
    /// implied by routing alone.
    pub callee_agent_id: Option<String>,
    /// Opaque caller-assigned task identifier. Joins the audit
    /// pipeline; never used as a metric label.
    pub task_id: String,
    /// Request id of the parent hop (the hop that called this one).
    /// None for the chain root.
    pub parent_request_id: Option<String>,
    /// 1 for the first hop, +1 per nested call. Capped at 32 by the
    /// policy module.
    pub chain_depth: u32,
    /// Full ancestor chain, oldest first. Empty for the chain root.
    pub chain: Vec<ChainHop>,
    /// Free-form spec-version string (e.g. `"anthropic-v0"`,
    /// `"google-v0"`). Surfaced to the audit event verbatim so
    /// reconstructions across spec rev bumps stay debuggable.
    pub raw_envelope_version: String,
    /// Whether the identity fields on this envelope came from a source
    /// the proxy trusts.
    ///
    /// False means the fields were either absent or supplied by an
    /// untrusted peer and therefore discarded. The distinction matters:
    /// an untrusted caller that simply omits `x-a2a-chain` is
    /// indistinguishable from a genuine chain root, so a policy that
    /// wants to fail closed on unknown identity needs this flag rather
    /// than inferring trust from `chain_depth == 1`.
    ///
    /// Set by [`envelope_from_headers`] from the caller's trust
    /// decision; body parsers leave it false because a request body is
    /// no more trustworthy than the headers that framed it.
    pub identity_verified: bool,
}

impl A2AContext {
    /// Build an empty (zero-default) context for the given spec.
    /// Useful when detection succeeded but parsing produced no fields,
    /// so the policy module can still apply route-level limits.
    pub fn empty(spec: A2ASpec) -> Self {
        Self {
            spec,
            caller_agent_id: String::new(),
            callee_agent_id: None,
            task_id: String::new(),
            parent_request_id: None,
            chain_depth: 1,
            chain: Vec::new(),
            raw_envelope_version: spec.as_label().to_string(),
            identity_verified: false,
        }
    }
}

/// Build an [`A2AContext`] from the `x-a2a-*` request headers, honoring
/// them only when the immediate peer is trusted.
///
/// `peer_trusted` MUST be the same trust decision the request filter
/// makes from `proxy.trusted_proxies`. When it is false every
/// `x-a2a-*` field is discarded and the returned envelope is the
/// zero-default for `spec` with [`A2AContext::identity_verified`]
/// clear.
///
/// This is the security boundary for the header transport. The fields
/// feed `caller_denylist`, `callee_allowlist`, and cycle detection, so
/// honoring them from an arbitrary client lets that client name itself,
/// name its callee, and assert its own call chain.
pub fn envelope_from_headers(
    headers: &http::HeaderMap,
    spec: A2ASpec,
    peer_trusted: bool,
) -> A2AContext {
    let mut ctx = A2AContext::empty(spec);
    if !peer_trusted {
        return ctx;
    }
    ctx.identity_verified = true;

    let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());

    if let Some(v) = get("x-a2a-caller-agent-id") {
        ctx.caller_agent_id = v.to_string();
    }
    if let Some(v) = get("x-a2a-callee-agent-id") {
        ctx.callee_agent_id = Some(v.to_string());
    }
    if let Some(v) = get("x-a2a-task-id") {
        ctx.task_id = v.to_string();
    }
    if let Some(v) = get("x-a2a-parent-request-id") {
        ctx.parent_request_id = Some(v.to_string());
    }
    if let Some(v) = get("x-a2a-chain-depth").and_then(|s| s.parse::<u32>().ok()) {
        ctx.chain_depth = v.max(1);
    }
    if let Some(parsed) =
        get("x-a2a-chain").and_then(|raw| serde_json::from_str::<Vec<ChainHop>>(raw).ok())
    {
        ctx.chain = parsed;
    }

    ctx
}

/// Walk the [RFC 8693] `act` (actor) delegation chain out of a set of
/// already-verified token claims.
///
/// Returns the actor subjects **oldest first**, matching the ordering
/// of [`A2AContext::chain`]. RFC 8693 nests the chain the other way
/// round: the outermost `act` is the current actor and each nested
/// `act` is a prior actor, so this reverses as it unwinds.
///
/// An actor level with no `sub` still counts as a hop. Skipping it
/// would let a malformed token shorten its own apparent chain, which is
/// the exact evasion the depth cap exists to stop.
///
/// The caller is responsible for having verified the token's signature;
/// this reads claims and does not authenticate them.
///
/// [RFC 8693]: https://datatracker.ietf.org/doc/html/rfc8693#section-4.1
pub fn chain_from_act_claims(claims: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    let mut newest_first = Vec::new();
    let mut cur = claims.get("act");
    while let Some(act) = cur {
        newest_first.push(
            act.get("sub")
                .and_then(|s| s.as_str())
                .unwrap_or_default()
                .to_string(),
        );
        cur = act.get("act");
    }
    newest_first.reverse();
    newest_first
}

/// Overlay a verified [RFC 8693] `act` delegation chain onto an
/// envelope, replacing whatever the transport claimed.
///
/// This is what makes `max_chain_depth` and cycle detection meaningful
/// against a hostile caller. The header transport is forgeable in the
/// shallow direction: a caller that asserts `x-a2a-chain-depth: 1`, or
/// simply omits it, lands on depth 1 and clears any cap. A signed token
/// cannot be flattened that way, so when the token carries a chain it
/// overrides the envelope and marks the identity verified.
///
/// A token with no `act` chain is left alone rather than treated as an
/// assertion of depth 1. "The token says nothing about delegation" and
/// "the token says this is the first hop" are different facts, and
/// collapsing them would reintroduce the evasion through the back door.
///
/// `claims` must already be signature-verified.
///
/// [RFC 8693]: https://datatracker.ietf.org/doc/html/rfc8693#section-4.1
pub fn apply_verified_act_chain(
    ctx: &mut A2AContext,
    claims: &serde_json::Map<String, serde_json::Value>,
) {
    let actors = chain_from_act_claims(claims);
    if actors.is_empty() {
        return;
    }

    // The most recent actor is the agent making this call.
    if let Some(current) = actors.last() {
        ctx.caller_agent_id = current.clone();
    }
    // Depth counts the hops that led here plus this one, matching the
    // `chain.len() + 1` convention the body parsers use.
    ctx.chain_depth = (actors.len() as u32).saturating_add(1);
    ctx.chain = actors
        .into_iter()
        .map(|agent_id| ChainHop {
            agent_id,
            // The token carries identity, not per-hop request ids or
            // timestamps. Downstream reads empty / zero as unknown.
            request_id: String::new(),
            timestamp_ms: 0,
        })
        .collect();
    ctx.identity_verified = true;
}

/// Detection signal: which spec a request appears to be A2A under.
/// `None` means "not an A2A request, fall through to the regular
/// HTTP path".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedSpec {
    /// Anthropic A2A path (MCP method).
    Anthropic,
    /// Google A2A path (dedicated content type).
    Google,
    /// Operator escape hatch (`a2a.route_glob`); the spec is
    /// indeterminate but the request is still A2A traffic.
    OperatorRoute,
}

impl DetectedSpec {
    /// Map the detection signal back to a spec for context construction.
    /// `OperatorRoute` defaults to `GoogleV0` because the operator
    /// escape hatch is most commonly used for Google-shaped envelopes.
    pub fn to_spec(self) -> A2ASpec {
        match self {
            Self::Anthropic => A2ASpec::AnthropicV0,
            Self::Google | Self::OperatorRoute => A2ASpec::GoogleV0,
        }
    }
}

/// Detect whether a request looks like A2A traffic.
///
/// Runs once per request, before any policy evaluation. Returns the
/// matched detection signal, or `None` for plain HTTP requests. The
/// function does not parse the body; parsing is deferred to the
/// feature-gated parsers.
///
/// Detection cases (per ADR § "Detection"):
///
/// 1. `Content-Type: application/a2a+json` (with optional `; version=*`)
///    triggers Google detection.
/// 2. `MCP-Method: agents.invoke` triggers Anthropic detection.
/// 3. The path matching `route_glob` is the operator escape hatch.
pub fn detect(
    headers: &http::HeaderMap,
    path: &str,
    route_glob: Option<&str>,
) -> Option<DetectedSpec> {
    if let Some(ct) = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    {
        let lower = ct.to_ascii_lowercase();
        // Match on the bare type or `application/a2a+json; version=*`.
        let bare = lower.split(';').next().unwrap_or("").trim();
        if bare == "application/a2a+json" {
            return Some(DetectedSpec::Google);
        }
    }

    if let Some(method) = headers.get("mcp-method").and_then(|v| v.to_str().ok()) {
        if method.trim().eq_ignore_ascii_case("agents.invoke") {
            return Some(DetectedSpec::Anthropic);
        }
    }

    if let Some(glob) = route_glob {
        if glob_matches(glob, path) {
            return Some(DetectedSpec::OperatorRoute);
        }
    }

    None
}

/// Tiny glob matcher supporting `*` (single segment) and `**` (any
/// suffix). Used for the operator route escape hatch and the policy
/// allowlist matcher; standalone so the policy module does not pull
/// a regex dep just for path matching.
pub(crate) fn glob_matches(glob: &str, path: &str) -> bool {
    if glob == "**" || glob == "*" {
        return true;
    }
    if let Some(prefix) = glob.strip_suffix("/**") {
        return path == prefix || path.starts_with(&format!("{prefix}/"));
    }
    if let Some(prefix) = glob.strip_suffix('*') {
        return path.starts_with(prefix);
    }
    glob == path
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                http::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn detect_returns_none_for_plain_request() {
        let h = headers(&[("content-type", "application/json")]);
        assert_eq!(detect(&h, "/api/x", None), None);
    }

    #[test]
    fn detect_google_via_content_type() {
        let h = headers(&[("content-type", "application/a2a+json")]);
        assert_eq!(detect(&h, "/", None), Some(DetectedSpec::Google));
    }

    #[test]
    fn detect_google_via_content_type_with_version_param() {
        let h = headers(&[("content-type", "application/a2a+json; version=1")]);
        assert_eq!(detect(&h, "/", None), Some(DetectedSpec::Google));
    }

    #[test]
    fn detect_google_is_case_insensitive() {
        let h = headers(&[("content-type", "Application/A2A+JSON")]);
        assert_eq!(detect(&h, "/", None), Some(DetectedSpec::Google));
    }

    #[test]
    fn detect_anthropic_via_mcp_method() {
        let h = headers(&[("mcp-method", "agents.invoke")]);
        assert_eq!(detect(&h, "/", None), Some(DetectedSpec::Anthropic));
    }

    #[test]
    fn detect_anthropic_other_methods_ignored() {
        let h = headers(&[("mcp-method", "tools.list")]);
        assert_eq!(detect(&h, "/", None), None);
    }

    #[test]
    fn detect_operator_route_glob_matches_prefix() {
        let h = headers(&[]);
        assert_eq!(
            detect(&h, "/agents/invoke", Some("/agents/**")),
            Some(DetectedSpec::OperatorRoute)
        );
    }

    #[test]
    fn detect_content_type_takes_precedence_over_glob() {
        let h = headers(&[("content-type", "application/a2a+json")]);
        assert_eq!(
            detect(&h, "/agents/x", Some("/agents/**")),
            Some(DetectedSpec::Google)
        );
    }

    #[test]
    fn glob_matches_supports_double_star() {
        assert!(glob_matches("/api/**", "/api/v1/x"));
        assert!(glob_matches("/api/**", "/api"));
        assert!(!glob_matches("/api/**", "/other"));
    }

    #[test]
    fn glob_matches_supports_prefix_star() {
        assert!(glob_matches("/foo*", "/foobar"));
        assert!(!glob_matches("/foo*", "/bar"));
    }

    #[test]
    fn glob_matches_exact() {
        assert!(glob_matches("/exact", "/exact"));
        assert!(!glob_matches("/exact", "/exact/x"));
    }

    #[test]
    fn empty_context_uses_sensible_defaults() {
        let ctx = A2AContext::empty(A2ASpec::GoogleV0);
        assert_eq!(ctx.chain_depth, 1);
        assert!(ctx.chain.is_empty());
        assert_eq!(ctx.raw_envelope_version, "google-v0");
    }

    /// Every `x-a2a-*` field an untrusted caller can set. Used by the
    /// trust-gate tests below so both directions cover the same surface.
    fn forged_envelope_headers() -> http::HeaderMap {
        headers(&[
            ("x-a2a-caller-agent-id", "billing-orchestrator"),
            ("x-a2a-callee-agent-id", "payments-agent"),
            ("x-a2a-task-id", "task-42"),
            ("x-a2a-parent-request-id", "req-41"),
            ("x-a2a-chain-depth", "1"),
            (
                "x-a2a-chain",
                r#"[{"agent_id":"a","request_id":"r","timestamp_ms":1}]"#,
            ),
        ])
    }

    #[test]
    fn envelope_from_untrusted_peer_ignores_forged_identity_headers() {
        let ctx = envelope_from_headers(&forged_envelope_headers(), A2ASpec::GoogleV0, false);

        // An untrusted caller must not be able to name itself, name its
        // callee, or assert a chain. Those three feed `caller_denylist`,
        // `callee_allowlist`, and cycle detection respectively.
        assert_eq!(ctx.caller_agent_id, "");
        assert_eq!(ctx.callee_agent_id, None);
        assert!(ctx.chain.is_empty());
    }

    #[test]
    fn envelope_from_trusted_peer_honors_identity_headers() {
        let ctx = envelope_from_headers(&forged_envelope_headers(), A2ASpec::GoogleV0, true);

        assert_eq!(ctx.caller_agent_id, "billing-orchestrator");
        assert_eq!(ctx.callee_agent_id, Some("payments-agent".to_string()));
        assert_eq!(ctx.task_id, "task-42");
        assert_eq!(ctx.chain.len(), 1);
    }

    /// Claims for a token delegated twice: `orchestrator` acted for the
    /// original subject, then `worker` acted on top of that.
    ///
    /// Per RFC 8693 the OUTERMOST `act` is the current actor and nested
    /// `act` claims are prior actors, so this reads worker-then-
    /// orchestrator on the wire and must come back oldest-first.
    fn delegated_claims() -> serde_json::Map<String, serde_json::Value> {
        match serde_json::json!({
            "sub": "user-1",
            "act": {
                "sub": "worker",
                "act": { "sub": "orchestrator" }
            }
        }) {
            serde_json::Value::Object(m) => m,
            _ => unreachable!(),
        }
    }

    #[test]
    fn act_chain_is_returned_oldest_first() {
        // Oldest-first matches `A2AContext::chain` ordering, where
        // chain[0] is the root. Reversing this silently breaks cycle
        // detection, so the order is pinned here deliberately.
        assert_eq!(
            chain_from_act_claims(&delegated_claims()),
            vec!["orchestrator".to_string(), "worker".to_string()]
        );
    }

    #[test]
    fn act_chain_is_empty_for_an_undelegated_token() {
        let claims = match serde_json::json!({ "sub": "user-1" }) {
            serde_json::Value::Object(m) => m,
            _ => unreachable!(),
        };
        assert!(chain_from_act_claims(&claims).is_empty());
    }

    #[test]
    fn act_chain_skips_actor_levels_with_no_subject() {
        // A malformed actor level must not silently shorten the chain
        // into a passing depth; it still counts as a hop.
        let claims = match serde_json::json!({
            "sub": "user-1",
            "act": { "act": { "sub": "orchestrator" } }
        }) {
            serde_json::Value::Object(m) => m,
            _ => unreachable!(),
        };
        assert_eq!(chain_from_act_claims(&claims).len(), 2);
    }

    #[test]
    fn verified_act_chain_overrides_a_forged_shallow_depth() {
        // The evasion this closes: an untrusted caller asserts depth 1
        // (or omits the header entirely, which lands on the same
        // default) and sails past `max_chain_depth`. The token says
        // otherwise, and the token wins.
        let mut ctx = A2AContext::empty(A2ASpec::GoogleV0);
        ctx.chain_depth = 1;

        apply_verified_act_chain(&mut ctx, &delegated_claims());

        assert_eq!(ctx.chain_depth, 3, "two actors plus this hop");
        assert!(ctx.identity_verified);
    }

    #[test]
    fn verified_act_chain_populates_chain_for_cycle_detection() {
        let mut ctx = A2AContext::empty(A2ASpec::GoogleV0);

        apply_verified_act_chain(&mut ctx, &delegated_claims());

        let ids: Vec<&str> = ctx.chain.iter().map(|h| h.agent_id.as_str()).collect();
        assert_eq!(ids, vec!["orchestrator", "worker"]);
    }

    #[test]
    fn verified_act_chain_sets_caller_to_the_most_recent_actor() {
        let mut ctx = A2AContext::empty(A2ASpec::GoogleV0);
        ctx.caller_agent_id = "spoofed".to_string();

        apply_verified_act_chain(&mut ctx, &delegated_claims());

        assert_eq!(ctx.caller_agent_id, "worker");
    }

    #[test]
    fn undelegated_token_leaves_the_envelope_alone() {
        let claims = match serde_json::json!({ "sub": "user-1" }) {
            serde_json::Value::Object(m) => m,
            _ => unreachable!(),
        };
        let mut ctx = A2AContext::empty(A2ASpec::GoogleV0);
        ctx.chain_depth = 4;

        apply_verified_act_chain(&mut ctx, &claims);

        // No `act` chain means the token says nothing about delegation.
        // It must not be read as an assertion that depth is 1.
        assert_eq!(ctx.chain_depth, 4);
        assert!(!ctx.identity_verified);
    }

    #[test]
    fn envelope_from_untrusted_peer_marks_identity_unverified() {
        let trusted = envelope_from_headers(&forged_envelope_headers(), A2ASpec::GoogleV0, true);
        let untrusted = envelope_from_headers(&forged_envelope_headers(), A2ASpec::GoogleV0, false);

        // The policy needs to tell "no chain was asserted" apart from
        // "a chain was asserted but we do not trust it", so it can deny
        // on unknown identity rather than silently treating the caller
        // as a chain root.
        assert!(trusted.identity_verified);
        assert!(!untrusted.identity_verified);
    }

    #[test]
    fn spec_label_round_trips() {
        assert_eq!(A2ASpec::AnthropicV0.as_label(), "anthropic-v0");
        assert_eq!(A2ASpec::GoogleV0.as_label(), "google-v0");
    }

    #[test]
    fn detected_spec_maps_to_spec() {
        assert_eq!(DetectedSpec::Anthropic.to_spec(), A2ASpec::AnthropicV0);
        assert_eq!(DetectedSpec::Google.to_spec(), A2ASpec::GoogleV0);
        assert_eq!(DetectedSpec::OperatorRoute.to_spec(), A2ASpec::GoogleV0);
    }
}

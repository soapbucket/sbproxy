//! A2A policy conformance tests (Wave 7 / Q7.3).
//!
//! Boots a harness origin configured with the `a2a` policy and
//! drives detection + denial paths end-to-end. Coverage:
//!
//! * Detection by `Content-Type: application/a2a+json` (Google).
//! * Detection by `MCP-Method: agents.invoke` (Anthropic).
//! * Detection in graceful-degradation mode (parsers off; OSS default).
//! * Chain-depth cap denial (429 with Retry-After: 0 + JSON body).
//! * Cycle detection in the three modes (`strict`, `by_agent_id`,
//!   `by_callable_endpoint`).
//! * Callee allowlist (403).
//! * Caller denylist (403).
//! * Tolerance for partial / missing envelope fields.
//! * The trust gate on the header transport: an untrusted peer's
//!   `x-a2a-*` headers are ignored by the policy AND stripped before
//!   the upstream sees them.
//! * A signed `act` delegation chain outranking a forged shallow
//!   `x-a2a-chain-depth`.
//!
//! All envelope fields are passed through `X-A2A-*` headers so the
//! tests do not depend on the feature-flagged body parsers.
//!
//! Those headers are only read when the immediate peer sits inside
//! `proxy.trusted_proxies`, so every config below states its trust
//! boundary explicitly rather than inheriting one. See
//! [`a2a_config`] for why that matters.

use jsonwebtoken::{encode, EncodingKey, Header};
use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde::Serialize;
use serde_json::json;

// --- Config helpers ---

/// Loopback trust boundary: the harness client on 127.0.0.1 is inside
/// it, so the `x-a2a-*` envelope headers are honoured.
const TRUST_INCLUDES_CLIENT: &str = r#"    - "127.0.0.0/8"
    - "::1/128""#;

/// A trust boundary the harness client can never fall inside.
/// `192.0.2.0/24` is RFC 5737 TEST-NET-1: a real, parseable range
/// reserved for documentation, which keeps the config valid while
/// leaving the loopback client outside the boundary.
const TRUST_EXCLUDES_CLIENT: &str = r#"    - "192.0.2.0/24""#;

/// Origin-level `authentication` block used by the delegation-chain
/// test. HS256 against a literal shared secret, matching `auth_jwt.rs`.
const JWT_AUTH_BLOCK: &str = "    authentication:
      type: jwt
      secret: shared-secret-abc
      algorithms: [HS256]
";

/// Shared secret for the minted delegation tokens.
const JWT_SECRET: &str = "shared-secret-abc";

/// The six envelope headers the transport carries. Kept in one place so
/// the forge-and-strip tests cover exactly the set
/// `request_phase.rs` removes from an untrusted peer.
const ENVELOPE_HEADERS: [&str; 6] = [
    "x-a2a-caller-agent-id",
    "x-a2a-callee-agent-id",
    "x-a2a-task-id",
    "x-a2a-parent-request-id",
    "x-a2a-chain-depth",
    "x-a2a-chain",
];

/// Build the suite's config from a trust boundary, an optional
/// origin-level block, and the `a2a` policy fields.
///
/// `trust_cidrs`, `origin_extra`, and `policy_fields` are spliced in
/// pre-indented, so callers write them the way they appear in YAML.
///
/// `proxy.trusted_proxies` is authored here, in the single place the
/// whole file routes through, because it is the precondition for most
/// of the suite. The envelope headers are only read from a peer inside
/// that list: from anyone else `envelope_from_headers` returns the
/// zero-default envelope (depth 1, no caller, no callee, empty chain)
/// and the request filter deletes the headers on ingress. A denial test
/// run against an untrusted peer therefore observes nothing to deny and
/// passes with a 200 while asserting on a control that never fired.
///
/// The harness's `inject_port` supplies the same loopback range when a
/// config omits the field, so on the trusted path this is belt and
/// braces. It is spelled out anyway: a default applied in the harness
/// is invisible from here, and it is the load-bearing precondition for
/// six denial assertions in this file.
fn a2a_config(
    upstream_url: &str,
    trust_cidrs: &str,
    origin_extra: &str,
    policy_fields: &str,
) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  trusted_proxies:
{trust_cidrs}
origins:
  "a2a.localhost":
    action:
      type: proxy
      url: "{upstream_url}"
{origin_extra}    policies:
      - type: a2a
{policy_fields}
"#
    )
}

/// Config whose trust boundary contains the harness client, so the
/// `x-a2a-*` envelope headers are honoured.
fn trusted_peer_config(upstream_url: &str, policy_fields: &str) -> String {
    a2a_config(upstream_url, TRUST_INCLUDES_CLIENT, "", policy_fields)
}

/// Config whose trust boundary excludes the harness client, so the
/// `x-a2a-*` envelope headers are discarded and stripped.
fn untrusted_peer_config(upstream_url: &str, policy_fields: &str) -> String {
    a2a_config(upstream_url, TRUST_EXCLUDES_CLIENT, "", policy_fields)
}

fn config_default(upstream_url: &str) -> String {
    trusted_peer_config(
        upstream_url,
        "        max_chain_depth: 5
        cycle_detection: by_agent_id",
    )
}

fn config_strict_cycle(upstream_url: &str) -> String {
    trusted_peer_config(
        upstream_url,
        "        max_chain_depth: 5
        cycle_detection: strict",
    )
}

fn config_by_endpoint(upstream_url: &str) -> String {
    trusted_peer_config(
        upstream_url,
        "        max_chain_depth: 5
        cycle_detection: by_callable_endpoint",
    )
}

fn config_with_allowlist(upstream_url: &str) -> String {
    trusted_peer_config(
        upstream_url,
        r#"        max_chain_depth: 5
        callee_allowlist:
          - "agent:openai:gpt-5"
          - "agent:anthropic:claude-4""#,
    )
}

fn config_with_denylist(upstream_url: &str) -> String {
    trusted_peer_config(
        upstream_url,
        r#"        caller_denylist:
          - "agent:bad:actor""#,
    )
}

fn config_low_depth(upstream_url: &str) -> String {
    trusted_peer_config(upstream_url, "        max_chain_depth: 2")
}

/// Every control this suite configures, on one route. Used by the
/// trust-gate test so the trusted and untrusted runs differ in the
/// trust boundary alone.
const ALL_CONTROLS_POLICY: &str = r#"        max_chain_depth: 2
        cycle_detection: by_agent_id
        callee_allowlist:
          - "agent:openai:gpt-5"
        caller_denylist:
          - "agent:bad:actor""#;

/// Permissive policy for the strip test: the point there is what the
/// upstream received, so nothing must deny before the request gets
/// there on either side of the boundary.
const PERMISSIVE_POLICY: &str = "        max_chain_depth: 5
        cycle_detection: by_agent_id";

/// Delegation-chain config: JWT auth so the policy sees verified
/// claims, and a depth cap of 2 so a two-actor `act` chain trips it.
fn config_jwt_depth_2(upstream_url: &str, trust_cidrs: &str) -> String {
    a2a_config(
        upstream_url,
        trust_cidrs,
        JWT_AUTH_BLOCK,
        "        max_chain_depth: 2",
    )
}

// --- Header helpers ---

fn google_headers() -> Vec<(&'static str, &'static str)> {
    vec![("content-type", "application/a2a+json")]
}

fn anthropic_headers() -> Vec<(&'static str, &'static str)> {
    vec![("mcp-method", "agents.invoke")]
}

// --- Token helpers ---

/// Claim shape for the delegation tests. `act` is left out of the
/// encoded payload when absent so "the token says nothing about
/// delegation" stays distinguishable from "the token asserts an empty
/// chain"; the two are treated differently by
/// `apply_verified_act_chain`.
#[derive(Serialize)]
struct DelegationClaims {
    sub: String,
    exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    act: Option<serde_json::Value>,
}

/// Far-future expiry (year 2286) so the token never starts flaking on
/// a long-lived release branch.
const FAR_FUTURE_EXP: i64 = 9_999_999_999;

fn mint(act: Option<serde_json::Value>) -> String {
    encode(
        &Header::default(),
        &DelegationClaims {
            sub: "user-1".to_string(),
            exp: FAR_FUTURE_EXP,
            act,
        },
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .expect("jwt encode")
}

/// A token delegated twice. Per RFC 8693 the outermost `act` is the
/// current actor and each nested `act` is a prior one, so this is
/// `orchestrator` then `worker`: two actors, and with this hop a chain
/// depth of 3.
fn token_delegated_twice() -> String {
    mint(Some(json!({
        "sub": "worker",
        "act": { "sub": "orchestrator" }
    })))
}

/// A valid token that asserts no delegation at all.
fn token_undelegated() -> String {
    mint(None)
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

// --- Tests ---

#[test]
fn detection_via_content_type_passes_to_upstream() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_default(&upstream.base_url())).expect("start");

    // A2A request with depth 1, no callee. The default config has no
    // allowlist / denylist, so it should pass through.
    let resp = harness
        .get_with_headers(
            "/agents/invoke",
            "a2a.localhost",
            &[
                ("content-type", "application/a2a+json"),
                ("x-a2a-caller-agent-id", "agent:caller"),
                ("x-a2a-task-id", "task-1"),
                ("x-a2a-chain-depth", "1"),
            ],
        )
        .expect("send");
    assert_eq!(resp.status, 200, "default config allows depth=1");
}

#[test]
fn detection_via_mcp_method_passes_to_upstream() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_default(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers(
            "/mcp/x",
            "a2a.localhost",
            &[
                ("mcp-method", "agents.invoke"),
                ("x-a2a-caller-agent-id", "agent:caller"),
                ("x-a2a-chain-depth", "1"),
            ],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
}

#[test]
fn graceful_degradation_when_parsers_off() {
    // Parsers are off in the OSS default build. Detection still
    // populates a zero-default A2AContext so the policy can apply
    // route-level limits even without parser data.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_low_depth(&upstream.base_url())).expect("start");

    // Detected as A2A (content-type), no envelope headers => zero
    // default depth = 1, which is below the configured cap of 2 =>
    // request passes.
    let mut headers = google_headers();
    headers.push(("x-a2a-caller-agent-id", "agent:caller"));
    let resp = harness
        .get_with_headers("/", "a2a.localhost", &headers)
        .expect("send");
    assert_eq!(
        resp.status, 200,
        "detection-only path with default depth=1 must pass when limit=2"
    );
}

#[test]
fn chain_depth_exceeded_returns_429() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_low_depth(&upstream.base_url())).expect("start");

    // Limit is 2; we send depth=5 to force a denial. The config puts
    // the client inside `proxy.trusted_proxies`, which is what makes
    // the depth header readable at all.
    let resp = harness
        .get_with_headers(
            "/agents/invoke",
            "a2a.localhost",
            &[
                ("content-type", "application/a2a+json"),
                ("x-a2a-caller-agent-id", "agent:caller"),
                ("x-a2a-callee-agent-id", "agent:b"),
                ("x-a2a-chain-depth", "5"),
            ],
        )
        .expect("send");
    assert_eq!(resp.status, 429, "depth exceeded must return 429");
    assert_eq!(
        resp.headers.get("retry-after").map(String::as_str),
        Some("0"),
        "depth denial must stamp Retry-After: 0"
    );
    let body: serde_json::Value = resp.json().expect("json body");
    assert_eq!(body["error"], "a2a_chain_depth_exceeded");
    assert_eq!(body["limit"], 2);
    assert_eq!(body["depth"], 5);
}

#[test]
fn cycle_by_agent_id_returns_409() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_default(&upstream.base_url())).expect("start");

    // Chain already contains agent:b; calling agent:b again is a cycle.
    let chain = json!([
        {"agent_id": "agent:root", "request_id": "r-root", "timestamp_ms": 100},
        {"agent_id": "agent:b", "request_id": "r-b", "timestamp_ms": 200}
    ])
    .to_string();
    let resp = harness
        .get_with_headers(
            "/agents/invoke",
            "a2a.localhost",
            &[
                ("content-type", "application/a2a+json"),
                ("x-a2a-caller-agent-id", "agent:caller"),
                ("x-a2a-callee-agent-id", "agent:b"),
                ("x-a2a-chain-depth", "3"),
                ("x-a2a-chain", &chain),
            ],
        )
        .expect("send");
    assert_eq!(resp.status, 409, "cycle must return 409");
    let body: serde_json::Value = resp.json().expect("json body");
    assert_eq!(body["error"], "a2a_cycle_detected");
    assert_eq!(body["callee"], "agent:b");
    assert_eq!(body["cycle_position"], 1);
}

#[test]
fn cycle_strict_requires_request_id_match() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_strict_cycle(&upstream.base_url())).expect("start");

    // Strict mode: agent:b appears in chain but with request_id
    // different from parent_request_id. Not a cycle.
    let chain = json!([
        {"agent_id": "agent:b", "request_id": "r-old", "timestamp_ms": 100}
    ])
    .to_string();
    let resp = harness
        .get_with_headers(
            "/agents/invoke",
            "a2a.localhost",
            &[
                ("content-type", "application/a2a+json"),
                ("x-a2a-caller-agent-id", "agent:caller"),
                ("x-a2a-callee-agent-id", "agent:b"),
                ("x-a2a-parent-request-id", "r-different"),
                ("x-a2a-chain-depth", "2"),
                ("x-a2a-chain", &chain),
            ],
        )
        .expect("send");
    assert_eq!(
        resp.status, 200,
        "strict mode tolerates same agent with different request_id"
    );

    // Strict mode: agent:b appears with matching request_id => cycle.
    let chain2 = json!([
        {"agent_id": "agent:b", "request_id": "r-parent", "timestamp_ms": 100}
    ])
    .to_string();
    let resp2 = harness
        .get_with_headers(
            "/agents/invoke",
            "a2a.localhost",
            &[
                ("content-type", "application/a2a+json"),
                ("x-a2a-caller-agent-id", "agent:caller"),
                ("x-a2a-callee-agent-id", "agent:b"),
                ("x-a2a-parent-request-id", "r-parent"),
                ("x-a2a-chain-depth", "2"),
                ("x-a2a-chain", &chain2),
            ],
        )
        .expect("send");
    assert_eq!(
        resp2.status, 409,
        "strict mode flags cycle on matching request_id"
    );
}

#[test]
fn cycle_by_callable_endpoint_distinguishes_methods() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_by_endpoint(&upstream.base_url())).expect("start");

    // Chain entry agent:b had request_id "/endpoint-list"; now we
    // call agent:b at "/endpoint-create". The mode treats different
    // endpoints as different calls => no cycle. Since the request
    // path becomes the callable_endpoint, the URL needs to differ
    // from the chain entry's request_id.
    let chain = json!([
        {"agent_id": "agent:b", "request_id": "/endpoint-list", "timestamp_ms": 100}
    ])
    .to_string();
    let resp = harness
        .get_with_headers(
            "/endpoint-create",
            "a2a.localhost",
            &[
                ("content-type", "application/a2a+json"),
                ("x-a2a-caller-agent-id", "agent:caller"),
                ("x-a2a-callee-agent-id", "agent:b"),
                ("x-a2a-chain-depth", "2"),
                ("x-a2a-chain", &chain),
            ],
        )
        .expect("send");
    assert_eq!(
        resp.status, 200,
        "by_callable_endpoint allows same agent with different endpoint"
    );
}

#[test]
fn callee_not_on_allowlist_returns_403() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_with_allowlist(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers(
            "/agents/invoke",
            "a2a.localhost",
            &[
                ("content-type", "application/a2a+json"),
                ("x-a2a-caller-agent-id", "agent:caller"),
                ("x-a2a-callee-agent-id", "agent:not-listed"),
                ("x-a2a-chain-depth", "1"),
            ],
        )
        .expect("send");
    assert_eq!(resp.status, 403);
    let body: serde_json::Value = resp.json().expect("json body");
    assert_eq!(body["error"], "a2a_callee_not_allowed");
    assert_eq!(body["callee"], "agent:not-listed");
}

#[test]
fn callee_on_allowlist_passes() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_with_allowlist(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers(
            "/agents/invoke",
            "a2a.localhost",
            &[
                ("content-type", "application/a2a+json"),
                ("x-a2a-caller-agent-id", "agent:caller"),
                ("x-a2a-callee-agent-id", "agent:openai:gpt-5"),
                ("x-a2a-chain-depth", "1"),
            ],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
}

#[test]
fn caller_on_denylist_returns_403() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_with_denylist(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers(
            "/agents/invoke",
            "a2a.localhost",
            &anthropic_headers()
                .into_iter()
                .chain([
                    ("x-a2a-caller-agent-id", "agent:bad:actor"),
                    ("x-a2a-callee-agent-id", "agent:any"),
                    ("x-a2a-chain-depth", "1"),
                ])
                .collect::<Vec<_>>(),
        )
        .expect("send");
    assert_eq!(resp.status, 403);
    let body: serde_json::Value = resp.json().expect("json body");
    assert_eq!(body["error"], "a2a_caller_denied");
    assert_eq!(body["caller"], "agent:bad:actor");
}

#[test]
fn missing_envelope_fields_tolerated() {
    // No X-A2A-* headers at all; detection still fires on
    // content-type and the policy operates on zero-defaults
    // (depth=1, no callee). With the default config (limit 5,
    // no allowlist) the request passes.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_default(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers("/agents/invoke", "a2a.localhost", &google_headers())
        .expect("send");
    assert_eq!(resp.status, 200);
}

#[test]
fn non_a2a_request_unaffected() {
    // Plain HTTP request with no detection signal must pass through
    // unchanged regardless of the a2a policy.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_low_depth(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers(
            "/some/path",
            "a2a.localhost",
            &[("content-type", "application/json")],
        )
        .expect("send");
    assert_eq!(
        resp.status, 200,
        "non-A2A requests bypass the policy entirely"
    );
}

// --- Trust gate on the header transport ---

#[test]
fn forged_envelope_from_an_untrusted_peer_governs_nothing() {
    // WOR-2120 AC1, transport half. The envelope headers name the
    // caller, name the callee, and assert the call chain, which is the
    // entire input to `caller_denylist`, `callee_allowlist`, and cycle
    // detection. Read from an arbitrary client they are not a policy,
    // they are a request form the caller fills in.
    //
    // One request, sent twice against identical policy, differing only
    // in whether the client sits inside `proxy.trusted_proxies`. The
    // envelope is hostile in four directions at once: the caller is on
    // the denylist, the depth is over the cap, the callee is off the
    // allowlist, and the chain replays the callee.
    let forged_chain = json!([
        {"agent_id": "agent:b", "request_id": "r-b", "timestamp_ms": 100}
    ])
    .to_string();
    let forged = [
        ("content-type", "application/a2a+json"),
        ("x-a2a-caller-agent-id", "agent:bad:actor"),
        ("x-a2a-callee-agent-id", "agent:b"),
        ("x-a2a-task-id", "task-1"),
        ("x-a2a-chain-depth", "9"),
        ("x-a2a-chain", forged_chain.as_str()),
    ];

    // Trusted peer: the proxy believes the envelope, and the denylist
    // (which the policy evaluates first) fires. This half exists so the
    // untrusted 200 below cannot be read as "the policy was never
    // configured to deny this request in the first place."
    let trusted_upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let trusted = ProxyHarness::start_with_yaml(&trusted_peer_config(
        &trusted_upstream.base_url(),
        ALL_CONTROLS_POLICY,
    ))
    .expect("start trusted");
    let denied = trusted
        .get_with_headers("/agents/invoke", "a2a.localhost", &forged)
        .expect("send");
    assert_eq!(
        denied.status, 403,
        "from a trusted peer the same envelope must trip the denylist"
    );
    let denied_body: serde_json::Value = denied.json().expect("json body");
    assert_eq!(denied_body["error"], "a2a_caller_denied");
    assert_eq!(denied_body["caller"], "agent:bad:actor");
    assert!(
        trusted_upstream.captured().is_empty(),
        "a denied request must never reach the upstream"
    );

    // Untrusted peer: every field is discarded before the policy runs,
    // so it evaluates the zero-default envelope (depth 1, no caller, no
    // callee, empty chain) and allows.
    //
    // 200 is the point. A caller must not get to pick its own answer,
    // in either direction: it cannot name itself off a denylist, and it
    // cannot forge its way into a control it was never subject to.
    let untrusted_upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let untrusted = ProxyHarness::start_with_yaml(&untrusted_peer_config(
        &untrusted_upstream.base_url(),
        ALL_CONTROLS_POLICY,
    ))
    .expect("start untrusted");
    let allowed = untrusted
        .get_with_headers("/agents/invoke", "a2a.localhost", &forged)
        .expect("send");
    assert_eq!(
        allowed.status, 200,
        "an untrusted peer's forged envelope must govern nothing"
    );
    assert_eq!(
        untrusted_upstream.captured().len(),
        1,
        "the request itself is not denied, only its identity claims are dropped"
    );
}

#[test]
fn forged_envelope_headers_never_reach_the_upstream() {
    // The inbound strip in `request_phase.rs`. Discarding the headers
    // for our own policy decision is not enough: forwarding them
    // reintroduces the forgery one hop in, where the upstream agent (or
    // a second SBproxy that does trust us) reads them as a chain we
    // vouched for. The only place this is observable is what the
    // upstream actually received.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&untrusted_peer_config(
        &upstream.base_url(),
        PERMISSIVE_POLICY,
    ))
    .expect("start untrusted");

    let chain = json!([
        {"agent_id": "agent:root", "request_id": "r-root", "timestamp_ms": 100}
    ])
    .to_string();
    let envelope = [
        ("content-type", "application/a2a+json"),
        ("x-a2a-caller-agent-id", "agent:caller"),
        ("x-a2a-callee-agent-id", "agent:b"),
        ("x-a2a-task-id", "task-1"),
        ("x-a2a-parent-request-id", "r-parent"),
        ("x-a2a-chain-depth", "2"),
        ("x-a2a-chain", chain.as_str()),
    ];

    let resp = harness
        .get_with_headers("/agents/invoke", "a2a.localhost", &envelope)
        .expect("send");
    assert_eq!(resp.status, 200, "the permissive policy must allow");

    let captured = upstream.captured();
    assert_eq!(captured.len(), 1, "request must reach the upstream");
    for name in ENVELOPE_HEADERS {
        assert!(
            !captured[0].headers.contains_key(name),
            "{name} from an untrusted peer must be stripped before the upstream, saw {:?}",
            captured[0].headers
        );
    }

    // Control: the same six headers on the trusted path DO reach the
    // upstream. Without this the loop above would also pass if the
    // client never sent them, or if the mock upstream dropped unknown
    // headers, neither of which has anything to do with the strip.
    let trusted_upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let trusted = ProxyHarness::start_with_yaml(&trusted_peer_config(
        &trusted_upstream.base_url(),
        PERMISSIVE_POLICY,
    ))
    .expect("start trusted");
    let trusted_resp = trusted
        .get_with_headers("/agents/invoke", "a2a.localhost", &envelope)
        .expect("send");
    assert_eq!(trusted_resp.status, 200, "the permissive policy must allow");

    let trusted_captured = trusted_upstream.captured();
    assert_eq!(trusted_captured.len(), 1, "request must reach the upstream");
    for name in ENVELOPE_HEADERS {
        assert!(
            trusted_captured[0].headers.contains_key(name),
            "{name} from a trusted peer must be forwarded, saw {:?}",
            trusted_captured[0].headers
        );
    }
}

#[test]
fn verified_act_chain_overrides_a_forged_shallow_chain_depth() {
    // WOR-2120 AC1, token half. The header transport is forgeable in
    // the direction that matters: a caller that asserts
    // `x-a2a-chain-depth: 1`, or omits it entirely, lands on depth 1
    // and clears any cap. That is true even from a trusted peer, since
    // "trusted" means the hop is allowed to speak for its clients, not
    // that its arithmetic is audited.
    //
    // An RFC 8693 `act` delegation chain cannot be flattened that way,
    // so when the verified principal carries one it replaces the
    // claimed depth before the policy evaluates. Both runs below are on
    // the trusted path so the token override is isolated from the
    // header trust gate.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_jwt_depth_2(
        &upstream.base_url(),
        TRUST_INCLUDES_CLIENT,
    ))
    .expect("start");

    // Control first: same forged depth, a valid token that asserts no
    // delegation. Depth 1 stands, and the request passes. This pins
    // that the 429 below comes from the token's chain and not from
    // something incidental to the config.
    let undelegated = harness
        .get_with_headers(
            "/agents/invoke",
            "a2a.localhost",
            &[
                ("content-type", "application/a2a+json"),
                ("authorization", &bearer(&token_undelegated())),
                ("x-a2a-caller-agent-id", "agent:caller"),
                ("x-a2a-chain-depth", "1"),
            ],
        )
        .expect("send");
    assert_eq!(
        undelegated.status, 200,
        "a token with no act chain says nothing about delegation and must not deny"
    );

    // Two actors in the token plus this hop is depth 3, over the cap
    // of 2, even though the transport claimed depth 1.
    let delegated = harness
        .get_with_headers(
            "/agents/invoke",
            "a2a.localhost",
            &[
                ("content-type", "application/a2a+json"),
                ("authorization", &bearer(&token_delegated_twice())),
                ("x-a2a-caller-agent-id", "agent:caller"),
                ("x-a2a-chain-depth", "1"),
            ],
        )
        .expect("send");
    assert_eq!(
        delegated.status, 429,
        "a forged shallow depth must not clear max_chain_depth when the token carries the chain"
    );
    let body: serde_json::Value = delegated.json().expect("json body");
    assert_eq!(body["error"], "a2a_chain_depth_exceeded");
    assert_eq!(body["limit"], 2);
    assert_eq!(
        body["depth"], 3,
        "depth must come from the act chain (two actors plus this hop), not the header"
    );
}

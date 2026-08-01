// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! A2A policy module.
//!
//! Per-route enforcement for agent-to-agent calls.
//!
//! The policy fires after authentication and after the agent-class
//! resolver chain has populated `caller_agent_id`. It evaluates against an
//! `A2AContext` populated by detection + the optional spec parsers;
//! denial paths surface as typed `A2APolicyDecision` variants that
//! the request filter maps to HTTP responses with the spec-pinned
//! status codes and JSON bodies.

use anyhow::Context as _;
use sbproxy_config::types::FailureMode;
use serde::Deserialize;

use crate::auth::a2a::{A2AContext, DetectedSpec};

/// Hard ceiling on `max_chain_depth`. Cannot be lifted via config;
/// the limit reflects a memory bound on chain reconstruction (each
/// hop is ~256 bytes, 32 hops cap at 8 KB per envelope). Operators
/// that need deeper chains must disable the policy entirely.
pub const A2A_HARD_CHAIN_DEPTH_CEILING: u32 = 32;

/// Default chain-depth cap. Empirical traces show depth >= 4 is
/// rare; 5 leaves headroom for legitimate orchestration.
pub const DEFAULT_MAX_CHAIN_DEPTH: u32 = 5;

/// How "cycle" is interpreted by the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CycleDetection {
    /// The exact `(agent_id, request_id)` pair must not appear
    /// earlier in the chain. Detects only true loops; almost never
    /// fires in practice but is the safest baseline.
    Strict,
    /// Default. The callee `agent_id` must not appear anywhere
    /// earlier in the chain. Detects "agent A calls B which calls
    /// A again."
    #[default]
    ByAgentId,
    /// The callee `(agent_id, callable_endpoint)` tuple must not
    /// appear. Allows agent A to call agent B which calls agent A
    /// with a different method.
    ByCallableEndpoint,
}

/// YAML config for the `a2a` policy.
#[derive(Debug, Clone, Deserialize)]
pub struct A2APolicyConfig {
    /// Hard ceiling on chain depth before the policy denies.
    /// Capped at [`A2A_HARD_CHAIN_DEPTH_CEILING`] regardless of the
    /// configured value.
    #[serde(default = "default_max_chain_depth")]
    pub max_chain_depth: u32,
    /// When true, cycles are allowed. Default false.
    #[serde(default)]
    pub allow_cycles: bool,
    /// Cycle detection semantics. Default [`CycleDetection::ByAgentId`].
    #[serde(default)]
    pub cycle_detection: CycleDetection,
    /// Optional callee allowlist. When present, only listed agents
    /// may be called from this route. Empty list means "no allowlist
    /// configured" (any callee passes).
    #[serde(default)]
    pub callee_allowlist: Vec<String>,
    /// Caller denylist. Agents in this list may never initiate A2A
    /// from this route. Empty list disables.
    #[serde(default)]
    pub caller_denylist: Vec<String>,
    /// When true (default), the caller's wallet is charged. Setting
    /// this false flips to callee-billed semantics; the audit log
    /// stamps `pricing_anomaly: callee_billed` on every such
    /// transaction. Kept as a kill switch for experimental setups
    /// per the ADR's Pricing section.
    #[serde(default = "default_bill_caller_only")]
    pub bill_caller_only: bool,
    /// Operator escape hatch route glob. Detection consults this
    /// alongside content-type and MCP-Method. Empty disables.
    #[serde(default)]
    pub route_glob: Option<String>,
    /// Hosts permitted as A2A push-notification webhook targets even
    /// when they resolve to private address space.
    ///
    /// A2A 1.0 lets a caller register a URL that the upstream agent
    /// POSTs task status and artifacts to. Left unchecked that is
    /// server-side request forgery by protocol design, aimed at cloud
    /// metadata endpoints and internal admin planes, and the payload
    /// carries task artifacts so a hit exfiltrates rather than merely
    /// probes. The default posture blocks private targets; internal
    /// callbacks are a legitimate deployment, so this exists, but the
    /// operator has to name the host rather than get it implicitly.
    #[serde(default)]
    pub push_target_allowlist: Vec<String>,
    /// What this policy does with a request it is attached to but could
    /// not identify as A2A.
    ///
    /// # When this fires
    ///
    /// Detection has four inputs: `A2A-Version: 1.x`, `Content-Type:
    /// application/a2a+json`, `MCP-Method: agents.invoke`, and the
    /// operator's [`Self::route_glob`]. The first three are the
    /// caller's to send or withhold. When none of the four matches, the
    /// policy has nothing to evaluate, and this key decides what
    /// happens to that request.
    ///
    /// # Postures
    ///
    /// - `open` (default): admit the request. The A2A policy simply
    ///   does not apply to traffic it could not identify.
    /// - `closed`: refuse the request with 403. Every request to a
    ///   route carrying this policy must be identifiable as A2A.
    /// - `observe`: admit, and count the request under a decision label
    ///   that says `closed` would have refused it. The rollout posture:
    ///   flip to `observe`, watch
    ///   `sbproxy_a2a_hops_total{decision="observe:undetected"}` for a
    ///   day, and you know the blast radius of `closed` before you take
    ///   it.
    /// - `degraded`: admit, and count the request as one where the A2A
    ///   guarantee was explicitly not made. Same traffic outcome as
    ///   `open`, a different label, for operators who want the series to
    ///   alert on rather than a default they can forget about.
    ///
    /// All four are distinguishable on the `decision` label of
    /// `sbproxy_a2a_hops_total`, so nothing is rejected at compile
    /// time here: every posture does something this site can express.
    ///
    /// # Why the default is `open`
    ///
    /// The house rule is closed for anything enforcing a security
    /// boundary and open only where refusing would turn a non-security
    /// failure into an outage. This is the second case, narrowly.
    ///
    /// A policy is attached per origin, not per path, and it runs on
    /// every request that origin serves. Defaulting to `closed` would
    /// mean that the moment an operator upgraded, any origin carrying an
    /// `a2a` policy would start refusing its health checks, its metrics
    /// scrape, and every ordinary non-A2A request it also serves. That
    /// is an outage caused by an upgrade, not a boundary being enforced.
    ///
    /// The reason `open` is defensible rather than merely convenient is
    /// that the gap is closable and visible.
    /// [`Self::route_glob`] is a detection signal the caller cannot opt
    /// out of, so an operator who declares the route gets every request
    /// on it governed regardless of what the caller sends. And an
    /// undetected request is counted at
    /// `sbproxy_a2a_hops_total{decision="skip:undetected"}`, so a route
    /// that is quietly ungoverned shows up on a dashboard instead of
    /// reading as healthy.
    ///
    /// Set `route_glob` first. Reach for `failure_posture: closed` when
    /// the origin serves agent traffic and nothing else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_posture: Option<FailureMode>,
}

fn default_max_chain_depth() -> u32 {
    DEFAULT_MAX_CHAIN_DEPTH
}

fn default_bill_caller_only() -> bool {
    true
}

impl Default for A2APolicyConfig {
    fn default() -> Self {
        Self {
            max_chain_depth: DEFAULT_MAX_CHAIN_DEPTH,
            allow_cycles: false,
            cycle_detection: CycleDetection::default(),
            callee_allowlist: Vec::new(),
            caller_denylist: Vec::new(),
            bill_caller_only: true,
            route_glob: None,
            push_target_allowlist: Vec::new(),
            // `None`, not `Some(Open)`. The absent key and an explicit
            // `open` mean the same thing at runtime, and keeping them
            // distinct in the struct lets the accessor be the one place
            // the default is written down.
            failure_posture: None,
        }
    }
}

/// Effective failure posture when a policy does not configure one.
///
/// Named rather than inlined so the value is greppable and so the
/// argument for it lives next to it. See
/// [`A2APolicyConfig::failure_posture`] for the full reasoning: the
/// short version is that flipping this to `Closed` would make every
/// origin carrying an `a2a` policy start refusing its ordinary non-A2A
/// traffic on upgrade, and the gap this leaves is both closable
/// (`route_glob`) and visible (`decision="skip:undetected"`).
pub const DEFAULT_A2A_FAILURE_POSTURE: FailureMode = FailureMode::Open;

/// Compiled A2A policy.
#[derive(Debug, Clone)]
pub struct A2APolicy {
    config: A2APolicyConfig,
}

/// Outcome of evaluating an [`A2APolicy`] against an [`A2AContext`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum A2APolicyDecision {
    /// All checks passed.
    Allow,
    /// Chain depth exceeds `max_chain_depth` (or the hard ceiling).
    ChainDepthExceeded {
        /// Configured (and ceiling-clamped) limit.
        limit: u32,
        /// Observed chain depth.
        depth: u32,
    },
    /// Cycle detected on the callee. `cycle_position` is the index
    /// in the chain where the callee already appears.
    CycleDetected {
        /// Callee identifier that already appears in the chain.
        callee: String,
        /// Index in the chain (0-based) of the existing entry.
        cycle_position: usize,
    },
    /// Callee is not on the configured allowlist.
    CalleeNotAllowed {
        /// Callee identifier that did not match any allowlist entry.
        callee: String,
    },
    /// A push-notification webhook target failed egress validation.
    PushTargetBlocked {
        /// Why the target was refused. Never echoes a resolved address,
        /// so the denial cannot be used as a network oracle.
        reason: String,
    },
    /// Caller is on the configured denylist.
    CallerDenied {
        /// Caller identifier that matched a denylist entry.
        caller: String,
    },
    /// The policy is attached to this route but could not identify the
    /// request as A2A, and the configured failure posture is
    /// [`FailureMode::Closed`].
    ///
    /// Produced by the enforcer rather than by [`A2APolicy::evaluate`]:
    /// detection runs before evaluation, so by the time `evaluate`
    /// would be called there is nothing to evaluate against. It lives
    /// on this enum anyway so the status code, the JSON body, and the
    /// metric label for every A2A refusal come from one place.
    Undetected,
}

impl A2APolicyDecision {
    /// True when the decision allows the request.
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Stable string label used for metrics / audit `reason` fields.
    /// Value for the `decision` label on `sbproxy_a2a_hops_total`.
    ///
    /// Allows are split by whether the envelope's identity was verified,
    /// because the two are operationally different facts that used to
    /// share one label. A policy that never engages, or that only ever
    /// sees forgeable caller-supplied envelopes, emits an unbroken
    /// stream of allows and reads exactly like a healthy one. Splitting
    /// the label lets an operator alert on "this policy is configured
    /// but has never evaluated a verified chain."
    ///
    /// Denials keep naming the control that fired, which is what a page
    /// is written against, and ignore verification state.
    pub fn metric_label(&self, identity_verified: bool) -> String {
        if self.is_allow() {
            if identity_verified {
                "allow:verified".to_string()
            } else {
                "allow:unverified".to_string()
            }
        } else {
            format!("deny:{}", self.reason_label())
        }
    }

    /// Short label naming the control that produced a denial.
    pub fn reason_label(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::ChainDepthExceeded { .. } => "depth",
            Self::CycleDetected { .. } => "cycle",
            Self::CalleeNotAllowed { .. } => "callee_not_allowed",
            Self::PushTargetBlocked { .. } => "push_target_blocked",
            Self::CallerDenied { .. } => "caller_denied",
            Self::Undetected => "undetected",
        }
    }

    /// HTTP status code per the ADR's failure-mode pin.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::Allow => 200,
            Self::ChainDepthExceeded { .. } => 429,
            Self::CycleDetected { .. } => 409,
            Self::CalleeNotAllowed { .. } => 403,
            // 403 rather than 400: the target is refused by policy, not
            // malformed. A 400 would invite the caller to retry with a
            // reshaped URL as if the syntax were the problem.
            Self::PushTargetBlocked { .. } => 403,
            Self::CallerDenied { .. } => 403,
            // 403, not 400. The request is well formed; this origin
            // just does not serve traffic it cannot identify as A2A.
            Self::Undetected => 403,
        }
    }

    /// JSON response body per the ADR's failure-mode pin.
    pub fn json_body(&self) -> String {
        match self {
            Self::Allow => "{}".to_string(),
            Self::ChainDepthExceeded { limit, depth } => format!(
                "{{\"error\":\"a2a_chain_depth_exceeded\",\"limit\":{limit},\"depth\":{depth}}}"
            ),
            Self::CycleDetected {
                callee,
                cycle_position,
            } => format!(
                "{{\"error\":\"a2a_cycle_detected\",\"callee\":{},\"cycle_position\":{cycle_position}}}",
                json_escape(callee)
            ),
            Self::CalleeNotAllowed { callee } => format!(
                "{{\"error\":\"a2a_callee_not_allowed\",\"callee\":{}}}",
                json_escape(callee)
            ),
            Self::PushTargetBlocked { reason } => format!(
                "{{\"error\":\"a2a_push_target_blocked\",\"reason\":{}}}",
                json_escape(reason)
            ),
            Self::CallerDenied { caller } => format!(
                "{{\"error\":\"a2a_caller_denied\",\"caller\":{}}}",
                json_escape(caller)
            ),
            // No detail beyond the error code. Telling the caller which
            // signals detection looks at would be telling it which one
            // to forge.
            Self::Undetected => "{\"error\":\"a2a_undetected\"}".to_string(),
        }
    }
}

/// Minimal JSON string escape for the four denial-body paths. We
/// avoid `serde_json::to_string` here so the body format stays
/// byte-stable across serde minor versions.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

impl A2APolicy {
    /// Build the policy from a JSON config value.
    ///
    /// Errors are wrapped so they name the policy. Without that, an
    /// operator who writes `failure_posture: fail_open` gets serde's
    /// bare "unknown variant" line with no indication of which of the
    /// origin's policies produced it.
    ///
    /// Every [`FailureMode`] variant is meaningful at this site, so
    /// none is rejected here. See
    /// [`A2APolicyConfig::failure_posture`].
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let config: A2APolicyConfig = serde_json::from_value(value).context("a2a policy config")?;
        Ok(Self::with_config(config))
    }

    /// Effective failure posture for requests this policy is attached
    /// to but could not identify as A2A.
    ///
    /// There is no legacy boolean to convert at this site, so the
    /// fallback is [`DEFAULT_A2A_FAILURE_POSTURE`]. This is the only
    /// supported read path; the config field holds the raw
    /// `Option` and callers should not branch on it directly.
    pub fn failure_posture(&self) -> FailureMode {
        self.config
            .failure_posture
            .unwrap_or(DEFAULT_A2A_FAILURE_POSTURE)
    }

    /// Metric `decision` label for a request this policy did not detect
    /// as A2A, under the policy's effective failure posture.
    ///
    /// The four postures are deliberately four distinct label values
    /// rather than one `skip:undetected` with a second label. An
    /// operator alerting on "this route is ungoverned" and one watching
    /// a `closed` rollout are asking different questions, and folding
    /// them together is how a bypass stays invisible on a dashboard.
    ///
    /// `open` keeps the exact string it emitted before this knob
    /// existed, so dashboards and alerts written against
    /// `decision="skip:undetected"` keep working unchanged.
    pub fn undetected_decision_label(&self) -> &'static str {
        match self.failure_posture() {
            FailureMode::Open => "skip:undetected",
            FailureMode::Closed => "deny:undetected",
            // Admitted, and the counterfactual recorded: `closed` would
            // have refused this request.
            FailureMode::Observe => "observe:undetected",
            // Admitted, with the A2A guarantee explicitly not made.
            FailureMode::Degraded => "degraded:undetected",
        }
    }

    /// Build the policy from a typed config (used by tests and the
    /// e2e harness when bypassing the YAML decoder).
    pub fn with_config(config: A2APolicyConfig) -> Self {
        Self { config }
    }

    /// Borrow the parsed config.
    pub fn config(&self) -> &A2APolicyConfig {
        &self.config
    }

    /// Effective chain-depth limit: the configured value clamped to
    /// the hard ceiling so an operator can never lift it past 32.
    pub fn effective_chain_depth_limit(&self) -> u32 {
        self.config
            .max_chain_depth
            .min(A2A_HARD_CHAIN_DEPTH_CEILING)
    }

    /// Operator route glob, when configured.
    /// Whether this policy governs the given request, consulting the
    /// operator's `route_glob` alongside the caller-supplied detection
    /// signals.
    ///
    /// This is the operator-controlled entry point. Header detection
    /// alone is not sufficient, because both signals it matches on
    /// (`Content-Type` and `MCP-Method`) are chosen by the caller, so a
    /// caller that omits them is never detected. Declaring `route_glob`
    /// makes the route governed regardless of what the caller sends.
    ///
    /// Prefer this over calling [`crate::detect_a2a`] directly; the
    /// bare function cannot see the policy's configured glob.
    pub fn governs(&self, headers: &http::HeaderMap, path: &str) -> Option<DetectedSpec> {
        crate::auth::a2a::detect(headers, path, self.route_glob())
    }

    /// Validate the webhook target on an A2A 1.0
    /// `CreateTaskPushNotificationConfig` request before it reaches the
    /// upstream agent.
    ///
    /// A2A lets a client register a URL and have the agent POST task
    /// status and artifacts to it. The URL is caller-supplied and the
    /// dial is made by an authenticated backend, which is the textbook
    /// confused-deputy shape. Because the payload carries artifacts, a
    /// successful redirect into private space exfiltrates rather than
    /// merely probes.
    ///
    /// Requests that register no webhook are allowed untouched.
    ///
    /// This is registration-time validation only, and the proxy is not
    /// the party that later dials the URL: the upstream agent is. So
    /// this cannot close the DNS-rebinding window between registration
    /// and delivery, because it does not own the dial. It refuses the
    /// obviously-hostile targets at the door. Closing the rebinding gap
    /// needs the agent to pin the address it validated, which is a
    /// contract with the upstream rather than something the gateway can
    /// impose.
    pub fn check_push_notification(
        &self,
        req: &crate::auth::a2a::v1::V1Request,
    ) -> A2APolicyDecision {
        let Some(url) = req.push_notification_url.as_deref() else {
            return A2APolicyDecision::Allow;
        };
        match sbproxy_security::ssrf::validate_url_resolved(url, &self.config.push_target_allowlist)
        {
            Ok(_) => A2APolicyDecision::Allow,
            // The guard's message names the class of block (scheme,
            // private address) without echoing a resolved address, so
            // the denial does not become a network-mapping oracle.
            Err(reason) => A2APolicyDecision::PushTargetBlocked { reason },
        }
    }

    /// Operator escape-hatch glob, if configured. Most callers want
    /// [`Self::governs`], which applies it.
    pub fn route_glob(&self) -> Option<&str> {
        self.config.route_glob.as_deref()
    }

    /// Evaluate the policy against the request's A2A envelope.
    ///
    /// `callable_endpoint` is the endpoint identifier used by the
    /// `by_callable_endpoint` cycle detector; pass an empty string
    /// when the spec does not surface one.
    pub fn evaluate(&self, ctx: &A2AContext, callable_endpoint: &str) -> A2APolicyDecision {
        // 1. Caller denylist. Runs first because it's the cheapest
        //    check and a denied caller never gets to see the other
        //    failure modes.
        if !self.config.caller_denylist.is_empty()
            && self
                .config
                .caller_denylist
                .iter()
                .any(|c| c == &ctx.caller_agent_id)
        {
            return A2APolicyDecision::CallerDenied {
                caller: ctx.caller_agent_id.clone(),
            };
        }

        // 2. Chain depth. The ceiling is enforced regardless of
        //    config so a misconfigured high limit can never bypass
        //    the memory bound.
        let limit = self.effective_chain_depth_limit();
        if ctx.chain_depth > limit {
            return A2APolicyDecision::ChainDepthExceeded {
                limit,
                depth: ctx.chain_depth,
            };
        }

        // 3. Cycle detection (skipped when allow_cycles is true).
        if !self.config.allow_cycles {
            if let Some(callee) = ctx.callee_agent_id.as_deref() {
                if let Some(pos) =
                    detect_cycle(ctx, callee, callable_endpoint, self.config.cycle_detection)
                {
                    return A2APolicyDecision::CycleDetected {
                        callee: callee.to_string(),
                        cycle_position: pos,
                    };
                }
            }
        }

        // 4. Callee allowlist. Empty list means "no allowlist
        //    configured" -> allow.
        if !self.config.callee_allowlist.is_empty() {
            if let Some(callee) = ctx.callee_agent_id.as_deref() {
                if !self.config.callee_allowlist.iter().any(|c| c == callee) {
                    return A2APolicyDecision::CalleeNotAllowed {
                        callee: callee.to_string(),
                    };
                }
            }
        }

        A2APolicyDecision::Allow
    }
}

/// Find the position of `callee` in `ctx.chain` under the given
/// cycle-detection mode. Returns `None` when no cycle is detected.
fn detect_cycle(
    ctx: &A2AContext,
    callee: &str,
    callable_endpoint: &str,
    mode: CycleDetection,
) -> Option<usize> {
    match mode {
        CycleDetection::Strict => {
            // Strict requires the exact (agent_id, request_id) pair.
            // Without a per-callee request_id we cannot match strictly,
            // so the strict mode degrades to "no cycle detected" when
            // the callee has no associated chain entry. The pair we
            // look for is (callee, ctx.parent_request_id) because the
            // parent_request_id is what would be replayed on a true loop.
            let pid = ctx.parent_request_id.as_deref()?;
            ctx.chain
                .iter()
                .position(|hop| hop.agent_id == callee && hop.request_id == pid)
        }
        CycleDetection::ByAgentId => ctx.chain.iter().position(|hop| hop.agent_id == callee),
        CycleDetection::ByCallableEndpoint => {
            // The chain entries don't carry endpoint metadata in the
            // ChainHop struct. We approximate by matching agent_id and
            // requiring the supplied `callable_endpoint` to match the
            // chain entry's request_id slot (a pragmatic signal until
            // the wire envelope grows endpoint metadata). Different
            // endpoint = different call = no cycle.
            // When `callable_endpoint` is empty, fall back to
            // by_agent_id semantics so the policy never silently
            // permits.
            if callable_endpoint.is_empty() {
                return ctx.chain.iter().position(|hop| hop.agent_id == callee);
            }
            ctx.chain
                .iter()
                .position(|hop| hop.agent_id == callee && hop.request_id == callable_endpoint)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::a2a::{A2ASpec, ChainHop};

    fn ctx(callee: &str, chain_depth: u32, chain: Vec<ChainHop>) -> A2AContext {
        A2AContext {
            spec: A2ASpec::GoogleV0,
            caller_agent_id: "agent:caller".to_string(),
            callee_agent_id: Some(callee.to_string()),
            task_id: "task-1".to_string(),
            parent_request_id: Some("req-parent".to_string()),
            chain_depth,
            chain,
            raw_envelope_version: "google-v0".to_string(),
            // These fixtures model an envelope the proxy has already
            // decided to trust; the untrusted case is covered in the
            // `auth::a2a` trust-gate tests.
            identity_verified: true,
        }
    }

    fn push_registration(url: &str) -> crate::auth::a2a::v1::V1Request {
        crate::auth::a2a::v1::V1Request {
            method: Some(crate::auth::a2a::v1::V1Method::CreateTaskPushNotificationConfig),
            push_notification_url: Some(url.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn push_webhook_to_cloud_metadata_is_blocked() {
        // A2A lets a caller register a URL that the upstream agent then
        // POSTs task artifacts to. That is server-side request forgery
        // as a protocol feature, and the payload is not empty, so a
        // successful hit is exfiltration rather than a probe.
        let policy = A2APolicy::with_config(A2APolicyConfig::default());
        let decision =
            policy.check_push_notification(&push_registration("http://169.254.169.254/latest/"));
        assert!(!decision.is_allow());
        assert_eq!(decision.reason_label(), "push_target_blocked");
    }

    #[test]
    fn push_webhook_to_loopback_is_blocked() {
        let policy = A2APolicy::with_config(A2APolicyConfig::default());
        assert!(!policy
            .check_push_notification(&push_registration("http://127.0.0.1:8080/admin"))
            .is_allow());
    }

    #[test]
    fn push_webhook_with_a_non_http_scheme_is_blocked() {
        let policy = A2APolicy::with_config(A2APolicyConfig::default());
        assert!(!policy
            .check_push_notification(&push_registration("file:///etc/passwd"))
            .is_allow());
    }

    #[test]
    fn a_request_that_registers_no_webhook_is_allowed() {
        let policy = A2APolicy::with_config(A2APolicyConfig::default());
        let plain = crate::auth::a2a::v1::V1Request {
            method: Some(crate::auth::a2a::v1::V1Method::SendMessage),
            ..Default::default()
        };
        assert!(policy.check_push_notification(&plain).is_allow());
    }

    #[test]
    fn an_operator_allowlisted_private_target_is_permitted() {
        // Internal callbacks are a legitimate deployment, so the escape
        // hatch exists; it just has to be named explicitly rather than
        // inferred. An IP literal keeps this hermetic: the hostname
        // branch of the guard does a best-effort DNS resolve, which
        // would put a resolver in the path of a unit test.
        let policy = A2APolicy::with_config(A2APolicyConfig {
            push_target_allowlist: vec!["10.0.0.5".to_string()],
            ..A2APolicyConfig::default()
        });
        assert!(policy
            .check_push_notification(&push_registration("http://10.0.0.5/hook"))
            .is_allow());
    }

    #[test]
    fn the_same_private_target_is_blocked_without_the_allowlist() {
        // Pins that the previous test passes because of the allowlist
        // and not because 10.0.0.0/8 was never blocked to begin with.
        let policy = A2APolicy::with_config(A2APolicyConfig::default());
        assert!(!policy
            .check_push_notification(&push_registration("http://10.0.0.5/hook"))
            .is_allow());
    }

    #[test]
    fn metric_label_separates_verified_allows_from_unverified_ones() {
        // Without this split a policy that never engages emits the same
        // `allow` as one that evaluated a verified chain, so a dashboard
        // showing nothing but allows reads as healthy whether the policy
        // is working or completely bypassed.
        assert_eq!(
            A2APolicyDecision::Allow.metric_label(true),
            "allow:verified"
        );
        assert_eq!(
            A2APolicyDecision::Allow.metric_label(false),
            "allow:unverified"
        );
    }

    #[test]
    fn metric_label_for_a_denial_names_the_control_that_fired() {
        let denied = A2APolicyDecision::ChainDepthExceeded { limit: 5, depth: 9 };
        assert_eq!(denied.metric_label(true), "deny:depth");
    }

    #[test]
    fn metric_label_for_a_denial_ignores_verification_state() {
        // A deny is a deny; the reason is what an operator pages on.
        let denied = A2APolicyDecision::ChainDepthExceeded { limit: 5, depth: 9 };
        assert_eq!(denied.metric_label(false), denied.metric_label(true));
    }

    #[test]
    fn governs_matches_operator_declared_route_without_caller_headers() {
        // The operator declares the route as A2A. A caller that sends no
        // A2A-shaped headers at all must still be governed, otherwise
        // the policy is opt-in for the attacker.
        let policy = A2APolicy::with_config(A2APolicyConfig {
            route_glob: Some("/agents/**".to_string()),
            ..A2APolicyConfig::default()
        });

        assert!(policy
            .governs(&http::HeaderMap::new(), "/agents/invoke")
            .is_some());
    }

    #[test]
    fn governs_ignores_routes_outside_the_declared_glob() {
        let policy = A2APolicy::with_config(A2APolicyConfig {
            route_glob: Some("/agents/**".to_string()),
            ..A2APolicyConfig::default()
        });

        assert!(policy
            .governs(&http::HeaderMap::new(), "/public/health")
            .is_none());
    }

    #[test]
    fn governs_still_honors_header_detection_when_no_glob_configured() {
        let policy = A2APolicy::with_config(A2APolicyConfig::default());
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/a2a+json"),
        );

        assert!(policy.governs(&headers, "/anything").is_some());
    }

    // --- Failure posture on undetected traffic (WOR-2120 AC5) ---

    /// Headers with nothing A2A about them, plus a hostile
    /// `a2a-version` that this build cannot decode. Used by the posture
    /// tests so every one of them is asking about a request detection
    /// genuinely cannot classify.
    fn undetectable_headers() -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        h.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        h.insert(
            http::HeaderName::from_static("a2a-version"),
            http::HeaderValue::from_static("2.0"),
        );
        h
    }

    /// No key configured means the policy behaves exactly as it did
    /// before the key existed: an undetected request is allowed and
    /// counted under the same metric label. This is the compatibility
    /// pin for every operator upgrading into this change.
    #[test]
    fn default_failure_posture_allows_undetected_traffic() {
        let policy = A2APolicy::with_config(A2APolicyConfig::default());

        assert_eq!(policy.config().failure_posture, None, "no key by default");
        assert_eq!(policy.failure_posture(), FailureMode::Open);
        assert!(policy.failure_posture().admits());
        assert_eq!(
            policy.undetected_decision_label(),
            "skip:undetected",
            "existing dashboards are written against this exact string"
        );
    }

    /// An empty config block resolves the same way as the typed
    /// default. The two paths are separate code and both are shipped.
    #[test]
    fn default_failure_posture_is_open_through_from_config_too() {
        let policy = A2APolicy::from_config(serde_json::json!({})).unwrap();
        assert_eq!(policy.failure_posture(), DEFAULT_A2A_FAILURE_POSTURE);
        assert_eq!(policy.failure_posture(), FailureMode::Open);
    }

    /// `closed` refuses a request the policy could not identify as A2A.
    /// Asserted end to end: detection really does miss this request,
    /// the posture really is closed, and the refusal carries the status
    /// and body the enforcer returns.
    #[test]
    fn closed_failure_posture_denies_undetected_traffic() {
        let policy = A2APolicy::from_config(serde_json::json!({
            "failure_posture": "closed",
        }))
        .unwrap();

        assert!(
            policy
                .governs(&undetectable_headers(), "/internal/health")
                .is_none(),
            "the premise of this test is that detection misses the request"
        );
        assert_eq!(policy.failure_posture(), FailureMode::Closed);
        assert!(!policy.failure_posture().admits());
        assert_eq!(policy.undetected_decision_label(), "deny:undetected");

        let decision = A2APolicyDecision::Undetected;
        assert!(!decision.is_allow());
        assert_eq!(decision.http_status(), 403);
        assert_eq!(decision.reason_label(), "undetected");
        assert_eq!(decision.metric_label(false), "deny:undetected");
        let body: serde_json::Value = serde_json::from_str(&decision.json_body()).unwrap();
        assert_eq!(body["error"], "a2a_undetected");
    }

    /// `observe` admits the request and records what `closed` would
    /// have done. The counterfactual is the whole point, so it is the
    /// label that is asserted, not just the allow.
    #[test]
    fn observe_failure_posture_allows_and_records_the_counterfactual() {
        let policy = A2APolicy::from_config(serde_json::json!({
            "failure_posture": "observe",
        }))
        .unwrap();

        assert_eq!(policy.failure_posture(), FailureMode::Observe);
        assert!(
            policy.failure_posture().admits(),
            "observe must not refuse traffic"
        );
        assert!(policy.failure_posture().records_counterfactual());
        assert_eq!(
            policy.undetected_decision_label(),
            "observe:undetected",
            "must be its own series; folding it into skip:undetected \
             would hide the blast radius of flipping to closed"
        );
    }

    /// `degraded` admits while marking the guarantee as not made, and
    /// is distinguishable from a plain `open` in the metric.
    #[test]
    fn degraded_failure_posture_admits_but_marks_the_guarantee_waived() {
        let policy = A2APolicy::from_config(serde_json::json!({
            "failure_posture": "degraded",
        }))
        .unwrap();

        assert!(policy.failure_posture().admits());
        assert!(policy.failure_posture().guarantee_waived());
        assert_eq!(policy.undetected_decision_label(), "degraded:undetected");
    }

    /// Every posture gets its own decision label. A shared label would
    /// make "ungoverned by default" and "would have been refused" the
    /// same series, which is the failure this key exists to surface.
    #[test]
    fn every_posture_has_a_distinct_undetected_label() {
        let mut seen = std::collections::HashSet::new();
        for posture in ["open", "closed", "observe", "degraded"] {
            let policy = A2APolicy::from_config(serde_json::json!({
                "failure_posture": posture,
            }))
            .unwrap();
            assert!(
                seen.insert(policy.undetected_decision_label()),
                "duplicate decision label for {posture}"
            );
        }
        assert_eq!(seen.len(), 4);
    }

    /// A route the operator declared stays governed no matter what the
    /// caller sends, including a version header this build cannot
    /// decode. Regression pin for the one-header bypass, asserted here
    /// (not only in the detection module) because this is the entry
    /// point the enforcer calls.
    #[test]
    fn declared_route_is_governed_regardless_of_caller_headers() {
        let policy = A2APolicy::with_config(A2APolicyConfig {
            route_glob: Some("/agents/**".to_string()),
            ..A2APolicyConfig::default()
        });

        assert!(
            policy
                .governs(&undetectable_headers(), "/agents/invoke")
                .is_some(),
            "a caller-chosen header must not remove a declared route from the policy"
        );
        assert!(
            policy
                .governs(&http::HeaderMap::new(), "/agents/invoke")
                .is_some(),
            "nor must sending no headers at all"
        );
    }

    /// A misspelled posture value fails config compile with an error
    /// that names the policy. serde's bare "unknown variant" line does
    /// not say which of an origin's policies produced it.
    #[test]
    fn an_unknown_failure_posture_value_fails_compile_naming_the_policy() {
        let err = A2APolicy::from_config(serde_json::json!({
            "failure_posture": "fail_open",
        }))
        .expect_err("an unknown posture must not compile");
        let msg = format!("{err:#}");
        assert!(msg.contains("a2a policy"), "must name the site: {msg}");
    }

    fn hop(agent: &str, rid: &str) -> ChainHop {
        ChainHop {
            agent_id: agent.to_string(),
            request_id: rid.to_string(),
            timestamp_ms: 0,
        }
    }

    #[test]
    fn defaults_match_adr() {
        let cfg = A2APolicyConfig::default();
        assert_eq!(cfg.max_chain_depth, 5);
        assert!(!cfg.allow_cycles);
        assert_eq!(cfg.cycle_detection, CycleDetection::ByAgentId);
        assert!(cfg.bill_caller_only);
        assert!(cfg.callee_allowlist.is_empty());
        assert!(cfg.caller_denylist.is_empty());
    }

    #[test]
    fn allow_when_no_constraints_match() {
        let p = A2APolicy::with_config(A2APolicyConfig::default());
        let c = ctx("agent:b", 1, Vec::new());
        assert_eq!(p.evaluate(&c, ""), A2APolicyDecision::Allow);
    }

    #[test]
    fn chain_depth_exceeded_emits_429() {
        let cfg = A2APolicyConfig {
            max_chain_depth: 2,
            ..A2APolicyConfig::default()
        };
        let p = A2APolicy::with_config(cfg);
        let c = ctx("agent:b", 5, Vec::new());
        let d = p.evaluate(&c, "");
        assert_eq!(d.http_status(), 429);
        assert_eq!(d.reason_label(), "depth");
        assert!(d.json_body().contains("a2a_chain_depth_exceeded"));
        assert!(d.json_body().contains("\"limit\":2"));
        assert!(d.json_body().contains("\"depth\":5"));
    }

    #[test]
    fn hard_ceiling_clamps_max_chain_depth() {
        let cfg = A2APolicyConfig {
            max_chain_depth: 100,
            ..A2APolicyConfig::default()
        };
        let p = A2APolicy::with_config(cfg);
        assert_eq!(
            p.effective_chain_depth_limit(),
            A2A_HARD_CHAIN_DEPTH_CEILING
        );
        // Depth right at the ceiling passes; ceiling+1 fails.
        let c_ok = ctx("agent:b", A2A_HARD_CHAIN_DEPTH_CEILING, Vec::new());
        assert!(p.evaluate(&c_ok, "").is_allow());
        let c_bad = ctx("agent:b", A2A_HARD_CHAIN_DEPTH_CEILING + 1, Vec::new());
        match p.evaluate(&c_bad, "") {
            A2APolicyDecision::ChainDepthExceeded { limit, .. } => {
                assert_eq!(limit, A2A_HARD_CHAIN_DEPTH_CEILING);
            }
            other => panic!("expected ChainDepthExceeded, got {other:?}"),
        }
    }

    #[test]
    fn cycle_detected_by_agent_id_default() {
        let p = A2APolicy::with_config(A2APolicyConfig::default());
        let chain = vec![hop("agent:root", "req-root"), hop("agent:b", "req-b")];
        let c = ctx("agent:b", 3, chain);
        let d = p.evaluate(&c, "");
        assert_eq!(d.http_status(), 409);
        assert_eq!(d.reason_label(), "cycle");
        assert!(d.json_body().contains("a2a_cycle_detected"));
        assert!(d.json_body().contains("\"cycle_position\":1"));
    }

    #[test]
    fn cycle_skipped_when_allow_cycles_true() {
        let cfg = A2APolicyConfig {
            allow_cycles: true,
            ..A2APolicyConfig::default()
        };
        let p = A2APolicy::with_config(cfg);
        let chain = vec![hop("agent:b", "req-b")];
        let c = ctx("agent:b", 2, chain);
        assert!(p.evaluate(&c, "").is_allow());
    }

    #[test]
    fn cycle_strict_requires_request_id_match() {
        let cfg = A2APolicyConfig {
            cycle_detection: CycleDetection::Strict,
            ..A2APolicyConfig::default()
        };
        let p = A2APolicy::with_config(cfg);
        // Strict: agent appears in chain but with a different
        // request_id from the parent_request_id => no cycle.
        let chain = vec![hop("agent:b", "req-old")];
        let c = ctx("agent:b", 2, chain);
        assert!(p.evaluate(&c, "").is_allow());
        // Strict: agent appears with matching parent_request_id => cycle.
        let chain2 = vec![hop("agent:b", "req-parent")];
        let c2 = ctx("agent:b", 2, chain2);
        assert_eq!(p.evaluate(&c2, "").reason_label(), "cycle");
    }

    #[test]
    fn cycle_by_callable_endpoint() {
        let cfg = A2APolicyConfig {
            cycle_detection: CycleDetection::ByCallableEndpoint,
            ..A2APolicyConfig::default()
        };
        let p = A2APolicy::with_config(cfg);
        // Same agent in chain, different endpoint => allowed.
        let chain = vec![hop("agent:b", "endpoint-list")];
        let c = ctx("agent:b", 2, chain);
        assert!(p.evaluate(&c, "endpoint-create").is_allow());
        // Same agent in chain, same endpoint (request_id slot) => not a cycle (per impl).
        // But same agent with different endpoint passes; verify
        // by_agent_id-fallback when endpoint is empty.
        let chain2 = vec![hop("agent:b", "endpoint-list")];
        let c2 = ctx("agent:b", 2, chain2);
        assert_eq!(p.evaluate(&c2, "").reason_label(), "cycle");
    }

    #[test]
    fn callee_not_on_allowlist() {
        let cfg = A2APolicyConfig {
            callee_allowlist: vec!["agent:openai:gpt-5".to_string()],
            ..A2APolicyConfig::default()
        };
        let p = A2APolicy::with_config(cfg);
        let c = ctx("agent:other", 1, Vec::new());
        let d = p.evaluate(&c, "");
        assert_eq!(d.http_status(), 403);
        assert_eq!(d.reason_label(), "callee_not_allowed");
        assert!(d.json_body().contains("a2a_callee_not_allowed"));
        assert!(d.json_body().contains("agent:other"));
    }

    #[test]
    fn callee_on_allowlist_passes() {
        let cfg = A2APolicyConfig {
            callee_allowlist: vec!["agent:openai:gpt-5".to_string()],
            ..A2APolicyConfig::default()
        };
        let p = A2APolicy::with_config(cfg);
        let c = ctx("agent:openai:gpt-5", 1, Vec::new());
        assert!(p.evaluate(&c, "").is_allow());
    }

    #[test]
    fn caller_on_denylist() {
        let cfg = A2APolicyConfig {
            caller_denylist: vec!["agent:caller".to_string()],
            ..A2APolicyConfig::default()
        };
        let p = A2APolicy::with_config(cfg);
        let c = ctx("agent:b", 1, Vec::new());
        let d = p.evaluate(&c, "");
        assert_eq!(d.http_status(), 403);
        assert_eq!(d.reason_label(), "caller_denied");
        assert!(d.json_body().contains("a2a_caller_denied"));
    }

    #[test]
    fn caller_denylist_runs_before_other_checks() {
        // If both denylist and depth would fire, the denylist wins.
        let cfg = A2APolicyConfig {
            caller_denylist: vec!["agent:caller".to_string()],
            max_chain_depth: 1,
            ..A2APolicyConfig::default()
        };
        let p = A2APolicy::with_config(cfg);
        let c = ctx("agent:b", 50, Vec::new());
        assert_eq!(p.evaluate(&c, "").reason_label(), "caller_denied");
    }

    #[test]
    fn from_config_round_trips_yaml_shape() {
        let json = serde_json::json!({
            "max_chain_depth": 3,
            "allow_cycles": false,
            "cycle_detection": "by_agent_id",
            "callee_allowlist": ["agent:a"],
            "caller_denylist": ["agent:bad"],
            "bill_caller_only": true
        });
        let p = A2APolicy::from_config(json).unwrap();
        assert_eq!(p.config().max_chain_depth, 3);
        assert_eq!(p.config().callee_allowlist, vec!["agent:a"]);
        assert_eq!(p.config().caller_denylist, vec!["agent:bad"]);
    }

    #[test]
    fn from_config_accepts_empty_block() {
        let p = A2APolicy::from_config(serde_json::json!({})).unwrap();
        assert_eq!(p.config().max_chain_depth, DEFAULT_MAX_CHAIN_DEPTH);
    }

    #[test]
    fn json_body_escapes_quotes_and_backslashes() {
        let d = A2APolicyDecision::CalleeNotAllowed {
            callee: "agent:\"weird\\name\"".to_string(),
        };
        let body = d.json_body();
        // Must be valid JSON.
        let _: serde_json::Value = serde_json::from_str(&body).unwrap();
    }

    #[test]
    fn cycle_position_indexes_chain_correctly() {
        let p = A2APolicy::with_config(A2APolicyConfig::default());
        let chain = vec![
            hop("agent:root", "r0"),
            hop("agent:mid", "r1"),
            hop("agent:b", "r2"),
        ];
        let c = ctx("agent:b", 4, chain);
        match p.evaluate(&c, "") {
            A2APolicyDecision::CycleDetected { cycle_position, .. } => {
                assert_eq!(cycle_position, 2);
            }
            other => panic!("expected CycleDetected, got {other:?}"),
        }
    }
}

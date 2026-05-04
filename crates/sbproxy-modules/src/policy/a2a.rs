// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Soap Bucket LLC

//! A2A policy module (Wave 7 / A7.2).
//!
//! Per-route enforcement for agent-to-agent calls. See
//! `docs/adr-a2a-protocol-envelope.md` § "Policy hook points".
//!
//! The policy fires after authentication and after the G1.4 resolver
//! chain has populated `caller_agent_id`. It evaluates against an
//! `A2AContext` populated by detection + the optional spec parsers;
//! denial paths surface as typed `A2APolicyDecision` variants that
//! the request filter maps to HTTP responses with the spec-pinned
//! status codes and JSON bodies.

use serde::Deserialize;

use crate::auth::a2a::A2AContext;

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
        }
    }
}

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
    /// Caller is on the configured denylist.
    CallerDenied {
        /// Caller identifier that matched a denylist entry.
        caller: String,
    },
}

impl A2APolicyDecision {
    /// True when the decision allows the request.
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Stable string label used for metrics / audit `reason` fields.
    pub fn reason_label(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::ChainDepthExceeded { .. } => "depth",
            Self::CycleDetected { .. } => "cycle",
            Self::CalleeNotAllowed { .. } => "callee_not_allowed",
            Self::CallerDenied { .. } => "caller_denied",
        }
    }

    /// HTTP status code per the ADR's failure-mode pin.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::Allow => 200,
            Self::ChainDepthExceeded { .. } => 429,
            Self::CycleDetected { .. } => 409,
            Self::CalleeNotAllowed { .. } => 403,
            Self::CallerDenied { .. } => 403,
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
            Self::CallerDenied { caller } => format!(
                "{{\"error\":\"a2a_caller_denied\",\"caller\":{}}}",
                json_escape(caller)
            ),
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
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let config: A2APolicyConfig = serde_json::from_value(value)?;
        Ok(Self::with_config(config))
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
        }
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

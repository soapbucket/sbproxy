//! Unified CEL policy plane over the AI decision pipeline.
//!
//! One sandboxed CEL expression expresses cross-cutting rules over the
//! signals the gateway already computes (guardrail verdicts, budget state,
//! routing candidate, principal context) and emits a small, closed set of
//! typed actions, instead of those decisions living in four separate config
//! blocks. The escape hatch in callback-style gateways is an arbitrary
//! Python hook; here the expression runs on the same sandboxed CEL engine
//! as the rest of sbproxy, at line rate, and can only emit actions from the
//! closed [`AiPolicyAction`] set.
//!
//! ## Shape
//!
//! The expression reads an `ai.*` namespace and returns either one action
//! token (a string) or a list of them. Example: "if a free-tier prompt is
//! flagged by two or more guardrails, redact it, route it to the cheap
//! model, and emit a high-priority audit event":
//!
//! ```text
//! ai.principal.tier == "free" && ai.guardrails.flagged_count >= 2
//!   ? ["redact", "route_to:gpt-4o-mini", "audit:high"]
//!   : ["allow"]
//! ```
//!
//! Recognized action tokens (the closed set): `allow`, `block`, `redact`,
//! `route_to:<model>`, `compression:<selector>`, `set_sink_tag:<tag>`,
//! `audit:<priority>`. The
//! expression is compiled (syntax-validated) when the policy is built; an
//! unrecognized token or a non-string/list result at evaluation time falls
//! back to the configured `on_error` action (default `allow`, i.e.
//! fail-open).
//!
//! ## Why this site does not take a failure posture
//!
//! Most controls in the gateway spell their failure behavior as one of
//! four posture words (`closed`, `open`, `degraded`, `observe`). This one
//! deliberately does not, and `AiPolicyConfig::on_error` keeps its own
//! vocabulary. See that field's documentation for the argument.

use sbproxy_extension::cel::{CelContext, CelSurface, CelValue, CompiledCel};
use serde::Deserialize;
use std::collections::HashMap;

/// A single typed action the policy plane can emit. Closed set: parsing an
/// unrecognized token is an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AiPolicyAction {
    /// Proceed unchanged.
    Allow,
    /// Reject the request before dispatch.
    Block,
    /// Mask sensitive content in the prompt and continue.
    Redact,
    /// Force the request onto a specific model.
    RouteTo(String),
    /// Select a route-local request compression pipeline.
    Compression(crate::compression::CompressionSelector),
    /// A recognized compression action whose selector is malformed.
    ///
    /// Evaluation preserves this as a typed action so the request path can
    /// disable compression safely instead of applying the policy-wide
    /// `on_error` fallback.
    InvalidCompressionSelector,
    /// Tag the usage record emitted for this request.
    SetSinkTag(String),
    /// Emit an audit event at the given priority.
    Audit(String),
}

impl AiPolicyAction {
    /// Parse one action token. `name:arg` forms carry an argument.
    pub fn parse(token: &str) -> anyhow::Result<Self> {
        let token = token.trim();
        if let Some((name, arg)) = token.split_once(':') {
            let name = name.trim();
            let arg = arg.trim();
            if arg.is_empty() {
                if name == "compression" {
                    return Ok(Self::InvalidCompressionSelector);
                }
                anyhow::bail!("ai policy action '{name}' requires an argument (got '{token}')");
            }
            return match name {
                "route_to" => Ok(Self::RouteTo(arg.to_string())),
                "compression" => match crate::compression::CompressionSelector::parse(arg) {
                    Ok(selector) => Ok(Self::Compression(selector)),
                    Err(_) => Ok(Self::InvalidCompressionSelector),
                },
                "set_sink_tag" => Ok(Self::SetSinkTag(arg.to_string())),
                "audit" => Ok(Self::Audit(arg.to_string())),
                other => anyhow::bail!("unknown ai policy action '{other}'"),
            };
        }
        match token {
            "allow" => Ok(Self::Allow),
            "block" => Ok(Self::Block),
            "redact" => Ok(Self::Redact),
            other => anyhow::bail!("unknown ai policy action '{other}'"),
        }
    }
}

/// The decision produced by evaluating a policy: an ordered set of actions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AiPolicyDecision {
    /// The actions emitted, in expression order.
    pub actions: Vec<AiPolicyAction>,
    /// True when these actions came from `on_error` rather than from the
    /// expression evaluating successfully.
    ///
    /// The request proceeded *without the policy's decision being made*,
    /// which is a fail-open and is a different operational fact from a
    /// policy that ran and had no opinion. Without this flag the two are
    /// indistinguishable downstream: an expression that dereferences a
    /// field which is null for some traffic would raise the ordinary
    /// decline count and leave the fail-open counter reading zero, so the
    /// only trace of a half-broken policy would be a log line.
    pub fail_open: bool,
}

impl AiPolicyDecision {
    /// True when the request should be rejected.
    pub fn is_block(&self) -> bool {
        self.actions.contains(&AiPolicyAction::Block)
    }
    /// True when the prompt should be redacted before dispatch.
    pub fn redact(&self) -> bool {
        self.actions.contains(&AiPolicyAction::Redact)
    }
    /// The model to force the request onto, if any.
    pub fn route_model(&self) -> Option<&str> {
        self.actions.iter().find_map(|a| match a {
            AiPolicyAction::RouteTo(m) => Some(m.as_str()),
            _ => None,
        })
    }
    /// The first compression selector to apply, if any.
    pub fn compression_selector(&self) -> Option<&crate::compression::CompressionSelector> {
        self.actions
            .iter()
            .find_map(|action| match action {
                AiPolicyAction::Compression(selector) => Some(Some(selector)),
                AiPolicyAction::InvalidCompressionSelector => Some(None),
                _ => None,
            })
            .flatten()
    }
    /// True when the first compression action carries a malformed selector.
    pub fn compression_selector_invalid(&self) -> bool {
        self.actions
            .iter()
            .find_map(|action| match action {
                AiPolicyAction::Compression(_) => Some(false),
                AiPolicyAction::InvalidCompressionSelector => Some(true),
                _ => None,
            })
            .unwrap_or(false)
    }
    /// The usage-record tag to apply, if any.
    pub fn sink_tag(&self) -> Option<&str> {
        self.actions.iter().find_map(|a| match a {
            AiPolicyAction::SetSinkTag(t) => Some(t.as_str()),
            _ => None,
        })
    }
    /// The audit priority to emit at, if any.
    pub fn audit_priority(&self) -> Option<&str> {
        self.actions.iter().find_map(|a| match a {
            AiPolicyAction::Audit(p) => Some(p.as_str()),
            _ => None,
        })
    }
}

/// One configured provider's live runtime state, exposed to a routing policy
/// as `ai.providers[i]`.
///
/// A plain-data mirror of [`crate::routing::ProviderRuntimeState`] with the
/// provider name attached and latency converted to milliseconds, so a policy
/// can write `ai.providers.filter(p, p.healthy && p.latency_ms < 500)`
/// directly.
#[derive(Debug, Clone, Default)]
pub struct ProviderStateView {
    /// Provider name (its stable id).
    pub name: String,
    /// `false` only when an active probe marked the provider unhealthy.
    pub healthy: bool,
    /// Health label: `healthy`, `unhealthy`, or `unknown`.
    pub health: String,
    /// Observed p50 latency in milliseconds; `0.0` before the first
    /// observation.
    pub latency_ms: f64,
    /// In-flight request count.
    pub in_flight: i64,
    /// Tokens charged to the current minute.
    pub tokens_used: i64,
    /// `true` when the circuit breaker is open (requests are being rejected).
    pub circuit_open: bool,
    /// Circuit label: `closed`, `open`, or `half_open`.
    pub circuit: String,
}

impl ProviderStateView {
    /// Build a policy-facing view from a router snapshot and the provider's
    /// configured name, converting the p50 latency to milliseconds.
    pub fn from_runtime(name: String, s: &crate::routing::ProviderRuntimeState) -> Self {
        Self {
            name,
            healthy: s.healthy,
            health: s.health.to_string(),
            latency_ms: s.latency_us as f64 / 1000.0,
            in_flight: i64::from(s.in_flight),
            tokens_used: i64::try_from(s.tokens_used).unwrap_or(i64::MAX),
            circuit_open: s.circuit_open,
            circuit: s.circuit.to_string(),
        }
    }
}

/// Borrowed snapshot of the AI decision signals exposed to the policy as
/// the `ai.*` CEL namespace.
#[derive(Debug, Clone, Default)]
pub struct AiDecisionView {
    /// Classified surface (`chat_completions`, `embeddings`, ...).
    pub surface: String,
    /// Requested / resolved model.
    pub model: String,
    /// Leading routing candidate provider name.
    pub provider: String,
    /// Tenant the request resolved to.
    pub tenant: String,
    /// Authenticated key id, when known.
    pub api_key_id: String,
    /// Principal tier / plan tag (e.g. `free`, `pro`), when known.
    pub tier: String,
    /// Security verdict and non-enforcing routing labels exposed to policy.
    pub guardrail_labels: Vec<String>,
    /// Number of enforcing security guardrails that flagged.
    pub guardrail_flagged_count: usize,
    /// Fraction (0.0-1.0+) of the tightest active budget window consumed.
    pub budget_fraction: f64,
    /// True when a budget window is already exceeded.
    pub budget_exceeded: bool,
    /// Estimated prompt tokens, when computed.
    pub input_tokens_est: i64,
    /// Heuristic prompt-difficulty score in `[0.0, 1.0]`, blending prompt
    /// length with code, math, and multi-step-reasoning signals. Low means
    /// "route cheap", high means "route frontier"; zero when the body carries
    /// no scorable prompt text. This is the score the built-in `cost_quality`
    /// strategy routes on, exposed so a routing policy can author that
    /// decision. Bound as `ai.prompt.difficulty`.
    pub prompt_difficulty: f64,
    /// Per-provider live runtime state (health, latency, in-flight, tokens
    /// used, circuit state), index-aligned with the configured providers.
    /// Bound as the `ai.providers` list. Empty when no router state is
    /// gathered (the default).
    pub providers: Vec<ProviderStateView>,
}

impl AiDecisionView {
    /// Build the `ai` CEL namespace map from this view.
    ///
    /// `pub(crate)` so the routing-policy surface (WOR-2366) can bind the
    /// same `ai` decision view a security policy sees.
    pub(crate) fn to_cel(&self) -> CelValue {
        let guardrails = HashMap::from([
            (
                "flagged".to_string(),
                CelValue::Bool(self.guardrail_flagged_count > 0),
            ),
            (
                "flagged_count".to_string(),
                CelValue::Int(self.guardrail_flagged_count as i64),
            ),
            (
                "labels".to_string(),
                CelValue::List(
                    self.guardrail_labels
                        .iter()
                        .map(|l| CelValue::String(l.clone()))
                        .collect(),
                ),
            ),
        ]);
        let budget = HashMap::from([
            (
                "fraction".to_string(),
                CelValue::Float(self.budget_fraction),
            ),
            ("exceeded".to_string(), CelValue::Bool(self.budget_exceeded)),
        ]);
        let tokens = HashMap::from([(
            "input_est".to_string(),
            CelValue::Int(self.input_tokens_est),
        )]);
        let prompt = HashMap::from([(
            "difficulty".to_string(),
            CelValue::Float(self.prompt_difficulty),
        )]);
        let providers = CelValue::List(
            self.providers
                .iter()
                .map(|p| {
                    CelValue::Map(HashMap::from([
                        ("name".to_string(), CelValue::String(p.name.clone())),
                        ("healthy".to_string(), CelValue::Bool(p.healthy)),
                        ("health".to_string(), CelValue::String(p.health.clone())),
                        ("latency_ms".to_string(), CelValue::Float(p.latency_ms)),
                        ("in_flight".to_string(), CelValue::Int(p.in_flight)),
                        ("tokens_used".to_string(), CelValue::Int(p.tokens_used)),
                        ("circuit_open".to_string(), CelValue::Bool(p.circuit_open)),
                        ("circuit".to_string(), CelValue::String(p.circuit.clone())),
                    ]))
                })
                .collect(),
        );
        let principal = HashMap::from([
            ("tenant".to_string(), CelValue::String(self.tenant.clone())),
            (
                "api_key_id".to_string(),
                CelValue::String(self.api_key_id.clone()),
            ),
            ("tier".to_string(), CelValue::String(self.tier.clone())),
        ]);
        let ai = HashMap::from([
            (
                "surface".to_string(),
                CelValue::String(self.surface.clone()),
            ),
            ("model".to_string(), CelValue::String(self.model.clone())),
            (
                "provider".to_string(),
                CelValue::String(self.provider.clone()),
            ),
            ("guardrails".to_string(), CelValue::Map(guardrails)),
            ("budget".to_string(), CelValue::Map(budget)),
            ("tokens".to_string(), CelValue::Map(tokens)),
            ("prompt".to_string(), CelValue::Map(prompt)),
            ("providers".to_string(), providers),
            ("principal".to_string(), CelValue::Map(principal)),
        ]);
        CelValue::Map(ai)
    }
}

/// Declarative config for the AI policy plane, set as
/// `AiHandlerConfig.ai_policy`.
#[derive(Debug, Clone, Deserialize)]
pub struct AiPolicyConfig {
    /// CEL expression returning an action token or a list of tokens.
    pub expression: String,
    /// Action(s) applied when the expression errors or returns an
    /// unrecognized value. Space- or comma-separated tokens. Defaults to
    /// `allow` (fail-open) so a policy bug cannot take the gateway down.
    ///
    /// # Why this is not a failure posture
    ///
    /// Other controls spell this axis with one of four shared words:
    /// `closed`, `open`, `degraded`, `observe`. This site keeps its own
    /// vocabulary on purpose, because it is not a posture. A posture
    /// answers one question, "does the request proceed", and leaves the
    /// rest of the pipeline alone. `on_error` is a whole fallback
    /// decision: an ordered list drawn from the same closed seven-variant
    /// action set the expression itself emits, so the fallback can route,
    /// redact, tag, and audit, not merely admit or refuse. Real
    /// configurations use that:
    ///
    /// ```yaml
    /// on_error: redact route_to:gpt-4o-mini audit:high
    /// ```
    ///
    /// Collapsing that onto four words would delete expressiveness
    /// operators are already using, and there is no posture word for
    /// "redact, downgrade the model, and page someone". Two of the seven
    /// tokens happen to line up, and it is worth knowing which:
    ///
    /// | `on_error` | Shared posture | Meaning |
    /// |---|---|---|
    /// | `block` | `closed` | Reject the request |
    /// | `allow` | `open` | Proceed unchanged, claim nothing |
    ///
    /// The other five have no posture spelling at all. `degraded` has no
    /// analogue either: a policy that could not be evaluated made no
    /// guarantee to waive, because the expression is an operator's own
    /// rule rather than a control with an advertised outcome. Neither
    /// does `observe`, because there is no counterfactual to record: the
    /// expression failed, so there is no decision it would have taken.
    ///
    /// This is also not the unvalidated string it looks like. Every
    /// token is parsed by `parse_action_list` at config-compile time by
    /// [`CompiledAiPolicy::compile`], which rejects an unknown token, an
    /// empty list, and a malformed compression selector before the
    /// policy is ever published. A bad `on_error` is a startup failure,
    /// not a request-time surprise.
    ///
    /// # Why the default is open, and why that is correct
    ///
    /// Every other security control in the gateway defaults closed, and
    /// this one deliberately does not. The rule is that a control
    /// defaults closed when it enforces a security boundary and open
    /// only where refusing would take the gateway down over something
    /// that is not one. This is the second case. `on_error` fires when
    /// the operator's own CEL expression could not be evaluated: a typo
    /// in a field path, a type error, a token the closed set does not
    /// contain. That is a bug in a rule, not evidence that the request
    /// is dangerous, and the guardrails, budgets, and rate limits that
    /// do enforce boundaries have already run and are unaffected by it.
    /// Defaulting closed here would let one malformed expression
    /// black-hole every request on the route, which is a worse outcome
    /// than the rule not applying. An operator who wants the strict
    /// reading sets `on_error: block`, and one who wants the failure
    /// visible without refusing traffic sets `on_error: allow audit:high`.
    #[serde(default = "default_on_error")]
    pub on_error: String,
}

fn default_on_error() -> String {
    "allow".to_string()
}

/// A compiled, ready-to-evaluate policy.
pub struct CompiledAiPolicy {
    cel: CompiledCel,
    on_error: Vec<AiPolicyAction>,
}

impl std::fmt::Debug for CompiledAiPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledAiPolicy")
            .field("expression", &self.cel.source())
            .field("on_error", &self.on_error)
            .finish()
    }
}

/// Parse a whitespace/comma separated list of action tokens.
fn parse_action_list(s: &str) -> anyhow::Result<Vec<AiPolicyAction>> {
    let actions = s
        .split([',', ' ', '\n', '\t'])
        .filter(|t| !t.trim().is_empty())
        .map(AiPolicyAction::parse)
        .collect::<anyhow::Result<Vec<_>>>()?;
    if actions.is_empty() {
        anyhow::bail!("empty action list");
    }
    Ok(actions)
}

impl CompiledAiPolicy {
    /// Compile a policy from config. Fails on a CEL syntax error or an
    /// invalid `on_error` action, so misconfiguration is caught at config
    /// load rather than on the request path.
    pub fn compile(cfg: &AiPolicyConfig) -> anyhow::Result<Self> {
        // Through `CompiledCel` like every other CEL surface, so a
        // reference to a binding the evaluator never sets (there is
        // only `ai`) is a load error with the surface's vocabulary in
        // the message, not a runtime fault the `on_error` list eats.
        let cel = CompiledCel::compile(
            CelSurface::AiPolicy,
            "ai_policy `expression`",
            &cfg.expression,
        )?;
        let on_error = parse_action_list(&cfg.on_error)
            .map_err(|e| anyhow::anyhow!("ai_policy.on_error: {e}"))?;
        if on_error
            .iter()
            .any(|action| matches!(action, AiPolicyAction::InvalidCompressionSelector))
        {
            anyhow::bail!("ai_policy.on_error: invalid compression selector");
        }
        Ok(Self { cel, on_error })
    }

    /// The fallback decision used on an evaluation error.
    fn on_error_decision(&self) -> AiPolicyDecision {
        AiPolicyDecision {
            actions: self.on_error.clone(),
            fail_open: true,
        }
    }

    /// Evaluate the policy against a decision view. Never panics: any
    /// evaluation or parse failure degrades to the configured `on_error`
    /// action.
    pub fn evaluate(&self, view: &AiDecisionView) -> AiPolicyDecision {
        let mut ctx = CelContext::new();
        ctx.set("ai", view.to_cel());
        match self.cel.eval(&ctx) {
            Ok(CelValue::String(s)) => match AiPolicyAction::parse(&s) {
                Ok(a) => AiPolicyDecision {
                    actions: vec![a],
                    fail_open: false,
                },
                Err(e) => {
                    tracing::warn!(error = %e, "ai_policy: unrecognized action token; using on_error");
                    self.on_error_decision()
                }
            },
            Ok(CelValue::List(items)) => {
                let mut actions = Vec::with_capacity(items.len());
                for item in items {
                    match item {
                        CelValue::String(s) => match AiPolicyAction::parse(&s) {
                            Ok(a) => actions.push(a),
                            Err(e) => {
                                tracing::warn!(error = %e, "ai_policy: unrecognized action token; using on_error");
                                return self.on_error_decision();
                            }
                        },
                        other => {
                            tracing::warn!(
                                ?other,
                                "ai_policy: non-string action in list; using on_error"
                            );
                            return self.on_error_decision();
                        }
                    }
                }
                if actions.is_empty() {
                    actions.push(AiPolicyAction::Allow);
                }
                AiPolicyDecision {
                    actions,
                    fail_open: false,
                }
            }
            Ok(other) => {
                tracing::warn!(
                    ?other,
                    "ai_policy: expression returned neither a string nor a list; using on_error"
                );
                self.on_error_decision()
            }
            Err(e) => {
                tracing::warn!(error = %e, "ai_policy: evaluation failed; using on_error");
                self.on_error_decision()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(expr: &str) -> CompiledAiPolicy {
        CompiledAiPolicy::compile(&AiPolicyConfig {
            expression: expr.to_string(),
            on_error: "allow".to_string(),
        })
        .unwrap()
    }

    #[test]
    fn parses_each_action_token() {
        assert_eq!(
            AiPolicyAction::parse("allow").unwrap(),
            AiPolicyAction::Allow
        );
        assert_eq!(
            AiPolicyAction::parse("block").unwrap(),
            AiPolicyAction::Block
        );
        assert_eq!(
            AiPolicyAction::parse("redact").unwrap(),
            AiPolicyAction::Redact
        );
        assert_eq!(
            AiPolicyAction::parse("route_to:gpt-4o-mini").unwrap(),
            AiPolicyAction::RouteTo("gpt-4o-mini".into())
        );
        assert_eq!(
            AiPolicyAction::parse("audit:high").unwrap(),
            AiPolicyAction::Audit("high".into())
        );
        assert_eq!(
            AiPolicyAction::parse("compression:coding-agent").unwrap(),
            AiPolicyAction::Compression(crate::compression::CompressionSelector::Profile(
                "coding-agent".into()
            ))
        );
        assert_eq!(
            AiPolicyAction::parse("compression:Bad Name").unwrap(),
            AiPolicyAction::InvalidCompressionSelector
        );
        assert_eq!(
            AiPolicyAction::parse("compression:").unwrap(),
            AiPolicyAction::InvalidCompressionSelector
        );
        assert!(AiPolicyAction::parse("nonsense").is_err());
        assert!(AiPolicyAction::parse("route_to:").is_err());
    }

    #[test]
    fn invalid_expression_fails_to_compile() {
        let err = CompiledAiPolicy::compile(&AiPolicyConfig {
            expression: "this is not ( valid".to_string(),
            on_error: "allow".to_string(),
        });
        assert!(err.is_err(), "syntax error caught at compile time");
    }

    #[test]
    fn malformed_compression_selector_in_on_error_fails_to_compile() {
        let err = CompiledAiPolicy::compile(&AiPolicyConfig {
            expression: r#""allow""#.to_string(),
            on_error: "compression:Upper".to_string(),
        });

        assert!(
            err.is_err(),
            "configured on_error selectors must be validated at config load"
        );
    }

    #[test]
    fn block_when_two_guardrails_flag() {
        let p = policy(r#"ai.guardrails.flagged_count >= 2 ? "block" : "allow""#);
        let mut view = AiDecisionView {
            guardrail_labels: vec!["pii".into(), "injection".into()],
            guardrail_flagged_count: 2,
            ..Default::default()
        };
        assert!(p.evaluate(&view).is_block());
        view.guardrail_labels = vec!["pii".into()];
        view.guardrail_flagged_count = 1;
        assert!(!p.evaluate(&view).is_block());
    }

    #[test]
    fn routing_label_does_not_become_a_security_flag() {
        let p = policy(
            r#""documentation" in ai.guardrails.labels
               && ai.guardrails.flagged_count == 0
               && !ai.guardrails.flagged
               ? "allow"
               : "block""#,
        );
        let view = AiDecisionView {
            guardrail_labels: vec!["documentation".into()],
            ..Default::default()
        };

        assert!(!p.evaluate(&view).is_block());
    }

    #[test]
    fn fuse_redact_route_and_audit_for_free_tier() {
        let p = policy(
            r#"ai.principal.tier == "free" && ai.guardrails.flagged_count >= 2
               ? ["redact", "route_to:gpt-4o-mini", "audit:high"]
               : ["allow"]"#,
        );
        let view = AiDecisionView {
            tier: "free".into(),
            guardrail_labels: vec!["pii".into(), "toxicity".into()],
            guardrail_flagged_count: 2,
            ..Default::default()
        };
        let d = p.evaluate(&view);
        assert!(d.redact());
        assert_eq!(d.route_model(), Some("gpt-4o-mini"));
        assert_eq!(d.audit_priority(), Some("high"));
        assert!(!d.is_block());
    }

    #[test]
    fn budget_fraction_drives_downgrade() {
        let p = policy(r#"ai.budget.fraction > 0.9 ? "route_to:gpt-4o-mini" : "allow""#);
        let view = AiDecisionView {
            budget_fraction: 0.95,
            ..Default::default()
        };
        assert_eq!(p.evaluate(&view).route_model(), Some("gpt-4o-mini"));
    }

    #[test]
    fn prompt_difficulty_is_bound_and_drives_upgrade() {
        // The operator-authored `cost_quality`: a hard prompt routes frontier,
        // an easy one falls through to the configured strategy.
        let p = policy(r#"ai.prompt.difficulty > 0.7 ? "route_to:gpt-4o" : "allow""#);
        let hard = AiDecisionView {
            prompt_difficulty: 0.85,
            ..Default::default()
        };
        assert_eq!(p.evaluate(&hard).route_model(), Some("gpt-4o"));
        let easy = AiDecisionView {
            prompt_difficulty: 0.1,
            ..Default::default()
        };
        assert_eq!(p.evaluate(&easy).route_model(), None);
    }

    #[test]
    fn provider_state_is_bound_and_filters_on_health_and_latency() {
        // Operator-authored latency/health-aware routing: allow only when a
        // healthy, fast, non-tripped provider exists. Proves `ai.providers`
        // binds as a list of maps a comprehension can filter.
        let p = policy(
            r#"ai.providers.exists(x, x.healthy && x.latency_ms < 500.0 && !x.circuit_open)
               ? "allow" : "block""#,
        );
        let healthy_fast = ProviderStateView {
            name: "a".into(),
            healthy: true,
            health: "healthy".into(),
            latency_ms: 120.0,
            circuit: "closed".into(),
            ..Default::default()
        };
        let view = AiDecisionView {
            providers: vec![healthy_fast],
            ..Default::default()
        };
        assert!(!p.evaluate(&view).is_block());

        // A single slow, unhealthy, tripped provider: the comprehension finds
        // nobody, so the expression blocks.
        let slow_sick = ProviderStateView {
            name: "b".into(),
            healthy: false,
            health: "unhealthy".into(),
            latency_ms: 2000.0,
            circuit_open: true,
            circuit: "open".into(),
            ..Default::default()
        };
        let view2 = AiDecisionView {
            providers: vec![slow_sick],
            ..Default::default()
        };
        assert!(p.evaluate(&view2).is_block());
    }

    #[test]
    fn from_runtime_converts_latency_and_carries_state() {
        use crate::routing::ProviderRuntimeState;
        let healthy = ProviderRuntimeState {
            latency_us: 2_500, // 2.5 ms
            in_flight: 3,
            tokens_used: 100,
            healthy: true,
            health: "unknown",
            circuit_open: false,
            circuit: "closed",
        };
        let v = ProviderStateView::from_runtime("a".into(), &healthy);
        assert_eq!(v.name, "a");
        assert_eq!(v.latency_ms, 2.5);
        assert_eq!(v.in_flight, 3);
        assert_eq!(v.tokens_used, 100);
        assert!(v.healthy);
        assert_eq!(v.health, "unknown");
        assert!(!v.circuit_open);
        assert_eq!(v.circuit, "closed");

        let degraded = ProviderRuntimeState {
            latency_us: 0,
            in_flight: 0,
            tokens_used: 0,
            healthy: false,
            health: "unhealthy",
            circuit_open: true,
            circuit: "open",
        };
        let v2 = ProviderStateView::from_runtime("b".into(), &degraded);
        assert_eq!(v2.latency_ms, 0.0);
        assert!(!v2.healthy);
        assert_eq!(v2.health, "unhealthy");
        assert!(v2.circuit_open);
        assert_eq!(v2.circuit, "open");
    }

    #[test]
    fn decision_exposes_first_compression_selector() {
        let p = policy(r#"["compression:off", "compression:coding-agent"]"#);
        let decision = p.evaluate(&AiDecisionView::default());

        assert_eq!(
            decision.compression_selector(),
            Some(&crate::compression::CompressionSelector::Off)
        );
    }

    #[test]
    fn malformed_compression_action_is_typed_safe_off_not_policy_on_error() {
        let policy = CompiledAiPolicy::compile(&AiPolicyConfig {
            expression: r#""compression:Bad Name""#.into(),
            on_error: "allow".into(),
        })
        .unwrap();

        let decision = policy.evaluate(&AiDecisionView::default());

        assert!(decision.compression_selector().is_none());
        assert!(decision.compression_selector_invalid());
        assert_eq!(
            decision.actions,
            vec![AiPolicyAction::InvalidCompressionSelector]
        );
    }

    #[test]
    fn evaluation_error_falls_back_to_on_error() {
        // `on_error` set to block; force a type error by returning an int.
        let p = CompiledAiPolicy::compile(&AiPolicyConfig {
            expression: "1 + 1".to_string(),
            on_error: "block".to_string(),
        })
        .unwrap();
        let d = p.evaluate(&AiDecisionView::default());
        assert!(d.is_block(), "non-string result uses on_error");
    }

    #[test]
    fn on_error_keeps_its_own_vocabulary_and_its_deliberate_open_default() {
        // The default is open on purpose, and it is the one place in the
        // gateway where that is the right call: a bug in an operator's
        // own expression must not black-hole every request on the route.
        assert_eq!(default_on_error(), "allow");
        let document = serde_json::json!({"expression": r#""allow""#});
        let config: AiPolicyConfig = serde_json::from_value(document).unwrap();
        assert_eq!(config.on_error, "allow");

        // The two tokens that line up with the shared posture words.
        assert_eq!(
            parse_action_list("block").unwrap(),
            vec![AiPolicyAction::Block]
        );
        assert_eq!(
            parse_action_list("allow").unwrap(),
            vec![AiPolicyAction::Allow]
        );

        // The multi-token fallback decision no posture word can express,
        // which is the reason this site kept its own vocabulary.
        let actions = parse_action_list("redact route_to:gpt-4o-mini audit:high").unwrap();
        assert_eq!(
            actions,
            vec![
                AiPolicyAction::Redact,
                AiPolicyAction::RouteTo("gpt-4o-mini".into()),
                AiPolicyAction::Audit("high".into()),
            ]
        );

        // A posture word is not an action token here. It is rejected at
        // config-compile time rather than quietly accepted and mapped to
        // something arbitrary.
        for posture in ["closed", "open", "degraded", "observe"] {
            assert!(AiPolicyAction::parse(posture).is_err(), "{posture}");
            let config = AiPolicyConfig {
                expression: r#""allow""#.to_string(),
                on_error: posture.to_string(),
            };
            assert!(CompiledAiPolicy::compile(&config).is_err(), "{posture}");
        }
    }

    #[test]
    fn unknown_runtime_token_uses_on_error() {
        let p = CompiledAiPolicy::compile(&AiPolicyConfig {
            expression: r#""frobnicate""#.to_string(),
            on_error: "allow".to_string(),
        })
        .unwrap();
        let d = p.evaluate(&AiDecisionView::default());
        assert_eq!(d.actions, vec![AiPolicyAction::Allow]);
    }
}

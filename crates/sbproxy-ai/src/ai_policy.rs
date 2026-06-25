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
//! `route_to:<model>`, `set_sink_tag:<tag>`, `audit:<priority>`. The
//! expression is compiled (syntax-validated) when the policy is built; an
//! unrecognized token or a non-string/list result at evaluation time falls
//! back to the configured `on_error` action (default `allow`, i.e.
//! fail-open).

use sbproxy_extension::cel::{CelContext, CelEngine, CelExpression, CelValue};
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
            let arg = arg.trim();
            if arg.is_empty() {
                anyhow::bail!("ai policy action '{name}' requires an argument (got '{token}')");
            }
            return match name.trim() {
                "route_to" => Ok(Self::RouteTo(arg.to_string())),
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
    /// Labels of the guardrails that flagged the request.
    pub guardrail_labels: Vec<String>,
    /// Fraction (0.0-1.0+) of the tightest active budget window consumed.
    pub budget_fraction: f64,
    /// True when a budget window is already exceeded.
    pub budget_exceeded: bool,
    /// Estimated prompt tokens, when computed.
    pub input_tokens_est: i64,
}

impl AiDecisionView {
    /// Build the `ai` CEL namespace map from this view.
    fn to_cel(&self) -> CelValue {
        let guardrails = HashMap::from([
            (
                "flagged".to_string(),
                CelValue::Bool(!self.guardrail_labels.is_empty()),
            ),
            (
                "flagged_count".to_string(),
                CelValue::Int(self.guardrail_labels.len() as i64),
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
    #[serde(default = "default_on_error")]
    pub on_error: String,
}

fn default_on_error() -> String {
    "allow".to_string()
}

/// A compiled, ready-to-evaluate policy.
pub struct CompiledAiPolicy {
    engine: CelEngine,
    expr: CelExpression,
    on_error: Vec<AiPolicyAction>,
}

impl std::fmt::Debug for CompiledAiPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledAiPolicy")
            .field("expression", &self.expr.source())
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
        let engine = CelEngine::new();
        let expr = engine
            .compile(&cfg.expression)
            .map_err(|e| anyhow::anyhow!("ai_policy.expression: {e}"))?;
        let on_error = parse_action_list(&cfg.on_error)
            .map_err(|e| anyhow::anyhow!("ai_policy.on_error: {e}"))?;
        Ok(Self {
            engine,
            expr,
            on_error,
        })
    }

    /// The fallback decision used on an evaluation error.
    fn on_error_decision(&self) -> AiPolicyDecision {
        AiPolicyDecision {
            actions: self.on_error.clone(),
        }
    }

    /// Evaluate the policy against a decision view. Never panics: any
    /// evaluation or parse failure degrades to the configured `on_error`
    /// action.
    pub fn evaluate(&self, view: &AiDecisionView) -> AiPolicyDecision {
        let mut ctx = CelContext::new();
        ctx.set("ai", view.to_cel());
        match self.engine.eval(&self.expr, &ctx) {
            Ok(CelValue::String(s)) => match AiPolicyAction::parse(&s) {
                Ok(a) => AiPolicyDecision { actions: vec![a] },
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
                AiPolicyDecision { actions }
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
    fn block_when_two_guardrails_flag() {
        let p = policy(r#"ai.guardrails.flagged_count >= 2 ? "block" : "allow""#);
        let mut view = AiDecisionView {
            guardrail_labels: vec!["pii".into(), "injection".into()],
            ..Default::default()
        };
        assert!(p.evaluate(&view).is_block());
        view.guardrail_labels = vec!["pii".into()];
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

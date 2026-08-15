// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The operator-authored AI routing policy (WOR-2366).
//!
//! A security policy ([`crate::ai_policy`]) returns an action from a
//! closed set. A routing policy returns a *plan*: an ordered list of
//! provider/model candidates the request should try, in order, with
//! per-candidate quality and cost gates. The plan dispatches through the
//! same cascade executor the built-in `Cascade` strategy uses, so a
//! policy is never less capable than the strategy it extends.
//!
//! The engine is CEL for now. CEL returns a scalar, not a document, so
//! this surface exists to prove the shape; the document engines (Lua,
//! JavaScript, WASM, Rego) slot in later behind the same
//! [`crate::route_event`] decoder without changing the plan type or the
//! dispatch wiring.
//!
//! ## Three outcomes, not two
//!
//! - [`AiRoutingOutcome::Plan`] executes the plan.
//! - [`AiRoutingOutcome::Decline`] is the common, cheap path: the policy
//!   had no opinion, so the configured [`crate::routing::RoutingStrategy`]
//!   runs unchanged. A null, an empty document, or an absent `candidates`
//!   key all decline.
//! - [`AiRoutingOutcome::Error`] is an evaluation fault, a malformed
//!   document, a missing reason, or a plan naming an unconfigured
//!   provider. `on_error` governs it, and it is counted separately from a
//!   decline so "the policy had no opinion" and "the policy broke" are
//!   never the same line on a dashboard.

use std::collections::HashSet;

use sbproxy_extension::cel::{CelContext, CelSurface, CelValue, CompiledCel};
use serde::Deserialize;

use crate::ai_policy::AiDecisionView;
use crate::route_event::{decode_route_plan, RouteDecision};
use crate::routing::CascadeConfig;

/// Upper bound on the operator's `reason_codes` allowlist.
///
/// Every entry is a permitted value of a bounded metric label, so the
/// list is a cardinality budget. A config that named hundreds of codes
/// would defeat the point of normalizing the label at all.
const MAX_REASON_CODES: usize = 32;

/// Upper bound on one `reason_codes` entry, in bytes.
const MAX_REASON_CODE_BYTES: usize = 64;

/// What a routing policy does when its evaluation faults.
///
/// Scoped to this policy rather than reusing `ai_policy.on_error`: the two
/// are separate sites (a routing user should not have to configure a
/// security policy to say what happens when routing breaks), and a
/// routing fault has only two sensible answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AiRoutingOnError {
    /// Fall through to the configured routing strategy, the same as a
    /// decline. Fail-open, and the default: a broken optimization policy
    /// should not take the gateway down.
    #[default]
    Decline,
    /// Block the request. Fail-closed, for an operator who would rather a
    /// routing fault surface than silently serve on the default strategy.
    Block,
}

impl AiRoutingOnError {
    fn parse(raw: &str) -> anyhow::Result<Self> {
        match raw.trim() {
            "decline" => Ok(Self::Decline),
            "block" => Ok(Self::Block),
            other => anyhow::bail!(
                "ai_routing_policy.on_error must be `decline` or `block`, got {other:?}"
            ),
        }
    }
}

/// Config for the operator-authored routing policy.
///
/// Two mutually exclusive authoring forms:
///
/// - `expression`: a CEL expression (the original form, unchanged).
/// - `engine` + `source`: an inline document engine, `lua`, `js`, or
///   `rego`. Rego additionally accepts `query` (default
///   `data.sbproxy.route`), `data` (a base-data document, WOR-2420), and
///   `budget_ms`. A `wasm` routing hook is a compiled bundle, not inline
///   source, and arrives through the extension-bundle registry in a later
///   slice, mirroring the decision-script rule.
///
/// `on_error` and `reason_codes` are engine-neutral.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiRoutingPolicyConfig {
    /// CEL expression returning a routing-plan document (or a decline).
    /// Mutually exclusive with `engine`/`source`.
    #[serde(default)]
    pub expression: Option<String>,
    /// Document engine for `source`: `lua`, `js`, or `rego`.
    #[serde(default)]
    pub engine: Option<String>,
    /// Inline script/module for `engine`. The script reads the same `ai`
    /// document CEL reads (Lua/JS as an `ai` global, Rego as `input.ai`)
    /// and returns a routing-plan document, or null/nothing to decline.
    #[serde(default)]
    pub source: Option<String>,
    /// Rego only: the rule to evaluate. Defaults to `data.sbproxy.route`.
    #[serde(default)]
    pub query: Option<String>,
    /// Rego only: a base-data document the rules read as `data.*`, kept
    /// separate from the module so tables change without policy edits.
    #[serde(default)]
    pub data: Option<serde_json::Value>,
    /// Rego only: evaluation budget in milliseconds. Defaults to 50, the
    /// same bound the `rego` policy module uses.
    #[serde(default)]
    pub budget_ms: Option<u64>,
    /// What to do when the expression faults or returns a malformed plan.
    /// `decline` (default) or `block`.
    #[serde(default = "default_on_error")]
    pub on_error: String,
    /// Allowlist of `reason_code` values the routing metric may carry.
    /// A code the policy returns that is not listed collapses to `other`;
    /// an absent code becomes the constant `policy`. This keeps a policy
    /// from minting unbounded metric-label cardinality through the door.
    #[serde(default)]
    pub reason_codes: Vec<String>,
}

fn default_on_error() -> String {
    "decline".to_owned()
}

/// Default Rego evaluation budget, matching the `rego` policy module.
const DEFAULT_REGO_BUDGET_MS: u64 = 50;

/// Default Rego rule for a routing policy.
const DEFAULT_REGO_QUERY: &str = "data.sbproxy.route";

/// The compiled program behind one routing policy, one variant per engine.
///
/// Every variant produces the same routing-plan JSON document; everything
/// after the document (decode, reason, provider check, metric label) is
/// shared, which is what makes the engines interchangeable.
enum RoutingProgram {
    /// A CEL expression, evaluated against the `ai` binding.
    Cel(CompiledCel),
    /// An inline Luau script; the `ai` document is a global. Fresh VM per
    /// evaluation, the decision-script cost model.
    Lua { source: String },
    /// An inline JavaScript script; the `ai` document is a global. Fresh
    /// VM per evaluation, the decision-script cost model.
    Js { source: String },
    /// A Rego module, evaluated on a shared interpreter behind a lock;
    /// the `ai` document is `input.ai`. Boxed because the interpreter is
    /// an order of magnitude larger than the other variants and the
    /// program is built once per config load, so the indirection costs
    /// one allocation per load, not per request.
    Rego(Box<std::sync::Mutex<sbproxy_extension::rego::CompiledRego>>),
}

impl RoutingProgram {
    const fn label(&self) -> &'static str {
        match self {
            Self::Cel(_) => "cel",
            Self::Lua { .. } => "lua",
            Self::Js { .. } => "js",
            Self::Rego(_) => "rego",
        }
    }
}

/// A compiled routing policy, ready to evaluate per request.
pub struct CompiledAiRoutingPolicy {
    program: RoutingProgram,
    on_error: AiRoutingOnError,
    reason_codes: HashSet<String>,
}

impl std::fmt::Debug for CompiledAiRoutingPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledAiRoutingPolicy")
            .field("engine", &self.program.label())
            .field("on_error", &self.on_error)
            .field("reason_codes", &self.reason_codes)
            .finish_non_exhaustive()
    }
}

/// The result of evaluating a routing policy for one request.
#[derive(Debug, Clone, PartialEq)]
pub enum AiRoutingOutcome {
    /// Execute this plan through the cascade executor.
    Plan {
        /// The plan as a cascade config, ready for the executor.
        cascade: CascadeConfig,
        /// The operator-supplied reason, bound for the access log.
        reason: String,
        /// The normalized reason code, bound for the routing metric label.
        reason_code: &'static str,
    },
    /// The policy had no opinion; the configured strategy applies.
    Decline,
    /// Evaluation faulted; `on_error` governs what the caller does.
    Error {
        /// A bounded detail for the debug line, never a metric label.
        detail: String,
        /// The configured `on_error` posture.
        on_error: AiRoutingOnError,
    },
}

impl CompiledAiRoutingPolicy {
    /// Compile and validate a routing policy at config load.
    ///
    /// # Errors
    ///
    /// Returns an error when neither or both authoring forms are present,
    /// when the engine is not one of `lua`/`js`/`rego` (with a
    /// self-explaining refusal for `cel` and `wasm`), when a Rego-only
    /// knob accompanies a non-Rego form, when the program itself does not
    /// compile (CEL against the routing surface; a Rego module through
    /// parse plus the evaluability proof), when `on_error` is not a
    /// recognized posture, or when `reason_codes` exceeds its bounds.
    pub fn compile(cfg: &AiRoutingPolicyConfig) -> anyhow::Result<Self> {
        let program = Self::compile_program(cfg)?;
        let on_error = AiRoutingOnError::parse(&cfg.on_error)?;
        if cfg.reason_codes.len() > MAX_REASON_CODES {
            anyhow::bail!(
                "ai_routing_policy.reason_codes has {} entries, the cap is {MAX_REASON_CODES}",
                cfg.reason_codes.len()
            );
        }
        for code in &cfg.reason_codes {
            if code.is_empty() || code.len() > MAX_REASON_CODE_BYTES {
                anyhow::bail!(
                    "ai_routing_policy.reason_codes entry must be 1..={MAX_REASON_CODE_BYTES} \
                     bytes, got {} bytes",
                    code.len()
                );
            }
        }
        Ok(Self {
            program,
            on_error,
            reason_codes: cfg.reason_codes.iter().cloned().collect(),
        })
    }

    /// Resolve the authoring form and compile the engine-specific program.
    fn compile_program(cfg: &AiRoutingPolicyConfig) -> anyhow::Result<RoutingProgram> {
        match (&cfg.expression, &cfg.engine) {
            (Some(_), Some(_)) => anyhow::bail!(
                "ai_routing_policy takes either `expression` (CEL) or `engine` + `source`, \
                 not both"
            ),
            (None, None) => {
                anyhow::bail!("ai_routing_policy needs `expression` (CEL) or `engine` + `source`")
            }
            (Some(expression), None) => {
                if cfg.source.is_some()
                    || cfg.query.is_some()
                    || cfg.data.is_some()
                    || cfg.budget_ms.is_some()
                {
                    anyhow::bail!(
                        "ai_routing_policy `source`/`query`/`data`/`budget_ms` belong to the \
                         `engine` form; an `expression` policy is CEL and takes none of them"
                    );
                }
                Ok(RoutingProgram::Cel(CompiledCel::compile(
                    CelSurface::AiRouting,
                    "ai_routing_policy `expression`",
                    expression,
                )?))
            }
            (None, Some(engine)) => {
                let source = cfg.source.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("ai_routing_policy `engine: {engine}` needs an inline `source`")
                })?;
                let rego_only_knobs =
                    cfg.query.is_some() || cfg.data.is_some() || cfg.budget_ms.is_some();
                match engine.trim() {
                    "lua" | "js" if rego_only_knobs => anyhow::bail!(
                        "ai_routing_policy `query`/`data`/`budget_ms` are Rego knobs; \
                         `engine: {engine}` takes only `source`"
                    ),
                    "lua" => {
                        // Syntax errors refuse at load. Runtime faults (a nil
                        // index, a bad return shape) still follow `on_error`.
                        sbproxy_extension::lua::LuaEngine::check_syntax(source).map_err(
                            |error| {
                                anyhow::anyhow!(
                                    "ai_routing_policy lua `source` does not parse: {error:#}"
                                )
                            },
                        )?;
                        Ok(RoutingProgram::Lua {
                            source: source.to_owned(),
                        })
                    }
                    // JS has no compile-only seam in the embedded engine, so
                    // a syntax error surfaces at first evaluation under
                    // `on_error` rather than at load; the docs say so.
                    "js" => Ok(RoutingProgram::Js {
                        source: source.to_owned(),
                    }),
                    "rego" => {
                        // Same invariant the `rego` policy module holds: a zero
                        // budget reads as "no budget" but is an instantly
                        // expired timer. The load-time evaluability trial can
                        // finish before regorus's first deadline check, so a
                        // zero would load green and then abort every real
                        // request into `on_error`.
                        if cfg.budget_ms == Some(0) {
                            anyhow::bail!(
                                "ai_routing_policy `budget_ms` must be greater than zero; a \
                                 zero budget would abort every evaluation before the rule ran"
                            );
                        }
                        Ok(RoutingProgram::Rego(Box::new(std::sync::Mutex::new(
                            sbproxy_extension::rego::CompiledRego::compile(
                                "ai_routing_policy",
                                source,
                                cfg.query.as_deref().unwrap_or(DEFAULT_REGO_QUERY),
                                cfg.budget_ms.unwrap_or(DEFAULT_REGO_BUDGET_MS),
                                cfg.data.clone(),
                            )?,
                        ))))
                    }
                    "cel" => anyhow::bail!(
                        "ai_routing_policy CEL policies are written as `expression`, not \
                         `engine: cel`"
                    ),
                    "wasm" => anyhow::bail!(
                        "ai_routing_policy `engine: wasm` is a compiled bundle, not inline \
                         source; a WASM routing hook arrives through the extension-bundle \
                         registry in a later release"
                    ),
                    other => anyhow::bail!(
                        "ai_routing_policy `engine` must be `lua`, `js`, or `rego`, got \
                         {other:?}"
                    ),
                }
            }
        }
    }

    /// The engine label for decision events, mirroring what the program is.
    pub fn decision_engine(&self) -> sbproxy_observe::decision::DecisionEngine {
        match &self.program {
            RoutingProgram::Cel(_) => sbproxy_observe::decision::DecisionEngine::Cel,
            RoutingProgram::Lua { .. } => sbproxy_observe::decision::DecisionEngine::Lua,
            RoutingProgram::Js { .. } => sbproxy_observe::decision::DecisionEngine::JavaScript,
            RoutingProgram::Rego(_) => sbproxy_observe::decision::DecisionEngine::Rego,
        }
    }

    /// Normalize a policy-returned reason code to a bounded metric label.
    ///
    /// Absent becomes the constant `policy`; a code in the operator's
    /// allowlist is returned verbatim (as a `'static` interned string); an
    /// unlisted code collapses to `other`. This is the same closed-set
    /// discipline `ai_metrics::record_routing_fallback` uses, with the
    /// allowlist supplied by config rather than compiled in.
    fn normalize_reason_code(&self, code: Option<&str>) -> &'static str {
        match code {
            None => "policy",
            Some(code) if self.reason_codes.contains(code) => interned_reason_code(code),
            Some(_) => "other",
        }
    }

    /// Evaluate the policy for one request.
    ///
    /// `configured_providers` is the set of provider names the plan's
    /// candidates must resolve against; a plan naming an unconfigured
    /// provider is an [`AiRoutingOutcome::Error`] this release (a strictly
    /// safer disposition than the runtime drop-and-continue a later slice
    /// may adopt).
    pub fn evaluate(
        &self,
        view: &AiDecisionView,
        configured_providers: &[String],
    ) -> AiRoutingOutcome {
        let document = match self.produce_document(view) {
            Ok(document) => document,
            Err(detail) => return self.error(detail),
        };
        let decision = match decode_route_plan(&document) {
            Ok(decision) => decision,
            Err(error) => return self.error(error.to_string()),
        };
        let plan = match decision {
            RouteDecision::Decline => return AiRoutingOutcome::Decline,
            RouteDecision::Plan(plan) => plan,
        };
        if plan.reason.trim().is_empty() {
            return self.error("a non-empty plan must carry a `reason`".to_owned());
        }
        if let Err(error) = plan.require_known_providers(configured_providers) {
            return self.error(error.to_string());
        }
        let reason_code = self.normalize_reason_code(reason_code_of(&document));
        AiRoutingOutcome::Plan {
            // A policy-computed plan has no cascade-wide cost cap; per-
            // candidate `cost_cap` still applies.
            cascade: plan.to_cascade_config(None),
            reason: plan.reason,
            reason_code,
        }
    }

    /// Run the program and produce the routing-plan JSON document.
    ///
    /// Every engine reads the same `ai` vocabulary: CEL binds
    /// [`AiDecisionView::to_cel`], the document engines read
    /// [`AiDecisionView::to_json`] (Lua/JS as an `ai` global, Rego as
    /// `input.ai`), and the parity test keeps the two forms identical. An
    /// `Err` here is an evaluation fault, bounded to a debug detail.
    fn produce_document(&self, view: &AiDecisionView) -> Result<serde_json::Value, String> {
        match &self.program {
            RoutingProgram::Cel(cel) => {
                let mut ctx = CelContext::new();
                ctx.set("ai", view.to_cel());
                match cel.eval(&ctx) {
                    Ok(value) => Ok(cel_to_json(&value)),
                    Err(error) => Err(format!("expression evaluation failed: {error}")),
                }
            }
            RoutingProgram::Lua { source } => {
                let engine = sbproxy_extension::lua::LuaEngine::new()
                    .map_err(|error| format!("lua engine unavailable: {error:#}"))?;
                let mut globals = std::collections::HashMap::new();
                globals.insert("ai".to_owned(), view.to_json());
                engine
                    .execute(source, globals)
                    .map_err(|error| format!("lua evaluation failed: {error:#}"))
            }
            RoutingProgram::Js { source } => {
                let engine = sbproxy_extension::js::JsEngine::new()
                    .map_err(|error| format!("js engine unavailable: {error:#}"))?;
                let mut globals = std::collections::HashMap::new();
                globals.insert("ai".to_owned(), view.to_json());
                engine
                    .execute(source, globals)
                    .map_err(|error| format!("js evaluation failed: {error}"))
            }
            RoutingProgram::Rego(program) => {
                let mut guard = program
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                guard
                    .eval_value(serde_json::json!({ "ai": view.to_json() }))
                    .map_err(|error| format!("rego evaluation failed: {error:#}"))
            }
        }
    }

    fn error(&self, detail: String) -> AiRoutingOutcome {
        AiRoutingOutcome::Error {
            detail,
            on_error: self.on_error,
        }
    }
}

/// Read the top-level `reason_code` string from a plan document, if any.
fn reason_code_of(document: &serde_json::Value) -> Option<&str> {
    document
        .get("reason_code")
        .and_then(serde_json::Value::as_str)
}

/// Intern an allowlisted reason code as a `'static` string.
///
/// The metric label API takes `&'static str`. The allowlist is fixed for
/// the process lifetime (a config reload rebuilds the policy), and the set
/// is capped at [`MAX_REASON_CODES`], so leaking one small string per
/// distinct allowlisted code is bounded and one-time.
fn interned_reason_code(code: &str) -> &'static str {
    use std::sync::{Mutex, OnceLock};
    static INTERNED: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
    let mut set = INTERNED
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(existing) = set.get(code) {
        return existing;
    }
    let leaked: &'static str = Box::leak(code.to_owned().into_boxed_str());
    set.insert(leaked);
    leaked
}

/// Convert a [`CelValue`] into a [`serde_json::Value`] so the shared
/// [`decode_route_plan`] decoder can read it.
///
/// A non-finite float has no JSON representation and becomes `null`;
/// `decode_route_plan` then treats it as an absent optional or a missing
/// field, which is the same as any other malformed number.
pub(crate) fn cel_to_json(value: &CelValue) -> serde_json::Value {
    match value {
        CelValue::String(string) => serde_json::Value::String(string.clone()),
        CelValue::Int(int) => serde_json::Value::from(*int),
        CelValue::Float(float) => serde_json::Number::from_f64(*float)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        CelValue::Bool(boolean) => serde_json::Value::Bool(*boolean),
        CelValue::Map(map) => serde_json::Value::Object(
            map.iter()
                .map(|(key, value)| (key.clone(), cel_to_json(value)))
                .collect(),
        ),
        CelValue::List(list) => serde_json::Value::Array(list.iter().map(cel_to_json).collect()),
        CelValue::Null => serde_json::Value::Null,
        // A pre-converted shared value (the catalog binds as one): the policy
        // result never is, but materialize and convert rather than guess.
        CelValue::Shared(_) => cel_to_json(&value.clone().into_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(expression: &str) -> AiRoutingPolicyConfig {
        AiRoutingPolicyConfig {
            expression: Some(expression.to_owned()),
            engine: None,
            source: None,
            query: None,
            data: None,
            budget_ms: None,
            on_error: default_on_error(),
            reason_codes: Vec::new(),
        }
    }

    /// A config in the `engine` + `source` form, for the document engines.
    fn engine_config(engine: &str, source: &str) -> AiRoutingPolicyConfig {
        AiRoutingPolicyConfig {
            expression: None,
            engine: Some(engine.to_owned()),
            source: Some(source.to_owned()),
            query: None,
            data: None,
            budget_ms: None,
            on_error: default_on_error(),
            reason_codes: Vec::new(),
        }
    }

    fn compile(expression: &str) -> CompiledAiRoutingPolicy {
        CompiledAiRoutingPolicy::compile(&config(expression)).expect("compiles")
    }

    fn providers() -> Vec<String> {
        vec!["openai".to_owned(), "anthropic".to_owned()]
    }

    #[track_caller]
    fn expect_plan(outcome: AiRoutingOutcome) -> (CascadeConfig, String, &'static str) {
        match outcome {
            AiRoutingOutcome::Plan {
                cascade,
                reason,
                reason_code,
            } => (cascade, reason, reason_code),
            other => panic!("expected a plan, got {other:?}"),
        }
    }

    #[test]
    fn a_lua_policy_plans_declines_and_labels_its_engine() {
        let planning = CompiledAiRoutingPolicy::compile(&engine_config(
            "lua",
            r#"
            if ai.prompt.difficulty < 0.5 then
              return { candidates = {{provider_id = "openai", model = "gpt-4o-mini"}},
                       reason = "easy prompt" }
            end
            return nil
            "#,
        ))
        .expect("lua compiles");
        assert_eq!(
            planning.decision_engine(),
            sbproxy_observe::decision::DecisionEngine::Lua
        );

        let easy = AiDecisionView::default(); // difficulty 0.0
        let (cascade, reason, code) = expect_plan(planning.evaluate(&easy, &providers()));
        assert_eq!(cascade.tiers[0].provider_id, "openai");
        assert_eq!(reason, "easy prompt");
        assert_eq!(code, "policy");

        let hard = AiDecisionView {
            prompt_difficulty: 0.9,
            ..Default::default()
        };
        assert_eq!(
            planning.evaluate(&hard, &providers()),
            AiRoutingOutcome::Decline
        );
    }

    #[test]
    fn a_js_policy_plans_and_declines() {
        let policy = CompiledAiRoutingPolicy::compile(&engine_config(
            "js",
            r#"
            ai.budget.fraction > 0.8
              ? { candidates: [{provider_id: "anthropic", model: "claude-sonnet-5"}],
                  reason: "budget pressure", reason_code: "cost" }
              : null
            "#,
        ))
        .expect("js compiles");
        assert_eq!(
            policy.decision_engine(),
            sbproxy_observe::decision::DecisionEngine::JavaScript
        );

        let pressed = AiDecisionView {
            budget_fraction: 0.95,
            ..Default::default()
        };
        let (cascade, _, code) = expect_plan(policy.evaluate(&pressed, &providers()));
        assert_eq!(cascade.tiers[0].provider_id, "anthropic");
        // `cost` is not in the (empty) allowlist, so it collapses.
        assert_eq!(code, "other");

        assert_eq!(
            policy.evaluate(&AiDecisionView::default(), &providers()),
            AiRoutingOutcome::Decline
        );
    }

    #[test]
    fn a_rego_policy_plans_declines_and_reads_base_data() {
        let mut cfg = engine_config(
            "rego",
            r#"
            package sbproxy
            route := {"candidates": [{"provider_id": data.cheap_provider, "model": "gpt-4o-mini"}],
                      "reason": "over budget"} if {
                input.ai.budget.fraction > 0.8
            }
            "#,
        );
        cfg.data = Some(serde_json::json!({ "cheap_provider": "openai" }));
        let policy = CompiledAiRoutingPolicy::compile(&cfg).expect("rego compiles");
        assert_eq!(
            policy.decision_engine(),
            sbproxy_observe::decision::DecisionEngine::Rego
        );

        let pressed = AiDecisionView {
            budget_fraction: 0.9,
            ..Default::default()
        };
        let (cascade, reason, _) = expect_plan(policy.evaluate(&pressed, &providers()));
        assert_eq!(cascade.tiers[0].provider_id, "openai");
        assert_eq!(reason, "over budget");

        // Rule undefined for this input: the policy declines, not errors.
        assert_eq!(
            policy.evaluate(&AiDecisionView::default(), &providers()),
            AiRoutingOutcome::Decline
        );
    }

    #[test]
    fn the_authoring_forms_are_validated_at_load() {
        // Both forms at once.
        let mut both = engine_config("lua", "return nil");
        both.expression = Some("null".to_owned());
        assert!(CompiledAiRoutingPolicy::compile(&both).is_err());

        // Neither form.
        let mut neither = config("null");
        neither.expression = None;
        assert!(CompiledAiRoutingPolicy::compile(&neither).is_err());

        // Engine without source.
        let mut missing = engine_config("lua", "return nil");
        missing.source = None;
        assert!(CompiledAiRoutingPolicy::compile(&missing).is_err());

        // `cel` and `wasm` refuse with their own messages; unknown refuses.
        for engine in ["cel", "wasm", "python"] {
            let error = CompiledAiRoutingPolicy::compile(&engine_config(engine, "x"))
                .expect_err("refused engine");
            assert!(
                error.to_string().contains("ai_routing_policy"),
                "refusal must name the site: {error}"
            );
        }

        // Rego knobs on a non-Rego engine.
        let mut knobs = engine_config("lua", "return nil");
        knobs.budget_ms = Some(10);
        assert!(CompiledAiRoutingPolicy::compile(&knobs).is_err());

        // Rego knobs on the CEL form.
        let mut cel_knobs = config("null");
        cel_knobs.query = Some("data.x.y".to_owned());
        assert!(CompiledAiRoutingPolicy::compile(&cel_knobs).is_err());

        // A Rego module whose query names no rule fails at load, not at
        // the first request.
        let bad_query = engine_config("rego", "package sbproxy\nroute := 1");
        let mut bad = bad_query;
        bad.query = Some("data.sbproxy.missing".to_owned());
        assert!(CompiledAiRoutingPolicy::compile(&bad).is_err());

        // A zero Rego budget would abort every evaluation before the rule
        // ran; refuse it by name, the same invariant the rego policy
        // module holds.
        let mut zero = engine_config("rego", "package sbproxy\nroute := 1");
        zero.budget_ms = Some(0);
        let error = CompiledAiRoutingPolicy::compile(&zero).expect_err("zero budget refused");
        assert!(error.to_string().contains("budget_ms"), "{error}");

        // A Lua syntax error refuses at load, not at the first request.
        let error = CompiledAiRoutingPolicy::compile(&engine_config("lua", "retrun nil"))
            .expect_err("lua typo refused");
        assert!(error.to_string().contains("does not parse"), "{error}");
    }

    #[test]
    fn compile_rejects_a_bad_on_error_and_oversized_reason_codes() {
        let mut cfg = config("null");
        cfg.on_error = "explode".to_owned();
        assert!(CompiledAiRoutingPolicy::compile(&cfg).is_err());

        let mut cfg = config("null");
        cfg.reason_codes = (0..MAX_REASON_CODES + 1).map(|i| format!("c{i}")).collect();
        assert!(CompiledAiRoutingPolicy::compile(&cfg).is_err());

        let mut cfg = config("null");
        cfg.reason_codes = vec!["x".repeat(MAX_REASON_CODE_BYTES + 1)];
        assert!(CompiledAiRoutingPolicy::compile(&cfg).is_err());
    }

    #[test]
    fn a_plan_becomes_a_cascade_with_reason_and_normalized_code() {
        let mut cfg = config(
            r#"{"candidates": [{"provider_id": "openai", "model": "gpt-4o"}], "reason": "cheap tier", "reason_code": "cost"}"#,
        );
        cfg.reason_codes = vec!["cost".to_owned()];
        let policy = CompiledAiRoutingPolicy::compile(&cfg).expect("compiles");
        let view = AiDecisionView::default();

        let AiRoutingOutcome::Plan {
            cascade,
            reason,
            reason_code,
        } = policy.evaluate(&view, &providers())
        else {
            panic!("expected a plan");
        };
        assert_eq!(cascade.tiers.len(), 1);
        assert_eq!(cascade.tiers[0].provider_id, "openai");
        assert_eq!(reason, "cheap tier");
        // An allowlisted code passes through verbatim.
        assert_eq!(reason_code, "cost");
    }

    #[test]
    fn an_unlisted_code_is_other_and_an_absent_code_is_policy() {
        let listed = compile(
            r#"{"candidates": [{"provider_id": "openai", "model": "m"}], "reason": "r", "reason_code": "surprise"}"#,
        );
        let AiRoutingOutcome::Plan { reason_code, .. } =
            listed.evaluate(&AiDecisionView::default(), &providers())
        else {
            panic!("expected a plan");
        };
        assert_eq!(reason_code, "other", "an unlisted code collapses to other");

        let absent =
            compile(r#"{"candidates": [{"provider_id": "openai", "model": "m"}], "reason": "r"}"#);
        let AiRoutingOutcome::Plan { reason_code, .. } =
            absent.evaluate(&AiDecisionView::default(), &providers())
        else {
            panic!("expected a plan");
        };
        assert_eq!(
            reason_code, "policy",
            "an absent code is the policy constant"
        );
    }

    #[test]
    fn declining_spellings_all_leave_the_strategy_alone() {
        for expression in ["null", "{}", r#"{"candidates": []}"#] {
            assert_eq!(
                compile(expression).evaluate(&AiDecisionView::default(), &providers()),
                AiRoutingOutcome::Decline,
                "{expression} must decline"
            );
        }
    }

    #[test]
    fn a_plan_with_no_reason_is_an_error() {
        let outcome = compile(r#"{"candidates": [{"provider_id": "openai", "model": "m"}]}"#)
            .evaluate(&AiDecisionView::default(), &providers());
        assert!(
            matches!(outcome, AiRoutingOutcome::Error { .. }),
            "a non-empty plan must carry a reason, got {outcome:?}"
        );
    }

    #[test]
    fn a_plan_naming_an_unconfigured_provider_is_an_error_not_a_decline() {
        let outcome =
            compile(r#"{"candidates": [{"provider_id": "ghost", "model": "m"}], "reason": "r"}"#)
                .evaluate(&AiDecisionView::default(), &providers());
        let AiRoutingOutcome::Error { detail, .. } = outcome else {
            panic!("an unconfigured provider must be an error, not a decline");
        };
        assert!(
            detail.contains("ghost"),
            "detail names the provider: {detail}"
        );
    }

    #[test]
    fn an_expression_fault_is_an_error_carrying_the_on_error_posture() {
        let mut cfg = config(r#"{"candidates": [{"model": 7}], "reason": "r"}"#);
        cfg.on_error = "block".to_owned();
        // A numeric model is a decode fault (model must be a non-empty string).
        let outcome = CompiledAiRoutingPolicy::compile(&cfg)
            .expect("compiles")
            .evaluate(&AiDecisionView::default(), &providers());
        assert!(matches!(
            outcome,
            AiRoutingOutcome::Error {
                on_error: AiRoutingOnError::Block,
                ..
            }
        ));
    }

    #[test]
    fn cel_to_json_round_trips_the_document_shapes() {
        assert_eq!(cel_to_json(&CelValue::Null), serde_json::Value::Null);
        assert_eq!(cel_to_json(&CelValue::Bool(true)), serde_json::json!(true));
        assert_eq!(cel_to_json(&CelValue::Int(-3)), serde_json::json!(-3));
        assert_eq!(
            cel_to_json(&CelValue::String("s".to_owned())),
            serde_json::json!("s")
        );
        // A non-finite float has no JSON representation and becomes null.
        assert_eq!(
            cel_to_json(&CelValue::Float(f64::NAN)),
            serde_json::Value::Null
        );
        let list = CelValue::List(vec![CelValue::Int(1), CelValue::Int(2)]);
        assert_eq!(cel_to_json(&list), serde_json::json!([1, 2]));
    }
}

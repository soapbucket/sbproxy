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
//! The engines are CEL (`expression`), the inline document engines
//! (`engine: lua`, `js`, `rego`), and compiled WASM bundle hooks
//! (`engine: wasm` + `type`). Every document engine feeds the same
//! [`crate::route_event`] decoder, so the plan type and the dispatch
//! wiring never vary by engine.
//!
//! ## Three outcomes, not two
//!
//! - [`AiRoutingOutcome::Plan`] executes the plan, and carries the ids of
//!   any tiers dropped on the way so the caller can record the re-route.
//! - [`AiRoutingOutcome::Decline`] is the common, cheap path: the policy
//!   had no opinion, so the configured [`crate::routing::RoutingStrategy`]
//!   runs unchanged. A null, an empty document, or an absent `candidates`
//!   key all decline.
//! - [`AiRoutingOutcome::Error`] is an evaluation fault, a malformed
//!   document, a missing reason, or a plan whose every candidate names an
//!   unconfigured provider. A partially unknown plan is not an error: the
//!   dead tiers drop with a warning and the survivors run (WOR-2366 D6).
//!   `on_error` governs the error, and it is counted separately from a
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
/// Three mutually exclusive authoring forms:
///
/// - `expression`: a CEL expression (the original form, unchanged).
/// - `engine` + `source`: an inline document engine, `lua`, `js`, or
///   `rego`. Rego additionally accepts `query` (default
///   `data.sbproxy.route`), `data` (a base-data document, WOR-2420),
///   `budget_ms`, `module_path` (a file alternative to `source`,
///   mutually exclusive with it), and `rego_v0` (parse pre-OPA-1.0
///   syntax).
/// - `engine: wasm` + `type`: a compiled bundle hook of kind
///   `ai_routing`, resolved from the loaded extension bundles when the
///   config compiles, with `vars` as its optional per-policy
///   configuration. Not inline source: the wasm form takes none of the
///   inline knobs, mirroring the decision-script rule.
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
    /// Rego only: a filesystem path to a `.rego` file, read once at
    /// config load (and again on every reload) in place of an inline
    /// `source`. Mutually exclusive with `source`; the Rego form needs
    /// exactly one of the two, the same rule `policy: rego`'s `module` /
    /// `module_path` holds.
    #[serde(default)]
    pub module_path: Option<String>,
    /// Rego only: parse the module as pre-OPA-1.0 Rego v0 (no
    /// `if`/`contains` required) instead of the v1 default. A
    /// compatibility escape hatch for a module pasted from an older OPA
    /// install.
    #[serde(default)]
    pub rego_v0: bool,
    /// Wasm only: the bundle hook's `type:` name. Names an `ai_routing`
    /// hook in a loaded extension bundle; the hook is resolved when the
    /// config compiles, so a typo refuses at load rather than at the
    /// first request.
    #[serde(rename = "type", default)]
    pub hook_type: Option<String>,
    /// Wasm only: per-policy configuration handed to the hook. Validated
    /// against the hook's own `config_schema` (defaults applied, declared
    /// `secret_vars` resolved) when the bundle program is built, the same
    /// prepare path every other envelope adapter takes.
    #[serde(default)]
    pub vars: Option<serde_json::Value>,
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

/// How a wasm routing hook was resolved by the layer that owns the
/// extension-bundle registry.
///
/// A runtime compile prepares the program (schema defaults, secrets,
/// sandbox limits) and hands it over. A validation compile deliberately
/// stops at the lookup, because preparing would resolve the hook's
/// declared secrets and `sbproxy validate` must not reach a secret
/// backend; it reports that the hook exists so the policy still compiles
/// and every other refusal in this file still runs (WOR-2366).
pub enum WasmRoutingResolution {
    /// The hook was resolved and prepared; this program runs the policy.
    Prepared(Box<sbproxy_extension::bundle::WasmAiRoutingProgram>),
    /// The hook was found in the registry but deliberately not prepared.
    /// A policy compiled this way validates but cannot evaluate.
    ValidatedOnly,
}

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
    /// A wasm hook proven to exist but never prepared, the shape a
    /// validation-only compile produces. Evaluating it is a fault
    /// (`on_error` governs), which no production path reaches because
    /// only a runtime compile serves requests.
    WasmValidatedOnly,
    /// A Rego module, evaluated on a shared interpreter behind a lock;
    /// the `ai` document is `input.ai`. Boxed because the interpreter is
    /// an order of magnitude larger than the other variants and the
    /// program is built once per config load, so the indirection costs
    /// one allocation per load, not per request.
    Rego(Box<std::sync::Mutex<sbproxy_extension::rego::CompiledRego>>),
    /// A compiled bundle hook of kind `ai_routing`, resolved at config
    /// compile. The program was prepared through the bundle's
    /// schema/secrets path (its `config_schema` defaults and declared
    /// `secret_vars` applied to `vars`, the sandbox budget attached), so
    /// by the time it lands here it is ready to invoke per request.
    /// Boxed because the program holds an engine handle far larger than
    /// the inline variants, the same `large_enum_variant` reasoning as
    /// `Rego`.
    Wasm(Box<sbproxy_extension::bundle::WasmAiRoutingProgram>),
}

impl RoutingProgram {
    const fn label(&self) -> &'static str {
        match self {
            Self::Cel(_) => "cel",
            Self::Lua { .. } => "lua",
            Self::Js { .. } => "js",
            Self::WasmValidatedOnly => "wasm",
            Self::Rego(_) => "rego",
            Self::Wasm(_) => "wasm",
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
        /// Provider ids dropped from the plan because they named no
        /// configured provider, in plan order. Empty when the plan ran
        /// whole, which is the ordinary case.
        ///
        /// Carried on the outcome rather than left to the warning line
        /// because the dispatcher, not this module, owns what a routing
        /// decision records: a drop changes which tiers run, so a log
        /// line that rotates away cannot be the only trace of it. The
        /// caller is expected to count the drops and reflect them in
        /// whatever it records for the decision, since `reason` and
        /// `reason_code` still describe the plan the policy returned
        /// rather than the one that ran.
        dropped: Vec<String>,
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
    /// Compile and validate a routing policy at config load, with no
    /// bundle program.
    ///
    /// A thin wrapper over [`Self::compile_with_program`] passing `None`:
    /// every non-wasm form compiles identically through either entry, and
    /// an `engine: wasm` config refuses through this one because there is
    /// no loaded bundle to resolve the hook against.
    ///
    /// # Errors
    ///
    /// Everything [`Self::compile_with_program`] refuses.
    pub fn compile(cfg: &AiRoutingPolicyConfig) -> anyhow::Result<Self> {
        Self::compile_with_program(cfg, None)
    }

    /// Compile and validate a routing policy at config load, resolving an
    /// `engine: wasm` form against an already-built bundle program.
    ///
    /// `wasm` is the hook program the caller resolved from the loaded
    /// extension bundles, prepared through the bundle's schema/secrets
    /// path; `None` means no bundle program was supplied, which only an
    /// `engine: wasm` config notices.
    ///
    /// # Errors
    ///
    /// Returns an error when neither or both authoring forms are present,
    /// when the engine is not one of `lua`/`js`/`rego`/`wasm` (with a
    /// self-explaining refusal for `cel`), when a Rego-only knob
    /// accompanies a non-Rego form, when `type`/`vars` accompany a
    /// non-wasm form, when the wasm form is missing its `type` or its
    /// bundle program, when the program itself does not compile (CEL
    /// against the routing surface; a Rego module through parse plus the
    /// evaluability proof), when `on_error` is not a recognized posture,
    /// or when `reason_codes` exceeds its bounds.
    pub fn compile_with_program(
        cfg: &AiRoutingPolicyConfig,
        wasm: Option<WasmRoutingResolution>,
    ) -> anyhow::Result<Self> {
        let program = Self::compile_program(cfg, wasm)?;
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
    ///
    /// `wasm` is consumed only by the `engine: wasm` arm; every other
    /// form ignores it.
    fn compile_program(
        cfg: &AiRoutingPolicyConfig,
        wasm: Option<WasmRoutingResolution>,
    ) -> anyhow::Result<RoutingProgram> {
        // The wasm knobs are refused on every other form up front, the
        // same posture as the Rego-only knobs: a knob that silently does
        // nothing is a config the operator cannot trust.
        if cfg.engine.as_deref().map(str::trim) != Some("wasm")
            && (cfg.hook_type.is_some() || cfg.vars.is_some())
        {
            anyhow::bail!(
                "ai_routing_policy `type`/`vars` belong to `engine: wasm`; no other form \
                 takes them"
            );
        }
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
                // The wasm form is not an inline engine, so it branches
                // before the `source` requirement rather than after it.
                if engine.trim() == "wasm" {
                    return Self::compile_wasm_program(cfg, wasm);
                }
                let rego_only_knobs = cfg.query.is_some()
                    || cfg.data.is_some()
                    || cfg.budget_ms.is_some()
                    || cfg.module_path.is_some()
                    || cfg.rego_v0;
                match engine.trim() {
                    "lua" | "js" if rego_only_knobs => anyhow::bail!(
                        "ai_routing_policy `query`/`data`/`budget_ms`/`module_path`/`rego_v0` \
                         are Rego knobs; `engine: {engine}` takes only `source`"
                    ),
                    "lua" => {
                        let source = cfg.source.as_deref().ok_or_else(|| {
                            anyhow::anyhow!(
                                "ai_routing_policy `engine: {engine}` needs an inline `source`"
                            )
                        })?;
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
                    "js" => {
                        let source = cfg.source.as_deref().ok_or_else(|| {
                            anyhow::anyhow!(
                                "ai_routing_policy `engine: {engine}` needs an inline `source`"
                            )
                        })?;
                        Ok(RoutingProgram::Js {
                            source: source.to_owned(),
                        })
                    }
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
                        // Exactly one of `source` (inline) or `module_path` (a
                        // `.rego` file), the same split `policy: rego`'s
                        // `module` / `module_path` holds.
                        let module = match (&cfg.source, &cfg.module_path) {
                            (Some(_), Some(_)) => anyhow::bail!(
                                "ai_routing_policy rego form takes either `source` (inline) or \
                                 `module_path` (a path to a .rego file), not both"
                            ),
                            (None, None) => anyhow::bail!(
                                "ai_routing_policy `engine: rego` needs `source` (inline) or \
                                 `module_path` (a path to a .rego file)"
                            ),
                            (Some(source), None) => source.clone(),
                            (None, Some(path)) => {
                                std::fs::read_to_string(path).map_err(|error| {
                                    anyhow::anyhow!(
                                        "ai_routing_policy: loading module from {path}: {error}"
                                    )
                                })?
                            }
                        };
                        Ok(RoutingProgram::Rego(Box::new(std::sync::Mutex::new(
                            sbproxy_extension::rego::CompiledRego::compile(
                                "ai_routing_policy",
                                &module,
                                cfg.query.as_deref().unwrap_or(DEFAULT_REGO_QUERY),
                                cfg.budget_ms.unwrap_or(DEFAULT_REGO_BUDGET_MS),
                                cfg.data.clone(),
                                cfg.rego_v0,
                            )?,
                        ))))
                    }
                    "cel" => anyhow::bail!(
                        "ai_routing_policy CEL policies are written as `expression`, not \
                         `engine: cel`"
                    ),
                    other => anyhow::bail!(
                        "ai_routing_policy `engine` must be `lua`, `js`, `rego`, or `wasm`, \
                         got {other:?}"
                    ),
                }
            }
        }
    }

    /// Compile the `engine: wasm` form: a bundle hook named by `type`.
    ///
    /// The config-shape refusals come first so a malformed wasm form
    /// fails the same way whether or not a bundle program was supplied;
    /// the missing-program bail is the defensive last arm, because
    /// production resolution happens where the action compiles and hands
    /// the program in.
    fn compile_wasm_program(
        cfg: &AiRoutingPolicyConfig,
        wasm: Option<WasmRoutingResolution>,
    ) -> anyhow::Result<RoutingProgram> {
        if cfg.hook_type.is_none() {
            anyhow::bail!("ai_routing_policy `engine: wasm` needs a bundle hook `type` to resolve");
        }
        if cfg.source.is_some()
            || cfg.query.is_some()
            || cfg.data.is_some()
            || cfg.budget_ms.is_some()
        {
            anyhow::bail!(
                "ai_routing_policy `source`/`query`/`data`/`budget_ms` are inline-engine \
                 knobs; `engine: wasm` names a compiled bundle hook by `type` and takes \
                 none of them"
            );
        }
        match wasm {
            Some(WasmRoutingResolution::Prepared(program)) => Ok(RoutingProgram::Wasm(program)),
            Some(WasmRoutingResolution::ValidatedOnly) => Ok(RoutingProgram::WasmValidatedOnly),
            None => anyhow::bail!(
                "ai_routing_policy `engine: wasm` requires a loaded extension bundle; the \
                 hook is resolved when the config compiles"
            ),
        }
    }

    /// The engine label for decision events, mirroring what the program is.
    pub fn decision_engine(&self) -> sbproxy_observe::decision::DecisionEngine {
        match &self.program {
            RoutingProgram::Cel(_) => sbproxy_observe::decision::DecisionEngine::Cel,
            RoutingProgram::Lua { .. } => sbproxy_observe::decision::DecisionEngine::Lua,
            RoutingProgram::Js { .. } => sbproxy_observe::decision::DecisionEngine::JavaScript,
            RoutingProgram::WasmValidatedOnly => sbproxy_observe::decision::DecisionEngine::Wasm,
            RoutingProgram::Rego(_) => sbproxy_observe::decision::DecisionEngine::Rego,
            RoutingProgram::Wasm(_) => sbproxy_observe::decision::DecisionEngine::Wasm,
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
    /// candidates resolve against. A candidate naming an unconfigured
    /// provider is a dead tier: it is dropped with a warning and the
    /// survivors run (WOR-2366 D6). The outcome is an
    /// [`AiRoutingOutcome::Error`] only when no candidate survives.
    ///
    /// The dropped ids come back on [`AiRoutingOutcome::Plan`] as
    /// `dropped`, in plan order, so the caller can record the re-route
    /// rather than depend on the warning surviving log rotation.
    pub async fn evaluate(
        &self,
        view: &AiDecisionView,
        configured_providers: &[String],
    ) -> AiRoutingOutcome {
        let document = match self.produce_document(view).await {
            Ok(document) => document,
            Err(detail) => return self.error(detail),
        };
        let decision = match decode_route_plan(&document) {
            Ok(decision) => decision,
            Err(error) => return self.error(error.to_string()),
        };
        let mut plan = match decision {
            RouteDecision::Decline => return AiRoutingOutcome::Decline,
            RouteDecision::Plan(plan) => plan,
        };
        if plan.reason.trim().is_empty() {
            return self.error("a non-empty plan must carry a `reason`".to_owned());
        }
        // WOR-2366 D6: drop the dead tiers and continue on the survivors;
        // error only when nothing survives.
        let dropped = plan.retain_known_providers(configured_providers);
        if plan.candidates.is_empty() {
            return self.error(format!(
                "route.decide named only unconfigured providers: {}",
                quoted_provider_list(&dropped)
            ));
        }
        if !dropped.is_empty() {
            // Attributed to the principal the plan was computed for: a
            // warning naming only the dead providers cannot tell an
            // operator whose traffic re-routed, and one tenant's policy
            // typo looks exactly like every other tenant's in the log.
            tracing::warn!(
                dropped = %quoted_provider_list(&dropped),
                tenant = %view.tenant,
                api_key_id = %view.api_key_id,
                model = %view.model,
                "ai_routing_policy: plan named unconfigured providers; dropped those tiers"
            );
        }
        let reason_code = self.normalize_reason_code(reason_code_of(&document));
        AiRoutingOutcome::Plan {
            // A policy-computed plan has no cascade-wide cost cap; per-
            // candidate `cost_cap` still applies.
            cascade: plan.to_cascade_config(None),
            reason: plan.reason,
            reason_code,
            dropped,
        }
    }

    /// Run the program and produce the routing-plan JSON document.
    ///
    /// Every engine reads the same `ai` vocabulary: CEL binds
    /// [`AiDecisionView::to_cel`], the document engines read
    /// [`AiDecisionView::to_json`] (Lua/JS as an `ai` global, Rego as
    /// `input.ai`, WASM as the invocation document), and the parity test
    /// keeps the two forms identical. An `Err` here is an evaluation
    /// fault, bounded to a debug detail.
    async fn produce_document(&self, view: &AiDecisionView) -> Result<serde_json::Value, String> {
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
            // Unreachable in production: only a runtime compile serves
            // requests, and it always carries a prepared program.
            RoutingProgram::WasmValidatedOnly => Err(
                "wasm routing hook was validated but never prepared; this config was built \
                 for validation only"
                    .to_owned(),
            ),
            RoutingProgram::Rego(program) => {
                let mut guard = program
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                guard
                    .eval_value(serde_json::json!({ "ai": view.to_json() }), &view.tenant)
                    .map_err(|error| format!("rego evaluation failed: {error:#}"))
            }
            // A Null document declines through the shared decode tail,
            // the same as any other engine returning null.
            RoutingProgram::Wasm(program) => program
                .plan(view.to_json())
                .await
                .map_err(|error| format!("wasm evaluation failed: {error}")),
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

/// Join dropped provider ids for a warning or error detail, each in
/// backticks so a blank id stays visible.
///
/// Bounded by construction rather than by truncation: a decoded plan has
/// at most [`crate::route_event::MAX_ROUTE_CANDIDATES`] candidates, each
/// id at most [`crate::route_event::MAX_ROUTE_NAME_BYTES`] bytes.
fn quoted_provider_list(ids: &[String]) -> String {
    ids.iter()
        .map(|id| format!("`{id}`"))
        .collect::<Vec<_>>()
        .join(", ")
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
/// A non-finite float has no JSON representation and becomes `null`, and
/// the decoder reads a null limit as an absent one. An expression whose
/// arithmetic goes NaN or infinite therefore yields a candidate with no
/// `quality_threshold` or `cost_cap` rather than a refusal, which is why
/// [`crate::route_event::RouteCandidate`] tells an operator computing a
/// cap to guard the expression instead.
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
            module_path: None,
            rego_v0: false,
            hook_type: None,
            vars: None,
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
            module_path: None,
            rego_v0: false,
            hook_type: None,
            vars: None,
            on_error: default_on_error(),
            reason_codes: Vec::new(),
        }
    }

    /// A config in the `engine: wasm` + `type` form.
    fn wasm_config(hook_type: Option<&str>) -> AiRoutingPolicyConfig {
        AiRoutingPolicyConfig {
            expression: None,
            engine: Some("wasm".to_owned()),
            source: None,
            query: None,
            data: None,
            budget_ms: None,
            module_path: None,
            rego_v0: false,
            hook_type: hook_type.map(str::to_owned),
            vars: None,
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
                ..
            } => (cascade, reason, reason_code),
            other => panic!("expected a plan, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_lua_policy_plans_declines_and_labels_its_engine() {
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
        let (cascade, reason, code) = expect_plan(planning.evaluate(&easy, &providers()).await);
        assert_eq!(cascade.tiers[0].provider_id, "openai");
        assert_eq!(reason, "easy prompt");
        assert_eq!(code, "policy");

        let hard = AiDecisionView {
            prompt_difficulty: 0.9,
            ..Default::default()
        };
        assert_eq!(
            planning.evaluate(&hard, &providers()).await,
            AiRoutingOutcome::Decline
        );
    }

    #[tokio::test]
    async fn a_js_policy_plans_and_declines() {
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
        let (cascade, _, code) = expect_plan(policy.evaluate(&pressed, &providers()).await);
        assert_eq!(cascade.tiers[0].provider_id, "anthropic");
        // `cost` is not in the (empty) allowlist, so it collapses.
        assert_eq!(code, "other");

        assert_eq!(
            policy
                .evaluate(&AiDecisionView::default(), &providers())
                .await,
            AiRoutingOutcome::Decline
        );
    }

    #[tokio::test]
    async fn a_rego_policy_plans_declines_and_reads_base_data() {
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
        let (cascade, reason, _) = expect_plan(policy.evaluate(&pressed, &providers()).await);
        assert_eq!(cascade.tiers[0].provider_id, "openai");
        assert_eq!(reason, "over budget");

        // Rule undefined for this input: the policy declines, not errors.
        assert_eq!(
            policy
                .evaluate(&AiDecisionView::default(), &providers())
                .await,
            AiRoutingOutcome::Decline
        );
    }

    const ROUTE_ON_BUDGET: &str = r#"
package sbproxy
route := {"candidates": [{"provider_id": "openai", "model": "gpt-4o-mini"}],
          "reason": "over budget"} if {
    input.ai.budget.fraction > 0.8
}
"#;

    #[tokio::test]
    async fn a_rego_module_path_plans_the_same_as_the_inline_source() {
        let directory = tempfile::TempDir::new().expect("tempdir");
        let path = directory.path().join("route.rego");
        std::fs::write(&path, ROUTE_ON_BUDGET).expect("write fixture module");

        let mut cfg = engine_config("rego", "");
        cfg.source = None;
        cfg.module_path = Some(path.display().to_string());
        let policy = CompiledAiRoutingPolicy::compile(&cfg)
            .expect("a module read from module_path compiles");

        let pressed = AiDecisionView {
            budget_fraction: 0.9,
            ..Default::default()
        };
        let (cascade, reason, _) = expect_plan(policy.evaluate(&pressed, &providers()).await);
        assert_eq!(cascade.tiers[0].provider_id, "openai");
        assert_eq!(reason, "over budget");
    }

    #[test]
    fn rego_source_and_module_path_together_or_neither_is_refused() {
        let mut both = engine_config("rego", ROUTE_ON_BUDGET);
        both.module_path = Some("/etc/sbproxy/policies/route.rego".to_owned());
        let error = CompiledAiRoutingPolicy::compile(&both).expect_err("both must refuse");
        assert!(error.to_string().contains("not both"), "{error}");

        let mut neither = engine_config("rego", "");
        neither.source = None;
        let error = CompiledAiRoutingPolicy::compile(&neither).expect_err("neither must refuse");
        assert!(error.to_string().contains("module_path"), "{error}");
    }

    #[test]
    fn module_path_on_a_non_rego_engine_is_refused_as_a_rego_knob() {
        let mut lua = engine_config("lua", "return nil");
        lua.module_path = Some("/etc/sbproxy/policies/route.rego".to_owned());
        let error = CompiledAiRoutingPolicy::compile(&lua).expect_err("module_path on lua refused");
        assert!(error.to_string().contains("Rego knobs"), "{error}");
    }

    #[tokio::test]
    async fn rego_v0_is_wired_from_config_through_to_the_engine() {
        // The exact shape Regorus's own `set_rego_v0` doctest uses: a
        // rule body with no `if`, which the v1 default refuses to parse.
        const V0_STYLE: &str = r#"
package sbproxy
route := {"candidates": [{"provider_id": "openai", "model": "m"}], "reason": "r"} {
    input.ai.budget.fraction > 0.8
}
"#;
        CompiledAiRoutingPolicy::compile(&engine_config("rego", V0_STYLE))
            .expect_err("v0 syntax must not compile without rego_v0: true");

        let mut cfg = engine_config("rego", V0_STYLE);
        cfg.rego_v0 = true;
        let policy =
            CompiledAiRoutingPolicy::compile(&cfg).expect("rego_v0: true compiles the same module");
        let pressed = AiDecisionView {
            budget_fraction: 0.9,
            ..Default::default()
        };
        let (cascade, ..) = expect_plan(policy.evaluate(&pressed, &providers()).await);
        assert_eq!(cascade.tiers[0].provider_id, "openai");
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
    fn a_wasm_form_without_a_hook_type_is_refused_naming_type() {
        let error = CompiledAiRoutingPolicy::compile(&wasm_config(None)).expect_err("no hook type");
        assert!(
            error.to_string().contains("`type`"),
            "the refusal names the missing knob: {error}"
        );

        // The inline knobs are refused on the wasm form even when `type`
        // is present: they belong to the inline engines.
        let mut inline = wasm_config(Some("router"));
        inline.source = Some("return nil".to_owned());
        let error = CompiledAiRoutingPolicy::compile(&inline).expect_err("inline knob refused");
        assert!(error.to_string().contains("inline-engine"), "{error}");
    }

    #[test]
    fn the_wasm_knobs_are_refused_on_every_other_form() {
        // `type` on an inline engine.
        let mut lua = engine_config("lua", "return nil");
        lua.hook_type = Some("router".to_owned());
        let error = CompiledAiRoutingPolicy::compile(&lua).expect_err("type on lua refused");
        assert!(error.to_string().contains("engine: wasm"), "{error}");

        // `vars` on the CEL form.
        let mut cel = config("null");
        cel.vars = Some(serde_json::json!({"tier": "cheap"}));
        let error = CompiledAiRoutingPolicy::compile(&cel).expect_err("vars on cel refused");
        assert!(error.to_string().contains("engine: wasm"), "{error}");
    }

    #[test]
    fn a_wasm_form_through_plain_compile_requires_a_bundle() {
        // `compile` passes no bundle program, so a wasm form through it
        // hits the defensive arm: production resolution happens where the
        // action compiles and hands the program in.
        let error = CompiledAiRoutingPolicy::compile(&wasm_config(Some("router")))
            .expect_err("no bundle program");
        assert!(
            error
                .to_string()
                .contains("requires a loaded extension bundle"),
            "{error}"
        );
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

    #[tokio::test]
    async fn a_plan_becomes_a_cascade_with_reason_and_normalized_code() {
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
            dropped,
        } = policy.evaluate(&view, &providers()).await
        else {
            panic!("expected a plan");
        };
        assert_eq!(cascade.tiers.len(), 1);
        assert_eq!(cascade.tiers[0].provider_id, "openai");
        assert_eq!(reason, "cheap tier");
        // An allowlisted code passes through verbatim.
        assert_eq!(reason_code, "cost");
        assert!(
            dropped.is_empty(),
            "a plan that ran whole reports no drops: {dropped:?}"
        );
    }

    #[tokio::test]
    async fn an_unlisted_code_is_other_and_an_absent_code_is_policy() {
        let listed = compile(
            r#"{"candidates": [{"provider_id": "openai", "model": "m"}], "reason": "r", "reason_code": "surprise"}"#,
        );
        let AiRoutingOutcome::Plan { reason_code, .. } = listed
            .evaluate(&AiDecisionView::default(), &providers())
            .await
        else {
            panic!("expected a plan");
        };
        assert_eq!(reason_code, "other", "an unlisted code collapses to other");

        let absent =
            compile(r#"{"candidates": [{"provider_id": "openai", "model": "m"}], "reason": "r"}"#);
        let AiRoutingOutcome::Plan { reason_code, .. } = absent
            .evaluate(&AiDecisionView::default(), &providers())
            .await
        else {
            panic!("expected a plan");
        };
        assert_eq!(
            reason_code, "policy",
            "an absent code is the policy constant"
        );
    }

    #[tokio::test]
    async fn declining_spellings_all_leave_the_strategy_alone() {
        for expression in ["null", "{}", r#"{"candidates": []}"#] {
            assert_eq!(
                compile(expression)
                    .evaluate(&AiDecisionView::default(), &providers())
                    .await,
                AiRoutingOutcome::Decline,
                "{expression} must decline"
            );
        }
    }

    #[tokio::test]
    async fn a_plan_with_no_reason_is_an_error() {
        let outcome = compile(r#"{"candidates": [{"provider_id": "openai", "model": "m"}]}"#)
            .evaluate(&AiDecisionView::default(), &providers())
            .await;
        assert!(
            matches!(outcome, AiRoutingOutcome::Error { .. }),
            "a non-empty plan must carry a reason, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn a_plan_naming_only_unconfigured_providers_is_an_error_not_a_decline() {
        // WOR-2366 D6: when nothing survives the drop there is nothing to
        // route, so the whole plan is an error, and the detail names every
        // dropped provider so the operator sees all the typos at once.
        let outcome = compile(
            r#"{"candidates": [{"provider_id": "ghost", "model": "m"},
                               {"provider_id": "phantom", "model": "m2"}], "reason": "r"}"#,
        )
        .evaluate(&AiDecisionView::default(), &providers())
        .await;
        let AiRoutingOutcome::Error { detail, .. } = outcome else {
            panic!("a fully unconfigured plan must be an error, not a decline");
        };
        assert!(
            detail.contains("ghost") && detail.contains("phantom"),
            "detail names every dropped provider: {detail}"
        );
    }

    #[tokio::test]
    async fn a_partially_unconfigured_plan_proceeds_on_the_survivors() {
        // WOR-2366 D6: the dead tier drops with a warning and the
        // survivor runs, rather than the whole plan erroring over one
        // unconfigured name.
        let outcome = compile(
            r#"{"candidates": [{"provider_id": "ghost", "model": "m1"},
                               {"provider_id": "openai", "model": "m2"}], "reason": "r"}"#,
        )
        .evaluate(&AiDecisionView::default(), &providers())
        .await;
        let AiRoutingOutcome::Plan {
            cascade,
            reason,
            dropped,
            ..
        } = outcome
        else {
            panic!("a partially unconfigured plan must still route");
        };
        assert_eq!(cascade.tiers.len(), 1, "the dead tier is gone");
        assert_eq!(cascade.tiers[0].provider_id, "openai");
        assert_eq!(cascade.tiers[0].model, "m2");
        assert_eq!(reason, "r", "the surviving plan keeps its reason");
        // The drop reaches the caller as data, not only as a log line the
        // next rotation takes away: `reason` still describes the plan the
        // policy returned, so the outcome is the only place the dispatcher
        // can learn which tiers actually ran.
        assert_eq!(dropped, vec!["ghost".to_owned()]);
    }

    #[tokio::test]
    async fn an_expression_fault_is_an_error_carrying_the_on_error_posture() {
        let mut cfg = config(r#"{"candidates": [{"model": 7}], "reason": "r"}"#);
        cfg.on_error = "block".to_owned();
        // A numeric model is a decode fault (model must be a non-empty string).
        let outcome = CompiledAiRoutingPolicy::compile(&cfg)
            .expect("compiles")
            .evaluate(&AiDecisionView::default(), &providers())
            .await;
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

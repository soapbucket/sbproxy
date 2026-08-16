// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Rego evaluation for `policy: rego`, on the Regorus interpreter.
//!
//! Rego is a second decision language, offered because some operators
//! already have Rego and would rather not rewrite it. It is not a
//! replacement for CEL and not a wider surface: it decides, and it
//! cannot transform, act, or authenticate. That boundary is a property
//! of the language rather than of our sandbox, because Rego performs no
//! I/O during evaluation, so what reaches a policy is whatever the host
//! established first.
//!
//! # Why Regorus and not OPA compiled to WASM
//!
//! OPA's WASM ABI requires the host to allocate inside the guest and
//! the guest to call back into host functions mid-evaluation. Our
//! sandbox holds the opposite invariant: a guest owns its linear memory
//! and the host never reaches in, which is what makes a fresh `Store`
//! per call a complete reset. Supporting OPA's ABI would mean running a
//! second, weaker isolation model beside the first. Regorus evaluates
//! in process against Rust values, so there is no linear memory to
//! cross and no marshalling to pay for.
//!
//! # The input contract
//!
//! `input` is built from the same [`CelContext`]
//! that `policy: expression` evaluates against, converted to JSON. That
//! is deliberate and is the whole reason [`context_to_input`] exists
//! rather than a second assembly path.
//!
//! An operator moving a decision between the two engines should be
//! porting syntax, not vocabulary. `request.trust_tier` in CEL is
//! `input.request.trust_tier` in Rego, and the set of things that exist
//! is identical because it is literally the same map. A second
//! assembler would drift the moment either engine gained a binding, and
//! the drift would be invisible until someone's policy silently read
//! undefined.
//!
//! # What Rego does not inherit
//!
//! The config-load check that [`crate::cel::surface`] performs does not
//! transfer. A CEL expression names its bindings as identifiers, so an
//! unavailable one is detectable before the first request. In Rego,
//! `input.request.nonsense` is simply undefined, which is a legal value
//! the language is built to handle. There is nothing to refuse at load,
//! so a typo degrades to a rule that never fires rather than to a
//! config error.
//!
//! That asymmetry is real and is the strongest argument for preferring
//! CEL where either would do. It is called out in `docs/scripting.md`
//! rather than papered over.
//!
//! # Coverage
//!
//! [`CompiledRego::set_enable_coverage`] and
//! [`CompiledRego::coverage_report`] are thin wrappers over Regorus's
//! own `set_enable_coverage`/`get_coverage_report`, which this crate
//! already pays for (the `coverage` Cargo feature is part of Regorus's
//! `full-opa` default). Nothing on the request path calls either: the
//! sole caller is `sbproxy rego test`, the offline fixture-driven test
//! loop, which enables coverage before running a fixture's cases and
//! reads the report back to print a summary and enforce
//! `--min-coverage`. A production `policy: rego` or `ai_routing_policy`
//! engine never turns this on, so evaluating real traffic pays no
//! coverage-tracking cost.
//!
//! # Rego v0 and `print()`
//!
//! Regorus defaults to Rego v1 (`if`/`contains` required), matching OPA
//! 1.0. `compile`'s `rego_v0` parameter is the escape hatch for a module
//! authored before that switch: it calls
//! [`regorus::Engine::set_rego_v0`] before the module is parsed, so a
//! bare `allow { ... }` rule body compiles the way it did on OPA before
//! 1.0. Leave it `false` for anything written against current OPA.
//!
//! `print()` inside a module never reaches stderr here.
//! [`regorus::Engine::set_gather_prints`] is enabled once, in `compile`,
//! and [`CompiledRego::eval_bool`] / [`CompiledRego::eval_value`] drain
//! whatever the evaluation gathered into one `tracing` event per call,
//! at INFO under the `rego_print` target, naming the site, the query,
//! and the tenant when the caller has one. A print during the one-time
//! load-time evaluability trial that `compile` runs is discarded rather
//! than logged: that trial runs against an empty input for every module
//! regardless of whether an operator's traffic ever reaches it, so
//! treating it as a request-time signal would manufacture an event
//! nothing real produced.

use std::collections::HashMap;

use anyhow::{Context, Result};

use crate::cel::{CelContext, CelValue};

/// Work units between deadline checks during evaluation.
///
/// Regorus checks the clock every N units rather than continuously, so
/// this trades deadline precision against the cost of the check. A
/// thousand is fine grained enough that a runaway rule is stopped in
/// well under a millisecond of overshoot.
const EXECUTION_CHECK_INTERVAL: std::num::NonZeroU32 = match std::num::NonZeroU32::new(1_000) {
    Some(interval) => interval,
    None => unreachable!(),
};

/// A compiled Rego policy, parsed once at config load.
///
/// Holds the engine with its module already added. Per-request work is
/// setting `input` and evaluating the query, which the spike measured
/// at roughly 57 µs against a policy with a role check, a numeric cap,
/// and an ownership rule.
pub struct CompiledRego {
    /// Operator-facing identity, for diagnostics.
    site: String,
    /// The rule reference evaluated per request, for example
    /// `data.sbproxy.allow`.
    query: String,
    engine: regorus::Engine,
}

impl std::fmt::Debug for CompiledRego {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompiledRego")
            .field("site", &self.site)
            .field("query", &self.query)
            .finish()
    }
}

/// Whether a base-data document already defines a value at the rule
/// path a query names.
///
/// The query is `data.<seg>.<seg>...`; the data document is rooted at
/// `data`, so the query's path after the `data.` prefix indexes
/// straight into it. A defined value there is the shadowing Regorus
/// resolves in the base document's favor.
fn data_defines_query_path(data: &serde_json::Value, query: &str) -> bool {
    let Some(path) = query.strip_prefix("data.") else {
        // A query not rooted at `data` (rare) cannot be shadowed by a
        // `data` document; nothing to refuse.
        return false;
    };
    let mut cursor = data;
    for segment in path.split('.') {
        match cursor.get(segment) {
            Some(next) => cursor = next,
            None => return false,
        }
    }
    !cursor.is_null()
}

/// One source file's line coverage from a [`CompiledRego`] engine, read
/// back via [`CompiledRego::coverage_report`].
///
/// Wraps Regorus's own `coverage::Report`/`coverage::File` (line
/// granularity: Regorus does not track which named rule a line belongs
/// to, only whether the interpreter executed it) in a type that does
/// not leak the `regorus` crate through this module's public surface.
#[derive(Debug, Clone)]
pub struct RegoCoverage {
    /// The name `compile` registered the module under (its `site`
    /// argument, with `.rego` appended, since that is the string
    /// `compile` passes to `add_policy`).
    pub path: String,
    /// Source line numbers the interpreter executed at least once.
    pub covered: Vec<u32>,
    /// Source line numbers the interpreter never reached.
    pub not_covered: Vec<u32>,
}

impl RegoCoverage {
    /// Percentage of `covered ∪ not_covered` lines that were covered.
    ///
    /// `100.0` when the module has no lines Regorus tracks coverage for
    /// at all (for example a comment-only file), since there is nothing
    /// for a case to have missed.
    pub fn percent(&self) -> f64 {
        let total = self.covered.len() + self.not_covered.len();
        if total == 0 {
            100.0
        } else {
            (self.covered.len() as f64 / total as f64) * 100.0
        }
    }
}

impl CompiledRego {
    /// Parse `module` and pin `query` as the rule this policy evaluates.
    ///
    /// `rego_v0` selects the parser dialect: `false` (the default
    /// everywhere this is called from config) requires current Rego v1
    /// syntax (`if`/`contains`), matching Regorus's own default and OPA
    /// 1.0. `true` calls [`regorus::Engine::set_rego_v0`] first, so a
    /// module written before that switch (`allow { ... }` with no `if`)
    /// parses. Set it per policy for a pasted-in legacy module rather
    /// than rewriting it; a module authored fresh should not need it.
    ///
    /// # Errors
    ///
    /// Returns an error naming the site when the module does not parse.
    /// A malformed policy is a config error, so boot and reload both
    /// refuse it, matching every other engine that compiles from static
    /// config.
    pub fn compile(
        site: impl Into<String>,
        module: &str,
        query: impl Into<String>,
        budget_ms: u64,
        data: Option<serde_json::Value>,
        rego_v0: bool,
    ) -> Result<Self> {
        let site = site.into();
        let query = query.into();
        let mut engine = regorus::Engine::new();
        // Dialect selection has to precede parsing: v0/v1 changes what
        // the parser accepts, not a post-parse pass.
        engine.set_rego_v0(rego_v0);
        // Gathered rather than left at Regorus's default of stderr, so a
        // `print()` inside a policy lands in the same structured
        // tracing every other engine's script signal goes through
        // rather than on the process's raw stderr. `eval_bool` and
        // `eval_value` drain this per evaluation; the trial run below
        // drains and discards it before the engine ever serves a
        // request.
        engine.set_gather_prints(true);
        engine
            .add_policy(format!("{site}.rego"), module.to_owned())
            .inspect_err(|_| {
                sbproxy_observe::metrics::record_script_compile("rego", "parse_error");
            })
            .with_context(|| format!("{site}: invalid Rego module"))?;

        // Base data (the OPA `data` document, WOR-2420): a static
        // allowlist, role table, or routing map the rule reads as
        // `data.<name>`, kept separate from the module so an operator
        // edits the table without touching the policy logic. Added once
        // here, not per request: the document is fixed for the life of
        // this engine (a config reload rebuilds it), so evaluation pays
        // no clone. A malformed document is a config-load error, not a
        // runtime one.
        if let Some(data) = data {
            // A base-data document that defines a value at the queried
            // rule's own path silently overrides the rule: Regorus
            // prefers the base document over a rule's computed value at
            // the same path, so `data.sbproxy.allow: true` would clobber
            // the `allow` rule and make every request identical while
            // the rule body still runs and spends the budget. Refuse it
            // at load, because nothing downstream can tell the operator
            // their policy logic is dead. The check is at the query
            // path specifically, so base data at a sibling path
            // (`data.sbproxy.roles` next to an `allow` rule) is fine.
            if data_defines_query_path(&data, &query) {
                return Err(anyhow::anyhow!(
                    "{site}: base data defines `{query}`, the rule the query names, so it \
                     would override the rule's own value; put base data under a different \
                     key than the queried rule"
                ));
            }
            let value = regorus::Value::from_json_str(&data.to_string())
                .with_context(|| format!("{site}: base data is not valid JSON"))?;
            engine
                .add_data(value)
                .with_context(|| format!("{site}: base data could not be loaded"))?;
        }

        // Bound evaluation before anything is evaluated, including the
        // trial below. Without this a policy is unbounded on the request
        // path: `net.cidr_expand` over an attacker-supplied header can
        // allocate millions of strings, and it would do so while holding
        // this engine's lock on a runtime worker.
        engine.set_execution_timer_config(regorus::utils::limits::ExecutionTimerConfig {
            limit: std::time::Duration::from_millis(budget_ms),
            check_interval: EXECUTION_CHECK_INTERVAL,
        });

        let mut compiled = Self {
            site,
            query,
            engine,
        };

        // `add_policy` parses and stops. Scheduling, safety analysis,
        // and rule resolution happen on the first evaluation, so a
        // module with an unsafe variable, or a `query` naming no rule,
        // parses clean and then fails every request forever. Force that
        // work now, against an empty input, so it is a config error at
        // boot and reload rather than an origin that 403s permanently
        // with only a warn line to explain it.
        compiled.prove_evaluable().inspect_err(|_| {
            sbproxy_observe::metrics::record_script_compile("rego", "semantic_error");
        })?;
        sbproxy_observe::metrics::record_script_compile("rego", "ok");
        Ok(compiled)
    }

    /// Run the query once against an empty input so deferred analysis
    /// happens at config load.
    ///
    /// An empty input is enough: the analyzer's work does not depend on
    /// input values, and a rule that reads a missing binding yields
    /// `undefined` rather than an error. So this catches the structural
    /// faults and does not reject a policy for reading a field a real
    /// request would carry.
    fn prove_evaluable(&mut self) -> Result<()> {
        self.engine
            .set_input_json("{}")
            .with_context(|| format!("{}: empty input rejected", self.site))?;
        let result = self.engine.eval_rule(self.query.clone());
        // Discard rather than log: this trial runs against an empty
        // input for every module at every boot and reload, whether or
        // not the policy ever sees real traffic, so a `print()` here
        // describes the trial, not a request. Draining still matters,
        // otherwise a print from this call would sit in the buffer and
        // get attributed to whatever the first real evaluation is.
        let _ = self.engine.take_prints();
        result.with_context(|| {
            format!(
                "{}: rule `{}` could not be evaluated. The module parsed, so this is a \
                     semantic fault: an unsafe variable, or a query naming a rule the module \
                     does not define",
                self.site, self.query
            )
        })?;
        Ok(())
    }

    /// Drain `print()` output gathered during the last evaluation into
    /// tracing, one event per call, and never to stderr.
    ///
    /// `compile` turns on [`regorus::Engine::set_gather_prints`] once;
    /// this is the only place that buffer is read. Called after every
    /// per-request evaluation attempt, on both the success and the
    /// error path, since a rule can print before a later line in the
    /// same evaluation faults. `tenant` is the empty string when the
    /// caller has none to attribute the event to.
    fn drain_prints(&mut self, tenant: &str) {
        let Ok(prints) = self.engine.take_prints() else {
            // Only errors when gathering was never enabled, which
            // `compile` always does; nothing to drain either way.
            return;
        };
        for message in prints {
            tracing::info!(
                target: "rego_print",
                site = %self.site,
                query = %self.query,
                tenant_id = tenant,
                "{message}"
            );
        }
    }

    /// The config site this policy came from.
    pub fn site(&self) -> &str {
        &self.site
    }

    /// The rule reference this policy evaluates.
    pub fn query(&self) -> &str {
        &self.query
    }

    /// Enable or disable Regorus's line-coverage instrumentation on this
    /// engine.
    ///
    /// Off by default, matching Regorus's own default, and nothing on
    /// the request path calls this; see the module's "Coverage" section.
    /// Toggling clears whatever coverage the engine has gathered so far
    /// (Regorus's own documented behavior for `set_enable_coverage`).
    pub fn set_enable_coverage(&mut self, enable: bool) {
        self.engine.set_enable_coverage(enable);
    }

    /// Line coverage gathered across every evaluation since coverage was
    /// last enabled or cleared, one entry per source file `compile`
    /// registered (in practice exactly one: this type parses a single
    /// module).
    ///
    /// # Errors
    ///
    /// Returns an error if Regorus cannot assemble the report. The
    /// public API offers no way to trigger this deliberately; the
    /// underlying call is fallible so this mirrors it rather than
    /// hiding a failure behind an empty report.
    pub fn coverage_report(&self) -> Result<Vec<RegoCoverage>> {
        let report = self.engine.get_coverage_report()?;
        Ok(report
            .files
            .into_iter()
            .map(|file| RegoCoverage {
                path: file.path,
                covered: file.covered.into_iter().collect(),
                not_covered: file.not_covered.into_iter().collect(),
            })
            .collect())
    }

    /// Evaluate the pinned query against `ctx`.
    ///
    /// Returns the rule's boolean result. A non-boolean result is an
    /// error rather than a coerced truthy value: a policy whose rule
    /// returns a document has not answered the question this surface
    /// asked, and guessing which way it meant would be worse than
    /// saying so.
    ///
    /// # Errors
    ///
    /// Returns an error when `input` cannot be set, the rule does not
    /// evaluate, or the result is not a boolean. Every one of those is
    /// a fail-closed condition at the call site.
    pub fn eval_bool(&mut self, ctx: &CelContext) -> Result<bool> {
        let start = std::time::Instant::now();
        let outcome = self.eval_bool_inner(ctx);
        sbproxy_observe::metrics::record_script_duration("rego", start.elapsed().as_secs_f64());
        sbproxy_observe::metrics::record_script_invocation(
            "rego",
            if outcome.is_ok() {
                "ok"
            } else {
                "runtime_error"
            },
        );
        outcome
    }

    /// Evaluate the query against an arbitrary JSON `input` document and
    /// return the rule's value as JSON.
    ///
    /// The document form of [`Self::eval_bool`], for callers whose rule
    /// returns a structured decision (the AI routing plan, WOR-2366)
    /// rather than an allow/deny. A rule that is defined but undefined for
    /// this input returns JSON `null`, which such callers read as "the
    /// policy declined"; it is not an error. Stamps the same script
    /// metrics as the boolean form.
    ///
    /// `tenant` attributes any `print()` output from this evaluation;
    /// pass the empty string when the caller has none.
    pub fn eval_value(
        &mut self,
        input: serde_json::Value,
        tenant: &str,
    ) -> Result<serde_json::Value> {
        let start = std::time::Instant::now();
        let outcome = self.eval_value_inner(input, tenant);
        sbproxy_observe::metrics::record_script_duration("rego", start.elapsed().as_secs_f64());
        sbproxy_observe::metrics::record_script_invocation(
            "rego",
            if outcome.is_ok() {
                "ok"
            } else {
                "runtime_error"
            },
        );
        outcome
    }

    fn eval_value_inner(
        &mut self,
        input: serde_json::Value,
        tenant: &str,
    ) -> Result<serde_json::Value> {
        use serde::Deserialize;
        let input = regorus::Value::deserialize(input)
            .with_context(|| format!("{}: input document rejected", self.site))?;
        self.engine.set_input(input);
        let result = self.engine.eval_rule(self.query.clone());
        self.drain_prints(tenant);
        let value = result
            .with_context(|| format!("{}: rule `{}` did not evaluate", self.site, self.query))?;
        if value == regorus::Value::Undefined {
            // An undefined rule value is the policy having no opinion for
            // this input, not a fault.
            return Ok(serde_json::Value::Null);
        }
        serde_json::to_value(&value)
            .with_context(|| format!("{}: rule `{}` value is not JSON", self.site, self.query))
    }

    fn eval_bool_inner(&mut self, ctx: &CelContext) -> Result<bool> {
        use serde::Deserialize;
        // Feed regorus the tree directly rather than serialising to a
        // string it immediately reparses; the conversion is the only
        // pass over the context this way.
        let input = regorus::Value::deserialize(context_to_input(ctx))
            .with_context(|| format!("{}: input document rejected", self.site))?;
        self.engine.set_input(input);
        let result = self.engine.eval_rule(self.query.clone());
        self.drain_prints(tenant_from_context(ctx));
        let value = result
            .with_context(|| format!("{}: rule `{}` did not evaluate", self.site, self.query))?;
        match value {
            regorus::Value::Bool(allowed) => Ok(allowed),
            other => anyhow::bail!(
                "{}: rule `{}` returned {other:?} rather than a boolean",
                self.site,
                self.query
            ),
        }
    }
}

/// The tenant a `policy: expression`-shaped [`CelContext`] resolved to,
/// for attributing a `print()` event to the request that produced it.
///
/// Mirrors the `principal.tenant_id` binding `populate_principal_namespace`
/// sets (see [`crate::cel::context`]): the empty string when no principal
/// namespace was populated, or when it was populated with no tenant.
fn tenant_from_context(ctx: &CelContext) -> &str {
    match ctx.variables.get("principal") {
        Some(CelValue::Map(fields)) => match fields.get("tenant_id") {
            Some(CelValue::String(tenant)) => tenant.as_str(),
            _ => "",
        },
        _ => "",
    }
}

/// Convert the shared CEL context into Rego's `input` document.
///
/// This is the parity seam. Both engines read the same map, so the
/// bindings available to a Rego policy are exactly those available to a
/// CEL expression on the same surface, and adding a binding to one adds
/// it to the other without anybody remembering to.
pub fn context_to_input(ctx: &CelContext) -> serde_json::Value {
    let mut root = serde_json::Map::with_capacity(ctx.variables.len());
    for (name, value) in &ctx.variables {
        root.insert(name.clone(), cel_to_json(value));
    }
    serde_json::Value::Object(root)
}

/// Convert one [`CelValue`] to JSON.
///
/// A non-finite float becomes `null` rather than panicking, because
/// `serde_json::Number::from_f64` refuses NaN and infinity and a
/// decision path must not fail on a value it can represent as absent.
fn cel_to_json(value: &CelValue) -> serde_json::Value {
    match value {
        CelValue::String(text) => serde_json::Value::String(text.clone()),
        CelValue::Int(number) => serde_json::Value::from(*number),
        CelValue::Float(number) => serde_json::Number::from_f64(*number)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        CelValue::Bool(flag) => serde_json::Value::Bool(*flag),
        CelValue::Null => serde_json::Value::Null,
        CelValue::List(items) => serde_json::Value::Array(items.iter().map(cel_to_json).collect()),
        CelValue::Map(entries) => convert_map(entries),
        // A pre-converted shared value: materialize it (an Arc walk, not a
        // document copy at the top) and convert the owned form.
        CelValue::Shared(_) => cel_to_json(&value.clone().into_owned()),
    }
}

/// Convert a CEL map. The source is a `HashMap` with no order of its
/// own; `serde_json::Map` (without `preserve_order`) is a BTreeMap, so
/// keys come out sorted and the document is deterministic.
fn convert_map(entries: &HashMap<String, CelValue>) -> serde_json::Value {
    let mut object = serde_json::Map::with_capacity(entries.len());
    for (key, value) in entries {
        object.insert(key.clone(), cel_to_json(value));
    }
    serde_json::Value::Object(object)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALLOW_ENGINEERS: &str = r#"
package sbproxy

default allow := false

allow if {
    input.request.trust_tier == "strong"
}

allow if {
    input.request.method == "GET"
    input.request.path == "/health"
}
"#;

    fn context() -> CelContext {
        let mut ctx = crate::cel::context::build_request_context(
            "GET",
            "/v1/chat",
            &http::HeaderMap::new(),
            None,
            Some("203.0.113.7"),
            "api.example.com",
        );
        crate::cel::context::populate_trust_tier_namespace(&mut ctx, "anonymous");
        ctx
    }

    /// Like [`context`], with the method and path under the caller's
    /// control, for coverage tests that need to steer which branch of a
    /// rule body a request takes.
    fn ctx_for(method: &str, path: &str) -> CelContext {
        let mut ctx = crate::cel::context::build_request_context(
            method,
            path,
            &http::HeaderMap::new(),
            None,
            Some("203.0.113.7"),
            "api.example.com",
        );
        crate::cel::context::populate_trust_tier_namespace(&mut ctx, "anonymous");
        ctx
    }

    #[test]
    fn a_malformed_module_is_a_config_error_naming_the_site() {
        let error = CompiledRego::compile(
            "policy `rego` (authz)",
            "this is not rego !!!",
            "data.x",
            50,
            None,
            false,
        )
        .expect_err("a malformed module must not compile");
        assert!(error.to_string().contains("policy `rego` (authz)"));
    }

    #[test]
    fn a_rule_decides_from_the_shared_context() {
        let mut policy = CompiledRego::compile(
            "policy `rego`",
            ALLOW_ENGINEERS,
            "data.sbproxy.allow",
            50,
            None,
            false,
        )
        .expect("module compiles");
        let mut ctx = context();
        assert!(
            !policy.eval_bool(&ctx).expect("evaluates"),
            "an anonymous request to /v1/chat matches neither rule"
        );

        crate::cel::context::populate_trust_tier_namespace(&mut ctx, "strong");
        assert!(
            policy.eval_bool(&ctx).expect("evaluates"),
            "a strong trust tier matches the first rule"
        );
    }

    #[test]
    fn a_rule_reads_a_base_data_document() {
        // The OPA data/input split: the module logic references
        // `data.allowed_methods` while the table lives in a separate
        // config value. A request whose method is in the table passes;
        // one that is not is denied.
        const METHOD_ALLOWLIST: &str = r#"
package sbproxy

default allow := false

allow if {
    input.request.method == data.allowed_methods[_]
}
"#;
        let data = serde_json::json!({ "allowed_methods": ["GET", "HEAD"] });
        let mut policy = CompiledRego::compile(
            "policy `rego`",
            METHOD_ALLOWLIST,
            "data.sbproxy.allow",
            50,
            Some(data),
            false,
        )
        .expect("a module reading base data compiles");
        // context() builds a GET, which is in the table.
        let ctx = context();
        assert!(
            policy.eval_bool(&ctx).expect("evaluates"),
            "GET is in the base-data allowlist"
        );

        // A method not in the table is denied, proving the rule really
        // consulted `data` rather than passing everything.
        let mut post_ctx = crate::cel::context::build_request_context(
            "POST",
            "/v1/chat",
            &http::HeaderMap::new(),
            None,
            Some("203.0.113.7"),
            "api.example.com",
        );
        crate::cel::context::populate_trust_tier_namespace(&mut post_ctx, "anonymous");
        assert!(
            !policy.eval_bool(&post_ctx).expect("evaluates"),
            "POST is not in the base-data allowlist"
        );
    }

    #[test]
    fn base_data_shadowing_the_queried_rule_refuses_at_load() {
        // The Regorus base-over-virtual override: a data key at the
        // query path silently clobbers the rule. Refuse it at load.
        let error = CompiledRego::compile(
            "policy `rego`",
            ALLOW_ENGINEERS,
            "data.sbproxy.allow",
            50,
            Some(serde_json::json!({ "sbproxy": { "allow": true } })),
            false,
        )
        .expect_err("base data at the query path must refuse");
        assert!(
            error.to_string().contains("would override the rule"),
            "{error}"
        );
    }

    #[test]
    fn base_data_at_a_sibling_path_is_allowed() {
        // Data under the same package but a different leaf than the
        // queried rule does not shadow it and must load.
        CompiledRego::compile(
            "policy `rego`",
            ALLOW_ENGINEERS,
            "data.sbproxy.allow",
            50,
            Some(serde_json::json!({ "sbproxy": { "roles": ["admin"] } })),
            false,
        )
        .expect("sibling base data does not shadow the rule");
    }

    #[test]
    fn the_input_document_is_the_cel_context_verbatim() {
        // The parity guarantee. If these drift, a policy moved between
        // engines reads undefined where it used to read a value, and
        // Rego will not say so.
        let ctx = context();
        let input = context_to_input(&ctx);
        let object = input.as_object().expect("input is an object");
        for root in ctx.variables.keys() {
            assert!(
                object.contains_key(root),
                "`{root}` is in the CEL context but missing from the Rego input"
            );
        }
        assert_eq!(
            object.len(),
            ctx.variables.len(),
            "the input document must not invent roots the CEL context does not have"
        );
        assert_eq!(
            input["request"]["trust_tier"],
            serde_json::json!("anonymous"),
            "a nested binding must survive the conversion"
        );
    }

    #[test]
    fn a_non_boolean_rule_is_an_error_rather_than_a_guess() {
        const RETURNS_A_DOCUMENT: &str = r#"
package sbproxy

allow := {"reason": "because"}
"#;
        let mut policy = CompiledRego::compile(
            "policy `rego`",
            RETURNS_A_DOCUMENT,
            "data.sbproxy.allow",
            50,
            None,
            false,
        )
        .expect("module compiles");
        let error = policy
            .eval_bool(&context())
            .expect_err("a document is not a verdict");
        assert!(
            error.to_string().contains("rather than a boolean"),
            "{error}"
        );
    }

    #[test]
    fn a_missing_rule_is_refused_at_load_rather_than_denying_forever() {
        // Now a *load* error rather than a runtime one: a query naming
        // no rule used to parse clean and then deny every request
        // forever, with a warn line as the only explanation.
        CompiledRego::compile(
            "policy `rego`",
            ALLOW_ENGINEERS,
            "data.sbproxy.nonexistent",
            50,
            None,
            false,
        )
        .expect_err("a query naming no rule must not load");
    }

    #[test]
    fn a_module_that_parses_but_cannot_be_analysed_is_refused_at_load() {
        // `add_policy` parses and stops; scheduling and safety analysis
        // run on first evaluation. Without the trial evaluation in
        // `compile`, this module booted fine and then denied every
        // request to its origin permanently.
        const UNSAFE_VAR: &str = r#"
package sbproxy

allow if {
    x == 1
}
"#;
        let error = CompiledRego::compile(
            "policy `rego`",
            UNSAFE_VAR,
            "data.sbproxy.allow",
            50,
            None,
            false,
        )
        .expect_err("an unsafe variable must not load");
        let message = format!("{error:#}");
        assert!(message.contains("semantic fault"), "{message}");
    }

    #[test]
    fn a_non_finite_float_becomes_null_rather_than_panicking() {
        let mut ctx = CelContext::new();
        ctx.set("score", CelValue::Float(f64::NAN));
        assert_eq!(context_to_input(&ctx)["score"], serde_json::Value::Null);
    }

    // --- rego_v0 ---

    #[test]
    fn rego_v0_true_accepts_pre_v1_syntax_the_v1_default_refuses() {
        // The exact shape Regorus's own `set_rego_v0` doctest uses: a
        // rule body with no `if`, valid before OPA 1.0 and rejected by
        // Regorus's v1 default the same way current OPA is.
        const V0_STYLE: &str = r#"
package sbproxy

allow {
    input.request.method == "GET"
}
"#;
        CompiledRego::compile(
            "policy `rego`",
            V0_STYLE,
            "data.sbproxy.allow",
            50,
            None,
            false,
        )
        .expect_err("v0 syntax must not compile under the v1 default");

        let mut accepted = CompiledRego::compile(
            "policy `rego`",
            V0_STYLE,
            "data.sbproxy.allow",
            50,
            None,
            true,
        )
        .expect("rego_v0: true compiles the same module");
        assert!(
            accepted.eval_bool(&context()).expect("evaluates"),
            "the v0 rule still decides once it parses"
        );
    }

    // --- coverage ---

    #[test]
    fn coverage_report_reflects_which_branch_a_case_took() {
        // Two comparisons in one rule body, AND-joined, so Rego's own
        // short-circuit semantics (not a Regorus implementation detail)
        // guarantee the second is skipped whenever the first fails.
        // That guarantee is what this test leans on, rather than a
        // hardcoded line number for what Regorus's coverage attributes
        // to a bare `allow if {` declaration line.
        const MODULE: &str = r#"
package sbproxy

default allow := false

allow if {
    input.request.method == "GET"
    input.request.path == "/health"
}
"#;
        let method_line = MODULE
            .lines()
            .position(|line| line.contains("input.request.method"))
            .map(|index| index as u32 + 1)
            .expect("fixture has a method comparison line");
        let path_line = MODULE
            .lines()
            .position(|line| line.contains("input.request.path"))
            .map(|index| index as u32 + 1)
            .expect("fixture has a path comparison line");
        assert_ne!(method_line, path_line);

        let mut both_match = CompiledRego::compile(
            "coverage test",
            MODULE,
            "data.sbproxy.allow",
            50,
            None,
            false,
        )
        .expect("module compiles");
        both_match.set_enable_coverage(true);
        assert!(
            both_match
                .eval_bool(&ctx_for("GET", "/health"))
                .expect("evaluates"),
            "a GET to /health matches both conditions"
        );
        let report = both_match.coverage_report().expect("coverage report");
        assert_eq!(report.len(), 1, "one module was compiled");
        assert_eq!(report[0].path, "coverage test.rego");
        assert!(
            report[0].covered.contains(&method_line) && report[0].covered.contains(&path_line),
            "both comparisons execute when both match: {:?}",
            report[0]
        );

        let mut short_circuits = CompiledRego::compile(
            "coverage test",
            MODULE,
            "data.sbproxy.allow",
            50,
            None,
            false,
        )
        .expect("module compiles");
        short_circuits.set_enable_coverage(true);
        assert!(
            !short_circuits
                .eval_bool(&ctx_for("POST", "/health"))
                .expect("evaluates"),
            "a POST never matches"
        );
        let report = short_circuits.coverage_report().expect("coverage report");
        assert!(
            report[0].covered.contains(&method_line),
            "the method comparison still runs and fails: {:?}",
            report[0]
        );
        assert!(
            report[0].not_covered.contains(&path_line),
            "the path comparison is never reached once the method check fails: {:?}",
            report[0]
        );
        assert!(
            report[0].percent() < 100.0,
            "an unreached line must pull coverage below full: {:?}",
            report[0]
        );
    }

    // --- print() capture ---
    //
    // A hand-rolled `tracing::Subscriber` rather than `tracing-subscriber`,
    // which this crate does not depend on; mirrors
    // `bundle::proxy_wasm::tests::GuestLogLevelCapture`, the existing
    // in-crate tracing-capture pattern. Installed via
    // `tracing::subscriber::with_default` around the one evaluation under
    // test, with `rebuild_interest_cache` forced afterward so a callsite
    // whose Interest cached `Never` under an earlier no-subscriber run
    // cannot stay stuck (see the span-metadata test landmine: a callsite's
    // Interest is cached process-wide, not per test).

    #[derive(Debug, Default, Clone)]
    struct CapturedPrint {
        level: Option<tracing::Level>,
        site: String,
        query: String,
        tenant_id: String,
        message: String,
    }

    impl CapturedPrint {
        fn set(&mut self, name: &str, value: String) {
            match name {
                "site" => self.site = value,
                "query" => self.query = value,
                "tenant_id" => self.tenant_id = value,
                "message" => self.message = value,
                _ => {}
            }
        }
    }

    impl tracing::field::Visit for CapturedPrint {
        // `tenant_id` is passed as a bare `&str`, which tracing routes
        // through `record_str`.
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.set(field.name(), value.to_owned());
        }

        // `site`, `query` (`%`-prefixed) and the format-string `message`
        // field all route through `record_debug`; the `%` wrapper's
        // `Debug` impl is defined in terms of the wrapped type's
        // `Display`, so this renders identically to `record_str` would.
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.set(field.name(), format!("{value:?}"));
        }
    }

    #[derive(Clone, Default)]
    struct RegoPrintCapture {
        events: std::sync::Arc<std::sync::Mutex<Vec<CapturedPrint>>>,
    }

    impl tracing::Subscriber for RegoPrintCapture {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            metadata.target() == "rego_print"
        }

        fn register_callsite(
            &self,
            _metadata: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::sometimes()
        }

        fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
            Some(tracing::level_filters::LevelFilter::TRACE)
        }

        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            if event.metadata().target() != "rego_print" {
                return;
            }
            let mut captured = CapturedPrint {
                level: Some(*event.metadata().level()),
                ..Default::default()
            };
            event.record(&mut captured);
            self.events.lock().unwrap().push(captured);
        }

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }

    #[test]
    fn print_reaches_tracing_at_info_under_rego_print_never_stderr() {
        const PRINTS_WHEN_CHECKED: &str = r#"
package sbproxy

default allow := false

allow if {
    print("checking method:", input.request.method)
    input.request.method == "GET"
}
"#;
        let mut policy = CompiledRego::compile(
            "policy `rego` (print-test)",
            PRINTS_WHEN_CHECKED,
            "data.sbproxy.allow",
            50,
            None,
            false,
        )
        .expect("module compiles");

        let mut ctx = context();
        crate::cel::context::populate_principal_namespace(
            &mut ctx,
            &crate::cel::context::PrincipalView {
                tenant_id: Some("acme"),
                ..Default::default()
            },
        );

        let capture = RegoPrintCapture::default();
        tracing::subscriber::with_default(capture.clone(), || {
            tracing::callsite::rebuild_interest_cache();
            assert!(
                policy.eval_bool(&ctx).expect("evaluates"),
                "a GET from api.example.com still decides true"
            );
        });

        let events = capture.events.lock().expect("capture lock");
        assert_eq!(
            events.len(),
            1,
            "one print() call must produce exactly one event: {events:?}"
        );
        let event = &events[0];
        assert_eq!(event.level, Some(tracing::Level::INFO), "{event:?}");
        assert_eq!(event.site, "policy `rego` (print-test)", "{event:?}");
        assert_eq!(event.query, "data.sbproxy.allow", "{event:?}");
        assert_eq!(
            event.tenant_id, "acme",
            "the tenant on the evaluated context reaches the event: {event:?}"
        );
        assert!(
            event.message.contains("checking method"),
            "the print() text reaches the event: {event:?}"
        );
    }

    #[test]
    fn trial_evaluation_prints_are_discarded_not_logged() {
        // `compile`'s load-time trial (`prove_evaluable`) runs this same
        // query against an empty input at every boot and reload, whether
        // or not the policy ever sees real traffic. The print here does
        // not depend on `input`, so it fires identically on the trial
        // and on a real evaluation; only the trial's `take_prints()` is
        // discarded rather than drained through `tracing`. This pins
        // that split so a future refactor cannot fold the trial into
        // `drain_prints` and start misattributing boot-time trial prints
        // as request-scoped `rego_print` events.
        const ALWAYS_PRINTS: &str = r#"
package sbproxy

default allow := false

allow if {
    print("trial or real, always prints")
    true
}
"#;
        let capture = RegoPrintCapture::default();

        let mut policy = tracing::subscriber::with_default(capture.clone(), || {
            tracing::callsite::rebuild_interest_cache();
            CompiledRego::compile(
                "policy `rego` (trial-print-test)",
                ALWAYS_PRINTS,
                "data.sbproxy.allow",
                50,
                None,
                false,
            )
            .expect("module compiles")
        });
        assert!(
            capture.events.lock().expect("capture lock").is_empty(),
            "compile's load-time trial must not produce a rego_print event: {:?}",
            capture.events.lock().expect("capture lock")
        );

        tracing::subscriber::with_default(capture.clone(), || {
            tracing::callsite::rebuild_interest_cache();
            assert!(
                policy.eval_bool(&context()).expect("evaluates"),
                "the rule decides true on a real evaluation too"
            );
        });
        let events = capture.events.lock().expect("capture lock");
        assert_eq!(
            events.len(),
            1,
            "a real evaluation of the same print() must produce exactly one event: {events:?}"
        );
        assert!(
            events[0].message.contains("trial or real, always prints"),
            "{:?}",
            events[0]
        );
    }
}

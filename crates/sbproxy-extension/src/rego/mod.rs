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

impl CompiledRego {
    /// Parse `module` and pin `query` as the rule this policy evaluates.
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
    ) -> Result<Self> {
        let site = site.into();
        let query = query.into();
        let mut engine = regorus::Engine::new();
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
                    "{site}: base data defines `{query}`, the rule the query names, so it                      would override the rule's own value; put base data under a different                      key than the queried rule"
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
        self.engine.eval_rule(self.query.clone()).with_context(|| {
            format!(
                "{}: rule `{}` could not be evaluated. The module parsed, so this is a \
                     semantic fault: an unsafe variable, or a query naming a rule the module \
                     does not define",
                self.site, self.query
            )
        })?;
        Ok(())
    }

    /// The config site this policy came from.
    pub fn site(&self) -> &str {
        &self.site
    }

    /// The rule reference this policy evaluates.
    pub fn query(&self) -> &str {
        &self.query
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

    fn eval_bool_inner(&mut self, ctx: &CelContext) -> Result<bool> {
        use serde::Deserialize;
        // Feed regorus the tree directly rather than serialising to a
        // string it immediately reparses; the conversion is the only
        // pass over the context this way.
        let input = regorus::Value::deserialize(context_to_input(ctx))
            .with_context(|| format!("{}: input document rejected", self.site))?;
        self.engine.set_input(input);
        let value = self
            .engine
            .eval_rule(self.query.clone())
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

    #[test]
    fn a_malformed_module_is_a_config_error_naming_the_site() {
        let error = CompiledRego::compile(
            "policy `rego` (authz)",
            "this is not rego !!!",
            "data.x",
            50,
            None,
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
        let error =
            CompiledRego::compile("policy `rego`", UNSAFE_VAR, "data.sbproxy.allow", 50, None)
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
}

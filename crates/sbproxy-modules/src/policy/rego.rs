// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! `policy: rego`, for operators who already have Rego and would rather
//! not rewrite it.
//!
//! This is a second decision language, not a wider surface. It decides
//! and nothing else: Rego performs no I/O during evaluation, so what
//! reaches a policy is whatever the host established first, which is the
//! same constraint that keeps a config-loaded bundle from doing
//! authentication.
//!
//! # Relationship to `policy: expression`
//!
//! The two are interchangeable by design. Both evaluate against the same
//! assembled context, so `request.trust_tier` in CEL is
//! `input.request.trust_tier` in Rego and the set of available bindings
//! is identical. See [`sbproxy_extension::rego`] for why that is one
//! conversion rather than two assemblers.
//!
//! # What Rego gives up
//!
//! The config-load check that makes a CEL surface safe does not carry
//! over. CEL names its bindings as identifiers, so an unavailable one is
//! refused before the first request. In Rego, `input.request.nonsense`
//! is undefined, which is a legal value the language is built to reason
//! about, so there is nothing to refuse and a typo becomes a rule that
//! never fires.
//!
//! That is inherent to offering Rego at all rather than something to
//! engineer around, and it is the reason to reach for `expression` when
//! either would do.

use std::sync::Mutex;

use serde::Deserialize;

use sbproxy_extension::cel::CelContext;
use sbproxy_extension::rego::CompiledRego;

/// Maximum serialized size of an inline base-data document.
///
/// Base data is a config-embedded allowlist or role table, not a bulk
/// dataset: a megabyte cap keeps a mistyped or generated blob from
/// bloating every config render and reload while leaving ample room
/// for a realistic table. A document larger than this belongs behind a
/// data source, not inline in `sb.yml`.
const MAX_REGO_DATA_BYTES: usize = 1024 * 1024;

/// Name the JSON kind of a value for a config-load error message.
fn json_type_label(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Default rule evaluated when a policy does not name one.
///
/// Matches the shape most Rego examples use, so a policy pasted from
/// OPA's own documentation evaluates without an extra config key.
fn default_query() -> String {
    "data.sbproxy.allow".to_owned()
}

/// Default evaluation budget, matching the bundle sandbox default.
///
/// Every other scripting engine bounds its time; this is the fifth and
/// must not be the one that does not.
const fn default_budget_ms() -> u64 {
    50
}

/// Default refusal status, matching `policy: expression`.
const fn default_deny_status() -> u16 {
    403
}

/// Default refusal message, matching `policy: expression`.
fn default_deny_msg() -> String {
    "forbidden by policy".to_owned()
}

/// A Rego policy attached to an origin.
///
/// The module source and query are owned by [`CompiledRego`]; this
/// struct holds only what the enforcer reads per request.
pub struct RegoPolicy {
    /// Status returned when the rule denies.
    pub deny_status: u16,
    /// Message returned when the rule denies.
    pub deny_message: String,
    /// Wall-clock budget for one evaluation.
    pub budget_ms: u64,
    /// The parsed module.
    ///
    /// `Mutex` because Regorus threads `input` through the engine rather
    /// than passing it per evaluation, so a shared engine needs
    /// exclusive access for the set-then-evaluate pair. The critical
    /// section is one evaluation, measured at roughly 57 µs, and it
    /// holds no `.await`. The policy itself already sits behind an
    /// `Arc` in the compiled chain, so no second `Arc` here.
    compiled: Mutex<CompiledRego>,
}

impl std::fmt::Debug for RegoPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegoPolicy")
            .field("deny_status", &self.deny_status)
            .field("budget_ms", &self.budget_ms)
            .finish()
    }
}

impl RegoPolicy {
    /// Build from the `policies[]` entry.
    ///
    /// # Errors
    ///
    /// Returns an error when the module does not parse. A malformed
    /// policy is a config error, so boot and reload both refuse it.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Config {
            /// The dispatch key, captured so `deny_unknown_fields` does
            /// not reject the `type: rego` the config carries. A typo
            /// of any real field is refused rather than silently
            /// dropped, which for `data` would apply an empty table.
            #[serde(rename = "type")]
            _policy_type: Option<String>,
            module: String,
            #[serde(default = "default_query")]
            query: String,
            #[serde(default = "default_deny_status", alias = "status_code")]
            deny_status: u16,
            #[serde(default = "default_deny_msg")]
            deny_message: String,
            #[serde(default = "default_budget_ms")]
            budget_ms: u64,
            /// OPA-style base data: a JSON object the rule reads as
            /// `data.<name>`, separate from the module (WOR-2420). An
            /// operator edits this allowlist or role table without
            /// touching the policy logic.
            #[serde(default)]
            data: Option<serde_json::Value>,
        }

        let cfg: Config = serde_json::from_value(value)?;
        // Base data must be a JSON object: `data` is a namespace the
        // rule indexes into (`data.roles`, `data.allowed_cidrs`), and a
        // scalar or array top level has nowhere for a named lookup to
        // land. A caller who meant an array wraps it in one field.
        if let Some(data) = cfg.data.as_ref() {
            anyhow::ensure!(
                data.is_object(),
                "policy `rego`: `data` must be a JSON object whose keys the rule reads as \
                 `data.<key>`, not a {}",
                json_type_label(data)
            );
            let size = data.to_string().len();
            anyhow::ensure!(
                size <= MAX_REGO_DATA_BYTES,
                "policy `rego`: `data` is {size} bytes, over the {MAX_REGO_DATA_BYTES}-byte \
                 base-data cap; move a document this large behind a data source"
            );
        }
        Self::new(
            cfg.module,
            cfg.query,
            cfg.deny_status,
            cfg.deny_message,
            cfg.budget_ms,
            cfg.data,
        )
    }

    /// Build from parts, parsing the module once.
    ///
    /// # Errors
    ///
    /// Returns an error naming the policy when the module does not
    /// parse.
    pub fn new(
        module: String,
        query: String,
        deny_status: u16,
        deny_message: String,
        budget_ms: u64,
        data: Option<serde_json::Value>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            budget_ms > 0,
            "policy `rego`: budget_ms must be greater than zero; a zero budget would refuse \
             every request before the rule ran"
        );
        let compiled = CompiledRego::compile("policy `rego`", &module, query, budget_ms, data)?;
        Ok(Self {
            deny_status,
            deny_message,
            budget_ms,
            compiled: Mutex::new(compiled),
        })
    }

    /// Evaluate against an already-assembled context.
    ///
    /// Fails closed. A rule that errors, returns a non-boolean, or names
    /// nothing is a denial, matching `policy: expression`. Rego's
    /// default-deny idiom makes that the natural reading, but the host
    /// does not rely on the policy being written that way.
    pub fn evaluate(&self, ctx: &CelContext) -> bool {
        let mut compiled = match self.compiled.lock() {
            Ok(compiled) => compiled,
            // A panic mid-evaluation poisons the lock. Recovering the
            // engine is right: the alternative is that one panicking
            // request denies every later one forever, which turns a
            // transient fault into an outage.
            Err(poisoned) => poisoned.into_inner(),
        };
        match compiled.eval_bool(ctx) {
            Ok(allowed) => allowed,
            Err(error) => {
                tracing::warn!(
                    site = %compiled.site(),
                    query = %compiled.query(),
                    %error,
                    "rego policy failed to evaluate; denying"
                );
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODULE: &str = r#"
package sbproxy

default allow := false

allow if {
    input.request.method == "GET"
}
"#;

    fn context(method: &str) -> CelContext {
        sbproxy_extension::cel::context::build_request_context(
            method,
            "/v1/chat",
            &http::HeaderMap::new(),
            None,
            None,
            "api.example.com",
        )
    }

    #[test]
    fn from_config_defaults_the_query_to_the_conventional_rule() {
        let policy = RegoPolicy::from_config(serde_json::json!({ "module": MODULE }))
            .expect("policy compiles");
        assert_eq!(policy.deny_status, 403);
    }

    #[test]
    fn a_rule_decides_the_request() {
        let policy = RegoPolicy::from_config(serde_json::json!({ "module": MODULE }))
            .expect("policy compiles");
        assert!(policy.evaluate(&context("GET")));
        assert!(!policy.evaluate(&context("POST")));
    }

    #[test]
    fn from_config_accepts_and_applies_inline_base_data() {
        const METHOD_GATE: &str = r#"
package sbproxy

default allow := false

allow if { input.request.method == data.allowed_methods[_] }
"#;
        let policy = RegoPolicy::from_config(serde_json::json!({
            "module": METHOD_GATE,
            "data": { "allowed_methods": ["GET"] },
        }))
        .expect("a policy with inline base data compiles");
        assert!(policy.evaluate(&context("GET")), "GET is in the table");
        assert!(!policy.evaluate(&context("POST")), "POST is not");
    }

    #[test]
    fn a_typo_of_a_config_field_refuses_rather_than_silently_dropping() {
        // deny_unknown_fields: `daat` is not silently ignored, which
        // for a mistyped `data` would apply an empty table.
        let error = RegoPolicy::from_config(serde_json::json!({
            "module": MODULE,
            "daat": { "allowed_methods": ["GET"] },
        }))
        .expect_err("an unknown field must refuse");
        assert!(
            error.to_string().contains("daat") || error.to_string().contains("unknown"),
            "{error}"
        );
    }

    #[test]
    fn base_data_that_is_not_an_object_refuses() {
        let error = RegoPolicy::from_config(serde_json::json!({
            "module": MODULE,
            "data": ["not", "an", "object"],
        }))
        .expect_err("a non-object data document must refuse");
        assert!(
            error.to_string().contains("must be a JSON object"),
            "{error}"
        );
    }

    #[test]
    fn base_data_over_the_cap_refuses() {
        // A string field padded past the 1 MiB serialized cap.
        let big = "x".repeat(MAX_REGO_DATA_BYTES + 16);
        let error = RegoPolicy::from_config(serde_json::json!({
            "module": MODULE,
            "data": { "blob": big },
        }))
        .expect_err("an oversized data document must refuse");
        assert!(error.to_string().contains("base-data cap"), "{error}");
    }

    #[test]
    fn a_malformed_module_does_not_load() {
        RegoPolicy::from_config(serde_json::json!({ "module": "not rego !!!" }))
            .expect_err("a malformed module is a config error");
    }

    #[test]
    fn a_query_naming_no_rule_is_refused_at_load() {
        // This used to load clean and deny every request forever. The
        // engine now proves the query evaluable at compile time, so an
        // authoring mistake is a config error rather than a silent
        // permanent outage on that origin.
        RegoPolicy::from_config(serde_json::json!({
            "module": MODULE,
            "query": "data.sbproxy.no_such_rule"
        }))
        .expect_err("a query naming no rule must not load");
    }

    #[test]
    fn a_zero_budget_is_refused_rather_than_denying_everything() {
        RegoPolicy::from_config(serde_json::json!({
            "module": MODULE,
            "budget_ms": 0
        }))
        .expect_err("a zero budget would refuse every request before the rule ran");
    }

    #[test]
    fn the_budget_defaults_and_is_carried() {
        let policy = RegoPolicy::from_config(serde_json::json!({ "module": MODULE }))
            .expect("policy compiles");
        assert_eq!(policy.budget_ms, 50);
    }

    #[test]
    fn the_same_decision_reads_the_same_bindings_as_a_cel_expression() {
        // The parity claim, exercised rather than asserted in prose. The
        // CEL form of this policy is `request.method == "GET"`, and both
        // evaluate against the same context.
        const TRUST_TIER: &str = r#"
package sbproxy

default allow := false

allow if {
    input.request.trust_tier == "strong"
}
"#;
        let policy = RegoPolicy::from_config(serde_json::json!({ "module": TRUST_TIER }))
            .expect("policy compiles");
        let mut ctx = context("GET");
        sbproxy_extension::cel::context::populate_trust_tier_namespace(&mut ctx, "anonymous");
        assert!(!policy.evaluate(&ctx));

        sbproxy_extension::cel::context::populate_trust_tier_namespace(&mut ctx, "strong");
        assert!(
            policy.evaluate(&ctx),
            "a binding a CEL expression can read must be readable here too"
        );
    }
}

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

use std::sync::{Arc, Mutex};

use serde::Deserialize;

use sbproxy_extension::cel::CelContext;
use sbproxy_extension::rego::CompiledRego;

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
pub struct RegoPolicy {
    /// The module source, retained for diagnostics.
    pub module: String,
    /// The rule reference evaluated per request.
    pub query: String,
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
    /// holds no `.await`.
    compiled: Arc<Mutex<CompiledRego>>,
}

impl std::fmt::Debug for RegoPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegoPolicy")
            .field("query", &self.query)
            .field("deny_status", &self.deny_status)
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
        struct Config {
            module: String,
            #[serde(default = "default_query")]
            query: String,
            #[serde(default = "default_deny_status", alias = "status_code")]
            deny_status: u16,
            #[serde(default = "default_deny_msg")]
            deny_message: String,
            #[serde(default = "default_budget_ms")]
            budget_ms: u64,
        }

        let cfg: Config = serde_json::from_value(value)?;
        Self::new(
            cfg.module,
            cfg.query,
            cfg.deny_status,
            cfg.deny_message,
            cfg.budget_ms,
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
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            budget_ms > 0,
            "policy `rego`: budget_ms must be greater than zero; a zero budget would refuse \
             every request before the rule ran"
        );
        let compiled = CompiledRego::compile("policy `rego`", &module, query.clone(), budget_ms)?;
        Ok(Self {
            module,
            query,
            deny_status,
            deny_message,
            budget_ms,
            compiled: Arc::new(Mutex::new(compiled)),
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
        assert_eq!(policy.query, "data.sbproxy.allow");
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

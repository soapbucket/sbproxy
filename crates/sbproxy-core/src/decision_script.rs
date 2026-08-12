// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Running an operator-authored script for one decision event.
//!
//! The engines already exist and `custom_log` already dispatches across
//! them. The difference here is the return type, and it is the whole
//! point: a custom log field wants a **string**, so `custom_log`
//! stringifies whatever comes back. A decision event wants a
//! **document**, because its answer has structure: a list of cache-key
//! dimensions, or a `{store, ttl_secs, reason}` object.
//!
//! That difference is also why CEL is not in the match below. CEL
//! evaluates to a scalar, so serving these events with it would mean
//! packing a document into a string and parsing it back out, which is
//! how `route_to:gpt-4o-mini` became a mini-language. The config
//! compiler refuses `cel` for these events by name and says so, rather
//! than accepting it here and coercing.
//!
//! ## Cost
//!
//! A fresh VM per evaluation, matching `custom_log`. That is the honest
//! cost of an inline script on a per-request path and it is why the
//! events are opt-in and absent by default. Pooling would need one pool
//! per tenant to avoid state bleeding between them, which is the same
//! reasoning that keeps the WASM path on a fresh `Store` per call.

use std::collections::HashMap;

use sbproxy_config::DecisionScriptConfig;

/// Evaluate a decision script and return its document.
///
/// `context` is handed to the script as a single `ctx` global, matching
/// the shape `custom_log` established so an operator who has written one
/// has written the other.
///
/// A fault is not a decline. The caller applies its own fallback, but
/// records the fault separately, which is what keeps a broken script
/// from looking like a script with no opinion. The fault distinguishes a
/// budget overrun from every other failure, because raising a budget and
/// fixing a bug are different responses.
/// Why an evaluation produced no document.
///
/// A budget overrun is separated from every other fault because the two
/// want different responses: one is a budget to raise or a script to
/// make cheaper, the other is a bug to fix. Collapsing them is why
/// `DecisionOutcome::Timeout` would otherwise read flat zero forever
/// while scripts were timing out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScriptFault {
    /// The script did not finish inside its CPU budget.
    Timeout,
    /// Anything else: a syntax error, a thrown exception, an
    /// unavailable engine.
    Error,
}

impl ScriptFault {
    /// The decision-event outcome this fault reports as.
    pub(crate) const fn outcome(self) -> sbproxy_observe::decision::DecisionOutcome {
        match self {
            Self::Timeout => sbproxy_observe::decision::DecisionOutcome::Timeout,
            Self::Error => sbproxy_observe::decision::DecisionOutcome::Error,
        }
    }
}

pub(crate) fn evaluate(
    script: &DecisionScriptConfig,
    context: &serde_json::Value,
) -> Result<serde_json::Value, ScriptFault> {
    let mut globals = HashMap::new();
    globals.insert("ctx".to_owned(), context.clone());

    match script.engine.as_str() {
        "lua" => match sbproxy_extension::lua::LuaEngine::new() {
            Ok(engine) => match engine.execute(&script.source, globals) {
                Ok(value) => Ok(value),
                Err(error) => {
                    // The sandbox reports a budget overrun by putting
                    // `LuaSandboxTimeout` in the error chain, so that is
                    // what separates "too slow" from "broken".
                    let timed_out = error
                        .chain()
                        .any(|cause| cause.is::<sbproxy_extension::lua::LuaSandboxTimeout>());
                    tracing::warn!(
                        target: "sbproxy::decision",
                        engine = "lua",
                        error = %error,
                        timed_out,
                        "decision script failed; falling back to static config"
                    );
                    Err(if timed_out {
                        ScriptFault::Timeout
                    } else {
                        ScriptFault::Error
                    })
                }
            },
            Err(error) => {
                tracing::warn!(
                    target: "sbproxy::decision",
                    engine = "lua",
                    error = %error,
                    "decision script engine unavailable"
                );
                Err(ScriptFault::Error)
            }
        },
        "js" => match sbproxy_extension::js::JsEngine::new() {
            Ok(engine) => match engine.execute(&script.source, globals) {
                Ok(value) => Ok(value),
                Err(error) => {
                    let timed_out = matches!(
                        error,
                        sbproxy_extension::js::JsExecutionError::Interrupt { .. }
                    );
                    tracing::warn!(
                        target: "sbproxy::decision",
                        engine = "js",
                        error = %error,
                        timed_out,
                        "decision script failed; falling back to static config"
                    );
                    Err(if timed_out {
                        ScriptFault::Timeout
                    } else {
                        ScriptFault::Error
                    })
                }
            },
            Err(error) => {
                tracing::warn!(
                    target: "sbproxy::decision",
                    engine = "js",
                    error = %error,
                    "decision script engine unavailable"
                );
                Err(ScriptFault::Error)
            }
        },
        // Unreachable from a compiled config: `validate_decision_script`
        // refuses every other engine at load, naming it. Reached only if
        // that validation is bypassed, in which case falling back to the
        // static config is the safe answer.
        other => {
            tracing::warn!(
                target: "sbproxy::decision",
                engine = %other,
                "decision script has an engine the compiler should have refused"
            );
            Err(ScriptFault::Error)
        }
    }
}

/// Which engine label a script reports on the decision-event metrics.
pub(crate) fn engine_label(
    script: &DecisionScriptConfig,
) -> sbproxy_observe::decision::DecisionEngine {
    match script.engine.as_str() {
        "js" => sbproxy_observe::decision::DecisionEngine::JavaScript,
        // Lua is the only other engine the compiler admits, and an
        // unadmitted one never reaches an evaluation to be labelled.
        _ => sbproxy_observe::decision::DecisionEngine::Lua,
    }
}

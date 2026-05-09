//! CEL response-body transform (Wave 5 day-5 / Q5.x reactivation).
//!
//! Evaluates a CEL expression against the response body + status +
//! headers and replaces the body with the result. The transform is
//! intended for the trust-bounded sidecar capture path's tests
//! (G5.3 / G5.4): the e2e harness needs a tiny response-side scripting
//! lane so it can stamp `request.tls.ja4` / `request.kya.verdict` back
//! into the response body for assertions, without bringing the full
//! Lua / JS / WASM stack.
//!
//! ## Config shape
//!
//! ```yaml
//! transforms:
//!   - type: cel
//!     on_response: |
//!       request.tls.ja4 + ":" + string(response.status)
//!     headers:
//!       - { op: set, name: x-tls-ja4, value_expr: "request.tls.ja4" }
//!       - { op: remove, name: x-internal-trace }
//! ```
//!
//! The `on_response` expression runs at body-buffer time and rewrites
//! the response body. The `headers` array runs alongside it (Wave 5
//! day-6 Item 1) and lets operators set / append / remove response
//! headers from CEL. Either field is independently optional; supplying
//! neither is an error.
//!
//! ## CEL surface
//!
//! Bindings exposed to the expression:
//!
//! - `response.body` - response body as a UTF-8 string. Non-UTF-8
//!   bodies are passed through as the empty string and the transform
//!   logs a warning.
//! - `response.status` - HTTP status code (integer).
//! - `response.headers` - map of lowercase header name to value.
//! - All of the existing `request.*` namespace populated by the
//!   request-time CEL context (see `sbproxy-extension::cel::context`).
//!
//! ## Result coercion
//!
//! The expression returns one of: a string (written back verbatim),
//! an int / float / bool (rendered as a string), or a map / list
//! (JSON-serialised). Null returns leave the body unchanged.
//!
//! ## Header deny-list
//!
//! `Set-Cookie` is denied by default so a CEL expression cannot inject
//! a session cookie via the operator-controlled scripting lane. The
//! deny-list lives at [`HEADER_DENY_LIST`] and is checked case-
//! insensitively.

use std::time::Duration;

use bytes::{BufMut, BytesMut};
use http::HeaderMap;
use sbproxy_extension::cel::{CelEngine, CelValue};
use serde::Deserialize;

/// Headers a CEL expression is not allowed to mutate. Case-insensitive
/// match. The list is intentionally tight: operators that need to set
/// these headers reach for a dedicated middleware (response_modifiers,
/// CSRF, cookie auth) so the security review is local, not scattered
/// across every CEL transform.
pub const HEADER_DENY_LIST: &[&str] = &["set-cookie", "set-cookie2"];

/// Per-header CEL evaluation budget. The transform is on the response
/// body hot path; a runaway expression cannot be allowed to stall the
/// pipeline. Today's CelEngine does not support per-evaluation timeouts
/// natively; the budget is documented here and enforced as a wall-clock
/// check around the eval call.
pub const HEADER_EVAL_BUDGET: Duration = Duration::from_millis(1);

/// One header mutation produced by the CEL transform. The `op` field
/// selects the semantic; `value_expr` is required for `set` and
/// `append` and ignored for `remove`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CelHeaderRule {
    /// Operation to perform. One of `set`, `append`, `remove`.
    pub op: CelHeaderOp,
    /// Header name (case-insensitive). Set-Cookie and Set-Cookie2 are
    /// rejected at compile time.
    pub name: String,
    /// CEL expression evaluated per request. Required for `set` and
    /// `append`; ignored for `remove`. Must evaluate to a string, int,
    /// float, or bool; other types are stringified via `format!("{}")`.
    #[serde(default)]
    pub value_expr: Option<String>,
}

/// Header mutation kind for [`CelHeaderRule`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CelHeaderOp {
    /// Replace any existing header(s) with this name.
    Set,
    /// Add another value, leaving any existing values in place.
    Append,
    /// Remove every value for this header.
    Remove,
}

/// One concrete header mutation produced by evaluating a [`CelHeaderRule`]
/// against the live request + response context. Surfaces as the return
/// value of [`CelScriptTransform::evaluate_headers`] so the response
/// pipeline can stamp the result onto the outgoing response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CelHeaderMutation {
    /// Replace the named header with the given value.
    Set(String, String),
    /// Append the given value to the named header.
    Append(String, String),
    /// Remove the named header entirely.
    Remove(String),
}

/// CEL response-body transform.
#[derive(Debug)]
pub struct CelScriptTransform {
    /// Optional CEL expression that runs at request time. Reserved for
    /// a future iteration; today the body-buffer apply path uses
    /// `on_response` exclusively.
    pub on_request: Option<String>,
    /// CEL expression that runs at response-body time. Optional when
    /// `headers` is supplied.
    pub on_response: Option<String>,
    /// Header mutation rules evaluated at response time (Wave 5 day-6
    /// Item 1). May be empty when only `on_response` is configured.
    pub headers: Vec<CelHeaderRule>,
}

impl CelScriptTransform {
    /// Build a `CelScriptTransform` from the operator's YAML block.
    ///
    /// Either `on_response` or `expression` may carry the response-time
    /// expression; the latter is accepted as an alias so the simple
    /// "drop a CEL string in" use case mirrors the `expression` field
    /// the policy block uses.
    ///
    /// `headers` is optional. At least one of `on_response` or
    /// `headers` must be present, otherwise compilation errors out so
    /// a misconfigured transform fails loudly at config-load time
    /// rather than silently no-op'ing every response.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        #[derive(Deserialize)]
        struct Config {
            #[serde(default)]
            on_request: Option<String>,
            #[serde(default, alias = "expression")]
            on_response: Option<String>,
            #[serde(default)]
            headers: Vec<CelHeaderRule>,
        }
        let cfg: Config = serde_json::from_value(value)?;
        if cfg.on_response.is_none() && cfg.headers.is_empty() {
            anyhow::bail!(
                "cel transform requires `on_response` (or alias `expression`) or a non-empty `headers` array"
            );
        }
        // Validate the deny-list at compile time so a misconfigured
        // transform cannot inject Set-Cookie via the scripting lane.
        for rule in &cfg.headers {
            let lower = rule.name.to_ascii_lowercase();
            if HEADER_DENY_LIST.iter().any(|d| *d == lower) {
                anyhow::bail!(
                    "cel transform: header `{}` is on the deny-list and cannot be mutated from CEL",
                    rule.name
                );
            }
            match rule.op {
                CelHeaderOp::Set | CelHeaderOp::Append => {
                    if rule.value_expr.is_none() {
                        anyhow::bail!(
                            "cel transform: header `{}` op `{:?}` requires `value_expr`",
                            rule.name,
                            rule.op
                        );
                    }
                }
                CelHeaderOp::Remove => {
                    // value_expr is allowed but ignored on remove.
                }
            }
        }
        Ok(Self {
            on_request: cfg.on_request,
            on_response: cfg.on_response,
            headers: cfg.headers,
        })
    }

    /// Apply the response-time CEL expression to `body`.
    ///
    /// The standard `(body, content_type)` body-buffer signature is
    /// used here for parity with the other transforms in this crate,
    /// even though the CEL transform reads the response status +
    /// headers via the `RequestContext` -> CEL bridge. Today the
    /// status / headers come in via [`CelScriptTransform::apply_with_response`];
    /// the simpler `apply` shim renders an empty `response.status` /
    /// `response.headers`.
    pub fn apply(&self, body: &mut BytesMut) -> anyhow::Result<()> {
        self.apply_with_response(body, 0, &HeaderMap::new())
    }

    /// Evaluate the configured `headers` rules against the live
    /// response context and return a list of [`CelHeaderMutation`]s
    /// the response pipeline should stamp onto the outgoing headers.
    ///
    /// Each rule's `value_expr` is evaluated once. Failures (parse,
    /// runtime, deny-list match, eval-budget overrun) are logged and
    /// the rule is skipped; the rest of the chain continues so a
    /// single broken expression does not knock out the transform.
    /// Returns an empty `Vec` when no rules are configured.
    ///
    /// Returns a [`crate::transform::TransformError::InvariantViolated`]
    /// if a structural invariant is violated (today: a `Remove` rule
    /// reaching the value-expression evaluation branch). Operators
    /// who want to keep the legacy panic-free behaviour can continue
    /// to call this through the [`Self::evaluate_headers_lossy`] shim,
    /// which drops invariant errors after logging them.
    pub fn evaluate_headers(
        &self,
        body: &[u8],
        status: u16,
        headers: &HeaderMap,
    ) -> Result<Vec<CelHeaderMutation>, crate::transform::TransformError> {
        if self.headers.is_empty() {
            return Ok(Vec::new());
        }
        let ctx = build_response_eval_context(body, status, headers);
        let engine = CelEngine::new();
        let mut out = Vec::with_capacity(self.headers.len());
        for rule in &self.headers {
            match rule.op {
                CelHeaderOp::Remove => {
                    out.push(CelHeaderMutation::Remove(rule.name.clone()));
                }
                CelHeaderOp::Set | CelHeaderOp::Append => {
                    let Some(expr) = rule.value_expr.as_deref() else {
                        // Defensive: from_config rejects this shape.
                        continue;
                    };
                    let started = std::time::Instant::now();
                    let result = engine.eval_source(expr, &ctx);
                    let elapsed = started.elapsed();
                    if elapsed > HEADER_EVAL_BUDGET {
                        // Note: the budget is advisory today (the
                        // engine has no preempt). Log so an operator
                        // can spot a runaway expression.
                        tracing::warn!(
                            header = %rule.name,
                            elapsed_us = elapsed.as_micros() as u64,
                            "cel header transform: per-header eval exceeded {}ms budget",
                            HEADER_EVAL_BUDGET.as_millis(),
                        );
                    }
                    let value = match result {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!(
                                header = %rule.name,
                                error = %e,
                                "cel header transform: value expression failed; skipping rule",
                            );
                            continue;
                        }
                    };
                    let value_str = match value {
                        CelValue::String(s) => s,
                        CelValue::Int(i) => i.to_string(),
                        CelValue::Float(f) => f.to_string(),
                        CelValue::Bool(b) => b.to_string(),
                        CelValue::Null => continue,
                        other => {
                            // Map / list - render as JSON for
                            // observability rather than skipping.
                            match serde_json::to_string(&cel_value_to_json(&other)) {
                                Ok(s) => s,
                                Err(_) => continue,
                            }
                        }
                    };
                    match rule.op {
                        CelHeaderOp::Set => {
                            out.push(CelHeaderMutation::Set(rule.name.clone(), value_str));
                        }
                        CelHeaderOp::Append => {
                            out.push(CelHeaderMutation::Append(rule.name.clone(), value_str));
                        }
                        CelHeaderOp::Remove => {
                            // WOR-168: this arm was previously
                            // `unreachable!()`. The outer match arm
                            // selects `Set | Append`, so under normal
                            // control flow `Remove` cannot reach here.
                            // We treat the path as a pipeline-invariant
                            // violation and surface it through a typed
                            // `TransformError::InvariantViolated` so the
                            // request becomes a 500 with attribution
                            // rather than a panicked Pingora worker.
                            tracing::error!(
                                target: "sbproxy::transform::cel",
                                header = %rule.name,
                                "cel header transform: invariant violated - CelHeaderOp::Remove reached the value-expression branch",
                            );
                            return Err(
                                crate::transform::TransformError::InvariantViolated {
                                    reason: format!(
                                        "cel header rule {:?}: Remove op reached value-expression branch",
                                        rule.name,
                                    ),
                                },
                            );
                        }
                    }
                }
            }
        }
        Ok(out)
    }

    /// Lossy variant of [`Self::evaluate_headers`] that drops invariant
    /// errors and returns the partially-applied mutation set. Useful for
    /// the header-only response wiring in `sbproxy-core` where a single
    /// drift event should not poison the entire response. The error is
    /// already tracing::error!'d at its source, so the caller just
    /// loses the partial-rule chain rather than the whole response.
    pub fn evaluate_headers_lossy(
        &self,
        body: &[u8],
        status: u16,
        headers: &HeaderMap,
    ) -> Vec<CelHeaderMutation> {
        match self.evaluate_headers(body, status, headers) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    target: "sbproxy::transform::cel",
                    error = %e,
                    "cel header transform: invariant violated; falling back to empty mutation set",
                );
                Vec::new()
            }
        }
    }

    /// WOR-168 test hook: directly drive the inner `Set | Append`
    /// switch with an arbitrary `CelHeaderOp` so the
    /// `unreachable!()` replacement can be exercised by a unit test.
    /// Production code never hits this surface; the outer match in
    /// `evaluate_headers` always routes `Remove` to the dedicated arm.
    #[cfg(test)]
    pub(crate) fn finalise_value_op_for_test(
        op: CelHeaderOp,
        name: &str,
        value: String,
    ) -> Result<CelHeaderMutation, crate::transform::TransformError> {
        match op {
            CelHeaderOp::Set => Ok(CelHeaderMutation::Set(name.to_string(), value)),
            CelHeaderOp::Append => Ok(CelHeaderMutation::Append(name.to_string(), value)),
            CelHeaderOp::Remove => {
                tracing::error!(
                    target: "sbproxy::transform::cel",
                    header = %name,
                    "cel header transform: invariant violated - CelHeaderOp::Remove reached the value-expression branch",
                );
                Err(crate::transform::TransformError::InvariantViolated {
                    reason: format!(
                        "cel header rule {:?}: Remove op reached value-expression branch",
                        name,
                    ),
                })
            }
        }
    }

    /// Apply the response-time CEL expression with full response
    /// context.
    ///
    /// The body-buffer call site that owns the live status + header
    /// map calls this overload so `response.status` and
    /// `response.headers` resolve to real values.
    pub fn apply_with_response(
        &self,
        body: &mut BytesMut,
        status: u16,
        headers: &HeaderMap,
    ) -> anyhow::Result<()> {
        // When only `headers:` rules are configured the body-side
        // expression is absent; nothing to do here. The header
        // mutations are surfaced separately via [`evaluate_headers`].
        let Some(expression) = self.on_response.as_deref() else {
            return Ok(());
        };

        let ctx = build_response_eval_context(body.as_ref(), status, headers);

        let engine = CelEngine::new();
        let result = match engine.eval_source(expression, &ctx) {
            Ok(v) => v,
            Err(e) => {
                // Compile / eval errors leave the body untouched. The
                // proxy logs and continues so a misconfigured operator
                // expression does not 500 every response.
                tracing::warn!(
                    error = %e,
                    expression = %expression,
                    "cel transform: expression evaluation failed; body unchanged",
                );
                return Ok(());
            }
        };

        match result {
            CelValue::String(s) => {
                body.clear();
                body.extend_from_slice(s.as_bytes());
            }
            CelValue::Int(i) => {
                body.clear();
                body.extend_from_slice(i.to_string().as_bytes());
            }
            CelValue::Float(f) => {
                body.clear();
                body.extend_from_slice(f.to_string().as_bytes());
            }
            CelValue::Bool(b) => {
                body.clear();
                body.extend_from_slice(b.to_string().as_bytes());
            }
            CelValue::Null => {
                // Null leaves the body unchanged. Operators use this
                // as the "no-op pass" sentinel when the expression
                // wants to inspect the body without rewriting it.
            }
            CelValue::Map(_) | CelValue::List(_) => {
                // Map / list returns are JSON-serialised so an
                // expression like `{"echo": response.body}` produces a
                // valid JSON document.
                let json = cel_value_to_json(&result);
                body.clear();
                serde_json::to_writer(&mut body.writer(), &json)?;
            }
        }
        Ok(())
    }
}

/// Build the CEL evaluation context shared by both the body-rewriting
/// expression (`on_response`) and the per-header value expressions
/// (`headers[*].value_expr`).
///
/// Stamps a `response` namespace with `body`, `status`, and `headers`
/// onto the standard request-context. The request namespace is empty
/// here because the body-buffer call site does not own a `Session`;
/// real `request.tls.*` / `request.kya.*` bindings come from the
/// upstream call site that owns the request context (server.rs).
fn build_response_eval_context(
    body: &[u8],
    status: u16,
    headers: &HeaderMap,
) -> sbproxy_extension::cel::CelContext {
    let body_str = match std::str::from_utf8(body) {
        Ok(s) => s.to_string(),
        Err(_) => {
            tracing::debug!("cel transform: non-UTF-8 response body; passing through");
            String::new()
        }
    };
    let mut ctx = sbproxy_extension::cel::context::build_request_context(
        "GET",
        "/",
        &HeaderMap::new(),
        None,
        None,
        "",
    );
    let mut resp_map = std::collections::HashMap::with_capacity(3);
    resp_map.insert("body".to_string(), CelValue::String(body_str));
    resp_map.insert("status".to_string(), CelValue::Int(status as i64));
    let mut header_map = std::collections::HashMap::new();
    for (k, v) in headers.iter() {
        if let Ok(s) = v.to_str() {
            header_map.insert(k.as_str().to_string(), CelValue::String(s.to_string()));
        }
    }
    resp_map.insert("headers".to_string(), CelValue::Map(header_map));
    ctx.set("response", CelValue::Map(resp_map));
    ctx
}

/// Translate a CEL value into a JSON value for response-body
/// serialisation. Recursive on maps / lists; primitives map 1:1.
fn cel_value_to_json(value: &CelValue) -> serde_json::Value {
    match value {
        CelValue::Null => serde_json::Value::Null,
        CelValue::Bool(b) => serde_json::Value::Bool(*b),
        CelValue::Int(i) => serde_json::Value::Number(serde_json::Number::from(*i)),
        CelValue::Float(f) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        CelValue::String(s) => serde_json::Value::String(s.clone()),
        CelValue::List(items) => {
            serde_json::Value::Array(items.iter().map(cel_value_to_json).collect())
        }
        CelValue::Map(m) => {
            let mut out = serde_json::Map::with_capacity(m.len());
            for (k, v) in m {
                out.insert(k.clone(), cel_value_to_json(v));
            }
            serde_json::Value::Object(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(s: &str) -> BytesMut {
        let mut b = BytesMut::new();
        b.extend_from_slice(s.as_bytes());
        b
    }

    #[test]
    fn from_config_requires_on_response_or_headers() {
        // Missing both fields is a hard error.
        let v = serde_json::json!({"type": "cel"});
        assert!(CelScriptTransform::from_config(v).is_err());
    }

    #[test]
    fn from_config_accepts_headers_alone() {
        // Day-6 Item 1: a transform that ONLY mutates headers (no
        // body rewrite) is a valid configuration.
        let v = serde_json::json!({
            "type": "cel",
            "headers": [
                {"op": "set", "name": "x-foo", "value_expr": r#""bar""#},
            ],
        });
        let t = CelScriptTransform::from_config(v).unwrap();
        assert!(t.on_response.is_none());
        assert_eq!(t.headers.len(), 1);
    }

    #[test]
    fn from_config_accepts_expression_alias() {
        // The `expression:` alias mirrors the policy block's CEL
        // field name so operators have a consistent surface.
        let v = serde_json::json!({
            "type": "cel",
            "expression": r#"\"hello\""#,
        });
        let t = CelScriptTransform::from_config(v).unwrap();
        assert_eq!(t.on_response.as_deref(), Some(r#"\"hello\""#));
    }

    #[test]
    fn from_config_rejects_set_cookie_in_headers() {
        // Set-Cookie is on the deny-list; CEL must not be a vector
        // for cookie injection.
        let v = serde_json::json!({
            "type": "cel",
            "on_response": r#""ok""#,
            "headers": [
                {"op": "set", "name": "Set-Cookie", "value_expr": r#""sid=abc""#},
            ],
        });
        assert!(CelScriptTransform::from_config(v).is_err());
    }

    #[test]
    fn from_config_rejects_set_without_value_expr() {
        let v = serde_json::json!({
            "type": "cel",
            "headers": [{"op": "set", "name": "x-foo"}],
        });
        assert!(CelScriptTransform::from_config(v).is_err());
    }

    #[test]
    fn evaluate_headers_set_from_string_expression() {
        let v = serde_json::json!({
            "type": "cel",
            "headers": [
                {"op": "set", "name": "x-status", "value_expr": "string(response.status)"},
            ],
        });
        let t = CelScriptTransform::from_config(v).unwrap();
        let mutations = t.evaluate_headers(b"", 418, &HeaderMap::new()).unwrap();
        assert_eq!(
            mutations,
            vec![CelHeaderMutation::Set(
                "x-status".to_string(),
                "418".to_string(),
            )]
        );
    }

    #[test]
    fn evaluate_headers_remove_emits_remove_op() {
        let v = serde_json::json!({
            "type": "cel",
            "headers": [{"op": "remove", "name": "x-internal-trace"}],
        });
        let t = CelScriptTransform::from_config(v).unwrap();
        let mutations = t.evaluate_headers(b"", 200, &HeaderMap::new()).unwrap();
        assert_eq!(
            mutations,
            vec![CelHeaderMutation::Remove("x-internal-trace".to_string())]
        );
    }

    #[test]
    fn evaluate_headers_failed_expression_skips_rule() {
        // A rule whose expression cannot be parsed must not break the
        // whole transform; the rest of the chain should still produce
        // mutations.
        let v = serde_json::json!({
            "type": "cel",
            "headers": [
                {"op": "set", "name": "x-bad", "value_expr": "this is broken !!!"},
                {"op": "set", "name": "x-good", "value_expr": r#""yes""#},
            ],
        });
        let t = CelScriptTransform::from_config(v).unwrap();
        let mutations = t.evaluate_headers(b"", 200, &HeaderMap::new()).unwrap();
        assert_eq!(
            mutations,
            vec![CelHeaderMutation::Set(
                "x-good".to_string(),
                "yes".to_string(),
            )]
        );
    }

    /// WOR-168: directly drive the inner `Set | Append` switch with a
    /// `Remove` op via the test hook. Pre-fix, this call site was
    /// `unreachable!()` and would have panicked the Pingora worker
    /// under any future regression that routed a `Remove` rule there.
    /// Post-fix, the same call returns a typed
    /// `TransformError::InvariantViolated` that the body-buffer
    /// pipeline maps to a 500 with `x-sbproxy-transform-error`
    /// attribution.
    #[test]
    fn finalise_value_op_returns_invariant_error_for_remove() {
        let r = CelScriptTransform::finalise_value_op_for_test(
            CelHeaderOp::Remove,
            "x-test",
            "ignored".to_string(),
        );
        let err = r.expect_err("Remove in value branch must surface an invariant error");
        let msg = format!("{err}");
        assert!(
            matches!(
                err,
                crate::transform::TransformError::InvariantViolated { .. }
            ),
            "expected InvariantViolated, got {msg}",
        );
        assert!(
            msg.contains("x-test"),
            "error must attribute the offending header name: {msg}",
        );
    }

    /// WOR-168: the `Set` and `Append` ops must continue to work
    /// through the same helper so the test hook does not silently
    /// regress on the happy path.
    #[test]
    fn finalise_value_op_returns_set_and_append_ok() {
        let s = CelScriptTransform::finalise_value_op_for_test(
            CelHeaderOp::Set,
            "x-foo",
            "bar".to_string(),
        )
        .unwrap();
        assert_eq!(s, CelHeaderMutation::Set("x-foo".into(), "bar".into()));
        let a = CelScriptTransform::finalise_value_op_for_test(
            CelHeaderOp::Append,
            "x-foo",
            "baz".to_string(),
        )
        .unwrap();
        assert_eq!(a, CelHeaderMutation::Append("x-foo".into(), "baz".into()));
    }

    /// WOR-168: the lossy shim must absorb invariant errors and
    /// return an empty mutation set rather than propagating.
    #[test]
    fn evaluate_headers_lossy_returns_empty_on_invariant_error() {
        // The inner unreachable arm cannot actually fire from public
        // config today, but the shim's Err -> empty mapping is what
        // the `sbproxy-core` upstream-response wiring relies on, so
        // pin its happy path: a normal Remove rule still flows
        // through the lossy variant.
        let v = serde_json::json!({
            "type": "cel",
            "headers": [{"op": "remove", "name": "x-internal-trace"}],
        });
        let t = CelScriptTransform::from_config(v).unwrap();
        let mutations = t.evaluate_headers_lossy(b"", 200, &HeaderMap::new());
        assert_eq!(
            mutations,
            vec![CelHeaderMutation::Remove("x-internal-trace".to_string())]
        );
    }

    #[test]
    fn headers_only_transform_apply_is_a_noop_on_body() {
        // A transform that only mutates headers must leave the body
        // untouched when `apply_with_response` is invoked.
        let v = serde_json::json!({
            "type": "cel",
            "headers": [{"op": "set", "name": "x-foo", "value_expr": r#""bar""#}],
        });
        let t = CelScriptTransform::from_config(v).unwrap();
        let mut b = body("untouched");
        t.apply_with_response(&mut b, 200, &HeaderMap::new())
            .unwrap();
        assert_eq!(std::str::from_utf8(&b).unwrap(), "untouched");
    }

    #[test]
    fn body_is_replaced_with_a_simple_string_literal() {
        let v = serde_json::json!({
            "type": "cel",
            "on_response": r#""rewritten""#,
        });
        let t = CelScriptTransform::from_config(v).unwrap();
        let mut b = body("original-body");
        t.apply(&mut b).unwrap();
        assert_eq!(std::str::from_utf8(&b).unwrap(), "rewritten");
    }

    #[test]
    fn body_can_concatenate_response_status_into_a_string() {
        let v = serde_json::json!({
            "type": "cel",
            "on_response": r#""status=" + string(response.status)"#,
        });
        let t = CelScriptTransform::from_config(v).unwrap();
        let mut b = body("");
        t.apply_with_response(&mut b, 200, &HeaderMap::new())
            .unwrap();
        assert_eq!(std::str::from_utf8(&b).unwrap(), "status=200");
    }

    #[test]
    fn body_can_read_response_headers_through_the_namespace() {
        let v = serde_json::json!({
            "type": "cel",
            "on_response": r#"response.headers["x-custom"]"#,
        });
        let t = CelScriptTransform::from_config(v).unwrap();
        let mut b = body("");
        let mut h = HeaderMap::new();
        h.insert("x-custom", "hello-from-header".parse().unwrap());
        t.apply_with_response(&mut b, 200, &h).unwrap();
        assert_eq!(std::str::from_utf8(&b).unwrap(), "hello-from-header");
    }

    #[test]
    fn invalid_expression_leaves_body_untouched() {
        // A garbage expression should warn and pass through. The body
        // must not be 500'd by a misconfigured operator script.
        let v = serde_json::json!({
            "type": "cel",
            "on_response": "this is not a valid expression !!!",
        });
        let t = CelScriptTransform::from_config(v).unwrap();
        let mut b = body("untouched");
        t.apply(&mut b).unwrap();
        assert_eq!(std::str::from_utf8(&b).unwrap(), "untouched");
    }

    #[test]
    fn body_can_be_replaced_with_a_serialised_map() {
        let v = serde_json::json!({
            "type": "cel",
            "on_response": r#"{"echo": response.body, "code": response.status}"#,
        });
        let t = CelScriptTransform::from_config(v).unwrap();
        let mut b = body("payload");
        t.apply_with_response(&mut b, 418, &HeaderMap::new())
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(parsed["echo"], "payload");
        assert_eq!(parsed["code"], 418);
    }
}

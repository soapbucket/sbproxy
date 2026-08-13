//! One compile-once seam for CEL that comes from static operator
//! config (WOR-2164).
//!
//! Every CEL expression sbproxy runs falls into one of two classes:
//!
//! - **Static config source.** The operator wrote it in `sb.yml`, so it
//!   is fixed for the life of a config generation: an `expression` or
//!   `assertion` policy, a `cel` transform, a rate-limit `key:`, a
//!   custom log field. There is exactly one moment to parse it, and
//!   that moment is config load.
//! - **Request-supplied source.** The text arrives with the request, so
//!   it cannot be known ahead of time. [`super::CelEngine::eval_source`]
//!   and [`super::CelEngine::eval_bool_source`] exist for that case and
//!   stay in place for it.
//!
//! [`CompiledCel`] is the type the first class uses. It owns the
//! engine, the compiled program, and the config identity that a
//! diagnostic has to name, and it exposes evaluation only. A call site
//! that holds one cannot compile per request, because there is no
//! source string left to compile.
//!
//! ## What a caller gets
//!
//! - Malformed CEL is an error at [`CompiledCel::compile`], which config
//!   compilation propagates, so boot and reload both refuse the config.
//!   The message names the site and quotes the bad expression.
//! - Evaluation returns `Result`. The posture on a runtime error (a
//!   missing map key, a non-boolean result) is deliberately **not**
//!   decided here: an `expression` policy fails closed, a log-only
//!   assertion records a pass, a body transform leaves the body alone.
//!   Each call site documents and tests its own choice.

use std::cell::Cell;

use anyhow::Result;

use super::surface::CelSurface;
use super::{CelContext, CelEngine, CelExpression, CelValue};

thread_local! {
    /// Number of [`CompiledCel::compile`] calls made on this thread.
    ///
    /// Compilation is a config-load activity; the request path only ever
    /// evaluates. The counter makes that testable: a test compiles a
    /// config, records the count, drives the request path, and asserts
    /// the count did not move. Thread-local rather than global so a
    /// parallel test run cannot make one test's count depend on
    /// another's.
    static COMPILE_COUNT: Cell<u64> = const { Cell::new(0) };
}

/// Reads the current thread's [`CompiledCel::compile`] count.
#[cfg(test)]
pub(crate) fn compile_count_on_this_thread() -> u64 {
    COMPILE_COUNT.with(Cell::get)
}

/// A CEL expression from static operator config, compiled once.
///
/// Build one at config-load time with [`Self::compile`] and evaluate it
/// per request with [`Self::eval`] or [`Self::eval_bool`]. See the
/// [module docs](self) for why the request path never holds the source.
pub struct CompiledCel {
    /// Where this expression came from in the operator's config, for
    /// example ``policy `assertion` (no-5xx)``. Only used in
    /// diagnostics.
    site: String,
    engine: CelEngine,
    expr: CelExpression,
}

impl std::fmt::Debug for CompiledCel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledCel")
            .field("site", &self.site)
            .field("source", &self.expr.source())
            .finish()
    }
}

impl CompiledCel {
    /// Compile `source` once, tagging it with the config `site` that
    /// owns it.
    ///
    /// `site` is the operator-facing identity of the expression and is
    /// the only thing a reader of the error has to go on, so name the
    /// config surface and, where there is one, the specific entry:
    /// ``policy `assertion` (no-5xx)``, ``transform `cel` header
    /// `x-tls-ja4```, ``policy `rate_limiting` key``,
    /// ``custom log field `caller_tier```. The origin is added by the
    /// caller further up (see `compile_origin_policy_chain` in
    /// `sbproxy-core`).
    ///
    /// Returns an error naming the site and quoting the source when the
    /// expression does not parse, or when it reads a binding `surface`
    /// does not populate.
    ///
    /// Those two failures are separate series on
    /// `sbproxy_script_compile_total{engine="cel"}`. A refusal here
    /// parsed successfully, so it counts once under `result="ok"` from
    /// [`CelEngine::compile`] and once under `result="surface_error"`.
    /// The number of expressions that actually loaded is `ok` minus
    /// `surface_error`; alert on the latter directly rather than
    /// inferring it from a dip in the former.
    pub fn compile(surface: CelSurface, site: impl Into<String>, source: &str) -> Result<Self> {
        let site = site.into();
        let engine = CelEngine::new();
        let expr = engine
            .compile(source)
            .map_err(|e| anyhow::anyhow!("{site}: invalid CEL expression {source:?}: {e}"))?;
        surface
            .validate(&site, source, expr.program())
            .map_err(|message| {
                sbproxy_observe::metrics::record_script_compile("cel", "surface_error");
                anyhow::anyhow!("{message}")
            })?;
        COMPILE_COUNT.with(|c| c.set(c.get().saturating_add(1)));
        Ok(Self { site, engine, expr })
    }

    /// The config site this expression was compiled for.
    pub fn site(&self) -> &str {
        &self.site
    }

    /// The original expression text, for logs and diagnostics.
    pub fn source(&self) -> &str {
        self.expr.source()
    }

    /// Evaluate against `ctx`. Errors are runtime failures only (a
    /// missing map key, a bad type); a syntax error cannot happen here
    /// because the expression compiled at config load.
    pub fn eval(&self, ctx: &CelContext) -> Result<CelValue> {
        self.engine.eval(&self.expr, ctx)
    }

    /// Evaluate against `ctx` and require a boolean result. A
    /// non-boolean result is a runtime error, the same as it is for
    /// [`super::CelEngine::eval_bool`].
    pub fn eval_bool(&self, ctx: &CelContext) -> Result<bool> {
        self.engine.eval_bool(&self.expr, ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_rejects_malformed_source_and_names_the_site() {
        let err = CompiledCel::compile(
            CelSurface::PolicyAssertion,
            "policy `assertion` (no-5xx)",
            "this is not valid CEL !!!",
        )
        .expect_err("malformed CEL must not compile");
        let msg = err.to_string();
        assert!(msg.contains("policy `assertion` (no-5xx)"), "{msg}");
        assert!(msg.contains("this is not valid CEL !!!"), "{msg}");
    }

    #[test]
    fn compile_happens_once_and_evaluation_never_compiles() {
        // The whole point of the type: a config generation pays one
        // parse, and the request path pays none. If a future refactor
        // reintroduces a per-evaluation compile, this fails.
        let before = compile_count_on_this_thread();
        let compiled = CompiledCel::compile(
            CelSurface::PolicyExpression,
            "test site",
            r#"request.method == "GET""#,
        )
        .expect("valid CEL compiles");
        let after = compile_count_on_this_thread();
        assert_eq!(after - before, 1, "one call, one parse");

        let mut ctx = CelContext::new();
        let mut request = std::collections::HashMap::new();
        request.insert("method".to_string(), CelValue::String("GET".to_string()));
        ctx.set("request", CelValue::Map(request));
        for _ in 0..100 {
            assert!(compiled.eval_bool(&ctx).expect("evaluates"));
        }

        assert_eq!(compile_count_on_this_thread(), after, "no parse per eval");
    }

    #[test]
    fn eval_bool_surfaces_a_runtime_error_rather_than_deciding_a_posture() {
        // A non-boolean result is a runtime error. The type reports it
        // and lets the call site decide what to do, which is what makes
        // per-surface postures possible.
        let compiled = CompiledCel::compile(CelSurface::PolicyExpression, "test site", "1 + 1")
            .expect("valid CEL");
        let ctx = CelContext::new();
        assert!(compiled.eval_bool(&ctx).is_err());
        assert!(matches!(compiled.eval(&ctx), Ok(CelValue::Int(2))));
    }

    #[test]
    fn has_needs_a_field_selection_and_in_is_what_a_hyphenated_header_wants() {
        // This one shipped wrong. `has(request.headers["x-tier"])` reads
        // like the obvious way to ask whether a header is present, and
        // it is not CEL: the has() macro takes a field selection, not an
        // index. It sat in an example, a doc, and the access-log page,
        // where it compiled per record, failed, and silently omitted the
        // field. Pinning both halves here so the next person reaching
        // for a presence check finds the working form next to the
        // broken one.
        let err = CompiledCel::compile(
            CelSurface::PolicyExpression,
            "probe",
            r#"has(request.headers["x-tier"])"#,
        )
        .expect_err("has() over an index must not compile");
        assert!(
            err.to_string().contains("has() macro"),
            "the parse error should name the macro: {err}"
        );

        // Dotted access is a field selection, so has() takes it. Only
        // useful for header names that are legal CEL identifiers.
        CompiledCel::compile(
            CelSurface::PolicyExpression,
            "probe",
            "has(request.headers.host)",
        )
        .expect("has() over a field");

        // The form a hyphenated header actually needs.
        CompiledCel::compile(
            CelSurface::PolicyExpression,
            "probe",
            r#""x-tier" in request.headers"#,
        )
        .expect("in over a map");
    }

    #[test]
    fn site_and_source_are_readable_for_diagnostics() {
        let compiled = CompiledCel::compile(
            CelSurface::RateLimitKey,
            "policy `rate_limiting` key",
            "request.key_id",
        )
        .expect("valid");
        assert_eq!(compiled.site(), "policy `rate_limiting` key");
        assert_eq!(compiled.source(), "request.key_id");
        let debug = format!("{compiled:?}");
        assert!(debug.contains("request.key_id"), "{debug}");
    }
}

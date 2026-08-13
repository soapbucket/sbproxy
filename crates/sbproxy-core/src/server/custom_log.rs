// SPDX-License-Identifier: Apache-2.0
//! Operator-defined custom access-log fields.
//!
//! `proxy.observability.log.custom_fields:` lets an operator add keys to
//! the access line's `custom` object, computed per request from either a
//! static string with `${...}` variable interpolation or a script (CEL /
//! Lua / JS) evaluated against the request context. This is the runtime
//! evaluator: [`evaluate`] turns the compiled field list plus a request
//! into the `custom` map the access log carries.
//!
//! Engines accept inline `source` text, so the three text languages
//! (CEL, Lua, JS) are supported here. WASM log fields would need a
//! compiled-module path rather than inline source and are validated out
//! at config-load time.
//!
//! Evaluation is best-effort: a field whose script errors (or whose
//! variable does not resolve) is logged at debug and omitted from the
//! line rather than failing the request or dropping the whole log
//! record. The resulting values ride through the same redaction pass as
//! every other field because they are set on the entry before
//! `AccessLogEntry::emit`.
//!
//! ## CEL fields compile once per config publication (WOR-2164)
//!
//! A `engine: cel` field used to be parsed again for every log record
//! it appeared on, which is once per request on a busy origin, and a
//! malformed expression was only ever discovered there: the config
//! booted, the field quietly never appeared, and the operator had a
//! debug line for it at best. [`compile_cel_programs`] now parses every
//! CEL field across every scope while the pipeline is being built, so
//! malformed source rejects the candidate config and the log path only
//! evaluates. Lua and JS fields still build their interpreter per
//! record by design (that is their isolation model).

use std::collections::{BTreeMap, HashMap};

use pingora_proxy::Session;
use sbproxy_extension::cel::surface::CelSurface;
use sbproxy_extension::cel::CompiledCel;

use crate::context::RequestContext;

/// Every `engine: cel` custom log field in a config generation,
/// compiled once and keyed by its source text.
///
/// Keyed by source rather than by field name because the same
/// expression can be declared at proxy, tenant, and origin scope, and
/// because scope resolution happens per request: the log path has the
/// winning field in hand and needs the program for its source.
pub(crate) type CompiledLogPrograms = HashMap<String, CompiledCel>;

/// Compile every CEL custom log field declared at proxy, tenant, or
/// origin scope.
///
/// Called once per config publication, from `CompiledPipeline::from_config`,
/// so malformed CEL rejects the candidate config at boot and at reload.
/// The diagnostic names the scope and the field.
pub(crate) fn compile_cel_programs(
    config: &sbproxy_config::CompiledConfig,
) -> anyhow::Result<CompiledLogPrograms> {
    let mut programs = CompiledLogPrograms::new();

    let proxy_fields = config
        .server
        .observability
        .as_ref()
        .and_then(|o| o.log.as_ref())
        .map(|l| l.custom_fields.as_slice())
        .unwrap_or(&[]);
    compile_scope(&mut programs, "proxy", proxy_fields)?;

    for tenant in &config.server.tenants {
        let scope = format!("tenant `{}`", tenant.id);
        let fields = tenant
            .observability
            .as_ref()
            .map(|o| o.log.custom_fields.as_slice())
            .unwrap_or(&[]);
        compile_scope(&mut programs, &scope, fields)?;
    }

    for origin in &config.origins {
        let scope = format!("origin `{}`", origin.origin_id);
        let fields = origin
            .observability
            .as_ref()
            .map(|o| o.log.custom_fields.as_slice())
            .unwrap_or(&[]);
        compile_scope(&mut programs, &scope, fields)?;
    }

    Ok(programs)
}

/// Compile the CEL fields of one scope into `programs`. Non-CEL fields
/// (static values, Lua, JS) are skipped.
fn compile_scope(
    programs: &mut CompiledLogPrograms,
    scope: &str,
    fields: &[sbproxy_config::CustomLogFieldConfig],
) -> anyhow::Result<()> {
    for field in fields {
        let (Some("cel"), Some(source)) = (field.engine.as_deref(), field.source.as_deref()) else {
            continue;
        };
        if programs.contains_key(source) {
            continue;
        }
        let compiled = CompiledCel::compile(
            CelSurface::CustomLogField,
            format!("{scope}: custom log field `{}`", field.name),
            source,
        )?;
        programs.insert(source.to_string(), compiled);
    }
    Ok(())
}

/// Evaluate the configured custom fields into the access line's `custom`
/// map. Returns an empty map when nothing is configured or nothing
/// resolved.
#[allow(clippy::too_many_arguments)]
pub(super) fn evaluate(
    fields: &[sbproxy_config::CustomLogFieldConfig],
    session: &Session,
    ctx: &RequestContext,
    status: u16,
    host: &str,
    method: &str,
    path: &str,
) -> BTreeMap<String, String> {
    let context = build_context(session, ctx, status, host, method, path);
    let programs = &ctx.pipeline.custom_log_programs;
    let mut out = BTreeMap::new();
    for field in fields {
        let value = if let Some(template) = field.value.as_deref() {
            interpolate(template, &context)
        } else if let (Some(engine), Some(source)) =
            (field.engine.as_deref(), field.source.as_deref())
        {
            match eval_script(engine, source, programs, &context) {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(
                        field = %field.name,
                        engine = %engine,
                        error = %e,
                        "custom log field: evaluation failed; field omitted"
                    );
                    continue;
                }
            }
        } else {
            // Config validation rejects fields with neither/both, so
            // this is unreachable for a compiled config; skip defensively.
            continue;
        };
        if !value.is_empty() {
            out.insert(field.name.clone(), value);
        }
    }
    out
}

/// Merge custom-field definitions across scopes, most-specific wins by
/// `name`: proxy is the base, a tenant field overrides the proxy field
/// of the same name, and an origin field overrides both. Returns one
/// definition per unique name (so the more-specific definition is the
/// only one evaluated, regardless of what the broader one would resolve
/// to). Returns an empty Vec when every scope is empty.
pub(super) fn merge_scoped(
    proxy: &[sbproxy_config::CustomLogFieldConfig],
    tenant: &[sbproxy_config::CustomLogFieldConfig],
    origin: &[sbproxy_config::CustomLogFieldConfig],
) -> Vec<sbproxy_config::CustomLogFieldConfig> {
    if proxy.is_empty() && tenant.is_empty() && origin.is_empty() {
        return Vec::new();
    }
    // Insertion order proxy -> tenant -> origin; a later insert with the
    // same key replaces the earlier one, so origin wins, then tenant.
    let mut by_name: BTreeMap<&str, &sbproxy_config::CustomLogFieldConfig> = BTreeMap::new();
    for field in proxy.iter().chain(tenant).chain(origin) {
        by_name.insert(field.name.as_str(), field);
    }
    by_name.into_values().cloned().collect()
}

/// Build the request-context object shared by static interpolation and
/// every engine. Scripts see it as a single `ctx` global (`ctx.request.
/// method`, `ctx.attribution['feature']`, ...); CEL sees the same keys
/// as top-level variables.
fn build_context(
    session: &Session,
    ctx: &RequestContext,
    status: u16,
    host: &str,
    method: &str,
    path: &str,
) -> serde_json::Value {
    use serde_json::{json, Value};
    let req = session.req_header();
    let headers = build_header_context(&req.headers, |name| {
        ctx.pipeline.is_credential_carrier(name)
    });
    let query = req.uri.query().unwrap_or("");
    let attribution: serde_json::Map<String, Value> = ctx
        .attribution_tags
        .iter()
        .map(|(k, v)| (k.to_string(), Value::String(v.to_string())))
        .collect();
    json!({
        "request": {
            "method": method,
            "path": path,
            "host": host,
            "query": query,
            "headers": headers,
        },
        "response": { "status": status },
        "tenant_id": ctx.tenant_id.as_str(),
        "provider": ctx.ai_provider.clone().unwrap_or_default(),
        "model": ctx.ai_model.clone().unwrap_or_default(),
        "tokens_in": ctx.ai_tokens_in.unwrap_or(0),
        "tokens_out": ctx.ai_tokens_out.unwrap_or(0),
        "client_ip": ctx.client_ip.map(|ip| ip.to_string()).unwrap_or_default(),
        "attribution": attribution,
    })
}

fn build_header_context(
    headers: &http::HeaderMap,
    is_credential_carrier: impl Fn(&str) -> bool,
) -> serde_json::Map<String, serde_json::Value> {
    let mut captured = serde_json::Map::new();
    for (name, value) in headers {
        let canonical = name.as_str().to_ascii_lowercase();
        if is_credential_carrier(&canonical) {
            continue;
        }
        if let Ok(value) = value.to_str() {
            captured.insert(canonical, serde_json::Value::String(value.to_string()));
        }
    }
    captured
}

/// Resolve `${...}` references in a static value against the context.
/// Unknown references resolve to the empty string (and are logged at
/// debug once per miss). Literal `$` without a following `{` is passed
/// through unchanged.
fn interpolate(template: &str, context: &serde_json::Value) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        if let Some(end) = after.find('}') {
            out.push_str(&resolve_var(&after[..end], context));
            rest = &after[end + 1..];
        } else {
            // No closing brace: emit the literal `${` and stop scanning.
            out.push_str("${");
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// Resolve a single `${...}` variable name to a string.
fn resolve_var(key: &str, context: &serde_json::Value) -> String {
    if let Some(name) = key.strip_prefix("env.") {
        return std::env::var(name).unwrap_or_default();
    }
    if let Some(name) = key.strip_prefix("request.header.") {
        return context
            .pointer(&format!("/request/headers/{}", name.to_ascii_lowercase()))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
    }
    if let Some(name) = key.strip_prefix("attribution.") {
        return context
            .pointer(&format!("/attribution/{name}"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
    }
    // Bare top-level names (method/path/host/status/tenant_id/provider/
    // model). `method`/`path`/`host` live under `request`; the rest are
    // top-level. Try the friendly aliases first, then a direct lookup.
    let pointer = match key {
        "method" | "path" | "host" | "query" => format!("/request/{key}"),
        "status" => "/response/status".to_string(),
        other => format!("/{other}"),
    };
    json_scalar_to_string(context.pointer(&pointer))
}

/// Evaluate an inline script and stringify its result.
fn eval_script(
    engine: &str,
    source: &str,
    programs: &CompiledLogPrograms,
    context: &serde_json::Value,
) -> anyhow::Result<String> {
    match engine {
        "cel" => eval_cel(source, programs, context),
        "lua" => {
            let lua = sbproxy_extension::lua::LuaEngine::new()?;
            let value = lua.execute(source, script_globals(context))?;
            Ok(json_value_to_string(&value))
        }
        "js" => {
            let js = sbproxy_extension::js::JsEngine::new()?;
            let value = js
                .execute(source, script_globals(context))
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            Ok(json_value_to_string(&value))
        }
        other => Err(anyhow::anyhow!(
            "unsupported custom-log-field engine `{other}`"
        )),
    }
}

/// Globals handed to Lua / JS: the whole context under `ctx`.
fn script_globals(context: &serde_json::Value) -> HashMap<String, serde_json::Value> {
    let mut g = HashMap::new();
    g.insert("ctx".to_string(), context.clone());
    g
}

/// Evaluate a CEL custom log field against a context whose top-level
/// keys mirror the shared context object.
///
/// The program comes from `programs`, compiled at config publication.
/// A source with no entry there did not go through
/// [`compile_cel_programs`], which for a live request means the field
/// was not part of the pinned config generation; the field is omitted
/// and the caller logs, exactly as an evaluation error would be. The
/// log path never falls back to parsing the source.
fn eval_cel(
    source: &str,
    programs: &CompiledLogPrograms,
    context: &serde_json::Value,
) -> anyhow::Result<String> {
    use sbproxy_extension::cel::CelContext;
    let Some(program) = programs.get(source) else {
        anyhow::bail!("custom log field: no compiled CEL program for this config generation");
    };
    let mut cel = CelContext::new();
    if let Some(obj) = context.as_object() {
        for (key, value) in obj {
            cel.set(key.clone(), json_to_cel(value));
        }
    }
    let result = program.eval(&cel).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(cel_to_string(&result))
}

/// Convert a JSON value into a `CelValue` for the CEL context.
fn json_to_cel(value: &serde_json::Value) -> sbproxy_extension::cel::CelValue {
    use sbproxy_extension::cel::CelValue;
    match value {
        serde_json::Value::Null => CelValue::Null,
        serde_json::Value::Bool(b) => CelValue::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                CelValue::Int(i)
            } else {
                CelValue::Float(n.as_f64().unwrap_or(0.0))
            }
        }
        serde_json::Value::String(s) => CelValue::String(s.clone()),
        serde_json::Value::Array(items) => CelValue::List(items.iter().map(json_to_cel).collect()),
        serde_json::Value::Object(map) => CelValue::Map(
            map.iter()
                .map(|(k, v)| (k.clone(), json_to_cel(v)))
                .collect(),
        ),
    }
}

/// Stringify a `CelValue` result for the log line.
fn cel_to_string(value: &sbproxy_extension::cel::CelValue) -> String {
    use sbproxy_extension::cel::CelValue;
    match value {
        CelValue::String(s) => s.clone(),
        CelValue::Int(i) => i.to_string(),
        CelValue::Float(f) => f.to_string(),
        CelValue::Bool(b) => b.to_string(),
        CelValue::Null => String::new(),
        other => format!("{other:?}"),
    }
}

/// Stringify a JSON script result: strings unwrap, scalars render, null
/// becomes empty, and composite values fall back to compact JSON.
fn json_value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

/// Stringify a scalar JSON pointer result for static interpolation.
fn json_scalar_to_string(value: Option<&serde_json::Value>) -> String {
    match value {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Number(n)) => n.to_string(),
        Some(serde_json::Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn field(name: &str, value: &str) -> sbproxy_config::CustomLogFieldConfig {
        sbproxy_config::CustomLogFieldConfig {
            name: name.to_string(),
            value: Some(value.to_string()),
            engine: None,
            source: None,
        }
    }

    #[test]
    fn merge_scoped_precedence_origin_over_tenant_over_proxy() {
        let proxy = vec![field("a", "proxy_a"), field("b", "proxy_b")];
        let tenant = vec![field("b", "tenant_b"), field("c", "tenant_c")];
        let origin = vec![field("c", "origin_c"), field("d", "origin_d")];
        let merged = merge_scoped(&proxy, &tenant, &origin);
        let got: std::collections::BTreeMap<_, _> = merged
            .iter()
            .map(|f| (f.name.as_str(), f.value.as_deref().unwrap()))
            .collect();
        // a: only proxy. b: tenant overrides proxy. c: origin overrides
        // tenant. d: only origin. One entry per unique name.
        assert_eq!(got["a"], "proxy_a");
        assert_eq!(got["b"], "tenant_b");
        assert_eq!(got["c"], "origin_c");
        assert_eq!(got["d"], "origin_d");
        assert_eq!(merged.len(), 4);
    }

    #[test]
    fn merge_scoped_all_empty_is_empty() {
        assert!(merge_scoped(&[], &[], &[]).is_empty());
    }

    fn ctx() -> serde_json::Value {
        json!({
            "request": {
                "method": "POST",
                "path": "/v1/chat/completions",
                "host": "api.local",
                "headers": { "x-tier": "gold" },
            },
            "response": { "status": 200 },
            "tenant_id": "acme",
            "provider": "openai",
            "model": "gpt-4o",
            "attribution": { "feature": "checkout" },
        })
    }

    #[test]
    fn interpolate_resolves_known_variables() {
        let c = ctx();
        assert_eq!(
            interpolate("${method} ${path}", &c),
            "POST /v1/chat/completions"
        );
        assert_eq!(interpolate("t=${tenant_id}", &c), "t=acme");
        assert_eq!(interpolate("${request.header.x-tier}", &c), "gold");
        assert_eq!(interpolate("${attribution.feature}", &c), "checkout");
        assert_eq!(interpolate("${response.status}", &c), "");
        assert_eq!(interpolate("${status}", &c), "200");
    }

    #[test]
    fn interpolate_unknown_resolves_empty_and_passes_literals() {
        let c = ctx();
        assert_eq!(interpolate("a${nope}b", &c), "ab");
        assert_eq!(interpolate("price is $5", &c), "price is $5");
    }

    /// Build the compiled-program map a config publication would
    /// produce for `sources`.
    fn programs_for(sources: &[&str]) -> CompiledLogPrograms {
        let fields: Vec<sbproxy_config::CustomLogFieldConfig> = sources
            .iter()
            .enumerate()
            .map(|(i, source)| sbproxy_config::CustomLogFieldConfig {
                name: format!("f{i}"),
                value: None,
                engine: Some("cel".to_string()),
                source: Some((*source).to_string()),
            })
            .collect();
        let mut programs = CompiledLogPrograms::new();
        compile_scope(&mut programs, "test scope", &fields).expect("valid CEL compiles");
        programs
    }

    #[test]
    fn cel_field_reads_context() {
        let c = ctx();
        let sources = [
            "tenant_id",
            "request.headers[\"x-tier\"]",
            "provider + \"/\" + model",
        ];
        let programs = programs_for(&sources);
        // CEL sees the top-level keys directly.
        assert_eq!(eval_cel(sources[0], &programs, &c).unwrap(), "acme");
        assert_eq!(eval_cel(sources[1], &programs, &c).unwrap(), "gold");
        assert_eq!(
            eval_cel(sources[2], &programs, &c).unwrap(),
            "openai/gpt-4o"
        );
    }

    #[test]
    fn compile_scope_rejects_malformed_cel_and_names_the_field() {
        // WOR-2164: a malformed CEL log field used to boot fine and
        // then quietly never appear in the log line.
        let fields = vec![sbproxy_config::CustomLogFieldConfig {
            name: "caller_tier".to_string(),
            value: None,
            engine: Some("cel".to_string()),
            source: Some("this is not valid CEL !!!".to_string()),
        }];
        let mut programs = CompiledLogPrograms::new();
        let err = compile_scope(&mut programs, "proxy", &fields)
            .expect_err("malformed CEL must not compile");
        let msg = err.to_string();
        assert!(msg.contains("proxy"), "must name the scope: {msg}");
        assert!(msg.contains("caller_tier"), "must name the field: {msg}");
        assert!(
            msg.contains("this is not valid CEL !!!"),
            "must quote the source: {msg}"
        );
    }

    #[test]
    fn compile_scope_skips_static_and_non_cel_fields() {
        let fields = vec![
            field("region", "${env.REGION}"),
            sbproxy_config::CustomLogFieldConfig {
                name: "lua_field".to_string(),
                value: None,
                engine: Some("lua".to_string()),
                source: Some("return 1".to_string()),
            },
        ];
        let mut programs = CompiledLogPrograms::new();
        compile_scope(&mut programs, "proxy", &fields).expect("nothing to compile");
        assert!(programs.is_empty());
    }

    #[test]
    fn cel_log_fields_compile_once_per_publication_not_per_record() {
        // WOR-2164: the log path evaluates, it does not parse. The
        // engine stamps `sbproxy_script_compile_total{engine="cel"}` on
        // every parse, so the counter is the arbiter.
        let before = cel_compile_count();
        let programs = programs_for(&["tenant_id"]);
        let after_load = cel_compile_count();
        assert_eq!(after_load - before, 1, "one parse per publication");

        let c = ctx();
        for _ in 0..25 {
            assert_eq!(eval_cel("tenant_id", &programs, &c).unwrap(), "acme");
        }
        assert_eq!(cel_compile_count(), after_load, "no parse per log record");
    }

    #[test]
    fn cel_field_without_a_compiled_program_is_omitted_rather_than_compiled() {
        // The only way to reach this is a source that never went
        // through compile_cel_programs. It must not fall back to
        // parsing on the log path.
        let c = ctx();
        let programs = CompiledLogPrograms::new();
        let before = cel_compile_count();
        assert!(eval_cel("tenant_id", &programs, &c).is_err());
        assert_eq!(cel_compile_count(), before, "no program, no compile");
    }

    /// Total CEL compiles recorded by the engine so far, across every
    /// result label.
    fn cel_compile_count() -> u64 {
        prometheus::gather()
            .into_iter()
            .find(|family| family.name() == "sbproxy_script_compile_total")
            .map(|family| {
                family
                    .get_metric()
                    .iter()
                    .filter(|metric| {
                        metric
                            .get_label()
                            .iter()
                            .any(|label| label.name() == "engine" && label.value() == "cel")
                    })
                    .map(|metric| metric.get_counter().value() as u64)
                    .sum()
            })
            .unwrap_or_default()
    }

    #[test]
    fn custom_log_header_context_excludes_primary_credential_carriers() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-opaque-credential",
            http::HeaderValue::from_static("opaque-caller-secret"),
        );
        headers.insert("x-public", http::HeaderValue::from_static("visible"));

        let captured = build_header_context(&headers, |name| name == "x-opaque-credential");
        assert!(!captured.contains_key("x-opaque-credential"));
        assert_eq!(
            captured.get("x-public"),
            Some(&serde_json::Value::String("visible".to_string()))
        );
        assert!(
            !format!("{captured:?}").contains("opaque-caller-secret"),
            "custom log templates and scripts must never receive credential material"
        );
    }
}

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

use std::collections::{BTreeMap, HashMap};

use pingora_proxy::Session;

use crate::context::RequestContext;

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
    let mut out = BTreeMap::new();
    for field in fields {
        let value = if let Some(template) = field.value.as_deref() {
            interpolate(template, &context)
        } else if let (Some(engine), Some(source)) =
            (field.engine.as_deref(), field.source.as_deref())
        {
            match eval_script(engine, source, &context) {
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
    let mut headers = serde_json::Map::new();
    for (name, value) in req.headers.iter() {
        if let Ok(v) = value.to_str() {
            headers.insert(
                name.as_str().to_ascii_lowercase(),
                Value::String(v.to_string()),
            );
        }
    }
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
fn eval_script(engine: &str, source: &str, context: &serde_json::Value) -> anyhow::Result<String> {
    match engine {
        "cel" => eval_cel(source, context),
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

/// Evaluate a CEL expression against a context whose top-level keys
/// mirror the shared context object.
fn eval_cel(source: &str, context: &serde_json::Value) -> anyhow::Result<String> {
    use sbproxy_extension::cel::{CelContext, CelEngine};
    let mut cel = CelContext::new();
    if let Some(obj) = context.as_object() {
        for (key, value) in obj {
            cel.set(key.clone(), json_to_cel(value));
        }
    }
    let engine = CelEngine::new();
    let result = engine
        .eval_source(source, &cel)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
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

    #[test]
    fn cel_field_reads_context() {
        let c = ctx();
        // CEL sees the top-level keys directly.
        assert_eq!(eval_cel("tenant_id", &c).unwrap(), "acme");
        assert_eq!(eval_cel("request.headers[\"x-tier\"]", &c).unwrap(), "gold");
        assert_eq!(
            eval_cel("provider + \"/\" + model", &c).unwrap(),
            "openai/gpt-4o"
        );
    }
}

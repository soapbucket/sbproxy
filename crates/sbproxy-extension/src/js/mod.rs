//! JavaScript scripting engine for sbproxy.
//!
//! Provides a sandboxed JavaScript execution environment using QuickJS
//! (via rquickjs) for running user-defined scripts in request/response
//! processing. Used for custom matching logic, request transformations,
//! and WAF rules. Parallel alternative to the Lua engine.

use std::collections::HashMap;

use anyhow::Result;
use rquickjs::function::Rest;
use rquickjs::{Array, Context, Function, Object, Runtime, String as JsString, Value};

// --- JS Engine ---

/// A sandboxed JavaScript execution environment.
///
/// Wraps a rquickjs `Context` with dangerous globals removed, JSON helper
/// functions registered, and memory/stack limits enforced. Each engine
/// instance maintains its own QuickJS runtime and context.
pub struct JsEngine {
    // The Runtime must be kept alive for the lifetime of the Context.
    // It is not accessed after construction but must not be dropped.
    #[allow(dead_code)]
    runtime: Runtime,
    context: Context,
}

impl JsEngine {
    /// Create a new sandboxed JS engine with default configuration.
    ///
    /// Sets a 16 MB memory limit and a 1 MB stack size limit. Removes `eval`
    /// to prevent dynamic code injection, and registers `json_encode` /
    /// `json_decode` as global helpers.
    pub fn new() -> Result<Self> {
        Self::with_memory_limit(16 * 1024 * 1024)
    }

    /// Create a new sandboxed JS engine with a custom memory limit.
    ///
    /// The stack size limit is fixed at 1 MB. The memory limit applies to the
    /// entire QuickJS runtime heap.
    pub fn with_memory_limit(limit_bytes: usize) -> Result<Self> {
        let runtime = Runtime::new()?;
        runtime.set_memory_limit(limit_bytes);
        runtime.set_max_stack_size(1024 * 1024);

        let context = Context::full(&runtime)?;

        context.with(|ctx| {
            // Sandbox: remove dangerous globals
            Self::sandbox(&ctx)?;
            // Register json_encode / json_decode helpers
            Self::register_helpers(&ctx)?;
            Ok::<_, anyhow::Error>(())
        })?;

        Ok(Self { runtime, context })
    }

    /// Remove dangerous globals for sandboxing.
    ///
    /// QuickJS does not expose filesystem or network APIs by default, but we
    /// additionally remove `eval` to prevent dynamic code construction and
    /// injection attacks.
    fn sandbox(ctx: &rquickjs::Ctx) -> Result<()> {
        let globals = ctx.globals();
        globals.remove("eval")?;
        Ok(())
    }

    /// Register `json_encode` and `json_decode` as global convenience aliases.
    ///
    /// These mirror the Lua engine API. `json_encode` maps to `JSON.stringify`
    /// and `json_decode` maps to `JSON.parse`, which are built into QuickJS.
    fn register_helpers(ctx: &rquickjs::Ctx) -> Result<()> {
        ctx.eval::<(), _>(
            r#"
            globalThis.json_encode = JSON.stringify;
            globalThis.json_decode = JSON.parse;
            "#,
        )?;
        Ok(())
    }

    /// Execute a JavaScript script with the given globals set.
    ///
    /// Each key in `globals` is set as a global variable before execution.
    /// The return value of the script expression is converted to JSON.
    /// Scripts that produce `undefined` return `null`.
    pub fn execute(
        &self,
        script: &str,
        globals: HashMap<String, serde_json::Value>,
    ) -> Result<serde_json::Value> {
        self.context.with(|ctx| {
            let global = ctx.globals();

            // Set input globals before running the script
            for (key, value) in &globals {
                let js_val = json_to_js(&ctx, value)?;
                global.set(key.as_str(), js_val)?;
            }

            // Execute the script and capture the result value
            let result: Value = ctx.eval(script)?;

            js_to_json(&ctx, &result)
        })
    }

    /// Execute a script that defines a named function, then call that function.
    ///
    /// The script is evaluated first (which should define the function as a
    /// global). The named function is then retrieved and called with the
    /// provided arguments. Returns the function's return value as JSON.
    ///
    /// This supports the proxy config pattern where scripts define functions
    /// like `modify_request(req, ctx)`, `modify_response(resp, ctx)`, or
    /// `modify_json(data, ctx)`.
    pub fn call_function(
        &self,
        script: &str,
        func_name: &str,
        args: Vec<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        self.context.with(|ctx| {
            // Load the script so the function is defined as a global
            ctx.eval::<(), _>(script)?;

            let global = ctx.globals();
            let func: Function = global.get(func_name)?;

            // Convert args to JS values
            let js_args: Vec<Value> = args
                .iter()
                .map(|a| json_to_js(&ctx, a))
                .collect::<anyhow::Result<Vec<_>>>()?;

            // --- Dispatch by arg count ---
            // For 0-2 args we construct typed tuples so rquickjs can pass
            // them directly. For 3+ args we wrap the remaining values in
            // `Rest<Value>` so they are spread into the call without any
            // string interpolation. The previous implementation built a
            // `format!("{}(...__js_args__)", func_name)` and passed it to
            // `ctx.eval`, which let an attacker-controlled `func_name`
            // inject arbitrary JavaScript (H7).
            let result: Value = match js_args.len() {
                0 => func.call(())?,
                1 => func.call((js_args.into_iter().next().unwrap(),))?,
                2 => {
                    let mut iter = js_args.into_iter();
                    func.call((iter.next().unwrap(), iter.next().unwrap()))?
                }
                _ => {
                    let mut iter = js_args.into_iter();
                    let a0 = iter.next().unwrap();
                    let a1 = iter.next().unwrap();
                    let rest: Vec<Value> = iter.collect();
                    func.call((a0, a1, Rest(rest)))?
                }
            };

            js_to_json(&ctx, &result)
        })
    }

    /// Execute a request matching function.
    ///
    /// Loads and evaluates the script (which must define a `match_request`
    /// function at the global scope), then calls `match_request(req, ctx)`
    /// with the request and context JSON values. Returns the boolean result.
    ///
    /// Example script:
    /// ```js
    /// function match_request(req, ctx) {
    ///     return req.path === "/api/admin" && ctx.is_admin === true;
    /// }
    /// ```
    pub fn match_request(
        &self,
        script: &str,
        request: &serde_json::Value,
        context: &serde_json::Value,
    ) -> Result<bool> {
        self.context.with(|ctx| {
            ctx.eval::<(), _>(script)?;

            let global = ctx.globals();
            let func: Function = global.get("match_request")?;

            let req_js = json_to_js(&ctx, request)?;
            let ctx_js = json_to_js(&ctx, context)?;

            let result: bool = func.call((req_js, ctx_js))?;
            Ok(result)
        })
    }

    /// Execute a WAF custom rule.
    ///
    /// Loads and evaluates the script (which must define a `match` function),
    /// then calls `match(request)` where `request` is an object with `uri`,
    /// `headers`, `body` fields plus a `header(name)` method that performs
    /// case-insensitive header lookup.
    ///
    /// Example script:
    /// ```js
    /// function match(request) {
    ///     const ua = request.header("user-agent") || "";
    ///     return ua.includes("malicious-bot");
    /// }
    /// ```
    pub fn waf_match(
        &self,
        script: &str,
        uri: &str,
        headers: &HashMap<String, String>,
        body: Option<&str>,
    ) -> Result<bool> {
        self.context.with(|ctx| {
            // --- Build the request object ---
            let req = Object::new(ctx.clone())?;
            req.set("uri", uri)?;

            // Normalize header names to lowercase in a JS object
            let hdrs_obj = Object::new(ctx.clone())?;
            for (k, v) in headers {
                hdrs_obj.set(k.to_lowercase().as_str(), v.as_str())?;
            }
            req.set("headers", hdrs_obj)?;

            if let Some(b) = body {
                req.set("body", b)?;
            }

            // Register a shared header-lookup function and attach it to the
            // request object. Using a pre-defined JS function lets QuickJS
            // resolve `this` correctly when called as request.header("...").
            ctx.eval::<(), _>(
                r#"
                globalThis.__waf_header_fn__ = function(name) {
                    return this.headers[name.toLowerCase()];
                };
                "#,
            )?;
            let header_fn: Function = ctx.globals().get("__waf_header_fn__")?;
            req.set("header", header_fn)?;

            // --- Load script and call match() ---
            ctx.eval::<(), _>(script)?;
            let global = ctx.globals();
            let func: Function = global.get("match")?;
            let result: bool = func.call((req,))?;
            Ok(result)
        })
    }
}

// --- JSON <-> JS Value Conversion ---

/// Convert a `serde_json::Value` to a `rquickjs::Value`.
///
/// Mapping:
/// - `null` -> JS null
/// - `bool` -> JS boolean
/// - integer numbers -> JS int (i32); large numbers -> JS float (f64)
/// - float numbers -> JS float (f64)
/// - strings -> JS string
/// - arrays -> JS Array with 0-based indexing
/// - objects -> JS Object with string keys
fn json_to_js<'js>(
    ctx: &rquickjs::Ctx<'js>,
    json: &serde_json::Value,
) -> anyhow::Result<Value<'js>> {
    match json {
        serde_json::Value::Null => Ok(Value::new_null(ctx.clone())),
        serde_json::Value::Bool(b) => Ok(Value::new_bool(ctx.clone(), *b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                // Fit into i32 if possible, otherwise promote to f64
                if i >= i32::MIN as i64 && i <= i32::MAX as i64 {
                    Ok(Value::new_int(ctx.clone(), i as i32))
                } else {
                    Ok(Value::new_float(ctx.clone(), i as f64))
                }
            } else if let Some(f) = n.as_f64() {
                Ok(Value::new_float(ctx.clone(), f))
            } else {
                Ok(Value::new_null(ctx.clone()))
            }
        }
        serde_json::Value::String(s) => Ok(JsString::from_str(ctx.clone(), s)?.into()),
        serde_json::Value::Array(arr) => {
            let js_arr = Array::new(ctx.clone())?;
            for (i, v) in arr.iter().enumerate() {
                js_arr.set(i, json_to_js(ctx, v)?)?;
            }
            Ok(js_arr.into_value())
        }
        serde_json::Value::Object(obj) => {
            let js_obj = Object::new(ctx.clone())?;
            for (k, v) in obj {
                js_obj.set(k.as_str(), json_to_js(ctx, v)?)?;
            }
            Ok(js_obj.into_value())
        }
    }
}

/// Convert a `rquickjs::Value` to `serde_json::Value`.
///
/// Uses `JSON.stringify` for reliable conversion of all JS value types,
/// including nested objects and arrays. `undefined` and values that
/// stringify to `"undefined"` are mapped to JSON null.
fn js_to_json<'js>(
    ctx: &rquickjs::Ctx<'js>,
    val: &Value<'js>,
) -> anyhow::Result<serde_json::Value> {
    // Early-out for explicit null/undefined to avoid stringify overhead
    if val.is_null() || val.is_undefined() {
        return Ok(serde_json::Value::Null);
    }

    // Use JSON.stringify for reliable serialization of objects/arrays/primitives
    let json_obj: Object = ctx.globals().get("JSON")?;
    let stringify: Function = json_obj.get("stringify")?;
    let result: Value = stringify.call((val.clone(),))?;

    if result.is_undefined() || result.is_null() {
        return Ok(serde_json::Value::Null);
    }

    let json_str = result
        .into_string()
        .ok_or_else(|| anyhow::anyhow!("JSON.stringify returned non-string"))?;
    let s = json_str.to_string()?;

    if s.is_empty() || s == "undefined" {
        return Ok(serde_json::Value::Null);
    }

    let parsed = serde_json::from_str(&s)?;
    Ok(parsed)
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    // --- Engine Construction ---

    #[test]
    fn test_new_engine() {
        let _engine = JsEngine::new().unwrap();
        // Should construct without panic
    }

    #[test]
    fn test_with_memory_limit() {
        let _engine = JsEngine::with_memory_limit(32 * 1024 * 1024).unwrap();
    }

    // --- Basic Execution ---

    #[test]
    fn test_execute_simple_addition() {
        let engine = JsEngine::new().unwrap();
        let result = engine.execute("1 + 2", HashMap::new()).unwrap();
        assert_eq!(result, serde_json::json!(3));
    }

    #[test]
    fn test_execute_returns_string() {
        let engine = JsEngine::new().unwrap();
        let result = engine.execute(r#""hello world""#, HashMap::new()).unwrap();
        assert_eq!(result, serde_json::json!("hello world"));
    }

    #[test]
    fn test_execute_returns_boolean() {
        let engine = JsEngine::new().unwrap();
        let result = engine.execute("true", HashMap::new()).unwrap();
        assert_eq!(result, serde_json::json!(true));
    }

    #[test]
    fn test_execute_returns_null() {
        let engine = JsEngine::new().unwrap();
        let result = engine.execute("null", HashMap::new()).unwrap();
        assert_eq!(result, serde_json::Value::Null);
    }

    #[test]
    fn test_execute_returns_undefined_as_null() {
        let engine = JsEngine::new().unwrap();
        let result = engine.execute("undefined", HashMap::new()).unwrap();
        assert_eq!(result, serde_json::Value::Null);
    }

    #[test]
    fn test_execute_returns_object() {
        let engine = JsEngine::new().unwrap();
        let result = engine
            .execute(r#"({name: "alice", age: 30})"#, HashMap::new())
            .unwrap();
        assert_eq!(result["name"], "alice");
        assert_eq!(result["age"], 30);
    }

    #[test]
    fn test_execute_returns_array() {
        let engine = JsEngine::new().unwrap();
        let result = engine.execute("[10, 20, 30]", HashMap::new()).unwrap();
        assert_eq!(result, serde_json::json!([10, 20, 30]));
    }

    #[test]
    fn test_execute_float_value() {
        let engine = JsEngine::new().unwrap();
        let result = engine.execute("2.5", HashMap::new()).unwrap();
        let f = result.as_f64().unwrap();
        assert!((f - 2.5).abs() < 0.001);
    }

    // --- Globals ---

    #[test]
    fn test_execute_with_numeric_globals() {
        let engine = JsEngine::new().unwrap();
        let mut globals = HashMap::new();
        globals.insert("x".to_string(), serde_json::json!(10));
        globals.insert("y".to_string(), serde_json::json!(20));
        let result = engine.execute("x + y", globals).unwrap();
        assert_eq!(result, serde_json::json!(30));
    }

    #[test]
    fn test_execute_with_string_global() {
        let engine = JsEngine::new().unwrap();
        let mut globals = HashMap::new();
        globals.insert("name".to_string(), serde_json::json!("world"));
        let result = engine.execute(r#"`hello ${name}`"#, globals).unwrap();
        assert_eq!(result, serde_json::json!("hello world"));
    }

    #[test]
    fn test_execute_with_object_global() {
        let engine = JsEngine::new().unwrap();
        let mut globals = HashMap::new();
        globals.insert(
            "req".to_string(),
            serde_json::json!({"method": "GET", "path": "/api"}),
        );
        let result = engine.execute("req.method", globals).unwrap();
        assert_eq!(result, serde_json::json!("GET"));
    }

    // --- JSON Helpers ---

    #[test]
    fn test_json_decode_helper() {
        let engine = JsEngine::new().unwrap();
        let result = engine
            .execute(r#"json_decode('{"a":1}').a"#, HashMap::new())
            .unwrap();
        assert_eq!(result, serde_json::json!(1));
    }

    #[test]
    fn test_json_encode_helper() {
        let engine = JsEngine::new().unwrap();
        let result = engine
            .execute(r#"json_encode({name: "test", value: 42})"#, HashMap::new())
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(result.as_str().unwrap()).unwrap();
        assert_eq!(parsed["name"], "test");
        assert_eq!(parsed["value"], 42);
    }

    #[test]
    fn test_json_roundtrip() {
        let engine = JsEngine::new().unwrap();
        let result = engine
            .execute(
                r#"
                const original = {items: [1, 2, 3], active: true};
                const encoded = json_encode(original);
                const decoded = json_decode(encoded);
                decoded.active
                "#,
                HashMap::new(),
            )
            .unwrap();
        assert_eq!(result, serde_json::json!(true));
    }

    // --- call_function ---

    #[test]
    fn test_call_function_two_args() {
        let engine = JsEngine::new().unwrap();
        let result = engine
            .call_function(
                "function add(a, b) { return a + b; }",
                "add",
                vec![serde_json::json!(3), serde_json::json!(4)],
            )
            .unwrap();
        assert_eq!(result, serde_json::json!(7));
    }

    #[test]
    fn test_call_function_no_args() {
        let engine = JsEngine::new().unwrap();
        let result = engine
            .call_function("function answer() { return 42; }", "answer", vec![])
            .unwrap();
        assert_eq!(result, serde_json::json!(42));
    }

    #[test]
    fn test_call_function_one_arg() {
        let engine = JsEngine::new().unwrap();
        let result = engine
            .call_function(
                "function double(x) { return x * 2; }",
                "double",
                vec![serde_json::json!(21)],
            )
            .unwrap();
        assert_eq!(result, serde_json::json!(42));
    }

    #[test]
    fn test_call_function_three_args() {
        let engine = JsEngine::new().unwrap();
        let result = engine
            .call_function(
                "function sum3(a, b, c) { return a + b + c; }",
                "sum3",
                vec![
                    serde_json::json!(10),
                    serde_json::json!(20),
                    serde_json::json!(30),
                ],
            )
            .unwrap();
        assert_eq!(result, serde_json::json!(60));
    }

    #[test]
    fn test_call_function_with_object_arg() {
        let engine = JsEngine::new().unwrap();
        let result = engine
            .call_function(
                r#"function transform(data) {
                    data.processed = true;
                    data.count = data.count * 2;
                    return data;
                }"#,
                "transform",
                vec![serde_json::json!({"count": 5, "name": "test"})],
            )
            .unwrap();
        assert_eq!(result["processed"], true);
        assert_eq!(result["count"], 10);
    }

    #[test]
    fn test_call_modify_request_returns_set_headers() {
        let engine = JsEngine::new().unwrap();
        let script = r#"
            function modify_request(req, ctx) {
                return {
                    set_headers: {
                        "X-JS-Modified": "true",
                        "X-JS-Method": req.method,
                        "X-JS-Path": req.path,
                    }
                };
            }
        "#;
        let req = serde_json::json!({
            "method": "GET",
            "path": "/api/v1/users",
            "headers": {"x-role": "admin"},
            "host": "js-reqmod.test",
        });
        let result = engine
            .call_function(script, "modify_request", vec![req, serde_json::json!({})])
            .unwrap();

        let set_headers = result.get("set_headers").unwrap().as_object().unwrap();
        assert_eq!(
            set_headers.get("X-JS-Modified").unwrap().as_str().unwrap(),
            "true"
        );
        assert_eq!(
            set_headers.get("X-JS-Method").unwrap().as_str().unwrap(),
            "GET"
        );
        assert_eq!(
            set_headers.get("X-JS-Path").unwrap().as_str().unwrap(),
            "/api/v1/users"
        );
    }

    #[test]
    fn test_call_modify_request_conditional_header() {
        let engine = JsEngine::new().unwrap();
        let script = r#"
            function modify_request(req, ctx) {
                const role = req.headers["x-role"] || "";
                return {
                    set_headers: {
                        "X-JS-Is-Admin": role === "admin" ? "true" : "false",
                    }
                };
            }
        "#;

        let req = serde_json::json!({
            "method": "GET", "path": "/", "headers": {"x-role": "admin"}, "host": "test"
        });
        let result = engine
            .call_function(script, "modify_request", vec![req, serde_json::json!({})])
            .unwrap();
        let headers = result.get("set_headers").unwrap().as_object().unwrap();
        assert_eq!(
            headers.get("X-JS-Is-Admin").unwrap().as_str().unwrap(),
            "true"
        );
    }

    #[test]
    fn test_call_modify_response_returns_set_headers() {
        let engine = JsEngine::new().unwrap();
        let script = r#"
            function modify_response(resp, ctx) {
                return {
                    set_headers: {
                        "X-JS-Stage": "response",
                        "X-JS-Status": String(resp.status_code),
                    }
                };
            }
        "#;
        let resp = serde_json::json!({"status_code": 200});
        let result = engine
            .call_function(script, "modify_response", vec![resp, serde_json::json!({})])
            .unwrap();

        let set_headers = result.get("set_headers").unwrap().as_object().unwrap();
        assert_eq!(
            set_headers.get("X-JS-Stage").unwrap().as_str().unwrap(),
            "response"
        );
        assert_eq!(
            set_headers.get("X-JS-Status").unwrap().as_str().unwrap(),
            "200"
        );
    }

    #[test]
    fn test_call_function_rejects_injected_func_name() {
        // H7 regression: an attacker-controlled `func_name` containing
        // a JavaScript fragment (here: a statement that would set
        // `globalThis.x` if eval'd) must NOT execute. The lookup must
        // fail because no global property has that exact name.
        let engine = JsEngine::new().unwrap();
        let script = "function f(a, b, c) { return a + b + c; }";
        let func_name = "f; globalThis.x = 1";

        let result = engine.call_function(
            script,
            func_name,
            vec![
                serde_json::json!(1),
                serde_json::json!(2),
                serde_json::json!(3),
            ],
        );
        assert!(
            result.is_err(),
            "lookup for an injected func_name should fail, got Ok: {:?}",
            result.ok()
        );

        let x = engine
            .execute("typeof globalThis.x", HashMap::new())
            .unwrap();
        assert_eq!(
            x,
            serde_json::json!("undefined"),
            "injected code modified globalThis.x: {x:?}"
        );
    }

    #[test]
    fn test_call_function_four_args() {
        let engine = JsEngine::new().unwrap();
        let result = engine
            .call_function(
                "function sum4(a, b, c, d) { return a + b + c + d; }",
                "sum4",
                vec![
                    serde_json::json!(1),
                    serde_json::json!(2),
                    serde_json::json!(3),
                    serde_json::json!(4),
                ],
            )
            .unwrap();
        assert_eq!(result, serde_json::json!(10));
    }

    // --- match_request ---

    #[test]
    fn test_match_request_returns_true() {
        let engine = JsEngine::new().unwrap();
        let script = r#"
            function match_request(req, ctx) {
                return req.method === "POST" && req.path.startsWith("/api");
            }
        "#;
        let request = serde_json::json!({"method": "POST", "path": "/api/v1/users"});
        let context = serde_json::json!({});
        let result = engine.match_request(script, &request, &context).unwrap();
        assert!(result);
    }

    #[test]
    fn test_match_request_returns_false() {
        let engine = JsEngine::new().unwrap();
        let script = r#"
            function match_request(req, ctx) {
                return req.method === "DELETE";
            }
        "#;
        let request = serde_json::json!({"method": "GET", "path": "/"});
        let context = serde_json::json!({});
        let result = engine.match_request(script, &request, &context).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_match_request_with_context() {
        let engine = JsEngine::new().unwrap();
        let script = r#"
            function match_request(req, ctx) {
                return ctx.is_admin === true;
            }
        "#;
        let request = serde_json::json!({"method": "GET", "path": "/admin"});
        let context = serde_json::json!({"is_admin": true});
        let result = engine.match_request(script, &request, &context).unwrap();
        assert!(result);
    }

    #[test]
    fn test_match_request_header_check() {
        let engine = JsEngine::new().unwrap();
        let script = r#"
            function match_request(req, ctx) {
                return !!(req.headers && req.headers["x-api-key"]);
            }
        "#;
        let request = serde_json::json!({
            "method": "GET",
            "path": "/secure",
            "headers": {"x-api-key": "abc123"}
        });
        let context = serde_json::json!({});
        let result = engine.match_request(script, &request, &context).unwrap();
        assert!(result);
    }

    // --- waf_match ---

    #[test]
    fn test_waf_match_detects_malicious_ua() {
        let engine = JsEngine::new().unwrap();
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "malicious-bot/1.0".to_string());
        let result = engine
            .waf_match(
                r#"function match(request) {
                    const ua = request.header("user-agent") || "";
                    return ua.includes("malicious");
                }"#,
                "/test",
                &headers,
                None,
            )
            .unwrap();
        assert!(result);
    }

    #[test]
    fn test_waf_no_match_clean_ua() {
        let engine = JsEngine::new().unwrap();
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "Mozilla/5.0".to_string());
        let result = engine
            .waf_match(
                r#"function match(request) {
                    const ua = request.header("user-agent") || "";
                    return ua.includes("malicious");
                }"#,
                "/test",
                &headers,
                None,
            )
            .unwrap();
        assert!(!result);
    }

    #[test]
    fn test_waf_match_uri() {
        let engine = JsEngine::new().unwrap();
        let headers = HashMap::new();
        let result = engine
            .waf_match(
                r#"function match(request) {
                    return request.uri.includes("../");
                }"#,
                "/etc/../passwd",
                &headers,
                None,
            )
            .unwrap();
        assert!(result);
    }

    #[test]
    fn test_waf_match_body() {
        let engine = JsEngine::new().unwrap();
        let headers = HashMap::new();
        let result = engine
            .waf_match(
                r#"function match(request) {
                    const body = request.body || "";
                    return body.includes("<script>");
                }"#,
                "/submit",
                &headers,
                Some("<script>alert(1)</script>"),
            )
            .unwrap();
        assert!(result);
    }

    #[test]
    fn test_waf_header_case_insensitive() {
        let engine = JsEngine::new().unwrap();
        let mut headers = HashMap::new();
        // Header stored with mixed case; lookup should be case-insensitive
        headers.insert("User-Agent".to_string(), "curl/7.0".to_string());
        let result = engine
            .waf_match(
                r#"function match(request) {
                    const ua = request.header("User-Agent") || "";
                    return ua.startsWith("curl");
                }"#,
                "/",
                &headers,
                None,
            )
            .unwrap();
        assert!(result);
    }

    // --- Sandbox ---

    #[test]
    fn test_sandbox_eval_removed() {
        let engine = JsEngine::new().unwrap();
        let result = engine.execute("typeof eval", HashMap::new()).unwrap();
        assert_eq!(result, serde_json::json!("undefined"));
    }

    #[test]
    fn test_sandbox_no_filesystem() {
        let engine = JsEngine::new().unwrap();
        // QuickJS has no built-in fs; accessing it should return undefined
        let result = engine.execute("typeof process", HashMap::new()).unwrap();
        assert_eq!(result, serde_json::json!("undefined"));
    }

    #[test]
    fn test_sandbox_safe_builtins_available() {
        let engine = JsEngine::new().unwrap();
        // Math, Date, JSON, String, Array should all be present
        let result = engine.execute("typeof Math.max", HashMap::new()).unwrap();
        assert_eq!(result, serde_json::json!("function"));

        let result = engine
            .execute("typeof JSON.stringify", HashMap::new())
            .unwrap();
        assert_eq!(result, serde_json::json!("function"));
    }

    // --- Memory Limit ---

    #[test]
    fn test_memory_limit_enforced() {
        let engine = JsEngine::with_memory_limit(512 * 1024).unwrap(); // 512 KB
                                                                       // Try to allocate far more than the limit
        let result = engine.execute(
            "let arr = []; for(let i = 0; i < 10000000; i++) arr.push('x'.repeat(1000));",
            HashMap::new(),
        );
        assert!(result.is_err(), "Expected OOM error with 512KB limit");
    }

    // --- Error Handling ---

    #[test]
    fn test_syntax_error() {
        let engine = JsEngine::new().unwrap();
        let result = engine.execute("this is not !!! valid js", HashMap::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_runtime_error() {
        let engine = JsEngine::new().unwrap();
        let result = engine.execute("throw new Error('something went wrong')", HashMap::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_match_request_missing_function() {
        let engine = JsEngine::new().unwrap();
        let script = "// no match_request defined";
        let request = serde_json::json!({"method": "GET"});
        let context = serde_json::json!({});
        let result = engine.match_request(script, &request, &context);
        assert!(result.is_err());
    }

    #[test]
    fn test_json_decode_invalid_input() {
        let engine = JsEngine::new().unwrap();
        let result = engine.execute("json_decode('{{{invalid')", HashMap::new());
        assert!(result.is_err());
    }

    // --- Modern JavaScript Features ---

    #[test]
    fn test_es2020_arrow_functions_and_destructuring() {
        let engine = JsEngine::new().unwrap();
        let result = engine
            .execute(
                r#"
                const transform = ({name, ...rest}) => ({
                    greeting: `Hello, ${name}!`,
                    ...rest,
                    processed: true
                });
                transform({name: "sbproxy", version: "1.0"})
                "#,
                HashMap::new(),
            )
            .unwrap();
        assert_eq!(result["greeting"], "Hello, sbproxy!");
        assert_eq!(result["version"], "1.0");
        assert_eq!(result["processed"], true);
    }

    #[test]
    fn test_optional_chaining() {
        let engine = JsEngine::new().unwrap();
        let result = engine
            .execute(
                r#"
                const obj = {a: {b: {c: 42}}};
                obj?.a?.b?.c
                "#,
                HashMap::new(),
            )
            .unwrap();
        assert_eq!(result, serde_json::json!(42));
    }

    #[test]
    fn test_nullish_coalescing() {
        let engine = JsEngine::new().unwrap();
        let result = engine.execute("null ?? 'default'", HashMap::new()).unwrap();
        assert_eq!(result, serde_json::json!("default"));
    }

    #[test]
    fn test_template_literals() {
        let engine = JsEngine::new().unwrap();
        let mut globals = HashMap::new();
        globals.insert("input".to_string(), serde_json::json!("Hello, World!"));
        let result = engine
            .execute("input.toLowerCase().replace('world', 'rust')", globals)
            .unwrap();
        assert_eq!(result, serde_json::json!("hello, rust!"));
    }

    #[test]
    fn test_nested_objects() {
        let engine = JsEngine::new().unwrap();
        let result = engine
            .execute(
                r#"({user: {name: "bob", roles: ["admin", "user"]}})"#,
                HashMap::new(),
            )
            .unwrap();
        assert_eq!(result["user"]["name"], "bob");
        assert_eq!(result["user"]["roles"][0], "admin");
        assert_eq!(result["user"]["roles"][1], "user");
    }

    // --- Agent-class exposure (G1.4) ---
    //
    // The JS engine consumes a `serde_json::Value` for `request`, so
    // any caller that builds `request` with `agent_id`, `agent_class`,
    // `agent_vendor`, `agent_id_source`, `agent_rdns_hostname` keys
    // (mirroring the CEL / Lua / WASM bridges) sees those fields under
    // `req.agent_id` etc. We assert that the round-trip works so the
    // contract stays in sync.

    #[test]
    fn match_request_can_branch_on_agent_id() {
        let engine = JsEngine::new().unwrap();
        let script = r#"
            function match_request(req, ctx) {
                return req.agent_id === "openai-gptbot"
                    && req.agent_vendor === "OpenAI";
            }
        "#;
        let request = serde_json::json!({
            "method": "GET",
            "path": "/article",
            "agent_id": "openai-gptbot",
            "agent_class": "openai-gptbot",
            "agent_vendor": "OpenAI",
            "agent_purpose": "training",
            "agent_id_source": "user_agent",
            "agent_rdns_hostname": "",
        });
        let context = serde_json::json!({});
        let result = engine.match_request(script, &request, &context).unwrap();
        assert!(result);
    }

    #[test]
    fn match_request_treats_missing_agent_fields_as_undefined() {
        let engine = JsEngine::new().unwrap();
        let script = r#"
            function match_request(req, ctx) {
                // Human / unset agent: agent_id is empty string.
                return (req.agent_id || "") === "";
            }
        "#;
        let request = serde_json::json!({
            "method": "GET",
            "path": "/",
            "agent_id": "",
        });
        let context = serde_json::json!({});
        let result = engine.match_request(script, &request, &context).unwrap();
        assert!(result);
    }
}

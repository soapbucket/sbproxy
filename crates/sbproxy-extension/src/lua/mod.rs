//! Lua scripting engine for sbproxy.
//!
//! Provides a sandboxed Lua execution environment using Luau (Roblox's Lua
//! dialect) for running user-defined scripts in request/response processing.
//! Used for custom matching logic, request transformations, and WAF rules.

pub mod bindings;
pub mod sandbox;

use std::collections::HashMap;

use anyhow::Result;
use mlua::prelude::*;

pub use sandbox::SandboxConfig;

// --- Lua Engine ---

/// A sandboxed Lua execution environment.
///
/// Each public method (`execute`, `call_function`, `match_request`,
/// `waf_match`) builds a fresh `mlua::Lua` so globals set by one
/// invocation cannot leak into the next. This is the H6 isolation
/// guarantee: there is no shared interpreter state across calls.
pub struct LuaEngine {
    _private: (),
}

impl LuaEngine {
    /// Create a new sandboxed Lua engine with default configuration.
    ///
    /// Construction is cheap: each `execute` / `call_function` /
    /// `match_request` / `waf_match` call builds its own Lua state
    /// internally, so the engine itself holds no Lua state.
    pub fn new() -> Result<Self> {
        let _ = Self::fresh_lua()?;
        Ok(Self { _private: () })
    }

    /// Build a fresh sandboxed Lua state. Used per-invocation to
    /// guarantee globals from one call do not bleed into the next.
    fn fresh_lua() -> Result<Lua> {
        let lua = Lua::new();
        Self::sandbox(&lua)?;
        Self::register_json_helpers(&lua)?;
        Ok(lua)
    }

    /// Remove dangerous Lua globals.
    ///
    /// Nilling these out neutralises filesystem access (`io`, `loadfile`,
    /// `dofile`), process-level access (`os`), dynamic code construction
    /// (`load`, `loadstring`), introspection-based escape paths
    /// (`debug`, `package`), and raw table mutation (`rawset`, `rawget`).
    fn sandbox(lua: &Lua) -> Result<()> {
        let globals = lua.globals();
        globals.set("os", mlua::Value::Nil)?;
        globals.set("io", mlua::Value::Nil)?;
        globals.set("loadfile", mlua::Value::Nil)?;
        globals.set("dofile", mlua::Value::Nil)?;
        globals.set("require", mlua::Value::Nil)?;
        globals.set("rawset", mlua::Value::Nil)?;
        globals.set("rawget", mlua::Value::Nil)?;
        globals.set("load", mlua::Value::Nil)?;
        globals.set("loadstring", mlua::Value::Nil)?;
        globals.set("debug", mlua::Value::Nil)?;
        globals.set("package", mlua::Value::Nil)?;
        Ok(())
    }

    /// Register JSON encode/decode helper functions.
    ///
    /// Makes `json_encode(value)` and `json_decode(string)` available as
    /// global functions in the Lua VM.
    fn register_json_helpers(lua: &Lua) -> Result<()> {
        let json_encode = lua.create_function(|lua, value: mlua::Value| {
            let json = lua_value_to_json(lua, &value)?;
            let s = serde_json::to_string(&json).map_err(mlua::Error::external)?;
            Ok(s)
        })?;

        let json_decode = lua.create_function(|lua, s: String| {
            let json: serde_json::Value =
                serde_json::from_str(&s).map_err(mlua::Error::external)?;
            json_to_lua_value(lua, &json)
        })?;

        lua.globals().set("json_encode", json_encode)?;
        lua.globals().set("json_decode", json_decode)?;
        Ok(())
    }

    /// Execute a Lua script with the given globals set.
    ///
    /// Each key in `globals` is set as a Lua global variable before execution.
    /// The return value of the script is converted back to a JSON value.
    pub fn execute(
        &self,
        script: &str,
        globals: HashMap<String, serde_json::Value>,
    ) -> Result<serde_json::Value> {
        let lua = Self::fresh_lua()?;

        for (key, value) in &globals {
            let lua_val = json_to_lua_value(&lua, value)?;
            lua.globals().set(key.as_str(), lua_val)?;
        }

        let result: mlua::Value = lua.load(script).eval()?;

        let json = lua_value_to_json(&lua, &result)?;
        Ok(json)
    }

    /// Execute a script that defines a named function, then call that function
    /// with the given arguments. Returns the function's return value as JSON.
    ///
    /// This supports the Go config pattern where scripts define functions like
    /// `modify_request(req, ctx)`, `modify_response(resp, ctx)`, or
    /// `modify_json(data, ctx)` instead of using bare top-level code.
    pub fn call_function(
        &self,
        script: &str,
        func_name: &str,
        args: Vec<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        let lua = Self::fresh_lua()?;

        lua.load(script).exec()?;

        let func: mlua::Function = lua.globals().get(func_name)?;

        let lua_args: Vec<mlua::Value> = args
            .iter()
            .map(|a| json_to_lua_value(&lua, a))
            .collect::<mlua::Result<Vec<_>>>()?;

        let result: mlua::Value = match lua_args.len() {
            0 => func.call(())?,
            1 => func.call(lua_args.into_iter().next().unwrap())?,
            _ => func.call(mlua::MultiValue::from_iter(lua_args))?,
        };

        let json = lua_value_to_json(&lua, &result)?;
        Ok(json)
    }

    /// Execute a Lua function that matches requests.
    ///
    /// Loads and executes the script (which must define a `match_request`
    /// function), then calls `match_request(req, ctx)` with the provided
    /// request and context JSON values. Returns the boolean result.
    pub fn match_request(
        &self,
        script: &str,
        request: &serde_json::Value,
        context: &serde_json::Value,
    ) -> Result<bool> {
        let lua = Self::fresh_lua()?;

        lua.load(script).exec()?;

        let func: mlua::Function = lua.globals().get("match_request")?;

        let req_lua = json_to_lua_value(&lua, request)?;
        let ctx_lua = json_to_lua_value(&lua, context)?;

        let result: bool = func.call((req_lua, ctx_lua))?;
        Ok(result)
    }

    /// Execute a WAF Lua custom rule.
    ///
    /// Loads and executes the script (which must define a `match` function),
    /// then calls `match(request)` where `request` is a table with a `header()`
    /// method that looks up HTTP headers:
    /// ```lua
    /// function match(request)
    ///   local ua = request:header("User-Agent") or ""
    ///   if string.find(ua, "malicious%-bot") then return true end
    ///   return false
    /// end
    /// ```
    pub fn waf_match(
        &self,
        script: &str,
        uri: &str,
        headers: &std::collections::HashMap<String, String>,
        body: Option<&str>,
    ) -> Result<bool> {
        let lua = Self::fresh_lua()?;

        let req_table = lua.create_table()?;
        req_table.set("uri", uri)?;

        let headers_table = lua.create_table()?;
        for (k, v) in headers {
            headers_table.set(k.to_lowercase().as_str(), v.as_str())?;
        }
        req_table.set("headers", headers_table)?;

        if let Some(b) = body {
            req_table.set("body", b)?;
        }

        let header_fn = lua.create_function(|_, (tbl, name): (mlua::Table, String)| {
            let hdrs: mlua::Table = tbl.get("headers")?;
            let val: mlua::Value = hdrs.get(name.to_lowercase().as_str())?;
            Ok(val)
        })?;
        req_table.set("header", header_fn)?;

        lua.load(script).exec()?;

        let func: mlua::Function = lua.globals().get("match")?;
        let result: bool = func.call(req_table)?;
        Ok(result)
    }
}

// --- JSON <-> Lua Conversion ---

/// Convert a `serde_json::Value` to a `mlua::Value`.
///
/// Maps JSON types to their Lua equivalents:
/// - null -> nil
/// - bool -> boolean
/// - number -> integer or float
/// - string -> string
/// - array -> table with integer keys (1-indexed)
/// - object -> table with string keys
fn json_to_lua_value(lua: &Lua, json: &serde_json::Value) -> mlua::Result<mlua::Value> {
    match json {
        serde_json::Value::Null => Ok(mlua::Value::Nil),
        serde_json::Value::Bool(b) => Ok(mlua::Value::Boolean(*b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(mlua::Value::Integer(i))
            } else if let Some(f) = n.as_f64() {
                Ok(mlua::Value::Number(f))
            } else {
                Ok(mlua::Value::Nil)
            }
        }
        serde_json::Value::String(s) => Ok(mlua::Value::String(lua.create_string(s)?)),
        serde_json::Value::Array(arr) => {
            let table = lua.create_table()?;
            for (i, v) in arr.iter().enumerate() {
                table.set(i + 1, json_to_lua_value(lua, v)?)?;
            }
            Ok(mlua::Value::Table(table))
        }
        serde_json::Value::Object(obj) => {
            let table = lua.create_table()?;
            for (k, v) in obj {
                table.set(k.as_str(), json_to_lua_value(lua, v)?)?;
            }
            Ok(mlua::Value::Table(table))
        }
    }
}

/// Convert a `mlua::Value` back to `serde_json::Value`.
///
/// Uses a heuristic for tables: if the table has sequential integer keys
/// starting from 1, it is treated as an array. Otherwise it is treated
/// as an object with string keys.
#[allow(clippy::only_used_in_recursion)]
fn lua_value_to_json(lua: &Lua, value: &mlua::Value) -> mlua::Result<serde_json::Value> {
    match value {
        mlua::Value::Nil => Ok(serde_json::Value::Null),
        mlua::Value::Boolean(b) => Ok(serde_json::Value::Bool(*b)),
        mlua::Value::Integer(i) => Ok(serde_json::json!(*i)),
        mlua::Value::Number(f) => Ok(serde_json::json!(*f)),
        mlua::Value::String(s) => Ok(serde_json::Value::String(s.to_str()?.to_string())),
        mlua::Value::Table(t) => {
            // Check if it looks like an array (sequential integer keys starting from 1)
            let len = t.raw_len();
            if len > 0 {
                // Verify it is actually a sequence by checking key 1 exists
                let first: mlua::Value = t.raw_get(1)?;
                if first != mlua::Value::Nil {
                    let mut arr = Vec::new();
                    for i in 1..=len {
                        let val: mlua::Value = t.get(i)?;
                        arr.push(lua_value_to_json(lua, &val)?);
                    }
                    return Ok(serde_json::Value::Array(arr));
                }
            }
            // Treat as object
            let mut map = serde_json::Map::new();
            for pair in t.pairs::<String, mlua::Value>() {
                let (key, val) = pair?;
                map.insert(key, lua_value_to_json(lua, &val)?);
            }
            Ok(serde_json::Value::Object(map))
        }
        _ => Ok(serde_json::Value::Null),
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    // --- Basic Execution ---

    #[test]
    fn test_execute_returns_number() {
        let engine = LuaEngine::new().unwrap();
        let result = engine.execute("return 42", HashMap::new()).unwrap();
        assert_eq!(result, serde_json::json!(42));
    }

    #[test]
    fn test_execute_returns_string() {
        let engine = LuaEngine::new().unwrap();
        let result = engine
            .execute("return \"hello world\"", HashMap::new())
            .unwrap();
        assert_eq!(result, serde_json::json!("hello world"));
    }

    #[test]
    fn test_execute_returns_boolean() {
        let engine = LuaEngine::new().unwrap();
        let result = engine.execute("return true", HashMap::new()).unwrap();
        assert_eq!(result, serde_json::json!(true));
    }

    #[test]
    fn test_execute_returns_nil() {
        let engine = LuaEngine::new().unwrap();
        let result = engine.execute("return nil", HashMap::new()).unwrap();
        assert_eq!(result, serde_json::Value::Null);
    }

    #[test]
    fn test_execute_returns_table_as_object() {
        let engine = LuaEngine::new().unwrap();
        let result = engine
            .execute(r#"return {name = "alice", age = 30}"#, HashMap::new())
            .unwrap();
        assert_eq!(result["name"], "alice");
        assert_eq!(result["age"], 30);
    }

    #[test]
    fn test_execute_returns_table_as_array() {
        let engine = LuaEngine::new().unwrap();
        let result = engine
            .execute("return {10, 20, 30}", HashMap::new())
            .unwrap();
        assert_eq!(result, serde_json::json!([10, 20, 30]));
    }

    // --- Globals ---

    #[test]
    fn test_execute_with_globals() {
        let engine = LuaEngine::new().unwrap();
        let mut globals = HashMap::new();
        globals.insert("x".to_string(), serde_json::json!(10));
        globals.insert("y".to_string(), serde_json::json!(20));
        let result = engine.execute("return x + y", globals).unwrap();
        assert_eq!(result, serde_json::json!(30));
    }

    #[test]
    fn test_execute_with_string_global() {
        let engine = LuaEngine::new().unwrap();
        let mut globals = HashMap::new();
        globals.insert("name".to_string(), serde_json::json!("world"));
        let result = engine
            .execute(r#"return "hello " .. name"#, globals)
            .unwrap();
        assert_eq!(result, serde_json::json!("hello world"));
    }

    #[test]
    fn test_execute_with_table_global() {
        let engine = LuaEngine::new().unwrap();
        let mut globals = HashMap::new();
        globals.insert(
            "req".to_string(),
            serde_json::json!({"method": "GET", "path": "/api"}),
        );
        let result = engine.execute("return req.method", globals).unwrap();
        assert_eq!(result, serde_json::json!("GET"));
    }

    // --- JSON Helpers ---

    #[test]
    fn test_json_encode() {
        let engine = LuaEngine::new().unwrap();
        let result = engine
            .execute(
                r#"return json_encode({name = "test", value = 42})"#,
                HashMap::new(),
            )
            .unwrap();
        let s = result.as_str().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(s).unwrap();
        assert_eq!(parsed["name"], "test");
        assert_eq!(parsed["value"], 42);
    }

    #[test]
    fn test_json_decode() {
        let engine = LuaEngine::new().unwrap();
        let mut globals = HashMap::new();
        globals.insert(
            "input".to_string(),
            serde_json::json!(r#"{"status":"ok","code":200}"#),
        );
        let result = engine
            .execute("local t = json_decode(input)\nreturn t.status", globals)
            .unwrap();
        assert_eq!(result, serde_json::json!("ok"));
    }

    #[test]
    fn test_json_roundtrip() {
        let engine = LuaEngine::new().unwrap();
        let result = engine
            .execute(
                r#"
                local original = {items = {1, 2, 3}, active = true}
                local encoded = json_encode(original)
                local decoded = json_decode(encoded)
                return decoded.active
                "#,
                HashMap::new(),
            )
            .unwrap();
        assert_eq!(result, serde_json::json!(true));
    }

    // --- match_request ---

    #[test]
    fn test_match_request_returns_true() {
        let engine = LuaEngine::new().unwrap();
        let script = r#"
            function match_request(req, ctx)
                return req.method == "POST" and string.find(req.path, "/api") ~= nil
            end
        "#;
        let request = serde_json::json!({"method": "POST", "path": "/api/v1/users"});
        let context = serde_json::json!({});
        let result = engine.match_request(script, &request, &context).unwrap();
        assert!(result);
    }

    #[test]
    fn test_match_request_returns_false() {
        let engine = LuaEngine::new().unwrap();
        let script = r#"
            function match_request(req, ctx)
                return req.method == "DELETE"
            end
        "#;
        let request = serde_json::json!({"method": "GET", "path": "/"});
        let context = serde_json::json!({});
        let result = engine.match_request(script, &request, &context).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_match_request_with_context() {
        let engine = LuaEngine::new().unwrap();
        let script = r#"
            function match_request(req, ctx)
                return ctx.is_admin == true
            end
        "#;
        let request = serde_json::json!({"method": "GET", "path": "/admin"});
        let context = serde_json::json!({"is_admin": true});
        let result = engine.match_request(script, &request, &context).unwrap();
        assert!(result);
    }

    #[test]
    fn test_match_request_header_check() {
        let engine = LuaEngine::new().unwrap();
        let script = r#"
            function match_request(req, ctx)
                if req.headers == nil then return false end
                return req.headers["x-api-key"] ~= nil
            end
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

    // --- Sandbox ---

    #[test]
    fn test_sandbox_os_is_nil() {
        let engine = LuaEngine::new().unwrap();
        let result = engine.execute("return os == nil", HashMap::new()).unwrap();
        assert_eq!(result, serde_json::json!(true));
    }

    #[test]
    fn test_sandbox_io_is_nil() {
        let engine = LuaEngine::new().unwrap();
        let result = engine.execute("return io == nil", HashMap::new()).unwrap();
        assert_eq!(result, serde_json::json!(true));
    }

    #[test]
    fn test_sandbox_require_is_nil() {
        let engine = LuaEngine::new().unwrap();
        let result = engine
            .execute("return require == nil", HashMap::new())
            .unwrap();
        assert_eq!(result, serde_json::json!(true));
    }

    #[test]
    fn test_sandbox_loadfile_is_nil() {
        let engine = LuaEngine::new().unwrap();
        let result = engine
            .execute("return loadfile == nil", HashMap::new())
            .unwrap();
        assert_eq!(result, serde_json::json!(true));
    }

    #[test]
    fn test_sandbox_dofile_is_nil() {
        let engine = LuaEngine::new().unwrap();
        let result = engine
            .execute("return dofile == nil", HashMap::new())
            .unwrap();
        assert_eq!(result, serde_json::json!(true));
    }

    #[test]
    fn test_sandbox_rawset_is_nil() {
        let engine = LuaEngine::new().unwrap();
        let result = engine
            .execute("return rawset == nil", HashMap::new())
            .unwrap();
        assert_eq!(result, serde_json::json!(true));
    }

    #[test]
    fn test_sandbox_load_is_nil() {
        let engine = LuaEngine::new().unwrap();
        let result = engine
            .execute("return load == nil", HashMap::new())
            .unwrap();
        assert_eq!(result, serde_json::json!(true));
    }

    #[test]
    fn test_sandbox_loadstring_is_nil() {
        let engine = LuaEngine::new().unwrap();
        let result = engine
            .execute("return loadstring == nil", HashMap::new())
            .unwrap();
        assert_eq!(result, serde_json::json!(true));
    }

    #[test]
    fn test_sandbox_debug_is_nil() {
        let engine = LuaEngine::new().unwrap();
        let result = engine
            .execute("return debug == nil", HashMap::new())
            .unwrap();
        assert_eq!(result, serde_json::json!(true));
    }

    #[test]
    fn test_sandbox_package_is_nil() {
        let engine = LuaEngine::new().unwrap();
        let result = engine
            .execute("return package == nil", HashMap::new())
            .unwrap();
        assert_eq!(result, serde_json::json!(true));
    }

    #[test]
    fn test_sandbox_load_eval_escape_blocked() {
        let engine = LuaEngine::new().unwrap();
        // C4 regression: an attacker-controlled script must not be able
        // to use `load` to construct and execute Lua at runtime. The
        // exact attack from the OPENSOURCE.md finding.
        let result = engine.execute(r#"return load("os.execute('echo hi')")()"#, HashMap::new());
        assert!(
            result.is_err(),
            "load() must be unavailable in the sandbox, got Ok: {:?}",
            result.ok()
        );
    }

    #[test]
    fn test_state_isolation_globals_do_not_leak() {
        let engine = LuaEngine::new().unwrap();

        let set_result = engine
            .execute("auth_token = 'super-secret'; return true", HashMap::new())
            .unwrap();
        assert_eq!(set_result, serde_json::json!(true));

        let leaked = engine
            .execute("return auth_token == nil", HashMap::new())
            .unwrap();
        assert_eq!(
            leaked,
            serde_json::json!(true),
            "globals from a prior execute() call leaked into a later call"
        );
    }

    #[test]
    fn test_state_isolation_call_function_globals_do_not_leak() {
        let engine = LuaEngine::new().unwrap();

        let _ = engine
            .call_function(
                r#"
                function script_a(req, ctx)
                    secret_token = req.headers.auth
                    return { ok = true }
                end
                "#,
                "script_a",
                vec![
                    serde_json::json!({"headers": {"auth": "leaked-value"}}),
                    serde_json::json!({}),
                ],
            )
            .unwrap();

        let result = engine
            .call_function(
                r#"
                function script_b(req, ctx)
                    return { token_visible = secret_token ~= nil }
                end
                "#,
                "script_b",
                vec![serde_json::json!({}), serde_json::json!({})],
            )
            .unwrap();

        assert_eq!(
            result.get("token_visible").and_then(|v| v.as_bool()),
            Some(false),
            "globals from script_a leaked into script_b: {result:?}"
        );
    }

    #[test]
    fn test_sandbox_safe_functions_available() {
        let engine = LuaEngine::new().unwrap();
        // string, math, table should still be available
        let result = engine
            .execute("return type(string) == \"table\"", HashMap::new())
            .unwrap();
        assert_eq!(result, serde_json::json!(true));

        let result = engine
            .execute("return type(math) == \"table\"", HashMap::new())
            .unwrap();
        assert_eq!(result, serde_json::json!(true));
    }

    // --- Error Handling ---

    #[test]
    fn test_syntax_error() {
        let engine = LuaEngine::new().unwrap();
        let result = engine.execute("this is not valid lua !!!", HashMap::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_runtime_error() {
        let engine = LuaEngine::new().unwrap();
        let result = engine.execute("error('something went wrong')", HashMap::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_match_request_missing_function() {
        let engine = LuaEngine::new().unwrap();
        let script = "-- no match_request defined";
        let request = serde_json::json!({"method": "GET"});
        let context = serde_json::json!({});
        let result = engine.match_request(script, &request, &context);
        assert!(result.is_err());
    }

    #[test]
    fn test_json_decode_invalid_input() {
        let engine = LuaEngine::new().unwrap();
        let mut globals = HashMap::new();
        globals.insert("bad".to_string(), serde_json::json!("not json {{{"));
        let result = engine.execute("return json_decode(bad)", globals);
        assert!(result.is_err());
    }

    // --- JSON Conversion Edge Cases ---

    #[test]
    fn test_nested_tables() {
        let engine = LuaEngine::new().unwrap();
        let result = engine
            .execute(
                r#"return {user = {name = "bob", roles = {"admin", "user"}}}"#,
                HashMap::new(),
            )
            .unwrap();
        assert_eq!(result["user"]["name"], "bob");
        assert_eq!(result["user"]["roles"][0], "admin");
        assert_eq!(result["user"]["roles"][1], "user");
    }

    #[test]
    fn test_float_values() {
        let engine = LuaEngine::new().unwrap();
        let result = engine.execute("return 2.5", HashMap::new()).unwrap();
        let f = result.as_f64().unwrap();
        assert!((f - 2.5).abs() < 0.001);
    }

    #[test]
    fn test_empty_table_is_object() {
        let engine = LuaEngine::new().unwrap();
        let result = engine.execute("return {}", HashMap::new()).unwrap();
        // Empty table should be treated as an object (no integer keys)
        assert!(result.is_object());
    }

    // --- Lua request modifier pattern (modify_request) ---

    #[test]
    fn test_call_modify_request_returns_set_headers() {
        let engine = LuaEngine::new().unwrap();
        let script = r#"
            function modify_request(req, ctx)
              local result = {}
              result.set_headers = {}
              result.set_headers["X-Lua-Modified"] = "true"
              result.set_headers["X-Lua-Method"] = req.method
              result.set_headers["X-Lua-Path"] = req.path
              return result
            end
        "#;
        let req_table = serde_json::json!({
            "method": "GET",
            "path": "/api/v1/users",
            "headers": {"x-role": "admin"},
            "host": "lua-reqmod.test",
        });
        let ctx_table = serde_json::json!({});

        let result = engine
            .call_function(script, "modify_request", vec![req_table, ctx_table])
            .unwrap();

        let set_headers = result.get("set_headers").unwrap().as_object().unwrap();
        assert_eq!(
            set_headers.get("X-Lua-Modified").unwrap().as_str().unwrap(),
            "true"
        );
        assert_eq!(
            set_headers.get("X-Lua-Method").unwrap().as_str().unwrap(),
            "GET"
        );
        assert_eq!(
            set_headers.get("X-Lua-Path").unwrap().as_str().unwrap(),
            "/api/v1/users"
        );
    }

    #[test]
    fn test_call_modify_request_conditional_header() {
        let engine = LuaEngine::new().unwrap();
        let script = r#"
            function modify_request(req, ctx)
              local result = {}
              result.set_headers = {}
              local role = req.headers["x-role"] or ""
              if role == "admin" then
                result.set_headers["X-Lua-Is-Admin"] = "true"
              else
                result.set_headers["X-Lua-Is-Admin"] = "false"
              end
              return result
            end
        "#;

        // With admin role
        let req = serde_json::json!({
            "method": "GET", "path": "/", "headers": {"x-role": "admin"}, "host": "test"
        });
        let result = engine
            .call_function(script, "modify_request", vec![req, serde_json::json!({})])
            .unwrap();
        let headers = result.get("set_headers").unwrap().as_object().unwrap();
        assert_eq!(
            headers.get("X-Lua-Is-Admin").unwrap().as_str().unwrap(),
            "true"
        );
    }

    #[test]
    fn test_call_modify_request_compact_syntax() {
        let engine = LuaEngine::new().unwrap();
        let script = r#"
            function modify_request(req, ctx)
              return {
                set_headers = {
                  ["X-Lua-Stage"] = "request",
                  ["X-Lua-Original-Path"] = req.path
                }
              }
            end
        "#;
        let req = serde_json::json!({
            "method": "POST", "path": "/submit", "headers": {}, "host": "test"
        });
        let result = engine
            .call_function(script, "modify_request", vec![req, serde_json::json!({})])
            .unwrap();

        let set_headers = result.get("set_headers").unwrap().as_object().unwrap();
        assert_eq!(
            set_headers.get("X-Lua-Stage").unwrap().as_str().unwrap(),
            "request"
        );
        assert_eq!(
            set_headers
                .get("X-Lua-Original-Path")
                .unwrap()
                .as_str()
                .unwrap(),
            "/submit"
        );
    }

    #[test]
    fn test_call_modify_response_returns_set_headers() {
        let engine = LuaEngine::new().unwrap();
        let script = r#"
            function modify_response(resp, ctx)
              return {
                set_headers = {
                  ["X-Lua-Stage"] = "response",
                  ["X-Lua-Processed"] = "true"
                }
              }
            end
        "#;
        let resp = serde_json::json!({"status_code": 200});
        let result = engine
            .call_function(script, "modify_response", vec![resp, serde_json::json!({})])
            .unwrap();

        let set_headers = result.get("set_headers").unwrap().as_object().unwrap();
        assert_eq!(
            set_headers.get("X-Lua-Stage").unwrap().as_str().unwrap(),
            "response"
        );
        assert_eq!(
            set_headers
                .get("X-Lua-Processed")
                .unwrap()
                .as_str()
                .unwrap(),
            "true"
        );
    }
}

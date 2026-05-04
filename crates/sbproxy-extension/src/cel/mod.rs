//! CEL (Common Expression Language) engine for sbproxy.
//!
//! Provides compilation and evaluation of CEL expressions against HTTP request
//! contexts. Used for conditional routing, access control, header matching,
//! and other policy decisions.

pub mod context;
pub mod functions;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use cel::objects::Key;

// --- Re-exports ---

pub use cel::Value as CelRawValue;
pub use functions::{set_tls_fingerprint_matcher, TlsFingerprintMatcher};

// --- Types ---

/// A compiled CEL expression ready for evaluation.
pub struct CelExpression {
    source: String,
    program: cel::Program,
}

impl CelExpression {
    /// Returns the original source string of this expression.
    pub fn source(&self) -> &str {
        &self.source
    }
}

/// CEL evaluation context built from request data.
pub struct CelContext {
    /// Variables exposed to the expression keyed by identifier.
    pub variables: HashMap<String, CelValue>,
}

impl CelContext {
    /// Create an empty context.
    pub fn new() -> Self {
        Self {
            variables: HashMap::new(),
        }
    }

    /// Insert a variable into the context.
    pub fn set(&mut self, name: impl Into<String>, value: CelValue) {
        self.variables.insert(name.into(), value);
    }
}

impl Default for CelContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Values that can be used in CEL expressions.
#[derive(Debug, Clone)]
pub enum CelValue {
    /// UTF-8 string value.
    String(String),
    /// 64-bit signed integer.
    Int(i64),
    /// 64-bit floating point value.
    Float(f64),
    /// Boolean value.
    Bool(bool),
    /// Map keyed by string with CEL value entries.
    Map(HashMap<String, CelValue>),
    /// Ordered list of CEL values.
    List(Vec<CelValue>),
    /// Null / absent value.
    Null,
}

impl CelValue {
    /// Convert this value into the cel crate's native Value type.
    fn into_cel_value(self) -> cel::Value {
        match self {
            CelValue::String(s) => cel::Value::String(Arc::new(s)),
            CelValue::Int(i) => cel::Value::Int(i),
            CelValue::Float(f) => cel::Value::Float(f),
            CelValue::Bool(b) => cel::Value::Bool(b),
            CelValue::Null => cel::Value::Null,
            CelValue::List(items) => {
                let values: Vec<cel::Value> =
                    items.into_iter().map(|v| v.into_cel_value()).collect();
                cel::Value::List(Arc::new(values))
            }
            CelValue::Map(map) => {
                let mut cel_map = HashMap::new();
                for (k, v) in map {
                    cel_map.insert(Key::from(k), v.into_cel_value());
                }
                cel::Value::Map(cel::objects::Map {
                    map: Arc::new(cel_map),
                })
            }
        }
    }
}

/// Convert a cel crate Value back into our CelValue.
fn from_cel_value(value: &cel::Value) -> CelValue {
    match value {
        cel::Value::String(s) => CelValue::String(s.as_str().to_string()),
        cel::Value::Int(i) => CelValue::Int(*i),
        cel::Value::UInt(u) => CelValue::Int(*u as i64),
        cel::Value::Float(f) => CelValue::Float(*f),
        cel::Value::Bool(b) => CelValue::Bool(*b),
        cel::Value::Null => CelValue::Null,
        cel::Value::List(items) => CelValue::List(items.iter().map(from_cel_value).collect()),
        cel::Value::Map(m) => {
            let mut map = HashMap::new();
            for (k, v) in m.map.iter() {
                map.insert(k.to_string(), from_cel_value(v));
            }
            CelValue::Map(map)
        }
        // Bytes, Duration, Timestamp, Function, Opaque all map to Null for now
        _ => CelValue::Null,
    }
}

// --- CelEngine ---

/// The CEL engine compiles and evaluates expressions.
///
/// Custom sbproxy functions (ip_in_cidr, sha256, base64_encode, etc.) are
/// registered on every evaluation context automatically.
pub struct CelEngine {
    _private: (),
}

impl CelEngine {
    /// Create a new CEL engine.
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Compile a CEL expression from a source string.
    pub fn compile(&self, source: &str) -> Result<CelExpression> {
        let program =
            cel::Program::compile(source).map_err(|e| anyhow::anyhow!("CEL parse error: {}", e))?;
        Ok(CelExpression {
            source: source.to_string(),
            program,
        })
    }

    /// Build a cel::Context with variables and custom functions.
    fn build_cel_context<'a>(&self, ctx: &CelContext) -> cel::Context<'a> {
        let mut cel_ctx = cel::Context::default();

        // Add all user variables
        for (name, value) in &ctx.variables {
            cel_ctx.add_variable_from_value(name.clone(), value.clone().into_cel_value());
        }

        // Register custom functions
        functions::register_all(&mut cel_ctx);

        cel_ctx
    }

    /// Evaluate a CEL expression as a boolean.
    ///
    /// Returns an error if the expression does not evaluate to a boolean or
    /// if evaluation fails.
    pub fn eval_bool(&self, expr: &CelExpression, ctx: &CelContext) -> Result<bool> {
        let cel_ctx = self.build_cel_context(ctx);
        let result = expr
            .program
            .execute(&cel_ctx)
            .map_err(|e| anyhow::anyhow!("CEL execution error: {}", e))?;

        match result {
            cel::Value::Bool(b) => Ok(b),
            other => Err(anyhow::anyhow!(
                "CEL expression did not return bool, got: {:?}",
                other
            )),
        }
    }

    /// Evaluate a CEL expression and return the result as a CelValue.
    pub fn eval(&self, expr: &CelExpression, ctx: &CelContext) -> Result<CelValue> {
        let cel_ctx = self.build_cel_context(ctx);
        let result = expr
            .program
            .execute(&cel_ctx)
            .map_err(|e| anyhow::anyhow!("CEL execution error: {}", e))?;

        Ok(from_cel_value(&result))
    }

    /// Compile and evaluate a CEL expression in one step. Convenience method
    /// for one-off evaluations where caching the compiled expression is not needed.
    pub fn eval_source(&self, source: &str, ctx: &CelContext) -> Result<CelValue> {
        let expr = self.compile(source)?;
        self.eval(&expr, ctx)
    }

    /// Compile and evaluate a CEL expression as a boolean in one step.
    pub fn eval_bool_source(&self, source: &str, ctx: &CelContext) -> Result<bool> {
        let expr = self.compile(source)?;
        self.eval_bool(&expr, ctx)
    }
}

impl Default for CelEngine {
    fn default() -> Self {
        Self::new()
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_valid_expression() {
        let engine = CelEngine::new();
        let expr = engine.compile("1 + 1 == 2");
        assert!(expr.is_ok());
    }

    #[test]
    fn test_compile_invalid_expression() {
        let engine = CelEngine::new();
        let expr = engine.compile("1 +");
        assert!(expr.is_err());
    }

    #[test]
    fn test_eval_bool_true() {
        let engine = CelEngine::new();
        let expr = engine.compile("1 + 1 == 2").unwrap();
        let ctx = CelContext::new();
        assert!(engine.eval_bool(&expr, &ctx).unwrap());
    }

    #[test]
    fn test_eval_bool_false() {
        let engine = CelEngine::new();
        let expr = engine.compile("1 + 1 == 3").unwrap();
        let ctx = CelContext::new();
        assert!(!engine.eval_bool(&expr, &ctx).unwrap());
    }

    #[test]
    fn test_eval_bool_not_bool() {
        let engine = CelEngine::new();
        let expr = engine.compile("1 + 1").unwrap();
        let ctx = CelContext::new();
        assert!(engine.eval_bool(&expr, &ctx).is_err());
    }

    #[test]
    fn test_eval_with_variables() {
        let engine = CelEngine::new();
        let expr = engine.compile("x + y == 10").unwrap();
        let mut ctx = CelContext::new();
        ctx.set("x", CelValue::Int(3));
        ctx.set("y", CelValue::Int(7));
        assert!(engine.eval_bool(&expr, &ctx).unwrap());
    }

    #[test]
    fn test_eval_string_comparison() {
        let engine = CelEngine::new();
        let expr = engine.compile(r#"name == "alice""#).unwrap();
        let mut ctx = CelContext::new();
        ctx.set("name", CelValue::String("alice".to_string()));
        assert!(engine.eval_bool(&expr, &ctx).unwrap());
    }

    #[test]
    fn test_eval_map_access() {
        let engine = CelEngine::new();
        let expr = engine.compile(r#"request.method == "GET""#).unwrap();
        let mut request = HashMap::new();
        request.insert("method".to_string(), CelValue::String("GET".to_string()));
        let mut ctx = CelContext::new();
        ctx.set("request", CelValue::Map(request));
        assert!(engine.eval_bool(&expr, &ctx).unwrap());
    }

    #[test]
    fn test_eval_nested_map() {
        let engine = CelEngine::new();
        let expr = engine
            .compile(r#"request.headers.host == "example.com""#)
            .unwrap();
        let mut headers = HashMap::new();
        headers.insert(
            "host".to_string(),
            CelValue::String("example.com".to_string()),
        );
        let mut request = HashMap::new();
        request.insert("headers".to_string(), CelValue::Map(headers));
        let mut ctx = CelContext::new();
        ctx.set("request", CelValue::Map(request));
        assert!(engine.eval_bool(&expr, &ctx).unwrap());
    }

    #[test]
    fn test_eval_boolean_operators() {
        let engine = CelEngine::new();
        let expr = engine.compile("true && !false").unwrap();
        let ctx = CelContext::new();
        assert!(engine.eval_bool(&expr, &ctx).unwrap());
    }

    #[test]
    fn test_eval_or_operator() {
        let engine = CelEngine::new();
        let expr = engine.compile("false || true").unwrap();
        let ctx = CelContext::new();
        assert!(engine.eval_bool(&expr, &ctx).unwrap());
    }

    #[test]
    fn test_eval_string_contains() {
        let engine = CelEngine::new();
        let expr = engine.compile(r#"path.contains("/api/")"#).unwrap();
        let mut ctx = CelContext::new();
        ctx.set("path", CelValue::String("/api/v1/users".to_string()));
        assert!(engine.eval_bool(&expr, &ctx).unwrap());
    }

    #[test]
    fn test_eval_string_starts_with() {
        let engine = CelEngine::new();
        let expr = engine.compile(r#"path.startsWith("/admin")"#).unwrap();
        let mut ctx = CelContext::new();
        ctx.set("path", CelValue::String("/admin/settings".to_string()));
        assert!(engine.eval_bool(&expr, &ctx).unwrap());
    }

    #[test]
    fn test_eval_list_operations() {
        let engine = CelEngine::new();
        let expr = engine.compile("size(items) == 3").unwrap();
        let mut ctx = CelContext::new();
        ctx.set(
            "items",
            CelValue::List(vec![CelValue::Int(1), CelValue::Int(2), CelValue::Int(3)]),
        );
        assert!(engine.eval_bool(&expr, &ctx).unwrap());
    }

    #[test]
    fn test_eval_generic_value() {
        let engine = CelEngine::new();
        let expr = engine.compile("1 + 2").unwrap();
        let ctx = CelContext::new();
        let result = engine.eval(&expr, &ctx).unwrap();
        match result {
            CelValue::Int(n) => assert_eq!(n, 3),
            other => panic!("Expected Int(3), got {:?}", other),
        }
    }

    #[test]
    fn test_eval_source_convenience() {
        let engine = CelEngine::new();
        let ctx = CelContext::new();
        let result = engine.eval_bool_source("2 * 3 == 6", &ctx).unwrap();
        assert!(result);
    }

    #[test]
    fn test_expression_source() {
        let engine = CelEngine::new();
        let expr = engine.compile("1 + 1").unwrap();
        assert_eq!(expr.source(), "1 + 1");
    }
}

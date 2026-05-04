//! Transform module - enum dispatch for built-in transform handlers.
//!
//! Provides JSON manipulation transforms (set/remove/rename fields,
//! field projection, schema validation), text transforms (template
//! rendering, string replacement, normalization, encoding, format
//! conversion), control transforms (payload limits, discard, SSE
//! chunking), and a pipeline wrapper that controls content-type
//! matching and error behavior.

mod boilerplate;
mod cel_script;
mod citation_block;
mod control;
mod json;
mod json_envelope;
mod markup;
mod text;

pub use boilerplate::{BoilerplateConfig, BoilerplateTransform};
pub use cel_script::{
    CelHeaderMutation, CelHeaderOp, CelHeaderRule, CelScriptTransform, HEADER_DENY_LIST,
    HEADER_EVAL_BUDGET,
};
pub use citation_block::{CitationBlockConfig, CitationBlockTransform};
pub use control::{DiscardTransform, PayloadLimitTransform, SseChunkingTransform};
pub use json::{JsonProjectionTransform, JsonSchemaTransform, JsonTransform};
pub use json_envelope::{
    JsonEnvelope, JsonEnvelopeTransform, JSON_ENVELOPE_CONTENT_TYPE, JSON_ENVELOPE_PROFILE,
    JSON_ENVELOPE_SCHEMA_VERSION,
};
pub use markup::{
    CssTransform, HtmlToMarkdownTransform, HtmlTransform, MarkdownProjection, MarkdownTransform,
    OptimizeHtmlTransform, DEFAULT_TOKEN_BYTES_RATIO,
};
pub use text::{
    EncodingTransform, FormatConvertTransform, NormalizeTransform, ReplaceStringsTransform,
    TemplateTransform,
};

use bytes::{BufMut, BytesMut};
use sbproxy_plugin::{TransformContext, TransformHandler};
use serde::Deserialize;

// --- Transform Enum ---

/// Transform handler - enum dispatch for built-in types.
/// Each variant holds its compiled config inline (no Box indirection).
pub enum Transform {
    /// Modify JSON by setting, removing, or renaming fields.
    Json(JsonTransform),
    /// Extract or exclude specific fields from JSON.
    JsonProjection(JsonProjectionTransform),
    /// Validate JSON against a schema.
    JsonSchema(JsonSchemaTransform),
    /// Render a template using response body as input data.
    Template(TemplateTransform),
    /// Find-and-replace strings (literal or regex) in the body.
    ReplaceStrings(ReplaceStringsTransform),
    /// Normalize whitespace, newlines, and trim the body.
    Normalize(NormalizeTransform),
    /// Base64 or URL encode/decode the body.
    Encoding(EncodingTransform),
    /// Convert between JSON and YAML formats.
    FormatConvert(FormatConvertTransform),
    /// Enforce a maximum body size (truncate or reject).
    PayloadLimit(PayloadLimitTransform),
    /// Discard the entire response body.
    Discard(DiscardTransform),
    /// Format the body as SSE events with proper chunking.
    SseChunking(SseChunkingTransform),
    /// Manipulate HTML content (inject, remove, rewrite attributes).
    Html(HtmlTransform),
    /// Minify HTML by removing comments and collapsing whitespace.
    OptimizeHtml(OptimizeHtmlTransform),
    /// Convert HTML to Markdown.
    HtmlToMarkdown(HtmlToMarkdownTransform),
    /// Convert Markdown to HTML.
    Markdown(MarkdownTransform),
    /// Manipulate CSS (inject rules, remove selectors, minify).
    Css(CssTransform),
    /// Lua-based JSON transform. Executes a Lua script that receives the
    /// JSON body and returns a modified version.
    LuaJson(LuaJsonTransform),
    /// JavaScript-based body transform. Calls a user-defined JS function
    /// with the raw body string, returning the modified string.
    JavaScript(JavaScriptTransform),
    /// JavaScript-based JSON transform. Calls a user-defined JS function
    /// with the parsed JSON body, returning the modified JSON value.
    JsJson(JsJsonTransform),
    /// WebAssembly-based body transform. Pipes the body through a sandboxed
    /// WASI module's stdin/stdout, returning whatever the module writes back.
    Wasm(WasmTransform),
    /// G4.10 boilerplate strip (Wave 4). Removes nav/footer/aside/ad
    /// chrome from HTML before the Markdown projection runs. Runs in
    /// the standard body-buffer pipeline; does not require per-request
    /// context.
    Boilerplate(BoilerplateTransform),
    /// G4.10 citation block (Wave 4). Prepends an attribution
    /// blockquote to a Markdown projection. The standard body-buffer
    /// `apply` is a no-op because the transform needs per-request
    /// `RequestContext` fields (`canonical_url`, `rsl_urn`,
    /// `citation_required`) that the simple `(body, content_type)`
    /// signature can't carry. The day-5 response-filter wiring calls
    /// the typed `CitationBlockTransform::apply` with the ctx fields.
    CitationBlock(CitationBlockTransform),
    /// G4.4 JSON envelope (Wave 4). Wraps a Markdown projection in
    /// the v1 JSON envelope. Same caveat as `CitationBlock`: the
    /// standard body-buffer `apply` is a no-op; day-5 response-filter
    /// wiring calls the typed `JsonEnvelopeTransform::apply` with the
    /// ctx fields.
    JsonEnvelope(JsonEnvelopeTransform),
    /// Wave 5 day-5 / Q5.x: CEL response-body transform. Evaluates a
    /// CEL expression against `response.body` / `response.status` /
    /// `response.headers` and replaces the body with the result. Used
    /// by the e2e tests to stamp `request.tls.ja4` /
    /// `request.kya.verdict` back into the response body for
    /// assertions.
    CelScript(CelScriptTransform),
    /// No transformation applied.
    Noop,
    /// Third-party plugin (only case using dynamic dispatch).
    Plugin(Box<dyn TransformHandler>),
}

impl Transform {
    /// Get the type name for this transform.
    pub fn transform_type(&self) -> &str {
        match self {
            Self::Json(_) => "json",
            Self::JsonProjection(_) => "json_projection",
            Self::JsonSchema(_) => "json_schema",
            Self::Template(_) => "template",
            Self::ReplaceStrings(_) => "replace_strings",
            Self::Normalize(_) => "normalize",
            Self::Encoding(_) => "encoding",
            Self::FormatConvert(_) => "format_convert",
            Self::PayloadLimit(_) => "payload_limit",
            Self::Discard(_) => "discard",
            Self::SseChunking(_) => "sse_chunking",
            Self::Html(_) => "html",
            Self::OptimizeHtml(_) => "optimize_html",
            Self::HtmlToMarkdown(_) => "html_to_markdown",
            Self::Markdown(_) => "markdown",
            Self::Css(_) => "css",
            Self::LuaJson(_) => "lua_json",
            Self::JavaScript(_) => "javascript",
            Self::JsJson(_) => "js_json",
            Self::Wasm(_) => "wasm",
            Self::Boilerplate(_) => "boilerplate",
            Self::CitationBlock(_) => "citation_block",
            Self::JsonEnvelope(_) => "json_envelope",
            Self::CelScript(_) => "cel",
            Self::Noop => "noop",
            Self::Plugin(p) => p.transform_type(),
        }
    }

    /// Apply this transform to a body buffer.
    pub fn apply(&self, body: &mut BytesMut, content_type: Option<&str>) -> anyhow::Result<()> {
        match self {
            Self::Json(t) => t.apply(body),
            Self::JsonProjection(t) => t.apply(body),
            Self::JsonSchema(t) => t.apply(body),
            Self::Template(t) => t.apply(body),
            Self::ReplaceStrings(t) => t.apply(body),
            Self::Normalize(t) => t.apply(body),
            Self::Encoding(t) => t.apply(body),
            Self::FormatConvert(t) => t.apply(body),
            Self::PayloadLimit(t) => t.apply(body),
            Self::Discard(t) => t.apply(body),
            Self::SseChunking(t) => t.apply(body),
            Self::Html(t) => t.apply(body),
            Self::OptimizeHtml(t) => t.apply(body),
            Self::HtmlToMarkdown(t) => t.apply(body),
            Self::Markdown(t) => t.apply(body),
            Self::Css(t) => t.apply(body),
            Self::LuaJson(t) => t.apply(body),
            Self::JavaScript(t) => t.apply(body),
            Self::JsJson(t) => t.apply(body),
            Self::Wasm(t) => t.apply(body),
            Self::Boilerplate(t) => {
                // G4.10: byte count goes onto ctx.metrics in the
                // response-filter wiring; the standard pipeline path
                // discards it.
                t.apply(body).map(|_| ())
            }
            // G4.10 / G4.4: these two transforms need per-request
            // context (canonical_url, rsl_urn, citation_required) that
            // the standard body-buffer signature can't carry. The
            // day-5 response-filter wiring invokes the typed `apply`
            // methods directly with the ctx fields. In the meantime
            // they are no-ops here so the YAML schema accepts them
            // and the chain compiles end-to-end.
            Self::CitationBlock(_) | Self::JsonEnvelope(_) => Ok(()),
            Self::CelScript(t) => t.apply(body),
            Self::Noop => Ok(()),
            Self::Plugin(handler) => dispatch_plugin(handler.as_ref(), body, content_type),
        }
    }
}

/// Dispatch a `Transform::Plugin` to the held `TransformHandler`.
///
/// The trait's `apply` is async (it returns `Pin<Box<dyn Future>>`) but the
/// transform pipeline runs from sync response-filter call sites, so we
/// drive the future to completion with `futures::executor::block_on`. The
/// inventory registry is consulted to confirm the handler is registered
/// under its declared `transform_type` name; an unknown name surfaces as
/// an error instead of a silent no-op so misconfigured pipelines fail
/// loudly.
fn dispatch_plugin(
    handler: &dyn TransformHandler,
    body: &mut BytesMut,
    content_type: Option<&str>,
) -> anyhow::Result<()> {
    let plugin_name = handler.transform_type();
    if sbproxy_plugin::get_plugin(sbproxy_plugin::PluginKind::Transform, plugin_name).is_none() {
        anyhow::bail!(
            "transform plugin {:?} is not registered in the inventory registry",
            plugin_name
        );
    }
    let ctx = TransformContext::empty();
    futures::executor::block_on(handler.apply(body, content_type, &ctx))
}

impl std::fmt::Debug for Transform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(t) => f.debug_tuple("Json").field(t).finish(),
            Self::JsonProjection(t) => f.debug_tuple("JsonProjection").field(t).finish(),
            Self::JsonSchema(t) => f.debug_tuple("JsonSchema").field(t).finish(),
            Self::Template(t) => f.debug_tuple("Template").field(t).finish(),
            Self::ReplaceStrings(t) => f.debug_tuple("ReplaceStrings").field(t).finish(),
            Self::Normalize(t) => f.debug_tuple("Normalize").field(t).finish(),
            Self::Encoding(t) => f.debug_tuple("Encoding").field(t).finish(),
            Self::FormatConvert(t) => f.debug_tuple("FormatConvert").field(t).finish(),
            Self::PayloadLimit(t) => f.debug_tuple("PayloadLimit").field(t).finish(),
            Self::Discard(t) => f.debug_tuple("Discard").field(t).finish(),
            Self::SseChunking(t) => f.debug_tuple("SseChunking").field(t).finish(),
            Self::Html(t) => f.debug_tuple("Html").field(t).finish(),
            Self::OptimizeHtml(t) => f.debug_tuple("OptimizeHtml").field(t).finish(),
            Self::HtmlToMarkdown(t) => f.debug_tuple("HtmlToMarkdown").field(t).finish(),
            Self::Markdown(t) => f.debug_tuple("Markdown").field(t).finish(),
            Self::Css(t) => f.debug_tuple("Css").field(t).finish(),
            Self::LuaJson(t) => f.debug_tuple("LuaJson").field(t).finish(),
            Self::JavaScript(t) => f.debug_tuple("JavaScript").field(t).finish(),
            Self::JsJson(t) => f.debug_tuple("JsJson").field(t).finish(),
            Self::Wasm(t) => f.debug_tuple("Wasm").field(t).finish(),
            Self::Boilerplate(t) => f.debug_tuple("Boilerplate").field(t).finish(),
            Self::CitationBlock(t) => f.debug_tuple("CitationBlock").field(t).finish(),
            Self::JsonEnvelope(t) => f.debug_tuple("JsonEnvelope").field(t).finish(),
            Self::CelScript(t) => f.debug_tuple("CelScript").field(t).finish(),
            Self::Noop => write!(f, "Noop"),
            Self::Plugin(_) => write!(f, "Plugin(...)"),
        }
    }
}

// --- TransformConfig (deserialization wrapper) ---

fn default_max_body() -> usize {
    10 * 1024 * 1024
}

/// Wrapper that controls when a transform is applied.
#[derive(Debug, Deserialize)]
pub struct TransformConfig {
    /// The transform type discriminator (e.g. "json", "json_projection").
    #[serde(rename = "type")]
    pub transform_type: String,
    /// Only apply to these content types (empty = all).
    #[serde(default)]
    pub content_types: Vec<String>,
    /// If true, an error in this transform fails the entire response.
    #[serde(default)]
    pub fail_on_error: bool,
    /// Max body size to buffer for this transform (default 10MB).
    #[serde(default = "default_max_body")]
    pub max_body_size: usize,
    /// Whether this transform is disabled.
    #[serde(default)]
    pub disabled: bool,
    /// The remaining fields are passed to the specific transform.
    #[serde(flatten)]
    pub config: serde_json::Value,
}

// --- CompiledTransform (pipeline entry) ---

/// A compiled transform with its pipeline metadata.
#[derive(Debug)]
pub struct CompiledTransform {
    /// The transform variant to apply.
    pub transform: Transform,
    /// Content-Type substrings this transform applies to (empty matches all).
    pub content_types: Vec<String>,
    /// When true, transform errors abort the request instead of being skipped.
    pub fail_on_error: bool,
    /// Maximum body size, in bytes, before the transform is skipped.
    pub max_body_size: usize,
}

impl CompiledTransform {
    /// Check if this transform should apply to the given content type.
    pub fn matches_content_type(&self, content_type: Option<&str>) -> bool {
        if self.content_types.is_empty() {
            return true; // No filter means apply to all.
        }
        match content_type {
            Some(ct) => self
                .content_types
                .iter()
                .any(|allowed| ct.contains(allowed)),
            None => false,
        }
    }

    /// Apply this transform to a body buffer, respecting content-type filters.
    pub fn apply(&self, body: &mut BytesMut, content_type: Option<&str>) -> anyhow::Result<()> {
        if !self.matches_content_type(content_type) {
            return Ok(());
        }
        self.transform.apply(body, content_type)
    }
}

// --- LuaJsonTransform ---

/// Lua-based JSON transform.
///
/// Executes a Lua script that receives the JSON body as a global `body`
/// variable and must return a modified JSON value. The script runs in a
/// sandboxed Lua VM with no filesystem or network access.
#[derive(Debug)]
pub struct LuaJsonTransform {
    /// Lua source code executed against the JSON body.
    pub script: String,
}

impl LuaJsonTransform {
    /// Build a LuaJsonTransform from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        #[derive(Deserialize)]
        struct Config {
            #[serde(alias = "lua_script")]
            script: String,
        }
        let cfg: Config = serde_json::from_value(value)?;
        Ok(Self { script: cfg.script })
    }

    /// Apply the Lua script to the JSON body.
    ///
    /// Supports two script formats:
    /// 1. **Function format** (Go-compatible): script defines `modify_json(data, ctx)`.
    ///    The function receives the parsed JSON body and an empty context table.
    /// 2. **Global format** (legacy): script uses a `body` global variable directly.
    ///
    /// The function format is tried first. If `modify_json` is not defined, the
    /// engine falls back to the global format.
    pub fn apply(&self, body: &mut BytesMut) -> anyhow::Result<()> {
        let json: serde_json::Value = serde_json::from_slice(body)?;
        let engine = sbproxy_extension::lua::LuaEngine::new()?;

        // Try function format first: modify_json(data, ctx)
        let ctx = serde_json::json!({});
        let result =
            match engine.call_function(&self.script, "modify_json", vec![json.clone(), ctx]) {
                Ok(r) => r,
                Err(_) => {
                    // Fall back to global format: body as a global variable
                    let engine = sbproxy_extension::lua::LuaEngine::new()?;
                    let mut globals = std::collections::HashMap::new();
                    globals.insert("body".to_string(), json);
                    engine.execute(&self.script, globals)?
                }
            };

        body.clear();
        serde_json::to_writer(&mut body.writer(), &result)?;
        Ok(())
    }
}

// --- JavaScriptTransform ---

/// JavaScript-based body transform using JsEngine (QuickJS).
///
/// The script must define a function (default name: `transform`) that receives
/// the raw body string and returns the modified string. If the function returns
/// a non-string value it is JSON-serialized before writing back to the buffer.
///
/// Example script:
/// ```js
/// function transform(body) {
///     return body.toUpperCase();
/// }
/// ```
#[derive(Debug)]
pub struct JavaScriptTransform {
    /// JavaScript source executed against the body.
    pub script: String,
    /// Name of the entrypoint function (defaults to `transform`).
    pub function_name: Option<String>,
}

impl JavaScriptTransform {
    /// Build a JavaScriptTransform from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        #[derive(Deserialize)]
        struct Config {
            script: String,
            function_name: Option<String>,
        }
        let cfg: Config = serde_json::from_value(value)?;
        Ok(Self {
            script: cfg.script,
            function_name: cfg.function_name,
        })
    }

    /// Apply the JavaScript transform using JsEngine.
    pub fn apply(&self, body: &mut BytesMut) -> anyhow::Result<()> {
        let engine = sbproxy_extension::js::JsEngine::new()?;
        let input = String::from_utf8_lossy(body).to_string();
        let func = self.function_name.as_deref().unwrap_or("transform");

        let result =
            engine.call_function(&self.script, func, vec![serde_json::Value::String(input)])?;

        let output = match result {
            serde_json::Value::String(s) => s,
            other => serde_json::to_string(&other)?,
        };

        body.clear();
        body.extend_from_slice(output.as_bytes());
        Ok(())
    }
}

// --- JsJsonTransform ---

/// JavaScript-based JSON transform using JsEngine (QuickJS).
///
/// The script must define a function (default name: `modify_json`) that receives
/// the parsed JSON body as a JavaScript object and returns the modified value.
/// The result is serialized back to JSON and replaces the buffer contents.
///
/// Example script:
/// ```js
/// function modify_json(data) {
///     data.processed = true;
///     data.count = data.count * 2;
///     return data;
/// }
/// ```
#[derive(Debug)]
pub struct JsJsonTransform {
    /// JavaScript source executed against the parsed JSON body.
    pub script: String,
    /// Name of the entrypoint function (defaults to `modify_json`).
    pub function_name: Option<String>,
}

impl JsJsonTransform {
    /// Build a JsJsonTransform from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        #[derive(Deserialize)]
        struct Config {
            #[serde(alias = "js_script")]
            script: String,
            function_name: Option<String>,
        }
        let cfg: Config = serde_json::from_value(value)?;
        Ok(Self {
            script: cfg.script,
            function_name: cfg.function_name,
        })
    }

    /// Apply the JS JSON transform using JsEngine.
    pub fn apply(&self, body: &mut BytesMut) -> anyhow::Result<()> {
        let input: serde_json::Value = serde_json::from_slice(body)?;
        let engine = sbproxy_extension::js::JsEngine::new()?;
        let func = self.function_name.as_deref().unwrap_or("modify_json");

        let result = engine.call_function(&self.script, func, vec![input])?;

        let output = serde_json::to_vec(&result)?;
        body.clear();
        body.extend_from_slice(&output);
        Ok(())
    }
}

// --- WasmTransform ---

/// WebAssembly-based body transform using a sandboxed WASI module.
///
/// The module receives the response body on stdin and returns the
/// transformed body on stdout. Any wasm32-wasi binary works without
/// custom glue; see `docs/wasm-development.md` for the authoring
/// contract and Rust + TinyGo recipes.
///
/// Sandbox limits (memory cap, wall-clock timeout) are configured on
/// the underlying [`sbproxy_extension::wasm::WasmConfig`]; defaults
/// are 16 MiB / 1 s.
///
/// Example config:
/// ```yaml
/// transforms:
///   - type: wasm
///     module_path: /opt/sbproxy/wasm/echo.wasm
///     timeout_ms: 500
/// ```
#[derive(Debug)]
pub struct WasmTransform {
    /// Display name used in metrics + logs (defaults to the module
    /// file stem when `module_path` is set, otherwise "inline").
    pub name: String,
    /// Pre-compiled module + sandbox config. Compilation happens once
    /// at config-load time; per-request we only pay for instantiation
    /// and execution.
    runtime: sbproxy_extension::wasm::WasmRuntime,
}

impl WasmTransform {
    /// Build a `WasmTransform` from a generic JSON config value.
    ///
    /// Either `module_path` (filesystem path to a `.wasm`) or
    /// `module_bytes` (inline bytes) must be set; failing to set
    /// either is an error so misconfigured pipelines fail loudly at
    /// startup instead of silently accepting traffic with a no-op.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let cfg: sbproxy_extension::wasm::WasmConfig = serde_json::from_value(value)?;
        if cfg.module_path.is_none() && cfg.module_bytes.is_none() {
            anyhow::bail!("wasm transform requires either module_path or module_bytes");
        }
        let name = cfg
            .module_path
            .as_deref()
            .and_then(|p| std::path::Path::new(p).file_stem())
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "inline".to_string());
        let runtime = sbproxy_extension::wasm::WasmRuntime::new(cfg)?;
        Ok(Self { name, runtime })
    }

    /// Apply the WASM transform: feed `body` into the module's stdin,
    /// replace `body` with whatever the module wrote to stdout.
    pub fn apply(&self, body: &mut BytesMut) -> anyhow::Result<()> {
        let output = self.runtime.execute("transform", body)?;
        body.clear();
        body.extend_from_slice(&output);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Transform enum basics ---

    #[test]
    fn noop_transform_type() {
        let transform = Transform::Noop;
        assert_eq!(transform.transform_type(), "noop");
    }

    #[test]
    fn transform_debug_noop() {
        assert_eq!(format!("{:?}", Transform::Noop), "Noop");
    }

    #[test]
    fn json_transform_type() {
        let t = Transform::Json(JsonTransform {
            set: Default::default(),
            remove: vec![],
            rename: Default::default(),
        });
        assert_eq!(t.transform_type(), "json");
    }

    #[test]
    fn json_projection_transform_type() {
        let t = Transform::JsonProjection(JsonProjectionTransform {
            fields: vec!["id".into()],
            exclude: false,
        });
        assert_eq!(t.transform_type(), "json_projection");
    }

    #[test]
    fn json_schema_transform_type() {
        let t = Transform::JsonSchema(
            JsonSchemaTransform::from_config(serde_json::json!({"schema": {}})).unwrap(),
        );
        assert_eq!(t.transform_type(), "json_schema");
    }

    // --- Transform::apply dispatch ---

    #[test]
    fn apply_noop_leaves_body_unchanged() {
        let mut body = BytesMut::from(&b"{\"a\":1}"[..]);
        Transform::Noop.apply(&mut body, None).unwrap();
        assert_eq!(&body[..], b"{\"a\":1}");
    }

    #[test]
    fn apply_dispatches_to_json_transform() {
        let t = Transform::Json(JsonTransform {
            set: [("added".into(), serde_json::json!(true))]
                .into_iter()
                .collect(),
            remove: vec!["x".into()],
            rename: Default::default(),
        });
        let mut body = BytesMut::from(&b"{\"x\":1,\"y\":2}"[..]);
        t.apply(&mut body, Some("application/json")).unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(result.get("x").is_none());
        assert_eq!(result["added"], true);
        assert_eq!(result["y"], 2);
    }

    // --- TransformConfig deserialization ---

    #[test]
    fn transform_config_defaults() {
        let json = serde_json::json!({
            "type": "json",
            "set": {"foo": "bar"}
        });
        let cfg: TransformConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.transform_type, "json");
        assert!(cfg.content_types.is_empty());
        assert!(!cfg.fail_on_error);
        assert_eq!(cfg.max_body_size, 10 * 1024 * 1024);
        assert!(!cfg.disabled);
    }

    #[test]
    fn transform_config_with_all_fields() {
        let json = serde_json::json!({
            "type": "json_projection",
            "content_types": ["application/json"],
            "fail_on_error": true,
            "max_body_size": 1024,
            "disabled": true,
            "fields": ["id", "name"]
        });
        let cfg: TransformConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.transform_type, "json_projection");
        assert_eq!(cfg.content_types, vec!["application/json"]);
        assert!(cfg.fail_on_error);
        assert_eq!(cfg.max_body_size, 1024);
        assert!(cfg.disabled);
    }

    // --- CompiledTransform content-type matching ---

    #[test]
    fn compiled_transform_matches_all_when_empty() {
        let ct = CompiledTransform {
            transform: Transform::Noop,
            content_types: vec![],
            fail_on_error: false,
            max_body_size: 1024,
        };
        assert!(ct.matches_content_type(Some("text/html")));
        assert!(ct.matches_content_type(Some("application/json")));
        assert!(ct.matches_content_type(None));
    }

    #[test]
    fn compiled_transform_matches_specific_content_type() {
        let ct = CompiledTransform {
            transform: Transform::Noop,
            content_types: vec!["application/json".into()],
            fail_on_error: false,
            max_body_size: 1024,
        };
        assert!(ct.matches_content_type(Some("application/json")));
        assert!(ct.matches_content_type(Some("application/json; charset=utf-8")));
        assert!(!ct.matches_content_type(Some("text/html")));
        assert!(!ct.matches_content_type(None));
    }

    #[test]
    fn compiled_transform_skips_non_matching_content_type() {
        let ct = CompiledTransform {
            transform: Transform::Json(JsonTransform {
                set: [("injected".into(), serde_json::json!(true))]
                    .into_iter()
                    .collect(),
                remove: vec![],
                rename: Default::default(),
            }),
            content_types: vec!["application/json".into()],
            fail_on_error: false,
            max_body_size: 1024,
        };
        let mut body = BytesMut::from(&b"{\"a\":1}"[..]);
        // text/html does not match, so body should be unchanged.
        ct.apply(&mut body, Some("text/html")).unwrap();
        assert_eq!(&body[..], b"{\"a\":1}");
    }

    // --- LuaJsonTransform tests ---

    #[test]
    fn lua_json_transform_type() {
        let t = Transform::LuaJson(LuaJsonTransform {
            script: "return body".to_string(),
        });
        assert_eq!(t.transform_type(), "lua_json");
    }

    #[test]
    fn lua_json_from_config() {
        let t = LuaJsonTransform::from_config(serde_json::json!({
            "script": "body.added = true\nreturn body"
        }))
        .unwrap();
        assert_eq!(t.script, "body.added = true\nreturn body");
    }

    #[test]
    fn lua_json_from_config_missing_script_errors() {
        let result = LuaJsonTransform::from_config(serde_json::json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn lua_json_apply_modifies_body() {
        let t = LuaJsonTransform::from_config(serde_json::json!({
            "script": "body.added = true\nreturn body"
        }))
        .unwrap();
        let mut body = BytesMut::from(&b"{\"x\":1}"[..]);
        t.apply(&mut body).unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["x"], 1);
        assert_eq!(result["added"], true);
    }

    #[test]
    fn lua_json_apply_returns_new_value() {
        let t = LuaJsonTransform::from_config(serde_json::json!({
            "script": "return {status = \"ok\", count = 42}"
        }))
        .unwrap();
        let mut body = BytesMut::from(&b"{}"[..]);
        t.apply(&mut body).unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["count"], 42);
    }

    #[test]
    fn lua_json_apply_invalid_json_body_errors() {
        let t = LuaJsonTransform {
            script: "return body".to_string(),
        };
        let mut body = BytesMut::from(&b"not json"[..]);
        assert!(t.apply(&mut body).is_err());
    }

    #[test]
    fn lua_json_apply_bad_script_errors() {
        let t = LuaJsonTransform {
            script: "this is not valid lua !!!".to_string(),
        };
        let mut body = BytesMut::from(&b"{}"[..]);
        assert!(t.apply(&mut body).is_err());
    }

    // --- JavaScriptTransform tests ---

    // --- JavaScriptTransform tests ---

    #[test]
    fn javascript_transform_type() {
        let t = Transform::JavaScript(JavaScriptTransform {
            script: "function transform(b) { return b; }".to_string(),
            function_name: None,
        });
        assert_eq!(t.transform_type(), "javascript");
    }

    #[test]
    fn javascript_from_config() {
        let t = JavaScriptTransform::from_config(serde_json::json!({
            "script": "function transform(b) { return b; }"
        }))
        .unwrap();
        assert_eq!(t.script, "function transform(b) { return b; }");
        assert!(t.function_name.is_none());
    }

    #[test]
    fn javascript_from_config_with_function_name() {
        let t = JavaScriptTransform::from_config(serde_json::json!({
            "script": "function process(b) { return b.toUpperCase(); }",
            "function_name": "process"
        }))
        .unwrap();
        assert_eq!(t.function_name.as_deref(), Some("process"));
    }

    #[test]
    fn javascript_from_config_missing_script_errors() {
        let result = JavaScriptTransform::from_config(serde_json::json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn javascript_apply_transforms_body() {
        let t = JavaScriptTransform::from_config(serde_json::json!({
            "script": "function transform(body) { return body.toUpperCase(); }"
        }))
        .unwrap();
        let mut body = BytesMut::from(&b"hello world"[..]);
        t.apply(&mut body).unwrap();
        assert_eq!(&body[..], b"HELLO WORLD");
    }

    #[test]
    fn javascript_apply_returns_string_result() {
        let t = JavaScriptTransform::from_config(serde_json::json!({
            "script": "function transform(body) { return body.replace('foo', 'bar'); }"
        }))
        .unwrap();
        let mut body = BytesMut::from(&b"foo baz foo"[..]);
        t.apply(&mut body).unwrap();
        assert_eq!(&body[..], b"bar baz foo");
    }

    #[test]
    fn javascript_apply_with_custom_function_name() {
        let t = JavaScriptTransform::from_config(serde_json::json!({
            "script": "function process(body) { return body + '!'; }",
            "function_name": "process"
        }))
        .unwrap();
        let mut body = BytesMut::from(&b"hello"[..]);
        t.apply(&mut body).unwrap();
        assert_eq!(&body[..], b"hello!");
    }

    // --- JsJsonTransform tests ---

    #[test]
    fn js_json_transform_type() {
        let t = Transform::JsJson(JsJsonTransform {
            script: "function modify_json(d) { return d; }".to_string(),
            function_name: None,
        });
        assert_eq!(t.transform_type(), "js_json");
    }

    #[test]
    fn js_json_from_config() {
        let t = JsJsonTransform::from_config(serde_json::json!({
            "script": "function modify_json(d) { return d; }"
        }))
        .unwrap();
        assert_eq!(t.script, "function modify_json(d) { return d; }");
        assert!(t.function_name.is_none());
    }

    #[test]
    fn js_json_from_config_with_js_script_alias() {
        let t = JsJsonTransform::from_config(serde_json::json!({
            "js_script": "function modify_json(d) { return d; }"
        }))
        .unwrap();
        assert!(!t.script.is_empty());
    }

    #[test]
    fn js_json_from_config_missing_script_errors() {
        let result = JsJsonTransform::from_config(serde_json::json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn js_json_apply_modifies_body() {
        let t = JsJsonTransform::from_config(serde_json::json!({
            "script": "function modify_json(data) { data.added = true; return data; }"
        }))
        .unwrap();
        let mut body = BytesMut::from(&b"{\"x\":1}"[..]);
        t.apply(&mut body).unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["x"], 1);
        assert_eq!(result["added"], true);
    }

    #[test]
    fn js_json_apply_doubles_count() {
        let t = JsJsonTransform::from_config(serde_json::json!({
            "script": "function modify_json(data) { data.count = data.count * 2; return data; }"
        }))
        .unwrap();
        let mut body = BytesMut::from(&b"{\"count\":5}"[..]);
        t.apply(&mut body).unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["count"], 10);
    }

    #[test]
    fn js_json_apply_with_custom_function_name() {
        let t = JsJsonTransform::from_config(serde_json::json!({
            "script": "function transform_json(data) { data.transformed = true; return data; }",
            "function_name": "transform_json"
        }))
        .unwrap();
        let mut body = BytesMut::from(&b"{\"x\":1}"[..]);
        t.apply(&mut body).unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["transformed"], true);
    }

    #[test]
    fn js_json_apply_invalid_json_body_errors() {
        let t = JsJsonTransform {
            script: "function modify_json(d) { return d; }".to_string(),
            function_name: None,
        };
        let mut body = BytesMut::from(&b"not json"[..]);
        assert!(t.apply(&mut body).is_err());
    }

    // --- Debug fmt ---

    #[test]
    fn transform_debug_lua_json() {
        let t = Transform::LuaJson(LuaJsonTransform {
            script: "return body".to_string(),
        });
        let debug = format!("{:?}", t);
        assert!(debug.contains("LuaJson"));
    }

    #[test]
    fn transform_debug_javascript() {
        let t = Transform::JavaScript(JavaScriptTransform {
            script: "function transform(b) { return b; }".to_string(),
            function_name: None,
        });
        let debug = format!("{:?}", t);
        assert!(debug.contains("JavaScript"));
    }

    #[test]
    fn transform_debug_js_json() {
        let t = Transform::JsJson(JsJsonTransform {
            script: "function modify_json(d) { return d; }".to_string(),
            function_name: None,
        });
        let debug = format!("{:?}", t);
        assert!(debug.contains("JsJson"));
    }

    // --- Plugin dispatch regression test ---

    use sbproxy_plugin::{PluginKind, PluginRegistration};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Mock handler that records its call count and rewrites the body.
    struct RecordingTransformHandler {
        calls: Arc<AtomicUsize>,
    }

    impl TransformHandler for RecordingTransformHandler {
        fn transform_type(&self) -> &'static str {
            "test-recording-transform"
        }

        fn apply<'a>(
            &'a self,
            body: &'a mut bytes::BytesMut,
            _content_type: Option<&'a str>,
            _ctx: &'a TransformContext<'a>,
        ) -> Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>> {
            let calls = self.calls.clone();
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                body.clear();
                body.extend_from_slice(b"transformed");
                Ok(())
            })
        }
    }

    inventory::submit! {
        PluginRegistration {
            kind: PluginKind::Transform,
            name: "test-recording-transform",
            factory: |_config| Ok(Box::new(())),
        }
    }

    #[test]
    fn plugin_apply_dispatches_to_handler() {
        let calls = Arc::new(AtomicUsize::new(0));
        let handler = RecordingTransformHandler {
            calls: calls.clone(),
        };
        let t = Transform::Plugin(Box::new(handler));
        let mut body = BytesMut::from(&b"original"[..]);
        t.apply(&mut body, Some("text/plain")).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(&body[..], b"transformed");
    }

    #[test]
    fn plugin_apply_errors_when_not_registered() {
        struct UnregisteredHandler;
        impl TransformHandler for UnregisteredHandler {
            fn transform_type(&self) -> &'static str {
                "unregistered-transform"
            }
            fn apply<'a>(
                &'a self,
                _body: &'a mut bytes::BytesMut,
                _content_type: Option<&'a str>,
                _ctx: &'a TransformContext<'a>,
            ) -> Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>>
            {
                Box::pin(async { Ok(()) })
            }
        }

        let t = Transform::Plugin(Box::new(UnregisteredHandler));
        let mut body = BytesMut::from(&b"x"[..]);
        let err = t.apply(&mut body, None).unwrap_err();
        assert!(err.to_string().contains("unregistered-transform"));
    }
}

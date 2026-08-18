//! `${...}` interpolation engine for `type: local` MCP tools (WOR-2489).
//!
//! Shared by every compiled local-tool handler that needs to build a
//! live value from the call's arguments: a standalone `http` handler
//! (the request URL, header values, and JSON body) and a `steps`
//! DAG's own per-step HTTP calls (WOR-2489 Task 4), which reuse this
//! exact engine over a wider context object,
//! `{"args": <arguments>, "steps": <step outputs so far>}`, built at
//! the DAG executor's call site -- see the `steps.*` tests below for
//! the exact shape a step's context entry takes.
//!
//! Fail closed. A `${...}` reference to a path that is not present in
//! the context is a hard error, never an empty string: silently
//! splicing empty text into a URL, header, or request body would send
//! an origin a request no operator configured, which is a worse
//! failure mode than refusing the call outright.
//!
//! Escaping. `$$` renders one literal `$`, and does not open a
//! placeholder: `$${args.x}` renders the literal text `${args.x}`,
//! with `args.x` never looked up. Any other bare `$` not immediately
//! followed by `{` or another `$` is also literal (an unterminated or
//! empty `${...}` is instead a fail-closed error -- see
//! [`InterpolationError`]).
//!
//! Splice vs. stringify. When the entire template string is exactly
//! one `${...}` placeholder with no surrounding text, the resolved
//! JSON value is spliced in unchanged: a number stays a number, an
//! object stays an object. This is what lets `body: {"id": "${args.id}"}`
//! send a typed value straight from the caller's arguments instead of
//! a quoted string. A placeholder embedded in a larger string (leading
//! or trailing text, or more than one placeholder) is always rendered
//! to text, and the field becomes a JSON string.

use std::fmt;

use serde_json::Value;

/// Build the context object every `${...}` path in a standalone local
/// `http` handler resolves against. Only `args` is populated here
/// (the tool call's JSON-RPC arguments); a `steps` DAG's `${steps.*}`
/// root (WOR-2489 Task 4) is a wider context object built at that
/// executor's own call site instead, not by changing this function --
/// path resolution below is generic over whatever keys the context
/// object carries, which is what lets `steps.*` slot in with zero
/// changes here.
pub(crate) fn args_context(arguments: &Value) -> Value {
    serde_json::json!({ "args": arguments })
}

/// A `${...}` placeholder could not be resolved. Every variant's
/// message embeds only the dotted path an operator wrote in config,
/// never a live argument value, so it is always safe to surface
/// verbatim in a JSON-RPC error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InterpolationError {
    /// `${` with no matching `}` before the template ended.
    Unterminated,
    /// `${}` -- a placeholder with an empty path.
    Empty,
    /// `path` does not resolve against the context: its root segment
    /// names no context key, an intermediate segment is missing, or a
    /// segment indexes into a JSON scalar or array rather than an
    /// object. All three collapse to one fail-closed outcome: the
    /// call cannot proceed with this argument unresolved.
    MissingPath { path: String },
}

impl fmt::Display for InterpolationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unterminated => write!(f, "unterminated ${{...}} placeholder"),
            Self::Empty => write!(f, "empty ${{}} placeholder"),
            Self::MissingPath { path } => {
                write!(f, "${{{path}}} does not resolve against the call arguments")
            }
        }
    }
}

impl std::error::Error for InterpolationError {}

enum Segment {
    Literal(String),
    Placeholder(String),
}

/// Scan `template` into literal and placeholder segments, resolving
/// `$$` escaping along the way. Does not resolve any placeholder path;
/// that happens in [`interpolate_value`], which is also where a
/// resolution failure (as opposed to a scan failure) is reported.
fn scan(template: &str) -> Result<Vec<Segment>, InterpolationError> {
    let mut segments = Vec::new();
    let mut literal = String::new();
    let mut chars = template.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '$' {
            literal.push(ch);
            continue;
        }
        match chars.peek() {
            Some('$') => {
                chars.next();
                literal.push('$');
            }
            Some('{') => {
                chars.next(); // consume '{'
                let mut path = String::new();
                let mut closed = false;
                for c in chars.by_ref() {
                    if c == '}' {
                        closed = true;
                        break;
                    }
                    path.push(c);
                }
                if !closed {
                    return Err(InterpolationError::Unterminated);
                }
                if path.is_empty() {
                    return Err(InterpolationError::Empty);
                }
                if !literal.is_empty() {
                    segments.push(Segment::Literal(std::mem::take(&mut literal)));
                }
                segments.push(Segment::Placeholder(path));
            }
            _ => literal.push('$'),
        }
    }
    if !literal.is_empty() {
        segments.push(Segment::Literal(literal));
    }
    Ok(segments)
}

/// Resolve a dotted path (`args.user.id`) against `context`. Only
/// object-key traversal is supported (no array indexing); a segment
/// that does not exist, or that would index into a scalar or array,
/// is [`InterpolationError::MissingPath`].
fn resolve_path<'a>(path: &str, context: &'a Value) -> Result<&'a Value, InterpolationError> {
    let mut segments = path.split('.');
    let root = segments.next().unwrap_or("");
    let missing = || InterpolationError::MissingPath {
        path: path.to_string(),
    };
    if root.is_empty() {
        return Err(missing());
    }
    let mut current = context.get(root).ok_or_else(missing)?;
    for segment in segments {
        if segment.is_empty() {
            return Err(missing());
        }
        current = current
            .as_object()
            .and_then(|obj| obj.get(segment))
            .ok_or_else(missing)?;
    }
    Ok(current)
}

/// Render a resolved JSON value into text for the "embedded" case: a
/// placeholder that is part of a larger string. Strings pass through
/// unchanged (no re-quoting); numbers and booleans render as their
/// bare text; `null` renders as an empty string; objects and arrays
/// render as compact JSON text.
fn stringify(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        Value::Bool(_) | Value::Number(_) => value.to_string(),
        Value::Array(_) | Value::Object(_) => value.to_string(),
    }
}

/// Interpolate `template` against `context`, returning a JSON value.
///
/// A template that is nothing but one `${...}` placeholder splices the
/// resolved value in unchanged (see the module doc). Any other
/// template -- literal text only, or a placeholder mixed with literal
/// text, or more than one placeholder -- always yields a JSON string.
pub(crate) fn interpolate_value(
    template: &str,
    context: &Value,
) -> Result<Value, InterpolationError> {
    let segments = scan(template)?;
    match segments.as_slice() {
        [Segment::Placeholder(path)] => Ok(resolve_path(path, context)?.clone()),
        _ => {
            let mut out = String::new();
            for segment in &segments {
                match segment {
                    Segment::Literal(s) => out.push_str(s),
                    Segment::Placeholder(path) => {
                        out.push_str(&stringify(resolve_path(path, context)?));
                    }
                }
            }
            Ok(Value::String(out))
        }
    }
}

/// [`interpolate_value`] for a field that must remain a string (a URL
/// or an HTTP header value): a whole-string splice of a non-string
/// value is rendered the same way [`stringify`] renders an embedded
/// one, since a URL or header can only ever hold text.
pub(crate) fn interpolate_string(
    template: &str,
    context: &Value,
) -> Result<String, InterpolationError> {
    Ok(stringify(&interpolate_value(template, context)?))
}

/// Recursively interpolate every string leaf of a JSON tree (a local
/// HTTP tool's `body:`), preserving structure. A string leaf is
/// resolved with [`interpolate_value`] (so a whole-string placeholder
/// splices its JSON type into the tree); every other JSON type passes
/// through unchanged, including a string that is a JSON object/array
/// key (keys are never interpolated).
pub(crate) fn interpolate_json_tree(
    value: &Value,
    context: &Value,
) -> Result<Value, InterpolationError> {
    match value {
        Value::String(s) => interpolate_value(s, context),
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(interpolate_json_tree(item, context)?);
            }
            Ok(Value::Array(out))
        }
        Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (key, val) in map {
                out.insert(key.clone(), interpolate_json_tree(val, context)?);
            }
            Ok(Value::Object(out))
        }
        other => Ok(other.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn args(value: Value) -> Value {
        args_context(&value)
    }

    #[test]
    fn whole_string_placeholder_splices_the_json_value_unstringified() {
        let ctx = args(json!({"count": 42, "nested": {"flag": true}}));
        assert_eq!(
            interpolate_value("${args.count}", &ctx).expect("resolves"),
            json!(42)
        );
        assert_eq!(
            interpolate_value("${args.nested}", &ctx).expect("resolves"),
            json!({"flag": true})
        );
        assert_eq!(
            interpolate_value("${args.nested.flag}", &ctx).expect("resolves"),
            json!(true)
        );
    }

    #[test]
    fn embedded_placeholder_stringifies_into_surrounding_text() {
        let ctx = args(json!({"id": 42, "name": "widget"}));
        assert_eq!(
            interpolate_value("item-${args.id}", &ctx).expect("resolves"),
            json!("item-42")
        );
        assert_eq!(
            interpolate_value("${args.name} (#${args.id})", &ctx).expect("resolves"),
            json!("widget (#42)")
        );
    }

    #[test]
    fn interpolate_string_stringifies_a_whole_string_non_string_splice() {
        // A URL or header can only be text, so a whole-string splice
        // of a JSON object still renders as text there, unlike
        // `interpolate_value`'s behaviour for a body leaf.
        let ctx = args(json!({"obj": {"a": 1}}));
        assert_eq!(
            interpolate_string("${args.obj}", &ctx).expect("resolves"),
            "{\"a\":1}"
        );
    }

    #[test]
    fn missing_path_is_a_fail_closed_error_not_empty_string() {
        let ctx = args(json!({"present": "value"}));
        let err = interpolate_value("${args.missing}", &ctx).expect_err("must fail closed");
        assert_eq!(
            err,
            InterpolationError::MissingPath {
                path: "args.missing".to_string()
            }
        );
    }

    #[test]
    fn unknown_context_root_is_a_fail_closed_error() {
        let ctx = args(json!({}));
        let err = interpolate_value("${steps.one.output}", &ctx).expect_err("must fail closed");
        assert_eq!(
            err,
            InterpolationError::MissingPath {
                path: "steps.one.output".to_string()
            }
        );
    }

    #[test]
    fn indexing_into_a_scalar_is_a_fail_closed_error() {
        let ctx = args(json!({"count": 42}));
        let err = interpolate_value("${args.count.nope}", &ctx).expect_err("must fail closed");
        assert_eq!(
            err,
            InterpolationError::MissingPath {
                path: "args.count.nope".to_string()
            }
        );
    }

    #[test]
    fn escaped_dollar_brace_is_never_treated_as_a_placeholder() {
        let ctx = args(json!({}));
        assert_eq!(
            interpolate_value("$${args.x}", &ctx).expect("resolves"),
            json!("${args.x}"),
            "the escaped form must render literally without resolving `args.x`"
        );
    }

    #[test]
    fn bare_dollar_not_followed_by_brace_or_dollar_is_literal() {
        let ctx = args(json!({}));
        assert_eq!(
            interpolate_value("$5 total", &ctx).expect("resolves"),
            json!("$5 total")
        );
        assert_eq!(
            interpolate_value("trailing $", &ctx).expect("resolves"),
            json!("trailing $")
        );
    }

    #[test]
    fn unterminated_placeholder_is_a_fail_closed_error() {
        let ctx = args(json!({}));
        let err = interpolate_value("${args.x", &ctx).expect_err("must fail closed");
        assert_eq!(err, InterpolationError::Unterminated);
    }

    #[test]
    fn empty_placeholder_is_a_fail_closed_error() {
        let ctx = args(json!({}));
        let err = interpolate_value("${}", &ctx).expect_err("must fail closed");
        assert_eq!(err, InterpolationError::Empty);
    }

    #[test]
    fn literal_text_with_no_placeholder_round_trips() {
        let ctx = args(json!({}));
        assert_eq!(
            interpolate_value("no placeholders here", &ctx).expect("resolves"),
            json!("no placeholders here")
        );
        assert_eq!(interpolate_value("", &ctx).expect("resolves"), json!(""));
    }

    #[test]
    fn interpolate_json_tree_splices_leaves_and_preserves_structure() {
        let ctx = args(json!({"id": 7, "label": "widget"}));
        let body = json!({
            "user_id": "${args.id}",
            "note": "created ${args.label}",
            "static": "unchanged",
            "count": 3,
            "tags": ["a", "${args.label}"],
        });
        let rendered = interpolate_json_tree(&body, &ctx).expect("resolves");
        assert_eq!(
            rendered,
            json!({
                "user_id": 7,
                "note": "created widget",
                "static": "unchanged",
                "count": 3,
                "tags": ["a", "widget"],
            })
        );
    }

    #[test]
    fn interpolate_json_tree_fails_closed_on_a_missing_leaf() {
        let ctx = args(json!({}));
        let body = json!({"user_id": "${args.missing}"});
        let err = interpolate_json_tree(&body, &ctx).expect_err("must fail closed");
        assert_eq!(
            err,
            InterpolationError::MissingPath {
                path: "args.missing".to_string()
            }
        );
    }

    #[test]
    fn object_keys_are_never_interpolated() {
        let ctx = args(json!({}));
        let body = json!({"${args.missing}": "value"});
        // The key itself is never scanned for placeholders, so this
        // must succeed even though `args.missing` does not resolve.
        let rendered = interpolate_json_tree(&body, &ctx).expect("keys are not interpolated");
        assert_eq!(rendered, json!({"${args.missing}": "value"}));
    }

    // --- `${steps.*}` context paths (WOR-2489 Task 4) ---
    //
    // The step DAG executor builds a wider context object,
    // `{"args": <arguments>, "steps": <step outputs so far>}`, and
    // passes it to the same functions above -- nothing in this module
    // changes for that, since path resolution was always generic over
    // whatever top-level keys the context carries (see the module
    // doc). These tests pin that convergence: `${steps...}` is not a
    // special case, just another root key.

    /// A step's own document (built by
    /// `run_local_http_call_with_resolver`) always has this shape:
    /// `{"status": <u16>, "headers": {...}, "body": <parsed>}`.
    fn steps_context(entries: Value) -> Value {
        json!({ "args": {}, "steps": entries })
    }

    #[test]
    fn steps_status_and_body_resolve_through_the_generic_engine() {
        let ctx = steps_context(json!({
            "fetch": {
                "status": 200,
                "headers": {"content-type": "application/json"},
                "body": {"vendor_id": 42, "name": "widget"},
            }
        }));
        assert_eq!(
            interpolate_value("${steps.fetch.status}", &ctx).expect("resolves"),
            json!(200)
        );
        assert_eq!(
            interpolate_value("${steps.fetch.body.vendor_id}", &ctx).expect("resolves"),
            json!(42)
        );
        assert_eq!(
            interpolate_string("vendor-${steps.fetch.body.vendor_id}", &ctx).expect("resolves"),
            "vendor-42"
        );
        // A whole-string splice of the body preserves its type (an
        // object), the same "splice vs. stringify" rule any other
        // context root follows.
        assert_eq!(
            interpolate_value("${steps.fetch.body}", &ctx).expect("resolves"),
            json!({"vendor_id": 42, "name": "widget"})
        );
    }

    /// A step recorded with only `continue_on_error`'s `error` entry
    /// (WOR-2489 Task 4: a `Failed` step's `steps.<name>` context entry
    /// carries *only* `error`, never `status`/`headers`/`body`) still
    /// resolves `${steps.<name>.error}` -- but a later step reading
    /// `.body` or `.status` off it fails closed with `MissingPath`,
    /// exactly like reading into any other object that lacks that key.
    /// This is what makes "only steps that have already completed are
    /// in scope for `${steps...}`" (the DAG executor's own module doc)
    /// true without any special-casing in this module.
    #[test]
    fn a_continue_on_error_step_exposes_only_error_not_body_or_status() {
        let ctx = steps_context(json!({
            "flaky": {"error": "mcp: local step 'flaky' returned non-success status 500"}
        }));
        assert_eq!(
            interpolate_value("${steps.flaky.error}", &ctx).expect("resolves"),
            json!("mcp: local step 'flaky' returned non-success status 500")
        );
        let err = interpolate_value("${steps.flaky.body}", &ctx).expect_err("must fail closed");
        assert_eq!(
            err,
            InterpolationError::MissingPath {
                path: "steps.flaky.body".to_string()
            }
        );
        let err = interpolate_value("${steps.flaky.status}", &ctx).expect_err("must fail closed");
        assert_eq!(
            err,
            InterpolationError::MissingPath {
                path: "steps.flaky.status".to_string()
            }
        );
    }

    /// A skipped step (its `condition` evaluated false) gets no entry
    /// in the `steps` object at all (WOR-2489 Task 4), so any read of
    /// it -- the bare name or a nested path -- fails closed the same
    /// way an unknown context root always has.
    #[test]
    fn a_skipped_step_has_no_context_entry_and_fails_closed() {
        let ctx = steps_context(json!({}));
        let err =
            interpolate_value("${steps.skipped_step.status}", &ctx).expect_err("must fail closed");
        assert_eq!(
            err,
            InterpolationError::MissingPath {
                path: "steps.skipped_step.status".to_string()
            }
        );
    }
}

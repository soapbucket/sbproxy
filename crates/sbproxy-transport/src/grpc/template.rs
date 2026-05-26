//! HTTP path templates from `google.api.http` annotations.
//!
//! A transcoding route binds an HTTP method and path template to a gRPC
//! method. The template syntax is the one defined by `google.api.http`
//! (the `HttpRule` `path` grammar): literal segments, single-segment
//! wildcards (`*`), multi-segment wildcards (`**`), and field-path
//! captures of the form `{field}` or `{field=segments/**}`.
//!
//! This module compiles a template string into a matcher and, on a
//! match, returns the captured field bindings (the protobuf field path
//! mapped to the matched value). Those bindings are then merged into the
//! request message alongside the body and query parameters.

use std::collections::BTreeMap;

/// One segment of a compiled path template.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    /// A literal path segment that must match exactly.
    Literal(String),
    /// A single-segment wildcard (`*`): matches exactly one segment.
    Single,
    /// A multi-segment wildcard (`**`): matches the remaining segments.
    Multi,
    /// A capture `{field=...}`. The inner pattern is the segment list
    /// that fills the bound variable; an empty inner means `{field}`
    /// which is shorthand for `{field=*}`.
    Capture {
        /// Dotted protobuf field path the captured value binds to.
        field: String,
        /// The sub-pattern matched into this variable.
        pattern: Vec<Segment>,
    },
}

/// A compiled `google.api.http` path template.
#[derive(Debug, Clone)]
pub struct PathTemplate {
    segments: Vec<Segment>,
}

impl PathTemplate {
    /// Compile a template string such as `/v1/{name=shelves/*}/books`.
    ///
    /// The leading slash is optional. Returns an error on unbalanced
    /// braces or a nested capture (the grammar does not allow a capture
    /// inside a capture).
    pub fn parse(template: &str) -> anyhow::Result<Self> {
        let trimmed = template.trim_start_matches('/');
        let segments = parse_segments(trimmed, true)?;
        Ok(Self { segments })
    }

    /// Match a request path against the template.
    ///
    /// Returns `None` when the path does not match. On a match, returns
    /// the captured variable bindings: the protobuf field path to the
    /// joined matched value. Percent-encoded octets in captured values
    /// are left as-is; the caller decodes per field type.
    pub fn match_path(&self, path: &str) -> Option<BTreeMap<String, String>> {
        let path = path.split('?').next().unwrap_or(path);
        let parts: Vec<&str> = path
            .trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        let mut bindings = BTreeMap::new();
        if match_segments(&self.segments, &parts, &mut bindings) {
            Some(bindings)
        } else {
            None
        }
    }
}

/// Split a pattern on `/`, but keep a `{...}` capture (which may itself
/// contain `/`) as a single token. Returns an error on unbalanced
/// braces.
fn split_top_level(pattern: &str) -> anyhow::Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;
    for ch in pattern.chars() {
        match ch {
            '{' => {
                depth += 1;
                current.push(ch);
            }
            '}' => {
                depth -= 1;
                if depth < 0 {
                    anyhow::bail!("unbalanced '}}' in path template");
                }
                current.push(ch);
            }
            '/' if depth == 0 => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if depth != 0 {
        anyhow::bail!("unterminated capture segment in path template");
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Ok(tokens)
}

/// Parse a slash-separated pattern into segments. When `allow_capture`
/// is false (inside a capture's sub-pattern) a nested `{...}` is an
/// error.
fn parse_segments(pattern: &str, allow_capture: bool) -> anyhow::Result<Vec<Segment>> {
    let mut out = Vec::new();
    for raw in split_top_level(pattern)? {
        let raw = raw.as_str();
        if raw.is_empty() {
            continue;
        }
        if raw.starts_with('{') {
            if !allow_capture {
                anyhow::bail!("nested capture is not allowed in path template");
            }
            if !raw.ends_with('}') {
                anyhow::bail!("unterminated capture segment in path template: {raw}");
            }
            let inner = &raw[1..raw.len() - 1];
            let (field, sub) = match inner.split_once('=') {
                Some((f, s)) => (f.trim(), s.trim()),
                None => (inner.trim(), "*"),
            };
            if field.is_empty() {
                anyhow::bail!("empty capture field name in path template");
            }
            let pattern = parse_segments(sub, false)?;
            out.push(Segment::Capture {
                field: field.to_string(),
                pattern,
            });
        } else if raw == "*" {
            out.push(Segment::Single);
        } else if raw == "**" {
            out.push(Segment::Multi);
        } else if raw.contains('{') || raw.contains('}') {
            anyhow::bail!("malformed capture braces in path template segment: {raw}");
        } else {
            out.push(Segment::Literal(raw.to_string()));
        }
    }
    Ok(out)
}

/// Recursive matcher. Consumes `segments` against `parts`, recording
/// capture bindings as it goes.
fn match_segments(
    segments: &[Segment],
    parts: &[&str],
    bindings: &mut BTreeMap<String, String>,
) -> bool {
    let mut pi = 0; // index into parts
    let mut si = 0; // index into segments
    while si < segments.len() {
        match &segments[si] {
            Segment::Literal(lit) => {
                if pi >= parts.len() || parts[pi] != lit {
                    return false;
                }
                pi += 1;
            }
            Segment::Single => {
                if pi >= parts.len() {
                    return false;
                }
                pi += 1;
            }
            Segment::Multi => {
                // `**` greedily consumes the rest. It must be the final
                // segment in a valid template, so anything after it
                // cannot match.
                return si + 1 == segments.len();
            }
            Segment::Capture { field, pattern } => {
                let captured_len = capture_len(pattern, parts.len() - pi.min(parts.len()));
                if pi + captured_len > parts.len() {
                    return false;
                }
                let value = parts[pi..pi + captured_len].join("/");
                // Verify the captured slice satisfies the sub-pattern
                // (mainly to reject a too-short slice for a `*` capture).
                if !sub_pattern_matches(pattern, &parts[pi..pi + captured_len]) {
                    return false;
                }
                bindings.insert(field.clone(), value);
                pi += captured_len;
            }
        }
        si += 1;
    }
    pi == parts.len()
}

/// How many path segments a capture sub-pattern consumes given the
/// number of segments still available.
fn capture_len(pattern: &[Segment], remaining: usize) -> usize {
    let mut len = 0;
    for seg in pattern {
        match seg {
            Segment::Multi => return remaining, // `**` eats everything left
            _ => len += 1,
        }
    }
    len
}

/// Whether the captured slice matches the capture's sub-pattern. The
/// sub-pattern only ever contains literals, `*`, and `**`.
fn sub_pattern_matches(pattern: &[Segment], parts: &[&str]) -> bool {
    let mut bindings = BTreeMap::new();
    match_segments(pattern, parts, &mut bindings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_path_matches_exactly() {
        let tpl = PathTemplate::parse("/v1/echo/hello").unwrap();
        assert!(tpl.match_path("/v1/echo/hello").unwrap().is_empty());
        assert!(tpl.match_path("/v1/echo/world").is_none());
        assert!(tpl.match_path("/v1/echo").is_none());
    }

    #[test]
    fn simple_field_capture() {
        let tpl = PathTemplate::parse("/v1/messages/{message_id}").unwrap();
        let b = tpl.match_path("/v1/messages/42").unwrap();
        assert_eq!(b.get("message_id").unwrap(), "42");
        // Two segments do not fit a single-segment `{message_id}`.
        assert!(tpl.match_path("/v1/messages/42/extra").is_none());
    }

    #[test]
    fn capture_with_resource_pattern() {
        let tpl = PathTemplate::parse("/v1/{name=shelves/*/books/*}").unwrap();
        let b = tpl.match_path("/v1/shelves/7/books/13").unwrap();
        assert_eq!(b.get("name").unwrap(), "shelves/7/books/13");
        assert!(tpl.match_path("/v1/shelves/7/books").is_none());
    }

    #[test]
    fn multi_segment_wildcard_capture() {
        let tpl = PathTemplate::parse("/v1/{path=**}").unwrap();
        let b = tpl.match_path("/v1/a/b/c/d").unwrap();
        assert_eq!(b.get("path").unwrap(), "a/b/c/d");
    }

    #[test]
    fn dotted_field_path_capture() {
        let tpl = PathTemplate::parse("/v1/users/{user.id}").unwrap();
        let b = tpl.match_path("/v1/users/abc").unwrap();
        assert_eq!(b.get("user.id").unwrap(), "abc");
    }

    #[test]
    fn single_wildcard_no_binding() {
        let tpl = PathTemplate::parse("/v1/*/info").unwrap();
        assert!(tpl.match_path("/v1/anything/info").unwrap().is_empty());
        assert!(tpl.match_path("/v1/info").is_none());
    }

    #[test]
    fn trailing_segments_after_capture() {
        let tpl = PathTemplate::parse("/v1/{id}/details").unwrap();
        let b = tpl.match_path("/v1/99/details").unwrap();
        assert_eq!(b.get("id").unwrap(), "99");
        assert!(tpl.match_path("/v1/99").is_none());
    }

    #[test]
    fn query_string_is_ignored_for_matching() {
        let tpl = PathTemplate::parse("/v1/items/{id}").unwrap();
        let b = tpl.match_path("/v1/items/5?verbose=true").unwrap();
        assert_eq!(b.get("id").unwrap(), "5");
    }

    #[test]
    fn unterminated_capture_is_an_error() {
        assert!(PathTemplate::parse("/v1/{id").is_err());
    }

    #[test]
    fn nested_capture_is_an_error() {
        assert!(PathTemplate::parse("/v1/{a={b}}").is_err());
    }

    #[test]
    fn empty_field_name_is_an_error() {
        assert!(PathTemplate::parse("/v1/{=*}").is_err());
    }
}

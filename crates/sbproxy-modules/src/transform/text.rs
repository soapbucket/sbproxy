//! Text transforms: template rendering, string replacement, normalization,
//! encoding conversion, and format conversion.

use bytes::BytesMut;
use serde::Deserialize;

// --- TemplateTransform ---

/// Renders a template using response body as input data.
/// Uses minijinja for `{{ variable }}` syntax.
#[derive(Debug, Deserialize)]
pub struct TemplateTransform {
    /// Template string with `{{ variable }}` syntax.
    pub template: String,
}

impl TemplateTransform {
    /// Create from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Parse body as JSON, render template with body data as context.
    pub fn apply(&self, body: &mut BytesMut) -> anyhow::Result<()> {
        let json: serde_json::Value = serde_json::from_slice(body)?;

        let env = minijinja::Environment::new();
        let rendered = env.render_str(&self.template, json)?;

        body.clear();
        body.extend_from_slice(rendered.as_bytes());
        Ok(())
    }
}

// --- ReplaceStringsTransform ---

/// A single find-and-replace rule.
#[derive(Debug, Deserialize, Clone)]
pub struct StringReplacement {
    /// The string (or regex pattern) to find.
    pub find: String,
    /// The replacement string.
    pub replace: String,
    /// If true, treat `find` as a regex pattern.
    #[serde(default)]
    pub regex: bool,
}

/// Applies a list of string replacements to the response body.
#[derive(Debug, Deserialize)]
pub struct ReplaceStringsTransform {
    /// Ordered list of replacements to apply.
    pub replacements: Vec<StringReplacement>,
}

impl ReplaceStringsTransform {
    /// Create from a generic JSON config value.
    ///
    /// Accepts both flat format (`{replacements: [...]}`) and Go-compat
    /// nested format (`{replace_strings: {replacements: [...]}}`).
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        // Try Go-compat nested format first: { replace_strings: { replacements: [...] } }
        if let Some(inner) = value.get("replace_strings") {
            if inner.is_object() {
                return Ok(serde_json::from_value(inner.clone())?);
            }
        }
        Ok(serde_json::from_value(value)?)
    }

    /// Apply all replacements sequentially to the body.
    pub fn apply(&self, body: &mut BytesMut) -> anyhow::Result<()> {
        let mut text = String::from_utf8(body.to_vec())
            .map_err(|e| anyhow::anyhow!("body is not valid UTF-8: {}", e))?;

        for replacement in &self.replacements {
            if replacement.regex {
                let re = regex::Regex::new(&replacement.find)
                    .map_err(|e| anyhow::anyhow!("invalid regex '{}': {}", replacement.find, e))?;
                text = re
                    .replace_all(&text, replacement.replace.as_str())
                    .into_owned();
            } else {
                text = text.replace(&replacement.find, &replacement.replace);
            }
        }

        body.clear();
        body.extend_from_slice(text.as_bytes());
        Ok(())
    }
}

// --- NormalizeTransform ---

/// Normalizes whitespace in the response body.
#[derive(Debug, Deserialize, Default)]
pub struct NormalizeTransform {
    /// Trim leading and trailing whitespace.
    #[serde(default)]
    pub trim: bool,
    /// Collapse consecutive whitespace into a single space.
    #[serde(default)]
    pub collapse_whitespace: bool,
    /// Convert `\r\n` to `\n`.
    #[serde(default)]
    pub normalize_newlines: bool,
}

impl NormalizeTransform {
    /// Create from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Apply normalization rules to the body.
    pub fn apply(&self, body: &mut BytesMut) -> anyhow::Result<()> {
        let mut text = String::from_utf8(body.to_vec())
            .map_err(|e| anyhow::anyhow!("body is not valid UTF-8: {}", e))?;

        if self.normalize_newlines {
            text = text.replace("\r\n", "\n");
        }

        if self.collapse_whitespace {
            // Collapse runs of whitespace (spaces, tabs) into a single space,
            // but preserve newlines as-is.
            let mut result = String::with_capacity(text.len());
            let mut prev_was_space = false;
            for ch in text.chars() {
                if ch == ' ' || ch == '\t' {
                    if !prev_was_space {
                        result.push(' ');
                    }
                    prev_was_space = true;
                } else {
                    prev_was_space = false;
                    result.push(ch);
                }
            }
            text = result;
        }

        if self.trim {
            text = text.trim().to_string();
        }

        body.clear();
        body.extend_from_slice(text.as_bytes());
        Ok(())
    }
}

// --- EncodingTransform ---

/// Base64 or URL encode/decode the response body.
#[derive(Debug, Deserialize)]
pub struct EncodingTransform {
    /// One of: "base64_encode", "base64_decode", "url_encode", "url_decode".
    pub encoding: String,
}

impl EncodingTransform {
    /// Create from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Apply the encoding/decoding operation to the body.
    pub fn apply(&self, body: &mut BytesMut) -> anyhow::Result<()> {
        use base64::Engine;

        match self.encoding.as_str() {
            "base64_encode" => {
                let encoded = base64::engine::general_purpose::STANDARD.encode(&body[..]);
                body.clear();
                body.extend_from_slice(encoded.as_bytes());
            }
            "base64_decode" => {
                let text = std::str::from_utf8(&body[..]).map_err(|e| {
                    anyhow::anyhow!("body is not valid UTF-8 for base64 decode: {}", e)
                })?;
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(text.trim())
                    .map_err(|e| anyhow::anyhow!("invalid base64: {}", e))?;
                body.clear();
                body.extend_from_slice(&decoded);
            }
            "url_encode" => {
                let text = std::str::from_utf8(&body[..]).map_err(|e| {
                    anyhow::anyhow!("body is not valid UTF-8 for URL encode: {}", e)
                })?;
                let encoded =
                    percent_encoding::utf8_percent_encode(text, percent_encoding::NON_ALPHANUMERIC)
                        .to_string();
                body.clear();
                body.extend_from_slice(encoded.as_bytes());
            }
            "url_decode" => {
                let text = std::str::from_utf8(&body[..]).map_err(|e| {
                    anyhow::anyhow!("body is not valid UTF-8 for URL decode: {}", e)
                })?;
                let decoded = percent_encoding::percent_decode_str(text)
                    .decode_utf8()
                    .map_err(|e| anyhow::anyhow!("invalid percent-encoded UTF-8: {}", e))?
                    .into_owned();
                body.clear();
                body.extend_from_slice(decoded.as_bytes());
            }
            other => {
                anyhow::bail!(
                    "unknown encoding '{}': expected one of base64_encode, base64_decode, url_encode, url_decode",
                    other
                );
            }
        }
        Ok(())
    }
}

// --- FormatConvertTransform ---

/// Convert between JSON and YAML formats.
#[derive(Debug, Deserialize)]
pub struct FormatConvertTransform {
    /// Source format: "json" or "yaml".
    pub from: String,
    /// Target format: "json" or "yaml".
    pub to: String,
}

impl FormatConvertTransform {
    /// Create from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Parse the body from the source format and serialize to the target format.
    pub fn apply(&self, body: &mut BytesMut) -> anyhow::Result<()> {
        // Parse from source format into a generic Value.
        let value: serde_json::Value = match self.from.as_str() {
            "json" => serde_json::from_slice(body)?,
            "yaml" => {
                let text = std::str::from_utf8(&body[..])
                    .map_err(|e| anyhow::anyhow!("body is not valid UTF-8: {}", e))?;
                serde_yaml::from_str(text).map_err(|e| anyhow::anyhow!("invalid YAML: {}", e))?
            }
            other => anyhow::bail!(
                "unsupported source format '{}': expected json or yaml",
                other
            ),
        };

        // Serialize to target format.
        let output = match self.to.as_str() {
            "json" => serde_json::to_vec_pretty(&value)?,
            "yaml" => {
                let yaml_str = serde_yaml::to_string(&value)
                    .map_err(|e| anyhow::anyhow!("failed to serialize to YAML: {}", e))?;
                yaml_str.into_bytes()
            }
            other => anyhow::bail!(
                "unsupported target format '{}': expected json or yaml",
                other
            ),
        };

        body.clear();
        body.extend_from_slice(&output);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- TemplateTransform tests ---

    #[test]
    fn template_from_config() {
        let config = serde_json::json!({
            "template": "Hello, {{ name }}!"
        });
        let t = TemplateTransform::from_config(config).unwrap();
        assert_eq!(t.template, "Hello, {{ name }}!");
    }

    #[test]
    fn template_apply_basic() {
        let t = TemplateTransform {
            template: "Hello, {{ name }}! You are {{ age }} years old.".into(),
        };
        let mut body = BytesMut::from(&b"{\"name\":\"Alice\",\"age\":30}"[..]);
        t.apply(&mut body).unwrap();
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            "Hello, Alice! You are 30 years old."
        );
    }

    #[test]
    fn template_apply_nested_data() {
        let t = TemplateTransform {
            template: "{{ user.name }} - {{ user.role }}".into(),
        };
        let mut body = BytesMut::from(&b"{\"user\":{\"name\":\"Bob\",\"role\":\"admin\"}}"[..]);
        t.apply(&mut body).unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), "Bob - admin");
    }

    #[test]
    fn template_apply_invalid_json() {
        let t = TemplateTransform {
            template: "{{ x }}".into(),
        };
        let mut body = BytesMut::from(&b"not json"[..]);
        assert!(t.apply(&mut body).is_err());
    }

    #[test]
    fn template_apply_empty_body() {
        let t = TemplateTransform {
            template: "static text".into(),
        };
        // Empty body is not valid JSON.
        let mut body = BytesMut::new();
        assert!(t.apply(&mut body).is_err());
    }

    // --- ReplaceStringsTransform tests ---

    #[test]
    fn replace_strings_from_config() {
        let config = serde_json::json!({
            "replacements": [
                {"find": "foo", "replace": "bar"},
                {"find": "\\d+", "replace": "NUM", "regex": true}
            ]
        });
        let t = ReplaceStringsTransform::from_config(config).unwrap();
        assert_eq!(t.replacements.len(), 2);
        assert!(!t.replacements[0].regex);
        assert!(t.replacements[1].regex);
    }

    #[test]
    fn replace_strings_literal() {
        let t = ReplaceStringsTransform {
            replacements: vec![StringReplacement {
                find: "world".into(),
                replace: "Rust".into(),
                regex: false,
            }],
        };
        let mut body = BytesMut::from(&b"Hello world, world!"[..]);
        t.apply(&mut body).unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), "Hello Rust, Rust!");
    }

    #[test]
    fn replace_strings_regex() {
        let t = ReplaceStringsTransform {
            replacements: vec![StringReplacement {
                find: r"\d+".into(),
                replace: "NUM".into(),
                regex: true,
            }],
        };
        let mut body = BytesMut::from(&b"order 123 has 4 items"[..]);
        t.apply(&mut body).unwrap();
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            "order NUM has NUM items"
        );
    }

    #[test]
    fn replace_strings_multiple_replacements() {
        let t = ReplaceStringsTransform {
            replacements: vec![
                StringReplacement {
                    find: "A".into(),
                    replace: "B".into(),
                    regex: false,
                },
                StringReplacement {
                    find: "B".into(),
                    replace: "C".into(),
                    regex: false,
                },
            ],
        };
        let mut body = BytesMut::from(&b"A"[..]);
        t.apply(&mut body).unwrap();
        // A -> B -> C (sequential application)
        assert_eq!(std::str::from_utf8(&body).unwrap(), "C");
    }

    #[test]
    fn replace_strings_empty_body() {
        let t = ReplaceStringsTransform {
            replacements: vec![StringReplacement {
                find: "x".into(),
                replace: "y".into(),
                regex: false,
            }],
        };
        let mut body = BytesMut::new();
        t.apply(&mut body).unwrap();
        assert!(body.is_empty());
    }

    #[test]
    fn replace_strings_no_match() {
        let t = ReplaceStringsTransform {
            replacements: vec![StringReplacement {
                find: "missing".into(),
                replace: "found".into(),
                regex: false,
            }],
        };
        let mut body = BytesMut::from(&b"nothing to replace"[..]);
        t.apply(&mut body).unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), "nothing to replace");
    }

    #[test]
    fn replace_strings_invalid_regex() {
        let t = ReplaceStringsTransform {
            replacements: vec![StringReplacement {
                find: "[invalid".into(),
                replace: "x".into(),
                regex: true,
            }],
        };
        let mut body = BytesMut::from(&b"test"[..]);
        assert!(t.apply(&mut body).is_err());
    }

    // --- NormalizeTransform tests ---

    #[test]
    fn normalize_from_config() {
        let config = serde_json::json!({
            "trim": true,
            "collapse_whitespace": true,
            "normalize_newlines": true
        });
        let t = NormalizeTransform::from_config(config).unwrap();
        assert!(t.trim);
        assert!(t.collapse_whitespace);
        assert!(t.normalize_newlines);
    }

    #[test]
    fn normalize_defaults() {
        let config = serde_json::json!({});
        let t = NormalizeTransform::from_config(config).unwrap();
        assert!(!t.trim);
        assert!(!t.collapse_whitespace);
        assert!(!t.normalize_newlines);
    }

    #[test]
    fn normalize_trim() {
        let t = NormalizeTransform {
            trim: true,
            ..Default::default()
        };
        let mut body = BytesMut::from(&b"  hello world  "[..]);
        t.apply(&mut body).unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), "hello world");
    }

    #[test]
    fn normalize_collapse_whitespace() {
        let t = NormalizeTransform {
            collapse_whitespace: true,
            ..Default::default()
        };
        let mut body = BytesMut::from(&b"hello   world\t\there"[..]);
        t.apply(&mut body).unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), "hello world here");
    }

    #[test]
    fn normalize_newlines() {
        let t = NormalizeTransform {
            normalize_newlines: true,
            ..Default::default()
        };
        let mut body = BytesMut::from(&b"line1\r\nline2\r\nline3"[..]);
        t.apply(&mut body).unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), "line1\nline2\nline3");
    }

    #[test]
    fn normalize_all_options() {
        let t = NormalizeTransform {
            trim: true,
            collapse_whitespace: true,
            normalize_newlines: true,
        };
        let mut body = BytesMut::from(&b"  hello   world\r\n  foo  bar  "[..]);
        t.apply(&mut body).unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), "hello world\n foo bar");
    }

    #[test]
    fn normalize_empty_body() {
        let t = NormalizeTransform {
            trim: true,
            collapse_whitespace: true,
            normalize_newlines: true,
        };
        let mut body = BytesMut::new();
        t.apply(&mut body).unwrap();
        assert!(body.is_empty());
    }

    // --- EncodingTransform tests ---

    #[test]
    fn encoding_from_config() {
        let config = serde_json::json!({"encoding": "base64_encode"});
        let t = EncodingTransform::from_config(config).unwrap();
        assert_eq!(t.encoding, "base64_encode");
    }

    #[test]
    fn encoding_base64_encode() {
        let t = EncodingTransform {
            encoding: "base64_encode".into(),
        };
        let mut body = BytesMut::from(&b"Hello, World!"[..]);
        t.apply(&mut body).unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), "SGVsbG8sIFdvcmxkIQ==");
    }

    #[test]
    fn encoding_base64_decode() {
        let t = EncodingTransform {
            encoding: "base64_decode".into(),
        };
        let mut body = BytesMut::from(&b"SGVsbG8sIFdvcmxkIQ=="[..]);
        t.apply(&mut body).unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), "Hello, World!");
    }

    #[test]
    fn encoding_base64_roundtrip() {
        let original = b"Some binary-like data: \x01\x02\x03";
        let encode = EncodingTransform {
            encoding: "base64_encode".into(),
        };
        let decode = EncodingTransform {
            encoding: "base64_decode".into(),
        };
        let mut body = BytesMut::from(&original[..]);
        encode.apply(&mut body).unwrap();
        decode.apply(&mut body).unwrap();
        assert_eq!(&body[..], original);
    }

    #[test]
    fn encoding_url_encode() {
        let t = EncodingTransform {
            encoding: "url_encode".into(),
        };
        let mut body = BytesMut::from(&b"hello world&foo=bar"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(result.contains("hello%20world"));
        assert!(result.contains("%26"));
    }

    #[test]
    fn encoding_url_decode() {
        let t = EncodingTransform {
            encoding: "url_decode".into(),
        };
        let mut body = BytesMut::from(&b"hello%20world%26foo%3Dbar"[..]);
        t.apply(&mut body).unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), "hello world&foo=bar");
    }

    #[test]
    fn encoding_unknown_type() {
        let t = EncodingTransform {
            encoding: "rot13".into(),
        };
        let mut body = BytesMut::from(&b"test"[..]);
        assert!(t.apply(&mut body).is_err());
    }

    #[test]
    fn encoding_invalid_base64() {
        let t = EncodingTransform {
            encoding: "base64_decode".into(),
        };
        let mut body = BytesMut::from(&b"not!valid!base64!!!"[..]);
        assert!(t.apply(&mut body).is_err());
    }

    #[test]
    fn encoding_empty_body() {
        let t = EncodingTransform {
            encoding: "base64_encode".into(),
        };
        let mut body = BytesMut::new();
        t.apply(&mut body).unwrap();
        // base64 of empty is empty.
        assert!(body.is_empty());
    }

    // --- FormatConvertTransform tests ---

    #[test]
    fn format_convert_from_config() {
        let config = serde_json::json!({"from": "json", "to": "yaml"});
        let t = FormatConvertTransform::from_config(config).unwrap();
        assert_eq!(t.from, "json");
        assert_eq!(t.to, "yaml");
    }

    #[test]
    fn format_convert_json_to_yaml() {
        let t = FormatConvertTransform {
            from: "json".into(),
            to: "yaml".into(),
        };
        let mut body = BytesMut::from(&b"{\"name\":\"Alice\",\"age\":30}"[..]);
        t.apply(&mut body).unwrap();
        let result = std::str::from_utf8(&body).unwrap();
        assert!(result.contains("name:"));
        assert!(result.contains("Alice"));
        assert!(result.contains("age:"));
    }

    #[test]
    fn format_convert_yaml_to_json() {
        let t = FormatConvertTransform {
            from: "yaml".into(),
            to: "json".into(),
        };
        let mut body = BytesMut::from(&b"name: Alice\nage: 30\n"[..]);
        t.apply(&mut body).unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["name"], "Alice");
        assert_eq!(result["age"], 30);
    }

    #[test]
    fn format_convert_json_to_json() {
        let t = FormatConvertTransform {
            from: "json".into(),
            to: "json".into(),
        };
        let mut body = BytesMut::from(&b"{\"a\":1}"[..]);
        t.apply(&mut body).unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["a"], 1);
    }

    #[test]
    fn format_convert_unsupported_format() {
        let t = FormatConvertTransform {
            from: "xml".into(),
            to: "json".into(),
        };
        let mut body = BytesMut::from(&b"<root/>"[..]);
        assert!(t.apply(&mut body).is_err());
    }

    #[test]
    fn format_convert_invalid_source() {
        let t = FormatConvertTransform {
            from: "json".into(),
            to: "yaml".into(),
        };
        let mut body = BytesMut::from(&b"not json"[..]);
        assert!(t.apply(&mut body).is_err());
    }
}

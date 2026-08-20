//! `body_threat_protection` policy: structural limits on JSON and
//! XML request bodies.
//!
//! Kong gates the equivalent capability (its JSON Threat Protection
//! and XML Threat Protection plugins) behind its Enterprise tier;
//! SBproxy ships it in OSS. The policy is shape enforcement, not
//! signature matching: it bounds nesting depth, container sizes, and
//! string lengths, and it refuses XML DTDs outright, which is what
//! kills the billion-laughs entity-expansion class. Because the
//! checks are structural they are immune to the encoding-evasion
//! problems a signature WAF corpus has, and they run in one pass over
//! the buffered body.
//!
//! Evaluation happens at the request-body buffering boundary in
//! `sbproxy-core` (`request_body_filter`), the same seam
//! `request_validator` and `openapi_validation` use: the enforcer
//! marks the request for buffering when the `Content-Type` is in the
//! JSON or XML family, and the buffered bytes are scanned once at
//! end-of-stream. Bodies of any other content type stream through
//! untouched; a wrong-content-type body misses rather than
//! misparses.
//!
//! The JSON scanner is a hand-rolled iterative tokenizer rather than
//! a `serde_json` parse: `serde_json` imposes its own recursion limit
//! of 128, so a 200-level document would be refused as "invalid
//! JSON" instead of naming the depth limit, and a document that
//! passes the limits would still pay for a full DOM. The scanner is
//! O(n), allocates nothing but a small state stack, and exits on the
//! first violation. XML is scanned with `quick-xml`'s pull reader,
//! which never expands entities during event iteration.
//!
//! This policy is a complement to a body-aware WAF rule engine, not a
//! substitute: it bounds the shape of a body, it does not inspect the
//! content. See `docs/waf-options.md` for what the WAF baseline does
//! and does not read.

use serde::Deserialize;

/// Default maximum nesting depth for both JSON and XML. Half of
/// `serde_json`'s own recursion limit (128), so any recursive
/// consumer behind the proxy that uses stock serde settings is
/// protected with margin.
pub const DEFAULT_MAX_DEPTH: usize = 64;
/// Default maximum entries in any single JSON object.
pub const DEFAULT_MAX_OBJECT_ENTRIES: usize = 10_000;
/// Default maximum items in any single JSON array.
pub const DEFAULT_MAX_ARRAY_ITEMS: usize = 10_000;
/// Default maximum byte length of a JSON object key.
pub const DEFAULT_MAX_KEY_LENGTH: usize = 1_024;
/// Default maximum byte length of a JSON string value (128 KiB).
pub const DEFAULT_MAX_STRING_LENGTH: usize = 128 * 1024;
/// Default maximum total number of JSON containers (objects plus
/// arrays) in one document.
pub const DEFAULT_MAX_CONTAINERS: usize = 50_000;
/// Default maximum total number of XML elements in one document.
pub const DEFAULT_MAX_ELEMENTS: usize = 10_000;
/// Default maximum number of attributes on any single XML element.
pub const DEFAULT_MAX_ATTRIBUTES: usize = 256;
/// Absolute nesting-depth ceiling for the JSON scanner, applied even
/// when `max_depth: 0` (or a larger configured value) would otherwise
/// disable or exceed it. The scanner keeps one small state frame per
/// open container, so an unbounded depth would let a body of nothing
/// but `[` grow scanner memory to a multiple of the body size; the
/// ceiling caps that at a few hundred kilobytes. No legitimate
/// document nests ten thousand containers deep.
pub const JSON_ABSOLUTE_MAX_DEPTH: usize = 10_000;

/// What the policy does when a body violates a limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyThreatMode {
    /// Refuse the request with a 400 naming the violated limit. The
    /// upstream is never contacted. This is the default.
    Block,
    /// Log the violation and increment the policy metric without
    /// blocking, mirroring the `object_authz` detect-only precedent:
    /// shape limits can false-positive on legitimately deep payloads,
    /// so operators get a way to observe before enforcing.
    Tap,
}

/// Body family a request's `Content-Type` resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyThreatFamily {
    /// `application/json` or any `+json` structured-syntax suffix.
    Json,
    /// `application/xml`, `text/xml`, or any `+xml` suffix.
    Xml,
}

/// Structural limits for JSON bodies. Any limit set to `0` disables
/// that single check.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonThreatLimits {
    /// Master switch for the JSON family. Default on.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Maximum container nesting depth; a top-level object or array
    /// is depth 1. Independent of this setting, the scanner enforces
    /// the [`JSON_ABSOLUTE_MAX_DEPTH`] ceiling so that `0` (disabled)
    /// or an enormous configured value cannot turn the scanner's own
    /// per-container state into a memory amplifier.
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,
    /// Maximum entries in any single object.
    #[serde(default = "default_max_object_entries")]
    pub max_object_entries: usize,
    /// Maximum items in any single array.
    #[serde(default = "default_max_array_items")]
    pub max_array_items: usize,
    /// Maximum byte length of any object key, measured over the
    /// encoded representation as it appears in the document.
    #[serde(default = "default_max_key_length")]
    pub max_key_length: usize,
    /// Maximum byte length of any string value, measured over the
    /// encoded representation.
    #[serde(default = "default_max_string_length")]
    pub max_string_length: usize,
    /// Maximum total number of containers (objects plus arrays).
    #[serde(default = "default_max_containers")]
    pub max_containers: usize,
}

impl Default for JsonThreatLimits {
    fn default() -> Self {
        Self {
            enabled: true,
            max_depth: DEFAULT_MAX_DEPTH,
            max_object_entries: DEFAULT_MAX_OBJECT_ENTRIES,
            max_array_items: DEFAULT_MAX_ARRAY_ITEMS,
            max_key_length: DEFAULT_MAX_KEY_LENGTH,
            max_string_length: DEFAULT_MAX_STRING_LENGTH,
            max_containers: DEFAULT_MAX_CONTAINERS,
        }
    }
}

/// Structural limits for XML bodies. Any limit set to `0` disables
/// that single check. DTD refusal is not configurable: a `<!DOCTYPE`
/// declaration is always refused, because entity declarations are the
/// primitive every expansion attack (billion laughs, external
/// entities) is built from and API payloads do not carry DTDs.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XmlThreatLimits {
    /// Master switch for the XML family. Default on.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Maximum element nesting depth; the root element is depth 1.
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,
    /// Maximum total number of elements in the document.
    #[serde(default = "default_max_elements")]
    pub max_elements: usize,
    /// Maximum number of attributes on any single element.
    #[serde(default = "default_max_attributes")]
    pub max_attributes: usize,
}

impl Default for XmlThreatLimits {
    fn default() -> Self {
        Self {
            enabled: true,
            max_depth: DEFAULT_MAX_DEPTH,
            max_elements: DEFAULT_MAX_ELEMENTS,
            max_attributes: DEFAULT_MAX_ATTRIBUTES,
        }
    }
}

/// One violated limit. Carries the stable limit name plus the
/// observed and allowed numbers, and never any body content, so the
/// rejection body and the audit trail cannot echo attacker-controlled
/// bytes back out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyThreatViolation {
    /// Stable name of the violated limit (`json.max_depth`,
    /// `xml.doctype`, ...). This is the string the 400 body, the log
    /// line, and the audit event all carry.
    pub limit: &'static str,
    /// Observed value; `0` for the checks that are refusals rather
    /// than counters (`xml.doctype`, malformed input).
    pub observed: usize,
    /// Configured bound; `0` for refusal-style checks.
    pub allowed: usize,
}

impl BodyThreatViolation {
    fn over(limit: &'static str, observed: usize, allowed: usize) -> Self {
        Self {
            limit,
            observed,
            allowed,
        }
    }

    fn refusal(limit: &'static str) -> Self {
        Self {
            limit,
            observed: 0,
            allowed: 0,
        }
    }

    /// Human-readable detail naming the limit and the numbers. No
    /// body content, ever.
    pub fn detail(&self) -> String {
        match self.limit {
            "xml.doctype" => {
                "xml.doctype: DOCTYPE declarations are refused (entity expansion guard)".to_string()
            }
            "json.malformed" => {
                "json.malformed: body is not well-formed for its declared content type".to_string()
            }
            "xml.malformed" => {
                "xml.malformed: body is not well-formed for its declared content type".to_string()
            }
            _ => format!(
                "{}: observed {} exceeds the configured limit {}",
                self.limit, self.observed, self.allowed
            ),
        }
    }
}

/// Structural JSON/XML body threat limits, evaluated over the
/// buffered request body at the same seam as `request_validator`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BodyThreatProtectionPolicy {
    /// `block` (default) refuses violations with a 400; `tap` logs
    /// and counts without blocking.
    #[serde(default = "default_mode")]
    pub mode: BodyThreatMode,
    /// JSON-family limits. Omitting the block enforces the defaults.
    #[serde(default)]
    pub json: JsonThreatLimits,
    /// XML-family limits. Omitting the block enforces the defaults.
    #[serde(default)]
    pub xml: XmlThreatLimits,
}

fn default_true() -> bool {
    true
}
fn default_mode() -> BodyThreatMode {
    BodyThreatMode::Block
}
fn default_max_depth() -> usize {
    DEFAULT_MAX_DEPTH
}
fn default_max_object_entries() -> usize {
    DEFAULT_MAX_OBJECT_ENTRIES
}
fn default_max_array_items() -> usize {
    DEFAULT_MAX_ARRAY_ITEMS
}
fn default_max_key_length() -> usize {
    DEFAULT_MAX_KEY_LENGTH
}
fn default_max_string_length() -> usize {
    DEFAULT_MAX_STRING_LENGTH
}
fn default_max_containers() -> usize {
    DEFAULT_MAX_CONTAINERS
}
fn default_max_elements() -> usize {
    DEFAULT_MAX_ELEMENTS
}
fn default_max_attributes() -> usize {
    DEFAULT_MAX_ATTRIBUTES
}

/// Resolve a request `Content-Type` header to the body family this
/// policy scans, or `None` when the body must pass untouched.
///
/// JSON: `application/json` or any media type with a `+json`
/// structured-syntax suffix. XML: `application/xml`, `text/xml`, or
/// any `+xml` suffix. Parameters (`; charset=utf-8`) are ignored and
/// matching is case-insensitive. An absent `Content-Type` resolves to
/// `None`: the policy refuses to guess, mirroring the
/// wrong-content-type-should-miss rule.
pub fn body_threat_family(content_type: Option<&str>) -> Option<BodyThreatFamily> {
    let media_type = content_type?.split(';').next()?.trim().to_ascii_lowercase();
    if media_type == "application/json" || media_type.ends_with("+json") {
        return Some(BodyThreatFamily::Json);
    }
    if media_type == "application/xml" || media_type == "text/xml" || media_type.ends_with("+xml") {
        return Some(BodyThreatFamily::Xml);
    }
    None
}

impl BodyThreatProtectionPolicy {
    /// Build from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let mut value = value;
        if let Some(map) = value.as_object_mut() {
            map.remove("type");
        }
        let policy: Self = serde_json::from_value(value)
            .map_err(|e| anyhow::anyhow!("invalid `body_threat_protection` policy: {e}"))?;
        Ok(policy)
    }

    /// True when this policy wants the request body buffered for the
    /// given `Content-Type`: the header resolves to a family and that
    /// family's checks are enabled.
    pub fn wants_body(&self, content_type: Option<&str>) -> bool {
        match body_threat_family(content_type) {
            Some(BodyThreatFamily::Json) => self.json.enabled,
            Some(BodyThreatFamily::Xml) => self.xml.enabled,
            None => false,
        }
    }

    /// Scan a complete buffered body against the configured limits
    /// for its family. `Ok(())` means every enabled check passed.
    pub fn check(&self, family: BodyThreatFamily, body: &[u8]) -> Result<(), BodyThreatViolation> {
        match family {
            BodyThreatFamily::Json if self.json.enabled => scan_json(body, &self.json),
            BodyThreatFamily::Xml if self.xml.enabled => scan_xml(body, &self.xml),
            _ => Ok(()),
        }
    }
}

/// One frame of the JSON scanner's container stack.
enum JsonContainer {
    /// `entries` counts keys seen; `expecting_key` is true between
    /// `{` / `,` and the key string.
    Object { entries: usize, expecting_key: bool },
    /// `items` counts values whose first token was seen at this
    /// level.
    Array { items: usize },
}

/// Iterative structural scan of a JSON document. Counts containers,
/// depth, per-object entries, per-array items, and string lengths in
/// one pass without building a DOM and without recursion, so a
/// hostile depth cannot touch the proxy's stack. Exits on the first
/// violation. Not a full grammar validator: a body that is
/// structurally balanced but semantically invalid JSON is the
/// upstream's problem (`request_validator` and `openapi_validation`
/// own correctness); a body whose *structure* cannot be scanned
/// (unterminated string, unbalanced or mismatched brackets) is
/// refused as `json.malformed`, which is the fail-closed direction.
fn scan_json(body: &[u8], limits: &JsonThreatLimits) -> Result<(), BodyThreatViolation> {
    let mut stack: Vec<JsonContainer> = Vec::new();
    let mut containers_total: usize = 0;
    let mut i: usize = 0;
    let len = body.len();
    // `max_depth: 0` disables the operator-facing check but not the
    // scanner's own memory bound; see [`JSON_ABSOLUTE_MAX_DEPTH`].
    let depth_cap = if limits.max_depth == 0 {
        JSON_ABSOLUTE_MAX_DEPTH
    } else {
        limits.max_depth.min(JSON_ABSOLUTE_MAX_DEPTH)
    };

    while i < len {
        let b = body[i];
        match b {
            b' ' | b'\t' | b'\n' | b'\r' => {
                i += 1;
            }
            b'{' | b'[' => {
                count_array_item(&mut stack, limits)?;
                containers_total += 1;
                if limits.max_containers > 0 && containers_total > limits.max_containers {
                    return Err(BodyThreatViolation::over(
                        "json.max_containers",
                        containers_total,
                        limits.max_containers,
                    ));
                }
                stack.push(if b == b'{' {
                    JsonContainer::Object {
                        entries: 0,
                        expecting_key: true,
                    }
                } else {
                    JsonContainer::Array { items: 0 }
                });
                if stack.len() > depth_cap {
                    return Err(BodyThreatViolation::over(
                        "json.max_depth",
                        stack.len(),
                        depth_cap,
                    ));
                }
                i += 1;
            }
            b'}' => {
                if !matches!(stack.pop(), Some(JsonContainer::Object { .. })) {
                    return Err(BodyThreatViolation::refusal("json.malformed"));
                }
                i += 1;
            }
            b']' => {
                if !matches!(stack.pop(), Some(JsonContainer::Array { .. })) {
                    return Err(BodyThreatViolation::refusal("json.malformed"));
                }
                i += 1;
            }
            b'"' => {
                let start = i + 1;
                let end = scan_json_string(body, start)
                    .ok_or_else(|| BodyThreatViolation::refusal("json.malformed"))?;
                let raw_len = end - start;
                let is_key = matches!(
                    stack.last(),
                    Some(JsonContainer::Object {
                        expecting_key: true,
                        ..
                    })
                );
                if is_key {
                    if limits.max_key_length > 0 && raw_len > limits.max_key_length {
                        return Err(BodyThreatViolation::over(
                            "json.max_key_length",
                            raw_len,
                            limits.max_key_length,
                        ));
                    }
                    if let Some(JsonContainer::Object {
                        entries,
                        expecting_key,
                    }) = stack.last_mut()
                    {
                        *entries += 1;
                        *expecting_key = false;
                        if limits.max_object_entries > 0 && *entries > limits.max_object_entries {
                            let observed = *entries;
                            return Err(BodyThreatViolation::over(
                                "json.max_object_entries",
                                observed,
                                limits.max_object_entries,
                            ));
                        }
                    }
                } else {
                    count_array_item(&mut stack, limits)?;
                    if limits.max_string_length > 0 && raw_len > limits.max_string_length {
                        return Err(BodyThreatViolation::over(
                            "json.max_string_length",
                            raw_len,
                            limits.max_string_length,
                        ));
                    }
                }
                i = end + 1;
            }
            b',' => {
                if let Some(JsonContainer::Object { expecting_key, .. }) = stack.last_mut() {
                    *expecting_key = true;
                }
                i += 1;
            }
            b':' => {
                i += 1;
            }
            _ => {
                // Scalar literal (number, true, false, null). Count it
                // as an array item when it starts one, then skip to
                // the next structural byte.
                count_array_item(&mut stack, limits)?;
                while i < len
                    && !matches!(body[i], b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r')
                {
                    i += 1;
                }
            }
        }
    }

    if stack.is_empty() {
        Ok(())
    } else {
        // Unclosed containers at end of body: refuse rather than
        // trust a document the scanner could not finish.
        Err(BodyThreatViolation::refusal("json.malformed"))
    }
}

/// When the current container is an array, count the value that is
/// about to start and enforce `max_array_items`.
fn count_array_item(
    stack: &mut [JsonContainer],
    limits: &JsonThreatLimits,
) -> Result<(), BodyThreatViolation> {
    if let Some(JsonContainer::Array { items }) = stack.last_mut() {
        *items += 1;
        if limits.max_array_items > 0 && *items > limits.max_array_items {
            return Err(BodyThreatViolation::over(
                "json.max_array_items",
                *items,
                limits.max_array_items,
            ));
        }
    }
    Ok(())
}

/// Find the closing quote of a JSON string whose content starts at
/// `start`. Returns the index of the closing `"`, or `None` when the
/// string never terminates. Escape-aware: `\"` does not close, `\\`
/// does not escape the byte after it.
fn scan_json_string(body: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i < body.len() {
        match body[i] {
            b'\\' => i += 2,
            b'"' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// Structural scan of an XML document with `quick-xml`'s pull
/// reader. Entities are never expanded during event iteration, and
/// any DOCTYPE declaration is refused outright: entity declarations
/// live in the DTD, so refusing the DTD refuses the whole expansion
/// class (billion laughs and external entities alike) without
/// needing to model expansion at all.
fn scan_xml(body: &[u8], limits: &XmlThreatLimits) -> Result<(), BodyThreatViolation> {
    use quick_xml::events::Event;

    let mut reader = quick_xml::Reader::from_reader(body);
    let mut depth: usize = 0;
    let mut elements: usize = 0;

    loop {
        match reader.read_event() {
            Ok(Event::Eof) => {
                // Elements still open at end of input: refuse rather
                // than trust a document the scanner could not finish,
                // mirroring the JSON unclosed-container rule.
                if depth != 0 {
                    return Err(BodyThreatViolation::refusal("xml.malformed"));
                }
                return Ok(());
            }
            Ok(Event::DocType(_)) => {
                return Err(BodyThreatViolation::refusal("xml.doctype"));
            }
            Ok(Event::Start(e)) => {
                depth += 1;
                elements += 1;
                check_xml_element(limits, depth, elements, count_attributes(&e)?)?;
            }
            Ok(Event::Empty(e)) => {
                elements += 1;
                check_xml_element(limits, depth + 1, elements, count_attributes(&e)?)?;
            }
            Ok(Event::End(_)) => {
                depth = depth.saturating_sub(1);
            }
            Ok(_) => {}
            Err(_) => {
                // Parser detail deliberately dropped: quick-xml errors
                // can quote document content, and the refusal must not
                // echo body bytes.
                return Err(BodyThreatViolation::refusal("xml.malformed"));
            }
        }
    }
}

/// Count an element's attributes, refusing the document when the
/// attribute list itself cannot be parsed.
fn count_attributes(e: &quick_xml::events::BytesStart<'_>) -> Result<usize, BodyThreatViolation> {
    let mut count = 0;
    for attr in e.attributes() {
        if attr.is_err() {
            return Err(BodyThreatViolation::refusal("xml.malformed"));
        }
        count += 1;
    }
    Ok(count)
}

/// Enforce the per-element XML limits for one start or empty tag.
fn check_xml_element(
    limits: &XmlThreatLimits,
    depth: usize,
    elements: usize,
    attributes: usize,
) -> Result<(), BodyThreatViolation> {
    if limits.max_depth > 0 && depth > limits.max_depth {
        return Err(BodyThreatViolation::over(
            "xml.max_depth",
            depth,
            limits.max_depth,
        ));
    }
    if limits.max_elements > 0 && elements > limits.max_elements {
        return Err(BodyThreatViolation::over(
            "xml.max_elements",
            elements,
            limits.max_elements,
        ));
    }
    if limits.max_attributes > 0 && attributes > limits.max_attributes {
        return Err(BodyThreatViolation::over(
            "xml.max_attributes",
            attributes,
            limits.max_attributes,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(config: serde_json::Value) -> BodyThreatProtectionPolicy {
        BodyThreatProtectionPolicy::from_config(config).expect("policy compiles")
    }

    /// Build a JSON document nested `depth` containers deep:
    /// `{"a":{"a":...0...}}`.
    fn nested_json(depth: usize) -> Vec<u8> {
        let mut doc = String::new();
        for _ in 0..depth {
            doc.push_str("{\"a\":");
        }
        doc.push('0');
        for _ in 0..depth {
            doc.push('}');
        }
        doc.into_bytes()
    }

    /// Build an XML document nested `depth` elements deep.
    fn nested_xml(depth: usize) -> Vec<u8> {
        let mut doc = String::new();
        for _ in 0..depth {
            doc.push_str("<a>");
        }
        for _ in 0..depth {
            doc.push_str("</a>");
        }
        doc.into_bytes()
    }

    // --- config surface ---

    #[test]
    fn empty_config_gets_safe_defaults_in_block_mode() {
        let p = policy(serde_json::json!({ "type": "body_threat_protection" }));
        assert_eq!(p.mode, BodyThreatMode::Block);
        assert!(p.json.enabled);
        assert_eq!(p.json.max_depth, DEFAULT_MAX_DEPTH);
        assert_eq!(p.json.max_object_entries, DEFAULT_MAX_OBJECT_ENTRIES);
        assert_eq!(p.json.max_array_items, DEFAULT_MAX_ARRAY_ITEMS);
        assert_eq!(p.json.max_key_length, DEFAULT_MAX_KEY_LENGTH);
        assert_eq!(p.json.max_string_length, DEFAULT_MAX_STRING_LENGTH);
        assert_eq!(p.json.max_containers, DEFAULT_MAX_CONTAINERS);
        assert!(p.xml.enabled);
        assert_eq!(p.xml.max_depth, DEFAULT_MAX_DEPTH);
        assert_eq!(p.xml.max_elements, DEFAULT_MAX_ELEMENTS);
        assert_eq!(p.xml.max_attributes, DEFAULT_MAX_ATTRIBUTES);
    }

    #[test]
    fn unknown_config_keys_are_refused() {
        let err = BodyThreatProtectionPolicy::from_config(serde_json::json!({
            "json": { "max_dpeth": 3 }
        }))
        .expect_err("typo must not silently disable a limit");
        assert!(err.to_string().contains("body_threat_protection"));
    }

    // --- content-type gate ---

    #[test]
    fn content_type_gate_resolves_families_and_passes_others() {
        assert_eq!(
            body_threat_family(Some("application/json")),
            Some(BodyThreatFamily::Json)
        );
        assert_eq!(
            body_threat_family(Some("Application/JSON; charset=utf-8")),
            Some(BodyThreatFamily::Json)
        );
        assert_eq!(
            body_threat_family(Some("application/hal+json")),
            Some(BodyThreatFamily::Json)
        );
        assert_eq!(
            body_threat_family(Some("application/xml")),
            Some(BodyThreatFamily::Xml)
        );
        assert_eq!(
            body_threat_family(Some("text/xml")),
            Some(BodyThreatFamily::Xml)
        );
        assert_eq!(
            body_threat_family(Some("application/soap+xml; action=\"x\"")),
            Some(BodyThreatFamily::Xml)
        );
        // Pass untouched: not a JSON/XML family, or no declared type.
        assert_eq!(body_threat_family(Some("text/plain")), None);
        assert_eq!(body_threat_family(Some("multipart/form-data")), None);
        assert_eq!(body_threat_family(Some("application/octet-stream")), None);
        assert_eq!(body_threat_family(None), None);
    }

    #[test]
    fn wants_body_respects_family_switches() {
        let p = policy(serde_json::json!({ "json": { "enabled": false } }));
        assert!(!p.wants_body(Some("application/json")));
        assert!(p.wants_body(Some("application/xml")));
        assert!(!p.wants_body(Some("text/plain")));
        assert!(!p.wants_body(None));
    }

    // --- JSON: each limit red at limit+1, green at the limit ---

    #[test]
    fn json_depth_over_limit_refused_naming_the_limit() {
        let p = policy(serde_json::json!({ "json": { "max_depth": 8 } }));
        let violation = p
            .check(BodyThreatFamily::Json, &nested_json(9))
            .expect_err("depth 9 must refuse at limit 8");
        assert_eq!(violation.limit, "json.max_depth");
        assert_eq!(violation.observed, 9);
        assert_eq!(violation.allowed, 8);
    }

    #[test]
    fn json_depth_at_limit_passes() {
        let p = policy(serde_json::json!({ "json": { "max_depth": 8 } }));
        assert_eq!(p.check(BodyThreatFamily::Json, &nested_json(8)), Ok(()));
    }

    #[test]
    fn json_depth_beyond_serde_recursion_limit_still_names_depth() {
        // A 200-level document would fail a serde_json parse with a
        // recursion error and be misreported as malformed. The
        // iterative scanner must name the depth limit instead.
        let p = policy(serde_json::json!({ "json": { "max_depth": 64 } }));
        let violation = p
            .check(BodyThreatFamily::Json, &nested_json(200))
            .expect_err("depth 200 must refuse");
        assert_eq!(violation.limit, "json.max_depth");
        assert_eq!(violation.observed, 65);
    }

    #[test]
    fn json_object_entries_over_limit_refused_at_limit_passes() {
        let p = policy(serde_json::json!({ "json": { "max_object_entries": 3 } }));
        let at = br#"{"a":1,"b":2,"c":3}"#;
        assert_eq!(p.check(BodyThreatFamily::Json, at), Ok(()));
        let over = br#"{"a":1,"b":2,"c":3,"d":4}"#;
        let violation = p
            .check(BodyThreatFamily::Json, over)
            .expect_err("4 entries must refuse at limit 3");
        assert_eq!(violation.limit, "json.max_object_entries");
        assert_eq!((violation.observed, violation.allowed), (4, 3));
    }

    #[test]
    fn json_array_items_over_limit_refused_at_limit_passes() {
        let p = policy(serde_json::json!({ "json": { "max_array_items": 3 } }));
        assert_eq!(p.check(BodyThreatFamily::Json, b"[1,2,3]"), Ok(()));
        let violation = p
            .check(BodyThreatFamily::Json, b"[1,2,3,4]")
            .expect_err("4 items must refuse at limit 3");
        assert_eq!(violation.limit, "json.max_array_items");
        assert_eq!((violation.observed, violation.allowed), (4, 3));
    }

    #[test]
    fn json_nested_containers_do_not_inflate_parent_array_count() {
        let p = policy(serde_json::json!({ "json": { "max_array_items": 2 } }));
        // Two items, each itself a container with content: the inner
        // structure must not count against the outer array.
        assert_eq!(
            p.check(BodyThreatFamily::Json, br#"[{"a":[1,2]},{"b":[3,4]}]"#),
            Ok(())
        );
    }

    #[test]
    fn json_key_length_over_limit_refused_at_limit_passes() {
        let p = policy(serde_json::json!({ "json": { "max_key_length": 8 } }));
        let at = format!("{{\"{}\":1}}", "k".repeat(8)).into_bytes();
        assert_eq!(p.check(BodyThreatFamily::Json, &at), Ok(()));
        let over = format!("{{\"{}\":1}}", "k".repeat(9)).into_bytes();
        let violation = p
            .check(BodyThreatFamily::Json, &over)
            .expect_err("9-byte key must refuse at limit 8");
        assert_eq!(violation.limit, "json.max_key_length");
        assert_eq!((violation.observed, violation.allowed), (9, 8));
    }

    #[test]
    fn json_string_length_over_limit_refused_at_limit_passes() {
        let p = policy(serde_json::json!({ "json": { "max_string_length": 16 } }));
        let at = format!("{{\"k\":\"{}\"}}", "s".repeat(16)).into_bytes();
        assert_eq!(p.check(BodyThreatFamily::Json, &at), Ok(()));
        let over = format!("{{\"k\":\"{}\"}}", "s".repeat(17)).into_bytes();
        let violation = p
            .check(BodyThreatFamily::Json, &over)
            .expect_err("17-byte string must refuse at limit 16");
        assert_eq!(violation.limit, "json.max_string_length");
        assert_eq!((violation.observed, violation.allowed), (17, 16));
    }

    #[test]
    fn json_escaped_quote_does_not_end_a_string() {
        let p = policy(serde_json::json!({ "json": { "max_string_length": 4 } }));
        // Content is 6 raw bytes: ab\"cd. The escaped quote must not
        // terminate the scan early and hide the overage.
        let doc = br#"{"k":"ab\"cd"}"#;
        let violation = p
            .check(BodyThreatFamily::Json, doc)
            .expect_err("escaped quote must not end the string early");
        assert_eq!(violation.limit, "json.max_string_length");
    }

    #[test]
    fn json_container_total_over_limit_refused_at_limit_passes() {
        let p = policy(serde_json::json!({ "json": { "max_containers": 3 } }));
        assert_eq!(p.check(BodyThreatFamily::Json, br#"[[],[]]"#), Ok(())); // 3 containers
        let violation = p
            .check(BodyThreatFamily::Json, br#"[[],[],[]]"#) // 4 containers
            .expect_err("4 containers must refuse at limit 3");
        assert_eq!(violation.limit, "json.max_containers");
        assert_eq!((violation.observed, violation.allowed), (4, 3));
    }

    #[test]
    fn json_malformed_is_refused_fail_closed() {
        let p = policy(serde_json::json!({}));
        for doc in [
            &br#"{"a": [1, 2}"#[..],        // mismatched close
            &br#"{"a": "unterminated"#[..], // unterminated string
            &br#"[1, 2"#[..],               // unclosed container
        ] {
            let violation = p
                .check(BodyThreatFamily::Json, doc)
                .expect_err("structurally broken body must refuse");
            assert_eq!(violation.limit, "json.malformed");
        }
    }

    #[test]
    fn json_zero_disables_a_single_check() {
        let p = policy(serde_json::json!({ "json": { "max_depth": 0, "max_containers": 0 } }));
        assert_eq!(p.check(BodyThreatFamily::Json, &nested_json(300)), Ok(()));
    }

    #[test]
    fn json_absolute_depth_ceiling_holds_even_with_checks_disabled() {
        // With max_depth and max_containers both disabled, the
        // scanner's own per-container state stack is the resource
        // under attack; the absolute ceiling is what bounds it.
        let p = policy(serde_json::json!({
            "json": { "max_depth": 0, "max_containers": 0 }
        }));
        let violation = p
            .check(
                BodyThreatFamily::Json,
                &nested_json(JSON_ABSOLUTE_MAX_DEPTH + 1),
            )
            .expect_err("the absolute depth ceiling must hold");
        assert_eq!(violation.limit, "json.max_depth");
        assert_eq!(violation.allowed, JSON_ABSOLUTE_MAX_DEPTH);
    }

    #[test]
    fn json_family_disabled_passes_everything() {
        let p = policy(serde_json::json!({
            "json": { "enabled": false, "max_depth": 1 }
        }));
        assert_eq!(p.check(BodyThreatFamily::Json, &nested_json(50)), Ok(()));
    }

    #[test]
    fn json_violation_detail_names_limit_and_numbers_only() {
        let p = policy(serde_json::json!({ "json": { "max_string_length": 4 } }));
        let secret_doc = br#"{"k":"SECRET-VALUE"}"#;
        let violation = p.check(BodyThreatFamily::Json, secret_doc).unwrap_err();
        let detail = violation.detail();
        assert!(detail.contains("json.max_string_length"));
        assert!(
            !detail.contains("SECRET"),
            "refusal detail must never echo body content: {detail}"
        );
    }

    // --- XML ---

    #[test]
    fn xml_depth_over_limit_refused_at_limit_passes() {
        let p = policy(serde_json::json!({ "xml": { "max_depth": 8 } }));
        assert_eq!(p.check(BodyThreatFamily::Xml, &nested_xml(8)), Ok(()));
        let violation = p
            .check(BodyThreatFamily::Xml, &nested_xml(9))
            .expect_err("depth 9 must refuse at limit 8");
        assert_eq!(violation.limit, "xml.max_depth");
        assert_eq!((violation.observed, violation.allowed), (9, 8));
    }

    #[test]
    fn xml_element_count_over_limit_refused_at_limit_passes() {
        let p = policy(serde_json::json!({ "xml": { "max_elements": 4 } }));
        assert_eq!(
            p.check(BodyThreatFamily::Xml, b"<r><a/><b/><c/></r>"),
            Ok(())
        );
        let violation = p
            .check(BodyThreatFamily::Xml, b"<r><a/><b/><c/><d/></r>")
            .expect_err("5 elements must refuse at limit 4");
        assert_eq!(violation.limit, "xml.max_elements");
        assert_eq!((violation.observed, violation.allowed), (5, 4));
    }

    #[test]
    fn xml_attribute_count_over_limit_refused_at_limit_passes() {
        let p = policy(serde_json::json!({ "xml": { "max_attributes": 2 } }));
        assert_eq!(
            p.check(BodyThreatFamily::Xml, br#"<r a="1" b="2"/>"#),
            Ok(())
        );
        let violation = p
            .check(BodyThreatFamily::Xml, br#"<r a="1" b="2" c="3"/>"#)
            .expect_err("3 attributes must refuse at limit 2");
        assert_eq!(violation.limit, "xml.max_attributes");
        assert_eq!((violation.observed, violation.allowed), (3, 2));
    }

    #[test]
    fn xml_doctype_refused_outright_billion_laughs() {
        let p = policy(serde_json::json!({}));
        // The classic billion-laughs prefix. The scan must refuse at
        // the DOCTYPE without ever considering the entity bodies.
        let doc = br#"<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<lolz>&lol2;</lolz>"#;
        let violation = p
            .check(BodyThreatFamily::Xml, doc)
            .expect_err("DOCTYPE with entity declarations must refuse");
        assert_eq!(violation.limit, "xml.doctype");
        assert!(violation.detail().contains("entity expansion"));
    }

    #[test]
    fn xml_bare_doctype_refused_even_without_entities() {
        let p = policy(serde_json::json!({}));
        let doc = b"<!DOCTYPE note SYSTEM \"http://attacker.example/evil.dtd\"><note/>";
        let violation = p
            .check(BodyThreatFamily::Xml, doc)
            .expect_err("external DTD subset must refuse");
        assert_eq!(violation.limit, "xml.doctype");
    }

    #[test]
    fn xml_predefined_entities_and_char_refs_pass() {
        // Without a DTD there is nothing to expand: the five
        // predefined entities and numeric character references are
        // 1:1 and legitimate.
        let p = policy(serde_json::json!({}));
        let doc = b"<note>fish &amp; chips &#38; more</note>";
        assert_eq!(p.check(BodyThreatFamily::Xml, doc), Ok(()));
    }

    #[test]
    fn xml_within_all_defaults_passes() {
        let p = policy(serde_json::json!({}));
        let doc = br#"<?xml version="1.0" encoding="utf-8"?>
<order id="42"><item sku="a-1" qty="2">widget</item></order>"#;
        assert_eq!(p.check(BodyThreatFamily::Xml, doc), Ok(()));
    }

    #[test]
    fn xml_malformed_is_refused_fail_closed() {
        let p = policy(serde_json::json!({}));
        for doc in [
            &b"<a><b></a></b>"[..], // mismatched end tags
            &b"<a><b>"[..],         // unclosed at end of input
        ] {
            let violation = p
                .check(BodyThreatFamily::Xml, doc)
                .expect_err("structurally broken XML must refuse");
            assert_eq!(violation.limit, "xml.malformed");
        }
    }

    #[test]
    fn xml_family_disabled_passes_everything() {
        let p = policy(serde_json::json!({
            "xml": { "enabled": false, "max_depth": 1 }
        }));
        assert_eq!(p.check(BodyThreatFamily::Xml, &nested_xml(50)), Ok(()));
    }

    #[test]
    fn tap_mode_parses_from_config() {
        let p = policy(serde_json::json!({ "mode": "tap" }));
        assert_eq!(p.mode, BodyThreatMode::Tap);
    }
}

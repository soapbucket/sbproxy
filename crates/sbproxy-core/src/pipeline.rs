//! Compiled pipeline: config + instantiated module enums + optional hooks.
//!
//! [`CompiledPipeline`] bridges the gap between `sbproxy-config` (which stores
//! JSON `serde_json::Value` blobs) and `sbproxy-modules` (which defines typed
//! `Action` / `Auth` / `Policy` enums). It holds a `CompiledConfig` alongside
//! parallel vecs of compiled module instances indexed by origin position:
//! index `N` in `actions` corresponds to index `N` in `config.origins`.
//!
//! In addition to the compiled modules, a `CompiledPipeline` owns:
//! * an optional shared `CacheStore` (from `sbproxy-cache`) for the
//!   response cache: whichever backend `proxy.response_cache_store`
//!   selects, or, when that block is absent, Redis if `config.l2_store`
//!   is set and an in-memory LRU otherwise,
//! * an optional [`Hooks`](crate::hooks::Hooks) bundle of traits populated by a
//!   [`PipelineLifecycleHook`](crate::hooks::PipelineLifecycleHook) when registered.
//!
//! This struct lives in `sbproxy-core` to avoid a circular dependency:
//! config -> modules -> config would be circular, but core depends on both.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::builtin_enforcers::{compile_builtin_enforcers, CompiledEnforcer};
use crate::extension_inventory::{
    compiled_inventory, reserved_extension_hook_names, CompiledExtensionAttachments,
};
use crate::router::HostRouter;
use compact_str::CompactString;
use sbproxy_cache::{
    CacheReserveBackend, CacheStore, EncryptedCacheStore, FileCacheConfig, FileCacheStore,
    FsReserve, MemcachedConfig, MemcachedStore, MemoryCacheStore, MemoryReserve, RedisCacheStore,
    RedisReserve,
};
use sbproxy_config::{CompiledConfig, Parameter, RequestModifierConfig};
use sbproxy_extension::bundle::{BundleRegistry, DynamicBundleRegistry};
use sbproxy_modules::compile::{
    compile_action_for_origin_for_validation_with_registry,
    compile_action_for_origin_with_registry, compile_action_with_registry, compile_auth,
    compile_auth_with_registry, compile_policy, compile_policy_with_registry, compile_transform,
    compile_transform_with_registry,
};
use sbproxy_modules::transform::{CompiledTransform, TransformConfig};
use sbproxy_modules::{Action, Auth, BotDetection, Policy, ThreatProtection};
use sbproxy_plugin::{ExtensionInventorySnapshot, ExtensionScopeMode};

// --- Forward Rule types ---

/// One parsed segment of a `Template` path matcher.
///
/// Literal segments must match exactly. `Param` segments capture a single
/// path segment under the given name, optionally validated against a regex
/// constraint. `CatchAll` captures the remainder of the path (all segments
/// after this point) and may only appear as the final segment.
#[derive(Debug)]
pub enum TemplateSegment {
    /// A literal path segment that must match exactly.
    Literal(String),
    /// A named `{name}` segment with an optional regex constraint
    /// (e.g. `{id:[0-9]+}`).
    Param {
        /// The captured parameter name.
        name: String,
        /// Optional per-segment regex constraint anchored at both ends.
        constraint: Option<regex::Regex>,
    },
    /// A `{*name}` catch-all segment that captures the rest of the path.
    /// Only valid as the final segment.
    CatchAll(String),
}

/// A compiled OpenAPI-style path template (e.g. `/users/{id}/posts/{*rest}`).
///
/// Matching walks the segments in O(n) where n is the number of path
/// segments; per-segment regex constraints are only evaluated when the
/// segment is explicitly constrained, so unconstrained templates pay no
/// regex cost on the hot path.
#[derive(Debug)]
pub struct PathTemplate {
    /// Original template string (preserved for OpenAPI emission, debug
    /// logging, and error messages).
    pub raw: String,
    /// Parsed segment list. `CatchAll` may only appear as the final entry.
    pub segments: Vec<TemplateSegment>,
}

impl PathTemplate {
    /// Compile a template string into a [`PathTemplate`].
    ///
    /// Errors when:
    /// - a segment uses unbalanced braces
    /// - a constraint regex fails to compile
    /// - a `{*name}` catch-all is not the final segment
    pub fn compile(template: &str) -> anyhow::Result<Self> {
        let raw = template.to_string();
        let trimmed = template.strip_prefix('/').unwrap_or(template);
        let parts: Vec<&str> = if trimmed.is_empty() {
            Vec::new()
        } else {
            trimmed.split('/').collect()
        };
        let mut segments = Vec::with_capacity(parts.len());
        let last_idx = parts.len().saturating_sub(1);
        for (i, part) in parts.iter().enumerate() {
            let seg = parse_template_segment(part, i == last_idx)?;
            if matches!(seg, TemplateSegment::CatchAll(_)) && i != last_idx {
                anyhow::bail!("catch-all segment must be last in template '{}'", template);
            }
            segments.push(seg);
        }
        Ok(PathTemplate { raw, segments })
    }

    /// Match the given path against this template, returning captured params
    /// on a successful match.
    pub fn match_path(&self, path: &str) -> Option<HashMap<String, String>> {
        let trimmed = path.strip_prefix('/').unwrap_or(path);
        // An empty path == "/" -> zero parts. Splitting an empty string yields
        // [""] which would break length compares, so guard explicitly.
        let parts: Vec<&str> = if trimmed.is_empty() {
            Vec::new()
        } else {
            trimmed.split('/').collect()
        };

        // Catch-all loosens the length constraint to ">= segments-1" since
        // the final segment soaks up everything else. Without one we need
        // an exact length match.
        let has_catch_all = matches!(self.segments.last(), Some(TemplateSegment::CatchAll(_)));
        if has_catch_all {
            if parts.len() < self.segments.len() - 1 {
                return None;
            }
        } else if parts.len() != self.segments.len() {
            return None;
        }

        let mut captured: HashMap<String, String> = HashMap::new();
        for (idx, seg) in self.segments.iter().enumerate() {
            match seg {
                TemplateSegment::Literal(lit) => {
                    if parts.get(idx).copied() != Some(lit.as_str()) {
                        return None;
                    }
                }
                TemplateSegment::Param { name, constraint } => {
                    let value = parts.get(idx).copied()?;
                    if let Some(re) = constraint {
                        if !re.is_match(value) {
                            return None;
                        }
                    }
                    captured.insert(name.clone(), value.to_string());
                }
                TemplateSegment::CatchAll(name) => {
                    // Splice the remainder back together with '/' so the
                    // captured value reads naturally (e.g. "css/site.css"
                    // not ["css", "site.css"]).
                    let rest = parts[idx..].join("/");
                    captured.insert(name.clone(), rest);
                    break;
                }
            }
        }
        Some(captured)
    }
}

fn parse_template_segment(part: &str, _is_last: bool) -> anyhow::Result<TemplateSegment> {
    // Literals: no leading '{' means we treat the whole segment as a literal.
    // Mid-segment '{' is rejected as malformed since we do not support
    // mixed-content segments (e.g. "users-{id}") - this keeps emission
    // unambiguous and lines up with OpenAPI 3.0 path-template semantics.
    if !part.starts_with('{') {
        if part.contains('{') || part.contains('}') {
            anyhow::bail!("mixed literal/param segments are not supported: '{}'", part);
        }
        return Ok(TemplateSegment::Literal(part.to_string()));
    }
    let inner = part
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .ok_or_else(|| {
            anyhow::anyhow!("malformed template segment '{}': unbalanced braces", part)
        })?;

    // Catch-all: leading '*' marks the rest of the path.
    if let Some(name) = inner.strip_prefix('*') {
        if name.is_empty() {
            anyhow::bail!("catch-all segment '{}' missing name", part);
        }
        return Ok(TemplateSegment::CatchAll(name.to_string()));
    }

    // Named param with optional constraint: split on the first ':'.
    let (name, constraint) = match inner.split_once(':') {
        Some((n, pat)) => {
            // Anchor the regex at both ends so a constraint like `[0-9]+`
            // doesn't match a path segment that merely *contains* digits.
            let anchored = format!("^(?:{})$", pat);
            let re = regex::Regex::new(&anchored).map_err(|e| {
                anyhow::anyhow!("invalid constraint regex in segment '{}': {}", part, e)
            })?;
            (n, Some(re))
        }
        None => (inner, None),
    };
    if name.is_empty() {
        anyhow::bail!("named segment '{}' missing param name", part);
    }
    Ok(TemplateSegment::Param {
        name: name.to_string(),
        constraint,
    })
}

/// A single path-matching rule within a forward rule.
///
/// Variants are ordered cheapest-first on the hot path. `Prefix` and
/// `Exact` are byte comparisons. `Template` walks segments and only
/// evaluates regex when a segment is explicitly constrained. `Regex`
/// pays the full regex cost per match and is the escape hatch for
/// patterns the template syntax cannot express.
pub enum PathMatch {
    /// Matches if the request path starts with this prefix.
    Prefix(String),
    /// Matches if the request path equals this exactly.
    Exact(String),
    /// OpenAPI-style template (named segments, catch-all, optional
    /// per-segment regex constraints).
    Template(PathTemplate),
    /// Whole-path regex. Named captures are exposed as path params.
    Regex(regex::Regex),
}

impl PathMatch {
    /// Check whether the given request path matches this rule.
    ///
    /// Retained for callers that only need the boolean. Prefer
    /// [`Self::match_with_params`] to also surface captured path params
    /// on the request context.
    pub fn matches(&self, path: &str) -> bool {
        self.match_with_params(path).is_some()
    }

    /// Match the path and return any captured params.
    ///
    /// Returns `Some(map)` on a successful match, where `map` is empty
    /// for `Prefix`/`Exact` rules (which capture nothing). Returns
    /// `None` when the path does not match.
    pub fn match_with_params(&self, path: &str) -> Option<HashMap<String, String>> {
        match self {
            PathMatch::Prefix(p) => {
                if path.starts_with(p.as_str()) {
                    Some(HashMap::new())
                } else {
                    None
                }
            }
            PathMatch::Exact(e) => {
                if path == e.as_str() {
                    Some(HashMap::new())
                } else {
                    None
                }
            }
            PathMatch::Template(t) => t.match_path(path),
            PathMatch::Regex(re) => {
                let caps = re.captures(path)?;
                let mut map = HashMap::new();
                for name in re.capture_names().flatten() {
                    if let Some(m) = caps.name(name) {
                        map.insert(name.to_string(), m.as_str().to_string());
                    }
                }
                Some(map)
            }
        }
    }
}

/// Match a request header by exact value or value prefix.
///
/// Header name lookup is case-insensitive (per RFC 7230). Value comparison
/// is case-sensitive. Choose `Equals` for exact match, `Prefix` for value
/// prefix.
pub enum HeaderMatch {
    /// Header must exist and its value must equal `value` exactly.
    Equals {
        /// Header name, precompiled at config-load time (WOR-1698) so
        /// the request path does a constant-time lookup rather than
        /// re-deriving the name from a `String` on every match.
        name: http::HeaderName,
        /// Expected value.
        value: String,
    },
    /// Header must exist and its value must start with `prefix`.
    Prefix {
        /// Header name, precompiled at config-load time (WOR-1698).
        name: http::HeaderName,
        /// Required value prefix.
        prefix: String,
    },
}

impl HeaderMatch {
    /// Test the matcher against a Pingora-style header map.
    pub fn matches(&self, headers: &http::HeaderMap) -> bool {
        match self {
            HeaderMatch::Equals { name, value } => headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(|got| got == value)
                .unwrap_or(false),
            HeaderMatch::Prefix { name, prefix } => headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(|got| got.starts_with(prefix.as_str()))
                .unwrap_or(false),
        }
    }
}

/// Match a query string parameter by exact value or by mere presence.
pub enum QueryMatch {
    /// Parameter must be present and equal `value`.
    Equals {
        /// Query parameter name (case-sensitive).
        name: String,
        /// Expected value.
        value: String,
    },
    /// Parameter must merely be present.
    Present {
        /// Query parameter name (case-sensitive).
        name: String,
    },
}

impl QueryMatch {
    /// Test the matcher against a raw URI query string (e.g. `a=1&b=2`).
    pub fn matches(&self, query: Option<&str>) -> bool {
        let Some(q) = query else {
            return false;
        };
        for pair in q.split('&') {
            let mut it = pair.splitn(2, '=');
            let key = it.next().unwrap_or("");
            let val = it.next().unwrap_or("");
            match self {
                QueryMatch::Equals { name, value } => {
                    if key == name && val == value {
                        return true;
                    }
                }
                QueryMatch::Present { name } => {
                    if key == name {
                        return true;
                    }
                }
            }
        }
        false
    }
}

/// Match the request method against a precompiled set of allowed methods.
///
/// Methods are parsed and uppercased at config-load time, so the request
/// path compares `http::Method` values directly; for the standard methods
/// that is a comparison against interned statics, the cheapest test any
/// matcher in the entry performs.
pub struct MethodMatch {
    /// Allowed methods, uppercased and parsed at config-load time.
    pub methods: smallvec::SmallVec<[http::Method; 4]>,
}

impl MethodMatch {
    /// Test the matcher against the request method.
    #[must_use]
    pub fn matches(&self, method: &http::Method) -> bool {
        self.methods.contains(method)
    }
}

/// The comparison a [`BodyMatch`] applies to the value its pointer resolved to.
pub enum BodyCompare {
    /// The resolved value, rendered as text, must equal this exactly.
    Equals(String),
    /// The resolved value, rendered as text, must start with this.
    Prefix(String),
    /// The pointer must resolve to any JSON value at all. An object or an
    /// array counts, which is how `pointer: /tools` asks whether the request
    /// declares tools without naming one.
    Present,
}

/// Match a field inside a JSON request body, addressed by JSON Pointer.
///
/// This is the only matcher whose input is not already in hand when routing
/// starts, so it is the only one with a size limit and the only one that can
/// be asked to decide with nothing to decide on. Both cases resolve the same
/// way: the matcher misses. It never fails the request, because a body the
/// proxy could not read is not evidence that the operator's rule should have
/// fired, and it is not evidence of a client error either.
///
/// [`Self::matches`] therefore returns `false` for a body that was never
/// buffered, a body past `max_bytes`, a body that is not JSON, a body that
/// does not parse, a pointer that resolves to nothing, and a container
/// compared against a configured string. Routing then continues to the next
/// entry, the next rule, and finally the origin's own action, which is the
/// header-only route the request would have taken anyway.
pub struct BodyMatch {
    /// Decoded RFC 6901 reference tokens, split once at config-load time so
    /// the request path never re-parses the pointer string.
    pub pointer: Vec<String>,
    /// The comparison to apply to the resolved value.
    pub compare: BodyCompare,
    /// Largest body this matcher reads, in bytes. Never above
    /// [`sbproxy_config::BODY_MATCH_MAX_BYTES`].
    pub max_bytes: usize,
}

impl BodyMatch {
    /// Test the matcher against the buffered request body.
    ///
    /// `body` is `None` when the request had no body, when the origin's
    /// buffering was skipped because the declared `Content-Length` already
    /// exceeded the cap, or when the replay buffer filled before the body
    /// ended. All three are misses.
    #[must_use]
    pub fn matches(&self, body: Option<&[u8]>) -> bool {
        let Some(bytes) = body else {
            return false;
        };
        if bytes.len() > self.max_bytes {
            return false;
        }
        let Some(target) = crate::json_pointer::resolve(bytes, &self.pointer) else {
            return false;
        };
        match (&self.compare, target) {
            (BodyCompare::Present, _) => true,
            (BodyCompare::Equals(expected), crate::json_pointer::PointerTarget::Scalar(got)) => {
                got == *expected
            }
            (BodyCompare::Prefix(expected), crate::json_pointer::PointerTarget::Scalar(got)) => {
                got.starts_with(expected.as_str())
            }
            // A configured string cannot equal an object or an array.
            (
                BodyCompare::Equals(_) | BodyCompare::Prefix(_),
                crate::json_pointer::PointerTarget::Container,
            ) => false,
        }
    }
}

/// One AND-grouped match entry inside a forward rule's `rules:` list.
///
/// Every present matcher (`method`, `path`, `header`, `query`, `body`) must
/// succeed for the entry to fire. The enclosing list of entries is ORed: any
/// matching entry triggers the rule.
pub struct MatcherEntry {
    /// HTTP method matcher. Evaluated first because an `http::Method`
    /// comparison is the cheapest test in the entry and captures nothing.
    pub method: Option<MethodMatch>,
    /// Path matcher (any of prefix / exact / template / regex).
    pub path: Option<PathMatch>,
    /// Header matcher.
    pub header: Option<HeaderMatch>,
    /// Query parameter matcher.
    pub query: Option<QueryMatch>,
    /// JSON request-body field matcher. Evaluated last because it is the
    /// only matcher that reads bytes the request phase had to buffer.
    pub body: Option<BodyMatch>,
    /// CEL predicate ANDed with the matchers above, evaluated last.
    ///
    /// `Arc` because a compiled entry is cloned per config generation
    /// and the program is immutable once compiled.
    pub when: Option<std::sync::Arc<sbproxy_extension::cel::CompiledCel>>,
}

impl MatcherEntry {
    /// Evaluate this entry against the incoming request, with no body.
    ///
    /// Callers that only need to know which action a request will land on,
    /// and that run before or without body buffering, use this.
    ///
    /// An entry carrying a body matcher or a `when` predicate cannot pass
    /// here, because neither input is available yet. That makes a `None`
    /// from this method ambiguous: it means "no rule matched" *or* "a rule
    /// could not be evaluated". Callers previewing routing should use
    /// [`preview_forward_rules`] instead, which walks the rules in
    /// priority order and says explicitly when the answer is unknowable.
    /// Guessing the base action for a rule that routes elsewhere is how a
    /// stale-while-revalidate write lands in the wrong cache entry.
    pub fn match_request(
        &self,
        method: &http::Method,
        path: &str,
        query: Option<&str>,
        headers: &http::HeaderMap,
    ) -> Option<HashMap<String, String>> {
        self.match_request_with_body(method, path, query, headers, None, None)
    }

    /// Evaluate this entry against the incoming request and its buffered body.
    ///
    /// Returns the captured path params (possibly empty) when every present
    /// matcher passes. Returns `None` when any present matcher fails or when
    /// the entry has no matchers at all.
    ///
    /// `body` is `Some` only for origins that declare a body matcher; every
    /// other origin passes `None` and never pays for buffering or parsing.
    pub fn match_request_with_body(
        &self,
        method: &http::Method,
        path: &str,
        query: Option<&str>,
        headers: &http::HeaderMap,
        body: Option<&[u8]>,
        cel_ctx: Option<&sbproxy_extension::cel::CelContext>,
    ) -> Option<HashMap<String, String>> {
        let any_present = self.method.is_some()
            || self.path.is_some()
            || self.header.is_some()
            || self.query.is_some()
            || self.body.is_some()
            || self.when.is_some();
        if !any_present {
            return None;
        }
        // Method first: it captures nothing and is the cheapest test in the
        // entry, so a wrong-method request pays for nothing else.
        if let Some(m) = &self.method {
            if !m.matches(method) {
                return None;
            }
        }
        let captured = if let Some(p) = &self.path {
            p.match_with_params(path)?
        } else {
            HashMap::new()
        };
        if let Some(h) = &self.header {
            if !h.matches(headers) {
                return None;
            }
        }
        if let Some(q) = &self.query {
            if !q.matches(query) {
                return None;
            }
        }
        if let Some(b) = &self.body {
            if !b.matches(body) {
                return None;
            }
        }
        // Last, and only once every structured matcher has passed, so a
        // rule that fails a cheap path check never pays for an
        // evaluation.
        if let Some(predicate) = &self.when {
            let Some(cel_ctx) = cel_ctx else {
                // The caller builds the context only when some entry
                // declares a `when`. Reaching here without one means the
                // rule cannot be evaluated, and a routing rule that
                // cannot be evaluated must not match: silently routing
                // on the structured half alone would send traffic
                // somewhere the operator gated.
                return None;
            };
            match predicate.eval_bool(cel_ctx) {
                Ok(true) => {}
                Ok(false) => return None,
                Err(error) => {
                    // Fail closed for the same reason. A predicate that
                    // errors has not said yes.
                    tracing::warn!(
                        site = %predicate.site(),
                        %error,
                        "forward rule `when` failed to evaluate; rule did not match"
                    );
                    return None;
                }
            }
        }
        Some(captured)
    }
}

/// What a preview of one matcher entry could establish without a body
/// or a CEL context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatcherPreview {
    /// Every present matcher was evaluable and at least one failed, so
    /// this entry cannot fire no matter what the body or predicate say.
    NoMatch,
    /// Every present matcher was evaluable and all passed.
    Match,
    /// The evaluable matchers passed, but the entry also carries a
    /// `body:` or `when:` this preview cannot answer, so whether it
    /// fires is unknowable here.
    Unevaluable,
}

impl MatcherEntry {
    /// Preview this entry against the request head alone.
    ///
    /// The distinction between [`MatcherPreview::NoMatch`] and
    /// [`MatcherPreview::Unevaluable`] is what lets a rule walk stay
    /// cheap: an entry whose *path already fails* cannot match at full
    /// evaluation either, whatever its predicate says, so it does not
    /// poison the preview for the rules after it.
    #[must_use]
    pub fn preview(
        &self,
        method: &http::Method,
        path: &str,
        query: Option<&str>,
        headers: &http::HeaderMap,
    ) -> MatcherPreview {
        let any_present = self.method.is_some()
            || self.path.is_some()
            || self.header.is_some()
            || self.query.is_some()
            || self.body.is_some()
            || self.when.is_some();
        if !any_present {
            return MatcherPreview::NoMatch;
        }
        if let Some(m) = &self.method {
            if !m.matches(method) {
                return MatcherPreview::NoMatch;
            }
        }
        if let Some(p) = &self.path {
            if p.match_with_params(path).is_none() {
                return MatcherPreview::NoMatch;
            }
        }
        if let Some(h) = &self.header {
            if !h.matches(headers) {
                return MatcherPreview::NoMatch;
            }
        }
        if let Some(q) = &self.query {
            if !q.matches(query) {
                return MatcherPreview::NoMatch;
            }
        }
        if self.body.is_some() || self.when.is_some() {
            return MatcherPreview::Unevaluable;
        }
        MatcherPreview::Match
    }
}

/// What a preview of a whole forward-rule set could establish.
///
/// No `Debug`/`PartialEq`: `CompiledForwardRule` derives neither, and
/// callers match on the shape rather than compare values.
#[derive(Clone, Copy)]
pub enum ForwardRulePreview<'a> {
    /// The first rule that can fire is fully evaluable and matched.
    Matched(&'a CompiledForwardRule),
    /// No rule can fire on this request head.
    NoMatch,
    /// Before any evaluable rule matched, a rule was reached whose
    /// verdict needs the body or a CEL context. Everything after it is
    /// shadowed by first-match-wins, so the preview must stop claiming
    /// anything.
    Indeterminate,
}

/// Walk `rules` in priority order and preview which will fire.
///
/// First match wins at full evaluation, so the walk must stop at the
/// first rule it cannot answer for: a later rule that previews clean is
/// not the winner if an earlier unevaluable rule fires. Getting this
/// wrong is how a stale-while-revalidate refresh follows a later rule's
/// upstream into an earlier rule's cache entry, or how the idempotency
/// middleware serves cached bytes ahead of the guardrails of the AI
/// action the request actually lands on.
#[must_use]
pub fn preview_forward_rules<'a>(
    rules: &'a [CompiledForwardRule],
    method: &http::Method,
    path: &str,
    query: Option<&str>,
    headers: &http::HeaderMap,
) -> ForwardRulePreview<'a> {
    for rule in rules {
        let mut rule_unevaluable = false;
        for entry in &rule.matchers {
            match entry.preview(method, path, query, headers) {
                // Entries within a rule are ORed, so one clean match
                // settles the rule regardless of its siblings.
                MatcherPreview::Match => return ForwardRulePreview::Matched(rule),
                MatcherPreview::Unevaluable => rule_unevaluable = true,
                MatcherPreview::NoMatch => {}
            }
        }
        if rule_unevaluable {
            return ForwardRulePreview::Indeterminate;
        }
    }
    ForwardRulePreview::NoMatch
}

/// Largest request body any body matcher across `rules` will read, or `None`
/// when not one of them declares a body matcher.
///
/// This is the gate on the whole buffering seam. `None` means the request
/// phase never enables replay buffering, never drains the downstream body
/// early, and never parses anything, which is what keeps body-field routing
/// off the hot path of every origin that does not ask for it.
#[must_use]
pub fn forward_rule_body_cap(rules: &[CompiledForwardRule]) -> Option<usize> {
    rules
        .iter()
        .flat_map(|rule| rule.matchers.iter())
        .filter_map(|entry| entry.body.as_ref())
        .map(|body| body.max_bytes)
        .max()
}

/// A compiled forward rule: match conditions + inline origin action + request modifiers.
pub struct CompiledForwardRule {
    /// AND-grouped matcher entries evaluated in order. Entries are ORed: the
    /// first entry whose every present matcher passes wins.
    pub matchers: Vec<MatcherEntry>,
    /// Action executed when the rule matches.
    pub action: Action,
    /// Request modifiers applied before the action runs.
    pub request_modifiers: Vec<RequestModifierConfig>,
    /// OpenAPI 3.0 Parameter Object declarations carried verbatim from
    /// config. Consumed by OpenAPI emission to populate `parameters[]`
    /// on emitted operations; available for future runtime validation
    /// of captured params.
    pub parameters: Vec<Parameter>,
    /// Optional identifier from the rule's inline `origin.id`, used in
    /// metrics and logs (the `route` label on
    /// `sbproxy_deprecated_requests_total` prefers it over the rule
    /// index).
    pub id: Option<String>,
    /// WOR-2565: compiled deprecation announcement scoped to this
    /// rule's matches. Overrides the origin-scope block when present.
    pub deprecation: Option<sbproxy_config::CompiledDeprecation>,
}

/// A compiled fallback origin: triggers and the fallback action.
pub struct CompiledFallback {
    /// Trigger on upstream connection error / timeout.
    pub on_error: bool,
    /// Trigger on these upstream HTTP status codes.
    pub on_status: Vec<u16>,
    /// Add an X-Fallback-Trigger debug header to the response.
    pub add_debug_header: bool,
    /// The fallback action to serve.
    pub action: Action,
}

/// Admission settings for the Cache Reserve cold tier.
///
/// Pre-extracted from `proxy.cache_reserve` so the request path can
/// gate every reserve write on three cheap checks (sample roll, TTL
/// floor, size ceiling) without re-walking the YAML schema struct.
#[derive(Debug, Clone, Copy)]
pub struct ReserveAdmission {
    /// Fraction of writes mirrored to the reserve.
    pub sample_rate: f64,
    /// Minimum TTL (seconds) an entry must carry to be admitted.
    pub min_ttl: u64,
    /// Upper bound on the body size of an admitted entry. `0`
    /// disables the cap.
    pub max_size_bytes: u64,
}

impl ReserveAdmission {
    /// Returns true when the entry passes the size and TTL gates.
    /// Sample-rate is rolled separately by the caller so the random
    /// draw can be skipped when the other gates already reject.
    pub fn admits(&self, ttl_secs: u64, body_len: usize) -> bool {
        if ttl_secs < self.min_ttl {
            return false;
        }
        if self.max_size_bytes > 0 && (body_len as u64) > self.max_size_bytes {
            return false;
        }
        true
    }
}

/// Build the OSS Cache Reserve backend from the YAML config block.
///
/// Returns `(None, None)` when the block is absent, disabled, or
/// targets an extension-provided backend the pipeline does not know how
/// to instantiate. Failures during construction (e.g. an invalid
/// Redis URL) are logged at `warn` level and surfaced as `(None, None)`
/// so a misconfigured reserve degrades to plain hot-cache behavior
/// rather than failing the whole config load.
fn build_cache_reserve(
    cfg: &Option<sbproxy_config::CacheReserveConfig>,
) -> (
    Option<Arc<dyn CacheReserveBackend>>,
    Option<ReserveAdmission>,
) {
    let Some(cfg) = cfg.as_ref() else {
        return (None, None);
    };
    if !cfg.enabled {
        return (None, None);
    }
    let Some(backend) = cfg.backend.as_ref() else {
        tracing::warn!("cache_reserve.enabled = true but no backend configured; ignoring");
        return (None, None);
    };
    let admission = ReserveAdmission {
        sample_rate: cfg.sample_rate.clamp(0.0, 1.0),
        min_ttl: cfg.min_ttl,
        max_size_bytes: cfg.max_size_bytes,
    };
    let built: Option<Arc<dyn CacheReserveBackend>> = match backend {
        sbproxy_config::CacheReserveBackendConfig::Memory => Some(Arc::new(MemoryReserve::new())),
        sbproxy_config::CacheReserveBackendConfig::Filesystem { path } => {
            Some(Arc::new(FsReserve::new(path)))
        }
        sbproxy_config::CacheReserveBackendConfig::Redis {
            redis_url,
            key_prefix,
        } => match RedisReserve::new(
            redis_url,
            key_prefix
                .clone()
                .unwrap_or_else(|| "sbproxy:reserve:".to_string()),
        ) {
            Ok(r) => Some(Arc::new(r)),
            Err(e) => {
                tracing::warn!(error = %e, "cache_reserve redis backend init failed; reserve disabled");
                None
            }
        },
        sbproxy_config::CacheReserveBackendConfig::Other => {
            tracing::warn!(
                "cache_reserve backend type is unknown; a pipeline lifecycle hook may attach an implementation"
            );
            None
        }
    };
    if built.is_some() {
        (built, Some(admission))
    } else {
        (None, None)
    }
}

/// Resolve an at-rest encryption key reference to raw key material.
///
/// One resolution path for every at-rest surface, so a new surface cannot
/// quietly accept a different reference syntax or a different failure mode.
/// `config_path` only shapes the error message, naming the block the operator
/// has to fix.
///
/// Accepts a provider URI (`secret://backend/name`, `vault://...`) resolved
/// through the process secret resolver, a `file:/path` reference, or a
/// whole-value `${ENV_VAR}` (handled by the resolver). Anything else is taken
/// as literal material.
///
/// There is no plaintext fallback anywhere on this path: a reference that looks
/// like a secret URI with no backend to resolve it is an error rather than key
/// material spelled `secret://...`.
pub(crate) fn resolve_at_rest_key_material(
    reference: &str,
    config_path: &str,
) -> anyhow::Result<Vec<u8>> {
    use anyhow::Context;

    if let Some(resolver) = sbproxy_vault::process_resolver() {
        return Ok(resolver.resolve(reference)?.into_bytes());
    }
    if let Some(path) = reference.strip_prefix("file:") {
        let raw =
            std::fs::read(path).with_context(|| format!("read {config_path} key file '{path}'"))?;
        // Trim so a trailing newline in the key file does not silently
        // change the derived key. Matches the resolver's `file:`
        // semantics, which also trim.
        return Ok(raw.trim_ascii().to_vec());
    }
    if sbproxy_vault::looks_like_secret_reference_uri(reference) {
        anyhow::bail!(
            "{config_path} references the secret '{reference}' but no secret backend is \
             configured to resolve it; declare one under proxy.secrets.backends"
        );
    }
    Ok(reference.as_bytes().to_vec())
}

/// The response-cache store plus the per-origin handles onto it.
///
/// `unscoped` is the admin/purge handle. `per_origin` is empty unless
/// at-rest encryption is on; when it is, it holds one handle per compiled
/// origin, each bound to that origin's key ring.
pub(crate) struct ResponseCacheStores {
    pub unscoped: Arc<dyn CacheStore>,
    pub per_origin: HashMap<CompactString, Arc<dyn CacheStore>>,
}

impl std::fmt::Debug for ResponseCacheStores {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResponseCacheStores")
            .field("backend", &self.unscoped.backend_name())
            .field("scoped_origins", &self.per_origin.len())
            .finish()
    }
}

/// Build the shared response-cache store.
///
/// `store_cfg` is `proxy.response_cache_store`. When it is `None` the
/// legacy selection applies: `redis_store` if the operator configured
/// `proxy.l2_cache`, otherwise an in-process map. That branch exists so
/// upgrading does not silently move an existing Redis deployment onto a
/// per-replica cache.
///
/// `redis_store` is the already-wrapped Redis store, passed in rather
/// than built here so this function never has to name the KV trait and
/// stays unit-testable.
///
/// `origins` supplies each origin's id and its per-origin encryption
/// block. Every reference either resolves at boot or aborts startup with
/// an error naming the origin, which is the same no-plaintext-fallback
/// rule the store-wide key already follows. Multiplying the number of
/// secrets resolved at boot is the cost of key separation; failing loud
/// on each is what keeps that cost honest.
///
/// In `Validation` mode the shape is checked but no secret is resolved
/// and no directory is created, matching how the rest of `sbproxy
/// validate` treats secrets and the filesystem.
fn build_response_cache_store(
    store_cfg: Option<&sbproxy_config::ResponseCacheStoreConfig>,
    redis_store: Option<Arc<dyn CacheStore>>,
    memory_max_entries: usize,
    origins: &[OriginCacheKeys<'_>],
    mode: PipelineConstructionMode,
) -> anyhow::Result<ResponseCacheStores> {
    use anyhow::Context;

    let validating = matches!(mode, PipelineConstructionMode::Validation);

    let plain = |store: Arc<dyn CacheStore>| ResponseCacheStores {
        unscoped: store,
        per_origin: HashMap::new(),
    };

    let Some(cfg) = store_cfg else {
        // Legacy selection, byte-identical to the pre-block behaviour.
        return Ok(plain(match redis_store {
            Some(store) => store,
            None => Arc::new(MemoryCacheStore::new(memory_max_entries)),
        }));
    };

    let base: Arc<dyn CacheStore> = match &cfg.backend {
        sbproxy_config::ResponseCacheBackendConfig::Memory => {
            Arc::new(MemoryCacheStore::new(memory_max_entries))
        }
        sbproxy_config::ResponseCacheBackendConfig::File { path, max_size_mb } => {
            if validating {
                // Do not create directories during `sbproxy validate`.
                Arc::new(MemoryCacheStore::new(memory_max_entries))
            } else {
                Arc::new(
                    FileCacheStore::new(FileCacheConfig {
                        directory: path.clone(),
                        max_size_mb: *max_size_mb,
                    })
                    .context("proxy.response_cache_store.backend type `file`")?,
                )
            }
        }
        sbproxy_config::ResponseCacheBackendConfig::Memcached { host, port } => {
            Arc::new(MemcachedStore::new(MemcachedConfig {
                host: host.clone(),
                port: *port,
            }))
        }
        sbproxy_config::ResponseCacheBackendConfig::Redis => match redis_store {
            Some(store) => store,
            None => anyhow::bail!(
                "proxy.response_cache_store.backend type `redis` needs a connection; \
                 configure proxy.l2_cache with driver: redis or pick another backend"
            ),
        },
    };

    let Some(enc) = cfg.encryption.as_ref().filter(|e| e.enabled) else {
        // An origin that declared its own key while store-wide
        // encryption is off wrote something that would never take
        // effect. Say so rather than storing that tenant in the clear.
        if let Some(origin) = origins.iter().find(|o| o.declares_a_key()) {
            anyhow::bail!(
                "origin '{}' declares response_cache.encryption but \
                 proxy.response_cache_store.encryption is not enabled; enable it or remove the \
                 per-origin block",
                origin.id
            );
        }
        tracing::info!(
            backend = base.backend_name(),
            "response cache backend ready without at-rest encryption"
        );
        return Ok(plain(base));
    };

    // Bound to a local rather than matched inline so the config-key
    // reader scan can see a plain field read of `per_origin_keys`.
    let per_origin_mode = enc.per_origin_keys;
    let strict = per_origin_mode == sbproxy_config::PerOriginKeyMode::Required;

    // Under `required` the store-wide key is not a fallback, but it is
    // still the thing an operator most likely left in place while
    // migrating. Requiring it anyway would make the switch a two-step
    // edit for no safety gain, so it stays optional-but-accepted and
    // simply never gets inherited.
    let store_wide_reference = enc.key.as_deref();
    if store_wide_reference.is_none() && !strict {
        anyhow::bail!(
            "proxy.response_cache_store.encryption.enabled is true but no `key` is set; \
             point `key` at a secret reference such as `secret://local/response-cache`, \
             give every caching origin its own key under \
             `per_origin_keys: required`, or set `enabled: false`"
        );
    }

    if strict {
        let missing: Vec<&str> = origins
            .iter()
            .filter(|o| o.caches && !o.declares_a_key())
            .map(|o| o.id)
            .collect();
        if !missing.is_empty() {
            anyhow::bail!(
                "proxy.response_cache_store.encryption.per_origin_keys is `required`, but these \
                 caching origins declare no encryption key of their own: {}. Give each one an \
                 `origins.<host>.response_cache.encryption.key`, or switch back to `inherit`.",
                missing.join(", ")
            );
        }
    }

    if validating {
        // The shape is valid. Resolving the keys would read files and
        // dial secret backends, which `sbproxy validate` does not do.
        return Ok(plain(base));
    }

    let resolve_ring = |reference: &str, previous: &[String], config_path: &str| {
        let active = resolve_at_rest_key_material(reference, config_path)
            .with_context(|| format!("{config_path}.key"))?;
        let mut retired = Vec::with_capacity(previous.len());
        for (index, reference) in previous.iter().enumerate() {
            retired.push(
                resolve_at_rest_key_material(reference, config_path)
                    .with_context(|| format!("{config_path}.previous_keys[{index}]"))?,
            );
        }
        sbproxy_cache::cache_key_ring(active, retired).context(config_path.to_string())
    };

    let default_ring = match store_wide_reference {
        Some(reference) => Some(resolve_ring(
            reference,
            &enc.previous_keys,
            "proxy.response_cache_store.encryption",
        )?),
        None => None,
    };

    let mut per_origin_rings = HashMap::new();
    for origin in origins {
        let Some(reference) = origin.key else {
            continue;
        };
        let path = format!("origins.{}.response_cache.encryption", origin.id);
        per_origin_rings.insert(
            origin.id.to_string(),
            resolve_ring(reference, origin.previous_keys, &path)?,
        );
    }

    tracing::info!(
        backend = base.backend_name(),
        key_id = default_ring
            .as_ref()
            .map(|r| r.active_key_id())
            .unwrap_or_else(|| "none".to_string()),
        retired_keys = enc.previous_keys.len(),
        per_origin_keys = per_origin_rings.len(),
        strict = strict,
        "response cache backend ready with at-rest encryption"
    );

    let directory = Arc::new(sbproxy_cache::CacheKeyDirectory::new(
        default_ring,
        per_origin_rings,
    ));
    let per_origin = origins
        .iter()
        .map(|origin| {
            let handle: Arc<dyn CacheStore> = Arc::new(EncryptedCacheStore::scoped(
                Arc::clone(&base),
                Arc::clone(&directory),
                origin.id,
            ));
            (CompactString::new(origin.id), handle)
        })
        .collect();
    Ok(ResponseCacheStores {
        unscoped: Arc::new(EncryptedCacheStore::unscoped(base, directory)),
        per_origin,
    })
}

/// One origin's contribution to response-cache key resolution.
///
/// Borrowed from the compiled config so the builder can stay a free
/// function that unit tests drive with literals.
pub(crate) struct OriginCacheKeys<'a> {
    /// Origin id, which is the hostname the operator wrote in YAML.
    pub id: &'a str,
    /// Whether this origin has `response_cache.enabled: true`.
    pub caches: bool,
    /// This origin's active key reference, if it declared one.
    pub key: Option<&'a str>,
    /// This origin's retired key references.
    pub previous_keys: &'a [String],
}

impl OriginCacheKeys<'_> {
    /// Whether this origin declared any key material of its own.
    ///
    /// `previous_keys` counts: an origin mid-rotation that has already
    /// had its active key removed still holds material nobody else does.
    fn declares_a_key(&self) -> bool {
        self.key.is_some() || !self.previous_keys.is_empty()
    }
}

/// TLS-fingerprint capture mode.
///
/// `passive` and `sidecar` are wire-equivalent today; the OSS path
/// captures fingerprints exclusively from the sidecar header pattern
/// because Pingora 0.8 does not surface the raw ClientHello bytes. The
/// distinct names are reserved so a future native-capture implementation
/// can flip to `passive` without an operator-visible config change.
/// `disabled` short-circuits the capture path even when sidecar headers
/// arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TlsFingerprintMode {
    /// Capture fingerprints natively from the TLS handshake (reserved
    /// for a future implementation; behaves like `sidecar` today).
    Passive,
    /// Capture fingerprints from sidecar-injected request headers.
    /// Requires `proxy.trusted_proxies` to cover the sidecar's source
    /// range so the sidecar headers cannot be forged by a downstream
    /// client.
    #[default]
    Sidecar,
    /// No capture. Sidecar TLS-fingerprint headers are stripped on
    /// ingress regardless of `proxy.trusted_proxies`.
    Disabled,
}

/// TLS-fingerprint capture configuration.
///
/// Lifted onto [`CompiledPipeline`] from the
/// `proxy.extensions.tls_fingerprint` block (canonical) or the legacy
/// `features.tls_fingerprint` shape (rewritten by the day-6 Item 2
/// migration). Default: `disabled`, no headers honoured, no capture.
///
/// ## Schema
///
/// ```yaml
/// proxy:
///   extensions:
///     tls_fingerprint:
///       enabled: true
///       mode: sidecar
///       sidecar_header_allowlist:
///         - x-forwarded-ja3
///         - x-forwarded-ja4
///         - x-forwarded-ja4h
///         - x-forwarded-ja4s
/// ```
///
/// `enabled: false` is equivalent to omitting the block. `mode` is
/// `sidecar` by default. `sidecar_header_allowlist` is the operator-
/// supplied set of trust-bounded sidecar headers; the canonical
/// `x-sbproxy-tls-*` family is always honoured (see the request
/// entry hook). The allowlist is the operator's escape hatch for
/// CDN-specific header names (`x-forwarded-ja4` is Cloudflare and
/// Fastly's spelling).
#[derive(Debug, Clone, serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TlsFingerprintConfig {
    /// Master switch. `false` (the default) disables the capture path
    /// entirely.
    #[serde(default)]
    pub enabled: bool,
    /// Capture mode. See [`TlsFingerprintMode`] for semantics.
    #[serde(default)]
    pub mode: TlsFingerprintMode,
    /// Additional sidecar header names the request entry hook will
    /// read JA3 / JA4 / JA4H / JA4S values from. Honoured only when
    /// the immediate TCP peer is in `proxy.trusted_proxies`.
    #[serde(default)]
    pub sidecar_header_allowlist: Vec<String>,
    /// Per-origin trustworthy CIDR ranges (clients seen as the direct
    /// TCP peer get `request.tls.trustworthy = true`). When unset the
    /// request entry hook defaults `trustworthy` based on whether the
    /// sidecar marked the value true.
    #[serde(default)]
    pub trustworthy_client_cidrs: Vec<String>,
    /// CIDR ranges flagged as untrusted (e.g. CDN egress pools). When
    /// the resolved client IP falls in this set the captured
    /// fingerprint is marked `trustworthy = false` even when the
    /// sidecar reported it as trustworthy.
    #[serde(default)]
    pub untrusted_client_cidrs: Vec<String>,
    /// Path to a JA3 / JA4 / JA4H catalogue, in the schema of
    /// `crates/sbproxy-classifiers/data/tls-fingerprints.json`. When
    /// set, it replaces the embedded catalogue entirely rather than
    /// merging with it, so an operator's file is the whole truth and
    /// nothing ships underneath it that they did not put there.
    ///
    /// This exists because the embedded catalogue carries **no
    /// fingerprints**. A JA4 value is a measurement of a specific
    /// client, and the published databases of those measurements come
    /// with their own licenses, so shipping a populated default meant
    /// redistributing somebody else's licensed data inside an
    /// Apache-2.0 binary (WOR-2296). Capturing the values is the
    /// operator's job now, and the trade is deliberate: an empty
    /// catalogue answers every `tls_fingerprint_matches` with `true`,
    /// which is the conservative direction. Detection is inert until a
    /// file is supplied; nothing is falsely accused of spoofing.
    ///
    /// Populate it from your own traffic. `request.tls.ja4` carries the
    /// value this proxy computed for the live handshake, so a CEL
    /// transform that stamps it into a response header, or an access-log
    /// field, turns a known-good client into one catalogue line. See
    /// `docs/headless-detection.md`.
    #[serde(default)]
    pub catalog_file: Option<String>,
    /// Pre-parsed [`Self::trustworthy_client_cidrs`] (WOR-1698/WOR-1699),
    /// compiled once at config load so the per-request fingerprint path
    /// does a membership check without re-parsing CIDR strings. Populated
    /// by [`Self::from_extensions`]; empty for the disabled default.
    #[serde(skip)]
    trustworthy_cidrs_compiled: Vec<ipnetwork::IpNetwork>,
    /// Pre-parsed [`Self::untrusted_client_cidrs`] (WOR-1699).
    #[serde(skip)]
    untrusted_cidrs_compiled: Vec<ipnetwork::IpNetwork>,
}

thread_local! {
    /// Number of TLS-fingerprint CIDR lists parsed on this thread.
    ///
    /// Parsing an operator's CIDR strings is a config-load activity; the
    /// request path only ever does a membership check against the parsed
    /// set. The counter makes that testable the same way
    /// `sbproxy_extension::cel` counts expression compiles: a test loads
    /// a config, records the count, drives the classification path, and
    /// asserts the count did not move. Thread-local rather than global so
    /// a parallel test run cannot make one test's count depend on
    /// another's.
    static CIDR_PARSE_COUNT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Reads the current thread's TLS-fingerprint CIDR parse count.
#[cfg(test)]
pub(crate) fn cidr_parse_count_on_this_thread() -> u64 {
    CIDR_PARSE_COUNT.with(std::cell::Cell::get)
}

impl TlsFingerprintConfig {
    /// Parse the CIDR string lists into their compiled forms once, at
    /// config load (moved here from the per-request path, WOR-1699).
    /// An invalid entry fails the config compile. It used to be dropped
    /// with a warn, but `untrusted_client_cidrs` is a deny list, so a
    /// typo silently weakened it while the proxy kept serving.
    fn compile_cidrs(&mut self) -> anyhow::Result<()> {
        fn parse(list: &[String], field: &str) -> anyhow::Result<Vec<ipnetwork::IpNetwork>> {
            CIDR_PARSE_COUNT.with(|c| c.set(c.get().saturating_add(1)));
            sbproxy_security::parse_cidrs(list.iter().map(String::as_str), field)
        }
        self.trustworthy_cidrs_compiled =
            parse(&self.trustworthy_client_cidrs, "trustworthy_client_cidrs")?;
        self.untrusted_cidrs_compiled =
            parse(&self.untrusted_client_cidrs, "untrusted_client_cidrs")?;
        Ok(())
    }

    /// Build a [`TlsFingerprintConfig`] from the parsed
    /// `proxy.extensions.tls_fingerprint` YAML block.
    ///
    /// Returns `Ok(Default::default())` (disabled) when the block is
    /// absent. A block that fails to parse while declaring
    /// `enabled: true` is a hard compile error (WOR-1161): the operator
    /// asked for the capture path, so silently disabling it is a
    /// fail-open. The error carries serde's diagnostic, which names the
    /// malformed field. A malformed block that does not declare
    /// `enabled: true` keeps the warn-and-disable path, since the
    /// disabled outcome matches the operator's stated intent.
    ///
    /// A block that parses but carries an unparseable CIDR entry is a
    /// hard compile error regardless of `enabled`: the lists only exist
    /// to gate trust, and dropping an entry silently narrows them (see
    /// `compile_cidrs`).
    pub fn from_extensions(
        extensions: &std::collections::HashMap<String, serde_yaml::Value>,
    ) -> anyhow::Result<Self> {
        let Some(block) = extensions.get("tls_fingerprint") else {
            return Ok(Self::default());
        };
        match serde_yaml::from_value::<TlsFingerprintConfig>(block.clone()) {
            Ok(mut cfg) => {
                cfg.compile_cidrs()?;
                Ok(cfg)
            }
            Err(e) => {
                // WOR-1161: a malformed block used to fall back to
                // disabled silently, a fail-open when the operator
                // meant to turn the feature on. Detect the stated
                // intent from the raw block: a bare `tls_fingerprint:
                // true` or an `enabled:` key that reads as true means
                // the operator wanted capture on, so refuse the config.
                let wants_capture = block.as_bool() == Some(true)
                    || match block.get("enabled") {
                        Some(v) => {
                            v.as_bool() == Some(true)
                                || v.as_str().is_some_and(|s| s.eq_ignore_ascii_case("true"))
                        }
                        None => false,
                    };
                if wants_capture {
                    anyhow::bail!(
                        "proxy.extensions.tls_fingerprint has `enabled: true` but failed to \
                         parse: {e}. Refusing to start with TLS-fingerprint capture silently \
                         disabled; fix or remove the block."
                    );
                }
                tracing::warn!(
                    error = %e,
                    "proxy.extensions.tls_fingerprint failed to parse; capture disabled",
                );
                Ok(Self::default())
            }
        }
    }

    /// Pre-parsed [`Self::trustworthy_client_cidrs`], compiled once at
    /// config load (WOR-1699). Empty when the field is unset, equivalent
    /// to "no trust list".
    pub(crate) fn trustworthy_cidrs(&self) -> &[ipnetwork::IpNetwork] {
        &self.trustworthy_cidrs_compiled
    }

    /// Pre-parsed [`Self::untrusted_client_cidrs`], compiled once at
    /// config load (WOR-1699).
    pub(crate) fn untrusted_cidrs(&self) -> &[ipnetwork::IpNetwork] {
        &self.untrusted_cidrs_compiled
    }

    /// Decide whether a captured fingerprint is trustworthy.
    ///
    /// This is the single trust-classification decision for the sidecar
    /// capture path; the request entry hook calls it and stores the
    /// result on [`sbproxy_tls::TlsFingerprint::trustworthy`].
    ///
    /// `sidecar_override` is the parsed `x-sbproxy-tls-trustworthy`
    /// header, `None` when the trusted sidecar did not assert one.
    /// `client_ip` is the resolved client IP after the forwarded-header
    /// trust boundary has run.
    ///
    /// The order is:
    ///
    /// 1. Start from the sidecar's assertion, defaulting to `true` when
    ///    it made none. The sidecar only reaches this code from a peer
    ///    in `proxy.trusted_proxies`, so absent any operator CIDR rules
    ///    its capture is taken at face value.
    /// 2. A client IP inside [`Self::untrusted_client_cidrs`] forces
    ///    `false`, outranking the sidecar. That list is how an operator
    ///    names CDN egress and corporate MITM pools.
    /// 3. Otherwise, when [`Self::trustworthy_client_cidrs`] is
    ///    non-empty, the answer is membership in it: an operator who
    ///    took the trouble to enumerate direct-client ranges is stating
    ///    that everything else is not a direct client. An empty trust
    ///    list is not that statement, so it leaves step 1 standing.
    ///
    /// The `true` default in step 1 is deliberate and is pinned by
    /// `trustworthy_defaults_to_true_without_an_override`. It is not the
    /// conservative choice; it is the shipped one, and the capture path
    /// is only reachable behind the trusted-peer check.
    pub fn resolve_trustworthy(
        &self,
        sidecar_override: Option<bool>,
        client_ip: Option<std::net::IpAddr>,
    ) -> bool {
        let trustworthy = sidecar_override.unwrap_or(true);
        let Some(ip) = client_ip else {
            return trustworthy;
        };
        if sbproxy_security::ip_in_cidrs(&ip, self.untrusted_cidrs()) {
            return false;
        }
        let trust_list = self.trustworthy_cidrs();
        if trust_list.is_empty() {
            return trustworthy;
        }
        sbproxy_security::ip_in_cidrs(&ip, trust_list)
    }

    /// Whether the named header should be honoured as a trust-bounded
    /// sidecar TLS-fingerprint signal. Always honours the canonical
    /// `x-sbproxy-tls-*` family; defers to
    /// [`Self::sidecar_header_allowlist`] for everything else. Matches
    /// case-insensitively.
    pub fn header_allowed(&self, name: &str) -> bool {
        // WOR-1699: compare case-insensitively against the byte-borrowed
        // name instead of allocating a lowercased copy per call (this
        // runs up to 8 times per request on the fingerprint path).
        const CANONICAL: [&str; 5] = [
            "x-sbproxy-tls-ja3",
            "x-sbproxy-tls-ja4",
            "x-sbproxy-tls-ja4h",
            "x-sbproxy-tls-ja4s",
            "x-sbproxy-tls-trustworthy",
        ];
        if CANONICAL.iter().any(|c| c.eq_ignore_ascii_case(name)) {
            return true;
        }
        self.sidecar_header_allowlist
            .iter()
            .any(|h| h.eq_ignore_ascii_case(name))
    }
}

/// Agent-detect engine configuration, read from
/// `proxy.extensions.agent_detect`.
///
/// `enabled: false` (the default) keeps the scorer out of the request
/// path entirely, so deployments that do not use agent detection pay
/// nothing. When enabled, `request_filter` builds the TLS + HTTP signal
/// bag, runs the rule-pack scorer, and stores the verdict on the request
/// context for the scripting bridges (`request.agent.*`) and the
/// `trust_tier` combiner.
///
/// WOR-2181: unknown keys are refused. A misspelled `rule_pack_paths:`
/// used to deserialize silently and leave the scorer running against
/// an empty pack, which scores every request as unsigned-anonymous.
/// The deny only turns that into an error; what makes the error reach
/// the operator is [`Self::from_extensions`] refusing the config
/// rather than warning, which it does whenever the block asks for the
/// scorer to be on.
#[derive(Debug, Clone, serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AgentDetectConfig {
    /// Master switch. `false` (the default) disables the scorer.
    #[serde(default)]
    pub enabled: bool,
    /// Path to the ADRF YAML rule pack. When unset the scorer runs with
    /// an empty pack (every request scores as unsigned-anonymous);
    /// operators normally point this at their pack.
    #[serde(default)]
    pub rule_pack_path: Option<String>,
    /// Path to a CatBoost ONNX model exported with the raw probability
    /// tensor output. When set, startup loads the model and installs it
    /// as the fallback scorer behind exact rule-pack matches.
    #[serde(default)]
    pub onnx_model_path: Option<String>,
}

impl AgentDetectConfig {
    /// Build from the parsed `proxy.extensions.agent_detect` block.
    ///
    /// Returns `Ok(Default::default())` (disabled) when the block is
    /// absent, which is the shape of every config that does not use
    /// agent detection and stays a non-event.
    ///
    /// A block that fails to parse while asking for the scorer to be on
    /// is a hard compile error (WOR-2181), mirroring
    /// [`TlsFingerprintConfig::from_extensions`]. The operator asked
    /// for detection, so warning and returning the disabled default
    /// would run the proxy with the control off while the config says
    /// it is on. Denying unknown fields without this would have made
    /// the situation worse rather than better: a typo that used to be
    /// dropped (leaving the scorer on with the rest of the block
    /// intact) would have become a parse error and switched the whole
    /// scorer off.
    ///
    /// A malformed block that does not ask for the scorer keeps the
    /// warn-and-disable path, since disabled is what it asked for.
    pub fn from_extensions(
        extensions: &std::collections::HashMap<String, serde_yaml::Value>,
    ) -> anyhow::Result<Self> {
        let Some(block) = extensions.get("agent_detect") else {
            return Ok(Self::default());
        };
        match serde_yaml::from_value::<AgentDetectConfig>(block.clone()) {
            Ok(cfg) => Ok(cfg),
            Err(e) => {
                // Read the stated intent off the raw block rather than
                // the parse that just failed: a bare `agent_detect:
                // true` or an `enabled:` key that reads as true means
                // the operator wanted the scorer on.
                let wants_detection = block.as_bool() == Some(true)
                    || match block.get("enabled") {
                        Some(v) => {
                            v.as_bool() == Some(true)
                                || v.as_str().is_some_and(|s| s.eq_ignore_ascii_case("true"))
                        }
                        None => false,
                    };
                if wants_detection {
                    anyhow::bail!(
                        "proxy.extensions.agent_detect has `enabled: true` but failed to \
                         parse: {e}. Refusing to start with agent detection silently \
                         disabled; fix or remove the block."
                    );
                }
                tracing::warn!(
                    error = %e,
                    "proxy.extensions.agent_detect failed to parse; agent detection disabled",
                );
                Ok(Self::default())
            }
        }
    }
}

/// Compiled idempotency middleware bound to a single origin.
///
/// Built once at config-compile time and held by [`CompiledPipeline`]
/// keyed by origin index. The cache implementation is selected from
/// the [`sbproxy_config::IdempotencyBackend`] discriminator: `Memory`
/// gets an [`sbproxy_middleware::idempotency::InMemoryIdempotencyCache`]
/// and `Redis` gets a
/// [`sbproxy_middleware::idempotency::KvIdempotencyCache`] wrapping
/// the cluster L2 store.
pub struct CompiledIdempotency {
    /// Cache backend trait object. Workspace-scoped per call.
    pub cache: Arc<dyn sbproxy_middleware::idempotency::IdempotencyCache>,
    /// Request header carrying the idempotency key. Defaults to
    /// `Idempotency-Key` but the operator can override per origin.
    pub header_name: String,
    /// Time-to-live for cached entries, in seconds. Pre-applied
    /// default (24 h) so the request path doesn't re-check.
    pub ttl_secs: u64,
    /// HTTP methods this middleware engages on. Pre-parsed from the
    /// authored YAML so the request path does a `.contains` against
    /// a small vec rather than reparsing on every request.
    pub methods: smallvec::SmallVec<[http::Method; 4]>,
    /// Maximum request body bytes the middleware will buffer for
    /// the cache check. Requests larger than this cap gracefully
    /// degrade: skip caching and stamp the SKIPPED-OVERSIZE-REQUEST
    /// marker.
    pub max_request_body_bytes: usize,
    /// Maximum response body bytes the middleware will buffer for
    /// caching. Responses larger than this cap stream uncached.
    pub max_response_body_bytes: usize,
    /// Per-origin semaphore capping concurrent buffered requests.
    /// Acquire a permit on engagement; pool exhaustion forces the
    /// request through the no-cache path.
    pub permits: Arc<tokio::sync::Semaphore>,
}

/// Immutable MCP catalog sources owned by one compiled pipeline generation.
///
/// The outer key is the route-derived tenant id and the inner key is the MCP
/// action's advertised server name. Keeping this registry on the pipeline
/// makes request pinning cover catalog injection just like every other
/// compiled dependency: a candidate reload cannot overwrite a live source.
#[derive(Default)]
pub(crate) struct McpInjectRegistry {
    by_tenant: HashMap<String, HashMap<String, Arc<sbproxy_modules::action::McpInjectSource>>>,
}

impl McpInjectRegistry {
    fn insert(
        &mut self,
        tenant_id: &str,
        server_name: &str,
        source: Arc<sbproxy_modules::action::McpInjectSource>,
    ) -> anyhow::Result<()> {
        let tenant_sources = self.by_tenant.entry(tenant_id.to_owned()).or_default();
        if tenant_sources.contains_key(server_name) {
            anyhow::bail!(
                "duplicate MCP inject source for tenant '{}' and server '{}'",
                tenant_id,
                server_name
            );
        }
        tenant_sources.insert(server_name.to_owned(), source);
        Ok(())
    }

    fn get(
        &self,
        tenant_id: &str,
        server_name: &str,
    ) -> Option<Arc<sbproxy_modules::action::McpInjectSource>> {
        self.by_tenant
            .get(tenant_id)?
            .get(server_name)
            .map(Arc::clone)
    }
}

/// A compiled config with its module instances ready for request processing.
///
/// Each vec is parallel to `config.origins` - index N in `actions` corresponds
/// to index N in `config.origins`. This avoids per-request JSON parsing.
pub struct CompiledPipeline {
    /// The underlying compiled config (origins, host_map, server settings).
    pub config: CompiledConfig,
    /// Dynamic hooks loaded and compiled with this pipeline generation.
    #[allow(dead_code)]
    pub(crate) extension_registry: Arc<DynamicBundleRegistry>,
    /// Awaited AI hook chain prepared with this exact generation.
    pub(crate) ai_extension_chain: Arc<sbproxy_extension::bundle::AiExtensionChain>,
    /// Prepared payment hook chain selected by this generation's config.
    #[cfg(feature = "payments")]
    pub(crate) payment_extension_chain: Option<sbproxy_extension::bundle::PaymentExtensionChain>,
    /// Candidate or running inventory derived from this generation's attachments.
    pub(crate) extension_inventory: ExtensionInventorySnapshot,
    /// Dynamic key plane built from the same immutable config generation.
    ///
    /// Request contexts pin the pipeline at ingress, so keeping the plane here
    /// prevents a reload from changing key resolution, governance, or bound
    /// upstream credentials underneath an in-flight request.
    pub(crate) key_plane: Option<Arc<crate::key_plane::KeyPlane>>,
    /// Sensitive request-header names for this exact config generation.
    ///
    /// Requests pin a pipeline at ingress. Keeping custom credential carriers
    /// here prevents a concurrent reload from changing redaction or outbound
    /// scrubbing semantics for requests that are still in flight.
    pub(crate) sensitive_header_names: HashSet<String>,
    /// Bloom filter + HashMap router for fast hostname lookup.
    pub router: HostRouter,
    /// Compiled action for each origin (parallel to config.origins).
    pub actions: Vec<Action>,
    /// Tenant-scoped MCP injection sources pinned to this generation.
    pub(crate) mcp_inject_registry: McpInjectRegistry,
    /// Compiled Proxy-Wasm filter chain for each origin.
    pub(crate) proxy_wasm_filters: Vec<Option<crate::proxy_wasm_http::ProxyWasmFilterChain>>,
    /// Guards the one-time activation of this generation's background tasks.
    pub(crate) background_tasks_started: AtomicBool,
    /// Immutable per-origin AI compression dependencies and policies.
    pub compression_runtimes: crate::compression_runtime::CompressionRuntimeRegistry,
    /// Immutable route-scoped RAG runtimes keyed by origin and optional
    /// forward rule (WOR-2098). Populated only for `ai_proxy` actions that
    /// configure `rag:`; a forward rule without its own `rag:` block has no
    /// runtime and never falls back to the origin's.
    #[cfg(feature = "rag")]
    pub rag_runtimes: crate::rag_runtime::RagRuntimeRegistry,
    /// The published settlement runtime for this config generation, when
    /// `proxy.payments` is configured (WOR-2100).
    ///
    /// Attached after construction rather than built inside it, because
    /// publishing is async and proving the store answers has to happen while
    /// the previous generation is still serving. `None` means settlement is
    /// not configured, which is the default and leaves the existing
    /// non-settlement ledger behaviour exactly as it was.
    ///
    /// Pinned to the pipeline for the same reason the key plane is: a
    /// request pins a pipeline at ingress, so a reload cannot move a paid
    /// request onto a different settlement store than the one that issued
    /// its challenge.
    #[cfg(feature = "payments")]
    pub payments: Option<Arc<crate::billing_runtime::PaymentsRuntime>>,
    /// Immutable route-scoped semantic caches keyed by origin and optional
    /// forward rule (WOR-2099). Populated only for `ai_proxy` actions that
    /// configure `semantic_cache:`; a forward rule without its own block
    /// has no cache and never falls back to the origin's. The registry
    /// owns whichever memory, Redis, or mesh adapters this config
    /// generation selected, so an in-flight request holding this snapshot
    /// keeps reading the backend it started with across a reload.
    pub semantic_caches: crate::semantic_cache_runtime::SemanticCacheRuntimeRegistry,
    /// Compiled auth for each origin (None if no auth configured).
    pub auths: Vec<Option<Auth>>,
    /// Compiled policies for each origin (may be empty).
    ///
    /// Response-phase code (`SecHeaders`, `PageShield`, `Sri`) walks
    /// this vector at response time. Request-phase enforcement uses
    /// the parallel [`Self::enforcers`] vector below, which carries
    /// the same chain dispatched through the
    /// [`sbproxy_plugin::PolicyEnforcer`] trait.
    pub policies: Vec<Vec<Policy>>,
    /// Compiled built-in + plugin enforcers for each origin (parallel
    /// to [`Self::policies`]).
    ///
    /// Request-phase entry point: `server::check_policies` iterates
    /// this list and routes each entry through the
    /// [`sbproxy_plugin::PolicyEnforcer`] trait. Built one-time at
    /// config compile by [`compile_builtin_enforcers`].
    pub enforcers: Vec<Vec<CompiledEnforcer>>,
    /// Compiled transforms for each origin (may be empty).
    pub transforms: Vec<Vec<CompiledTransform>>,
    /// Compiled forward rules for each origin (may be empty).
    pub forward_rules: Vec<Vec<CompiledForwardRule>>,
    /// Compiled fallback origin for each origin (None if not configured).
    pub fallbacks: Vec<Option<CompiledFallback>>,
    /// Compiled bot detection for each origin (None if not configured).
    pub bot_detections: Vec<Option<BotDetection>>,
    /// Compiled threat protection for each origin (None if not configured).
    pub threat_protections: Vec<Option<ThreatProtection>>,
    /// Compiled outbound credential resolver for each origin (None if
    /// not configured). Parallel to [`Self::config`].`origins`. WOR-802.
    pub outbound_creds:
        Vec<Option<sbproxy_modules::auth::outbound_credential::OutboundCredentialConfig>>,
    /// Per-origin opt-in for outbound Web Bot Auth signing (WOR-805).
    /// Parallel to [`Self::config`].`origins`.
    pub outbound_wba: Vec<bool>,
    /// Shared outbound Web Bot Auth signer, built once from
    /// `proxy.web_bot_auth`. `None` when no web_bot_auth key is
    /// configured, in which case `outbound_wba` opt-ins are no-ops.
    pub web_bot_auth_signer: Option<Arc<sbproxy_middleware::signatures_egress::MessageSigner>>,
    /// `Signature-Agent` header value (the proxy's published directory
    /// URL) stamped alongside an outbound Web Bot Auth signature when
    /// `proxy.web_bot_auth.directory_url` is set.
    pub web_bot_auth_signature_agent: Option<String>,
    /// Consumption attestation for this pipeline generation (WOR-2127),
    /// built once from `proxy.attestation`. `None` when the block is
    /// absent, when its role is `off`, and always under validation
    /// construction, which must not create the queue or ledger
    /// directories on an operator's laptop.
    pub attestation: Option<Arc<crate::attestation::AttestationRuntime>>,
    /// Per-origin attestation posture, composed once from the
    /// proxy-wide role and each origin's override. Parallel to
    /// [`Self::config`].`origins`, so the request path indexes rather
    /// than re-deriving precedence per request.
    pub origin_attestations: Vec<crate::attestation::ResolvedOriginAttestation>,
    /// Compiled idempotency middleware for each origin (None when the
    /// origin has no `idempotency:` block or `enabled = false`).
    /// Parallel to [`Self::config`].`origins`.
    pub idempotencies: Vec<Option<Arc<CompiledIdempotency>>>,
    /// Every `engine: cel` custom log field in this config generation,
    /// compiled once and keyed by source text (WOR-2164).
    ///
    /// The access-log path resolves the winning field per request and
    /// looks its source up here, so a log record evaluates without
    /// parsing. Malformed CEL rejected the config before this map was
    /// ever built.
    pub(crate) custom_log_programs: crate::server::custom_log::CompiledLogPrograms,
    /// Shared response cache backend.
    ///
    /// Selected by `proxy.response_cache_store`, which names one of
    /// memory, file, memcached, or redis and can wrap the choice in
    /// at-rest encryption. When that block is absent the historical
    /// selection applies: a Redis-backed store when
    /// `CompiledConfig.l2_store` is set, otherwise an in-process
    /// `MemoryCacheStore`. A single backend is shared by all origins;
    /// per-origin `ResponseCacheConfig` gates whether the cache is
    /// actually used for that origin.
    ///
    /// This is the *unscoped* handle. It supports purge and reports the
    /// backend name, which is all the admin API needs. When at-rest
    /// encryption is on it refuses reads and writes, because sealing an
    /// entry requires knowing which origin it belongs to. Data paths must
    /// go through [`Self::cache_store_for`].
    pub cache_store: Option<Arc<dyn CacheStore>>,
    /// Per-origin handles onto [`Self::cache_store`], keyed by origin id.
    ///
    /// Empty unless at-rest encryption is on, in which case there is one
    /// entry per compiled origin. Each handle seals and opens under that
    /// origin's key ring and binds the origin into the associated data.
    /// Read it through [`Self::cache_store_for`] rather than directly.
    pub origin_cache_stores: HashMap<CompactString, Arc<dyn CacheStore>>,
    /// Optional Cache Reserve cold-tier backend.
    ///
    /// Built from the top-level `cache_reserve:` block. When `Some`, the
    /// request path consults the reserve on hot-cache misses, promotes
    /// reserve hits back into the hot tier, and writes evicted entries
    /// into the reserve subject to admission control. When `None`, the
    /// cache path runs unchanged.
    pub cache_reserve: Option<Arc<dyn CacheReserveBackend>>,
    /// Settings carried alongside [`Self::cache_reserve`] (sample
    /// rate, min TTL, max object size). Cached here so the request
    /// path doesn't have to re-walk `config.server.cache_reserve` on
    /// every put.
    pub cache_reserve_admission: Option<ReserveAdmission>,
    /// Optional pipeline hooks bundle.
    ///
    /// All fields default to `None`. A lifecycle extension registers
    /// implementations (classifier, semantic cache, etc.) via the
    /// `PipelineLifecycleHook` pattern. Request-path code invokes these
    /// optionally and no-ops when they are `None`.
    pub hooks: crate::hooks::Hooks,
    /// Pre-parsed CIDRs from `proxy.trusted_proxies`. When the immediate
    /// TCP peer's IP falls inside one of these networks, the proxy honors
    /// the inbound `X-Forwarded-For` / `X-Real-IP` / `Forwarded` headers
    /// and recovers the real client IP from them. Otherwise those headers
    /// are stripped on ingress (they cannot be trusted).
    pub trusted_proxy_cidrs: Vec<ipnetwork::IpNetwork>,
    /// TLS fingerprint capture configuration.
    ///
    /// Lifted from `proxy.extensions.tls_fingerprint` (or the migrated
    /// legacy `features.tls_fingerprint` shape). When `enabled = false`
    /// (the default), the request entry
    /// hook ignores sidecar TLS-fingerprint headers entirely so an
    /// operator's deployment that lacks a TLS-terminating sidecar does
    /// not pay the parse cost.
    pub tls_fingerprint_config: TlsFingerprintConfig,
    /// Agent-detect engine config. When `enabled = false`
    /// (the default) the scorer never runs in `request_filter`.
    pub agent_detect_config: AgentDetectConfig,
    /// Opt-in switch for raw CSP-report logging.
    ///
    /// CSP reports may carry URLs with embedded credentials, session
    /// IDs, or tokens; the structured log path always redacts them. An
    /// operator who needs the raw payload (e.g. for forensic analysis
    /// in an isolated environment) sets
    /// `proxy.extensions.page_shield.raw_report_log: true` to also
    /// emit the unredacted body at debug level. Default `false`.
    pub page_shield_raw_report_log: bool,
    /// Per-tenant allowlist of private CIDRs that upstream URLs are
    /// permitted to resolve to.
    ///
    /// Lifted from `proxy.extensions.upstream.allow_private_cidrs`,
    /// which accepts a list of CIDR strings (`"10.0.0.0/8"`,
    /// `"169.254.0.0/16"`). Empty by default, in which case any
    /// upstream URL that resolves to a private / loopback / link-local
    /// IP is rejected before `HttpPeer` construction. Used by the
    /// SSRF guard in `upstream_peer`.
    pub upstream_allow_private_cidrs: Vec<ipnetwork::IpNetwork>,
    /// Short hex tag identifying the loaded config revision. Webhooks
    /// and alerts include this so receivers can tell when the config
    /// changed underneath them. Recomputed on every hot reload.
    pub config_revision: String,
    /// Shared DNS resolver used by `service_discovery`-enabled
    /// upstreams. One refresher backs every origin so resolutions
    /// are not duplicated when several origins point at the same
    /// hostname.
    pub dns_resolver: Arc<sbproxy_platform::RefreshingResolver>,
    /// Repo-native Listing registry populated at config
    /// load.
    ///
    /// Each Listing's `spec.skills[]` block feeds the
    /// per-Listing Agent Skills projection at
    /// `/.well-known/agent-skills/<listing-name>/index.json` plus the
    /// aggregated `/.well-known/agent-skills/index.json` surface on a
    /// Catalog domain. The registry is empty when the Repo has no
    /// `listings/` directory; in that case the top-level
    /// `agent_skills:` block keeps the WOR-193 surface intact.
    pub listings: sbproxy_config::ListingRegistry,
}

/// Hash a stable view of the loaded origin set into a `config_revision`.
///
/// Webhook receivers, the request log, the access log, the CSV export
/// and `policy_version`'s prefix all carry this value, and every one of
/// them reads it as "the config generation that served the request". So
/// the only property that matters is that it is a pure function of the
/// config's content: equal content, equal revision, on any process, on
/// any host, at any time.
///
/// The view is the routable hostname set in sorted order, each host
/// paired with its rank in that same sorted order, prefixed by the
/// origin count. Rank rather than the index `host_map` stores: those
/// indices are positions into `CompiledConfig::origins`, and a position
/// is a property of how the config was loaded rather than of what it
/// says. WOR-2602 is what that cost. `compile_config` used to walk a
/// `HashMap` to fill those positions, so three boots of one unchanged
/// two-origin file reported two revisions, alternating. The compiler
/// now assigns them in sorted key order, which fixes it at the source;
/// ranking again here means a later change that reorders `origins` for
/// its own reasons cannot reopen the same hole.
///
/// Byte-perfect fidelity to the config is not the goal and never was:
/// the contract is "different when the routable surface differs", not
/// "different when any byte differs".
fn compute_config_revision(config: &CompiledConfig) -> String {
    let mut hosts: Vec<&compact_str::CompactString> = config.host_map.keys().collect();
    hosts.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    let mut buf = Vec::with_capacity(hosts.len() * 32);
    // `hosts.len()` rather than `config.origins.len()`: the two are
    // equal for anything `compile_config` built, one insert and one
    // push per origin, but a hand-assembled `CompiledConfig` can carry
    // vectors that disagree, and a hash that reads two collections has
    // two ways to be wrong. This one reads the collection it hashes.
    buf.extend_from_slice(format!("origins:{}\n", hosts.len()).as_bytes());
    for (rank, host) in hosts.iter().enumerate() {
        buf.extend_from_slice(host.as_bytes());
        buf.push(b'=');
        buf.extend_from_slice(rank.to_string().as_bytes());
        buf.push(b'\n');
    }
    crate::identity::config_revision(&buf)
}

fn compile_sensitive_header_names(config: &CompiledConfig) -> HashSet<String> {
    let mut names = sbproxy_config::types::SENSITIVE_HEADER_DENYLIST
        .iter()
        .map(|name| (*name).to_string())
        .collect::<HashSet<_>>();
    if let Some(key_management) = config.server.key_management.as_ref() {
        names.extend(key_management.inbound.credential_carrier_names());
    }
    names
}

fn empty_extension_registry() -> Arc<DynamicBundleRegistry> {
    DynamicBundleRegistry::load(
        &sbproxy_config::ExtensionBundlesConfig::default(),
        Path::new("."),
        &BTreeSet::new(),
    )
    .expect("an empty extension bundle configuration is valid")
}

fn configured_type(value: &serde_json::Value) -> Option<&str> {
    value.get("type").and_then(serde_json::Value::as_str)
}

impl Default for CompiledPipeline {
    fn default() -> Self {
        let config = CompiledConfig::default();
        let router = HostRouter::new(&config);
        let sensitive_header_names = compile_sensitive_header_names(&config);
        let extension_registry = empty_extension_registry();
        let ai_extension_chain = Arc::new(
            sbproxy_extension::bundle::AiExtensionChain::from_registry(extension_registry.as_ref())
                .expect("linked AI extension registrations must be valid"),
        );
        let extension_inventory = compiled_inventory(
            &extension_registry,
            &config,
            "",
            CompiledExtensionAttachments {
                scope: ExtensionScopeMode::Running,
                ai_chain: ai_extension_chain.as_ref(),
                payment_chain: None,
            },
        )
        .expect("linked extension inventory must be valid");
        Self {
            config,
            extension_registry,
            ai_extension_chain,
            #[cfg(feature = "payments")]
            payment_extension_chain: None,
            extension_inventory,
            key_plane: None,
            sensitive_header_names,
            router,
            actions: Vec::new(),
            mcp_inject_registry: McpInjectRegistry::default(),
            proxy_wasm_filters: Vec::new(),
            background_tasks_started: AtomicBool::new(false),
            compression_runtimes: crate::compression_runtime::CompressionRuntimeRegistry::default(),
            #[cfg(feature = "rag")]
            rag_runtimes: crate::rag_runtime::RagRuntimeRegistry::default(),
            // Attached by the lifecycle after an async health check, never
            // by construction. A default pipeline has no settlement.
            #[cfg(feature = "payments")]
            payments: None,
            // Default construction must stay pure: no config read, no DNS
            // resolution, no Redis dial, no cluster-state read, and no
            // mesh binding. Test pipelines are built this way constantly.
            semantic_caches: crate::semantic_cache_runtime::SemanticCacheRuntimeRegistry::default(),
            auths: Vec::new(),
            policies: Vec::new(),
            enforcers: Vec::new(),
            transforms: Vec::new(),
            forward_rules: Vec::new(),
            fallbacks: Vec::new(),
            bot_detections: Vec::new(),
            threat_protections: Vec::new(),
            outbound_creds: Vec::new(),
            outbound_wba: Vec::new(),
            web_bot_auth_signer: None,
            web_bot_auth_signature_agent: None,
            attestation: None,
            origin_attestations: Vec::new(),
            idempotencies: Vec::new(),
            custom_log_programs: crate::server::custom_log::CompiledLogPrograms::new(),
            cache_store: None,
            origin_cache_stores: HashMap::new(),
            cache_reserve: None,
            cache_reserve_admission: None,
            hooks: crate::hooks::Hooks::default(),
            trusted_proxy_cidrs: Vec::new(),
            tls_fingerprint_config: TlsFingerprintConfig::default(),
            agent_detect_config: AgentDetectConfig::default(),
            page_shield_raw_report_log: false,
            upstream_allow_private_cidrs: Vec::new(),
            config_revision: String::new(),
            dns_resolver: Arc::new(sbproxy_platform::RefreshingResolver::new()),
            listings: sbproxy_config::ListingRegistry::default(),
        }
    }
}

#[derive(Clone, Copy)]
enum PipelineConstructionMode {
    Runtime,
    Validation,
}

/// Process-lifetime runtime for tasks owned by published pipeline generations.
///
/// The synchronous startup path publishes its pipeline before Pingora creates
/// a service runtime. Keeping these tasks here gives startup and reload the
/// same lifetime and prevents a temporary hook or validation runtime from
/// becoming their accidental owner.
fn pipeline_background_runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("sbproxy-pipeline-tasks")
            .enable_all()
            .build()
            .expect("build pipeline background-task runtime")
    })
}

fn parse_outbound_credential_config(
    origin_id: &str,
    config: &serde_json::Value,
) -> anyhow::Result<sbproxy_modules::auth::outbound_credential::OutboundCredentialConfig> {
    let parsed: sbproxy_modules::auth::outbound_credential::OutboundCredentialConfig =
        serde_json::from_value(config.clone())
            .map_err(|error| anyhow::anyhow!("origin {origin_id}: outbound_credential: {error}"))?;
    if let sbproxy_modules::auth::outbound_credential::OutboundCredentialConfig::VaultSecret(
        vault,
    ) = &parsed
    {
        if sbproxy_config::types::credential_header_is_reserved(&vault.header) {
            anyhow::bail!(
                "origin {origin_id}: outbound_credential: header may not carry a credential"
            );
        }
    }
    // WOR-2316: token exchange delegates the caller's identity to an
    // upstream, so its issuer and audience allowlists must be authored.
    // An empty list used to mean "any"; it now denies, and the config
    // that relied on the permissive default is refused here rather than
    // failing every request at runtime.
    parsed
        .validate_allowlists()
        .map_err(|error| anyhow::anyhow!("origin {origin_id}: outbound_credential: {error}"))?;
    Ok(parsed)
}

/// Bind the proxy's zone identity to every compiled load balancer
/// (WOR-2328).
///
/// The zone resolves once per pipeline compilation, `proxy.zone` first
/// and the `SB_ZONE` environment variable as the fallback (config
/// wins), and reaches every `load_balancer` action wherever one can be
/// compiled: per-origin actions, forward-rule inline actions, and
/// fallback actions. With no zone resolved the bind is skipped and
/// selection behaves exactly as it did before zone-aware routing
/// shipped; authored `targets[].zone` labels in that state steer
/// nothing, so the mismatch is called out in one boot warning naming
/// both knobs rather than left silent.
fn bind_zone_identity(pipeline: &CompiledPipeline) {
    use sbproxy_modules::Action;

    let zone = pipeline.config.server.resolve_zone();
    let load_balancers = pipeline
        .actions
        .iter()
        .chain(
            pipeline
                .forward_rules
                .iter()
                .flatten()
                .map(|rule| &rule.action),
        )
        .chain(
            pipeline
                .fallbacks
                .iter()
                .flatten()
                .map(|fallback| &fallback.action),
        )
        .filter_map(|action| match action {
            Action::LoadBalancer(lb) => Some(lb),
            _ => None,
        });

    let mut zoned_but_unbound = false;
    for lb in load_balancers {
        match zone.as_deref() {
            Some(zone) => lb.bind_local_zone(zone),
            None => zoned_but_unbound |= lb.has_zoned_targets(),
        }
    }
    if zoned_but_unbound {
        tracing::warn!(
            "load_balancer targets carry `zone` labels but the proxy has no zone identity; \
             set `proxy.zone` (or the `SB_ZONE` environment variable) to activate same-zone \
             preference, or remove the labels. Until then selection ignores them."
        );
    }
}

impl CompiledPipeline {
    /// Dynamic bundle registry pinned to this pipeline generation.
    pub(crate) fn extension_registry(&self) -> &Arc<DynamicBundleRegistry> {
        &self.extension_registry
    }

    /// Awaited AI hook chain pinned to this pipeline generation.
    pub(crate) fn ai_extension_chain(&self) -> &Arc<sbproxy_extension::bundle::AiExtensionChain> {
        &self.ai_extension_chain
    }

    /// Prepared payment hook chain pinned to this pipeline generation.
    #[cfg(feature = "payments")]
    pub(crate) fn payment_extension_chain(
        &self,
    ) -> Option<&sbproxy_extension::bundle::PaymentExtensionChain> {
        self.payment_extension_chain.as_ref()
    }

    /// Prepare this running generation's inventory for successful payment attachment.
    #[cfg(feature = "payments")]
    pub(crate) fn inventory_with_payment_extensions_attached(
        &self,
    ) -> anyhow::Result<ExtensionInventorySnapshot> {
        Ok(compiled_inventory(
            self.extension_registry.as_ref(),
            &self.config,
            &self.config_revision,
            CompiledExtensionAttachments {
                scope: ExtensionScopeMode::Running,
                ai_chain: self.ai_extension_chain.as_ref(),
                payment_chain: self
                    .payment_extension_chain
                    .as_ref()
                    .filter(|chain| !chain.is_empty()),
            },
        )?)
    }

    /// Publish a precomputed inventory after payment dispatch attaches.
    #[cfg(feature = "payments")]
    pub(crate) fn mark_payment_extensions_attached(
        &mut self,
        inventory: ExtensionInventorySnapshot,
    ) {
        debug_assert_eq!(inventory.scope.mode, ExtensionScopeMode::Running);
        self.extension_inventory = inventory;
    }

    /// Authoritative extension inventory for this pipeline generation.
    #[cfg(test)]
    pub(crate) const fn extension_inventory(&self) -> &ExtensionInventorySnapshot {
        &self.extension_inventory
    }

    /// Dynamic key plane for this exact pipeline generation.
    pub fn key_plane(&self) -> Option<&Arc<crate::key_plane::KeyPlane>> {
        self.key_plane.as_ref()
    }

    /// Whether a request header is sensitive for this pipeline generation.
    pub(crate) fn is_sensitive_header(&self, header_name: &str) -> bool {
        self.sensitive_header_names.contains(header_name)
    }

    /// Immutable inbound key configuration pinned to this pipeline.
    pub(crate) fn inbound_key_config(&self) -> Option<&sbproxy_config::KeyInboundConfig> {
        self.config
            .server
            .key_management
            .as_ref()
            .map(|config| &config.inbound)
    }

    /// Whether a header is a primary credential carrier for this exact
    /// pipeline generation.
    pub(crate) fn is_credential_carrier(&self, header_name: &str) -> bool {
        self.inbound_key_config()
            .is_some_and(|inbound| inbound.is_credential_carrier(header_name))
    }

    /// Resolve an injectable MCP source from this exact pipeline generation.
    ///
    /// `tenant_id` must come from the matched route, not from a caller-mutable
    /// principal attribute. Returning an owned `Arc` keeps the source pinned
    /// without borrowing the pipeline across request work.
    pub(crate) fn mcp_inject_source(
        &self,
        tenant_id: &str,
        server_name: &str,
    ) -> Option<Arc<sbproxy_modules::action::McpInjectSource>> {
        self.mcp_inject_registry.get(tenant_id, server_name)
    }

    /// The response-cache handle the data path must use for `origin_id`.
    ///
    /// With at-rest encryption on, this is the handle bound to that
    /// origin's key ring, which is the only one that can seal or open an
    /// entry: the origin is authenticated in every envelope, so reading
    /// one tenant's entry through another tenant's handle fails rather
    /// than returning plaintext. With encryption off there are no
    /// per-origin handles and every origin gets the one shared store,
    /// exactly as before.
    ///
    /// [`Self::cache_store`] is the purge handle. Reaching for it on the
    /// data path is the mistake this method exists to prevent.
    pub fn cache_store_for(&self, origin_id: &str) -> Option<&Arc<dyn CacheStore>> {
        self.origin_cache_stores
            .get(origin_id)
            .or(self.cache_store.as_ref())
    }

    /// Compile a config into a full pipeline with modules instantiated.
    ///
    /// Iterates over every origin in the config, compiling its action,
    /// auth, and policy JSON values into typed enum variants. Fails if
    /// any origin has an invalid or unrecognized module config.
    pub fn from_config(config: CompiledConfig) -> anyhow::Result<Self> {
        Self::from_config_with_mode(config, PipelineConstructionMode::Runtime)
    }

    /// Compile a runtime pipeline with bundle paths relative to its config document.
    ///
    /// Background tasks stay dormant until the pipeline reaches
    /// [`crate::reload::load_pipeline`], so a lifecycle hook can still reject
    /// this candidate without leaving work behind.
    pub fn from_config_at(config: CompiledConfig, base_dir: &Path) -> anyhow::Result<Self> {
        let fetch_context =
            crate::config_source::build_extension_fetch_context(&config.extension_bundles)?;
        let extension_registry = DynamicBundleRegistry::load_with_context(
            &config.extension_bundles,
            base_dir,
            &reserved_extension_hook_names()?,
            &fetch_context,
        )?;
        Self::from_config_with_mode_and_registry(
            config,
            PipelineConstructionMode::Runtime,
            extension_registry,
            false,
        )
    }

    /// Construct a runtime pipeline around an already validated immutable
    /// bundle registry candidate.
    pub(crate) fn from_config_at_with_extension_registry(
        config: CompiledConfig,
        extension_registry: Arc<DynamicBundleRegistry>,
    ) -> anyhow::Result<Self> {
        Self::from_config_with_mode_and_registry(
            config,
            PipelineConstructionMode::Runtime,
            extension_registry,
            false,
        )
    }

    /// Compile every module for validation, without side effects that
    /// outlive the returned pipeline.
    ///
    /// Use this whenever the pipeline is built only to find out whether a
    /// config would construct, and is then dropped. Unlike
    /// [`Self::from_config`] it spawns no background tasks, does not create
    /// cache directories, and does not resolve the response-cache
    /// encryption key. It also avoids the process cluster handle and the
    /// shared AI client, deriving equivalents from the config instead.
    ///
    /// It is not fully isolated from process state. Module construction
    /// still reads the AI provider registry, still resolves secret
    /// references through the process secret resolver, and still populates
    /// the shared JWKS cache. Those are reads and idempotent inserts rather
    /// than installs, so repeated calls are safe, but a caller cannot treat
    /// this as a pure function.
    pub fn from_config_for_validation(config: CompiledConfig) -> anyhow::Result<Self> {
        Self::from_config_for_validation_at(config, Path::new("."))
    }

    /// Compile every module for validation with bundle paths relative to its config document.
    pub fn from_config_for_validation_at(
        config: CompiledConfig,
        base_dir: &Path,
    ) -> anyhow::Result<Self> {
        let reserved_names = reserved_extension_hook_names()?;
        let fetch_context =
            crate::config_source::build_extension_fetch_context(&config.extension_bundles)?;
        let extension_registry = DynamicBundleRegistry::load_with_context(
            &config.extension_bundles,
            base_dir,
            &reserved_names,
            &fetch_context,
        )?;
        Self::from_config_with_mode_and_registry(
            config,
            PipelineConstructionMode::Validation,
            extension_registry,
            false,
        )
    }

    fn from_config_with_mode(
        config: CompiledConfig,
        mode: PipelineConstructionMode,
    ) -> anyhow::Result<Self> {
        Self::from_config_with_mode_and_registry(
            config,
            mode,
            empty_extension_registry(),
            matches!(mode, PipelineConstructionMode::Runtime),
        )
    }

    fn from_config_with_mode_and_registry(
        config: CompiledConfig,
        mode: PipelineConstructionMode,
        extension_registry: Arc<DynamicBundleRegistry>,
        start_background_tasks: bool,
    ) -> anyhow::Result<Self> {
        // WOR-2084: async twin of the shared L2 store. The rate-limit
        // policy's hot path awaits `AsyncKVStore::incr_with_ttl`
        // directly when this is attached, instead of bridging every
        // shared-counter decision through `spawn_blocking`. Built once
        // and shared across origins; the sync handle stays attached too
        // as the fallback and for callers that have not migrated.
        let l2_async_store: Option<Arc<dyn sbproxy_platform::storage::AsyncKVStore>> = config
            .l2_store
            .as_deref()
            .and_then(|kv| kv.validated_redis_connection())
            .map(|connection| {
                sbproxy_platform::storage::AsyncRedisKVStore::new(
                    sbproxy_platform::storage::AsyncRedisConfig::from_connection(connection),
                ) as Arc<dyn sbproxy_platform::storage::AsyncKVStore>
            });

        let sensitive_header_names = compile_sensitive_header_names(&config);
        let mut actions = Vec::with_capacity(config.origins.len());
        let mut mcp_inject_registry = McpInjectRegistry::default();
        let mut proxy_wasm_filters = Vec::with_capacity(config.origins.len());
        let mut auths = Vec::with_capacity(config.origins.len());
        let mut policies = Vec::with_capacity(config.origins.len());
        let mut enforcers: Vec<Vec<CompiledEnforcer>> = Vec::with_capacity(config.origins.len());
        let mut transforms = Vec::with_capacity(config.origins.len());
        let mut forward_rules = Vec::with_capacity(config.origins.len());
        let mut fallbacks = Vec::with_capacity(config.origins.len());
        let mut bot_detections = Vec::with_capacity(config.origins.len());
        let mut threat_protections = Vec::with_capacity(config.origins.len());
        let mut outbound_creds = Vec::with_capacity(config.origins.len());
        let mut outbound_wba = Vec::with_capacity(config.origins.len());
        let mut origin_attestations: Vec<crate::attestation::ResolvedOriginAttestation> =
            Vec::with_capacity(config.origins.len());

        for origin in &config.origins {
            // Compile action (required for every origin).
            let action_identity = routing_action_identity(
                origin.workspace_id.as_str(),
                origin.origin_id.as_str(),
                None,
            );
            // The registry rides along for every action type, not only
            // the ones a loaded bundle names: a built-in action may attach
            // bundle hooks by `type:`, and `ai_proxy`'s `engine: wasm`
            // routing policy is the first that does (WOR-2366). Finding a
            // bundle action is still the compiler's job, in its
            // unknown-type fall-through, so a built-in or linked-plugin
            // `type:` reaches exactly the arm it always did.
            //
            // `mut` because an MCP action is bound to its route authority
            // immediately below.
            let mut action = match mode {
                PipelineConstructionMode::Runtime => compile_action_for_origin_with_registry(
                    &origin.action_config,
                    &action_identity,
                    extension_registry.as_ref(),
                )?,
                PipelineConstructionMode::Validation => {
                    compile_action_for_origin_for_validation_with_registry(
                        &origin.action_config,
                        &action_identity,
                        extension_registry.as_ref(),
                    )?
                }
            };
            if let Action::Mcp(mcp) = &mut action {
                mcp.bind_exact_route_authority(origin.hostname.as_str());
                mcp_inject_registry.insert(
                    origin.tenant_id.as_str(),
                    &mcp.server_name,
                    mcp.inject_source(),
                )?;
            }
            let proxy_wasm_filter = if origin.filters.is_empty() {
                None
            } else {
                if !matches!(&action, Action::Proxy(_)) {
                    anyhow::bail!(
                        "origin `{}`: Proxy-Wasm filters require a proxy action",
                        origin.origin_id
                    );
                }
                Some(crate::proxy_wasm_http::ProxyWasmFilterChain::compile(
                    origin.origin_id.as_str(),
                    &origin.filters,
                    extension_registry.as_ref(),
                )?)
            };
            proxy_wasm_filters.push(proxy_wasm_filter);
            let origin_action_is_mcp = matches!(&action, Action::Mcp(_));
            actions.push(action);

            // Compile auth (optional per origin). Route through the
            // registry-aware compile only when the `type:` names a loaded
            // bundle auth hook, so built-ins and linked plugins keep their
            // exact existing path (WOR-2426). A list-form block (WOR-2517)
            // takes the registry-aware path when any entry names a bundle
            // hook, for the same reason a scalar one does.
            let auth = match &origin.auth_config {
                Some(cfg) => {
                    let names_bundle_hook = |value: &serde_json::Value| {
                        configured_type(value)
                            .is_some_and(|name| extension_registry.auth(name).is_some())
                    };
                    let uses_bundle_hook = match cfg.as_array() {
                        Some(entries) => entries.iter().any(names_bundle_hook),
                        None => names_bundle_hook(cfg),
                    };
                    Some(if uses_bundle_hook {
                        compile_auth_with_registry(cfg, extension_registry.as_ref())?
                    } else {
                        compile_auth(cfg)?
                    })
                }
                None => None,
            };
            auths.push(auth);

            // Compile policies (zero or more per origin) twice: once for the
            // response-phase `Vec<Policy>` that SecHeaders/PageShield/Sri
            // walk at response time, and once for the request-phase
            // `Vec<Box<dyn PolicyEnforcer>>` the dispatcher iterates. The
            // built-in `compile_policy` is a pure parse over `serde_json::Value`,
            // so the double pass is one-time at config load and has no
            // request-path cost.
            let origin_policies = compile_origin_policy_chain(
                &origin.policy_configs,
                config.l2_store.clone(),
                l2_async_store.clone(),
                origin.origin_id.as_str(),
                extension_registry.as_ref(),
            )?;
            let policies_for_enforcers = compile_origin_policy_chain(
                &origin.policy_configs,
                config.l2_store.clone(),
                l2_async_store.clone(),
                origin.origin_id.as_str(),
                extension_registry.as_ref(),
            )?;
            // WOR-2164: enforcers that compile static CEL (the rate
            // limiter's `key:`) reject the candidate config here, so
            // name the origin the same way the policy chain does.
            use anyhow::Context as _;
            let origin_id_for_enforcers = origin.origin_id.as_str();
            enforcers.push(
                compile_builtin_enforcers(policies_for_enforcers, origin.hostname.as_str())
                    .with_context(|| {
                        format!("origin `{origin_id_for_enforcers}`: invalid policy config")
                    })?,
            );
            policies.push(origin_policies);

            // Compile transforms (zero or more per origin).
            let origin_transforms: Vec<CompiledTransform> = origin
                .transform_configs
                .iter()
                .filter_map(|cfg| {
                    // Parse wrapper config to check disabled flag and extract metadata.
                    let wrapper: TransformConfig = match serde_json::from_value(cfg.clone()) {
                        Ok(w) => w,
                        Err(e) => {
                            return Some(Err(anyhow::anyhow!("invalid transform config: {}", e)))
                        }
                    };
                    // Validated before the disabled check on purpose: a
                    // failure axis that says two things at once is a config
                    // error even on a transform that is currently off.
                    if let Err(e) = wrapper.validate_failure_posture() {
                        return Some(Err(e));
                    }
                    if wrapper.disabled {
                        return None;
                    }
                    let compiled = if configured_type(cfg)
                        .is_some_and(|name| extension_registry.transform(name).is_some())
                    {
                        compile_transform_with_registry(cfg, extension_registry.as_ref())
                    } else {
                        compile_transform(cfg)
                    };
                    let transform = match compiled {
                        Ok(t) => t,
                        // WOR-2179: name the origin, the same way the
                        // policy chain does, so an operator can find the
                        // offending block. The transform module's own
                        // error names the transform and, for CEL, quotes
                        // the bad expression.
                        Err(e) => {
                            return Some(Err(e.context(format!(
                                "origin `{}`: invalid transform config",
                                origin.origin_id
                            ))))
                        }
                    };
                    let failure_posture = effective_transform_posture(&wrapper, &transform);
                    Some(Ok(CompiledTransform {
                        transform,
                        content_types: wrapper.content_types,
                        failure_posture,
                        max_body_size: wrapper.max_body_size,
                    }))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            // The response cache stores each transform's output at
            // admission and replays it to every later requester, and
            // the stale-while-revalidate refresh reruns the chain with
            // no request in scope. Both are sound only for transforms
            // whose output is a pure function of the response, so a
            // request-dependent transform on a cached origin is
            // refused here, where the compiled variant can answer for
            // itself, rather than trusted to an operator promise.
            if origin
                .response_cache
                .as_ref()
                .is_some_and(|cache| cache.enabled)
            {
                if let Some(dependent) = origin_transforms
                    .iter()
                    .find(|compiled| compiled.transform.request_dependent())
                {
                    anyhow::bail!(
                        "origin `{}`: transform `{}` reads request state, so its output cannot be \
                         stored in the response cache or recomputed by the stale-while-revalidate \
                         refresh; remove the transform, disable `response_cache`, or split the \
                         cached content onto its own origin",
                        origin.origin_id,
                        dependent.transform.transform_type()
                    );
                }
            }
            transforms.push(origin_transforms);

            // Compile forward rules (zero or more per origin).
            let mut origin_fwd_rules = compile_forward_rules(
                &origin.forward_rules,
                origin.workspace_id.as_str(),
                origin.origin_id.as_str(),
                mode,
                extension_registry.as_ref(),
            )?;
            for rule in &mut origin_fwd_rules {
                if let Action::Mcp(mcp) = &mut rule.action {
                    mcp.bind_exact_route_authority(origin.hostname.as_str());
                }
            }
            // MCP picks its protocol era and trust anchor from the route
            // before the body is buffered or auth has run. Any rule that
            // could be selected ahead of an mcp action therefore has to be
            // decidable from method, path, headers, and query alone;
            // otherwise the gateway cannot tell pre-auth whether a request
            // belongs to MCP at all.
            // Guard through the LAST mcp rule, not up to the first. The mcp
            // rule's own matchers decide whether MCP is selected at all, and a
            // rule sitting between two mcp rules is still ahead of one of them.
            let guarded_rules = if origin_action_is_mcp {
                origin_fwd_rules.len()
            } else {
                origin_fwd_rules
                    .iter()
                    .rposition(|rule| matches!(&rule.action, Action::Mcp(_)))
                    .map_or(0, |index| index + 1)
            };
            for rule in origin_fwd_rules.iter().take(guarded_rules) {
                if let Some(label) = rule.matchers.iter().find_map(indeterminate_matcher_label) {
                    anyhow::bail!(
                        "origin `{}`: forward rule matcher `{label}` cannot be decided before an \
                         `mcp` action is selected, so it would shadow MCP route selection; drop \
                         the `{label}` matcher or move the mcp action onto its own origin",
                        origin.hostname
                    );
                }
            }
            if !origin.filters.is_empty() {
                if let Some((rule_index, _)) = origin_fwd_rules
                    .iter()
                    .enumerate()
                    .find(|(_, rule)| !matches!(&rule.action, Action::Proxy(_)))
                {
                    anyhow::bail!(
                        "origin `{}`: Proxy-Wasm filters require forward rule {rule_index} to use a proxy action",
                        origin.origin_id
                    );
                }
            }
            forward_rules.push(origin_fwd_rules);

            // Compile fallback origin (optional per origin).
            let fallback =
                compile_fallback(&origin.fallback_origin, mode, extension_registry.as_ref())?;
            // The fallback dispatcher serves a prepared response after the
            // primary action already failed. It has no MCP session, no
            // negotiated era, and no trust anchor, so an `mcp` action placed
            // here could never dispatch.
            if fallback
                .as_ref()
                .is_some_and(|fallback| matches!(&fallback.action, Action::Mcp(_)))
            {
                anyhow::bail!(
                    "origin `{}`: fallback_origin cannot serve an `mcp` action; the fallback \
                     dispatcher has no negotiated MCP era or trust anchor to dispatch through",
                    origin.hostname
                );
            }
            if !origin.filters.is_empty() && fallback.is_some() {
                anyhow::bail!(
                    "origin `{}`: Proxy-Wasm filters do not support fallback_origin responses",
                    origin.origin_id
                );
            }
            fallbacks.push(fallback);

            // Compile bot detection (optional per origin).
            let bot = match &origin.bot_detection {
                Some(cfg) => Some(BotDetection::from_config(cfg.clone())?),
                None => None,
            };
            bot_detections.push(bot);

            // Compile threat protection (optional per origin).
            let threat = match &origin.threat_protection {
                Some(cfg) => Some(ThreatProtection::from_config(cfg.clone())?),
                None => None,
            };
            threat_protections.push(threat);

            // Compile outbound credential resolver (optional per origin).
            // WOR-802: parse the JSON into the typed closed enum so a bad
            // mode fails config load rather than silently at request time.
            let outbound_cred = match &origin.outbound_credential {
                Some(cfg) => {
                    let mut parsed = parse_outbound_credential_config(&origin.origin_id, cfg)?;
                    if parsed.is_dpop_enabled()
                        && (matches!(actions.last(), Some(Action::LoadBalancer(_)))
                            || forward_rules.last().is_some_and(|rules| {
                                rules
                                    .iter()
                                    .any(|rule| matches!(&rule.action, Action::LoadBalancer(_)))
                            }))
                    {
                        anyhow::bail!(
                            "origin {}: outbound_credential: DPoP is not supported with load-balanced actions",
                            origin.origin_id
                        );
                    }
                    // Live pipelines resolve and compile the DPoP private key
                    // at boot. Validation pipelines check only the reference,
                    // algorithm, and public JWK so CLI validation never
                    // dereferences an external secret.
                    let prepared = match mode {
                        PipelineConstructionMode::Runtime => parsed.resolve_runtime_secret_refs(),
                        PipelineConstructionMode::Validation => parsed.validate_dpop(),
                    };
                    prepared.map_err(|e| {
                        anyhow::anyhow!("origin {}: outbound_credential: {}", origin.origin_id, e)
                    })?;
                    Some(parsed)
                }
                None => None,
            };
            outbound_creds.push(outbound_cred);
            outbound_wba.push(origin.outbound_web_bot_auth);

            // WOR-2127: compose the proxy-wide attestation role with
            // this origin's override once, here, rather than per
            // request. Resolved even when the block is absent, so the
            // vector stays index-parallel with `config.origins` and the
            // request path can index it without a bounds dance.
            origin_attestations.push(crate::attestation::resolve_origin_attestation(
                config.server.attestation.as_ref(),
                origin.attestation.as_ref(),
            ));
        }

        // --- Compile per-origin idempotency middleware ---
        //
        // Built after the main per-origin loop because the Redis backend
        // binds to the cluster L2 store on `CompiledConfig`. Memory
        // backends are origin-local. An origin asking for `backend:
        // redis` without `proxy.l2_store` configured surfaces a clear
        // compile-time error rather than silently downgrading.
        let mut idempotencies: Vec<Option<Arc<CompiledIdempotency>>> =
            Vec::with_capacity(config.origins.len());
        for origin in &config.origins {
            let cfg = match origin.idempotency.as_ref() {
                Some(c) if c.enabled => c,
                _ => {
                    idempotencies.push(None);
                    continue;
                }
            };
            let compiled = compile_origin_idempotency(cfg, &config)
                .map_err(|e| anyhow::anyhow!("origin {}: {}", origin.origin_id, e))?;
            idempotencies.push(Some(Arc::new(compiled)));
        }

        let router = HostRouter::new(&config);

        // --- Shared response cache backend ---
        //
        // One store serves every origin; the cache key namespaces by
        // workspace and hostname so they cannot collide. The store is
        // only built when at least one origin has
        // `response_cache.enabled = true`, so a config that does not
        // cache pays nothing.
        //
        // `proxy.response_cache_store` selects the backend explicitly.
        // When that block is absent the selection is the historical one,
        // Redis if `proxy.l2_cache` is set and an in-process map
        // otherwise, so an upgrade never moves an existing deployment
        // off the backend it already had.
        let any_cache_enabled = config
            .origins
            .iter()
            .any(|o| o.response_cache.as_ref().is_some_and(|c| c.enabled));
        let cache_store: Option<ResponseCacheStores> = if any_cache_enabled {
            // Take the largest configured max_size across origins so the
            // shared memory cache can fit all of them.
            let memory_max = config
                .origins
                .iter()
                .filter_map(|o| o.response_cache.as_ref())
                .map(|c| c.max_size)
                .max()
                .unwrap_or(10_000);
            let redis_store: Option<Arc<dyn CacheStore>> = config
                .l2_store
                .clone()
                .map(|kv| Arc::new(RedisCacheStore::new(kv)) as Arc<dyn CacheStore>);
            let origin_keys: Vec<OriginCacheKeys<'_>> = config
                .origins
                .iter()
                .map(|o| {
                    let encryption = o
                        .response_cache
                        .as_ref()
                        .and_then(|c| c.encryption.as_ref());
                    OriginCacheKeys {
                        id: o.origin_id.as_str(),
                        caches: o.response_cache.as_ref().is_some_and(|c| c.enabled),
                        key: encryption.and_then(|e| e.key.as_deref()),
                        previous_keys: encryption
                            .map(|e| e.previous_keys.as_slice())
                            .unwrap_or(&[]),
                    }
                })
                .collect();
            Some(build_response_cache_store(
                config.server.response_cache_store.as_ref(),
                redis_store,
                memory_max,
                &origin_keys,
                mode,
            )?)
        } else {
            None
        };
        let (cache_store, origin_cache_stores) = match cache_store {
            Some(stores) => (Some(stores.unscoped), stores.per_origin),
            None => (None, HashMap::new()),
        };

        // --- Cache Reserve cold tier ---
        //
        // Built from the top-level `cache_reserve:` block. The OSS
        // backends (memory / filesystem / redis) are instantiated here;
        // unknown or extension-provided backends drop through to `None` with a
        // warning so a pipeline lifecycle hook can swap in its own
        // implementation post-compile.
        let (cache_reserve, cache_reserve_admission) =
            build_cache_reserve(&config.server.cache_reserve);

        // Pre-parse trusted_proxies CIDRs once at compile time so the
        // request path can do a constant-time membership check. An
        // invalid entry fails the compile rather than silently
        // shrinking the trust list.
        let trusted_proxy_cidrs: Vec<ipnetwork::IpNetwork> = sbproxy_security::parse_cidrs(
            config.server.trusted_proxies.iter().map(String::as_str),
            "trusted_proxies",
        )?;

        let config_revision = compute_config_revision(&config);

        // Wave 5 day-6 Item 3: lift TLS-fingerprint config off
        // proxy.extensions[tls_fingerprint] (which the day-6 Item 2
        // migration also fills from legacy features.tls_fingerprint).
        let tls_fingerprint_config =
            TlsFingerprintConfig::from_extensions(&config.server.extensions)?;
        let agent_detect_config = AgentDetectConfig::from_extensions(&config.server.extensions)?;

        // --- Page Shield raw-report opt-in ---
        // CSP reports default to redacted-only structured logs. The
        // operator can opt into raw-body capture for forensics.
        let page_shield_raw_report_log = config
            .server
            .extensions
            .get("page_shield")
            .and_then(|v| v.get("raw_report_log"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // --- SSRF private-CIDR allowlist ---
        // Operators that intentionally target a private network
        // (corporate VPN, mesh sidecar, internal registry) opt in
        // explicitly. An invalid CIDR fails the config compile.
        let upstream_allow_private_cidrs: Vec<ipnetwork::IpNetwork> = config
            .server
            .extensions
            .get("upstream")
            .and_then(|v| v.get("allow_private_cidrs"))
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                sbproxy_security::parse_cidrs(
                    seq.iter().filter_map(|entry| entry.as_str()),
                    "upstream.allow_private_cidrs",
                )
            })
            .transpose()?
            .unwrap_or_default();

        // WOR-805: build the shared outbound Web Bot Auth signer once
        // from the proxy-level key. Origins opt in per-origin via
        // `outbound_web_bot_auth` (collected in `outbound_wba`); the
        // signer and the Signature-Agent directory URL are shared.
        let (web_bot_auth_signer, web_bot_auth_signature_agent) =
            match config.server.web_bot_auth.as_ref() {
                Some(wba) => {
                    let seed = hex::decode(&wba.ed25519_seed_hex).map_err(|e| {
                        anyhow::anyhow!("proxy.web_bot_auth.ed25519_seed_hex: invalid hex: {e}")
                    })?;
                    let signer = sbproxy_middleware::signatures_egress::MessageSigner::new(
                        sbproxy_middleware::signatures_egress::SignerConfig {
                            key_id: wba.key_id.clone(),
                            algorithm: sbproxy_middleware::signatures::SignatureAlgorithm::Ed25519,
                            secret: seed,
                            covered_components: vec![
                                "@authority".to_string(),
                                "@method".to_string(),
                                "@path".to_string(),
                            ],
                        },
                    )
                    .map_err(|e| anyhow::anyhow!("proxy.web_bot_auth outbound signer: {e}"))?
                    // Web Bot Auth signatures are short-lived; a 60s window
                    // is consumed by the immediate upstream verifier.
                    .with_web_bot_auth_profile("web-bot-auth", 60);
                    (Some(Arc::new(signer)), wba.directory_url.clone())
                }
                None => (None, None),
            };

        let compression_runtimes = match mode {
            PipelineConstructionMode::Runtime => {
                crate::compression_runtime::CompressionRuntimeRegistry::from_process(
                    &config.server,
                    config.l2_store.as_deref(),
                    &actions,
                )?
            }
            PipelineConstructionMode::Validation => {
                crate::compression_runtime::CompressionRuntimeRegistry::for_validation(
                    &config.server,
                    config.l2_store.as_deref(),
                    &actions,
                )?
            }
        };

        // WOR-2098: build the route-scoped RAG runtimes after both the
        // main actions and the forward rules are compiled. Validation
        // construction maps to `RagBuildMode::Validation`, which checks
        // every configured provider without dialing.
        #[cfg(feature = "rag")]
        let rag_runtimes = crate::rag_runtime::RagRuntimeRegistry::build(
            &actions,
            &forward_rules,
            match mode {
                PipelineConstructionMode::Runtime => sbproxy_rag::RagBuildMode::Runtime,
                PipelineConstructionMode::Validation => sbproxy_rag::RagBuildMode::Validation,
            },
        )?;
        // Without the `rag` feature a configured `rag:` block must fail
        // loud at construction rather than silently proxying unaugmented
        // traffic.
        #[cfg(not(feature = "rag"))]
        reject_configured_rag(&actions, &forward_rules)?;

        // WOR-2099: build the route-scoped semantic caches after both the
        // main actions and the forward rules are compiled, because a
        // forward rule carries its own `semantic_cache:` block and never
        // inherits the origin's. Validation construction checks the same
        // configuration and dependency declarations but binds stub stores,
        // so validating a candidate config dials neither Redis nor the
        // mesh.
        let semantic_caches = match mode {
            PipelineConstructionMode::Runtime => {
                crate::semantic_cache_runtime::SemanticCacheRuntimeRegistry::from_process(
                    &config.server,
                    config.l2_store.as_deref(),
                    &config.origins,
                    &actions,
                    &forward_rules,
                )?
            }
            PipelineConstructionMode::Validation => {
                crate::semantic_cache_runtime::SemanticCacheRuntimeRegistry::for_validation(
                    &config.server,
                    config.l2_store.as_deref(),
                    &config.origins,
                    &actions,
                    &forward_rules,
                )?
            }
        };

        let key_plane = match mode {
            PipelineConstructionMode::Runtime => {
                crate::key_plane::prepare_key_plane(config.server.key_management.as_ref())?
            }
            PipelineConstructionMode::Validation => None,
        };

        // WOR-2127: lower `proxy.attestation` into the metering
        // vocabulary. Runtime only, because the queue and the ledger are
        // filesystem state and `sbproxy validate` must be able to check
        // a candidate config without creating directories for a proxy
        // that is not going to run. Everything decidable without a
        // filesystem was already decided at config compile, so
        // validation still rejects a broken block.
        // WOR-2128: the revision goes in here rather than being read at
        // resolve time. Every route weight this generation produces cites
        // it, and a weight that cited whatever config happened to be live
        // when the receipt was written would name a document that did not
        // price the call.
        // WOR-2145: the receipt chain is opened here too, under the same
        // runtime-only gate and for the same reason. `node_id` is the mesh
        // identity when a mesh is configured, because that is the key a
        // cluster-wide gather files chain segments under; with no mesh
        // there is one chain and the per-process instance id names it.
        // Matching `admin_meter`'s derivation is load bearing: a chain
        // written under one id and reported under another is a chain
        // nobody can attribute.
        let attestation = match mode {
            PipelineConstructionMode::Runtime => {
                let node_id = crate::cluster::current_cluster_handle()
                    .map(|handle| handle.identity().node_id.clone())
                    .unwrap_or_else(|| crate::identity::instance_id().to_string());
                crate::attestation::prepare_attestation(
                    config.server.attestation.as_ref(),
                    config.server.web_bot_auth.as_ref(),
                    &config_revision,
                    &node_id,
                )?
            }
            PipelineConstructionMode::Validation => None,
        };

        // WOR-2164: parse every `engine: cel` custom log field for this
        // generation here, while the config is still borrowable, so the
        // access-log path evaluates rather than parsing per record and
        // malformed source rejects the candidate config.
        let custom_log_programs = crate::server::custom_log::compile_cel_programs(&config)?;
        let ai_extension_chain =
            Arc::new(sbproxy_extension::bundle::AiExtensionChain::from_registry(
                extension_registry.as_ref(),
            )?);
        let payment_extension_chain = config
            .server
            .payments
            .as_ref()
            .map(|_| {
                sbproxy_extension::bundle::PaymentExtensionChain::from_registry(
                    extension_registry.as_ref(),
                )
            })
            .transpose()?;
        let scope = match mode {
            PipelineConstructionMode::Runtime => ExtensionScopeMode::Running,
            PipelineConstructionMode::Validation => ExtensionScopeMode::Doctor,
        };
        let extension_inventory = compiled_inventory(
            extension_registry.as_ref(),
            &config,
            &config_revision,
            CompiledExtensionAttachments {
                scope,
                ai_chain: ai_extension_chain.as_ref(),
                payment_chain: matches!(mode, PipelineConstructionMode::Validation)
                    .then(|| payment_extension_chain.as_ref())
                    .flatten()
                    .filter(|chain| !chain.is_empty()),
            },
        )?;

        let pipeline = Self {
            config,
            extension_registry,
            ai_extension_chain,
            #[cfg(feature = "payments")]
            payment_extension_chain,
            extension_inventory,
            key_plane,
            sensitive_header_names,
            router,
            actions,
            mcp_inject_registry,
            proxy_wasm_filters,
            background_tasks_started: AtomicBool::new(false),
            compression_runtimes,
            #[cfg(feature = "rag")]
            rag_runtimes,
            // Attached by the lifecycle after an async health check, never
            // by construction: publishing starts a worker, and a candidate
            // that is then discarded must not leave one claiming leases.
            #[cfg(feature = "payments")]
            payments: None,
            semantic_caches,
            auths,
            policies,
            enforcers,
            transforms,
            forward_rules,
            fallbacks,
            bot_detections,
            threat_protections,
            outbound_creds,
            outbound_wba,
            web_bot_auth_signer,
            web_bot_auth_signature_agent,
            attestation,
            origin_attestations,
            idempotencies,
            custom_log_programs,
            cache_store,
            origin_cache_stores,
            cache_reserve,
            cache_reserve_admission,
            hooks: crate::hooks::Hooks::default(),
            trusted_proxy_cidrs,
            tls_fingerprint_config,
            agent_detect_config,
            page_shield_raw_report_log,
            upstream_allow_private_cidrs,
            config_revision,
            dns_resolver: Arc::new(sbproxy_platform::RefreshingResolver::new()),
            listings: sbproxy_config::ListingRegistry::default(),
        };
        // Bind the proxy's zone identity to every compiled load
        // balancer (WOR-2328) before any request can select through
        // one. Both construction modes bind, so `sbproxy validate`
        // and `doctor` see the same locality posture the runtime will.
        bind_zone_identity(&pipeline);

        // Spawn active health-check probes for any load_balancer
        // target that has `health_check:` configured. Best-effort: if
        // we are not running inside a Tokio runtime (e.g. unit tests),
        // the call is a no-op.
        //
        // Validation-mode pipelines are thrown away by the caller, so they
        // must never issue probes against the operator's upstreams. Runtime
        // candidates built relative to a config path are activated only by
        // the publication boundary after lifecycle hooks have accepted them.
        if start_background_tasks {
            pipeline.start_background_tasks();
        }
        Ok(pipeline)
    }

    /// Start background tasks owned by the pipeline.
    ///
    /// Currently this covers the active health-check probes on
    /// `Action::LoadBalancer` targets and on `Action::AiProxy` provider
    /// pools, but it is the seam any future pipeline-scoped task (e.g.
    /// periodic cache eviction sweeps, dynamic blocklist refresh) will
    /// plug into.
    fn start_background_tasks(&self) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        self.start_background_tasks_on(&handle);
    }

    /// Activate tasks for a pipeline that has passed every publication gate.
    ///
    /// Startup compilation runs before Pingora creates its service runtimes,
    /// so published tasks live on a dedicated process-lifetime runtime rather
    /// than whichever short-lived runtime happened to construct the pipeline.
    pub(crate) fn activate_background_tasks(&self) {
        self.start_background_tasks_on(pipeline_background_runtime().handle());
    }

    fn start_background_tasks_on(&self, handle: &tokio::runtime::Handle) {
        if self.background_tasks_started.swap(true, Ordering::AcqRel) {
            return;
        }
        for action in &self.actions {
            match action {
                sbproxy_modules::Action::LoadBalancer(lb) => {
                    lb.spawn_health_probes_on(handle);
                }
                // The AI provider pool carries the same active-probe
                // axis, and its router consults the flag on every
                // routing decision. Without this arm the pool's
                // `resilience.health_check` block parses and is then
                // never acted on (WOR-2224).
                sbproxy_modules::Action::AiProxy(ai) => {
                    sbproxy_ai::health_probe::spawn_provider_health_probes_on(&ai.config, handle);
                }
                _ => {}
            }
        }
    }

    /// Construct a minimal empty pipeline for unit tests.
    ///
    /// All vectors are empty, the router is built from an empty config, and
    /// hooks default to `None`. Intended only for tests that need to assert
    /// invariants on a freshly constructed pipeline without compiling any
    /// origins.
    #[cfg(test)]
    pub(crate) fn empty_for_test() -> Self {
        Self::default()
    }

    /// Resolve a hostname to an origin index.
    ///
    /// Uses the bloom filter to fast-reject unknown hostnames before
    /// falling through to the HashMap lookup. Exact origin keys win
    /// over `*.suffix` wildcards; between wildcards the longest
    /// matching suffix wins.
    pub fn resolve_origin(&self, hostname: &str) -> Option<usize> {
        self.router.resolve(hostname)
    }
}

// --- Forward rule / fallback compilation helpers ---

/// Compile a list of forward rule JSON values into typed forward rules.
/// Compile one origin's policy chain from its raw JSON configs and
/// attach the cluster-shared L2 store to each RateLimit policy.
///
/// Called twice per origin during `CompiledPipeline::from_config`:
/// once for the response-phase `Vec<Policy>` stored on
/// `pipeline.policies` and once for the request-phase
/// `Vec<Box<dyn PolicyEnforcer>>` stored on `pipeline.enforcers`.
/// Both call sites pass the same inputs so the two chains stay in
/// lockstep.
/// Build a [`CompiledIdempotency`] from the authored YAML block.
///
/// `Memory` backend allocates a fresh in-process cache per origin so
/// each origin has its own keyspace and a config reload does not leak
/// state across configs. `Redis` backend wraps the cluster L2 store
/// declared at `proxy.l2_store`; if that is absent the function
/// returns an error rather than silently downgrading.
fn compile_origin_idempotency(
    cfg: &sbproxy_config::IdempotencyConfig,
    config: &CompiledConfig,
) -> anyhow::Result<CompiledIdempotency> {
    let ttl_secs = cfg
        .ttl_secs
        .unwrap_or(sbproxy_middleware::idempotency::DEFAULT_TTL_SECS);
    let header_name = cfg
        .header_name
        .as_deref()
        .unwrap_or(sbproxy_middleware::idempotency::IDEMPOTENCY_KEY_HEADER)
        .to_string();
    let methods = match cfg.methods.as_ref() {
        Some(list) => list
            .iter()
            .map(|m| {
                http::Method::from_bytes(m.to_ascii_uppercase().as_bytes()).map_err(|e| {
                    anyhow::anyhow!("invalid HTTP method `{}` in idempotency.methods: {}", m, e)
                })
            })
            .collect::<anyhow::Result<smallvec::SmallVec<[http::Method; 4]>>>()?,
        None => {
            // Default: the three methods that conventionally carry an
            // Idempotency-Key per RFC 8594 §2.
            smallvec::smallvec![http::Method::POST, http::Method::PUT, http::Method::PATCH,]
        }
    };
    let cache: Arc<dyn sbproxy_middleware::idempotency::IdempotencyCache> = match cfg.backend {
        sbproxy_config::IdempotencyBackend::Memory => {
            Arc::new(sbproxy_middleware::idempotency::InMemoryIdempotencyCache::new())
        }
        sbproxy_config::IdempotencyBackend::Redis => {
            let kv = config.l2_store.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "idempotency.backend = redis requires proxy.l2_store to be configured"
                )
            })?;
            Arc::new(sbproxy_middleware::idempotency::KvIdempotencyCache::new(
                kv, ttl_secs,
            ))
        }
    };
    let max_request_body_bytes = cfg
        .max_request_body_bytes
        .unwrap_or(sbproxy_config::DEFAULT_IDEMPOTENCY_MAX_REQUEST_BYTES);
    let max_response_body_bytes = cfg
        .max_response_body_bytes
        .unwrap_or(sbproxy_config::DEFAULT_IDEMPOTENCY_MAX_RESPONSE_BYTES);
    let max_concurrent_buffers = cfg
        .max_concurrent_buffers
        .unwrap_or(sbproxy_config::DEFAULT_IDEMPOTENCY_MAX_CONCURRENT_BUFFERS);
    let permits = Arc::new(tokio::sync::Semaphore::new(max_concurrent_buffers));
    Ok(CompiledIdempotency {
        cache,
        header_name,
        ttl_secs,
        methods,
        max_request_body_bytes,
        max_response_body_bytes,
        permits,
    })
}

fn compile_origin_policy_chain(
    policy_configs: &[serde_json::Value],
    l2_store: Option<Arc<dyn sbproxy_platform::storage::KVStore>>,
    l2_async_store: Option<Arc<dyn sbproxy_platform::storage::AsyncKVStore>>,
    origin_id: &str,
    extension_registry: &dyn BundleRegistry,
) -> anyhow::Result<Vec<Policy>> {
    let mut chain: Vec<Policy> = policy_configs
        .iter()
        .map(|cfg| {
            // WOR-2162: name the origin on a policy compile failure so
            // an operator can find the offending block (the policy
            // module's own error names the policy type and, for CEL,
            // quotes the bad expression).
            use anyhow::Context as _;
            let compiled = if configured_type(cfg)
                .is_some_and(|name| extension_registry.policy(name).is_some())
            {
                compile_policy_with_registry(cfg, extension_registry)
            } else {
                compile_policy(cfg)
            };
            compiled.with_context(|| format!("origin `{origin_id}`: invalid policy config"))
        })
        .collect::<anyhow::Result<_>>()?;
    if l2_store.is_some() {
        for p in chain.iter_mut() {
            match p {
                Policy::RateLimit(rl) => {
                    // take+replace: with_store consumes self and returns Self.
                    let taken = std::mem::replace(
                        rl,
                        sbproxy_modules::RateLimitPolicy::from_config(serde_json::json!({
                            "requests_per_second": 10.0
                        }))?,
                    );
                    // WOR-2084: attach the async handle alongside the
                    // sync one. `allow_with_info_async` prefers it and
                    // skips the spawn_blocking bridge; the sync handle
                    // remains the fallback. Both setters derive the same
                    // counter-key prefix, so attach order cannot split
                    // counters across keyspaces (pinned by a test in
                    // sbproxy-modules).
                    //
                    // WOR-2332: attaching a store here is necessary but
                    // was not sufficient. Until the `check_policies`
                    // shared-admission seam existed, nothing on the
                    // request path called `allow_with_info_async`, so
                    // this tier was compiled in and never consulted.
                    // `compile_builtin_enforcers` now derives a
                    // shared-admission handle from whatever this loop
                    // attached, which is what connects the two.
                    *rl = taken
                        .with_store(l2_store.clone(), origin_id)
                        .with_async_store(l2_async_store.clone(), origin_id);
                }
                Policy::Waf(waf) => {
                    // Attach the same shared L2 store to the WAF
                    // persistent-block state machine so time-boxed blocks
                    // are enforced across replicas. No-op when persistent
                    // blocking is disabled on the policy.
                    let taken = std::mem::replace(
                        waf,
                        sbproxy_modules::policy::WafPolicy::from_config(serde_json::json!({}))?,
                    );
                    *waf = taken.with_block_store(l2_store.clone(), origin_id);
                }
                Policy::AgentBudget(ab) => {
                    // WOR-2540: same shared L2 store as RateLimit's tier
                    // above, so `requests_per_minute` is decided by one
                    // fixed-window counter per agent instead of once per
                    // replica. `with_store`/`with_async_store` take the
                    // same store types RateLimit's setters do and consume
                    // an owned `AgentBudgetPolicy` by value, but WOR-506
                    // wraps the compiled policy in `Arc` so the
                    // request-path enforcer wrapper can share bucket
                    // state without cloning the LRU caches, so the Arc
                    // has to be unwrapped rather than the policy taken
                    // directly.
                    let taken = std::mem::replace(
                        ab,
                        Arc::new(sbproxy_modules::AgentBudgetPolicy::from_config(
                            serde_json::json!({}),
                        )?),
                    );
                    *ab = match Arc::try_unwrap(taken) {
                        Ok(policy) => Arc::new(
                            policy
                                .with_store(l2_store.clone(), origin_id)
                                .with_async_store(l2_async_store.clone(), origin_id),
                        ),
                        // The chain was just compiled by this function, so
                        // nothing else can hold a second strong reference
                        // to a policy still in it. Fall back to the
                        // pre-attachment Arc rather than assuming that
                        // invariant holds, so a violation degrades to
                        // per-replica enforcement instead of losing the
                        // compiled policy state.
                        Err(shared) => shared,
                    };
                }
                _ => {}
            }
        }
    } else if let Some(tier) = crate::rate_limit_cluster::tier_if_clustered() {
        // No shared counter, but this node is on a mesh. Attach the cluster
        // tier so the limit is enforced across the cluster instead of N times
        // over. A shared counter is exact and always wins, which is why this
        // is the `else` branch.
        for p in chain.iter_mut() {
            if let Policy::RateLimit(rl) = p {
                let taken = std::mem::replace(
                    rl,
                    sbproxy_modules::RateLimitPolicy::from_config(serde_json::json!({
                        "requests_per_second": 10.0
                    }))?,
                );
                if !taken.converges_on_mesh() {
                    tracing::warn!(
                        origin = %origin_id,
                        "requests_per_second is enforced per node on a mesh cluster: a one \
                         second window closes before a peer contribution can arrive, so the \
                         cluster admits up to N times this limit. Configure an L2 store for an \
                         exact cluster-wide per-second limit, or express the limit as \
                         requests_per_minute, which does converge."
                    );
                }
                *rl = taken.with_cluster(Some(tier.clone()), origin_id);
            }
        }
    }
    Ok(chain)
}

fn routing_action_identity(
    workspace_id: &str,
    origin_id: &str,
    forward_rule_index: Option<usize>,
) -> String {
    let scope = forward_rule_index
        .map(|index| format!("forward-rule:{index}"))
        .unwrap_or_else(|| "main".to_string());
    serde_json::to_string(&(workspace_id, origin_id, scope))
        .expect("routing action identity fields are serializable")
}

/// Name the first matcher in `entry` that cannot be decided from the route
/// alone, if there is one.
///
/// A `body` matcher needs buffered bytes and a `when` predicate needs the CEL
/// context, so neither is available at the point MCP has to pick its protocol
/// era and trust anchor.
fn indeterminate_matcher_label(entry: &MatcherEntry) -> Option<&'static str> {
    if entry.body.is_some() {
        return Some("body");
    }
    if entry.when.is_some() {
        return Some("when");
    }
    None
}

fn compile_forward_rules(
    raw_rules: &[serde_json::Value],
    workspace_id: &str,
    origin_id: &str,
    mode: PipelineConstructionMode,
    extension_registry: &dyn BundleRegistry,
) -> anyhow::Result<Vec<CompiledForwardRule>> {
    let mut compiled = Vec::with_capacity(raw_rules.len());
    for (rule_index, rule_val) in raw_rules.iter().enumerate() {
        let rule_id = routing_action_identity(workspace_id, origin_id, Some(rule_index));
        let fwd = compile_single_forward_rule(rule_val, &rule_id, mode, extension_registry)?;
        compiled.push(fwd);
    }
    Ok(compiled)
}

/// Compile a single forward rule from its JSON representation.
///
/// Expected structure:
/// ```yaml
/// rules:
///   - path:
///       prefix: /api/
///   - path:
///       exact: /health
///   - path:
///       template: /users/{id}/posts/{post_id}
///   - path:
///       template: /static/{*rest}
///   - path:
///       regex: '^/v(?P<version>\d+)/items'
/// origin:
///   action:
///     type: proxy
///     url: http://...
///   request_modifiers:
///     - headers:
///         set:
///           X-Routed-To: api-backend
/// ```
///
/// When more than one of `prefix`/`exact`/`template`/`regex` is set on the
/// same `path` block, precedence is `template` > `regex` > `exact` >
/// `prefix`. The shorthand `match: <prefix>` field is always treated as a
/// prefix match.
fn compile_single_forward_rule(
    val: &serde_json::Value,
    rule_id: &str,
    mode: PipelineConstructionMode,
    extension_registry: &dyn BundleRegistry,
) -> anyhow::Result<CompiledForwardRule> {
    let rules_arr = val
        .get("rules")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("forward rule missing 'rules' array"))?;

    // `serde_json::to_value` on `RawForwardRule` emits `null` for absent
    // optional fields (because the struct uses `#[serde(default)]` rather
    // than `skip_serializing_if`). Treat both `None` and `Value::Null` as
    // "field absent" so the compiler is forgiving on the wire format.
    let mut matchers: Vec<MatcherEntry> = Vec::with_capacity(rules_arr.len());
    for rule in rules_arr {
        let method = compile_method_matcher(non_null(rule.get("method")))?;
        let path = compile_path_matcher(rule)?;
        let header = compile_header_matcher(non_null(rule.get("header")))?;
        let query = compile_query_matcher(non_null(rule.get("query")))?;
        let body = compile_body_matcher(non_null(rule.get("body")))?;
        let when = match non_null(rule.get("when")).and_then(|v| v.as_str()) {
            Some(source) => Some(std::sync::Arc::new(
                sbproxy_extension::cel::CompiledCel::compile(
                    sbproxy_extension::cel::CelSurface::ForwardRuleWhen,
                    format!("forward rule `{rule_id}` when"),
                    source,
                )?,
            )),
            None => None,
        };
        if method.is_some()
            || path.is_some()
            || header.is_some()
            || query.is_some()
            || body.is_some()
            || when.is_some()
        {
            matchers.push(MatcherEntry {
                method,
                path,
                header,
                query,
                body,
                when,
            });
        }
    }

    // Parse the inline origin config.
    let origin_obj = val
        .get("origin")
        .ok_or_else(|| anyhow::anyhow!("forward rule missing 'origin' object"))?;

    // The action is nested under origin.action.
    let action_config = origin_obj
        .get("action")
        .ok_or_else(|| anyhow::anyhow!("forward rule origin missing 'action'"))?;
    // Same reasoning as the per-origin action site: the registry is
    // passed for every action type, because a built-in action may attach
    // bundle hooks by `type:` (`ai_proxy`'s `engine: wasm` routing
    // policy, WOR-2366). The bundle-action lookup itself happens inside
    // the compiler's unknown-type fall-through.
    let action = match mode {
        PipelineConstructionMode::Runtime => {
            compile_action_for_origin_with_registry(action_config, rule_id, extension_registry)?
        }
        PipelineConstructionMode::Validation => {
            compile_action_for_origin_for_validation_with_registry(
                action_config,
                rule_id,
                extension_registry,
            )?
        }
    };

    // Parse request modifiers (optional).
    // Supports both Rust format ({ headers: { set: ... } }) and Go format
    // ({ type: "header", set: { ... } }). The Go format is normalized to Rust format.
    let request_modifiers: Vec<RequestModifierConfig> =
        if let Some(mods) = origin_obj.get("request_modifiers") {
            if let Some(arr) = mods.as_array() {
                arr.iter().map(normalize_request_modifier).collect()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

    // Rule-level OpenAPI parameter declarations. Optional; absent
    // entirely when the rule is described only by prefix/exact paths.
    let parameters: Vec<Parameter> = match val.get("parameters") {
        Some(p) => serde_json::from_value(p.clone())
            .map_err(|e| anyhow::anyhow!("invalid 'parameters' in forward rule: {}", e))?,
        None => Vec::new(),
    };

    // WOR-2565: rule-scope deprecation announcement. `compile_config`
    // already validated every block, so a failure here is a malformed
    // hand-built rule JSON rather than an operator error; surface it
    // the same way the other malformed-field arms do.
    let deprecation = match non_null(val.get("deprecation")) {
        Some(raw) => {
            let parsed: sbproxy_config::DeprecationConfig = serde_json::from_value(raw.clone())
                .map_err(|e| anyhow::anyhow!("invalid 'deprecation' in forward rule: {}", e))?;
            Some(sbproxy_config::compile_deprecation(
                &parsed,
                &format!("forward rule `{rule_id}`"),
            )?)
        }
        None => None,
    };

    Ok(CompiledForwardRule {
        matchers,
        action,
        request_modifiers,
        parameters,
        id: origin_obj
            .get("id")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        deprecation,
    })
}

/// Treat `Some(Value::Null)` as `None` so `serde_json::to_value` round-trips
/// of optional matcher fields do not look "present" downstream.
fn non_null(v: Option<&serde_json::Value>) -> Option<&serde_json::Value> {
    match v {
        Some(serde_json::Value::Null) => None,
        other => other,
    }
}

/// Compile the `path:` block of a single matcher entry, plus the `match:`
/// shorthand. Returns the most expressive matcher present (template, regex,
/// exact, prefix; in that priority). When both `path:` and `match:` are
/// present, `path:` wins because it is the canonical form.
fn compile_path_matcher(rule: &serde_json::Value) -> anyhow::Result<Option<PathMatch>> {
    if let Some(path_obj) = rule.get("path") {
        if let Some(template) = path_obj.get("template").and_then(|v| v.as_str()) {
            return Ok(Some(PathMatch::Template(PathTemplate::compile(template)?)));
        }
        if let Some(pattern) = path_obj.get("regex").and_then(|v| v.as_str()) {
            let re = regex::Regex::new(pattern)
                .map_err(|e| anyhow::anyhow!("invalid forward-rule regex '{}': {}", pattern, e))?;
            return Ok(Some(PathMatch::Regex(re)));
        }
        if let Some(exact) = path_obj.get("exact").and_then(|v| v.as_str()) {
            return Ok(Some(PathMatch::Exact(exact.to_string())));
        }
        if let Some(prefix) = path_obj.get("prefix").and_then(|v| v.as_str()) {
            return Ok(Some(PathMatch::Prefix(prefix.to_string())));
        }
    }
    if let Some(match_str) = rule.get("match").and_then(|v| v.as_str()) {
        return Ok(Some(PathMatch::Prefix(match_str.to_string())));
    }
    Ok(None)
}

/// Compile the `header:` block of a single matcher entry. Accepts
/// `{ name, value }` (exact) or `{ name, prefix }` (value prefix).
fn compile_header_matcher(val: Option<&serde_json::Value>) -> anyhow::Result<Option<HeaderMatch>> {
    let Some(obj) = val else {
        return Ok(None);
    };
    let name_str = obj
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("forward-rule header matcher missing 'name'"))?;
    // WOR-1698: validate + intern the header name at load time so the
    // request path never re-parses it. An invalid name now fails config
    // load with a clear error instead of silently never matching.
    let name = http::HeaderName::from_bytes(name_str.as_bytes()).map_err(|e| {
        anyhow::anyhow!("forward-rule header matcher has invalid name '{name_str}': {e}")
    })?;
    if let Some(value) = obj.get("value").and_then(|v| v.as_str()) {
        return Ok(Some(HeaderMatch::Equals {
            name,
            value: value.to_string(),
        }));
    }
    if let Some(prefix) = obj.get("prefix").and_then(|v| v.as_str()) {
        return Ok(Some(HeaderMatch::Prefix {
            name,
            prefix: prefix.to_string(),
        }));
    }
    Err(anyhow::anyhow!(
        "forward-rule header matcher '{}' needs 'value' or 'prefix'",
        name.as_str()
    ))
}

/// Compile the `query:` block of a single matcher entry. Accepts
/// `{ name, value }` (exact) or just `{ name }` (presence-only).
fn compile_query_matcher(val: Option<&serde_json::Value>) -> anyhow::Result<Option<QueryMatch>> {
    let Some(obj) = val else {
        return Ok(None);
    };
    let name = obj
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("forward-rule query matcher missing 'name'"))?
        .to_string();
    if let Some(value) = obj.get("value").and_then(|v| v.as_str()) {
        return Ok(Some(QueryMatch::Equals {
            name,
            value: value.to_string(),
        }));
    }
    Ok(Some(QueryMatch::Present { name }))
}

/// Compile the `method:` block of a single matcher entry. Accepts a single
/// method string or a non-empty list of them.
///
/// Tokens are uppercased before parsing. RFC 9110 defines method names as
/// case-sensitive tokens, but every registered method is uppercase and
/// clients send them that way, so authored case is treated as presentation
/// rather than meaning: `post` compiles to the same matcher as `POST`.
/// Validation is `http::Method::from_bytes` on the uppercased token, the
/// same parser the proxy's HTTP layer uses, so a token the proxy would
/// refuse on the wire fails config load with a clear error instead of
/// silently never matching.
fn compile_method_matcher(val: Option<&serde_json::Value>) -> anyhow::Result<Option<MethodMatch>> {
    let Some(val) = val else {
        return Ok(None);
    };
    let tokens: Vec<&str> = match val {
        serde_json::Value::String(s) => vec![s.as_str()],
        serde_json::Value::Array(arr) => arr
            .iter()
            .map(|v| {
                v.as_str().ok_or_else(|| {
                    anyhow::anyhow!("forward-rule method matcher entries must be strings, got {v}")
                })
            })
            .collect::<anyhow::Result<_>>()?,
        other => anyhow::bail!(
            "forward-rule method matcher must be a string or a list of strings, got {other}"
        ),
    };
    if tokens.is_empty() {
        anyhow::bail!(
            "forward-rule method matcher is an empty list, which can never match \
             any request. Remove the matcher instead."
        );
    }
    let methods = tokens
        .iter()
        .map(|token| {
            http::Method::from_bytes(token.to_ascii_uppercase().as_bytes()).map_err(|e| {
                anyhow::anyhow!("forward-rule method matcher has invalid method '{token}': {e}")
            })
        })
        .collect::<anyhow::Result<smallvec::SmallVec<[http::Method; 4]>>>()?;
    Ok(Some(MethodMatch { methods }))
}

/// Compile the `body:` block of a single matcher entry. Accepts
/// `{ pointer, value }` (exact), `{ pointer, prefix }` (value prefix), or
/// just `{ pointer }` (presence-only), plus an optional `max_bytes`.
///
/// The pointer is split into its reference tokens here so the request path
/// never re-parses it, and an unusable pointer fails config load with a clear
/// message instead of quietly never matching.
fn compile_body_matcher(val: Option<&serde_json::Value>) -> anyhow::Result<Option<BodyMatch>> {
    let Some(obj) = val else {
        return Ok(None);
    };
    let pointer_str = obj
        .get("pointer")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("forward-rule body matcher missing 'pointer'"))?;
    let pointer = crate::json_pointer::compile_pointer(pointer_str)
        .map_err(|e| anyhow::anyhow!("forward-rule body matcher: {e}"))?;

    let max_bytes = match obj.get("max_bytes").and_then(serde_json::Value::as_u64) {
        Some(configured) => {
            if configured == 0 {
                anyhow::bail!(
                    "forward-rule body matcher on '{pointer_str}' sets `max_bytes: 0`, \
                     which can never match any body. Remove the matcher instead."
                );
            }
            if configured > sbproxy_config::BODY_MATCH_MAX_BYTES {
                anyhow::bail!(
                    "forward-rule body matcher on '{pointer_str}' sets `max_bytes: {configured}`, \
                     above the {} byte replay buffer that holds a body read during route \
                     selection. Bytes past that are not retained and could not be forwarded \
                     upstream, so the larger cap could not be honored. Lower it to {} or less.",
                    sbproxy_config::BODY_MATCH_MAX_BYTES,
                    sbproxy_config::BODY_MATCH_MAX_BYTES,
                );
            }
            configured
        }
        None => sbproxy_config::BODY_MATCH_MAX_BYTES,
    };
    // The ceiling above is `u64` to match the schema; the cast is lossless on
    // every target the proxy builds for, all of which have a 32-bit or wider
    // `usize`, and the ceiling itself is 65536.
    let max_bytes = usize::try_from(max_bytes).unwrap_or(usize::MAX);

    let compare = if let Some(value) = obj.get("value").and_then(|v| v.as_str()) {
        BodyCompare::Equals(value.to_string())
    } else if let Some(prefix) = obj.get("prefix").and_then(|v| v.as_str()) {
        BodyCompare::Prefix(prefix.to_string())
    } else {
        BodyCompare::Present
    };

    Ok(Some(BodyMatch {
        pointer,
        compare,
        max_bytes,
    }))
}

/// Compile a fallback origin from its JSON representation (if present).
///
/// Expected structure:
/// ```yaml
/// fallback_origin:
///   on_error: true
///   on_status: [502, 503, 504]
///   add_debug_header: true
///   origin:
///     action:
///       type: static
///       status_code: 200
///       json_body: { ... }
/// ```
fn compile_fallback(
    raw: &Option<serde_json::Value>,
    mode: PipelineConstructionMode,
    extension_registry: &dyn BundleRegistry,
) -> anyhow::Result<Option<CompiledFallback>> {
    let val = match raw {
        Some(v) => v,
        None => return Ok(None),
    };

    let on_error = val
        .get("on_error")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let on_status: Vec<u16> = val
        .get("on_status")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_u64().map(|n| n as u16))
                .collect()
        })
        .unwrap_or_default();

    let add_debug_header = val
        .get("add_debug_header")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let origin_obj = val
        .get("origin")
        .ok_or_else(|| anyhow::anyhow!("fallback_origin missing 'origin' object"))?;

    let action_config = origin_obj
        .get("action")
        .ok_or_else(|| anyhow::anyhow!("fallback origin missing 'action'"))?;
    // The fallback action takes the registry for every type too: a
    // built-in action may attach bundle hooks by `type:` (`ai_proxy`'s
    // `engine: wasm` routing policy, WOR-2366), and the bundle-action
    // lookup happens inside the compiler's unknown-type fall-through.
    // `compile_action_with_registry` is the empty-origin-id form of the
    // per-origin entry point, which is what a fallback action has always
    // compiled through.
    let action = match mode {
        PipelineConstructionMode::Runtime => {
            compile_action_with_registry(action_config, extension_registry)?
        }
        PipelineConstructionMode::Validation => {
            compile_action_for_origin_for_validation_with_registry(
                action_config,
                "",
                extension_registry,
            )?
        }
    };

    Ok(Some(CompiledFallback {
        on_error,
        on_status,
        add_debug_header,
        action,
    }))
}

/// Reject any main or forward-rule `ai_proxy` action that configures
/// `rag:` when this binary was built without the `rag` feature (WOR-2098).
///
/// Dropping the block silently would proxy unaugmented traffic that the
/// operator believes carries retrieved context, so the mismatch fails
/// construction with a pointer at the rebuild flag instead.
#[cfg(not(feature = "rag"))]
fn reject_configured_rag(
    actions: &[Action],
    forward_rules: &[Vec<CompiledForwardRule>],
) -> anyhow::Result<()> {
    fn has_rag(action: &Action) -> bool {
        matches!(action, Action::AiProxy(action) if action.config.rag.is_some())
    }
    for (origin_idx, action) in actions.iter().enumerate() {
        if has_rag(action) {
            anyhow::bail!(
                "origin {origin_idx}: ai_proxy configures `rag:` but this build does not \
                 include RAG support; rebuild with feature 'rag'"
            );
        }
    }
    for (origin_idx, rules) in forward_rules.iter().enumerate() {
        for (rule_idx, rule) in rules.iter().enumerate() {
            if has_rag(&rule.action) {
                anyhow::bail!(
                    "origin {origin_idx}: forward rule {rule_idx}: ai_proxy configures `rag:` \
                     but this build does not include RAG support; rebuild with feature 'rag'"
                );
            }
        }
    }
    Ok(())
}

/// Normalize a request modifier from either Go format or Rust format.
///
/// Go format: `{ type: "header", set: { "X-Foo": "bar" } }`
/// Rust format: `{ headers: { set: { "X-Foo": "bar" } } }`
///
/// The Go format is converted to Rust format before deserialization.
/// Default (empty) request modifier config used as a fallback when deserialization fails.
fn default_request_modifier() -> RequestModifierConfig {
    RequestModifierConfig {
        headers: None,
        url: None,
        query: None,
        method: None,
        body: None,
        lua_script: None,
        js_script: None,
        rego_module: None,
        rego_module_path: None,
        rego_budget_ms: None,
        rego_v0: false,
    }
}

fn normalize_request_modifier(val: &serde_json::Value) -> RequestModifierConfig {
    // If it already has a `headers` field, it's in Rust format.
    if val.get("headers").is_some() {
        return serde_json::from_value(val.clone()).unwrap_or_else(|_| default_request_modifier());
    }

    // Check for Go format: { type: "header", set: { ... }, add: { ... }, remove/delete: [...] }
    if val.get("type").and_then(|v| v.as_str()) == Some("header") {
        let set = val.get("set").cloned().unwrap_or(serde_json::json!({}));
        let add = val.get("add").cloned().unwrap_or(serde_json::json!({}));
        let remove = val
            .get("remove")
            .or_else(|| val.get("delete"))
            .cloned()
            .unwrap_or(serde_json::json!([]));
        let normalized = serde_json::json!({
            "headers": {
                "set": set,
                "add": add,
                "remove": remove,
            }
        });
        return serde_json::from_value(normalized).unwrap_or_else(|_| default_request_modifier());
    }

    // Fallback: try direct deserialization (handles url, query, method, body modifier types).
    serde_json::from_value(val.clone()).unwrap_or_else(|_| default_request_modifier())
}

/// Resolve the posture the response pipeline applies when this transform
/// fails.
///
/// Precedence, highest first:
///
/// 1. An explicit `failure_posture` or `fail_on_error` on the attachment.
///    The operator wiring the transform into an origin overrides whoever
///    wrote the bundle.
/// 2. The bundle manifest's declared posture, for a dynamic bundle hook.
/// 3. The attachment default, which is [`FailureMode::Open`].
///
/// Two and three have to be distinguished by whether the operator wrote
/// anything, not by the resolved value: `TransformConfig::failure_posture`
/// returns `Open` both for an explicit `open` and for silence, and reading
/// silence as `open` is what dropped the manifest posture on the floor
/// (WOR-2268).
fn effective_transform_posture(
    wrapper: &sbproxy_modules::transform::TransformConfig,
    transform: &sbproxy_modules::Transform,
) -> sbproxy_config::FailureMode {
    if wrapper.has_explicit_failure_posture() {
        return wrapper.failure_posture();
    }
    match transform {
        sbproxy_modules::Transform::Plugin(plugin) => plugin
            .dynamic_hook()
            .map(|hook| hook.failure_posture())
            .unwrap_or_else(|| wrapper.failure_posture()),
        _ => wrapper.failure_posture(),
    }
}

#[cfg(test)]
mod transform_posture_tests {
    use super::effective_transform_posture;
    use sbproxy_config::{BundleBodyMode, FailureMode};
    use sbproxy_modules::transform::TransformConfig;
    use sbproxy_modules::{DynamicHookMetadata, PluginTransform, Transform};
    use sbproxy_plugin::{TransformContext, TransformHandler};

    struct StubTransform;

    impl TransformHandler for StubTransform {
        fn transform_type(&self) -> &str {
            "stub_bundle_transform"
        }

        fn apply<'a>(
            &'a self,
            _body: &'a mut bytes::BytesMut,
            _content_type: Option<&'a str>,
            _ctx: &'a TransformContext,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = sbproxy_plugin::PluginResult<()>> + Send + 'a>,
        > {
            Box::pin(async { Ok(()) })
        }
    }

    fn wrapper(json: serde_json::Value) -> TransformConfig {
        serde_json::from_value(json).expect("transform wrapper fixture")
    }

    fn dynamic_transform(posture: FailureMode) -> Transform {
        Transform::Plugin(PluginTransform::dynamic(
            Box::new(StubTransform),
            DynamicHookMetadata::new(
                "stub-bundle",
                "stub_bundle_transform",
                sbproxy_config::BundleRuntime::Wasm,
                BundleBodyMode::Buffered,
                1024,
                posture,
            ),
        ))
    }

    #[test]
    fn a_silent_attachment_inherits_the_manifest_posture() {
        let posture = effective_transform_posture(
            &wrapper(serde_json::json!({"type": "stub_bundle_transform"})),
            &dynamic_transform(FailureMode::Closed),
        );
        assert_eq!(posture, FailureMode::Closed);
    }

    #[test]
    fn an_explicit_attachment_posture_overrides_the_manifest() {
        let posture = effective_transform_posture(
            &wrapper(
                serde_json::json!({"type": "stub_bundle_transform", "failure_posture": "open"}),
            ),
            &dynamic_transform(FailureMode::Closed),
        );
        assert_eq!(posture, FailureMode::Open);
    }

    #[test]
    fn the_legacy_boolean_also_counts_as_explicit() {
        let posture = effective_transform_posture(
            &wrapper(serde_json::json!({"type": "stub_bundle_transform", "fail_on_error": true})),
            &dynamic_transform(FailureMode::Open),
        );
        assert_eq!(posture, FailureMode::Closed);
    }

    #[test]
    fn a_linked_plugin_keeps_the_attachment_default() {
        let linked = Transform::Plugin(PluginTransform::linked(Box::new(StubTransform)));
        let posture = effective_transform_posture(
            &wrapper(serde_json::json!({"type": "stub_bundle_transform"})),
            &linked,
        );
        assert_eq!(posture, FailureMode::Open);
    }

    #[test]
    fn a_built_in_transform_is_unaffected() {
        let posture = effective_transform_posture(
            &wrapper(serde_json::json!({"type": "noop"})),
            &Transform::Noop,
        );
        assert_eq!(posture, FailureMode::Open);
    }
}

#[cfg(test)]
mod mcp_inject_registry_tests {
    use super::CompiledPipeline;
    use sbproxy_extension::mcp::protocol::McpToolContract;
    use sbproxy_extension::mcp::FederatedTool;
    use sbproxy_modules::Action;
    use std::collections::{BTreeSet, HashMap};

    fn compile_mcp_pipeline(
        origins: &[(&str, &str, &str, &str)],
    ) -> anyhow::Result<CompiledPipeline> {
        let tenant_ids = origins
            .iter()
            .map(|(_, tenant_id, _, _)| *tenant_id)
            .collect::<BTreeSet<_>>();
        let mut yaml = String::from("proxy:\n  tenants:\n");
        for tenant_id in tenant_ids {
            yaml.push_str(&format!("    - id: {tenant_id}\n"));
        }
        yaml.push_str("origins:\n");
        for (hostname, tenant_id, server_name, upstream_prefix) in origins {
            yaml.push_str(&format!(
                "  {hostname}:\n    tenant_id: {tenant_id}\n    action:\n      type: mcp\n      mode: gateway\n      server_info:\n        name: {server_name}\n        version: private-config-canary\n      federated_servers:\n        - origin: https://test.sbproxy.dev\n          prefix: {upstream_prefix}\n"
            ));
        }
        let config = sbproxy_config::compile_config(&yaml).expect("MCP pipeline fixture compiles");
        CompiledPipeline::from_config_for_validation(config)
    }

    fn federated_tool(name: &str, server_name: &str) -> FederatedTool {
        let input_schema = serde_json::json!({"type": "object", "properties": {}});
        let contract = McpToolContract::try_from(serde_json::json!({
            "name": name,
            "description": "tenant-scoped fixture",
            "inputSchema": input_schema.clone(),
        }))
        .expect("tenant-scoped tool contract");
        FederatedTool {
            name: name.to_string(),
            upstream_name: name.to_string(),
            description: "tenant-scoped fixture".to_string(),
            input_schema,
            server_name: server_name.to_string(),
            streaming: false,
            meta: None,
            contract: Some(contract),
            legacy_document: None,
            modern_contract: None,
            modern_incompatibility: None,
        }
    }

    fn seed_tool(
        pipeline: &CompiledPipeline,
        hostname: &str,
        upstream_prefix: &str,
        tool_name: &str,
    ) {
        let origin_index = pipeline
            .resolve_origin(hostname)
            .expect("fixture origin resolves");
        let Action::Mcp(action) = &pipeline.actions[origin_index] else {
            panic!("fixture origin must compile an MCP action");
        };
        action.federation.seed_tools_for_test(
            HashMap::from([(
                tool_name.to_string(),
                federated_tool(tool_name, upstream_prefix),
            )]),
            None,
        );
    }

    fn resolved_tool_names(source: &sbproxy_modules::action::McpInjectSource) -> Vec<String> {
        source
            .resolve_tools(
                &sbproxy_plugin::Principal::anonymous(),
                &[],
                sbproxy_ai::identity::McpToolFormat::Openai,
            )
            .into_iter()
            .filter_map(|tool| {
                tool.get("function")?
                    .get("name")?
                    .as_str()
                    .map(str::to_owned)
            })
            .collect()
    }

    #[test]
    fn task_5b_same_mcp_server_name_coexists_across_tenants() {
        let pipeline = compile_mcp_pipeline(&[
            ("mcp-a.test", "tenant-a", "shared-tools", "alpha"),
            ("mcp-b.test", "tenant-b", "shared-tools", "beta"),
        ])
        .expect("distinct tenant identities compile");
        seed_tool(&pipeline, "mcp-a.test", "alpha", "alpha.lookup");
        seed_tool(&pipeline, "mcp-b.test", "beta", "beta.lookup");

        let tenant_a = pipeline
            .mcp_inject_source("tenant-a", "shared-tools")
            .expect("tenant A source");
        let tenant_b = pipeline
            .mcp_inject_source("tenant-b", "shared-tools")
            .expect("tenant B source");

        assert_eq!(resolved_tool_names(&tenant_a), ["alpha.lookup"]);
        assert_eq!(resolved_tool_names(&tenant_b), ["beta.lookup"]);
    }

    #[test]
    fn task_5b_duplicate_mcp_inject_identity_rejects_pipeline_compilation() {
        let error = match compile_mcp_pipeline(&[
            ("mcp-primary.test", "tenant-a", "shared-tools", "primary"),
            (
                "mcp-secondary.test",
                "tenant-a",
                "shared-tools",
                "secondary",
            ),
        ]) {
            Ok(_) => panic!("a duplicate tenant and MCP server identity must be rejected"),
            Err(error) => error,
        };
        let message = error.to_string();

        assert!(message.contains("duplicate"), "{message}");
        assert!(message.contains("tenant-a"), "{message}");
        assert!(message.contains("shared-tools"), "{message}");
        assert!(
            !message.contains("private-config-canary"),
            "the duplicate error must not echo unrelated action configuration: {message}"
        );
    }

    #[test]
    fn task_5b_mcp_inject_lookup_fails_closed_outside_its_tenant_or_name() {
        let pipeline =
            compile_mcp_pipeline(&[("mcp-a.test", "tenant-a", "tenant-a-tools", "alpha")])
                .expect("fixture pipeline compiles");

        assert!(pipeline
            .mcp_inject_source("tenant-b", "tenant-a-tools")
            .is_none());
        assert!(pipeline
            .mcp_inject_source("tenant-a", "unknown-tools")
            .is_none());
    }

    #[test]
    fn task_5b_mcp_inject_sources_remain_pinned_to_their_pipeline_generation() {
        let old_pipeline =
            compile_mcp_pipeline(&[("mcp-a.test", "tenant-a", "shared-tools", "alpha")])
                .expect("old generation compiles");
        seed_tool(&old_pipeline, "mcp-a.test", "alpha", "alpha.old");

        let new_pipeline =
            compile_mcp_pipeline(&[("mcp-a.test", "tenant-a", "shared-tools", "alpha")])
                .expect("new generation compiles");
        seed_tool(&new_pipeline, "mcp-a.test", "alpha", "alpha.new");

        let old_source = old_pipeline
            .mcp_inject_source("tenant-a", "shared-tools")
            .expect("old generation source");
        let new_source = new_pipeline
            .mcp_inject_source("tenant-a", "shared-tools")
            .expect("new generation source");

        assert_eq!(resolved_tool_names(&old_source), ["alpha.old"]);
        assert_eq!(resolved_tool_names(&new_source), ["alpha.new"]);
    }
}

#[cfg(test)]
mod mcp_modern_http_authority_tests {
    use super::CompiledPipeline;
    use http::{HeaderMap, HeaderValue};
    use sbproxy_modules::action::mcp::{McpAction, McpModernHttpRejection};
    use sbproxy_modules::Action;

    fn compile_mcp_pipeline(
        origin_key: &str,
        modern_http: Option<&str>,
    ) -> anyhow::Result<CompiledPipeline> {
        let modern_http = modern_http.unwrap_or_default();
        let yaml = format!(
            r#"
origins:
  "{origin_key}":
    action:
      type: mcp
      mode: gateway
{modern_http}      federated_servers:
        - origin: https://test.sbproxy.dev
          prefix: upstream
"#
        );
        let config = sbproxy_config::compile_config(&yaml)?;
        CompiledPipeline::from_config_for_validation(config)
    }

    fn mcp_action(pipeline: &CompiledPipeline) -> &McpAction {
        let Some(Action::Mcp(action)) = pipeline.actions.first() else {
            panic!("fixture origin must compile an MCP action");
        };
        action
    }

    fn browser_headers(authority: &str, origin: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::HOST,
            HeaderValue::from_str(authority).expect("fixture authority is a valid header value"),
        );
        headers.insert(
            http::header::ORIGIN,
            HeaderValue::from_str(origin).expect("fixture origin is a valid header value"),
        );
        headers
    }

    fn origin_header(origin: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::ORIGIN,
            HeaderValue::from_str(origin).expect("fixture origin is a valid header value"),
        );
        headers
    }

    #[test]
    fn task_5c_exact_mcp_origin_derives_scheme_aware_default_authority() {
        let pipeline = compile_mcp_pipeline("mcp.localhost", None)
            .expect("exact MCP origin pipeline compiles");
        let action = mcp_action(&pipeline);

        for (scheme, authority, origin) in [
            ("http", "mcp.localhost", "http://mcp.localhost:80"),
            ("http", "mcp.localhost:80", "http://mcp.localhost"),
        ] {
            assert_eq!(
                action.validate_modern_http_request(
                    scheme,
                    None,
                    &browser_headers(authority, origin),
                ),
                Ok(()),
                "{scheme} request should canonicalize its default effective port"
            );
        }
        for (authority, origin) in [
            ("mcp.localhost", "https://mcp.localhost:443"),
            ("mcp.localhost:443", "https://mcp.localhost"),
        ] {
            assert_eq!(
                action.validate_modern_http_request(
                    "https",
                    Some(authority),
                    &origin_header(origin),
                ),
                Ok(()),
                "HTTP/2 authority should canonicalize its default effective port"
            );
        }
    }

    #[test]
    fn task_5c_exact_mcp_origin_rejects_an_untrusted_authority() {
        let pipeline = compile_mcp_pipeline("mcp.localhost", None)
            .expect("exact MCP origin pipeline compiles");
        let action = mcp_action(&pipeline);

        assert_eq!(
            action.validate_modern_http_request(
                "https",
                Some("evil.example"),
                &browser_headers("mcp.localhost", "https://mcp.localhost"),
            ),
            Err(McpModernHttpRejection::Authority)
        );
    }

    #[test]
    fn task_5c_wildcard_mcp_origin_does_not_derive_a_trust_anchor() {
        let pipeline = compile_mcp_pipeline("*.localhost", None)
            .expect("wildcard MCP origin pipeline compiles");
        let action = mcp_action(&pipeline);

        assert_eq!(
            action.validate_modern_http_request(
                "http",
                None,
                &browser_headers("tenant.localhost", "http://tenant.localhost"),
            ),
            Err(McpModernHttpRejection::MissingTrustAnchor)
        );
    }

    #[test]
    fn task_5c_explicit_modern_public_origin_remains_authoritative() {
        let pipeline = compile_mcp_pipeline(
            "mcp.localhost",
            Some(
                r#"      modern_http:
        public_origin: https://mcp.localhost:8443
"#,
            ),
        )
        .expect("explicit modern HTTP origin pipeline compiles");
        let action = mcp_action(&pipeline);

        assert_eq!(
            action.validate_modern_http_request(
                "https",
                None,
                &browser_headers("mcp.localhost:8443", "https://mcp.localhost:8443"),
            ),
            Ok(())
        );
        assert_eq!(
            action.validate_modern_http_request(
                "https",
                None,
                &browser_headers("mcp.localhost", "https://mcp.localhost:8443"),
            ),
            Err(McpModernHttpRejection::Authority)
        );
    }

    #[test]
    fn task_5c_inner_wildcard_mcp_origin_is_rejected_before_pipeline_compilation() {
        assert!(compile_mcp_pipeline("mcp.*.localhost", None).is_err());
    }

    #[test]
    fn task_5c_forward_rule_mcp_action_inherits_the_exact_route_authority() {
        let yaml = r#"
origins:
  "mcp.localhost":
    action:
      type: static
      status_code: 404
    forward_rules:
      - rules:
          - path:
              prefix: /
        origin:
          id: forwarded-mcp
          action:
            type: mcp
            mode: gateway
            federated_servers:
              - origin: https://test.sbproxy.dev
                prefix: upstream
"#;
        let config = sbproxy_config::compile_config(yaml).expect("forward MCP config compiles");
        let pipeline = CompiledPipeline::from_config_for_validation(config)
            .expect("forward MCP pipeline compiles");
        let Some(Action::Mcp(action)) = pipeline.forward_rules[0].first().map(|rule| &rule.action)
        else {
            panic!("forward rule must compile an MCP action");
        };

        assert_eq!(
            action.validate_modern_http_request(
                "https",
                Some("mcp.localhost"),
                &origin_header("https://mcp.localhost"),
            ),
            Ok(())
        );
    }

    #[test]
    fn task_5c_mcp_routes_reject_body_or_cel_dependent_forward_selection() {
        let cases = [
            (r#"body: {pointer: /route, value: mcp}"#, "body"),
            (r#"when: 'request.path == "/mcp"'"#, "when"),
        ];

        for (matcher, label) in cases {
            let yaml = format!(
                r#"
origins:
  "mcp.localhost":
    action:
      type: mcp
      mode: gateway
      federated_servers:
        - origin: https://test.sbproxy.dev
          prefix: upstream
    forward_rules:
      - rules:
          - path:
              prefix: /
            {matcher}
        origin:
          id: conditional-route
          action:
            type: static
            status_code: 404
"#
            );
            let config = sbproxy_config::compile_config(&yaml)
                .unwrap_or_else(|error| panic!("{label} fixture config compiles: {error}"));
            let error = CompiledPipeline::from_config_for_validation(config)
                .err()
                .unwrap_or_else(|| panic!("{label} matcher must be rejected on an MCP origin"));
            let message = error.to_string();
            assert!(message.contains("mcp.localhost"), "{label}: {message}");
            assert!(message.contains(label), "{label}: {message}");
        }
    }

    #[test]
    fn task_5c_forward_mcp_route_rejects_an_earlier_indeterminate_rule() {
        let yaml = r#"
origins:
  "mcp.localhost":
    action:
      type: static
      status_code: 404
    forward_rules:
      - rules:
          - path:
              prefix: /
            when: 'request.path.startsWith("/shadow")'
        origin:
          id: conditional-shadow
          action:
            type: static
            status_code: 403
      - rules:
          - path:
              prefix: /mcp
        origin:
          id: forwarded-mcp
          action:
            type: mcp
            mode: gateway
            federated_servers:
              - origin: https://test.sbproxy.dev
                prefix: upstream
"#;
        let config = sbproxy_config::compile_config(yaml).expect("forward MCP config compiles");
        let error = CompiledPipeline::from_config_for_validation(config)
            .err()
            .expect("an earlier indeterminate route must not shadow MCP pre-auth selection");
        let message = error.to_string();
        assert!(message.contains("mcp.localhost"), "{message}");
        assert!(message.contains("when"), "{message}");
    }

    #[test]
    fn task_5c_an_mcp_rule_cannot_carry_its_own_indeterminate_matcher() {
        // The mcp rule's own matchers decide whether MCP is selected at all. A
        // body matcher here arms the route-matching body drain, so the MCP
        // handler would re-read an already-consumed body and decode nothing.
        let yaml = r#"
origins:
  "mcp.localhost":
    action:
      type: proxy
      url: https://api.example.com
    forward_rules:
      - rules:
          - path:
              prefix: /
            body: {pointer: /route, value: mcp}
        origin:
          id: body-selected-mcp
          action:
            type: mcp
            mode: gateway
            federated_servers:
              - origin: https://test.sbproxy.dev
                prefix: upstream
"#;
        let config = sbproxy_config::compile_config(yaml).expect("body-selected MCP config parses");
        let error = CompiledPipeline::from_config_for_validation(config)
            .err()
            .expect("an mcp rule must not select on the request body");
        let message = error.to_string();
        assert!(message.contains("mcp.localhost"), "{message}");
        assert!(message.contains("body"), "{message}");
    }

    #[test]
    fn task_5c_a_rule_between_two_mcp_rules_is_still_guarded() {
        // Guarding only up to the FIRST mcp rule would let this one through.
        let yaml = r#"
origins:
  "mcp.localhost":
    action:
      type: proxy
      url: https://api.example.com
    forward_rules:
      - rules:
          - path:
              prefix: /first
        origin:
          id: first-mcp
          action:
            type: mcp
            mode: gateway
            federated_servers:
              - origin: https://test.sbproxy.dev
                prefix: upstream
      - rules:
          - path:
              prefix: /shadow
            when: 'request.path.startsWith("/shadow")'
        origin:
          id: conditional-shadow
          action:
            type: static
            status_code: 403
      - rules:
          - path:
              prefix: /second
        origin:
          id: second-mcp
          action:
            type: mcp
            mode: gateway
            federated_servers:
              - origin: https://test.sbproxy.dev
                prefix: upstream
"#;
        let config = sbproxy_config::compile_config(yaml).expect("interleaved MCP config parses");
        let error = CompiledPipeline::from_config_for_validation(config)
            .err()
            .expect("a rule between two mcp rules must not be indeterminate");
        let message = error.to_string();
        assert!(message.contains("mcp.localhost"), "{message}");
        assert!(message.contains("when"), "{message}");
    }

    #[test]
    fn task_5c_mcp_is_rejected_as_an_undispatchable_fallback_action() {
        let yaml = r#"
origins:
  "api.localhost":
    action:
      type: proxy
      url: https://api.example.com
    fallback_origin:
      on_error: true
      origin:
        id: invalid-mcp-fallback
        action:
          type: mcp
          mode: gateway
          federated_servers:
            - origin: https://test.sbproxy.dev
              prefix: upstream
"#;
        let config = sbproxy_config::compile_config(yaml).expect("fallback MCP config parses");
        let error = CompiledPipeline::from_config_for_validation(config)
            .err()
            .expect("MCP cannot run through the static-only fallback dispatcher");
        let message = error.to_string();
        assert!(message.contains("fallback"), "{message}");
        assert!(message.contains("mcp"), "{message}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use compact_str::CompactString;
    use sbproxy_extension::bundle::BundleRegistry;
    use sbproxy_plugin::{ExtensionHookKind, ExtensionState};
    use std::collections::HashMap;
    use tempfile::TempDir;

    /// One unchanged multi-origin config hashes to one revision.
    ///
    /// WOR-2602. `config_revision` rides the request log, the access
    /// log, the CSV export, webhook envelopes and `policy_version`'s
    /// prefix, and every one of those readers takes it to mean "the
    /// config generation that served this". It used to be a function of
    /// `HashMap` iteration order instead: the hashed view paired each
    /// sorted hostname with its position in `CompiledConfig::origins`,
    /// and the compiler filled those positions by walking a `HashMap`.
    /// Three boots of one unchanged two-origin file reported
    /// `8cb4b33d8ffc` and `cf7ba3e14142`, alternating.
    ///
    /// Four origins and 128 compiles walk the map-order space: four
    /// origins give 24 index permutations, and `RandomState` bumps its
    /// seed per map instance within a thread, so each compile is a
    /// fresh draw rather than a repeat of the first one. What a green
    /// run proves is that nothing on the whole compile-to-revision
    /// path reads that order anymore. It is deliberately not the red
    /// test for the compiler seam: `compute_config_revision` ranks
    /// hostnames internally, so this assertion holds even over a
    /// compiler that assigns indices in map order. The test that goes
    /// red on that regression is the compiler's own
    /// `repeated_compiles_assign_the_same_origin_indices`; this one
    /// exists so the end-to-end contract keeps a pin of its own if the
    /// hash input ever grows a new order-sensitive component.
    #[test]
    fn one_unchanged_multi_origin_config_hashes_to_one_revision() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
origins:
  alpha.test.sbproxy.dev:
    action:
      type: proxy
      url: http://localhost:3001
  bravo.test.sbproxy.dev:
    action:
      type: proxy
      url: http://localhost:3002
  charlie.test.sbproxy.dev:
    action:
      type: proxy
      url: http://localhost:3003
  delta.test.sbproxy.dev:
    action:
      type: proxy
      url: http://localhost:3004
"#;

        let mut revisions = std::collections::BTreeSet::new();
        for _ in 0..128 {
            let config =
                sbproxy_config::compile_config(yaml).expect("multi-origin fixture compiles");
            revisions.insert(compute_config_revision(&config));
        }

        assert_eq!(
            revisions.len(),
            1,
            "one unchanged config must hash to one revision, saw {revisions:?}"
        );
        // The value, not just its stability. Asserting only "one
        // distinct revision" would stay green through a rewrite of the
        // serialization itself, and that serialization is what pins
        // `8f10eba811d1` and `8cb4b33d8ffc` into the pages under
        // `scripts/check-doc-captures.py` and into every signed
        // metering receipt already issued. Changing it is a decision,
        // so it should have to be made here rather than happen.
        assert_eq!(
            revisions.iter().next().map(String::as_str),
            Some("9e1c694ee344"),
            "the revision for this fixture is a published constant"
        );
    }

    /// A revision holds still when only an origin's behavior changes.
    ///
    /// This is the shape of the value rather than a gap in it: the
    /// hashed view is the routable hostname set, so the revision
    /// answers "is this the same routable surface" and not "is this
    /// the same file". Same hostnames, same revision, however different
    /// the auth, policies, transforms or upstreams behind them.
    ///
    /// It is asserted because things keep trying to key caches on it.
    /// `render_openapi` did, and served the pre-reload document for the
    /// life of the process on any config whose hostnames did not move;
    /// it keys on the pipeline generation now. Anything asking "has the
    /// loaded config drifted from the file" wants the config content
    /// hash behind `/admin/drift`, which is a hash of the bytes.
    #[test]
    fn a_revision_holds_still_when_only_an_origins_behavior_changes() {
        let bare = r#"
proxy:
  http_bind_port: 8080
origins:
  app.example.com:
    action:
      type: proxy
      url: http://localhost:3001
"#;
        let with_auth = r#"
proxy:
  http_bind_port: 8080
origins:
  app.example.com:
    auth:
      type: api_key
      keys: ["secret-one"]
    action:
      type: proxy
      url: http://localhost:3001
"#;

        let bare = sbproxy_config::compile_config(bare).expect("bare fixture compiles");
        let with_auth = sbproxy_config::compile_config(with_auth).expect("auth fixture compiles");
        assert_eq!(
            compute_config_revision(&bare),
            compute_config_revision(&with_auth),
            "the revision tracks the routable surface, not the file"
        );
    }

    /// An MCP catalogue is injectable only by keys on its own tenant.
    ///
    /// The lookup used to be process-global by server name, so a key on any
    /// tenant could name any gateway and get its tools. Scoping it is the
    /// point, and the same-name case is what proves the scoping is real:
    /// two tenants may both run a gateway called `toolhub`, and each must see
    /// only its own.
    #[test]
    fn an_mcp_catalogue_is_reachable_only_from_its_own_tenant() {
        fn source(name: &str) -> Arc<sbproxy_modules::action::McpInjectSource> {
            let action = sbproxy_modules::action::McpAction::from_config(serde_json::json!({
                "type": "mcp",
                "mode": "gateway",
                "server_info": {"name": name, "version": "1.0.0"},
                "federated_servers": [{"origin": "upstream.example.com"}]
            }))
            .expect("mcp fixture compiles");
            action.inject_source()
        }

        let mut registry = McpInjectRegistry::default();
        registry
            .insert("tenant-a", "toolhub", source("toolhub"))
            .expect("tenant-a toolhub");
        registry
            .insert("tenant-b", "toolhub", source("toolhub"))
            .expect("a second tenant may reuse the name");

        assert!(registry.get("tenant-a", "toolhub").is_some());
        assert!(registry.get("tenant-b", "toolhub").is_some());
        assert!(
            registry.get("tenant-c", "toolhub").is_none(),
            "a tenant with no gateway of that name must not borrow another's"
        );
        assert!(
            registry.get("", "toolhub").is_none(),
            "an empty tenant must not act as a wildcard"
        );

        // Same tenant, same name, twice is an operator error rather than a
        // silent last-one-wins.
        assert!(registry
            .insert("tenant-a", "toolhub", source("toolhub"))
            .is_err());
    }

    #[test]
    fn routing_state_namespace_is_workspace_and_rule_scoped() {
        let workspace_a = routing_action_identity("workspace-a", "shared-origin", None);
        let workspace_b = routing_action_identity("workspace-b", "shared-origin", None);
        let first_rule = routing_action_identity("workspace-a", "shared-origin", Some(0));
        let second_rule = routing_action_identity("workspace-a", "shared-origin", Some(1));

        assert_ne!(workspace_a, workspace_b);
        assert_ne!(workspace_a, first_rule);
        assert_ne!(first_rule, second_rule);
    }

    fn make_config(
        hostname: &str,
        action: serde_json::Value,
        auth: Option<serde_json::Value>,
        policies: Vec<serde_json::Value>,
    ) -> CompiledConfig {
        let mut host_map = HashMap::new();
        host_map.insert(CompactString::new(hostname), 0);
        CompiledConfig {
            extension_bundles: Default::default(),
            origins: vec![sbproxy_config::CompiledOrigin {
                hostname: CompactString::new(hostname),
                origin_id: CompactString::new(hostname),
                cache_config_fingerprint: CompactString::default(),
                workspace_id: CompactString::default(),
                tenant_id: compact_str::CompactString::const_new("__default__"),
                action_config: action,
                auth_config: auth,
                policy_configs: policies,
                transform_configs: Vec::new(),
                filters: Vec::new(),
                cors: None,
                hsts: None,
                compression: None,
                session: None,
                properties: None,
                sessions: None,
                user: None,
                force_ssl: false,
                allowed_methods: smallvec::smallvec![],
                request_modifiers: smallvec::smallvec![],
                response_modifiers: smallvec::smallvec![],
                variables: None,
                forward_rules: Vec::new(),
                fallback_origin: None,
                error_pages: None,
                problem_details: None,
                proxy_status: None,
                deprecation: None,
                message_signatures: None,
                olp: None,
                web_bot_auth_publish: None,
                idempotency: None,
                timeouts: sbproxy_config::UpstreamTimeouts::default(),
                bot_detection: None,
                threat_protection: None,
                on_request: Vec::new(),
                on_response: Vec::new(),
                response_cache: None,
                mirror: None,
                extensions: HashMap::new(),
                expose_openapi: false,
                stream_safety: Vec::new(),
                auto_content_negotiate: None,
                content_signal: None,
                token_bytes_ratio: None,
                agent_skills: Vec::new(),
                agents_md: None,
                ai_txt: None,
                agents_json: None,
                outbound_credential: None,
                outbound_web_bot_auth: false,
                observability: None,
                attestation: None,
                owasp_pack_manifest: None,
            }],
            host_map,
            server: sbproxy_config::ProxyServerConfig::default(),
            l2_store: None,
            mesh: None,
            access_log: None,
            decision_audit: Default::default(),
            agent_classes: None,
            rate_limits: None,
            audit: None,
            session_ledger: None,
            request_events: None,
            events: None,
            flags: Vec::new(),
            egress: Default::default(),
        }
    }

    fn write_dynamic_action_bundle(root: &std::path::Path, version: &str, marker: &str) {
        let bundle = root.join("bundles").join("generation-action");
        std::fs::create_dir_all(&bundle).expect("create extension bundle directory");
        std::fs::write(
            bundle.join("entry.js"),
            format!(
                r#"export function run() {{
                    return {{
                        version: "sbproxy-envelope/v1",
                        outcome: "response",
                        status: 204,
                        headers: [],
                        body_base64: ""
                    }};
                }}
                // {marker}
"#
            ),
        )
        .expect("write extension artifact");
        std::fs::write(
            bundle.join("bundle.yaml"),
            format!(
                r#"apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: generation-action
version: {version}
runtime: javascript
entry: entry.js
hooks:
  - kind: action
    type: generation_action
    export: run
"#
            ),
        )
        .expect("write extension manifest");
    }

    fn dynamic_action_config() -> CompiledConfig {
        let mut config = make_config(
            "extension.example",
            serde_json::json!({"type": "generation_action"}),
            None,
            Vec::new(),
        );
        config.extension_bundles.bundles_dir = Some("bundles".to_owned());
        config
    }

    fn write_dynamic_auth_bundle(root: &std::path::Path) {
        let bundle = root.join("bundles").join("generation-auth");
        std::fs::create_dir_all(&bundle).expect("create extension auth bundle directory");
        std::fs::write(
            bundle.join("entry.js"),
            r#"export function run() {
                return { version: "sbproxy-envelope/v1", decision: "allow" };
            }
"#,
        )
        .expect("write extension auth artifact");
        std::fs::write(
            bundle.join("bundle.yaml"),
            r#"apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: generation-auth
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: auth
    type: bundle_auth
    export: run
"#,
        )
        .expect("write extension auth manifest");
    }

    fn write_lifecycle_inventory_bundle(root: &std::path::Path) {
        let bundle = root.join("bundles").join("lifecycle-inventory");
        std::fs::create_dir_all(&bundle).expect("create lifecycle bundle directory");
        std::fs::write(
            bundle.join("entry.js"),
            r#"export function inspect() {
                return { version: "sbproxy-envelope/v1", decision: "continue" };
            }
            export function enforce() {
                return { version: "sbproxy-envelope/v1", decision: "allow" };
            }
"#,
        )
        .expect("write lifecycle bundle artifact");
        std::fs::write(
            bundle.join("bundle.yaml"),
            r#"apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: lifecycle-inventory
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: ai_guardrail_input
    type: candidate_guardrail
    export: inspect
  - kind: payment
    type: candidate_payment
    export: inspect
    execution:
      body_mode: none
  - kind: policy
    type: unattached_policy
    export: enforce
"#,
        )
        .expect("write lifecycle bundle manifest");
    }

    fn lifecycle_inventory_config(root: &std::path::Path) -> CompiledConfig {
        let mut config = make_config(
            "extension.example",
            serde_json::json!({"type": "static", "body": "ok"}),
            None,
            Vec::new(),
        );
        config.extension_bundles.bundles_dir = Some("bundles".to_owned());
        config.server.payments = Some(sbproxy_config::PaymentsConfig {
            state_path: root.join("payments.sqlite3").display().to_string(),
            challenge_binding_key: "secretfile:///unused-candidate-secret".to_owned(),
            authorization_timeout_ms: 2_000,
            max_body_bytes: 65_536,
            failure_mode: sbproxy_config::FailureMode::Closed,
            recovery_encryption: None,
            worker: sbproxy_config::PaymentsWorkerConfig::default(),
            protocols: sbproxy_config::PaymentProtocolsConfig::default(),
            rails: sbproxy_config::PaymentRailsConfig::default(),
            usage_reporters: sbproxy_config::UsageReportersConfig::default(),
        });
        config
    }

    #[test]
    fn extension_inventory_validation_candidate_proves_lifecycle_attachments() {
        let directory = TempDir::new().expect("temporary config directory");
        write_lifecycle_inventory_bundle(directory.path());

        let pipeline = CompiledPipeline::from_config_for_validation_at(
            lifecycle_inventory_config(directory.path()),
            directory.path(),
        )
        .expect("validation candidate should prepare lifecycle hooks");
        let inventory = pipeline.extension_inventory();

        assert_eq!(inventory.scope.mode, ExtensionScopeMode::Doctor);
        let state = |kind, match_key| {
            inventory
                .hooks
                .iter()
                .find(|hook| hook.kind == kind && hook.match_key == match_key)
                .map(|hook| (hook.id.as_str(), hook.state))
                .expect("lifecycle hook should be inventoried")
        };
        assert_eq!(
            state(ExtensionHookKind::AiGuardrailInput, "candidate_guardrail"),
            (
                "lifecycle-inventory:ai_guardrail_input:candidate_guardrail",
                ExtensionState::Active,
            )
        );
        assert_eq!(
            state(ExtensionHookKind::Payment, "candidate_payment"),
            (
                "lifecycle-inventory:payment:candidate_payment",
                ExtensionState::Active,
            )
        );
        assert_eq!(
            state(ExtensionHookKind::Policy, "unattached_policy").1,
            ExtensionState::Unconsumed
        );
    }

    #[test]
    fn extension_inventory_running_leaves_unconfigured_payment_hook_unconsumed() {
        let directory = TempDir::new().expect("temporary config directory");
        write_lifecycle_inventory_bundle(directory.path());
        let mut config = make_config(
            "extension.example",
            serde_json::json!({"type": "static", "body": "ok"}),
            None,
            Vec::new(),
        );
        config.extension_bundles.bundles_dir = Some("bundles".to_owned());

        let pipeline = CompiledPipeline::from_config_at(config, directory.path())
            .expect("runtime candidate should prepare configured lifecycle paths");
        let inventory = pipeline.extension_inventory();

        assert_eq!(inventory.scope.mode, ExtensionScopeMode::Running);
        assert_eq!(
            inventory
                .hooks
                .iter()
                .find(|hook| hook.kind == ExtensionHookKind::AiGuardrailInput)
                .map(|hook| hook.state),
            Some(ExtensionState::Active)
        );
        assert_eq!(
            inventory
                .hooks
                .iter()
                .find(|hook| hook.kind == ExtensionHookKind::Payment)
                .map(|hook| hook.state),
            Some(ExtensionState::Unconsumed)
        );
    }

    #[test]
    fn extension_inventory_pipeline_loads_relative_bundle_and_owns_running_snapshot() {
        let directory = TempDir::new().expect("temporary config directory");
        write_dynamic_action_bundle(directory.path(), "1.0.0", "generation one");

        let pipeline = CompiledPipeline::from_config_at(dynamic_action_config(), directory.path())
            .expect("pipeline should load its relative bundle directory");

        assert_eq!(pipeline.actions[0].action_type(), "generation_action");
        assert!(pipeline
            .extension_registry()
            .action("generation_action")
            .is_some());
        assert_eq!(pipeline.extension_inventory().summary.active, 1);
        assert_eq!(pipeline.extension_inventory().summary.available, 0);
        assert_eq!(
            pipeline
                .extension_inventory()
                .scope
                .config_revision
                .as_deref(),
            Some(pipeline.config_revision.as_str())
        );
        assert_eq!(
            pipeline.extension_inventory().hooks[0].state,
            ExtensionState::Active
        );
        assert_eq!(
            pipeline.extension_inventory().bundles[0].state,
            ExtensionState::Active
        );
    }

    #[test]
    fn extension_inventory_pipeline_rejects_a_bundle_that_claims_a_builtin_name() {
        let directory = TempDir::new().expect("temporary config directory");
        let bundle = directory.path().join("bundles").join("collision");
        std::fs::create_dir_all(&bundle).expect("create extension bundle directory");
        std::fs::write(
            bundle.join("entry.js"),
            "export function run() { return { version: 'sbproxy-envelope/v1', outcome: 'response', status: 204, headers: [], body_base64: '' }; }",
        )
        .expect("write extension artifact");
        std::fs::write(
            bundle.join("bundle.yaml"),
            r#"apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: collision
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: action
    type: noop
    export: run
"#,
        )
        .expect("write extension manifest");
        let mut config = make_config(
            "extension.example",
            serde_json::json!({"type": "noop"}),
            None,
            Vec::new(),
        );
        config.extension_bundles.bundles_dir = Some("bundles".to_owned());

        let error = match CompiledPipeline::from_config_at(config, directory.path()) {
            Ok(_) => panic!("a built-in hook name must stay reserved"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("reserved"), "{error:#}");
    }

    #[test]
    fn reload_keeps_the_prior_extension_generation_alive_for_a_pinned_request() {
        let first_directory = TempDir::new().expect("first config directory");
        write_dynamic_action_bundle(first_directory.path(), "1.0.0", "generation one");
        let first =
            CompiledPipeline::from_config_at(dynamic_action_config(), first_directory.path())
                .expect("first extension generation should compile");
        let first_registry = Arc::downgrade(first.extension_registry());
        crate::reload::load_pipeline(first);
        let pinned_request = crate::reload::current_pipeline_full();

        let second_directory = TempDir::new().expect("second config directory");
        write_dynamic_action_bundle(second_directory.path(), "2.0.0", "generation two");
        let second =
            CompiledPipeline::from_config_at(dynamic_action_config(), second_directory.path())
                .expect("second extension generation should compile");
        crate::reload::load_pipeline(second);
        let next_request = crate::reload::current_pipeline_full();

        assert!(!Arc::ptr_eq(&pinned_request, &next_request));
        assert!(std::str::from_utf8(
            pinned_request
                .extension_registry()
                .action("generation_action")
                .expect("first hook remains reachable")
                .artifact(),
        )
        .expect("fixture source is UTF-8")
        .contains("generation one"));
        assert!(std::str::from_utf8(
            next_request
                .extension_registry()
                .action("generation_action")
                .expect("second hook is reachable")
                .artifact(),
        )
        .expect("fixture source is UTF-8")
        .contains("generation two"));
        assert!(first_registry.upgrade().is_some());

        drop(pinned_request);
        assert!(first_registry.upgrade().is_none());
    }

    #[test]
    fn pipeline_from_proxy_config() {
        let config = make_config(
            "api.example.com",
            serde_json::json!({"type": "proxy", "url": "http://localhost:3000"}),
            None,
            vec![],
        );
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        assert_eq!(pipeline.actions.len(), 1);
        assert_eq!(pipeline.actions[0].action_type(), "proxy");
        assert!(pipeline.auths[0].is_none());
        assert!(pipeline.policies[0].is_empty());
    }

    #[test]
    fn pipeline_with_auth_and_policies() {
        let config = make_config(
            "secure.example.com",
            serde_json::json!({"type": "static", "body": "ok"}),
            Some(serde_json::json!({"type": "api_key", "api_keys": ["key1"]})),
            vec![serde_json::json!({
                "type": "rate_limiting",
                "requests_per_second": 10.0,
                "burst": 5
            })],
        );
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        assert_eq!(pipeline.actions[0].action_type(), "static");
        assert!(pipeline.auths[0].is_some());
        assert_eq!(pipeline.auths[0].as_ref().unwrap().auth_type(), "api_key");
        assert_eq!(pipeline.policies[0].len(), 1);
        assert_eq!(pipeline.policies[0][0].policy_type(), "rate_limiting");
    }

    #[test]
    fn pipeline_compiles_an_origin_authed_by_a_bundle_hook() {
        // WOR-2426: the per-origin auth site routes a `type:` naming a
        // loaded bundle auth hook through the registry-aware compile. A
        // built-in auth type never reaches here, so without that routing
        // the origin would bail with "unknown auth type".
        let directory = TempDir::new().expect("temporary config directory");
        write_dynamic_auth_bundle(directory.path());
        let mut config = make_config(
            "extension.example",
            serde_json::json!({"type": "static", "body": "ok"}),
            Some(serde_json::json!({"type": "bundle_auth"})),
            Vec::new(),
        );
        config.extension_bundles.bundles_dir = Some("bundles".to_owned());

        let pipeline = CompiledPipeline::from_config_at(config, directory.path())
            .expect("an origin authed by a loaded bundle hook should compile");

        assert!(pipeline.extension_registry().auth("bundle_auth").is_some());
        assert!(pipeline.auths[0].is_some());
        assert_eq!(
            pipeline.auths[0].as_ref().unwrap().auth_type(),
            "bundle_auth"
        );
    }

    /// An `ai_proxy` action whose routing policy names a wasm bundle hook
    /// that no loaded bundle declares.
    fn wasm_routed_ai_proxy_action() -> serde_json::Value {
        serde_json::json!({
            "type": "ai_proxy",
            "ai_routing_policy": {"engine": "wasm", "type": "steer"}
        })
    }

    /// Assert a construction failed on hook resolution rather than on a
    /// missing registry.
    ///
    /// The two refusals are what discriminate a registry that reached the
    /// `ai_proxy` compile from one that never arrived, so the pair of
    /// assertions is factored out instead of repeated per call site.
    #[track_caller]
    fn assert_registry_reached_wasm_routing(error: &anyhow::Error, site: &str) {
        let message = format!("{error:#}");
        assert!(
            !message.contains("requires a loaded extension bundle"),
            "the {site} action compiled with no registry, so the bundle registry never \
             reached `ai_proxy`: {message}"
        );
        assert!(
            message.contains("no loaded extension bundle declares an `ai_routing` hook"),
            "expected the {site} action to refuse on hook resolution: {message}"
        );
    }

    #[test]
    fn wasm_ai_routing_reaches_the_registry_at_every_action_site() {
        // WOR-2366: `ai_proxy` is a built-in `type:`, so a registry arm
        // guarded by `registry.action("ai_proxy")` never fires and every
        // `engine: wasm` routing policy refuses at boot. Staging a real
        // `ai_routing` bundle here would need a compiled wasm module this
        // crate has no dev-dependency to produce, so each site is proven
        // by which refusal it returns instead. "requires a loaded
        // extension bundle" is `prepare_wasm_routing` seeing no registry
        // at all, which is the bug; naming the unresolved hook type is a
        // registry that did arrive and simply holds no `steer` hook.
        let directory = TempDir::new().expect("temporary config directory");

        let origin_action = make_config(
            "wasm-routing.example",
            wasm_routed_ai_proxy_action(),
            None,
            Vec::new(),
        );
        let error = match CompiledPipeline::from_config_at(origin_action, directory.path()) {
            Ok(_) => panic!("an unresolvable wasm ai_routing hook must refuse the origin action"),
            Err(error) => error,
        };
        assert_registry_reached_wasm_routing(&error, "origin");

        let mut forward_rule = make_config(
            "wasm-routing.example",
            serde_json::json!({"type": "static", "body": "ok"}),
            None,
            Vec::new(),
        );
        forward_rule.origins[0].forward_rules = vec![serde_json::json!({
            "rules": [{"path": {"prefix": "/chat"}}],
            "origin": {"action": wasm_routed_ai_proxy_action()}
        })];
        let error = match CompiledPipeline::from_config_at(forward_rule, directory.path()) {
            Ok(_) => panic!("an unresolvable wasm ai_routing hook must refuse the forward rule"),
            Err(error) => error,
        };
        assert_registry_reached_wasm_routing(&error, "forward-rule");

        let mut fallback = make_config(
            "wasm-routing.example",
            serde_json::json!({"type": "static", "body": "ok"}),
            None,
            Vec::new(),
        );
        fallback.origins[0].fallback_origin = Some(serde_json::json!({
            "on_error": true,
            "origin": {"action": wasm_routed_ai_proxy_action()}
        }));
        let error = match CompiledPipeline::from_config_at(fallback, directory.path()) {
            Ok(_) => panic!("an unresolvable wasm ai_routing hook must refuse the fallback origin"),
            Err(error) => error,
        };
        assert_registry_reached_wasm_routing(&error, "fallback");
    }

    #[test]
    fn pipeline_resolve_origin() {
        let config = make_config(
            "test.example.com",
            serde_json::json!({"type": "noop"}),
            None,
            vec![],
        );
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        assert_eq!(pipeline.resolve_origin("test.example.com"), Some(0));
        assert_eq!(pipeline.resolve_origin("unknown.com"), None);
    }

    #[test]
    fn pipeline_resolve_origin_wildcard_lands_on_origin_and_tenant() {
        // Compile from YAML so the wildcard key passes through the real
        // config-compile validation, then prove a wildcard-matched
        // request resolves to the wildcard origin with its tenant
        // stamped, exactly like an exact-matched one would.
        let yaml = r#"
proxy:
  tenants:
    - id: acme
origins:
  "*.acme.example.com":
    tenant_id: acme
    action:
      type: proxy
      url: http://127.0.0.1:3000
  api.example.com:
    action:
      type: proxy
      url: http://127.0.0.1:3001
"#;
        let config = sbproxy_config::compile_config(yaml).unwrap();
        let pipeline = CompiledPipeline::from_config(config).unwrap();

        let idx = pipeline
            .resolve_origin("customer-a.acme.example.com")
            .expect("wildcard-matched host resolves");
        let origin = &pipeline.config.origins[idx];
        assert_eq!(origin.hostname.as_str(), "*.acme.example.com");
        assert_eq!(origin.tenant_id.as_str(), "acme");

        // Deeper subdomains match too; `*.` covers one or more labels.
        assert_eq!(pipeline.resolve_origin("a.b.acme.example.com"), Some(idx));

        // Exact origins keep resolving, and the wildcard's bare suffix
        // still falls through to a routing miss.
        assert!(pipeline.resolve_origin("api.example.com").is_some());
        assert_eq!(pipeline.resolve_origin("acme.example.com"), None);
        assert_eq!(pipeline.resolve_origin("example.com"), None);
    }

    #[test]
    fn pipeline_invalid_action_errors() {
        let config = make_config(
            "bad.example.com",
            serde_json::json!({"type": "unknown_action_type"}),
            None,
            vec![],
        );
        assert!(CompiledPipeline::from_config(config).is_err());
    }

    #[test]
    fn pipeline_invalid_auth_errors() {
        let config = make_config(
            "bad.example.com",
            serde_json::json!({"type": "noop"}),
            Some(serde_json::json!({"type": "nonexistent_auth"})),
            vec![],
        );
        assert!(CompiledPipeline::from_config(config).is_err());
    }

    #[test]
    fn pipeline_invalid_policy_errors() {
        let config = make_config(
            "bad.example.com",
            serde_json::json!({"type": "noop"}),
            None,
            vec![serde_json::json!({"type": "nonexistent_policy"})],
        );
        assert!(CompiledPipeline::from_config(config).is_err());
    }

    // --- WOR-2540: agent_budget adopts the same L2 store `compile_origin_policy_chain` already attaches to RateLimit and Waf ---

    fn compiled_agent_budget(chain: &[Policy]) -> &sbproxy_modules::AgentBudgetPolicy {
        match chain.first() {
            Some(Policy::AgentBudget(ab)) => ab.as_ref(),
            other => panic!("expected a compiled AgentBudget policy, got {other:?}"),
        }
    }

    /// Minimal `AsyncKVStore` fake, enough to prove attachment without a
    /// real backend: every increment reports `1`, always inside any
    /// configured cap.
    struct AlwaysAdmitAsyncStore;

    #[async_trait::async_trait]
    impl sbproxy_platform::storage::AsyncKVStore for AlwaysAdmitAsyncStore {
        async fn get(&self, _key: &[u8]) -> anyhow::Result<Option<bytes::Bytes>> {
            Ok(None)
        }
        async fn put(&self, _key: &[u8], _value: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }
        async fn put_with_ttl(
            &self,
            _key: &[u8],
            _value: &[u8],
            _ttl_secs: u64,
        ) -> anyhow::Result<()> {
            Ok(())
        }
        async fn incr_with_ttl(&self, _key: &[u8], _ttl_secs: u64) -> anyhow::Result<i64> {
            Ok(1)
        }
        async fn delete(&self, _key: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn compile_origin_policy_chain_attaches_the_sync_store_to_agent_budget() {
        // Before WOR-2540, `compile_origin_policy_chain` attached the
        // shared L2 store to `Policy::RateLimit` and `Policy::Waf` but fell
        // through the `_ => {}` catch-all for `Policy::AgentBudget`, even
        // though `AgentBudgetPolicy::with_store`/`with_async_store` exist,
        // are tested, and are documented as the cluster-shared path. This
        // is the compile-time half of that seam: proves the store the
        // pipeline holds actually reaches the policy. The enforcer-side
        // half (a store on the policy produces a `shared_admission`
        // handle) is already pinned by
        // `agent_budget_with_a_store_produces_a_shared_admission_handle`
        // in `builtin_enforcers::registry`.
        let store: Arc<dyn sbproxy_platform::storage::KVStore> =
            Arc::new(sbproxy_platform::storage::MemoryKVStore::new(0));
        let registry = empty_extension_registry();
        let chain = compile_origin_policy_chain(
            &[serde_json::json!({
                "type": "agent_budget",
                "requests_per_minute": 2.0
            })],
            Some(store),
            None,
            "wor-2540-origin",
            registry.as_ref(),
        )
        .expect("agent_budget policy compiles");

        let ab = compiled_agent_budget(&chain);
        assert!(
            ab.has_shared_tier(),
            "an agent_budget policy compiled with an L2 store configured must \
             report a shared tier, the same way RateLimit's store attachment \
             makes `converges_on_mesh`-style state observable"
        );
        let debug = format!("{ab:?}");
        assert!(
            debug.contains("store_attached: true"),
            "sync store must be attached: {debug}"
        );
    }

    #[test]
    fn compile_origin_policy_chain_attaches_the_async_store_to_agent_budget() {
        // `with_async_store` is a separate setter from `with_store`, and
        // the pipeline attaches both together (mirroring the WOR-2084
        // comment on the RateLimit arm above): the async handle is only
        // ever derived from a configured sync `l2_store`, so both are
        // `Some` here, the only combination `compile_pipeline` actually
        // produces (see the `l2_async_store` derivation a few hundred
        // lines up, which maps `config.l2_store` through
        // `validated_redis_connection`).
        let store: Arc<dyn sbproxy_platform::storage::KVStore> =
            Arc::new(sbproxy_platform::storage::MemoryKVStore::new(0));
        let async_store: Arc<dyn sbproxy_platform::storage::AsyncKVStore> =
            Arc::new(AlwaysAdmitAsyncStore);
        let registry = empty_extension_registry();
        let chain = compile_origin_policy_chain(
            &[serde_json::json!({
                "type": "agent_budget",
                "requests_per_minute": 2.0
            })],
            Some(store),
            Some(async_store),
            "wor-2540-origin",
            registry.as_ref(),
        )
        .expect("agent_budget policy compiles");

        let ab = compiled_agent_budget(&chain);
        assert!(
            ab.has_shared_tier(),
            "an agent_budget policy compiled with an async L2 store configured \
             must report a shared tier"
        );
        let debug = format!("{ab:?}");
        assert!(
            debug.contains("store_attached: true") && debug.contains("async_store_attached: true"),
            "both the sync and async handles must be attached: {debug}"
        );
    }

    #[test]
    fn compile_origin_policy_chain_leaves_agent_budget_local_without_a_store() {
        // The other half of the contract already pinned for RateLimit at
        // the enforcer layer: an origin with no L2 store configured must
        // not pay for the seam, and must keep the policy's local-only view.
        let registry = empty_extension_registry();
        let chain = compile_origin_policy_chain(
            &[serde_json::json!({
                "type": "agent_budget",
                "requests_per_minute": 2.0
            })],
            None,
            None,
            "wor-2540-origin",
            registry.as_ref(),
        )
        .expect("agent_budget policy compiles");

        let ab = compiled_agent_budget(&chain);
        assert!(
            !ab.has_shared_tier(),
            "no L2 store configured must leave agent_budget on its local bucket"
        );
    }

    fn make_config_with_transforms(
        hostname: &str,
        action: serde_json::Value,
        transforms: Vec<serde_json::Value>,
    ) -> CompiledConfig {
        let mut host_map = HashMap::new();
        host_map.insert(CompactString::new(hostname), 0);
        CompiledConfig {
            extension_bundles: Default::default(),
            origins: vec![sbproxy_config::CompiledOrigin {
                hostname: CompactString::new(hostname),
                origin_id: CompactString::new(hostname),
                cache_config_fingerprint: CompactString::default(),
                workspace_id: CompactString::default(),
                tenant_id: compact_str::CompactString::const_new("__default__"),
                action_config: action,
                auth_config: None,
                policy_configs: Vec::new(),
                transform_configs: transforms,
                filters: Vec::new(),
                cors: None,
                hsts: None,
                compression: None,
                session: None,
                properties: None,
                sessions: None,
                user: None,
                force_ssl: false,
                allowed_methods: smallvec::smallvec![],
                request_modifiers: smallvec::smallvec![],
                response_modifiers: smallvec::smallvec![],
                variables: None,
                forward_rules: Vec::new(),
                fallback_origin: None,
                error_pages: None,
                problem_details: None,
                proxy_status: None,
                deprecation: None,
                message_signatures: None,
                olp: None,
                web_bot_auth_publish: None,
                idempotency: None,
                timeouts: sbproxy_config::UpstreamTimeouts::default(),
                bot_detection: None,
                threat_protection: None,
                on_request: Vec::new(),
                on_response: Vec::new(),
                response_cache: None,
                mirror: None,
                extensions: HashMap::new(),
                expose_openapi: false,
                stream_safety: Vec::new(),
                auto_content_negotiate: None,
                content_signal: None,
                token_bytes_ratio: None,
                agent_skills: Vec::new(),
                agents_md: None,
                ai_txt: None,
                agents_json: None,
                outbound_credential: None,
                outbound_web_bot_auth: false,
                observability: None,
                attestation: None,
                owasp_pack_manifest: None,
            }],
            host_map,
            server: sbproxy_config::ProxyServerConfig::default(),
            l2_store: None,
            mesh: None,
            access_log: None,
            decision_audit: Default::default(),
            agent_classes: None,
            rate_limits: None,
            audit: None,
            session_ledger: None,
            request_events: None,
            events: None,
            flags: Vec::new(),
            egress: Default::default(),
        }
    }

    #[test]
    fn pipeline_with_transforms() {
        let config = make_config_with_transforms(
            "t.example.com",
            serde_json::json!({"type": "proxy", "url": "http://localhost:3000"}),
            vec![
                serde_json::json!({"type": "json", "set": {"injected": true}, "remove": ["secret"]}),
                serde_json::json!({"type": "noop"}),
            ],
        );
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        assert_eq!(pipeline.transforms.len(), 1); // One origin.
        assert_eq!(pipeline.transforms[0].len(), 2); // Two transforms.
        assert_eq!(pipeline.transforms[0][0].transform.transform_type(), "json");
        assert_eq!(pipeline.transforms[0][1].transform.transform_type(), "noop");
        // Default metadata values.
        assert_eq!(
            pipeline.transforms[0][0].failure_posture,
            sbproxy_config::types::FailureMode::Open
        );
        assert_eq!(pipeline.transforms[0][0].max_body_size, 10 * 1024 * 1024);
        assert!(pipeline.transforms[0][0].content_types.is_empty());
    }

    #[test]
    fn a_cached_origin_refuses_request_dependent_transforms() {
        // A request-dependent transform's stored output would bake one
        // requester's context into a shared entry, and the SWR refresh
        // could not rerun it at all (no request exists there).
        let mut config = make_config_with_transforms(
            "t.example.com",
            serde_json::json!({"type": "proxy", "url": "http://localhost:3000"}),
            vec![serde_json::json!({
                "type": "lua_json",
                "script": "function modify_json(data, ctx) return data end",
            })],
        );
        config.origins[0].response_cache = Some(sbproxy_config::ResponseCacheConfig {
            enabled: true,
            ..Default::default()
        });
        let error = match CompiledPipeline::from_config(config) {
            Ok(_) => panic!("a request-dependent transform on a cached origin must refuse"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("lua_json"), "{error}");
        assert!(error.contains("t.example.com"), "{error}");
        assert!(error.contains("response cache"), "{error}");
    }

    #[test]
    fn a_cached_origin_accepts_request_independent_transforms() {
        let mut config = make_config_with_transforms(
            "t.example.com",
            serde_json::json!({"type": "proxy", "url": "http://localhost:3000"}),
            vec![serde_json::json!({
                "type": "replace_strings",
                "replacements": [{"find": "raw", "replace": "clean"}],
            })],
        );
        config.origins[0].response_cache = Some(sbproxy_config::ResponseCacheConfig {
            enabled: true,
            ..Default::default()
        });
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        assert_eq!(pipeline.transforms[0].len(), 1);
    }

    #[test]
    fn a_disabled_cache_does_not_refuse_dependent_transforms() {
        // The refusal is about what the cache would store; an origin
        // whose cache block is disabled stores nothing.
        let mut config = make_config_with_transforms(
            "t.example.com",
            serde_json::json!({"type": "proxy", "url": "http://localhost:3000"}),
            vec![serde_json::json!({
                "type": "lua_json",
                "script": "function modify_json(data, ctx) return data end",
            })],
        );
        config.origins[0].response_cache = Some(sbproxy_config::ResponseCacheConfig {
            enabled: false,
            ..Default::default()
        });
        CompiledPipeline::from_config(config).unwrap();
    }

    #[test]
    fn pipeline_disabled_transforms_are_skipped() {
        let config = make_config_with_transforms(
            "t.example.com",
            serde_json::json!({"type": "noop"}),
            vec![
                serde_json::json!({"type": "json", "set": {"a": 1}}),
                serde_json::json!({"type": "noop", "disabled": true}),
                serde_json::json!({"type": "json", "remove": ["x"], "fail_on_error": true, "max_body_size": 512}),
            ],
        );
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        // The disabled noop should be filtered out, leaving 2 transforms.
        assert_eq!(pipeline.transforms[0].len(), 2);
        assert_eq!(pipeline.transforms[0][0].transform.transform_type(), "json");
        assert_eq!(pipeline.transforms[0][1].transform.transform_type(), "json");
        // The legacy `fail_on_error: true` wire spelling resolves to closed.
        assert_eq!(
            pipeline.transforms[0][1].failure_posture,
            sbproxy_config::types::FailureMode::Closed
        );
        assert_eq!(pipeline.transforms[0][1].max_body_size, 512);
    }

    #[test]
    fn pipeline_transform_failure_posture_wire_key_resolves() {
        let config = make_config_with_transforms(
            "t.example.com",
            serde_json::json!({"type": "noop"}),
            vec![serde_json::json!({"type": "json", "set": {"a": 1}, "failure_posture": "closed"})],
        );
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        assert_eq!(
            pipeline.transforms[0][0].failure_posture,
            sbproxy_config::types::FailureMode::Closed
        );
    }

    #[test]
    fn pipeline_transform_conflicting_failure_spellings_error() {
        let config = make_config_with_transforms(
            "t.example.com",
            serde_json::json!({"type": "noop"}),
            vec![serde_json::json!({
                "type": "json",
                "set": {"a": 1},
                "fail_on_error": true,
                "failure_posture": "open",
            })],
        );
        let err = CompiledPipeline::from_config(config)
            .err()
            .expect("disagreeing spellings must fail config load")
            .to_string();
        assert!(err.contains("fail_on_error"), "{err}");
        assert!(err.contains("failure_posture"), "{err}");
    }

    #[test]
    fn pipeline_transform_observe_posture_errors_even_when_disabled() {
        // Rejecting before the disabled check keeps a nonsense axis from
        // hiding inside a switched-off transform.
        let config = make_config_with_transforms(
            "t.example.com",
            serde_json::json!({"type": "noop"}),
            vec![serde_json::json!({
                "type": "json",
                "set": {"a": 1},
                "disabled": true,
                "failure_posture": "observe",
            })],
        );
        let err = CompiledPipeline::from_config(config)
            .err()
            .expect("observe must fail config load")
            .to_string();
        assert!(err.contains("observe"), "{err}");
    }

    #[test]
    fn pipeline_invalid_transform_errors() {
        let config = make_config_with_transforms(
            "bad.example.com",
            serde_json::json!({"type": "noop"}),
            vec![serde_json::json!({"type": "unknown_transform_type"})],
        );
        assert!(CompiledPipeline::from_config(config).is_err());
    }

    #[test]
    fn pipeline_no_transforms_gives_empty_vec() {
        let config = make_config(
            "api.example.com",
            serde_json::json!({"type": "noop"}),
            None,
            vec![],
        );
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        assert_eq!(pipeline.transforms.len(), 1); // One origin.
        assert!(pipeline.transforms[0].is_empty()); // No transforms.
    }

    #[test]
    fn pipeline_default_is_empty() {
        let pipeline = CompiledPipeline::default();
        assert!(pipeline.actions.is_empty());
        assert!(pipeline.auths.is_empty());
        assert!(pipeline.policies.is_empty());
        assert!(pipeline.transforms.is_empty());
        assert!(pipeline.forward_rules.is_empty());
        assert!(pipeline.fallbacks.is_empty());
        assert!(pipeline.config.origins.is_empty());
    }

    #[test]
    fn compiled_pipeline_has_hooks_field_defaulting_to_none() {
        let pipeline = CompiledPipeline::empty_for_test();
        assert!(pipeline.hooks.startup.is_none());
        assert!(pipeline.hooks.prompt_classifier.is_none());
        assert!(pipeline.hooks.intent_detection.is_none());
        assert!(pipeline.hooks.quality_scoring.is_none());
        assert!(pipeline.hooks.stream_safety.is_none());
    }

    /// A default pipeline must carry an empty semantic-cache registry.
    /// The default path is taken by hundreds of unit tests, so it must not
    /// inspect config, resolve DNS, open Redis, read cluster state, or
    /// bind a mesh store.
    #[test]
    fn compiled_pipeline_default_has_an_empty_semantic_cache_registry() {
        let pipeline = CompiledPipeline::default();
        assert!(pipeline.semantic_caches.get(0, None).is_none());
        assert!(pipeline.semantic_caches.get(0, Some(0)).is_none());
    }

    #[test]
    fn compiled_pipeline_default_semantic_registry_has_no_registrations() {
        let pipeline = CompiledPipeline::default();
        assert_eq!(pipeline.semantic_caches.registrations().count(), 0);
    }

    #[test]
    fn pipeline_compiles_forward_rules() {
        let yaml = r#"
proxy:
  http_bind_port: 18080
origins:
  "routing.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    forward_rules:
      - rules:
          - path:
              prefix: /api/
        origin:
          id: api-backend
          action:
            type: proxy
            url: http://127.0.0.1:18888/echo
      - rules:
          - path:
              exact: /health
        origin:
          id: health-static
          action:
            type: static
            status_code: 200
            content_type: application/json
            json_body:
              status: healthy
"#;
        let config = sbproxy_config::compile_config(yaml).unwrap();
        let pipeline = CompiledPipeline::from_config(config).unwrap();

        assert_eq!(pipeline.forward_rules.len(), 1); // One origin.
        assert_eq!(pipeline.forward_rules[0].len(), 2); // Two forward rules.

        // First rule: prefix /api/ -> proxy action
        let rule0 = &pipeline.forward_rules[0][0];
        assert_eq!(rule0.matchers.len(), 1);
        let path0 = rule0.matchers[0].path.as_ref().expect("path matcher");
        assert!(path0.matches("/api/users"));
        assert!(!path0.matches("/health"));
        assert_eq!(rule0.action.action_type(), "proxy");

        // Second rule: exact /health -> static action
        let rule1 = &pipeline.forward_rules[0][1];
        assert_eq!(rule1.matchers.len(), 1);
        let path1 = rule1.matchers[0].path.as_ref().expect("path matcher");
        assert!(path1.matches("/health"));
        assert!(!path1.matches("/health/"));
        assert_eq!(rule1.action.action_type(), "static");
    }

    #[test]
    fn pipeline_compiles_fallback_origin() {
        let yaml = r#"
origins:
  "fb.test":
    action:
      type: proxy
      url: http://127.0.0.1:19999
    fallback_origin:
      on_error: true
      on_status: [502, 503, 504]
      add_debug_header: true
      origin:
        id: fb-fallback
        action:
          type: static
          status_code: 200
          content_type: application/json
          json_body:
            source: fallback
"#;
        let config = sbproxy_config::compile_config(yaml).unwrap();
        let pipeline = CompiledPipeline::from_config(config).unwrap();

        assert_eq!(pipeline.fallbacks.len(), 1);
        let fb = pipeline.fallbacks[0].as_ref().unwrap();
        assert!(fb.on_error);
        assert_eq!(fb.on_status, vec![502, 503, 504]);
        assert!(fb.add_debug_header);
        assert_eq!(fb.action.action_type(), "static");
    }

    #[test]
    fn pipeline_no_forward_rules_or_fallback() {
        let config = make_config(
            "simple.test",
            serde_json::json!({"type": "proxy", "url": "http://localhost:3000"}),
            None,
            vec![],
        );
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        assert!(pipeline.forward_rules[0].is_empty());
        assert!(pipeline.fallbacks[0].is_none());
    }
    #[test]
    fn pipeline_forward_rule_request_modifiers_are_applied() {
        // Verifies that forward rule request modifiers (e.g., X-Routed-To) are
        // correctly compiled and can be applied to a HeaderMap.
        let yaml = r#"
proxy:
  http_bind_port: 18080
origins:
  "fwdlocal.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888/echo
    forward_rules:
      - rules:
          - path:
              prefix: /api/
        origin:
          id: api-route
          action:
            type: proxy
            url: http://127.0.0.1:18888/echo
          request_modifiers:
            - headers:
                set:
                  X-Routed-To: api-backend
"#;
        let config = sbproxy_config::compile_config(yaml).unwrap();
        let pipeline = CompiledPipeline::from_config(config).unwrap();

        let fwd = &pipeline.forward_rules[0];
        assert_eq!(fwd.len(), 1);
        assert!(!fwd[0].request_modifiers.is_empty());

        // Simulate applying modifiers to a header map.
        let mut headers = http::HeaderMap::new();
        sbproxy_middleware::modifiers::apply_request_modifiers(
            &fwd[0].request_modifiers,
            &mut headers,
        );
        assert_eq!(
            headers.get("x-routed-to").map(|v| v.to_str().unwrap()),
            Some("api-backend"),
            "X-Routed-To header should be set by forward rule modifier"
        );
    }

    // --- Path matcher tests ---

    #[test]
    fn template_matches_named_segments() {
        let t = PathTemplate::compile("/users/{id}/posts/{post_id}").unwrap();
        let captured = t.match_path("/users/42/posts/abc").unwrap();
        assert_eq!(captured.get("id").map(String::as_str), Some("42"));
        assert_eq!(captured.get("post_id").map(String::as_str), Some("abc"));
    }

    #[test]
    fn template_rejects_wrong_segment_count() {
        let t = PathTemplate::compile("/users/{id}").unwrap();
        assert!(t.match_path("/users/42/extra").is_none());
        assert!(t.match_path("/users").is_none());
    }

    #[test]
    fn template_literal_segments_must_match() {
        let t = PathTemplate::compile("/users/{id}/posts").unwrap();
        assert!(t.match_path("/users/42/posts").is_some());
        assert!(t.match_path("/users/42/comments").is_none());
    }

    #[test]
    fn template_catch_all_captures_remainder() {
        let t = PathTemplate::compile("/static/{*rest}").unwrap();
        let captured = t.match_path("/static/css/site.css").unwrap();
        assert_eq!(
            captured.get("rest").map(String::as_str),
            Some("css/site.css")
        );

        // Catch-all may match zero remaining segments too.
        let captured = t.match_path("/static").unwrap();
        assert_eq!(captured.get("rest").map(String::as_str), Some(""));
    }

    #[test]
    fn template_catch_all_must_be_last() {
        let err = PathTemplate::compile("/static/{*rest}/extra").unwrap_err();
        assert!(err.to_string().contains("catch-all"));
    }

    #[test]
    fn template_constraint_passes_only_when_regex_matches() {
        let t = PathTemplate::compile("/users/{id:[0-9]+}").unwrap();
        assert!(t.match_path("/users/42").is_some());
        assert!(
            t.match_path("/users/abc").is_none(),
            "constraint should reject non-numeric id"
        );
    }

    #[test]
    fn template_invalid_constraint_errors_at_compile() {
        let err = PathTemplate::compile("/x/{id:[}").unwrap_err();
        assert!(err.to_string().contains("invalid constraint regex"));
    }

    #[test]
    fn template_mixed_literal_param_segment_rejected() {
        let err = PathTemplate::compile("/users-{id}").unwrap_err();
        assert!(err.to_string().contains("mixed"));
    }

    #[test]
    fn path_match_template_via_match_with_params() {
        let pm = PathMatch::Template(PathTemplate::compile("/users/{id}").unwrap());
        let params = pm.match_with_params("/users/42").unwrap();
        assert_eq!(params.get("id").map(String::as_str), Some("42"));
        assert!(pm.match_with_params("/orders/42").is_none());
    }

    #[test]
    fn path_match_regex_named_captures() {
        let re = regex::Regex::new(r"^/v(?P<version>\d+)/items").unwrap();
        let pm = PathMatch::Regex(re);
        let params = pm.match_with_params("/v3/items/123").unwrap();
        assert_eq!(params.get("version").map(String::as_str), Some("3"));
    }

    #[test]
    fn path_match_prefix_returns_empty_params() {
        let pm = PathMatch::Prefix("/api/".to_string());
        let params = pm.match_with_params("/api/users").unwrap();
        assert!(params.is_empty());
        assert!(pm.match_with_params("/health").is_none());
    }

    #[test]
    fn path_match_exact_returns_empty_params() {
        let pm = PathMatch::Exact("/health".to_string());
        let params = pm.match_with_params("/health").unwrap();
        assert!(params.is_empty());
        assert!(pm.match_with_params("/health/").is_none());
    }

    #[test]
    fn pipeline_compiles_template_forward_rule() {
        let yaml = r#"
proxy:
  http_bind_port: 18080
origins:
  "tmpl.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    forward_rules:
      - rules:
          - path:
              template: /users/{id}/posts/{post_id}
        origin:
          id: posts
          action:
            type: proxy
            url: http://127.0.0.1:18888/posts
"#;
        let config = sbproxy_config::compile_config(yaml).unwrap();
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        let rule = &pipeline.forward_rules[0][0];
        assert_eq!(rule.matchers.len(), 1);
        let path = rule.matchers[0].path.as_ref().expect("path matcher");
        let params = path
            .match_with_params("/users/42/posts/abc")
            .expect("template should match");
        assert_eq!(params.get("id").map(String::as_str), Some("42"));
        assert_eq!(params.get("post_id").map(String::as_str), Some("abc"));
    }

    #[test]
    fn pipeline_propagates_rule_parameters() {
        let yaml = r#"
proxy:
  http_bind_port: 18080
origins:
  "params.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    forward_rules:
      - rules:
          - path:
              template: /users/{id}
        parameters:
          - name: id
            in: path
            required: true
            description: Numeric user identifier
            schema:
              type: integer
              format: int64
          - name: include
            in: query
            required: false
            schema:
              type: string
        origin:
          id: users-api
          action:
            type: proxy
            url: http://127.0.0.1:18888/users
"#;
        let config = sbproxy_config::compile_config(yaml).unwrap();
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        let rule = &pipeline.forward_rules[0][0];
        assert_eq!(rule.parameters.len(), 2);
        assert_eq!(rule.parameters[0].name, "id");
        assert_eq!(
            rule.parameters[0].location,
            sbproxy_config::ParameterLocation::Path
        );
        assert!(rule.parameters[0].required);
        assert_eq!(
            rule.parameters[0].description.as_deref(),
            Some("Numeric user identifier")
        );
        assert_eq!(
            rule.parameters[0]
                .schema
                .get("type")
                .and_then(|v| v.as_str()),
            Some("integer")
        );
        assert_eq!(rule.parameters[1].name, "include");
        assert_eq!(
            rule.parameters[1].location,
            sbproxy_config::ParameterLocation::Query
        );
    }

    #[test]
    fn pipeline_compiles_regex_forward_rule() {
        let yaml = r#"
proxy:
  http_bind_port: 18080
origins:
  "rx.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    forward_rules:
      - rules:
          - path:
              regex: '^/v(?P<version>[0-9]+)/items'
        origin:
          id: versioned
          action:
            type: proxy
            url: http://127.0.0.1:18888/items
"#;
        let config = sbproxy_config::compile_config(yaml).unwrap();
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        let rule = &pipeline.forward_rules[0][0];
        let path = rule.matchers[0].path.as_ref().expect("path matcher");
        let params = path
            .match_with_params("/v3/items/abc")
            .expect("regex should match");
        assert_eq!(params.get("version").map(String::as_str), Some("3"));
    }

    #[test]
    fn pipeline_compiles_header_forward_rule() {
        let yaml = r#"
proxy:
  http_bind_port: 18080
origins:
  "h.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    forward_rules:
      - rules:
          - header:
              name: X-Tenant
              value: foo
        origin:
          id: tenant-foo
          action:
            type: proxy
            url: http://127.0.0.1:18889
"#;
        let config = sbproxy_config::compile_config(yaml).unwrap();
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        let rule = &pipeline.forward_rules[0][0];
        assert_eq!(rule.matchers.len(), 1);
        let mut headers = http::HeaderMap::new();
        headers.insert("x-tenant", http::HeaderValue::from_static("foo"));
        let captured =
            rule.matchers[0].match_request(&http::Method::GET, "/anything", None, &headers);
        assert!(captured.is_some(), "header match should fire");

        let mut other = http::HeaderMap::new();
        other.insert("x-tenant", http::HeaderValue::from_static("bar"));
        assert!(rule.matchers[0]
            .match_request(&http::Method::GET, "/anything", None, &other)
            .is_none());
    }

    #[test]
    fn pipeline_compiles_method_forward_rule() {
        let yaml = r#"
proxy:
  http_bind_port: 18080
origins:
  "m.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    forward_rules:
      - rules:
          - method: post
        origin:
          id: writes
          action:
            type: proxy
            url: http://127.0.0.1:18893
"#;
        let config = sbproxy_config::compile_config(yaml).unwrap();
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        let rule = &pipeline.forward_rules[0][0];
        assert_eq!(rule.matchers.len(), 1);
        let headers = http::HeaderMap::new();
        // Authored lowercase, matched against the uppercase wire method.
        assert!(rule.matchers[0]
            .match_request(&http::Method::POST, "/anything", None, &headers)
            .is_some());
        assert!(rule.matchers[0]
            .match_request(&http::Method::GET, "/anything", None, &headers)
            .is_none());
    }

    #[test]
    fn pipeline_compiles_method_list_forward_rule() {
        let yaml = r#"
proxy:
  http_bind_port: 18080
origins:
  "ml.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    forward_rules:
      - rules:
          - path:
              prefix: /api/
            method: [POST, PUT]
        origin:
          id: api-writes
          action:
            type: proxy
            url: http://127.0.0.1:18894
"#;
        let config = sbproxy_config::compile_config(yaml).unwrap();
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        let rule = &pipeline.forward_rules[0][0];
        let headers = http::HeaderMap::new();
        // Method and path AND within the entry.
        assert!(rule.matchers[0]
            .match_request(&http::Method::PUT, "/api/x", None, &headers)
            .is_some());
        assert!(rule.matchers[0]
            .match_request(&http::Method::GET, "/api/x", None, &headers)
            .is_none());
        assert!(rule.matchers[0]
            .match_request(&http::Method::PUT, "/web/x", None, &headers)
            .is_none());
    }

    #[test]
    fn pipeline_compiles_query_forward_rule() {
        let yaml = r#"
proxy:
  http_bind_port: 18080
origins:
  "q.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    forward_rules:
      - rules:
          - query:
              name: env
              value: staging
        origin:
          id: q-staging
          action:
            type: proxy
            url: http://127.0.0.1:18890
"#;
        let config = sbproxy_config::compile_config(yaml).unwrap();
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        let rule = &pipeline.forward_rules[0][0];
        assert_eq!(rule.matchers.len(), 1);
        let headers = http::HeaderMap::new();
        assert!(rule.matchers[0]
            .match_request(
                &http::Method::GET,
                "/anything",
                Some("env=staging&x=1"),
                &headers
            )
            .is_some());
        assert!(rule.matchers[0]
            .match_request(&http::Method::GET, "/anything", Some("env=prod"), &headers)
            .is_none());
        assert!(rule.matchers[0]
            .match_request(&http::Method::GET, "/anything", None, &headers)
            .is_none());
    }

    #[test]
    fn pipeline_path_and_header_are_anded() {
        let yaml = r#"
proxy:
  http_bind_port: 18080
origins:
  "and.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    forward_rules:
      - rules:
          - path:
              prefix: /api/
            header:
              name: X-Beta
              value: "true"
        origin:
          id: beta
          action:
            type: proxy
            url: http://127.0.0.1:18891
"#;
        let config = sbproxy_config::compile_config(yaml).unwrap();
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        let rule = &pipeline.forward_rules[0][0];
        let mut beta = http::HeaderMap::new();
        beta.insert("x-beta", http::HeaderValue::from_static("true"));
        let mut not_beta = http::HeaderMap::new();
        not_beta.insert("x-beta", http::HeaderValue::from_static("false"));

        // Both must hold.
        assert!(rule.matchers[0]
            .match_request(&http::Method::GET, "/api/x", None, &beta)
            .is_some());
        // Path matches, header wrong: AND fails.
        assert!(rule.matchers[0]
            .match_request(&http::Method::GET, "/api/x", None, &not_beta)
            .is_none());
        // Header matches, path wrong: AND fails.
        assert!(rule.matchers[0]
            .match_request(&http::Method::GET, "/web/x", None, &beta)
            .is_none());
    }

    #[test]
    fn pipeline_compiles_header_prefix() {
        let yaml = r#"
proxy:
  http_bind_port: 18080
origins:
  "hp.test":
    action:
      type: proxy
      url: http://127.0.0.1:18888
    forward_rules:
      - rules:
          - header:
              name: Authorization
              prefix: "Bearer "
        origin:
          id: bearer
          action:
            type: proxy
            url: http://127.0.0.1:18892
"#;
        let config = sbproxy_config::compile_config(yaml).unwrap();
        let pipeline = CompiledPipeline::from_config(config).unwrap();
        let rule = &pipeline.forward_rules[0][0];
        let mut bearer = http::HeaderMap::new();
        bearer.insert(
            "authorization",
            http::HeaderValue::from_static("Bearer abc123"),
        );
        let mut basic = http::HeaderMap::new();
        basic.insert("authorization", http::HeaderValue::from_static("Basic xyz"));
        assert!(rule.matchers[0]
            .match_request(&http::Method::GET, "/", None, &bearer)
            .is_some());
        assert!(rule.matchers[0]
            .match_request(&http::Method::GET, "/", None, &basic)
            .is_none());
    }

    #[test]
    fn validation_rejects_dpop_on_load_balanced_action() {
        let yaml = r#"
proxy:
  http_bind_port: 18080
  # `compile_config` refuses a `secret://<backend>/...` naming a backend
  # that is not declared, and this case is about the DPoP rule, not that
  # one, so the backend is declared. Nothing resolves it here.
  secrets:
    backends:
      - type: local
        name: prod
origins:
  "dpop-lb.test":
    action:
      type: load_balancer
      algorithm: round_robin
      targets:
        - url: https://one.example.test
        - url: https://two.example.test
    outbound_credential:
      type: client_credentials
      token_endpoint: https://idp.example.test/token
      client_id: sbproxy
      client_secret: secret://prod/client-secret
      dpop:
        key: secret://prod/dpop-key
        alg: ES256
        jwk:
          kty: EC
          crv: P-256
          x: DpZdjog3y9hgIyKgEPltBi5ptXKUeuRwVOAPSmoQAu4
          y: bfVVYV9slbMcg4dvtvYbeekYtpFXsYCWcIa9RCrBmTc
"#;
        let config = sbproxy_config::compile_config(yaml).unwrap();
        let error = match CompiledPipeline::from_config_for_validation(config) {
            Ok(_) => panic!("load-balanced DPoP configuration must be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("not supported with load-balanced actions"));
    }

    #[test]
    fn validation_rejects_hop_by_hop_outbound_credential_headers() {
        for header in ["keep-alive", "proxy-connection", "te", "trailer"] {
            let yaml = format!(
                r#"
proxy:
  http_bind_port: 18080
origins:
  "credential.test":
    action:
      type: proxy
      url: https://upstream.example.test
    outbound_credential:
      type: vault_secret
      secret: operator-secret
      header: {header}
"#
            );
            let config = sbproxy_config::compile_config(&yaml).unwrap();
            let error = match CompiledPipeline::from_config_for_validation(config) {
                Ok(_) => panic!("{header} must not be an outbound credential carrier"),
                Err(error) => error,
            };
            assert!(
                error
                    .to_string()
                    .contains("header may not carry a credential"),
                "unexpected {header} validation error: {error}"
            );
        }
    }

    /// WOR-2316: token exchange is a delegation primitive, so an
    /// unauthored allowlist must fail config compilation with the key
    /// named rather than silently accepting any issuer or audience.
    #[test]
    fn validation_rejects_empty_token_exchange_allowlists() {
        for (omitted, present) in [
            (
                "subject_token_issuers",
                "      allowed_audiences: [\"https://api.example.test\"]",
            ),
            (
                "allowed_audiences",
                "      subject_token_issuers: [\"https://idp.example.test\"]",
            ),
        ] {
            let yaml = format!(
                r#"
proxy:
  http_bind_port: 18080
origins:
  "exchange.test":
    action:
      type: proxy
      url: https://upstream.example.test
    outbound_credential:
      type: token_exchange
      token_endpoint: https://idp.example.test/token
      audience: https://api.example.test
{present}
"#
            );
            let config = sbproxy_config::compile_config(&yaml).unwrap();
            let error = match CompiledPipeline::from_config_for_validation(config) {
                Ok(_) => panic!("an empty {omitted} allowlist must be rejected"),
                Err(error) => error,
            };
            let text = error.to_string();
            assert!(
                text.contains(omitted),
                "error must name the empty key {omitted}, got: {text}"
            );
            assert!(
                text.contains("exchange.test"),
                "error must name the origin, got: {text}"
            );
        }
    }

    /// The other half of WOR-2316: an authored pair still compiles, so
    /// the fix is "list the values", not "stop using token exchange".
    #[test]
    fn validation_accepts_explicit_token_exchange_allowlists() {
        let yaml = r#"
proxy:
  http_bind_port: 18080
origins:
  "exchange.test":
    action:
      type: proxy
      url: https://upstream.example.test
    outbound_credential:
      type: token_exchange
      token_endpoint: https://idp.example.test/token
      audience: https://api.example.test
      subject_token_issuers: ["https://idp.example.test"]
      allowed_audiences: ["https://api.example.test"]
"#;
        let config = sbproxy_config::compile_config(yaml).unwrap();
        CompiledPipeline::from_config_for_validation(config)
            .expect("an explicitly allowlisted token exchange compiles");
    }
}

#[cfg(test)]
mod normalize_tests {
    use super::*;

    #[test]
    fn normalize_go_header_modifier() {
        let val = serde_json::json!({
            "type": "header",
            "set": {
                "X-Routed-To": "api-backend"
            }
        });
        let config = normalize_request_modifier(&val);
        assert!(config.headers.is_some(), "headers should be Some");
        let headers = config.headers.unwrap();
        assert_eq!(
            headers.set.get("X-Routed-To").map(|s| s.as_str()),
            Some("api-backend")
        );
    }
}

/// WOR-2306: body-field route matching.
#[cfg(test)]
mod body_matcher_tests {
    use super::*;

    /// A representative chat-completion request. `model` is a body field in
    /// this shape, which is the whole reason the matcher exists.
    const CHAT_BODY: &[u8] = br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"stream":true,"tools":[{"name":"search"}]}"#;

    fn compiled(json: serde_json::Value) -> BodyMatch {
        compile_body_matcher(Some(&json))
            .expect("body matcher compiles")
            .expect("body matcher is present")
    }

    fn body_only_entry(json: serde_json::Value) -> MatcherEntry {
        MatcherEntry {
            method: None,
            path: None,
            header: None,
            query: None,
            body: Some(compiled(json)),
            when: None,
        }
    }

    fn rule_with(matchers: Vec<MatcherEntry>) -> CompiledForwardRule {
        CompiledForwardRule {
            matchers,
            action: Action::Noop,
            request_modifiers: Vec::new(),
            parameters: Vec::new(),
            id: None,
            deprecation: None,
        }
    }

    #[test]
    fn an_equals_matcher_hits_the_model_it_names() {
        let matcher = compiled(serde_json::json!({"pointer": "/model", "value": "gpt-4o"}));
        assert!(matcher.matches(Some(CHAT_BODY)));
    }

    #[test]
    fn an_equals_matcher_misses_a_different_model() {
        let matcher = compiled(serde_json::json!({"pointer": "/model", "value": "gpt-4o-mini"}));
        assert!(!matcher.matches(Some(CHAT_BODY)));
    }

    #[test]
    fn a_prefix_matcher_groups_a_model_family() {
        let hit = compiled(serde_json::json!({"pointer": "/model", "prefix": "gpt-"}));
        assert!(hit.matches(Some(CHAT_BODY)));
        let miss = compiled(serde_json::json!({"pointer": "/model", "prefix": "claude-"}));
        assert!(!miss.matches(Some(CHAT_BODY)));
    }

    #[test]
    fn value_wins_over_prefix_when_both_are_configured() {
        // Mirrors the header matcher, where `value` also wins.
        let matcher = compiled(serde_json::json!({
            "pointer": "/model",
            "value": "gpt-4o",
            "prefix": "claude-",
        }));
        assert!(matcher.matches(Some(CHAT_BODY)));
    }

    #[test]
    fn a_presence_matcher_fires_on_a_container_field() {
        let matcher = compiled(serde_json::json!({"pointer": "/tools"}));
        assert!(matcher.matches(Some(CHAT_BODY)));
    }

    #[test]
    fn a_boolean_compares_against_its_text_form() {
        let matcher = compiled(serde_json::json!({"pointer": "/stream", "value": "true"}));
        assert!(matcher.matches(Some(CHAT_BODY)));
    }

    #[test]
    fn a_missing_field_misses() {
        let matcher = compiled(serde_json::json!({"pointer": "/provider", "value": "openai"}));
        assert!(!matcher.matches(Some(CHAT_BODY)));
        let present = compiled(serde_json::json!({"pointer": "/provider"}));
        assert!(!present.matches(Some(CHAT_BODY)));
    }

    #[test]
    fn a_container_never_equals_a_configured_string() {
        // The wrong-type case: `/tools` resolves, but to an array, so a
        // string comparison against it cannot succeed and must not error.
        let equals = compiled(serde_json::json!({"pointer": "/tools", "value": "search"}));
        assert!(!equals.matches(Some(CHAT_BODY)));
        let prefix = compiled(serde_json::json!({"pointer": "/tools", "prefix": "se"}));
        assert!(!prefix.matches(Some(CHAT_BODY)));
    }

    #[test]
    fn a_non_json_body_misses_without_erroring() {
        let matcher = compiled(serde_json::json!({"pointer": "/model", "value": "gpt-4o"}));
        assert!(!matcher.matches(Some(b"model=gpt-4o&stream=true")));
        assert!(!matcher.matches(Some(b"<request><model>gpt-4o</model></request>")));
        assert!(!matcher.matches(Some(&[0x1f, 0x8b, 0x08, 0x00])));
        assert!(!matcher.matches(Some(b"")));
    }

    #[test]
    fn a_malformed_json_body_misses_without_erroring() {
        let matcher = compiled(serde_json::json!({"pointer": "/model", "value": "gpt-4o"}));
        assert!(!matcher.matches(Some(br#"{"model":"gpt-4o""#)));
        assert!(!matcher.matches(Some(br#"{"model":}"#)));
        assert!(!matcher.matches(Some(br#"{"model":"gpt-4o",}"#)));
    }

    #[test]
    fn a_body_over_the_cap_misses_rather_than_failing() {
        let matcher = compiled(serde_json::json!({
            "pointer": "/model",
            "value": "gpt-4o",
            "max_bytes": 32,
        }));
        assert!(
            CHAT_BODY.len() > 32,
            "the fixture has to exceed the cap for this to test anything"
        );
        assert!(!matcher.matches(Some(CHAT_BODY)));

        // The same matcher against a body inside its cap still hits, so the
        // cap is what rejected the larger one and not the pointer.
        assert!(matcher.matches(Some(br#"{"model":"gpt-4o"}"#)));
    }

    #[test]
    fn an_unbuffered_body_misses() {
        // `None` is what the request phase passes when the body was never
        // read: no body at all, a Content-Length already past the cap, or a
        // replay buffer that filled before the body ended.
        let matcher = compiled(serde_json::json!({"pointer": "/model", "value": "gpt-4o"}));
        assert!(!matcher.matches(None));
        let present = compiled(serde_json::json!({"pointer": "/model"}));
        assert!(!present.matches(None));
    }

    fn when_predicate(source: &str) -> std::sync::Arc<sbproxy_extension::cel::CompiledCel> {
        std::sync::Arc::new(
            sbproxy_extension::cel::CompiledCel::compile(
                sbproxy_extension::cel::CelSurface::ForwardRuleWhen,
                "forward rule `test` when",
                source,
            )
            .expect("test predicate compiles"),
        )
    }

    fn request_cel_context(
        path: &str,
        headers: &http::HeaderMap,
    ) -> sbproxy_extension::cel::CelContext {
        sbproxy_extension::cel::context::build_request_context(
            "GET",
            path,
            headers,
            None,
            None,
            "api.example.com",
        )
    }

    #[test]
    fn a_when_predicate_ands_with_the_structured_matchers() {
        let entry = MatcherEntry {
            method: None,
            path: Some(PathMatch::Prefix("/v1".to_string())),
            header: None,
            query: None,
            body: None,
            when: Some(when_predicate(r#"request.path.endsWith("/chat")"#)),
        };
        let headers = http::HeaderMap::new();

        let ctx = request_cel_context("/v1/chat", &headers);
        assert!(
            entry
                .match_request_with_body(
                    &http::Method::GET,
                    "/v1/chat",
                    None,
                    &headers,
                    None,
                    Some(&ctx),
                )
                .is_some(),
            "prefix and predicate both pass"
        );

        // Prefix passes, predicate does not: the entry must not fire.
        let ctx = request_cel_context("/v1/models", &headers);
        assert!(entry
            .match_request_with_body(
                &http::Method::GET,
                "/v1/models",
                None,
                &headers,
                None,
                Some(&ctx),
            )
            .is_none());
    }

    #[test]
    fn a_when_predicate_without_a_context_does_not_match() {
        // Fail closed. The caller builds a context only when some entry
        // declares a `when`, so arriving here without one is a bug, and
        // matching on the structured half alone would route traffic
        // past a gate the operator wrote.
        let entry = MatcherEntry {
            method: None,
            path: Some(PathMatch::Prefix("/v1".to_string())),
            header: None,
            query: None,
            body: None,
            when: Some(when_predicate("true")),
        };
        assert!(
            entry
                .match_request_with_body(
                    &http::Method::GET,
                    "/v1/chat",
                    None,
                    &http::HeaderMap::new(),
                    None,
                    None,
                )
                .is_none(),
            "a predicate that could not be evaluated has not said yes"
        );
    }

    #[test]
    fn a_when_predicate_that_errors_does_not_match() {
        // Same posture for a runtime failure. `request.headers[...]` on
        // an absent key errors rather than returning a falsy value.
        let entry = MatcherEntry {
            method: None,
            path: None,
            header: None,
            query: None,
            body: None,
            when: Some(when_predicate(r#"request.headers["x-absent"] == "1""#)),
        };
        let headers = http::HeaderMap::new();
        let ctx = request_cel_context("/v1/chat", &headers);
        assert!(entry
            .match_request_with_body(
                &http::Method::GET,
                "/v1/chat",
                None,
                &headers,
                None,
                Some(&ctx),
            )
            .is_none());
    }

    #[test]
    fn a_when_predicate_expresses_the_or_the_structured_matchers_cannot() {
        // The reason this exists. Two independent structured matchers
        // always AND; this is the same rule as an OR.
        let entry = MatcherEntry {
            method: None,
            path: None,
            header: None,
            query: None,
            body: None,
            when: Some(when_predicate(
                r#"request.path.startsWith("/v1") || request.path.startsWith("/v2")"#,
            )),
        };
        let headers = http::HeaderMap::new();
        for path in ["/v1/chat", "/v2/chat"] {
            let ctx = request_cel_context(path, &headers);
            assert!(
                entry
                    .match_request_with_body(
                        &http::Method::GET,
                        path,
                        None,
                        &headers,
                        None,
                        Some(&ctx),
                    )
                    .is_some(),
                "{path} should match"
            );
        }
        let ctx = request_cel_context("/v3/chat", &headers);
        assert!(entry
            .match_request_with_body(
                &http::Method::GET,
                "/v3/chat",
                None,
                &headers,
                None,
                Some(&ctx)
            )
            .is_none());
    }

    #[test]
    fn the_body_matcher_ands_with_the_other_matchers() {
        let entry = MatcherEntry {
            method: None,
            path: Some(PathMatch::Prefix("/v1/chat".to_string())),
            header: Some(HeaderMatch::Equals {
                name: http::HeaderName::from_static("x-tier"),
                value: "gold".to_string(),
            }),
            query: None,
            body: Some(compiled(
                serde_json::json!({"pointer": "/model", "value": "gpt-4o"}),
            )),
            when: None,
        };
        let mut headers = http::HeaderMap::new();
        headers.insert("x-tier", http::HeaderValue::from_static("gold"));

        assert!(entry
            .match_request_with_body(
                &http::Method::POST,
                "/v1/chat/completions",
                None,
                &headers,
                Some(CHAT_BODY),
                None,
            )
            .is_some());
        // Body agrees, path does not.
        assert!(entry
            .match_request_with_body(
                &http::Method::POST,
                "/v1/embeddings",
                None,
                &headers,
                Some(CHAT_BODY),
                None,
            )
            .is_none());
        // Path and header agree, body does not.
        assert!(entry
            .match_request_with_body(
                &http::Method::POST,
                "/v1/chat/completions",
                None,
                &headers,
                Some(br#"{"model":"claude-sonnet-4"}"#),
                None,
            )
            .is_none());
        // Everything else agrees but no body was buffered.
        assert!(entry
            .match_request_with_body(
                &http::Method::POST,
                "/v1/chat/completions",
                None,
                &headers,
                None,
                None,
            )
            .is_none());
    }

    #[test]
    fn a_header_only_entry_is_unaffected_by_the_new_argument() {
        let entry = MatcherEntry {
            method: None,
            path: Some(PathMatch::Prefix("/v1".to_string())),
            header: None,
            query: None,
            body: None,
            when: None,
        };
        let headers = http::HeaderMap::new();
        assert!(entry
            .match_request(&http::Method::GET, "/v1/chat", None, &headers)
            .is_some());
        assert!(entry
            .match_request_with_body(
                &http::Method::GET,
                "/v1/chat",
                None,
                &headers,
                Some(CHAT_BODY),
                None,
            )
            .is_some());
    }

    #[test]
    fn an_origin_without_a_body_matcher_never_buffers() {
        // `forward_rule_body_cap` is the single gate the request phase reads
        // before it enables replay buffering or drains the downstream body.
        // `None` here is the proof that an origin routing on path, header,
        // and query pays nothing for a feature it did not ask for: no
        // buffering, no drain, no parse.
        let rules = vec![
            rule_with(vec![MatcherEntry {
                method: None,
                path: Some(PathMatch::Prefix("/v1".to_string())),
                header: None,
                query: None,
                body: None,
                when: None,
            }]),
            rule_with(vec![MatcherEntry {
                method: None,
                path: None,
                header: None,
                query: Some(QueryMatch::Present {
                    name: "debug".to_string(),
                }),
                body: None,
                when: None,
            }]),
        ];
        assert_eq!(forward_rule_body_cap(&rules), None);
        assert_eq!(forward_rule_body_cap(&[]), None);
    }

    #[test]
    fn the_cap_for_an_origin_is_the_largest_any_of_its_matchers_asks_for() {
        let rules = vec![
            rule_with(vec![body_only_entry(serde_json::json!({
                "pointer": "/model",
                "value": "gpt-4o",
                "max_bytes": 4096,
            }))]),
            rule_with(vec![body_only_entry(serde_json::json!({
                "pointer": "/model",
                "value": "claude-sonnet-4",
                "max_bytes": 16384,
            }))]),
        ];
        assert_eq!(forward_rule_body_cap(&rules), Some(16384));
    }

    #[test]
    fn the_default_cap_is_the_replay_buffer_size() {
        let matcher = compiled(serde_json::json!({"pointer": "/model"}));
        assert_eq!(
            matcher.max_bytes,
            usize::try_from(sbproxy_config::BODY_MATCH_MAX_BYTES).expect("cap fits in usize")
        );
    }

    // `.err().expect(..)` rather than `.expect_err(..)` throughout this
    // group, for the same reason the `CompiledPipeline` tests further down
    // do it: `BodyMatch` withholds `Debug` on purpose, since it holds a
    // compiled matcher whose contents are config detail rather than
    // something worth printing, and `expect_err` requires `Debug` on the
    // `Ok` type. The test bends, not the production type (WOR-2193).
    #[test]
    fn a_cap_above_the_replay_buffer_is_refused_at_config_load() {
        let error = compile_body_matcher(Some(&serde_json::json!({
            "pointer": "/model",
            "max_bytes": 1_048_576,
        })))
        .err()
        .expect("a cap the replay buffer cannot hold must not compile");
        let message = format!("{error:#}");
        assert!(message.contains("65536"), "{message}");
        assert!(message.contains("replay buffer"), "{message}");
    }

    #[test]
    fn a_zero_cap_is_refused_at_config_load() {
        let error = compile_body_matcher(Some(&serde_json::json!({
            "pointer": "/model",
            "max_bytes": 0,
        })))
        .err()
        .expect("a cap of zero can never match and must not compile");
        assert!(format!("{error:#}").contains("never match"), "{error:#}");
    }

    #[test]
    fn an_unusable_pointer_fails_config_load() {
        let error = compile_body_matcher(Some(&serde_json::json!({"pointer": "model"})))
            .err()
            .expect("a bare field name is not a JSON Pointer");
        assert!(format!("{error:#}").contains("RFC 6901"), "{error:#}");

        let error = compile_body_matcher(Some(&serde_json::json!({"value": "gpt-4o"})))
            .err()
            .expect("a body matcher without a pointer must not compile");
        assert!(
            format!("{error:#}").contains("missing 'pointer'"),
            "{error:#}"
        );
    }

    #[test]
    fn a_full_forward_rule_carries_its_body_matcher_through_compilation() {
        let rule = serde_json::json!({
            "rules": [{
                "path": {"prefix": "/v1/chat"},
                "body": {"pointer": "/model", "prefix": "gpt-"},
            }],
            "origin": {
                "action": {"type": "proxy", "url": "https://openai.test"}
            }
        });
        let registry = empty_extension_registry();
        let compiled_rule = compile_single_forward_rule(
            &rule,
            "openai-lane",
            PipelineConstructionMode::Validation,
            registry.as_ref(),
        )
        .expect("the forward rule compiles");
        assert_eq!(
            forward_rule_body_cap(std::slice::from_ref(&compiled_rule)),
            Some(usize::try_from(sbproxy_config::BODY_MATCH_MAX_BYTES).expect("cap fits"))
        );
        let headers = http::HeaderMap::new();
        assert!(compiled_rule.matchers[0]
            .match_request_with_body(
                &http::Method::POST,
                "/v1/chat/completions",
                None,
                &headers,
                Some(CHAT_BODY),
                None,
            )
            .is_some());
    }
}

/// Request-method route matching.
#[cfg(test)]
mod method_matcher_tests {
    use super::*;

    fn compiled(json: serde_json::Value) -> MethodMatch {
        compile_method_matcher(Some(&json))
            .expect("method matcher compiles")
            .expect("method matcher is present")
    }

    fn method_only_entry(json: serde_json::Value) -> MatcherEntry {
        MatcherEntry {
            method: Some(compiled(json)),
            path: None,
            header: None,
            query: None,
            body: None,
            when: None,
        }
    }

    #[test]
    fn a_single_method_matches_only_itself() {
        let matcher = compiled(serde_json::json!("POST"));
        assert!(matcher.matches(&http::Method::POST));
        assert!(!matcher.matches(&http::Method::GET));
    }

    #[test]
    fn a_list_matches_any_of_its_methods() {
        let matcher = compiled(serde_json::json!(["GET", "HEAD"]));
        assert!(matcher.matches(&http::Method::GET));
        assert!(matcher.matches(&http::Method::HEAD));
        assert!(!matcher.matches(&http::Method::DELETE));
    }

    #[test]
    fn authored_case_is_normalized_to_uppercase() {
        let matcher = compiled(serde_json::json!(["post", "Delete"]));
        assert!(matcher.matches(&http::Method::POST));
        assert!(matcher.matches(&http::Method::DELETE));
        assert!(!matcher.matches(&http::Method::GET));
    }

    #[test]
    fn an_extension_method_is_accepted_and_uppercased() {
        // PURGE has no `http::Method` constant but is a valid method token,
        // which is exactly the charset `Method::from_bytes` accepts.
        let matcher = compiled(serde_json::json!("purge"));
        let purge = http::Method::from_bytes(b"PURGE").expect("valid token");
        assert!(matcher.matches(&purge));
    }

    // `.err().expect(..)` rather than `.expect_err(..)` here for the same
    // reason the body-matcher group above does it: `MethodMatch` withholds
    // `Debug`, and `expect_err` requires `Debug` on the `Ok` type. The test
    // bends, not the production type (WOR-2193).
    #[test]
    fn an_empty_list_is_refused_at_config_load() {
        let error = compile_method_matcher(Some(&serde_json::json!([])))
            .err()
            .expect("an empty method list can never match and must not compile");
        assert!(format!("{error:#}").contains("never match"), "{error:#}");
    }

    #[test]
    fn an_invalid_token_is_refused_at_config_load() {
        let error = compile_method_matcher(Some(&serde_json::json!("GET POST")))
            .err()
            .expect("a token with a space is not an HTTP method");
        assert!(format!("{error:#}").contains("invalid method"), "{error:#}");
    }

    #[test]
    fn a_non_string_shape_is_refused_at_config_load() {
        assert!(compile_method_matcher(Some(&serde_json::json!(7))).is_err());
        assert!(compile_method_matcher(Some(&serde_json::json!([7]))).is_err());
    }

    #[test]
    fn a_method_only_entry_fires_on_its_method_alone() {
        let entry = method_only_entry(serde_json::json!(["DELETE"]));
        let headers = http::HeaderMap::new();
        assert!(entry
            .match_request(&http::Method::DELETE, "/anything", None, &headers)
            .is_some());
        assert!(entry
            .match_request(&http::Method::GET, "/anything", None, &headers)
            .is_none());
    }

    #[test]
    fn the_method_matcher_ands_with_the_path_matcher() {
        let entry = MatcherEntry {
            method: Some(compiled(serde_json::json!("POST"))),
            path: Some(PathMatch::Prefix("/api/".to_string())),
            header: None,
            query: None,
            body: None,
            when: None,
        };
        let headers = http::HeaderMap::new();
        // Both must hold.
        assert!(entry
            .match_request(&http::Method::POST, "/api/x", None, &headers)
            .is_some());
        // Path agrees, method does not.
        assert!(entry
            .match_request(&http::Method::GET, "/api/x", None, &headers)
            .is_none());
        // Method agrees, path does not.
        assert!(entry
            .match_request(&http::Method::POST, "/web/x", None, &headers)
            .is_none());
    }

    #[test]
    fn a_when_predicate_survives_config_compilation() {
        // The seam the unit tests above cannot reach. They build
        // `MatcherEntry` literals, so a typo in the `when` key name would
        // leave every predicate compiled to `None` and every entry
        // matching on its structured half alone. That direction fails
        // *open*, which is the whole thing this feature exists to stop.
        let rule = serde_json::json!({
            "rules": [{
                "path": {"prefix": "/v1/"},
                "when": "request.path.endsWith(\"/chat\")",
            }],
            "origin": {
                "action": {"type": "proxy", "url": "https://api.test"}
            }
        });
        let registry = empty_extension_registry();
        let compiled_rule = compile_single_forward_rule(
            &rule,
            "chat-lane",
            PipelineConstructionMode::Validation,
            registry.as_ref(),
        )
        .expect("the forward rule compiles");
        assert!(
            compiled_rule.matchers[0].when.is_some(),
            "the predicate must survive compilation; if this is None the entry \
             silently matches on its path prefix alone"
        );

        let headers = http::HeaderMap::new();
        let ctx = sbproxy_extension::cel::context::build_request_context(
            "GET",
            "/v1/models",
            &headers,
            None,
            None,
            "api.test",
        );
        assert!(
            compiled_rule.matchers[0]
                .match_request_with_body(
                    &http::Method::GET,
                    "/v1/models",
                    None,
                    &headers,
                    None,
                    Some(&ctx),
                )
                .is_none(),
            "the prefix matches but the predicate does not, so the entry must not fire"
        );
    }

    #[test]
    fn a_when_naming_an_unavailable_binding_fails_config_load() {
        // `trust_tier` is stamped long after routing. Refusing here is
        // what keeps it from being an expression that reads empty on
        // every request.
        let rule = serde_json::json!({
            "rules": [{"when": "request.trust_tier == \"named\""}],
            "origin": {"action": {"type": "proxy", "url": "https://api.test"}}
        });
        let registry = empty_extension_registry();
        // `CompiledForwardRule` has no `Debug`, so unwrap the error side
        // by hand rather than through `expect_err`.
        let Err(error) = compile_single_forward_rule(
            &rule,
            "gated-lane",
            PipelineConstructionMode::Validation,
            registry.as_ref(),
        ) else {
            panic!("a binding routing cannot supply must not load");
        };
        let message = format!("{error:#}");
        assert!(message.contains("request.trust_tier"), "{message}");
    }

    fn preview_rule(spec: serde_json::Value) -> CompiledForwardRule {
        let registry = empty_extension_registry();
        compile_single_forward_rule(
            &spec,
            "preview-lane",
            PipelineConstructionMode::Validation,
            registry.as_ref(),
        )
        .expect("compiles")
    }

    #[test]
    fn a_reachable_predicate_makes_the_preview_indeterminate() {
        // Guards the fallback that would otherwise revalidate against
        // the wrong upstream.
        let rules = [preview_rule(serde_json::json!({
            "rules": [{"path": {"prefix": "/v1/"}, "when": "true"}],
            "origin": {"action": {"type": "proxy", "url": "https://api.test"}}
        }))];
        let headers = http::HeaderMap::new();
        assert!(matches!(
            preview_forward_rules(&rules, &http::Method::GET, "/v1/chat", None, &headers),
            ForwardRulePreview::Indeterminate
        ));
    }

    #[test]
    fn a_predicate_behind_a_failing_path_does_not_poison_the_preview() {
        // The evaluable half of the entry already failed, so the
        // predicate can never fire and the walk keeps going.
        let rules = [
            preview_rule(serde_json::json!({
                "rules": [{"path": {"prefix": "/admin/"}, "when": "true"}],
                "origin": {"action": {"type": "proxy", "url": "https://admin.test"}}
            })),
            preview_rule(serde_json::json!({
                "rules": [{"path": {"prefix": "/api/"}}],
                "origin": {"action": {"type": "proxy", "url": "https://api.test"}}
            })),
        ];
        let headers = http::HeaderMap::new();
        assert!(matches!(
            preview_forward_rules(&rules, &http::Method::GET, "/api/items", None, &headers),
            ForwardRulePreview::Matched(rule) if std::ptr::eq(rule, &rules[1])
        ));
    }

    #[test]
    fn an_earlier_reachable_predicate_shadows_a_later_clean_match() {
        // WOR-2409. First match wins at full evaluation, so a later
        // rule that previews clean is not the winner when an earlier
        // rule's predicate might fire. Answering with the later rule is
        // how the idempotency middleware serves cached bytes ahead of
        // the AI guardrails the request actually lands on.
        let rules = [
            preview_rule(serde_json::json!({
                "rules": [{"when": "request.path.startsWith(\"/api/\")"}],
                "origin": {"action": {"type": "proxy", "url": "https://gated.test"}}
            })),
            preview_rule(serde_json::json!({
                "rules": [{"path": {"prefix": "/api/"}}],
                "origin": {"action": {"type": "proxy", "url": "https://plain.test"}}
            })),
        ];
        let headers = http::HeaderMap::new();
        assert!(matches!(
            preview_forward_rules(&rules, &http::Method::GET, "/api/items", None, &headers),
            ForwardRulePreview::Indeterminate
        ));
    }

    #[test]
    fn a_rule_set_with_no_match_previews_as_no_match() {
        let rules = [preview_rule(serde_json::json!({
            "rules": [{"path": {"prefix": "/v1/"}}],
            "origin": {"action": {"type": "proxy", "url": "https://api.test"}}
        }))];
        let headers = http::HeaderMap::new();
        assert!(matches!(
            preview_forward_rules(&rules, &http::Method::GET, "/other", None, &headers),
            ForwardRulePreview::NoMatch
        ));
    }

    #[test]
    fn a_full_forward_rule_carries_its_method_matcher_through_compilation() {
        let rule = serde_json::json!({
            "rules": [{
                "path": {"prefix": "/v1/"},
                "method": ["post"],
            }],
            "origin": {
                "action": {"type": "proxy", "url": "https://api.test"}
            }
        });
        let registry = empty_extension_registry();
        let compiled_rule = compile_single_forward_rule(
            &rule,
            "writes-lane",
            PipelineConstructionMode::Validation,
            registry.as_ref(),
        )
        .expect("the forward rule compiles");
        let headers = http::HeaderMap::new();
        // The authored lowercase `post` matches the uppercase wire method.
        assert!(compiled_rule.matchers[0]
            .match_request(&http::Method::POST, "/v1/items", None, &headers)
            .is_some());
        // A method the rule does not list falls through to the origin's
        // own action.
        assert!(compiled_rule.matchers[0]
            .match_request(&http::Method::GET, "/v1/items", None, &headers)
            .is_none());
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    /// Load the case-09 forward-rules fixture relative to the crate root.
    ///
    /// The `e2e/` directory lives alongside this crate and is populated
    /// out-of-band (historically via a symlink to the Go repo's fixtures).
    /// If the fixture is not present we skip the test rather than panic so
    /// CI environments without the fixtures still pass.
    #[test]
    fn load_case09_forward_rules() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../e2e/cases/09-forwarding-rules/sb.yml");
        let Ok(yaml) = std::fs::read_to_string(&fixture) else {
            eprintln!(
                "skipping load_case09_forward_rules: fixture missing at {}",
                fixture.display()
            );
            return;
        };
        let config = sbproxy_config::compile_config(&yaml).unwrap();
        let origin = config.resolve_origin("routing.test").unwrap();
        assert!(
            !origin.forward_rules.is_empty(),
            "forward_rules should not be empty"
        );
        assert_eq!(origin.forward_rules.len(), 3, "should have 3 forward rules");

        let pipeline = CompiledPipeline::from_config(config).unwrap();
        assert!(!pipeline.forward_rules.is_empty());
        let fwd = &pipeline.forward_rules[0];
        assert_eq!(fwd.len(), 3, "compiled should have 3 forward rules");

        // Check first rule has request modifier
        assert!(
            !fwd[0].request_modifiers.is_empty(),
            "first rule should have modifiers"
        );
        let modifier = &fwd[0].request_modifiers[0];
        assert!(modifier.headers.is_some(), "modifier should have headers");
        let headers = modifier.headers.as_ref().unwrap();
        assert_eq!(
            headers.set.get("X-Routed-To").map(|s| s.as_str()),
            Some("api-backend")
        );
    }

    // --- Wave 5 day-6 Item 3: TlsFingerprintConfig roundtrip tests ---

    #[test]
    fn tls_fingerprint_config_default_is_disabled() {
        let cfg = TlsFingerprintConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.mode, TlsFingerprintMode::Sidecar);
        assert!(cfg.sidecar_header_allowlist.is_empty());
    }

    #[test]
    fn tls_fingerprint_config_round_trips_from_extensions_block() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
  extensions:
    tls_fingerprint:
      enabled: true
      mode: sidecar
      sidecar_header_allowlist:
        - x-forwarded-ja3
        - x-forwarded-ja4
      trustworthy_client_cidrs:
        - 127.0.0.0/8
      untrusted_client_cidrs:
        - 173.245.48.0/20
origins: {}
"#;
        let cfg = sbproxy_config::compile_config(yaml).expect("compile");
        let tls =
            TlsFingerprintConfig::from_extensions(&cfg.server.extensions).expect("well-formed");
        assert!(tls.enabled);
        assert_eq!(tls.mode, TlsFingerprintMode::Sidecar);
        assert_eq!(tls.sidecar_header_allowlist.len(), 2);
        assert!(tls.header_allowed("x-forwarded-ja3"));
        assert!(tls.header_allowed("X-Forwarded-JA4"));
        assert!(!tls.header_allowed("x-evil"));
        // Canonical headers always allowed.
        assert!(tls.header_allowed("x-sbproxy-tls-ja3"));
        assert!(tls.header_allowed("X-SBProxy-TLS-Trustworthy"));
        let trustworthy_cidrs = tls.trustworthy_cidrs();
        assert_eq!(trustworthy_cidrs.len(), 1);
        let untrusted_cidrs = tls.untrusted_cidrs();
        assert_eq!(untrusted_cidrs.len(), 1);
    }

    // --- WOR-1699: trust classification on the fingerprint fast path ---
    //
    // These pin the behavior the request entry hook used to spell out
    // inline. The consolidation onto `resolve_trustworthy` is only safe
    // if the answers are unchanged, and the default in particular had
    // nothing holding it in place: the one written-down default in the
    // workspace lived on a dead `sbproxy-tls` helper that said `false`,
    // the opposite of what ships.

    fn tls_cfg_with(trustworthy: &[&str], untrusted: &[&str]) -> TlsFingerprintConfig {
        let mut cfg = TlsFingerprintConfig {
            enabled: true,
            trustworthy_client_cidrs: trustworthy.iter().map(|s| s.to_string()).collect(),
            untrusted_client_cidrs: untrusted.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        cfg.compile_cidrs().expect("test CIDRs parse");
        cfg
    }

    #[test]
    fn trustworthy_defaults_to_true_without_an_override() {
        // The capture path is only reachable from a peer already in
        // `proxy.trusted_proxies`, so an unqualified capture is taken at
        // face value. Flipping this to `false` would silently drop every
        // deployment that has a sidecar but no CIDR lists out of the
        // trustworthy tier.
        let cfg = tls_cfg_with(&[], &[]);
        assert!(cfg.resolve_trustworthy(None, None), "no ip, no override");
        assert!(
            cfg.resolve_trustworthy(None, Some("203.0.113.10".parse().unwrap())),
            "an ip that matches no rule does not lower the default"
        );
        // The default is exactly that, a default: the sidecar still wins.
        assert!(!cfg.resolve_trustworthy(Some(false), None));
        assert!(!cfg.resolve_trustworthy(Some(false), Some("203.0.113.10".parse().unwrap())));
        assert!(cfg.resolve_trustworthy(Some(true), None));

        // Same answer for the disabled default value of the type, which
        // is what a config with no `tls_fingerprint` block produces.
        assert!(TlsFingerprintConfig::default().resolve_trustworthy(None, None));
    }

    #[test]
    fn untrusted_cidr_overrides_a_sidecar_trustworthy_header() {
        // CDN egress and corporate MITM pools are named here, and the
        // sidecar sitting inside one of them cannot vouch for itself.
        let cfg = tls_cfg_with(&["203.0.113.0/24"], &["203.0.113.10/32"]);
        assert!(!cfg.resolve_trustworthy(Some(true), Some("203.0.113.10".parse().unwrap())));
        // Membership in untrusted beats membership in trustworthy.
        assert!(cfg.resolve_trustworthy(None, Some("203.0.113.11".parse().unwrap())));
    }

    #[test]
    fn a_configured_trust_list_decides_on_its_own() {
        // A non-empty trustworthy list is the operator stating which
        // ranges are direct clients, so a miss is a `false` even when
        // the sidecar asserted `true`. An empty list is not that
        // statement and leaves the default standing (asserted above).
        let cfg = tls_cfg_with(&["203.0.113.0/24"], &[]);
        assert!(cfg.resolve_trustworthy(None, Some("203.0.113.10".parse().unwrap())));
        assert!(!cfg.resolve_trustworthy(Some(true), Some("198.51.100.10".parse().unwrap())));
        // A match promotes a sidecar `false`, which is what the inline
        // code did before the consolidation.
        assert!(cfg.resolve_trustworthy(Some(false), Some("203.0.113.10".parse().unwrap())));
    }

    #[test]
    fn ipv6_client_ips_classify_against_ipv6_cidrs() {
        let cfg = tls_cfg_with(&["2001:db8::/32"], &[]);
        assert!(cfg.resolve_trustworthy(None, Some("2001:db8::1".parse().unwrap())));
        assert!(!cfg.resolve_trustworthy(None, Some("2001:dba::1".parse().unwrap())));
    }

    #[test]
    fn invalid_cidr_entries_fail_the_config_compile() {
        // These lists used to warn-and-drop an unparseable entry, which
        // silently narrowed a deny list (`untrusted_client_cidrs`) on a
        // typo. Fail closed: the config is refused, and the error names
        // the field and the offending entry so the operator can fix it.
        let yaml = r#"
proxy:
  http_bind_port: 8080
  extensions:
    tls_fingerprint:
      enabled: true
      untrusted_client_cidrs:
        - bogus
        - 10.0.0.0/8
origins: {}
"#;
        let compiled = sbproxy_config::compile_config(yaml).expect("compile");
        let err = TlsFingerprintConfig::from_extensions(&compiled.server.extensions)
            .expect_err("an unparseable CIDR entry must reject the config");
        let msg = err.to_string();
        assert!(
            msg.contains("untrusted_client_cidrs"),
            "names the field: {msg}"
        );
        assert!(msg.contains("bogus"), "names the entry: {msg}");
        assert!(msg.contains("invalid CIDR"), "names the problem: {msg}");
    }

    #[test]
    fn fingerprint_cidrs_parse_at_config_load_and_never_per_request() {
        // The whole point of the compiled fields: a config generation
        // pays one parse per list, and the request path pays none. If a
        // future refactor moves a `parse::<IpNetwork>()` back onto the
        // classification path, this fails.
        let yaml = r#"
proxy:
  http_bind_port: 8080
  extensions:
    tls_fingerprint:
      enabled: true
      trustworthy_client_cidrs:
        - 203.0.113.0/24
      untrusted_client_cidrs:
        - 198.51.100.0/24
origins: {}
"#;
        let before = cidr_parse_count_on_this_thread();
        let compiled = sbproxy_config::compile_config(yaml).expect("compile");
        let tls = TlsFingerprintConfig::from_extensions(&compiled.server.extensions)
            .expect("well-formed");
        let after = cidr_parse_count_on_this_thread();
        assert_eq!(after - before, 2, "one parse per configured list, at load");

        let direct: std::net::IpAddr = "203.0.113.10".parse().unwrap();
        let cdn: std::net::IpAddr = "198.51.100.10".parse().unwrap();
        for _ in 0..100 {
            assert!(tls.resolve_trustworthy(None, Some(direct)));
            assert!(!tls.resolve_trustworthy(Some(true), Some(cdn)));
        }
        assert_eq!(
            cidr_parse_count_on_this_thread(),
            after,
            "no parse per classification"
        );

        // Cloning the config into a new pipeline generation does not
        // re-parse either; the compiled sets come along.
        let cloned = tls.clone();
        assert!(cloned.resolve_trustworthy(None, Some(direct)));
        assert_eq!(
            cidr_parse_count_on_this_thread(),
            after,
            "no parse on clone"
        );
    }

    // --- WOR-706: AgentDetectConfig roundtrip tests ---

    #[test]
    fn agent_detect_config_default_is_disabled() {
        let cfg = AgentDetectConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.rule_pack_path.is_none());
        assert!(cfg.onnx_model_path.is_none());
    }

    #[test]
    fn agent_detect_config_absent_block_is_disabled() {
        // No proxy.extensions.agent_detect at all: disabled default.
        let yaml = "proxy:\n  http_bind_port: 8080\norigins: {}\n";
        let cfg = sbproxy_config::compile_config(yaml).expect("compile");
        let ad =
            AgentDetectConfig::from_extensions(&cfg.server.extensions).expect("absent block is ok");
        assert!(!ad.enabled);
        assert!(ad.rule_pack_path.is_none());
        assert!(ad.onnx_model_path.is_none());
    }

    #[test]
    fn agent_detect_config_round_trips_from_extensions_block() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
  extensions:
    agent_detect:
      enabled: true
      rule_pack_path: /etc/sbproxy/agents.yml
      onnx_model_path: /etc/sbproxy/ja4-catboost.onnx
origins: {}
"#;
        let cfg = sbproxy_config::compile_config(yaml).expect("compile");
        let ad = AgentDetectConfig::from_extensions(&cfg.server.extensions)
            .expect("well-formed block parses");
        assert!(ad.enabled);
        assert_eq!(
            ad.rule_pack_path.as_deref(),
            Some("/etc/sbproxy/agents.yml")
        );
        assert_eq!(
            ad.onnx_model_path.as_deref(),
            Some("/etc/sbproxy/ja4-catboost.onnx")
        );
    }

    /// WOR-2181. A typo in an `enabled: true` block refuses the
    /// config. Two things had to change together for this: the struct
    /// denies unknown fields, and `from_extensions` hard-fails instead
    /// of warning. Before either, `rule_pack_paths:` was dropped and
    /// the scorer ran against an empty pack, scoring every request as
    /// unsigned-anonymous while the config named a rule pack.
    #[test]
    fn agent_detect_unknown_key_refuses_an_enabled_block() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
  extensions:
    agent_detect:
      enabled: true
      rule_pack_paths: /etc/sbproxy/agents.yml
origins: {}
"#;
        let cfg = sbproxy_config::compile_config(yaml).expect("the envelope still compiles");
        let err = AgentDetectConfig::from_extensions(&cfg.server.extensions)
            .expect_err("an enabled block with a typo must not resolve to the disabled default");
        let text = format!("{err:#}");
        assert!(
            text.contains("rule_pack_paths"),
            "the error must name the key the operator typed: {text}"
        );
        assert!(
            text.contains("agent_detect"),
            "the error must name the block: {text}"
        );
    }

    /// The other side of the same switch: a block that does not ask
    /// for the scorer keeps the warn-and-disable path, because
    /// disabled is the outcome it asked for.
    #[test]
    fn agent_detect_unknown_key_on_a_disabled_block_still_warns_and_disables() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
  extensions:
    agent_detect:
      enabled: false
      rule_pack_paths: /etc/sbproxy/agents.yml
origins: {}
"#;
        let cfg = sbproxy_config::compile_config(yaml).expect("the envelope still compiles");
        let ad = AgentDetectConfig::from_extensions(&cfg.server.extensions)
            .expect("a block that asks for nothing must not refuse the config");
        assert!(!ad.enabled);
    }

    /// A correctly spelled enabled block still reaches the scorer
    /// through the whole pipeline compile, not just the parser. A deny
    /// that refused working configs would be the worse bug.
    #[test]
    fn agent_detect_enabled_block_survives_the_pipeline_compile() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
  extensions:
    agent_detect:
      enabled: true
      rule_pack_path: /etc/sbproxy/agents.yml
origins: {}
"#;
        let cfg = sbproxy_config::compile_config(yaml).expect("compile");
        let pipeline =
            CompiledPipeline::from_config_for_validation(cfg).expect("pipeline compiles");
        assert!(pipeline.agent_detect_config.enabled);
        assert_eq!(
            pipeline.agent_detect_config.rule_pack_path.as_deref(),
            Some("/etc/sbproxy/agents.yml")
        );
    }

    /// The refusal reaches the pipeline compile, which is the call
    /// site an operator's `serve`, `validate`, and hot reload all go
    /// through.
    #[test]
    fn agent_detect_typo_refuses_the_pipeline_compile() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
  extensions:
    agent_detect:
      enabled: true
      rule_pack_paths: /etc/sbproxy/agents.yml
origins: {}
"#;
        let cfg = sbproxy_config::compile_config(yaml).expect("the envelope still compiles");
        // CompiledPipeline has no Debug, so Option::expect replaces expect_err.
        let err = CompiledPipeline::from_config_for_validation(cfg)
            .err()
            .expect("the pipeline compile must carry the refusal, not just the parser");
        let text = format!("{err:#}");
        assert!(
            text.contains("rule_pack_paths"),
            "the error must name the key: {text}"
        );
    }

    #[test]
    fn tls_fingerprint_config_lifts_legacy_features_block() {
        // Day-6 Item 2 + Item 3 together: a legacy
        // features.tls_fingerprint block is migrated and the typed
        // config picks it up.
        let yaml = r#"
proxy:
  http_bind_port: 8080
features:
  tls_fingerprint:
    enabled: true
    sidecar_header_allowlist:
      - x-forwarded-ja4
origins: {}
"#;
        let cfg = sbproxy_config::compile_config(yaml).expect("compile");
        let tls =
            TlsFingerprintConfig::from_extensions(&cfg.server.extensions).expect("well-formed");
        assert!(tls.enabled);
        assert!(tls.header_allowed("x-forwarded-ja4"));
    }

    #[test]
    fn tls_fingerprint_config_threads_onto_compiled_pipeline() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
  extensions:
    tls_fingerprint:
      enabled: true
      mode: passive
origins: {}
"#;
        let cfg = sbproxy_config::compile_config(yaml).expect("compile");
        let pipeline = CompiledPipeline::from_config(cfg).expect("compile pipeline");
        assert!(pipeline.tls_fingerprint_config.enabled);
        assert_eq!(
            pipeline.tls_fingerprint_config.mode,
            TlsFingerprintMode::Passive,
        );
    }

    #[test]
    fn tls_fingerprint_config_disabled_mode_blocks_capture() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
  extensions:
    tls_fingerprint:
      enabled: true
      mode: disabled
origins: {}
"#;
        let cfg = sbproxy_config::compile_config(yaml).expect("compile");
        let pipeline = CompiledPipeline::from_config(cfg).expect("compile pipeline");
        assert_eq!(
            pipeline.tls_fingerprint_config.mode,
            TlsFingerprintMode::Disabled,
        );
    }

    #[test]
    fn tls_fingerprint_config_invalid_block_falls_through_to_default() {
        // A malformed block that does not declare `enabled: true`
        // keeps the warn-and-disable path (WOR-1161 only hard-fails
        // when the operator asked for capture).
        let yaml = r#"
proxy:
  http_bind_port: 8080
  extensions:
    tls_fingerprint:
      enabled: not-a-bool
origins: {}
"#;
        let cfg = sbproxy_config::compile_config(yaml).expect("compile");
        let tls = TlsFingerprintConfig::from_extensions(&cfg.server.extensions)
            .expect("no enabled:true, so the block degrades to disabled");
        // Default => disabled (safe).
        assert!(!tls.enabled);
    }

    #[test]
    fn tls_fingerprint_malformed_block_with_enabled_true_fails_compile() {
        // WOR-1161: `enabled: true` plus a parse failure must reject
        // the config instead of silently disabling capture. The typo'd
        // field also exercises `deny_unknown_fields`.
        let yaml = r#"
proxy:
  http_bind_port: 8080
  extensions:
    tls_fingerprint:
      enabled: true
      sidecar_headers_allowlist:
        - x-forwarded-ja4
origins: {}
"#;
        let cfg = sbproxy_config::compile_config(yaml).expect("compile_config only parses YAML");
        let err = TlsFingerprintConfig::from_extensions(&cfg.server.extensions)
            .expect_err("enabled:true with a malformed block must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("sidecar_headers_allowlist"),
            "error must name the malformed field: {msg}"
        );
        assert!(
            msg.contains("tls_fingerprint"),
            "error must name the block: {msg}"
        );

        // And the failure propagates: the pipeline (boot and reload both
        // construct through here) refuses the config outright.
        let cfg = sbproxy_config::compile_config(yaml).expect("compile_config only parses YAML");
        assert!(
            CompiledPipeline::from_config(cfg).is_err(),
            "pipeline construction must reject the malformed enabled:true block"
        );
    }

    #[test]
    fn tls_fingerprint_unknown_field_with_enabled_true_fails_compile() {
        // A well-formed block with an extra unknown key is a parse
        // error under deny_unknown_fields; with enabled:true it must
        // reject the config.
        let yaml = r#"
proxy:
  http_bind_port: 8080
  extensions:
    tls_fingerprint:
      enabled: true
      mode: sidecar
      not_a_real_field: 1
origins: {}
"#;
        let cfg = sbproxy_config::compile_config(yaml).expect("compile_config only parses YAML");
        let err = TlsFingerprintConfig::from_extensions(&cfg.server.extensions)
            .expect_err("unknown field with enabled:true must fail");
        assert!(
            err.to_string().contains("not_a_real_field"),
            "error must name the unknown field: {err}"
        );
    }

    // --- WOR-2162: expression policies reject invalid CEL at compile ---

    #[test]
    fn expression_policy_with_invalid_cel_rejects_the_config() {
        // The old behavior accepted this config and then ADMITTED every
        // request when the per-request CEL compile failed. Pipeline
        // construction (the shared path under boot and reload) must
        // refuse it with a diagnostic naming the origin, the policy,
        // and the bad expression.
        let yaml = r#"
proxy:
  http_bind_port: 8080
origins:
  "cel.local":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: expression
        expression: 'this is not valid CEL !!!'
"#;
        let cfg = sbproxy_config::compile_config(yaml).expect("yaml parses");
        // CompiledPipeline has no Debug, so Option::expect replaces expect_err.
        let err = CompiledPipeline::from_config(cfg)
            .err()
            .expect("invalid CEL must reject the candidate config");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("cel.local"),
            "diagnostic must name the origin: {msg}"
        );
        assert!(
            msg.contains("expression"),
            "diagnostic must name the policy type: {msg}"
        );
        assert!(
            msg.contains("this is not valid CEL !!!"),
            "diagnostic must quote the bad expression: {msg}"
        );
    }

    #[test]
    fn expression_policy_with_valid_cel_still_compiles() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
origins:
  "cel.local":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: expression
        expression: 'request.method == "GET"'
"#;
        let cfg = sbproxy_config::compile_config(yaml).expect("yaml parses");
        CompiledPipeline::from_config(cfg).expect("valid CEL must keep compiling");
    }

    // --- WOR-2179 / WOR-2164: the other static-CEL config surfaces ---

    /// Build a pipeline from `yaml` and return the rejection message.
    /// `CompiledPipeline` has no `Debug`, so `Result::expect_err` cannot
    /// be used here.
    fn pipeline_rejection(yaml: &str) -> String {
        let cfg = sbproxy_config::compile_config(yaml).expect("yaml parses");
        let err = CompiledPipeline::from_config(cfg)
            .err()
            .expect("invalid CEL must reject the candidate config");
        format!("{err:#}")
    }

    #[test]
    fn assertion_policy_with_invalid_cel_rejects_the_config() {
        // The old behavior accepted this config, then failed the
        // per-response compile and recorded a pass, so the assertion
        // the operator wrote never ran.
        let msg = pipeline_rejection(
            r#"
proxy:
  http_bind_port: 8080
origins:
  "assert.local":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: assertion
        name: no-5xx
        expression: 'this is not valid CEL !!!'
"#,
        );
        assert!(
            msg.contains("assert.local"),
            "diagnostic must name the origin: {msg}"
        );
        assert!(
            msg.contains("assertion"),
            "diagnostic must name the policy: {msg}"
        );
        assert!(
            msg.contains("this is not valid CEL !!!"),
            "diagnostic must quote the expression: {msg}"
        );
    }

    #[test]
    fn cel_transform_with_invalid_expression_rejects_the_config() {
        let msg = pipeline_rejection(
            r#"
proxy:
  http_bind_port: 8080
origins:
  "transform.local":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    transforms:
      - type: cel
        headers:
          - { op: set, name: x-broken, value_expr: 'this is not valid CEL !!!' }
"#,
        );
        assert!(
            msg.contains("transform.local"),
            "diagnostic must name the origin: {msg}"
        );
        assert!(
            msg.contains("x-broken"),
            "diagnostic must name the header: {msg}"
        );
        assert!(
            msg.contains("this is not valid CEL !!!"),
            "diagnostic must quote the expression: {msg}"
        );
    }

    #[test]
    fn cel_transform_body_replacement_rejects_the_config_naming_the_origin() {
        // WOR-2362: refusing the key is only useful if the operator can
        // find which origin carries it.
        for key in ["on_response", "expression"] {
            let msg = pipeline_rejection(&format!(
                r#"
proxy:
  http_bind_port: 8080
origins:
  "transform.local":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    transforms:
      - type: cel
        {key}: '"rewritten"'
"#
            ));
            assert!(
                msg.contains("transform.local"),
                "diagnostic must name the origin: {msg}"
            );
            assert!(msg.contains(key), "diagnostic must name the key: {msg}");
        }
    }

    #[test]
    fn cel_transform_header_rule_with_invalid_expression_rejects_the_config() {
        let msg = pipeline_rejection(
            r#"
proxy:
  http_bind_port: 8080
origins:
  "header.local":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    transforms:
      - type: cel
        headers:
          - op: set
            name: x-tenant
            value_expr: 'this is not valid CEL !!!'
"#,
        );
        assert!(
            msg.contains("header.local"),
            "diagnostic must name the origin: {msg}"
        );
        assert!(
            msg.contains("x-tenant"),
            "diagnostic must name the header: {msg}"
        );
    }

    #[test]
    fn rate_limit_key_with_invalid_cel_rejects_the_config() {
        // The old behavior accepted this and then dropped every
        // request into the default bucket, silently.
        let msg = pipeline_rejection(
            r#"
proxy:
  http_bind_port: 8080
origins:
  "ratelimit.local":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: rate_limiting
        requests_per_second: 10
        key: 'this is not valid CEL !!!'
"#,
        );
        assert!(
            msg.contains("ratelimit.local"),
            "diagnostic must name the origin: {msg}"
        );
        assert!(
            msg.contains("rate_limiting"),
            "diagnostic must name the policy: {msg}"
        );
        assert!(
            msg.contains("this is not valid CEL !!!"),
            "diagnostic must quote the expression: {msg}"
        );
    }

    #[test]
    fn custom_log_field_with_invalid_cel_rejects_the_config() {
        // The old behavior compiled this once per log record, failed
        // every time, and omitted the field.
        let msg = pipeline_rejection(
            r#"
proxy:
  http_bind_port: 8080
  observability:
    log:
      custom_fields:
        - name: caller_tier
          engine: cel
          source: 'this is not valid CEL !!!'
origins: {}
"#,
        );
        assert!(
            msg.contains("proxy"),
            "diagnostic must name the scope: {msg}"
        );
        assert!(
            msg.contains("caller_tier"),
            "diagnostic must name the field: {msg}"
        );
        assert!(
            msg.contains("this is not valid CEL !!!"),
            "diagnostic must quote the source: {msg}"
        );
    }

    #[test]
    fn origin_scoped_custom_log_field_with_invalid_cel_rejects_the_config() {
        let msg = pipeline_rejection(
            r#"
proxy:
  http_bind_port: 8080
origins:
  "log.local":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    observability:
      log:
        custom_fields:
          - name: route_tier
            engine: cel
            source: 'this is not valid CEL !!!'
"#,
        );
        assert!(
            msg.contains("log.local"),
            "diagnostic must name the origin: {msg}"
        );
        assert!(
            msg.contains("route_tier"),
            "diagnostic must name the field: {msg}"
        );
    }

    #[test]
    fn waf_persistent_block_key_with_invalid_cel_rejects_the_config() {
        // The WAF tracking key is the fifth static-CEL surface, and it
        // gets the same end-to-end proof as the other four rather than
        // only a crate-local unit test: the compile has to happen on
        // the path boot and reload actually take.
        let msg = pipeline_rejection(
            r#"
proxy:
  http_bind_port: 8080
origins:
  "waf.local":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: waf
        persistent_block:
          enabled: true
          track_by: cel
          key: 'this is not valid CEL !!!'
"#,
        );
        assert!(
            msg.contains("waf.local"),
            "diagnostic must name the origin: {msg}"
        );
        assert!(
            msg.contains("persistent_block") || msg.contains("waf"),
            "diagnostic must name the policy surface: {msg}"
        );
    }

    #[test]
    fn waf_persistent_block_cel_tracking_without_a_key_rejects_the_config() {
        // `track_by: cel` with no `key:` is the other way to write an
        // unusable tracking key, and it has to be refused on the same
        // path. Left unchecked it silently tracks nothing, which reads
        // as "no attacker ever tripped the threshold".
        let msg = pipeline_rejection(
            r#"
proxy:
  http_bind_port: 8080
origins:
  "wafkey.local":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: waf
        persistent_block:
          enabled: true
          track_by: cel
"#,
        );
        assert!(
            msg.contains("wafkey.local"),
            "diagnostic must name the origin: {msg}"
        );
        assert!(
            msg.contains("key"),
            "diagnostic must say a key is required: {msg}"
        );
    }

    #[test]
    fn the_static_cel_surfaces_all_keep_compiling_when_valid() {
        // One config exercising every surface this change touched, so
        // the rejection tests above cannot be satisfied by rejecting
        // everything.
        let yaml = r#"
proxy:
  http_bind_port: 8080
  observability:
    log:
      custom_fields:
        - name: caller_tier
          engine: cel
          source: '"x-tier" in request.headers ? request.headers["x-tier"] : "standard"'
origins:
  "all.local":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: assertion
        name: no-5xx
        expression: 'response.status < 500'
      - type: rate_limiting
        requests_per_second: 10
        key: 'request.key_id'
      - type: waf
        persistent_block:
          enabled: true
          track_by: cel
          key: 'request.key_id'
    transforms:
      - type: cel
        headers:
          - op: set
            name: x-status
            value_expr: 'string(response.status)'
"#;
        let cfg = sbproxy_config::compile_config(yaml).expect("yaml parses");
        let pipeline = CompiledPipeline::from_config(cfg).expect("valid CEL must keep compiling");
        let programs = pipeline.custom_log_programs.len();
        assert_eq!(programs, 1, "compiled once at publication");
    }

    // --- response cache store selection ---

    /// Stand-in for a Redis-backed store, so the selection tests can
    /// assert which backend was chosen without a live Redis.
    struct FakeRedisStore;

    impl sbproxy_cache::CacheStore for FakeRedisStore {
        fn get(&self, _key: &str) -> anyhow::Result<Option<sbproxy_cache::CachedResponse>> {
            Ok(None)
        }
        fn put(&self, _key: &str, _value: &sbproxy_cache::CachedResponse) -> anyhow::Result<()> {
            Ok(())
        }
        fn delete(&self, _key: &str) -> anyhow::Result<()> {
            Ok(())
        }
        fn clear(&self) -> anyhow::Result<()> {
            Ok(())
        }
        fn backend_name(&self) -> &'static str {
            "redis"
        }
    }

    fn fake_redis() -> Option<Arc<dyn CacheStore>> {
        Some(Arc::new(FakeRedisStore) as Arc<dyn CacheStore>)
    }

    #[test]
    fn no_store_block_with_l2_still_selects_redis() {
        // The compatibility promise: an operator who has only
        // proxy.l2_cache set keeps Redis after this change.
        let store = build_response_cache_store(
            None,
            fake_redis(),
            10_000,
            &[],
            PipelineConstructionMode::Runtime,
        )
        .expect("legacy selection should build");
        assert_eq!(store.unscoped.backend_name(), "redis");
    }

    #[test]
    fn no_store_block_without_l2_selects_memory() {
        let store =
            build_response_cache_store(None, None, 10_000, &[], PipelineConstructionMode::Runtime)
                .expect("legacy selection should build");
        assert_eq!(store.unscoped.backend_name(), "memory");
    }

    #[test]
    fn an_explicit_memory_backend_overrides_a_configured_l2() {
        // An explicit block means the operator chose; it must win over
        // the presence of an l2_cache connection.
        let cfg = sbproxy_config::ResponseCacheStoreConfig::default();
        let store = build_response_cache_store(
            Some(&cfg),
            fake_redis(),
            10_000,
            &[],
            PipelineConstructionMode::Runtime,
        )
        .expect("explicit memory should build");
        assert_eq!(store.unscoped.backend_name(), "memory");
    }

    #[test]
    fn a_file_backend_is_constructed_and_creates_its_directory() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("responses");
        let cfg = sbproxy_config::ResponseCacheStoreConfig {
            backend: sbproxy_config::ResponseCacheBackendConfig::File {
                path: path.to_string_lossy().into_owned(),
                max_size_mb: 0,
            },
            encryption: None,
        };
        let store = build_response_cache_store(
            Some(&cfg),
            None,
            10_000,
            &[],
            PipelineConstructionMode::Runtime,
        )
        .expect("file backend should build");
        assert_eq!(store.unscoped.backend_name(), "file");
        assert!(path.is_dir(), "the cache directory must be created");
    }

    #[test]
    fn a_file_backend_that_cannot_be_created_fails_the_build() {
        // A file created where the directory should be. create_dir_all
        // fails, and that must abort rather than silently downgrade to
        // memory.
        let dir = tempfile::TempDir::new().expect("temp dir");
        let blocker = dir.path().join("blocked");
        std::fs::write(&blocker, b"not a directory").expect("write blocker");
        let cfg = sbproxy_config::ResponseCacheStoreConfig {
            backend: sbproxy_config::ResponseCacheBackendConfig::File {
                path: blocker.to_string_lossy().into_owned(),
                max_size_mb: 0,
            },
            encryption: None,
        };
        assert!(build_response_cache_store(
            Some(&cfg),
            None,
            10_000,
            &[],
            PipelineConstructionMode::Runtime
        )
        .is_err());
    }

    #[test]
    fn a_memcached_backend_is_constructed_without_connecting() {
        // Construction must not dial the server; the store opens a
        // connection per operation, so a config load against a
        // temporarily-down memcached still boots.
        let cfg = sbproxy_config::ResponseCacheStoreConfig {
            backend: sbproxy_config::ResponseCacheBackendConfig::Memcached {
                host: "127.0.0.1".to_string(),
                port: 1,
            },
            encryption: None,
        };
        let store = build_response_cache_store(
            Some(&cfg),
            None,
            10_000,
            &[],
            PipelineConstructionMode::Runtime,
        )
        .expect("memcached backend should build without dialing");
        assert_eq!(store.unscoped.backend_name(), "memcached");
    }

    #[test]
    fn a_redis_backend_without_l2_cache_is_a_startup_error() {
        let cfg = sbproxy_config::ResponseCacheStoreConfig {
            backend: sbproxy_config::ResponseCacheBackendConfig::Redis,
            encryption: None,
        };
        let Err(err) = build_response_cache_store(
            Some(&cfg),
            None,
            10_000,
            &[],
            PipelineConstructionMode::Runtime,
        ) else {
            panic!("redis without l2_cache must fail loudly");
        };
        assert!(
            err.to_string().contains("proxy.l2_cache"),
            "the error must point at the missing block: {err}"
        );
    }

    #[test]
    fn encryption_enabled_without_a_key_is_a_startup_error() {
        // The core security requirement: never fall through to storing
        // plaintext because the key was left out.
        let cfg = sbproxy_config::ResponseCacheStoreConfig {
            backend: sbproxy_config::ResponseCacheBackendConfig::Memory,
            encryption: Some(sbproxy_config::ResponseCacheEncryptionConfig {
                enabled: true,
                key: None,
                previous_keys: Vec::new(),
                per_origin_keys: Default::default(),
            }),
        };
        let Err(err) = build_response_cache_store(
            Some(&cfg),
            None,
            10_000,
            &[],
            PipelineConstructionMode::Runtime,
        ) else {
            panic!("encryption without a key must fail loudly");
        };
        assert!(
            err.to_string().contains("no `key` is set"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn encryption_with_short_key_material_is_a_startup_error() {
        let cfg = sbproxy_config::ResponseCacheStoreConfig {
            backend: sbproxy_config::ResponseCacheBackendConfig::Memory,
            encryption: Some(sbproxy_config::ResponseCacheEncryptionConfig {
                enabled: true,
                key: Some("short".to_string()),
                previous_keys: Vec::new(),
                per_origin_keys: Default::default(),
            }),
        };
        assert!(build_response_cache_store(
            Some(&cfg),
            None,
            10_000,
            &[],
            PipelineConstructionMode::Runtime
        )
        .is_err());
    }

    #[test]
    fn an_unresolvable_secret_reference_is_never_used_as_key_material() {
        // The footgun this closes: with no secret backend installed, a
        // `secret://` reference must not become the literal key.
        let cfg = sbproxy_config::ResponseCacheStoreConfig {
            backend: sbproxy_config::ResponseCacheBackendConfig::Memory,
            encryption: Some(sbproxy_config::ResponseCacheEncryptionConfig {
                enabled: true,
                key: Some("secret://primary/response-cache-key".to_string()),
                previous_keys: Vec::new(),
                per_origin_keys: Default::default(),
            }),
        };
        let Err(err) = build_response_cache_store(
            Some(&cfg),
            None,
            10_000,
            &[],
            PipelineConstructionMode::Runtime,
        ) else {
            panic!("an unresolvable reference must not be used verbatim");
        };
        assert!(
            format!("{err:#}").contains("proxy.secrets.backends"),
            "the error must point at the missing backend: {err:#}"
        );
    }

    #[test]
    fn encryption_reads_key_material_from_a_file_reference() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let key_file = dir.path().join("cache.key");
        std::fs::write(&key_file, b"0123456789abcdef0123456789abcdef\n").expect("write key");

        let cfg = sbproxy_config::ResponseCacheStoreConfig {
            backend: sbproxy_config::ResponseCacheBackendConfig::Memory,
            encryption: Some(sbproxy_config::ResponseCacheEncryptionConfig {
                enabled: true,
                key: Some(format!("file:{}", key_file.display())),
                previous_keys: Vec::new(),
                per_origin_keys: Default::default(),
            }),
        };
        let store = build_response_cache_store(
            Some(&cfg),
            None,
            10_000,
            &[origin_keys("api.example", true, None)],
            PipelineConstructionMode::Runtime,
        )
        .expect("file-referenced key should build");

        // Still reports the wrapped backend, and actually encrypts.
        assert_eq!(store.unscoped.backend_name(), "memory");
        let scoped = &store.per_origin["api.example"];
        let entry = sbproxy_cache::CachedResponse {
            generation: 0,
            status: 200,
            headers: vec![],
            body: b"needle-in-the-haystack".to_vec(),
            cached_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            ttl_secs: 300,
            swr_secs: None,
            config_fp: String::new(),
        };
        scoped.put("k", &entry).unwrap();
        assert_eq!(scoped.get("k").unwrap().expect("hit").body, entry.body);
    }

    #[test]
    fn a_disabled_encryption_block_leaves_the_store_unwrapped() {
        let cfg = sbproxy_config::ResponseCacheStoreConfig {
            backend: sbproxy_config::ResponseCacheBackendConfig::Memory,
            encryption: Some(sbproxy_config::ResponseCacheEncryptionConfig {
                enabled: false,
                key: None,
                previous_keys: Vec::new(),
                per_origin_keys: Default::default(),
            }),
        };
        assert!(build_response_cache_store(
            Some(&cfg),
            None,
            10_000,
            &[],
            PipelineConstructionMode::Runtime
        )
        .is_ok());
    }

    #[test]
    fn validation_mode_skips_key_resolution_but_still_checks_shape() {
        // `sbproxy validate` must not read key files or dial secret
        // backends, but a redis backend with no l2_cache is a config
        // error it can and should report.
        let encrypted = sbproxy_config::ResponseCacheStoreConfig {
            backend: sbproxy_config::ResponseCacheBackendConfig::Memory,
            encryption: Some(sbproxy_config::ResponseCacheEncryptionConfig {
                enabled: true,
                key: Some("file:/definitely/not/here.key".to_string()),
                previous_keys: Vec::new(),
                per_origin_keys: Default::default(),
            }),
        };
        assert!(build_response_cache_store(
            Some(&encrypted),
            None,
            10_000,
            &[],
            PipelineConstructionMode::Validation,
        )
        .is_ok());

        let bad_redis = sbproxy_config::ResponseCacheStoreConfig {
            backend: sbproxy_config::ResponseCacheBackendConfig::Redis,
            encryption: None,
        };
        assert!(build_response_cache_store(
            Some(&bad_redis),
            None,
            10_000,
            &[],
            PipelineConstructionMode::Validation,
        )
        .is_err());
    }

    // --- Per-origin cache encryption keys ---

    /// A store config with encryption on, sealed under `key`, in the
    /// given per-origin mode.
    fn encrypted_store(
        key: Option<&str>,
        mode: sbproxy_config::PerOriginKeyMode,
    ) -> sbproxy_config::ResponseCacheStoreConfig {
        sbproxy_config::ResponseCacheStoreConfig {
            backend: sbproxy_config::ResponseCacheBackendConfig::Memory,
            encryption: Some(sbproxy_config::ResponseCacheEncryptionConfig {
                enabled: true,
                key: key.map(String::from),
                previous_keys: Vec::new(),
                per_origin_keys: mode,
            }),
        }
    }

    /// Literal key material long enough to pass the 16-byte floor. The
    /// resolver treats anything that is not a provider URI or `file:`
    /// reference as literal material, which keeps these tests off disk.
    const A_KEY: &str = "origin-a-key-material-0000000001";
    const B_KEY: &str = "origin-b-key-material-0000000002";
    const STORE_KEY: &str = "store-wide-key-material-00000001";

    const NO_PREVIOUS: &[String] = &[];

    fn origin_keys<'a>(id: &'a str, caches: bool, key: Option<&'a str>) -> OriginCacheKeys<'a> {
        OriginCacheKeys {
            id,
            caches,
            key,
            previous_keys: NO_PREVIOUS,
        }
    }

    #[test]
    fn per_origin_keys_produce_one_handle_per_origin() {
        let cfg = encrypted_store(Some(STORE_KEY), sbproxy_config::PerOriginKeyMode::Inherit);
        let origins = [
            origin_keys("a.example", true, Some(A_KEY)),
            origin_keys("b.example", true, None),
        ];
        let stores = build_response_cache_store(
            Some(&cfg),
            None,
            10_000,
            &origins,
            PipelineConstructionMode::Runtime,
        )
        .expect("both keys resolve");
        assert_eq!(stores.per_origin.len(), 2);
        assert!(stores.per_origin.contains_key("a.example"));
        assert!(stores.per_origin.contains_key("b.example"));
    }

    #[test]
    fn an_entry_sealed_for_one_origin_is_unreadable_through_another_handle() {
        // The end-to-end version of the multi-tenant property, driven
        // through the real config path rather than the store's own unit
        // tests. Both origins inherit the store-wide key here, so only
        // the origin binding separates them.
        let cfg = encrypted_store(Some(STORE_KEY), sbproxy_config::PerOriginKeyMode::Inherit);
        let origins = [
            origin_keys("a.example", true, None),
            origin_keys("b.example", true, None),
        ];
        let stores = build_response_cache_store(
            Some(&cfg),
            None,
            10_000,
            &origins,
            PipelineConstructionMode::Runtime,
        )
        .expect("store-wide key resolves");

        let entry = sbproxy_cache::CachedResponse {
            generation: 1,
            status: 200,
            headers: vec![("x-tenant".into(), "a".into())],
            body: b"tenant a private body".to_vec(),
            cached_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            ttl_secs: 300,
            swr_secs: None,
            config_fp: String::new(),
        };
        stores.per_origin["a.example"]
            .put("shared-key", &entry)
            .expect("seal for a");
        assert!(
            stores.per_origin["b.example"].get("shared-key").is_err(),
            "origin b must not be able to open origin a's entry"
        );
    }

    #[test]
    fn strict_mode_names_every_caching_origin_without_a_key() {
        let cfg = encrypted_store(Some(STORE_KEY), sbproxy_config::PerOriginKeyMode::Required);
        let origins = [
            origin_keys("has-key.example", true, Some(A_KEY)),
            origin_keys("missing-one.example", true, None),
            origin_keys("missing-two.example", true, None),
            // Not caching, so it is not required to hold a key.
            origin_keys("no-cache.example", false, None),
        ];
        let err = build_response_cache_store(
            Some(&cfg),
            None,
            10_000,
            &origins,
            PipelineConstructionMode::Runtime,
        )
        .expect_err("strict mode must refuse an origin with no key");
        let message = err.to_string();
        assert!(message.contains("missing-one.example"), "{message}");
        assert!(message.contains("missing-two.example"), "{message}");
        assert!(
            !message.contains("no-cache.example"),
            "an origin that does not cache needs no key: {message}"
        );
    }

    #[test]
    fn strict_mode_accepts_a_config_where_every_caching_origin_has_a_key() {
        let cfg = encrypted_store(None, sbproxy_config::PerOriginKeyMode::Required);
        let origins = [
            origin_keys("a.example", true, Some(A_KEY)),
            origin_keys("b.example", true, Some(B_KEY)),
        ];
        let stores = build_response_cache_store(
            Some(&cfg),
            None,
            10_000,
            &origins,
            PipelineConstructionMode::Runtime,
        )
        .expect("every caching origin declares a key");
        assert_eq!(stores.per_origin.len(), 2);
    }

    #[test]
    fn inherit_mode_still_requires_a_store_wide_key() {
        // Without a store-wide key there is nothing for an origin to
        // inherit, so this is the same misconfiguration as before
        // per-origin keys existed and must fail the same way.
        let cfg = encrypted_store(None, sbproxy_config::PerOriginKeyMode::Inherit);
        let err = build_response_cache_store(
            Some(&cfg),
            None,
            10_000,
            &[origin_keys("a.example", true, None)],
            PipelineConstructionMode::Runtime,
        )
        .expect_err("inherit with nothing to inherit must fail");
        assert!(err.to_string().contains("no `key` is set"), "{err}");
    }

    #[test]
    fn an_unresolvable_per_origin_key_names_the_origin() {
        // The guardrail: per-origin keys multiply the secrets resolved at
        // boot, so the failure has to say which one.
        let cfg = encrypted_store(Some(STORE_KEY), sbproxy_config::PerOriginKeyMode::Inherit);
        let err = build_response_cache_store(
            Some(&cfg),
            None,
            10_000,
            &[origin_keys(
                "broken.example",
                true,
                Some("file:/definitely/not/here.key"),
            )],
            PipelineConstructionMode::Runtime,
        )
        .expect_err("an unreadable key file must abort startup");
        let message = format!("{err:#}");
        assert!(
            message.contains("origins.broken.example.response_cache.encryption"),
            "the error must name the origin whose key failed: {message}"
        );
    }

    #[test]
    fn a_short_per_origin_key_is_refused() {
        let cfg = encrypted_store(Some(STORE_KEY), sbproxy_config::PerOriginKeyMode::Inherit);
        let err = build_response_cache_store(
            Some(&cfg),
            None,
            10_000,
            &[origin_keys("short.example", true, Some("tiny"))],
            PipelineConstructionMode::Runtime,
        )
        .expect_err("a four-byte key must be refused, not stretched");
        assert!(format!("{err:#}").contains("at least 16 bytes"), "{err:#}");
    }

    #[test]
    fn a_per_origin_key_without_store_wide_encryption_is_a_config_error() {
        // An operator who wrote a key here expected sealing to happen.
        // Quietly ignoring it would store that tenant in the clear.
        let cfg = sbproxy_config::ResponseCacheStoreConfig {
            backend: sbproxy_config::ResponseCacheBackendConfig::Memory,
            encryption: None,
        };
        let err = build_response_cache_store(
            Some(&cfg),
            None,
            10_000,
            &[origin_keys("a.example", true, Some(A_KEY))],
            PipelineConstructionMode::Runtime,
        )
        .expect_err("a per-origin key with encryption off must not be silently ignored");
        assert!(err.to_string().contains("a.example"), "{err}");
    }

    #[test]
    fn validation_mode_resolves_no_per_origin_secret() {
        // `sbproxy validate` checks shape without dialing secret
        // backends or reading key files, for per-origin keys too.
        let cfg = encrypted_store(Some(STORE_KEY), sbproxy_config::PerOriginKeyMode::Inherit);
        assert!(build_response_cache_store(
            Some(&cfg),
            None,
            10_000,
            &[origin_keys(
                "a.example",
                true,
                Some("file:/definitely/not/here.key"),
            )],
            PipelineConstructionMode::Validation,
        )
        .is_ok());
    }

    #[test]
    fn validation_mode_still_catches_a_strict_mode_violation() {
        // Shape errors are exactly what validate is for, so the strict
        // check must run there even though key resolution does not.
        let cfg = encrypted_store(Some(STORE_KEY), sbproxy_config::PerOriginKeyMode::Required);
        assert!(build_response_cache_store(
            Some(&cfg),
            None,
            10_000,
            &[origin_keys("a.example", true, None)],
            PipelineConstructionMode::Validation,
        )
        .is_err());
    }

    #[test]
    fn per_origin_rotation_is_independent() {
        // Rotating one origin must leave every other origin's entries
        // readable, which is the operational payoff of separate rings.
        let cfg = encrypted_store(Some(STORE_KEY), sbproxy_config::PerOriginKeyMode::Inherit);
        let entry = sbproxy_cache::CachedResponse {
            generation: 1,
            status: 200,
            headers: Vec::new(),
            body: b"body".to_vec(),
            cached_at: 1_700_000_000,
            ttl_secs: 300,
            swr_secs: None,
            config_fp: String::new(),
        };

        let before = build_response_cache_store(
            Some(&cfg),
            None,
            10_000,
            &[
                origin_keys("a.example", true, Some(A_KEY)),
                origin_keys("b.example", true, Some(B_KEY)),
            ],
            PipelineConstructionMode::Runtime,
        )
        .expect("build");
        before.per_origin["a.example"].put("a", &entry).unwrap();
        before.per_origin["b.example"].put("b", &entry).unwrap();

        // Only a.example rotates. Its old key moves into previous_keys.
        let rotated_previous = vec![A_KEY.to_string()];
        let after = build_response_cache_store(
            Some(&cfg),
            None,
            10_000,
            &[
                OriginCacheKeys {
                    id: "a.example",
                    caches: true,
                    key: Some("origin-a-key-material-0000000003"),
                    previous_keys: &rotated_previous,
                },
                origin_keys("b.example", true, Some(B_KEY)),
            ],
            PipelineConstructionMode::Runtime,
        )
        .expect("build after rotation");

        // Both stores share the same in-process backend only when the
        // backend instance is shared, which it is not across two builds,
        // so this test asserts the ring shape instead: a.example can
        // still be built with a retired key, and b.example is untouched.
        assert_eq!(after.per_origin.len(), 2);
        assert!(after.per_origin.contains_key("a.example"));
        assert!(after.per_origin.contains_key("b.example"));
    }

    /// WOR-2328: the proxy's zone identity must reach every place a
    /// load balancer can be compiled, not only per-origin actions. A
    /// forward-rule inline LB or a fallback LB that missed the bind
    /// would silently ignore `targets[].zone` on exactly the paths an
    /// operator cannot watch, which is the inert-label failure this
    /// feature exists to remove.
    #[test]
    fn zone_identity_binds_origin_forward_rule_and_fallback_load_balancers() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
  zone: zone-a
origins:
  "lb.test":
    action:
      type: load_balancer
      targets:
        - { url: "http://a:8080", zone: zone-a }
        - { url: "http://b:8080", zone: zone-b }
    forward_rules:
      - rules:
          - path: { prefix: /shard/ }
        origin:
          id: shard
          action:
            type: load_balancer
            targets:
              - { url: "http://c:8080", zone: zone-a }
              - { url: "http://d:8080", zone: zone-b }
    fallback_origin:
      on_error: true
      origin:
        action:
          type: load_balancer
          targets:
            - { url: "http://e:8080", zone: zone-a }
            - { url: "http://f:8080", zone: zone-b }
"#;
        let config = sbproxy_config::compile_config(yaml).expect("zone fixture compiles");
        let pipeline = CompiledPipeline::from_config_for_validation(config)
            .expect("zone fixture builds a pipeline");

        fn expect_bound(action: &sbproxy_modules::Action, surface: &str) {
            match action {
                sbproxy_modules::Action::LoadBalancer(lb) => assert_eq!(
                    lb.local_zone(),
                    Some("zone-a"),
                    "{surface} load balancer missed the zone bind"
                ),
                _ => panic!("{surface} should compile a load balancer"),
            }
        }

        expect_bound(&pipeline.actions[0], "per-origin");
        expect_bound(&pipeline.forward_rules[0][0].action, "forward-rule inline");
        expect_bound(
            &pipeline.fallbacks[0]
                .as_ref()
                .expect("fallback compiled")
                .action,
            "fallback",
        );
    }
}

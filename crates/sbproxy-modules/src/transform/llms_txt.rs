// SPDX-License-Identifier: BUSL-1.1
//! Auto-generated `llms.txt` from runtime config.
//!
//! This module exists alongside the older `projections::llms` renderer.
//! The projection variant in `projections/llms.rs` is the AI-crawl-pricing
//! flavour of `llms.txt`: it carries a YAML-like header with
//! sitename / version / payment lines and is keyed off the
//! `ai_crawl_control` policy. WOR-130 is the orthogonal flavour described
//! on `https://llmstxt.org/`: a Markdown-shaped index of the host's
//! capabilities derived from a one-shot classifier pass over the
//! compiled origin (AI gateway models, exposed routes, access policies).
//!
//! Two public entry points:
//!
//! 1. [`parse`] - parse a Markdown-shaped `llms.txt` document into a
//!    typed [`LlmsTxt`] value. This is the function the
//!    `llms_txt_parser` fuzz target drives.
//! 2. [`LlmsTxtGenerator`] - render an `llms.txt` for a single
//!    hostname out of a [`sbproxy_config::CompiledConfig`] snapshot.
//!
//! The two functions are duals: `LlmsTxtGenerator::generate(host)` emits
//! a document that `parse` accepts.
//!
//! ## Format reference
//!
//! Per `https://llmstxt.org/` the document has this shape:
//!
//! ```text
//! # Project name
//!
//! > One-paragraph project summary.
//!
//! ## Section heading
//!
//! - [Link title](URL): description.
//! - [Link title](URL): description.
//! ```
//!
//! The parser is intentionally lenient about extra blank lines and
//! trailing whitespace so the fuzz target's bounded-byte inputs are
//! tolerated without panics.

use std::sync::Arc;

use sbproxy_config::CompiledConfig;

// --- Parser ---

/// A parsed `llms.txt` document.
///
/// Fields mirror the four blocks defined on `https://llmstxt.org/`:
/// the top-level H1 title, the block-quote summary directly under it,
/// and one or more H2 sections each holding a bulleted link list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LlmsTxt {
    /// Top-level `# Title` heading. Empty if the document did not
    /// open with one.
    pub name: String,
    /// `> Summary` block-quote that follows the H1 (joined with single
    /// spaces if the quote spans multiple lines). Empty if absent.
    pub summary: String,
    /// One entry per `## Section` block, in document order.
    pub sections: Vec<Section>,
}

/// One `## Section heading` block from an `llms.txt` document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Section {
    /// Section heading text (the part after `## `).
    pub heading: String,
    /// Links from the bulleted list immediately under the heading.
    pub links: Vec<Link>,
}

/// One `- [title](url): description` line from a section.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Link {
    /// Link title (the part between `[` and `]`).
    pub title: String,
    /// Link URL (the part between `(` and `)`).
    pub url: String,
    /// Optional description (the trimmed part after the `): ` separator).
    /// Empty when the bullet line has no description.
    pub description: String,
}

/// Errors returned by [`parse`].
///
/// The parser is lenient: it accepts trailing whitespace, blank lines,
/// and unknown lines without erroring. The only inputs that produce an
/// `Err` are inputs that cannot be interpreted as UTF-8 text. Every
/// other malformed input shape is tolerated (and the offending lines
/// are skipped) so the fuzz target's "no panic, bounded memory"
/// contract is upheld for any byte sequence.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// The input was not valid UTF-8.
    #[error("llms.txt input is not valid UTF-8: {0}")]
    NotUtf8(#[from] std::str::Utf8Error),
}

/// Hard cap on the number of links the parser will retain. Mirrors the
/// fuzz harness's `MAX_ENTRIES` so adversarial input cannot wedge the
/// parser into a multi-gigabyte allocation.
const MAX_LINKS: usize = 65_536;

/// Parse a Markdown-shaped `llms.txt` document.
///
/// Returns a typed [`LlmsTxt`] holding the title, summary, and one
/// [`Section`] per `## ` heading. Lines that cannot be interpreted
/// under the documented shape (e.g. bullets that do not contain a
/// `[label](url)` pair) are skipped silently. The parser never panics
/// for any UTF-8 input and caps retained link count at 65_536.
///
/// # Errors
///
/// Returns [`ParseError::NotUtf8`] only if the bytes behind `text`
/// cannot be reinterpreted as UTF-8. Callers that already hold a
/// `&str` will never see this variant.
pub fn parse(text: &str) -> Result<LlmsTxt, ParseError> {
    let mut doc = LlmsTxt::default();
    let mut summary_lines: Vec<String> = Vec::new();
    let mut current: Option<Section> = None;
    let mut total_links: usize = 0;

    for raw in text.lines() {
        let trimmed = raw.trim_end();
        let line = trimmed.trim_start();

        if line.is_empty() {
            continue;
        }

        // Top-level title. The first `# ` wins; later ones are
        // demoted to "unknown content" and skipped so a document with
        // accidental duplicate H1s does not silently overwrite the
        // intended title.
        if let Some(rest) = line.strip_prefix("# ") {
            if doc.name.is_empty() {
                doc.name = rest.trim().to_string();
            }
            continue;
        }

        // Section heading. Flush the previous section (if any) onto
        // the document and start a new one. An H2 with no following
        // links is still emitted with an empty link list so callers
        // can detect "section declared but empty".
        if let Some(rest) = line.strip_prefix("## ") {
            if let Some(prev) = current.take() {
                doc.sections.push(prev);
            }
            current = Some(Section {
                heading: rest.trim().to_string(),
                links: Vec::new(),
            });
            continue;
        }

        // Block-quote summary. Accumulate lines until the next H1 /
        // H2 / bullet; they are joined with a single space so callers
        // get a coherent paragraph.
        if let Some(rest) = line.strip_prefix("> ") {
            summary_lines.push(rest.trim().to_string());
            continue;
        }

        // Bullet entry. Accept both `-` and `*` markers per the spec.
        let bullet_body = line.strip_prefix("- ").or_else(|| line.strip_prefix("* "));
        if let Some(body) = bullet_body {
            if total_links >= MAX_LINKS {
                continue;
            }
            if let Some(link) = parse_link(body) {
                total_links = total_links.saturating_add(1);
                match current.as_mut() {
                    Some(section) => section.links.push(link),
                    None => {
                        // Bullet outside any section: open a synthetic
                        // section so the link is not lost. Producers
                        // following the spec always emit a section
                        // first; this branch covers permissive input.
                        let mut section = Section {
                            heading: String::new(),
                            links: Vec::new(),
                        };
                        section.links.push(link);
                        current = Some(section);
                    }
                }
            }
            continue;
        }

        // Anything else (raw paragraph, unrecognised marker) is
        // skipped. Tolerance is deliberate per the fuzz contract.
    }

    if let Some(last) = current.take() {
        doc.sections.push(last);
    }
    doc.summary = summary_lines.join(" ");
    Ok(doc)
}

/// Pull `(title, url, description)` out of a bulleted line body.
///
/// `body` is the bullet text *after* the `- ` / `* ` marker. Returns
/// `None` if the `[...](...)` shape is missing or malformed.
fn parse_link(body: &str) -> Option<Link> {
    let open_bracket = body.find('[')?;
    let close_bracket = body[open_bracket..].find(']')? + open_bracket;
    let after_close = body.get(close_bracket + 1..)?;
    let open_paren_rel = after_close.find('(')?;
    if open_paren_rel != 0 {
        // The `]` and `(` must be adjacent per the Markdown link shape.
        return None;
    }
    let url_start = close_bracket + 2; // skip `](`
    let url_end_rel = body.get(url_start..)?.find(')')?;
    let url_end = url_start + url_end_rel;

    let title = body
        .get(open_bracket + 1..close_bracket)?
        .trim()
        .to_string();
    let url = body.get(url_start..url_end)?.trim().to_string();
    if title.is_empty() || url.is_empty() {
        return None;
    }

    // Optional description after `): `.
    let description = body
        .get(url_end + 1..)
        .map(|tail| tail.trim_start_matches(':').trim().to_string())
        .unwrap_or_default();

    Some(Link {
        title,
        url,
        description,
    })
}

// --- Generator ---

/// Render an `llms.txt` for a single host out of the compiled config.
///
/// The generator inspects the [`sbproxy_config::CompiledOrigin`] for a
/// hostname and emits a Markdown-shaped document describing:
///
/// - the AI models exposed at the host (read from any AI-proxy action),
/// - the path-based forward rules / proxy routes the host fronts,
/// - per-host rate-limit ceilings and authentication requirements.
///
/// One generator is built per [`CompiledConfig`] snapshot; the same
/// generator can render different hosts. The cost of [`Self::generate`]
/// is one hash-map lookup plus a fixed-size string assembly; no I/O
/// happens at render time.
pub struct LlmsTxtGenerator {
    config: Arc<CompiledConfig>,
}

impl LlmsTxtGenerator {
    /// Build a generator backed by the supplied compiled config.
    pub fn new(config: Arc<CompiledConfig>) -> Self {
        Self { config }
    }

    /// Render an `llms.txt` document for `host`.
    ///
    /// Returns a placeholder "host not fronted by this proxy" document
    /// when the hostname is not registered with the compiled config so
    /// the output is always a valid `llms.txt` (the parser will accept
    /// it). Operators wiring this behind a `GET /llms.txt` handler can
    /// surface the empty case as a 404 instead if they prefer.
    pub fn generate(&self, host: &str) -> String {
        let Some(origin) = self.config.resolve_origin(host) else {
            return render_unknown_host(host);
        };

        let models = collect_models(origin);
        let endpoints = collect_endpoints(origin);
        let access = collect_access(origin);

        let origin_count = self.config.origins.len();
        let mut out = String::with_capacity(512);

        // Title.
        push_line(&mut out, &format!("# {host}"));
        out.push('\n');

        // Summary block-quote.
        push_line(
            &mut out,
            &format!(
                "> SBproxy-fronted gateway. {origin_count} origins, {} models accessible.",
                models.len(),
            ),
        );
        out.push('\n');

        // Models section. Always emitted so the document shape is
        // predictable; an empty list collapses to a single placeholder
        // line so the section is still grep-able by downstream agents.
        push_line(&mut out, "## Models");
        out.push('\n');
        if models.is_empty() {
            push_line(&mut out, "- No AI models advertised at this host.");
        } else {
            for (model, provider) in &models {
                push_line(
                    &mut out,
                    &format!("- [{model}](/v1/chat/completions): {provider}"),
                );
            }
        }
        out.push('\n');

        // Endpoints section.
        push_line(&mut out, "## Endpoints");
        out.push('\n');
        if endpoints.is_empty() {
            push_line(&mut out, "- No forward rules configured for this host.");
        } else {
            for (path, target) in &endpoints {
                push_line(&mut out, &format!("- [{path}]({path}): {target}"));
            }
        }
        out.push('\n');

        // Access section.
        push_line(&mut out, "## Access");
        out.push('\n');
        for line in &access {
            push_line(&mut out, &format!("- {line}"));
        }

        out
    }
}

/// Render the placeholder document used when a host is not registered.
///
/// Kept as a freestanding helper so callers exercising the
/// "unknown host" branch in tests do not need an `Arc<CompiledConfig>`.
fn render_unknown_host(host: &str) -> String {
    let mut out = String::with_capacity(128);
    push_line(&mut out, &format!("# {host}"));
    out.push('\n');
    push_line(&mut out, "> Host is not fronted by this proxy.");
    out.push('\n');
    push_line(&mut out, "## Models");
    out.push('\n');
    push_line(&mut out, "- No AI models advertised at this host.");
    out.push('\n');
    push_line(&mut out, "## Endpoints");
    out.push('\n');
    push_line(&mut out, "- No forward rules configured for this host.");
    out.push('\n');
    push_line(&mut out, "## Access");
    out.push('\n');
    push_line(&mut out, "- No access policy advertised at this host.");
    out
}

/// Append `line` to `out` followed by a single `\n`. Centralised so
/// the generator never accidentally emits CRLF on a Windows builder.
fn push_line(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}

/// Walk an origin's action config, surfacing `(model, provider)`
/// pairs for any AI proxy action found.
///
/// The compiler keeps `action_config` as a `serde_json::Value` until
/// module-layer compilation; we only need the model list, which the
/// AI gateway emits under `providers[].models[]` with a `name` field
/// per provider.
fn collect_models(origin: &sbproxy_config::CompiledOrigin) -> Vec<(String, String)> {
    let action_type = origin
        .action_config
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if action_type != "ai_proxy" && action_type != "ai" {
        return Vec::new();
    }

    let Some(providers) = origin
        .action_config
        .get("providers")
        .and_then(|v| v.as_array())
    else {
        return Vec::new();
    };

    let mut out: Vec<(String, String)> = Vec::new();
    for provider in providers {
        let provider_name = provider
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        if let Some(models) = provider.get("models").and_then(|v| v.as_array()) {
            for model in models {
                if let Some(name) = model.as_str() {
                    out.push((name.to_string(), provider_name.clone()));
                }
            }
        }
        // Surface the default model even when `models[]` is empty.
        if let Some(default_model) = provider.get("default_model").and_then(|v| v.as_str()) {
            let pair = (default_model.to_string(), provider_name.clone());
            if !out.contains(&pair) {
                out.push(pair);
            }
        }
    }
    out
}

/// Walk the origin's forward rules for path-shaped routes plus the
/// default upstream URL. The result is `(path_or_label, target_url)`
/// pairs in declaration order.
fn collect_endpoints(origin: &sbproxy_config::CompiledOrigin) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();

    // Default upstream from the action config (proxy URL or AI gateway).
    if let Some(url) = origin.action_config.get("url").and_then(|v| v.as_str()) {
        out.push(("/".to_string(), url.to_string()));
    }

    for rule in &origin.forward_rules {
        let target_url = rule
            .get("origin")
            .and_then(|o| o.get("url").or_else(|| o.get("action")?.get("url")))
            .and_then(|v| v.as_str())
            .unwrap_or("inline")
            .to_string();
        if let Some(rules) = rule.get("rules").and_then(|v| v.as_array()) {
            for matcher in rules {
                let path = matcher
                    .get("path")
                    .and_then(|v| v.as_str())
                    .or_else(|| matcher.get("prefix").and_then(|v| v.as_str()))
                    .or_else(|| matcher.get("template").and_then(|v| v.as_str()))
                    .unwrap_or("/*")
                    .to_string();
                out.push((path, target_url.clone()));
            }
        }
    }

    out
}

/// Compose the bullet lines for the `## Access` section.
fn collect_access(origin: &sbproxy_config::CompiledOrigin) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();

    if let Some(limits) = &origin.rate_limits {
        lines.push(format!(
            "Tenant rate limit: {} rps sustained, {} rps burst.",
            limits.tenant_sustained, limits.tenant_burst,
        ));
        if !limits.route_overrides.is_empty() {
            lines.push(format!(
                "Per-route ceilings: {} entries (default {} rps).",
                limits.route_overrides.len(),
                limits.route_default,
            ));
        }
    } else {
        lines.push("No tenant rate limit configured.".to_string());
    }

    match &origin.auth_config {
        Some(auth) => {
            let kind = auth
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("custom");
            lines.push(format!("Authentication required: {kind}."));
        }
        None => lines.push("Authentication: open access.".to_string()),
    }

    if origin.force_ssl {
        lines.push("Transport: HTTPS required (force_ssl on).".to_string());
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;

    use compact_str::CompactString;
    use sbproxy_config::types::OriginRateLimitsConfig;
    use sbproxy_config::{CompiledConfig, CompiledOrigin, ProxyServerConfig};
    use serde_json::json;
    use smallvec::smallvec;

    // --- parse() ---

    #[test]
    fn parse_round_trips_documented_example() {
        // Copy of the canonical example documented at
        // `https://llmstxt.org/`. The parser must extract title,
        // summary, and one section with two links.
        let doc = "\
# Example Project

> One-paragraph project summary.

## API

- [Quickstart](/docs/quickstart): a one-page intro.
- [Reference](/docs/api): full reference manual.
";
        let parsed = parse(doc).expect("documented example must parse");
        assert_eq!(parsed.name, "Example Project");
        assert_eq!(parsed.summary, "One-paragraph project summary.");
        assert_eq!(parsed.sections.len(), 1);
        let section = &parsed.sections[0];
        assert_eq!(section.heading, "API");
        assert_eq!(section.links.len(), 2);
        assert_eq!(section.links[0].title, "Quickstart");
        assert_eq!(section.links[0].url, "/docs/quickstart");
        assert!(section.links[0].description.contains("one-page intro"));
        assert_eq!(section.links[1].title, "Reference");
        assert_eq!(section.links[1].url, "/docs/api");
    }

    #[test]
    fn parse_tolerates_malformed_input_without_panicking() {
        // Each of these inputs is malformed but the parser must
        // return `Ok` with a (possibly empty) document.
        let inputs = [
            "",
            "\n\n\n",
            "## section with no title",
            "- [missing url]",
            "- [missing closing bracket(http://x",
            "# title only",
            "- [](https://example.com)",
            "- [text](): empty url",
            "> orphan summary with no title",
        ];
        for raw in inputs {
            let parsed = parse(raw).expect("malformed input must not error");
            // No assertions on content; we only require no panic and
            // a well-typed return value.
            std::hint::black_box(parsed);
        }
    }

    #[test]
    fn parse_collects_multiple_sections() {
        let doc = "\
# Host

> Two sections.

## Models

- [gpt-4o](/v1/chat/completions): OpenAI.

## Endpoints

- [/](https://upstream.example.com): default upstream.
";
        let parsed = parse(doc).expect("multi-section parse");
        assert_eq!(parsed.sections.len(), 2);
        assert_eq!(parsed.sections[0].heading, "Models");
        assert_eq!(parsed.sections[1].heading, "Endpoints");
        assert_eq!(parsed.sections[0].links[0].title, "gpt-4o");
        assert_eq!(parsed.sections[1].links[0].title, "/");
    }

    // --- generate() ---

    fn make_origin(
        hostname: &str,
        action_config: serde_json::Value,
        rate_limits: Option<OriginRateLimitsConfig>,
        auth_config: Option<serde_json::Value>,
        forward_rules: Vec<serde_json::Value>,
    ) -> CompiledOrigin {
        CompiledOrigin {
            hostname: CompactString::new(hostname),
            origin_id: CompactString::new(hostname),
            workspace_id: CompactString::default(),
            action_config,
            auth_config,
            policy_configs: Vec::new(),
            transform_configs: Vec::new(),
            cors: None,
            hsts: None,
            compression: None,
            session: None,
            properties: None,
            sessions: None,
            user: None,
            force_ssl: false,
            allowed_methods: smallvec![],
            request_modifiers: smallvec![],
            response_modifiers: smallvec![],
            variables: None,
            forward_rules,
            fallback_origin: None,
            error_pages: None,
            problem_details: None,
            proxy_status: None,
            message_signatures: None,
            idempotency: None,
            bot_detection: None,
            threat_protection: None,
            on_request: Vec::new(),
            on_response: Vec::new(),
            response_cache: None,
            mirror: None,
            extensions: HashMap::new(),
            expose_openapi: false,
            stream_safety: Vec::new(),
            rate_limits,
            auto_content_negotiate: None,
            content_signal: None,
            token_bytes_ratio: None,
            agent_skills: Vec::new(),
            agents_md: None,
            ai_txt: None,
            agents_json: None,
            outbound_credential: None,
            outbound_web_bot_auth: false,
        }
    }

    fn build_config(origins: Vec<CompiledOrigin>) -> Arc<CompiledConfig> {
        let mut host_map = HashMap::new();
        for (idx, origin) in origins.iter().enumerate() {
            host_map.insert(origin.hostname.clone(), idx);
        }
        Arc::new(CompiledConfig {
            origins,
            host_map,
            server: ProxyServerConfig::default(),
            l2_store: None,
            messenger: None,
            mesh: None,
            access_log: None,
            agent_classes: None,
        })
    }

    #[test]
    fn generate_emits_expected_sections_with_two_origins_three_models() {
        // Origin 1: AI gateway with three models across two providers.
        let ai = make_origin(
            "ai.example.com",
            json!({
                "type": "ai_proxy",
                "providers": [
                    {"name": "openai", "models": ["gpt-4o", "gpt-4o-mini"]},
                    {"name": "anthropic", "models": ["claude-3-5-sonnet"]},
                ],
            }),
            Some(OriginRateLimitsConfig {
                tenant_sustained: 500,
                tenant_burst: 1_000,
                ..Default::default()
            }),
            Some(json!({"type": "api_key"})),
            vec![json!({
                "rules": [{"prefix": "/v1/chat"}],
                "origin": {"url": "https://upstream.example.com"},
            })],
        );

        // Origin 2: a plain proxy with no AI surface.
        let api = make_origin(
            "api.example.com",
            json!({"type": "proxy", "url": "https://backend.example.com"}),
            None,
            None,
            Vec::new(),
        );

        let cfg = build_config(vec![ai, api]);
        let gen = LlmsTxtGenerator::new(cfg);
        let doc = gen.generate("ai.example.com");

        // The document must round-trip through the parser.
        let parsed = parse(&doc).expect("generator output must parse");
        assert_eq!(parsed.name, "ai.example.com");
        assert!(parsed.summary.contains("3 models accessible"));
        assert!(parsed.summary.contains("2 origins"));

        // Three sections in order: Models, Endpoints, Access.
        let headings: Vec<&str> = parsed.sections.iter().map(|s| s.heading.as_str()).collect();
        assert_eq!(headings, vec!["Models", "Endpoints", "Access"]);

        // Models section: three entries.
        assert_eq!(parsed.sections[0].links.len(), 3);
        let model_names: Vec<&str> = parsed.sections[0]
            .links
            .iter()
            .map(|l| l.title.as_str())
            .collect();
        assert!(model_names.contains(&"gpt-4o"));
        assert!(model_names.contains(&"gpt-4o-mini"));
        assert!(model_names.contains(&"claude-3-5-sonnet"));

        // The "Access" bullets do not carry a `[label](url)` shape;
        // they round-trip as plain bullet lines and the parser skips
        // them. Assert on the raw generated doc to confirm the
        // rate-limit and auth context are present.
        assert!(doc.contains("500 rps sustained"));
        assert!(doc.contains("api_key"));
    }

    #[test]
    fn generate_differs_for_two_hosts_on_same_proxy() {
        let a = make_origin(
            "a.example.com",
            json!({
                "type": "ai_proxy",
                "providers": [{"name": "openai", "models": ["gpt-4o"]}],
            }),
            None,
            None,
            Vec::new(),
        );
        let b = make_origin(
            "b.example.com",
            json!({"type": "proxy", "url": "https://backend.example.com"}),
            Some(OriginRateLimitsConfig::default()),
            Some(json!({"type": "basic_auth"})),
            Vec::new(),
        );

        let cfg = build_config(vec![a, b]);
        let gen = LlmsTxtGenerator::new(cfg);
        let doc_a = gen.generate("a.example.com");
        let doc_b = gen.generate("b.example.com");

        assert_ne!(
            doc_a, doc_b,
            "two hosts on the same proxy must produce distinct llms.txt"
        );
        assert!(doc_a.contains("# a.example.com"));
        assert!(doc_b.contains("# b.example.com"));
        assert!(doc_a.contains("gpt-4o"));
        assert!(!doc_b.contains("gpt-4o"));
        assert!(doc_b.contains("basic_auth"));
    }

    #[test]
    fn generate_unknown_host_returns_placeholder() {
        let cfg = build_config(Vec::new());
        let gen = LlmsTxtGenerator::new(cfg);
        let doc = gen.generate("not-fronted.example.com");
        let parsed = parse(&doc).expect("placeholder must parse");
        assert_eq!(parsed.name, "not-fronted.example.com");
        assert!(parsed.summary.contains("not fronted"));
    }

    #[test]
    fn collect_models_skips_non_ai_actions() {
        let origin = make_origin(
            "h",
            json!({"type": "proxy", "url": "https://backend.example.com"}),
            None,
            None,
            Vec::new(),
        );
        assert!(collect_models(&origin).is_empty());
    }

    #[test]
    fn collect_endpoints_carries_default_url_and_forward_rules() {
        let origin = make_origin(
            "h",
            json!({"type": "proxy", "url": "https://up.example.com"}),
            None,
            None,
            vec![json!({
                "rules": [{"prefix": "/api/v1"}, {"path": "/health"}],
                "origin": {"url": "https://child.example.com"},
            })],
        );
        let endpoints = collect_endpoints(&origin);
        assert_eq!(endpoints.len(), 3);
        assert_eq!(endpoints[0].0, "/");
        assert_eq!(endpoints[0].1, "https://up.example.com");
        assert_eq!(endpoints[1].0, "/api/v1");
        assert_eq!(endpoints[1].1, "https://child.example.com");
        assert_eq!(endpoints[2].0, "/health");
    }
}

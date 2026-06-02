//! Access-log emission, per-agent label bundling, and PII redaction
//! for the request-logging hook.
//!
//! Extracted from `server.rs`. Behavior-preserving move:
//! no logic changes. `use super::*` re-imports the parent module's
//! private items (statics, sibling helpers) these functions rely on.

use super::*;

// --- Access log emission helpers ---

/// Pull the per-agent label bundle off the request context.
///
/// When the `agent-class` feature is on the
/// request pipeline runs the `AgentClassResolver` early in
/// `request_filter`, stamping `agent_id`, `agent_vendor`, etc. onto
/// the context. The hot-path `logging` callback feeds those values
/// into the per-agent metric labels via this helper.
///
/// When the feature is off, the helper returns the all-empty
/// `AgentLabels::unset()` and the cardinality limiter sees an empty
/// label set (no demotions, no overhead).
///
/// `payment_rail` and `content_shape` are intentionally left empty
/// here: payment-rail resolution is a follow-up (the rail is
/// known after the AI handler dispatches but before the response
/// completes; threading it through the logging hook is a separate
/// task). `content_shape` is observed at response-time and lives on
/// a follow-up label-stamping path.
pub(super) fn build_agent_labels(ctx: &RequestContext) -> sbproxy_observe::AgentLabels<'_> {
    #[cfg(feature = "agent-class")]
    {
        sbproxy_observe::AgentLabels {
            agent_id: ctx.agent_id.as_ref().map(|id| id.as_str()).unwrap_or(""),
            agent_class: agent_class_label(ctx),
            agent_vendor: ctx.agent_vendor.as_deref().unwrap_or(""),
            payment_rail: "",
            content_shape: "",
        }
    }
    #[cfg(not(feature = "agent-class"))]
    {
        let _ = ctx;
        sbproxy_observe::AgentLabels::unset()
    }
}

/// Map the resolved `AgentPurpose` to the `agent_class` label vocabulary.
///
/// The metric label is a closed-string view; the resolver carries the
/// typed `AgentPurpose` enum. This shim flattens to the metric
/// vocabulary without allocation.
///
/// When the resolver has not run, return `""` (the documented "no
/// classification" sentinel). When it has run but the catalog yields
/// `Unknown`, return `"unknown"` so dashboards can split untyped
/// traffic from explicitly unclassified traffic.
#[cfg(feature = "agent-class")]
pub(super) fn agent_class_label(ctx: &RequestContext) -> &'static str {
    use sbproxy_classifiers::AgentPurpose;
    match ctx.agent_purpose {
        // Distinguish "no resolution" from "resolved to Unknown".
        Some(AgentPurpose::Unknown) if ctx.agent_id.is_some() => "unknown",
        Some(AgentPurpose::Unknown) => "",
        Some(p) => p.as_str(),
        None => "",
    }
}

// --- Wave 3 / G1.4 wire: agent-class resolver startup ---

/// Build the process-wide `AgentClassResolver` from the parsed
/// top-level `agent_classes:` block (or defaults when absent) and
/// install it in [`reload::set_agent_class_resolver`].
///
/// Catalog selection mirrors the YAML schema:
///
/// - `None` (no top-level block) or `catalog: builtin`: use
///   `AgentClassCatalog::defaults()`.
/// - `catalog: hosted-feed`: reserved for the registry fetcher landing
///   in the registry fetcher; for now we log a warning and fall back
///   to defaults so YAML written against the larger schema still boots.
/// - `catalog: merged`: same as `hosted-feed` until the registry ships the
///   overlay path. Falls back to defaults with the same warning.
/// - Any other catalog string: warns and falls back to defaults.
///
/// DNS resolver: the OSS build does not pull `hickory-resolver`, so we
/// install [`sbproxy_security::agent_verify::SystemResolver`]. Its
/// `reverse()` returns an error verdict; the resolver chain treats
/// that as a transient miss and falls through to UA matching, matching
/// the documented "no working PTR" degradation path. Operators who
/// want forward-confirmed rDNS in production can flip
/// `agent_classes.resolver.rdns_enabled: false` to skip the lookup
/// entirely (saves a syscall) until a real resolver lands.
///
/// Cache size honours `agent_classes.resolver.cache_size`; the default
/// (10 000 entries) matches the OSS recommendation in the resolver
/// docs.
#[cfg(feature = "agent-class")]
pub(super) fn install_agent_class_resolver(block: Option<&sbproxy_config::AgentClassesConfig>) {
    use std::sync::Arc;

    use sbproxy_classifiers::AgentClassCatalog;
    use sbproxy_modules::policy::agent_class::AgentClassResolver;
    use sbproxy_security::agent_verify::SystemResolver;

    let (catalog, cache_size) = match block {
        None => (AgentClassCatalog::defaults(), 10_000usize),
        Some(cfg) => {
            let catalog = match cfg.catalog.as_str() {
                "builtin" => AgentClassCatalog::defaults(),
                "hosted-feed" | "merged" => {
                    tracing::warn!(
                        catalog = %cfg.catalog,
                        "agent_classes.catalog '{}' selected but the registry fetcher \
                         (G2.2) has not landed yet; falling back to the built-in defaults",
                        cfg.catalog,
                    );
                    AgentClassCatalog::defaults()
                }
                other => {
                    tracing::warn!(
                        catalog = %other,
                        "agent_classes.catalog '{}' is not recognised; falling back to \
                         the built-in defaults",
                        other,
                    );
                    AgentClassCatalog::defaults()
                }
            };
            (catalog, cfg.resolver.cache_size)
        }
    };

    let dns_resolver = Arc::new(SystemResolver);
    let resolver = AgentClassResolver::new(Arc::new(catalog), dns_resolver, cache_size);
    reload::set_agent_class_resolver(Arc::new(resolver));
    tracing::info!(
        cache_size = %cache_size,
        "agent_class resolver installed",
    );
}

/// Cached default-rule PII redactor for access-log header capture.
/// Building the redactor compiles ~10 regexes plus an Aho-Corasick
/// prefilter, so we keep one instance for the whole process lifetime.
/// The scoped variant (`access_log.capture_headers.redact_pii_rules`)
/// is built per-emit because it depends on operator config; the cost
/// is bounded by the access-log sample rate in practice.
pub(super) fn default_pii_redactor() -> &'static sbproxy_security::pii::PiiRedactor {
    static CELL: std::sync::OnceLock<sbproxy_security::pii::PiiRedactor> =
        std::sync::OnceLock::new();
    CELL.get_or_init(sbproxy_security::pii::PiiRedactor::defaults)
}

/// Build a PII redactor scoped to the named subset of the built-in
/// default rules. Case-insensitive name match. Returns `None` when no
/// names match, so the caller can fall back to no-redaction.
pub(super) fn build_scoped_pii_redactor(
    rule_names: &[String],
) -> Option<sbproxy_security::pii::PiiRedactor> {
    let scoped: Vec<sbproxy_security::pii::PiiRule> = sbproxy_security::pii::default_rules()
        .into_iter()
        .filter(|r| rule_names.iter().any(|n| n.eq_ignore_ascii_case(&r.name)))
        .collect();
    if scoped.is_empty() {
        return None;
    }
    let cfg = sbproxy_security::pii::PiiConfig {
        enabled: true,
        defaults: false,
        redact_request: true,
        redact_response: true,
        rules: scoped,
    };
    sbproxy_security::pii::PiiRedactor::from_config(&cfg).ok()
}

/// Apply the typed PII redactor to the access-log fields that can
/// carry PII but are not request / response headers (those are covered
/// by `capture_headers.redact_pii`). Currently scopes to `path`,
/// `user_id`, `properties` values (keys are left intact since they are
/// schema-defined names from the `X-Sb-Property-*` headers), and the
/// AI `model` string. WOR-118.
///
/// `rule_names` follows the same shape as `redact_pii_rules`: empty
/// uses the full default rule set; non-empty restricts to the listed
/// rules. When no rule names match, this is a no-op so the caller
/// degrades to the cheap `redact_secrets` pass that runs at emit time.
pub(super) fn redact_pii_other_fields(
    entry: &mut sbproxy_observe::AccessLogEntry,
    rule_names: &[String],
) {
    // Build (or borrow) the redactor first so we run a single
    // compile per emit when a scoped rule list is configured.
    enum RedactorRef<'a> {
        Default(&'a sbproxy_security::pii::PiiRedactor),
        Scoped(sbproxy_security::pii::PiiRedactor),
    }
    impl RedactorRef<'_> {
        fn get(&self) -> &sbproxy_security::pii::PiiRedactor {
            match self {
                RedactorRef::Default(r) => r,
                RedactorRef::Scoped(r) => r,
            }
        }
    }

    let redactor = if rule_names.is_empty() {
        RedactorRef::Default(default_pii_redactor())
    } else {
        match build_scoped_pii_redactor(rule_names) {
            Some(r) => RedactorRef::Scoped(r),
            // No matching rule names: no-op so the caller falls back
            // to the cheap `redact_secrets` pass alone, matching the
            // header-scope behaviour in `capture_headers_for_log`.
            None => return,
        }
    };
    let redactor = redactor.get();

    // Path: replace with the redacted form even when the rules drop
    // the original wholesale (e.g. the entire path was an email);
    // preserving structure via the [REDACTED:*] markers is intentional.
    let new_path = redactor.redact(&entry.path).into_owned();
    entry.path = new_path;

    if let Some(user_id) = entry.user_id.as_ref() {
        let redacted = redactor.redact(user_id).into_owned();
        entry.user_id = Some(redacted);
    }

    if let Some(model) = entry.model.as_ref() {
        let redacted = redactor.redact(model).into_owned();
        entry.model = Some(redacted);
    }

    // Properties: redact each value in place; keys are intentionally
    // left untouched since they are schema-defined names captured from
    // `X-Sb-Property-*` request headers.
    for value in entry.properties.values_mut() {
        let redacted = redactor.redact(value).into_owned();
        *value = redacted;
    }
}

/// Capture the subset of `headers` that the compiled allowlist
/// accepts, applying the configured truncation and (optional)
/// PII redaction. Returns an empty map when the allowlist is empty
/// (the common case).
pub(super) fn capture_headers_for_log(
    headers: &http::HeaderMap,
    allowlist: &sbproxy_config::CompiledHeaderAllowlist,
    max_value_bytes: usize,
    redact_pii: bool,
    redact_pii_rules: &[String],
) -> std::collections::BTreeMap<String, String> {
    if allowlist.is_empty() {
        return std::collections::BTreeMap::new();
    }
    if redact_pii {
        if redact_pii_rules.is_empty() {
            let redactor = default_pii_redactor();
            sbproxy_observe::capture::capture_headers(
                headers,
                |name| allowlist.matches(name),
                max_value_bytes,
                Some(|v: &str| redactor.redact(v).into_owned()),
            )
        } else if let Some(redactor) = build_scoped_pii_redactor(redact_pii_rules) {
            sbproxy_observe::capture::capture_headers(
                headers,
                |name| allowlist.matches(name),
                max_value_bytes,
                Some(|v: &str| redactor.redact(v).into_owned()),
            )
        } else {
            // No matching rules: fall through to no-redaction.
            sbproxy_observe::capture::capture_headers(
                headers,
                |name| allowlist.matches(name),
                max_value_bytes,
                None::<fn(&str) -> String>,
            )
        }
    } else {
        sbproxy_observe::capture::capture_headers(
            headers,
            |name| allowlist.matches(name),
            max_value_bytes,
            None::<fn(&str) -> String>,
        )
    }
}

/// Emit one-shot WARN lines for sensitive headers an operator opted
/// into capturing by exact name. Called from the config-load and
/// config-reload paths so the warning surfaces once per reload, not
/// per request.
pub(super) fn log_capture_header_warnings(cfg: &sbproxy_config::AccessLogConfig) {
    let (_, req_warnings) =
        sbproxy_config::CompiledHeaderAllowlist::compile(&cfg.capture_headers.request);
    let (_, resp_warnings) =
        sbproxy_config::CompiledHeaderAllowlist::compile(&cfg.capture_headers.response);
    for header in &req_warnings {
        tracing::warn!(
            header = %header,
            "access_log.capture_headers.request includes a sensitive header by exact match; \
             values will be captured (redact_secrets still strips known token shapes)",
        );
    }
    for header in &resp_warnings {
        tracing::warn!(
            header = %header,
            "access_log.capture_headers.response includes a sensitive header by exact match; \
             values will be captured (redact_secrets still strips known token shapes)",
        );
    }
}

/// Build and emit an access-log entry when the active pipeline has
/// access-log emission enabled and the request passes the filter and
/// sampler. A no-op when access-log is unconfigured or disabled.
pub(super) fn emit_access_log(
    session: &Session,
    ctx: &RequestContext,
    status: u16,
    method: &str,
    hostname: &str,
    duration_secs: f64,
) {
    let pipeline = reload::current_pipeline();
    let Some(cfg) = pipeline.config.access_log.as_ref() else {
        return;
    };

    let req_header = session.req_header();
    let path = req_header.uri.path().to_string();
    // Capture standard HTTP fields once so the JSON shape stays
    // close to what every other access-log consumer (Apache, NGINX,
    // Envoy, the cookie-cutter ELK pipeline) expects without making
    // the operator opt them in through the header allowlist.
    let query = req_header
        .uri
        .query()
        .filter(|q| !q.is_empty())
        .map(|q| q.to_string());
    let protocol = Some(format!("{:?}", req_header.version));
    let scheme = req_header
        .uri
        .scheme_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let host = req_header
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let user_agent = req_header
        .headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let referer = req_header
        .headers
        .get("referer")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let trace_id = ctx.trace_ctx.as_ref().map(|t| t.trace_id.clone());
    let request_id = if !ctx.request_id.is_empty() {
        ctx.request_id.to_string()
    } else {
        // Fallback when the request_phase generator never ran (in-process
        // synthetic call, missing X-Request-Id and disabled correlation
        // middleware). Use the same UUIDv7 generator as the main path so
        // a downstream ClickHouse / SIEM JOIN sees one column shape.
        crate::identity::new_request_id()
    };
    let client_ip = ctx.client_ip.map(|ip| ip.to_string()).unwrap_or_default();

    let auth_type = ctx
        .origin_idx
        .and_then(|idx| pipeline.auths.get(idx))
        .and_then(|opt| opt.as_ref())
        .map(|auth| auth.auth_type().to_string());
    // WOR-1047: principal_kind = the auth_type slug, with two extras
    // the auth-provider enum cannot express on its own:
    //   * `virtual_key` when an AI virtual key matched (detected by
    //     the AI-VK fields stamped on ctx by `handle_ai_proxy`);
    //   * `none` when the origin has no auth provider configured.
    // The AI virtual key case takes precedence over the auth-provider
    // case because a configured auth provider can sit in front of the
    // AI handler; the attribution-relevant principal is the matched
    // VK, not the bearer / api_key that the request used to reach the
    // AI handler.
    let principal_kind = if ctx.principal.virtual_key.is_some() {
        Some("virtual_key".to_string())
    } else {
        Some(auth_type.clone().unwrap_or_else(|| "none".to_string()))
    };
    let workspace_id = ctx
        .origin_idx
        .and_then(|idx| pipeline.config.origins.get(idx))
        .map(|origin| origin.workspace_id.to_string())
        .unwrap_or_default();

    // The cache-result label comes from `ctx.cache_status` (set when
    // a cacheable response landed in the store) and
    // `ctx.served_from_cache` (set when the request hit the cache and
    // skipped the upstream). The two combine into the four canonical
    // labels the access log records.
    let cache_result = if ctx.served_from_cache {
        Some("hit".to_string())
    } else if ctx.cache_status.is_some() {
        Some("miss".to_string())
    } else {
        None
    };

    // --- Wave 6 / G6.2 access-log v1 stamping ---
    //
    // The body-shape transformer field (G4.3 / G4.4) lands as a
    // closed-enum string for the `shape` access-log field. The
    // pricing-pass shape is recorded separately via the existing
    // `content_shape` slot stamped by the agent-class wiring.
    let shape = ctx
        .content_shape_transform
        .as_ref()
        .map(|s| format!("{s:?}").to_ascii_lowercase());

    // --- G6.4 captured-header stamping ---
    //
    // Compile the allowlists per emit. The allowlist is small (a
    // handful of header names plus optional globs) so the compile cost
    // is negligible relative to the JSON serialisation that follows.
    // Caching the compiled form on the pipeline is a follow-up; doing
    // so requires plumbing through the `CompiledPipeline` build path
    // and is out of scope for the first cut.
    let (request_headers, response_headers) =
        if cfg.capture_headers.request.is_empty() && cfg.capture_headers.response.is_empty() {
            (
                std::collections::BTreeMap::new(),
                std::collections::BTreeMap::new(),
            )
        } else {
            let (req_allow, _) =
                sbproxy_config::CompiledHeaderAllowlist::compile(&cfg.capture_headers.request);
            let (resp_allow, _) =
                sbproxy_config::CompiledHeaderAllowlist::compile(&cfg.capture_headers.response);
            let req_headers = capture_headers_for_log(
                &session.req_header().headers,
                &req_allow,
                cfg.capture_headers.max_value_bytes,
                cfg.capture_headers.redact_pii,
                &cfg.capture_headers.redact_pii_rules,
            );
            let resp_headers = match session.response_written() {
                Some(written) => capture_headers_for_log(
                    &written.headers,
                    &resp_allow,
                    cfg.capture_headers.max_value_bytes,
                    cfg.capture_headers.redact_pii,
                    &cfg.capture_headers.redact_pii_rules,
                ),
                None => std::collections::BTreeMap::new(),
            };
            (req_headers, resp_headers)
        };

    // Capture the headline response fields once. `response_content_type`
    // + `response_content_encoding` are primary fields rather than
    // generic-allowlist captures because every analytics consumer
    // slices on them; making the operator opt them in through the
    // header allowlist is brittle. `upstream_status` only surfaces
    // when the proxy rewrote the status the client sees (retry,
    // fallback, response_modifier).
    let response_content_type = session
        .response_written()
        .and_then(|w| w.headers.get("content-type"))
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let response_content_encoding = session
        .response_written()
        .and_then(|w| w.headers.get("content-encoding"))
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let upstream_status = ctx.response_status.filter(|upstream| *upstream != status);

    let context = AccessLogContext {
        envelope_request_id: ctx.envelope_request_id.map(|u| u.to_string()),
        user_id: ctx.user_id.clone(),
        user_id_source: ctx.user_id_source,
        session_id: ctx.session_id.map(|u| u.to_string()),
        parent_session_id: ctx.parent_session_id.map(|u| u.to_string()),
        properties: ctx.properties.clone(),
        workspace_id,
        tenant_id: ctx.tenant_id.to_string(),
        auth_type,
        principal_kind,
        served_from_cache: Some(ctx.served_from_cache),
        fallback_triggered: Some(ctx.fallback_triggered),
        retry_count: Some(ctx.retry_count),
        forward_rule_idx: ctx.forward_rule_idx,
        request_geo: ctx.request_geo.clone(),
        classifier_prompt: ctx.classifier_prompt.as_ref().map(classifier_label),
        classifier_intent: ctx.classifier_intent.map(intent_label),
        error_class: classify_error_class(status),
        auth_ms: ctx
            .request_start
            .zip(ctx.auth_finished_at)
            .map(|(s, e)| e.saturating_duration_since(s).as_secs_f64() * 1000.0),
        upstream_ttfb_ms: ctx
            .request_start
            .zip(ctx.upstream_first_byte_at)
            .map(|(s, e)| e.saturating_duration_since(s).as_secs_f64() * 1000.0),
        response_filter_ms: ctx
            .upstream_first_byte_at
            .zip(ctx.response_filter_finished_at)
            .map(|(s, e)| e.saturating_duration_since(s).as_secs_f64() * 1000.0),
        bytes_in: ctx.request_body_bytes,
        bytes_out: ctx.response_body_bytes,
        provider: ctx.ai_provider.clone(),
        model: ctx.ai_model.clone(),
        prompt_name: ctx.ai_prompt_name.clone(),
        prompt_version: ctx.ai_prompt_version.clone(),
        project: ctx.principal.attrs.project.clone(),
        user: ctx.principal.attrs.user.clone(),
        metadata: ctx
            .principal
            .attrs
            .metadata
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        tokens_in: ctx.ai_tokens_in,
        tokens_out: ctx.ai_tokens_out,
        ai_surface: ctx.ai_surface.clone(),
        cache_result,
        // Wave 6 / G6.2 access-log v1 fields. Most surface stamping
        // lands as the request flows through the pipeline (e.g.
        // `cap_token_id` from the CAP verifier in R6.1, `rail` /
        // `txhash` from the multi-rail 402 handler, `tier` from the
        // tier resolver). At this terminal site we copy whatever is
        // already on `RequestContext`; later waves widen the context
        // surface and this stamping layer follows.
        tier: None,
        shape,
        price: None,
        currency: None,
        rail: None,
        redeemed_token_id: None,
        txhash: None,
        license_token_id: None,
        cap_token_id: None,
        upstream_host: None,
        request_headers,
        response_headers,
    };

    emit_access_log_entry(
        cfg,
        status,
        method,
        hostname,
        &path,
        duration_secs,
        request_id,
        client_ip,
        trace_id,
        HttpFields {
            query,
            protocol,
            scheme,
            host,
            user_agent,
            referer,
            upstream_status,
            response_content_type,
            response_content_encoding,
        },
        context,
    );
}

/// Standard HTTP request + response fields lifted out of the wire
/// headers for stamping onto the access-log entry. Pulled into a
/// struct so the `emit_access_log_entry` signature does not grow by
/// an argument per HTTP field.
pub(super) struct HttpFields {
    pub(super) query: Option<String>,
    pub(super) protocol: Option<String>,
    pub(super) scheme: Option<String>,
    pub(super) host: Option<String>,
    pub(super) user_agent: Option<String>,
    pub(super) referer: Option<String>,
    pub(super) upstream_status: Option<u16>,
    pub(super) response_content_type: Option<String>,
    pub(super) response_content_encoding: Option<String>,
}

impl HttpFields {
    /// All-None HttpFields for tests that do not exercise these
    /// fields. Production callers always construct from
    /// `session.req_header()` + `session.response_written()`.
    #[cfg(test)]
    pub(super) fn empty() -> Self {
        Self {
            query: None,
            protocol: None,
            scheme: None,
            host: None,
            user_agent: None,
            referer: None,
            upstream_status: None,
            response_content_type: None,
            response_content_encoding: None,
        }
    }
}

/// Bundle of `RequestContext`-derived fields that flow into the
/// access-log entry. Pulled out so the test entry-point and the
/// production path share the same shape, and so adding a field
/// doesn't churn every test fixture.
pub(super) struct AccessLogContext {
    pub(super) envelope_request_id: Option<String>,
    pub(super) user_id: Option<String>,
    pub(super) user_id_source: Option<sbproxy_observe::UserIdSource>,
    pub(super) session_id: Option<String>,
    pub(super) parent_session_id: Option<String>,
    pub(super) properties: std::collections::BTreeMap<String, String>,
    pub(super) workspace_id: String,
    /// WOR-1053: resolved tenant from `origin.tenant_id`. `__default__`
    /// when the operator never declared tenants.
    pub(super) tenant_id: String,
    pub(super) auth_type: Option<String>,
    /// WOR-1047: closed-enum principal kind. Mirrors `auth_type` for
    /// the auth-provider variants and adds `virtual_key` (AI-gateway
    /// VK match) and `none` (no auth provider configured). Used by
    /// downstream ClickHouse / Grafana queries to partition the log
    /// by principal source without joining on `auth_type IS NULL`.
    pub(super) principal_kind: Option<String>,
    pub(super) served_from_cache: Option<bool>,
    pub(super) fallback_triggered: Option<bool>,
    pub(super) retry_count: Option<u32>,
    pub(super) forward_rule_idx: Option<usize>,
    pub(super) request_geo: Option<String>,
    pub(super) classifier_prompt: Option<String>,
    pub(super) classifier_intent: Option<String>,
    pub(super) error_class: Option<String>,
    /// Auth-phase latency in milliseconds, derived from
    /// `ctx.auth_finished_at - ctx.request_start`. `None` for
    /// origins without an auth provider.
    pub(super) auth_ms: Option<f64>,
    /// Upstream TTFB in milliseconds, derived from
    /// `ctx.upstream_first_byte_at - ctx.request_start`. `None`
    /// for requests that never hit an upstream (early auth/policy
    /// short-circuit, cache hit).
    pub(super) upstream_ttfb_ms: Option<f64>,
    /// Response-filter phase latency in milliseconds, derived from
    /// `ctx.response_filter_finished_at - ctx.upstream_first_byte_at`.
    /// `None` when no response_filter ran.
    pub(super) response_filter_ms: Option<f64>,
    /// Total request body bytes seen by `request_body_filter`.
    pub(super) bytes_in: u64,
    /// Total response body bytes sent to the client by
    /// `response_body_filter`.
    pub(super) bytes_out: u64,
    /// AI gateway provider name (`openai`, `anthropic`, ...) when
    /// the AI handler picked an upstream; `None` for non-AI traffic.
    pub(super) provider: Option<String>,
    /// AI model identifier the request was routed to.
    pub(super) model: Option<String>,
    /// WOR-800: stored prompt name + version the request resolved.
    pub(super) prompt_name: Option<String>,
    pub(super) prompt_version: Option<String>,
    /// WOR-894: project + user + metadata copied off the matched
    /// virtual key (per-key reporting dimensions).
    pub(super) project: Option<String>,
    pub(super) user: Option<String>,
    pub(super) metadata: std::collections::HashMap<String, String>,
    /// Prompt / input tokens consumed (from the provider response).
    pub(super) tokens_in: Option<u64>,
    /// Completion / output tokens generated.
    pub(super) tokens_out: Option<u64>,
    /// Classified AI surface label (`chat_completions`, `assistants`,
    /// `image_generation`, ...). Stamped by `handle_ai_proxy` so the
    /// access log carries it alongside provider/model/token counts.
    pub(super) ai_surface: Option<String>,
    /// Cache result label (`hit`, `miss`, `stale`, `bypass`) when
    /// the response cache ran.
    pub(super) cache_result: Option<String>,
    // --- Wave 6 / G6.2 access-log v1 fields ---
    /// Pricing tier the request matched (`free`, `commercial`,
    /// operator-defined name).
    pub(super) tier: Option<String>,
    /// Response body shape from the q-value-aware Accept resolver.
    pub(super) shape: Option<String>,
    /// Quote price in micro-units of `currency`.
    pub(super) price: Option<u64>,
    /// ISO 4217 fiat currency or rail-specific code.
    pub(super) currency: Option<String>,
    /// Billing rail that settled the request.
    pub(super) rail: Option<String>,
    /// `jti` of the redeemed quote token.
    pub(super) redeemed_token_id: Option<String>,
    /// On-chain settlement hash for crypto rails.
    pub(super) txhash: Option<String>,
    /// `jti` of the OLP license token presented.
    pub(super) license_token_id: Option<String>,
    /// `jti` of the CAP token presented.
    pub(super) cap_token_id: Option<String>,
    /// Resolved upstream host the request was proxied to.
    pub(super) upstream_host: Option<String>,
    /// Captured request headers (lowercased keys, truncated and
    /// optionally PII-redacted values). Empty when capture is off or
    /// no allowlisted header was present on the request.
    pub(super) request_headers: std::collections::BTreeMap<String, String>,
    /// Captured response headers; same semantics as
    /// `request_headers`. Empty when no response was written (early
    /// abort) or no allowlisted header was set on the response.
    pub(super) response_headers: std::collections::BTreeMap<String, String>,
}

impl AccessLogContext {
    #[cfg(test)]
    pub(super) fn empty() -> Self {
        Self {
            envelope_request_id: None,
            user_id: None,
            user_id_source: None,
            session_id: None,
            parent_session_id: None,
            properties: std::collections::BTreeMap::new(),
            workspace_id: String::new(),
            tenant_id: String::new(),
            auth_type: None,
            principal_kind: None,
            served_from_cache: None,
            fallback_triggered: None,
            retry_count: None,
            forward_rule_idx: None,
            request_geo: None,
            classifier_prompt: None,
            classifier_intent: None,
            error_class: None,
            auth_ms: None,
            upstream_ttfb_ms: None,
            response_filter_ms: None,
            bytes_in: 0,
            bytes_out: 0,
            provider: None,
            model: None,
            prompt_name: None,
            prompt_version: None,
            project: None,
            user: None,
            metadata: std::collections::HashMap::new(),
            tokens_in: None,
            tokens_out: None,
            ai_surface: None,
            cache_result: None,
            tier: None,
            shape: None,
            price: None,
            currency: None,
            rail: None,
            redeemed_token_id: None,
            txhash: None,
            license_token_id: None,
            cap_token_id: None,
            upstream_host: None,
            request_headers: std::collections::BTreeMap::new(),
            response_headers: std::collections::BTreeMap::new(),
        }
    }
}

/// Compact stable label for the prompt classifier verdict. The full
/// score map lives on the capture envelope event; the access log only
/// carries the top label so downstream ML pipelines have a bounded
/// feature dimension. Empty `labels` falls back to `"unknown"`.
pub(super) fn classifier_label(verdict: &crate::hooks::ClassifyVerdict) -> String {
    verdict
        .labels
        .first()
        .cloned()
        .unwrap_or_else(|| "unknown".to_string())
}

pub(super) fn intent_label(intent: crate::hooks::IntentCategory) -> String {
    format!("{intent:?}").to_ascii_lowercase()
}

/// Map a status code to a coarse failure label suitable for an ML
/// feature. `None` for 2xx; categorical strings otherwise. Specific
/// failure modes (waf_blocked, rate_limited, ...) are stamped at the
/// failure site via `ctx.short_circuit_status` paths; this fallback
/// only fires when no upstream classification ran.
pub(super) fn classify_error_class(status: u16) -> Option<String> {
    match status {
        200..=299 => None,
        401 | 403 => Some("auth_denied".to_string()),
        404 => Some("not_found".to_string()),
        429 => Some("rate_limited".to_string()),
        408 | 504 => Some("upstream_timeout".to_string()),
        500..=599 => Some("upstream_5xx".to_string()),
        400..=499 => Some("client_error".to_string()),
        _ => Some("other".to_string()),
    }
}

/// Pure builder + sampler that the logging hook (and unit tests) call.
/// Splits cleanly off `emit_access_log` so we can drive the emission
/// pipeline without a Pingora `Session`.
#[allow(clippy::too_many_arguments)]
pub(super) fn emit_access_log_entry(
    cfg: &sbproxy_config::AccessLogConfig,
    status: u16,
    method: &str,
    hostname: &str,
    path: &str,
    duration_secs: f64,
    request_id: String,
    client_ip: String,
    trace_id: Option<String>,
    http_fields: HttpFields,
    context: AccessLogContext,
) {
    let latency_ms = duration_secs * 1000.0;
    if !cfg.matches_filters(status, method) {
        return;
    }
    if !cfg.should_sample(status, latency_ms, rand::random::<f64>()) {
        return;
    }

    let mut entry = sbproxy_observe::AccessLogEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        request_id,
        origin: hostname.to_string(),
        method: method.to_string(),
        path: path.to_string(),
        query: http_fields.query,
        protocol: http_fields.protocol,
        scheme: http_fields.scheme,
        host: http_fields.host,
        user_agent: http_fields.user_agent,
        referer: http_fields.referer,
        status,
        upstream_status: http_fields.upstream_status,
        response_content_type: http_fields.response_content_type,
        response_content_encoding: http_fields.response_content_encoding,
        latency_ms,
        auth_ms: context.auth_ms,
        upstream_ttfb_ms: context.upstream_ttfb_ms,
        response_filter_ms: context.response_filter_ms,
        bytes_in: context.bytes_in,
        bytes_out: context.bytes_out,
        client_ip,
        provider: context.provider,
        model: context.model,
        prompt_name: context.prompt_name,
        prompt_version: context.prompt_version,
        project: context.project,
        user: context.user,
        metadata: context.metadata,
        tokens_in: context.tokens_in,
        tokens_out: context.tokens_out,
        ai_surface: context.ai_surface,
        trace_id,
        cache_result: context.cache_result,
        envelope_request_id: context.envelope_request_id,
        user_id: context.user_id,
        user_id_source: context.user_id_source,
        session_id: context.session_id,
        parent_session_id: context.parent_session_id,
        properties: context.properties,
        workspace_id: context.workspace_id,
        tenant_id: context.tenant_id,
        auth_type: context.auth_type,
        principal_kind: context.principal_kind,
        served_from_cache: context.served_from_cache,
        fallback_triggered: context.fallback_triggered,
        retry_count: context.retry_count,
        forward_rule_idx: context.forward_rule_idx,
        request_geo: context.request_geo,
        classifier_prompt: context.classifier_prompt,
        classifier_intent: context.classifier_intent,
        error_class: context.error_class,
        // Wave 1 / G1.6: per-agent dimensions. The agent-class
        // resolver lands the typed values on `context` in a
        // follow-up; until then the access log surfaces None and
        // dashboards keying on these fields treat the absence as
        // "unset".
        agent_id: None,
        agent_class: None,
        agent_vendor: None,
        payment_rail: None,
        content_shape: None,
        // Wave 6 / G6.2 access-log v1 fields. See the parent
        // `emit_access_log` for the per-field stamping commentary.
        tier: context.tier,
        shape: context.shape,
        price: context.price,
        currency: context.currency,
        rail: context.rail,
        redeemed_token_id: context.redeemed_token_id,
        txhash: context.txhash,
        license_token_id: context.license_token_id,
        cap_token_id: context.cap_token_id,
        upstream_host: context.upstream_host,
        request_headers: context.request_headers,
        response_headers: context.response_headers,
    };

    // WOR-118: extend the typed PII redactor to non-header fields when
    // the operator opts in via `capture_headers.redact_pii_other_fields`.
    // The cheap `redact_secrets` pass on the full JSON line still runs
    // unconditionally inside `entry.emit()` / `emit_to_file()`; this
    // step adds the broader email / phone / SSN / credit-card coverage
    // to the typed slots that previously relied on `redact_secrets`
    // alone (`path`, `user_id`, `properties` values, `model`).
    if cfg.capture_headers.redact_pii_other_fields {
        redact_pii_other_fields(&mut entry, &cfg.capture_headers.redact_pii_rules);
    }

    match cfg.output.output_type.as_str() {
        "file" => {
            if let Some(path) = cfg.output.path.as_deref() {
                let max_size_bytes = cfg
                    .output
                    .max_size_mb
                    .max(1)
                    .saturating_mul(1024)
                    .saturating_mul(1024);
                let max_backups = cfg.output.max_backups;
                let compress = cfg.output.compress;
                let path_buf = std::path::PathBuf::from(path);
                // WOR-618: per-request file writes (open, append, rotation,
                // gzip on rollover) issue blocking I/O. Dispatch to the
                // tokio blocking pool when a runtime is in scope so the
                // reactor thread keeps serving other requests; fall back
                // to inline execution from unit tests that drive this code
                // path without a runtime.
                if tokio::runtime::Handle::try_current().is_ok() {
                    let path_for_log = path_buf.clone();
                    tokio::task::spawn_blocking(move || {
                        if let Err(e) =
                            entry.emit_to_file(&path_buf, max_size_bytes, max_backups, compress)
                        {
                            tracing::warn!(
                                error = %e,
                                path = %path_for_log.display(),
                                "access log file write failed",
                            );
                        }
                    });
                } else if let Err(e) =
                    entry.emit_to_file(&path_buf, max_size_bytes, max_backups, compress)
                {
                    tracing::warn!(
                        error = %e,
                        path = %path_buf.display(),
                        "access log file write failed",
                    );
                }
            } else {
                tracing::warn!("access_log.output.type=file configured without output.path");
            }
        }
        _ => entry.emit(),
    }
}

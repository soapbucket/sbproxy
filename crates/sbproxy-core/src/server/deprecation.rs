//! First-class API deprecation (WOR-2565).
//!
//! Resolves which `deprecation:` announcement covers a request, builds
//! the RFC-mandated response headers, and decides the post-sunset
//! posture. Three sources feed the resolution, most specific first:
//!
//! 1. the matched forward rule's `deprecation:` block,
//! 2. the origin's `deprecation:` block,
//! 3. a spec-driven match staged by the `openapi_validation` policy's
//!    `deprecation_headers:` sub-block (see
//!    [`crate::context::SpecDeprecation`]).
//!
//! Header emission (all values precomputed at config compile in
//! `sbproxy_config::compile_deprecation`):
//!
//! - `Deprecation: @<unix>`, an RFC 9651 structured-field Date per
//!   RFC 9745. A bare `deprecated: true` emits no `Deprecation` header
//!   because the RFC requires a Date value.
//! - `Sunset: <HTTP-date>` per RFC 8594.
//! - `Link: <url>; rel="successor-version"` per RFC 5829 and
//!   `Link: <url>; rel="deprecation"` per RFC 9745, appended so an
//!   upstream's own `Link` headers survive.
//!
//! The route gate at the top of `handle_action` records
//! `sbproxy_deprecated_requests_total` for every request that settles
//! on a deprecated route and, when the block says `after_sunset: gone`,
//! refuses post-sunset requests with `410 Gone` and a JSON body naming
//! the successor. Stamping happens in both response paths: Pingora's
//! `response_filter` for proxied exchanges and
//! `apply_generated_response_phases` for locally generated ones, so
//! static, mock, and redirect origins announce exactly like proxied
//! ones.

use super::*;
use sbproxy_config::CompiledDeprecation;

/// The deprecation announcement that covers one settled route, plus
/// the metric labels describing which announcement it was.
pub(crate) struct ResolvedDeprecation<'a> {
    /// The compiled block whose headers apply.
    pub config: &'a CompiledDeprecation,
    /// `route` label for `sbproxy_deprecated_requests_total`: the
    /// forward rule's id (or index), the OpenAPI path template for a
    /// spec-driven match, or `""` for a whole-origin block.
    pub rule_label: String,
}

/// Resolve the deprecation announcement covering the settled route,
/// most specific source first: forward-rule block, origin block, then
/// the spec-driven match the `openapi_validation` enforcer staged.
///
/// A free function rather than a method so the config-reader guard can
/// see the `deprecation` field reads.
pub(crate) fn resolved_deprecation<'a>(
    pipeline: &'a CompiledPipeline,
    origin_idx: usize,
    forward_rule_idx: Option<usize>,
    spec: Option<&'a crate::context::SpecDeprecation>,
) -> Option<ResolvedDeprecation<'a>> {
    if let Some(rule_idx) = forward_rule_idx {
        if let Some(rule) = pipeline
            .forward_rules
            .get(origin_idx)
            .and_then(|rules| rules.get(rule_idx))
        {
            if let Some(config) = rule.deprecation.as_ref() {
                return Some(ResolvedDeprecation {
                    config,
                    rule_label: rule.id.clone().unwrap_or_else(|| rule_idx.to_string()),
                });
            }
        }
    }
    if let Some(config) = pipeline
        .config
        .origins
        .get(origin_idx)
        .and_then(|origin| origin.deprecation.as_ref())
    {
        return Some(ResolvedDeprecation {
            config,
            rule_label: String::new(),
        });
    }
    spec.map(|s| ResolvedDeprecation {
        config: &s.config,
        rule_label: s.template.clone(),
    })
}

/// Build the response headers a compiled announcement emits, in stamp
/// order. `Deprecation` and `Sunset` replace any upstream value of the
/// same name (the gateway is the authority on this origin's lifecycle);
/// `Link` entries are appended so upstream `Link` headers survive.
pub(crate) fn response_headers(dep: &CompiledDeprecation) -> Vec<(&'static str, String)> {
    let mut headers = Vec::with_capacity(4);
    if let Some(value) = dep.deprecation_header.as_ref() {
        headers.push(("deprecation", value.clone()));
    }
    if let Some(value) = dep.sunset_header.as_ref() {
        headers.push(("sunset", value.clone()));
    }
    if let Some(url) = dep.successor.as_ref() {
        headers.push(("link", format!("<{url}>; rel=\"successor-version\"")));
    }
    if let Some(url) = dep.link.as_ref() {
        headers.push(("link", format!("<{url}>; rel=\"deprecation\"")));
    }
    headers
}

/// Whether `now_unix` is past the announced sunset instant. `false`
/// when the block announces no sunset.
pub(crate) fn past_sunset(dep: &CompiledDeprecation, now_unix: i64) -> bool {
    dep.sunset_at.is_some_and(|sunset| now_unix >= sunset)
}

/// Whether a request arriving at `now_unix` gets refused with
/// `410 Gone`: only when the block says `after_sunset: gone` AND the
/// sunset instant has passed.
pub(crate) fn refuse_as_gone(dep: &CompiledDeprecation, now_unix: i64) -> bool {
    dep.gone_after_sunset && past_sunset(dep, now_unix)
}

/// Wall-clock unix seconds. The decision helpers above take the
/// instant as an argument so tests can inject one.
pub(crate) fn now_unix() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        // Saturate rather than `as`-wrap: a u64 seconds value past
        // i64::MAX is a broken clock, and saturating keeps it "far
        // future" instead of wrapping negative and un-sunsetting
        // every announcement.
        Ok(elapsed) => i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
        // Pre-epoch clocks exist only on broken hardware; treating
        // them as the epoch keeps every announcement in the future,
        // which fails open (serve, no past_sunset) rather than closed.
        Err(_) => 0,
    }
}

/// The `410 Gone` body for a post-sunset refusal: names the sunset
/// instant and, when configured, the successor and documentation URLs
/// so the refusal itself tells the caller where to go.
pub(crate) fn gone_body(dep: &CompiledDeprecation) -> serde_json::Value {
    let mut body = serde_json::Map::new();
    body.insert("error".to_string(), serde_json::json!("gone"));
    body.insert(
        "message".to_string(),
        serde_json::json!("This API has been retired."),
    );
    if let Some(sunset) = dep.sunset_header.as_ref() {
        body.insert("sunset".to_string(), serde_json::json!(sunset));
    }
    if let Some(successor) = dep.successor.as_ref() {
        body.insert("successor".to_string(), serde_json::json!(successor));
    }
    if let Some(link) = dep.link.as_ref() {
        body.insert("link".to_string(), serde_json::json!(link));
    }
    serde_json::Value::Object(body)
}

/// Stable `event_type` for a post-sunset refusal, on the audit record
/// and on any SIEM rule written against it.
const GONE_AUDIT_EVENT_TYPE: &str = "api_deprecation";

/// Log and audit one `410 Gone` refusal.
///
/// Shaped exactly like the other proxy refusals that reach a SIEM (see
/// `body_threat_protection` in `proxy_http.rs`): a `policy_violation`
/// entry chaining tenant, key context, and the accountable key id, so a
/// rule shaped "which key is still calling the retired API" has
/// something to key on.
///
/// `reason` is proxy-authored and reaches third-party webhook sinks
/// verbatim through the `policy_denied` bridge, so it is built from a
/// constant, the compiled sunset string, and the announcement's rule
/// label. All three come from the operator's own config or from a spec
/// the operator loaded; no request byte reaches it.
fn audit_gone_refusal(
    ctx: &RequestContext,
    resolved: &ResolvedDeprecation<'_>,
    method: Option<&str>,
    now: i64,
) {
    let rule = if resolved.rule_label.is_empty() {
        "<origin>"
    } else {
        resolved.rule_label.as_str()
    };
    let sunset = resolved.config.sunset_header.as_deref().unwrap_or("unset");
    warn!(
        target: "sbproxy::api_deprecation",
        hostname = %ctx.hostname,
        tenant = %ctx.tenant_id,
        request_id = %ctx.request_id,
        rule,
        sunset,
        now,
        "refused: this route is past its announced sunset and the origin says after_sunset: gone"
    );
    sbproxy_observe::SecurityAuditEntry::policy_violation(
        GONE_AUDIT_EVENT_TYPE,
        format!("route retired at sunset {sunset}; announcement: {rule}"),
        410,
        Some(ctx.hostname.to_string()),
        ctx.client_ip,
        Some(ctx.request_id.to_string()),
        method.map(str::to_string),
    )
    .with_tenant_id(ctx.tenant_id.to_string())
    .with_key_context(
        ctx.native_key_provider.clone(),
        ctx.inbound_key_mode.as_str(),
    )
    .with_api_key_id(ctx.accountable_key_id())
    .emit();
}

/// Route-settlement gate, called once per request from the top of
/// `handle_action` (both settlement sites route through it: a matched
/// forward rule and the origin's own action).
///
/// Records `sbproxy_deprecated_requests_total` for every request that
/// settles on a deprecated route, and refuses post-sunset requests
/// with `410 Gone` when the covering block says `after_sunset: gone`.
/// Returns `Ok(true)` when the 410 was written (short-circuit),
/// `Ok(false)` to continue serving.
///
/// The refusal is enforcement, so it reaches the evidence channels every
/// other proxy refusal reaches rather than only the counter: a
/// [`sbproxy_observe::SecurityAuditEntry::policy_violation`] carries it
/// to the `security_audit` tracing target, the admin console's audit
/// ring, the hash-chained file under `audit.sink: chain`, and the
/// `events:` egress as a `policy_denied` event, and a `warn!` names the
/// origin and the announcement in the ordinary log. Without them an
/// operator asked "who did we cut off, and when" had only
/// `sbproxy_requests_total{status="410"}`, which cannot tell a gateway
/// refusal from an upstream 410.
pub(crate) async fn enforce_at_route(
    session: &mut Session,
    pipeline: &CompiledPipeline,
    origin_idx: usize,
    ctx: &mut RequestContext,
) -> Result<bool> {
    let now = now_unix();
    let body_bytes = {
        let Some(resolved) = resolved_deprecation(
            pipeline,
            origin_idx,
            ctx.forward_rule_idx,
            ctx.openapi_deprecation.as_ref(),
        ) else {
            return Ok(false);
        };
        let gone = refuse_as_gone(resolved.config, now);
        // `ctx.hostname` rather than the configured `origin.hostname`,
        // so this family's `origin` label means what it means on
        // `sbproxy_requests_total`. Under a wildcard origin the two
        // differ, and the migration tracker an operator actually writes,
        // `sum by (origin) (rate(deprecated[5m])) / sum by (origin)
        // (rate(requests[5m]))`, joins on the label rather than on the
        // config.
        sbproxy_observe::metrics::record_deprecated_request(
            ctx.hostname.as_str(),
            &resolved.rule_label,
            past_sunset(resolved.config, now),
            gone,
        );
        if !gone {
            return Ok(false);
        }
        audit_gone_refusal(
            ctx,
            &resolved,
            Some(session.req_header().method.as_str()),
            now,
        );
        gone_body(resolved.config).to_string().into_bytes()
    };

    let mut header = pingora_http::ResponseHeader::build(410, Some(4)).map_err(|e| {
        Error::because(
            ErrorType::InternalError,
            "failed to build 410 Gone header",
            e,
        )
    })?;
    header
        .insert_header("content-type", "application/json")
        .map_err(|e| Error::because(ErrorType::InternalError, "failed to set content-type", e))?;
    header
        .insert_header("content-length", body_bytes.len().to_string())
        .map_err(|e| Error::because(ErrorType::InternalError, "failed to set content-length", e))?;
    ctx.response_status = Some(410);
    // Response-phase policies, cookies, and the deprecation headers
    // themselves apply to the refusal exactly as they would to any
    // other generated response.
    apply_generated_response_phases(
        session,
        ctx,
        pipeline,
        Some(origin_idx),
        &mut header,
        &body_bytes,
    );
    session
        .write_response_header(Box::new(header), false)
        .await?;
    session
        .write_response_body(Some(bytes::Bytes::from(body_bytes)), true)
        .await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_config::{compile_deprecation, DeprecationConfig};

    fn compiled(yaml: &str) -> CompiledDeprecation {
        let raw: DeprecationConfig = serde_yaml::from_str(yaml).expect("fixture block parses");
        compile_deprecation(&raw, "test fixture").expect("fixture block compiles")
    }

    #[test]
    fn full_block_emits_all_four_headers_byte_exact() {
        let dep = compiled(
            r#"
deprecated: 2026-09-01
sunset: 2026-12-31T23:59:59Z
successor: https://api.example.com/v2/
link: https://developer.example.com/deprecation
"#,
        );
        assert_eq!(
            response_headers(&dep),
            vec![
                // 2026-09-01T00:00:00Z
                ("deprecation", "@1788220800".to_string()),
                ("sunset", "Thu, 31 Dec 2026 23:59:59 GMT".to_string()),
                (
                    "link",
                    "<https://api.example.com/v2/>; rel=\"successor-version\"".to_string()
                ),
                (
                    "link",
                    "<https://developer.example.com/deprecation>; rel=\"deprecation\"".to_string()
                ),
            ],
        );
    }

    #[test]
    fn bare_true_emits_no_deprecation_header_but_sunset_still_emits() {
        // RFC 9745 requires a Date value; the draft-era literal `true`
        // did not survive into the RFC, so a bare flag drives metrics
        // and spec emission only.
        let dep = compiled("deprecated: true\nsunset: 2027-01-01\n");
        let headers = response_headers(&dep);
        assert!(
            !headers.iter().any(|(name, _)| *name == "deprecation"),
            "bare `deprecated: true` must not emit a Deprecation header: {headers:?}"
        );
        assert!(
            headers
                .iter()
                .any(|(name, value)| *name == "sunset" && value == "Fri, 01 Jan 2027 00:00:00 GMT"),
            "sunset must still emit: {headers:?}"
        );
    }

    #[test]
    fn past_sunset_flips_with_the_injected_clock() {
        let dep = compiled("deprecated: 2026-09-01\nsunset: 2026-12-31T23:59:59Z\n");
        let sunset_unix = dep.sunset_at.expect("sunset parsed");
        assert!(!past_sunset(&dep, sunset_unix - 1));
        assert!(past_sunset(&dep, sunset_unix));
        assert!(past_sunset(&dep, sunset_unix + 1));
    }

    #[test]
    fn no_sunset_is_never_past_sunset() {
        let dep = compiled("deprecated: 2020-01-01\n");
        assert!(!past_sunset(&dep, i64::MAX));
    }

    #[test]
    fn default_posture_serves_past_sunset_and_gone_refuses() {
        let serve = compiled("deprecated: 2020-01-01\nsunset: 2020-06-01\n");
        let gone = compiled("deprecated: 2020-01-01\nsunset: 2020-06-01\nafter_sunset: gone\n");
        let sunset_unix = serve.sunset_at.expect("sunset parsed");
        // Past the instant: the default posture keeps serving, the
        // explicit `gone` posture refuses.
        assert!(!refuse_as_gone(&serve, sunset_unix + 1));
        assert!(refuse_as_gone(&gone, sunset_unix + 1));
        // Before the instant nobody refuses.
        assert!(!refuse_as_gone(&gone, sunset_unix - 1));
    }

    #[test]
    fn gone_body_names_the_successor() {
        let dep = compiled(
            "deprecated: 2020-01-01\nsunset: 2020-06-01\nafter_sunset: gone\nsuccessor: https://api.example.com/v2/\n",
        );
        let body = gone_body(&dep);
        assert_eq!(body["error"], "gone");
        assert_eq!(body["successor"], "https://api.example.com/v2/");
        assert_eq!(body["sunset"], "Mon, 01 Jun 2020 00:00:00 GMT");
    }

    /// Fix round on the #1177 review, red-first: the `410 Gone`
    /// refusal produced a counter and nothing else. No audit record, no
    /// event, no log line at any level, while its sibling refusal in
    /// the same union (`body_threat_protection`'s 400) emits a
    /// `policy_violation` that bridges to `policy_denied` on the
    /// `events:` feed.
    ///
    /// An operator asked "who did we cut off, and when" had only
    /// `sbproxy_requests_total{status="410"}`, which cannot tell a
    /// gateway refusal from an upstream 410. This asserts the record
    /// reaches the normalized channel with the attribution a SIEM rule
    /// needs, and that its reason names the announcement rather than
    /// echoing anything the caller sent.
    #[test]
    fn a_gone_refusal_reaches_the_audit_channel_with_attribution() {
        const REQUEST_ID: &str = "req-gone-audit-1";
        let dep = compiled(
            "deprecated: 2020-01-01\nsunset: 2020-06-01\nafter_sunset: gone\nsuccessor: https://api.example.com/v2/\n",
        );
        let resolved = ResolvedDeprecation {
            config: &dep,
            rule_label: "legacy-v1".to_string(),
        };
        let mut ctx = RequestContext::new();
        ctx.hostname = "api.local".into();
        ctx.tenant_id = "acme".into();
        ctx.request_id = REQUEST_ID.into();
        ctx.client_ip = Some("203.0.113.9".parse().expect("test ip"));

        audit_gone_refusal(&ctx, &resolved, Some("GET"), 1_600_000_000);

        let events = sbproxy_observe::audit_ring::recent_audit_events(
            64,
            Some("security"),
            Some(GONE_AUDIT_EVENT_TYPE),
            None,
        );
        let entry = events
            .iter()
            .find(|event| event.request_id.as_deref() == Some(REQUEST_ID))
            .expect(
                "a 410 refusal must reach the security audit channel; a refusal nobody can see \
                 is not enforcement",
            );
        assert_eq!(entry.tenant_id.as_deref(), Some("acme"));
        let detail = entry.detail.as_deref().unwrap_or_default();
        assert!(
            detail.contains("Mon, 01 Jun 2020 00:00:00 GMT"),
            "the reason must name the sunset that retired the route: {detail}"
        );
        assert!(
            detail.contains("legacy-v1"),
            "the reason must name which announcement refused: {detail}"
        );
    }

    /// The whole-origin announcement has no rule id, and the record
    /// still has to say which announcement fired rather than leaving
    /// the field blank in a SIEM.
    #[test]
    fn a_whole_origin_gone_refusal_names_the_origin_announcement() {
        const REQUEST_ID: &str = "req-gone-audit-2";
        let dep = compiled("deprecated: 2020-01-01\nsunset: 2020-06-01\nafter_sunset: gone\n");
        let resolved = ResolvedDeprecation {
            config: &dep,
            rule_label: String::new(),
        };
        let mut ctx = RequestContext::new();
        ctx.hostname = "api.local".into();
        ctx.request_id = REQUEST_ID.into();

        audit_gone_refusal(&ctx, &resolved, Some("POST"), 1_600_000_000);

        let events = sbproxy_observe::audit_ring::recent_audit_events(
            64,
            Some("security"),
            Some(GONE_AUDIT_EVENT_TYPE),
            None,
        );
        let entry = events
            .iter()
            .find(|event| event.request_id.as_deref() == Some(REQUEST_ID))
            .expect("the whole-origin refusal is audited too");
        assert!(
            entry
                .detail
                .as_deref()
                .unwrap_or_default()
                .contains("<origin>"),
            "an origin-wide announcement is named, not left empty: {:?}",
            entry.detail
        );
    }
}

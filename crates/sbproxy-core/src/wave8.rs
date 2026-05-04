// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Soap Bucket LLC

//! Wave 8 P0 edge capture wired into the Pingora request pipeline.
//!
//! `capture_dimensions` reads the four caller-supplied envelope
//! dimensions (custom properties, session ID, parent session ID, user
//! ID) from inbound headers and stamps them onto the per-request
//! [`crate::context::RequestContext`]. It is called from
//! `server::request_filter` immediately after request-id minting and
//! the trust-boundary header strip.
//!
//! ADR refs:
//!
//! * `docs/adr-event-envelope.md` (T5.1) - canonical envelope shape.
//! * `docs/adr-custom-properties.md` (T1.1) - properties caps, allowlist,
//!   redaction.
//! * `docs/adr-session-id.md` (T2.1) - ULID validation, AutoGenerate
//!   policy.
//! * `docs/adr-user-id.md` (T3.1) - resolution precedence.
//!
//! ## Auth-source plumbing for `user_id`
//!
//! The user-id ADR specifies three sources in precedence order:
//! `X-Sb-User-Id` header, JWT `sub` claim, forward-auth trust header.
//! All three are wired today: the auth providers stamp the resolved
//! subject onto [`sbproxy_plugin::AuthDecision::Allow`], the server
//! pipeline stores that decision on `RequestContext::auth_result`,
//! and `request_filter` reads it back into the
//! `(jwt_sub, forward_auth_user)` arguments before invoking
//! `capture_dimensions`.

use http::HeaderMap;
use sbproxy_observe::{
    capture_parent_session_id, capture_properties, capture_session_id, capture_user_id,
    dispatch_request_event, EventType, PropertiesConfig, RequestEvent, SessionsConfig, UserConfig,
};
use ulid::Ulid;

use crate::context::RequestContext;

/// Capture all four Wave 8 dimensions and stamp them on the context.
///
/// Order matters: user_id resolves first so the
/// `auto_generate: Anonymous` session policy can see whether a user
/// was identified. Properties and parent-session capture run in
/// parallel because they don't depend on either.
///
/// `jwt_sub` and `forward_auth_user` carry the subject the auth
/// providers extracted; the user-id resolver respects the
/// `header > jwt > forward_auth` precedence locked by the ADR.
///
/// `workspace_id` feeds the T2.3 / T3.3 budget gate inside the
/// observe layer (cap on auto-generated session IDs and user IDs per
/// workspace per window). Pass [`DEFAULT_WORKSPACE_ID`] for
/// single-tenant OSS deployments.
///
/// Drop counters from the helpers are not surfaced here; the
/// dispatching counter wire-up lives in a follow-up slice that hooks
/// into the Prometheus registry directly.
// The dimension count is locked by the Wave 8 envelope schema:
// properties + sessions + users + workspace + auth-source pair are
// all mandatory inputs to the capture pipeline. Bundling them into
// a struct would obscure the call sites without removing any of the
// state, so the lint is intentionally relaxed here.
#[allow(clippy::too_many_arguments)]
pub fn capture_dimensions(
    ctx: &mut RequestContext,
    headers: &HeaderMap,
    properties_cfg: &PropertiesConfig,
    sessions_cfg: &SessionsConfig,
    user_cfg: &UserConfig,
    jwt_sub: Option<&str>,
    forward_auth_user: Option<&str>,
    workspace_id: &str,
) {
    // Mint the envelope's ULID alongside the existing UUID-based
    // ctx.request_id. The UUID continues to feed the correlation
    // header / webhook envelopes / access logs (callers depend on its
    // 32-hex format); the ULID feeds the Wave 8 envelope which the
    // enterprise ingest pipeline consumes verbatim.
    if ctx.envelope_request_id.is_none() {
        ctx.envelope_request_id = Some(Ulid::new());
    }

    // T1.2: properties capture. The echo flag lifts onto the
    // context so response_filter can stamp X-Sb-Property-* response
    // headers without a second config lookup.
    let (props, prop_drops) = capture_properties(headers, properties_cfg);
    ctx.properties = props;
    ctx.properties_echo = properties_cfg.echo;
    sbproxy_observe::metrics::record_capture_drop(
        workspace_id,
        "property",
        "count",
        prop_drops.count as u64,
    );
    sbproxy_observe::metrics::record_capture_drop(
        workspace_id,
        "property",
        "key_len",
        prop_drops.key_len as u64,
    );
    sbproxy_observe::metrics::record_capture_drop(
        workspace_id,
        "property",
        "value_len",
        prop_drops.value_len as u64,
    );
    sbproxy_observe::metrics::record_capture_drop(
        workspace_id,
        "property",
        "payload_size",
        prop_drops.payload_size as u64,
    );
    sbproxy_observe::metrics::record_capture_drop(
        workspace_id,
        "property",
        "regex",
        prop_drops.regex as u64,
    );

    // T3.2: user_id resolution. Header > JWT > forward-auth per the
    // ADR.
    let (user, user_drops) =
        capture_user_id(headers, jwt_sub, forward_auth_user, user_cfg, workspace_id);
    if let Some((id, src)) = user {
        ctx.user_id = Some(id);
        ctx.user_id_source = Some(src);
    }
    sbproxy_observe::metrics::record_capture_drop(
        workspace_id,
        "user",
        "length",
        user_drops.length as u64,
    );
    sbproxy_observe::metrics::record_capture_drop(
        workspace_id,
        "user",
        "empty",
        user_drops.empty as u64,
    );

    // T2.2: session_id capture. The Anonymous auto-generate policy
    // depends on whether user_id resolved; pass that signal in.
    let user_resolved = ctx.user_id.is_some();
    let (sid, sess_drops) = capture_session_id(headers, sessions_cfg, user_resolved, workspace_id);
    ctx.session_id = sid;
    sbproxy_observe::metrics::record_capture_drop(
        workspace_id,
        "session",
        "invalid_format",
        sess_drops.invalid_format as u64,
    );
    sbproxy_observe::metrics::record_capture_drop(
        workspace_id,
        "session",
        "too_long",
        sess_drops.too_long as u64,
    );
    sbproxy_observe::metrics::record_capture_drop(
        workspace_id,
        "session",
        "empty",
        sess_drops.empty as u64,
    );

    let (psid, parent_drops) = capture_parent_session_id(headers);
    ctx.parent_session_id = psid;
    sbproxy_observe::metrics::record_capture_drop(
        workspace_id,
        "parent_session",
        "invalid_format",
        parent_drops.invalid_format as u64,
    );
    sbproxy_observe::metrics::record_capture_drop(
        workspace_id,
        "parent_session",
        "too_long",
        parent_drops.too_long as u64,
    );
    sbproxy_observe::metrics::record_capture_drop(
        workspace_id,
        "parent_session",
        "empty",
        parent_drops.empty as u64,
    );
}

/// Default workspace identifier used by single-tenant OSS deployments.
/// Enterprise deployments override this via per-origin config (a
/// follow-up slice plumbs the override through `sb.yml`).
pub const DEFAULT_WORKSPACE_ID: &str = "default";

/// Build the terminal `RequestEvent` from collected context state and
/// hand it to the registered [`sbproxy_observe::RequestEventSink`].
///
/// Called from `server::logging` after status, latency, and error
/// state are known. When no sink has been registered, dispatch is a
/// no-op (the OSS default); enterprise startup wires a real sink.
///
/// `error_class` is supplied by the caller when the request
/// terminated with an error so the consumer can route by failure mode
/// without parsing log lines.
pub fn dispatch_terminal_event(
    ctx: &RequestContext,
    workspace_id: &str,
    latency_ms: Option<u32>,
    error_class: Option<&str>,
) {
    // We need a ULID; if request_filter never minted one (the
    // capture path was skipped, e.g. on a very early short-circuit
    // before the trust-boundary block) we cannot meaningfully publish
    // an envelope event, so we drop quietly.
    let Some(request_id) = ctx.envelope_request_id else {
        return;
    };

    let event_type = if error_class.is_some() {
        EventType::RequestError
    } else {
        EventType::RequestCompleted
    };

    let mut ev = RequestEvent::new_started(
        ctx.hostname.to_string(),
        request_id,
        workspace_id.to_string(),
    );
    ev.event_type = event_type;
    ev.latency_ms = latency_ms;
    ev.session_id = ctx.session_id;
    ev.parent_session_id = ctx.parent_session_id;
    ev.user_id = ctx.user_id.clone();
    ev.user_id_source = ctx.user_id_source;
    ev.properties = ctx.properties.clone();
    ev.status_code = ctx.response_status;
    ev.error_class = error_class.map(str::to_string);
    ev.request_geo = ctx.request_geo.clone();

    dispatch_request_event(ev);
}

#[cfg(test)]
mod dispatch_tests {
    use super::*;
    use sbproxy_observe::{
        set_request_event_sink, RequestEvent as ObsRequestEvent, RequestEventSink,
    };
    use std::sync::{Arc, Mutex};

    /// Process-wide global; see the comment in `dispatch_round_trip`.
    static CAPTURED: Mutex<Vec<ObsRequestEvent>> = Mutex::new(Vec::new());

    struct TestSink;

    impl RequestEventSink for TestSink {
        fn publish(&self, event: ObsRequestEvent) {
            CAPTURED.lock().expect("test sink lock").push(event);
        }
    }

    /// The dispatch test must run alone because the sink registry is
    /// a process-wide `OnceLock` set at most once. We register `TestSink`
    /// here and rely on test execution order being deterministic
    /// within a single test binary; if other tests need a different
    /// sink they should not share this binary.
    #[test]
    fn dispatch_round_trip() {
        // Set the sink. If another test in this binary already set
        // one, accept the existing registration and trust that it is
        // ours from a previous invocation.
        let _ = set_request_event_sink(Arc::new(TestSink));

        let mut ctx = RequestContext::new();
        ctx.envelope_request_id = Some(Ulid::new());
        ctx.hostname = compact_str::CompactString::new("api.example.com");
        ctx.response_status = Some(200);
        ctx.user_id = Some("u".to_string());

        CAPTURED.lock().expect("test sink lock").clear();
        dispatch_terminal_event(&ctx, DEFAULT_WORKSPACE_ID, Some(42), None);

        let captured = CAPTURED.lock().expect("test sink lock");
        assert_eq!(captured.len(), 1, "sink must receive exactly one event");
        let ev = &captured[0];
        assert_eq!(ev.workspace_id, DEFAULT_WORKSPACE_ID);
        assert_eq!(ev.hostname, "api.example.com");
        assert_eq!(ev.latency_ms, Some(42));
        assert_eq!(ev.status_code, Some(200));
        assert_eq!(ev.user_id.as_deref(), Some("u"));
        assert!(matches!(ev.event_type, EventType::RequestCompleted));
    }

    #[test]
    fn dispatch_skipped_when_envelope_request_id_unset() {
        // Cover the early-short-circuit branch: when capture never
        // ran, we have no ULID, so we skip dispatch entirely rather
        // than emit a malformed event.
        let _ = set_request_event_sink(Arc::new(TestSink));
        CAPTURED.lock().expect("test sink lock").clear();

        let ctx = RequestContext::new(); // envelope_request_id stays None
        dispatch_terminal_event(&ctx, DEFAULT_WORKSPACE_ID, Some(0), None);

        assert!(
            CAPTURED.lock().expect("test sink lock").is_empty(),
            "no envelope request id => no event dispatched"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, HeaderName, HeaderValue};
    use sbproxy_observe::{AutoGenerate, UserIdSource};
    use ulid::Ulid;

    fn headers_from(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (n, v) in pairs {
            h.append(
                HeaderName::from_bytes(n.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn ulid_str() -> String {
        Ulid::new().to_string()
    }

    #[test]
    fn fully_anonymous_request_auto_generates_session_only() {
        let mut ctx = RequestContext::new();
        let headers = HeaderMap::new();
        capture_dimensions(
            &mut ctx,
            &headers,
            &PropertiesConfig::default(),
            &SessionsConfig::default(),
            &UserConfig::default(),
            None,
            None,
            DEFAULT_WORKSPACE_ID,
        );

        assert!(ctx.user_id.is_none());
        assert!(ctx.user_id_source.is_none());
        assert!(ctx.parent_session_id.is_none());
        assert!(ctx.properties.is_empty());
        // Anonymous + no user resolved -> session auto-generated.
        assert!(ctx.session_id.is_some());
    }

    #[test]
    fn authenticated_request_does_not_auto_generate_session() {
        let mut ctx = RequestContext::new();
        let headers = headers_from(&[("X-Sb-User-Id", "user_42")]);
        capture_dimensions(
            &mut ctx,
            &headers,
            &PropertiesConfig::default(),
            &SessionsConfig::default(),
            &UserConfig::default(),
            None,
            None,
            DEFAULT_WORKSPACE_ID,
        );

        assert_eq!(ctx.user_id.as_deref(), Some("user_42"));
        assert_eq!(ctx.user_id_source, Some(UserIdSource::Header));
        // Anonymous policy + user resolved -> no session unless caller supplied one.
        assert!(ctx.session_id.is_none());
    }

    #[test]
    fn caller_supplied_session_survives_auto_generate_off() {
        let mut ctx = RequestContext::new();
        let id = ulid_str();
        let headers = headers_from(&[("X-Sb-Session-Id", id.as_str())]);
        let cfg = SessionsConfig {
            auto_generate: AutoGenerate::Never,
            ..SessionsConfig::default()
        };
        capture_dimensions(
            &mut ctx,
            &headers,
            &PropertiesConfig::default(),
            &cfg,
            &UserConfig::default(),
            None,
            None,
            DEFAULT_WORKSPACE_ID,
        );
        assert_eq!(ctx.session_id.unwrap().to_string(), id);
    }

    #[test]
    fn parent_session_captured_from_header() {
        let mut ctx = RequestContext::new();
        let pid = ulid_str();
        let headers = headers_from(&[("X-Sb-Parent-Session-Id", pid.as_str())]);
        capture_dimensions(
            &mut ctx,
            &headers,
            &PropertiesConfig::default(),
            &SessionsConfig::default(),
            &UserConfig::default(),
            None,
            None,
            DEFAULT_WORKSPACE_ID,
        );
        assert_eq!(ctx.parent_session_id.unwrap().to_string(), pid);
    }

    #[test]
    fn properties_captured_into_context() {
        let mut ctx = RequestContext::new();
        let headers = headers_from(&[
            ("X-Sb-Property-Environment", "prod"),
            ("X-Sb-Property-Customer-Tier", "enterprise"),
        ]);
        capture_dimensions(
            &mut ctx,
            &headers,
            &PropertiesConfig::default(),
            &SessionsConfig::default(),
            &UserConfig::default(),
            None,
            None,
            DEFAULT_WORKSPACE_ID,
        );

        assert_eq!(ctx.properties.len(), 2);
        assert_eq!(ctx.properties.get("environment").unwrap(), "prod");
        assert_eq!(ctx.properties.get("customer-tier").unwrap(), "enterprise");
    }

    #[test]
    fn properties_echo_flag_propagates_to_context() {
        let mut ctx = RequestContext::new();
        let headers = headers_from(&[("X-Sb-Property-Environment", "prod")]);
        let cfg = PropertiesConfig {
            echo: true,
            ..PropertiesConfig::default()
        };
        capture_dimensions(
            &mut ctx,
            &headers,
            &cfg,
            &SessionsConfig::default(),
            &UserConfig::default(),
            None,
            None,
            DEFAULT_WORKSPACE_ID,
        );
        assert!(ctx.properties_echo, "echo flag must lift onto context");
    }

    #[test]
    fn properties_echo_default_off() {
        let mut ctx = RequestContext::new();
        let headers = headers_from(&[("X-Sb-Property-Environment", "prod")]);
        capture_dimensions(
            &mut ctx,
            &headers,
            &PropertiesConfig::default(),
            &SessionsConfig::default(),
            &UserConfig::default(),
            None,
            None,
            DEFAULT_WORKSPACE_ID,
        );
        assert!(
            !ctx.properties_echo,
            "echo defaults off so properties never leak by accident"
        );
    }

    #[test]
    fn jwt_sub_resolves_user_when_no_header() {
        let mut ctx = RequestContext::new();
        let headers = HeaderMap::new();
        capture_dimensions(
            &mut ctx,
            &headers,
            &PropertiesConfig::default(),
            &SessionsConfig::default(),
            &UserConfig::default(),
            Some("subject-from-token"),
            None,
            DEFAULT_WORKSPACE_ID,
        );
        assert_eq!(ctx.user_id.as_deref(), Some("subject-from-token"));
        assert_eq!(ctx.user_id_source, Some(UserIdSource::Jwt));
    }

    #[test]
    fn forward_auth_resolves_user_when_no_header_no_jwt() {
        let mut ctx = RequestContext::new();
        let headers = HeaderMap::new();
        capture_dimensions(
            &mut ctx,
            &headers,
            &PropertiesConfig::default(),
            &SessionsConfig::default(),
            &UserConfig::default(),
            None,
            Some("user-from-fa"),
            DEFAULT_WORKSPACE_ID,
        );
        assert_eq!(ctx.user_id.as_deref(), Some("user-from-fa"));
        assert_eq!(ctx.user_id_source, Some(UserIdSource::ForwardAuth));
    }

    #[test]
    fn header_wins_precedence_over_jwt_and_forward_auth() {
        let mut ctx = RequestContext::new();
        let headers = headers_from(&[("X-Sb-User-Id", "header-wins")]);
        capture_dimensions(
            &mut ctx,
            &headers,
            &PropertiesConfig::default(),
            &SessionsConfig::default(),
            &UserConfig::default(),
            Some("from-jwt"),
            Some("from-fa"),
            DEFAULT_WORKSPACE_ID,
        );
        assert_eq!(ctx.user_id.as_deref(), Some("header-wins"));
        assert_eq!(ctx.user_id_source, Some(UserIdSource::Header));
    }
}

//! Newtype wrapper enforcer for the `Policy::UserAgent` variant.
//!
//! Parses the request's `User-Agent` header via
//! [`sbproxy_modules::ParsedUserAgent::parse`], stamps the result
//! onto [`RequestContext::parsed_user_agent`] for
//! `sbproxy_plugin::RequestContextView` consumers, and (when
//! `inject` is set) serializes it as JSON onto
//! [`RequestContext::trust_headers`] under the configured header
//! name.
//!
//! Never denies: an absent or unparseable `User-Agent` header still
//! produces a (mostly empty) [`sbproxy_modules::ParsedUserAgent`] and
//! falls through to [`PolicyDecision::Allow`].

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};

use bytes::Bytes;
use prometheus::{register_int_counter_vec, IntCounterVec};
use sbproxy_modules::{ParsedUserAgent, UserAgentPolicy};
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use super::registered;
use crate::context::RequestContext;

/// Newtype wrapper that adapts [`UserAgentPolicy`] to the
/// [`PolicyEnforcer`] trait surface.
pub struct UserAgentEnforcer(pub Arc<UserAgentPolicy>);

/// User-Agent parses, labeled by `device_type`. The label is drawn
/// from the fixed set `ParsedUserAgent::device_type` returns
/// (`desktop`, `mobile`, `tablet`, `bot`, `unknown`), never from the
/// header, so a caller cannot drive its cardinality.
static PARSE_TOTAL: LazyLock<Option<IntCounterVec>> = LazyLock::new(|| {
    registered(
        register_int_counter_vec!(
            "sbproxy_user_agent_parse_total",
            "user_agent_parser policy runs, labeled by device_type",
            &["device_type"],
        ),
        "sbproxy_user_agent_parse_total",
    )
});

/// Headless-automation-library detections, labeled by `library`. Same
/// cardinality argument as `PARSE_TOTAL`: the label is one of the five
/// known tokens the parser matches, never the raw header.
static HEADLESS_TOTAL: LazyLock<Option<IntCounterVec>> = LazyLock::new(|| {
    registered(
        register_int_counter_vec!(
            "sbproxy_user_agent_headless_total",
            "user_agent_parser headless-automation-library detections, labeled by library",
            &["library"],
        ),
        "sbproxy_user_agent_headless_total",
    )
});

impl PolicyEnforcer for UserAgentEnforcer {
    fn policy_type(&self) -> &'static str {
        "user_agent_parser"
    }

    fn enforce(
        &self,
        req: &http::Request<Bytes>,
        ctx: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn Future<Output = sbproxy_plugin::PluginResult<PolicyDecision>> + Send + '_>>
    {
        let policy = Arc::clone(&self.0);
        let ctx = match ctx.downcast_mut::<RequestContext>() {
            Some(c) => c,
            None => {
                return Box::pin(async move { Ok(PolicyDecision::Allow) });
            }
        };

        let ua_str = req
            .headers()
            .get(http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let parsed = ParsedUserAgent::parse(ua_str);

        if let Some(counter) = PARSE_TOTAL.as_ref() {
            counter
                .with_label_values(&[parsed.device_type.as_str()])
                .inc();
        }
        if let Some(library) = parsed.headless_library.as_deref() {
            if let Some(counter) = HEADLESS_TOTAL.as_ref() {
                counter.with_label_values(&[library]).inc();
            }
        }

        tracing::debug!(
            browser = %parsed.browser_name,
            browser_version = %parsed.browser_version,
            os = %parsed.os_name,
            os_version = %parsed.os_version,
            device_type = %parsed.device_type,
            headless_library = ?parsed.headless_library,
            "user_agent_parser policy: parse completed"
        );

        if policy.inject {
            if let Ok(json) = serde_json::to_string(&parsed) {
                let entry = (policy.inject_header.clone(), json);
                match ctx.trust_headers.as_mut() {
                    Some(v) => v.push(entry),
                    None => ctx.trust_headers = Some(vec![entry]),
                }
            }
        }

        ctx.parsed_user_agent = Some(parsed);

        Box::pin(async move { Ok(PolicyDecision::Allow) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enforcer(inject: bool) -> UserAgentEnforcer {
        UserAgentEnforcer(Arc::new(UserAgentPolicy {
            inject_header: "x-parsed-ua".to_string(),
            inject,
        }))
    }

    #[tokio::test]
    async fn populates_context_and_injects_header_by_default() {
        let enforcer = enforcer(true);
        let req = http::Request::builder()
            .header(
                "user-agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            )
            .body(Bytes::new())
            .unwrap();
        let mut ctx = RequestContext::default();
        let ctx_any: &mut dyn std::any::Any = &mut ctx;
        let decision = enforcer.enforce(&req, ctx_any).await.unwrap();
        assert_eq!(decision, PolicyDecision::Allow);
        let parsed = ctx.parsed_user_agent.expect("parsed UA stored on context");
        assert_eq!(parsed.browser_name, "Chrome");
        let headers = ctx.trust_headers.expect("header injected");
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "x-parsed-ua");
        assert!(headers[0].1.contains("Chrome"));
    }

    #[tokio::test]
    async fn does_not_inject_header_when_disabled() {
        let enforcer = enforcer(false);
        let req = http::Request::builder()
            .header("user-agent", "curl/8.5.0")
            .body(Bytes::new())
            .unwrap();
        let mut ctx = RequestContext::default();
        let ctx_any: &mut dyn std::any::Any = &mut ctx;
        let decision = enforcer.enforce(&req, ctx_any).await.unwrap();
        assert_eq!(decision, PolicyDecision::Allow);
        assert!(ctx.trust_headers.is_none());
        assert_eq!(
            ctx.parsed_user_agent
                .as_ref()
                .map(|p| p.device_type.as_str()),
            Some("bot")
        );
    }

    #[tokio::test]
    async fn missing_user_agent_header_still_allows() {
        let enforcer = enforcer(true);
        let req = http::Request::builder().body(Bytes::new()).unwrap();
        let mut ctx = RequestContext::default();
        let ctx_any: &mut dyn std::any::Any = &mut ctx;
        let decision = enforcer.enforce(&req, ctx_any).await.unwrap();
        assert_eq!(decision, PolicyDecision::Allow);
        assert_eq!(
            ctx.parsed_user_agent
                .as_ref()
                .map(|p| p.device_type.as_str()),
            Some("unknown")
        );
    }

    #[tokio::test]
    async fn headless_ua_sets_headless_library_on_context() {
        let enforcer = enforcer(true);
        let req = http::Request::builder()
            .header(
                "user-agent",
                "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/120.0.6099.109 Safari/537.36",
            )
            .body(Bytes::new())
            .unwrap();
        let mut ctx = RequestContext::default();
        let ctx_any: &mut dyn std::any::Any = &mut ctx;
        let _ = enforcer.enforce(&req, ctx_any).await.unwrap();
        assert_eq!(
            ctx.parsed_user_agent
                .as_ref()
                .and_then(|p| p.headless_library.as_deref()),
            Some("headless_chrome")
        );
    }

    #[test]
    fn policy_type_is_user_agent_parser() {
        assert_eq!(enforcer(true).policy_type(), "user_agent_parser");
    }
}

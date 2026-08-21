//! Newtype wrapper enforcer for the `Policy::ContentDigest` variant
//! (WOR-805).
//!
//! Lifts the body of the `Policy::ContentDigest(_)` arm. The policy
//! has two decisions in it, and they are decidable at different
//! times, so this enforcer splits them:
//!
//! * **The header is absent.** Nothing about that verdict depends on
//!   the body, so it is settled here, in the header phase, before
//!   `upstream_peer` picks a peer. `on_missing: require` refuses;
//!   `on_missing: skip` falls through to the body filter so the rest
//!   of the pipeline behaves as it always did.
//! * **The header is present.** Whether it matches needs the body, so
//!   the context is marked for buffering and `request_body_filter`
//!   runs the comparison. Same shape as the
//!   [`super::request_validator::RequestValidatorEnforcer`] companion.
//!
//! WOR-2528 is why the split exists. Both decisions used to run in
//! the body filter, which Pingora reaches only after the upstream
//! connection is established, so a request the proxy had already
//! decided to refuse paid for a full upstream dial first. Against an
//! upstream that does not answer, the client waited out the connect
//! timeout for a verdict that was available from the request headers.
//! The refusal was never wrong, only late, and late is an
//! availability problem: the connection slot is held for the whole
//! dial, and the symptom reads like an upstream fault rather than a
//! policy refusal.
//!
//! The header lookup below is deliberately the same expression the
//! body filter uses (`content-digest`, then `repr-digest`, then
//! `to_str().ok()`). A detector narrower than the enforcer it stands
//! in front of would refuse a different set of requests than the one
//! it replaced: a non-UTF-8 header value, for instance, is "absent"
//! to the body filter, so it has to be "absent" here too.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use sbproxy_modules::{
    ContentDigestOnMissing as OnMissing, ContentDigestPolicy,
    ContentDigestVerifyOutcome as VerifyOutcome,
};
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use crate::context::RequestContext;

/// Look up the inbound digest header the way the body filter does.
///
/// `Content-Digest` wins over `Repr-Digest` per RFC 9530 §2 (clients
/// that set both prefer it), and a value that is not valid UTF-8 is
/// treated as absent rather than as a malformed header.
///
/// Free function rather than a method so the header-phase and
/// body-phase call sites provably share one definition of "absent".
pub fn inbound_digest_header(headers: &http::HeaderMap) -> Option<&str> {
    headers
        .get("content-digest")
        .or_else(|| headers.get("repr-digest"))
        .and_then(|value| value.to_str().ok())
}

/// Newtype wrapper that adapts [`ContentDigestPolicy`] to the
/// [`PolicyEnforcer`] trait surface.
pub struct ContentDigestEnforcer(pub Arc<ContentDigestPolicy>);

impl PolicyEnforcer for ContentDigestEnforcer {
    fn policy_type(&self) -> &'static str {
        "content_digest"
    }

    fn enforce(
        &self,
        req: &http::Request<Bytes>,
        ctx: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn Future<Output = sbproxy_plugin::PluginResult<PolicyDecision>> + Send + '_>>
    {
        // The header is absent and the operator asked us to require
        // one: refuse now. Nothing downstream of this point can change
        // the answer, and every microsecond past it is spent dialing an
        // upstream that must not see the request.
        if inbound_digest_header(req.headers()).is_none() && self.0.on_missing == OnMissing::Require
        {
            let envelope = self.0.rejection_envelope(VerifyOutcome::MissingRequired);
            let (status, body, content_type) = match envelope {
                Some(parts) => parts,
                // `rejection_envelope` returns `None` only for the two
                // pass outcomes, neither of which is reachable here.
                // Fall through to the body filter rather than invent a
                // verdict if that ever changes.
                None => {
                    if let Some(c) = ctx.downcast_mut::<RequestContext>() {
                        c.validate_request_body = true;
                    }
                    return Box::pin(async move { Ok(PolicyDecision::Allow) });
                }
            };
            if let Some(c) = ctx.downcast_mut::<RequestContext>() {
                // The decision below carries a status and a message.
                // The operator's configured `error_body` and
                // `error_content_type` ride on the context instead so
                // the response phase can emit them byte for byte.
                c.content_digest_denial = Some((body, content_type));
                // Without this the dispatcher labels the refusal with
                // the generic `plugin` fallback: the metric, the audit
                // entry, and the lookup that emits the configured
                // envelope are all keyed on it, so an unstamped deny is
                // an uncountable one that also loses `error_body`.
                c.deny_policy_type = Some("content_digest");
            }
            tracing::warn!(
                target: "sbproxy::content_digest",
                reason = "missing_required",
                status = status,
                "content_digest refused the request before the upstream was dialed"
            );
            return Box::pin(async move {
                Ok(PolicyDecision::Deny {
                    status,
                    message: "Content-Digest header required but absent".to_string(),
                })
            });
        }

        if let Some(c) = ctx.downcast_mut::<RequestContext>() {
            c.validate_request_body = true;
        }
        Box::pin(async move { Ok(PolicyDecision::Allow) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(json: serde_json::Value) -> Arc<ContentDigestPolicy> {
        Arc::new(ContentDigestPolicy::from_config(json).expect("policy"))
    }

    fn request(headers: &[(&str, &[u8])]) -> http::Request<Bytes> {
        let mut req = http::Request::builder()
            .method("POST")
            .uri("/payload")
            .body(Bytes::new())
            .expect("request");
        for (name, value) in headers {
            req.headers_mut().insert(
                http::HeaderName::from_bytes(name.as_bytes()).expect("name"),
                http::HeaderValue::from_bytes(value).expect("value"),
            );
        }
        req
    }

    async fn decide(
        policy: Arc<ContentDigestPolicy>,
        req: &http::Request<Bytes>,
    ) -> (PolicyDecision, RequestContext) {
        let mut ctx = RequestContext::new();
        let decision = {
            let any: &mut dyn std::any::Any = &mut ctx;
            ContentDigestEnforcer(policy)
                .enforce(req, any)
                .await
                .expect("decision")
        };
        (decision, ctx)
    }

    #[tokio::test]
    async fn missing_header_under_require_denies_in_the_header_phase() {
        let (decision, ctx) = decide(policy(serde_json::json!({})), &request(&[])).await;
        match decision {
            PolicyDecision::Deny { status, message } => {
                assert_eq!(status, 400);
                assert!(
                    message.contains("required but absent"),
                    "the deny reason must name the cause; got: {message}"
                );
            }
            other => panic!("expected a header-phase deny, got {other:?}"),
        }
        // The whole point: the body is never buffered, so the request
        // never reaches the phase that runs after the upstream dial.
        assert!(
            !ctx.validate_request_body,
            "a refused request must not ask the body filter to buffer"
        );
        assert_eq!(
            ctx.deny_policy_type,
            Some("content_digest"),
            "the refusal has to carry its own label or the dispatcher counts it as `plugin` \
             and drops the configured envelope"
        );
        let (body, content_type) = ctx.content_digest_denial.expect("envelope parked on ctx");
        assert!(body.contains("Content-Digest header required but absent"));
        assert_eq!(content_type, "application/json");
    }

    #[tokio::test]
    async fn missing_header_under_skip_still_falls_through_to_the_body_filter() {
        let (decision, ctx) = decide(
            policy(serde_json::json!({ "on_missing": "skip" })),
            &request(&[]),
        )
        .await;
        assert!(matches!(decision, PolicyDecision::Allow));
        assert!(ctx.validate_request_body);
        assert!(ctx.content_digest_denial.is_none());
    }

    #[tokio::test]
    async fn present_header_defers_to_the_body_filter() {
        // Whether the digest matches needs the body, so a request that
        // carries a header must still take the buffered path even when
        // the value is nonsense.
        for header in ["content-digest", "repr-digest"] {
            let (decision, ctx) = decide(
                policy(serde_json::json!({})),
                &request(&[(header, b"sha-256=:not-a-real-digest:")]),
            )
            .await;
            assert!(
                matches!(decision, PolicyDecision::Allow),
                "{header} present must not be refused in the header phase"
            );
            assert!(ctx.validate_request_body, "{header} must still buffer");
        }
    }

    #[tokio::test]
    async fn non_utf8_header_value_counts_as_absent() {
        // The body filter reads the header through `to_str().ok()`, so
        // a non-UTF-8 value is "absent" to it. The header-phase check
        // has to agree, or the two phases refuse different request
        // sets and the move changes behavior rather than timing.
        let (decision, _ctx) = decide(
            policy(serde_json::json!({})),
            &request(&[("content-digest", &[0xff, 0xfe])]),
        )
        .await;
        assert!(
            matches!(decision, PolicyDecision::Deny { .. }),
            "a non-UTF-8 digest header is absent to both phases"
        );
    }

    #[tokio::test]
    async fn configured_missing_status_and_body_ride_the_header_phase_refusal() {
        let (decision, ctx) = decide(
            policy(serde_json::json!({
                "missing_status": 428,
                "error_body": "digest required",
                "error_content_type": "text/plain",
            })),
            &request(&[]),
        )
        .await;
        match decision {
            PolicyDecision::Deny { status, .. } => assert_eq!(status, 428),
            other => panic!("expected deny, got {other:?}"),
        }
        assert_eq!(
            ctx.content_digest_denial,
            Some(("digest required".to_string(), "text/plain".to_string()))
        );
        assert_eq!(ctx.deny_policy_type, Some("content_digest"));
    }

    #[test]
    fn inbound_digest_header_prefers_content_digest() {
        let req = request(&[
            ("content-digest", b"sha-256=:aaa:"),
            ("repr-digest", b"sha-256=:bbb:"),
        ]);
        assert_eq!(
            inbound_digest_header(req.headers()),
            Some("sha-256=:aaa:"),
            "content-digest wins the tie, matching the body filter"
        );
    }
}

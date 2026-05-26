//! Newtype wrapper enforcer for the
//! `Policy::Waf` variant.
//!
//! Lifts the body of the `Policy::Waf(p)` arm. Runs the configured
//! WAF engine against the request URI + headers. On
//! [`sbproxy_modules::WafResult::Blocked`] returns the policy's
//! denial message; on [`sbproxy_modules::WafResult::Error`]
//! routes by the policy's `fail_open` flag (allow with a warning
//! on `true`, deny on `false`).
//!
//! When persistent (time-boxed) blocking is enabled on the policy, the
//! enforcer also:
//!
//! 1. Rejects up front any client currently inside an active block
//!    window, before the rule engine runs.
//! 2. After a WAF deny, records a strike against the client and, when
//!    the strike threshold is crossed, escalates the client into a fresh
//!    time-boxed block.
//!
//! Both the strike counter and the block marker are backed by the
//! existing rate-limit store (in-process map locally, shared Redis when
//! `proxy.l2_store` is configured), so blocks survive across requests
//! and across replicas. Persistent-block actions are stamped onto the
//! `sbproxy_waf_persistent_blocks_total` metric and the security audit
//! channel.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use sbproxy_modules::policy::waf::BlockKeyKind;
use sbproxy_modules::policy::WafPolicy;
use sbproxy_modules::WafResult;
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use crate::context::RequestContext;

/// Newtype wrapper that adapts [`WafPolicy`] to the
/// [`PolicyEnforcer`] trait surface.
pub struct WafEnforcer(pub Arc<WafPolicy>);

/// Resolve the persistent-block tracking key for `client` from the
/// configured key kind. IP and CEL keys can both be empty (no client IP,
/// failed CEL eval); the caller treats an empty key as "cannot track" and
/// skips persistent blocking for that request rather than collapsing
/// every untrackable client into one shared bucket.
fn resolve_block_key(
    kind: BlockKeyKind,
    cel_key: Option<&str>,
    req: &http::Request<Bytes>,
    ctx: &RequestContext,
) -> Option<String> {
    match kind {
        BlockKeyKind::Ip => ctx.client_ip.map(|ip| ip.to_string()),
        BlockKeyKind::ApiKey => req
            .headers()
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string()),
        BlockKeyKind::Cel => {
            let expr = cel_key?;
            super::rate_limit::rate_limit_key_from_cel(req, ctx, expr)
        }
    }
}

impl PolicyEnforcer for WafEnforcer {
    fn policy_type(&self) -> &'static str {
        "waf"
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
                return Box::pin(async move {
                    Ok(PolicyDecision::Deny {
                        status: 500,
                        message: "waf enforcer: bad context".to_string(),
                    })
                });
            }
        };

        // Resolve the persistent-block tracking key up front (while we
        // still hold `ctx`), if persistent blocking is enabled. The
        // origin label for metrics/audit is the request hostname.
        let origin = ctx.hostname.to_string();
        let block_state = policy.block_store().map(|store| {
            let kind = store.key_kind();
            let key = resolve_block_key(kind, store.cel_key(), req, ctx);
            (Arc::clone(store), kind, key)
        });

        let uri = req.uri().to_string();
        let waf_result = policy.check_request(&uri, req.headers(), None);

        match waf_result {
            WafResult::Clean => {
                // Even on a clean request, an existing time-boxed block must
                // still reject the client until the window lifts.
                Box::pin(async move {
                    if let Some((store, kind, Some(key))) = block_state.as_ref() {
                        if store.is_blocked(key).await {
                            sbproxy_observe::metrics::record_waf_persistent_block(
                                &origin,
                                "blocked",
                                kind.as_str(),
                            );
                            return Ok(PolicyDecision::Deny {
                                status: 403,
                                message: "WAF: client is temporarily blocked".to_string(),
                            });
                        }
                    }
                    Ok(PolicyDecision::Allow)
                })
            }
            WafResult::Blocked(msg) => {
                ctx.deny_policy_type = Some("waf");
                Box::pin(async move {
                    // A WAF deny is a strike. If the client was already
                    // blocked, keep blocking; otherwise count the strike
                    // and escalate when the threshold is crossed.
                    if let Some((store, kind, Some(key))) = block_state.as_ref() {
                        if store.is_blocked(key).await {
                            sbproxy_observe::metrics::record_waf_persistent_block(
                                &origin,
                                "blocked",
                                kind.as_str(),
                            );
                        } else {
                            match store.record_strike(key).await {
                                sbproxy_modules::policy::waf::StrikeOutcome::Escalated => {
                                    sbproxy_observe::metrics::record_waf_persistent_block(
                                        &origin,
                                        "escalated",
                                        kind.as_str(),
                                    );
                                    sbproxy_observe::SecurityAuditEntry::policy_violation(
                                        "waf_persistent_block",
                                        format!("client escalated to time-boxed block: {}", msg),
                                        403,
                                        Some(origin.clone()),
                                        ctx_client_ip(key, *kind),
                                        None,
                                        None,
                                    )
                                    .emit();
                                }
                                sbproxy_modules::policy::waf::StrikeOutcome::Counted => {
                                    sbproxy_observe::metrics::record_waf_persistent_block(
                                        &origin,
                                        "strike",
                                        kind.as_str(),
                                    );
                                }
                            }
                        }
                    }
                    Ok(PolicyDecision::Deny {
                        status: 403,
                        message: msg,
                    })
                })
            }
            WafResult::Error(err) => {
                if policy.fail_open {
                    tracing::warn!(error = %err, "WAF engine error, fail_open=true, allowing request");
                    Box::pin(async move { Ok(PolicyDecision::Allow) })
                } else {
                    tracing::warn!(error = %err, "WAF engine error, fail_open=false, blocking request");
                    ctx.deny_policy_type = Some("waf");
                    Box::pin(async move {
                        Ok(PolicyDecision::Deny {
                            status: 403,
                            message: "WAF engine error".to_string(),
                        })
                    })
                }
            }
        }
    }
}

/// Best-effort parse of the tracking key back into an [`std::net::IpAddr`]
/// for the audit entry's `client_ip` field. Only the IP key kind yields a
/// parseable address; api_key and CEL keys are not IPs, so the audit
/// entry omits the field (the `reason` still carries the key context via
/// the deny message).
fn ctx_client_ip(key: &str, kind: BlockKeyKind) -> Option<std::net::IpAddr> {
    if kind == BlockKeyKind::Ip {
        key.parse().ok()
    } else {
        None
    }
}

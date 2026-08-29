//! Newtype wrapper enforcer for the `Policy::GeoIp` variant.
//!
//! Resolves the request's client IP against the configured (or
//! embedded) MMDB via [`sbproxy_modules::GeoIpPolicy::lookup`],
//! stamps the result onto [`RequestContext::geo_lookup`] for
//! `sbproxy_plugin::RequestContextView` consumers, and (when
//! `inject_headers` is set) pushes `X-Geo-*` pairs onto
//! [`RequestContext::trust_headers`], the same upstream-header sink
//! `exposed_credentials` and forward-auth already use.
//!
//! Never denies: a missing database, an unresolved client IP, or an
//! empty lookup all fall through to [`PolicyDecision::Allow`] with no
//! headers added. Per-deny-reason label: none, this policy has no
//! deny path.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};

use bytes::Bytes;
use prometheus::{register_int_counter_vec, IntCounterVec};
use sbproxy_modules::GeoIpPolicy;
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use super::registered;
use crate::context::RequestContext;

/// Newtype wrapper that adapts [`GeoIpPolicy`] to the
/// [`PolicyEnforcer`] trait surface.
pub struct GeoIpEnforcer(pub Arc<GeoIpPolicy>);

/// GeoIP lookups, labeled by `result`: `hit` (the database carried a
/// record), `miss` (it did not), `no_database` (none configured or
/// embedded), or `no_client_ip` (nothing to look up). Bounded at four
/// values.
static LOOKUP_TOTAL: LazyLock<Option<IntCounterVec>> = LazyLock::new(|| {
    registered(
        register_int_counter_vec!(
            "sbproxy_geoip_lookup_total",
            "geoip policy lookups, labeled by outcome",
            &["result"],
        ),
        "sbproxy_geoip_lookup_total",
    )
});

/// Count one lookup outcome. A no-op when the family failed to
/// register.
fn record_lookup(result: &str) {
    if let Some(counter) = LOOKUP_TOTAL.as_ref() {
        counter.with_label_values(&[result]).inc();
    }
}

impl PolicyEnforcer for GeoIpEnforcer {
    fn policy_type(&self) -> &'static str {
        "geoip"
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

        if !policy.has_database() {
            record_lookup("no_database");
            return Box::pin(async move { Ok(PolicyDecision::Allow) });
        }

        // Prefer the pipeline's already-resolved client IP (the
        // trusted value Pingora derived from the connection / proxy
        // protocol); fall back to header extraction only when the
        // pipeline has none, matching the original enterprise
        // behavior for deployments that terminate a trusted proxy
        // chain in front of sbproxy.
        let ip = ctx
            .client_ip
            .or_else(|| GeoIpPolicy::extract_client_ip(req).and_then(|s| s.parse().ok()));

        let Some(ip) = ip else {
            record_lookup("no_client_ip");
            return Box::pin(async move { Ok(PolicyDecision::Allow) });
        };

        let lookup = policy.lookup(ip);
        if lookup.is_empty() {
            record_lookup("miss");
        } else {
            record_lookup("hit");
        }

        tracing::debug!(
            client_ip = %ip,
            country = ?lookup.country,
            continent = ?lookup.continent,
            city = ?lookup.city,
            asn = ?lookup.asn,
            "geoip policy: lookup completed"
        );

        if policy.inject_headers {
            let headers = lookup.as_headers();
            if !headers.is_empty() {
                match ctx.trust_headers.as_mut() {
                    Some(v) => v.extend(headers),
                    None => ctx.trust_headers = Some(headers),
                }
            }
        }

        ctx.geo_lookup = Some(lookup);

        Box::pin(async move { Ok(PolicyDecision::Allow) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_modules::GeoIpPolicy;

    fn enforcer(inject_headers: bool) -> GeoIpEnforcer {
        GeoIpEnforcer(Arc::new(GeoIpPolicy {
            database_path: None,
            inject_headers,
        }))
    }

    #[tokio::test]
    async fn allows_when_no_database_available() {
        let enforcer = enforcer(true);
        let req = http::Request::builder()
            .header("x-real-ip", "203.0.113.10")
            .body(Bytes::new())
            .unwrap();
        let mut ctx = RequestContext::default();
        let ctx_any: &mut dyn std::any::Any = &mut ctx;
        let decision = enforcer.enforce(&req, ctx_any).await.unwrap();
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[tokio::test]
    async fn allows_and_leaves_context_untouched_without_a_client_ip() {
        let enforcer = enforcer(true);
        let req = http::Request::builder().body(Bytes::new()).unwrap();
        let mut ctx = RequestContext::default();
        let ctx_any: &mut dyn std::any::Any = &mut ctx;
        let decision = enforcer.enforce(&req, ctx_any).await.unwrap();
        assert_eq!(decision, PolicyDecision::Allow);
        assert!(ctx.geo_lookup.is_none());
        assert!(ctx.trust_headers.is_none());
    }

    #[tokio::test]
    async fn bad_context_downcast_still_allows() {
        let enforcer = enforcer(true);
        let req = http::Request::builder().body(Bytes::new()).unwrap();
        let mut not_a_context = 0_u32;
        let ctx_any: &mut dyn std::any::Any = &mut not_a_context;
        let decision = enforcer.enforce(&req, ctx_any).await.unwrap();
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn policy_type_is_geoip() {
        assert_eq!(enforcer(true).policy_type(), "geoip");
    }
}

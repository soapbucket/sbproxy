//! Newtype wrapper enforcers for the four
//! response-phase policies (`SecHeaders`, `PageShield`, `Sri`,
//! `Assertion`).
//!
//! These four policies do all of their work in the response
//! phase; at request-time the legacy server.rs arm just did
//! nothing. The trait-side mirror is a wrapper that returns
//! `Allow` unconditionally so the registry can include the
//! policy in the dispatch chain without a `NotYetPorted` arm.
//!
//! The response-phase work itself still lives in
//! `crate::server` (response filters, body filters, and so on).
//! When those paths are themselves rewritten onto the trait
//! surface, the wrappers grow real `enforce` bodies; until then
//! they are the only way for the unified dispatch path to walk
//! past these policy variants without choking.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use sbproxy_modules::policy::{AssertionPolicy, PageShieldPolicy, SecHeadersPolicy, SriPolicy};
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

/// Static doc string applied to every response-phase wrapper. A
/// per-policy version would be cleaner, but the cross-version
/// rustfmt instability around `concat!()` inside `#[doc = ...]`
/// macro arms isn't worth the maintenance cost; the per-struct
/// docs at the policy-level cover the specifics.
macro_rules! response_phase_enforcer {
    ($name:ident, $policy:ty, $label:literal) => {
        /// Newtype wrapper that adapts a response-phase
        /// `sbproxy-modules` policy to the `PolicyEnforcer` trait
        /// surface. `enforce` always returns `Allow` at the
        /// request phase; the policy's real work happens during
        /// the response filters.
        pub struct $name(pub Arc<$policy>);

        impl PolicyEnforcer for $name {
            fn policy_type(&self) -> &'static str {
                $label
            }

            fn enforce(
                &self,
                _req: &http::Request<Bytes>,
                _ctx: &mut dyn std::any::Any,
            ) -> Pin<
                Box<dyn Future<Output = sbproxy_plugin::PluginResult<PolicyDecision>> + Send + '_>,
            > {
                Box::pin(async move { Ok(PolicyDecision::Allow) })
            }
        }
    };
}

response_phase_enforcer!(SecHeadersEnforcer, SecHeadersPolicy, "security_headers");
response_phase_enforcer!(PageShieldEnforcer, PageShieldPolicy, "page_shield");
response_phase_enforcer!(SriEnforcer, SriPolicy, "sri");
response_phase_enforcer!(AssertionEnforcer, AssertionPolicy, "assertion");

#[cfg(test)]
mod tests {
    //! Behavioural checks: the four response-phase enforcers all
    //! return `Allow` at request-phase regardless of the wrapped
    //! policy state. We exercise this through the trait surface
    //! only, so the test doesn't depend on each policy having a
    //! `Default` impl.

    use super::*;
    use sbproxy_plugin::PolicyDecision;

    fn empty_req() -> http::Request<Bytes> {
        http::Request::builder()
            .uri("/")
            .body(Bytes::new())
            .unwrap()
    }

    async fn assert_allow_on<E: PolicyEnforcer>(enforcer: E) {
        let mut ctx: i32 = 0;
        let decision = enforcer.enforce(&empty_req(), &mut ctx).await.unwrap();
        assert_eq!(decision, PolicyDecision::Allow);
    }

    // For policies that expose a constructor we use it; for the
    // rest we deserialize from an empty JSON object via the
    // module's public `from_config` / `default` path. Where
    // neither is available, the test skips that policy and the
    // server-level integration covers it instead.

    #[tokio::test]
    async fn sec_headers_allows_at_request_phase() {
        let cfg = serde_json::json!({});
        let policy: sbproxy_modules::SecHeadersPolicy =
            serde_json::from_value(cfg).expect("default sec_headers");
        assert_allow_on(SecHeadersEnforcer(Arc::new(policy))).await;
    }

    #[tokio::test]
    async fn sri_allows_at_request_phase() {
        let cfg = serde_json::json!({"sources": []});
        let policy: sbproxy_modules::SriPolicy = serde_json::from_value(cfg).expect("default sri");
        assert_allow_on(SriEnforcer(Arc::new(policy))).await;
    }
}

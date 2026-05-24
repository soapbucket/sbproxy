// SPDX-License-Identifier: BUSL-1.1
//! Newtype wrapper enforcer for the
//! [`Policy::PeerPricingPreflight`](sbproxy_modules::policy::Policy::PeerPricingPreflight)
//! variant.
//!
//! The pre-flight policy runs on the outbound path: it parses a peer's
//! `llms.txt`, gates the call on the operator's budget, and may
//! short-circuit with a structured 402 to the agent. The inbound
//! request filter never blocks on it, which is why this enforcer
//! returns `PolicyDecision::Allow` unconditionally.
//!
//! The configured policy is held inside the variant so the outbound
//! dispatcher (a later wiring PR) can clone a cheap handle out of the
//! compiled chain via `Policy::PeerPricingPreflight(arc).clone()`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use sbproxy_modules::policy::PeerPricingPreflightPolicy;
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

/// Newtype wrapper that adapts
/// [`PeerPricingPreflightPolicy`] to the
/// [`PolicyEnforcer`] trait surface. The inbound `enforce` is a
/// no-op; the real work happens on the outbound side via the typed
/// API on [`PeerPricingPreflightPolicy::evaluate`].
pub struct PeerPricingPreflightEnforcer(pub Arc<PeerPricingPreflightPolicy>);

impl PolicyEnforcer for PeerPricingPreflightEnforcer {
    fn policy_type(&self) -> &'static str {
        "peer_pricing_preflight"
    }

    fn enforce(
        &self,
        _req: &http::Request<Bytes>,
        _ctx: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn Future<Output = sbproxy_plugin::PluginResult<PolicyDecision>> + Send + '_>>
    {
        Box::pin(async move { Ok(PolicyDecision::Allow) })
    }
}

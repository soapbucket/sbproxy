//! The seam for policies whose admission decision lives outside this
//! process.
//!
//! ## Why this is not on `PolicyEnforcer`
//!
//! [`sbproxy_plugin::PolicyEnforcer::enforce`] already returns a future
//! and may await. What it cannot do is hold the request context across
//! that await. The context arrives as `&mut dyn std::any::Any`, `dyn Any`
//! is not `Send`, and the trait requires the returned future to be
//! `Send`. A future that captures the context across an await is
//! therefore not `Send` and will not compile.
//!
//! So an enforcer may mutate the context eagerly, or it may await, but
//! not both. The rate limiter needs both: it derives its bucket key from
//! the request and the context, and it writes `deny_policy_type` and
//! `rate_limit_info` back after admission. Before WOR-2332 it resolved
//! that by doing everything eagerly and calling the synchronous,
//! local-only admission path, which is why a configured Redis or mesh
//! tier was attached at config-compile time and never consulted.
//!
//! ## The split
//!
//! The context borrow has to end before the await, so key derivation and
//! the shared-tier call are two separate calls:
//!
//! * [`SharedAdmission::shared_admission_key`] is synchronous. It borrows
//!   the request and the context and returns an owned key.
//! * [`SharedAdmission::shared_admit`] is asynchronous. It takes the
//!   owned key and never touches the context, so its future is `Send`.
//!
//! `check_policies` in `server.rs` is the only caller. It already holds
//! `ctx: &mut RequestContext` across awaits, which is why the seam lives
//! at the call site rather than inside the enforcer.
//!
//! ## Why it is internal
//!
//! `PolicyEnforcer` is on the public plugin surface. This is an internal
//! wiring defect and closing it should not cost out-of-tree implementors
//! a breaking change, so the trait stays `pub(crate)` and the resolved
//! decision reaches the enforcer through the context it already receives.

use std::future::Future;
use std::pin::Pin;

use bytes::Bytes;
use sbproxy_modules::policy::RateLimitInfo;

use crate::context::RequestContext;

/// A compiled policy that admits against state shared with other
/// replicas.
///
/// Implemented only for policies that can be configured with an L2 store
/// or a mesh tier. A policy with neither resolves to `None` in
/// [`crate::builtin_enforcers::CompiledEnforcer::shared_admission`], so
/// the ordinary local-only deployment keeps exactly its previous
/// synchronous path and pays nothing for this seam.
pub(crate) trait SharedAdmission: Send + Sync {
    /// Derive the bucket key for this request.
    ///
    /// Synchronous on purpose: this is the only part of admission that
    /// needs the request context, and it needs it only immutably. The
    /// borrow ends when this returns, which is what lets the caller await
    /// [`Self::shared_admit`] and then write the result back.
    ///
    /// `None` means this request does not participate in the shared tier
    /// and the enforcer should take its ordinary local path.
    fn shared_admission_key(
        &self,
        req: &http::Request<Bytes>,
        ctx: &RequestContext,
    ) -> Option<String>;

    /// Admit `key` against the shared tier.
    ///
    /// Takes the key by value and never touches the request context, so
    /// the returned future is `Send` and may be awaited at the call site.
    fn shared_admit<'a>(
        &'a self,
        key: String,
    ) -> Pin<Box<dyn Future<Output = RateLimitInfo> + Send + 'a>>;
}

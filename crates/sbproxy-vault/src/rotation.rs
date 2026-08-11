//! Secret rotation policy for resolved upstream credentials.
//!
//! Governs two things about a credential the proxy resolves from a secret
//! backend and then presents to an upstream:
//!
//! * **How quickly a rotated value is picked up.** A resolved credential
//!   is cached; [`RotationPolicy::re_resolve_interval`] is how long that
//!   cache entry stays fresh before the backend is consulted again.
//! * **What happens when the backend cannot be reached.** Within
//!   [`RotationPolicy::grace_period`] of a cache entry going stale, the
//!   last successfully resolved value keeps being served rather than the
//!   request being refused.
//!
//! ## Why grace means last-known-good and not credential overlap
//!
//! The obvious reading of "rotation grace period" is the one secret
//! providers implement: a window where both the old and the new value are
//! accepted, which is AWS Secrets Manager's `AWSPREVIOUS` staging label
//! and Vault's lease-plus-revocation-delay.
//!
//! That is not something this proxy can do, because it is the wrong side
//! of the exchange. On this path sbproxy **presents** a credential to an
//! upstream; it never validates one. There is no candidate value to
//! accept-or-reject, so there is nothing for an overlap window to act on.
//! Honoring the overlap is the secret provider's job, and every backend
//! this crate speaks to already does it.
//!
//! What the proxy *can* get wrong is availability: before this policy
//! existed, a vault that was briefly unreachable turned every request
//! carrying a bound credential into a 503, even though a perfectly good
//! value had been resolved seconds earlier. Serving that last known-good
//! value for a bounded window is the standard answer (it is
//! stale-while-revalidate, and it is what Envoy's SDS does with a failed
//! secret refresh), and it is what `grace_period_secs` now buys.
//!
//! An earlier `RotationManager` here implemented the overlap reading,
//! with a `validate(name, candidate)` that accepted the current or the
//! previous value. It was tested and it was correct, and nothing in the
//! workspace could ever have called it, because no code path validates a
//! credential this crate resolved. It was removed rather than carried
//! (WOR-2327).

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// Process-wide rotation policy, installed once at binary boot beside the
/// secret resolver.
///
/// Same shape and same lifecycle as
/// [`crate::resolver::install_process_resolver`]: `proxy.secrets` is
/// process-owned, a reload that changes it is refused, so a policy read
/// at boot stays true for the life of the process.
static PROCESS_ROTATION: OnceLock<Mutex<Option<Arc<RotationPolicy>>>> = OnceLock::new();

fn process_rotation_cell() -> &'static Mutex<Option<Arc<RotationPolicy>>> {
    PROCESS_ROTATION.get_or_init(|| Mutex::new(None))
}

/// How long a resolved credential stays fresh, and how long a stale one
/// may still be served when the backend cannot be reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationPolicy {
    /// How long a resolved credential is served without re-consulting the
    /// backend. Shorter means a rotated secret is picked up sooner and the
    /// backend is called more often.
    re_resolve_interval: Duration,
    /// How long past the end of the fresh window a resolved credential may
    /// still be served, and only when re-resolution has actually failed.
    /// Zero disables it, so a backend failure refuses the request
    /// immediately.
    grace_period: Duration,
}

impl RotationPolicy {
    /// Build a policy from the two `proxy.secrets.rotation` values.
    pub fn new(re_resolve_interval_secs: u64, grace_period_secs: u64) -> Self {
        Self {
            re_resolve_interval: Duration::from_secs(re_resolve_interval_secs),
            grace_period: Duration::from_secs(grace_period_secs),
        }
    }

    /// How long a resolved credential is served before the backend is
    /// consulted again.
    pub fn re_resolve_interval(&self) -> Duration {
        self.re_resolve_interval
    }

    /// How long a stale credential may be served after a failed
    /// re-resolution.
    pub fn grace_period(&self) -> Duration {
        self.grace_period
    }

    /// The age past which a cached credential may not be served at all,
    /// even when the backend is down.
    ///
    /// Fresh window plus grace window. A cache entry older than this is
    /// unusable and a backend failure becomes a refusal.
    pub fn stale_serve_deadline(&self) -> Duration {
        self.re_resolve_interval.saturating_add(self.grace_period)
    }
}

impl Default for RotationPolicy {
    /// The behaviour a config with no `proxy.secrets.rotation:` block
    /// gets.
    ///
    /// The 60 second interval is not a new number: it is the constant that
    /// was hardcoded in the key plane before this policy existed, kept so
    /// adding the block is what changes behaviour, never upgrading.
    ///
    /// Grace defaults to zero for the same reason. Serving a stale
    /// credential is a real availability-over-freshness trade and an
    /// operator should opt into it, not inherit it from a default.
    fn default() -> Self {
        Self::new(60, 0)
    }
}

/// Install the process-wide rotation policy. Call once at boot, before the
/// server compiles its config. A second call is ignored, matching
/// [`crate::resolver::install_process_resolver`].
pub fn install_process_rotation(policy: Arc<RotationPolicy>) {
    let mut slot = process_rotation_cell()
        .lock()
        .expect("process rotation mutex");
    if slot.is_none() {
        *slot = Some(policy);
    }
}

/// The process-wide rotation policy.
///
/// Returns [`RotationPolicy::default`] when no `proxy.secrets.rotation:`
/// block was installed, which keeps a config that never mentions rotation
/// on exactly the behaviour it had before the block was consumed.
pub fn process_rotation() -> RotationPolicy {
    process_rotation_cell()
        .lock()
        .expect("process rotation mutex")
        .as_deref()
        .copied()
        .unwrap_or_default()
}

/// Clear the installed policy so a test can install its own.
#[doc(hidden)]
pub fn reset_process_rotation_for_test() {
    if let Ok(mut slot) = process_rotation_cell().lock() {
        *slot = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_config_keeps_the_previously_hardcoded_interval() {
        // The key plane used a bare `const RESOLVED_CREDENTIAL_TTL =
        // 60s`. A config with no rotation block has to land on the same
        // number, or wiring the key becomes a silent behaviour change for
        // every existing deployment.
        let policy = RotationPolicy::default();
        assert_eq!(policy.re_resolve_interval(), Duration::from_secs(60));
    }

    #[test]
    fn grace_is_off_unless_asked_for() {
        // Serving a stale credential trades freshness for availability.
        // That is the operator's call, so the default must not make it
        // for them.
        assert_eq!(RotationPolicy::default().grace_period(), Duration::ZERO);
        assert_eq!(
            RotationPolicy::default().stale_serve_deadline(),
            Duration::from_secs(60),
            "with no grace, the deadline is just the fresh window"
        );
    }

    #[test]
    fn stale_serve_deadline_is_the_two_windows_summed() {
        let policy = RotationPolicy::new(60, 300);
        assert_eq!(policy.stale_serve_deadline(), Duration::from_secs(360));
    }

    #[test]
    fn stale_serve_deadline_saturates_rather_than_overflowing() {
        // Both values are operator-supplied `u64` seconds, so the sum can
        // overflow a Duration. Saturating means an absurd config produces
        // "effectively forever" instead of a panic on the request path.
        let policy = RotationPolicy::new(u64::MAX, u64::MAX);
        assert_eq!(policy.stale_serve_deadline(), Duration::MAX);
    }
}

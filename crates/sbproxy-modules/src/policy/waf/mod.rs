//! Web Application Firewall policy and supporting machinery.
//!
//! The [`policy`] submodule holds the [`WafPolicy`] struct itself,
//! the OWASP-lite paranoia gate, the built-in signature corpus, and
//! the custom-rule evaluator. The [`feed`] submodule subscribes the
//! OSS proxy to a signed remote rule feed for hot-loaded signatures;
//! the publisher side ships separately.

pub mod bundle;
pub mod feed;
pub mod persistent;
pub mod policy;

pub use bundle::{crs_bundle, CrsBundleConfig, CRS_BUNDLE_VERSION};
pub use feed::{
    FeedRule, FeedRuleAction, FeedRuleSeverity, RuleSet, WafFeedConfig, WafFeedSubscriber,
    WafFeedTransport, WAF_FEED_TASKS,
};
pub use persistent::{BlockKeyKind, PersistentBlockConfig, PersistentBlockStore, StrikeOutcome};
pub use policy::{WafPolicy, WafResult};

/// Drain in-flight WAF rule-feed background tasks. Intended for the
/// graceful-shutdown driver: call this from the same async context the
/// server runs in, after listeners stop accepting new connections, so
/// any in-flight HTTP poll or Redis XREAD has a chance to settle (or
/// hit its per-call timeout) before the runtime tears down. The
/// tracker is closed for new spawns afterward; subsequent
/// `WAF_FEED_TASKS.spawn(...)` calls become no-ops.
pub async fn shutdown_waf_feed_tasks() {
    WAF_FEED_TASKS.close();
    WAF_FEED_TASKS.wait().await;
}

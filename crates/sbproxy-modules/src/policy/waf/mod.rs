//! WAF subscribed rule feed (OSS subscriber side).
//!
//! The legacy WAF policy struct, paranoia gate, OWASP-lite built-in
//! signatures, and custom-rule evaluators continue to live alongside
//! the rest of the policies in [`crate::policy`] (`policy/mod.rs`).
//! This `waf` subdirectory is the new home for *additions* that are
//! large enough to warrant their own file.
//!
//! Today that is [`feed`], which subscribes the OSS proxy to a signed
//! remote rule feed. The publisher side ships separately; everything
//! in this module is the subscriber.

pub mod feed;

pub use feed::{
    FeedRule, FeedRuleAction, FeedRuleSeverity, RuleSet, WafFeedConfig, WafFeedSubscriber,
    WafFeedTransport, WAF_FEED_TASKS,
};

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

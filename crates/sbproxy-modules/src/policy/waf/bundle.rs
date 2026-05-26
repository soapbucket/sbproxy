//! Shipped OWASP Core Rule Set managed bundle.
//!
//! This is the in-tree, signature-free counterpart to the remote signed
//! rule feed in [`super::feed`]. The bundle is vendored as JSON
//! (`coreruleset/owasp-crs-bundle.json`), compiled at startup into the
//! same [`RuleSet`] the feed produces, and enabled with one config flag.
//! There is no network fetch and no HMAC verification: the rules ship
//! with the binary, so they are trusted by provenance, not by signature.
//!
//! Keeping this distinct from the signed feed matters. The feed is the
//! enterprise distribution channel (a publisher signs revisions, OSS
//! subscribers verify and hot-load them). The managed bundle is the
//! batteries-included OSS baseline: turn it on and a curated CRS-derived
//! corpus is live, no publisher required. Operators can run either, both,
//! or neither.
//!
//! Each rule carries an OWASP CRS-style paranoia tag (1-4). The WAF
//! policy's `paranoia` level gates which bundle rules run, exactly as it
//! gates the built-in patterns and the feed rules, so a single
//! `paranoia:` knob controls strictness across all three corpora.

use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::Deserialize;

use super::feed::{RuleSet, SignedBundle};

/// Version string of the vendored bundle, surfaced for logs and tests.
/// Tracks the `version` field of the embedded JSON.
pub const CRS_BUNDLE_VERSION: &str = "2026-05-25T00:00:00Z";

/// Raw JSON of the vendored bundle, embedded at compile time.
const CRS_BUNDLE_JSON: &str = include_str!("coreruleset/owasp-crs-bundle.json");

/// One-flag configuration for the shipped OWASP CRS managed bundle.
///
/// Lives under the WAF policy's `owasp_crs` block. The single required
/// switch is `managed_bundle: true`; `paranoia_level` is the optional
/// selectable strictness knob (the top-level `paranoia` field still
/// wins when both are present, see
/// [`WafPolicy::effective_paranoia`](super::policy::WafPolicy)).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CrsBundleConfig {
    /// Master switch. When `true`, the vendored CRS bundle is compiled
    /// and evaluated alongside the built-in patterns. Defaults to
    /// `false` so existing configs are unaffected.
    #[serde(default)]
    pub managed_bundle: bool,
}

/// Compile and return the vendored CRS bundle as a shared [`RuleSet`].
///
/// Parsed and compiled once, then cached: the embedded JSON never
/// changes at runtime, so every WAF policy that enables the managed
/// bundle shares one compiled corpus. Returns an empty rule set if the
/// embedded JSON ever fails to parse (a build-time invariant that the
/// `bundle_parses_and_compiles` test pins), so a malformed bundle
/// degrades to "no managed rules" rather than panicking the proxy.
pub fn crs_bundle() -> Arc<RuleSet> {
    static CACHE: std::sync::OnceLock<ArcSwap<RuleSet>> = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| {
        let set = match serde_json::from_str::<SignedBundle>(CRS_BUNDLE_JSON) {
            Ok(bundle) => RuleSet::from_bundle(bundle),
            Err(e) => {
                tracing::error!(error = %e, "vendored OWASP CRS bundle failed to parse; managed bundle disabled");
                RuleSet::default()
            }
        };
        ArcSwap::from_pointee(set)
    });
    cache.load_full()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_parses_and_compiles() {
        let set = crs_bundle();
        assert_eq!(set.version, CRS_BUNDLE_VERSION);
        assert_eq!(set.channel, "owasp-crs-managed");
        assert!(
            set.rules.len() >= 10,
            "expected a non-trivial managed corpus, got {}",
            set.rules.len()
        );
    }

    #[test]
    fn bundle_carries_paranoia_one_and_higher_rules() {
        let set = crs_bundle();
        assert!(
            set.rules.iter().any(|r| r.paranoia == 1),
            "bundle must include always-on paranoia=1 baseline rules"
        );
        assert!(
            set.rules.iter().any(|r| r.paranoia >= 2),
            "bundle must include stricter paranoia>=2 rules so the level knob is meaningful"
        );
    }

    #[test]
    fn config_defaults_to_disabled() {
        let c: CrsBundleConfig = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(!c.managed_bundle);
    }

    #[test]
    fn config_enables_with_one_flag() {
        let c: CrsBundleConfig =
            serde_json::from_value(serde_json::json!({ "managed_bundle": true })).unwrap();
        assert!(c.managed_bundle);
    }
}

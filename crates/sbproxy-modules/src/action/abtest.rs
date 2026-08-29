//! A/B testing action - traffic-split routing between weighted variants.
//!
//! Ported from `sbproxy-enterprise-modules::action::abtest` (WOR-2671).
//! Routes a request to one of several backend variants, weighted by the
//! configured `weight`, and pins a returning client to its first
//! assignment via a sticky cookie so a multi-request user journey does
//! not see a different variant on every request.
//!
//! The enterprise source stopped at selecting a variant and returning an
//! abstract "proxy" outcome; the source's plugin dispatch resolved what
//! that meant. OSS's built-in actions have no such indirection, so the
//! selected variant's URL is resolved to a real `(host, port, tls)`
//! upstream target here (mirroring [`super::ProxyAction::parse_upstream`])
//! and carried on the request context by
//! `sbproxy-core`'s `handle_action`, which is what makes the request
//! actually reach the chosen backend.

use rand::Rng;
use serde::Deserialize;

use super::memoized_upstream;

/// A/B testing action config - splits traffic across weighted variants.
#[derive(Debug, Deserialize)]
pub struct AbTestAction {
    /// Variants to route traffic between. Must not be empty.
    pub variants: Vec<AbTestVariant>,
    /// Cookie name used to pin a client to its assigned variant across
    /// requests.
    #[serde(default = "default_ab_sticky_cookie")]
    pub sticky_cookie: String,
}

/// A single A/B test variant.
#[derive(Debug, Clone, Deserialize)]
pub struct AbTestVariant {
    /// Variant name. Used as the sticky cookie's value and as the
    /// `variant` label on `sbproxy_action_abtest_variant_selected_total`.
    pub name: String,
    /// Backend URL for this variant.
    pub url: String,
    /// Relative weight for traffic distribution. Weights do not need to
    /// sum to any particular total; a variant's share of traffic is its
    /// weight divided by the sum of all weights.
    pub weight: u32,
}

fn default_ab_sticky_cookie() -> String {
    "sb_ab_variant".to_string()
}

impl AbTestAction {
    /// Build an AbTestAction from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let action: Self = serde_json::from_value(value)?;
        if action.variants.is_empty() {
            anyhow::bail!("abtest action requires at least one entry in `variants`");
        }
        Ok(action)
    }

    /// Select a variant by weighted random distribution.
    ///
    /// A total weight of zero (every variant weighted `0`) falls back to
    /// the first variant rather than dividing by zero.
    pub fn select_variant(&self) -> Option<&AbTestVariant> {
        let total_weight: u32 = self.variants.iter().map(|v| v.weight).sum();
        if total_weight == 0 {
            return self.variants.first();
        }

        let mut rng = rand::thread_rng();
        let roll = rng.gen_range(0..total_weight);
        let mut cumulative = 0;
        for variant in &self.variants {
            cumulative += variant.weight;
            if roll < cumulative {
                return Some(variant);
            }
        }
        self.variants.last()
    }

    /// Look up the variant named by the sticky cookie in a raw `Cookie`
    /// header value, if present and if it still names a configured
    /// variant (a variant removed from config since the cookie was set
    /// falls through to a fresh [`Self::select_variant`] pick).
    pub fn sticky_variant(&self, cookie_header: Option<&str>) -> Option<&AbTestVariant> {
        let cookie_header = cookie_header?;
        let prefix = format!("{}=", self.sticky_cookie);
        for part in cookie_header.split(';') {
            let trimmed = part.trim();
            if let Some(value) = trimmed.strip_prefix(&prefix) {
                return self.variants.iter().find(|v| v.name == value);
            }
        }
        None
    }

    /// Resolve the variant a request should see: the sticky cookie's
    /// variant when present and still configured, otherwise a fresh
    /// weighted pick.
    pub fn resolve_variant(&self, cookie_header: Option<&str>) -> Option<&AbTestVariant> {
        self.sticky_variant(cookie_header)
            .or_else(|| self.select_variant())
    }

    /// Parse a variant's URL into `(host, port, tls)` for the Pingora
    /// upstream peer, memoized the same way
    /// [`super::ProxyAction::parse_upstream`] is (the variant URL set is
    /// fixed per config, so the parse result never changes for a given
    /// config generation).
    pub fn parse_variant_upstream(
        &self,
        variant: &AbTestVariant,
    ) -> anyhow::Result<(String, u16, bool)> {
        memoized_upstream(&variant.url, || {
            let parsed = url::Url::parse(&variant.url)?;
            let host = parsed
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("missing host in abtest variant URL"))?
                .to_string();
            let tls = parsed.scheme() == "https";
            let port = parsed.port().unwrap_or(if tls { 443 } else { 80 });
            Ok((host, port, tls))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> serde_json::Value {
        serde_json::json!({
            "type": "abtest",
            "variants": [
                { "name": "control", "url": "https://a.example.com", "weight": 50 },
                { "name": "experiment", "url": "https://b.example.com", "weight": 50 }
            ]
        })
    }

    #[test]
    fn deserialize_config() {
        let action = AbTestAction::from_config(sample_config()).unwrap();
        assert_eq!(action.variants.len(), 2);
        assert_eq!(action.variants[0].name, "control");
        assert_eq!(action.variants[1].url, "https://b.example.com");
        assert_eq!(action.sticky_cookie, "sb_ab_variant");
    }

    #[test]
    fn select_variant_returns_some() {
        let action = AbTestAction::from_config(sample_config()).unwrap();
        let variant = action.select_variant();
        assert!(variant.is_some());
    }

    #[test]
    fn sticky_cookie_selects_variant() {
        let action = AbTestAction::from_config(sample_config()).unwrap();

        let variant = action.sticky_variant(Some("sb_ab_variant=experiment; other=value"));
        assert!(variant.is_some());
        assert_eq!(variant.unwrap().name, "experiment");
    }

    #[test]
    fn sticky_cookie_returns_none_for_unknown() {
        let action = AbTestAction::from_config(sample_config()).unwrap();

        let variant = action.sticky_variant(Some("sb_ab_variant=nonexistent"));
        assert!(variant.is_none());
    }

    #[test]
    fn no_cookie_returns_none() {
        let action = AbTestAction::from_config(sample_config()).unwrap();
        assert!(action.sticky_variant(None).is_none());
    }

    #[test]
    fn weighted_selection_respects_zero_weights() {
        let action = AbTestAction::from_config(serde_json::json!({
            "type": "abtest",
            "variants": [
                { "name": "a", "url": "https://a.example.com", "weight": 0 },
                { "name": "b", "url": "https://b.example.com", "weight": 0 }
            ]
        }))
        .unwrap();
        // With all zero weights, should return the first variant.
        let variant = action.select_variant();
        assert!(variant.is_some());
        assert_eq!(variant.unwrap().name, "a");
    }

    #[test]
    fn single_variant_always_selected() {
        let action = AbTestAction::from_config(serde_json::json!({
            "type": "abtest",
            "variants": [
                { "name": "only", "url": "https://only.example.com", "weight": 100 }
            ]
        }))
        .unwrap();
        for _ in 0..20 {
            let variant = action.select_variant().unwrap();
            assert_eq!(variant.name, "only");
        }
    }

    #[test]
    fn custom_cookie_name() {
        let action = AbTestAction::from_config(serde_json::json!({
            "type": "abtest",
            "variants": [
                { "name": "v1", "url": "https://v1.example.com", "weight": 50 }
            ],
            "sticky_cookie": "my_variant"
        }))
        .unwrap();
        assert_eq!(action.sticky_cookie, "my_variant");
        assert!(action.sticky_variant(Some("my_variant=v1")).is_some());
    }

    #[test]
    fn empty_variants_rejected_at_config_load() {
        let err = AbTestAction::from_config(serde_json::json!({
            "type": "abtest",
            "variants": []
        }))
        .expect_err("empty variants must be rejected");
        assert!(err.to_string().contains("variants"));
    }

    // --- resolve_variant / parse_variant_upstream (the OSS-specific
    // seam that replaces the source's `handle()` + `ActionOutcome::Proxy`) ---

    #[test]
    fn resolve_variant_prefers_sticky_cookie_over_random_pick() {
        let action = AbTestAction::from_config(sample_config()).unwrap();
        for _ in 0..20 {
            let variant = action
                .resolve_variant(Some("sb_ab_variant=experiment"))
                .unwrap();
            assert_eq!(variant.name, "experiment");
        }
    }

    #[test]
    fn resolve_variant_falls_back_to_weighted_pick_with_no_cookie() {
        let action = AbTestAction::from_config(sample_config()).unwrap();
        let variant = action.resolve_variant(None);
        assert!(variant.is_some());
    }

    #[test]
    fn parse_variant_upstream_resolves_host_port_tls() {
        let action = AbTestAction::from_config(sample_config()).unwrap();
        let variant = &action.variants[0];
        let (host, port, tls) = action.parse_variant_upstream(variant).unwrap();
        assert_eq!(host, "a.example.com");
        assert_eq!(port, 443);
        assert!(tls);
    }

    #[test]
    fn parse_variant_upstream_rejects_invalid_url() {
        let action = AbTestAction::from_config(serde_json::json!({
            "type": "abtest",
            "variants": [{ "name": "bad", "url": "not a valid url", "weight": 1 }]
        }))
        .unwrap();
        let variant = &action.variants[0];
        assert!(action.parse_variant_upstream(variant).is_err());
    }
}

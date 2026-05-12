//! Budget enforcement for AI gateway usage tracking and limits.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::handler::AiSurface;

/// Budget enforcement configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct BudgetConfig {
    /// Budget limits by scope.
    #[serde(default)]
    pub limits: Vec<BudgetLimit>,
    /// What to do when budget is exceeded.
    #[serde(default)]
    pub on_exceed: OnExceedAction,
}

/// A single budget limit rule.
#[derive(Debug, Clone, Deserialize)]
pub struct BudgetLimit {
    /// The scope this limit applies to.
    pub scope: BudgetScope,
    /// Maximum tokens allowed.
    pub max_tokens: Option<u64>,
    /// Maximum cost in USD.
    pub max_cost_usd: Option<f64>,
    /// Time period: "daily", "monthly", or "total".
    #[serde(default)]
    pub period: Option<String>,
    /// Model to downgrade to when limit is exceeded.
    #[serde(default)]
    pub downgrade_to: Option<String>,
}

/// Scope at which a budget limit is enforced.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum BudgetScope {
    /// Limit applies across the entire workspace.
    Workspace,
    /// Limit applies per virtual API key.
    ApiKey,
    /// Limit applies per end-user identifier.
    User,
    /// Limit applies per model name.
    Model,
    /// Limit applies per upstream origin.
    Origin,
    /// Limit applies per metadata tag value.
    Tag,
}

/// Action taken when a budget limit is exceeded.
#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OnExceedAction {
    /// Block the request (default).
    #[default]
    Block,
    /// Log a warning but allow the request.
    Log,
    /// Downgrade to a cheaper model.
    Downgrade,
}

/// Tracks accumulated usage per scope key.
pub struct BudgetTracker {
    usage: DashMap<String, UsageRecord>,
}

/// Accumulated usage for a single scope key.
#[derive(Debug, Clone, Default)]
pub struct UsageRecord {
    /// Total tokens consumed (prompt + completion).
    pub tokens: u64,
    /// Total cost in USD across all requests.
    pub cost_usd: f64,
    /// Total number of recorded requests.
    pub request_count: u64,
}

impl Default for BudgetTracker {
    fn default() -> Self {
        Self {
            usage: DashMap::new(),
        }
    }
}

impl BudgetTracker {
    /// Create a new empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record token usage for a scope.
    ///
    /// Uses `entry().and_modify().or_insert_with()` so the
    /// read-modify-write is atomic under DashMap's per-shard write lock.
    pub fn record_usage(&self, scope_key: &str, tokens: u64, cost: f64) {
        self.usage
            .entry(scope_key.to_string())
            .and_modify(|record| {
                record.tokens += tokens;
                record.cost_usd += cost;
                record.request_count += 1;
            })
            .or_insert_with(|| UsageRecord {
                tokens,
                cost_usd: cost,
                request_count: 1,
            });
    }

    /// Get current usage for a scope.
    pub fn get_usage(&self, scope_key: &str) -> UsageRecord {
        self.usage
            .get(scope_key)
            .map(|r| r.clone())
            .unwrap_or_default()
    }

    /// Check if any budget limit is exceeded. Returns `Some` with details if exceeded.
    pub fn check_limits(
        &self,
        config: &BudgetConfig,
        scope_key: &str,
    ) -> Option<BudgetCheckResult> {
        let usage = self.get_usage(scope_key);
        for limit in &config.limits {
            if let Some(max_tokens) = limit.max_tokens {
                if usage.tokens >= max_tokens {
                    return Some(BudgetCheckResult {
                        exceeded: true,
                        action: config.on_exceed.clone(),
                        downgrade_to: limit.downgrade_to.clone(),
                        reason: format!("token limit exceeded: {} >= {}", usage.tokens, max_tokens),
                        current_tokens: usage.tokens,
                        current_cost_usd: usage.cost_usd,
                    });
                }
            }
            if let Some(max_cost) = limit.max_cost_usd {
                if usage.cost_usd >= max_cost {
                    return Some(BudgetCheckResult {
                        exceeded: true,
                        action: config.on_exceed.clone(),
                        downgrade_to: limit.downgrade_to.clone(),
                        reason: format!(
                            "cost limit exceeded: ${:.4} >= ${:.4}",
                            usage.cost_usd, max_cost
                        ),
                        current_tokens: usage.tokens,
                        current_cost_usd: usage.cost_usd,
                    });
                }
            }
        }
        None
    }

    /// Compose a deterministic scope key for the given limit's scope.
    /// `workspace_id` identifies the AI proxy origin (typically its
    /// hostname), and the optional inputs come from per-request state.
    /// Returns `None` when the request lacks the data the scope keys
    /// off (e.g. `User` with no user header set), in which case the
    /// caller should skip enforcement for that limit.
    pub fn scope_key(
        scope: &BudgetScope,
        workspace_id: &str,
        api_key: Option<&str>,
        user: Option<&str>,
        model: Option<&str>,
        origin: Option<&str>,
        tag: Option<&str>,
    ) -> Option<String> {
        match scope {
            BudgetScope::Workspace => Some(format!("workspace:{}", workspace_id)),
            BudgetScope::ApiKey => api_key.map(|k| format!("api_key:{}:{}", workspace_id, k)),
            BudgetScope::User => user.map(|u| format!("user:{}:{}", workspace_id, u)),
            BudgetScope::Model => model.map(|m| format!("model:{}:{}", workspace_id, m)),
            BudgetScope::Origin => origin.map(|o| format!("origin:{}", o)),
            BudgetScope::Tag => tag.map(|t| format!("tag:{}:{}", workspace_id, t)),
        }
    }

    /// Reset usage for a scope.
    pub fn reset(&self, scope_key: &str) {
        self.usage.remove(scope_key);
    }
}

/// Result of a budget limit check.
#[derive(Debug, Clone)]
pub struct BudgetCheckResult {
    /// Whether the budget was exceeded.
    pub exceeded: bool,
    /// The action to take.
    pub action: OnExceedAction,
    /// Model to downgrade to, if action is Downgrade.
    pub downgrade_to: Option<String>,
    /// Human-readable reason for the exceeded budget.
    pub reason: String,
    /// Current accumulated tokens for the scope at check time.
    pub current_tokens: u64,
    /// Current accumulated cost for the scope at check time.
    pub current_cost_usd: f64,
}

/// Per-million-token pricing for a known model.
///
/// Values are USD per million tokens. The catalog covers the major
/// hosted families that the YAML provider list ships with; unknown
/// models fall back to a conservative default in [`estimate_cost`].
#[derive(Debug, Clone, Copy)]
pub struct ModelPrice {
    /// Cost per million prompt tokens, in USD.
    pub input_per_million: f64,
    /// Cost per million completion tokens, in USD.
    pub output_per_million: f64,
}

/// Built-in price catalog. Numbers are static published list prices
/// at the time of writing; operators that need exact billing should
/// pair this with their own ledger. The default is intentionally
/// pessimistic (assume the more expensive of input/output dominates)
/// so a budget cap fires earlier rather than later when a model is
/// unknown.
fn lookup_price(model: &str) -> Option<ModelPrice> {
    let m = model.to_ascii_lowercase();
    // OpenAI
    if m.starts_with("gpt-4o-mini") {
        return Some(ModelPrice {
            input_per_million: 0.15,
            output_per_million: 0.60,
        });
    }
    if m.starts_with("gpt-4o") {
        return Some(ModelPrice {
            input_per_million: 2.50,
            output_per_million: 10.00,
        });
    }
    if m.starts_with("gpt-4-turbo") {
        return Some(ModelPrice {
            input_per_million: 10.00,
            output_per_million: 30.00,
        });
    }
    if m.starts_with("gpt-4") {
        return Some(ModelPrice {
            input_per_million: 30.00,
            output_per_million: 60.00,
        });
    }
    if m.starts_with("gpt-3.5") {
        return Some(ModelPrice {
            input_per_million: 0.50,
            output_per_million: 1.50,
        });
    }
    // Anthropic
    if m.contains("claude-3-5-haiku") || m.contains("claude-3-haiku") {
        return Some(ModelPrice {
            input_per_million: 0.80,
            output_per_million: 4.00,
        });
    }
    if m.contains("claude-3-5-sonnet") || m.contains("claude-3-sonnet") {
        return Some(ModelPrice {
            input_per_million: 3.00,
            output_per_million: 15.00,
        });
    }
    if m.contains("claude-3-opus") {
        return Some(ModelPrice {
            input_per_million: 15.00,
            output_per_million: 75.00,
        });
    }
    // Google
    if m.contains("gemini-1.5-flash") || m.contains("gemini-flash") {
        return Some(ModelPrice {
            input_per_million: 0.075,
            output_per_million: 0.30,
        });
    }
    if m.contains("gemini-1.5-pro") || m.contains("gemini-pro") {
        return Some(ModelPrice {
            input_per_million: 1.25,
            output_per_million: 5.00,
        });
    }
    None
}

/// Look up a per-image USD price for `model` at the given resolution.
///
/// Resolutions are matched case-insensitively against the model's
/// published rate card. Returns `None` for unknown model+resolution
/// combinations; the caller falls back to zero so unknown surfaces
/// don't silently inflate cost.
fn lookup_image_price(model: &str, resolution: &str) -> Option<f64> {
    let m = model.to_ascii_lowercase();
    let r = resolution.to_ascii_lowercase();
    // OpenAI DALL-E 3 (list prices as of 2026)
    if m.contains("dall-e-3") {
        return match r.as_str() {
            "1024x1024" => Some(0.040),
            "1024x1792" | "1792x1024" => Some(0.080),
            // HD variants typically appear as a separate model in
            // the request body; if the operator encodes it in the
            // resolution string we recognize the canonical HD shapes.
            "hd-1024x1024" => Some(0.080),
            "hd-1024x1792" | "hd-1792x1024" => Some(0.120),
            _ => None,
        };
    }
    // OpenAI DALL-E 2
    if m.contains("dall-e-2") {
        return match r.as_str() {
            "256x256" => Some(0.016),
            "512x512" => Some(0.018),
            "1024x1024" => Some(0.020),
            _ => None,
        };
    }
    None
}

/// Look up a per-second USD price for audio transcription / translation.
/// Whisper bills $0.006 per minute = $0.0001 per second.
fn lookup_audio_transcription_price(model: &str) -> Option<f64> {
    let m = model.to_ascii_lowercase();
    if m.contains("whisper") {
        return Some(0.000_1);
    }
    None
}

/// Look up a per-character USD price for text-to-speech.
/// OpenAI tts-1: $15 / 1M chars; tts-1-hd: $30 / 1M chars.
fn lookup_audio_speech_price(model: &str) -> Option<f64> {
    let m = model.to_ascii_lowercase();
    if m.contains("tts-1-hd") {
        return Some(0.000_030);
    }
    if m.contains("tts-1") {
        return Some(0.000_015);
    }
    None
}

/// Look up a per-document USD price for reranking. Cohere bills
/// $2 / 1000 documents = $0.002 per document.
fn lookup_rerank_price(model: &str) -> Option<f64> {
    let m = model.to_ascii_lowercase();
    if m.starts_with("rerank-") {
        return Some(0.002);
    }
    None
}

/// Estimate the USD cost of a billing event given the model name and
/// the surface-specific usage record.
///
/// Token-bearing usage delegates to [`estimate_cost`]. Image, audio,
/// character, and rerank usage consults its own pricing helper.
/// `PerCall` always returns 0.0 (flat-fee endpoints like moderations
/// don't scale with payload size; the operator can pair this with
/// their own ledger if they need per-call accounting).
pub fn estimate_cost_for_usage(model: &str, usage: &AiUsage) -> f64 {
    match usage {
        AiUsage::Tokens { input, output } => estimate_cost(model, *input, *output),
        AiUsage::Images { count, resolution } => lookup_image_price(model, resolution)
            .map(|p| p * (*count as f64))
            .unwrap_or(0.0),
        AiUsage::AudioSeconds { seconds } => lookup_audio_transcription_price(model)
            .map(|p| p * seconds)
            .unwrap_or(0.0),
        AiUsage::Characters { count } => lookup_audio_speech_price(model)
            .map(|p| p * (*count as f64))
            .unwrap_or(0.0),
        AiUsage::RerankUnits { documents } => lookup_rerank_price(model)
            .map(|p| p * (*documents as f64))
            .unwrap_or(0.0),
        AiUsage::PerCall => 0.0,
    }
}

/// Estimate the USD cost of a request given the model name and token
/// counts. Unknown models fall back to a flat $5 per million blended
/// rate so a missing entry never silently zero-rates a request.
pub fn estimate_cost(model: &str, prompt_tokens: u64, completion_tokens: u64) -> f64 {
    let price = lookup_price(model).unwrap_or(ModelPrice {
        input_per_million: 5.0,
        output_per_million: 5.0,
    });
    let prompt_cost = (prompt_tokens as f64) * price.input_per_million / 1_000_000.0;
    let completion_cost = (completion_tokens as f64) * price.output_per_million / 1_000_000.0;
    prompt_cost + completion_cost
}

/// Pick the cheapest model from a list of candidates, using the
/// built-in price catalog. Returns `None` when the list is empty.
/// Models without a known price are scored at the default fallback
/// rate (not cheapest, not most expensive) so they neither dominate
/// nor get silently excluded from the comparison.
pub fn cheapest_model(candidates: &[String]) -> Option<String> {
    let mut best: Option<(f64, &String)> = None;
    for name in candidates {
        let price = lookup_price(name).unwrap_or(ModelPrice {
            input_per_million: 5.0,
            output_per_million: 5.0,
        });
        // Score against a representative 1000-prompt / 500-completion
        // mix so input-heavy and output-heavy models are weighted
        // realistically rather than by either rate in isolation.
        let score = price.input_per_million * 1000.0 + price.output_per_million * 500.0;
        match best {
            None => best = Some((score, name)),
            Some((cur, _)) if score < cur => best = Some((score, name)),
            _ => {}
        }
    }
    best.map(|(_, name)| name.clone())
}

// --- Surface-aware billing events (Phase 8) ---

/// Per-surface usage record carried by an [`AiBillingEvent`].
///
/// Different surfaces bill in different units: chat completions and
/// embeddings bill per token; image generation bills per image plus
/// resolution; transcription and realtime audio bill per second of
/// input/output audio; text-to-speech bills per character; reranking
/// bills per document scored. `PerCall` covers fixed-fee endpoints
/// (moderations) where the cost is independent of payload size.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AiUsage {
    /// Token-based usage (chat completions, embeddings, assistants,
    /// fine-tuning training).
    Tokens {
        /// Prompt/input tokens consumed.
        input: u64,
        /// Completion/output tokens emitted.
        output: u64,
    },
    /// Image generation usage. `count` is the number of images
    /// returned; `resolution` is the dimension string sent to the
    /// provider (e.g. `1024x1024`, `1792x1024`).
    Images {
        /// Number of images returned in the response.
        count: u32,
        /// Resolution string as sent to the provider.
        resolution: String,
    },
    /// Audio usage measured in seconds. Covers realtime audio frames
    /// and transcription duration.
    AudioSeconds {
        /// Audio duration in seconds, fractional.
        seconds: f64,
    },
    /// Character-based usage (text-to-speech synthesis).
    Characters {
        /// Number of input characters synthesized.
        count: u64,
    },
    /// Document-count-based usage (reranking).
    RerankUnits {
        /// Number of documents scored.
        documents: u64,
    },
    /// Flat per-call usage. Cost does not scale with payload size
    /// (moderations, list endpoints, single-record GETs).
    PerCall,
}

/// Billing event emitted by the AI gateway for a single dispatched
/// request.
///
/// The event is published onto the observability bus and consumed by
/// any number of sinks: the OSS budget tracker (which enforces token
/// limits and audio-second caps for the enforceable units), the
/// enterprise billing pipeline (which records chargeback rows), and
/// audit log targets.
///
/// `occurred_at_unix_secs` is a UTC Unix timestamp so the shape is
/// JSON-serializable across the observability bus without leaking
/// `SystemTime`'s opaque representation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AiBillingEvent {
    /// AI surface classification (chat completions, assistants,
    /// image generation, ...). Carried as the label string from
    /// [`AiSurface::label()`] for stable cross-version serialization.
    pub surface: String,
    /// Provider that received the dispatched request.
    pub provider: String,
    /// Model identifier if the surface carries one. Optional because
    /// stateful surfaces (file operations, batch status polls) may not
    /// carry a model.
    pub model: Option<String>,
    /// Surface-specific usage record.
    pub usage: AiUsage,
    /// Estimated cost in USD. Zero when pricing for the surface is
    /// not in the catalog (image and audio pricing land alongside
    /// per-surface enforcement in a follow-up).
    pub cost_usd: f64,
    /// UTC Unix timestamp in seconds when the event was created.
    pub occurred_at_unix_secs: i64,
    /// Budget scope keys this event should be debited against
    /// (workspace, hostname, user, api-key, tag, model). Derived from
    /// the existing [`BudgetTracker::scope_key`] machinery so the
    /// same key shapes flow through both the event bus and the
    /// in-process budget tracker.
    pub scope_keys: Vec<String>,
}

impl AiBillingEvent {
    /// Construct a new event with the current wall-clock timestamp.
    pub fn new(
        surface: AiSurface,
        provider: impl Into<String>,
        model: Option<String>,
        usage: AiUsage,
    ) -> Self {
        Self {
            surface: surface.label().to_string(),
            provider: provider.into(),
            model,
            usage,
            cost_usd: 0.0,
            occurred_at_unix_secs: now_unix_secs(),
            scope_keys: Vec::new(),
        }
    }

    /// Construct a new event from a pre-computed surface label string.
    ///
    /// Use this when the dispatch path already carries the surface
    /// label (the stable string from [`AiSurface::label`]) and we
    /// don't want to round-trip through the `AiSurface` enum to set
    /// it. Functionally equivalent to [`AiBillingEvent::new`].
    pub fn from_label(
        surface_label: impl Into<String>,
        provider: impl Into<String>,
        model: Option<String>,
        usage: AiUsage,
    ) -> Self {
        Self {
            surface: surface_label.into(),
            provider: provider.into(),
            model,
            usage,
            cost_usd: 0.0,
            occurred_at_unix_secs: now_unix_secs(),
            scope_keys: Vec::new(),
        }
    }

    /// Attach an estimated cost in USD. Chainable so call sites can
    /// build the event in one expression.
    pub fn with_cost(mut self, cost_usd: f64) -> Self {
        self.cost_usd = cost_usd;
        self
    }

    /// Attach budget scope keys to the event. Chainable.
    pub fn with_scope_keys(mut self, keys: Vec<String>) -> Self {
        self.scope_keys = keys;
        self
    }
}

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Apply an [`AiBillingEvent`] to a [`BudgetTracker`].
///
/// Token-based usage (`Tokens`) is debited against every scope key on
/// the event. Other surface usage types (image, audio, character,
/// rerank, per-call) are accepted but only contribute to the request
/// counter today; per-unit budget enforcement for those surfaces
/// lands when the enforceable-unit budget shapes ship.
pub fn record_billing_event(tracker: &BudgetTracker, event: &AiBillingEvent) {
    let token_total: u64 = match &event.usage {
        AiUsage::Tokens { input, output } => input.saturating_add(*output),
        _ => 0,
    };
    for key in &event.scope_keys {
        tracker.record_usage(key, token_total, event.cost_usd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(
        max_tokens: Option<u64>,
        max_cost: Option<f64>,
        on_exceed: OnExceedAction,
        downgrade_to: Option<String>,
    ) -> BudgetConfig {
        BudgetConfig {
            limits: vec![BudgetLimit {
                scope: BudgetScope::Workspace,
                max_tokens,
                max_cost_usd: max_cost,
                period: None,
                downgrade_to,
            }],
            on_exceed,
        }
    }

    #[test]
    fn record_usage_increments() {
        let tracker = BudgetTracker::new();
        tracker.record_usage("ws:1", 100, 0.01);
        tracker.record_usage("ws:1", 200, 0.02);

        let usage = tracker.get_usage("ws:1");
        assert_eq!(usage.tokens, 300);
        assert!((usage.cost_usd - 0.03).abs() < 1e-10);
        assert_eq!(usage.request_count, 2);
    }

    #[test]
    fn check_limits_under_limit_returns_none() {
        let tracker = BudgetTracker::new();
        tracker.record_usage("ws:1", 50, 0.005);

        let config = make_config(Some(1000), Some(1.0), OnExceedAction::Block, None);
        assert!(tracker.check_limits(&config, "ws:1").is_none());
    }

    #[test]
    fn check_limits_token_exceeded() {
        let tracker = BudgetTracker::new();
        tracker.record_usage("ws:1", 1000, 0.01);

        let config = make_config(Some(1000), None, OnExceedAction::Block, None);
        let result = tracker.check_limits(&config, "ws:1").unwrap();
        assert!(result.exceeded);
        assert_eq!(result.action, OnExceedAction::Block);
        assert!(result.reason.contains("token limit exceeded"));
    }

    #[test]
    fn check_limits_cost_exceeded() {
        let tracker = BudgetTracker::new();
        tracker.record_usage("ws:1", 100, 5.0);

        let config = make_config(None, Some(1.0), OnExceedAction::Log, None);
        let result = tracker.check_limits(&config, "ws:1").unwrap();
        assert!(result.exceeded);
        assert_eq!(result.action, OnExceedAction::Log);
        assert!(result.reason.contains("cost limit exceeded"));
    }

    #[test]
    fn on_exceed_downgrade_with_target() {
        let tracker = BudgetTracker::new();
        tracker.record_usage("ws:1", 5000, 0.0);

        let config = make_config(
            Some(1000),
            None,
            OnExceedAction::Downgrade,
            Some("gpt-3.5-turbo".to_string()),
        );
        let result = tracker.check_limits(&config, "ws:1").unwrap();
        assert!(result.exceeded);
        assert_eq!(result.action, OnExceedAction::Downgrade);
        assert_eq!(result.downgrade_to.as_deref(), Some("gpt-3.5-turbo"));
    }

    #[test]
    fn reset_clears_usage() {
        let tracker = BudgetTracker::new();
        tracker.record_usage("ws:1", 1000, 1.0);
        tracker.reset("ws:1");

        let usage = tracker.get_usage("ws:1");
        assert_eq!(usage.tokens, 0);
        assert_eq!(usage.cost_usd, 0.0);
        assert_eq!(usage.request_count, 0);
    }

    #[test]
    fn unknown_scope_key_returns_default() {
        let tracker = BudgetTracker::new();
        let usage = tracker.get_usage("nonexistent");
        assert_eq!(usage.tokens, 0);
        assert_eq!(usage.cost_usd, 0.0);
        assert_eq!(usage.request_count, 0);
    }

    #[test]
    fn no_limits_configured_returns_none() {
        let tracker = BudgetTracker::new();
        tracker.record_usage("ws:1", 999999, 999.0);

        let config = BudgetConfig {
            limits: vec![],
            on_exceed: OnExceedAction::Block,
        };
        assert!(tracker.check_limits(&config, "ws:1").is_none());
    }

    #[test]
    fn concurrent_record_usage_is_race_correct() {
        use std::sync::Arc;
        use std::thread;

        let tracker = Arc::new(BudgetTracker::new());
        let mut handles = Vec::new();
        for _ in 0..16 {
            let t = Arc::clone(&tracker);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    t.record_usage("ws:concurrent", 1, 0.001);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let usage = tracker.get_usage("ws:concurrent");
        assert_eq!(usage.tokens, 16 * 1000);
        assert_eq!(usage.request_count, 16 * 1000);
    }

    // --- AiBillingEvent and AiUsage (Phase 8 foundations) ---

    #[test]
    fn billing_event_tokens_serializes_with_kind_tag() {
        let event = AiBillingEvent::new(
            AiSurface::ChatCompletions,
            "openai",
            Some("gpt-4o".to_string()),
            AiUsage::Tokens {
                input: 1000,
                output: 500,
            },
        )
        .with_cost(0.012)
        .with_scope_keys(vec!["ws:acme".to_string()]);

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"surface\":\"chat_completions\""));
        assert!(json.contains("\"kind\":\"tokens\""));
        assert!(json.contains("\"input\":1000"));
        assert!(json.contains("\"output\":500"));
        assert!(json.contains("\"cost_usd\":0.012"));
        // Round-trips back through Deserialize.
        let parsed: AiBillingEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn billing_event_image_usage_round_trip() {
        let event = AiBillingEvent::new(
            AiSurface::ImageGeneration,
            "openai",
            Some("dall-e-3".to_string()),
            AiUsage::Images {
                count: 2,
                resolution: "1024x1024".to_string(),
            },
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"kind\":\"images\""));
        assert!(json.contains("\"resolution\":\"1024x1024\""));
        let parsed: AiBillingEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.surface, "image_generation");
        match parsed.usage {
            AiUsage::Images { count, resolution } => {
                assert_eq!(count, 2);
                assert_eq!(resolution, "1024x1024");
            }
            _ => panic!("expected Images usage"),
        }
    }

    #[test]
    fn billing_event_audio_seconds_and_characters_round_trip() {
        let audio = AiBillingEvent::new(
            AiSurface::Realtime,
            "openai",
            Some("gpt-4o-realtime".to_string()),
            AiUsage::AudioSeconds { seconds: 12.5 },
        );
        let chars = AiBillingEvent::new(
            AiSurface::AudioSpeech,
            "openai",
            Some("tts-1".to_string()),
            AiUsage::Characters { count: 240 },
        );
        // Round-trips don't lose precision on the non-token shapes.
        let audio_json = serde_json::to_string(&audio).unwrap();
        let chars_json = serde_json::to_string(&chars).unwrap();
        assert!(audio_json.contains("\"seconds\":12.5"));
        assert!(chars_json.contains("\"count\":240"));
        let _: AiBillingEvent = serde_json::from_str(&audio_json).unwrap();
        let _: AiBillingEvent = serde_json::from_str(&chars_json).unwrap();
    }

    #[test]
    fn billing_event_rerank_units_and_per_call_round_trip() {
        let rerank = AiBillingEvent::new(
            AiSurface::Reranking,
            "cohere",
            Some("rerank-english-v3.0".to_string()),
            AiUsage::RerankUnits { documents: 42 },
        );
        let per_call = AiBillingEvent::new(
            AiSurface::Moderations,
            "openai",
            Some("omni-moderation-latest".to_string()),
            AiUsage::PerCall,
        );
        let _: AiBillingEvent =
            serde_json::from_str(&serde_json::to_string(&rerank).unwrap()).unwrap();
        let _: AiBillingEvent =
            serde_json::from_str(&serde_json::to_string(&per_call).unwrap()).unwrap();
    }

    #[test]
    fn record_billing_event_debits_tokens_against_each_scope_key() {
        let tracker = BudgetTracker::new();
        let event = AiBillingEvent::new(
            AiSurface::ChatCompletions,
            "openai",
            Some("gpt-4o".to_string()),
            AiUsage::Tokens {
                input: 800,
                output: 200,
            },
        )
        .with_cost(0.01)
        .with_scope_keys(vec!["ws:acme".to_string(), "user:alice".to_string()]);

        record_billing_event(&tracker, &event);

        let ws = tracker.get_usage("ws:acme");
        let user = tracker.get_usage("user:alice");
        assert_eq!(ws.tokens, 1000);
        assert_eq!(user.tokens, 1000);
        assert!((ws.cost_usd - 0.01).abs() < 1e-9);
        assert!((user.cost_usd - 0.01).abs() < 1e-9);
        assert_eq!(ws.request_count, 1);
        assert_eq!(user.request_count, 1);
    }

    // --- estimate_cost_for_usage and per-surface pricing helpers ---

    #[test]
    fn estimate_cost_for_usage_tokens_matches_estimate_cost() {
        let usage = AiUsage::Tokens {
            input: 1000,
            output: 500,
        };
        let via_usage = estimate_cost_for_usage("gpt-4o", &usage);
        let via_legacy = estimate_cost("gpt-4o", 1000, 500);
        assert!((via_usage - via_legacy).abs() < 1e-9);
        assert!(via_usage > 0.0);
    }

    #[test]
    fn estimate_cost_for_usage_image_dalle_3() {
        let usage_std = AiUsage::Images {
            count: 1,
            resolution: "1024x1024".to_string(),
        };
        let usage_wide = AiUsage::Images {
            count: 1,
            resolution: "1024x1792".to_string(),
        };
        let usage_pair = AiUsage::Images {
            count: 2,
            resolution: "1024x1024".to_string(),
        };
        assert!((estimate_cost_for_usage("dall-e-3", &usage_std) - 0.040).abs() < 1e-9);
        assert!((estimate_cost_for_usage("dall-e-3", &usage_wide) - 0.080).abs() < 1e-9);
        assert!((estimate_cost_for_usage("dall-e-3", &usage_pair) - 0.080).abs() < 1e-9);
    }

    #[test]
    fn estimate_cost_for_usage_image_dalle_2_resolutions() {
        for (res, expected) in [("256x256", 0.016), ("512x512", 0.018), ("1024x1024", 0.020)] {
            let usage = AiUsage::Images {
                count: 1,
                resolution: res.to_string(),
            };
            let got = estimate_cost_for_usage("dall-e-2", &usage);
            assert!(
                (got - expected).abs() < 1e-9,
                "expected ${expected} at {res}, got ${got}"
            );
        }
    }

    #[test]
    fn estimate_cost_for_usage_audio_transcription_per_second() {
        let usage = AiUsage::AudioSeconds { seconds: 60.0 };
        // Whisper: $0.006 per minute = $0.36 per hour, $0.0001 per second.
        let got = estimate_cost_for_usage("whisper-1", &usage);
        assert!((got - 0.006).abs() < 1e-9, "got ${got}");
    }

    #[test]
    fn estimate_cost_for_usage_audio_speech_per_character() {
        let usage = AiUsage::Characters { count: 1_000_000 };
        // tts-1: $15 per 1M chars.
        let standard = estimate_cost_for_usage("tts-1", &usage);
        assert!((standard - 15.0).abs() < 1e-6, "got ${standard}");
        // tts-1-hd: $30 per 1M chars.
        let hd = estimate_cost_for_usage("tts-1-hd", &usage);
        assert!((hd - 30.0).abs() < 1e-6, "got ${hd}");
    }

    #[test]
    fn estimate_cost_for_usage_rerank_per_document() {
        let usage = AiUsage::RerankUnits { documents: 1000 };
        // Cohere rerank: $2 per 1000 docs.
        let got = estimate_cost_for_usage("rerank-english-v3.0", &usage);
        assert!((got - 2.0).abs() < 1e-9, "got ${got}");
    }

    #[test]
    fn estimate_cost_for_usage_per_call_is_zero() {
        assert_eq!(estimate_cost_for_usage("any-model", &AiUsage::PerCall), 0.0);
    }

    #[test]
    fn estimate_cost_for_usage_unknown_model_returns_zero_for_per_unit_surfaces() {
        // Image / audio / character / rerank with an unknown model
        // surfaces 0.0 (so operators don't see fabricated cost). This
        // is the opposite default from token-based pricing, which
        // falls back to a pessimistic blended rate so a budget cap
        // still fires.
        let img = AiUsage::Images {
            count: 1,
            resolution: "1024x1024".to_string(),
        };
        assert_eq!(estimate_cost_for_usage("unknown-image-model", &img), 0.0);
        let audio = AiUsage::AudioSeconds { seconds: 30.0 };
        assert_eq!(estimate_cost_for_usage("unknown-audio-model", &audio), 0.0);
        let chars = AiUsage::Characters { count: 1000 };
        assert_eq!(estimate_cost_for_usage("unknown-tts-model", &chars), 0.0);
        let rerank = AiUsage::RerankUnits { documents: 10 };
        assert_eq!(
            estimate_cost_for_usage("unknown-rerank-model", &rerank),
            0.0
        );
    }

    #[test]
    fn record_billing_event_non_token_usage_records_zero_tokens() {
        // Image / audio / character / rerank / per-call events still
        // tick the request_count and accumulate any per-call cost, but
        // they contribute zero tokens because the unit doesn't map.
        let tracker = BudgetTracker::new();
        let event = AiBillingEvent::new(
            AiSurface::ImageGeneration,
            "openai",
            Some("dall-e-3".to_string()),
            AiUsage::Images {
                count: 1,
                resolution: "1024x1024".to_string(),
            },
        )
        .with_cost(0.04)
        .with_scope_keys(vec!["ws:acme".to_string()]);

        record_billing_event(&tracker, &event);
        let usage = tracker.get_usage("ws:acme");
        assert_eq!(usage.tokens, 0, "image events do not contribute tokens");
        assert!((usage.cost_usd - 0.04).abs() < 1e-9);
        assert_eq!(usage.request_count, 1);
    }
}

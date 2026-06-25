//! AI request handler configuration and path parsing.

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::budget::BudgetConfig;
use crate::guardrails::GuardrailsConfig;
use crate::identity::VirtualKeyConfig;
use crate::ids::ModelId;
use crate::provider::ProviderConfig;
use crate::ratelimit::{ModelRateConfig, SurfaceRateConfig};
use crate::routing::RoutingStrategy;

/// AI gateway handler configuration.
#[derive(Debug, Deserialize)]
pub struct AiHandlerConfig {
    /// Configured upstream AI providers eligible for routing.
    pub providers: Vec<ProviderConfig>,
    /// Strategy used to select a provider for each request.
    #[serde(default = "default_strategy", deserialize_with = "deserialize_routing")]
    pub routing: RoutingStrategy,
    /// Optional allow-list of model names; empty means allow all.
    #[serde(default)]
    pub allowed_models: Vec<ModelId>,
    /// Block-list of model names that takes precedence over the allow-list.
    #[serde(default)]
    pub blocked_models: Vec<ModelId>,
    /// Maximum request body size in bytes accepted by the gateway.
    #[serde(default)]
    pub max_body_size: Option<usize>,
    /// Optional input/output guardrails pipeline.
    #[serde(default)]
    pub guardrails: Option<GuardrailsConfig>,
    /// Optional budget enforcement configuration.
    #[serde(default)]
    pub budget: Option<BudgetConfig>,
    /// Virtual API keys mapped to provider keys and scopes.
    #[serde(default)]
    pub virtual_keys: Vec<VirtualKeyConfig>,
    /// Per-model rate limit overrides keyed by model name.
    #[serde(default)]
    pub model_rate_limits: HashMap<String, ModelRateConfig>,
    /// Per-surface rate-limit overrides keyed by surface label
    /// (`chat_completions`, `assistants`, `image_generation`, etc.;
    /// see [`crate::handler::AiSurface::label`]). Operators may cap
    /// expensive surfaces (image generation, realtime) independently
    /// of chat. Surfaces without an entry are not capped.
    #[serde(default)]
    pub per_surface_rate_limits: HashMap<String, SurfaceRateConfig>,
    /// Maximum concurrent in-flight requests per provider.
    #[serde(default)]
    pub max_concurrent: Option<HashMap<String, u32>>,
    /// Optional per-provider resilience policy (circuit breaker plus
    /// outlier detection plus active health probes). When set, the
    /// router skips providers whose state machine has tripped, the
    /// same way the proxy / load_balancer paths exclude unhealthy
    /// upstreams.
    #[serde(default)]
    pub resilience: Option<AiResilienceConfig>,
    /// Optional shadow / side-by-side eval. The primary response is
    /// served unchanged; a copy of every request goes to the shadow
    /// provider concurrently and metrics (TTFT, tokens, cost,
    /// finish_reason) are logged.
    #[serde(default)]
    pub shadow: Option<AiShadowConfig>,
    /// Optional pattern-aware PII redaction applied at the request
    /// and (optionally) response body boundary. When set the gateway
    /// scans the JSON body for the configured PII shapes and
    /// rewrites them to fixed markers before forwarding upstream.
    /// See `sbproxy_security::pii::PiiConfig` for the rule schema.
    #[serde(default)]
    pub pii: Option<sbproxy_security::pii::PiiConfig>,
    /// WOR-1228: when `true`, emit prompt and completion text as the
    /// OpenInference `input.value` / `output.value` span attributes plus
    /// role-aware message events so trace backends (Phoenix, Langfuse) show
    /// the actual conversation, not just token counts. Off by default
    /// because content is sensitive: when on, the text is routed through the
    /// configured `pii` redactor (if any), the always-on secret redactor, and
    /// a capture payload cap before it lands on the span. Enable only with
    /// `pii` configured and a trace backend inside your trust boundary.
    #[serde(default)]
    pub trace_content: bool,
    /// Opaque semantic-cache configuration block. The OSS proxy
    /// stores this verbatim and surfaces it through the stream cache
    /// recorder hook so the enterprise implementation can read its
    /// `streaming` sub-block (`enabled`, `replay_pacing`, ...) without
    /// the OSS pipeline having to validate or interpret any of those
    /// fields. Shape contract lives in the enterprise crate; OSS only
    /// passes the value through.
    #[serde(default)]
    pub semantic_cache: Option<serde_json::Value>,
    /// WOR-800: per-origin versioned prompt store. Named prompts, each
    /// with one or more numbered versions and optional reusable
    /// `partials:` fragments, referenced from a request body as
    /// `"prompt": "name@version"` (or bare `"name"` for the pinned
    /// default version) and rendered server-side with the request
    /// variables before the messages reach the provider.
    #[serde(default)]
    pub prompts: Option<crate::prompts::PromptStore>,
    /// Selects the SSE usage parser for the streaming relay.
    /// Recognized values: `auto` (default; chooses by upstream URL,
    /// `Content-Type`, or response `X-Provider` header), `openai`,
    /// `anthropic`, `vertex`, `bedrock`, `cohere`, `ollama`,
    /// `generic`, or `none` (disable parsing). Unknown values warn
    /// and fall back to `generic` so a typo never silently disables
    /// budget recording.
    #[serde(default = "default_usage_parser")]
    pub usage_parser: String,
    /// Usage sinks: forward a record of every completed LLM call to external
    /// systems (a JSONL file, an HTTP collector). The open-source seam that
    /// LiteLLM's `success_callback` / `callbacks` map onto. Empty by default.
    #[serde(default)]
    pub usage_sinks: Vec<crate::usage_sink::UsageSinkConfig>,
    /// Lazy-built compiled redactor cached on the per-origin
    /// config. Built on first use so config-load does not pay the
    /// regex-compile cost for origins that never serve a request.
    /// `None` value inside the OnceLock means "tried to build and
    /// either no config or invalid"; the request path treats both
    /// the same way (skip redaction).
    #[serde(skip)]
    pub(crate) pii_redactor: OnceLock<Option<sbproxy_security::pii::PiiRedactor>>,
    /// Lazy-built OSS embedding semantic cache (WOR-796), parsed from
    /// the `semantic_cache` block on first use. `None` inside the
    /// OnceLock means the cache is disabled or misconfigured; the
    /// request path treats both as "no semantic layer". Held in an
    /// `Arc` so the instance (and its entries) persist across requests
    /// for the lifetime of this per-origin config.
    #[serde(skip)]
    pub(crate) embedding_cache:
        OnceLock<Option<std::sync::Arc<crate::semantic_cache::EmbeddingCache>>>,
    /// Lazily-built provider router (WOR-798), held in an `Arc` so its
    /// per-provider latency / token / connection state persists across
    /// requests for the lifetime of this per-origin config (rebuilt only
    /// on config reload). Latency- and usage-aware strategies
    /// (`peak_ewma`, `least_token_usage`, `lowest_latency`, ...) depend on
    /// this persistence; a per-request router would reset the state every
    /// call and degrade them to round-robin.
    #[serde(skip)]
    pub(crate) router: OnceLock<std::sync::Arc<crate::routing::Router>>,
    /// Lazy-built usage sinks, held in `Arc`s so a single instance per sink is
    /// shared across requests for the lifetime of this per-origin config.
    #[serde(skip)]
    pub(crate) usage_sinks_built: OnceLock<Vec<std::sync::Arc<dyn crate::usage_sink::UsageSink>>>,
}

fn default_usage_parser() -> String {
    "auto".to_string()
}

impl AiHandlerConfig {
    /// Return the compiled PII redactor for this handler, building
    /// it on first call. `None` when redaction is not configured
    /// or the configuration failed to compile (which is logged).
    pub fn pii_redactor(&self) -> Option<&sbproxy_security::pii::PiiRedactor> {
        self.pii_redactor
            .get_or_init(|| {
                let cfg = self.pii.as_ref()?;
                if !cfg.enabled {
                    return None;
                }
                match sbproxy_security::pii::PiiRedactor::from_config(cfg) {
                    Ok(r) => Some(r),
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "AI handler: PII redactor failed to compile; redaction disabled"
                        );
                        None
                    }
                }
            })
            .as_ref()
    }

    /// Return the OSS embedding semantic cache for this handler,
    /// building it on first call (WOR-796). `None` when the
    /// `semantic_cache` block is absent, disabled, missing the
    /// `embedding` provider sub-block, or fails to parse. The cache is
    /// opt-in, so the common path returns `None` with no cost beyond
    /// the one-time parse.
    pub fn embedding_cache(
        &self,
    ) -> Option<&std::sync::Arc<crate::semantic_cache::EmbeddingCache>> {
        self.embedding_cache
            .get_or_init(|| {
                let value = self.semantic_cache.as_ref()?;
                let cfg: crate::semantic_cache::EmbeddingCacheConfig =
                    match serde_json::from_value(value.clone()) {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "AI handler: semantic_cache block did not parse as an embedding \
                                 cache config; semantic caching disabled"
                            );
                            return None;
                        }
                    };
                crate::semantic_cache::EmbeddingCache::from_config(&cfg).map(std::sync::Arc::new)
            })
            .as_ref()
    }

    /// Return the shared usage sinks for this handler, building them once.
    /// Empty when none are configured. Sinks are best-effort and never fail a
    /// request.
    pub fn usage_sinks(&self) -> &[std::sync::Arc<dyn crate::usage_sink::UsageSink>] {
        self.usage_sinks_built
            .get_or_init(|| crate::usage_sink::build_sinks(&self.usage_sinks))
            .as_slice()
    }

    /// Return the shared provider router for this handler, building it
    /// once (WOR-798). The router holds live per-provider latency / token
    /// / connection state, so it must be reused across requests rather
    /// than reconstructed per request; this accessor guarantees a single
    /// instance per `AiHandlerConfig` (until config reload).
    pub fn router(&self) -> std::sync::Arc<crate::routing::Router> {
        self.router
            .get_or_init(|| {
                std::sync::Arc::new(crate::routing::Router::new(
                    self.routing.clone(),
                    self.providers.len(),
                ))
            })
            .clone()
    }

    /// Apply PII redaction to a parsed request body. Returns whether
    /// any redactor ran. Tests use this to assert that the wiring
    /// the request handler relies on (PII config -> redactor ->
    /// in-place JSON walk) actually mutates the body the way the
    /// downstream forward path will see it.
    ///
    /// This mirrors the call site in
    /// `sbproxy-core/src/server.rs::handle_ai_proxy` and is the
    /// integration shim e2e tests exercise.
    pub fn apply_request_pii(&self, body: &mut serde_json::Value) -> bool {
        let cfg = match self.pii.as_ref() {
            Some(c) if c.enabled && c.redact_request => c,
            _ => return false,
        };
        // Touching `cfg` keeps clippy from flagging the binding as
        // unused; the actual gate is `pii_redactor()` which reads
        // `self.pii` directly.
        let _ = cfg;
        if let Some(redactor) = self.pii_redactor() {
            redactor.redact_json(body);
            return true;
        }
        false
    }

    /// Whether request-body PII redaction is active for all named
    /// rules required by a matched credential. An empty requirement
    /// only requires that some request redactor is active.
    pub fn satisfies_pii_redaction_requirement(&self, required_rules: &[String]) -> bool {
        let Some(cfg) = self
            .pii
            .as_ref()
            .filter(|cfg| cfg.enabled && cfg.redact_request)
        else {
            return false;
        };
        let Some(redactor) = self.pii_redactor() else {
            return false;
        };
        if redactor.is_empty() {
            return false;
        }
        if required_rules.is_empty() {
            return true;
        }

        let mut active = std::collections::BTreeSet::new();
        if cfg.defaults {
            active.extend(
                sbproxy_security::pii::default_rules()
                    .into_iter()
                    .map(|r| r.name),
            );
        }
        active.extend(cfg.rules.iter().map(|r| r.name.clone()));
        required_rules.iter().all(|rule| active.contains(rule))
    }
}

/// Per-provider resilience signals layered on top of the routing
/// strategy. Each signal independently ejects a provider; when every
/// provider is ejected, the router falls back to the unfiltered list
/// rather than returning no provider at all.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct AiResilienceConfig {
    /// Formal Closed -> Open -> HalfOpen breaker per provider.
    #[serde(default)]
    pub circuit_breaker: Option<AiCircuitBreakerConfig>,
    /// Sliding-window failure-rate ejection.
    #[serde(default)]
    pub outlier_detection: Option<AiOutlierConfig>,
    /// Active health probe of the provider's `/v1/models` endpoint.
    #[serde(default)]
    pub health_check: Option<AiHealthCheckConfig>,
}

/// Circuit-breaker tuning shared with the load_balancer flavour.
#[derive(Debug, Deserialize, Clone)]
pub struct AiCircuitBreakerConfig {
    /// Consecutive failures (5xx or transport error) before the breaker opens.
    #[serde(default = "default_cb_failure_threshold")]
    pub failure_threshold: u32,
    /// Consecutive half-open successes required to close the breaker.
    #[serde(default = "default_cb_success_threshold")]
    pub success_threshold: u32,
    /// Cooldown in seconds after opening before a half-open probe is allowed.
    #[serde(default = "default_cb_open_duration_secs")]
    pub open_duration_secs: u64,
}

fn default_cb_failure_threshold() -> u32 {
    5
}
fn default_cb_success_threshold() -> u32 {
    2
}
fn default_cb_open_duration_secs() -> u64 {
    30
}

/// Outlier-detector tuning shared with the load_balancer flavour.
#[derive(Debug, Deserialize, Clone)]
pub struct AiOutlierConfig {
    /// Failure-rate threshold (0.0 to 1.0) over the window before ejection.
    #[serde(default = "default_outlier_threshold")]
    pub threshold: f64,
    /// Sliding window length in seconds.
    #[serde(default = "default_outlier_window")]
    pub window_secs: u64,
    /// Minimum sample count before the failure-rate is evaluated.
    #[serde(default = "default_outlier_min")]
    pub min_requests: u32,
    /// How long an ejected provider stays out of the rotation, in seconds.
    #[serde(default = "default_outlier_eject")]
    pub ejection_duration_secs: u64,
}

fn default_outlier_threshold() -> f64 {
    0.5
}
fn default_outlier_window() -> u64 {
    60
}
fn default_outlier_min() -> u32 {
    5
}
fn default_outlier_eject() -> u64 {
    30
}

/// Active probe of an AI provider. The probe is a `GET /models`
/// (or `path` if overridden); a 2xx response counts as success.
#[derive(Debug, Deserialize, Clone)]
pub struct AiHealthCheckConfig {
    /// Path probed on each provider's base URL. Defaults to `/models`.
    #[serde(default = "default_health_path")]
    pub path: String,
    /// How often to run the probe, in seconds.
    #[serde(default = "default_health_interval")]
    pub interval_secs: u64,
    /// Probe request timeout in milliseconds.
    #[serde(default = "default_health_timeout_ms")]
    pub timeout_ms: u64,
    /// Consecutive probe failures required to mark the provider unhealthy.
    #[serde(default = "default_health_unhealthy")]
    pub unhealthy_threshold: u32,
    /// Consecutive probe successes required to mark the provider healthy.
    #[serde(default = "default_health_healthy")]
    pub healthy_threshold: u32,
}

fn default_health_path() -> String {
    "/models".to_string()
}
fn default_health_interval() -> u64 {
    30
}
fn default_health_timeout_ms() -> u64 {
    5000
}
fn default_health_unhealthy() -> u32 {
    3
}
fn default_health_healthy() -> u32 {
    2
}

/// Shadow / side-by-side eval: send the same request to a second
/// provider concurrently and log metadata. The shadow response is
/// drained and discarded; the primary's response goes to the client
/// unchanged.
///
/// Shadow tasks are supervised by a bounded queue. When the in-flight
/// queue fills up the new request is dropped (a counter ticks) instead
/// of being silently spawned, and each task has a hard wall-clock
/// timeout that, when exceeded, drops the future and ticks a separate
/// timeout counter. See `sbproxy_ai::client::AiClient` for the
/// supervisor implementation.
#[derive(Debug, Deserialize, Clone)]
pub struct AiShadowConfig {
    /// Provider name to shadow against. Must also appear in the
    /// `providers` list (so its API key, base URL, and rate limits
    /// resolve normally). Use a different model than the primary if
    /// you want to A/B different model versions.
    pub provider: String,
    /// Optional model override for the shadow request. Defaults to
    /// the same model the client sent.
    #[serde(default)]
    pub model: Option<String>,
    /// Sample rate in `[0.0, 1.0]`. Default `1.0` (mirror every
    /// request). Set lower to avoid doubling spend on every call.
    #[serde(default = "default_shadow_sample_rate")]
    pub sample_rate: f32,
    /// Per-shadow-request HTTP timeout in milliseconds. Default
    /// 30000. This is the upstream request timeout passed to reqwest.
    #[serde(default = "default_shadow_timeout_ms")]
    pub timeout_ms: u64,
    /// Wall-clock supervisor timeout in milliseconds. The supervisor
    /// drops the spawned shadow future and ticks
    /// `sbproxy_ai_shadow_timeout_total` once this elapses, even if
    /// reqwest is still mid-handshake. Defaults to 30000 and is
    /// independent of `timeout_ms` so the operator can guard against
    /// providers that hang inside DNS, TLS, or pre-body read paths.
    #[serde(default = "default_shadow_task_timeout_ms")]
    pub task_timeout_ms: u64,
}

fn default_shadow_sample_rate() -> f32 {
    1.0
}
fn default_shadow_timeout_ms() -> u64 {
    30_000
}
fn default_shadow_task_timeout_ms() -> u64 {
    30_000
}

fn default_strategy() -> RoutingStrategy {
    RoutingStrategy::RoundRobin
}

/// Deserialize routing from either:
/// - A flat string: `"round_robin"` (Rust format)
/// - A nested object: `{strategy: "round_robin", ...}` (Go format)
/// - A cascade object: `{strategy: "cascade", tiers: [...], max_total_cost: ...}`
fn deserialize_routing<'de, D>(deserializer: D) -> Result<RoutingStrategy, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use crate::routing::{CascadeConfig, CascadeTier};
    use serde::de::Error;

    // Step 1: capture the raw input. Cascade carries a struct
    // payload alongside the `strategy` discriminator, so we cannot
    // round-trip through a unit-only enum like `RoutingStrategy`
    // before reading the cascade-specific fields.
    let value = serde_json::Value::deserialize(deserializer)?;

    // Flat string form: `"round_robin"` etc. Cascade has no flat
    // form because it carries required fields.
    if value.is_string() {
        return serde_json::from_value::<RoutingStrategy>(value).map_err(Error::custom);
    }

    // Nested object form: must have a `strategy` field. When the
    // strategy is `cascade`, the same object also carries `tiers`
    // and optional `max_total_cost`. Every other strategy is a
    // unit variant and ignores the extra keys.
    let obj = value.as_object().ok_or_else(|| {
        Error::custom("routing must be either a strategy name string or an object")
    })?;
    let strategy_raw = obj
        .get("strategy")
        .ok_or_else(|| Error::custom("routing object is missing the required `strategy` field"))?;
    let strategy_name = strategy_raw
        .as_str()
        .ok_or_else(|| Error::custom("routing.strategy must be a string"))?;

    if strategy_name == "cascade" {
        #[derive(Deserialize)]
        struct CascadePayload {
            #[serde(default)]
            tiers: Vec<CascadeTier>,
            #[serde(default)]
            max_total_cost: Option<u64>,
        }
        let payload: CascadePayload =
            serde_json::from_value(serde_json::Value::Object(obj.clone()))
                .map_err(Error::custom)?;
        if payload.tiers.is_empty() {
            return Err(Error::custom("cascade routing requires at least one tier"));
        }
        return Ok(RoutingStrategy::Cascade(CascadeConfig {
            tiers: payload.tiers,
            max_total_cost: payload.max_total_cost,
        }));
    }

    // WOR-797: cost/quality routing carries cheap_provider /
    // frontier_provider / cost_threshold alongside the discriminator.
    // `learned` is accepted as an alias.
    if strategy_name == "cost_quality" || strategy_name == "learned" {
        let cfg: crate::cost_quality::CostQualityConfig =
            serde_json::from_value(serde_json::Value::Object(obj.clone()))
                .map_err(Error::custom)?;
        return Ok(RoutingStrategy::CostQuality(cfg));
    }

    // Re-route every other strategy through the existing
    // unit-enum deserializer so the `snake_case` rename stays in
    // one place.
    let strategy_value = serde_json::Value::String(strategy_name.to_string());
    serde_json::from_value::<RoutingStrategy>(strategy_value).map_err(Error::custom)
}

impl AiResilienceConfig {
    /// Maximum total provider attempts when a request fails. Falls
    /// back to the count of enabled providers when no
    /// `circuit_breaker.failure_threshold` is configured (i.e. just
    /// "try every provider once" semantics).
    pub fn max_attempts(&self, num_providers: usize) -> usize {
        // Cap at provider count; the client also short-circuits when
        // it sees the same provider twice in a row.
        std::cmp::max(1, num_providers).min(num_providers.max(1))
    }
}

impl AiHandlerConfig {
    /// Build from a generic JSON value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let mut config: Self = serde_json::from_value(value)?;
        // WOR-1044 PR4: reversible PII and semantic caching cannot
        // safely co-exist on the same origin. The semantic cache
        // keys responses on a similarity hash of the prompt; two
        // requests that hash to the same key can carry different
        // captured originals (different customer names, order
        // numbers, ...). A cache hit would restore the prior
        // request's placeholders against the new request's capture
        // map, surfacing the wrong customer's data. The safer
        // disposition is to disable semantic caching whenever any
        // configured PII rule on the same origin is reversible.
        // Out-of-band placeholder maps (a per-request side channel
        // keyed off the cache hit) would re-enable both at once but
        // are out of scope for v1.
        let has_reversible = config
            .pii
            .as_ref()
            .map(|p| p.rules.iter().any(|r| r.reversible))
            .unwrap_or(false);
        if has_reversible && config.semantic_cache.is_some() {
            tracing::warn!(
                "ai handler: semantic cache disabled because reversible PII would cross requests"
            );
            config.semantic_cache = None;
        }
        // WOR-603: validate each provider's base_url at config load so an
        // SSRF target (file://, link-local metadata, loopback, ...) fails
        // fast here rather than being dispatched at request time.
        for provider in &config.providers {
            provider
                .validate_base_url()
                .map_err(|e| anyhow::anyhow!("ai provider {:?} base_url: {e}", provider.name))?;
        }
        // WOR-625: validate provider names and the model allow-list here
        // so a typo (`openAI` for `openai`) or an unknown model is caught
        // at config load rather than silently misrouting at request time.
        // The provider catalog is open (YAML-driven), so a provider passes
        // when it carries an explicit `base_url`, or its catalog key (its
        // `provider_type`, else its `name`) is an exact catalog entry.
        // Catalog keys are lowercase, so a case mismatch is rejected with a
        // suggestion.
        for provider in &config.providers {
            if provider.base_url.is_some() {
                continue; // explicit endpoint: any name is fine
            }
            // When `provider_type` is set it is the catalog key and `name`
            // is just a free-form label; otherwise `name` is the key.
            let (label, key) = match provider.provider_type.as_deref() {
                Some(pt) => ("provider_type", pt),
                None => ("provider name", provider.name.as_str()),
            };
            let lower = key.to_ascii_lowercase();
            if key == lower && crate::providers::get_provider_info(key).is_some() {
                continue; // exact catalog entry (canonical name or alias)
            }
            if crate::providers::get_provider_info(key).is_some() {
                // Resolves case-insensitively but not exactly: an
                // unambiguous casing typo (`openAI` for `openai`). Exact
                // names are what routing rules match, so this is rejected.
                anyhow::bail!(
                    "ai {label} {key:?} is not a known provider; names are case-sensitive, did you mean {lower:?}?"
                );
            }
            // Completely unknown name with no base_url. This may be an
            // intentional custom label, so it is a warning rather than a
            // hard error; without a base_url it falls back to a localhost
            // endpoint, which is usually a misconfiguration.
            tracing::warn!(
                "ai {label} {key:?} is not in the provider catalog and has no base_url; it will fall back to a localhost endpoint. Set base_url for a custom provider, or use a catalog provider name."
            );
        }
        // Validate the model allow-list against the union of the providers'
        // declared `models` lists, but only when every provider declares one
        // (an empty list defers to the upstream catalog and accepts any
        // model, so there is nothing to check against).
        if !config.allowed_models.is_empty()
            && !config.providers.is_empty()
            && config.providers.iter().all(|p| !p.models.is_empty())
        {
            let known: std::collections::HashSet<&str> = config
                .providers
                .iter()
                .flat_map(|p| p.models.iter().map(ModelId::as_str))
                .collect();
            for model in &config.allowed_models {
                if !known.contains(model.as_str()) {
                    anyhow::bail!(
                        "ai allowed_models entry {model:?} is not served by any configured provider"
                    );
                }
            }
        }
        Ok(config)
    }

    /// Number of provider attempts allowed for one client request.
    /// Defaults to 1 (no retry) when no `resilience` block is set.
    /// Otherwise capped at the configured provider count so we never
    /// loop forever on a totally degraded fleet.
    pub fn resilience_max_attempts(&self) -> usize {
        if self.resilience.is_some() {
            std::cmp::min(self.providers.len().max(1), 5)
        } else {
            1
        }
    }

    /// Check if a model is allowed by the allow/block lists.
    pub fn is_model_allowed(&self, model: &str) -> bool {
        // Block list takes precedence
        if !self.blocked_models.is_empty() && self.blocked_models.iter().any(|m| m == model) {
            return false;
        }
        // If allow list is set, model must be in it
        if !self.allowed_models.is_empty() {
            return self.allowed_models.iter().any(|m| m == model);
        }
        true
    }
}

/// Detected AI API path type.
///
/// Superseded by [`AiSurface`], which covers the full OpenAI-compatible
/// surface area (assistants, threads, batches, fine-tuning, files,
/// realtime, image, audio, moderations, reranking) in addition to the
/// three originally recognised endpoints. Kept for source compatibility
/// with downstream callers; new code should use `AiSurface`.
#[derive(Debug, PartialEq, Eq)]
pub enum AiApiPath {
    /// OpenAI-compatible chat completions endpoint.
    ChatCompletions,
    /// Model listing endpoint.
    Models,
    /// Embeddings creation endpoint.
    Embeddings,
    /// Path did not match any known AI endpoint.
    Unknown,
}

/// Parse a request path to determine the AI API endpoint type.
///
/// Superseded by [`classify_surface`]. Retained for source-compatible
/// callers; the dispatch path now uses `classify_surface`.
pub fn parse_ai_path(path: &str) -> AiApiPath {
    if path.ends_with("/chat/completions") {
        AiApiPath::ChatCompletions
    } else if path.ends_with("/models") {
        AiApiPath::Models
    } else if path.ends_with("/embeddings") {
        AiApiPath::Embeddings
    } else {
        AiApiPath::Unknown
    }
}

/// Classified AI API surface for a given request.
///
/// Unifies the older `AiApiPath` and `AiEndpoint` enums. Every variant
/// corresponds to a distinct dispatch path inside `handle_ai_proxy`.
/// New variants may be added in minor releases; pattern matches must
/// include a wildcard arm.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AiSurface {
    /// `POST /v1/chat/completions`.
    ChatCompletions,
    /// `GET /v1/models` or `GET /v1/models/{id}`.
    Models,
    /// `POST /v1/embeddings`.
    Embeddings,
    /// `/v1/assistants` and `/v1/assistants/{id}` (all methods).
    Assistants,
    /// `/v1/threads` and any sub-path (`messages`, `runs`, `cancel`, ...).
    Threads,
    /// `/v1/batches` and `/v1/batches/{id}` (and `/cancel`).
    Batches,
    /// `/v1/fine_tuning/jobs` and sub-paths (`events`, `cancel`).
    FineTuning,
    /// `/v1/files`, `/v1/files/{id}`, `/v1/files/{id}/content`.
    Files,
    /// `GET /v1/realtime` (WebSocket upgrade).
    Realtime,
    /// `POST /v1/images/generations`.
    ImageGeneration,
    /// `POST /v1/images/edits` (multipart body).
    ImageEdits,
    /// `POST /v1/images/variations` (multipart body).
    ImageVariations,
    /// `POST /v1/audio/transcriptions` (multipart body).
    AudioTranscription,
    /// `POST /v1/audio/speech` (binary response body).
    AudioSpeech,
    /// `POST /v1/moderations`.
    Moderations,
    /// `POST /v1/rerank` or `POST /v1/reranking`.
    Reranking,
    /// `POST /v1/messages` (Anthropic Messages native inbound). Bridged
    /// to the hub by `format::AnthropicMessagesFormat`.
    Messages,
    /// `POST /v1/responses` (OpenAI Responses native inbound). Bridged
    /// to the hub by `format::OpenAiResponsesFormat`.
    Responses,
    /// Path did not match any known AI surface.
    Unknown,
}

impl AiSurface {
    /// Short identifier suitable for metric labels and tracing
    /// attributes. Stable across versions.
    pub fn label(&self) -> &'static str {
        match self {
            AiSurface::ChatCompletions => "chat_completions",
            AiSurface::Models => "models",
            AiSurface::Embeddings => "embeddings",
            AiSurface::Assistants => "assistants",
            AiSurface::Threads => "threads",
            AiSurface::Batches => "batches",
            AiSurface::FineTuning => "fine_tuning",
            AiSurface::Files => "files",
            AiSurface::Realtime => "realtime",
            AiSurface::ImageGeneration => "image_generation",
            AiSurface::ImageEdits => "image_edits",
            AiSurface::ImageVariations => "image_variations",
            AiSurface::AudioTranscription => "audio_transcription",
            AiSurface::AudioSpeech => "audio_speech",
            AiSurface::Moderations => "moderations",
            AiSurface::Reranking => "reranking",
            AiSurface::Messages => "messages",
            AiSurface::Responses => "responses",
            AiSurface::Unknown => "unknown",
        }
    }
}

/// Extract the surface-specific input-text field from a parsed JSON
/// body, suitable for running through input guardrails or PII
/// redactors.
///
/// Different surfaces carry user input in different body fields:
/// image generation/edits/variations uses `body["prompt"]`, audio
/// speech synthesis uses `body["input"]`, and reranking uses
/// `body["query"]`. Chat-shape surfaces (ChatCompletions, Assistants,
/// Threads) carry input in `body["messages"]` and should be guarded
/// via [`crate::guardrails::GuardrailPipeline::check_input`] instead.
///
/// Returns `None` for surfaces whose input is not a single text field
/// (chat-shape surfaces, binary/multipart surfaces, GET-only surfaces).
pub fn extract_input_text(surface: &AiSurface, body: &serde_json::Value) -> Option<String> {
    let field = match surface {
        AiSurface::ImageGeneration | AiSurface::ImageEdits | AiSurface::ImageVariations => "prompt",
        AiSurface::AudioSpeech => "input",
        AiSurface::Reranking => "query",
        AiSurface::Moderations => "input",
        _ => return None,
    };
    body.get(field)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Classify an inbound request path (and method, where it disambiguates)
/// into an [`AiSurface`].
///
/// The classifier is method-aware where the OpenAI API uses the same path
/// for different surfaces (none today, but the signature reserves the
/// option). Paths are matched after stripping any `/v1` or `/api/v1`
/// prefix and any trailing slash, so the proxy works regardless of
/// whether the operator's clients send canonical or prefixed paths.
pub fn classify_surface(_method: &str, path: &str) -> AiSurface {
    // Strip query string and trailing slash, then strip any /v1 or
    // /api/v1 prefix.
    let path = path.split('?').next().unwrap_or(path);
    let path = path.trim_end_matches('/');
    let path = path
        .strip_prefix("/api/v1")
        .or_else(|| path.strip_prefix("/v1"))
        .unwrap_or(path);
    let path = if path.is_empty() { "/" } else { path };

    // Split into segments for prefix-aware matching.
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    match segments.as_slice() {
        ["chat", "completions"] => AiSurface::ChatCompletions,
        ["models"] | ["models", _] => AiSurface::Models,
        ["embeddings"] => AiSurface::Embeddings,

        // Assistants and any sub-path.
        ["assistants", ..] => AiSurface::Assistants,

        // Threads and any sub-path (messages, runs, cancel).
        ["threads", ..] => AiSurface::Threads,

        // Batches and any sub-path.
        ["batches", ..] => AiSurface::Batches,

        // Fine-tuning: OpenAI uses `/v1/fine_tuning/jobs[/...]`.
        ["fine_tuning", ..] => AiSurface::FineTuning,

        // Files and content sub-path.
        ["files"] | ["files", _] | ["files", _, "content"] => AiSurface::Files,

        // Realtime WebSocket.
        ["realtime", ..] => AiSurface::Realtime,

        // Image surfaces. `generations` does not take a multipart body;
        // `edits` and `variations` do.
        ["images", "generations"] => AiSurface::ImageGeneration,
        ["images", "edits"] => AiSurface::ImageEdits,
        ["images", "variations"] => AiSurface::ImageVariations,

        // Audio.
        ["audio", "transcriptions"] => AiSurface::AudioTranscription,
        ["audio", "translations"] => AiSurface::AudioTranscription, // same dispatch
        ["audio", "speech"] => AiSurface::AudioSpeech,

        ["moderations"] => AiSurface::Moderations,

        // Reranking has two canonical names.
        ["rerank"] | ["reranking"] => AiSurface::Reranking,

        // Native-format inbound paths. These bridge to the
        // hub format and then dispatch through the same upstream
        // pipeline as chat completions.
        ["messages"] => AiSurface::Messages,
        ["responses"] => AiSurface::Responses,

        _ => AiSurface::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_sinks_parse_and_build_from_config() {
        let cfg: AiHandlerConfig = serde_json::from_value(serde_json::json!({
            "providers": [{"name": "openai", "api_key": "k", "models": ["gpt-4o-mini"]}],
            "usage_sinks": [
                {"type": "jsonl_file", "path": "/var/log/sb.jsonl"},
                {"type": "webhook", "url": "https://collector.example/ingest"}
            ]
        }))
        .expect("config with usage_sinks parses");
        let sinks = cfg.usage_sinks();
        assert_eq!(sinks.len(), 2);
        assert_eq!(sinks[0].name(), "jsonl_file");
        assert_eq!(sinks[1].name(), "webhook");
        // The lazy accessor returns the same built instances on repeat calls.
        assert_eq!(cfg.usage_sinks().len(), 2);
    }

    #[test]
    fn parse_ai_path_chat_completions() {
        assert_eq!(
            parse_ai_path("/v1/chat/completions"),
            AiApiPath::ChatCompletions
        );
        assert_eq!(
            parse_ai_path("/api/v1/chat/completions"),
            AiApiPath::ChatCompletions
        );
    }

    #[test]
    fn parse_ai_path_models() {
        assert_eq!(parse_ai_path("/v1/models"), AiApiPath::Models);
    }

    #[test]
    fn parse_ai_path_embeddings() {
        assert_eq!(parse_ai_path("/v1/embeddings"), AiApiPath::Embeddings);
    }

    #[test]
    fn parse_ai_path_unknown() {
        assert_eq!(parse_ai_path("/v1/completions"), AiApiPath::Unknown);
        assert_eq!(parse_ai_path("/health"), AiApiPath::Unknown);
    }

    #[test]
    fn model_allowed_no_lists() {
        let config = AiHandlerConfig {
            providers: Vec::new(),
            routing: RoutingStrategy::RoundRobin,
            allowed_models: Vec::new(),
            blocked_models: Vec::new(),
            max_body_size: None,
            guardrails: None,
            budget: None,
            virtual_keys: vec![],
            model_rate_limits: HashMap::new(),
            per_surface_rate_limits: HashMap::new(),
            max_concurrent: None,
            resilience: None,
            shadow: None,
            pii: None,
            trace_content: false,
            semantic_cache: None,
            prompts: None,
            usage_parser: "auto".to_string(),
            pii_redactor: OnceLock::new(),
            embedding_cache: OnceLock::new(),
            router: OnceLock::new(),
            usage_sinks: vec![],
            usage_sinks_built: OnceLock::new(),
        };
        assert!(config.is_model_allowed("gpt-4"));
        assert!(config.is_model_allowed("anything"));
    }

    #[test]
    fn model_blocked() {
        let config = AiHandlerConfig {
            providers: Vec::new(),
            routing: RoutingStrategy::RoundRobin,
            allowed_models: Vec::new(),
            blocked_models: vec!["gpt-4".into()],
            max_body_size: None,
            guardrails: None,
            budget: None,
            virtual_keys: vec![],
            model_rate_limits: HashMap::new(),
            per_surface_rate_limits: HashMap::new(),
            max_concurrent: None,
            resilience: None,
            shadow: None,
            pii: None,
            trace_content: false,
            semantic_cache: None,
            prompts: None,
            usage_parser: "auto".to_string(),
            pii_redactor: OnceLock::new(),
            embedding_cache: OnceLock::new(),
            router: OnceLock::new(),
            usage_sinks: vec![],
            usage_sinks_built: OnceLock::new(),
        };
        assert!(!config.is_model_allowed("gpt-4"));
        assert!(config.is_model_allowed("gpt-3.5-turbo"));
    }

    #[test]
    fn model_allowed_list() {
        let config = AiHandlerConfig {
            providers: Vec::new(),
            routing: RoutingStrategy::RoundRobin,
            allowed_models: vec!["gpt-4".into(), "gpt-3.5-turbo".into()],
            blocked_models: Vec::new(),
            max_body_size: None,
            guardrails: None,
            budget: None,
            virtual_keys: vec![],
            model_rate_limits: HashMap::new(),
            per_surface_rate_limits: HashMap::new(),
            max_concurrent: None,
            resilience: None,
            shadow: None,
            pii: None,
            trace_content: false,
            semantic_cache: None,
            prompts: None,
            usage_parser: "auto".to_string(),
            pii_redactor: OnceLock::new(),
            embedding_cache: OnceLock::new(),
            router: OnceLock::new(),
            usage_sinks: vec![],
            usage_sinks_built: OnceLock::new(),
        };
        assert!(config.is_model_allowed("gpt-4"));
        assert!(config.is_model_allowed("gpt-3.5-turbo"));
        assert!(!config.is_model_allowed("claude-3"));
    }

    #[test]
    fn model_blocked_takes_precedence() {
        let config = AiHandlerConfig {
            providers: Vec::new(),
            routing: RoutingStrategy::RoundRobin,
            allowed_models: vec!["gpt-4".into()],
            blocked_models: vec!["gpt-4".into()],
            max_body_size: None,
            guardrails: None,
            budget: None,
            virtual_keys: vec![],
            model_rate_limits: HashMap::new(),
            per_surface_rate_limits: HashMap::new(),
            max_concurrent: None,
            resilience: None,
            shadow: None,
            pii: None,
            trace_content: false,
            semantic_cache: None,
            prompts: None,
            usage_parser: "auto".to_string(),
            pii_redactor: OnceLock::new(),
            embedding_cache: OnceLock::new(),
            router: OnceLock::new(),
            usage_sinks: vec![],
            usage_sinks_built: OnceLock::new(),
        };
        // Block list wins
        assert!(!config.is_model_allowed("gpt-4"));
    }

    #[test]
    fn ai_handler_config_from_config() {
        let json = serde_json::json!({
            "providers": [
                {"name": "openai", "api_key": "sk-test", "weight": 3},
                {"name": "anthropic", "api_key": "sk-ant-test", "priority": 1}
            ],
            "routing": "weighted",
            "allowed_models": ["gpt-4"],
            "max_body_size": 1048576
        });
        let config = AiHandlerConfig::from_config(json).unwrap();
        assert_eq!(config.providers.len(), 2);
        assert_eq!(config.providers[0].name, "openai");
        assert_eq!(config.providers[0].weight, 3);
        assert_eq!(config.allowed_models, vec!["gpt-4"]);
        assert_eq!(config.max_body_size, Some(1048576));
    }

    #[test]
    fn ai_handler_config_defaults() {
        let json = serde_json::json!({
            "providers": [{"name": "openai"}]
        });
        let config = AiHandlerConfig::from_config(json).unwrap();
        assert!(config.allowed_models.is_empty());
        assert!(config.blocked_models.is_empty());
        assert!(config.max_body_size.is_none());
    }

    #[test]
    fn ai_handler_config_missing_providers() {
        let json = serde_json::json!({});
        assert!(AiHandlerConfig::from_config(json).is_err());
    }

    /// WOR-1044 PR4: an origin that declares any reversible PII rule
    /// AND configures a semantic_cache block has the semantic cache
    /// dropped at compile time. The cache would otherwise restore a
    /// prior request's placeholders against a different request's
    /// capture map.
    #[test]
    fn semantic_cache_disabled_when_reversible_pii_enabled() {
        let json = serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "semantic_cache": {"enabled": true, "ttl_secs": 600},
            "pii": {
                "enabled": true,
                "defaults": false,
                "rules": [
                    {
                        "name": "email",
                        "pattern": r"\b[a-z0-9._%+\-]{1,64}@[a-z0-9.\-]{1,255}\.[a-z]{2,63}\b",
                        "reversible": true,
                        "mask_template": "<placeholder:email:%d>"
                    }
                ]
            }
        });
        let config = AiHandlerConfig::from_config(json).expect("compile");
        assert!(
            config.semantic_cache.is_none(),
            "semantic_cache should be dropped when a reversible rule is configured"
        );
    }

    /// Inverse: a non-reversible PII config leaves semantic_cache
    /// alone so the auto-disable does not over-fire on origins that
    /// only run destructive redaction.
    #[test]
    fn semantic_cache_kept_when_pii_is_not_reversible() {
        let json = serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "semantic_cache": {"enabled": true, "ttl_secs": 600},
            "pii": {
                "enabled": true,
                "defaults": false,
                "rules": [
                    {
                        "name": "email",
                        "pattern": r"\b[a-z0-9._%+\-]{1,64}@[a-z0-9.\-]{1,255}\.[a-z]{2,63}\b",
                        "reversible": false
                    }
                ]
            }
        });
        let config = AiHandlerConfig::from_config(json).expect("compile");
        assert!(
            config.semantic_cache.is_some(),
            "semantic_cache should survive when no reversible rule is configured"
        );
    }

    // --- WOR-625: provider-name + model-allow-list validation ---

    #[test]
    fn from_config_rejects_provider_name_case_typo() {
        // `openAI` resolves case-insensitively for base_url but breaks
        // exact-name routing, so it is rejected at config load, not at
        // the first request.
        let json = serde_json::json!({
            "providers": [{"name": "openAI", "api_key": "sk-test"}]
        });
        let err = AiHandlerConfig::from_config(json).unwrap_err().to_string();
        assert!(err.contains("openAI"), "error names the bad value: {err}");
        assert!(
            err.contains("openai"),
            "error suggests the canonical name: {err}"
        );
    }

    #[test]
    fn from_config_warns_but_accepts_unknown_provider() {
        // A completely unknown name (not a casing typo of a catalog
        // entry) may be an intentional custom label, so it is accepted
        // with a warning rather than rejected. Casing typos of a real
        // catalog name are the rejected case (see the test above).
        let json = serde_json::json!({
            "providers": [{"name": "my-custom-label", "api_key": "k"}]
        });
        assert!(AiHandlerConfig::from_config(json).is_ok());
    }

    #[test]
    fn from_config_accepts_custom_provider_with_base_url() {
        // An unknown name is fine when an explicit endpoint is given.
        let json = serde_json::json!({
            "providers": [{
                "name": "my-llm",
                "base_url": "http://127.0.0.1:9000/v1",
                "allow_private_base_url": true,
                "api_key": "k"
            }]
        });
        assert!(AiHandlerConfig::from_config(json).is_ok());
    }

    #[test]
    fn from_config_rejects_unknown_allowed_model() {
        // Every provider declares a model list, so allowed_models is
        // checked against their union; an entry no provider serves is
        // rejected.
        let json = serde_json::json!({
            "providers": [{"name": "openai", "api_key": "k", "models": ["gpt-4o"]}],
            "allowed_models": ["gpt-9-ultra"]
        });
        let err = AiHandlerConfig::from_config(json).unwrap_err().to_string();
        assert!(
            err.contains("gpt-9-ultra"),
            "error names the unknown model: {err}"
        );
    }

    #[test]
    fn from_config_allows_models_when_providers_defer_to_catalog() {
        // openai declares no `models` (defers to the catalog), so the
        // allow-list is not validated and any model passes.
        let json = serde_json::json!({
            "providers": [{"name": "openai", "api_key": "k"}],
            "allowed_models": ["some-future-model"]
        });
        assert!(AiHandlerConfig::from_config(json).is_ok());
    }

    // --- Cascade routing deserialization ---

    #[test]
    fn cascade_routing_parses_from_nested_object() {
        // The cascade form carries a non-trivial payload alongside
        // the `strategy` discriminator. The custom deserializer in
        // this module is responsible for stitching the two together
        // into `RoutingStrategy::Cascade(CascadeConfig { ... })`.
        let cfg_json = serde_json::json!({
            "providers": [
                {"name": "cheap", "api_key": "x"},
                {"name": "smart", "api_key": "y"}
            ],
            "routing": {
                "strategy": "cascade",
                "tiers": [
                    {
                        "provider_id": "cheap",
                        "model": "gpt-4o-mini",
                        "quality_threshold": 0.75
                    },
                    {
                        "provider_id": "smart",
                        "model": "gpt-4o",
                        "quality_threshold": 0.9,
                        "cost_cap": 50000
                    }
                ],
                "max_total_cost": 100000
            }
        });
        let config = AiHandlerConfig::from_config(cfg_json).expect("parse");
        let cascade = match &config.routing {
            RoutingStrategy::Cascade(c) => c,
            other => panic!("expected Cascade, got {other:?}"),
        };
        assert_eq!(cascade.tiers.len(), 2);
        assert_eq!(cascade.tiers[0].provider_id, "cheap");
        assert_eq!(cascade.tiers[0].model, "gpt-4o-mini");
        assert!((cascade.tiers[0].quality_threshold - 0.75).abs() < 1e-6);
        assert_eq!(cascade.tiers[1].cost_cap, Some(50000));
        assert_eq!(cascade.max_total_cost, Some(100000));
    }

    #[test]
    fn cascade_routing_rejects_empty_tiers() {
        // Cascade without any tiers is a configuration error: the
        // dispatch loop would have nothing to walk. The deserializer
        // surfaces the error at config-load time.
        let cfg_json = serde_json::json!({
            "providers": [{"name": "openai"}],
            "routing": {
                "strategy": "cascade",
                "tiers": []
            }
        });
        assert!(AiHandlerConfig::from_config(cfg_json).is_err());
    }

    // --- PII redaction end-to-end wiring ---
    //
    // These tests exercise the same code path the AI request handler
    // takes when forwarding to an upstream: parse the inbound body,
    // call `apply_request_pii`, then read the mutated body. Together
    // with the rule-level coverage in `sbproxy_security::pii::tests`
    // they prove the user-facing acceptance shape from the Phase 3
    // requirements.

    #[test]
    fn pii_request_redaction_replaces_email_and_credit_card() {
        // The exact body shape from the acceptance criterion:
        // {"prompt": "Email me at alice@example.com about card 4111-1111-1111-1111"}
        // After the handler's redaction pass, the upstream provider
        // must see the email and card replaced with markers.
        let cfg_json = serde_json::json!({
            "providers": [{"name": "openai"}],
            "pii": { "enabled": true }
        });
        let config = AiHandlerConfig::from_config(cfg_json).unwrap();

        let mut body = serde_json::json!({
            "prompt": "Email me at alice@example.com about card 4111-1111-1111-1111"
        });
        let redacted = config.apply_request_pii(&mut body);
        assert!(redacted, "redactor should have run");

        let prompt = body["prompt"].as_str().unwrap();
        assert!(!prompt.contains("alice@example.com"), "got: {prompt}");
        assert!(!prompt.contains("4111-1111-1111-1111"), "got: {prompt}");
        assert!(prompt.contains("[REDACTED:EMAIL]"), "got: {prompt}");
        assert!(prompt.contains("[REDACTED:CARD]"), "got: {prompt}");
    }

    #[test]
    fn pii_redaction_disabled_when_no_config() {
        let cfg_json = serde_json::json!({
            "providers": [{"name": "openai"}]
        });
        let config = AiHandlerConfig::from_config(cfg_json).unwrap();
        let mut body = serde_json::json!({"prompt": "alice@example.com"});
        let redacted = config.apply_request_pii(&mut body);
        assert!(!redacted, "no PII config = no redaction");
        assert_eq!(
            body["prompt"].as_str(),
            Some("alice@example.com"),
            "body must be untouched when PII is disabled"
        );
    }

    #[test]
    fn pii_redaction_skipped_when_request_redaction_off() {
        let cfg_json = serde_json::json!({
            "providers": [{"name": "openai"}],
            "pii": {
                "enabled": true,
                "redact_request": false,
                "redact_response": true
            }
        });
        let config = AiHandlerConfig::from_config(cfg_json).unwrap();
        let mut body = serde_json::json!({"prompt": "alice@example.com"});
        let redacted = config.apply_request_pii(&mut body);
        assert!(!redacted);
        assert_eq!(body["prompt"].as_str(), Some("alice@example.com"));
    }

    #[test]
    fn pii_requirement_satisfied_by_active_default_rule() {
        let cfg_json = serde_json::json!({
            "providers": [{"name": "openai"}],
            "pii": { "enabled": true }
        });
        let config = AiHandlerConfig::from_config(cfg_json).unwrap();

        assert!(config.satisfies_pii_redaction_requirement(&["email".to_string()]));
    }

    #[test]
    fn pii_requirement_rejects_missing_rule() {
        let cfg_json = serde_json::json!({
            "providers": [{"name": "openai"}],
            "pii": {
                "enabled": true,
                "defaults": false,
                "rules": [
                    { "name": "ticket", "pattern": "TICKET-[0-9]+" }
                ]
            }
        });
        let config = AiHandlerConfig::from_config(cfg_json).unwrap();

        assert!(!config.satisfies_pii_redaction_requirement(&["email".to_string()]));
        assert!(config.satisfies_pii_redaction_requirement(&["ticket".to_string()]));
    }

    #[test]
    fn pii_requirement_rejects_disabled_request_redaction() {
        let cfg_json = serde_json::json!({
            "providers": [{"name": "openai"}],
            "pii": {
                "enabled": true,
                "redact_request": false
            }
        });
        let config = AiHandlerConfig::from_config(cfg_json).unwrap();

        assert!(!config.satisfies_pii_redaction_requirement(&["email".to_string()]));
    }

    #[test]
    fn pii_redaction_walks_into_messages_array() {
        // Realistic OpenAI-style chat completions body.
        let cfg_json = serde_json::json!({
            "providers": [{"name": "openai"}],
            "pii": { "enabled": true }
        });
        let config = AiHandlerConfig::from_config(cfg_json).unwrap();
        let mut body = serde_json::json!({
            "model": "gpt-4o",
            "messages": [
                { "role": "system", "content": "Operator email is ops@example.com." },
                { "role": "user", "content": "Card on file 5555-5555-5555-4444. SSN 123-45-6789." }
            ]
        });
        let redacted = config.apply_request_pii(&mut body);
        assert!(redacted);

        let sys = body["messages"][0]["content"].as_str().unwrap();
        let usr = body["messages"][1]["content"].as_str().unwrap();
        assert!(sys.contains("[REDACTED:EMAIL]"), "system: {sys}");
        assert!(usr.contains("[REDACTED:CARD]"), "user: {usr}");
        assert!(usr.contains("[REDACTED:SSN]"), "user: {usr}");
        // Model name (which happens to be schema-defined) must
        // remain untouched.
        assert_eq!(body["model"].as_str(), Some("gpt-4o"));
    }

    #[test]
    fn pii_custom_rule_appended_via_config() {
        let cfg_json = serde_json::json!({
            "providers": [{"name": "openai"}],
            "pii": {
                "enabled": true,
                "rules": [
                    {
                        "name": "internal_id",
                        "pattern": "INT-\\d{6}",
                        "replacement": "[REDACTED:INTERNAL]",
                        "anchor": "INT-"
                    }
                ]
            }
        });
        let config = AiHandlerConfig::from_config(cfg_json).unwrap();
        let mut body = serde_json::json!({
            "prompt": "Reference INT-987654 plus alice@example.com."
        });
        let redacted = config.apply_request_pii(&mut body);
        assert!(redacted);
        let prompt = body["prompt"].as_str().unwrap();
        assert!(prompt.contains("[REDACTED:INTERNAL]"), "{prompt}");
        // Defaults still active alongside the custom rule.
        assert!(prompt.contains("[REDACTED:EMAIL]"), "{prompt}");
    }

    // --- classify_surface coverage ---

    #[test]
    fn classify_chat_completions_canonical_and_prefixed() {
        assert_eq!(
            classify_surface("POST", "/v1/chat/completions"),
            AiSurface::ChatCompletions
        );
        assert_eq!(
            classify_surface("POST", "/api/v1/chat/completions"),
            AiSurface::ChatCompletions
        );
        assert_eq!(
            classify_surface("POST", "/v1/chat/completions?stream=true"),
            AiSurface::ChatCompletions
        );
    }

    #[test]
    fn classify_models_list_and_get_by_id() {
        assert_eq!(classify_surface("GET", "/v1/models"), AiSurface::Models);
        assert_eq!(
            classify_surface("GET", "/v1/models/gpt-4o-mini"),
            AiSurface::Models
        );
    }

    #[test]
    fn classify_embeddings() {
        assert_eq!(
            classify_surface("POST", "/v1/embeddings"),
            AiSurface::Embeddings
        );
    }

    #[test]
    fn classify_assistants_surface() {
        for path in [
            "/v1/assistants",
            "/v1/assistants/asst_abc",
            "/v1/assistants/asst_abc/files",
            "/v1/assistants/asst_abc/files/file_xyz",
        ] {
            assert_eq!(
                classify_surface("GET", path),
                AiSurface::Assistants,
                "{path} should classify as Assistants"
            );
        }
    }

    #[test]
    fn classify_threads_surface() {
        for path in [
            "/v1/threads",
            "/v1/threads/thread_abc",
            "/v1/threads/thread_abc/messages",
            "/v1/threads/thread_abc/messages/msg_xyz",
            "/v1/threads/thread_abc/runs",
            "/v1/threads/thread_abc/runs/run_xyz",
            "/v1/threads/thread_abc/runs/run_xyz/cancel",
            "/v1/threads/runs",
        ] {
            assert_eq!(
                classify_surface("POST", path),
                AiSurface::Threads,
                "{path} should classify as Threads"
            );
        }
    }

    #[test]
    fn classify_batches_surface() {
        for path in [
            "/v1/batches",
            "/v1/batches/batch_abc",
            "/v1/batches/batch_abc/cancel",
        ] {
            assert_eq!(
                classify_surface("POST", path),
                AiSurface::Batches,
                "{path} should classify as Batches"
            );
        }
    }

    #[test]
    fn classify_fine_tuning_surface_uses_underscore_path() {
        // OpenAI uses /v1/fine_tuning (underscore), not /v1/fine-tuning.
        // The pre-existing parse_endpoint test treated /v1/fine-tuning/jobs
        // as Unknown; classify_surface accepts the canonical underscore form.
        for path in [
            "/v1/fine_tuning/jobs",
            "/v1/fine_tuning/jobs/ftjob_abc",
            "/v1/fine_tuning/jobs/ftjob_abc/cancel",
            "/v1/fine_tuning/jobs/ftjob_abc/events",
        ] {
            assert_eq!(
                classify_surface("POST", path),
                AiSurface::FineTuning,
                "{path} should classify as FineTuning"
            );
        }
    }

    #[test]
    fn classify_files_surface() {
        for path in [
            "/v1/files",
            "/v1/files/file_abc",
            "/v1/files/file_abc/content",
        ] {
            assert_eq!(
                classify_surface("GET", path),
                AiSurface::Files,
                "{path} should classify as Files"
            );
        }
    }

    #[test]
    fn classify_realtime_surface() {
        assert_eq!(classify_surface("GET", "/v1/realtime"), AiSurface::Realtime);
        // Realtime sometimes carries a model query param.
        assert_eq!(
            classify_surface("GET", "/v1/realtime?model=gpt-4o-realtime-preview"),
            AiSurface::Realtime
        );
    }

    #[test]
    fn classify_image_surfaces() {
        assert_eq!(
            classify_surface("POST", "/v1/images/generations"),
            AiSurface::ImageGeneration
        );
        assert_eq!(
            classify_surface("POST", "/v1/images/edits"),
            AiSurface::ImageEdits
        );
        assert_eq!(
            classify_surface("POST", "/v1/images/variations"),
            AiSurface::ImageVariations
        );
    }

    #[test]
    fn classify_audio_surfaces() {
        assert_eq!(
            classify_surface("POST", "/v1/audio/transcriptions"),
            AiSurface::AudioTranscription
        );
        // Translations dispatches as transcription (same handler, different
        // language semantics at the provider).
        assert_eq!(
            classify_surface("POST", "/v1/audio/translations"),
            AiSurface::AudioTranscription
        );
        assert_eq!(
            classify_surface("POST", "/v1/audio/speech"),
            AiSurface::AudioSpeech
        );
    }

    #[test]
    fn classify_moderations() {
        assert_eq!(
            classify_surface("POST", "/v1/moderations"),
            AiSurface::Moderations
        );
    }

    #[test]
    fn classify_reranking_both_paths() {
        assert_eq!(classify_surface("POST", "/v1/rerank"), AiSurface::Reranking);
        assert_eq!(
            classify_surface("POST", "/v1/reranking"),
            AiSurface::Reranking
        );
    }

    #[test]
    fn classify_unknown_path_returns_unknown() {
        assert_eq!(classify_surface("GET", "/health"), AiSurface::Unknown);
        assert_eq!(
            classify_surface("POST", "/v1/something/unmapped"),
            AiSurface::Unknown
        );
        assert_eq!(classify_surface("GET", "/"), AiSurface::Unknown);
    }

    #[test]
    fn classify_strips_trailing_slash() {
        assert_eq!(
            classify_surface("POST", "/v1/chat/completions/"),
            AiSurface::ChatCompletions
        );
        assert_eq!(
            classify_surface("GET", "/v1/assistants/"),
            AiSurface::Assistants
        );
    }

    #[test]
    fn extract_input_text_for_image_uses_prompt() {
        let body = serde_json::json!({"prompt": "a painting of a cat", "model": "dall-e-3"});
        assert_eq!(
            extract_input_text(&AiSurface::ImageGeneration, &body),
            Some("a painting of a cat".to_string())
        );
        assert_eq!(
            extract_input_text(&AiSurface::ImageEdits, &body),
            Some("a painting of a cat".to_string())
        );
    }

    #[test]
    fn extract_input_text_for_speech_uses_input() {
        let body = serde_json::json!({"model": "tts-1", "input": "hello world", "voice": "alloy"});
        assert_eq!(
            extract_input_text(&AiSurface::AudioSpeech, &body),
            Some("hello world".to_string())
        );
    }

    #[test]
    fn extract_input_text_for_reranking_uses_query() {
        let body = serde_json::json!({"query": "find documents about cats", "documents": []});
        assert_eq!(
            extract_input_text(&AiSurface::Reranking, &body),
            Some("find documents about cats".to_string())
        );
    }

    #[test]
    fn extract_input_text_for_moderations_uses_input() {
        let body = serde_json::json!({"input": "is this content safe?", "model": "omni"});
        assert_eq!(
            extract_input_text(&AiSurface::Moderations, &body),
            Some("is this content safe?".to_string())
        );
    }

    #[test]
    fn extract_input_text_returns_none_for_chat_shape_surfaces() {
        // Chat-shape surfaces carry input in `messages`; the existing
        // GuardrailPipeline::check_input handles them.
        let body = serde_json::json!({"messages": [{"role": "user", "content": "hi"}]});
        assert!(extract_input_text(&AiSurface::ChatCompletions, &body).is_none());
        assert!(extract_input_text(&AiSurface::Assistants, &body).is_none());
        assert!(extract_input_text(&AiSurface::Threads, &body).is_none());
        // Surfaces without a single text input field also return None.
        assert!(extract_input_text(&AiSurface::Batches, &body).is_none());
        assert!(extract_input_text(&AiSurface::FineTuning, &body).is_none());
        assert!(extract_input_text(&AiSurface::Files, &body).is_none());
    }

    #[test]
    fn extract_input_text_returns_none_when_field_missing_or_not_string() {
        let no_prompt = serde_json::json!({"model": "dall-e-3"});
        assert!(extract_input_text(&AiSurface::ImageGeneration, &no_prompt).is_none());

        // Field present but not a string.
        let array_prompt = serde_json::json!({"prompt": ["array", "elements"]});
        assert!(extract_input_text(&AiSurface::ImageGeneration, &array_prompt).is_none());
    }

    #[test]
    fn ai_surface_label_is_stable() {
        // Spot-check the label contract that metric collectors depend on.
        assert_eq!(AiSurface::ChatCompletions.label(), "chat_completions");
        assert_eq!(AiSurface::Assistants.label(), "assistants");
        assert_eq!(AiSurface::FineTuning.label(), "fine_tuning");
        assert_eq!(AiSurface::AudioTranscription.label(), "audio_transcription");
        assert_eq!(AiSurface::Unknown.label(), "unknown");
    }
}

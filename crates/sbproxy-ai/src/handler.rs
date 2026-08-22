//! AI request handler configuration and path parsing.

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::budget::BudgetConfig;
use crate::compression::{CompressionPolicy, CompressionSelector};
use crate::guardrails::GuardrailsConfig;
use crate::identity::VirtualKeyConfig;
use crate::ids::ModelId;
use crate::provider::ProviderConfig;
use crate::ratelimit::{ModelRateConfig, SurfaceRateConfig};
use crate::reasoning::ReasoningPolicy;
use crate::routing::RoutingStrategy;

fn value_ledger_for_sink(
    ledger: std::sync::Arc<crate::value_ledger::ValueLedger>,
    path: &std::path::Path,
) -> std::sync::Arc<crate::value_ledger::ValueLedger> {
    if !path.as_os_str().is_empty() {
        if let Err(error) = ledger.promote_to_redb(path) {
            // This helper runs inside usage_sinks_built, so each handler emits
            // at most one warning for a failed or conflicting promotion.
            tracing::warn!(
                error = %error,
                requested_path = %path.display(),
                fallback = "existing_backend",
                "value ledger: durable promotion failed; keeping existing backend"
            );
        }
    }
    ledger
}

struct CachedQuotaPoolStore {
    kind: &'static str,
    store: std::sync::Arc<dyn crate::quota_pool::QuotaPoolStore>,
}

impl std::fmt::Debug for CachedQuotaPoolStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CachedQuotaPoolStore")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// AI gateway handler configuration.
#[derive(Debug, Deserialize)]
pub struct AiHandlerConfig {
    /// Configured upstream AI providers eligible for routing.
    pub providers: Vec<ProviderConfig>,
    /// Strategy used to select a provider for each request.
    #[serde(default = "default_strategy", deserialize_with = "deserialize_routing")]
    pub routing: RoutingStrategy,
    /// Route a caller's repeated requests back to the provider that already
    /// holds their warm prompt cache.
    ///
    /// When a request carries a prompt cache key (`prompt_cache_key`, or
    /// `user` when that is absent), the gateway remembers which provider
    /// served it and prefers that provider for the caller's next request
    /// with the same key. It is a preference, never a pin: an unhealthy,
    /// ejected, or policy-ineligible provider is still skipped, and a
    /// request whose resolved model changed starts a fresh lease.
    ///
    /// This composes with `routing.strategy` rather than replacing it. The
    /// strategy still picks; affinity only moves a live lease holder to the
    /// front of the order it produced. The four strategies that own their
    /// ordering outright are the exception and are left alone:
    /// `fallback_chain`, `cascade`, `cost_quality`, and a `routing_policy`
    /// plan all express an order the operator wrote down, so a lease is
    /// neither read nor recorded on those origins.
    ///
    /// The lease is scoped to the tenant, the credential, the origin, and
    /// the API surface, so one caller's key can never steer another's
    /// routing. Nothing writes the key; a request that does not send one is
    /// routed by the configured strategy alone.
    ///
    /// State lives in this gateway process only. It does not survive a
    /// restart and is not shared between replicas. Unset disables the
    /// feature.
    #[serde(default)]
    pub cache_affinity: Option<crate::routing_state::CacheAffinityConfig>,
    /// Data-handling posture requirement gating provider eligibility.
    ///
    /// Evaluated as a hard candidate-set filter before any routing
    /// strategy runs, and composed with the per-request
    /// `x-sbproxy-require-zdr` / `x-sbproxy-disallow-data-collection`
    /// headers (most restrictive wins). A request left with no
    /// eligible provider fails closed with an error naming the
    /// constraint and the excluded providers. `None` (the default)
    /// leaves every provider eligible. See
    /// [`crate::data_posture`].
    #[serde(default)]
    pub data_posture: Option<crate::data_posture::DataPostureRequirement>,
    /// Typed fallback list for the context-window trigger (WOR-2556):
    /// provider names to reroute to when a prompt's pre-flight token
    /// estimate (or a provider's own rejection) overflows the model's
    /// context window. Ordered; each name must match a
    /// `providers[].name` (config load refuses unknown names). Empty
    /// (the default) disables the trigger, and the generic chain
    /// handles every failure as before. This is the
    /// `context_window_fallbacks` half of the LiteLLM
    /// `fallbacks` / `context_window_fallbacks` /
    /// `content_policy_fallbacks` split; the generic half is
    /// `routing.strategy: fallback_chain`.
    #[serde(default)]
    pub context_window_fallbacks: Vec<String>,
    /// Typed fallback list for the content-policy trigger (WOR-2556):
    /// provider names to reroute to when a provider refuses a request
    /// on content-policy / safety grounds. Ordered; each name must
    /// match a `providers[].name`. Empty (the default) disables the
    /// trigger; the legacy `resilience.content_policy_fallback`
    /// boolean (route to the next provider in order) keeps working
    /// unchanged when this list is not set.
    #[serde(default)]
    pub content_policy_fallbacks: Vec<String>,
    /// Optional allow-list of model names; empty means allow all.
    #[serde(default)]
    pub allowed_models: Vec<ModelId>,
    /// Block-list of model names that takes precedence over the allow-list.
    #[serde(default)]
    pub blocked_models: Vec<ModelId>,
    /// Global model aliases for this origin.
    ///
    /// Each entry binds a friendly name a caller may send as `model` to an
    /// upstream model id, and optionally pins it to one provider. Aliases
    /// resolve on the dispatch path before every model gate and before
    /// provider selection, which is what separates them from a provider's
    /// `model_map`: that map renames a model only after the router has
    /// already chosen that provider. See [`crate::model_alias`].
    #[serde(default)]
    pub model_aliases: Vec<crate::model_alias::ModelAlias>,
    /// Named model groups for this origin.
    ///
    /// Each entry binds one public name callers send as `model` to a
    /// list of members, each naming a provider on this action and the
    /// upstream model id it serves. A group carries its own routing
    /// strategy and per-member weights, so it load-balances
    /// independently of this action's `routing:`, and its members may
    /// serve different model ids. Groups resolve on the dispatch path
    /// before every model gate and before provider selection, the same
    /// point a `model_aliases` entry resolves, so every gate below
    /// judges the member's real model id. See [`crate::model_group`].
    #[serde(default)]
    pub model_groups: Vec<crate::model_group::ModelGroup>,
    /// Maximum request body size in bytes accepted by the gateway.
    ///
    /// Checked while the body arrives rather than once it is all in
    /// memory. A declared `Content-Length` over the cap is refused
    /// before the first read; a chunked upload that declares nothing is
    /// refused on the chunk that crosses the line. Both answer `413`
    /// from the request phase, so no provider is contacted and nothing
    /// reaches the response cache or the idempotency store.
    ///
    /// The same number bounds the buffered upstream response the relay
    /// holds in memory, and the multipart body a governed model
    /// rewrite produces.
    ///
    /// Unset means 64 MiB, not unlimited. An AI request body has to be
    /// held whole before it can be parsed, routed, and scanned, so a
    /// deployment that configured no cap still has one; `0` reads as
    /// unset, and anything above 1 GiB is clamped to 1 GiB.
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
    /// Require this origin to authenticate with a canonical governed key.
    ///
    /// The default is `false` for compatibility. When enabled, missing,
    /// unknown, inactive, malformed, and legacy credentials fail closed before
    /// model discovery, cache lookup, provider selection, or dispatch.
    #[serde(default)]
    pub require_governed_key: bool,
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
    /// Optional ordered context-compression policy.
    ///
    /// When present this block is authoritative, including an empty lever
    /// list. When absent, the legacy `resilience.llm_aware.context_compress`
    /// setting is adapted by [`Self::effective_compression_policy`].
    #[serde(default)]
    pub compression: Option<CompressionPolicy>,
    /// Optional concise-reasoning policy applied after per-provider model mapping.
    ///
    /// The default is [`ReasoningPolicy::Off`], which preserves existing
    /// request behavior.
    #[serde(default)]
    pub reasoning: ReasoningPolicy,
    /// Optional shadow / side-by-side eval for sampled non-streaming
    /// requests. The primary response is served unchanged; an admitted
    /// copy goes to the shadow provider in a bounded background task.
    /// Streaming requests are intentionally skipped.
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
    /// WOR-2096: retain a redacted sample of this origin's prompt and
    /// response text in a bounded in-memory store so an operator can
    /// inspect one request's content from the admin console. Off by
    /// default, and gated twice: capture happens only when this flag is
    /// on AND the governed key's policy sets `allow_content_capture`.
    /// The same redaction stack as `trace_content` applies (secret
    /// redactor, then the origin's `pii` redactor, then the payload
    /// cap). Nothing is durable: the store clears on restart, and the
    /// production-grade content path remains OTLP `trace_content`.
    #[serde(default)]
    pub capture_content: bool,
    /// Typed semantic-cache configuration for this action.
    ///
    /// Parsed and bounds-checked at config load rather than carried as an
    /// opaque value: WOR-2099 gave this block a backend selector, and a
    /// misspelled or out-of-range field has to fail the load instead of
    /// silently disabling the cache on first request. The compiled
    /// runtime is built from this by
    /// `sbproxy_core::semantic_cache_runtime`, which owns backend
    /// selection per origin and forward rule.
    #[serde(default)]
    pub semantic_cache: Option<crate::semantic_cache::EmbeddingCacheConfig>,
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
    /// WOR-1542: optional unified CEL policy plane over the AI decision
    /// pipeline. One sandboxed expression fuses guardrail verdicts, budget
    /// state, routing candidate, and principal context into a closed set of
    /// typed actions (block / redact / route_to / set_sink_tag / audit).
    /// `None` (the default) leaves the pipeline's per-block decisions
    /// unchanged.
    #[serde(default)]
    pub ai_policy: Option<crate::ai_policy::AiPolicyConfig>,
    /// WOR-2366: operator-authored routing policy. A CEL expression
    /// returns a routing plan (an ordered candidate list) that dispatches
    /// through the cascade executor, or declines to the configured
    /// strategy. Runs before `ai_policy`; a firing `ai_policy` `route_to`
    /// overrides it. `None` (the default) leaves routing to the strategy.
    #[serde(default)]
    pub ai_routing_policy: Option<crate::ai_routing_policy::AiRoutingPolicyConfig>,
    /// WOR-1707: operator model price table for cost reporting. Each
    /// entry (per-million USD input/output, optional cache rates)
    /// overrides the built-in catalog for that model. Empty by default.
    #[serde(default)]
    pub model_prices: HashMap<String, crate::budget::ModelPriceConfig>,
    /// WOR-1707: path to an external rate-card file in the LiteLLM
    /// `model_prices_and_context_window.json` schema. Loaded at config
    /// load as the base price layer (config `model_prices` win over it).
    /// A snapshot is vendored and refreshed out of band, not fetched at
    /// runtime. `None` uses only `model_prices` + the built-in catalog.
    #[serde(default)]
    pub rate_card: Option<String>,
    /// WOR-2559: origin-level hard price ceiling in USD per request (the
    /// OpenRouter `provider.max_price` analog). Before provider
    /// selection, each routing candidate on a token-priced chat surface
    /// (`/v1/chat/completions`, `/v1/messages`, `/v1/responses`) is
    /// estimated through the same price resolution cost tracking bills with
    /// (`model_prices`, rate card, built-in catalog, then the pessimistic
    /// $5/$5 fallback); candidates whose estimate exceeds the ceiling are
    /// excluded, and a fully excluded set refuses with 402 naming the
    /// ceiling and each candidate's resolved price. On a `cascade`
    /// origin the tier list is filtered the same way, priced on the model
    /// each tier names, because the cascade routes over its tiers rather
    /// than over the provider order. The `x-sbproxy-max-price` request
    /// header can tighten this per request but never raise it. Must be
    /// positive when set; `None` (the default) disables the gate.
    #[serde(default)]
    pub max_price_per_request: Option<f64>,
    /// Allow a caller's `x-sbproxy-timeout-ms` header to replace the
    /// selected provider's `timeout_ms` for one request.
    ///
    /// Defaults to `false`, and off means the header is ignored rather
    /// than honored or refused. A caller who can raise a timeout holds a
    /// downstream connection, a `quota_pool` slot, and an upstream
    /// generation open for as long as the ceiling allows, which is a
    /// capacity decision an operator makes. A caller who can lower one is
    /// no safer: `timeout_ms` runs from connect through the end of the
    /// response body, so a shortened budget cuts off a streaming
    /// completion the operator is already billed for and burns a retry
    /// attempt doing it.
    ///
    /// Turning this on requires `max_request_timeout_ms`. The flag alone
    /// is refused at config load, because an unbounded caller timeout is
    /// the failure this gate exists to prevent.
    ///
    /// Scope is the origin, so this enables the override for every caller
    /// and every tenant routed to this `ai_proxy` action.
    ///
    /// The override reaches every dispatch that goes out over the
    /// gateway's provider HTTP client: hosted providers, a confidence
    /// cascade's tiers, each racing leg, every retry attempt, and a
    /// `managed_model` this process serves locally, which is dialed over
    /// that same client once the engine is up. It does not reach a
    /// `managed_model` served by another node in a cluster, which is
    /// dispatched over the model plane on its own deadlines, nor the
    /// gateway's own routing work: semantic-cache and semantic-route
    /// embeddings and shadow copies keep their configured budgets.
    #[serde(default)]
    pub allow_request_timeout_override: bool,
    /// Hard ceiling in milliseconds on a caller's `x-sbproxy-timeout-ms`.
    ///
    /// A header above the ceiling is refused with 400 naming the accepted
    /// range rather than silently clamped, so a caller does not build a
    /// retry schedule on a budget it never got. Must be above zero when
    /// set, and required whenever `allow_request_timeout_override` is
    /// true.
    ///
    /// Independent of any provider's `timeout_ms`: this bounds what a
    /// caller may ask for, `timeout_ms` is what they get when they ask
    /// for nothing. It bounds one attempt rather than the whole request,
    /// so with `max_retries: 3` a caller asking for the ceiling can hold
    /// four attempts of it. Size it against the attempt, then multiply.
    ///
    /// An honored header replaces the gateway's 30-second HTTP client
    /// default as well as the provider's `timeout_ms`, so a ceiling above
    /// 30000 does buy a caller a longer attempt. That is the point of the
    /// ceiling: it is the only thing bounding how long one caller can
    /// hold a connection, a `quota_pool` slot, and an upstream generation.
    #[serde(default)]
    pub max_request_timeout_ms: Option<u64>,
    /// WOR-1880: optional fair-share quota pool across providers.
    /// When set, each provider attempt reserves against the pool before
    /// dispatch; a deny advances to the next candidate when alternatives
    /// exist. Process-local only unless a future atomic backend lands.
    #[serde(default)]
    pub quota_pool: Option<crate::quota_pool::QuotaPoolConfig>,
    /// Optional route-scoped retrieval augmentation.
    #[serde(default)]
    pub rag: Option<crate::rag_config::RagRouteConfig>,
    /// Lazy-compiled guardrail pipeline, owned by this reload-managed
    /// handler config. Keeping the cache here makes its lifetime follow
    /// the published config: a reload cannot reuse a pipeline by recycled
    /// memory address, and dropping the old config releases its pipeline
    /// once in-flight requests finish.
    ///
    /// Compilation failures are cached as strings so every request fails
    /// closed consistently without retrying deterministic bad config.
    #[serde(skip)]
    pub(crate) guardrails_pipeline:
        OnceLock<Result<std::sync::Arc<crate::guardrails::GuardrailPipeline>, String>>,
    /// Lazy-built compiled redactor cached on the per-origin
    /// config. Built on first use so config-load does not pay the
    /// regex-compile cost for origins that never serve a request.
    /// `None` value inside the OnceLock means "tried to build and
    /// either no config or invalid"; the request path treats both
    /// the same way (skip redaction).
    #[serde(skip)]
    pub(crate) pii_redactor: OnceLock<Option<sbproxy_security::pii::PiiRedactor>>,
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
    /// Lazy-compiled AI policy plane (WOR-1542). `None` inside the OnceLock
    /// means no policy is configured or it failed to compile; the request
    /// path treats both as "no policy".
    #[serde(skip)]
    pub(crate) ai_policy_compiled:
        OnceLock<Option<std::sync::Arc<crate::ai_policy::CompiledAiPolicy>>>,
    /// Lazy-compiled routing policy (WOR-2366). `None` inside the OnceLock
    /// means no routing policy is configured or it failed to compile; the
    /// request path treats both as "no routing policy". `from_config`
    /// validates the expression eagerly, so a compile failure here after a
    /// green load is not reachable in practice.
    #[serde(skip)]
    pub(crate) ai_routing_policy_compiled:
        OnceLock<Option<std::sync::Arc<crate::ai_routing_policy::CompiledAiRoutingPolicy>>>,
    /// Lazy-built `ai.catalog` base-data document (WOR-2366): per-model
    /// prices and context windows for this origin's declared models,
    /// converted once to the shared CEL form so each request binds it by
    /// reference-count bump. Rebuilt with the handler on config reload,
    /// after `from_config` has installed the price table.
    #[serde(skip)]
    ai_catalog_cel: OnceLock<sbproxy_extension::cel::CelValue>,
    /// Lazy-built fair-share pool store (WOR-1880, WOR-1993).
    #[serde(skip)]
    quota_pool_store: OnceLock<std::sync::Arc<CachedQuotaPoolStore>>,
    /// Alias index built from `model_aliases`. `from_config` warms it at
    /// config load, so the request path is one map lookup and a config
    /// that carries aliases is fully resolved before it is published.
    #[serde(skip)]
    model_alias_index: OnceLock<crate::model_alias::ModelAliasRegistry>,
    /// Group index built from `model_groups`. `from_config` warms it at
    /// config load, for the same reason the alias index is warmed there.
    #[serde(skip)]
    model_group_index: OnceLock<crate::model_group::ModelGroupRegistry>,
}

fn default_usage_parser() -> String {
    "auto".to_string()
}

impl AiHandlerConfig {
    /// Eagerly construct enforcing safety classifiers before publication.
    ///
    /// The shipped centroids are meaningful only for their pinned embedding
    /// model and tokenizer bytes. Startup and reload call this after the
    /// concrete classifier factory is installed, so an unavailable or
    /// mismatched artifact rejects the candidate pipeline. Routing-only
    /// `type: classifier` entries keep their established inert-on-error
    /// behavior.
    pub fn preflight_default_safety_centroids(&self) -> anyhow::Result<()> {
        let Some(config) = self.guardrails.as_ref() else {
            return Ok(());
        };
        if crate::guardrails::uses_default_safety_centroids(config) {
            self.guardrail_pipeline()?;
        }
        Ok(())
    }

    /// Return this handler's compiled guardrail pipeline, building it once.
    ///
    /// The returned `Arc` lets in-flight requests finish against the old
    /// pipeline during a config reload. The owning cache lives on this
    /// handler rather than in process-global address-keyed state, so the old
    /// generation is released when both the old config and those requests
    /// are gone. A compile error remains an error and must fail the request
    /// closed.
    pub fn guardrail_pipeline(
        &self,
    ) -> anyhow::Result<Option<std::sync::Arc<crate::guardrails::GuardrailPipeline>>> {
        let Some(config) = self.guardrails.as_ref() else {
            return Ok(None);
        };
        match self.guardrails_pipeline.get_or_init(|| {
            crate::guardrails::compile_pipeline(config)
                .map(std::sync::Arc::new)
                .map_err(|error| error.to_string())
        }) {
            Ok(pipeline) => Ok(Some(std::sync::Arc::clone(pipeline))),
            Err(error) => Err(anyhow::anyhow!("{error}")),
        }
    }

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

    /// Return the shared usage sinks for this handler, building them once.
    /// Empty when none are configured. Sinks are best-effort and never fail a
    /// request.
    pub fn usage_sinks(&self) -> &[std::sync::Arc<dyn crate::usage_sink::UsageSink>] {
        self.usage_sinks_built
            .get_or_init(|| {
                let mut sinks = crate::usage_sink::build_sinks(&self.usage_sinks);
                // WOR-1913: a served model that declares a `reference:` cloud
                // price gets a value recorder that prices each of its
                // completions at that reference, so the admin value route and
                // the dollars-saved doc claim are backed by a real
                // per-completion tally. No reference configured means no
                // recorder, never a guessed saving.
                //
                // WOR-2223: "each of its completions" covers both lanes. This
                // map prices a completion that spilled past the local engine
                // too, which is why it is keyed on the served model name
                // rather than on the provider that ends up billing.
                let mut references = std::collections::BTreeMap::new();
                let mut ledger_dir: Option<String> = None;
                for provider in &self.providers {
                    if let Some(serve) = &provider.serve {
                        let serve_references =
                            crate::value_ledger::ValueSink::references_from_serve(serve);
                        if !serve_references.is_empty() && ledger_dir.is_none() {
                            ledger_dir.clone_from(&serve.cache_dir);
                        }
                        references.extend(serve_references);
                    }
                }
                if !references.is_empty() {
                    // Persist under the serve cache dir when one is configured
                    // so the tally survives a restart; an unset cache dir keeps
                    // an in-memory tally for the life of the process.
                    let path = ledger_dir
                        .map(|dir| std::path::Path::new(&dir).join("value-ledger.redb"))
                        .unwrap_or_default();
                    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    // Every handler obtains the one stable process facade.
                    // A configured cache path promotes that facade in place,
                    // preserving compression and earlier ValueSink references.
                    // On promotion failure the sink remains active against the
                    // existing memory or durable backend.
                    let ledger = value_ledger_for_sink(
                        crate::value_ledger::value_ledger_or_init_memory(),
                        &path,
                    );
                    sinks.push(std::sync::Arc::new(crate::value_ledger::ValueSink::new(
                        ledger, references,
                    )));
                }
                sinks
            })
            .as_slice()
    }

    /// Return the compiled AI policy plane for this handler, compiling it
    /// once (WOR-1542). `None` when no policy is configured. The failure
    /// arm is defensive: `from_config` already refused any policy that
    /// does not compile (WOR-2422), so for a loaded config this compile
    /// cannot fail; if the invariant ever breaks it is still logged
    /// rather than panicking.
    pub fn ai_policy(&self) -> Option<&std::sync::Arc<crate::ai_policy::CompiledAiPolicy>> {
        self.ai_policy_compiled
            .get_or_init(|| {
                self.ai_policy.as_ref().and_then(|cfg| {
                    match crate::ai_policy::CompiledAiPolicy::compile(cfg) {
                        Ok(p) => Some(std::sync::Arc::new(p)),
                        Err(e) => {
                            tracing::error!(error = %e, "ai_policy: disabled (failed to compile)");
                            None
                        }
                    }
                })
            })
            .as_ref()
    }

    /// The `ai.catalog` base-data document for this origin's declared
    /// models (WOR-2366): per-model prices and context windows, built once
    /// per config generation and returned in the shared CEL form, so the
    /// clone this returns is a reference-count bump, not a document copy.
    pub fn ai_catalog_cel(&self) -> sbproxy_extension::cel::CelValue {
        self.ai_catalog_cel
            .get_or_init(|| crate::routing_base_data::build_catalog_cel(&self.providers))
            .clone()
    }

    /// Return the compiled routing policy for this handler, compiling it
    /// once (WOR-2366). `None` when no routing policy is configured. The
    /// failure arm is defensive for the same reason as [`Self::ai_policy`]:
    /// `from_config` already refused any expression that does not compile.
    pub fn ai_routing_policy(
        &self,
    ) -> Option<&std::sync::Arc<crate::ai_routing_policy::CompiledAiRoutingPolicy>> {
        self.ai_routing_policy_compiled
            .get_or_init(|| {
                self.ai_routing_policy.as_ref().and_then(|cfg| {
                    match crate::ai_routing_policy::CompiledAiRoutingPolicy::compile(cfg) {
                        Ok(policy) => Some(std::sync::Arc::new(policy)),
                        Err(error) => {
                            tracing::error!(
                                error = %error,
                                "ai_routing_policy: disabled (failed to compile)"
                            );
                            None
                        }
                    }
                })
            })
            .as_ref()
    }

    /// Return the shared provider router for this handler, building it
    /// once (WOR-798). The router holds live per-provider latency / token
    /// / connection state, so it must be reused across requests rather
    /// than reconstructed per request; this accessor guarantees a single
    /// instance per `AiHandlerConfig` (until config reload).
    /// The `resilience` blocks are attached here rather than by a
    /// background task, because a breaker and a detector are passive:
    /// they need to exist before the first request, not to be driven on
    /// a timer the way the probe axis is. This accessor is the one
    /// place a router is built, so it is the only place that can
    /// guarantee no request ever meets an unarmed one. That guarantee
    /// is the bug (WOR-2233): both blocks parsed, and neither was ever
    /// attached to anything.
    pub fn router(&self) -> std::sync::Arc<crate::routing::Router> {
        self.router
            .get_or_init(|| {
                let mut router =
                    crate::routing::Router::new(self.routing.clone(), self.providers.len())
                        // WOR-2657: one rotation cursor per named group,
                        // sized here for the same reason the
                        // per-provider vectors are sized in `new`.
                        .with_model_groups(
                            self.model_groups.iter().map(|group| group.name.as_str()),
                        );
                if let Some(cache_affinity) = self.cache_affinity {
                    router = router.with_cache_affinity(cache_affinity);
                    tracing::info!(
                        providers = self.providers.len(),
                        ttl_secs = cache_affinity.ttl_secs,
                        max_keys_per_provider = cache_affinity.max_keys_per_provider,
                        "ai prompt-cache affinity armed"
                    );
                }
                if let Some(resilience) = self.resilience.as_ref() {
                    if let Some(breaker) = resilience.circuit_breaker.as_ref() {
                        let failure_threshold = breaker.failure_threshold.max(1);
                        if failure_threshold != breaker.failure_threshold {
                            tracing::warn!(
                                configured = breaker.failure_threshold,
                                applied = failure_threshold,
                                "ai circuit breaker: failure_threshold below 1 would open on \
                                 the first failure; raising it"
                            );
                        }
                        router = router.with_circuit_breakers(
                            failure_threshold,
                            // No warning for this one: a success
                            // threshold of 0 and one of 1 both close the
                            // breaker on the first half-open success, so
                            // there is nothing an operator would want to
                            // change.
                            breaker.success_threshold.max(1),
                            breaker.open_duration_secs,
                        );
                        tracing::info!(
                            providers = self.providers.len(),
                            failure_threshold,
                            open_duration_secs = breaker.open_duration_secs,
                            "ai circuit breakers armed"
                        );
                    }
                    if let Some(outlier) = resilience.outlier_detection.as_ref() {
                        let config = outlier.detector_config();
                        tracing::info!(
                            threshold = config.threshold,
                            window_secs = config.window_secs,
                            min_requests = config.min_requests,
                            ejection_duration_secs = config.ejection_duration_secs,
                            "ai outlier detection armed"
                        );
                        router = router.with_outlier_detection(config);
                    }
                    if let Some(cooldown) = resilience.cooldown_policy.as_ref() {
                        tracing::info!(
                            providers = self.providers.len(),
                            "ai per-error-class cooldowns armed"
                        );
                        router = router.with_classified_cooldowns(cooldown.clone());
                    }
                }
                std::sync::Arc::new(router)
            })
            .clone()
    }

    /// Return the enforcing fair-share quota store for this handler.
    ///
    /// Local pools need no runtime backend. Approximate and strong pools bind
    /// to the installed governance store only when its consistency guarantee
    /// matches the configured pool.
    pub fn quota_pool_store(
        &self,
        governance: Option<(
            std::sync::Arc<dyn crate::governance::GovernanceStore>,
            crate::governance::GovernanceConsistency,
        )>,
    ) -> Result<
        Option<std::sync::Arc<dyn crate::quota_pool::QuotaPoolStore>>,
        crate::quota_pool::PoolError,
    > {
        let Some(config) = self.quota_pool.as_ref() else {
            return Ok(None);
        };
        if let Some(cached) = self.quota_pool_store.get() {
            return Ok(Some(std::sync::Arc::clone(&cached.store)));
        }

        let cached = match config.consistency {
            crate::quota_pool::QuotaPoolConsistency::Local => {
                let store = crate::quota_pool::LocalQuotaPool::new(vec![config.clone()])
                    .map_err(|_| crate::quota_pool::PoolError::InvalidState)?;
                CachedQuotaPoolStore {
                    kind: "local",
                    store: std::sync::Arc::new(store),
                }
            }
            crate::quota_pool::QuotaPoolConsistency::Approximate => {
                let (store, consistency) =
                    governance.ok_or(crate::quota_pool::PoolError::InvalidState)?;
                if consistency != crate::governance::GovernanceConsistency::Approximate {
                    return Err(crate::quota_pool::PoolError::InvalidState);
                }
                let store = crate::quota_pool::SharedQuotaPool::new(vec![config.clone()], store)
                    .map_err(|_| crate::quota_pool::PoolError::InvalidState)?;
                CachedQuotaPoolStore {
                    kind: "approximate",
                    store: std::sync::Arc::new(store),
                }
            }
            crate::quota_pool::QuotaPoolConsistency::Strong => {
                let (store, consistency) =
                    governance.ok_or(crate::quota_pool::PoolError::InvalidState)?;
                if consistency != crate::governance::GovernanceConsistency::Strict {
                    return Err(crate::quota_pool::PoolError::InvalidState);
                }
                let store = crate::quota_pool::SharedQuotaPool::new(vec![config.clone()], store)
                    .map_err(|_| crate::quota_pool::PoolError::InvalidState)?;
                CachedQuotaPoolStore {
                    kind: "strong",
                    store: std::sync::Arc::new(store),
                }
            }
        };
        let cached = self
            .quota_pool_store
            .get_or_init(|| std::sync::Arc::new(cached));
        Ok(Some(std::sync::Arc::clone(&cached.store)))
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
    /// WOR-1545 / WOR-1524: per-error-class retry counts. When set, the
    /// failover loop classifies each upstream failure into a
    /// [`crate::failure_cause::FailureCause`] and consults this policy,
    /// so (for example) a `429` rate limit can be retried while a
    /// malformed request is not. `None` keeps the status-code retry set.
    #[serde(default)]
    pub retry_policy: Option<crate::failure_cause::RetryPolicy>,
    /// WOR-2556: per-error-class cooldown durations, the provider-level
    /// counterpart to `retry_policy`'s request-level counts. When set,
    /// a classified failure of a mapped class removes that provider
    /// from candidate rotation for the configured number of seconds
    /// (advisory, like the breaker: an all-cooling pool is revived
    /// rather than turned into an outage). `None` keeps current
    /// behavior exactly.
    #[serde(default)]
    pub cooldown_policy: Option<crate::failure_cause::CooldownPolicy>,
    /// WOR-1545: LLM-aware failover actions on top of the per-error retry
    /// policy. `None` leaves the request path unchanged.
    #[serde(default)]
    pub llm_aware: Option<LlmAwareConfig>,
    /// WOR-1545: when true, a content-policy refusal (a 4xx whose body marks
    /// a content-policy / safety block) fails over to the next provider in
    /// order instead of returning the refusal, so an operator can list a
    /// more permissive model after a stricter one. Off by default.
    #[serde(default)]
    pub content_policy_fallback: bool,
    /// Milliseconds a streaming request may wait for the provider's
    /// response headers before the gateway gives up on that candidate and
    /// tries the next one.
    ///
    /// This bounds connect through upstream response headers only. Once
    /// the provider answers with a streaming content type the request is
    /// committed to that provider: a stall after that point ends the
    /// stream rather than failing over, because a later candidate cannot
    /// replace output the caller is already receiving. Those stalls are
    /// counted on `sbproxy_ai_stream_post_commit_failures_total`, and a
    /// failover taken on this budget is labeled
    /// `sbproxy_ai_failovers_total{reason="pre_header_timeout"}`.
    ///
    /// This is a different budget from `providers[].timeout_ms`, which is
    /// measured from connect through the end of the response body and so
    /// cuts a streaming completion off mid-stream. Set both: this one to
    /// fail off a wedged provider quickly, that one to cap the whole
    /// call.
    ///
    /// Applies to streaming requests only, and must be above zero when
    /// set. Unset leaves streaming requests bounded solely by
    /// `providers[].timeout_ms`, or by the gateway's 30-second HTTP
    /// client default when that is unset too, during which no failover
    /// happens.
    ///
    /// This budget only ever shortens an attempt, so a value above the
    /// attempt's own transport budget never fires: set it below
    /// `providers[].timeout_ms`, or below 30000 on a provider that sets
    /// no `timeout_ms`.
    ///
    /// Worst case before the caller sees an error is
    /// `(pre_header_timeout_ms + backoff) x candidate count`, since the
    /// dispatch loop visits each configured provider at most once.
    ///
    /// What it also covers, which is easy to miss on a cluster: a
    /// `managed_model` served by another node is dispatched over the
    /// model plane from inside the same bounded attempt, so this budget
    /// bounds that dispatch too, cold start included. A cold start is
    /// legitimately slower than any hosted provider's headers. On an
    /// origin that can route to a managed model, size this above the
    /// cold-start budget or leave it unset.
    #[serde(default)]
    pub pre_header_timeout_ms: Option<u64>,
}

/// LLM-aware failover actions (WOR-1545).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct LlmAwareConfig {
    /// Compress the prompt to fit the resolved model's context window
    /// before dispatch, so an over-long request succeeds on the same model
    /// instead of being rejected with a context-length error. Only the
    /// oldest non-system messages are dropped; the system message and the
    /// most recent turns are preserved.
    #[serde(default)]
    pub context_compress: bool,
    /// Tokens to reserve for the completion when fitting the prompt to the
    /// window. Defaults to 1024.
    #[serde(default)]
    pub completion_reserve_tokens: Option<u64>,
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

impl AiOutlierConfig {
    /// Translate to the platform detector's config, refusing the two
    /// values that would eject a provider the evidence does not
    /// condemn.
    ///
    /// A threshold of `0.0` ejects on `failure_rate >= 0.0`, which
    /// every provider satisfies including one that has never failed,
    /// and `min_requests: 0` lets that fire before a single request has
    /// been observed. Together they eject the whole pool on the first
    /// tick. Both parsed happily while nothing read this block, so no
    /// deployment has ever felt them; the first deployment to feel them
    /// should not be one that typed a zero.
    fn detector_config(&self) -> sbproxy_platform::outlier::OutlierDetectorConfig {
        let usable = self.threshold.is_finite() && self.threshold > 0.0;
        let threshold = if usable {
            self.threshold.min(1.0)
        } else {
            default_outlier_threshold()
        };
        if !usable || self.threshold > 1.0 {
            tracing::warn!(
                configured = self.threshold,
                applied = threshold,
                "ai outlier detection: threshold is a failure rate above 0 and at most 1"
            );
        }
        let min_requests = self.min_requests.max(1);
        if min_requests != self.min_requests {
            tracing::warn!(
                applied = min_requests,
                "ai outlier detection: min_requests of 0 would judge a provider before it \
                 had answered anything; raising it"
            );
        }
        sbproxy_platform::outlier::OutlierDetectorConfig {
            threshold,
            window_secs: self.window_secs,
            min_requests,
            ejection_duration_secs: self.ejection_duration_secs,
        }
    }
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

/// Active probe of an AI provider, driven by [`crate::health_probe`].
///
/// The probe is a `GET /models` (or `path` if overridden) carrying the
/// provider's own credential. Any answer that is not a 5xx counts as
/// success, because these base URLs come from the vendor catalog rather
/// than from an endpoint the operator controls: a 401, a 404, or a 429
/// says something about the probe or the account, not about whether the
/// provider is serving.
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

/// Shadow / side-by-side eval: send the same request to a second provider
/// concurrently and log metadata. V1 is restricted to non-streaming chat
/// evaluation surfaces (`chat/completions`, normalized `messages`, and
/// normalized `responses`). The shadow response is drained and discarded;
/// the primary's response goes to the client unchanged.
///
/// Shadow tasks are supervised by bounded task and memory admission. When
/// either capacity fills up the new request is dropped (a counter ticks)
/// instead of being silently spawned, and each task has a hard wall-clock
/// timeout that, when exceeded, drops the future and ticks a separate timeout
/// counter. See `sbproxy_ai::client::AiClient` for the supervisor
/// implementation.
#[derive(Debug, Clone)]
pub struct AiShadowConfig {
    /// Providers to shadow this route against.
    ///
    /// Every target sees the same request, independently sampled, and
    /// each produces its own usage-ledger row tagged `shadow` and
    /// grouped with the primary by `shadow_of`. The list is keyed by
    /// `provider`: two entries naming the same provider are refused at
    /// config load, because the provider name is what labels the
    /// metric and identifies the row.
    ///
    /// The single-target form is still accepted and means a one-entry
    /// list:
    ///
    /// ```yaml
    /// shadow:
    ///   provider: anthropic
    ///   sample_rate: 0.1
    /// ```
    pub targets: Vec<AiShadowTarget>,
}

/// One provider this route is shadowed against.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AiShadowTarget {
    /// Provider name to shadow against. Must also appear in the
    /// `providers` list (so its API key, base URL, and rate limits
    /// resolve normally). Use a different model than the primary if
    /// you want to A/B different model versions. No two targets may
    /// name the same provider.
    pub provider: String,
    /// Optional model override for the shadow request. Defaults to
    /// the same model the client sent.
    #[serde(default)]
    pub model: Option<String>,
    /// Sample rate in `[0.0, 1.0]`. Default `1.0` (mirror every
    /// request). Set lower to avoid doubling spend on every call.
    ///
    /// One draw is taken per request and every target is compared
    /// against that same draw, so target populations nest rather than
    /// diverge: everything a `0.1` target sees, a `0.5` target on the
    /// same route also saw. That is what makes two targets comparable
    /// on the smaller one's whole population.
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

/// The `targets:` spelling, kept separate from the flat one so an
/// unknown key inside it is still refused.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AiShadowTargetList {
    targets: Vec<AiShadowTarget>,
}

impl<'de> Deserialize<'de> for AiShadowConfig {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        // Branch on the presence of `targets` rather than with
        // `#[serde(untagged)]`: untagged reports "data did not match any
        // variant" for a typo anywhere in either arm, which for a block
        // with five sibling keys is a worse error than the one
        // `deny_unknown_fields` gives.
        let value = serde_json::Value::deserialize(deserializer)?;
        let targets = if value.get("targets").is_some() {
            serde_json::from_value::<AiShadowTargetList>(value)
                .map_err(D::Error::custom)?
                .targets
        } else {
            vec![serde_json::from_value::<AiShadowTarget>(value).map_err(D::Error::custom)?]
        };

        if targets.is_empty() {
            return Err(D::Error::custom(
                "ai shadow.targets must name at least one provider; remove the \
                 shadow block to disable shadow evaluation",
            ));
        }
        // The provider name labels the shadow metric families and
        // identifies the target's ledger rows. Two entries sharing it
        // would silently merge two evaluations into one series.
        for (index, target) in targets.iter().enumerate() {
            if let Some(earlier) = targets[..index]
                .iter()
                .position(|other| other.provider == target.provider)
            {
                return Err(D::Error::custom(format!(
                    "ai shadow.targets[{index}] repeats provider {:?} from \
                     targets[{earlier}]; each target is identified by its \
                     provider name",
                    target.provider
                )));
            }
        }
        Ok(Self { targets })
    }
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
pub(crate) fn deserialize_routing<'de, D>(deserializer: D) -> Result<RoutingStrategy, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use crate::routing::{CascadeConfig, CascadeTier, PeakEwmaConfig};
    use crate::routing_state::PrefixAffinityConfig;
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
    // `cache_affinity` composes with every strategy, so it is a sibling of
    // `routing:`, not a field inside it. Authored here it would otherwise
    // deserialize as an unknown strategy variant and refuse with a message
    // that names the wrong problem.
    if obj.contains_key("cache_affinity") {
        return Err(Error::custom(
            "cache_affinity is not a routing field; move it up one level so it \
             sits beside `routing:` on the ai action",
        ));
    }
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

    if strategy_name == "peak_ewma" {
        let config: PeakEwmaConfig = serde_json::from_value(serde_json::Value::Object(obj.clone()))
            .map_err(Error::custom)?;
        return Ok(RoutingStrategy::PeakEwma(config));
    }

    if strategy_name == "prefix_affinity" {
        let mut fields = obj.clone();
        fields.remove("strategy");
        let config: PrefixAffinityConfig =
            serde_json::from_value(serde_json::Value::Object(fields)).map_err(Error::custom)?;
        config.validate().map_err(Error::custom)?;
        return Ok(RoutingStrategy::PrefixAffinity(config));
    }

    // WOR-2564: semantic routing carries routes / min_similarity /
    // fallback / an embedding-source block alongside the discriminator.
    // Validation runs here so a strategy with nothing to embed with or
    // nothing to route to refuses the config at load.
    if strategy_name == "semantic_route" {
        let mut fields = obj.clone();
        fields.remove("strategy");
        let config: crate::routing::semantic_route::SemanticRouteConfig =
            serde_json::from_value(serde_json::Value::Object(fields)).map_err(Error::custom)?;
        config.validate().map_err(Error::custom)?;
        return Ok(RoutingStrategy::SemanticRoute(Box::new(config)));
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

impl AiHandlerConfig {
    /// Build from a generic JSON value.
    ///
    /// An authored `context_overflow:` block is refused. See the inline
    /// note below for why refusing beats ignoring it.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Self::from_config_inner(value, true, None)
    }

    /// [`Self::from_config`] for validation-only compiles: identical
    /// checks, but the candidate's price table is built (so a bad rate
    /// card still warns) and then dropped rather than installed into the
    /// process-global cost-accounting table. Without this split, validating
    /// a config that is then rejected left live cost accounting reading the
    /// rejected candidate's prices until the next successful load.
    pub fn from_config_for_validation(value: serde_json::Value) -> anyhow::Result<Self> {
        Self::from_config_inner(value, false, None)
    }

    /// [`Self::from_config`] with a prepared WASM routing program.
    ///
    /// An `ai_routing_policy` with `engine: wasm` names a hook inside an
    /// extension bundle, and the bundle registry is only visible to the
    /// action-compile layer. That layer resolves the hook against the
    /// registry, prepares the program, and hands it in here; the eager
    /// compile threads it into
    /// [`crate::ai_routing_policy::CompiledAiRoutingPolicy`] via
    /// `compile_with_program`. Passing `None` alongside an `engine: wasm`
    /// config makes the eager compile fail with the requires-a-bundle
    /// error, which is the load-time refusal the design wants: a wasm
    /// hook nothing resolved must refuse the config rather than boot with
    /// the policy silently absent.
    pub fn from_config_with_wasm_routing(
        value: serde_json::Value,
        wasm_routing: Option<crate::ai_routing_policy::WasmRoutingResolution>,
    ) -> anyhow::Result<Self> {
        Self::from_config_inner(value, true, wasm_routing)
    }

    /// [`Self::from_config_for_validation`] with a prepared WASM routing
    /// program: identical checks to
    /// [`Self::from_config_with_wasm_routing`], but the candidate's price
    /// table is built and then dropped rather than installed into the
    /// process-global cost-accounting table. As there, `None` plus an
    /// `engine: wasm` config refuses at load with the requires-a-bundle
    /// error.
    pub fn from_config_for_validation_with_wasm_routing(
        value: serde_json::Value,
        wasm_routing: Option<crate::ai_routing_policy::WasmRoutingResolution>,
    ) -> anyhow::Result<Self> {
        Self::from_config_inner(value, false, wasm_routing)
    }

    fn from_config_inner(
        value: serde_json::Value,
        install_price_table: bool,
        wasm_routing: Option<crate::ai_routing_policy::WasmRoutingResolution>,
    ) -> anyhow::Result<Self> {
        // WOR-2309: `context_overflow:` was never a field on this struct,
        // but ai-gateway.md named the block by that spelling and told
        // operators it was "ignored", which is an invitation to write it
        // and wait for the feature to arrive. The module behind that
        // promise held a `check_overflow` pair returning `Error`,
        // `FallbackToLarger`, or `Truncate`, and no dispatch code ever
        // called it; the doc paragraph and the decision layer are both
        // gone now. This struct does not set `deny_unknown_fields`, so
        // without an explicit refusal the key would go from
        // documented-and-inert to silently swallowed, which is the worse
        // of the two. Refusing also keeps the spelling free to come back
        // as a live key if the fallback-to-a-larger-model decision is
        // ever designed, rather than arriving to find it already sitting
        // in deployed configs meaning nothing.
        anyhow::ensure!(
            value.get("context_overflow").is_none(),
            "ai `context_overflow:` was removed: no dispatch code ever read it, so it never \
             errored, fell back to a larger model, or truncated anything. Fitting an \
             oversized prompt to the model's window is what the compression pipeline does: \
             add a `window_fit` lever under `compression.levers`, or set \
             `resilience.llm_aware.context_compress: true` for the one-lever shorthand. \
             To reroute an oversized prompt to a larger-window model instead, list that \
             provider in `context_window_fallbacks:` on this action."
        );
        // WOR-2556: the `routing:` object form ignores keys the selected
        // strategy does not read, so a typed fallback list authored there
        // would be silently swallowed, which is the failure mode the
        // `context_overflow:` refusal above exists to prevent. Refuse and
        // point at the level the keys live on.
        //
        // `resilience:` is checked on the same footing, and is the
        // likelier of the two misplacements: `content_policy_fallback`
        // (singular, a boolean) is a real key that already lives there,
        // so the plural list is one character and one nesting level from
        // a spelling operators are already using. `AiResilienceConfig`
        // sets no `deny_unknown_fields`, so without this the key is
        // dropped in silence, `sbproxy validate` exits 0, and every
        // content-policy refusal reaches the caller with nothing in the
        // logs to say the configured reroute never ran.
        for parent in ["routing", "resilience"] {
            let Some(object) = value.get(parent).and_then(|v| v.as_object()) else {
                continue;
            };
            for key in ["context_window_fallbacks", "content_policy_fallbacks"] {
                anyhow::ensure!(
                    !object.contains_key(key),
                    "ai `{parent}.{key}` is not read there and would be silently ignored: \
                     `{key}:` is a sibling of `{parent}:` on the ai_proxy action, not a key \
                     inside it"
                );
            }
        }
        // The same silent-swallow failure, one level out. `timeout_ms`
        // lives on `providers[]`, so an operator reaching for a second
        // timeout key reasonably guesses the action level; `resilience:`
        // is where this one is read. `AiHandlerConfig` sets no
        // `deny_unknown_fields` either, so without this the key is
        // dropped in silence and every streaming request keeps waiting
        // out the 30-second client default with no failover.
        anyhow::ensure!(
            value.get("pre_header_timeout_ms").is_none(),
            "ai `pre_header_timeout_ms` is not read at the action level and would be \
             silently ignored: it is `resilience.pre_header_timeout_ms`, a key inside \
             the `resilience:` block rather than a sibling of it"
        );
        let mut config: Self = serde_json::from_value(value)?;
        // WOR-2556: a typed fallback list is an aimed allowlist. A name
        // matching no provider would leave the trigger configured and
        // the reroute unreachable, so it fails the load instead.
        for (key, names) in [
            ("context_window_fallbacks", &config.context_window_fallbacks),
            ("content_policy_fallbacks", &config.content_policy_fallbacks),
        ] {
            for name in names {
                anyhow::ensure!(
                    config
                        .providers
                        .iter()
                        .any(|provider| provider.name.as_str() == name.as_str()),
                    "ai `{key}` names provider `{name}`, which does not match any \
                     `providers[].name` on this action"
                );
            }
        }
        // WOR-2559: a ceiling of zero or below cannot admit any request
        // whose estimate is a real cost, so it would blackhole the origin
        // at 402 for every chat request, which is what a typed `-0.05` or
        // a stray `0` looks like. The header form already refuses a
        // non-positive value; refusing here too means the operator learns
        // at load rather than from a support ticket.
        if let Some(ceiling) = config.max_price_per_request {
            if !ceiling.is_finite() || ceiling <= 0.0 {
                anyhow::bail!(
                    "ai max_price_per_request must be a positive USD amount, got {ceiling}. \
                     A ceiling at or below zero refuses every request, since no priced \
                     candidate estimates below it. Remove the key to disable the ceiling."
                );
            }
        }
        // A zero ceiling admits no caller header at all, so the flag
        // would be on and every request carrying the header would 400.
        // Same reading as a zero price ceiling: a typo, not a policy.
        if config.max_request_timeout_ms == Some(0) {
            anyhow::bail!(
                "ai max_request_timeout_ms must be above zero. A ceiling of zero refuses \
                 every x-sbproxy-timeout-ms header, which is the flag being off with extra \
                 steps. Remove the key, or set the largest per-attempt budget a caller may \
                 ask for."
            );
        }
        // The flag without a ceiling is the failure the gate exists to
        // prevent: any caller could then hold a downstream connection, a
        // quota_pool slot, and an upstream generation open for as long as
        // it liked. Refusing at load is the only place an operator finds
        // out before a caller does.
        if config.allow_request_timeout_override && config.max_request_timeout_ms.is_none() {
            anyhow::bail!(
                "ai allow_request_timeout_override requires max_request_timeout_ms. Without \
                 a ceiling the x-sbproxy-timeout-ms header is an unbounded per-attempt \
                 budget any caller can set. Set max_request_timeout_ms to the largest \
                 budget a caller may ask for, or remove allow_request_timeout_override."
            );
        }
        // A zero pre-header budget elapses before any provider can
        // answer, so every streaming request would burn the whole
        // candidate list and return an error. That reads as an outage,
        // not as a tuning mistake, so it fails at load the way a zero
        // `prefix_affinity.ttl` does.
        if let Some(resilience) = config.resilience.as_ref() {
            if resilience.pre_header_timeout_ms == Some(0) {
                anyhow::bail!(
                    "ai resilience.pre_header_timeout_ms must be above zero. A zero budget \
                     elapses before any provider can send response headers, so every \
                     streaming request would fail over through the whole candidate list \
                     and return an error. Remove the key to leave streaming requests \
                     bounded only by providers[].timeout_ms."
                );
            }
        }
        if let Some(rag) = config.rag.as_ref() {
            rag.validate()
                .map_err(|error| anyhow::anyhow!("ai rag: {error}"))?;
        }
        config
            .reasoning
            .validate()
            .map_err(|error| anyhow::anyhow!("ai reasoning: {error}"))?;
        // WOR-2422: every other CEL surface refuses the config when an
        // expression does not compile; this one used to log an error
        // and disable itself, so a typo shipped a proxy that booted
        // green with the policy silently absent. Compile once here for
        // validation (the runtime instance still compiles lazily on
        // first use); binding mistakes are caught too, because the
        // compile goes through the `ai_policy` CEL surface.
        if let Some(policy) = config.ai_policy.as_ref() {
            crate::ai_policy::CompiledAiPolicy::compile(policy)
                .map_err(|error| anyhow::anyhow!("ai ai_policy: {error}"))?;
        }
        // WOR-2366: same eager-compile discipline for the routing policy.
        // A CEL expression referencing a binding the routing surface does
        // not offer, a bad `on_error`, an oversized `reason_codes`, or a
        // Rego module that fails the evaluability proof fails config load
        // here rather than disabling the policy at first use. The compiled
        // program pre-warms the lazy cell rather than being dropped, so a
        // Rego module is parsed and proved once per load, not twice (and
        // the script-compile metric counts one compile per load). An
        // `engine: wasm` policy consumes the program the action-compile
        // layer resolved and passed through `wasm_routing`; with `None`
        // here, `compile_with_program` fails with the requires-a-bundle
        // error, so an unresolved wasm hook refuses the config at load.
        if let Some(policy) = config.ai_routing_policy.as_ref() {
            let compiled = crate::ai_routing_policy::CompiledAiRoutingPolicy::compile_with_program(
                policy,
                wasm_routing,
            )
            .map_err(|error| anyhow::anyhow!("ai ai_routing_policy: {error}"))?;
            let _ = config
                .ai_routing_policy_compiled
                .set(Some(std::sync::Arc::new(compiled)));
        }
        // WOR-2233: `token_rate` scores remaining headroom against a
        // per-provider tokens-per-minute limit, and nothing supplies
        // one. `Router::token_limits` has no config field and no
        // production writer, so every limit is zero and the score
        // reduces to `-tokens_used`: the documented strategy silently
        // becomes `least_token_usage`. Refusing is the honest
        // disposition until a limit field and the window reset that
        // would make it mean anything both exist. Anyone selecting it
        // today is already getting `least_token_usage`, so the fix
        // named in this message preserves their behaviour exactly.
        if matches!(config.routing, RoutingStrategy::TokenRate) {
            anyhow::bail!(
                "ai routing strategy `token_rate` ranks providers by remaining \
                 tokens-per-minute headroom against a declared per-provider limit, \
                 and no configuration field declares one. Every limit is zero, so \
                 the strategy would rank by observed usage alone and behave exactly \
                 like `least_token_usage`. Set `routing.strategy: least_token_usage` \
                 to keep that behaviour, or use `headroom` or `reset_aware`, which \
                 score the rate-limit headers providers actually return."
            );
        }
        if let Some(guardrails) = &config.guardrails {
            crate::guardrails::validate_pipeline_config(guardrails)
                .map_err(|error| anyhow::anyhow!("ai guardrails: {error}"))?;
        }
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
        // `pii.redact_response: true` ("apply redaction to outbound
        // response bodies") is declared on `PiiConfig` but nothing on
        // the AI response path reads it: `redact_request` is applied
        // by `apply_json_request_pii_redaction` before the request
        // forwards, and there is no response-side counterpart,
        // buffered or streaming. `PiiRedactor::from_config` itself
        // does not read either flag, so this is not caught anywhere
        // downstream either. An operator who sets `redact_response:
        // true` believes model output is being scrubbed when it is
        // not. Refuse rather than boot green with the knob silently
        // inert, the same disposition `routing.strategy: token_rate`
        // and the removed `context_overflow:` block get above.
        if config.pii.as_ref().is_some_and(|p| p.redact_response) {
            anyhow::bail!(
                "ai `pii.redact_response: true` is refused: no code path applies PII \
                 redaction to outbound AI response bodies today. `redact_request` covers \
                 inbound request bodies only. Configuring `redact_response: true` would \
                 leave an operator believing responses are scrubbed when they are not. \
                 Remove `redact_response` (or leave it at its default `false`) until \
                 response-body redaction ships. The AI guardrail mesh's `redact_on_flag` \
                 (docs/ai-guardrail-mesh.md) redacts a *request* body pre-dispatch on a \
                 flagged verdict; nothing redacts the model's response before it reaches \
                 the client."
            );
        }
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
        let mut provider_names = std::collections::HashSet::new();
        for provider in &config.providers {
            if !provider_names.insert(provider.name.as_str()) {
                anyhow::bail!(
                    "ai provider name {:?} is configured more than once",
                    provider.name
                );
            }
        }
        // WOR-2366: a cascade tier naming a provider that is not configured
        // is silently skipped at runtime (the cascade treats it as a failed
        // tier), so the operator's tier never runs and nothing says why.
        // Refuse it at load, the way a duplicate provider name is refused
        // above. This is also the literal, checkable half of the routing
        // policy's provider validation: a computed plan is checked per
        // request, but a statically configured tier is checked here.
        if let RoutingStrategy::Cascade(cascade) = &config.routing {
            for (index, tier) in cascade.tiers.iter().enumerate() {
                if !provider_names.contains(tier.provider_id.as_str()) {
                    anyhow::bail!(
                        "ai routing cascade tier {index} names provider {:?}, \
                         which is not configured",
                        tier.provider_id
                    );
                }
            }
        }
        // WOR-2564: the same literal, checkable discipline for semantic
        // routing. A route pinned to a deployment nobody configured, a
        // fallback nothing can serve, or an embedding provider outside
        // `providers` would each surface as a silent per-request fallback
        // at runtime; each is a config-compile refusal instead.
        if let RoutingStrategy::SemanticRoute(semantic) = &config.routing {
            for (index, rule) in semantic.routes.iter().enumerate() {
                if !provider_names.contains(rule.deployment.as_str()) {
                    anyhow::bail!(
                        "ai semantic_route route {index} names deployment {:?}, \
                         which is not a configured provider",
                        rule.deployment
                    );
                }
            }
            if let Some(fallback) = semantic.fallback.as_deref() {
                if !provider_names.contains(fallback) {
                    anyhow::bail!(
                        "ai semantic_route fallback names provider {fallback:?}, \
                         which is not configured"
                    );
                }
            }
            if let Some(embedding) = semantic.embedding.as_ref() {
                if !provider_names.contains(embedding.provider.as_str()) {
                    anyhow::bail!(
                        "ai semantic_route embedding provider {:?} is not configured; \
                         `source: provider` must name one of this origin's providers",
                        embedding.provider
                    );
                }
            }
        }
        for provider in &config.providers {
            provider.validate_managed_model().map_err(|error| {
                anyhow::anyhow!("ai provider {:?} managed model: {error}", provider.name)
            })?;
            provider
                .validate_native_credential_binding()
                .map_err(|error| {
                    anyhow::anyhow!(
                        "ai provider {:?} native credential binding: {error}",
                        provider.name
                    )
                })?;
            provider.validate_key_failure_posture().map_err(|error| {
                anyhow::anyhow!(
                    "ai provider {:?} key failure posture: {error}",
                    provider.name
                )
            })?;
            provider
                .validate_base_url()
                .map_err(|e| anyhow::anyhow!("ai provider {:?} base_url: {e}", provider.name))?;
            // WOR-2652: an entry that names a tier its vendor does not sell
            // would boot green and then serve every request on a tier the
            // operator did not choose, which shows up on the invoice rather
            // than in a log.
            crate::service_tier::validate_provider_tier(provider).map_err(|error| {
                anyhow::anyhow!("ai provider {:?} service tier: {error}", provider.name)
            })?;
            provider.validate_bedrock_guardrail().map_err(|error| {
                anyhow::anyhow!("ai provider {:?} bedrock guardrail: {error}", provider.name)
            })?;
            // WOR-1818: an unresolved `${VAR}` left by env interpolation
            // would reach the wire verbatim as a bearer token and read as
            // a provider auth outage at request time. Fail at config load
            // with the variable name instead.
            if let Some(key) = &provider.api_key {
                if let (Some(start), Some(end)) = (key.find("${"), key.find('}')) {
                    if end > start {
                        return Err(anyhow::anyhow!(
                            "ai provider {:?}: api_key contains the unresolved reference \
                             `{}`; export the environment variable before starting, or \
                             use a secret:// / vault:// reference.",
                            provider.name,
                            &key[start..=end]
                        ));
                    }
                }
            }
            // WOR-1683/1684/1681: validate a serve: block (unique model
            // names, no nameless raw refs, parseable keep_alive, pinned
            // container images) at config load so a bad local-serving
            // config fails at `plan` rather than at the first request.
            if let Some(serve) = &provider.serve {
                serve
                    .validate()
                    .map_err(|e| anyhow::anyhow!("ai provider {:?} serve: {e}", provider.name))?;
                // WOR-1680: a served provider hosts the model on this box,
                // so it needs no address. `serve:` with `base_url` is a
                // config error (which one wins would be ambiguous); the
                // gateway resolves the loopback port itself.
                if provider.base_url.is_some() {
                    return Err(anyhow::anyhow!(
                        "ai provider {:?}: sets both serve: and base_url:; a served provider is hosted locally and needs no base_url (remove it). Use base_url + allow_private_base_url only for a separately-running engine.",
                        provider.name
                    ));
                }
            }
        }
        // Both Bedrock guardrail controls on one origin is a legal and
        // sometimes deliberate deployment (ApplyGuardrail screens the
        // prompt out of band, the inline block screens the completion),
        // so this warns rather than refuses. It is still worth saying
        // once at load: AWS bills each evaluation, and an operator who
        // meant to migrate from one to the other has just doubled the
        // guardrail spend without changing any behavior they can see.
        let inline_guardrail_providers: Vec<&str> = config
            .providers
            .iter()
            .filter(|provider| provider.bedrock_guardrail.is_some())
            .map(|provider| provider.name.as_str())
            .collect();
        if !inline_guardrail_providers.is_empty() {
            let apply_guardrail = config.guardrails.as_ref().is_some_and(|guardrails| {
                guardrails.external.iter().any(|external| {
                    external.provider == crate::external_guardrail::GuardrailProvider::Bedrock
                })
            });
            if apply_guardrail {
                tracing::warn!(
                    providers = %inline_guardrail_providers.join(","),
                    "ai: providers[].bedrock_guardrail and guardrails.external[] with \
                     provider: bedrock are both configured; AWS evaluates and bills the \
                     guardrail twice per request"
                );
            }
        }

        // WOR-1880: reject strong consistency / invalid pool shapes at load.
        if let Some(pool) = &config.quota_pool {
            crate::quota_pool::validate_quota_pool_config(pool)
                .map_err(|error| anyhow::anyhow!("ai quota_pool: {error}"))?;
        }
        // WOR-1683: on a served provider the serve-entry name IS the
        // model id every plane sees, so an empty `models:` list derives
        // from the serve entries instead of forcing the operator to
        // write the same fact twice. An explicit list still wins (it
        // may deliberately expose a subset). `serve.validate()` above
        // already rejected duplicate and nameless entries.
        for provider in &mut config.providers {
            let Some(serve) = &provider.serve else {
                continue;
            };
            if !provider.models.is_empty() {
                continue;
            }
            for entry in &serve.models {
                let name = entry
                    .effective_name()
                    .map_err(|e| anyhow::anyhow!("ai provider {:?} serve: {e}", provider.name))?;
                provider.models.push(ModelId::from(name));
            }
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
            if provider.serve.is_some() {
                // WOR-1809: a served provider hosts its model on this
                // box; its name is a free-form label and the gateway
                // resolves the engine's loopback port itself, so the
                // localhost-fallback warning below does not apply.
                continue;
            }
            if provider.is_managed_model() {
                continue;
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
        // WOR-2312: an alias resolves before provider selection, so one
        // that reuses a name a provider already serves would silently
        // rewrite every request asking for the real model and nothing
        // downstream could tell. Validate after the serve-derived `models:`
        // lists are filled in above, so the shadow check sees the same
        // model set the router will.
        crate::model_alias::validate_model_aliases(&config.model_aliases, &config.providers)
            .map_err(|error| anyhow::anyhow!("ai model_aliases: {error}"))?;
        // Warm the index here rather than on the first request, so the
        // whole alias plane is resolved at config load.
        let _ = config.model_alias_registry();
        // WOR-2657: a group resolves at the same seam an alias does, so
        // it is validated against the same filled-in `models:` lists and
        // against the alias list itself: one name cannot be both.
        crate::model_group::validate_model_groups(
            &config.model_groups,
            &config.providers,
            &config.model_aliases,
        )
        .map_err(|error| anyhow::anyhow!("ai model_groups: {error}"))?;
        let _ = config.model_group_registry();
        // WOR-2557: a `data_posture:` block whose own requirement
        // excludes every provider the origin configures is a blackholed
        // origin, not a strict one: it boots green and then refuses
        // every request it is ever sent. Refuse it here, naming the key
        // and the excluded providers, rather than leaving the operator
        // to discover it from production traffic. Runs after the
        // serve-derived provider lists above so a locally served entry
        // (zero-data-retention by construction) counts as eligible.
        crate::data_posture::validate_posture_requirement(
            config.data_posture.as_ref(),
            &config.providers,
        )
        .map_err(|error| anyhow::anyhow!("ai {error}"))?;
        if let Some(compression) = &mut config.compression {
            compression.apply_state_defaults();
            compression.validate(&config.providers)?;
        }
        for (index, key) in config.virtual_keys.iter().enumerate() {
            let Some(raw_selector) = key.compression_profile.as_deref() else {
                continue;
            };
            let selector = CompressionSelector::parse(raw_selector).map_err(|_| {
                anyhow::anyhow!(
                    "ai virtual_keys[{index}].compression_profile must be on, off, or a valid profile name"
                )
            })?;
            if let CompressionSelector::Profile(name) = selector {
                let declared = config
                    .compression
                    .as_ref()
                    .is_some_and(|policy| policy.profiles.contains_key(&name));
                if !declared {
                    anyhow::bail!(
                        "ai virtual_keys[{index}].compression_profile selects an undeclared profile"
                    );
                }
            }
        }
        // WOR-1707: install the operator price table (config prices +
        // external rate card) into the process-global consulted by cost
        // estimation. Runs on every config (re)load so prices update
        // with the config; a missing/bad rate card warns and is skipped.
        // Validation-only compiles build the table (so its warnings still
        // fire) but never install it: a rejected candidate must not leave
        // live cost accounting on its prices.
        let price_table =
            crate::budget::build_price_table(&config.model_prices, config.rate_card.as_deref());
        if install_price_table {
            crate::budget::set_price_table(price_table);
        }
        Ok(config)
    }

    /// Resolve explicit compression or synthesize the legacy window-fit policy.
    ///
    /// An explicit block always wins, including an explicit empty lever list.
    /// The explicit path is borrowed and does not allocate on request handling.
    pub fn effective_compression_policy(&self) -> Option<std::borrow::Cow<'_, CompressionPolicy>> {
        if let Some(policy) = self.compression.as_ref() {
            return Some(std::borrow::Cow::Borrowed(policy));
        }
        let legacy = self
            .resilience
            .as_ref()
            .and_then(|resilience| resilience.llm_aware.as_ref())
            .filter(|legacy| legacy.context_compress)?;
        Some(std::borrow::Cow::Owned(
            CompressionPolicy::legacy_window_fit(legacy.completion_reserve_tokens),
        ))
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

    /// This origin's model-alias registry, built on first call.
    ///
    /// [`Self::from_config`] warms it, so the request path only ever hits
    /// the cached instance. The fallback build keeps a handler assembled
    /// some other way (a struct literal in a test) resolving the same
    /// aliases as one that came through config load.
    pub fn model_alias_registry(&self) -> &crate::model_alias::ModelAliasRegistry {
        self.model_alias_index.get_or_init(|| {
            crate::model_alias::ModelAliasRegistry::from_config(self.model_aliases.clone())
        })
    }

    /// This origin's model-group registry, built on first call.
    ///
    /// [`Self::from_config`] warms it, so the request path only ever
    /// hits the cached instance. The fallback build keeps a handler
    /// assembled some other way (a struct literal in a test) resolving
    /// the same groups as one that came through config load.
    pub fn model_group_registry(&self) -> &crate::model_group::ModelGroupRegistry {
        self.model_group_index.get_or_init(|| {
            crate::model_group::ModelGroupRegistry::from_config(self.model_groups.clone())
        })
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

/// Classified AI API surface for a given request.
///
/// Every variant corresponds to a distinct dispatch path inside
/// `handle_ai_proxy`. New variants may be added in minor releases;
/// pattern matches must include a wildcard arm.
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

    /// Every classified surface, in declaration order.
    ///
    /// The capability matrix in [`crate::api_routes`] and the model
    /// listing both need to iterate the whole surface set: the matrix
    /// tests to prove the documented contract holds for every cell, and
    /// [`crate::api_routes::surface_capability_names`] to decide which
    /// surfaces a listing may name. This array is the production copy
    /// both use, so a surface the dispatch path classifies cannot be
    /// invisible to the listing that describes it (WOR-2647).
    ///
    /// Writing the length into the type checks the literal only against
    /// itself, so the array on its own cannot notice a twentieth
    /// variant. The private `position` function below is the
    /// enforcement: its match is exhaustive, so a new variant fails to
    /// compile there, and the `const` block after this `impl` checks
    /// the two lists against each other at compile time.
    pub const ALL: [AiSurface; 19] = [
        AiSurface::ChatCompletions,
        AiSurface::Models,
        AiSurface::Embeddings,
        AiSurface::Assistants,
        AiSurface::Threads,
        AiSurface::Batches,
        AiSurface::FineTuning,
        AiSurface::Files,
        AiSurface::Realtime,
        AiSurface::ImageGeneration,
        AiSurface::ImageEdits,
        AiSurface::ImageVariations,
        AiSurface::AudioTranscription,
        AiSurface::AudioSpeech,
        AiSurface::Moderations,
        AiSurface::Reranking,
        AiSurface::Messages,
        AiSurface::Responses,
        AiSurface::Unknown,
    ];

    /// Where `surface` sits in [`Self::ALL`].
    ///
    /// This is the compile-time tie between the enum and the array.
    /// The match is exhaustive, so a new variant is an `E0004`
    /// "non-exhaustive patterns" error here rather than a quietly
    /// shorter sweep and a surface missing from every published
    /// listing. The `const` block after this `impl` then checks that
    /// the index each arm names is where the variant actually sits
    /// (WOR-2647).
    const fn position(surface: &AiSurface) -> usize {
        match *surface {
            AiSurface::ChatCompletions => 0,
            AiSurface::Models => 1,
            AiSurface::Embeddings => 2,
            AiSurface::Assistants => 3,
            AiSurface::Threads => 4,
            AiSurface::Batches => 5,
            AiSurface::FineTuning => 6,
            AiSurface::Files => 7,
            AiSurface::Realtime => 8,
            AiSurface::ImageGeneration => 9,
            AiSurface::ImageEdits => 10,
            AiSurface::ImageVariations => 11,
            AiSurface::AudioTranscription => 12,
            AiSurface::AudioSpeech => 13,
            AiSurface::Moderations => 14,
            AiSurface::Reranking => 15,
            AiSurface::Messages => 16,
            AiSurface::Responses => 17,
            AiSurface::Unknown => 18,
        }
    }

    /// Whether this surface legitimately carries a `multipart/form-data`
    /// request body. The OpenAI-compatible API takes multipart on image
    /// edits, image variations, audio transcription/translation, and file
    /// uploads; every other classified surface is JSON. `Unknown` returns
    /// true because unclassified pass-through paths may serve formats this
    /// table has no opinion on; the gate exists to stop a multipart
    /// Content-Type from relabeling a *known JSON* surface past the
    /// body-aware checks (WOR-2472).
    pub fn accepts_multipart(&self) -> bool {
        matches!(
            self,
            AiSurface::ImageEdits
                | AiSurface::ImageVariations
                | AiSurface::AudioTranscription
                | AiSurface::Files
                | AiSurface::Unknown
        )
    }

    /// The OpenTelemetry GenAI `gen_ai.operation.name` for this surface
    /// (WOR-2085).
    ///
    /// [`Self::label`] is the metrics/tracing *surface* identifier and
    /// stays exactly as it is; this mapping exists because the OTel
    /// convention names the operation differently: a chat completion is
    /// `chat`, not `chat_completions`, and every image or audio shape
    /// collapses onto one operation name. Before this mapping the
    /// request span stamped the surface label into
    /// `gen_ai.operation.name`, which happened to be right for
    /// embeddings and `images/generations` and wrong for everything
    /// else, chat included.
    ///
    /// Control-plane surfaces (models, files, batches, fine-tuning,
    /// assistants, threads, moderations, reranking, unknown) are
    /// deliberately left on their surface label: they are not GenAI
    /// generation operations, the convention has no name for them, and
    /// relabelling them `chat` would be the exact misreporting this
    /// mapping removes.
    pub fn operation_name(&self) -> &'static str {
        match self {
            // Chat-shaped generation, whatever the inbound dialect:
            // OpenAI chat completions, Anthropic Messages, OpenAI
            // Responses, and the realtime session all produce chat
            // turns.
            AiSurface::ChatCompletions
            | AiSurface::Messages
            | AiSurface::Responses
            | AiSurface::Realtime => crate::tracing_spans::OP_CHAT,
            AiSurface::Embeddings => crate::tracing_spans::OP_EMBEDDINGS,
            AiSurface::ImageGeneration | AiSurface::ImageEdits | AiSurface::ImageVariations => {
                crate::tracing_spans::OP_IMAGE_GENERATION
            }
            AiSurface::AudioTranscription | AiSurface::AudioSpeech => {
                crate::tracing_spans::OP_AUDIO
            }
            // Not generation operations; see the doc comment.
            AiSurface::Models
            | AiSurface::Assistants
            | AiSurface::Threads
            | AiSurface::Batches
            | AiSurface::FineTuning
            | AiSurface::Files
            | AiSurface::Moderations
            | AiSurface::Reranking
            | AiSurface::Unknown => self.label(),
        }
    }

    /// Whether v1 shadow evaluation may replay this request surface.
    ///
    /// Only chat evaluation surfaces are safe to copy. Mutating and non-chat
    /// APIs must never enter the shadow transport.
    pub fn supports_shadow_eval(&self) -> bool {
        matches!(
            self,
            AiSurface::ChatCompletions | AiSurface::Messages | AiSurface::Responses
        )
    }

    /// Whether a route reasoning policy may transform this request surface.
    ///
    /// Only prompt-completion surfaces carry the canonical message body and
    /// completion semantics required by provider reasoning controls.
    pub fn supports_reasoning_policy(&self) -> bool {
        matches!(
            self,
            AiSurface::ChatCompletions | AiSurface::Messages | AiSurface::Responses
        )
    }

    /// Whether an upstream service tier can be requested on this surface.
    ///
    /// The three conversational JSON surfaces, which are the ones the
    /// vendors document a `service_tier` field on. A tier written into an
    /// embeddings or image body would be a field the endpoint never asked
    /// for, so the operator's tier is not applied there; a caller's is
    /// still stripped everywhere. See [`crate::service_tier`].
    pub fn supports_service_tier(&self) -> bool {
        matches!(
            self,
            AiSurface::ChatCompletions | AiSurface::Messages | AiSurface::Responses
        )
    }
}

// [`AiSurface::ALL`] and `AiSurface::position` are one list written
// twice, so they are checked against each other at compile time rather
// than in a test somebody has to remember to run (WOR-2647).
//
// The loop rejects a reorder, a duplicate index, and a variant dropped
// from the array. The discriminant check rejects a variant added
// anywhere above `Unknown` without the array growing to match:
// `Unknown` is the last variant, so its discriminant is one less than
// the variant count, and a fieldless enum casts to that discriminant.
// Adding a variant fails in `position` first, which is exhaustive.
const _: () = {
    let mut index = 0;
    while index < AiSurface::ALL.len() {
        assert!(
            AiSurface::position(&AiSurface::ALL[index]) == index,
            "AiSurface::ALL and AiSurface::position name different orders"
        );
        index += 1;
    }
    assert!(
        AiSurface::Unknown as usize == AiSurface::ALL.len() - 1,
        "an AiSurface variant is missing from AiSurface::ALL"
    );
};

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
    use crate::reasoning::ReasoningPolicy;

    #[test]
    fn a_validation_compile_does_not_install_the_candidate_price_table() {
        let _guard = crate::budget::PRICE_TABLE_TEST_LOCK.lock().unwrap();
        // Install a known table through the real load path.
        AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{"name": "p", "api_key": "k"}],
            "model_prices": {
                "validation-split-model": {"input_per_million": 3.0, "output_per_million": 6.0}
            }
        }))
        .expect("valid config");
        assert_eq!(
            crate::budget::catalog_price("validation-split-model").map(|p| p.input_per_million),
            Some(3.0)
        );

        // A validation-only compile carrying different prices must leave the
        // installed table untouched: neither overriding the known model nor
        // introducing its new one.
        AiHandlerConfig::from_config_for_validation(serde_json::json!({
            "providers": [{"name": "p", "api_key": "k"}],
            "model_prices": {
                "validation-split-model": {"input_per_million": 999.0, "output_per_million": 999.0},
                "validation-split-other": {"input_per_million": 1.0, "output_per_million": 1.0}
            }
        }))
        .expect("valid config");
        assert_eq!(
            crate::budget::catalog_price("validation-split-model").map(|p| p.input_per_million),
            Some(3.0),
            "a rejected candidate's prices must not reach live accounting"
        );
        assert!(
            crate::budget::catalog_price("validation-split-other").is_none(),
            "a validation compile must not install anything"
        );
    }

    // --- Resilience wiring (WOR-2233) ---
    //
    // The defect these pin is not that ejection was wrong, it is that
    // ejection never happened: `router()` built a bare `Router`, so
    // `breakers` was empty and `outlier` was `None` no matter what the
    // config said. Each test below asserts behaviour rather than
    // reading the router's fields, because the fields were only ever
    // wrong in the sense of being untouched, and a behavioural
    // assertion fails the same way while also covering the axis.

    fn resilience_config(resilience: serde_json::Value) -> AiHandlerConfig {
        AiHandlerConfig::from_config(serde_json::json!({
            "providers": [
                {"name": "openai", "api_key": "k"},
                {"name": "anthropic", "api_key": "k"},
            ],
            "resilience": resilience,
        }))
        .expect("config compiles")
    }

    #[test]
    fn a_circuit_breaker_block_produces_a_router_that_actually_ejects() {
        let config = resilience_config(serde_json::json!({
            "circuit_breaker": {
                "failure_threshold": 2,
                "success_threshold": 1,
                "open_duration_secs": 300,
            },
        }));
        let router = config.router();

        assert_eq!(
            router.eligible_indices(&config.providers),
            vec![0, 1],
            "nothing has failed yet"
        );
        router.record_provider_failure(0, "openai");
        router.record_provider_failure(0, "openai");
        assert_eq!(
            router.eligible_indices(&config.providers),
            vec![1],
            "the configured threshold was reached and the provider left the pool"
        );
    }

    #[test]
    fn an_outlier_detection_block_produces_a_router_that_actually_ejects() {
        let config = resilience_config(serde_json::json!({
            "outlier_detection": {
                "threshold": 0.5,
                "window_secs": 60,
                "min_requests": 2,
                "ejection_duration_secs": 300,
            },
        }));
        let router = config.router();

        router.record_provider_failure(1, "anthropic");
        assert_eq!(
            router.eligible_indices(&config.providers),
            vec![0, 1],
            "one sample is under min_requests"
        );
        router.record_provider_failure(1, "anthropic");
        assert_eq!(
            router.eligible_indices(&config.providers),
            vec![0],
            "the failure rate crossed the threshold and the provider was ejected"
        );
    }

    #[test]
    fn a_config_without_a_resilience_block_ejects_nothing() {
        let config = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [
                {"name": "openai", "api_key": "k"},
                {"name": "anthropic", "api_key": "k"},
            ],
        }))
        .expect("config compiles");
        let router = config.router();

        for _ in 0..50 {
            router.record_provider_failure(0, "openai");
        }
        assert_eq!(
            router.eligible_indices(&config.providers),
            vec![0, 1],
            "an operator who configured no resilience gets none, however badly a provider behaves"
        );
    }

    #[test]
    fn one_configured_block_does_not_arm_the_other_axis() {
        // Only outlier detection is configured, and its thresholds are
        // far looser than the circuit breaker's defaults. If the two
        // axes shared a constructor, five failures would open a breaker
        // nobody asked for and the provider would leave anyway.
        let config = resilience_config(serde_json::json!({
            "outlier_detection": {
                "threshold": 1.0,
                "window_secs": 60,
                "min_requests": 1000,
                "ejection_duration_secs": 300,
            },
        }));
        let router = config.router();

        for _ in 0..10 {
            router.record_provider_failure(0, "openai");
        }
        assert_eq!(
            router.eligible_indices(&config.providers),
            vec![0, 1],
            "no circuit_breaker block means no circuit breaker"
        );
    }

    #[test]
    fn an_outlier_threshold_of_zero_does_not_eject_a_provider_that_never_failed() {
        let config = resilience_config(serde_json::json!({
            "outlier_detection": {
                "threshold": 0.0,
                "min_requests": 0,
                "ejection_duration_secs": 300,
            },
        }));
        let router = config.router();

        for _ in 0..10 {
            router.record_provider_success(0, "openai");
            router.record_provider_success(1, "anthropic");
        }
        // A failure is needed to run the evaluation at all, and it has
        // to be on a provider we are not asserting about.
        router.record_provider_failure(1, "anthropic");
        assert!(
            router.eligible_indices(&config.providers).contains(&0),
            "a provider with ten successes and no failures must survive a zeroed threshold"
        );
    }

    #[test]
    fn token_rate_is_refused_instead_of_quietly_becoming_least_token_usage() {
        let error = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{"name": "openai", "api_key": "k"}],
            "routing": "token_rate",
        }))
        .expect_err("token_rate has no per-provider limit to score against");
        let message = error.to_string();
        assert!(
            message.contains("least_token_usage"),
            "the error has to name the strategy that preserves today's behaviour: {message}"
        );
    }

    #[test]
    fn context_overflow_block_is_refused_instead_of_being_silently_swallowed() {
        let error = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{"name": "openai", "api_key": "k"}],
            "context_overflow": {"action": "fallback_to_larger", "fallback_model": "gpt-4o"},
        }))
        .expect_err("a key no code reads must fail the config, not sit in it");
        let message = error.to_string();
        assert!(
            message.contains("context_overflow"),
            "the error has to name the key an operator wrote: {message}"
        );
        assert!(
            message.contains("window_fit") && message.contains("context_compress"),
            "the error has to name the surfaces that do fit a prompt to the window: {message}"
        );
    }

    #[test]
    fn an_ai_config_without_a_context_overflow_block_still_compiles() {
        AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{"name": "openai", "api_key": "k"}],
        }))
        .expect("the refusal must be scoped to an authored context_overflow block");
    }

    #[test]
    fn typed_fallback_lists_naming_an_unknown_provider_are_refused() {
        // WOR-2556: a typed fallback list is an allowlist of provider
        // names. A name matching nothing would leave the trigger
        // configured and the reroute silently unreachable, which is the
        // exact rot mode the original WOR-1524 mechanism died of.
        let error = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{"name": "small", "api_key": "k"}],
            "context_window_fallbacks": ["big"],
        }))
        .expect_err("a fallback list naming no configured provider must fail the config");
        let message = error.to_string();
        assert!(
            message.contains("context_window_fallbacks") && message.contains("big"),
            "the error has to name the key and the unknown provider: {message}"
        );

        let error = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{"name": "strict", "api_key": "k"}],
            "content_policy_fallbacks": ["permissive"],
        }))
        .expect_err("a fallback list naming no configured provider must fail the config");
        let message = error.to_string();
        assert!(
            message.contains("content_policy_fallbacks") && message.contains("permissive"),
            "the error has to name the key and the unknown provider: {message}"
        );
    }

    #[test]
    fn typed_fallback_keys_nested_under_routing_are_refused() {
        // WOR-2556: the `routing:` object form ignores keys a strategy
        // does not read, so a typed fallback list nested there would be
        // silently swallowed. Refuse it and point at the right level.
        let error = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [
                {"name": "small", "api_key": "k"},
                {"name": "big", "api_key": "k"},
            ],
            "routing": {"strategy": "fallback_chain", "context_window_fallbacks": ["big"]},
        }))
        .expect_err("a typed fallback list nested under routing: must fail the config");
        let message = error.to_string();
        assert!(
            message.contains("context_window_fallbacks"),
            "the error has to name the misplaced key: {message}"
        );
    }

    #[test]
    fn typed_fallback_keys_nested_under_resilience_are_refused() {
        // WOR-2556 review: `resilience.content_policy_fallback`
        // (singular) is a real key, so the plural list next to it is the
        // likelier misplacement of the two. `AiResilienceConfig` has no
        // `deny_unknown_fields`, so nothing else in the load path sees it.
        for key in ["context_window_fallbacks", "content_policy_fallbacks"] {
            let mut resilience = serde_json::Map::new();
            resilience.insert(
                "content_policy_fallback".to_string(),
                serde_json::Value::Bool(true),
            );
            resilience.insert(key.to_string(), serde_json::json!(["permissive"]));
            let error = AiHandlerConfig::from_config(serde_json::json!({
                "providers": [
                    {"name": "small", "api_key": "k"},
                    {"name": "permissive", "api_key": "k"},
                ],
                "resilience": resilience,
            }))
            .expect_err("a typed fallback list nested under resilience: must fail the config");
            let message = error.to_string();
            assert!(
                message.contains(key) && message.contains("resilience"),
                "the error has to name the misplaced key and its parent: {message}"
            );
        }
    }

    #[test]
    fn typed_fallback_lists_parse_when_names_match_providers() {
        let config = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [
                {"name": "small", "api_key": "k"},
                {"name": "big", "api_key": "k"},
                {"name": "permissive", "api_key": "k"},
            ],
            "routing": {"strategy": "fallback_chain"},
            "context_window_fallbacks": ["big"],
            "content_policy_fallbacks": ["permissive"],
        }))
        .expect("typed fallback lists naming configured providers parse");
        assert_eq!(config.context_window_fallbacks, vec!["big".to_string()]);
        assert_eq!(
            config.content_policy_fallbacks,
            vec!["permissive".to_string()]
        );
    }

    #[test]
    fn cooldown_policy_removes_a_provider_after_a_mapped_failure_class() {
        let config = resilience_config(serde_json::json!({
            "cooldown_policy": {"rate_limit": 60},
        }));
        let router = config.router();
        assert_eq!(
            router.eligible_indices(&config.providers),
            vec![0, 1],
            "no failures yet: everyone eligible"
        );
        router.note_classified_failure(0, "openai", crate::failure_cause::FailureCause::RateLimit);
        assert_eq!(
            router.eligible_indices(&config.providers),
            vec![1],
            "a rate-limited provider is held out for the configured cooldown"
        );
        // A class the policy does not map must not cool anything down.
        router.note_classified_failure(
            1,
            "anthropic",
            crate::failure_cause::FailureCause::ServerError,
        );
        assert_eq!(
            router.eligible_indices(&config.providers),
            vec![1],
            "an unmapped class never triggers a cooldown"
        );
    }

    #[test]
    fn a_cooldown_records_the_parked_provider_and_cause_on_its_counter() {
        // WOR-2556 review: parking a provider is the moment traffic
        // stops reaching it, and a `warn!` line was the only record. A
        // rotating log line cannot be graphed and nothing can alert on
        // it, so the seam that parks the provider writes the counter
        // too. Asserted through `config.router()` rather than against
        // the recorder directly: a covered recorder is not a wired one.
        //
        // The provider name is unique to this test on purpose. The
        // prometheus registry is process-global and other tests in this
        // binary park providers of their own.
        let config = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [
                {"name": "cooldown-counter-probe", "api_key": "k"},
                {"name": "anthropic", "api_key": "k"},
            ],
            "resilience": {"cooldown_policy": {"auth": 300}},
        }))
        .expect("config compiles");
        let router = config.router();
        router.note_classified_failure(
            0,
            "cooldown-counter-probe",
            crate::failure_cause::FailureCause::Auth,
        );

        let families = prometheus::gather();
        let family = families
            .iter()
            .find(|family| family.name() == "sbproxy_ai_provider_cooldowns_total")
            .expect("the cooldown seam has to register its counter");
        let has_label = |metric: &prometheus::proto::Metric, name: &str, value: &str| {
            metric
                .get_label()
                .iter()
                .any(|label| label.name() == name && label.value() == value)
        };
        assert!(
            family.get_metric().iter().any(|metric| {
                has_label(metric, "provider", "cooldown-counter-probe")
                    && has_label(metric, "cause", "auth")
                    && metric.get_counter().value() >= 1.0
            }),
            "the parked provider and the class that parked it both have to be on the series"
        );
    }

    #[test]
    fn without_a_cooldown_policy_classified_failures_change_nothing() {
        let config = resilience_config(serde_json::json!({}));
        let router = config.router();
        router.note_classified_failure(0, "openai", crate::failure_cause::FailureCause::RateLimit);
        assert_eq!(
            router.eligible_indices(&config.providers),
            vec![0, 1],
            "defaults preserve current behavior exactly"
        );
    }

    #[test]
    fn least_token_usage_is_still_accepted() {
        AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{"name": "openai", "api_key": "k"}],
            "routing": "least_token_usage",
        }))
        .expect("the strategy token_rate degenerates into stays available");
    }

    /// One valid `semantic_route` block, shared by the registration and
    /// refusal tests so each refusal test mutates exactly one thing.
    fn semantic_route_config(routing: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "providers": [
                {"name": "code-pool", "api_key": "k"},
                {"name": "chat-pool", "api_key": "k"},
                {"name": "embedder", "api_key": "k"}
            ],
            "routing": routing,
        })
    }

    #[test]
    fn semantic_route_registers_as_a_named_strategy() {
        let config = AiHandlerConfig::from_config(semantic_route_config(serde_json::json!({
            "strategy": "semantic_route",
            "min_similarity": 0.7,
            "fallback": "chat-pool",
            "routes": [
                {"deployment": "code-pool", "exemplars": ["Write a Rust function that parses JSON"]},
                {"deployment": "chat-pool", "exemplars": ["Chat about everyday topics"]}
            ],
            "embedding": {"provider": "embedder", "model": "text-embedding-3-small"}
        })))
        .expect("semantic_route with routes and an embedding source compiles");
        assert_eq!(config.router().strategy_name(), "semantic_route");
    }

    #[test]
    fn semantic_route_without_an_embedding_source_is_refused_at_config_compile() {
        let error = AiHandlerConfig::from_config(semantic_route_config(serde_json::json!({
            "strategy": "semantic_route",
            "routes": [
                {"deployment": "code-pool", "exemplars": ["Write a Rust function that parses JSON"]}
            ]
        })))
        .expect_err("no embedding source must fail config compile, not surprise at runtime");
        let message = error.to_string();
        assert!(
            message.contains("semantic_route") && message.contains("embedding"),
            "the error has to name the strategy and the missing embedding block: {message}"
        );
    }

    #[test]
    fn semantic_route_naming_an_unknown_deployment_is_refused() {
        let error = AiHandlerConfig::from_config(semantic_route_config(serde_json::json!({
            "strategy": "semantic_route",
            "routes": [
                {"deployment": "no-such-pool", "exemplars": ["Write a Rust function"]}
            ],
            "embedding": {"provider": "embedder", "model": "text-embedding-3-small"}
        })))
        .expect_err("a route naming an unconfigured provider must be refused like a cascade tier");
        let message = error.to_string();
        assert!(
            message.contains("no-such-pool"),
            "the error has to name the offending deployment: {message}"
        );
    }

    #[test]
    fn semantic_route_naming_an_unknown_fallback_is_refused() {
        let error = AiHandlerConfig::from_config(semantic_route_config(serde_json::json!({
            "strategy": "semantic_route",
            "fallback": "no-such-pool",
            "routes": [
                {"deployment": "code-pool", "exemplars": ["Write a Rust function"]}
            ],
            "embedding": {"provider": "embedder", "model": "text-embedding-3-small"}
        })))
        .expect_err("a fallback naming an unconfigured provider must be refused");
        let message = error.to_string();
        assert!(
            message.contains("no-such-pool"),
            "the error has to name the offending fallback: {message}"
        );
    }

    #[test]
    fn semantic_route_embedding_provider_must_be_configured() {
        let error = AiHandlerConfig::from_config(semantic_route_config(serde_json::json!({
            "strategy": "semantic_route",
            "routes": [
                {"deployment": "code-pool", "exemplars": ["Write a Rust function"]}
            ],
            "embedding": {"provider": "no-such-embedder", "model": "text-embedding-3-small"}
        })))
        .expect_err("an embedding provider outside `providers` must be refused");
        let message = error.to_string();
        assert!(
            message.contains("no-such-embedder"),
            "the error has to name the offending embedding provider: {message}"
        );
    }

    #[tokio::test]
    async fn exemplars_embed_once_across_the_router_lookups_a_request_makes() {
        // WOR-2564's cost claim lives at this seam, not inside `decide`.
        // The dispatcher reaches the strategy through
        // `AiHandlerConfig::router()` on every request, so if that handed
        // back a freshly cloned config the exemplar cache would be cold
        // every time and the "config-time cost, not a per-request one"
        // promise would be false while `decide`'s own cache test stayed
        // green. Two lookups, two decisions, one exemplar build.
        let config = AiHandlerConfig::from_config(semantic_route_config(serde_json::json!({
            "strategy": "semantic_route",
            "min_similarity": 0.5,
            "routes": [
                {"deployment": "code-pool", "exemplars": ["one", "two"]},
                {"deployment": "chat-pool", "exemplars": ["three"]}
            ],
            "embedding": {"provider": "embedder", "model": "text-embedding-3-small"}
        })))
        .expect("semantic_route compiles");
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let embed = |_text: String| {
            calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            async { Ok(vec![1.0_f32, 0.0]) }
        };

        let first_lookup = config.router();
        let semantic = first_lookup
            .semantic_route_config()
            .expect("the compiled strategy is semantic_route");
        crate::routing::semantic_route::decide(semantic, "a request", &embed).await;
        // Three exemplars plus this request's own prompt.
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 4);
        drop(first_lookup);

        let second_lookup = config.router();
        let semantic = second_lookup
            .semantic_route_config()
            .expect("the compiled strategy is semantic_route");
        crate::routing::semantic_route::decide(semantic, "another request", &embed).await;
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::Relaxed),
            5,
            "a second request must cost one prompt embed, not a whole exemplar rebuild"
        );
    }

    #[test]
    fn the_shipped_semantic_routing_example_compiles_at_this_layer() {
        // compile_config leaves the ai_proxy action opaque, so the
        // sbproxy-config example sweep cannot prove the routing block.
        // This layer owns it; parse the published example directly.
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let example = manifest
            .parent()
            .and_then(std::path::Path::parent)
            .expect("crates/sbproxy-ai sits two levels under the workspace root")
            .join("examples/semantic-routing/sb.yml");
        let text = std::fs::read_to_string(&example)
            .unwrap_or_else(|error| panic!("read {}: {error}", example.display()));
        let parsed: serde_yaml::Value = serde_yaml::from_str(&text).expect("example parses");
        let action = parsed
            .get("origins")
            .and_then(|origins| origins.get("ai.local"))
            .and_then(|origin| origin.get("action"))
            .expect("example declares the ai.local action");
        let action_json = serde_json::to_value(action).expect("action converts to JSON");
        let config = AiHandlerConfig::from_config(action_json)
            .expect("the published semantic-routing example must compile");
        assert_eq!(config.router().strategy_name(), "semantic_route");
    }

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
    fn value_sink_initialization_keeps_the_winning_facade_on_path_conflict() {
        let dir = tempfile::tempdir().expect("tempdir");
        let winning_path = dir.path().join("winning.redb");
        let conflicting_path = dir.path().join("conflicting.redb");
        let ledger =
            std::sync::Arc::new(crate::value_ledger::ValueLedger::open("").expect("memory ledger"));
        ledger
            .promote_to_redb(&winning_path)
            .expect("winning promotion");

        let selected = value_ledger_for_sink(ledger.clone(), &conflicting_path);
        assert!(std::sync::Arc::ptr_eq(&ledger, &selected));
        selected.record_compression(
            "handler-fallback",
            crate::compression::LeverKind::WindowFit,
            23,
            0,
            sbproxy_model_host::TokenCountPrecision::Heuristic,
        );
        drop(selected);
        drop(ledger);

        let report = crate::value_ledger::ValueLedger::open(&winning_path)
            .expect("reopen winning ledger")
            .report();
        assert_eq!(report.total_compression_tokens_saved, 23);
        assert!(!conflicting_path.exists());
    }

    #[test]
    fn model_allowed_no_lists() {
        let config = AiHandlerConfig {
            providers: Vec::new(),
            routing: RoutingStrategy::RoundRobin,
            cache_affinity: None,
            data_posture: None,
            context_window_fallbacks: Vec::new(),
            content_policy_fallbacks: Vec::new(),
            allowed_models: Vec::new(),
            blocked_models: Vec::new(),
            max_body_size: None,
            guardrails: None,
            budget: None,
            virtual_keys: vec![],
            require_governed_key: false,
            model_rate_limits: HashMap::new(),
            per_surface_rate_limits: HashMap::new(),
            max_concurrent: None,
            resilience: None,
            compression: None,
            reasoning: ReasoningPolicy::Off,
            shadow: None,
            pii: None,
            trace_content: false,
            capture_content: false,
            semantic_cache: None,
            prompts: None,
            usage_parser: "auto".to_string(),
            pii_redactor: OnceLock::new(),
            router: OnceLock::new(),
            usage_sinks: vec![],
            usage_sinks_built: OnceLock::new(),
            ai_policy: None,
            ai_routing_policy: None,
            model_prices: std::collections::HashMap::new(),
            rate_card: None,
            max_price_per_request: None,
            allow_request_timeout_override: false,
            max_request_timeout_ms: None,
            quota_pool: None,
            rag: None,
            guardrails_pipeline: OnceLock::new(),
            ai_policy_compiled: OnceLock::new(),
            ai_routing_policy_compiled: OnceLock::new(),
            ai_catalog_cel: OnceLock::new(),
            quota_pool_store: OnceLock::new(),
            model_aliases: Vec::new(),
            model_alias_index: OnceLock::new(),
            model_groups: Vec::new(),
            model_group_index: OnceLock::new(),
        };
        assert!(config.is_model_allowed("gpt-4"));
        assert!(config.is_model_allowed("anything"));
    }

    #[test]
    fn model_blocked() {
        let config = AiHandlerConfig {
            providers: Vec::new(),
            routing: RoutingStrategy::RoundRobin,
            cache_affinity: None,
            data_posture: None,
            context_window_fallbacks: Vec::new(),
            content_policy_fallbacks: Vec::new(),
            allowed_models: Vec::new(),
            blocked_models: vec!["gpt-4".into()],
            max_body_size: None,
            guardrails: None,
            budget: None,
            virtual_keys: vec![],
            require_governed_key: false,
            model_rate_limits: HashMap::new(),
            per_surface_rate_limits: HashMap::new(),
            max_concurrent: None,
            resilience: None,
            compression: None,
            reasoning: ReasoningPolicy::Off,
            shadow: None,
            pii: None,
            trace_content: false,
            capture_content: false,
            semantic_cache: None,
            prompts: None,
            usage_parser: "auto".to_string(),
            pii_redactor: OnceLock::new(),
            router: OnceLock::new(),
            usage_sinks: vec![],
            usage_sinks_built: OnceLock::new(),
            ai_policy: None,
            ai_routing_policy: None,
            model_prices: std::collections::HashMap::new(),
            rate_card: None,
            max_price_per_request: None,
            allow_request_timeout_override: false,
            max_request_timeout_ms: None,
            quota_pool: None,
            rag: None,
            guardrails_pipeline: OnceLock::new(),
            ai_policy_compiled: OnceLock::new(),
            ai_routing_policy_compiled: OnceLock::new(),
            ai_catalog_cel: OnceLock::new(),
            quota_pool_store: OnceLock::new(),
            model_aliases: Vec::new(),
            model_alias_index: OnceLock::new(),
            model_groups: Vec::new(),
            model_group_index: OnceLock::new(),
        };
        assert!(!config.is_model_allowed("gpt-4"));
        assert!(config.is_model_allowed("gpt-3.5-turbo"));
    }

    #[test]
    fn model_allowed_list() {
        let config = AiHandlerConfig {
            providers: Vec::new(),
            routing: RoutingStrategy::RoundRobin,
            cache_affinity: None,
            data_posture: None,
            context_window_fallbacks: Vec::new(),
            content_policy_fallbacks: Vec::new(),
            allowed_models: vec!["gpt-4".into(), "gpt-3.5-turbo".into()],
            blocked_models: Vec::new(),
            max_body_size: None,
            guardrails: None,
            budget: None,
            virtual_keys: vec![],
            require_governed_key: false,
            model_rate_limits: HashMap::new(),
            per_surface_rate_limits: HashMap::new(),
            max_concurrent: None,
            resilience: None,
            compression: None,
            reasoning: ReasoningPolicy::Off,
            shadow: None,
            pii: None,
            trace_content: false,
            capture_content: false,
            semantic_cache: None,
            prompts: None,
            usage_parser: "auto".to_string(),
            pii_redactor: OnceLock::new(),
            router: OnceLock::new(),
            usage_sinks: vec![],
            usage_sinks_built: OnceLock::new(),
            ai_policy: None,
            ai_routing_policy: None,
            model_prices: std::collections::HashMap::new(),
            rate_card: None,
            max_price_per_request: None,
            allow_request_timeout_override: false,
            max_request_timeout_ms: None,
            quota_pool: None,
            rag: None,
            guardrails_pipeline: OnceLock::new(),
            ai_policy_compiled: OnceLock::new(),
            ai_routing_policy_compiled: OnceLock::new(),
            ai_catalog_cel: OnceLock::new(),
            quota_pool_store: OnceLock::new(),
            model_aliases: Vec::new(),
            model_alias_index: OnceLock::new(),
            model_groups: Vec::new(),
            model_group_index: OnceLock::new(),
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
            cache_affinity: None,
            data_posture: None,
            context_window_fallbacks: Vec::new(),
            content_policy_fallbacks: Vec::new(),
            allowed_models: vec!["gpt-4".into()],
            blocked_models: vec!["gpt-4".into()],
            max_body_size: None,
            guardrails: None,
            budget: None,
            virtual_keys: vec![],
            require_governed_key: false,
            model_rate_limits: HashMap::new(),
            per_surface_rate_limits: HashMap::new(),
            max_concurrent: None,
            resilience: None,
            compression: None,
            reasoning: ReasoningPolicy::Off,
            shadow: None,
            pii: None,
            trace_content: false,
            capture_content: false,
            semantic_cache: None,
            prompts: None,
            usage_parser: "auto".to_string(),
            pii_redactor: OnceLock::new(),
            router: OnceLock::new(),
            usage_sinks: vec![],
            usage_sinks_built: OnceLock::new(),
            ai_policy: None,
            ai_routing_policy: None,
            model_prices: std::collections::HashMap::new(),
            rate_card: None,
            max_price_per_request: None,
            allow_request_timeout_override: false,
            max_request_timeout_ms: None,
            quota_pool: None,
            rag: None,
            guardrails_pipeline: OnceLock::new(),
            ai_policy_compiled: OnceLock::new(),
            ai_routing_policy_compiled: OnceLock::new(),
            ai_catalog_cel: OnceLock::new(),
            quota_pool_store: OnceLock::new(),
            model_aliases: Vec::new(),
            model_alias_index: OnceLock::new(),
            model_groups: Vec::new(),
            model_group_index: OnceLock::new(),
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

    // WOR-2312: the alias plane is resolved at config load. A config that
    // carries aliases publishes a warm registry, and one whose alias would
    // shadow a real model never publishes at all.
    #[test]
    fn config_load_builds_the_model_alias_registry() {
        let json = serde_json::json!({
            "providers": [
                {"name": "openai", "api_key": "sk-test", "models": ["gpt-4o-mini"]},
                {"name": "anthropic", "api_key": "sk-ant", "models": ["claude-sonnet-4-5"]}
            ],
            "model_aliases": [
                {"alias": "fast", "provider": "openai", "model_id": "gpt-4o-mini"},
                {"alias": "smart", "provider": "anthropic", "model_id": "claude-sonnet-4-5"}
            ]
        });
        let config = AiHandlerConfig::from_config(json).expect("aliases load");

        let registry = config.model_alias_registry();
        assert!(!registry.is_empty());
        let fast = registry.resolve("fast").expect("fast is an alias");
        assert_eq!(fast.model_id, "gpt-4o-mini");
        assert_eq!(
            fast.provider.as_ref().map(crate::ids::ProviderName::as_str),
            Some("openai")
        );
        assert!(registry.resolve("gpt-4o-mini").is_none());
    }

    #[test]
    fn config_load_rejects_an_alias_that_shadows_a_served_model() {
        let json = serde_json::json!({
            "providers": [
                {"name": "openai", "api_key": "sk-test", "models": ["gpt-4o", "gpt-4o-mini"]}
            ],
            "model_aliases": [
                {"alias": "gpt-4o", "provider": "openai", "model_id": "gpt-4o-mini"}
            ]
        });
        let error = AiHandlerConfig::from_config(json)
            .expect_err("a shadowing alias is rejected at config load")
            .to_string();
        assert!(error.contains("ai model_aliases"), "{error}");
        assert!(error.contains("shadows a model provider"), "{error}");
    }

    // WOR-1683: a served provider's empty models: list derives from the
    // serve-entry names; an explicit list is left alone.
    #[test]
    fn served_provider_models_derive_from_serve_entry_names() {
        let json = serde_json::json!({
            "providers": [{
                "name": "local",
                "serve": {
                    "models": [
                        {"model": "qwen3-14b"},
                        {"model": "hf:Qwen/Qwen3-8B-GGUF:Q4_K_M", "name": "local-coder"}
                    ]
                }
            }]
        });
        let config = AiHandlerConfig::from_config(json).unwrap();
        assert_eq!(config.providers[0].models, vec!["qwen3-14b", "local-coder"]);

        let explicit = serde_json::json!({
            "providers": [{
                "name": "local",
                "models": ["qwen3-14b"],
                "serve": {
                    "models": [
                        {"model": "qwen3-14b"},
                        {"model": "hf:Qwen/Qwen3-8B-GGUF:Q4_K_M", "name": "local-coder"}
                    ]
                }
            }]
        });
        let config = AiHandlerConfig::from_config(explicit).unwrap();
        assert_eq!(
            config.providers[0].models,
            vec!["qwen3-14b"],
            "an explicit subset must win over derivation"
        );
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
        assert!(!config.require_governed_key);
        assert!(config.quota_pool.is_none());
        assert_eq!(config.reasoning, ReasoningPolicy::Off);
    }

    #[test]
    fn reasoning_policy_accepts_closed_config_shapes() {
        for (value, expected) in [
            (serde_json::json!("off"), ReasoningPolicy::Off),
            (serde_json::json!("concise"), ReasoningPolicy::Concise),
            (
                serde_json::json!({"budget": 2048}),
                ReasoningPolicy::Budget(2048),
            ),
        ] {
            let config = AiHandlerConfig::from_config(serde_json::json!({
                "providers": [{"name": "openai"}],
                "reasoning": value,
            }))
            .expect("valid reasoning policy");
            assert_eq!(config.reasoning, expected);
        }
    }

    #[test]
    fn reasoning_policy_rejects_zero_budget() {
        let error = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{"name": "openai"}],
            "reasoning": {"budget": 0},
        }))
        .expect_err("zero reasoning budget must fail validation")
        .to_string();

        assert!(
            error.contains("reasoning budget must be greater than zero"),
            "{error}"
        );
    }

    fn shadow_config(block: serde_json::Value) -> anyhow::Result<AiHandlerConfig> {
        AiHandlerConfig::from_config(serde_json::json!({
            "providers": [
                {"name": "primary", "api_key": "k"},
                {"name": "anthropic", "api_key": "k"},
                {"name": "gemini", "api_key": "k"},
            ],
            "shadow": block,
        }))
    }

    #[test]
    fn flat_shadow_config_still_parses_as_one_target() {
        // The compat promise. The flat form is five sibling keys, not a
        // renamed field, so nothing in serde keeps it working for free.
        let config = shadow_config(serde_json::json!({
            "provider": "anthropic",
            "model": "claude-sonnet-4",
            "sample_rate": 0.25,
            "timeout_ms": 1234,
            "task_timeout_ms": 4321,
        }))
        .expect("the single-target form is still accepted");
        let targets = &config.shadow.expect("shadow block").targets;
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].provider, "anthropic");
        assert_eq!(targets[0].model.as_deref(), Some("claude-sonnet-4"));
        assert!((targets[0].sample_rate - 0.25).abs() < f32::EPSILON);
        assert_eq!(targets[0].timeout_ms, 1234);
        assert_eq!(targets[0].task_timeout_ms, 4321);
    }

    #[test]
    fn a_shadow_targets_list_parses_and_keeps_its_order() {
        let config = shadow_config(serde_json::json!({
            "targets": [
                {"provider": "anthropic", "sample_rate": 0.1},
                {"provider": "gemini"},
            ],
        }))
        .expect("the targets form parses");
        let targets = &config.shadow.expect("shadow block").targets;
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].provider, "anthropic");
        assert_eq!(targets[1].provider, "gemini");
        assert!(
            (targets[1].sample_rate - 1.0).abs() < f32::EPSILON,
            "an omitted rate still defaults to mirroring every request"
        );
    }

    #[test]
    fn empty_shadow_targets_is_refused() {
        // An empty list is not "shadow disabled": it is a block the
        // operator wrote expecting evaluation, that silently produces
        // none. Removing the block is how you disable it.
        let error = shadow_config(serde_json::json!({"targets": []}))
            .expect_err("an empty target list must refuse the config")
            .to_string();
        assert!(error.contains("at least one provider"), "{error}");
    }

    #[test]
    fn duplicate_shadow_target_provider_is_refused() {
        // The provider name is the metric label and the ledger row's
        // target identity. Two entries sharing it merge two evaluations
        // into one series with no way to tell them apart.
        let error = shadow_config(serde_json::json!({
            "targets": [
                {"provider": "anthropic", "sample_rate": 0.1},
                {"provider": "anthropic", "model": "claude-opus-4"},
            ],
        }))
        .expect_err("two targets on one provider must refuse the config")
        .to_string();
        assert!(error.contains("anthropic"), "{error}");
        assert!(error.contains("targets[1]"), "{error}");
    }

    #[test]
    fn an_unknown_shadow_target_key_is_refused() {
        let error = shadow_config(serde_json::json!({
            "targets": [{"provider": "anthropic", "sample_rare": 0.1}],
        }))
        .expect_err("a typo'd key must not be silently dropped")
        .to_string();
        assert!(error.contains("sample_rare"), "{error}");
    }

    #[test]
    fn from_config_refuses_bedrock_guardrail_on_a_non_bedrock_provider() {
        // Drives the whole action body through `from_config_inner`
        // rather than calling `validate_bedrock_guardrail` directly. A
        // validator with no caller is a guard that reports green while
        // enforcing nothing, and that is the failure this asserts
        // against, not the validator's own logic (which
        // `provider::tests` covers).
        let error = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{
                "name": "openai",
                "api_key": "sk-test",
                "bedrock_guardrail": {"identifier": "gr-1", "version": "DRAFT"},
            }],
        }))
        .expect_err("an inline Bedrock guardrail on an OpenAI provider must refuse the config")
        .to_string();
        assert!(error.contains("bedrock guardrail"), "{error}");
        assert!(error.contains("openai"), "{error}");
    }

    #[test]
    fn from_config_accepts_bedrock_guardrail_on_a_bedrock_provider() {
        let config = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{
                "name": "bedrock",
                "aws_sigv4": {"region": "us-east-1"},
                "bedrock_guardrail": {
                    "identifier": "gr-abc123",
                    "version": "DRAFT",
                    "trace": true,
                },
            }],
        }))
        .expect("a Bedrock provider accepts the inline guardrail");
        let guardrail = config.providers[0]
            .bedrock_guardrail
            .as_deref()
            .expect("the block survives deserialization");
        assert_eq!(guardrail.identifier, "gr-abc123");
        assert!(guardrail.trace);
    }

    /// Collect `warn!` output produced while `body` runs.
    ///
    /// `fmt` with a shared buffer rather than a custom `Layer`: the
    /// assertion is on the message text an operator reads, not on a
    /// field set.
    fn captured_warnings(body: impl FnOnce()) -> String {
        use std::sync::{Arc, Mutex};

        #[derive(Clone, Default)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);

        impl std::io::Write for Buffer {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0
                    .lock()
                    .expect("log capture buffer")
                    .extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buffer {
            type Writer = Buffer;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let buffer = Buffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buffer.clone())
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, body);
        let bytes = buffer.0.lock().expect("log capture buffer").clone();
        String::from_utf8(bytes).expect("captured log output is UTF-8")
    }

    #[test]
    fn both_bedrock_guardrail_controls_on_one_origin_warn_once_and_still_load() {
        // Two AWS evaluations per request, both billed. Refusing would
        // break a deployment that deliberately screens the prompt out
        // of band and the completion inline, so this warns instead; the
        // test exists because an untested warning is one a refactor
        // drops silently.
        let action = serde_json::json!({
            "providers": [{
                "name": "bedrock",
                "aws_sigv4": {"region": "us-east-1"},
                "bedrock_guardrail": {"identifier": "gr-abc123", "version": "DRAFT"},
            }],
            "guardrails": {
                "external": [{
                    "name": "aws",
                    "provider": "bedrock",
                    "mode": "pre_call",
                    "api_key": "aws-test-key",
                    "url": "https://bedrock-runtime.us-east-1.amazonaws.com",
                    "guardrail_id": "gr-abc123",
                    "guardrail_version": "DRAFT",
                }],
            },
        });
        let logs = captured_warnings(|| {
            AiHandlerConfig::from_config(action)
                .expect("both controls on one origin is legal, not refused");
        });
        assert_eq!(
            logs.matches("bills the guardrail twice").count(),
            1,
            "expected exactly one double-billing warning, got: {logs}"
        );
        assert!(
            logs.contains("providers=bedrock"),
            "the warning names which provider entries carry the inline \
             control, or an operator with ten entries cannot act on it: {logs}"
        );

        // The inline control alone is the ordinary deployment and must
        // stay quiet, or the warning trains operators to ignore it.
        let inline_only = serde_json::json!({
            "providers": [{
                "name": "bedrock",
                "aws_sigv4": {"region": "us-east-1"},
                "bedrock_guardrail": {"identifier": "gr-abc123", "version": "DRAFT"},
            }],
        });
        let logs = captured_warnings(|| {
            AiHandlerConfig::from_config(inline_only).expect("inline alone loads");
        });
        assert!(
            !logs.contains("bills the guardrail twice"),
            "one control is not a double bill: {logs}"
        );
    }

    #[test]
    fn an_unknown_bedrock_guardrail_key_is_refused() {
        // `deny_unknown_fields`: the block is new and small, so a
        // typo'd key must not be silently dropped into a guardrail the
        // operator believes is configured.
        let error = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{
                "name": "bedrock",
                "aws_sigv4": {"region": "us-east-1"},
                "bedrock_guardrail": {
                    "identifier": "gr-abc123",
                    "version": "DRAFT",
                    "guardrail_version": "1",
                },
            }],
        }))
        .expect_err("an unknown key inside the guardrail block must refuse the config")
        .to_string();
        assert!(error.contains("guardrail_version"), "{error}");
    }

    #[test]
    fn from_config_rejects_a_price_ceiling_at_or_below_zero() {
        // A ceiling of zero or below admits nothing, so it turns the
        // origin into a 402 for every chat request. The header form
        // already refuses a non-positive value; a typo in the config must
        // not be the quieter of the two.
        for bad in [0.0, -0.05] {
            let json = serde_json::json!({
                "providers": [{"name": "openai", "api_key": "sk-test"}],
                "max_price_per_request": bad,
            });
            let error = AiHandlerConfig::from_config(json)
                .expect_err("a non-positive ceiling must refuse the config")
                .to_string();
            assert!(error.contains("max_price_per_request"), "{error}");
        }
    }

    #[test]
    fn from_config_accepts_a_positive_price_ceiling() {
        let config = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "max_price_per_request": 0.05,
        }))
        .expect("a positive ceiling is a valid config");
        assert_eq!(config.max_price_per_request, Some(0.05));
    }

    /// The seam is the validator's caller: `from_config_inner` has to
    /// reach the key, not just own it.
    #[test]
    fn a_zero_pre_header_timeout_is_refused_at_load() {
        let error = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "resilience": {"pre_header_timeout_ms": 0},
        }))
        .expect_err("a zero pre-header budget must refuse the config")
        .to_string();
        assert!(error.contains("pre_header_timeout_ms"), "{error}");
    }

    #[test]
    fn a_positive_pre_header_timeout_is_accepted() {
        let config = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "resilience": {"pre_header_timeout_ms": 750},
        }))
        .expect("a positive pre-header budget is a valid config");
        assert_eq!(
            config
                .resilience
                .as_ref()
                .and_then(|resilience| resilience.pre_header_timeout_ms),
            Some(750)
        );
    }

    /// The seam is the misplacement loop. `AiHandlerConfig` sets no
    /// `deny_unknown_fields`, so before this an action-level
    /// `pre_header_timeout_ms` was swallowed: `sbproxy validate` exited
    /// 0 and every streaming request kept waiting out the client
    /// default with no failover and nothing in the logs.
    #[test]
    fn a_pre_header_timeout_at_the_action_level_is_refused() {
        let error = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "pre_header_timeout_ms": 750,
        }))
        .expect_err("the key is not read at the action level")
        .to_string();
        assert!(
            error.contains("resilience.pre_header_timeout_ms"),
            "{error}"
        );
    }

    /// The flag without a ceiling hands every caller an unbounded
    /// per-attempt budget, which is the failure the gate exists to
    /// prevent, so it is refused at load rather than defaulted.
    #[test]
    fn the_override_flag_without_a_ceiling_is_refused_at_load() {
        let error = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "allow_request_timeout_override": true,
        }))
        .expect_err("the flag alone must refuse the config")
        .to_string();
        assert!(error.contains("allow_request_timeout_override"), "{error}");
        assert!(error.contains("max_request_timeout_ms"), "{error}");
    }

    #[test]
    fn a_zero_request_timeout_ceiling_is_refused_at_load() {
        let error = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "allow_request_timeout_override": true,
            "max_request_timeout_ms": 0,
        }))
        .expect_err("a zero ceiling must refuse the config")
        .to_string();
        assert!(error.contains("max_request_timeout_ms"), "{error}");
    }

    #[test]
    fn the_override_flag_with_a_ceiling_loads() {
        let config = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "allow_request_timeout_override": true,
            "max_request_timeout_ms": 5000,
        }))
        .expect("the flag plus a ceiling is a valid config");
        assert!(config.allow_request_timeout_override);
        assert_eq!(config.max_request_timeout_ms, Some(5000));
    }

    #[test]
    fn from_config_rejects_an_ai_policy_that_does_not_compile() {
        // WOR-2422: a policy typo used to log-and-disable, booting a
        // proxy that advertised a policy it silently did not run.
        let json = serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "ai_policy": {"expression": "ai.surface ==   "},
        });
        let error = AiHandlerConfig::from_config(json)
            .expect_err("a syntax error must refuse the config")
            .to_string();
        assert!(error.contains("ai_policy"), "{error}");
    }

    #[test]
    fn from_config_rejects_an_ai_policy_naming_a_binding_the_surface_lacks() {
        // The evaluator sets exactly one variable, `ai`; a reference
        // to the request vocabulary is a typo caught at load like on
        // every other CEL surface, not a runtime fault eaten by
        // `on_error`.
        let json = serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "ai_policy": {"expression": "request.method == \"GET\""},
        });
        let error = AiHandlerConfig::from_config(json)
            .expect_err("an unknown binding must refuse the config")
            .to_string();
        assert!(error.contains("ai_policy"), "{error}");
    }

    #[test]
    fn from_config_accepts_a_valid_ai_policy() {
        let json = serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "ai_policy": {"expression": "ai.guardrails.flagged_count > 1 ? 'block' : 'allow'"},
        });
        AiHandlerConfig::from_config(json).expect("a valid ai.* policy must load");
    }

    #[test]
    fn from_config_rejects_an_ai_routing_policy_that_does_not_compile() {
        // WOR-2366: same eager-validate discipline as ai_policy. A syntax
        // error, an unknown binding, or a bad on_error refuses at load.
        let syntax = serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "ai_routing_policy": {"expression": "ai.surface ==   "},
        });
        let error = AiHandlerConfig::from_config(syntax)
            .expect_err("a syntax error must refuse the config")
            .to_string();
        assert!(error.contains("ai_routing_policy"), "{error}");

        let binding = serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "ai_routing_policy": {"expression": "request.method == \"GET\""},
        });
        assert!(AiHandlerConfig::from_config(binding).is_err());

        let posture = serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "ai_routing_policy": {"expression": "null", "on_error": "explode"},
        });
        assert!(AiHandlerConfig::from_config(posture).is_err());
    }

    #[test]
    fn from_config_accepts_a_valid_ai_routing_policy() {
        let json = serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "ai_routing_policy": {
                "expression": "ai.tier == 'free' ? {'candidates': [{'provider_id': 'openai', 'model': 'gpt-4o-mini'}], 'reason': 'free tier'} : null",
                "reason_codes": ["free tier"],
            },
        });
        let config = AiHandlerConfig::from_config(json).expect("a valid routing policy must load");
        assert!(config.ai_routing_policy().is_some());
    }

    #[test]
    fn from_config_refuses_a_wasm_routing_policy_without_a_bundle_program() {
        // WOR-2366: plain `from_config` carries no resolved bundle
        // program, and only the action-compile layer can see the bundle
        // registry that would supply one. An `engine: wasm` hook must
        // therefore refuse the config at load rather than boot green with
        // the policy silently absent. The positive path (a real prepared
        // program threaded through `from_config_with_wasm_routing`) is
        // covered where a bundle fixture exists, not here.
        let json = serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "ai_routing_policy": {"engine": "wasm", "type": "x"},
        });
        let error = AiHandlerConfig::from_config(json)
            .expect_err("a wasm routing hook with no resolved program must refuse the config")
            .to_string();
        assert!(error.contains("extension bundle"), "{error}");
    }

    #[test]
    fn from_config_rejects_invalid_guardrail_placement_before_serving() {
        let json = serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "guardrails": {
                "input": [{
                    "type": "regex",
                    "patterns": ["secret"],
                    "action": "block"
                }],
                "output": [{
                    "type": "classifier",
                    "backend": {
                        "kind": "embedding",
                        "model_path": "/unused/model.onnx",
                        "tokenizer_path": "/unused/tokenizer.json"
                    },
                    "classes": {
                        "documentation": ["write the readme"]
                    }
                }]
            }
        });

        let error = AiHandlerConfig::from_config(json)
            .expect_err("an input-only classifier under output must fail config compilation")
            .to_string();
        assert!(
            error.contains("classifier") && error.contains("input-only"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn from_config_rejects_malformed_classifier_before_serving() {
        let json = serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "guardrails": {
                "input": [
                    {
                        "type": "regex",
                        "patterns": ["secret"],
                        "action": "block"
                    },
                    {
                        "type": "classifier",
                        "backend": {
                            "kind": "embedding",
                            "model_path": "/unused/model.onnx",
                            "tokenizer_path": "/unused/tokenizer.json"
                        },
                        "classes": {}
                    }
                ]
            }
        });

        let error = AiHandlerConfig::from_config(json)
            .expect_err("a malformed classifier must fail config compilation")
            .to_string();
        assert!(
            error.contains("classifier") && error.contains("classes"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn from_config_rejects_unknown_classifier_fields_before_serving() {
        let json = serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "guardrails": {
                "input": [{
                    "type": "classifier",
                    "backend": {
                        "kind": "embedding",
                        "model_path": "/unused/model.onnx",
                        "tokenizer_path": "/unused/tokenizer.json",
                        "min_socre": 0.30
                    },
                    "classes": {
                        "documentation": ["write the readme"]
                    }
                }]
            }
        });

        let error = AiHandlerConfig::from_config(json)
            .expect_err("unknown classifier fields must fail config compilation")
            .to_string();
        assert!(
            error.contains("unknown field") && error.contains("min_socre"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn from_config_rejects_overlong_classifier_examples_before_serving() {
        let json = serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "guardrails": {
                "input": [{
                    "type": "classifier",
                    "backend": {
                        "kind": "embedding",
                        "model_path": "/unused/model.onnx",
                        "tokenizer_path": "/unused/tokenizer.json"
                    },
                    "classes": {
                        "documentation": ["five!"]
                    },
                    "max_chars": 4
                }]
            }
        });

        let error = AiHandlerConfig::from_config(json)
            .expect_err("overlong examples must fail config compilation")
            .to_string();
        assert!(
            error.contains("documentation") && error.contains("max_chars"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn from_config_validates_classifier_without_loading_artifacts() {
        let json = serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "guardrails": {
                "input": [{
                    "type": "classifier",
                    "backend": {
                        "kind": "embedding",
                        "model_path": "/not-loaded-during-validation/model.onnx",
                        "tokenizer_path": "/not-loaded-during-validation/tokenizer.json"
                    },
                    "classes": {
                        "documentation": ["write the readme"]
                    }
                }]
            }
        });

        AiHandlerConfig::from_config(json)
            .expect("config compilation validates structure without opening model artifacts");
    }

    #[test]
    fn guardrail_pipeline_lifetime_tracks_reload_managed_handler_config() {
        fn config(pattern: &str) -> AiHandlerConfig {
            AiHandlerConfig::from_config(serde_json::json!({
                "providers": [{"name": "openai", "api_key": "sk-test"}],
                "guardrails": {
                    "input": [{
                        "type": "regex",
                        "patterns": [pattern],
                        "action": "block"
                    }]
                }
            }))
            .expect("valid handler config")
        }

        let old_config = config("old-secret");
        let old_pipeline = old_config
            .guardrail_pipeline()
            .expect("old pipeline compiles")
            .expect("old pipeline configured");
        let old_pipeline_again = old_config
            .guardrail_pipeline()
            .expect("cached old pipeline")
            .expect("old pipeline configured");
        assert!(
            std::sync::Arc::ptr_eq(&old_pipeline, &old_pipeline_again),
            "one handler config should compile its pipeline only once"
        );
        assert!(old_pipeline.check_input_text("old-secret").is_some());
        drop(old_pipeline_again);
        assert_eq!(
            std::sync::Arc::strong_count(&old_pipeline),
            2,
            "the handler config and in-flight request should be the only owners"
        );

        let new_config = config("new-secret");
        let new_pipeline = new_config
            .guardrail_pipeline()
            .expect("replacement pipeline compiles")
            .expect("replacement pipeline configured");
        assert!(new_pipeline.check_input_text("old-secret").is_none());
        assert!(new_pipeline.check_input_text("new-secret").is_some());

        drop(old_config);
        assert_eq!(
            std::sync::Arc::strong_count(&old_pipeline),
            1,
            "publishing a replacement config must release the old compiled pipeline"
        );
    }

    #[test]
    fn guardrail_pipeline_runtime_compilation_error_remains_fail_closed() {
        // Production publication goes through `from_config` and rejects this
        // first. Deserializing directly exercises the request path's final
        // defense against a future validation/compiler mismatch.
        let config: AiHandlerConfig = serde_json::from_value(serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "guardrails": {
                "input": [{
                    "type": "regex",
                    "patterns": ["("],
                    "action": "block"
                }]
            }
        }))
        .expect("raw handler shape");

        let first = config
            .guardrail_pipeline()
            .expect_err("invalid guardrail compilation must be an error")
            .to_string();
        let second = config
            .guardrail_pipeline()
            .expect_err("cached invalid guardrail compilation must remain an error")
            .to_string();
        assert!(first.contains("invalid regex pattern"), "{first}");
        assert_eq!(first, second);
    }

    #[test]
    fn from_config_accepts_strong_quota_pool_for_runtime_backend_binding() {
        let json = serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "quota_pool": {
                "name": "shared",
                "total_limit": 100,
                "weights": {"virtual-key-a": 1},
                "policy": "hard",
                "consistency": "strong"
            }
        });
        let config = AiHandlerConfig::from_config(json)
            .expect("backend-independent config validation accepts strong consistency");
        assert_eq!(
            config.quota_pool.as_ref().expect("quota pool").consistency,
            crate::quota_pool::QuotaPoolConsistency::Strong
        );
    }

    fn handler_with_quota_consistency(consistency: &str) -> AiHandlerConfig {
        AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "quota_pool": {
                "name": "shared",
                "total_limit": 10,
                "weights": {"virtual-key-a": 1},
                "policy": "burst",
                "consistency": consistency
            }
        }))
        .expect("valid handler quota config")
    }

    #[tokio::test]
    async fn local_quota_pool_builds_without_a_governance_backend() {
        let config = handler_with_quota_consistency("local");
        let store = config
            .quota_pool_store(None)
            .expect("local store builds")
            .expect("quota configured");

        let reservation = store
            .reserve("shared", "virtual-key-a", 1, "local-request:0")
            .await
            .expect("local pool admits configured member");
        store
            .reconcile(reservation, crate::quota_pool::PoolUsage { units: 1 })
            .await
            .expect("local reservation settles");
    }

    #[tokio::test]
    async fn approximate_quota_pool_requires_a_matching_governance_backend() {
        let missing = handler_with_quota_consistency("approximate");
        assert!(matches!(
            missing.quota_pool_store(None),
            Err(crate::quota_pool::PoolError::InvalidState)
        ));

        let mismatched = handler_with_quota_consistency("approximate");
        let governance: std::sync::Arc<dyn crate::governance::GovernanceStore> =
            std::sync::Arc::new(
                crate::governance::InMemoryGovernanceStore::new(Default::default())
                    .expect("memory governance"),
            );
        assert!(matches!(
            mismatched.quota_pool_store(Some((
                governance,
                crate::governance::GovernanceConsistency::Strict,
            ))),
            Err(crate::quota_pool::PoolError::InvalidState)
        ));

        let matching = handler_with_quota_consistency("approximate");
        let governance: std::sync::Arc<dyn crate::governance::GovernanceStore> =
            std::sync::Arc::new(
                crate::governance::InMemoryGovernanceStore::new(Default::default())
                    .expect("memory governance"),
            );
        let store = matching
            .quota_pool_store(Some((
                governance,
                crate::governance::GovernanceConsistency::Approximate,
            )))
            .expect("matching approximate backend")
            .expect("quota configured");
        assert!(store
            .reserve("shared", "virtual-key-a", 1, "approximate-request:0")
            .await
            .is_ok());
    }

    #[test]
    fn strong_quota_pool_treats_a_missing_or_mismatched_backend_as_invalid_state() {
        let missing = handler_with_quota_consistency("strong");
        assert!(matches!(
            missing.quota_pool_store(None),
            Err(crate::quota_pool::PoolError::InvalidState)
        ));

        let mismatched = handler_with_quota_consistency("strong");
        let governance: std::sync::Arc<dyn crate::governance::GovernanceStore> =
            std::sync::Arc::new(
                crate::governance::InMemoryGovernanceStore::new(Default::default())
                    .expect("memory governance"),
            );
        assert!(matches!(
            mismatched.quota_pool_store(Some((
                governance,
                crate::governance::GovernanceConsistency::Approximate,
            ))),
            Err(crate::quota_pool::PoolError::InvalidState)
        ));
    }

    #[test]
    fn prefix_affinity_object_parses_and_rejects_zero_bounds() {
        let config = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "routing": {
                "strategy": "prefix_affinity",
                "ttl_secs": 45,
                "max_prefixes_per_provider": 64
            }
        }))
        .expect("bounded prefix config");
        let RoutingStrategy::PrefixAffinity(prefix) = config.routing else {
            panic!("expected prefix affinity");
        };
        assert_eq!(prefix.ttl_secs, 45);
        assert_eq!(prefix.max_prefixes_per_provider, 64);

        let invalid = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "routing": {
                "strategy": "prefix_affinity",
                "ttl_secs": 0
            }
        }));
        assert!(invalid.is_err(), "zero TTL must fail config loading");
    }

    /// WOR-2651: `cache_affinity` composes with every strategy, so it is a
    /// sibling of `routing:`. Authored inside it, the block would otherwise
    /// refuse with "unknown variant", which names the wrong problem.
    #[test]
    fn cache_affinity_is_a_sibling_of_routing_not_a_field_inside_it() {
        let config = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "routing": "round_robin",
            "cache_affinity": {"ttl_secs": 60, "max_keys_per_provider": 32}
        }))
        .expect("cache affinity beside routing");
        let affinity = config.cache_affinity.expect("cache affinity parsed");
        assert_eq!(affinity.ttl_secs, 60);
        assert_eq!(affinity.max_keys_per_provider, 32);
        assert!(config.router().cache_affinity_enabled());

        let misplaced = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{"name": "openai", "api_key": "sk-test"}],
            "routing": {"strategy": "round_robin", "cache_affinity": {}}
        }))
        .expect_err("cache_affinity under routing is refused");
        assert!(
            misplaced.to_string().contains("not a routing field"),
            "{misplaced}"
        );
    }

    /// WOR-2652: the load-time half. The unit tests in
    /// `crate::service_tier` cover the check itself; this one proves it is
    /// wired into config compilation, which is the part a covered-but-
    /// unwired function would pass without.
    #[test]
    fn a_provider_tier_the_vendor_does_not_sell_is_refused_at_config_load() {
        let error = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{
                "name": "claude",
                "provider_type": "anthropic",
                "api_key": "sk-test",
                "service_tier": "flex"
            }]
        }))
        .expect_err("anthropic declares no service-tier vocabulary");
        assert!(error.to_string().contains("service tier"), "{error}");

        AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{
                "name": "openai-flex",
                "provider_type": "openai",
                "api_key": "sk-test",
                "service_tier": "flex"
            }]
        }))
        .expect("openai sells a flex tier");
    }

    #[test]
    fn governed_key_requirement_is_scoped_to_one_ai_origin() {
        let required = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{"name": "openai"}],
            "require_governed_key": true
        }))
        .expect("origin requiring governed keys");
        let compatible = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{"name": "openai"}]
        }))
        .expect("origin using the compatibility default");

        assert!(required.require_governed_key);
        assert!(!compatible.require_governed_key);
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
    fn from_config_rejects_a_posture_that_excludes_every_provider() {
        // WOR-2557: an origin whose own `data_posture:` block leaves no
        // eligible provider is a blackhole, not a strict policy. It is
        // refused at compile with the key named, rather than booting
        // green and refusing every request it is ever sent.
        let err = AiHandlerConfig::from_config(serde_json::json!({
            "data_posture": {"require_zdr": true},
            "providers": [
                {"name": "mistral", "api_key": "k"},
                {"name": "groq", "api_key": "k"}
            ]
        }))
        .unwrap_err()
        .to_string();
        assert!(err.contains("`data_posture`"), "error names the key: {err}");
        assert!(
            err.contains("require_zdr") && err.contains("mistral") && err.contains("groq"),
            "error names the constraint and the excluded providers: {err}"
        );
    }

    #[test]
    fn from_config_accepts_a_posture_one_provider_satisfies() {
        // The same block compiles once one entry declares the posture the
        // deployment actually holds. Compiled in validation mode so this
        // test does not install a price table into the process-global
        // that `a_validation_compile_does_not_install_the_candidate_price_table`
        // is asserting on; the posture check runs on both paths.
        AiHandlerConfig::from_config_for_validation(serde_json::json!({
            "data_posture": {"require_zdr": true},
            "providers": [
                {"name": "mistral", "api_key": "k"},
                {"name": "openai", "api_key": "k", "data_posture": {"zdr": true}}
            ]
        }))
        .expect("a posture with one eligible provider compiles");
    }

    #[test]
    fn from_config_rejects_duplicate_provider_destination_names() {
        let err = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [
                {"name": "primary", "base_url": "https://one.example/v1"},
                {"name": "primary", "base_url": "https://two.example/v1"}
            ]
        }))
        .unwrap_err()
        .to_string();
        assert!(err.contains("configured more than once"), "{err}");
    }

    #[test]
    fn from_config_validates_native_credential_destination_binding() {
        let err = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{
                "name": "primary",
                "provider_type": "openai",
                "base_url": "https://8.8.8.8/v1",
                "accept_native_credentials_for": "anthropic"
            }]
        }))
        .unwrap_err()
        .to_string();
        assert!(err.contains("native credential binding"), "{err}");

        assert!(AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{
                "name": "primary",
                "provider_type": "openai",
                "base_url": "https://8.8.8.8/v1",
                "accept_native_credentials_for": "openai"
            }]
        }))
        .is_ok());
    }

    #[test]
    fn from_config_rejects_serve_with_base_url() {
        // WOR-1680: a served provider is hosted locally and must not
        // also carry a base_url; `plan` rejects it with a clear message.
        let json = serde_json::json!({
            "providers": [{
                "name": "local",
                "base_url": "http://127.0.0.1:9000/v1",
                "allow_private_base_url": true,
                "serve": {"models": [{"model": "qwen3-14b"}]}
            }]
        });
        let err = AiHandlerConfig::from_config(json).unwrap_err().to_string();
        assert!(
            err.contains("serve") && err.contains("base_url"),
            "error explains the conflict: {err}"
        );
    }

    #[test]
    fn from_config_accepts_serve_only_provider() {
        // The quickstart shape: a provider whose body is just serve:,
        // with no address anywhere.
        let json = serde_json::json!({
            "providers": [{
                "name": "local",
                "serve": {"models": [{"model": "qwen3-14b"}]}
            }]
        });
        assert!(AiHandlerConfig::from_config(json).is_ok());
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

    // --- Peak EWMA routing deserialization ---

    #[test]
    fn peak_ewma_flat_form_uses_default_half_life() {
        let config = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{"name": "openai", "api_key": "x"}],
            "routing": "peak_ewma"
        }))
        .expect("flat peak_ewma parses");

        let RoutingStrategy::PeakEwma(config) = config.routing else {
            panic!("expected peak_ewma");
        };
        assert_eq!(config.half_life_secs, 10);
    }

    #[test]
    fn peak_ewma_object_form_parses_half_life() {
        let config = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{"name": "openai", "api_key": "x"}],
            "routing": {"strategy": "peak_ewma", "half_life": "30s"}
        }))
        .expect("configured peak_ewma parses");

        let RoutingStrategy::PeakEwma(config) = config.routing else {
            panic!("expected peak_ewma");
        };
        assert_eq!(config.half_life_secs, 30);
    }

    #[test]
    fn peak_ewma_rejects_zero_half_life() {
        let error = AiHandlerConfig::from_config(serde_json::json!({
            "providers": [{"name": "openai", "api_key": "x"}],
            "routing": {"strategy": "peak_ewma", "half_life": 0}
        }))
        .expect_err("zero half-life must fail");

        assert!(error.to_string().contains("half_life"));
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
    fn from_config_rejects_a_cascade_tier_naming_an_unconfigured_provider() {
        // WOR-2366: a cascade tier naming a provider that is not
        // configured is silently skipped at runtime, so the operator's
        // tier never runs. Refuse it at load instead. Red before the
        // backfill: nothing validated tier providers against `providers`.
        let cfg_json = serde_json::json!({
            "providers": [{"name": "cheap", "api_key": "x"}],
            "routing": {
                "strategy": "cascade",
                "tiers": [
                    {"provider_id": "cheap", "model": "gpt-4o-mini", "quality_threshold": 0.7},
                    {"provider_id": "ghost", "model": "gpt-4o", "quality_threshold": 0.9}
                ]
            }
        });
        let err = AiHandlerConfig::from_config(cfg_json)
            .unwrap_err()
            .to_string();
        assert!(err.contains("ghost"), "error names the bad provider: {err}");
        assert!(
            err.contains("tier 1"),
            "error names the offending tier index: {err}"
        );
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
                "redact_request": false
            }
        });
        let config = AiHandlerConfig::from_config(cfg_json).unwrap();
        let mut body = serde_json::json!({"prompt": "alice@example.com"});
        let redacted = config.apply_request_pii(&mut body);
        assert!(!redacted);
        assert_eq!(body["prompt"].as_str(), Some("alice@example.com"));
    }

    #[test]
    fn redact_response_true_is_refused_at_load() {
        let cfg_json = serde_json::json!({
            "providers": [{"name": "openai"}],
            "pii": {
                "enabled": true,
                "redact_response": true
            }
        });
        let err = AiHandlerConfig::from_config(cfg_json).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("redact_response"),
            "error should name the refused key: {message}"
        );
        assert!(
            message.contains("no code path applies PII"),
            "error should explain why, not just reject the value: {message}"
        );
    }

    #[test]
    fn redact_response_default_false_still_loads() {
        let cfg_json = serde_json::json!({
            "providers": [{"name": "openai"}],
            "pii": { "enabled": true }
        });
        AiHandlerConfig::from_config(cfg_json).unwrap();
    }

    #[test]
    fn redact_response_explicit_false_still_loads() {
        let cfg_json = serde_json::json!({
            "providers": [{"name": "openai"}],
            "pii": {
                "enabled": true,
                "redact_response": false
            }
        });
        AiHandlerConfig::from_config(cfg_json).unwrap();
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
        // The hyphenated spelling stays Unknown, which is the right
        // answer: it is not a path OpenAI serves.
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

    #[test]
    fn reasoning_policy_is_limited_to_prompt_completion_surfaces() {
        let all_surfaces = [
            AiSurface::ChatCompletions,
            AiSurface::Models,
            AiSurface::Embeddings,
            AiSurface::Assistants,
            AiSurface::Threads,
            AiSurface::Batches,
            AiSurface::FineTuning,
            AiSurface::Files,
            AiSurface::Realtime,
            AiSurface::ImageGeneration,
            AiSurface::ImageEdits,
            AiSurface::ImageVariations,
            AiSurface::AudioTranscription,
            AiSurface::AudioSpeech,
            AiSurface::Moderations,
            AiSurface::Reranking,
            AiSurface::Messages,
            AiSurface::Responses,
            AiSurface::Unknown,
        ];

        for surface in all_surfaces {
            let expected = matches!(
                surface,
                AiSurface::ChatCompletions | AiSurface::Messages | AiSurface::Responses
            );
            assert_eq!(
                surface.supports_reasoning_policy(),
                expected,
                "{} eligibility",
                surface.label()
            );
        }
    }

    #[test]
    fn multipart_acceptance_is_an_allowlist_of_multipart_surfaces() {
        assert!(AiSurface::ImageEdits.accepts_multipart());
        assert!(AiSurface::ImageVariations.accepts_multipart());
        assert!(AiSurface::AudioTranscription.accepts_multipart());
        assert!(AiSurface::Files.accepts_multipart());
        assert!(AiSurface::Unknown.accepts_multipart());
        assert!(!AiSurface::ChatCompletions.accepts_multipart());
        assert!(!AiSurface::Embeddings.accepts_multipart());
        assert!(!AiSurface::ImageGeneration.accepts_multipart());
        assert!(!AiSurface::Messages.accepts_multipart());
        assert!(!AiSurface::Responses.accepts_multipart());
    }
}

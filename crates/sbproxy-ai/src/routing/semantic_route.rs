//! Semantic (embedding-similarity) routing: the `semantic_route` strategy
//! (WOR-2564).
//!
//! The operator declares per-deployment specialties as exemplar prompts
//! (reference texts) or precomputed embedding centroids. The dispatcher
//! embeds the request's final user message once per request, cosine-matches
//! it against the declared exemplar vectors, and pins the routing set to
//! the best-scoring deployment when that score clears `min_similarity`.
//! This routes on what the request *means*, unlike `prefix_affinity`,
//! which routes on byte-stable prefixes to optimize KV-cache reuse.
//!
//! Exemplar texts embed once per process on first use and the vectors
//! are cached in [`SemanticRouteState`], so the steady-state cost is one
//! embedding call per request. Declared centroids never embed.
//!
//! That first-use build is the one place this strategy can amplify, so
//! it is bounded on three axes. It is single-flighted, so a cold start
//! that takes 100 concurrent requests pays one build rather than 100.
//! A failed build is negatively cached behind a doubling retry floor,
//! so a permanently unbuildable index (a typo in `embedding.model`, a
//! centroid whose dimensions disagree with the embedder's real output)
//! costs one build attempt per backoff window instead of one per
//! request, forever. And the total exemplar count is capped at
//! [`MAX_TOTAL_EXEMPLARS`], which
//! [`SemanticRouteConfig::validate`] refuses past and the build
//! enforces again, so the cold-start cost of the strategy is a number
//! an operator can read off the config.
//!
//! Fail posture: this strategy can only ever narrow a selection, never
//! fail or hang one. A below-floor score, a request without a user
//! message, an unavailable embedder, a build already in flight, and a
//! build inside its retry floor all produce a fallback outcome that the
//! dispatcher resolves to the declared `fallback` deployment when one
//! is eligible, and to the round-robin arm in
//! [`select_from_candidates`](crate::routing::Router) otherwise. The
//! embedding call itself is bounded by the embedding source's own
//! timeout, the same bound the semantic cache's lookup path relies on.
//!
//! Embedding traffic this strategy generates is metered against the
//! origin's `quota_pool` when one is configured and the source is one
//! the pool represents: the dispatcher reserves an attempt per embedding
//! call through `source: provider` or `source: openai`, and
//! [`embed_route_text`] settles it at the send seam, exactly as the
//! semantic cache's lookup embedding does. A `source: sidecar` embed
//! reserves nothing, because a local classifier process is not a pooled
//! provider call: taking a unit for it would let a full pool deny
//! traffic the pool never sees and push the origin onto its fallback
//! deployment for as long as the pool stays full.
//! [`SemanticRouteConfig::embed_meters_quota_pool`] is the one answer
//! both sides read. A pool denial folds into the same fallback outcome
//! as an embedder outage, so the shared limit is honored without the
//! routing decision ever failing a request.
//!
//! Requiring an embedding source is a config-compile refusal, not a
//! runtime surprise, matching the posture `token_rate`'s refusal set:
//! [`SemanticRouteConfig::validate`] runs from the handler's routing
//! deserializer, and the handler's `from_config` additionally proves
//! every named deployment, the `fallback`, and the `embedding.provider`
//! against the configured provider set the way cascade tiers are proved.

use std::future::Future;
use std::sync::Arc;

use serde::Deserialize;

use crate::provider::ProviderConfig;
use crate::semantic_cache::{
    EmbeddingProviderConfig, EmbeddingSource, OpenAiEmbeddingConfig, SidecarEmbeddingConfig,
    MAX_EMBEDDING_DIMENSIONS,
};

/// Hard cap on the number of declared routes.
pub const MAX_SEMANTIC_ROUTES: usize = 64;
/// Hard cap on the exemplar texts declared for one route.
pub const MAX_EXEMPLARS_PER_ROUTE: usize = 64;
/// Hard cap on one exemplar text in bytes.
pub const MAX_EXEMPLAR_BYTES: usize = 4096;
/// Hard cap on the exemplar texts declared across every route.
///
/// The per-route cap alone permits 64 routes of 64 exemplars, and every
/// one of those 4096 texts is a billed embedding call on the first
/// request that builds the index. This is the aggregate budget for that
/// build.
pub const MAX_TOTAL_EXEMPLARS: usize = 256;
/// Default similarity floor a match must clear to pin the deployment.
pub const DEFAULT_MIN_SIMILARITY: f32 = 0.75;

/// Shortest wait before a failed exemplar-index build is attempted again.
const EXEMPLAR_BUILD_RETRY_FLOOR: std::time::Duration = std::time::Duration::from_secs(30);
/// Longest the retry floor grows to under consecutive failed builds.
const EXEMPLAR_BUILD_RETRY_CEILING: std::time::Duration = std::time::Duration::from_secs(300);
/// How many times the floor may double before the ceiling applies.
const EXEMPLAR_BUILD_BACKOFF_DOUBLINGS: u32 = 4;

/// Error returned when a `semantic_route` routing block fails validation
/// at config load.
///
/// The message names the offending field and its safe bound. It never
/// carries exemplar text, a URL, or a credential.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SemanticRouteConfigError(String);

fn invalid(field: &str, message: impl std::fmt::Display) -> SemanticRouteConfigError {
    SemanticRouteConfigError(format!("semantic_route {field}: {message}"))
}

/// One declared specialty: a deployment plus the exemplars that describe
/// the traffic it should win.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticRouteRule {
    /// Provider name this specialty routes to. Must name an entry in the
    /// handler's `providers`; the handler's config compile proves it.
    pub deployment: String,
    /// Reference texts describing this deployment's specialty. Each embeds
    /// once per process on first use; the request's best cosine score over
    /// all of a rule's vectors is the rule's score.
    #[serde(default)]
    pub exemplars: Vec<String>,
    /// Optional precomputed embedding centroid for this specialty, in the
    /// same embedding space `source` produces. Scored alongside the
    /// exemplar vectors; never embeds.
    #[serde(default)]
    pub centroid: Option<Vec<f32>>,
}

impl std::fmt::Debug for SemanticRouteRule {
    /// Report the deployment and exemplar count. Exemplar text is
    /// operator-authored prose that has no business in logs.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SemanticRouteRule")
            .field("deployment", &self.deployment)
            .field("exemplars", &self.exemplars.len())
            .field("centroid", &self.centroid.as_ref().map(Vec::len))
            .finish()
    }
}

/// Operator config for the `semantic_route` strategy, parsed from the
/// `routing:` object alongside its `strategy` discriminator.
///
/// Unknown keys are rejected, so a misspelled `min_similarity` fails the
/// load instead of silently routing on the default floor.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticRouteConfig {
    /// Declared specialties, best cosine score wins. At least one.
    pub routes: Vec<SemanticRouteRule>,
    /// Similarity floor (`0.0..=1.0`) the best score must clear to pin a
    /// deployment. Defaults to [`DEFAULT_MIN_SIMILARITY`].
    #[serde(default = "default_min_similarity")]
    pub min_similarity: f32,
    /// Declared default deployment for every fallback outcome (below
    /// floor, no user message, embedder unavailable). Optional: with no
    /// fallback, the eligible order stands and round-robin picks.
    #[serde(default)]
    pub fallback: Option<String>,
    /// Where request and exemplar embeddings come from. Defaults to
    /// `provider`, the same default the semantic cache uses.
    #[serde(default)]
    pub source: EmbeddingSource,
    /// Embedding provider and model (for `source: provider`). Required by
    /// [`Self::validate`] when `source` is `provider`.
    #[serde(default)]
    pub embedding: Option<EmbeddingProviderConfig>,
    /// Local classifier-sidecar embedding endpoint (for `source: sidecar`).
    #[serde(default)]
    pub sidecar: Option<SidecarEmbeddingConfig>,
    /// Standalone OpenAI-compatible endpoint (for `source: openai`).
    #[serde(default)]
    pub openai: Option<OpenAiEmbeddingConfig>,
    /// Process-local exemplar-vector cache, shared across clones of this
    /// config (the handler clones the strategy into its router).
    #[serde(skip)]
    state: Arc<SemanticRouteState>,
}

impl std::fmt::Debug for SemanticRouteConfig {
    /// Report tuning only. Rules redact their exemplar text and the
    /// endpoint blocks carry their own redacted implementations.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SemanticRouteConfig")
            .field("routes", &self.routes)
            .field("min_similarity", &self.min_similarity)
            .field("fallback", &self.fallback)
            .field("source", &self.source)
            .field("embedding", &self.embedding)
            .field("sidecar", &self.sidecar)
            .field("openai", &self.openai)
            .finish()
    }
}

fn default_min_similarity() -> f32 {
    DEFAULT_MIN_SIMILARITY
}

/// Process-local exemplar-vector cache and the gate that bounds its
/// build.
///
/// Built on first use from the declared exemplars and centroids, then
/// reused for the life of the config. Two things guard that build. The
/// `build` mutex single-flights it, so concurrent cold-start requests
/// cannot each fire the whole exemplar set at the embedder. The
/// `failure` slot negatively caches a failed build with a doubling retry
/// floor, so an index that can never build (a mistyped embedding model,
/// a centroid whose dimensions disagree with the embedder) degrades to
/// one attempt per backoff window rather than one per request.
///
/// The retry floor is why a *transient* embedder blip now costs the
/// origin its matches for up to the current floor (30 seconds at the
/// first strike, doubling to a 5 minute cap) rather than for one
/// request. That is the deliberate trade: the alternative
/// posture turned a permanent failure into an unbounded per-request
/// embedding amplifier, and every request inside the floor still routes,
/// on the declared `fallback`.
pub struct SemanticRouteState {
    index: parking_lot::Mutex<Option<Arc<ExemplarIndex>>>,
    /// Single-flight gate. Async because a build awaits embedding calls;
    /// held only by the one request doing the building.
    build: tokio::sync::Mutex<()>,
    /// Negative cache for a failed build, cleared by the first success.
    failure: parking_lot::Mutex<Option<BuildFailure>>,
}

impl Default for SemanticRouteState {
    fn default() -> Self {
        Self {
            index: parking_lot::Mutex::new(None),
            build: tokio::sync::Mutex::new(()),
            failure: parking_lot::Mutex::new(None),
        }
    }
}

/// One failed exemplar build: when it failed, and how many consecutive
/// failures have accumulated behind it.
struct BuildFailure {
    at: std::time::Instant,
    strikes: u32,
}

impl SemanticRouteState {
    /// The built index, when one is cached.
    fn cached(&self) -> Option<Arc<ExemplarIndex>> {
        self.index.lock().clone()
    }

    /// Publish a built index and clear any negative-cache entry.
    fn store(&self, index: Arc<ExemplarIndex>) {
        *self.index.lock() = Some(index);
        *self.failure.lock() = None;
    }

    /// Record one failed build, returning its strike count and the retry
    /// floor that strike earned.
    fn note_build_failure(&self, now: std::time::Instant) -> (u32, std::time::Duration) {
        let mut failure = self.failure.lock();
        let strikes = failure
            .as_ref()
            .map_or(1, |prior| prior.strikes.saturating_add(1));
        *failure = Some(BuildFailure { at: now, strikes });
        (strikes, retry_backoff(strikes))
    }

    /// How much of the current retry floor is left at `now`, or `None`
    /// when a rebuild is due (including when nothing has failed).
    fn build_backoff_remaining(&self, now: std::time::Instant) -> Option<std::time::Duration> {
        let failure = self.failure.lock();
        let failure = failure.as_ref()?;
        let elapsed = now.saturating_duration_since(failure.at);
        retry_backoff(failure.strikes)
            .checked_sub(elapsed)
            .filter(|left| !left.is_zero())
    }
}

/// The retry floor a build failure earns: [`EXEMPLAR_BUILD_RETRY_FLOOR`]
/// doubling once per consecutive strike, capped at
/// [`EXEMPLAR_BUILD_RETRY_CEILING`].
fn retry_backoff(strikes: u32) -> std::time::Duration {
    let doublings = strikes
        .saturating_sub(1)
        .min(EXEMPLAR_BUILD_BACKOFF_DOUBLINGS);
    EXEMPLAR_BUILD_RETRY_FLOOR
        .saturating_mul(1u32 << doublings)
        .min(EXEMPLAR_BUILD_RETRY_CEILING)
}

/// One scored vector: which rule it belongs to and which exemplar ordinal
/// produced it (`None` for the rule's declared centroid).
struct ExemplarEntry {
    route_index: usize,
    exemplar: Option<usize>,
    vector: Vec<f32>,
}

/// The normalized exemplar vectors for one config, all sharing one
/// dimension count.
pub struct ExemplarIndex {
    entries: Vec<ExemplarEntry>,
    dimensions: usize,
}

/// What the strategy decided for one request. The dispatcher applies it:
/// `Matched` pins the deployment; everything else is a fallback outcome
/// counted on `sbproxy_ai_semantic_route_decisions_total{outcome}` and
/// `sbproxy_ai_routing_fallbacks_total{strategy="semantic_route"}`.
#[derive(Debug, Clone, PartialEq)]
pub enum SemanticRouteOutcome {
    /// The best score cleared the floor: route to this deployment.
    Matched {
        /// The winning rule's deployment (provider name).
        deployment: String,
        /// Ordinal of the winning exemplar within its rule, `None` when
        /// the rule's declared centroid won.
        exemplar: Option<usize>,
        /// Winning cosine similarity in `[-1.0, 1.0]`.
        score: f32,
    },
    /// Every score stayed below the floor: a normal outcome, not an
    /// error. The dispatcher routes to the declared `fallback`.
    BelowFloor {
        /// The deployment that came closest, for the operator's floor
        /// tuning.
        best_deployment: String,
        /// Its cosine similarity.
        best_score: f32,
    },
    /// The request carries no unambiguous user message to embed.
    NoPrompt,
    /// The embedder failed or returned vectors this config cannot score
    /// (wrong dimensions, non-finite, zero-length). Fail-open.
    EmbedderUnavailable,
}

impl SemanticRouteConfig {
    /// Whether one embedding call through this config's source spends
    /// against the origin's `quota_pool` (WOR-2564).
    ///
    /// `provider` and `openai` both POST to an upstream the pool
    /// represents, so each of their calls owes one reservation.
    /// `sidecar` is a local classifier process the pool does not
    /// represent, and `inprocess` never calls out at all (and
    /// [`Self::validate`] refuses it besides).
    ///
    /// The dispatcher reads this to decide whether to mint a
    /// reservation and [`embed_route_text`] is documented against the
    /// same answer, so the two sides cannot disagree about who owns the
    /// guard.
    #[must_use]
    pub const fn embed_meters_quota_pool(&self) -> bool {
        matches!(
            self.source,
            EmbeddingSource::Provider | EmbeddingSource::Openai
        )
    }

    /// Validate every bound and the embedding-source contract before the
    /// handler accepts the strategy.
    ///
    /// Unlike the semantic cache, whose enabled-but-sourceless block
    /// deliberately stays inert for importer compatibility, a routing
    /// strategy that cannot embed cannot do the one thing it was selected
    /// for, so a missing source block is a refusal here (WOR-2564), the
    /// `token_rate` posture.
    ///
    /// Errors name only the offending field and its safe bound.
    pub fn validate(&self) -> Result<(), SemanticRouteConfigError> {
        if self.routes.is_empty() {
            return Err(invalid("routes", "must declare at least one route"));
        }
        if self.routes.len() > MAX_SEMANTIC_ROUTES {
            return Err(invalid(
                "routes",
                format!("must declare at most {MAX_SEMANTIC_ROUTES} routes"),
            ));
        }
        for (index, rule) in self.routes.iter().enumerate() {
            let field = |name: &str| format!("routes[{index}].{name}");
            if rule.deployment.trim().is_empty() {
                return Err(invalid(&field("deployment"), "must not be empty"));
            }
            if rule.exemplars.len() > MAX_EXEMPLARS_PER_ROUTE {
                return Err(invalid(
                    &field("exemplars"),
                    format!("must declare at most {MAX_EXEMPLARS_PER_ROUTE} exemplars"),
                ));
            }
            for (exemplar_index, exemplar) in rule.exemplars.iter().enumerate() {
                if exemplar.trim().is_empty() {
                    return Err(invalid(
                        &field(&format!("exemplars[{exemplar_index}]")),
                        "must not be empty",
                    ));
                }
                if exemplar.len() > MAX_EXEMPLAR_BYTES {
                    return Err(invalid(
                        &field(&format!("exemplars[{exemplar_index}]")),
                        format!("must be at most {MAX_EXEMPLAR_BYTES} bytes"),
                    ));
                }
            }
            if let Some(centroid) = rule.centroid.as_ref() {
                if centroid.is_empty() || centroid.len() > MAX_EMBEDDING_DIMENSIONS {
                    return Err(invalid(
                        &field("centroid"),
                        format!("must carry 1 through {MAX_EMBEDDING_DIMENSIONS} dimensions"),
                    ));
                }
                if centroid.iter().any(|value| !value.is_finite()) {
                    return Err(invalid(&field("centroid"), "must be finite"));
                }
                if l2_normalize(centroid.clone()).is_none() {
                    return Err(invalid(&field("centroid"), "must have a nonzero norm"));
                }
            }
            if rule.exemplars.is_empty() && rule.centroid.is_none() {
                return Err(invalid(
                    &field("exemplars"),
                    "must declare at least one exemplar text or a centroid",
                ));
            }
        }
        // The per-route cap is not an aggregate budget: 64 routes of 64
        // exemplars is 4096 billed embedding calls on the request that
        // happens to build the index. Refuse at load, where the operator
        // can see the number, rather than at 03:00 on a cold start.
        let declared_exemplars: usize = self.routes.iter().map(|rule| rule.exemplars.len()).sum();
        if declared_exemplars > MAX_TOTAL_EXEMPLARS {
            return Err(invalid(
                "routes",
                format!(
                    "must declare at most {MAX_TOTAL_EXEMPLARS} exemplar texts across every \
                     route, and this config declares {declared_exemplars}: each one is an \
                     embedding call on the first request that builds the index"
                ),
            ));
        }
        if !self.min_similarity.is_finite() || !(0.0..=1.0).contains(&self.min_similarity) {
            return Err(invalid(
                "min_similarity",
                "must be a finite number between 0.0 and 1.0",
            ));
        }
        if self
            .fallback
            .as_deref()
            .is_some_and(|fallback| fallback.trim().is_empty())
        {
            return Err(invalid("fallback", "must not be empty when set"));
        }
        match self.source {
            EmbeddingSource::Provider => {
                if self.embedding.is_none() {
                    return Err(invalid(
                        "embedding",
                        "is required: `source: provider` needs an `embedding: {provider, model}` \
                         block naming one of this origin's providers. A semantic_route strategy \
                         with nothing to embed with cannot route on meaning, so this refuses at \
                         config compile rather than degrading at runtime",
                    ));
                }
            }
            EmbeddingSource::Sidecar => match self.sidecar.as_ref() {
                Some(sidecar) => {
                    crate::semantic_cache::config::validate_sidecar(sidecar)
                        .map_err(|error| invalid("sidecar", error))?;
                }
                None => {
                    return Err(invalid(
                        "sidecar",
                        "is required: `source: sidecar` needs a `sidecar: {endpoint}` embedding \
                         block",
                    ));
                }
            },
            EmbeddingSource::Openai => match self.openai.as_ref() {
                Some(openai) => {
                    crate::semantic_cache::config::validate_openai(openai)
                        .map_err(|error| invalid("openai", error))?;
                }
                None => {
                    return Err(invalid(
                        "openai",
                        "is required: `source: openai` needs an `openai: {base_url, model}` \
                         embedding block",
                    ));
                }
            },
            EmbeddingSource::Inprocess => {
                return Err(invalid(
                    "source",
                    "`inprocess` is not supported for semantic_route: the in-process embedder \
                     is compiled into sbproxy-core behind the `inprocess-embed` feature and is \
                     not reachable from the routing seam. Use `provider`, `sidecar`, or `openai`",
                ));
            }
        }
        Ok(())
    }

    /// The cached exemplar index, building it on first use by embedding
    /// every declared exemplar text through `embed` and normalizing every
    /// declared centroid.
    ///
    /// Three refusals here are not build failures and are deliberately
    /// not counted as strikes: a cached index short-circuits, a build
    /// already in flight elsewhere returns an error this request folds
    /// into its fallback rather than starting a second build, and a
    /// build inside its retry floor returns without touching the
    /// embedder at all.
    ///
    /// `try_lock` rather than `lock` is the fail-posture choice. Waiting
    /// on the in-flight build would trade the embedding amplifier for a
    /// latency stall on every request that arrived during a cold start,
    /// and this strategy's contract is to fall back rather than to hang.
    /// A request that misses the gate pays no embedding call at all and
    /// routes to the declared `fallback`.
    async fn exemplar_index<F, Fut>(&self, embed: &F) -> anyhow::Result<Arc<ExemplarIndex>>
    where
        F: Fn(String) -> Fut,
        Fut: Future<Output = anyhow::Result<Vec<f32>>>,
    {
        if let Some(index) = self.state.cached() {
            return Ok(index);
        }
        let Ok(_build) = self.state.build.try_lock() else {
            anyhow::bail!("semantic_route exemplar index is already being built");
        };
        // The holder of the gate may have finished between the read
        // above and this lock, so re-read before spending anything.
        if let Some(index) = self.state.cached() {
            return Ok(index);
        }
        if let Some(remaining) = self
            .state
            .build_backoff_remaining(std::time::Instant::now())
        {
            anyhow::bail!(
                "semantic_route exemplar index build is in backoff for another {} seconds",
                remaining.as_secs()
            );
        }
        match self.build_exemplar_index(embed).await {
            Ok(index) => {
                self.state.store(Arc::clone(&index));
                Ok(index)
            }
            Err(error) => {
                // Timed at the failure, not at the gate: the build's own
                // duration must not eat into the floor it just earned.
                let (strikes, retry_after) =
                    self.state.note_build_failure(std::time::Instant::now());
                // One line per build attempt, never one per exemplar: a
                // permanently unbuildable index must not turn the log
                // into an amplifier of its own.
                tracing::warn!(
                    routes = self.routes.len(),
                    strikes,
                    retry_after_secs = retry_after.as_secs(),
                    error = %error,
                    "AI proxy: semantic_route exemplar index build failed; requests take the \
                     declared fallback until the retry floor elapses"
                );
                Err(error)
            }
        }
    }

    /// Embed every declared exemplar and normalize every declared
    /// centroid into one index. Called only by
    /// [`Self::exemplar_index`], and only under its single-flight gate.
    ///
    /// Serial by design: the embedding source is a shared upstream, and
    /// a fan-out here would replace the per-request amplifier the gate
    /// just removed with a per-build one.
    async fn build_exemplar_index<F, Fut>(&self, embed: &F) -> anyhow::Result<Arc<ExemplarIndex>>
    where
        F: Fn(String) -> Fut,
        Fut: Future<Output = anyhow::Result<Vec<f32>>>,
    {
        let mut entries = Vec::new();
        let mut embedded = 0usize;
        let mut dimensions: Option<usize> = None;
        let mut check_dimensions = |vector: &[f32]| -> anyhow::Result<()> {
            match dimensions {
                None => {
                    dimensions = Some(vector.len());
                    Ok(())
                }
                Some(expected) if expected == vector.len() => Ok(()),
                Some(expected) => anyhow::bail!(
                    "exemplar vectors disagree on dimensions ({expected} vs {})",
                    vector.len()
                ),
            }
        };
        for (route_index, rule) in self.routes.iter().enumerate() {
            if let Some(centroid) = rule.centroid.as_ref() {
                let vector = l2_normalize(centroid.clone())
                    .ok_or_else(|| anyhow::anyhow!("declared centroid is not scoreable"))?;
                check_dimensions(&vector)?;
                entries.push(ExemplarEntry {
                    route_index,
                    exemplar: None,
                    vector,
                });
            }
            for (exemplar_index, exemplar) in rule.exemplars.iter().enumerate() {
                // The same aggregate budget `validate` refuses past,
                // enforced again here because a config can reach this
                // build without having been validated (serde `skip`
                // fields and `Default` both construct one).
                anyhow::ensure!(
                    embedded < MAX_TOTAL_EXEMPLARS,
                    "semantic_route declares more than {MAX_TOTAL_EXEMPLARS} exemplar texts \
                     across its routes"
                );
                embedded += 1;
                let vector = l2_normalize(embed(exemplar.clone()).await?)
                    .ok_or_else(|| anyhow::anyhow!("exemplar embedding is not scoreable"))?;
                check_dimensions(&vector)?;
                entries.push(ExemplarEntry {
                    route_index,
                    exemplar: Some(exemplar_index),
                    vector,
                });
            }
        }
        let Some(dimensions) = dimensions else {
            anyhow::bail!("no exemplar produced a scoreable vector");
        };
        tracing::debug!(
            routes = self.routes.len(),
            vectors = entries.len(),
            embedded,
            dimensions,
            "AI proxy: semantic_route exemplar index built"
        );
        Ok(Arc::new(ExemplarIndex {
            entries,
            dimensions,
        }))
    }
}

/// Decide where one request should route.
///
/// `prompt` is the request's semantic query (the final user message, as
/// extracted by the dispatcher's semantic-prompt splitter); `embed` is the
/// configured embedding source as a call. Every failure inside is folded
/// into a fallback outcome: this function never errors and never panics,
/// because the fail posture of the strategy is "fall to the declared
/// default, never fail the request".
///
/// `embed` is called once for the prompt in steady state. It is called
/// once per declared exemplar on the one request that builds the index,
/// and not at all on a request that arrives while another is building or
/// while a failed build is inside its retry floor: both of those are
/// fallback outcomes rather than embedding calls, which is what keeps a
/// cold start or an unbuildable index from amplifying into the embedder.
pub async fn decide<F, Fut>(
    config: &SemanticRouteConfig,
    prompt: &str,
    embed: F,
) -> SemanticRouteOutcome
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = anyhow::Result<Vec<f32>>>,
{
    if prompt.is_empty() {
        return SemanticRouteOutcome::NoPrompt;
    }
    let Ok(index) = config.exemplar_index(&embed).await else {
        return SemanticRouteOutcome::EmbedderUnavailable;
    };
    let Ok(raw_query) = embed(prompt.to_string()).await else {
        return SemanticRouteOutcome::EmbedderUnavailable;
    };
    let Some(query) = l2_normalize(raw_query) else {
        return SemanticRouteOutcome::EmbedderUnavailable;
    };
    if query.len() != index.dimensions {
        return SemanticRouteOutcome::EmbedderUnavailable;
    }
    let mut best: Option<(&ExemplarEntry, f32)> = None;
    for entry in &index.entries {
        let score = dot(&query, &entry.vector);
        // Strictly greater, so score ties keep the earliest declared
        // exemplar and the decision is deterministic across requests.
        if best.is_none_or(|(_, best_score)| score > best_score) {
            best = Some((entry, score));
        }
    }
    let Some((entry, score)) = best else {
        return SemanticRouteOutcome::EmbedderUnavailable;
    };
    let Some(rule) = config.routes.get(entry.route_index) else {
        return SemanticRouteOutcome::EmbedderUnavailable;
    };
    if score >= config.min_similarity {
        SemanticRouteOutcome::Matched {
            deployment: rule.deployment.clone(),
            exemplar: entry.exemplar,
            score,
        }
    } else {
        SemanticRouteOutcome::BelowFloor {
            best_deployment: rule.deployment.clone(),
            best_score: score,
        }
    }
}

/// Embed `text` through the configured embedding source, for both the
/// per-request prompt and the first-use exemplar builds.
///
/// `source: provider` resolves `embedding.provider` against the origin's
/// providers and honors the caller's credential provider policy, exactly
/// as the semantic cache's provider source does; `source: openai` is
/// skipped for a policy-restricted credential for the same reason the
/// cache skips it (a standalone endpoint cannot prove membership in the
/// restriction). Errors from this function are folded into
/// [`SemanticRouteOutcome::EmbedderUnavailable`] by [`decide`]'s callers
/// and never carry into a response.
///
/// # Who owns the quota-pool reservation
///
/// `quota_attempt` is one reservation against the origin's `quota_pool`,
/// minted by the dispatcher for this call and settled here at the send
/// seam by the `_with_quota` embedding variants, mirroring the semantic
/// cache's lookup embedding. Without it, a `semantic_route` origin
/// sharing a pool would drive two upstream calls per admitted request
/// and meter one.
///
/// Whether there is a reservation at all is the caller's decision, and
/// [`SemanticRouteConfig::embed_meters_quota_pool`] is that decision:
/// `Some` for the two sources that POST to an upstream the pool
/// represents, `None` for the ones that do not, including on a pooled
/// origin where the admission state would make it a no-op guard. This
/// function never hands a reservation back, because a caller that
/// minted one for an unmetered call has already spent a unit of a
/// shared store and can already have been denied by a pool that call
/// never spends against.
///
/// The guard is per call, not per request, because a cold start embeds
/// every exemplar and each of those is its own upstream call. A guard
/// that reaches an error path before any upstream call (a credential
/// the embedding provider is not available to, a missing source block)
/// is released when it drops, which is the right settlement for a call
/// that did not happen, so every path through here settles or releases
/// exactly once.
pub async fn embed_route_text(
    config: &SemanticRouteConfig,
    client: &crate::client::AiClient,
    providers: &[ProviderConfig],
    allowed: &[String],
    blocked: &[String],
    text: &str,
    quota_attempt: Option<crate::quota_pool::QuotaPoolAttemptGuard>,
) -> anyhow::Result<Vec<f32>> {
    match config.source {
        EmbeddingSource::Provider => {
            let Some(embedding) = config.embedding.as_ref() else {
                anyhow::bail!("semantic_route provider embedding block is missing");
            };
            let provider = providers
                .iter()
                .find(|provider| {
                    provider.name == embedding.provider
                        && crate::routing::provider_allowed_by_policy(
                            provider.name.as_str(),
                            allowed,
                            blocked,
                        )
                })
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "semantic_route embedding provider {} is unavailable for this credential",
                        embedding.provider
                    )
                })?;
            match quota_attempt {
                Some(attempt) => {
                    crate::semantic_cache::compute_embedding_with_quota(
                        client,
                        provider,
                        &embedding.model,
                        text,
                        attempt,
                    )
                    .await
                }
                None => {
                    crate::semantic_cache::compute_embedding(
                        client,
                        provider,
                        &embedding.model,
                        text,
                    )
                    .await
                }
            }
        }
        EmbeddingSource::Sidecar => {
            // A local classifier process is not a pooled provider call,
            // so this source owes no reservation and the dispatch seam
            // mints none for it. One arriving anyway is a caller that
            // has already taken a unit out of a shared store for
            // traffic the pool cannot see, which is what the assertion
            // is here to fail; releasing it is the best that can still
            // be done for the unit.
            debug_assert!(
                quota_attempt.is_none(),
                "a sidecar embed takes no quota-pool reservation; the dispatch seam gates on \
                 SemanticRouteConfig::embed_meters_quota_pool"
            );
            drop(quota_attempt);
            match config.sidecar.as_ref() {
                Some(sidecar) => {
                    crate::semantic_cache::compute_embedding_sidecar(sidecar, text).await
                }
                None => anyhow::bail!("semantic_route sidecar source has no sidecar config"),
            }
        }
        EmbeddingSource::Openai => match config
            .openai
            .as_ref()
            .filter(|_| allowed.is_empty() && blocked.is_empty())
        {
            Some(openai) => match quota_attempt {
                Some(attempt) => {
                    crate::semantic_cache::compute_embedding_openai_with_quota(
                        openai, text, attempt,
                    )
                    .await
                }
                None => crate::semantic_cache::compute_embedding_openai(openai, text).await,
            },
            None => anyhow::bail!(
                "semantic_route openai source has no openai config usable for this credential"
            ),
        },
        EmbeddingSource::Inprocess => anyhow::bail!(
            "semantic_route does not support source: inprocess; config validation refuses it"
        ),
    }
}

/// Normalize a vector to unit L2 length, so cosine similarity reduces to
/// a dot product. `None` when the vector is empty, non-finite, or has a
/// norm too small to divide by.
fn l2_normalize(mut vector: Vec<f32>) -> Option<Vec<f32>> {
    if vector.is_empty() || vector.iter().any(|value| !value.is_finite()) {
        return None;
    }
    let norm = vector
        .iter()
        .map(|value| f64::from(*value) * f64::from(*value))
        .sum::<f64>()
        .sqrt();
    if !norm.is_finite() || norm <= f64::EPSILON {
        return None;
    }
    for value in &mut vector {
        *value = (f64::from(*value) / norm) as f32;
    }
    Some(vector)
}

/// Dot product of two equal-length unit vectors: their cosine similarity.
fn dot(a: &[f32], b: &[f32]) -> f32 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| f64::from(*x) * f64::from(*y))
        .sum::<f64>() as f32
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Parse a `semantic_route` routing object (minus the `strategy`
    /// discriminator) without validation.
    fn parse(value: serde_json::Value) -> Result<SemanticRouteConfig, String> {
        serde_json::from_value::<SemanticRouteConfig>(value).map_err(|error| error.to_string())
    }

    /// Parse and validate, as the handler's routing deserializer does.
    fn parse_and_validate(value: serde_json::Value) -> Result<SemanticRouteConfig, String> {
        let config = parse(value)?;
        config.validate().map_err(|error| error.to_string())?;
        Ok(config)
    }

    /// Two specialties with declared centroids on orthogonal axes, so a
    /// test controls scores exactly: `code-pool` owns `[1, 0]` and
    /// `chat-pool` owns `[0, 1]`.
    fn centroid_config() -> SemanticRouteConfig {
        parse_and_validate(serde_json::json!({
            "routes": [
                {"deployment": "code-pool", "centroid": [1.0, 0.0]},
                {"deployment": "chat-pool", "centroid": [0.0, 1.0]}
            ],
            "min_similarity": 0.75,
            "fallback": "chat-pool",
            "embedding": {"provider": "embedder", "model": "text-embedding-3-small"}
        }))
        .expect("centroid fixture validates")
    }

    /// Exemplar-text config whose stub embedder maps text content onto
    /// the same orthogonal axes.
    fn exemplar_config() -> SemanticRouteConfig {
        parse_and_validate(serde_json::json!({
            "routes": [
                {"deployment": "code-pool", "exemplars": [
                    "Write a Rust function that parses JSON",
                    "Review this pull request for bugs"
                ]},
                {"deployment": "chat-pool", "exemplars": ["Chat about everyday topics"]}
            ],
            "min_similarity": 0.75,
            "embedding": {"provider": "embedder", "model": "text-embedding-3-small"}
        }))
        .expect("exemplar fixture validates")
    }

    /// Deterministic stub embedder: text mentioning code lands on the
    /// x axis, chat on the y axis, everything else in between.
    async fn stub_embed(text: String) -> anyhow::Result<Vec<f32>> {
        let lowered = text.to_lowercase();
        if lowered.contains("rust") || lowered.contains("bugs") {
            Ok(vec![0.95, 0.05])
        } else if lowered.contains("chat") {
            Ok(vec![0.05, 0.95])
        } else {
            Ok(vec![0.7, 0.714])
        }
    }

    #[tokio::test]
    async fn a_prompt_matching_specialty_a_routes_to_a() {
        let config = centroid_config();
        let outcome = decide(
            &config,
            "Write a Rust function that parses JSON",
            stub_embed,
        )
        .await;
        match outcome {
            SemanticRouteOutcome::Matched {
                deployment,
                exemplar,
                score,
            } => {
                assert_eq!(deployment, "code-pool");
                assert_eq!(exemplar, None, "the declared centroid won, not a text");
                assert!(score > 0.9, "orthogonal fixture must score high: {score}");
            }
            other => panic!("a specialty match must route to its deployment: {other:?}"),
        }
    }

    #[tokio::test]
    async fn exemplar_texts_embed_and_the_winning_ordinal_is_reported() {
        let config = exemplar_config();
        let outcome = decide(&config, "Please review my code for bugs", stub_embed).await;
        match outcome {
            SemanticRouteOutcome::Matched {
                deployment,
                exemplar,
                score,
            } => {
                assert_eq!(deployment, "code-pool");
                assert_eq!(
                    exemplar,
                    Some(0),
                    "both code exemplars embed identically; the first declared wins"
                );
                assert!(score > 0.9, "{score}");
            }
            other => panic!("an exemplar match must route to its deployment: {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_below_floor_prompt_reports_the_fallback_outcome() {
        let config = centroid_config();
        // The stub returns [0.7, 0.714] for unrecognized text: ~0.70
        // cosine against both centroids, below the 0.75 floor.
        let outcome = decide(&config, "Tell me something ambiguous", stub_embed).await;
        match outcome {
            SemanticRouteOutcome::BelowFloor {
                best_deployment,
                best_score,
            } => {
                assert_eq!(
                    best_deployment, "chat-pool",
                    "the closest specialty is still reported for floor tuning"
                );
                assert!(
                    best_score < 0.75 && best_score > 0.5,
                    "the near-miss score is reported: {best_score}"
                );
            }
            other => panic!("a below-floor score is a fallback, not a match: {other:?}"),
        }
        assert_eq!(
            config.fallback.as_deref(),
            Some("chat-pool"),
            "the declared default is what the dispatcher pins on this outcome"
        );
    }

    #[tokio::test]
    async fn an_embedder_failure_falls_back_instead_of_failing() {
        let config = centroid_config();
        let outcome = decide(&config, "Write a Rust function", |_text: String| async {
            anyhow::bail!("embedding endpoint unreachable")
        })
        .await;
        assert_eq!(
            outcome,
            SemanticRouteOutcome::EmbedderUnavailable,
            "an unavailable embedder must fold into the fail-open fallback outcome"
        );
    }

    #[tokio::test]
    async fn an_empty_prompt_never_calls_the_embedder() {
        let config = centroid_config();
        let calls = AtomicUsize::new(0);
        let outcome = decide(&config, "", |_text: String| {
            calls.fetch_add(1, Ordering::Relaxed);
            async { Ok(vec![1.0, 0.0]) }
        })
        .await;
        assert_eq!(outcome, SemanticRouteOutcome::NoPrompt);
        assert_eq!(
            calls.load(Ordering::Relaxed),
            0,
            "a request with nothing to embed must not pay for an embedding call"
        );
    }

    #[tokio::test]
    async fn exemplar_vectors_embed_once_and_are_cached_across_requests() {
        let config = exemplar_config();
        let calls = AtomicUsize::new(0);
        let embed = |text: String| {
            calls.fetch_add(1, Ordering::Relaxed);
            async move { stub_embed(text).await }
        };
        let first = decide(&config, "Write a Rust function", &embed).await;
        assert!(matches!(first, SemanticRouteOutcome::Matched { .. }));
        // Three exemplar embeds plus one prompt embed.
        assert_eq!(calls.load(Ordering::Relaxed), 4);
        let second = decide(&config, "Chat with me", &embed).await;
        assert!(matches!(second, SemanticRouteOutcome::Matched { .. }));
        // The cached index makes the second request one prompt embed.
        assert_eq!(
            calls.load(Ordering::Relaxed),
            5,
            "exemplars are a first-use cost, not a per-request one"
        );
    }

    #[tokio::test]
    async fn a_failed_exemplar_build_is_negatively_cached_behind_a_retry_floor() {
        // WOR-2564 review: without the negative cache, a config the
        // embedder can never build (a mistyped `embedding.model`, a
        // centroid whose dimensions disagree) re-embeds the whole
        // exemplar set on every single request, forever. One attempt per
        // backoff window is the bound.
        let config = exemplar_config();
        let calls = AtomicUsize::new(0);
        let broken = |_text: String| {
            calls.fetch_add(1, Ordering::Relaxed);
            async { anyhow::bail!("no such embedding model") }
        };
        let first = decide(&config, "Write a Rust function", &broken).await;
        assert_eq!(first, SemanticRouteOutcome::EmbedderUnavailable);
        let after_first = calls.load(Ordering::Relaxed);
        assert_eq!(
            after_first, 1,
            "the build stops at the first exemplar the embedder refuses"
        );
        let second = decide(&config, "Write a Rust function", &broken).await;
        assert_eq!(
            second,
            SemanticRouteOutcome::EmbedderUnavailable,
            "the strategy still falls back, it just does not pay for it twice"
        );
        assert_eq!(
            calls.load(Ordering::Relaxed),
            after_first,
            "a request inside the retry floor must not touch the embedder at all"
        );
    }

    #[test]
    fn the_build_retry_floor_doubles_per_strike_and_then_expires() {
        let state = SemanticRouteState::default();
        let now = std::time::Instant::now();
        assert_eq!(
            state.build_backoff_remaining(now),
            None,
            "a config that has never failed is always buildable"
        );

        let (strikes, first) = state.note_build_failure(now);
        assert_eq!(strikes, 1);
        assert_eq!(first, EXEMPLAR_BUILD_RETRY_FLOOR);
        assert!(state.build_backoff_remaining(now).is_some());
        assert_eq!(
            state.build_backoff_remaining(now + EXEMPLAR_BUILD_RETRY_FLOOR),
            None,
            "a recovered embedder is retried once the floor elapses"
        );

        let (strikes, second) = state.note_build_failure(now);
        assert_eq!(strikes, 2);
        assert_eq!(
            second,
            EXEMPLAR_BUILD_RETRY_FLOOR * 2,
            "consecutive failures back off rather than hammering the embedder"
        );
        assert_eq!(
            retry_backoff(u32::MAX),
            EXEMPLAR_BUILD_RETRY_CEILING,
            "the backoff is capped, so a recovered embedder is never parked forever"
        );

        state.store(Arc::new(ExemplarIndex {
            entries: Vec::new(),
            dimensions: 2,
        }));
        assert_eq!(
            state.build_backoff_remaining(now),
            None,
            "a successful build clears the negative cache"
        );
    }

    #[tokio::test]
    async fn a_build_already_in_flight_falls_back_instead_of_starting_a_second() {
        // 100 concurrent cold-start requests used to mean 100 full
        // exemplar builds fired at the embedder in one burst. The gate
        // makes that one build; everyone else takes the declared
        // fallback for free.
        let config = exemplar_config();
        let calls = AtomicUsize::new(0);
        let embed = |text: String| {
            calls.fetch_add(1, Ordering::Relaxed);
            async move { stub_embed(text).await }
        };
        let held = config.state.build.lock().await;
        let blocked = decide(&config, "Write a Rust function", &embed).await;
        assert_eq!(
            blocked,
            SemanticRouteOutcome::EmbedderUnavailable,
            "a request that misses the gate falls back rather than hanging on the build"
        );
        assert_eq!(
            calls.load(Ordering::Relaxed),
            0,
            "a request that misses the gate must not embed anything, exemplar or prompt"
        );
        drop(held);

        let served = decide(&config, "Write a Rust function", &embed).await;
        assert!(
            matches!(served, SemanticRouteOutcome::Matched { .. }),
            "missing the gate is not a build failure and must not earn a retry floor: {served:?}"
        );
    }

    #[tokio::test]
    async fn a_query_with_the_wrong_dimensions_is_an_embedder_failure() {
        let config = centroid_config();
        let outcome = decide(&config, "Write a Rust function", |_text: String| async {
            Ok(vec![1.0, 0.0, 0.0])
        })
        .await;
        assert_eq!(
            outcome,
            SemanticRouteOutcome::EmbedderUnavailable,
            "a 3-dimensional query cannot be scored against 2-dimensional centroids"
        );
    }

    #[test]
    fn validation_refuses_the_unroutable_shapes() {
        for (value, needle, label) in [
            (
                serde_json::json!({
                    "routes": [],
                    "embedding": {"provider": "e", "model": "m"}
                }),
                "routes",
                "no routes",
            ),
            (
                serde_json::json!({
                    "routes": [{"deployment": "a"}],
                    "embedding": {"provider": "e", "model": "m"}
                }),
                "exemplars",
                "a route with neither exemplars nor a centroid",
            ),
            (
                serde_json::json!({
                    "routes": [{"deployment": "a", "exemplars": ["x"]}],
                    "min_similarity": 1.5,
                    "embedding": {"provider": "e", "model": "m"}
                }),
                "min_similarity",
                "an out-of-range floor",
            ),
            (
                serde_json::json!({
                    "routes": [{"deployment": "a", "exemplars": ["x"]}]
                }),
                "embedding",
                "the default provider source without an embedding block",
            ),
            (
                serde_json::json!({
                    "routes": [{"deployment": "a", "exemplars": ["x"]}],
                    "source": "sidecar"
                }),
                "sidecar",
                "the sidecar source without a sidecar block",
            ),
            (
                serde_json::json!({
                    "routes": [{"deployment": "a", "exemplars": ["x"]}],
                    "source": "inprocess"
                }),
                "inprocess",
                "the unsupported in-process source",
            ),
            (
                serde_json::json!({
                    "routes": [{"deployment": "a", "centroid": [0.0, 0.0]}],
                    "embedding": {"provider": "e", "model": "m"}
                }),
                "centroid",
                "a zero-norm centroid",
            ),
            (
                serde_json::json!({
                    "routes": [{"deployment": "a", "exemplars": ["x"]}],
                    "fallback": "  ",
                    "embedding": {"provider": "e", "model": "m"}
                }),
                "fallback",
                "a blank fallback",
            ),
        ] {
            let error = match parse_and_validate(value) {
                Ok(_) => panic!("{label} must be refused"),
                Err(error) => error,
            };
            assert!(error.contains(needle), "{label}: {error}");
        }
    }

    #[test]
    fn an_over_long_exemplar_is_refused() {
        let error = parse_and_validate(serde_json::json!({
            "routes": [{"deployment": "a", "exemplars": ["x".repeat(MAX_EXEMPLAR_BYTES + 1)]}],
            "embedding": {"provider": "e", "model": "m"}
        }))
        .expect_err("an exemplar past the byte cap must be refused");
        assert!(error.contains("exemplars[0]"), "{error}");
    }

    #[test]
    fn a_total_exemplar_count_past_the_aggregate_budget_is_refused() {
        // The per-route cap alone permits 64 routes of 64 exemplars, and
        // every one of those is a billed embedding call on the request
        // that builds the index.
        let mut routes = Vec::new();
        let mut remaining = MAX_TOTAL_EXEMPLARS + 1;
        let mut route = 0;
        while remaining > 0 {
            let take = remaining.min(MAX_EXEMPLARS_PER_ROUTE);
            remaining -= take;
            routes.push(serde_json::json!({
                "deployment": format!("pool-{route}"),
                "exemplars": (0..take)
                    .map(|ordinal| format!("exemplar {route}-{ordinal}"))
                    .collect::<Vec<_>>(),
            }));
            route += 1;
        }
        let error = parse_and_validate(serde_json::json!({
            "routes": routes,
            "embedding": {"provider": "e", "model": "m"}
        }))
        .expect_err("an exemplar set past the aggregate budget must be refused");
        assert!(
            error.contains(&MAX_TOTAL_EXEMPLARS.to_string()),
            "the refusal has to name the budget: {error}"
        );
    }

    #[test]
    fn unknown_fields_are_refused_instead_of_becoming_unused_policy() {
        let error = parse(serde_json::json!({
            "routes": [{"deployment": "a", "exemplars": ["x"]}],
            "minimum_similarity": 0.9,
            "embedding": {"provider": "e", "model": "m"}
        }))
        .expect_err("a misspelled floor must not silently route on the default");
        assert!(error.contains("unknown field"), "{error}");
    }

    #[test]
    fn debug_output_withholds_exemplar_text() {
        let config = parse_and_validate(serde_json::json!({
            "routes": [{
                "deployment": "code-pool",
                "exemplars": ["sentinelexemplartext about acquisitions"]
            }],
            "embedding": {"provider": "embedder", "model": "text-embedding-3-small"}
        }))
        .expect("fixture validates");
        let formatted = format!("{config:?}");
        assert!(
            !formatted.contains("sentinelexemplartext"),
            "exemplar text leaked into Debug output: {formatted}"
        );
        assert!(formatted.contains("code-pool"), "{formatted}");
    }

    /// Quota store that records which reservations settled and which
    /// were released, so a test can tell a metered upstream call from an
    /// unmetered one.
    #[derive(Default)]
    struct RecordingQuotaStore {
        settled: parking_lot::Mutex<Vec<String>>,
        released: parking_lot::Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl crate::quota_pool::QuotaPoolStore for RecordingQuotaStore {
        async fn reserve(
            &self,
            pool: &str,
            member: &str,
            units: u64,
            reservation_id: &str,
        ) -> Result<crate::quota_pool::QuotaReservation, crate::quota_pool::PoolError> {
            Ok(crate::quota_pool::QuotaReservation {
                pool: pool.to_string(),
                member: member.to_string(),
                units,
                reservation_id: reservation_id.to_string(),
            })
        }

        async fn reconcile(
            &self,
            reservation: crate::quota_pool::QuotaReservation,
            _actual: crate::quota_pool::PoolUsage,
        ) -> Result<(), crate::quota_pool::PoolError> {
            self.settled.lock().push(reservation.reservation_id);
            Ok(())
        }

        async fn release(
            &self,
            reservation: crate::quota_pool::QuotaReservation,
        ) -> Result<(), crate::quota_pool::PoolError> {
            self.released.lock().push(reservation.reservation_id);
            Ok(())
        }
    }

    #[tokio::test]
    async fn the_routing_embed_settles_its_quota_reservation() {
        // WOR-2564 review: the semantic cache's lookup embedding goes
        // through the `_with_quota` variants on the same origin and the
        // same provider. Routing's did not, so an origin declaring a
        // `quota_pool` drove two upstream calls per admitted request and
        // metered one. The endpoint here is unreachable on purpose: the
        // settle happens at the send seam, before the socket, so the
        // reservation is the assertion and the transport error is
        // expected.
        let config = parse_and_validate(serde_json::json!({
            "routes": [{"deployment": "code-pool", "centroid": [1.0, 0.0]}],
            "source": "openai",
            "openai": {"base_url": "http://127.0.0.1:1/v1", "model": "m", "timeout_ms": 200}
        }))
        .expect("openai-source fixture validates");
        let recording = Arc::new(RecordingQuotaStore::default());
        let store: Arc<dyn crate::quota_pool::QuotaPoolStore> = recording.clone();
        let admission = crate::quota_pool::QuotaPoolAdmission::new(
            Some(
                serde_json::from_value(serde_json::json!({
                    "name": "shared-upstream",
                    "total_limit": 10,
                    "weights": {"virtual-key-a": 1},
                    "policy": "burst"
                }))
                .expect("quota fixture"),
            ),
            Ok(Some(store)),
            Ok("virtual-key-a".to_string()),
        );
        let reservation_id = "req-1:quota-pool:semantic-route:openai:0";
        let attempt = admission
            .reserve_attempt(reservation_id)
            .await
            .expect("quota reservation");

        let client = crate::client::AiClient::new();
        embed_route_text(&config, &client, &[], &[], &[], "route me", Some(attempt))
            .await
            .expect_err("nothing is listening on port 1");

        assert_eq!(
            recording.settled.lock().as_slice(),
            [reservation_id.to_string()],
            "the routing embed has to consume a pool unit like the cache's embed does"
        );
        assert!(
            recording.released.lock().is_empty(),
            "a dispatched embedding call settles, it does not release"
        );
    }

    #[test]
    fn normalization_rejects_the_unscoreable_vectors() {
        assert_eq!(l2_normalize(vec![]), None);
        assert_eq!(l2_normalize(vec![0.0, 0.0]), None);
        assert_eq!(l2_normalize(vec![f32::NAN, 1.0]), None);
        assert_eq!(l2_normalize(vec![f32::INFINITY]), None);
        let unit = l2_normalize(vec![3.0, 4.0]).expect("a real vector normalizes");
        assert!((dot(&unit, &unit) - 1.0).abs() < 1e-6);
    }
}

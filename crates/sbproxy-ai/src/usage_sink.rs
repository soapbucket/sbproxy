//! Pluggable usage sinks for completed LLM calls.
//!
//! A usage sink forwards a record of every finished LLM request to an external
//! system (a log file, an HTTP collector, an observability backend). This is
//! the open-source seam that LiteLLM's `success_callback` / `failure_callback`
//! / `callbacks` map onto: sinks emit outward and hold no internal durable
//! state, so the persistence lives in the external system. Closed-source sinks
//! extend the same [`UsageSink`] trait via the plugin registry.
//!
//! Sinks must be non-blocking on the request hot path and must never propagate
//! a failure: a broken sink cannot fail the request it is logging.

use sbproxy_security::egress::{
    configured_gate, evaluate_hop, record_egress_refused, record_egress_seen,
    CachedSystemResolver, EgressAuthorizer, EgressDenied, EgressPurpose, EgressSightingStatus,
    HostResolver, RedirectRule,
};
use serde::{Deserialize, Serialize};

/// A record of one completed LLM call, handed to every configured sink.
///
/// Deserializable as well as serializable so the verifiable ledger
/// (see [`crate::usage_ledger`]) can replay a persisted chain and
/// re-derive its hashes.
///
/// # This struct's shape is a file format
///
/// The ledger's verifier re-serializes the event it parsed and requires
/// byte-identical output against the bytes that were hashed. Field
/// declaration order and every `skip_serializing_if` are therefore part
/// of the on-disk contract, not just the Rust shape.
///
/// New fields go at the **end**, as `Option<...>` with
/// `#[serde(default, skip_serializing_if = "Option::is_none")]`. That
/// combination is what makes the addition invisible to a ledger written
/// by an older binary: the old record has no key for the new field, so
/// it deserializes to `None`, and `None` never serializes, so the
/// re-serialized bytes match what was hashed. Insert one mid-struct, or
/// leave off the skip, and every ledger already on a customer's disk
/// stops verifying. `crates/sbproxy-ai/tests/ledger_golden.rs` checks
/// two files written by an older binary on every run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmUsageEvent {
    /// Provider that served the request (e.g. `openai`).
    pub provider: String,
    /// Model that served the request.
    pub model: String,
    /// Prompt (input) tokens.
    pub prompt_tokens: u64,
    /// Completion (output) tokens.
    pub completion_tokens: u64,
    /// Total tokens billed.
    pub total_tokens: u64,
    /// Derived cost of the call in USD.
    pub cost_usd: f64,
    /// End-to-end latency in milliseconds.
    pub latency_ms: u64,
    /// Final HTTP status returned to the client.
    pub status: u16,
    /// Authenticated key identifier, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// Origin tenant boundary accepted for this request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Governed project attribution, when configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// End-user identifier, when supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Governed team attribution, when configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team: Option<String>,
    /// Operator-supplied grouping tags copied from the governed key policy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// String-only governed metadata. This is retained in usage records but
    /// deliberately excluded from metric labels.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub metadata: std::collections::BTreeMap<String, String>,
    /// Stable per-request identifier. The verifiable ledger uses it as
    /// the dedup key so an at-least-once delivery collapses to
    /// exactly-once on replay. `None` events are never deduplicated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Session the request belonged to, when the capture envelope
    /// resolved one (WOR-2093). Lets a downstream store join spend to
    /// the session a key has had without going through the access log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Optional tag set by a `set_sink_tag` action from the AI policy
    /// plane (WOR-1542), so a policy decision is queryable in the spend
    /// record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// Scheduling lane of the key that made the request (WOR-1679):
    /// `interactive`, `standard`, or `batch`. Present only when the key
    /// declares a priority, so ledger queries can attribute spend and
    /// latency per lane.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    /// Resolved version of the local inference engine that served the
    /// request (WOR-1906), captured at route time from the running
    /// engine. Answers "what served this request" from the ledger after
    /// the engine process is gone. Always `None` for hosted providers,
    /// and `None` for a served request whose engine never reported a
    /// version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_version: Option<String>,
    /// Which agent spent this (WOR-2140), from
    /// `A2AContext::caller_agent_id`, capped once at capture by
    /// [`crate::tracing_spans::cap_agent_id`] so the ledger, the span,
    /// and the metric label cannot name three different agents for one
    /// request.
    ///
    /// `None` for traffic that carried no agent identity at all. Present
    /// and unverified is a different statement from absent, which is why
    /// [`Self::a2a_identity_verified`] is a separate field rather than
    /// this one being cleared when the identity was not trusted: the
    /// spend is real either way and dropping the id would lose it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// The A2A `contextId` this call belonged to (WOR-2140), capped at
    /// [`crate::tracing_spans::MAX_RUN_ID_BYTES`].
    ///
    /// The run-scoped grouping key, and the same value the access log
    /// writes under this name and the request span writes as
    /// `session.id`. Task ids nest under a context id, so summing cost
    /// over one value of this field is what "what did this run cost"
    /// means. Never a metric label: it takes one distinct value per run,
    /// so it would mint a time series per run.
    ///
    /// Populated later in the request than [`Self::agent_id`], and on
    /// fewer surfaces. The `contextId` lives in the JSON-RPC request
    /// body, so it only exists once the A2A body phase has parsed it,
    /// whereas the agent id arrives in a header and is stamped during
    /// the request filter. On the AI-gateway surface the request is
    /// answered inside the request filter and the body phase never runs
    /// (WOR-2144), so this is `None` there today and run correlation
    /// rides the capture session instead. Absent is absent, not zero:
    /// treat it as "this record does not name a run".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a2a_context_id: Option<String>,
    /// Whether the identity in [`Self::agent_id`] and
    /// [`Self::a2a_context_id`] came from a source the proxy trusts
    /// (WOR-2140). `None` for traffic that carried no A2A envelope, so
    /// "no claim was made" stays distinguishable from "a claim was made
    /// and not trusted".
    ///
    /// This is not decoration. An untrusted caller names its own agent
    /// and its own run, so it can merge its spend into another agent's
    /// total, or shard itself across unbounded distinct agent ids until
    /// per-agent totals mean nothing. A per-agent or per-run total
    /// computed without filtering on this flag is a number the caller
    /// chose. The gateway records the spend either way, because the
    /// money was really spent, and marks it so a report cannot present
    /// it as verified by accident. Same trust decision the access log
    /// writes as `a2a_identity_verified` and the request span writes as
    /// `sbproxy.a2a.identity_verified`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a2a_identity_verified: Option<bool>,
    /// Caller-supplied workflow correlation id, from `SB-Attr-Trace-Id`.
    ///
    /// The third leg of (agent, workflow, run). It reaches the access
    /// log through [`crate::attribution::AttributionTags`] already, but
    /// the access log is not the ledger: spans and logs get sampled and
    /// rotated, and this record does not. Per-workflow spend that has
    /// to survive an argument has to be answerable from the tamper
    /// evident chain rather than from a join through a sampled surface.
    ///
    /// Caller-supplied, so it carries exactly as much trust as the
    /// caller does. Read it alongside `a2a_identity_verified` and treat
    /// it as a grouping key rather than as an assertion of fact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_id: Option<String>,
    /// The model the caller asked for, before per-provider mapping
    /// (WOR-2223).
    ///
    /// [`Self::model`] is the name the lane that answered bills under,
    /// which after a `model_map` rename is a different string. Both are
    /// needed to read a hybrid deployment: `model` says what was
    /// charged, this says which of the operator's lanes the request
    /// belonged to. A spilled completion and the local completions it
    /// displaced share this value and nothing else.
    ///
    /// `None` on surfaces that never resolve a caller-facing model, and
    /// on records that are not one caller's completion (a shadow eval,
    /// an MCP tool call).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logical_model: Option<String>,
    /// The `serve:` entry that answered this request on a locally hosted
    /// engine (WOR-2223), or `None` when the request left the box.
    ///
    /// The lane discriminator, and the reason it is a separate field
    /// from the two model names above rather than derived from them. A
    /// fallback provider that forwards the requested model id unchanged
    /// bills under the same string the local lane serves, so a lane
    /// decision made by comparing names credits a cloud completion as a
    /// local saving. Presence here is set at route time by the code that
    /// resolved a local engine, and nothing else can produce it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub served_model: Option<String>,
}

/// A destination for completed-call usage events.
///
/// Implementations must be non-blocking on the hot path and must never panic or
/// propagate an error: failures are logged and swallowed.
pub trait UsageSink: Send + Sync + std::fmt::Debug {
    /// Record one completed-call event. Best effort.
    fn record(&self, event: &LlmUsageEvent);
    /// A short, stable label for logs and metrics.
    fn name(&self) -> &str;
}

/// A sink that appends one JSON object per line to a file.
#[derive(Debug)]
pub struct JsonlFileSink {
    path: std::path::PathBuf,
}

impl JsonlFileSink {
    /// Create a sink that appends events to `path`, creating it if absent.
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl UsageSink for JsonlFileSink {
    fn record(&self, event: &LlmUsageEvent) {
        use std::io::Write as _;
        let line = match serde_json::to_string(event) {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(error = %e, "usage sink: failed to serialize event");
                return;
            }
        };
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(mut f) => {
                if let Err(e) = writeln!(f, "{line}") {
                    tracing::warn!(error = %e, path = %self.path.display(), "usage sink: write failed");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, path = %self.path.display(), "usage sink: open failed")
            }
        }
    }

    fn name(&self) -> &str {
        "jsonl_file"
    }
}

/// Authorize an HTTP usage-sink / webhook URL when an authorizer is
/// present. `None` preserves legacy ungated transport (omitted config).
pub fn authorize_usage_http(
    authorizer: Option<&EgressAuthorizer>,
    purpose: EgressPurpose,
    url: &str,
    resolver: &dyn HostResolver,
) -> Result<(), EgressDenied> {
    let Some(auth) = authorizer else {
        return Ok(());
    };
    auth.authorize(purpose, url, resolver).map(|_| ())
}

/// Build the sink transport (WOR-2165).
///
/// Sinks carry collector credentials in headers the HTTP client does
/// not treat as sensitive (`DD-API-KEY`) and in `Authorization`, so the
/// client must not follow a redirect on its own; [`send_sink_post`]
/// re-authorizes every hop instead.
fn sink_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// POST to a usage sink, re-authorizing each redirect hop (WOR-2165).
///
/// A usage sink URL is operator configuration naming exactly one
/// collector, so [`RedirectRule::SameOriginOnly`] is the whole policy
/// when no authorizer is attached: a 302 that walks the collector
/// credential to another host is refused rather than followed. Refusals
/// are attributed to the tenant whose event was being shipped, because
/// in a multi-tenant deployment a refusal on one tenant's traffic is
/// not the same signal as a refusal on everyone's.
async fn send_sink_post(
    client: &reqwest::Client,
    egress: Option<&EgressAuthorizer>,
    purpose: EgressPurpose,
    sink_name: &'static str,
    tenant: &str,
    mut request: reqwest::Request,
) -> Result<reqwest::Response, String> {
    let mut hop = 0usize;
    loop {
        let replay = request.try_clone();
        let from = request.url().clone();
        let resp = client
            .execute(request)
            .await
            .map_err(|error| error.to_string())?;
        if !resp.status().is_redirection() {
            return Ok(resp);
        }
        let Some(location) = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
        else {
            return Ok(resp);
        };
        hop += 1;
        let next = match evaluate_hop(
            egress,
            purpose,
            &from,
            &location,
            hop,
            RedirectRule::SameOriginOnly,
            &CachedSystemResolver,
        ) {
            Ok(next) => next,
            Err(denied) => {
                record_egress_refused(purpose, denied, tenant, sink_name);
                return Err(format!("egress denied: {denied:?}"));
            }
        };
        let Some(mut replay) = replay else {
            return Ok(resp);
        };
        if next.strip_credentials {
            crate::client::strip_sensitive_headers(replay.headers_mut());
        }
        *replay.url_mut() = next.url;
        request = replay;
    }
}

/// A sink that POSTs each event as JSON to a webhook URL, fire-and-forget.
#[derive(Debug)]
pub struct WebhookSink {
    url: String,
    client: reqwest::Client,
    egress: Option<EgressAuthorizer>,
}

impl WebhookSink {
    /// Create a webhook sink that POSTs events to `url`.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            client: sink_client(),
            egress: None,
        }
    }

    /// Attach a fail-closed egress authorizer (`EgressPurpose::Webhook`).
    pub fn with_egress(mut self, authorizer: EgressAuthorizer) -> Self {
        self.egress = Some(authorizer);
        self
    }
}

impl UsageSink for WebhookSink {
    fn record(&self, event: &LlmUsageEvent) {
        let tenant = event.tenant_id.clone().unwrap_or_default();
        // WOR-2476: every webhook URL lands in the egress inventory,
        // whether an authorizer is configured or not. `authorize_usage_http`
        // collapses "no authorizer" to `Ok(())`, so the stamp inspects
        // `self.egress` directly rather than trusting that result.
        match self.egress.as_ref() {
            None => {
                record_egress_seen(
                    EgressPurpose::Webhook,
                    &self.url,
                    "webhook",
                    EgressSightingStatus::Ungated,
                    None,
                );
            }
            Some(_) => match authorize_usage_http(
                self.egress.as_ref(),
                EgressPurpose::Webhook,
                &self.url,
                &CachedSystemResolver,
            ) {
                Ok(()) => {
                    record_egress_seen(
                        EgressPurpose::Webhook,
                        &self.url,
                        "webhook",
                        EgressSightingStatus::Allowed,
                        None,
                    );
                }
                Err(denied) => {
                    record_egress_seen(
                        EgressPurpose::Webhook,
                        &self.url,
                        "webhook",
                        EgressSightingStatus::Denied,
                        Some(denied),
                    );
                    record_egress_refused(EgressPurpose::Webhook, denied, &tenant, "webhook");
                    return;
                }
            },
        }
        let body = match serde_json::to_vec(event) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "usage sink: failed to serialize event");
                return;
            }
        };
        let url = self.url.clone();
        let client = self.client.clone();
        let egress = self.egress.clone();
        // Fire-and-forget so the request hot path is never blocked or failed by
        // the sink.
        tokio::spawn(async move {
            let request = match client
                .post(&url)
                .header("content-type", "application/json")
                .body(body)
                .build()
            {
                Ok(request) => request,
                Err(e) => {
                    tracing::warn!(error = %e, "usage sink: webhook request build failed");
                    return;
                }
            };
            if let Err(e) = send_sink_post(
                &client,
                egress.as_ref(),
                EgressPurpose::Webhook,
                "webhook",
                &tenant,
                request,
            )
            .await
            {
                tracing::warn!(error = %e, "usage sink: webhook POST failed");
            }
        });
    }

    fn name(&self) -> &str {
        "webhook"
    }
}

/// Build the Langfuse `/api/public/ingestion` request body for one event.
///
/// `event_id` is the batch event and observation id; `timestamp` is an
/// RFC-3339 string. Token counts go in `usage`; provider, cost, latency,
/// status, and identifiers go in `metadata`. Kept pure (no clock, no IO) so
/// the shape is unit-testable; the sink supplies the id and timestamp.
///
/// Agent attribution rides in `metadata` because Langfuse has nowhere
/// better to put it: cost lives on `generation` and `embedding`
/// observations, so the agent that spent the money is not a dimension
/// its cost model has. `agent_id`, `a2a_context_id`, and
/// `a2a_identity_verified` travel together for the same reason they do
/// everywhere else, so a Langfuse query cannot read the first two
/// without the third being right there.
pub fn langfuse_ingestion_body(
    event: &LlmUsageEvent,
    event_id: &str,
    timestamp: &str,
) -> serde_json::Value {
    let mut metadata = serde_json::Map::new();
    metadata.insert("provider".into(), serde_json::json!(event.provider));
    metadata.insert("cost_usd".into(), serde_json::json!(event.cost_usd));
    metadata.insert("latency_ms".into(), serde_json::json!(event.latency_ms));
    metadata.insert("status".into(), serde_json::json!(event.status));
    for (k, v) in [
        ("key_id", &event.key_id),
        ("tenant_id", &event.tenant_id),
        ("project", &event.project),
        ("user", &event.user),
        ("team", &event.team),
        ("tag", &event.tag),
        ("agent_id", &event.agent_id),
        ("a2a_context_id", &event.a2a_context_id),
    ] {
        if let Some(val) = v {
            metadata.insert(k.into(), serde_json::json!(val));
        }
    }
    if let Some(verified) = event.a2a_identity_verified {
        metadata.insert("a2a_identity_verified".into(), serde_json::json!(verified));
    }
    if !event.tags.is_empty() {
        metadata.insert("tags".into(), serde_json::json!(event.tags));
    }
    if !event.metadata.is_empty() {
        metadata.insert("metadata".into(), serde_json::json!(event.metadata));
    }
    serde_json::json!({
        "batch": [{
            "id": event_id,
            "type": "generation-create",
            "timestamp": timestamp,
            "body": {
                "id": event_id,
                "name": "sbproxy",
                "model": event.model,
                "usage": {
                    "input": event.prompt_tokens,
                    "output": event.completion_tokens,
                    "total": event.total_tokens,
                    "unit": "TOKENS",
                },
                "metadata": serde_json::Value::Object(metadata),
            },
        }],
    })
}

/// Build the Datadog logs-intake request body (an array of one log object)
/// for `event`, tagged with `service`. Pure (no clock, no IO); Datadog
/// stamps the ingestion time itself.
///
/// Carries the same agent attribution as
/// [`langfuse_ingestion_body`], and for the same reason: the trust flag
/// travels beside the ids so a facet built on `agent_id` cannot silently
/// mix verified and self-declared agents.
pub fn datadog_log_body(event: &LlmUsageEvent, service: &str) -> serde_json::Value {
    let mut log = serde_json::Map::new();
    log.insert("ddsource".into(), serde_json::json!("sbproxy"));
    log.insert("service".into(), serde_json::json!(service));
    log.insert(
        "message".into(),
        serde_json::json!(format!("llm call {}/{}", event.provider, event.model)),
    );
    log.insert("provider".into(), serde_json::json!(event.provider));
    log.insert("model".into(), serde_json::json!(event.model));
    log.insert(
        "prompt_tokens".into(),
        serde_json::json!(event.prompt_tokens),
    );
    log.insert(
        "completion_tokens".into(),
        serde_json::json!(event.completion_tokens),
    );
    log.insert("total_tokens".into(), serde_json::json!(event.total_tokens));
    log.insert("cost_usd".into(), serde_json::json!(event.cost_usd));
    log.insert("latency_ms".into(), serde_json::json!(event.latency_ms));
    log.insert("status".into(), serde_json::json!(event.status));
    for (k, v) in [
        ("key_id", &event.key_id),
        ("tenant_id", &event.tenant_id),
        ("project", &event.project),
        ("user", &event.user),
        ("team", &event.team),
        ("tag", &event.tag),
        ("agent_id", &event.agent_id),
        ("a2a_context_id", &event.a2a_context_id),
    ] {
        if let Some(val) = v {
            log.insert(k.into(), serde_json::json!(val));
        }
    }
    if let Some(verified) = event.a2a_identity_verified {
        log.insert("a2a_identity_verified".into(), serde_json::json!(verified));
    }
    if !event.tags.is_empty() {
        log.insert("tags".into(), serde_json::json!(event.tags));
    }
    if !event.metadata.is_empty() {
        log.insert("metadata".into(), serde_json::json!(event.metadata));
    }
    serde_json::Value::Array(vec![serde_json::Value::Object(log)])
}

/// A sink that POSTs each event to Langfuse's ingestion API, fire-and-forget.
#[derive(Debug)]
pub struct LangfuseSink {
    url: String,
    public_key: String,
    secret_key: String,
    client: reqwest::Client,
    egress: Option<EgressAuthorizer>,
}

impl LangfuseSink {
    /// Create a Langfuse sink. `host` is the base URL (e.g.
    /// `https://cloud.langfuse.com`); auth uses the public/secret key pair.
    pub fn new(host: &str, public_key: impl Into<String>, secret_key: impl Into<String>) -> Self {
        Self {
            url: format!("{}/api/public/ingestion", host.trim_end_matches('/')),
            public_key: public_key.into(),
            secret_key: secret_key.into(),
            client: sink_client(),
            egress: None,
        }
    }

    /// Attach a fail-closed egress authorizer (`EgressPurpose::UsageSink`).
    pub fn with_egress(mut self, authorizer: EgressAuthorizer) -> Self {
        self.egress = Some(authorizer);
        self
    }
}

impl UsageSink for LangfuseSink {
    fn record(&self, event: &LlmUsageEvent) {
        let tenant = event.tenant_id.clone().unwrap_or_default();
        // WOR-2476: every usage-sink URL lands in the egress inventory,
        // whether an authorizer is configured or not. `authorize_usage_http`
        // collapses "no authorizer" to `Ok(())`, so the stamp inspects
        // `self.egress` directly rather than trusting that result.
        match self.egress.as_ref() {
            None => {
                record_egress_seen(
                    EgressPurpose::UsageSink,
                    &self.url,
                    "langfuse",
                    EgressSightingStatus::Ungated,
                    None,
                );
            }
            Some(_) => match authorize_usage_http(
                self.egress.as_ref(),
                EgressPurpose::UsageSink,
                &self.url,
                &CachedSystemResolver,
            ) {
                Ok(()) => {
                    record_egress_seen(
                        EgressPurpose::UsageSink,
                        &self.url,
                        "langfuse",
                        EgressSightingStatus::Allowed,
                        None,
                    );
                }
                Err(denied) => {
                    record_egress_seen(
                        EgressPurpose::UsageSink,
                        &self.url,
                        "langfuse",
                        EgressSightingStatus::Denied,
                        Some(denied),
                    );
                    record_egress_refused(EgressPurpose::UsageSink, denied, &tenant, "langfuse");
                    return;
                }
            },
        }
        let timestamp = chrono::Utc::now().to_rfc3339();
        let id = event
            .request_id
            .clone()
            .unwrap_or_else(|| format!("sb-{}-{timestamp}", event.provider));
        let body = langfuse_ingestion_body(event, &id, &timestamp);
        let url = self.url.clone();
        let (pk, sk) = (self.public_key.clone(), self.secret_key.clone());
        let client = self.client.clone();
        let egress = self.egress.clone();
        tokio::spawn(async move {
            let request = match client
                .post(&url)
                .basic_auth(pk, Some(sk))
                .json(&body)
                .build()
            {
                Ok(request) => request,
                Err(e) => {
                    tracing::warn!(error = %e, "usage sink: langfuse request build failed");
                    return;
                }
            };
            if let Err(e) = send_sink_post(
                &client,
                egress.as_ref(),
                EgressPurpose::UsageSink,
                "langfuse",
                &tenant,
                request,
            )
            .await
            {
                tracing::warn!(error = %e, "usage sink: langfuse POST failed");
            }
        });
    }

    fn name(&self) -> &str {
        "langfuse"
    }
}

/// A sink that POSTs each event to Datadog's logs-intake API, fire-and-forget.
#[derive(Debug)]
pub struct DatadogSink {
    url: String,
    api_key: String,
    service: String,
    client: reqwest::Client,
    egress: Option<EgressAuthorizer>,
}

impl DatadogSink {
    /// Create a Datadog logs sink. `site` is the DD site (e.g.
    /// `datadoghq.com`, `datadoghq.eu`); `service` tags the log source.
    pub fn new(site: &str, api_key: impl Into<String>, service: impl Into<String>) -> Self {
        Self {
            url: format!("https://http-intake.logs.{site}/api/v2/logs"),
            api_key: api_key.into(),
            service: service.into(),
            client: sink_client(),
            egress: None,
        }
    }

    /// Attach a fail-closed egress authorizer (`EgressPurpose::UsageSink`).
    pub fn with_egress(mut self, authorizer: EgressAuthorizer) -> Self {
        self.egress = Some(authorizer);
        self
    }
}

impl UsageSink for DatadogSink {
    fn record(&self, event: &LlmUsageEvent) {
        let tenant = event.tenant_id.clone().unwrap_or_default();
        // WOR-2476: every usage-sink URL lands in the egress inventory,
        // whether an authorizer is configured or not. `authorize_usage_http`
        // collapses "no authorizer" to `Ok(())`, so the stamp inspects
        // `self.egress` directly rather than trusting that result.
        match self.egress.as_ref() {
            None => {
                record_egress_seen(
                    EgressPurpose::UsageSink,
                    &self.url,
                    "datadog",
                    EgressSightingStatus::Ungated,
                    None,
                );
            }
            Some(_) => match authorize_usage_http(
                self.egress.as_ref(),
                EgressPurpose::UsageSink,
                &self.url,
                &CachedSystemResolver,
            ) {
                Ok(()) => {
                    record_egress_seen(
                        EgressPurpose::UsageSink,
                        &self.url,
                        "datadog",
                        EgressSightingStatus::Allowed,
                        None,
                    );
                }
                Err(denied) => {
                    record_egress_seen(
                        EgressPurpose::UsageSink,
                        &self.url,
                        "datadog",
                        EgressSightingStatus::Denied,
                        Some(denied),
                    );
                    record_egress_refused(EgressPurpose::UsageSink, denied, &tenant, "datadog");
                    return;
                }
            },
        }
        let body = datadog_log_body(event, &self.service);
        let url = self.url.clone();
        let key = self.api_key.clone();
        let client = self.client.clone();
        let egress = self.egress.clone();
        tokio::spawn(async move {
            // WOR-2165: `DD-API-KEY` is a vendor header name, so the
            // HTTP client's own cross-origin credential stripping does
            // not cover it. Marking it sensitive puts it under the
            // shared strip that `send_sink_post` applies.
            let mut key_value = match reqwest::header::HeaderValue::from_str(&key) {
                Ok(value) => value,
                Err(e) => {
                    tracing::warn!(error = %e, "usage sink: datadog api key is not a valid header");
                    return;
                }
            };
            key_value.set_sensitive(true);
            let request = match client
                .post(&url)
                .header("DD-API-KEY", key_value)
                .json(&body)
                .build()
            {
                Ok(request) => request,
                Err(e) => {
                    tracing::warn!(error = %e, "usage sink: datadog request build failed");
                    return;
                }
            };
            if let Err(e) = send_sink_post(
                &client,
                egress.as_ref(),
                EgressPurpose::UsageSink,
                "datadog",
                &tenant,
                request,
            )
            .await
            {
                tracing::warn!(error = %e, "usage sink: datadog POST failed");
            }
        });
    }

    fn name(&self) -> &str {
        "datadog"
    }
}

fn default_dd_site() -> String {
    "datadoghq.com".to_string()
}

/// A sink that emits each usage event through the existing tracing /
/// OpenInference seam (GenAI + `llm.*` attributes), fire-and-forget.
///
/// Export to an OTLP collector is handled by the process-wide observe
/// pipeline (`sbproxy-observe`); this sink never blocks dispatch and
/// never propagates a failure. INT may later wire a direct OTel metrics
/// path by adding `opentelemetry` to `sbproxy-ai` if needed.
#[derive(Debug, Default)]
pub struct OtelSink;

impl OtelSink {
    /// Create an OTel usage sink that records via tracing attributes.
    pub fn new() -> Self {
        Self
    }
}

impl UsageSink for OtelSink {
    fn record(&self, event: &LlmUsageEvent) {
        // Clone the safe attribution fields only: no raw prompts, tool
        // output, tokens, or DSNs - matching the LiteLLM-style redaction
        // contract already enforced by [`LlmUsageEvent`]'s shape.
        let provider = event.provider.clone();
        let model = event.model.clone();
        let prompt_tokens = event.prompt_tokens;
        let completion_tokens = event.completion_tokens;
        let total_tokens = event.total_tokens;
        let cost_usd = event.cost_usd;
        let latency_ms = event.latency_ms;
        let status = event.status;
        let key_id = event.key_id.clone();
        let tenant_id = event.tenant_id.clone();
        let request_id = event.request_id.clone();
        // WOR-2140: the agent, its run, and whether either was verified.
        // Bounded identifiers already capped at capture, so they are the
        // same class of value as the key and tenant ids beside them.
        let agent_id = event.agent_id.clone();
        let a2a_context_id = event.a2a_context_id.clone();
        let identity_verified = event.a2a_identity_verified;
        tokio::spawn(async move {
            // Emit through the existing OpenInference / GenAI attribute
            // vocabulary (`tracing_spans`). The process-wide observe
            // pipeline exports these when OTLP is configured.
            let span = tracing::info_span!(
                "sbproxy.ai.usage_sink",
                "gen_ai.system" = %provider,
                "gen_ai.request.model" = %model,
                "gen_ai.usage.input_tokens" = prompt_tokens,
                "gen_ai.usage.output_tokens" = completion_tokens,
                "llm.token_count.prompt" = prompt_tokens,
                "llm.token_count.completion" = completion_tokens,
                "llm.token_count.total" = total_tokens,
                "gen_ai.usage.cost" = cost_usd,
                "llm.usage.total_cost" = cost_usd,
                "sbproxy.ai.latency_ms" = latency_ms,
                "http.response.status_code" = status,
                "sbproxy.key_id" = key_id.as_deref().unwrap_or(""),
                "sbproxy.tenant_id" = tenant_id.as_deref().unwrap_or(""),
                "gen_ai.response.id" = request_id.as_deref().unwrap_or(""),
                "sbproxy.a2a.caller_agent_id" = agent_id.as_deref().unwrap_or(""),
                "session.id" = a2a_context_id.as_deref().unwrap_or(""),
                "sbproxy.a2a.identity_verified" = identity_verified,
            );
            let _entered = span.enter();
        });
    }

    fn name(&self) -> &str {
        "otel"
    }
}

/// Which object-store backend a [`ObjectStoreSink`] targets.
#[derive(Debug, Clone, Copy)]
enum ObjectStoreKind {
    S3,
    Gcs,
}

/// A sink that writes each usage event as a JSON object to S3 or GCS,
/// fire-and-forget.
///
/// Builds the backend from the process environment (`AWS_*` /
/// `GOOGLE_APPLICATION_CREDENTIALS`, etc.) on each put. An empty bucket,
/// missing credentials, or a put failure logs and returns, never panics
/// or propagates to the request hot path.
///
/// `auth_url` (WOR-2476) is resolved once, at construction, via
/// [`object_store_authorization_url`], and reused for every `record()`
/// call rather than recomputed. A sink is built once per config
/// compile (see [`UsageSinkConfig::build`]) and lives for the process
/// lifetime, so this assumes an operator's S3 endpoint override
/// (`AWS_ENDPOINT_URL` / `AWS_ENDPOINT`) does not change mid-process;
/// it is read from the environment once, the same way every other
/// piece of process-lifetime config here is. Without this,
/// `AmazonS3Builder::from_env()`'s full `std::env::vars_os()` scan ran
/// synchronously on the request-logging hot path for every completed
/// AI call, duplicating the scan [`object_store_put`]'s builders
/// already do inside the spawned task.
#[derive(Debug)]
pub struct ObjectStoreSink {
    kind: ObjectStoreKind,
    bucket: String,
    prefix: String,
    egress: Option<EgressAuthorizer>,
    auth_url: String,
}

impl ObjectStoreSink {
    /// Create an S3 usage sink for `bucket` under `prefix`.
    pub fn s3(bucket: impl Into<String>, prefix: impl Into<String>) -> Self {
        let bucket = bucket.into();
        let auth_url = object_store_authorization_url(ObjectStoreKind::S3, &bucket);
        Self {
            kind: ObjectStoreKind::S3,
            bucket,
            prefix: prefix.into(),
            egress: None,
            auth_url,
        }
    }

    /// Create a GCS usage sink for `bucket` under `prefix`.
    pub fn gcs(bucket: impl Into<String>, prefix: impl Into<String>) -> Self {
        let bucket = bucket.into();
        let auth_url = object_store_authorization_url(ObjectStoreKind::Gcs, &bucket);
        Self {
            kind: ObjectStoreKind::Gcs,
            bucket,
            prefix: prefix.into(),
            egress: None,
            auth_url,
        }
    }

    /// Attach a fail-closed egress authorizer (`EgressPurpose::UsageSink`).
    pub fn with_egress(mut self, authorizer: EgressAuthorizer) -> Self {
        self.egress = Some(authorizer);
        self
    }
}

impl UsageSink for ObjectStoreSink {
    fn record(&self, event: &LlmUsageEvent) {
        if self.bucket.is_empty() {
            tracing::warn!(
                sink = self.name(),
                "usage sink: object store bucket missing"
            );
            return;
        }
        let tenant = event.tenant_id.clone().unwrap_or_default();
        // WOR-2476: gate the object-store destination before any I/O,
        // through the same `EgressPurpose::UsageSink` authorizer surface
        // as the other usage sinks. `authorize_usage_http` collapses "no
        // authorizer" to `Ok(())`, so the stamp inspects `self.egress`
        // directly rather than trusting that result. There is no literal
        // request URL here: `object_store`'s builders resolve the real
        // dial target from the environment (`AWS_*` /
        // `GOOGLE_APPLICATION_CREDENTIALS`, a possible custom endpoint
        // override, etc.), not from a field on this struct. `self.auth_url`
        // is that same environment read back, resolved once at
        // construction (see the struct doc comment) rather than here on
        // every `record()`: this method runs on the request-logging hot
        // path, and `AmazonS3Builder::from_env()` is a full
        // `std::env::vars_os()` scan that would otherwise run per logged
        // request in addition to the identical scan
        // [`object_store_put`]'s builders already do inside the spawned
        // task. See `object_store_authorization_url` for the S3-vs-GCS
        // derivation and the inventory-granularity note.
        let auth_url = &self.auth_url;
        match self.egress.as_ref() {
            None => {
                record_egress_seen(
                    EgressPurpose::UsageSink,
                    auth_url,
                    self.name(),
                    EgressSightingStatus::Ungated,
                    None,
                );
            }
            Some(_) => match authorize_usage_http(
                self.egress.as_ref(),
                EgressPurpose::UsageSink,
                auth_url,
                &CachedSystemResolver,
            ) {
                Ok(()) => {
                    record_egress_seen(
                        EgressPurpose::UsageSink,
                        auth_url,
                        self.name(),
                        EgressSightingStatus::Allowed,
                        None,
                    );
                }
                Err(denied) => {
                    record_egress_seen(
                        EgressPurpose::UsageSink,
                        auth_url,
                        self.name(),
                        EgressSightingStatus::Denied,
                        Some(denied),
                    );
                    record_egress_refused(EgressPurpose::UsageSink, denied, &tenant, self.name());
                    return;
                }
            },
        }
        let body = match serde_json::to_vec(event) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "usage sink: failed to serialize event");
                return;
            }
        };
        let kind = self.kind;
        let bucket = self.bucket.clone();
        let prefix = self.prefix.clone();
        let sink_name = self.name().to_string();
        let object_key = object_store_object_key(&prefix, event);
        tokio::spawn(async move {
            // Never log the event body (may carry governed metadata the
            // operator treats as sensitive); bucket + key are enough.
            if let Err(e) = object_store_put(kind, &bucket, &object_key, body).await {
                tracing::warn!(
                    error = %e,
                    sink = %sink_name,
                    bucket = %bucket,
                    object_key = %object_key,
                    "usage sink: object store put failed"
                );
            }
        });
    }

    fn name(&self) -> &str {
        match self.kind {
            ObjectStoreKind::S3 => "s3",
            ObjectStoreKind::Gcs => "gcs",
        }
    }
}

/// URL representing an object-store backend's destination, for egress
/// authorization only (WOR-2476).
///
/// `ObjectStoreSink` carries no endpoint field of its own: the real
/// dial target is resolved by [`object_store_put`]'s builders from the
/// process environment. For **S3**, `AmazonS3Builder::from_env()`
/// already parses `AWS_ENDPOINT_URL` / `AWS_ENDPOINT` into a builder
/// field, and reading it back via `get_config_value` is a synchronous
/// struct-field read (no I/O, no `.build()`), so an operator-configured
/// endpoint override (MinIO, R2, a self-hosted gateway, etc.) is used
/// directly instead of being silently assumed away; only an unset
/// override falls back to the well-known default AWS endpoint. **GCS**
/// has no equivalent accessor in `object_store` 0.11, so it stays on
/// its well-known default endpoint unconditionally. This also means the
/// two backends land in the inventory at different granularity: the S3
/// default is virtual-hosted style with the bucket in the host
/// (`<bucket>.s3.amazonaws.com`), so each bucket is its own row, while
/// the GCS default is path-style (`storage.googleapis.com/<bucket>`),
/// so every GCS bucket collapses onto the same host and the same row.
/// Never stored or logged with the raw bucket path; only host/port/
/// scheme reach the sightings inventory.
fn object_store_authorization_url(kind: ObjectStoreKind, bucket: &str) -> String {
    match kind {
        ObjectStoreKind::S3 => {
            s3_authorization_url(bucket, &object_store::aws::AmazonS3Builder::from_env())
        }
        ObjectStoreKind::Gcs => format!("https://storage.googleapis.com/{bucket}/"),
    }
}

/// S3 authorization URL for `bucket`, given an already-configured
/// `builder` (WOR-2476).
///
/// Split out from [`object_store_authorization_url`] so a test can
/// construct `builder` explicitly via `AmazonS3Builder::with_config`
/// instead of mutating real process environment variables: the
/// env-mutation guard (`scripts/check-env-mutation.sh`) restricts
/// direct `set_var`/`remove_var` to a documented per-crate
/// `EnvVarGuard` (`src/test_env.rs`), and `sbproxy-ai` has no such
/// guard today.
fn s3_authorization_url(bucket: &str, builder: &object_store::aws::AmazonS3Builder) -> String {
    use object_store::aws::AmazonS3ConfigKey;
    match builder.get_config_value(&AmazonS3ConfigKey::Endpoint) {
        Some(endpoint) if !endpoint.is_empty() => normalize_endpoint_url(&endpoint),
        _ => format!("https://{bucket}.s3.amazonaws.com/"),
    }
}

/// Ensure an operator-supplied `AWS_ENDPOINT_URL`-style value parses as
/// an absolute URL for the egress authorizer, which only inspects
/// host/port/scheme. A bare `host[:port]` with no scheme defaults to
/// `https://`.
fn normalize_endpoint_url(endpoint: &str) -> String {
    if endpoint.contains("://") {
        endpoint.to_string()
    } else {
        format!("https://{endpoint}")
    }
}

/// Put `body` to `bucket`/`object_key` via the matching object_store
/// backend. Credentials come from the environment. Returns an error on
/// build or put failure so the caller can log without panicking.
async fn object_store_put(
    kind: ObjectStoreKind,
    bucket: &str,
    object_key: &str,
    body: Vec<u8>,
) -> Result<(), String> {
    use object_store::path::Path as ObjectPath;
    use object_store::{ObjectStore, PutPayload};

    let store: std::sync::Arc<dyn ObjectStore> = match kind {
        ObjectStoreKind::S3 => {
            let store = object_store::aws::AmazonS3Builder::from_env()
                .with_bucket_name(bucket)
                .build()
                .map_err(|e| format!("s3 store build: {e}"))?;
            std::sync::Arc::new(store)
        }
        ObjectStoreKind::Gcs => {
            let store = object_store::gcp::GoogleCloudStorageBuilder::from_env()
                .with_bucket_name(bucket)
                .build()
                .map_err(|e| format!("gcs store build: {e}"))?;
            std::sync::Arc::new(store)
        }
    };
    let path = ObjectPath::from(object_key);
    store
        .put(&path, PutPayload::from(body))
        .await
        .map_err(|e| format!("put: {e}"))?;
    Ok(())
}

/// Build a stable object key under `prefix` for `event`. Prefers
/// `request_id` when present so at-least-once delivery collapses on
/// overwrite; otherwise falls back to a timestamped unique name.
fn object_store_object_key(prefix: &str, event: &LlmUsageEvent) -> String {
    let leaf = event
        .request_id
        .as_deref()
        .map(|id| format!("{id}.json"))
        .unwrap_or_else(|| {
            format!(
                "{}-{}-{}.json",
                event.provider,
                event.model.replace('/', "_"),
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
            )
        });
    if prefix.is_empty() {
        leaf
    } else if prefix.ends_with('/') {
        format!("{prefix}{leaf}")
    } else {
        format!("{prefix}/{leaf}")
    }
}

/// Declarative config for a usage sink, parsed from the action's
/// `usage_sinks` list.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UsageSinkConfig {
    /// Append events to a JSONL file.
    JsonlFile {
        /// Filesystem path to append to.
        path: String,
    },
    /// POST events to an HTTP collector.
    Webhook {
        /// Collector URL.
        url: String,
    },
    /// Append events to a tamper-evident, optionally signed ledger.
    ///
    /// See [`crate::usage_ledger`]. Each event is hash-chained to the
    /// previous one; with `signing_seed_hex` set, each entry is also
    /// Ed25519-signed so spend is provable, not just logged.
    Ledger {
        /// Filesystem path of the ledger (a JSONL write-ahead log).
        path: String,
        /// Optional 32-byte Ed25519 seed as hex. When present, every
        /// entry is signed. Resolve from a secret via `${VAR}` or a
        /// vault reference in the surrounding config.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signing_seed_hex: Option<String>,
    },
    /// POST events to Langfuse's ingestion API as generation observations.
    Langfuse {
        /// Base URL, e.g. `https://cloud.langfuse.com`.
        host: String,
        /// Langfuse public key.
        public_key: String,
        /// Langfuse secret key. Resolve from a secret via `${VAR}` or a
        /// vault reference in the surrounding config.
        secret_key: String,
    },
    /// POST events to Datadog's logs-intake API.
    Datadog {
        /// Datadog API key. Resolve from a secret via `${VAR}` or a vault
        /// reference in the surrounding config.
        api_key: String,
        /// Datadog site. Defaults to `datadoghq.com`; set `datadoghq.eu`,
        /// `us3.datadoghq.com`, etc. for other regions.
        #[serde(default = "default_dd_site")]
        site: String,
        /// Optional `service` tag on the emitted logs. Defaults to
        /// `sbproxy` at build time.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        service: Option<String>,
    },
    /// Emit events through the process OTel / OpenInference seam.
    Otel,
    /// Write events as JSON objects to an S3 bucket.
    S3 {
        /// Destination bucket name.
        bucket: String,
        /// Key prefix (e.g. `llm/`). Empty when omitted.
        #[serde(default)]
        prefix: String,
    },
    /// Write events as JSON objects to a GCS bucket.
    Gcs {
        /// Destination bucket name.
        bucket: String,
        /// Key prefix (e.g. `llm/`). Empty when omitted.
        #[serde(default)]
        prefix: String,
    },
}

impl UsageSinkConfig {
    /// Build the runtime sink for this config entry. Returned as an `Arc` so a
    /// single instance is shared across every request for the origin.
    ///
    /// WOR-2476: every network-reaching sink variant (`Webhook`,
    /// `Langfuse`, `Datadog`, `S3`, `Gcs`) attaches the process-wide
    /// `EgressPurpose::UsageSink` authorizer via `with_egress` when the
    /// top-level `egress.usage_sinks:` section configured one.
    /// `JsonlFile`, `Ledger`, and `Otel` never reach the network, so
    /// there is nothing here for an authorizer to gate.
    pub fn build(&self) -> std::sync::Arc<dyn UsageSink> {
        let egress = configured_gate(EgressPurpose::UsageSink);
        match self {
            UsageSinkConfig::JsonlFile { path } => std::sync::Arc::new(JsonlFileSink::new(path)),
            UsageSinkConfig::Webhook { url } => {
                let mut sink = WebhookSink::new(url);
                if let Some(authorizer) = &egress {
                    sink = sink.with_egress(authorizer.clone());
                }
                std::sync::Arc::new(sink)
            }
            UsageSinkConfig::Ledger {
                path,
                signing_seed_hex,
            } => crate::usage_ledger::LedgerSink::build(path, signing_seed_hex.as_deref()),
            UsageSinkConfig::Langfuse {
                host,
                public_key,
                secret_key,
            } => {
                let mut sink = LangfuseSink::new(host, public_key, secret_key);
                if let Some(authorizer) = &egress {
                    sink = sink.with_egress(authorizer.clone());
                }
                std::sync::Arc::new(sink)
            }
            UsageSinkConfig::Datadog {
                api_key,
                site,
                service,
            } => {
                let mut sink = DatadogSink::new(
                    site,
                    api_key,
                    service.clone().unwrap_or_else(|| "sbproxy".to_string()),
                );
                if let Some(authorizer) = &egress {
                    sink = sink.with_egress(authorizer.clone());
                }
                std::sync::Arc::new(sink)
            }
            UsageSinkConfig::Otel => std::sync::Arc::new(OtelSink::new()),
            UsageSinkConfig::S3 { bucket, prefix } => {
                let mut sink = ObjectStoreSink::s3(bucket, prefix);
                if let Some(authorizer) = &egress {
                    sink = sink.with_egress(authorizer.clone());
                }
                std::sync::Arc::new(sink)
            }
            UsageSinkConfig::Gcs { bucket, prefix } => {
                let mut sink = ObjectStoreSink::gcs(bucket, prefix);
                if let Some(authorizer) = &egress {
                    sink = sink.with_egress(authorizer.clone());
                }
                std::sync::Arc::new(sink)
            }
        }
    }
}

/// Build the runtime sinks for a list of configs.
pub fn build_sinks(configs: &[UsageSinkConfig]) -> Vec<std::sync::Arc<dyn UsageSink>> {
    configs.iter().map(UsageSinkConfig::build).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> LlmUsageEvent {
        LlmUsageEvent {
            provider: "openai".into(),
            model: "gpt-4o-mini".into(),
            prompt_tokens: 10,
            completion_tokens: 5,
            total_tokens: 15,
            cost_usd: 0.001,
            latency_ms: 200,
            status: 200,
            key_id: Some("k1".into()),
            tenant_id: None,
            project: None,
            user: None,
            team: None,
            tags: Vec::new(),
            metadata: std::collections::BTreeMap::new(),
            request_id: None,
            session_id: None,
            tag: None,
            priority: None,
            engine_version: None,
            agent_id: None,
            a2a_context_id: None,
            a2a_identity_verified: None,
            workflow_id: None,
            logical_model: None,
            served_model: None,
        }
    }

    /// A sample event carrying a verified agent identity (WOR-2140).
    fn agent_event() -> LlmUsageEvent {
        LlmUsageEvent {
            agent_id: Some("billing-orchestrator".into()),
            a2a_context_id: Some("ctx-run-7".into()),
            a2a_identity_verified: Some(true),
            ..sample_event()
        }
    }

    #[test]
    fn jsonl_file_sink_appends_parseable_events() {
        let path = std::env::temp_dir().join(format!("sb-usage-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let sink = JsonlFileSink::new(&path);
        sink.record(&sample_event());
        sink.record(&sample_event());

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2, "one JSON line per event");
        let parsed: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed["model"], "gpt-4o-mini");
        assert_eq!(parsed["total_tokens"], 15);
        // None fields are omitted, not serialized as null.
        assert!(parsed.get("user").is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn usage_event_preserves_safe_governed_attribution_fields() {
        let event: LlmUsageEvent = serde_json::from_value(serde_json::json!({
            "provider": "openai",
            "model": "gpt-4o-mini",
            "prompt_tokens": 10,
            "completion_tokens": 5,
            "total_tokens": 15,
            "cost_usd": 0.001,
            "latency_ms": 200,
            "status": 200,
            "key_id": "key-public-id",
            "tenant_id": "tenant-a",
            "project": "search",
            "user": "alice",
            "team": "platform",
            "tags": ["production", "chat"],
            "metadata": {"cost_center": "cc-42"}
        }))
        .expect("usage event with governed attribution");

        let value = serde_json::to_value(event).expect("serialize usage event");
        assert_eq!(value["key_id"], "key-public-id");
        assert_eq!(value["tenant_id"], "tenant-a");
        assert_eq!(value["project"], "search");
        assert_eq!(value["user"], "alice");
        assert_eq!(value["team"], "platform");
        assert_eq!(value["tags"], serde_json::json!(["production", "chat"]));
        assert_eq!(value["metadata"]["cost_center"], "cc-42");
    }

    #[test]
    fn engine_version_roundtrips_when_present() {
        let mut event = sample_event();
        event.engine_version = Some("0.11.0".to_string());

        let value = serde_json::to_value(&event).expect("serialize usage event");
        assert_eq!(value["engine_version"], "0.11.0");

        let back: LlmUsageEvent =
            serde_json::from_value(value).expect("deserialize usage event with engine_version");
        assert_eq!(back.engine_version.as_deref(), Some("0.11.0"));
    }

    #[test]
    fn engine_version_none_is_omitted_and_old_records_still_deserialize() {
        // None never serializes, so hosted-provider records keep their
        // pre-WOR-1906 wire shape byte-for-byte (the verifiable ledger
        // re-derives hashes from this serialization on replay).
        let value = serde_json::to_value(sample_event()).expect("serialize usage event");
        assert!(value.get("engine_version").is_none());

        // A record persisted before the field existed deserializes to None.
        let old: LlmUsageEvent = serde_json::from_value(serde_json::json!({
            "provider": "openai",
            "model": "gpt-4o-mini",
            "prompt_tokens": 10,
            "completion_tokens": 5,
            "total_tokens": 15,
            "cost_usd": 0.001,
            "latency_ms": 200,
            "status": 200
        }))
        .expect("old usage record without engine_version");
        assert!(old.engine_version.is_none());
    }

    /// WOR-2140: an event carrying agent identity round-trips through
    /// the exact serialize / deserialize pair the ledger's verifier uses
    /// on replay.
    #[test]
    fn agent_identity_round_trips() {
        let value = serde_json::to_value(agent_event()).expect("serialize usage event");
        assert_eq!(value["agent_id"], "billing-orchestrator");
        assert_eq!(value["a2a_context_id"], "ctx-run-7");
        assert_eq!(value["a2a_identity_verified"], true);

        let back: LlmUsageEvent =
            serde_json::from_value(value).expect("deserialize usage event with agent identity");
        assert_eq!(back.agent_id.as_deref(), Some("billing-orchestrator"));
        assert_eq!(back.a2a_context_id.as_deref(), Some("ctx-run-7"));
        assert_eq!(back.a2a_identity_verified, Some(true));
    }

    /// Verified, unverified, and "no claim at all" are three different
    /// states in the serialized event, not two.
    ///
    /// This is the whole reason the flag exists. An untrusted caller
    /// names its own agent and its own run, so a per-agent total that
    /// mixed the trusted rows with the self-declared ones would be a
    /// number the caller chose. `false` has to be visible on the wire,
    /// which means the flag cannot be skipped when it is false, and
    /// absent has to stay distinguishable from `false`, which is why it
    /// is an `Option<bool>` rather than a `bool` defaulting to false.
    #[test]
    fn verified_and_unverified_spend_are_distinguishable_on_the_wire() {
        let verified = serde_json::to_value(agent_event()).expect("serialize");
        assert_eq!(verified["a2a_identity_verified"], true);

        let mut untrusted = agent_event();
        untrusted.a2a_identity_verified = Some(false);
        let unverified = serde_json::to_value(&untrusted).expect("serialize");
        assert_eq!(
            unverified["a2a_identity_verified"], false,
            "a false flag must be written, not skipped as if it were absent"
        );
        // The spend itself is recorded either way: the money was really
        // spent, so dropping the row would under-report, and dropping
        // the id would lose which agent claimed it.
        assert_eq!(unverified["agent_id"], "billing-orchestrator");
        assert_eq!(unverified["cost_usd"], verified["cost_usd"]);

        // Non-agent traffic makes no claim, and that is a third state.
        let plain = serde_json::to_value(sample_event()).expect("serialize");
        assert!(
            plain.get("a2a_identity_verified").is_none(),
            "traffic with no agent envelope must not assert a trust value"
        );
    }

    /// The golden-fixture promise, asserted at the level this struct
    /// controls: an event with no agent fields serializes to exactly the
    /// bytes it did before the fields existed.
    ///
    /// `ledger_golden.rs` verifies two real files written by an older
    /// binary, which is the authoritative check. This one localises the
    /// failure: if the fields were inserted mid-struct, or shipped
    /// without `skip_serializing_if`, this test names the struct while
    /// the golden test can only say the chain broke.
    #[test]
    fn an_event_without_agent_fields_keeps_its_pre_wor2140_bytes() {
        // Copied verbatim out of the `event` object of the first line of
        // `tests/fixtures/ledger-v1-unsigned.jsonl`, which was written by
        // a binary that predates all of this.
        const LEGACY: &str = r#"{"provider":"openai","model":"gpt-4o-mini","prompt_tokens":10,"completion_tokens":5,"total_tokens":15,"cost_usd":1.0,"latency_ms":120,"status":200,"key_id":"k1","request_id":"req-0"}"#;

        // Parse then re-serialize is exactly what the ledger verifier
        // does before comparing against the bytes it hashed.
        let parsed: LlmUsageEvent = serde_json::from_str(LEGACY).expect("legacy record parses");
        assert!(parsed.agent_id.is_none());
        assert!(parsed.a2a_context_id.is_none());
        assert!(parsed.a2a_identity_verified.is_none());
        assert_eq!(
            serde_json::to_string(&parsed).expect("re-serialize"),
            LEGACY,
            "an event written before the agent fields existed must re-serialize \
             byte-identically, or every ledger already on disk stops verifying"
        );

        // Unset fields contribute no keys at all, which is the property
        // the assertion above depends on.
        let json = serde_json::to_string(&sample_event()).expect("serialize");
        for key in ["agent_id", "a2a_context_id", "a2a_identity_verified"] {
            assert!(!json.contains(key), "{key} must not appear when unset");
        }
    }

    /// The agent fields land at the END of the serialized object, after
    /// every field that predates them. Field order is part of the ledger
    /// file format, so this pins the one property that makes appending
    /// safe.
    #[test]
    fn agent_fields_serialize_after_every_older_field() {
        let mut event = agent_event();
        event.engine_version = Some("0.11.0".into());
        let json = serde_json::to_string(&event).expect("serialize");
        let at = |key: &str| json.find(key).unwrap_or_else(|| panic!("{key} missing"));
        assert!(at("\"engine_version\"") < at("\"agent_id\""));
        assert!(at("\"agent_id\"") < at("\"a2a_context_id\""));
        assert!(at("\"a2a_context_id\"") < at("\"a2a_identity_verified\""));
    }

    /// WOR-2140: agent attribution reaches the vendor sinks too, with
    /// the trust flag beside the ids rather than a hop away from them.
    #[test]
    fn vendor_sink_bodies_carry_agent_attribution() {
        let mut untrusted = agent_event();
        untrusted.a2a_identity_verified = Some(false);

        let body = langfuse_ingestion_body(&untrusted, "evt-2", "2026-08-01T00:00:00Z");
        let meta = &body["batch"][0]["body"]["metadata"];
        assert_eq!(meta["agent_id"], "billing-orchestrator");
        assert_eq!(meta["a2a_context_id"], "ctx-run-7");
        assert_eq!(meta["a2a_identity_verified"], false);

        let dd = datadog_log_body(&untrusted, "sbproxy-ai");
        let log = &dd[0];
        assert_eq!(log["agent_id"], "billing-orchestrator");
        assert_eq!(log["a2a_context_id"], "ctx-run-7");
        assert_eq!(log["a2a_identity_verified"], false);

        // Non-agent traffic adds no keys at all, so an existing
        // dashboard's facets do not gain an empty dimension.
        let plain = langfuse_ingestion_body(&sample_event(), "evt-3", "2026-08-01T00:00:00Z");
        let plain_meta = &plain["batch"][0]["body"]["metadata"];
        assert!(plain_meta.get("agent_id").is_none());
        assert!(plain_meta.get("a2a_identity_verified").is_none());
    }

    #[test]
    fn config_parses_and_builds_both_sink_types() {
        let cfgs: Vec<UsageSinkConfig> = serde_json::from_str(
            r#"[
                {"type":"jsonl_file","path":"/var/log/sb-usage.jsonl"},
                {"type":"webhook","url":"https://collector.example.com/ingest"}
            ]"#,
        )
        .unwrap();
        assert_eq!(cfgs.len(), 2);
        let sinks = build_sinks(&cfgs);
        assert_eq!(sinks[0].name(), "jsonl_file");
        assert_eq!(sinks[1].name(), "webhook");
    }

    #[test]
    fn ledger_sink_config_parses_with_and_without_seed() {
        let cfgs: Vec<UsageSinkConfig> = serde_json::from_str(
            r#"[
                {"type":"ledger","path":"/tmp/sb-x.jsonl"},
                {"type":"ledger","path":"/tmp/sb-y.jsonl","signing_seed_hex":"abcd"}
            ]"#,
        )
        .unwrap();
        assert_eq!(cfgs.len(), 2);
        match &cfgs[0] {
            UsageSinkConfig::Ledger {
                path,
                signing_seed_hex,
            } => {
                assert_eq!(path, "/tmp/sb-x.jsonl");
                assert!(signing_seed_hex.is_none(), "seed omitted parses as None");
            }
            other => panic!("expected ledger, got {other:?}"),
        }
        match &cfgs[1] {
            UsageSinkConfig::Ledger {
                signing_seed_hex, ..
            } => assert_eq!(signing_seed_hex.as_deref(), Some("abcd")),
            other => panic!("expected ledger, got {other:?}"),
        }
    }

    #[test]
    fn langfuse_body_shapes_a_generation_event() {
        let body = langfuse_ingestion_body(&sample_event(), "evt-1", "2026-06-26T00:00:00Z");
        let batch = body.get("batch").unwrap().as_array().unwrap();
        assert_eq!(batch.len(), 1);
        let item = &batch[0];
        assert_eq!(item["id"], "evt-1");
        assert_eq!(item["type"], "generation-create");
        assert_eq!(item["timestamp"], "2026-06-26T00:00:00Z");
        let b = &item["body"];
        assert_eq!(b["model"], "gpt-4o-mini");
        assert_eq!(b["usage"]["input"], 10);
        assert_eq!(b["usage"]["output"], 5);
        assert_eq!(b["usage"]["total"], 15);
        assert_eq!(b["usage"]["unit"], "TOKENS");
        assert_eq!(b["metadata"]["provider"], "openai");
        assert_eq!(b["metadata"]["key_id"], "k1");
    }

    #[test]
    fn datadog_body_carries_usage_attributes() {
        let body = datadog_log_body(&sample_event(), "sbproxy-ai");
        let arr = body.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        let log = &arr[0];
        assert_eq!(log["ddsource"], "sbproxy");
        assert_eq!(log["service"], "sbproxy-ai");
        assert_eq!(log["provider"], "openai");
        assert_eq!(log["model"], "gpt-4o-mini");
        assert_eq!(log["total_tokens"], 15);
        assert_eq!(log["status"], 200);
        assert_eq!(log["key_id"], "k1");
    }

    #[test]
    fn config_parses_and_builds_langfuse_and_datadog() {
        let cfgs: Vec<UsageSinkConfig> = serde_json::from_str(
            r#"[
                {"type":"langfuse","host":"https://cloud.langfuse.com","public_key":"pk","secret_key":"sk"},
                {"type":"datadog","api_key":"dd","site":"datadoghq.eu","service":"my-svc"}
            ]"#,
        )
        .unwrap();
        assert_eq!(cfgs.len(), 2);
        let sinks = build_sinks(&cfgs);
        assert_eq!(sinks[0].name(), "langfuse");
        assert_eq!(sinks[1].name(), "datadog");
    }

    #[test]
    fn datadog_site_and_service_default() {
        let cfgs: Vec<UsageSinkConfig> =
            serde_json::from_str(r#"[{"type":"datadog","api_key":"dd"}]"#).unwrap();
        match &cfgs[0] {
            UsageSinkConfig::Datadog { site, service, .. } => {
                assert_eq!(site, "datadoghq.com");
                assert!(service.is_none());
            }
            other => panic!("expected datadog, got {other:?}"),
        }
    }

    #[test]
    fn parses_otel_and_object_store_sink_configs() {
        let cfgs: Vec<UsageSinkConfig> = serde_json::from_str(
            r#"[
                {"type":"otel"},
                {"type":"s3","bucket":"usage","prefix":"llm/"},
                {"type":"gcs","bucket":"usage","prefix":"llm/"}
            ]"#,
        )
        .unwrap();
        assert_eq!(cfgs.len(), 3);
        match &cfgs[0] {
            UsageSinkConfig::Otel => {}
            other => panic!("expected otel, got {other:?}"),
        }
        match &cfgs[1] {
            UsageSinkConfig::S3 { bucket, prefix } => {
                assert_eq!(bucket, "usage");
                assert_eq!(prefix, "llm/");
            }
            other => panic!("expected s3, got {other:?}"),
        }
        match &cfgs[2] {
            UsageSinkConfig::Gcs { bucket, prefix } => {
                assert_eq!(bucket, "usage");
                assert_eq!(prefix, "llm/");
            }
            other => panic!("expected gcs, got {other:?}"),
        }
        let sinks = build_sinks(&cfgs);
        assert_eq!(sinks[0].name(), "otel");
        assert_eq!(sinks[1].name(), "s3");
        assert_eq!(sinks[2].name(), "gcs");
    }

    #[test]
    fn object_store_object_key_prefers_request_id_under_prefix() {
        let mut event = sample_event();
        event.request_id = Some("req-42".into());
        assert_eq!(object_store_object_key("llm/", &event), "llm/req-42.json");
        assert_eq!(object_store_object_key("llm", &event), "llm/req-42.json");
        assert_eq!(object_store_object_key("", &event), "req-42.json");
    }

    #[tokio::test]
    async fn sink_failure_does_not_panic_or_propagate() {
        // Broken / missing destinations must log and return: never panic or
        // surface an error that would break usage dispatch.
        let sinks = build_sinks(&[
            UsageSinkConfig::Otel,
            UsageSinkConfig::S3 {
                bucket: String::new(),
                prefix: "llm/".into(),
            },
            UsageSinkConfig::Gcs {
                bucket: String::new(),
                prefix: "llm/".into(),
            },
        ]);
        let event = sample_event();
        for sink in &sinks {
            sink.record(&event);
        }
    }

    /// Test resolver mapping a host to fixed addresses. Production
    /// sinks pass `CachedSystemResolver`.
    struct MapResolver {
        map: std::collections::HashMap<String, Vec<std::net::SocketAddr>>,
    }

    impl MapResolver {
        fn new(entries: Vec<(&str, Vec<std::net::SocketAddr>)>) -> Self {
            Self {
                map: entries
                    .into_iter()
                    .map(|(h, a)| (h.to_string(), a))
                    .collect(),
            }
        }
    }

    impl HostResolver for MapResolver {
        fn resolve(&self, host: &str, _port: u16) -> Result<Vec<std::net::SocketAddr>, ()> {
            self.map.get(host).cloned().ok_or(())
        }
    }

    fn public_addr(port: u16) -> std::net::SocketAddr {
        std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34)),
            port,
        )
    }

    fn enforce_purpose(purpose: EgressPurpose, hosts: &[&str]) -> EgressAuthorizer {
        use sbproxy_security::egress::{EgressConfig, PurposeAllowlist};
        use std::collections::HashMap;
        let mut allow = PurposeAllowlist::default();
        for h in hosts {
            allow.hosts.insert((*h).to_string());
        }
        allow.schemes.insert("https".to_string());
        allow.ports.insert(443);
        let mut purposes = HashMap::new();
        purposes.insert(purpose, allow);
        EgressAuthorizer::new(EgressConfig { purposes })
    }

    #[test]
    fn webhook_egress_denies_unlisted_host_with_shared_vocabulary() {
        let auth = enforce_purpose(EgressPurpose::Webhook, &["collector.example.com"]);
        let resolver = MapResolver::new(vec![("evil.example", vec![public_addr(443)])]);
        let err = authorize_usage_http(
            Some(&auth),
            EgressPurpose::Webhook,
            "https://evil.example/ingest",
            &resolver,
        )
        .expect_err("unlisted webhook host");
        assert_eq!(err, EgressDenied::UnlistedHost);
    }

    #[test]
    fn usage_sink_egress_denies_unlisted_host_with_shared_vocabulary() {
        let auth = enforce_purpose(EgressPurpose::UsageSink, &["cloud.langfuse.com"]);
        let resolver = MapResolver::new(vec![("evil.example", vec![public_addr(443)])]);
        let err = authorize_usage_http(
            Some(&auth),
            EgressPurpose::UsageSink,
            "https://evil.example/api/public/ingestion",
            &resolver,
        )
        .expect_err("unlisted usage-sink host");
        assert_eq!(err, EgressDenied::UnlistedHost);
    }

    #[test]
    fn usage_sink_egress_denies_a_listed_host_that_resolves_internal() {
        // Unreachable under the old fixed synthetic pin, which was
        // public for every host no matter what DNS actually said.
        let auth = enforce_purpose(EgressPurpose::UsageSink, &["collector.internal"]);
        let resolver = MapResolver::new(vec![(
            "collector.internal",
            vec![std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 5)),
                443,
            )],
        )]);
        assert_eq!(
            authorize_usage_http(
                Some(&auth),
                EgressPurpose::UsageSink,
                "https://collector.internal/api/public/ingestion",
                &resolver,
            )
            .unwrap_err(),
            EgressDenied::PrivateAddress
        );
    }

    #[test]
    fn omitted_egress_preserves_legacy_usage_sink_compatibility() {
        let resolver = MapResolver::new(vec![]);
        authorize_usage_http(
            None,
            EgressPurpose::Webhook,
            "https://evil.example/ingest",
            &resolver,
        )
        .expect("omitted egress must not deny, and must not even resolve");
    }

    #[test]
    fn enforce_webhook_sink_skips_post_when_denied() {
        // record() must not panic and must not attempt I/O when denied.
        let sink = WebhookSink::new("https://evil.example/ingest").with_egress(enforce_purpose(
            EgressPurpose::Webhook,
            &["collector.example.com"],
        ));
        sink.record(&sample_event());
    }

    #[test]
    fn config_build_arms_a_usage_sink_from_the_top_level_egress_registry() {
        // WOR-2476: proves the whole seam, not just the `with_egress`
        // builder in isolation. `UsageSinkConfig::build()` (what a
        // compiled `AiHandlerConfig` actually calls) reads the
        // process-wide `EgressPurpose::UsageSink` gate that
        // `sbproxy_config::compiler::compile_egress_gates` would install
        // from a `egress.usage_sinks.mode: deny_by_default` block, and
        // the resulting sink refuses to dispatch to a host outside it.
        sbproxy_security::egress::install_configured_gate(
            EgressPurpose::UsageSink,
            Some(enforce_purpose(
                EgressPurpose::UsageSink,
                &["collector.example.com"],
            )),
        );

        let sink = UsageSinkConfig::Webhook {
            url: "https://evil.example/ingest".to_string(),
        }
        .build();
        // Must not panic: a WebhookSink that dispatched would
        // `tokio::spawn` with no ambient runtime in this plain #[test].
        sink.record(&sample_event());

        let denied = sbproxy_security::egress::egress_inventory_snapshot()
            .into_iter()
            .find(|s| s.purpose == EgressPurpose::UsageSink.as_label() && s.host == "evil.example")
            .expect("the denied dispatch must be stamped in the inventory");
        assert_eq!(denied.status, "denied");

        sbproxy_security::egress::install_configured_gate(EgressPurpose::UsageSink, None);
    }

    #[test]
    fn config_build_leaves_a_usage_sink_ungated_when_the_registry_is_unset() {
        // WOR-2476: an omitted `egress.usage_sinks:` sub-block (nothing
        // installed in the registry) must preserve the exact legacy
        // ungated contract: `build()` returns a sink with no authorizer
        // attached, so `record()` proceeds. Guards the entry point tests
        // above depend on staying `None` by default.
        sbproxy_security::egress::install_configured_gate(EgressPurpose::UsageSink, None);

        let sink = UsageSinkConfig::Webhook {
            url: "https://evil.example/ingest".to_string(),
        }
        .build();
        assert!(
            configured_gate(EgressPurpose::UsageSink).is_none(),
            "test precondition: the registry must be unset"
        );
        // Building must not fail or panic; the sink is legacy ungated.
        let _ = sink;
    }

    /// One-shot loopback fixture serving `response` verbatim, reporting
    /// whether anything connected.
    fn dial_fixture(
        response: String,
    ) -> Option<(
        std::net::SocketAddr,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
    )> {
        use std::io::{Read, Write};
        use std::sync::atomic::{AtomicBool, Ordering};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
        let addr = listener.local_addr().ok()?;
        let hit = std::sync::Arc::new(AtomicBool::new(false));
        let hit_writer = std::sync::Arc::clone(&hit);
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                hit_writer.store(true, Ordering::SeqCst);
                let mut scratch = [0u8; 2048];
                let _ = stream.read(&mut scratch);
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        Some((addr, hit))
    }

    #[tokio::test]
    async fn usage_sink_refuses_a_cross_origin_redirect_hop() {
        use std::sync::atomic::Ordering;
        // The collector 302s the credential-bearing POST at a different
        // host. The hop must be refused and the second listener must
        // never see a connection.
        let Some((sink_addr, sink_hit)) = dial_fixture(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
        ) else {
            return;
        };
        let redirect = format!(
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/ingest\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            sink_addr.port()
        );
        let Some((collector_addr, collector_hit)) = dial_fixture(redirect) else {
            return;
        };

        let client = sink_client();
        let mut key = reqwest::header::HeaderValue::from_static("dd-secret");
        key.set_sensitive(true);
        let request = client
            .post(format!("http://{collector_addr}/api/v2/logs"))
            .header("DD-API-KEY", key)
            .json(&serde_json::json!([{"ddsource": "sbproxy"}]))
            .build()
            .expect("test request builds");

        let err = send_sink_post(
            &client,
            None,
            EgressPurpose::UsageSink,
            "datadog",
            "tenant-a",
            request,
        )
        .await
        .expect_err("a cross-origin hop must be refused, not followed");
        assert!(
            err.contains("RedirectToUnlistedHost"),
            "expected RedirectToUnlistedHost, got: {err}"
        );
        assert!(
            collector_hit.load(Ordering::SeqCst),
            "the configured collector must have served the redirect"
        );
        assert!(
            !sink_hit.load(Ordering::SeqCst),
            "the redirect target must never be contacted"
        );
    }

    /// Red-first: before this change, `ObjectStoreSink::record` called
    /// `object_store_put` with no `authorize_usage_http` call at all, so a
    /// bucket outside a configured allowlist was still dialed. The
    /// authorizer here only allows a different host, so the S3 put must
    /// be refused before `object_store_put` (and its `tokio::spawn`, which
    /// would panic in this non-`tokio::test` fn if reached) ever runs, and
    /// the refusal must land in the sightings inventory as `Denied`.
    #[test]
    fn enforce_object_store_sink_skips_put_when_denied() {
        let bucket = "wor-2476-denied-bucket";
        let sink = ObjectStoreSink::s3(bucket, "prefix").with_egress(enforce_purpose(
            EgressPurpose::UsageSink,
            &["allowed-bucket.s3.amazonaws.com"],
        ));

        // No panic: `object_store_put`'s `tokio::spawn` is never reached
        // outside a Tokio runtime, so reaching it here would abort the
        // test rather than merely fail an assertion.
        sink.record(&sample_event());

        let expected_host = format!("{bucket}.s3.amazonaws.com");
        let snapshot = sbproxy_security::egress::egress_inventory_snapshot();
        let entry = snapshot
            .iter()
            .find(|e| e.purpose == EgressPurpose::UsageSink.as_label() && e.host == expected_host)
            .expect("denied object-store destination must be stamped in the inventory");
        assert_eq!(entry.status, "denied");
        assert_eq!(
            entry.last_reason,
            Some(EgressDenied::UnlistedHost.as_label())
        );
    }

    /// An operator-configured S3 endpoint override must be authorized
    /// (and stamped) at its own real host, not the synthetic
    /// `<bucket>.s3.amazonaws.com` default (WOR-2476 follow-up).
    ///
    /// Builds the `AmazonS3Builder` explicitly via `with_config` rather
    /// than `AmazonS3Builder::from_env`: `sbproxy-ai` has no
    /// `EnvVarGuard` test helper, and `scripts/check-env-mutation.sh`
    /// restricts direct `set_var`/`remove_var` to the documented
    /// per-crate guards, so a real environment mutation is not an
    /// option here.
    #[test]
    fn s3_authorization_url_and_sighting_use_the_resolved_endpoint_override() {
        use object_store::aws::{AmazonS3Builder, AmazonS3ConfigKey};

        let bucket = "wor-2476-override-bucket";
        let override_host = "minio.internal.test";
        let builder = AmazonS3Builder::new().with_config(
            AmazonS3ConfigKey::Endpoint,
            format!("https://{override_host}"),
        );

        let url = s3_authorization_url(bucket, &builder);
        assert_eq!(
            url,
            format!("https://{override_host}"),
            "an endpoint override must be used as-is, not collapsed into \
             the synthetic <bucket>.s3.amazonaws.com default"
        );

        // The authorization decision itself must move with the URL: an
        // allowlist scoped to the synthetic default must not authorize
        // the real override host, and one scoped to the override host
        // must.
        let resolver = MapResolver::new(vec![(override_host, vec![public_addr(443)])]);
        let synthetic_host = format!("{bucket}.s3.amazonaws.com");
        let synthetic_only = enforce_purpose(EgressPurpose::UsageSink, &[synthetic_host.as_str()]);
        let err = authorize_usage_http(
            Some(&synthetic_only),
            EgressPurpose::UsageSink,
            &url,
            &resolver,
        )
        .expect_err("an allowlist scoped to the synthetic default must deny the real override");
        assert_eq!(err, EgressDenied::UnlistedHost);

        let override_allowed = enforce_purpose(EgressPurpose::UsageSink, &[override_host]);
        authorize_usage_http(
            Some(&override_allowed),
            EgressPurpose::UsageSink,
            &url,
            &resolver,
        )
        .expect("an allowlist scoped to the override host must authorize it");

        // And the sighting recorded for this destination must be keyed
        // by the override host, not the synthetic default.
        record_egress_seen(
            EgressPurpose::UsageSink,
            &url,
            "s3",
            EgressSightingStatus::Allowed,
            None,
        );
        let snapshot = sbproxy_security::egress::egress_inventory_snapshot();
        assert!(
            snapshot.iter().any(
                |e| e.purpose == EgressPurpose::UsageSink.as_label() && e.host == override_host
            ),
            "the override host must be stamped in the inventory"
        );
        assert!(
            !snapshot
                .iter()
                .any(|e| e.purpose == EgressPurpose::UsageSink.as_label()
                    && e.host == synthetic_host),
            "the synthetic default host must never be stamped once a real override resolves"
        );
    }

    /// `record()` must gate against the `auth_url` memoized at
    /// construction, never recompute it (WOR-2476 perf follow-up: a
    /// fresh `AmazonS3Builder::from_env()` per `record()` call is a
    /// full `std::env::vars_os()` scan on the request-logging hot path).
    ///
    /// Constructed via the struct literal rather than `ObjectStoreSink::s3`:
    /// `mod tests` is a child module of this file, so `ObjectStoreSink`'s
    /// private fields (including `auth_url`) are visible here, and that
    /// is the only way to plant an `auth_url` a fresh resolution could
    /// never produce. This test environment sets no `AWS_ENDPOINT_URL`,
    /// so `object_store_authorization_url` would resolve the synthetic
    /// `<bucket>.s3.amazonaws.com` default for this bucket if `record()`
    /// recomputed it; the sighting below is keyed by a different host
    /// entirely, so its presence is proof `record()` read the memoized
    /// field instead.
    #[test]
    fn record_gates_against_the_auth_url_memoized_at_construction() {
        let bucket = "wor-2476-memoized-bucket";
        let memoized_host = "already-resolved.internal.test";
        let sink = ObjectStoreSink {
            kind: ObjectStoreKind::S3,
            bucket: bucket.to_string(),
            prefix: "prefix".to_string(),
            egress: Some(enforce_purpose(
                EgressPurpose::UsageSink,
                &["allowed-elsewhere.example.com"],
            )),
            auth_url: format!("https://{memoized_host}"),
        };

        // No panic: the memoized host is denied by the authorizer above,
        // so `record()` returns before `object_store_put`'s
        // `tokio::spawn`, which would panic outside a Tokio runtime.
        sink.record(&sample_event());

        let snapshot = sbproxy_security::egress::egress_inventory_snapshot();
        let entry = snapshot
            .iter()
            .find(|e| e.purpose == EgressPurpose::UsageSink.as_label() && e.host == memoized_host)
            .expect("record() must gate against the memoized auth_url, not a fresh resolution");
        assert_eq!(entry.status, "denied");

        let synthetic_host = format!("{bucket}.s3.amazonaws.com");
        assert!(
            !snapshot
                .iter()
                .any(|e| e.purpose == EgressPurpose::UsageSink.as_label()
                    && e.host == synthetic_host),
            "record() must not recompute the synthetic default from a fresh environment scan"
        );
    }
}

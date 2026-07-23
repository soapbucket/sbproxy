//! LLM-backed classifier backend for the `type: classifier` guardrail.
//!
//! Asks an OpenAI-compatible `/chat/completions` endpoint to name the
//! class a prompt belongs to. The same config shape covers a hosted
//! provider (Anthropic, OpenAI) and a local runtime (Ollama, vLLM, LM
//! Studio); only `base_url`, `model`, and whether an API key is needed
//! differ.
//!
//! Two properties are load-bearing:
//!
//! 1. **The answer is constrained to the configured class set.** The
//!    model is told to reply with one of the configured class names or
//!    the literal `none`. Anything else it returns is discarded. A label
//!    that never appears in config must never reach the routing policy,
//!    because a CEL rule turns a label into a `route_to:<model>` and a
//!    hallucinated label would either dead-end the rule or, worse, match
//!    a rule the operator wrote for a different purpose.
//! 2. **No failure mode blocks a request.** A classifier is a routing
//!    hint, not a security control. Every failure mode (timeout,
//!    transport error, non-2xx, unparseable body, unrecognized class)
//!    yields no label and the request keeps its original routing.
//!    `fail_open` only changes the log level, never the outcome. Do not
//!    "fix" this into a blocking guard: use a `type: injection` or
//!    `type: regex` guardrail if you want something that can reject a
//!    request.
//!
//!    A *successful* label is a different matter, and it is the one
//!    thing an operator has to configure for. The mesh counts every
//!    guardrail that produced a label toward `flagged_count`, and
//!    [`super::mesh::GuardrailMeshConfig::block_threshold`] defaults to
//!    `1`, so under a default `mesh:` block a classified prompt is
//!    blocked with a 400 `guardrail_violation`. Label-only use, which is
//!    what routing wants, needs `block_threshold: 0` (optionally with
//!    `redact_on_flag: false`). This is the same rule the embedding
//!    backend has always been under; it is stated here because a
//!    classifier is the guardrail most likely to label a perfectly
//!    ordinary request.
//!
//! The HTTP call sits behind [`ChatCompletionsTransport`] so the
//! classification logic can be tested without a network.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::{json, Value as Json};
use sha2::{Digest, Sha256};
use tracing::{error, warn};

use super::classifier::{AsyncTextClassifier, ClassifierVerdict};

/// Reserved answer token meaning "no configured class fits". Also
/// rejected as a class name at construction time so an operator cannot
/// configure a class that collides with it.
const NONE_TOKEN: &str = "none";

/// Confidence reported for an LLM-assigned class.
///
/// A chat model answers with a discrete token and gives us no calibrated
/// probability, so there is nothing honest to put here but a constant.
/// The score exists because [`ClassifierVerdict`] is shared with the
/// embedding backend, where it is a real cosine similarity.
const LLM_VERDICT_SCORE: f32 = 1.0;

/// Upper bound on example prompts quoted per class in the instruction
/// block, so a large `classes` map cannot silently inflate every
/// classification call.
const MAX_EXAMPLES_PER_CLASS: usize = 10;

/// Upper bound on the characters of any single quoted example.
const MAX_EXAMPLE_CHARS: usize = 200;

fn default_llm_timeout_ms() -> u64 {
    2_000
}

fn default_llm_cache_capacity() -> usize {
    1_024
}

fn default_fail_open() -> bool {
    true
}

/// Config specific to the LLM backend: an OpenAI-compatible
/// chat-completions endpoint plus the model to ask.
///
/// ```yaml
/// backend:
///   kind: llm
///   base_url: http://localhost:11434/v1/chat/completions
///   model: qwen3-coder:30b
///   api_key: ${OPENAI_API_KEY}   # omit for a local runtime
///   timeout_ms: 2000
///   cache_capacity: 1024
///   fail_open: true
/// ```
#[derive(Clone, Deserialize)]
pub struct LlmBackendConfig {
    /// Full URL of the OpenAI-compatible chat-completions endpoint.
    /// This is the complete path, not a prefix: point it at
    /// `.../v1/chat/completions`, not `.../v1`.
    pub base_url: String,
    /// Model identifier sent as the `model` field of the request body.
    pub model: String,
    /// Bearer token for a hosted provider. Omit entirely for a local
    /// runtime that needs none. An empty value is a hard error, since it
    /// is wrong on every host. An unresolved `${VAR}`, which means the
    /// named variable was unset on *this* host, degrades this backend to
    /// inert and logs at `error!`: the classifier emits no label and
    /// every other guardrail on the origin keeps running. It is never
    /// sent as a literal bearer token.
    #[serde(default)]
    pub api_key: Option<String>,
    /// Per-call wall-clock timeout in milliseconds.
    #[serde(default = "default_llm_timeout_ms")]
    pub timeout_ms: u64,
    /// Capacity of the per-backend label cache, keyed by prompt text.
    #[serde(default = "default_llm_cache_capacity")]
    pub cache_capacity: usize,
    /// Log level for a failed classification: `true` (the default)
    /// warns, `false` logs at error. Both outcomes are the same: no
    /// label, and the request keeps its original routing. No failure
    /// mode of this backend blocks. A successful label is separate and
    /// does count toward the mesh quorum; see the module docs.
    #[serde(default = "default_fail_open")]
    pub fail_open: bool,
}

/// Stand-in printed wherever a secret would otherwise reach a log.
const REDACTED: &str = "[redacted]";

/// Hand-written so the resolved bearer token cannot reach a log.
///
/// `ChatCompletionsTransport` requires `Debug`, and the chain from
/// [`LlmClassifier`] up through [`super::GuardrailPipeline`] is `Debug`
/// throughout, so a single `debug!(?pipeline)` anywhere in the dispatch
/// path would otherwise print the key. Every other field stays visible,
/// since diagnosis is the whole point of `Debug` here.
impl std::fmt::Debug for LlmBackendConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlmBackendConfig")
            .field("base_url", &self.base_url)
            .field("model", &self.model)
            .field("api_key", &self.api_key.as_ref().map(|_| REDACTED))
            .field("timeout_ms", &self.timeout_ms)
            .field("cache_capacity", &self.cache_capacity)
            .field("fail_open", &self.fail_open)
            .finish()
    }
}

/// Why one classification call did not produce a usable body.
#[derive(Debug, thiserror::Error)]
pub enum ClassifierTransportError {
    /// The configured per-call timeout elapsed first.
    #[error("classifier LLM call timed out")]
    Timeout,
    /// A connection, TLS, or body-read failure.
    #[error("classifier LLM transport error: {0}")]
    Transport(String),
    /// The endpoint answered with a non-2xx status.
    #[error("classifier LLM endpoint returned HTTP {0}")]
    Status(u16),
}

/// One POST to an OpenAI-compatible chat-completions endpoint.
///
/// This is the seam the network sits behind: the classification logic
/// (prompt construction, reply matching, caching, failure handling) is
/// exercised in tests against a substitute transport, so none of it
/// needs a listening socket.
#[async_trait]
pub trait ChatCompletionsTransport: Send + Sync + std::fmt::Debug {
    /// POST `body` and return the raw response body on a 2xx.
    async fn post_chat(&self, body: Json) -> Result<String, ClassifierTransportError>;
}

/// The real transport: a `reqwest` client with the configured timeout
/// baked in and an optional bearer token.
pub struct ReqwestChatTransport {
    http: reqwest::Client,
    url: String,
    api_key: Option<String>,
}

/// Hand-written for the same reason as [`LlmBackendConfig`]'s: this type
/// holds the resolved bearer token, and `Debug` on it is reachable from
/// any `Debug` of the compiled guardrail pipeline.
impl std::fmt::Debug for ReqwestChatTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReqwestChatTransport")
            .field("http", &self.http)
            .field("url", &self.url)
            .field("api_key", &self.api_key.as_ref().map(|_| REDACTED))
            .finish()
    }
}

impl ReqwestChatTransport {
    /// Build a transport for `url`, bounded by `timeout`.
    ///
    /// The timeout lives on the client rather than per request so a
    /// hung endpoint cannot outlive the operator's configured budget.
    pub fn new(url: String, api_key: Option<String>, timeout: Duration) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| anyhow!("classifier LLM HTTP client builder failed: {e}"))?;
        Ok(Self { http, url, api_key })
    }
}

#[async_trait]
impl ChatCompletionsTransport for ReqwestChatTransport {
    async fn post_chat(&self, body: Json) -> Result<String, ClassifierTransportError> {
        let mut request = self
            .http
            .post(&self.url)
            .header("content-type", "application/json");
        if let Some(key) = &self.api_key {
            request = request.header("authorization", format!("Bearer {key}"));
        }
        let response = match request.json(&body).send().await {
            Ok(r) => r,
            Err(e) if e.is_timeout() => return Err(ClassifierTransportError::Timeout),
            Err(e) => return Err(ClassifierTransportError::Transport(e.to_string())),
        };
        let status = response.status();
        if !status.is_success() {
            return Err(ClassifierTransportError::Status(status.as_u16()));
        }
        response
            .text()
            .await
            .map_err(|e| ClassifierTransportError::Transport(format!("read body failed: {e}")))
    }
}

/// Classifier that asks an LLM which class a prompt belongs to.
#[derive(Debug)]
pub struct LlmClassifier {
    transport: Arc<dyn ChatCompletionsTransport>,
    /// Model identifier sent on every request body.
    model: String,
    /// Configured class names in config order, spelled exactly as the
    /// operator wrote them. A match returns this spelling, never the
    /// model's echo, so a case difference cannot produce a label the
    /// policy plane has never seen.
    classes: Vec<String>,
    /// Pre-rendered system prompt: the class list plus the few-shot
    /// examples. Built once at construction rather than per request.
    instructions: String,
    /// Prompt text to outcome, so a repeated prompt costs no network
    /// call. `None` (no class matched) is cached too, since a repeat of
    /// an unclassifiable prompt should not re-ask either. Failures are
    /// deliberately NOT cached: a timeout is transient and caching it
    /// would suppress classification for as long as the entry lived.
    cache: Mutex<lru::LruCache<[u8; 32], Option<ClassifierVerdict>>>,
    /// Log level selector for failures. See [`LlmBackendConfig::fail_open`].
    fail_open: bool,
    /// Endpoint host, attached to failure logs so an operator can tell
    /// which classifier is misbehaving without the full URL in the log.
    endpoint_label: String,
}

impl LlmClassifier {
    /// Build from config, over a real HTTP transport.
    ///
    /// Returns `Err` for config that is wrong on every host: a malformed
    /// `base_url`, an empty `model`, an empty `classes` map, a class
    /// named `none`, an empty `api_key`. Those an operator has to fix,
    /// and they fail the same way everywhere.
    ///
    /// Returns `Ok(None)` for the one failure that is host-specific: an
    /// `api_key` still holding the literal `${VAR}`, which means the
    /// named variable was unset when this config loaded. The caller must
    /// degrade the guardrail to inert in that case, exactly as the
    /// embedding backend degrades when its model file is missing. An
    /// `Err` there would abort `compile_pipeline` and take the PII,
    /// injection, and regex guardrails configured alongside this one
    /// down with it, turning one unset variable into an origin with no
    /// guardrails at all. A routing hint must never be able to do that.
    pub fn from_config(
        cfg: &LlmBackendConfig,
        classes: &BTreeMap<String, Vec<String>>,
    ) -> Result<Option<Self>> {
        let url = url::Url::parse(cfg.base_url.trim()).map_err(|e| {
            anyhow!(
                "classifier `llm` backend has an invalid base_url {:?}: {e}",
                cfg.base_url
            )
        })?;
        if cfg.model.trim().is_empty() {
            return Err(anyhow!(
                "classifier `llm` backend needs a non-empty `model`"
            ));
        }
        // Ahead of the key, so a config that is also shape-wrong still
        // fails loud rather than being masked by the inert path.
        validate_classes(classes)?;
        let api_key = match resolve_api_key(cfg.api_key.as_deref())? {
            ApiKey::Resolved(key) => key,
            ApiKey::Unresolved(var) => {
                // error!, not warn!: unlike a model file that may
                // legitimately be absent on a given host, an unset key
                // variable is nearly always a deployment mistake.
                error!(
                    endpoint = %endpoint_label_of(&cfg.base_url),
                    model = %cfg.model.trim(),
                    variable = %var,
                    "classifier `llm` backend api_key is still an unresolved reference, \
                     so the named environment variable was unset at config load; this \
                     classifier is inert and emits no label, while every other guardrail \
                     on this origin keeps running. Set the variable or remove `api_key`"
                );
                return Ok(None);
            }
        };
        let transport = ReqwestChatTransport::new(
            url.to_string(),
            api_key,
            Duration::from_millis(cfg.timeout_ms),
        )?;
        Self::with_transport(cfg, classes, Arc::new(transport)).map(Some)
    }

    /// Build over a caller-supplied transport. Used by the tests, and
    /// by any embedding of the proxy that already owns an HTTP client.
    pub fn with_transport(
        cfg: &LlmBackendConfig,
        classes: &BTreeMap<String, Vec<String>>,
        transport: Arc<dyn ChatCompletionsTransport>,
    ) -> Result<Self> {
        validate_classes(classes)?;
        // A configured 0 means "no cache"; the smallest legal LRU is the
        // closest honest reading of that, and every larger value is
        // already non-zero.
        let capacity = NonZeroUsize::new(cfg.cache_capacity).unwrap_or(NonZeroUsize::MIN);
        Ok(Self {
            transport,
            model: cfg.model.trim().to_string(),
            classes: classes.keys().cloned().collect(),
            instructions: build_instructions(classes),
            cache: Mutex::new(lru::LruCache::new(capacity)),
            fail_open: cfg.fail_open,
            endpoint_label: endpoint_label_of(&cfg.base_url),
        })
    }

    /// The request body for one classification call.
    fn request_body(&self, text: &str) -> Json {
        json!({
            "model": self.model,
            // A routing decision should not wander between identical
            // prompts. Note that a reasoning model which rejects an
            // explicit temperature answers non-2xx, which lands on the
            // no-label path like any other failure.
            "temperature": 0,
            "stream": false,
            "messages": [
                {"role": "system", "content": self.instructions},
                {"role": "user", "content": text},
            ],
        })
    }

    fn cache_get(&self, key: &[u8; 32]) -> Option<Option<ClassifierVerdict>> {
        let mut guard = self.cache.lock();
        guard.get(key).cloned()
    }

    fn cache_put(&self, key: [u8; 32], verdict: Option<ClassifierVerdict>) {
        let mut guard = self.cache.lock();
        guard.put(key, verdict);
    }

    /// Log a failed classification. The outcome is always the same (no
    /// label); `fail_open` only picks the level, so a fail-closed
    /// operator gets an alertable error line without the request being
    /// blocked on a routing hint.
    fn report_failure(&self, detail: &str) {
        if self.fail_open {
            warn!(
                endpoint = %self.endpoint_label,
                model = %self.model,
                detail = %detail,
                "classifier LLM call failed; no label emitted and the request keeps \
                 its original routing"
            );
        } else {
            error!(
                endpoint = %self.endpoint_label,
                model = %self.model,
                detail = %detail,
                "classifier LLM call failed; no label emitted and the request keeps \
                 its original routing (fail_open: false raises the level only, it \
                 never blocks the request)"
            );
        }
    }
}

#[async_trait]
impl AsyncTextClassifier for LlmClassifier {
    async fn classify(&self, text: &str) -> Option<ClassifierVerdict> {
        let key = prompt_key(text);
        if let Some(hit) = self.cache_get(&key) {
            return hit;
        }
        let raw = match self.transport.post_chat(self.request_body(text)).await {
            Ok(body) => body,
            Err(e) => {
                self.report_failure(&e.to_string());
                return None;
            }
        };
        let Some(reply) = extract_reply(&raw) else {
            self.report_failure("response had no choices[0].message.content string");
            return None;
        };
        let verdict = match_class(&reply, &self.classes).map(|label| ClassifierVerdict {
            label,
            score: LLM_VERDICT_SCORE,
        });
        if verdict.is_none() && normalize_reply(&reply) != NONE_TOKEN {
            // An answer outside the configured set is the case that
            // must never become a label. Log it so a bad prompt or a
            // chatty model is visible rather than silently degrading
            // routing.
            warn!(
                endpoint = %self.endpoint_label,
                model = %self.model,
                "classifier LLM answered with something outside the configured class \
                 set; treating it as no label"
            );
        }
        self.cache_put(key, verdict.clone());
        verdict
    }
}

/// Content-addressed cache key over the prompt text.
///
/// The model, endpoint, and class set are fixed for the life of one
/// [`LlmClassifier`], and a config change builds a new one, so the
/// prompt alone distinguishes entries within a single instance.
fn prompt_key(text: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(text.as_bytes());
    h.finalize().into()
}

/// Reject a class map that is wrong on every host.
///
/// Split out of [`LlmClassifier::with_transport`] so
/// [`LlmClassifier::from_config`] can run it before the API key is
/// resolved: a config that is both shape-wrong and key-unresolved has to
/// report the shape error rather than quietly taking the inert path.
fn validate_classes(classes: &BTreeMap<String, Vec<String>>) -> Result<()> {
    if classes.is_empty() {
        return Err(anyhow!(
            "classifier `llm` backend needs at least one entry under `classes`"
        ));
    }
    if let Some(bad) = classes
        .keys()
        .find(|k| normalize_reply(k.as_str()) == NONE_TOKEN)
    {
        return Err(anyhow!(
            "classifier class name {bad:?} collides with the reserved `none` answer \
             token that means no class fits; rename the class"
        ));
    }
    Ok(())
}

/// What resolving the configured `api_key` produced.
#[derive(Debug)]
enum ApiKey {
    /// Nothing was configured, or the configured value is a real key.
    Resolved(Option<String>),
    /// The value is still the literal `${VAR}`. Carries the variable
    /// name, which is the only useful thing to put in the log.
    Unresolved(String),
}

/// Resolve the configured API key, never sending an unresolved
/// reference as a bearer token.
///
/// The config loader interpolates `${VAR}` at load time and leaves the
/// literal `${VAR}` in place when the variable is unset. Passing that
/// through as a bearer token would produce a confusing 401 per request,
/// so it is reported to the caller as [`ApiKey::Unresolved`], which
/// degrades the backend to inert. An empty key is a different case: no
/// host can make that right, so it stays a hard error.
fn resolve_api_key(raw: Option<&str>) -> Result<ApiKey> {
    let Some(raw) = raw else {
        return Ok(ApiKey::Resolved(None));
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!(
            "classifier `llm` backend has an empty `api_key`; omit the field entirely \
             for an endpoint that needs no key"
        ));
    }
    if trimmed.starts_with("${") && trimmed.ends_with('}') {
        let name = &trimmed[2..trimmed.len() - 1];
        return Ok(ApiKey::Unresolved(name.to_string()));
    }
    Ok(ApiKey::Resolved(Some(trimmed.to_string())))
}

/// Host of the configured endpoint, for logs.
fn endpoint_label_of(base_url: &str) -> String {
    url::Url::parse(base_url.trim())
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_else(|| "unknown".to_string())
}

/// Render the system prompt: the closed class list, the `none` escape
/// hatch, and the configured examples as few-shot guidance.
fn build_instructions(classes: &BTreeMap<String, Vec<String>>) -> String {
    let names: Vec<&str> = classes.keys().map(|k| k.as_str()).collect();
    let mut out = String::new();
    out.push_str(
        "You are a request classifier. Read the user request and decide which single \
         class it belongs to.\n\n",
    );
    out.push_str("Valid classes: ");
    out.push_str(&names.join(", "));
    out.push_str("\n\n");
    out.push_str(
        "Answer with exactly one class name from that list and nothing else: no \
         punctuation, no explanation, no reasoning. If no class fits, answer with \
         exactly: none\n",
    );
    for (label, examples) in classes {
        let quoted: Vec<String> = examples
            .iter()
            .take(MAX_EXAMPLES_PER_CLASS)
            .map(|e| {
                let trimmed: String = e.trim().chars().take(MAX_EXAMPLE_CHARS).collect();
                format!("- {trimmed}")
            })
            .filter(|line| line.len() > 2)
            .collect();
        if quoted.is_empty() {
            continue;
        }
        out.push_str(&format!("\nRequests in class \"{label}\" look like:\n"));
        out.push_str(&quoted.join("\n"));
        out.push('\n');
    }
    out
}

/// Pull the assistant's answer out of a chat-completions response.
fn extract_reply(raw: &str) -> Option<String> {
    let parsed: Json = serde_json::from_str(raw).ok()?;
    parsed
        .pointer("/choices/0/message/content")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Lowercase and strip the punctuation a chat model tends to wrap an
/// answer in, so `"Coding."` and `` `coding` `` both compare equal to
/// `coding`.
fn normalize_reply(reply: &str) -> String {
    reply
        .trim()
        .trim_matches(|c: char| {
            c.is_whitespace()
                || c == '"'
                || c == '\''
                || c == '`'
                || c == '.'
                || c == ','
                || c == ':'
                || c == ';'
                || c == '*'
                || c == '#'
        })
        .to_lowercase()
}

/// Map a model reply onto one of the configured class names.
///
/// Returns `None` for the `none` token, for an empty answer, and for
/// anything that is not a configured class. That last case is the whole
/// point: a label the operator never configured must never reach the
/// routing policy, so an unrecognized answer is dropped rather than
/// passed through.
///
/// Two candidates are considered, in order: the whole reply, and its
/// last non-empty line (which is where a model that narrates first puts
/// its answer). Both are gated on the same class-set membership, so the
/// extra candidate can never widen the set of labels that can escape.
fn match_class(reply: &str, classes: &[String]) -> Option<String> {
    let mut candidates = vec![normalize_reply(reply)];
    if let Some(last) = reply.lines().rev().find(|l| !l.trim().is_empty()) {
        let normalized = normalize_reply(last);
        if !candidates.contains(&normalized) {
            candidates.push(normalized);
        }
    }
    for candidate in candidates {
        if candidate.is_empty() || candidate == NONE_TOKEN {
            return None;
        }
        if let Some(hit) = classes
            .iter()
            .find(|c| normalize_reply(c.as_str()) == candidate)
        {
            return Some(hit.clone());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// What the fake transport does when it is called.
    ///
    /// [`ClassifierTransportError`] is not `Clone`, so the outcome is
    /// stored as a description and the error is built per call.
    #[derive(Debug)]
    enum FakeOutcome {
        Body(String),
        Timeout,
        Status(u16),
        Transport(String),
    }

    /// Transport that answers with a canned body (or a canned failure)
    /// and records what it was asked, so tests can assert both the
    /// request shape and the call count without a socket.
    #[derive(Debug)]
    struct FakeTransport {
        outcome: FakeOutcome,
        calls: AtomicUsize,
        bodies: Mutex<Vec<Json>>,
    }

    impl FakeTransport {
        fn with_outcome(outcome: FakeOutcome) -> Self {
            Self {
                outcome,
                calls: AtomicUsize::new(0),
                bodies: Mutex::new(Vec::new()),
            }
        }

        fn answering(body: String) -> Self {
            Self::with_outcome(FakeOutcome::Body(body))
        }

        fn failing() -> Self {
            Self::with_outcome(FakeOutcome::Timeout)
        }

        fn returning_status(code: u16) -> Self {
            Self::with_outcome(FakeOutcome::Status(code))
        }

        fn failing_transport(detail: &str) -> Self {
            Self::with_outcome(FakeOutcome::Transport(detail.to_string()))
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl ChatCompletionsTransport for FakeTransport {
        async fn post_chat(&self, body: Json) -> Result<String, ClassifierTransportError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.bodies.lock().push(body);
            match &self.outcome {
                FakeOutcome::Body(r) => Ok(r.clone()),
                FakeOutcome::Timeout => Err(ClassifierTransportError::Timeout),
                FakeOutcome::Status(code) => Err(ClassifierTransportError::Status(*code)),
                FakeOutcome::Transport(detail) => {
                    Err(ClassifierTransportError::Transport(detail.clone()))
                }
            }
        }
    }

    /// A chat-completions response whose assistant message says `content`.
    fn chat_reply(content: &str) -> String {
        json!({"choices": [{"message": {"content": content}}]}).to_string()
    }

    fn classes() -> BTreeMap<String, Vec<String>> {
        BTreeMap::from([
            (
                "coding".to_string(),
                vec!["refactor the parser".to_string()],
            ),
            (
                "documentation".to_string(),
                vec!["write the readme".to_string()],
            ),
        ])
    }

    fn cfg() -> LlmBackendConfig {
        LlmBackendConfig {
            base_url: "http://localhost:11434/v1/chat/completions".to_string(),
            model: "qwen3-coder:30b".to_string(),
            api_key: None,
            timeout_ms: 2_000,
            cache_capacity: 16,
            fail_open: true,
        }
    }

    fn classifier(transport: Arc<FakeTransport>) -> LlmClassifier {
        LlmClassifier::with_transport(&cfg(), &classes(), transport).expect("builds")
    }

    #[tokio::test]
    async fn configured_class_reply_produces_that_label() {
        let t = Arc::new(FakeTransport::answering(chat_reply("documentation")));
        let c = classifier(t.clone());
        let v = c
            .classify("write the readme section")
            .await
            .expect("verdict");
        assert_eq!(v.label, "documentation");
        assert_eq!(t.calls(), 1);
    }

    #[tokio::test]
    async fn unconfigured_class_reply_produces_no_label() {
        // The load-bearing case: a label that is not in `classes` must
        // never reach the routing policy.
        let t = Arc::new(FakeTransport::answering(chat_reply("legal_review")));
        let c = classifier(t);
        assert!(c.classify("draft the contract").await.is_none());
    }

    #[tokio::test]
    async fn none_reply_produces_no_label() {
        let t = Arc::new(FakeTransport::answering(chat_reply("none")));
        let c = classifier(t);
        assert!(c.classify("what is the weather").await.is_none());
    }

    #[tokio::test]
    async fn transport_failure_produces_no_label_and_no_error() {
        let t = Arc::new(FakeTransport::failing());
        let c = classifier(t.clone());
        // No panic, no error escaping: a timeout is just no label.
        assert!(c.classify("write the readme").await.is_none());
        assert_eq!(t.calls(), 1);
    }

    #[tokio::test]
    async fn transport_failure_is_not_cached() {
        // A transient timeout must not suppress classification for
        // every later copy of the same prompt.
        let t = Arc::new(FakeTransport::failing());
        let c = classifier(t.clone());
        assert!(c.classify("same prompt").await.is_none());
        assert!(c.classify("same prompt").await.is_none());
        assert_eq!(t.calls(), 2, "a failure must not populate the cache");
    }

    #[tokio::test]
    async fn a_non_2xx_status_produces_no_label_and_is_not_cached() {
        // A 503 from an overloaded endpoint is transient in exactly the
        // way a timeout is, so it must not poison the cache either.
        let t = Arc::new(FakeTransport::returning_status(503));
        let c = classifier(t.clone());
        assert!(c.classify("write the readme").await.is_none());
        assert!(c.classify("write the readme").await.is_none());
        assert_eq!(t.calls(), 2, "a non-2xx must not populate the cache");
    }

    #[tokio::test]
    async fn a_transport_error_produces_no_label_and_is_not_cached() {
        let t = Arc::new(FakeTransport::failing_transport("connection refused"));
        let c = classifier(t.clone());
        assert!(c.classify("write the readme").await.is_none());
        assert!(c.classify("write the readme").await.is_none());
        assert_eq!(
            t.calls(),
            2,
            "a transport error must not populate the cache"
        );
    }

    #[test]
    fn every_transport_error_names_itself_in_its_message() {
        assert!(ClassifierTransportError::Timeout
            .to_string()
            .contains("timed out"));
        assert!(ClassifierTransportError::Status(503)
            .to_string()
            .contains("503"));
        assert!(
            ClassifierTransportError::Transport("connection refused".to_string())
                .to_string()
                .contains("connection refused")
        );
    }

    #[tokio::test]
    async fn unparseable_body_produces_no_label() {
        let t = Arc::new(FakeTransport::answering("this is not JSON".to_string()));
        let c = classifier(t);
        assert!(c.classify("write the readme").await.is_none());
    }

    #[tokio::test]
    async fn an_empty_choices_array_produces_no_label() {
        // Well-formed JSON with nothing to read: the pointer lookup has
        // to miss rather than panic or invent a label.
        let t = Arc::new(FakeTransport::answering(json!({"choices": []}).to_string()));
        let c = classifier(t.clone());
        assert!(c.classify("write the readme").await.is_none());
        assert_eq!(t.calls(), 1);
    }

    #[tokio::test]
    async fn repeated_prompt_is_served_from_cache() {
        let t = Arc::new(FakeTransport::answering(chat_reply("coding")));
        let c = classifier(t.clone());
        let first = c.classify("refactor the parser").await.expect("verdict");
        let second = c.classify("refactor the parser").await.expect("verdict");
        assert_eq!(first.label, second.label);
        assert_eq!(t.calls(), 1, "a repeated prompt must not re-call the model");
    }

    #[tokio::test]
    async fn a_no_label_answer_is_cached_too() {
        let t = Arc::new(FakeTransport::answering(chat_reply("none")));
        let c = classifier(t.clone());
        assert!(c.classify("small talk").await.is_none());
        assert!(c.classify("small talk").await.is_none());
        assert_eq!(t.calls(), 1);
    }

    #[tokio::test]
    async fn label_uses_the_configured_spelling_not_the_model_echo() {
        // The class is configured with a capital D and the model echoes
        // it lowercased and punctuated. The two spellings have to differ
        // for this assertion to discriminate: with a class already
        // spelled "documentation" it would pass whether the code
        // returned the config string or the normalized echo, and the
        // property is that the operator's spelling wins. It matters
        // because the label is what a CEL rule matches on to pick a
        // route.
        let configured = BTreeMap::from([(
            "Documentation".to_string(),
            vec!["write the readme".to_string()],
        )]);
        let t = Arc::new(FakeTransport::answering(chat_reply(
            "  \"documentation.\" ",
        )));
        let c = LlmClassifier::with_transport(&cfg(), &configured, t).expect("builds");
        let v = c.classify("write the readme").await.expect("verdict");
        assert_eq!(v.label, "Documentation", "config spelling wins");
    }

    #[tokio::test]
    async fn a_narrated_answer_still_resolves_from_its_last_line() {
        let t = Arc::new(FakeTransport::answering(chat_reply(
            "Let me think about this.\ncoding",
        )));
        let c = classifier(t);
        let v = c.classify("refactor the parser").await.expect("verdict");
        assert_eq!(v.label, "coding");
    }

    #[tokio::test]
    async fn request_body_carries_the_model_and_the_few_shot_examples() {
        let t = Arc::new(FakeTransport::answering(chat_reply("coding")));
        let c = classifier(t.clone());
        let _ = c.classify("refactor the parser").await;
        let bodies = t.bodies.lock();
        let body = bodies.first().expect("one call recorded");
        assert_eq!(body["model"], "qwen3-coder:30b");
        let system = body["messages"][0]["content"]
            .as_str()
            .expect("system message");
        assert!(system.contains("coding"), "class list: {system}");
        assert!(system.contains("documentation"), "class list: {system}");
        assert!(
            system.contains("write the readme"),
            "few-shot examples: {system}"
        );
        assert!(system.contains("none"), "none escape hatch: {system}");
        assert_eq!(body["messages"][1]["content"], "refactor the parser");
    }

    #[test]
    fn unresolved_api_key_degrades_the_backend_to_inert() {
        // An unset `${VAR}` survives config interpolation verbatim.
        // Sending it as a bearer token would 401 on every request, but
        // erroring here would abort `compile_pipeline` and disable every
        // other guardrail on the origin, so the backend goes inert
        // instead. `mod.rs` pins the pipeline-level half of this.
        let mut c = cfg();
        c.api_key = Some("${SBPROXY_TEST_CLASSIFIER_KEY_UNSET}".to_string());
        let built = LlmClassifier::from_config(&c, &classes())
            .expect("an unset key is not a hard config error");
        assert!(
            built.is_none(),
            "an unresolved key must yield no backend, not an authenticated one"
        );
    }

    #[test]
    fn a_shape_error_still_wins_over_an_unresolved_api_key() {
        // Both wrong at once: the class map is wrong on every host, so
        // that has to be the reported outcome rather than a quiet
        // degrade to inert.
        let mut c = cfg();
        c.api_key = Some("${SBPROXY_TEST_CLASSIFIER_KEY_UNSET}".to_string());
        assert!(LlmClassifier::from_config(&c, &BTreeMap::new()).is_err());
    }

    #[test]
    fn empty_api_key_is_a_hard_config_error() {
        // Unlike an unresolved reference, an empty key is wrong on every
        // host, so it stays loud.
        let mut c = cfg();
        c.api_key = Some("   ".to_string());
        assert!(LlmClassifier::from_config(&c, &classes()).is_err());
    }

    // Inside a runtime because this is the one construction test that
    // reaches the real `reqwest::Client` builder.
    #[tokio::test]
    async fn absent_api_key_is_fine_for_a_local_runtime() {
        let built = LlmClassifier::from_config(&cfg(), &classes()).expect("builds");
        assert!(built.is_some());
    }

    #[tokio::test]
    async fn debug_never_prints_the_api_key() {
        // Nothing logs the pipeline today, but the whole chain from this
        // transport up to `GuardrailPipeline` is `Debug`, so one
        // `debug!(?pipeline)` would otherwise print a bearer token.
        const SECRET: &str = "sk-do-not-log-me-0123456789";
        let mut c = cfg();
        c.api_key = Some(SECRET.to_string());
        let rendered = format!("{c:?}");
        assert!(
            !rendered.contains(SECRET),
            "config Debug leaked: {rendered}"
        );
        assert!(rendered.contains(REDACTED), "config Debug: {rendered}");
        // The other fields stay visible; Debug exists to diagnose.
        assert!(rendered.contains("qwen3-coder:30b"), "{rendered}");

        let transport = ReqwestChatTransport::new(
            c.base_url.clone(),
            Some(SECRET.to_string()),
            Duration::from_millis(c.timeout_ms),
        )
        .expect("transport builds");
        let rendered = format!("{transport:?}");
        assert!(
            !rendered.contains(SECRET),
            "transport Debug leaked: {rendered}"
        );
        assert!(rendered.contains(REDACTED), "transport Debug: {rendered}");
        assert!(rendered.contains("localhost"), "{rendered}");
    }

    #[test]
    fn invalid_base_url_is_a_hard_config_error() {
        let mut c = cfg();
        c.base_url = "not a url".to_string();
        assert!(LlmClassifier::from_config(&c, &classes()).is_err());
    }

    #[test]
    fn a_class_named_none_is_rejected() {
        let reserved = BTreeMap::from([("None".to_string(), vec!["anything".to_string()])]);
        let t: Arc<dyn ChatCompletionsTransport> =
            Arc::new(FakeTransport::answering(chat_reply("none")));
        assert!(LlmClassifier::with_transport(&cfg(), &reserved, t).is_err());
        assert!(LlmClassifier::from_config(&cfg(), &reserved).is_err());
    }

    #[test]
    fn empty_class_map_is_rejected() {
        let t: Arc<dyn ChatCompletionsTransport> =
            Arc::new(FakeTransport::answering(chat_reply("none")));
        assert!(LlmClassifier::with_transport(&cfg(), &BTreeMap::new(), t).is_err());
        assert!(LlmClassifier::from_config(&cfg(), &BTreeMap::new()).is_err());
    }

    #[test]
    fn match_class_only_returns_configured_names() {
        // Configured with capitals so every positive assertion tells the
        // operator's spelling apart from the model's echo: a normalized
        // echo would return "coding", not "Coding".
        let names = vec!["Coding".to_string(), "Documentation".to_string()];
        assert_eq!(match_class("Coding", &names).as_deref(), Some("Coding"));
        assert_eq!(match_class("coding", &names).as_deref(), Some("Coding"));
        assert_eq!(match_class("CODING", &names).as_deref(), Some("Coding"));
        assert_eq!(match_class("`coding`", &names).as_deref(), Some("Coding"));
        assert_eq!(
            match_class("documentation.", &names).as_deref(),
            Some("Documentation")
        );
        assert_eq!(
            match_class("Thinking it over.\ndocumentation", &names).as_deref(),
            Some("Documentation")
        );
        assert!(match_class("none", &names).is_none());
        assert!(match_class("NONE", &names).is_none());
        assert!(match_class("", &names).is_none());
        assert!(match_class("legal_review", &names).is_none());
        assert!(match_class("code", &names).is_none());
    }

    #[test]
    fn defaults_match_the_documented_config() {
        let parsed: LlmBackendConfig = serde_json::from_value(json!({
            "base_url": "http://localhost:11434/v1/chat/completions",
            "model": "qwen3-coder:30b",
        }))
        .expect("minimal config parses");
        assert_eq!(parsed.timeout_ms, 2_000);
        assert_eq!(parsed.cache_capacity, 1_024);
        assert!(parsed.fail_open, "fail_open defaults to true");
        assert!(parsed.api_key.is_none());
    }
}

//! MessagePack wire types for the TCP protocol on port 9400.
//!
//! Ported from the enterprise `sbproxy-classifier` crate's `protocol.rs`.
//! All requests arrive as a single [`Message`] struct with a `cmd` string
//! that dispatches to one of: `classify`, `register`, `delete`, `list`,
//! `quality_score`, `intent_detect`, `content_type_detect`,
//! `streaming_safety`, `version`. Response types are per-command.
//!
//! Length-prefixing is applied at the transport layer in
//! [`crate::tcp`], not here; the serde structs below are pure payload.
//!
//! Not ported: `embed` / `batch_embed` / `model_info` commands, and the
//! per-origin `models` block on registration (named embedding/judge/intent
//! model overrides). Embedding is served over gRPC's `InferenceService`
//! (ONNX-backed, matching the minimal sidecar); this crate does not port the
//! enterprise's LLM-judge backends, so there is nothing for a per-origin
//! judge/intent model override to select between. See
//! `docs/classifier-sidecar.md` for the full scope note.

use serde::{Deserialize, Serialize};

/// Incoming message; the `cmd` field determines the operation. Defaults to
/// `"classify"` when absent.
///
/// Carries `Serialize` (unusual for a request type this server only ever
/// receives) so `crate::tcp`'s tests can encode a real client-shaped frame
/// instead of only ever exercising the server side of the wire format.
#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    /// Which operation this message requests. One of `classify`,
    /// `register`, `delete`, `list`, `quality_score`, `intent_detect`,
    /// `content_type_detect`, `streaming_safety`, `version`.
    #[serde(default = "default_cmd")]
    pub cmd: String,

    // --- classify fields ---
    /// Caller-supplied correlation id, echoed back on [`ClassifyResponse::id`]
    /// / [`QualityScoreResponse::id`] so a client can match responses to
    /// requests over the shared connection.
    #[serde(default)]
    pub id: String,
    /// Text to classify (`cmd = "classify"`) or score (`cmd =
    /// "quality_score"`). Empty for commands that carry their input in a
    /// different field (`intent_text`, `streaming_tokens`,
    /// `detect_content`).
    #[serde(default)]
    pub text: String,
    /// Maximum number of labels to return for `cmd = "classify"`.
    #[serde(default = "default_top_k")]
    pub top_k: usize,
    /// Tenant to classify against. `None` selects the sidecar's default
    /// tenant.
    #[serde(default)]
    pub tenant: Option<String>,

    // --- register fields ---
    /// Inline tenant config (only used when cmd = "register").
    #[serde(default)]
    pub config: Option<TenantConfig>,

    // --- intent_detect fields ---
    /// Prompt text to classify into a coarse intent bucket
    /// (`cmd = "intent_detect"`).
    #[serde(default)]
    pub intent_text: Option<String>,

    // --- streaming_safety fields ---
    /// Next chunk of streamed model output to check
    /// (`cmd = "streaming_safety"`).
    #[serde(default)]
    pub streaming_tokens: Option<String>,
    /// Safety rule identifiers to enforce for this streaming session
    /// (`cmd = "streaming_safety"`).
    #[serde(default)]
    pub safety_rules: Option<Vec<String>>,

    // --- content_type_detect fields ---
    /// Text to classify by content type
    /// (`cmd = "content_type_detect"`).
    #[serde(default)]
    pub detect_content: Option<String>,
}

fn default_cmd() -> String {
    "classify".to_string()
}

fn default_top_k() -> usize {
    3
}

/// Tenant configuration passed inline with the `register` command.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TenantConfig {
    /// Labels this tenant classifies against, each with its own match
    /// patterns and weight.
    pub labels: Vec<TenantLabel>,
    /// Confidence threshold and default-label behavior for this tenant.
    /// `None` uses the classifier's built-in defaults.
    #[serde(default)]
    pub classification: Option<TenantClassification>,
    /// Text normalization rules applied before classification. `None`
    /// uses the classifier's built-in defaults.
    #[serde(default)]
    pub normalization: Option<TenantNormalization>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct TenantLabel {
    pub name: String,
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default = "default_weight")]
    pub weight: f64,
}

fn default_weight() -> f64 {
    1.0
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct TenantClassification {
    #[serde(default = "default_threshold")]
    pub confidence_threshold: f64,
    #[serde(default = "default_label")]
    pub default_label: String,
    #[serde(default = "default_boost")]
    pub default_boost: f64,
}

fn default_threshold() -> f64 {
    0.15
}
fn default_label() -> String {
    "conversation".to_string()
}
fn default_boost() -> f64 {
    0.5
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct TenantNormalization {
    #[serde(default = "default_true")]
    pub unicode_nfkc: bool,
    #[serde(default = "default_true")]
    pub trim: bool,
    #[serde(default)]
    pub rules: Vec<TenantNormRule>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct TenantNormRule {
    pub name: String,
    pub pattern: String,
    pub replace: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// Single label with confidence score.
///
/// Carries `Deserialize` (unusual for a response type this server only ever
/// sends) so `crate::tcp`'s tests can decode a real round trip through the
/// wire instead of asserting on the handler's return value directly.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Label {
    /// The classification label's name.
    pub label: String,
    /// Confidence score for this label, in `[0.0, 1.0]`.
    pub score: f64,
}

/// Classification response.
#[derive(Debug, Serialize, Deserialize)]
pub struct ClassifyResponse {
    /// Echoes [`Message::id`] from the request.
    pub id: String,
    /// Matched labels, highest score first, capped at [`Message::top_k`].
    pub labels: Vec<Label>,
    /// The input text after normalization, for callers that want to see
    /// exactly what was classified.
    pub normalized: String,
    /// Server-side processing time in microseconds.
    pub latency_us: i64,
    /// The tenant the request was classified against.
    pub tenant: String,
}

/// Version/info response.
#[derive(Debug, Serialize, Deserialize)]
pub struct VersionResponse {
    /// Sidecar binary name.
    pub name: String,
    /// Sidecar version string.
    pub version: String,
    /// Deployment mode label (e.g. `"minimal"`, `"rich"`).
    pub mode: String,
}

/// Quality score response.
#[derive(Debug, Serialize, Deserialize)]
pub struct QualityScoreResponse {
    /// Echoes [`Message::id`] from the request.
    pub id: String,
    /// Overall heuristic quality score in `[0.0, 1.0]`; see
    /// `crate::quality::quality_score`.
    pub score: f64,
    /// Individual signal scores (length, coherence, repetition,
    /// formatting, error patterns, casing) that combine into `score`.
    pub signals: std::collections::HashMap<String, f64>,
    /// Server-side processing time in microseconds.
    pub latency_us: i64,
}

/// Intent detection response.
#[derive(Debug, Serialize, Deserialize)]
pub struct IntentDetectResponse {
    /// Detected coarse intent bucket (e.g. `"coding"`, `"vision"`).
    pub intent: String,
    /// Confidence for `intent`, in `[0.0, 1.0]`.
    pub confidence: f64,
}

/// Streaming safety check response.
#[derive(Debug, Serialize, Deserialize)]
pub struct StreamingSafetyResponse {
    /// Whether the checked chunk passed every enforced safety rule.
    pub safe: bool,
    /// Whether the caller should terminate the stream because of this
    /// chunk. Distinct from `safe` so a caller can distinguish "this
    /// chunk alone looked fine" from "stop sending".
    pub blocked: bool,
    /// Operator-facing reason for `blocked`, empty when `blocked` is
    /// `false`.
    pub reason: String,
}

/// Content type detection response.
#[derive(Debug, Serialize, Deserialize)]
pub struct ContentTypeDetectResponse {
    /// Detected content type label (e.g. `"code"`, `"prose"`).
    pub content_type: String,
    /// Confidence for `content_type`, in `[0.0, 1.0]`.
    pub confidence: f64,
}

/// Response to `register` / `delete` / `list` commands.
#[derive(Debug, Serialize, Deserialize)]
pub struct AdminResponse {
    /// Whether the requested admin operation succeeded.
    pub ok: bool,
    /// Echoes [`Message::cmd`] from the request.
    pub cmd: String,
    /// The tenant the operation applied to (`register` / `delete`).
    /// Absent for `list`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Operator-facing failure reason when `ok` is `false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Every registered tenant and its label set. Only present on `list`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenants: Option<Vec<TenantInfo>>,
}

/// One registered tenant, as returned by the `list` command.
#[derive(Debug, Serialize, Deserialize)]
pub struct TenantInfo {
    /// The tenant's identifier.
    pub id: String,
    /// Names of the labels this tenant classifies against.
    pub labels: Vec<String>,
}

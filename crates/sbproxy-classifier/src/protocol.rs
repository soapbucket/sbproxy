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
    #[serde(default = "default_cmd")]
    pub cmd: String,

    // --- classify fields ---
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub text: String,
    #[serde(default = "default_top_k")]
    pub top_k: usize,
    #[serde(default)]
    pub tenant: Option<String>,

    // --- register fields ---
    /// Inline tenant config (only used when cmd = "register").
    #[serde(default)]
    pub config: Option<TenantConfig>,

    // --- intent_detect fields ---
    #[serde(default)]
    pub intent_text: Option<String>,

    // --- streaming_safety fields ---
    #[serde(default)]
    pub streaming_tokens: Option<String>,
    #[serde(default)]
    pub safety_rules: Option<Vec<String>>,

    // --- content_type_detect fields ---
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
    pub labels: Vec<TenantLabel>,
    #[serde(default)]
    pub classification: Option<TenantClassification>,
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
    pub label: String,
    pub score: f64,
}

/// Classification response.
#[derive(Debug, Serialize, Deserialize)]
pub struct ClassifyResponse {
    pub id: String,
    pub labels: Vec<Label>,
    pub normalized: String,
    pub latency_us: i64,
    pub tenant: String,
}

/// Version/info response.
#[derive(Debug, Serialize, Deserialize)]
pub struct VersionResponse {
    pub name: String,
    pub version: String,
    pub mode: String,
}

/// Quality score response.
#[derive(Debug, Serialize, Deserialize)]
pub struct QualityScoreResponse {
    pub id: String,
    pub score: f64,
    pub signals: std::collections::HashMap<String, f64>,
    pub latency_us: i64,
}

/// Intent detection response.
#[derive(Debug, Serialize, Deserialize)]
pub struct IntentDetectResponse {
    pub intent: String,
    pub confidence: f64,
}

/// Streaming safety check response.
#[derive(Debug, Serialize, Deserialize)]
pub struct StreamingSafetyResponse {
    pub safe: bool,
    pub blocked: bool,
    pub reason: String,
}

/// Content type detection response.
#[derive(Debug, Serialize, Deserialize)]
pub struct ContentTypeDetectResponse {
    pub content_type: String,
    pub confidence: f64,
}

/// Response to `register` / `delete` / `list` commands.
#[derive(Debug, Serialize, Deserialize)]
pub struct AdminResponse {
    pub ok: bool,
    pub cmd: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenants: Option<Vec<TenantInfo>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TenantInfo {
    pub id: String,
    pub labels: Vec<String>,
}

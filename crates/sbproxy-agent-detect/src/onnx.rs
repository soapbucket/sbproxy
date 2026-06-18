//! ONNX-backed CatBoost scorer for JA4-shaped agent detection.
//!
//! The feature layout follows the JA4 fields highlighted in
//! arXiv:2602.09606: protocol, TLS version, SNI flag, cipher count,
//! extension count, ALPN, JA4_B, and JA4_C. sbproxy appends already
//! available request-side context so the model can distinguish browser
//! traffic from SDK / automation traffic without reading payload text.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use tract_onnx::prelude::*;

use crate::{
    AgentDetection, AgentProvenance, AgentScorer, DefaultScorer, HttpSignals, PayloadSignals,
    Signals, TlsSignals,
};

/// Number of f32 features fed to the CatBoost ONNX model.
pub const JA4_CATBOOST_FEATURE_COUNT: usize = 14;

/// Ordered feature names for the ONNX input tensor.
pub const JA4_CATBOOST_FEATURE_NAMES: [&str; JA4_CATBOOST_FEATURE_COUNT] = [
    "protocol_code",
    "tls_version",
    "sni_present",
    "cipher_count",
    "extension_count",
    "alpn_code",
    "ja4_b_hash",
    "ja4_c_hash",
    "pq_tls_present",
    "ja4h_present",
    "cookie_persistence",
    "vendor_header_count",
    "filesystem_path_bucket",
    "payload_shape",
];

type RunnableOnnxModel =
    SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;

/// CatBoost ONNX scorer over [`Signals`].
///
/// Construction loads and optimises the ONNX graph once. [`AgentScorer::score`]
/// is then allocation-light: build the fixed feature vector, run the
/// in-process model, and translate the class-1 probability to the
/// public 0-100 score.
pub struct OnnxCatBoostScorer {
    model: RunnableOnnxModel,
    model_path: PathBuf,
}

impl OnnxCatBoostScorer {
    /// Load a CatBoost ONNX model from disk.
    ///
    /// CatBoost's stock ONNX export ends in a `ZipMap` sequence/map
    /// adapter that `tract-onnx` 0.21 cannot type. The vendored model
    /// keeps CatBoost's `TreeEnsembleClassifier` and exposes the raw
    /// `probability_tensor` output instead.
    pub fn load(model_path: impl AsRef<Path>) -> Result<Self> {
        let model_path = model_path.as_ref();
        let model = tract_onnx::onnx()
            .model_for_path(model_path)
            .with_context(|| format!("failed to parse ONNX model at {model_path:?}"))?
            .into_optimized()
            .context("failed to optimise ONNX model")?
            .into_runnable()
            .context("failed to make ONNX model runnable")?;

        Ok(Self {
            model,
            model_path: model_path.to_path_buf(),
        })
    }

    /// Path the scorer loaded. Exposed for startup logging and tests.
    pub fn model_path(&self) -> &Path {
        &self.model_path
    }

    /// Build the f32 tensor row consumed by the model.
    pub fn feature_vector(signals: &Signals) -> [f32; JA4_CATBOOST_FEATURE_COUNT] {
        build_feature_vector(signals)
    }

    /// Run inference and return the class-1 probability in `[0.0, 1.0]`.
    pub fn score_probability(&self, signals: &Signals) -> Result<f32> {
        let features = Self::feature_vector(signals);
        let input = tract_ndarray::Array2::from_shape_vec((1, features.len()), features.to_vec())
            .map_err(|e| anyhow!(e))?;
        let input_names = self
            .model
            .model()
            .input_outlets()
            .context("failed to inspect ONNX model inputs")?;

        let mut inputs: TVec<TValue> = tvec!();
        for _ in input_names {
            inputs.push(input.clone().into_tensor().into());
        }

        let outputs = self
            .model
            .run(inputs)
            .map_err(|e| anyhow!("ONNX agent-detect inference failed: {e}"))?;
        probability_from_outputs(outputs)
    }
}

impl AgentScorer for OnnxCatBoostScorer {
    fn score(&self, signals: &Signals) -> AgentDetection {
        match self.score_probability(signals) {
            Ok(probability) => {
                let probability = probability.clamp(0.0, 1.0);
                let score = (probability * 100.0).round().clamp(0.0, 100.0) as u8;
                AgentDetection {
                    score,
                    agent_id: None,
                    provenance: AgentProvenance::UnsignedAnonymous,
                    confidence: probability,
                    signals_used: model_signals_used(signals),
                    headless_score: 0,
                    headless_indicators: Vec::new(),
                }
            }
            Err(_) => {
                let mut detection = DefaultScorer.score(signals);
                detection
                    .signals_used
                    .push("onnx_catboost_error".to_string());
                detection
            }
        }
    }
}

fn build_feature_vector(signals: &Signals) -> [f32; JA4_CATBOOST_FEATURE_COUNT] {
    let tls = signals.tls.as_ref();
    let http = signals.http.as_ref();
    let payload = signals.payload.as_ref();
    let ja4_parts = tls
        .and_then(|t| t.ja4.as_deref())
        .map(parse_ja4)
        .unwrap_or_default();
    let alpn = ja4_parts
        .alpn
        .as_deref()
        .or_else(|| tls.and_then(first_alpn));

    [
        ja4_parts.protocol_code,
        ja4_parts.tls_version,
        ja4_parts.sni_present,
        ja4_parts.cipher_count,
        ja4_parts.extension_count,
        alpn.map(alpn_code).unwrap_or_default(),
        ja4_parts.ja4_b_hash,
        ja4_parts.ja4_c_hash,
        tls.map(|t| t.pq_tls_present as u8 as f32)
            .unwrap_or_default(),
        tls.and_then(|t| t.ja4h.as_ref())
            .map(|_| 1.0)
            .unwrap_or_default(),
        http.map(|h| h.cookie_persistence as u8 as f32)
            .unwrap_or_default(),
        http.map(vendor_header_count).unwrap_or_default(),
        payload.map(filesystem_path_bucket).unwrap_or_default(),
        payload.map(payload_shape).unwrap_or_default(),
    ]
}

fn model_signals_used(signals: &Signals) -> Vec<String> {
    let mut used = vec![
        "onnx_catboost".to_string(),
        "ja4_feature_vector".to_string(),
    ];
    if signals.tls.as_ref().and_then(|t| t.ja4.as_ref()).is_some() {
        used.push("ja4".to_string());
    }
    if signals.tls.as_ref().and_then(|t| t.ja4h.as_ref()).is_some() {
        used.push("ja4h".to_string());
    }
    if signals.http.is_some() {
        used.push("http".to_string());
    }
    if signals.payload.is_some() {
        used.push("payload".to_string());
    }
    used
}

#[derive(Debug, Clone, Default, PartialEq)]
struct ParsedJa4 {
    protocol_code: f32,
    tls_version: f32,
    sni_present: f32,
    cipher_count: f32,
    extension_count: f32,
    alpn: Option<String>,
    ja4_b_hash: f32,
    ja4_c_hash: f32,
}

fn parse_ja4(ja4: &str) -> ParsedJa4 {
    let mut parts = ja4.split('_');
    let prefix = parts.next().unwrap_or_default();
    let ja4_b = parts.next();
    let ja4_c = parts.next();
    let bytes = prefix.as_bytes();
    let tls_version = parse_two_digits(prefix, 1).unwrap_or_default();
    let cipher_count = parse_two_digits(prefix, 4).unwrap_or_default();
    let extension_count = parse_two_digits(prefix, 6).unwrap_or_default();
    let alpn = if bytes.len() > 8 {
        Some(prefix[8..].to_ascii_lowercase())
    } else {
        None
    };

    ParsedJa4 {
        protocol_code: bytes.first().map(|b| protocol_code(*b)).unwrap_or_default(),
        tls_version,
        sni_present: bytes
            .get(3)
            .map(|b| matches!(*b, b'd' | b'D') as u8 as f32)
            .unwrap_or_default(),
        cipher_count,
        extension_count,
        alpn,
        ja4_b_hash: ja4_b.map(hash_string_to_unit).unwrap_or_default(),
        ja4_c_hash: ja4_c.map(hash_string_to_unit).unwrap_or_default(),
    }
}

fn parse_two_digits(s: &str, start: usize) -> Option<f32> {
    let end = start.checked_add(2)?;
    let bytes = s.as_bytes().get(start..end)?;
    if bytes.iter().all(u8::is_ascii_digit) {
        std::str::from_utf8(bytes)
            .ok()?
            .parse::<u8>()
            .ok()
            .map(f32::from)
    } else {
        None
    }
}

fn protocol_code(protocol: u8) -> f32 {
    match protocol.to_ascii_lowercase() {
        b't' => 1.0,
        b'q' => 2.0,
        b'd' => 3.0,
        other => 10.0 + (other as f32 / 255.0),
    }
}

fn first_alpn(tls: &TlsSignals) -> Option<&str> {
    tls.alpn.first().map(String::as_str)
}

fn alpn_code(alpn: &str) -> f32 {
    match alpn.to_ascii_lowercase().as_str() {
        "" => 0.0,
        "http/1.1" | "http/1" | "h1" => 1.0,
        "h2" => 2.0,
        "h3" => 3.0,
        other => 10.0 + hash_string_to_unit(other),
    }
}

fn vendor_header_count(http: &HttpSignals) -> f32 {
    http.vendor_headers.len().min(8) as f32
}

fn filesystem_path_bucket(payload: &PayloadSignals) -> f32 {
    payload.filesystem_paths_leaked.min(8) as f32
}

fn payload_shape(payload: &PayloadSignals) -> f32 {
    (payload.stack_trace_shaped || payload.embedding_burst) as u8 as f32
}

fn hash_string_to_unit(value: &str) -> f32 {
    let digest = Sha256::digest(value.as_bytes());
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&digest[..4]);
    u32::from_be_bytes(bytes) as f32 / u32::MAX as f32
}

fn probability_from_outputs(outputs: TVec<TValue>) -> Result<f32> {
    for output in outputs {
        if let Ok(view) = output.to_array_view::<f32>() {
            let flat: Vec<f32> = view.iter().copied().collect();
            if flat.is_empty() {
                continue;
            }
            return probability_from_f32_slice(&flat);
        }
    }
    Err(anyhow!(
        "ONNX agent-detect model returned no f32 probability output"
    ))
}

fn probability_from_f32_slice(values: &[f32]) -> Result<f32> {
    if values.iter().any(|v| !v.is_finite()) {
        return Err(anyhow!(
            "ONNX agent-detect probability output was not finite"
        ));
    }
    match values {
        [single] => Ok(if (0.0..=1.0).contains(single) {
            *single
        } else {
            sigmoid(*single)
        }),
        [_, agent, ..] if looks_like_probability_vector(values) => Ok(*agent),
        [_, agent, ..] => {
            let probs = softmax(values);
            Ok(probs.get(1).copied().unwrap_or(*agent).clamp(0.0, 1.0))
        }
        [] => Err(anyhow!("ONNX agent-detect probability output was empty")),
    }
}

fn looks_like_probability_vector(values: &[f32]) -> bool {
    let sum: f32 = values.iter().sum();
    values.iter().all(|v| (0.0..=1.0).contains(v)) && (0.95..=1.05).contains(&sum)
}

fn softmax(values: &[f32]) -> Vec<f32> {
    let max = values.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let exp: Vec<f32> = values.iter().map(|v| (v - max).exp()).collect();
    let sum: f32 = exp.iter().sum();
    if sum == 0.0 {
        return vec![0.0; values.len()];
    }
    exp.into_iter().map(|v| v / sum).collect()
}

fn sigmoid(value: f32) -> f32 {
    if value >= 0.0 {
        1.0 / (1.0 + (-value).exp())
    } else {
        let exp = value.exp();
        exp / (1.0 + exp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HttpSignals, PayloadSignals, TlsSignals};

    const FIXTURE_MODEL: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/ja4_catboost_fixture.onnx"
    );

    fn fixture_signals() -> Signals {
        Signals {
            tls: Some(TlsSignals {
                ja4: Some("t13d1516h2_8daaf6152771_02713d6af862".to_string()),
                ja4h: Some("ge11nn030000_d4ce69e9c2f0".to_string()),
                sni: Some("api.example.test".to_string()),
                alpn: vec!["h2".to_string(), "http/1.1".to_string()],
                pq_tls_present: true,
                ..TlsSignals::default()
            }),
            http: Some(HttpSignals {
                cookie_persistence: true,
                vendor_headers: vec!["x-stainless-arch".to_string()],
                ..HttpSignals::default()
            }),
            payload: Some(PayloadSignals {
                filesystem_paths_leaked: 1,
                stack_trace_shaped: false,
                embedding_burst: false,
            }),
        }
    }

    #[test]
    fn parse_ja4_extracts_structured_fields() {
        let parsed = parse_ja4("t13d1516h2_8daaf6152771_02713d6af862");

        assert_eq!(parsed.protocol_code, 1.0);
        assert_eq!(parsed.tls_version, 13.0);
        assert_eq!(parsed.sni_present, 1.0);
        assert_eq!(parsed.cipher_count, 15.0);
        assert_eq!(parsed.extension_count, 16.0);
        assert_eq!(parsed.alpn.as_deref(), Some("h2"));
        assert!(parsed.ja4_b_hash > 0.0);
        assert!(parsed.ja4_c_hash > 0.0);
    }

    #[test]
    fn feature_vector_uses_expected_order() {
        let features = OnnxCatBoostScorer::feature_vector(&fixture_signals());

        assert_eq!(features.len(), JA4_CATBOOST_FEATURE_COUNT);
        assert_eq!(features[0], 1.0);
        assert_eq!(features[1], 13.0);
        assert_eq!(features[2], 1.0);
        assert_eq!(features[3], 15.0);
        assert_eq!(features[4], 16.0);
        assert_eq!(features[5], 2.0);
        assert_eq!(features[8], 1.0);
        assert_eq!(features[9], 1.0);
        assert_eq!(features[10], 1.0);
        assert_eq!(features[11], 1.0);
    }

    #[test]
    fn fixture_model_loads_and_scores() {
        let scorer = OnnxCatBoostScorer::load(FIXTURE_MODEL).expect("fixture model loads");
        let probability = scorer
            .score_probability(&fixture_signals())
            .expect("fixture inference succeeds");

        assert!((0.0..=1.0).contains(&probability));
    }

    #[test]
    fn score_returns_unsigned_anonymous_model_verdict() {
        let scorer = OnnxCatBoostScorer::load(FIXTURE_MODEL).expect("fixture model loads");
        let detection = scorer.score(&fixture_signals());

        assert_eq!(detection.provenance, AgentProvenance::UnsignedAnonymous);
        assert!(detection.agent_id.is_none());
        assert!(detection.score <= 100);
        assert!(detection
            .signals_used
            .contains(&"onnx_catboost".to_string()));
        assert!(detection
            .signals_used
            .contains(&"ja4_feature_vector".to_string()));
    }

    #[test]
    #[ignore = "bench gate; run release-mode with --ignored"]
    fn onnx_fixture_p99_under_500us_single_threaded() {
        let scorer = OnnxCatBoostScorer::load(FIXTURE_MODEL).expect("fixture model loads");
        let signals = fixture_signals();
        for _ in 0..128 {
            let _ = scorer.score_probability(&signals).expect("warmup scores");
        }

        let mut durations = Vec::with_capacity(2_000);
        for _ in 0..2_000 {
            let started = std::time::Instant::now();
            let _ = scorer.score_probability(&signals).expect("fixture scores");
            durations.push(started.elapsed());
        }
        durations.sort_unstable();
        let p99 = durations[(durations.len() * 99) / 100];

        assert!(
            p99 <= std::time::Duration::from_micros(500),
            "single-threaded fixture p99 {p99:?} exceeded 500us"
        );
    }

    #[test]
    fn probability_handles_logits_and_probabilities() {
        let from_probabilities = probability_from_f32_slice(&[0.25, 0.75]).unwrap();
        let from_logits = probability_from_f32_slice(&[-1.0, 1.0]).unwrap();
        let from_single_logit = probability_from_f32_slice(&[2.0]).unwrap();

        assert_eq!(from_probabilities, 0.75);
        assert!(from_logits > 0.85);
        assert!(from_single_logit > 0.88);
    }
}

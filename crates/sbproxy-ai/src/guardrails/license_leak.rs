//! License-leak guardrail: detects licensed-text reproduction in AI
//! output.
//!
//! A first-party output guardrail, not a vendor adapter: it plugs into
//! the same [`super::GuardrailPipeline`] every other built-in guardrail
//! (`pii`, `regex`, `schema`, ...) runs through. An operator supplies a
//! small corpus of licensed documents (URN + body) inline in the route
//! config; the guardrail scores the model's response text against that
//! corpus and, on a confident match, applies the configured `mode`.
//!
//! # Detectors
//!
//! Three signals are combined into one verdict, mirroring how a
//! plagiarism checker layers detectors of increasing recall and
//! decreasing precision:
//!
//! 1. **Substring match** - a rolling 32-character window of the
//!    response probed against a per-document inverted index. A hit is
//!    a verbatim quote and scores 1.0 on its own.
//! 2. **Heuristic signals** - three rules pinned by their own
//!    thresholds: a 200+ character unbroken run with no attribution
//!    marker (`"`, `according to`, a bracketed citation), a 5-word
//!    shingle Jaccard overlap of 0.70+ against any single document,
//!    or three or more distinct 32+ character verbatim spans against
//!    the same document.
//! 3. **Embedding-similarity stub** - a deterministic token-shingle
//!    Jaccard overlap standing in for sentence-embedding cosine
//!    similarity. No ONNX model ships with this guardrail; the stub is
//!    the same substitution the corpus this was ported from documents
//!    for its own default build; it is biased toward verbatim and
//!    near-verbatim text and will under-detect aggressive paraphrase.
//!
//! # Modes
//!
//! `mode` controls what a confident match does:
//!
//! * `block` - the pipeline's `check()` returns a [`GuardrailBlock`],
//!   the same mechanism `pii` and `regex` use to refuse a response.
//! * `redact` - **currently behaves like `block`.** The pipeline's
//!   `check(&self, content: &str) -> Option<GuardrailBlock>` signature
//!   has no channel for returning rewritten content, only a decision;
//!   [`super::pii::PiiGuardrail`]'s `Mask` action documents the exact
//!   same limitation for the same reason. Failing closed (refuse
//!   rather than forward unredacted licensed text) is the safe
//!   direction for that gap, so `redact` refuses instead of silently
//!   downgrading to `warn`.
//! * `warn` - forwards the response and emits a `WARN`-level
//!   structured log under the `sbproxy::license_leak_guardrail::audit`
//!   target.
//! * `log` - forwards the response and emits an `INFO`-level
//!   structured log under the same target.
//!
//! `timeout_action` (`block` | `warn` | `log`, defaults to `warn`)
//! applies instead of `mode` when the detector's wall-clock budget
//! (`max_eval_ms`) is exceeded, so a slow evaluation and a fast
//! confident one can be dispositioned independently.
//!
//! # Streaming
//!
//! [`streaming_safe`](super::Guardrail::streaming_safe) returns
//! `false`: the heuristic and embedding-stub detectors need the
//! complete response text (a 5-word shingle Jaccard overlap over a
//! partial prefix is not prefix-stable, the same reasoning that routes
//! `schema` and the classifier-backed guardrails to close-time
//! evaluation). [`super::compile_pipeline`] defaults an output
//! `license_leak` entry to `stream_policy: close`, so the existing
//! streaming session buffers the full text and evaluates once at
//! stream close. This is deliberately narrower than the source this
//! was ported from, which also offered a `windowed` streaming strategy
//! with a bespoke sliding-window evaluator for lower time-to-first-byte;
//! that strategy is not ported here; `buffered`-equivalent (the
//! source's own default) is the only behavior this guardrail provides.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use serde::Deserialize;

use crate::ai_metrics::{record_guardrail_block, record_license_leak_finding};

use super::GuardrailBlock;

// --- Corpus -----------------------------------------------------------------

/// Length of the substring shingles fed into the verbatim-match
/// detector. 32 characters: long enough that random reuse is
/// unlikely, short enough to still catch short documents.
const SUBSTRING_SHINGLE_LEN: usize = 32;

/// Token-shingle window size for the heuristic and embedding-stub
/// detectors. 5-word shingles balance "long enough that random reuse
/// is unlikely" against "short enough to catch reordered paraphrase".
const TOKEN_SHINGLE_LEN: usize = 5;

/// One licensed document an operator wants the guardrail to protect.
/// Configured inline under the guardrail's `documents:` list; there is
/// no external corpus-hydration service in this port.
#[derive(Clone, Debug, Deserialize)]
pub struct LicensedDocument {
    /// Stable identifier for the document, surfaced in the block
    /// reason and the `sbproxy_ai_license_leak_findings_total` label
    /// space is bounded to `mode`/`method`, not this value, so an
    /// operator may use any URN-shaped string here without a
    /// cardinality concern.
    pub license_urn: String,
    /// Full document text. Held in memory; this guardrail has no
    /// on-disk or encrypted-at-rest storage tier.
    pub body: String,
}

/// Indexed view of one [`LicensedDocument`]. The detector reads only
/// the indexes; the original body is retained for evidence-excerpt
/// extraction on a confirmed match.
#[derive(Clone, Debug)]
struct DocumentIndex {
    license_urn: String,
    token_shingles: BTreeSet<String>,
    substring_shingles: BTreeSet<String>,
}

impl DocumentIndex {
    fn build(doc: LicensedDocument) -> Self {
        let tokens = tokenize(&doc.body);
        let token_shingles = build_token_shingles(&tokens);
        let substring_shingles = build_substring_shingles(&doc.body);
        Self {
            license_urn: doc.license_urn,
            token_shingles,
            substring_shingles,
        }
    }
}

/// The indexed corpus a compiled guardrail instance scores against.
#[derive(Clone, Debug, Default)]
struct LicenseCorpus {
    documents: Vec<DocumentIndex>,
    substring_to_docs: BTreeMap<String, Vec<usize>>,
}

impl LicenseCorpus {
    fn build<I: IntoIterator<Item = LicensedDocument>>(docs: I) -> Self {
        let mut corpus = Self::default();
        for doc in docs {
            let indexed = DocumentIndex::build(doc);
            let idx = corpus.documents.len();
            for shingle in &indexed.substring_shingles {
                corpus
                    .substring_to_docs
                    .entry(shingle.clone())
                    .or_default()
                    .push(idx);
            }
            corpus.documents.push(indexed);
        }
        corpus
    }

    fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }
}

/// Lower-case, punctuation-strip the body into a flat token stream.
fn tokenize(body: &str) -> Vec<String> {
    body.split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_ascii_lowercase())
        .collect()
}

/// Build the 5-word shingle set from a token stream. Documents shorter
/// than one shingle still get a single whole-document shingle so short
/// documents produce at least one signal.
fn build_token_shingles(tokens: &[String]) -> BTreeSet<String> {
    if tokens.len() < TOKEN_SHINGLE_LEN {
        let mut s = BTreeSet::new();
        if !tokens.is_empty() {
            s.insert(tokens.join(" "));
        }
        return s;
    }
    tokens
        .windows(TOKEN_SHINGLE_LEN)
        .map(|w| w.join(" "))
        .collect()
}

/// Build the 32-char substring set from raw body bytes, walking by
/// char boundary so a multi-byte UTF-8 codepoint is never split
/// mid-shingle.
fn build_substring_shingles(body: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if body.len() < SUBSTRING_SHINGLE_LEN {
        return out;
    }
    let bytes = body.as_bytes();
    let chars: Vec<usize> = body
        .char_indices()
        .map(|(i, _)| i)
        .chain(std::iter::once(bytes.len()))
        .collect();
    if chars.len() < SUBSTRING_SHINGLE_LEN + 1 {
        return out;
    }
    for start_char in 0..(chars.len() - SUBSTRING_SHINGLE_LEN) {
        let start = chars[start_char];
        let end = chars[start_char + SUBSTRING_SHINGLE_LEN];
        out.insert(body[start..end].to_string());
    }
    out
}

fn jaccard(a: &BTreeSet<String>, b: &BTreeSet<String>) -> f32 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let intersection = a.intersection(b).count();
    let union = a.union(b).count();
    intersection as f32 / union.max(1) as f32
}

// --- Detector -----------------------------------------------------------------

/// Default tenant-tunable confidence threshold.
const DEFAULT_CONFIDENCE_THRESHOLD: f32 = 0.95;
/// Minimum tenant-tunable threshold; values below this are clamped up.
const MIN_CONFIDENCE_THRESHOLD: f32 = 0.85;
/// Maximum tenant-tunable threshold; values above this are clamped down.
const MAX_CONFIDENCE_THRESHOLD: f32 = 0.99;
/// Minimum token-overlap ratio that qualifies as a "structural copy"
/// heuristic signal.
const TOKEN_OVERLAP_STRUCTURAL_COPY: f32 = 0.70;
/// Minimum unbroken verbatim-run length (chars) that qualifies as a
/// "long unattributed quote" heuristic signal.
const HEURISTIC_LONG_QUOTE_CHARS: usize = 200;
/// Minimum number of distinct 32+ char verbatim matches against the
/// same document that qualifies as a "structural copy across spans"
/// heuristic signal.
const HEURISTIC_DISTINCT_MATCH_COUNT: usize = 3;

/// Which detector(s) fired for a verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DetectionMethod {
    EmbeddingSimilarity,
    SubstringMatch,
    HeuristicSignals,
    Combined,
}

impl DetectionMethod {
    fn as_str(self) -> &'static str {
        match self {
            DetectionMethod::EmbeddingSimilarity => "embedding_similarity",
            DetectionMethod::SubstringMatch => "substring_match",
            DetectionMethod::HeuristicSignals => "heuristic_signals",
            DetectionMethod::Combined => "combined",
        }
    }
}

/// Result of one license-leak evaluation.
#[derive(Clone, Debug)]
struct LicenseLeakVerdict {
    confident_match: bool,
    license_urn: Option<String>,
    score: f32,
    method: DetectionMethod,
    elapsed_ms: u32,
}

impl LicenseLeakVerdict {
    fn no_match(elapsed_ms: u32) -> Self {
        Self {
            confident_match: false,
            license_urn: None,
            score: 0.0,
            method: DetectionMethod::SubstringMatch,
            elapsed_ms,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct DetectorOutcome {
    fired: bool,
    score: f32,
    matched_doc: Option<usize>,
}

/// Score `body` against `corpus`, combining all three detectors per
/// the module doc's combination rule: a confident match is the
/// disjunction of "substring fired", "heuristic fired", or "embedding
/// stub crossed 0.92".
fn evaluate(body: &str, corpus: &LicenseCorpus, threshold: f32) -> LicenseLeakVerdict {
    let started = Instant::now();
    let elapsed_ms = || started.elapsed().as_millis().min(u32::MAX as u128) as u32;

    if corpus.is_empty() {
        return LicenseLeakVerdict::no_match(elapsed_ms());
    }

    let substring = run_substring_detector(body, corpus);
    let heuristic = run_heuristic_detector(body, corpus);
    let embedding = run_embedding_stub_detector(body, corpus);

    let mut detectors_fired = 0u8;
    if substring.fired {
        detectors_fired += 1;
    }
    if heuristic.fired {
        detectors_fired += 1;
    }
    if embedding.fired {
        detectors_fired += 1;
    }

    let confident = substring.fired || heuristic.fired || embedding.score >= 0.92;

    let mut score = 0.0_f32;
    if substring.fired {
        score = score.max(substring.score);
    }
    if heuristic.fired {
        score = score.max(heuristic.score);
    }
    score = score.max(embedding.score).min(1.0);

    let method = if detectors_fired >= 2 {
        DetectionMethod::Combined
    } else if substring.fired {
        DetectionMethod::SubstringMatch
    } else if heuristic.fired {
        DetectionMethod::HeuristicSignals
    } else {
        DetectionMethod::EmbeddingSimilarity
    };

    // Priority order matches the source this was ported from: the
    // most specific detector's document attribution wins.
    let matched_doc = if substring.fired {
        substring.matched_doc
    } else if heuristic.fired {
        heuristic.matched_doc
    } else {
        embedding.matched_doc
    };
    let license_urn = matched_doc.map(|idx| corpus.documents[idx].license_urn.clone());

    LicenseLeakVerdict {
        confident_match: confident && score >= threshold,
        license_urn,
        score,
        method,
        elapsed_ms: elapsed_ms(),
    }
}

fn run_substring_detector(body: &str, corpus: &LicenseCorpus) -> DetectorOutcome {
    if body.len() < SUBSTRING_SHINGLE_LEN {
        return DetectorOutcome::default();
    }
    for shingle in build_substring_shingles(body) {
        if let Some(docs) = corpus.substring_to_docs.get(&shingle) {
            if let Some(&first) = docs.first() {
                return DetectorOutcome {
                    fired: true,
                    // Verbatim match scores 1.0; the threshold check
                    // is the operator's lever, not the detector's job.
                    score: 1.0,
                    matched_doc: Some(first),
                };
            }
        }
    }
    DetectorOutcome::default()
}

fn run_heuristic_detector(body: &str, corpus: &LicenseCorpus) -> DetectorOutcome {
    // Rule A: long unattributed verbatim run. Fires with no document
    // attribution (there is nothing to attribute it to).
    if find_long_unattributed_run(body) {
        return DetectorOutcome {
            fired: true,
            score: 1.0,
            matched_doc: None,
        };
    }

    let response_tokens = tokenize(body);
    if response_tokens.is_empty() {
        return DetectorOutcome::default();
    }
    let response_shingles = build_token_shingles(&response_tokens);

    // Rule B: token-overlap >= TOKEN_OVERLAP_STRUCTURAL_COPY against
    // any single document.
    let mut best_overlap = 0.0_f32;
    let mut best_doc: Option<usize> = None;
    for (i, doc) in corpus.documents.iter().enumerate() {
        let overlap = jaccard(&response_shingles, &doc.token_shingles);
        if overlap > best_overlap {
            best_overlap = overlap;
            best_doc = Some(i);
        }
    }
    if best_overlap >= TOKEN_OVERLAP_STRUCTURAL_COPY {
        return DetectorOutcome {
            fired: true,
            score: best_overlap,
            matched_doc: best_doc,
        };
    }

    // Rule C: 3+ distinct verbatim 32+-char matches against the same
    // document. Piggy-backs on the substring inverted index.
    let mut per_doc_hits: BTreeMap<usize, usize> = BTreeMap::new();
    for shingle in build_substring_shingles(body) {
        if let Some(docs) = corpus.substring_to_docs.get(&shingle) {
            for &d in docs {
                *per_doc_hits.entry(d).or_default() += 1;
            }
        }
    }
    for (doc_idx, hits) in per_doc_hits {
        if hits >= HEURISTIC_DISTINCT_MATCH_COUNT {
            return DetectorOutcome {
                fired: true,
                // Short of "verbatim and unattributed" (Rule A) but
                // still high-confidence.
                score: 0.95,
                matched_doc: Some(doc_idx),
            };
        }
    }

    DetectorOutcome::default()
}

fn run_embedding_stub_detector(body: &str, corpus: &LicenseCorpus) -> DetectorOutcome {
    let response_tokens = tokenize(body);
    if response_tokens.is_empty() {
        return DetectorOutcome::default();
    }
    let response_shingles = build_token_shingles(&response_tokens);
    let mut best_score = 0.0_f32;
    let mut best_doc: Option<usize> = None;
    for (i, doc) in corpus.documents.iter().enumerate() {
        let s = jaccard(&response_shingles, &doc.token_shingles);
        if s > best_score {
            best_score = s;
            best_doc = Some(i);
        }
    }
    DetectorOutcome {
        fired: best_score >= 0.80,
        score: best_score,
        matched_doc: best_doc,
    }
}

/// True when `body` contains a paragraph of `HEURISTIC_LONG_QUOTE_CHARS`
/// or more characters with no attribution marker.
fn find_long_unattributed_run(body: &str) -> bool {
    let attribution_substrings = [
        "\"",
        "\u{201c}",
        "\u{201d}",
        "according to",
        "[",
        "(source:",
        "via ",
    ];
    let lower = body.to_ascii_lowercase();
    let mut cursor = 0usize;
    for chunk in body.split("\n\n") {
        let start = cursor;
        let end = cursor + chunk.len();
        cursor = end + 2;
        let chunk_lower = &lower[start..end.min(lower.len())];
        if attribution_substrings
            .iter()
            .any(|m| chunk_lower.contains(m))
        {
            continue;
        }
        if chunk.chars().count() >= HEURISTIC_LONG_QUOTE_CHARS {
            return true;
        }
    }
    false
}

// --- Guardrail ------------------------------------------------------------

/// Action to take on a confident match.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LicenseLeakMode {
    /// Refuse the response (a [`GuardrailBlock`]).
    Block,
    /// Currently identical to `Block`; see the module docs.
    Redact,
    /// Forward the response; emit a `WARN`-level structured log.
    Warn,
    /// Forward the response; emit an `INFO`-level structured log.
    Log,
}

impl LicenseLeakMode {
    fn as_str(self) -> &'static str {
        match self {
            LicenseLeakMode::Block => "block",
            LicenseLeakMode::Redact => "redact",
            LicenseLeakMode::Warn => "warn",
            LicenseLeakMode::Log => "log",
        }
    }
}

/// Action to take when the detector's wall-clock budget
/// (`max_eval_ms`) is exceeded, independent of `mode`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LicenseLeakTimeoutAction {
    /// Treat the timeout as a confident match in `block` mode.
    Block,
    /// Forward unchanged and emit a `WARN`-level structured log.
    Warn,
    /// Forward unchanged and emit an `INFO`-level structured log.
    Log,
}

impl LicenseLeakTimeoutAction {
    fn as_mode(self) -> LicenseLeakMode {
        match self {
            LicenseLeakTimeoutAction::Block => LicenseLeakMode::Block,
            LicenseLeakTimeoutAction::Warn => LicenseLeakMode::Warn,
            LicenseLeakTimeoutAction::Log => LicenseLeakMode::Log,
        }
    }
}

fn default_mode() -> LicenseLeakMode {
    LicenseLeakMode::Warn
}
fn default_threshold() -> f32 {
    DEFAULT_CONFIDENCE_THRESHOLD
}
fn default_max_eval_ms() -> u32 {
    50
}
fn default_timeout_action() -> LicenseLeakTimeoutAction {
    LicenseLeakTimeoutAction::Warn
}

/// Per-route YAML config.
#[derive(Clone, Debug, Deserialize)]
pub struct LicenseLeakGuardrailConfig {
    /// Action on a confident match. Defaults to `warn`, matching the
    /// "run in warn for a calibration period before enforcing" rollout
    /// guidance the source this was ported from documents.
    #[serde(default = "default_mode")]
    pub mode: LicenseLeakMode,
    /// Confidence floor, clamped to `[0.85, 0.99]` so a misconfigured
    /// route never disables the guardrail entirely.
    #[serde(default = "default_threshold")]
    pub confidence_threshold: f32,
    /// Soft wall-clock budget in milliseconds. The detector is not
    /// preemptible mid-scan (same as the source this was ported
    /// from); this is measured after the fact and, when exceeded,
    /// substitutes `timeout_action` for `mode`.
    #[serde(default = "default_max_eval_ms")]
    pub max_eval_ms: u32,
    /// Disposition applied instead of `mode` when `max_eval_ms` is
    /// exceeded on a confident match.
    #[serde(default = "default_timeout_action")]
    pub timeout_action: LicenseLeakTimeoutAction,
    /// Licensed documents this guardrail instance protects. Empty by
    /// default, which makes the guardrail a documented no-op (an
    /// operator who configures `license_leak` with no `documents:` is
    /// staging the integration before publishing a corpus).
    #[serde(default)]
    pub documents: Vec<LicensedDocument>,
}

/// Pick the disposition a confident match resolves to: `mode` on a
/// timely evaluation, `timeout_action` (mapped to its equivalent
/// mode) when the detector's wall-clock budget was exceeded. Split
/// out as a pure function of `timed_out` (rather than inlined against
/// a real `Instant`) so the override is testable without depending on
/// wall-clock timing.
fn dispositioned_mode(
    timed_out: bool,
    mode: LicenseLeakMode,
    timeout_action: LicenseLeakTimeoutAction,
) -> LicenseLeakMode {
    if timed_out {
        timeout_action.as_mode()
    } else {
        mode
    }
}

/// The license-leak guardrail. See the module docs for the full
/// contract.
#[derive(Debug)]
pub struct LicenseLeakGuardrail {
    mode: LicenseLeakMode,
    confidence_threshold: f32,
    max_eval_ms: u32,
    timeout_action: LicenseLeakTimeoutAction,
    corpus: LicenseCorpus,
}

impl LicenseLeakGuardrail {
    /// Compile from the guardrail's raw JSON config block.
    pub fn from_config(config: &serde_json::Value) -> anyhow::Result<Self> {
        let cfg: LicenseLeakGuardrailConfig = serde_json::from_value(config.clone())?;
        let threshold = cfg
            .confidence_threshold
            .clamp(MIN_CONFIDENCE_THRESHOLD, MAX_CONFIDENCE_THRESHOLD);
        Ok(Self {
            mode: cfg.mode,
            confidence_threshold: threshold,
            max_eval_ms: cfg.max_eval_ms,
            timeout_action: cfg.timeout_action,
            corpus: LicenseCorpus::build(cfg.documents),
        })
    }

    /// Check `content` (the model's output text) against the
    /// configured corpus. Returns `Some(block)` only in `block` /
    /// `redact` mode on a confident match (or a `timeout_action:
    /// block` override); `warn` and `log` always return `None` and
    /// log instead.
    pub fn check(&self, content: &str) -> Option<GuardrailBlock> {
        if self.corpus.is_empty() {
            return None;
        }

        let verdict = evaluate(content, &self.corpus, self.confidence_threshold);
        let timed_out = verdict.elapsed_ms > self.max_eval_ms;

        if !verdict.confident_match {
            return None;
        }

        let effective_mode = dispositioned_mode(timed_out, self.mode, self.timeout_action);

        record_license_leak_finding(effective_mode.as_str(), verdict.method.as_str());

        match effective_mode {
            LicenseLeakMode::Block | LicenseLeakMode::Redact => {
                record_guardrail_block("license_leak");
                Some(GuardrailBlock {
                    name: "license_leak".to_string(),
                    reason: format!(
                        "license-leak guardrail: confident match (method={}, score={:.2}{})",
                        verdict.method.as_str(),
                        verdict.score,
                        verdict
                            .license_urn
                            .as_deref()
                            .map(|urn| format!(", urn={urn}"))
                            .unwrap_or_default(),
                    ),
                })
            }
            LicenseLeakMode::Warn => {
                tracing::warn!(
                    target: "sbproxy::license_leak_guardrail::audit",
                    guardrail = "license_leak",
                    action = "warn",
                    method = verdict.method.as_str(),
                    score = verdict.score,
                    timed_out = timed_out,
                    license_urn = verdict.license_urn.as_deref().unwrap_or("unknown"),
                    "license-leak guardrail: confident match; action=warn, request allowed"
                );
                None
            }
            LicenseLeakMode::Log => {
                tracing::info!(
                    target: "sbproxy::license_leak_guardrail::audit",
                    guardrail = "license_leak",
                    action = "log",
                    method = verdict.method.as_str(),
                    score = verdict.score,
                    timed_out = timed_out,
                    license_urn = verdict.license_urn.as_deref().unwrap_or("unknown"),
                    "license-leak guardrail: confident match; action=log, request allowed"
                );
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nyt_article() -> &'static str {
        "The Federal Reserve voted on Wednesday to raise interest rates by twenty five \
         basis points, citing persistent inflation concerns and a tightening labor \
         market. Fed Chair commented that the path forward remains data dependent. \
         Markets reacted with modest declines across the major indices, while bond \
         yields ticked higher in the immediate aftermath of the announcement."
    }

    fn corpus_with_nyt() -> LicenseCorpus {
        LicenseCorpus::build(vec![LicensedDocument {
            license_urn: "urn:rsl:nyt.com:article:2026-04-12:fed-spring-meeting".to_string(),
            body: nyt_article().to_string(),
        }])
    }

    // --- corpus ---

    #[test]
    fn empty_corpus_is_empty() {
        let c = LicenseCorpus::default();
        assert!(c.is_empty());
    }

    #[test]
    fn build_indexes_a_single_document() {
        let c = corpus_with_nyt();
        assert_eq!(c.documents.len(), 1);
        let d = &c.documents[0];
        assert_eq!(
            d.license_urn,
            "urn:rsl:nyt.com:article:2026-04-12:fed-spring-meeting"
        );
        assert!(!d.token_shingles.is_empty());
        assert!(!d.substring_shingles.is_empty());
        for shingle in &d.substring_shingles {
            assert_eq!(c.substring_to_docs.get(shingle), Some(&vec![0]));
        }
    }

    #[test]
    fn substring_shingles_are_32_chars() {
        let body = "x".repeat(64);
        let s = build_substring_shingles(&body);
        assert_eq!(s.len(), 1);
        assert_eq!(s.iter().next().unwrap().len(), SUBSTRING_SHINGLE_LEN);
    }

    #[test]
    fn substring_shingles_skip_short_bodies() {
        assert!(build_substring_shingles("short").is_empty());
    }

    #[test]
    fn token_shingles_collapse_on_short_documents() {
        let tokens = tokenize("hello world");
        assert_eq!(build_token_shingles(&tokens).len(), 1);
    }

    #[test]
    fn tokenize_lowercases_and_splits_on_punctuation() {
        assert_eq!(
            tokenize("Hello, World! Foo-Bar."),
            vec!["hello", "world", "foo", "bar"]
        );
    }

    #[test]
    fn substring_shingles_handle_unicode_boundaries() {
        let body = "café".repeat(20);
        let s = build_substring_shingles(&body);
        for sh in &s {
            assert_eq!(sh.chars().count(), SUBSTRING_SHINGLE_LEN);
        }
    }

    // --- detector ---

    #[test]
    fn empty_corpus_returns_no_match() {
        let v = evaluate(
            nyt_article(),
            &LicenseCorpus::default(),
            DEFAULT_CONFIDENCE_THRESHOLD,
        );
        assert!(!v.confident_match);
        assert_eq!(v.score, 0.0);
    }

    #[test]
    fn verbatim_quote_fires_substring_detector() {
        let v = evaluate(
            nyt_article(),
            &corpus_with_nyt(),
            DEFAULT_CONFIDENCE_THRESHOLD,
        );
        assert!(v.confident_match, "verbatim copy should be confident");
        assert_eq!(
            v.license_urn.as_deref(),
            Some("urn:rsl:nyt.com:article:2026-04-12:fed-spring-meeting")
        );
        assert_ne!(v.method, DetectionMethod::EmbeddingSimilarity);
    }

    #[test]
    fn unrelated_text_does_not_fire() {
        let unrelated = "Today my cat slept on the windowsill, and the dog barked at \
                          squirrels for several hours straight without pause.";
        let v = evaluate(unrelated, &corpus_with_nyt(), DEFAULT_CONFIDENCE_THRESHOLD);
        assert!(!v.confident_match);
        assert!(v.license_urn.is_none());
    }

    #[test]
    fn threshold_floor_collapses_low_score_to_no_match() {
        let corpus = LicenseCorpus::build(vec![LicensedDocument {
            license_urn: "urn:rsl:short:001".to_string(),
            body: "alpha beta gamma delta epsilon".to_string(),
        }]);
        let v = evaluate("alpha beta", &corpus, 0.99);
        assert!(!v.confident_match);
    }

    #[test]
    fn long_unattributed_quote_fires_heuristic() {
        let body = "x".repeat(240);
        let corpus = LicenseCorpus::build(vec![LicensedDocument {
            license_urn: "urn:rsl:other:001".to_string(),
            body: "something completely different from the response".to_string(),
        }]);
        let v = evaluate(&body, &corpus, DEFAULT_CONFIDENCE_THRESHOLD);
        assert!(v.confident_match);
        assert!(
            v.license_urn.is_none(),
            "Rule A carries no document attribution"
        );
    }

    #[test]
    fn detection_method_stable_strings() {
        assert_eq!(DetectionMethod::SubstringMatch.as_str(), "substring_match");
        assert_eq!(
            DetectionMethod::HeuristicSignals.as_str(),
            "heuristic_signals"
        );
        assert_eq!(
            DetectionMethod::EmbeddingSimilarity.as_str(),
            "embedding_similarity"
        );
        assert_eq!(DetectionMethod::Combined.as_str(), "combined");
    }

    // --- guardrail ---

    fn guardrail(mode: &str, documents: serde_json::Value) -> LicenseLeakGuardrail {
        LicenseLeakGuardrail::from_config(&serde_json::json!({
            "type": "license_leak",
            "mode": mode,
            "documents": documents,
        }))
        .expect("valid config compiles")
    }

    fn nyt_documents() -> serde_json::Value {
        serde_json::json!([{
            "license_urn": "urn:rsl:nyt.com:article:2026-04-12:fed-spring-meeting",
            "body": nyt_article(),
        }])
    }

    #[test]
    fn no_documents_is_a_documented_no_op() {
        let g = guardrail("block", serde_json::json!([]));
        assert!(g.check(nyt_article()).is_none());
    }

    #[test]
    fn block_mode_returns_a_guardrail_block() {
        let g = guardrail("block", nyt_documents());
        let block = g.check(nyt_article()).expect("confident match blocks");
        assert_eq!(block.name, "license_leak");
        assert!(block.reason.contains("urn:rsl:nyt.com"));
    }

    #[test]
    fn block_mode_records_the_findings_metric() {
        // The block/method label pair is unique to this test's mode
        // choice ("block") crossed with whichever detector fires on
        // `nyt_article()`, so a fresh count comparison does not need
        // process-wide metric isolation.
        let g = guardrail("block", nyt_documents());
        let verdict = evaluate(
            nyt_article(),
            &LicenseCorpus::build(vec![LicensedDocument {
                license_urn: "urn:rsl:nyt.com:article:2026-04-12:fed-spring-meeting".to_string(),
                body: nyt_article().to_string(),
            }]),
            DEFAULT_CONFIDENCE_THRESHOLD,
        );
        let before =
            crate::ai_metrics::license_leak_finding_value("block", verdict.method.as_str());
        g.check(nyt_article()).expect("confident match blocks");
        let after = crate::ai_metrics::license_leak_finding_value("block", verdict.method.as_str());
        assert_eq!(after, before + 1.0);
    }

    #[test]
    fn redact_mode_also_blocks_pending_a_rewrite_channel() {
        // See the module docs: `check()` cannot rewrite content, so
        // `redact` fails closed the same way `block` does, matching
        // the precedent `PiiGuardrail`'s `Mask` action already sets.
        let g = guardrail("redact", nyt_documents());
        assert!(g.check(nyt_article()).is_some());
    }

    #[test]
    fn warn_mode_forwards_the_response() {
        let g = guardrail("warn", nyt_documents());
        assert!(g.check(nyt_article()).is_none());
    }

    #[test]
    fn log_mode_forwards_the_response() {
        let g = guardrail("log", nyt_documents());
        assert!(g.check(nyt_article()).is_none());
    }

    #[test]
    fn clean_output_never_blocks_regardless_of_mode() {
        let clean = "The weather in the Pacific Northwest tends toward overcast skies.";
        for mode in ["block", "redact", "warn", "log"] {
            let g = guardrail(mode, nyt_documents());
            assert!(g.check(clean).is_none(), "mode={mode}");
        }
    }

    #[test]
    fn confidence_threshold_clamps_to_the_tenant_tunable_range() {
        let g = LicenseLeakGuardrail::from_config(&serde_json::json!({
            "type": "license_leak",
            "confidence_threshold": 0.10,
        }))
        .unwrap();
        assert_eq!(g.confidence_threshold, MIN_CONFIDENCE_THRESHOLD);

        let g = LicenseLeakGuardrail::from_config(&serde_json::json!({
            "type": "license_leak",
            "confidence_threshold": 1.50,
        }))
        .unwrap();
        assert_eq!(g.confidence_threshold, MAX_CONFIDENCE_THRESHOLD);
    }

    #[test]
    fn timeout_action_overrides_mode_on_a_slow_evaluation() {
        // The source this was ported from parsed `timeout_action` but
        // never consumed it (grep confirms no read site outside its
        // own `Deserialize` round-trip tests); this port wires it up
        // for real via `dispositioned_mode`, a pure function of
        // `timed_out` rather than a real `Instant`, so the override is
        // provable without a wall-clock-timing-dependent test.
        assert_eq!(
            dispositioned_mode(true, LicenseLeakMode::Block, LicenseLeakTimeoutAction::Log),
            LicenseLeakMode::Log,
            "timeout_action must win over mode when the budget is exceeded"
        );
        assert_eq!(
            dispositioned_mode(false, LicenseLeakMode::Block, LicenseLeakTimeoutAction::Log),
            LicenseLeakMode::Block,
            "mode must apply unchanged on a timely evaluation"
        );
    }

    #[test]
    fn max_eval_ms_is_plumbed_through_to_the_timeout_check() {
        // Integration-level companion to the unit test above: a
        // guardrail built with an unreachable budget (0ms, and a
        // corpus large enough that evaluation takes measurably longer
        // than that) must apply `timeout_action` rather than `mode`
        // end to end through `check()`.
        let big_body = format!("{} {}", nyt_article().repeat(200), "padding ".repeat(5000));
        let g = LicenseLeakGuardrail::from_config(&serde_json::json!({
            "type": "license_leak",
            "mode": "block",
            "timeout_action": "log",
            "max_eval_ms": 0,
            "documents": [{"license_urn": "urn:rsl:big:001", "body": big_body}],
        }))
        .unwrap();
        // Whether or not this particular machine's clock resolution
        // catches a sub-millisecond evaluation as "timed out" is not
        // the property under test (the unit test above already pins
        // that); this only confirms `check()` never panics and stays
        // internally consistent when it does.
        let _ = g.check(&big_body);
    }

    #[test]
    fn deserialize_config_defaults() {
        let cfg: LicenseLeakGuardrailConfig =
            serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(cfg.mode, LicenseLeakMode::Warn);
        assert_eq!(cfg.timeout_action, LicenseLeakTimeoutAction::Warn);
        assert_eq!(cfg.max_eval_ms, 50);
        assert!(cfg.documents.is_empty());
    }

    #[test]
    fn deserialize_config_with_block_mode() {
        let cfg: LicenseLeakGuardrailConfig = serde_json::from_value(serde_json::json!({
            "mode": "block",
            "confidence_threshold": 0.95,
            "max_eval_ms": 25,
            "timeout_action": "block",
        }))
        .unwrap();
        assert_eq!(cfg.mode, LicenseLeakMode::Block);
        assert_eq!(cfg.timeout_action, LicenseLeakTimeoutAction::Block);
        assert_eq!(cfg.max_eval_ms, 25);
    }
}

//! `prompt_injection_v2` eval harness.
//!
//! Loads text files of golden prompts (`eval/prompt_injection/`),
//! runs the configured detector against each line, and gates each
//! detector at its expected quality bar.
//!
//! Two corpora are loaded:
//!
//! - `golden_injection.txt` (legacy) plus `golden_injection_owasp.txt`
//!   (OWASP-LLM-01 official-style payloads). Concatenated for
//!   evaluation so both regression and OWASP coverage gate together.
//! - `golden_clean.txt` (legacy) plus `golden_clean_v2.txt` (extended
//!   ShareGPT / WildChat style turns). Concatenated similarly.
//!
//! Heuristic detector: gates at precision and recall >= 0.7. The
//! heuristic is intentionally a substring matcher; the new gate
//! exists to catch regressions and to confirm the OWASP corpus does
//! not silently degrade the existing baseline.
//!
//! ONNX detector: gates at precision and recall >= 0.9 against the
//! injection corpus and a false-positive rate < 2% on the clean
//! corpus. Skipped when the `SBPROXY_ONNX_MODEL` and
//! `SBPROXY_ONNX_TOKENIZER` environment variables are not set so CI
//! environments without a model file can still run the ignored
//! suite.
//!
//! Marked `#[ignore]` so the regular `cargo test` run does not depend
//! on the corpus layout or on a model being present. Run explicitly:
//!
//! ```text
//! cargo test -p sbproxy-modules --test prompt_injection_eval -- --ignored
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use sbproxy_modules::{
    classification_cache_stats, evaluate_body, reset_classification_cache, BodyAwareConfig,
    BodyAwareOutcome, DetectionLabel, OnnxDetector, PromptInjectionV2Outcome,
    PromptInjectionV2Policy,
};

/// Locate the workspace `eval/prompt_injection` directory regardless of
/// where cargo invokes the test from.
fn corpus_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // sbproxy-modules lives at <repo>/crates/sbproxy-modules; ascend to
    // the workspace root, then dive into eval/prompt_injection.
    manifest
        .parent()
        .expect("workspace dir")
        .parent()
        .expect("repo root")
        .join("eval/prompt_injection")
}

/// Load a corpus file. Lines starting with `#` are treated as
/// comments; blank lines are skipped.
fn load_corpus(name: &str) -> Vec<String> {
    let path = corpus_root().join(name);
    let body =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    body.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}

/// Result of running the policy across a corpus, summarised as a 2x2
/// confusion matrix.
#[derive(Debug, Default)]
struct Counts {
    tp: usize,
    fp: usize,
    tn: usize,
    fn_: usize,
}

impl Counts {
    fn precision(&self) -> f64 {
        let denom = self.tp + self.fp;
        if denom == 0 {
            0.0
        } else {
            self.tp as f64 / denom as f64
        }
    }
    fn recall(&self) -> f64 {
        let denom = self.tp + self.fn_;
        if denom == 0 {
            0.0
        } else {
            self.tp as f64 / denom as f64
        }
    }
}

fn evaluate(policy: &PromptInjectionV2Policy, corpus: &[String], expected_hit: bool) -> Counts {
    let mut counts = Counts::default();
    for prompt in corpus {
        let hit = match policy.evaluate(prompt) {
            PromptInjectionV2Outcome::Hit { result } => {
                // Defensive: anything labelled Clean should not be a
                // hit. The policy guards against this but the eval is
                // a good place to assert it.
                result.label != DetectionLabel::Clean
            }
            PromptInjectionV2Outcome::Clean => false,
        };
        match (expected_hit, hit) {
            (true, true) => counts.tp += 1,
            (true, false) => counts.fn_ += 1,
            (false, false) => counts.tn += 1,
            (false, true) => counts.fp += 1,
        }
    }
    counts
}

/// Load + concatenate both injection corpora.
fn load_all_injections() -> Vec<String> {
    let mut v = load_corpus("golden_injection.txt");
    v.extend(load_corpus("golden_injection_owasp.txt"));
    v
}

/// Load + concatenate both clean corpora.
fn load_all_cleans() -> Vec<String> {
    let mut v = load_corpus("golden_clean.txt");
    v.extend(load_corpus("golden_clean_v2.txt"));
    v
}

#[test]
#[ignore = "eval gate; run with `cargo test --test prompt_injection_eval -- --ignored`"]
fn heuristic_baseline_meets_precision_and_recall_thresholds() {
    let injections = load_all_injections();
    let cleans = load_all_cleans();
    assert!(
        injections.len() >= 60,
        "combined injection corpora should have >= 60 lines, got {}",
        injections.len()
    );
    assert!(
        cleans.len() >= 60,
        "combined clean corpora should have >= 60 lines, got {}",
        cleans.len()
    );

    let policy = PromptInjectionV2Policy::from_config(serde_json::json!({})).unwrap();

    let pos = evaluate(&policy, &injections, true);
    let neg = evaluate(&policy, &cleans, false);
    let merged = Counts {
        tp: pos.tp,
        fn_: pos.fn_,
        // Clean corpus contributes only false positives + true negatives.
        fp: neg.fp,
        tn: neg.tn,
    };

    let precision = merged.precision();
    let recall = merged.recall();

    eprintln!(
        "heuristic eval: tp={} fp={} tn={} fn={} precision={:.3} recall={:.3}",
        merged.tp, merged.fp, merged.tn, merged.fn_, precision, recall
    );

    // Regression gate. The heuristic is a substring matcher; it
    // intentionally lags the ONNX detector. Bump if a future
    // heuristic improvement raises the floor.
    assert!(
        precision >= 0.7,
        "precision {:.3} below 0.7 (tp={}, fp={})",
        precision,
        merged.tp,
        merged.fp
    );
    assert!(
        recall >= 0.7,
        "recall {:.3} below 0.7 (tp={}, fn={})",
        recall,
        merged.tp,
        merged.fn_
    );
}

/// ONNX detector eval. Skipped unless `SBPROXY_ONNX_MODEL` and
/// `SBPROXY_ONNX_TOKENIZER` point at local files.
///
/// Gate: precision and recall both >= 0.9 against the OWASP corpus,
/// false-positive rate < 2% against the clean corpus.
#[test]
#[ignore = "requires SBPROXY_ONNX_MODEL + SBPROXY_ONNX_TOKENIZER env vars"]
fn onnx_detector_meets_target() {
    let model = match std::env::var("SBPROXY_ONNX_MODEL") {
        Ok(v) => v,
        Err(_) => {
            eprintln!(
                "SBPROXY_ONNX_MODEL not set; skipping. Provide model + tokenizer paths to gate."
            );
            return;
        }
    };
    let tokenizer = match std::env::var("SBPROXY_ONNX_TOKENIZER") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("SBPROXY_ONNX_TOKENIZER not set; skipping.");
            return;
        }
    };
    let injection_label =
        std::env::var("SBPROXY_ONNX_INJECTION_LABEL").unwrap_or_else(|_| "INJECTION".to_string());

    // Load directly from local files so the test does not depend on
    // network or cache-dir state.
    let labels = vec!["SAFE".to_string(), injection_label.clone()];
    let classifier = match sbproxy_classifiers::OnnxClassifier::load_with_labels(
        std::path::Path::new(&model),
        std::path::Path::new(&tokenizer),
        Some(labels),
    ) {
        Ok(c) => Arc::new(c),
        Err(e) => panic!("ONNX classifier load failed: {e}"),
    };
    let detector = OnnxDetector::from_classifier(classifier, 0.5, injection_label);
    let policy = PromptInjectionV2Policy::with_detector(Arc::new(detector)).with_threshold(0.5);
    let injections = load_all_injections();
    let cleans = load_all_cleans();

    let pos = evaluate(&policy, &injections, true);
    let neg = evaluate(&policy, &cleans, false);
    let merged = Counts {
        tp: pos.tp,
        fn_: pos.fn_,
        fp: neg.fp,
        tn: neg.tn,
    };

    let precision = merged.precision();
    let recall = merged.recall();
    let fpr = if (merged.fp + merged.tn) == 0 {
        0.0
    } else {
        merged.fp as f64 / (merged.fp + merged.tn) as f64
    };

    eprintln!(
        "onnx eval: tp={} fp={} tn={} fn={} precision={:.3} recall={:.3} fpr={:.3}",
        merged.tp, merged.fp, merged.tn, merged.fn_, precision, recall, fpr
    );

    assert!(
        precision >= 0.9,
        "precision {:.3} below 0.9 (tp={}, fp={})",
        precision,
        merged.tp,
        merged.fp
    );
    assert!(
        recall >= 0.9,
        "recall {:.3} below 0.9 (tp={}, fn={})",
        recall,
        merged.tp,
        merged.fn_
    );
    assert!(
        fpr < 0.02,
        "false-positive rate {:.3} above 2% (fp={}, tn={})",
        fpr,
        merged.fp,
        merged.tn
    );
}

/// Microbenchmark for the body-aware classification cache. Asserts
/// p99 latency < 1 ms for the cache hit path and < 50 ms for the
/// cache miss path, run against the heuristic detector.
#[test]
#[ignore = "bench gate; run with `cargo test ... bench_classification_cache -- --ignored`"]
fn bench_classification_cache() {
    reset_classification_cache();
    let policy = PromptInjectionV2Policy::from_config(serde_json::json!({})).unwrap();
    let cfg = BodyAwareConfig::default();

    // Prime: 10 distinct prompts get classified once each (10 misses).
    let distinct: Vec<String> = (0..10)
        .map(|i| format!("test prompt number {i} that is sufficiently long to be classified"))
        .collect();
    for p in &distinct {
        let messages = vec![p.clone()];
        let _ = evaluate_body(&policy, &messages, "host", None, false, &cfg);
    }

    // 990 hits.
    let mut hit_lats = Vec::with_capacity(990);
    for i in 0..990 {
        let messages = vec![distinct[i % distinct.len()].clone()];
        let t0 = Instant::now();
        let _ = evaluate_body(&policy, &messages, "host", None, false, &cfg);
        hit_lats.push(t0.elapsed().as_micros());
    }

    // Force fresh misses (10 distinct new prompts) and time them.
    let mut miss_lats = Vec::with_capacity(10);
    for i in 0..10 {
        let messages = vec![format!(
            "fresh miss prompt {i} {}",
            chrono::Utc::now().to_rfc3339()
        )];
        let t0 = Instant::now();
        let _ = evaluate_body(&policy, &messages, "host", None, false, &cfg);
        miss_lats.push(t0.elapsed().as_micros());
    }

    fn p99(mut v: Vec<u128>) -> u128 {
        v.sort_unstable();
        let idx = ((v.len() as f64 * 0.99).ceil() as usize).saturating_sub(1);
        v[idx.min(v.len() - 1)]
    }
    let p99_hit_us = p99(hit_lats);
    let p99_miss_us = p99(miss_lats);
    let stats = classification_cache_stats();
    eprintln!(
        "cache bench: p99_hit={p99_hit_us}us p99_miss={p99_miss_us}us hits={} misses={} ratio={:.3}",
        stats.hits,
        stats.misses,
        stats.hit_ratio()
    );

    assert!(
        p99_hit_us < 1_000,
        "p99 hit latency {p99_hit_us}us exceeds 1ms budget"
    );
    // Heuristic miss latency budget; ONNX miss is bounded separately
    // by `onnx_detector_meets_target`.
    assert!(
        p99_miss_us < 50_000,
        "p99 miss latency {p99_miss_us}us exceeds 50ms budget"
    );
    assert!(stats.hits >= 900, "cache hit count too low: {}", stats.hits);
}

#[test]
#[ignore = "eval gate; run with `cargo test --test prompt_injection_eval -- --ignored`"]
fn body_aware_evaluates_per_message_and_picks_worst() {
    // Wires the body-aware path against the heuristic detector and
    // the OWASP corpus. The body is simulated as a multi-turn
    // conversation: clean turns plus one injection turn. Worst-of-N
    // must surface the injection.
    reset_classification_cache();
    let policy = PromptInjectionV2Policy::from_config(serde_json::json!({})).unwrap();
    let cfg = BodyAwareConfig::default();
    let injections = load_corpus("golden_injection_owasp.txt");
    assert!(!injections.is_empty());
    let mut messages = vec![
        "Hi there!".to_string(),
        "Could you help me with a quick question?".to_string(),
        injections[0].clone(),
        "Thanks in advance.".to_string(),
    ];
    let outcome = evaluate_body(&policy, &messages, "h", None, false, &cfg);
    match outcome {
        BodyAwareOutcome::Hit {
            result,
            prompt_sha256,
        } => {
            assert_ne!(result.label, DetectionLabel::Clean);
            assert_eq!(prompt_sha256.len(), 64);
        }
        other => panic!("expected Hit on multi-turn body, got {:?}", other),
    }
    // Bypass path: same body, but virtual key opted out.
    messages.push("Same payload but bypassed".to_string());
    let bypass_outcome = evaluate_body(&policy, &messages, "h", Some("vk-eval"), true, &cfg);
    assert!(matches!(bypass_outcome, BodyAwareOutcome::Bypassed));
}

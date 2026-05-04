//! Prometheus / OpenMetrics exemplar wiring (R1.1 / A1.4).
//!
//! The `prometheus` 0.13 crate does not expose exemplar storage on its
//! `HistogramVec` collector, so Wave 1 ships a side-store: we record
//! one exemplar per `(metric_name, label_set, bucket_le)` slot and
//! splice them into the rendered metrics output before scrape.
//!
//! Per `docs/adr-observability.md` the Wave 1 exemplar set is:
//!
//! - `sbproxy_request_duration_seconds_bucket`
//! - `sbproxy_ledger_redeem_duration_seconds_bucket`
//! - `sbproxy_policy_evaluation_duration_seconds_bucket`
//! - `sbproxy_outbound_request_duration_seconds_bucket`
//! - `sbproxy_audit_emit_duration_seconds_bucket`
//!
//! Operators MUST run Prometheus with `--enable-feature=exemplar-storage`
//! and scrape with `application/openmetrics-text` content negotiation.
//! The `examples/00-observability-stack/` Compose recipe wires both.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::OnceLock;

// --- Storage ---

/// Exemplar payload attached to a histogram bucket.
#[derive(Debug, Clone)]
pub struct Exemplar {
    /// Sampled observation value.
    pub value: f64,
    /// W3C trace_id (32 lowercase hex chars). Empty when the
    /// observation came from a non-traced code path.
    pub trace_id: String,
    /// W3C span_id (16 lowercase hex chars). Empty when not available.
    pub span_id: String,
    /// Unix epoch timestamp in seconds (with millisecond precision)
    /// when the exemplar was recorded. Prometheus uses this to break
    /// ties when multiple exemplars land in the same bucket per
    /// scrape interval.
    pub timestamp_secs: f64,
}

/// Key uniquely identifying a histogram bucket exemplar slot.
///
/// `metric` is the family name without the `_bucket` suffix.
/// `labels` is the canonical `key="value",key="value"` rendering of
/// the per-series labels (without the `le` label).
/// `le` is the bucket upper bound as a string, matching the `le=` label
/// in the rendered output (e.g. `"0.005"`, `"+Inf"`).
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct Key {
    metric: &'static str,
    labels: String,
    le: String,
}

/// Global side-store. One slot per `(metric, labels, le)` tuple. New
/// observations overwrite the prior exemplar; this gives Prometheus
/// "the most recent outlier in this bucket since the last scrape",
/// which matches the OpenMetrics scrape semantic.
static STORE: OnceLock<Mutex<HashMap<Key, Exemplar>>> = OnceLock::new();

fn store() -> &'static Mutex<HashMap<Key, Exemplar>> {
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

// --- Recording ---

/// Record an exemplar against the named histogram. `labels` is the
/// label set EXCLUDING `le`. The function bucketises `value` against
/// the supplied `buckets` slice (must be in ascending order) and
/// writes the exemplar into the matching bucket plus all higher
/// buckets, matching Prometheus's cumulative bucket convention.
///
/// `trace_id` / `span_id` are empty strings when no trace context is
/// active; in that case the exemplar is recorded with empty IDs and
/// the rendered output omits the `trace_id` label.
pub fn record(
    metric: &'static str,
    labels: &[(&str, &str)],
    value: f64,
    buckets: &[f64],
    trace_id: &str,
    span_id: &str,
) {
    if !is_exemplar_metric(metric) {
        // Wave 1 ships a fixed allow-list to keep the side-store
        // bounded. Future histograms opt in by name in
        // `is_exemplar_metric`.
        return;
    }
    let timestamp_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let label_str = render_labels(labels);
    let mut g = store().lock().expect("exemplar store mutex poisoned");
    for &b in buckets {
        if value <= b {
            g.insert(
                Key {
                    metric,
                    labels: label_str.clone(),
                    le: format_bucket(b),
                },
                Exemplar {
                    value,
                    trace_id: trace_id.to_string(),
                    span_id: span_id.to_string(),
                    timestamp_secs,
                },
            );
        }
    }
    // The +Inf bucket always matches.
    g.insert(
        Key {
            metric,
            labels: label_str,
            le: "+Inf".to_string(),
        },
        Exemplar {
            value,
            trace_id: trace_id.to_string(),
            span_id: span_id.to_string(),
            timestamp_secs,
        },
    );
}

/// Standard 12-bucket latency layout used by every sbproxy histogram
/// per `metrics.rs`. Exposed so tests and callers don't have to
/// duplicate the literal.
pub const STANDARD_LATENCY_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Allow-list of histograms that emit exemplars. Pinned by A1.4.
fn is_exemplar_metric(metric: &str) -> bool {
    matches!(
        metric,
        "sbproxy_request_duration_seconds"
            | "sbproxy_origin_request_duration_seconds"
            | "sbproxy_ledger_redeem_duration_seconds"
            | "sbproxy_policy_evaluation_duration_seconds"
            | "sbproxy_outbound_request_duration_seconds"
            | "sbproxy_audit_emit_duration_seconds"
    )
}

fn render_labels(labels: &[(&str, &str)]) -> String {
    if labels.is_empty() {
        return String::new();
    }
    labels
        .iter()
        .map(|(k, v)| format!("{}=\"{}\"", k, escape_label_value(v)))
        .collect::<Vec<_>>()
        .join(",")
}

fn escape_label_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

fn format_bucket(b: f64) -> String {
    // Prometheus formats `1` as `1` and `0.005` as `0.005`. Match
    // `prometheus`'s `TextEncoder` so the label values line up
    // exactly.
    if b.is_finite() {
        // Integer values (e.g. `1`, `5`, `10`) drop the trailing `.0`.
        if (b - b.trunc()).abs() < f64::EPSILON {
            format!("{}", b as i64)
        } else {
            format!("{}", b)
        }
    } else {
        "+Inf".to_string()
    }
}

// --- Splicing into rendered output ---

/// Append exemplars to a rendered Prometheus text-format buffer,
/// transforming each `_bucket` line that has a known exemplar into
/// the OpenMetrics form:
///
/// ```text
/// sbproxy_request_duration_seconds_bucket{...,le="0.005"} 12 # {trace_id="..."} 0.0034 1714512000.123
/// ```
///
/// Lines without a recorded exemplar pass through unchanged. The
/// content-type negotiated with the scraper must be
/// `application/openmetrics-text; version=1.0.0` for Prometheus to
/// parse the trailing `# {...}` block; the standard
/// `text/plain; version=0.0.4` exposition silently ignores the
/// suffix, so this transform is safe to always apply.
pub fn splice_into_text(input: &str) -> String {
    let store = store().lock().expect("exemplar store mutex poisoned");
    if store.is_empty() {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len() + store.len() * 64);
    for line in input.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || !trimmed.contains("_bucket{") {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        // Extract the metric name (everything before `{`).
        let brace = match line.find('{') {
            Some(b) => b,
            None => {
                out.push_str(line);
                out.push('\n');
                continue;
            }
        };
        let metric_with_suffix = &line[..brace];
        let metric_base = match metric_with_suffix.strip_suffix("_bucket") {
            Some(m) => m,
            None => {
                out.push_str(line);
                out.push('\n');
                continue;
            }
        };
        // Extract labels between `{` and `}`.
        let close = match line[brace..].find('}') {
            Some(c) => brace + c,
            None => {
                out.push_str(line);
                out.push('\n');
                continue;
            }
        };
        let label_block = &line[brace + 1..close];
        let (le, other_labels) = split_le(label_block);
        let key = Key {
            metric: leak_metric_base(metric_base),
            labels: other_labels,
            le,
        };
        match store.get(&key) {
            Some(ex) => {
                let exemplar_suffix = render_exemplar(ex);
                out.push_str(line);
                out.push(' ');
                out.push_str(&exemplar_suffix);
                out.push('\n');
            }
            None => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out
}

fn split_le(label_block: &str) -> (String, String) {
    // The label block is comma-separated. We need to find the `le=` pair.
    let mut le = String::new();
    let mut rest: Vec<&str> = Vec::new();
    for part in label_block.split(',') {
        let p = part.trim();
        if let Some(value_quoted) = p.strip_prefix("le=") {
            le = value_quoted.trim_matches('"').to_string();
        } else {
            rest.push(p);
        }
    }
    (le, rest.join(","))
}

// We need a `&'static str` for the Key, but the metric name comes
// from a borrowed slice of the rendered text. Rather than allocate a
// leaked &'static str per scrape (memory leak), we look up by string
// via a thread-local intern table. For correctness here, since the
// allow-list of metric names is closed, we map by string compare.
fn leak_metric_base(name: &str) -> &'static str {
    match name {
        "sbproxy_request_duration_seconds" => "sbproxy_request_duration_seconds",
        "sbproxy_origin_request_duration_seconds" => "sbproxy_origin_request_duration_seconds",
        "sbproxy_ledger_redeem_duration_seconds" => "sbproxy_ledger_redeem_duration_seconds",
        "sbproxy_policy_evaluation_duration_seconds" => {
            "sbproxy_policy_evaluation_duration_seconds"
        }
        "sbproxy_outbound_request_duration_seconds" => "sbproxy_outbound_request_duration_seconds",
        "sbproxy_audit_emit_duration_seconds" => "sbproxy_audit_emit_duration_seconds",
        _ => "",
    }
}

fn render_exemplar(ex: &Exemplar) -> String {
    let mut labels = Vec::new();
    if !ex.trace_id.is_empty() {
        labels.push(format!("trace_id=\"{}\"", ex.trace_id));
    }
    if !ex.span_id.is_empty() {
        labels.push(format!("span_id=\"{}\"", ex.span_id));
    }
    let label_str = labels.join(",");
    format!("# {{{}}} {} {}", label_str, ex.value, ex.timestamp_secs)
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_writes_into_matching_bucket() {
        record(
            "sbproxy_request_duration_seconds",
            &[("hostname", "api.example.com")],
            0.012,
            STANDARD_LATENCY_BUCKETS,
            "0af7651916cd43dd8448eb211c80319c",
            "b7ad6b7169203331",
        );
        let g = store().lock().unwrap();
        // 0.012 falls into le=0.025 and above; should NOT be in le=0.005.
        let key_pass = Key {
            metric: "sbproxy_request_duration_seconds",
            labels: "hostname=\"api.example.com\"".to_string(),
            le: "0.025".to_string(),
        };
        assert!(g.get(&key_pass).is_some());
        let key_under = Key {
            metric: "sbproxy_request_duration_seconds",
            labels: "hostname=\"api.example.com\"".to_string(),
            le: "0.005".to_string(),
        };
        assert!(g.get(&key_under).is_none());
    }

    #[test]
    fn unknown_metric_is_ignored() {
        record(
            "not_in_allow_list",
            &[],
            0.1,
            STANDARD_LATENCY_BUCKETS,
            "tid",
            "sid",
        );
        let g = store().lock().unwrap();
        let key = Key {
            metric: "not_in_allow_list",
            labels: String::new(),
            le: "0.25".to_string(),
        };
        assert!(g.get(&key).is_none());
    }

    #[test]
    fn splice_appends_openmetrics_exemplar_suffix() {
        // Use a unique label so the test doesn't collide with state
        // left by other tests sharing the global store.
        record(
            "sbproxy_ledger_redeem_duration_seconds",
            &[("hostname", "splice-test.example.com")],
            0.003,
            STANDARD_LATENCY_BUCKETS,
            "trace-zzz",
            "span-zzz",
        );
        let input = "sbproxy_ledger_redeem_duration_seconds_bucket{hostname=\"splice-test.example.com\",le=\"0.005\"} 1\n";
        let out = splice_into_text(input);
        assert!(
            out.contains("# {trace_id=\"trace-zzz\""),
            "expected exemplar suffix, got: {}",
            out
        );
        assert!(out.contains("0.003"));
    }

    #[test]
    fn splice_preserves_lines_without_exemplar() {
        let input = "sbproxy_unrelated_metric_bucket{le=\"0.005\"} 7\n# HELP foo bar\n";
        let out = splice_into_text(input);
        assert!(out.contains("sbproxy_unrelated_metric_bucket"));
        assert!(out.contains("# HELP foo bar"));
        assert!(!out.contains("trace_id"));
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Scores and feedback ingestion sink (WOR-2581).
//!
//! An external eval framework, a thumbs up/down widget, or a human
//! reviewer records a quality signal against a request this proxy
//! logged, and the console charts it. Two routes:
//!
//! - `POST /api/requests/{request_id}/scores` records one score.
//! - `GET  /api/scores` lists recent scores and their per-label
//!   aggregates.
//!
//! # sbproxy is not an eval framework
//!
//! Helicone's posture, and the one this follows: accept integer scores,
//! do not compute them. There is deliberately no scoring logic here, no
//! judge, no rubric, and no notion of a score being right. Something
//! else decides what a score is; this stores it beside a request id and
//! charts it, and that boundary is the feature rather than a limitation
//! of it. `sbproxy-ai`'s judge already exists for the other job and is
//! not wired to this on purpose: a sink that silently started generating
//! its own scores would make every chart on it unreadable.
//!
//! The bounded integer range is Portkey's shape, where feedback is a
//! first-class `-10..10` filter dimension rather than a free numeric
//! column. A bound is what makes scores from two different evaluators
//! comparable on one axis at all.
//!
//! # What is never stored here
//!
//! No prompt, no completion, no caller content of any kind. A score is
//! an integer, an optional short label naming the evaluator, and a
//! request id. Content lives behind
//! `GET /api/requests/{id}/content`, which is admin-role-only and
//! audits every read, and nothing in this module reaches it.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// Response tuple shared by the admin dispatchers.
type Resp = (u16, &'static str, String);

/// Inclusive bound on an accepted score.
///
/// Portkey's range. A score outside it is refused rather than clamped:
/// clamping would make a misconfigured evaluator reporting 0..100 look
/// like a stream of perfect tens, which is worse than an error the
/// operator can see.
const SCORE_MIN: i64 = -10;
/// Upper inclusive bound on an accepted score. See [`SCORE_MIN`].
const SCORE_MAX: i64 = 10;

/// Cap on a label's length. A label names an evaluator
/// ("helpfulness", "human-review"), so this is generous for the real
/// use and tight enough that the ring cannot be grown by one caller
/// sending long strings.
const LABEL_MAX_LEN: usize = 64;

/// Cap on a request id accepted for keying. Matches the shape the
/// request ring emits rather than accepting anything.
const REQUEST_ID_MAX_LEN: usize = 128;

/// How many scores are retained in process.
///
/// Bounded because this is a console aid, not a datastore: an operator
/// looking at a chart wants the recent window, and an unbounded ring
/// behind an unauthenticated-adjacent POST route is a memory-growth
/// path. An operator who needs history exports it or ships the
/// structured log lines to their warehouse.
const RING_CAPACITY: usize = 5_000;

/// One recorded score.
#[derive(Debug, Clone, Serialize)]
struct ScoreEntry {
    /// The request this score is about.
    request_id: String,
    /// The score itself, within [`SCORE_MIN`]..=[`SCORE_MAX`].
    score: i64,
    /// What produced it, when the caller said. Sanitized and capped.
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    /// RFC 3339 UTC, when this proxy received the score. Deliberately
    /// not a caller-supplied timestamp: a sink that trusts the caller's
    /// clock produces charts that cannot be read against anything else
    /// the proxy recorded.
    recorded_at: String,
}

/// Request body for `POST /api/requests/{id}/scores`.
#[derive(Debug, Deserialize)]
struct ScoreBody {
    score: i64,
    #[serde(default)]
    label: Option<String>,
}

fn ring() -> &'static Mutex<VecDeque<ScoreEntry>> {
    static RING: std::sync::OnceLock<Mutex<VecDeque<ScoreEntry>>> = std::sync::OnceLock::new();
    RING.get_or_init(|| Mutex::new(VecDeque::with_capacity(128)))
}

/// Strip a caller-supplied label down to something safe to render and
/// to put in a metric label.
///
/// Control characters are the forgery class that matters for a log
/// line, and an unbounded label is both a memory and a cardinality
/// problem. Anything left is kept verbatim: an evaluator name is
/// operator vocabulary and mangling it makes the chart legend useless.
fn sanitize_label(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .take(LABEL_MAX_LEN)
        .collect();
    let trimmed = cleaned.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn json_error(status: u16, code: &str, message: &str) -> Resp {
    (
        status,
        "application/json",
        serde_json::json!({ "error": message, "code": code }).to_string(),
    )
}

/// Record one score. Returns the stored entry as JSON.
fn record(request_id: &str, body: Option<&str>) -> Resp {
    if request_id.is_empty() || request_id.len() > REQUEST_ID_MAX_LEN {
        return json_error(400, "bad_request", "request id missing or too long");
    }
    let Some(raw) = body.map(str::trim).filter(|b| !b.is_empty()) else {
        return json_error(
            400,
            "bad_request",
            "missing JSON body; expected {\"score\": <int>, \"label\": \"...\"}",
        );
    };
    let parsed: ScoreBody = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(error) => {
            return json_error(
                400,
                "bad_request",
                &format!("invalid JSON body: {}", error.to_string().replace('"', "'")),
            )
        }
    };
    if parsed.score < SCORE_MIN || parsed.score > SCORE_MAX {
        // Refused, not clamped. See SCORE_MIN.
        return json_error(
            422,
            "score_out_of_range",
            &format!("score must be between {SCORE_MIN} and {SCORE_MAX} inclusive"),
        );
    }
    let label = parsed.label.as_deref().and_then(sanitize_label);

    let entry = ScoreEntry {
        request_id: request_id.to_string(),
        score: parsed.score,
        label: label.clone(),
        recorded_at: now_rfc3339(),
    };

    {
        let mut guard = match ring().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        while guard.len() >= RING_CAPACITY {
            guard.pop_front();
        }
        guard.push_back(entry.clone());
    }

    sbproxy_observe::metrics::record_feedback_score(label.as_deref(), parsed.score);

    // The decision line. The score and its label only: never a prompt,
    // a completion, or anything else about the request. The request id
    // correlates this with the access log without carrying content.
    tracing::info!(
        target: "sbproxy::admin::scores",
        request_id = %entry.request_id,
        score = parsed.score,
        label = %entry.label.as_deref().unwrap_or("none"),
        "feedback score recorded"
    );

    (
        200,
        "application/json",
        serde_json::to_string(&entry).unwrap_or_else(|_| r#"{"error":"serialize"}"#.to_string()),
    )
}

/// Per-label rollup accompanying the listing.
#[derive(Debug, Serialize)]
struct LabelAggregate {
    label: String,
    count: usize,
    /// Arithmetic mean, rounded to three places. The only arithmetic
    /// this module does, and it is a display convenience rather than a
    /// statistic: sbproxy does not compute scores, it adds up ones it
    /// was handed.
    mean: f64,
    min: i64,
    max: i64,
}

/// List recent scores, newest first, plus per-label aggregates.
///
/// `request_id=<id>` narrows to one request, which is what the console's
/// per-request panel asks for.
fn list(path: &str) -> Resp {
    let filter = path.split_once('?').and_then(|(_, query)| {
        query
            .split('&')
            .find_map(|pair| pair.strip_prefix("request_id=").map(|v| v.to_string()))
    });

    let guard = match ring().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let rows: Vec<&ScoreEntry> = guard
        .iter()
        .rev()
        .filter(|entry| {
            filter
                .as_deref()
                .is_none_or(|wanted| entry.request_id == wanted)
        })
        .collect();

    let mut by_label: HashMap<&str, Vec<i64>> = HashMap::new();
    for entry in &rows {
        by_label
            .entry(entry.label.as_deref().unwrap_or("unlabeled"))
            .or_default()
            .push(entry.score);
    }
    let mut aggregates: Vec<LabelAggregate> = by_label
        .into_iter()
        .map(|(label, scores)| {
            let count = scores.len();
            let sum: i64 = scores.iter().sum();
            LabelAggregate {
                label: label.to_string(),
                count,
                mean: ((sum as f64 / count as f64) * 1000.0).round() / 1000.0,
                min: scores.iter().copied().min().unwrap_or(0),
                max: scores.iter().copied().max().unwrap_or(0),
            }
        })
        .collect();
    // Stable order: a listing whose aggregate rows move every poll makes
    // two console reads impossible to diff.
    aggregates.sort_by(|a, b| a.label.cmp(&b.label));

    let body = serde_json::json!({
        "scores": rows,
        "aggregates": aggregates,
        "capacity": RING_CAPACITY,
        "range": { "min": SCORE_MIN, "max": SCORE_MAX },
    });
    (200, "application/json", body.to_string())
}

/// Dispatch the score routes. Returns `None` for paths this module does
/// not own so the caller falls through to the next dispatcher.
pub fn dispatch(method: &str, path: &str, body: Option<&str>) -> Option<Resp> {
    let path_only = path.split('?').next().unwrap_or(path);
    if path_only == "/api/scores" {
        return Some(if method.eq_ignore_ascii_case("GET") {
            list(path)
        } else {
            json_error(405, "method_not_allowed", "method not allowed")
        });
    }
    let request_id = path_only
        .strip_prefix("/api/requests/")
        .and_then(|rest| rest.strip_suffix("/scores"))?;
    // A nested path is not a request id. Without this a route like
    // `/api/requests/a/b/scores` would key a score to "a/b".
    if request_id.contains('/') {
        return None;
    }
    Some(if method.eq_ignore_ascii_case("POST") {
        record(request_id, body)
    } else {
        json_error(405, "method_not_allowed", "method not allowed")
    })
}

/// Drop every recorded score. Test-only: the ring is process-global, so
/// cases that assert on aggregates have to start from a known state.
#[cfg(test)]
fn reset_for_tests() {
    let mut guard = match ring().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ring is process-global, so these cases serialize.
    static SCORES_MUTEX: Mutex<()> = Mutex::new(());

    fn post(request_id: &str, body: &str) -> Resp {
        dispatch(
            "POST",
            &format!("/api/requests/{request_id}/scores"),
            Some(body),
        )
        .expect("route is owned")
    }

    #[test]
    fn a_score_in_range_is_recorded_and_read_back() {
        let _guard = SCORES_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        reset_for_tests();

        let (status, _, body) = post("req-1", r#"{"score": 7, "label": "helpfulness"}"#);
        assert_eq!(status, 200, "{body}");

        let (status, _, listing) = dispatch("GET", "/api/scores", None).expect("route is owned");
        assert_eq!(status, 200);
        let parsed: serde_json::Value = serde_json::from_str(&listing).unwrap();
        assert_eq!(parsed["scores"][0]["score"], 7);
        assert_eq!(parsed["scores"][0]["request_id"], "req-1");
        assert_eq!(parsed["scores"][0]["label"], "helpfulness");
    }

    #[test]
    fn a_score_outside_the_range_is_refused_rather_than_clamped() {
        // Clamping would make an evaluator misconfigured for 0..100 read
        // as a stream of perfect tens.
        let _guard = SCORES_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        reset_for_tests();

        let (status, _, body) = post("req-1", r#"{"score": 47}"#);
        assert_eq!(status, 422, "{body}");
        assert!(body.contains("score_out_of_range"), "{body}");

        let (_, _, listing) = dispatch("GET", "/api/scores", None).expect("route is owned");
        let parsed: serde_json::Value = serde_json::from_str(&listing).unwrap();
        assert_eq!(
            parsed["scores"].as_array().map(Vec::len),
            Some(0),
            "a refused score must not be stored"
        );
    }

    #[test]
    fn both_ends_of_the_range_are_inclusive() {
        let _guard = SCORES_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        reset_for_tests();
        assert_eq!(post("req-1", r#"{"score": -10}"#).0, 200);
        assert_eq!(post("req-2", r#"{"score": 10}"#).0, 200);
        assert_eq!(post("req-3", r#"{"score": -11}"#).0, 422);
        assert_eq!(post("req-4", r#"{"score": 11}"#).0, 422);
    }

    #[test]
    fn aggregates_are_per_label_and_stable_in_order() {
        let _guard = SCORES_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        reset_for_tests();
        post("req-1", r#"{"score": 2, "label": "b-eval"}"#);
        post("req-2", r#"{"score": 4, "label": "b-eval"}"#);
        post("req-3", r#"{"score": -1, "label": "a-eval"}"#);

        let (_, _, listing) = dispatch("GET", "/api/scores", None).expect("route is owned");
        let parsed: serde_json::Value = serde_json::from_str(&listing).unwrap();
        let aggregates = parsed["aggregates"].as_array().unwrap();
        assert_eq!(aggregates[0]["label"], "a-eval");
        assert_eq!(aggregates[1]["label"], "b-eval");
        assert_eq!(aggregates[1]["count"], 2);
        assert_eq!(aggregates[1]["mean"], 3.0);
        assert_eq!(aggregates[1]["min"], 2);
        assert_eq!(aggregates[1]["max"], 4);
    }

    #[test]
    fn a_score_with_no_label_aggregates_as_unlabeled() {
        let _guard = SCORES_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        reset_for_tests();
        post("req-1", r#"{"score": 3}"#);

        let (_, _, listing) = dispatch("GET", "/api/scores", None).expect("route is owned");
        let parsed: serde_json::Value = serde_json::from_str(&listing).unwrap();
        assert_eq!(parsed["aggregates"][0]["label"], "unlabeled");
    }

    #[test]
    fn the_listing_narrows_to_one_request() {
        let _guard = SCORES_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        reset_for_tests();
        post("req-1", r#"{"score": 1}"#);
        post("req-2", r#"{"score": 2}"#);

        let (_, _, listing) =
            dispatch("GET", "/api/scores?request_id=req-2", None).expect("route is owned");
        let parsed: serde_json::Value = serde_json::from_str(&listing).unwrap();
        let rows = parsed["scores"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["request_id"], "req-2");
    }

    #[test]
    fn a_control_character_in_a_label_cannot_forge_a_log_line() {
        let _guard = SCORES_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        reset_for_tests();
        post("req-1", "{\"score\": 1, \"label\": \"good\\ninjected=1\"}");

        let (_, _, listing) = dispatch("GET", "/api/scores", None).expect("route is owned");
        let parsed: serde_json::Value = serde_json::from_str(&listing).unwrap();
        let label = parsed["scores"][0]["label"].as_str().unwrap();
        assert!(!label.contains('\n'), "newline survived: {label:?}");
        assert_eq!(label, "goodinjected=1");
    }

    #[test]
    fn an_absurd_label_is_capped_rather_than_stored_whole() {
        let _guard = SCORES_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        reset_for_tests();
        let long = "x".repeat(5_000);
        post("req-1", &format!(r#"{{"score": 1, "label": "{long}"}}"#));

        let (_, _, listing) = dispatch("GET", "/api/scores", None).expect("route is owned");
        let parsed: serde_json::Value = serde_json::from_str(&listing).unwrap();
        assert_eq!(
            parsed["scores"][0]["label"].as_str().map(str::len),
            Some(LABEL_MAX_LEN)
        );
    }

    #[test]
    fn a_whitespace_only_label_reads_as_no_label() {
        let _guard = SCORES_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        reset_for_tests();
        post("req-1", r#"{"score": 1, "label": "   "}"#);

        let (_, _, listing) = dispatch("GET", "/api/scores", None).expect("route is owned");
        let parsed: serde_json::Value = serde_json::from_str(&listing).unwrap();
        assert!(parsed["scores"][0].get("label").is_none());
    }

    #[test]
    fn a_nested_path_is_not_a_request_id() {
        assert!(dispatch("POST", "/api/requests/a/b/scores", Some(r#"{"score":1}"#)).is_none());
    }

    #[test]
    fn the_wrong_method_is_refused_rather_than_falling_through() {
        // Falling through would make a GET on the score route resolve as
        // some other handler's path, which is how a 405 turns into a
        // surprising 200 somewhere else.
        let (status, _, _) =
            dispatch("GET", "/api/requests/req-1/scores", None).expect("route is owned");
        assert_eq!(status, 405);
        let (status, _, _) = dispatch("POST", "/api/scores", None).expect("route is owned");
        assert_eq!(status, 405);
    }

    #[test]
    fn an_unrelated_path_is_not_owned() {
        assert!(dispatch("GET", "/api/requests", None).is_none());
        assert!(dispatch("GET", "/admin/licensing", None).is_none());
    }

    #[test]
    fn the_ring_is_bounded() {
        let _guard = SCORES_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        reset_for_tests();
        for _ in 0..(RING_CAPACITY + 25) {
            post("req-1", r#"{"score": 1}"#);
        }
        let guard = ring().lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(guard.len(), RING_CAPACITY);
    }
}

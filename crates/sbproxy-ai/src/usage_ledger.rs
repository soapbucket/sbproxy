// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Verifiable usage ledger: the AI gateway's binding of the generic hash
//! chain to the LLM call it records.
//!
//! The chain itself, the digest, the signing, the replay, and the verifier
//! all live in `sbproxy-meter` now, because none of them ever knew anything
//! about tokens. What is left here is the part that genuinely does: the
//! [`LlmUsageEvent`] payload, the [`UsageSink`] that feeds it in, and the
//! promise that the bytes on disk have not moved.
//!
//! Where a plain usage sink ([`crate::usage_sink`]) ships events outward
//! best-effort and unsigned, the ledger turns the same event stream into
//! a chain you can prove. Each [`LlmUsageEvent`] is hash-chained to the
//! previous entry, so mutating any record breaks every link after it, and
//! with a signing seed configured each entry is Ed25519-signed so spend is
//! attributable to the proxy that recorded it, not merely logged.
//!
//! ## The payload is on-disk contract
//!
//! The chain is monomorphized at [`LlmUsageEvent`], and verification
//! re-serializes the event it parsed and requires byte-identical output.
//! So the event's field declaration order and every
//! `skip_serializing_if` on it are part of the file format, not just its
//! Rust shape. `tests/ledger_golden.rs` verifies two files written by an
//! older binary on every run and is what turns that promise into
//! something the build enforces.
//!
//! ## Durability and exactly-once
//!
//! The ledger file is its own write-ahead log: an append serializes one
//! entry, writes it, and flushes, all under a mutex, before returning. A
//! local append is sub-millisecond, so it stays off the network hot path
//! while never dropping an event under load (the lock is the
//! backpressure). On open, the existing file is replayed to rebuild the
//! chain head and the dedup set, so an at-least-once delivery of an event
//! carrying a `request_id` collapses to exactly-once.
//!
//! ## OSS seam
//!
//! This ships the chain, signing, and local verification. Anchoring
//! receipts to an external transparency log or a portal is an enterprise
//! extension via the plugin trait registry; it consumes the same entries.
//!
//! ## Reconciling against a provider's own usage export (WOR-2476)
//!
//! The ledger proves what the gateway *saw*. It cannot, by itself, prove
//! that nothing else was spent: a call that never went through this
//! proxy never generates a ledger entry to compare against. [`reconcile_usage`]
//! closes part of that gap by comparing the ledger's per-(day, model)
//! totals against the provider's own organization usage export. A row
//! the export shows that the ledger has no matching request for is
//! evidence that spend happened outside this gateway's metering path,
//! for the API key or org that export covers. `sbproxy ai ledger
//! reconcile` is the CLI surface; see its `--help` and
//! `docs/ai-usage-ledger.md` for the caveats that make "the ledger never
//! saw it" a narrower claim than "it did not happen".

use crate::usage_sink::{LlmUsageEvent, UsageSink};
use ed25519_dalek::VerifyingKey;
use sbproxy_meter::ledger::LedgerPayload;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

pub use sbproxy_meter::ledger::{
    ledger_health, verifying_key_from_seed_hex, LedgerHealth, LedgerVerifyResult,
};

/// One link in the LLM usage chain, serialized as a single JSON line.
pub type LedgerEntry = sbproxy_meter::ledger::LedgerEntry<LlmUsageEvent>;

/// A tamper-evident append log of completed-call usage events.
pub type UsageLedger = sbproxy_meter::ledger::UsageLedger<LlmUsageEvent>;

/// The gateway's dedup key is the per-request identifier the capture
/// envelope resolved.
///
/// Events without one are never deduplicated, which is the safe default:
/// two calls that both lack a `request_id` are two calls, and collapsing
/// them would under-report spend rather than over-report it.
/// `chain_contribution` is deliberately left at its `None` default, which
/// keeps this chain out of `sbproxy_meter_divergence_total`.
///
/// Divergence compares units the meter counted against units that reached
/// the chain. This chain is a spend record for LLM calls, not an
/// attestation receipt chain: nothing counts its tokens through the meter's
/// unit path, so reporting them on the chain side would produce a permanent
/// one-sided imbalance and an alert that fires forever without anything
/// being wrong. Implement it when, and only when, the same events are
/// counted on both sides.
impl LedgerPayload for LlmUsageEvent {
    fn dedup_key(&self) -> Option<&str> {
        self.request_id.as_deref()
    }
}

/// Verify a ledger file of LLM usage events: re-derive the hash chain from
/// genesis and, when a `verifying_key` is supplied, check every entry's
/// signature. Reports the first broken link.
///
/// A thin monomorphization of the generic verifier so `sbproxy ai ledger
/// verify` does not have to name a payload type on the command line, and
/// so the payload the CLI checks is always the one the gateway writes.
pub fn verify_ledger(
    path: impl AsRef<Path>,
    verifying_key: Option<&VerifyingKey>,
) -> anyhow::Result<LedgerVerifyResult> {
    sbproxy_meter::ledger::verify_ledger::<LlmUsageEvent>(path, verifying_key)
}

/// A [`UsageSink`] that appends every event to a [`UsageLedger`].
///
/// This is the piece that cannot move to `sbproxy-meter`: [`UsageSink`] is
/// typed to the LLM event, and the metering crate cannot see it.
#[derive(Debug)]
pub struct LedgerSink {
    /// `None` when the ledger could not be opened; records become no-ops
    /// (the failure was logged once at build time) so a misconfiguration
    /// cannot crash the gateway.
    ledger: Option<Arc<UsageLedger>>,
}

impl LedgerSink {
    /// Build a ledger sink from config, logging and degrading to an inert
    /// sink if the ledger cannot be opened. Returned as a trait object so
    /// it slots into the usage-sink list.
    pub fn build(path: &str, signing_seed_hex: Option<&str>) -> Arc<dyn UsageSink> {
        match Self::try_build(path, signing_seed_hex) {
            Ok(sink) => Arc::new(sink),
            Err(e) => {
                tracing::error!(error = %e, path = %path, "usage ledger: disabled (failed to open); events will not be recorded to this sink");
                Arc::new(LedgerSink { ledger: None })
            }
        }
    }

    /// Fallible constructor used by tests and the CLI verify command.
    pub fn try_build(path: &str, signing_seed_hex: Option<&str>) -> anyhow::Result<Self> {
        let ledger = UsageLedger::open(path, signing_seed_hex)?;
        Ok(Self {
            ledger: Some(Arc::new(ledger)),
        })
    }

    /// The underlying ledger, when active.
    pub fn ledger(&self) -> Option<&Arc<UsageLedger>> {
        self.ledger.as_ref()
    }
}

impl UsageSink for LedgerSink {
    fn record(&self, event: &LlmUsageEvent) {
        if let Some(ledger) = &self.ledger {
            ledger.append(event);
        }
    }

    fn name(&self) -> &str {
        "ledger"
    }
}

/// Read every entry from a ledger file, in file order, without
/// re-deriving or checking its hash chain.
///
/// This is the raw-content half of reconciliation; [`verify_ledger`] is
/// the integrity half. `sbproxy ai ledger reconcile` runs both: verify
/// first, so a broken or tampered chain is reported as a broken chain
/// rather than silently reconciled as if its contents were trustworthy.
pub fn read_ledger_entries(path: impl AsRef<Path>) -> anyhow::Result<Vec<LedgerEntry>> {
    let path = path.as_ref();
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("usage ledger: cannot read {}: {e}", path.display()))?;
    content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<LedgerEntry>(line)
                .map_err(|e| anyhow::anyhow!("usage ledger: unparseable entry: {e}"))
        })
        .collect()
}

/// One (day, model) row aggregated from a provider's usage export, at the
/// same granularity [`reconcile_usage`] compares against the ledger.
///
/// `day` is a UTC calendar day (`YYYY-MM-DD`), matching how ledger
/// entries are bucketed from their `recorded_at` timestamp. `model` is
/// `"ungrouped"` when the export result carried no model (the export was
/// not fetched with `group_by[]=model`); such rows never join to a
/// per-model ledger row and are surfaced in the reconcile report rather
/// than silently dropped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderUsageRow {
    /// UTC calendar day, `YYYY-MM-DD`.
    pub day: String,
    /// Model name, or `"ungrouped"` when the export did not group by model.
    pub model: String,
    /// Request count the provider attributes to this day and model.
    pub requests: u64,
    /// `input_tokens + output_tokens` the provider attributes to this day
    /// and model. Provider-side cache and audio token breakdowns are not
    /// folded in; see [`parse_openai_usage_export`] for why.
    pub total_tokens: u64,
}

/// The fields `parse_openai_usage_export` reads from one
/// `organization.usage.completions.result` item. Other documented fields
/// (`project_id`, `user_id`, `api_key_id`, `batch`, `input_cached_tokens`,
/// `input_audio_tokens`, `output_audio_tokens`, `object`) are present in
/// the real export but unused here, so serde ignores them rather than
/// naming them for no reason.
#[derive(Debug, Deserialize)]
struct OpenAiUsageResult {
    input_tokens: u64,
    output_tokens: u64,
    num_model_requests: u64,
    model: Option<String>,
}

/// One `{"object": "bucket", ...}` entry of the export's `data` array.
/// `end_time` is not captured: with `bucket_width=1d` a bucket's
/// `start_time` alone already lands on UTC midnight, so it is a
/// complete, unambiguous day on its own and `end_time` would only ever
/// repeat the next bucket's `start_time`.
#[derive(Debug, Deserialize)]
struct OpenAiUsageBucket {
    start_time: i64,
    #[serde(default)]
    results: Vec<OpenAiUsageResult>,
}

/// The export's top-level `{"object": "page", "data": [...], ...}` shape.
/// `has_more` / `next_page` are read by a real client to paginate; a
/// reconcile run is handed one already-downloaded file, so they are
/// ignored here rather than threaded through.
#[derive(Debug, Deserialize)]
struct OpenAiUsagePage {
    data: Vec<OpenAiUsageBucket>,
}

/// Parse an OpenAI organization Usage API completions export into
/// per-(day, model) totals.
///
/// Fetch it as `GET /v1/organization/usage/completions` with
/// `bucket_width=1d` and `group_by[]=model` (an Admin API key is
/// required). Shape confirmed against the current documented API on
/// 2026-08-16:
/// <https://platform.openai.com/docs/api-reference/usage/completions>
/// (top-level `{"object": "page", "data": [...]}`, each bucket
/// `{"object": "bucket", "start_time", "end_time", "results": [...]}`)
/// and the worked example at
/// <https://developers.openai.com/cookbook/examples/completions_usage_api>,
/// which shows a result item's exact fields: `input_tokens`,
/// `output_tokens`, `num_model_requests`, `project_id`, `user_id`,
/// `api_key_id`, `model`, `batch`, `input_cached_tokens`,
/// `input_audio_tokens`, `output_audio_tokens`.
///
/// This is picked as the primary (and, for now, only) `--format` over
/// Anthropic's Admin usage/cost API
/// (<https://platform.claude.com/docs/en/manage-claude/usage-cost-api>,
/// endpoint reference at
/// <https://platform.claude.com/docs/en/api/admin/usage_report/retrieve_messages>).
/// Anthropic's `results` split input into `uncached_input_tokens`,
/// `cache_read_input_tokens`, and a nested `cache_creation` object with
/// two more token counts, so "the token total for this row" is a policy
/// choice there (which of those five count toward what the ledger should
/// have seen) that OpenAI's single `input_tokens` field does not force.
/// Adding an `anthropic-usage` format later is a natural extension of
/// this same module, not a redesign: the request/token aggregation this
/// function feeds, [`reconcile_usage`], only needs a `Vec<ProviderUsageRow>`.
///
/// A result with `model: null` (the export was not fetched with
/// `group_by[]=model`) aggregates under the literal model `"ungrouped"`.
pub fn parse_openai_usage_export(bytes: &[u8]) -> anyhow::Result<Vec<ProviderUsageRow>> {
    let page: OpenAiUsagePage = serde_json::from_slice(bytes)
        .map_err(|e| anyhow::anyhow!("parse OpenAI usage export: {e}"))?;
    let mut rows = Vec::new();
    for bucket in &page.data {
        let day = day_from_unix_seconds(bucket.start_time)?;
        for result in &bucket.results {
            rows.push(ProviderUsageRow {
                day: day.clone(),
                model: result
                    .model
                    .clone()
                    .unwrap_or_else(|| "ungrouped".to_string()),
                requests: result.num_model_requests,
                // WOR-2478 review, M9: these two fields come straight off
                // the provider's own JSON response, not a value this
                // process ever bounded, so a plain `+` is a panic (debug)
                // or a silent wrap (release) waiting on whatever number
                // the provider happens to send.
                total_tokens: result.input_tokens.saturating_add(result.output_tokens),
            });
        }
    }
    Ok(rows)
}

/// A UTC calendar day (`YYYY-MM-DD`) from a Unix-seconds bucket start.
fn day_from_unix_seconds(seconds: i64) -> anyhow::Result<String> {
    chrono::DateTime::from_timestamp(seconds, 0)
        .map(|dt| dt.format("%Y-%m-%d").to_string())
        .ok_or_else(|| anyhow::anyhow!("bucket start_time {seconds} is out of range"))
}

/// A UTC calendar day (`YYYY-MM-DD`) from a ledger entry's RFC 3339
/// `recorded_at`. Falls back to a plain byte-prefix on an unparseable
/// timestamp (never expected from this crate's own writer) rather than
/// panicking or dropping the entry from the comparison.
fn day_from_recorded_at(recorded_at: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(recorded_at)
        .map(|dt| {
            dt.with_timezone(&chrono::Utc)
                .format("%Y-%m-%d")
                .to_string()
        })
        .unwrap_or_else(|_| recorded_at.chars().take(10).collect())
}

/// One reconciled (day, model) row: the provider export's totals next to
/// what the local ledger recorded for the same day and model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReconcileRow {
    /// UTC calendar day, `YYYY-MM-DD`.
    pub day: String,
    /// Model name (or `"ungrouped"`; see [`ProviderUsageRow`]).
    pub model: String,
    /// Requests the provider export attributes to this day and model.
    pub provider_requests: u64,
    /// Requests the local ledger recorded for this day and model.
    pub ledger_requests: u64,
    /// Provider-reported `input_tokens + output_tokens` for this row.
    pub provider_total_tokens: u64,
    /// Ledger-recorded `total_tokens` for this row.
    pub ledger_total_tokens: u64,
}

impl ReconcileRow {
    /// Requests the provider's export shows for this day and model that
    /// the ledger has no matching request for. This is the bypass
    /// evidence: spend the gateway's own ledger never saw, visible only
    /// because the provider counted it.
    pub fn unseen_by_ledger(&self) -> u64 {
        self.provider_requests.saturating_sub(self.ledger_requests)
    }

    /// Requests the ledger recorded for this day and model that the
    /// export does not show. Not bypass evidence on its own: usually a
    /// clock-window edge (the export's bucket boundary and the ledger's
    /// `recorded_at` are not guaranteed to agree to the second), a
    /// key/org attribution mismatch (the export covers one org or API
    /// key; the ledger may span more), or an export that has not caught
    /// up yet (provider usage data can lag by minutes).
    pub fn unseen_by_provider(&self) -> u64 {
        self.ledger_requests.saturating_sub(self.provider_requests)
    }
}

/// Accumulator for one (day, model) key while folding both sides in.
/// Not public: [`ReconcileRow`] is the type callers see.
#[derive(Debug, Clone, Copy, Default)]
struct ReconcileAccum {
    provider_requests: u64,
    provider_total_tokens: u64,
    ledger_requests: u64,
    ledger_total_tokens: u64,
}

/// Full result of reconciling a local usage ledger against a provider's
/// usage export: one row per (day, model) key seen on either side.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ReconcileReport {
    /// One row per (day, model) key present in the ledger, the export, or
    /// both, sorted by day then model.
    pub rows: Vec<ReconcileRow>,
}

impl ReconcileReport {
    /// Rows with provider-side requests the ledger never recorded: the
    /// evidence a call reached the provider without going through this
    /// gateway's metering path, for the org or key this export covers.
    pub fn bypass_rows(&self) -> impl Iterator<Item = &ReconcileRow> {
        self.rows.iter().filter(|r| r.unseen_by_ledger() > 0)
    }

    /// Sum of [`ReconcileRow::unseen_by_ledger`] across every row: the
    /// total bypass-evidence request count.
    pub fn total_unseen_by_ledger(&self) -> u64 {
        self.rows.iter().map(ReconcileRow::unseen_by_ledger).sum()
    }
}

/// Reconcile a local usage ledger's entries against a provider's usage
/// export, aggregated per (day, model).
///
/// This proves bypass only for usage visible to the provider org and API
/// key the export covers: a call made under a different key, project, or
/// org produces no row here at all, on either side. It is a detector for
/// "the gateway's ledger disagrees with what this provider export
/// shows", not a complete audit of every dollar spent with the provider.
pub fn reconcile_usage(
    ledger_entries: &[LedgerEntry],
    provider_rows: &[ProviderUsageRow],
) -> ReconcileReport {
    let mut acc: BTreeMap<(String, String), ReconcileAccum> = BTreeMap::new();
    for entry in ledger_entries {
        let key = (
            day_from_recorded_at(&entry.recorded_at),
            entry.event.model.clone(),
        );
        let a = acc.entry(key).or_default();
        // WOR-2478 review, M9: accumulators here fold an unbounded number
        // of rows, and `row.requests` / `row.total_tokens` come from the
        // provider's own export; saturating keeps a pathological or
        // adversarial export from panicking or wrapping the reconcile
        // report instead of just reporting a very large, correct-enough
        // number.
        a.ledger_requests = a.ledger_requests.saturating_add(1);
        a.ledger_total_tokens = a
            .ledger_total_tokens
            .saturating_add(entry.event.total_tokens);
    }
    for row in provider_rows {
        let key = (row.day.clone(), row.model.clone());
        let a = acc.entry(key).or_default();
        a.provider_requests = a.provider_requests.saturating_add(row.requests);
        a.provider_total_tokens = a.provider_total_tokens.saturating_add(row.total_tokens);
    }
    let rows = acc
        .into_iter()
        .map(|((day, model), a)| ReconcileRow {
            day,
            model,
            provider_requests: a.provider_requests,
            ledger_requests: a.ledger_requests,
            provider_total_tokens: a.provider_total_tokens,
            ledger_total_tokens: a.ledger_total_tokens,
        })
        .collect();
    ReconcileReport { rows }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn event(rid: Option<&str>, cost: f64) -> LlmUsageEvent {
        LlmUsageEvent {
            provider: "openai".into(),
            model: "gpt-4o-mini".into(),
            prompt_tokens: 10,
            completion_tokens: 5,
            total_tokens: 15,
            cost_usd: cost,
            latency_ms: 120,
            status: 200,
            key_id: Some("k1".into()),
            tenant_id: None,
            project: None,
            user: None,
            team: None,
            tags: Vec::new(),
            metadata: std::collections::BTreeMap::new(),
            request_id: rid.map(|s| s.to_string()),
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
            finish_reason: None,
            shadow_of: None,
            credential_source: None,
        }
    }

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sb-ledger-{}-{}-{tag}.jsonl",
            std::process::id(),
            // a per-test discriminator without needing a clock
            tag.len()
        ))
    }

    /// The payload-aware half of the tamper test. The generic chain has its
    /// own version in `sbproxy-meter`; this one edits a field only this
    /// crate knows exists, so it also pins that `cost_usd` is inside the
    /// hashed bytes rather than beside them.
    #[test]
    fn tampering_with_cost_breaks_verification() {
        let path = temp_path("tamper");
        let _ = std::fs::remove_file(&path);
        {
            let ledger = UsageLedger::open(&path, None).unwrap();
            for i in 0..4 {
                ledger.append(&event(None, i as f64));
            }
        }
        // Mutate the cost in the second entry's event.
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        assert_eq!(lines.len(), 4, "every append landed");
        lines[1] = lines[1].replace("\"cost_usd\":1.0", "\"cost_usd\":999.0");
        assert!(lines[1].contains("999.0"), "edit landed");
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let res = verify_ledger(&path, None).unwrap();
        assert!(!res.ok, "tampered chain must fail");
        assert_eq!(res.broken_seq, Some(1));
        let _ = std::fs::remove_file(&path);
    }

    /// The sink is the only reason this module still exists, so exercise
    /// the whole way through: config-shaped construction, a `record` on the
    /// trait, and a chain that verifies afterwards.
    #[test]
    fn sink_records_through_to_a_verifiable_chain() {
        let path = temp_path("sink");
        let _ = std::fs::remove_file(&path);
        {
            let sink = LedgerSink::try_build(path.to_str().unwrap(), None).unwrap();
            assert_eq!(sink.name(), "ledger");
            sink.record(&event(Some("r1"), 1.0));
            // Same request_id: the dedup set collapses it.
            sink.record(&event(Some("r1"), 1.0));
            sink.record(&event(Some("r2"), 2.0));
            assert!(sink.ledger().is_some(), "sink opened its ledger");
        }
        let res = verify_ledger(&path, None).unwrap();
        assert!(res.ok, "sink-written chain verifies: {res:?}");
        assert_eq!(res.entries, 2, "only r1 and r2 recorded");
        let _ = std::fs::remove_file(&path);
    }

    /// Signing is configured per sink, so pin that the seed reaches the
    /// chain and that the key derived from the same seed accepts it.
    #[test]
    fn signed_sink_entries_verify_against_the_seed_key() {
        let path = temp_path("signedsink");
        let _ = std::fs::remove_file(&path);
        let seed = "1".repeat(64);
        {
            let sink = LedgerSink::try_build(path.to_str().unwrap(), Some(&seed)).unwrap();
            sink.record(&event(Some("s1"), 1.0));
            sink.record(&event(Some("s2"), 2.0));
        }
        let vk = verifying_key_from_seed_hex(&seed).unwrap();
        let res = verify_ledger(&path, Some(&vk)).unwrap();
        assert!(res.ok, "signed chain verifies against its key: {res:?}");
        assert_eq!(res.entries, 2);
        let _ = std::fs::remove_file(&path);
    }

    /// The provider export's shape is confirmed against the current
    /// documented OpenAI Usage API in `parse_openai_usage_export`'s doc
    /// comment; this pins the parser against the checked-in fixture
    /// (real field names/nesting, invented values), not an inline
    /// string, so a future edit to the fixture exercises the same code
    /// this crate ships.
    #[test]
    fn parse_openai_usage_export_reads_the_documented_shape() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("openai-usage-export.json");
        let bytes = std::fs::read(&path).unwrap();
        let mut rows = parse_openai_usage_export(&bytes).unwrap();
        rows.sort_by(|a, b| {
            (a.day.as_str(), a.model.as_str()).cmp(&(b.day.as_str(), b.model.as_str()))
        });
        assert_eq!(rows.len(), 3, "two rows on day one, one on day two");
        assert_eq!(
            rows[0],
            ProviderUsageRow {
                day: "2026-06-24".into(),
                model: "gpt-4o".into(),
                requests: 47,
                total_tokens: 91000 + 34500,
            }
        );
        assert_eq!(
            rows[1],
            ProviderUsageRow {
                day: "2026-06-24".into(),
                model: "gpt-4o-mini".into(),
                requests: 210,
                total_tokens: 48000 + 12500,
            }
        );
        assert_eq!(
            rows[2],
            ProviderUsageRow {
                day: "2026-06-25".into(),
                model: "gpt-4o-mini".into(),
                requests: 63,
                total_tokens: 15200 + 4100,
            }
        );
    }

    /// A result with `model: null` (the export was not fetched with
    /// `group_by[]=model`) must not be silently dropped: it aggregates
    /// under the literal model `"ungrouped"` so the reconcile report can
    /// call it out rather than hide it.
    #[test]
    fn parse_openai_usage_export_falls_back_to_ungrouped_for_a_null_model() {
        let json = br#"{
            "object": "page",
            "data": [
                {
                    "object": "bucket",
                    "start_time": 1782259200,
                    "end_time": 1782345600,
                    "results": [
                        {
                            "object": "organization.usage.completions.result",
                            "input_tokens": 100,
                            "output_tokens": 50,
                            "num_model_requests": 5,
                            "project_id": null,
                            "user_id": null,
                            "api_key_id": null,
                            "model": null,
                            "batch": null,
                            "input_cached_tokens": 0,
                            "input_audio_tokens": 0,
                            "output_audio_tokens": 0
                        }
                    ]
                }
            ],
            "has_more": false,
            "next_page": null
        }"#;
        let rows = parse_openai_usage_export(json).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].model, "ungrouped");
        assert_eq!(rows[0].day, "2026-06-24");
        assert_eq!(rows[0].requests, 5);
        assert_eq!(rows[0].total_tokens, 150);
    }

    /// Build a bare `LedgerEntry` for reconcile tests. `reconcile_usage`
    /// reads only `recorded_at` and `event`, so the chain-linkage fields
    /// below are dummy values, not a real verifiable chain.
    fn ledger_entry(recorded_at: &str, model: &str, total_tokens: u64) -> LedgerEntry {
        let mut ev = event(None, 0.0);
        ev.model = model.to_string();
        ev.total_tokens = total_tokens;
        LedgerEntry {
            seq: 0,
            recorded_at: recorded_at.to_string(),
            prev_hash: "0".repeat(64),
            entry_hash: "0".repeat(64),
            signature: None,
            event: ev,
        }
    }

    /// The reconcile math, straight: a row the ledger and the export
    /// agree on is not bypass evidence; a row the export shows requests
    /// for that the ledger has none of is; and a row only the ledger has
    /// is reported the other way, not counted as bypass.
    #[test]
    fn reconcile_usage_flags_provider_only_rows_as_bypass_and_leaves_matched_rows_clean() {
        let ledger_entries = vec![
            ledger_entry("2026-08-10T12:00:00+00:00", "gpt-4o-mini", 100),
            ledger_entry("2026-08-11T09:00:00+00:00", "gpt-4o-mini", 50),
        ];
        let provider_rows = vec![
            ProviderUsageRow {
                day: "2026-08-10".into(),
                model: "gpt-4o-mini".into(),
                requests: 1,
                total_tokens: 100,
            },
            // Injected provider-side-only row: a model the ledger never
            // recorded a single request for, on the same day.
            ProviderUsageRow {
                day: "2026-08-10".into(),
                model: "gpt-4o".into(),
                requests: 3,
                total_tokens: 900,
            },
        ];

        let report = reconcile_usage(&ledger_entries, &provider_rows);
        assert_eq!(report.rows.len(), 3, "three distinct (day, model) keys");

        let matched = report
            .rows
            .iter()
            .find(|r| r.day == "2026-08-10" && r.model == "gpt-4o-mini")
            .unwrap();
        assert_eq!(
            matched.unseen_by_ledger(),
            0,
            "matched row is not bypass evidence"
        );
        assert_eq!(matched.unseen_by_provider(), 0);

        let bypass = report
            .rows
            .iter()
            .find(|r| r.day == "2026-08-10" && r.model == "gpt-4o")
            .unwrap();
        assert_eq!(
            bypass.unseen_by_ledger(),
            3,
            "the injected row is fully unseen by the ledger"
        );
        assert_eq!(
            report.bypass_rows().count(),
            1,
            "exactly the injected row is bypass evidence"
        );
        assert_eq!(report.total_unseen_by_ledger(), 3);

        let ledger_only = report
            .rows
            .iter()
            .find(|r| r.day == "2026-08-11" && r.model == "gpt-4o-mini")
            .unwrap();
        assert_eq!(
            ledger_only.unseen_by_provider(),
            1,
            "the ledger-only row is reported, but as absent-from-export, not bypass"
        );
        assert_eq!(ledger_only.unseen_by_ledger(), 0);
    }
}

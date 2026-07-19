// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Per-completion local-vs-cloud savings recorder (WOR-1913).
//!
//! When a served model declares a `reference:` cloud price (see
//! `sbproxy_model_host::config::ReferenceModel`), every completion it
//! serves locally is priced at what the equivalent hosted API would have
//! charged. A local completion's marginal API cost is zero, so that
//! displaced price is the whole saving. This module turns the finished
//! usage event stream into a durable, per-served-model
//! [`sbproxy_model_host::LaneSplit`] tally so the admin value route can
//! report dollars saved per model and the number survives a restart.
//!
//! ## Shape
//!
//! [`ValueLedger`] stores one `LaneSplit` per served model in a redb
//! database (the workspace embedded KV store), keyed by the served model
//! name. An empty path selects an in-memory backend for tests and for
//! setups that want the recorder without a file. [`ValueSink`] is the
//! [`UsageSink`] that folds each finished
//! request into the ledger when its served model has a configured
//! reference price.
//!
//! ## Only the local lane, for now
//!
//! This pass records only local completions (a served model with a
//! reference). Cloud-spill attribution, the other lane of the report, is
//! left as follow-up so the number the value route shows is exactly the
//! dollars a configured local model saved, never a guessed cloud figure.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use anyhow::Context;
use redb::{Database, ReadableTable, TableDefinition};

use sbproxy_model_host::{CloudPrice, LaneSplit, ModelHostConfig, ValueReport};

use crate::usage_sink::{LlmUsageEvent, UsageSink};

/// redb table: served model name -> JSON-encoded [`LaneSplit`].
const LANES: TableDefinition<&str, &[u8]> = TableDefinition::new("value_lanes_v1");

/// The process-wide value ledger, set once when a `serve:` block
/// configured reference prices so the admin value route can read it.
static VALUE_LEDGER: OnceLock<Arc<ValueLedger>> = OnceLock::new();

/// Register the process-wide value ledger. Called once at boot when the
/// value recorder is wired; returns `Err` if it was already set.
pub fn set_value_ledger(ledger: Arc<ValueLedger>) -> Result<(), &'static str> {
    VALUE_LEDGER
        .set(ledger)
        .map_err(|_| "value ledger already set")
}

/// The process-wide value ledger, when the value recorder is active. The
/// admin value route reads this; `None` means no reference prices were
/// configured, which is the honest empty-report answer.
pub fn value_ledger() -> Option<Arc<ValueLedger>> {
    VALUE_LEDGER.get().cloned()
}

/// Where the ledger keeps its per-model tallies.
enum Backend {
    /// A durable redb database on disk.
    Redb(Database),
    /// An in-memory map (empty path): tests and file-less setups.
    Memory(parking_lot::Mutex<BTreeMap<String, LaneSplit>>),
}

/// A durable per-served-model local-vs-cloud savings tally.
pub struct ValueLedger {
    backend: Backend,
}

impl std::fmt::Debug for ValueLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match &self.backend {
            Backend::Redb(_) => "redb",
            Backend::Memory(_) => "memory",
        };
        f.debug_struct("ValueLedger")
            .field("backend", &kind)
            .finish()
    }
}

impl ValueLedger {
    /// Open (or create) the ledger at `path`. An empty path selects an
    /// in-memory backend that does not persist.
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        if path.as_os_str().is_empty() {
            return Ok(Self {
                backend: Backend::Memory(parking_lot::Mutex::new(BTreeMap::new())),
            });
        }
        let db = Database::create(path)
            .with_context(|| format!("open value ledger at {}", path.display()))?;
        // Ensure the table exists so a fresh open can be read immediately.
        let write = db.begin_write().context("value ledger: begin write")?;
        write
            .open_table(LANES)
            .context("value ledger: open table")?;
        write.commit().context("value ledger: commit initial")?;
        Ok(Self {
            backend: Backend::Redb(db),
        })
    }

    /// Record one completion served locally for `model`, adding the cloud
    /// price it displaced to that model's savings. Best effort: a storage
    /// error is logged and swallowed so the recorder can never fail the
    /// request it is pricing.
    pub fn record_local(
        &self,
        model: &str,
        prompt_tokens: u64,
        completion_tokens: u64,
        price: CloudPrice,
    ) {
        if let Err(error) = self.try_record_local(model, prompt_tokens, completion_tokens, price) {
            tracing::warn!(error = %error, model, "value ledger: record_local failed");
        }
    }

    fn try_record_local(
        &self,
        model: &str,
        prompt_tokens: u64,
        completion_tokens: u64,
        price: CloudPrice,
    ) -> anyhow::Result<()> {
        match &self.backend {
            Backend::Memory(map) => {
                map.lock()
                    .entry(model.to_string())
                    .or_default()
                    .record_local(prompt_tokens, completion_tokens, price);
                Ok(())
            }
            Backend::Redb(db) => {
                let write = db.begin_write().context("value ledger: begin write")?;
                {
                    let mut table = write
                        .open_table(LANES)
                        .context("value ledger: open table")?;
                    // Copy the stored bytes out so the read guard is dropped
                    // before we insert back into the same table.
                    let existing = table
                        .get(model)
                        .context("value ledger: read lane")?
                        .map(|guard| guard.value().to_vec());
                    let mut split: LaneSplit = match existing {
                        Some(bytes) => {
                            serde_json::from_slice(&bytes).context("value ledger: decode lane")?
                        }
                        None => LaneSplit::default(),
                    };
                    split.record_local(prompt_tokens, completion_tokens, price);
                    let encoded =
                        serde_json::to_vec(&split).context("value ledger: encode lane")?;
                    table
                        .insert(model, encoded.as_slice())
                        .context("value ledger: write lane")?;
                }
                write.commit().context("value ledger: commit")?;
                Ok(())
            }
        }
    }

    /// Aggregate every per-model tally into a [`ValueReport`]. Best effort:
    /// a storage error is logged and yields an empty report.
    pub fn report(&self) -> ValueReport {
        match self.report_inner() {
            Ok(report) => report,
            Err(error) => {
                tracing::warn!(error = %error, "value ledger: report failed");
                ValueReport::default()
            }
        }
    }

    fn report_inner(&self) -> anyhow::Result<ValueReport> {
        let lanes = match &self.backend {
            Backend::Memory(map) => map.lock().clone(),
            Backend::Redb(db) => {
                let read = db.begin_read().context("value ledger: begin read")?;
                let table = read.open_table(LANES).context("value ledger: open table")?;
                let mut lanes = BTreeMap::new();
                for entry in table
                    .range::<&str>(..)
                    .context("value ledger: scan lanes")?
                {
                    let (key, value) = entry.context("value ledger: read lane entry")?;
                    let split: LaneSplit = serde_json::from_slice(value.value())
                        .context("value ledger: decode lane")?;
                    lanes.insert(key.value().to_string(), split);
                }
                lanes
            }
        };
        Ok(ValueReport::from_lanes(&lanes))
    }
}

/// A [`UsageSink`] that records the
/// local-vs-cloud savings of every finished completion whose served model
/// has a configured cloud reference price.
#[derive(Debug)]
pub struct ValueSink {
    ledger: Arc<ValueLedger>,
    /// Served model name -> (reference model name, its cloud price). A
    /// completion is only recorded when its model (or provider) is a key
    /// here, so nothing without an explicit reference is ever priced.
    references: BTreeMap<String, (String, CloudPrice)>,
}

impl ValueSink {
    /// Build a value sink over `ledger` for the given reference-price map.
    pub fn new(
        ledger: Arc<ValueLedger>,
        references: BTreeMap<String, (String, CloudPrice)>,
    ) -> Self {
        Self { ledger, references }
    }

    /// The ledger this sink writes to.
    pub fn ledger(&self) -> &Arc<ValueLedger> {
        &self.ledger
    }

    /// Collect the reference-price map from a model-host `serve:` block:
    /// every entry that declares a `reference:` contributes its effective
    /// name -> (reference model, cloud price). Nameless raw references are
    /// skipped (they have no stable model id to record under).
    pub fn references_from_serve(
        config: &ModelHostConfig,
    ) -> BTreeMap<String, (String, CloudPrice)> {
        let mut references = BTreeMap::new();
        for entry in &config.models {
            let Some(reference) = &entry.reference else {
                continue;
            };
            if let Ok(name) = entry.effective_name() {
                references.insert(name, (reference.model.clone(), reference.cloud_price()));
            }
        }
        references
    }
}

impl UsageSink for ValueSink {
    fn record(&self, event: &LlmUsageEvent) {
        // Only local completions of a served model with a configured
        // reference are priced. Match the served model name first, then
        // the provider name.
        // TODO(WOR-1913): cloud-spill lane attribution.
        let Some((_reference, price)) = self
            .references
            .get(&event.model)
            .or_else(|| self.references.get(&event.provider))
        else {
            return;
        };
        self.ledger.record_local(
            &event.model,
            event.prompt_tokens,
            event.completion_tokens,
            *price,
        );
    }

    fn name(&self) -> &str {
        "value"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cloud() -> CloudPrice {
        CloudPrice {
            prompt_micros_per_mtok: 3_000_000,
            completion_micros_per_mtok: 15_000_000,
        }
    }

    fn event(model: &str, prompt_tokens: u64, completion_tokens: u64) -> LlmUsageEvent {
        LlmUsageEvent {
            provider: "local".into(),
            model: model.into(),
            prompt_tokens,
            completion_tokens,
            total_tokens: prompt_tokens + completion_tokens,
            cost_usd: 0.0,
            latency_ms: 10,
            status: 200,
            key_id: None,
            tenant_id: None,
            project: None,
            user: None,
            team: None,
            tags: Vec::new(),
            metadata: std::collections::BTreeMap::new(),
            request_id: None,
            tag: None,
            priority: None,
            engine_version: None,
        }
    }

    #[test]
    fn saved_micros_survive_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("value.redb");
        {
            let ledger = ValueLedger::open(&path).expect("open");
            ledger.record_local("qwen", 1000, 500, cloud()); // saves 10_500
            ledger.record_local("qwen", 1000, 500, cloud()); // saves 10_500
        }
        // Reopen at the same path: the tally must have persisted.
        let ledger = ValueLedger::open(&path).expect("reopen");
        let report = ledger.report();
        assert_eq!(report.total_saved_micros, 21_000);
        assert_eq!(report.total_local_completions, 2);
        assert_eq!(report.models.len(), 1);
        assert_eq!(report.models[0].model, "qwen");
    }

    #[test]
    fn empty_path_uses_in_memory_backend() {
        let ledger = ValueLedger::open("").expect("in-memory open");
        let price = CloudPrice {
            prompt_micros_per_mtok: 1_000_000,
            completion_micros_per_mtok: 1_000_000,
        };
        ledger.record_local("m", 1_000_000, 0, price);
        assert_eq!(ledger.report().total_saved_micros, 1_000_000);
    }

    #[test]
    fn value_sink_records_only_configured_references() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ledger = Arc::new(ValueLedger::open(dir.path().join("v.redb")).expect("open"));
        let mut references = BTreeMap::new();
        references.insert("qwen".to_string(), ("gpt-4o".to_string(), cloud()));
        let sink = ValueSink::new(ledger.clone(), references);

        sink.record(&event("qwen", 1000, 500)); // recorded
        sink.record(&event("unknown", 1000, 500)); // ignored: no reference

        let report = ledger.report();
        assert_eq!(report.total_local_completions, 1);
        assert_eq!(report.total_saved_micros, 10_500);
        assert_eq!(report.models.len(), 1);
        assert_eq!(report.models[0].model, "qwen");
        assert_eq!(sink.name(), "value");
    }

    #[test]
    fn references_from_serve_collects_configured_reference_prices() {
        let config: ModelHostConfig = serde_yaml::from_str(
            "models:\n  - model: qwen3-32b\n    name: qwen\n    reference:\n      model: gpt-4o\n      prompt_micros_per_mtok: 3000000\n      completion_micros_per_mtok: 15000000\n  - model: llama\n",
        )
        .expect("parse serve block");
        let references = ValueSink::references_from_serve(&config);
        assert_eq!(
            references.len(),
            1,
            "only the entry with a reference counts"
        );
        let (reference_model, price) = references.get("qwen").expect("qwen reference");
        assert_eq!(reference_model, "gpt-4o");
        assert_eq!(price.completion_micros_per_mtok, 15_000_000);
    }
}

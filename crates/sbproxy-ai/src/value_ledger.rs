// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Per-model value recorder for local serving and context compression.
//!
//! When a served model declares a `reference:` cloud price (see
//! `sbproxy_model_host::config::ReferenceModel`), every completion it
//! serves locally is priced at what the equivalent hosted API would have
//! charged. A local completion's marginal API cost is zero, so that
//! displaced price is the whole saving. This module turns the finished
//! usage event stream into a durable, per-served-model
//! [`sbproxy_model_host::LaneSplit`] tally so the admin value route can
//! report dollars saved per model and the number survives a restart.
//! Successful context-compression requests add prompt-free, per-lever target
//! token estimates and gross avoided-input-cost totals to the same report without
//! changing the local or cloud completion counts.
//!
//! ## Shape
//!
//! [`ValueLedger`] stores one `LaneSplit` per target model, keyed by model
//! name. A configured model-host cache uses redb, the workspace embedded KV
//! store. An empty path selects an in-memory backend for tests and
//! compression-only setups. [`ValueSink`] is the [`UsageSink`] that folds each
//! finished local completion into the ledger when its served model has a
//! configured reference price.
//!
//! ## Independent value dimensions
//!
//! [`ValueSink`] records local completions only when a served model declares a
//! cloud reference. Cloud-spill attribution remains a follow-up. Compression
//! value is recorded separately after terminal provider success using the
//! target model's configured or catalog input price. Unknown or unpriced models
//! remain zero-valued. It never fabricates a local completion or folds internal
//! summarizer spend into the gross avoided-cost value.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use anyhow::Context;
use redb::{Database, ReadableTable, TableDefinition};

use sbproxy_model_host::{
    CloudPrice, LaneSplit, ModelHostConfig, TokenCountPrecision, ValueReport,
};

use crate::compression::{CompressionRun, LeverKind, LeverOutcome};
use crate::usage_sink::{LlmUsageEvent, UsageSink};

/// redb table: served model name -> JSON-encoded [`LaneSplit`].
const LANES: TableDefinition<&str, &[u8]> = TableDefinition::new("value_lanes_v1");

/// Maximum number of model lanes retained by one value ledger, including the
/// deterministic overflow lane.
pub const VALUE_LEDGER_MODEL_LIMIT: usize = 1_000;

/// Stable model key that aggregates value after the model-lane budget fills.
pub const VALUE_LEDGER_OVERFLOW_MODEL: &str = "__other__";

/// The process-wide value ledger, set once for local-serving or compression
/// value so the admin value route can read it.
static VALUE_LEDGER: OnceLock<Arc<ValueLedger>> = OnceLock::new();

/// The process-wide value ledger, when a value recorder is active. The admin
/// value route reads this; `None` means no local-serving or compression value
/// has been recorded, which is the honest empty-report answer.
pub fn value_ledger() -> Option<Arc<ValueLedger>> {
    VALUE_LEDGER.get().cloned()
}

/// Return the process-wide ledger, installing an in-memory ledger when no
/// durable model-host ledger was configured.
///
/// Compression-only deployments use this path so the admin value response is
/// populated without creating worker-local durable state. If configured local
/// serving initializes later, it promotes and merges this same facade so
/// existing references follow the durable backend.
pub fn value_ledger_or_init_memory() -> Arc<ValueLedger> {
    value_ledger_or_init_memory_in(&VALUE_LEDGER)
}

fn value_ledger_or_init_memory_in(slot: &OnceLock<Arc<ValueLedger>>) -> Arc<ValueLedger> {
    slot.get_or_init(|| Arc::new(ValueLedger::memory())).clone()
}

#[cfg(test)]
fn value_ledger_or_init_redb_in(
    slot: &OnceLock<Arc<ValueLedger>>,
    path: impl AsRef<Path>,
) -> anyhow::Result<Arc<ValueLedger>> {
    let ledger = value_ledger_or_init_memory_in(slot);
    ledger.promote_to_redb(path)?;
    Ok(ledger)
}

/// Prompt-free target-model estimated savings waiting for provider success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCompressionValue {
    target_model: String,
    token_count_precision: TokenCountPrecision,
    levers: Vec<PendingCompressionLeverValue>,
}

impl PendingCompressionValue {
    /// Build pending value from applied levers with positive target-model
    /// token savings. Skips, failures, and zero-savings outcomes are omitted.
    pub fn from_run(target_model: impl Into<String>, run: &CompressionRun) -> Option<Self> {
        let token_count_precision = run.token_count_precision;
        let levers = run
            .lever_results
            .iter()
            .filter(|result| {
                matches!(result.outcome, LeverOutcome::Applied) && result.tokens_saved > 0
            })
            .map(|result| PendingCompressionLeverValue {
                lever: result.lever,
                tokens_saved: result.tokens_saved,
                token_count_precision,
            })
            .collect::<Vec<_>>();
        (!levers.is_empty()).then(|| Self {
            target_model: target_model.into(),
            token_count_precision,
            levers,
        })
    }

    /// Target model used by the compression runner's token counter and by
    /// avoided-input-cost pricing.
    pub fn target_model(&self) -> &str {
        &self.target_model
    }

    /// Applied positive per-lever estimated token savings in pipeline order.
    pub fn levers(&self) -> &[PendingCompressionLeverValue] {
        &self.levers
    }

    /// Precision signal from the target-model counter that produced these
    /// savings.
    pub fn token_count_precision(&self) -> TokenCountPrecision {
        self.token_count_precision
    }

    /// Price every per-lever saving as gross avoided input cost for the target
    /// model. This is intended for the terminal provider-success path.
    pub fn priced_records(&self) -> Vec<CompressionValueRecord> {
        self.levers
            .iter()
            .map(|pending| CompressionValueRecord {
                lever: pending.lever,
                tokens_saved: pending.tokens_saved,
                gross_cost_saved_micros: estimated_input_cost_micros(
                    &self.target_model,
                    pending.tokens_saved,
                ),
                token_count_precision: pending.token_count_precision,
            })
            .collect()
    }
}

/// One applied lever's target-model token saving, before success-time pricing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingCompressionLeverValue {
    lever: LeverKind,
    tokens_saved: u64,
    token_count_precision: TokenCountPrecision,
}

impl PendingCompressionLeverValue {
    /// Closed compression lever.
    pub fn lever(&self) -> LeverKind {
        self.lever
    }

    /// Estimated target-model input tokens avoided.
    pub fn tokens_saved(&self) -> u64 {
        self.tokens_saved
    }

    /// Precision signal from the target-model counter.
    pub fn token_count_precision(&self) -> TokenCountPrecision {
        self.token_count_precision
    }
}

/// Success-time compression value ready for the ledger and metrics surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionValueRecord {
    lever: LeverKind,
    tokens_saved: u64,
    gross_cost_saved_micros: u64,
    token_count_precision: TokenCountPrecision,
}

impl CompressionValueRecord {
    /// Closed compression lever.
    pub fn lever(&self) -> LeverKind {
        self.lever
    }

    /// Estimated target-model input tokens avoided.
    pub fn tokens_saved(&self) -> u64 {
        self.tokens_saved
    }

    /// Gross target-model input cost avoided, in micro-USD.
    pub fn gross_cost_saved_micros(&self) -> u64 {
        self.gross_cost_saved_micros
    }

    /// Precision signal from the target-model counter.
    pub fn token_count_precision(&self) -> TokenCountPrecision {
        self.token_count_precision
    }
}

fn estimated_input_cost_micros(model: &str, tokens: u64) -> u64 {
    let micros =
        crate::budget::estimate_known_input_cost(model, tokens).unwrap_or(0.0) * 1_000_000.0;
    if !micros.is_finite() || micros <= 0.0 {
        return 0;
    }
    micros.round().min(u64::MAX as f64) as u64
}

/// Where the ledger keeps its per-model tallies.
enum Backend {
    /// A durable redb database on disk.
    Redb {
        database: Database,
        path: PathBuf,
        model_keys: parking_lot::Mutex<BTreeSet<String>>,
    },
    /// An in-memory map (empty path): tests and file-less setups.
    Memory(parking_lot::Mutex<BTreeMap<String, LaneSplit>>),
}

/// A per-model local-serving and context-compression value tally.
pub struct ValueLedger {
    backend: parking_lot::RwLock<Backend>,
    overflow_logged: AtomicBool,
}

impl std::fmt::Debug for ValueLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let backend = self.backend.read();
        let kind = match &*backend {
            Backend::Redb { .. } => "redb",
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
            return Ok(Self::memory());
        }
        let (database, canonical_path, model_keys) = open_redb_backend(path)?;
        Ok(Self {
            backend: parking_lot::RwLock::new(Backend::Redb {
                database,
                path: canonical_path,
                model_keys: parking_lot::Mutex::new(model_keys),
            }),
            overflow_logged: AtomicBool::new(false),
        })
    }

    fn memory() -> Self {
        Self {
            backend: parking_lot::RwLock::new(Backend::Memory(parking_lot::Mutex::new(
                BTreeMap::new(),
            ))),
            overflow_logged: AtomicBool::new(false),
        }
    }

    /// Promote an in-memory ledger to durable redb storage without changing
    /// the ledger's identity.
    ///
    /// Existing on-disk lanes are merged with the in-memory snapshot in one
    /// transaction. The backend changes only after that transaction commits,
    /// so existing [`Arc<ValueLedger>`] and [`ValueSink`] references keep
    /// writing through the same facade and a failed promotion leaves the
    /// in-memory backend intact. A ledger that is already durable keeps its
    /// first configured redb backend.
    pub(crate) fn promote_to_redb(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        let path = path.as_ref();
        anyhow::ensure!(
            !path.as_os_str().is_empty(),
            "value ledger: durable path must not be empty"
        );

        let requested_path = resolve_redb_path(path)?;
        let mut backend = self.backend.write();
        let memory_lanes = match &*backend {
            Backend::Redb { path, .. } if path == &requested_path => return Ok(()),
            Backend::Redb { path, .. } => {
                anyhow::bail!(
                    "value ledger already uses durable path {}; cannot promote to different path {}",
                    path.display(),
                    requested_path.display()
                );
            }
            Backend::Memory(lanes) => lanes.lock().clone(),
        };

        let (database, canonical_path, _) = open_redb_backend(path)?;
        let (model_keys, overflowed) = merge_memory_lanes_into_redb(&database, memory_lanes)?;
        *backend = Backend::Redb {
            database,
            path: canonical_path,
            model_keys: parking_lot::Mutex::new(model_keys),
        };
        drop(backend);

        if overflowed {
            self.log_overflow_once();
        }
        Ok(())
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
        self.try_update_lane(model, |split| {
            split.record_local(prompt_tokens, completion_tokens, price);
        })
    }

    /// Record target-model input value delivered by one applied compression
    /// lever. The operation is best effort and never changes local or cloud
    /// completion counts.
    pub fn record_compression(
        &self,
        model: &str,
        lever: LeverKind,
        tokens_saved: u64,
        gross_cost_saved_micros: u64,
        token_count_precision: TokenCountPrecision,
    ) {
        if tokens_saved == 0 {
            return;
        }
        if let Err(error) = self.try_update_lane(model, |split| {
            split.record_compression(
                lever.as_str(),
                tokens_saved,
                gross_cost_saved_micros,
                token_count_precision,
            );
        }) {
            tracing::warn!(
                error = %error,
                lever = lever.as_str(),
                "value ledger: record_compression failed"
            );
        }
    }

    fn try_update_lane(
        &self,
        model: &str,
        update: impl FnOnce(&mut LaneSplit),
    ) -> anyhow::Result<()> {
        let backend = self.backend.read();
        match &*backend {
            Backend::Memory(map) => {
                let mut map = map.lock();
                let (model_key, overflowed) = bounded_memory_model_key(&mut map, model);
                update(map.entry(model_key).or_default());
                drop(map);
                if overflowed {
                    self.log_overflow_once();
                }
                Ok(())
            }
            Backend::Redb {
                database,
                model_keys,
                ..
            } => {
                let mut model_keys = model_keys.lock();
                let mut overflowed = false;
                let model_key = if model_keys.contains(model) {
                    model.to_string()
                } else {
                    let has_overflow = model_keys.contains(VALUE_LEDGER_OVERFLOW_MODEL);
                    let admission_limit = if has_overflow {
                        VALUE_LEDGER_MODEL_LIMIT
                    } else {
                        VALUE_LEDGER_MODEL_LIMIT.saturating_sub(1)
                    };
                    if model_keys.len() < admission_limit {
                        model.to_string()
                    } else if has_overflow {
                        overflowed = true;
                        VALUE_LEDGER_OVERFLOW_MODEL.to_string()
                    } else {
                        ensure_redb_overflow_lane(database, &mut model_keys)?;
                        overflowed = true;
                        VALUE_LEDGER_OVERFLOW_MODEL.to_string()
                    }
                };
                update_redb_lane(database, &model_key, update)?;
                model_keys.insert(model_key);
                drop(model_keys);
                if overflowed {
                    self.log_overflow_once();
                }
                Ok(())
            }
        }
    }

    fn log_overflow_once(&self) {
        if !self.overflow_logged.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                model_limit = VALUE_LEDGER_MODEL_LIMIT,
                overflow_model = VALUE_LEDGER_OVERFLOW_MODEL,
                "value ledger: model cardinality limit reached; aggregating additional models"
            );
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
        let backend = self.backend.read();
        let lanes = match &*backend {
            Backend::Memory(map) => map.lock().clone(),
            Backend::Redb { database, .. } => {
                let read = database.begin_read().context("value ledger: begin read")?;
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

fn open_redb_backend(path: &Path) -> anyhow::Result<(Database, PathBuf, BTreeSet<String>)> {
    let database = Database::create(path)
        .with_context(|| format!("open value ledger at {}", path.display()))?;
    // Ensure the table exists so a fresh open can be read immediately.
    let write = database
        .begin_write()
        .context("value ledger: begin write")?;
    write
        .open_table(LANES)
        .context("value ledger: open table")?;
    write.commit().context("value ledger: commit initial")?;
    let mut model_keys = read_redb_model_keys(&database)?;
    if model_keys.len() > VALUE_LEDGER_MODEL_LIMIT {
        ensure_redb_overflow_lane(&database, &mut model_keys)?;
    }
    let canonical_path = std::fs::canonicalize(path)
        .with_context(|| format!("canonicalize value ledger path {}", path.display()))?;
    Ok((database, canonical_path, model_keys))
}

fn resolve_redb_path(path: &Path) -> anyhow::Result<PathBuf> {
    if path.exists() {
        return std::fs::canonicalize(path)
            .with_context(|| format!("canonicalize value ledger path {}", path.display()));
    }

    let file_name = path
        .file_name()
        .context("value ledger: durable path must name a file")?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let canonical_parent = std::fs::canonicalize(parent).with_context(|| {
        format!(
            "canonicalize value ledger parent directory {}",
            parent.display()
        )
    })?;
    Ok(canonical_parent.join(file_name))
}

fn merge_memory_lanes_into_redb(
    database: &Database,
    memory_lanes: BTreeMap<String, LaneSplit>,
) -> anyhow::Result<(BTreeSet<String>, bool)> {
    let mut lanes = read_redb_lanes(database)?;
    let mut overflowed = false;
    for (model, source) in memory_lanes {
        let (model_key, did_overflow) = bounded_memory_model_key(&mut lanes, &model);
        merge_lane(lanes.entry(model_key).or_default(), source);
        overflowed |= did_overflow;
    }

    let write = database
        .begin_write()
        .context("value ledger: begin promotion write")?;
    {
        let mut table = write
            .open_table(LANES)
            .context("value ledger: open promotion table")?;
        table
            .retain(|_, _| false)
            .context("value ledger: clear promotion table")?;
        for (model, split) in &lanes {
            let encoded =
                serde_json::to_vec(split).context("value ledger: encode promoted lane")?;
            table
                .insert(model.as_str(), encoded.as_slice())
                .context("value ledger: write promoted lane")?;
        }
    }
    write.commit().context("value ledger: commit promotion")?;

    Ok((lanes.into_keys().collect(), overflowed))
}

fn merge_lane(target: &mut LaneSplit, source: LaneSplit) {
    target.local_completions = target
        .local_completions
        .saturating_add(source.local_completions);
    target.cloud_completions = target
        .cloud_completions
        .saturating_add(source.cloud_completions);
    target.saved_micros = target.saved_micros.saturating_add(source.saved_micros);
    target.cloud_spent_micros = target
        .cloud_spent_micros
        .saturating_add(source.cloud_spent_micros);
    for (lever, value) in source.compression {
        target.record_compression(
            &lever,
            value.tokens_saved,
            value.gross_cost_saved_micros,
            value.token_count_precision,
        );
    }
}

fn bounded_memory_model_key(
    lanes: &mut BTreeMap<String, LaneSplit>,
    model: &str,
) -> (String, bool) {
    if lanes.contains_key(model) {
        return (model.to_string(), false);
    }
    let has_overflow = lanes.contains_key(VALUE_LEDGER_OVERFLOW_MODEL);
    let admission_limit = if has_overflow {
        VALUE_LEDGER_MODEL_LIMIT
    } else {
        VALUE_LEDGER_MODEL_LIMIT.saturating_sub(1)
    };
    if lanes.len() < admission_limit {
        return (model.to_string(), false);
    }
    if has_overflow {
        return (VALUE_LEDGER_OVERFLOW_MODEL.to_string(), true);
    }

    let mut overflow = LaneSplit::default();
    while lanes.len() >= VALUE_LEDGER_MODEL_LIMIT {
        let Some(evicted_key) = lanes.keys().next_back().cloned() else {
            break;
        };
        if let Some(evicted) = lanes.remove(&evicted_key) {
            merge_lane(&mut overflow, evicted);
        }
    }
    merge_lane(
        lanes
            .entry(VALUE_LEDGER_OVERFLOW_MODEL.to_string())
            .or_default(),
        overflow,
    );
    (VALUE_LEDGER_OVERFLOW_MODEL.to_string(), true)
}

fn read_redb_model_keys(database: &Database) -> anyhow::Result<BTreeSet<String>> {
    let read = database
        .begin_read()
        .context("value ledger: begin model-key read")?;
    let table = read
        .open_table(LANES)
        .context("value ledger: open model-key table")?;
    let mut model_keys = BTreeSet::new();
    for entry in table
        .range::<&str>(..)
        .context("value ledger: scan model keys")?
    {
        let (key, _) = entry.context("value ledger: read model key")?;
        model_keys.insert(key.value().to_string());
    }
    Ok(model_keys)
}

fn read_redb_lanes(database: &Database) -> anyhow::Result<BTreeMap<String, LaneSplit>> {
    let read = database
        .begin_read()
        .context("value ledger: begin lane read")?;
    let table = read
        .open_table(LANES)
        .context("value ledger: open lane table")?;
    let mut lanes = BTreeMap::new();
    for entry in table
        .range::<&str>(..)
        .context("value ledger: scan lanes")?
    {
        let (key, value) = entry.context("value ledger: read lane entry")?;
        let split = serde_json::from_slice(value.value())
            .context("value ledger: decode lane during promotion")?;
        lanes.insert(key.value().to_string(), split);
    }
    Ok(lanes)
}

fn ensure_redb_overflow_lane(
    database: &Database,
    model_keys: &mut BTreeSet<String>,
) -> anyhow::Result<()> {
    let mut next_keys = model_keys.clone();
    next_keys.remove(VALUE_LEDGER_OVERFLOW_MODEL);

    let write = database
        .begin_write()
        .context("value ledger: begin overflow write")?;
    {
        let mut table = write
            .open_table(LANES)
            .context("value ledger: open overflow table")?;
        let existing_overflow = table
            .get(VALUE_LEDGER_OVERFLOW_MODEL)
            .context("value ledger: read overflow lane")?
            .map(|guard| guard.value().to_vec());
        let mut overflow = match existing_overflow {
            Some(bytes) => {
                serde_json::from_slice(&bytes).context("value ledger: decode overflow lane")?
            }
            None => LaneSplit::default(),
        };

        while next_keys.len() >= VALUE_LEDGER_MODEL_LIMIT {
            let evicted_key = next_keys
                .iter()
                .next_back()
                .cloned()
                .context("value ledger: missing overflow eviction candidate")?;
            let evicted_bytes = table
                .get(evicted_key.as_str())
                .context("value ledger: read overflow eviction")?
                .map(|guard| guard.value().to_vec())
                .context("value ledger: missing overflow eviction lane")?;
            let evicted: LaneSplit = serde_json::from_slice(&evicted_bytes)
                .context("value ledger: decode overflow eviction lane")?;
            merge_lane(&mut overflow, evicted);
            table
                .remove(evicted_key.as_str())
                .context("value ledger: remove overflow eviction lane")?;
            next_keys.remove(&evicted_key);
        }

        let encoded =
            serde_json::to_vec(&overflow).context("value ledger: encode overflow lane")?;
        table
            .insert(VALUE_LEDGER_OVERFLOW_MODEL, encoded.as_slice())
            .context("value ledger: write overflow lane")?;
    }
    write
        .commit()
        .context("value ledger: commit overflow lane")?;
    next_keys.insert(VALUE_LEDGER_OVERFLOW_MODEL.to_string());
    *model_keys = next_keys;
    Ok(())
}

fn update_redb_lane(
    database: &Database,
    model: &str,
    update: impl FnOnce(&mut LaneSplit),
) -> anyhow::Result<()> {
    let write = database
        .begin_write()
        .context("value ledger: begin write")?;
    {
        let mut table = write
            .open_table(LANES)
            .context("value ledger: open table")?;
        let existing = table
            .get(model)
            .context("value ledger: read lane")?
            .map(|guard| guard.value().to_vec());
        let mut split: LaneSplit = match existing {
            Some(bytes) => serde_json::from_slice(&bytes).context("value ledger: decode lane")?,
            None => LaneSplit::default(),
        };
        update(&mut split);
        let encoded = serde_json::to_vec(&split).context("value ledger: encode lane")?;
        table
            .insert(model, encoded.as_slice())
            .context("value ledger: write lane")?;
    }
    write.commit().context("value ledger: commit")?;
    Ok(())
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
    use crate::compression::{
        CompressionRun, FailureReason, LeverKind, LeverOutcome, LeverResult, SkipReason,
    };
    use std::time::Duration;

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

    fn lever_result(lever: LeverKind, outcome: LeverOutcome, tokens_saved: u64) -> LeverResult {
        LeverResult {
            lever,
            backend: None,
            outcome,
            before_tokens: tokens_saved.saturating_add(10),
            after_tokens: 10,
            tokens_saved,
            duration: Duration::from_millis(1),
        }
    }

    #[test]
    fn pending_value_keeps_only_applied_positive_levers_and_prices_known_target_model() {
        let run = CompressionRun {
            messages: Vec::new(),
            initial_tokens: 1_050_010,
            final_tokens: 10,
            tokens_saved: 1_050_000,
            token_count_precision: TokenCountPrecision::ModelTokenizer,
            lever_results: vec![
                lever_result(LeverKind::WindowFit, LeverOutcome::Applied, 1_000_000),
                lever_result(LeverKind::SummaryBuffer, LeverOutcome::Applied, 50_000),
                lever_result(
                    LeverKind::WindowFit,
                    LeverOutcome::Skipped {
                        reason: SkipReason::NoSavings,
                    },
                    0,
                ),
                lever_result(
                    LeverKind::SummaryBuffer,
                    LeverOutcome::Failed {
                        reason: FailureReason::Internal,
                    },
                    25,
                ),
            ],
        };

        let pending = PendingCompressionValue::from_run("gpt-4o", &run)
            .expect("positive applied outcomes create pending value");
        assert_eq!(pending.target_model(), "gpt-4o");
        assert_eq!(pending.levers().len(), 2);
        assert_eq!(pending.levers()[0].tokens_saved(), 1_000_000);
        assert_eq!(
            pending.token_count_precision(),
            TokenCountPrecision::ModelTokenizer
        );

        let records = pending.priced_records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].lever(), LeverKind::WindowFit);
        assert_eq!(records[0].gross_cost_saved_micros(), 2_500_000);
        assert_eq!(
            records[0].token_count_precision(),
            TokenCountPrecision::ModelTokenizer
        );
        assert_eq!(records[1].gross_cost_saved_micros(), 125_000);
    }

    #[test]
    fn unpriced_target_model_keeps_tokens_without_claiming_avoided_cost() {
        let run = CompressionRun {
            messages: Vec::new(),
            initial_tokens: 1_000_010,
            final_tokens: 10,
            tokens_saved: 1_000_000,
            token_count_precision: TokenCountPrecision::Heuristic,
            lever_results: vec![lever_result(
                LeverKind::WindowFit,
                LeverOutcome::Applied,
                1_000_000,
            )],
        };

        let pending = PendingCompressionValue::from_run("wor-1921-unpriced-test-model", &run)
            .expect("positive applied outcome creates pending value");
        let records = pending.priced_records();

        assert_eq!(records[0].tokens_saved(), 1_000_000);
        assert_eq!(records[0].gross_cost_saved_micros(), 0);
        assert_eq!(
            records[0].token_count_precision(),
            TokenCountPrecision::Heuristic
        );
    }

    #[test]
    fn pending_value_is_absent_for_skips_failures_and_zero_savings() {
        let run = CompressionRun {
            messages: Vec::new(),
            initial_tokens: 10,
            final_tokens: 10,
            tokens_saved: 0,
            token_count_precision: TokenCountPrecision::ModelTokenizer,
            lever_results: vec![
                lever_result(
                    LeverKind::WindowFit,
                    LeverOutcome::Skipped {
                        reason: SkipReason::NotNeeded,
                    },
                    0,
                ),
                lever_result(
                    LeverKind::SummaryBuffer,
                    LeverOutcome::Failed {
                        reason: FailureReason::Internal,
                    },
                    2,
                ),
            ],
        };

        assert!(PendingCompressionValue::from_run("gpt-4o-mini", &run).is_none());
    }

    #[test]
    fn compression_value_survives_reopen_without_completion_counts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("compression-value.redb");
        {
            let ledger = ValueLedger::open(&path).expect("open");
            ledger.record_compression(
                "gpt-4o-mini",
                LeverKind::WindowFit,
                500,
                75,
                TokenCountPrecision::ModelTokenizer,
            );
            ledger.record_compression(
                "gpt-4o-mini",
                LeverKind::WindowFit,
                250,
                38,
                TokenCountPrecision::ModelTokenizer,
            );
            ledger.record_compression(
                "gpt-4o-mini",
                LeverKind::SummaryBuffer,
                100,
                15,
                TokenCountPrecision::ModelTokenizer,
            );
        }

        let report = ValueLedger::open(&path).expect("reopen").report();
        assert_eq!(report.total_local_completions, 0);
        assert_eq!(report.total_cloud_completions, 0);
        assert_eq!(report.total_saved_micros, 0);
        assert_eq!(report.total_compression_tokens_saved, 850);
        assert_eq!(report.total_compression_gross_cost_saved_micros, 128);
        assert_eq!(report.compression_totals["window_fit"].tokens_saved, 750);
    }

    #[test]
    fn memory_ledger_bounds_model_cardinality_with_a_stable_overflow_lane() {
        let ledger = ValueLedger::open("").expect("memory ledger");
        for index in 0..999 {
            ledger.record_compression(
                &format!("model-{index:04}"),
                LeverKind::WindowFit,
                1,
                0,
                TokenCountPrecision::Heuristic,
            );
        }
        ledger.record_compression(
            "overflow-a",
            LeverKind::WindowFit,
            7,
            0,
            TokenCountPrecision::Heuristic,
        );
        ledger.record_compression(
            "overflow-b",
            LeverKind::WindowFit,
            11,
            0,
            TokenCountPrecision::Heuristic,
        );

        let report = ledger.report();
        assert_eq!(report.models.len(), 1_000);
        let overflow = report
            .compression
            .iter()
            .find(|value| value.model == "__other__")
            .expect("overflow lane");
        assert_eq!(overflow.tokens_saved, 18);
        assert_eq!(report.total_compression_tokens_saved, 1_017);
    }

    #[test]
    fn memory_reserved_overflow_model_does_not_consume_remaining_capacity() {
        let ledger = ValueLedger::open("").expect("memory ledger");
        for (model, tokens) in [
            (VALUE_LEDGER_OVERFLOW_MODEL, 3),
            ("normal-a", 5),
            ("normal-b", 7),
        ] {
            ledger.record_compression(
                model,
                LeverKind::WindowFit,
                tokens,
                0,
                TokenCountPrecision::Heuristic,
            );
        }

        let report = ledger.report();
        assert_eq!(report.models.len(), 3);
        assert!(report.models.iter().any(|value| value.model == "normal-a"));
        assert!(report.models.iter().any(|value| value.model == "normal-b"));
    }

    #[test]
    fn redb_ledger_persists_the_bounded_overflow_lane() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bounded-value.redb");
        {
            let ledger = ValueLedger::open(&path).expect("open");
            for index in 0..999 {
                ledger.record_compression(
                    &format!("model-{index:04}"),
                    LeverKind::WindowFit,
                    1,
                    0,
                    TokenCountPrecision::Heuristic,
                );
            }
            ledger.record_compression(
                "overflow-a",
                LeverKind::WindowFit,
                7,
                0,
                TokenCountPrecision::Heuristic,
            );
            ledger.record_compression(
                "overflow-b",
                LeverKind::WindowFit,
                11,
                0,
                TokenCountPrecision::Heuristic,
            );
        }

        let report = ValueLedger::open(&path).expect("reopen").report();
        assert_eq!(report.models.len(), 1_000);
        let overflow = report
            .compression
            .iter()
            .find(|value| value.model == "__other__")
            .expect("overflow lane");
        assert_eq!(overflow.tokens_saved, 18);
        assert_eq!(report.total_compression_tokens_saved, 1_017);
    }

    #[test]
    fn redb_reserved_overflow_model_does_not_consume_remaining_capacity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("reserved-overflow-value.redb");
        {
            let ledger = ValueLedger::open(&path).expect("open");
            for (model, tokens) in [
                (VALUE_LEDGER_OVERFLOW_MODEL, 3),
                ("normal-a", 5),
                ("normal-b", 7),
            ] {
                ledger.record_compression(
                    model,
                    LeverKind::WindowFit,
                    tokens,
                    0,
                    TokenCountPrecision::Heuristic,
                );
            }
        }

        let report = ValueLedger::open(&path).expect("reopen").report();
        assert_eq!(report.models.len(), 3);
        assert!(report.models.iter().any(|value| value.model == "normal-a"));
        assert!(report.models.iter().any(|value| value.model == "normal-b"));
    }

    #[test]
    fn memory_ledger_promotes_in_place_and_merges_existing_redb_lanes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("promoted-value.redb");
        {
            let durable = ValueLedger::open(&path).expect("open existing durable ledger");
            durable.record_compression(
                "shared-model",
                LeverKind::WindowFit,
                3,
                0,
                TokenCountPrecision::Heuristic,
            );
            durable.record_compression(
                VALUE_LEDGER_OVERFLOW_MODEL,
                LeverKind::WindowFit,
                5,
                0,
                TokenCountPrecision::Heuristic,
            );
        }

        let ledger = Arc::new(ValueLedger::open("").expect("memory ledger"));
        let original_reference = ledger.clone();
        ledger.record_compression(
            "shared-model",
            LeverKind::SummaryBuffer,
            7,
            0,
            TokenCountPrecision::Heuristic,
        );
        ledger.record_compression(
            VALUE_LEDGER_OVERFLOW_MODEL,
            LeverKind::WindowFit,
            11,
            0,
            TokenCountPrecision::Heuristic,
        );

        let mut references = BTreeMap::new();
        references.insert("qwen".to_string(), ("gpt-4o".to_string(), cloud()));
        let sink = ValueSink::new(original_reference.clone(), references);

        ledger
            .promote_to_redb(&path)
            .expect("promote memory ledger to durable storage");
        assert!(Arc::ptr_eq(&ledger, &original_reference));

        // A sink built before promotion must write through the same facade to
        // the newly durable backend.
        sink.record(&event("qwen", 1_000, 500));

        let report = ledger.report();
        assert_eq!(report.total_local_completions, 1);
        assert_eq!(report.total_saved_micros, 10_500);
        assert_eq!(report.total_compression_tokens_saved, 26);
        assert_eq!(report.compression_totals["window_fit"].tokens_saved, 19);
        assert_eq!(report.compression_totals["summary_buffer"].tokens_saved, 7);

        drop(sink);
        drop(original_reference);
        drop(ledger);

        let reopened = ValueLedger::open(&path).expect("reopen promoted ledger");
        let report = reopened.report();
        assert_eq!(report.total_local_completions, 1);
        assert_eq!(report.total_saved_micros, 10_500);
        assert_eq!(report.total_compression_tokens_saved, 26);
    }

    #[test]
    fn process_ledger_reuses_the_memory_initializer_during_durable_promotion() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("process-value.redb");
        let slot = Arc::new(OnceLock::new());
        let compression_ledger = value_ledger_or_init_memory_in(&slot);
        compression_ledger.record_compression(
            "compression-before-handler",
            LeverKind::WindowFit,
            13,
            0,
            TokenCountPrecision::Heuristic,
        );

        let mut references = BTreeMap::new();
        references.insert("qwen".to_string(), ("gpt-4o".to_string(), cloud()));
        let preexisting_sink = ValueSink::new(compression_ledger.clone(), references);

        let paths = [path.clone(), path.clone()];
        let promoted = paths.map(|path| {
            let slot = slot.clone();
            std::thread::spawn(move || {
                value_ledger_or_init_redb_in(&slot, path)
                    .expect("initialize durable process ledger")
            })
        });
        let [first_handler, second_handler] =
            promoted.map(|thread| thread.join().expect("promotion thread"));

        assert!(Arc::ptr_eq(&compression_ledger, &first_handler));
        assert!(Arc::ptr_eq(&first_handler, &second_handler));
        preexisting_sink.record(&event("qwen", 1_000, 500));

        let report = second_handler.report();
        assert_eq!(report.total_compression_tokens_saved, 13);
        assert_eq!(report.total_local_completions, 1);
        assert_eq!(report.total_saved_micros, 10_500);
        assert!(path.is_file());
    }

    #[test]
    fn durable_promotion_is_alias_idempotent_and_rejects_a_different_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first_path = dir.path().join("value.redb");
        let alias_path = dir.path().join(".").join("value.redb");
        let conflicting_path = dir.path().join("other-value.redb");
        let canonical_first = resolve_redb_path(&first_path).expect("resolve first path");
        let canonical_conflict =
            resolve_redb_path(&conflicting_path).expect("resolve conflicting path");
        let ledger = ValueLedger::open("").expect("memory ledger");

        ledger
            .promote_to_redb(&first_path)
            .expect("first durable promotion");
        ledger
            .promote_to_redb(&alias_path)
            .expect("same durable path through an alias is idempotent");

        let error = ledger
            .promote_to_redb(&conflicting_path)
            .expect_err("a different durable path must be observable");
        let error = error.to_string();
        assert!(error.contains(&canonical_first.display().to_string()));
        assert!(error.contains(&canonical_conflict.display().to_string()));

        ledger.record_compression(
            "still-on-first-path",
            LeverKind::WindowFit,
            17,
            0,
            TokenCountPrecision::Heuristic,
        );
        drop(ledger);

        let report = ValueLedger::open(&first_path)
            .expect("reopen first durable path")
            .report();
        assert_eq!(report.total_compression_tokens_saved, 17);
        assert!(!conflicting_path.exists());
    }

    #[test]
    fn failed_promotion_keeps_memory_data_and_allows_a_clean_retry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let corrupt_path = dir.path().join("corrupt.redb");
        {
            let database = Database::create(&corrupt_path).expect("create corrupt database");
            let write = database.begin_write().expect("begin corrupt write");
            {
                let mut table = write.open_table(LANES).expect("open corrupt table");
                table
                    .insert("corrupt-model", b"not-json".as_slice())
                    .expect("insert corrupt lane");
            }
            write.commit().expect("commit corrupt lane");
        }

        let ledger = ValueLedger::open("").expect("memory ledger");
        ledger.record_compression(
            "memory-model",
            LeverKind::WindowFit,
            29,
            0,
            TokenCountPrecision::Heuristic,
        );

        let error = ledger
            .promote_to_redb(&corrupt_path)
            .expect_err("corrupt durable lanes must reject promotion");
        assert!(error.to_string().contains("decode lane during promotion"));
        assert_eq!(ledger.report().total_compression_tokens_saved, 29);

        let valid_path = dir.path().join("valid.redb");
        ledger
            .promote_to_redb(&valid_path)
            .expect("retry promotion to a valid path");
        drop(ledger);
        let report = ValueLedger::open(&valid_path)
            .expect("reopen valid path")
            .report();
        assert_eq!(report.total_compression_tokens_saved, 29);
    }

    #[test]
    fn promotion_bounds_disjoint_memory_and_existing_redb_lanes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bounded-promotion.redb");
        {
            let database = Database::create(&path).expect("create database");
            let write = database.begin_write().expect("begin seed write");
            {
                let mut table = write.open_table(LANES).expect("open seed table");
                for index in 0..999 {
                    let mut split = LaneSplit::default();
                    split.record_compression(
                        LeverKind::WindowFit.as_str(),
                        1,
                        0,
                        TokenCountPrecision::Heuristic,
                    );
                    let encoded = serde_json::to_vec(&split).expect("encode seed lane");
                    let model = format!("disk-model-{index:04}");
                    table
                        .insert(model.as_str(), encoded.as_slice())
                        .expect("insert seed lane");
                }
            }
            write.commit().expect("commit seed lanes");
        }

        let ledger = ValueLedger::open("").expect("memory ledger");
        for index in 0..999 {
            ledger.record_compression(
                &format!("memory-model-{index:04}"),
                LeverKind::WindowFit,
                1,
                0,
                TokenCountPrecision::Heuristic,
            );
        }
        ledger
            .promote_to_redb(&path)
            .expect("promote near-capacity disjoint lanes");

        let report = ledger.report();
        assert_eq!(report.models.len(), VALUE_LEDGER_MODEL_LIMIT);
        assert_eq!(report.total_compression_tokens_saved, 1_998);
        let overflow = report
            .compression
            .iter()
            .find(|value| value.model == VALUE_LEDGER_OVERFLOW_MODEL)
            .expect("overflow lane");
        assert_eq!(overflow.tokens_saved, 999);
    }

    #[test]
    fn legacy_redb_lane_without_compression_fields_remains_readable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("legacy-value.redb");
        {
            let database = Database::create(&path).expect("create legacy database");
            let write = database.begin_write().expect("begin legacy write");
            {
                let mut table = write.open_table(LANES).expect("open legacy table");
                table
                    .insert(
                        "legacy-model",
                        br#"{"local_completions":3,"cloud_completions":1,"saved_micros":99,"cloud_spent_micros":25}"#
                            .as_slice(),
                    )
                    .expect("insert legacy lane");
            }
            write.commit().expect("commit legacy lane");
        }

        let report = ValueLedger::open(&path)
            .expect("open upgraded ledger")
            .report();
        assert_eq!(report.total_local_completions, 3);
        assert_eq!(report.total_cloud_completions, 1);
        assert_eq!(report.total_saved_micros, 99);
        assert!(report.compression.is_empty());
        assert!(report.compression_totals.is_empty());
    }

    #[test]
    fn legacy_redb_compression_defaults_to_heuristic_precision() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("legacy-compression-value.redb");
        {
            let database = Database::create(&path).expect("create legacy database");
            let write = database.begin_write().expect("begin legacy write");
            {
                let mut table = write.open_table(LANES).expect("open legacy table");
                table
                    .insert(
                        "legacy-model",
                        br#"{"local_completions":0,"cloud_completions":0,"saved_micros":0,"cloud_spent_micros":0,"compression":{"window_fit":{"tokens_saved":10,"gross_cost_saved_micros":0}}}"#
                            .as_slice(),
                    )
                    .expect("insert legacy compression lane");
            }
            write.commit().expect("commit legacy lane");
        }

        let report = ValueLedger::open(&path).expect("reopen").report();
        assert_eq!(
            report.compression[0].token_count_precision,
            TokenCountPrecision::Heuristic
        );
    }
}

//! WOR-1875: durable windowed usage rollups.
//!
//! Spend data was process-lifetime Prometheus counters only: the admin
//! SpendView zeroed on every restart and `/api/usage/spend` could not
//! answer "what did team X spend yesterday" without an external
//! Prometheus. This module folds the same observations the attributed
//! spend metrics see into durable hour buckets in a redb database,
//! with daily compaction and bounded retention, so the admin API can
//! serve windowed spend series that survive restarts.
//!
//! ## Shape
//!
//! Hour buckets are keyed by `{hour_start, provider, model, tenant,
//! team, api_key_id, project, origin}` and aggregate request counts, tokens by
//! direction, cost in micro-USD, and a closed outcome split
//! (`ok` / `error` / `blocked`). A compaction pass folds hourly rows
//! past the hourly retention into day buckets under the same
//! dimensions, and prunes day buckets past the daily retention.
//!
//! Rows carry no prompt content and no raw key material (`api_key_id`
//! only), so the file is safe to back up and ship. Aggregation is
//! deterministic: replaying the same events yields the same buckets.
//!
//! ## Write path
//!
//! The request path never touches redb. [`RollupWriter`](crate::usage_rollup::RollupWriter) owns a
//! bounded channel drained by one dedicated thread (redb is a
//! synchronous embedded store); a full queue drops the event and
//! increments `sbproxy_telemetry_dropped_total{kind="usage_rollup"}`
//! rather than blocking the data plane. Events are folded in batches
//! inside one write transaction.
//!
//! The store itself is exercised directly by tests with explicit
//! timestamps, so retention and grouping are fully deterministic
//! under test (no clock trait needed).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use redb::{Database, ReadableTable, TableDefinition};

/// Hourly buckets: encoded dimension key -> encoded aggregate.
const HOURLY: TableDefinition<&[u8], &[u8]> = TableDefinition::new("usage_rollups_hourly_v1");
/// Daily buckets, same encoding at day granularity.
const DAILY: TableDefinition<&[u8], &[u8]> = TableDefinition::new("usage_rollups_daily_v1");

const HOUR_SECS: u64 = 3_600;
const DAY_SECS: u64 = 86_400;

/// Attribution dimensions of one rollup bucket. Empty strings are the
/// "unattributed" segment, mirroring the attributed metric labels.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RollupDims {
    /// Origin hostname the request arrived on. Empty on rows written
    /// by builds that predate the dimension; those decode as the
    /// unattributed segment.
    pub origin: String,
    /// Upstream provider name.
    pub provider: String,
    /// Model identifier.
    pub model: String,
    /// Tenant / workspace id.
    pub tenant: String,
    /// Owning team from the credential's attribution tags.
    pub team: String,
    /// Stable credential id (never raw key material).
    pub api_key_id: String,
    /// Project from the credential's attribution tags.
    pub project: String,
}

/// Closed outcome split for the rollup rows. Maps the wider
/// `sbproxy_ai_requests_attributed_total{outcome}` vocabulary onto the
/// three buckets an operator slices spend by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollupOutcome {
    /// Served successfully.
    Ok,
    /// Blocked by governance (guardrail, content filter, budget,
    /// rate limit, auth, policy).
    Blocked,
    /// Everything else (upstream errors, timeouts, client errors).
    Error,
}

impl RollupOutcome {
    /// Map an attributed-outcome label onto the rollup split.
    pub fn from_outcome_label(label: &str) -> Self {
        match label {
            "ok" => Self::Ok,
            "guardrail_block" | "content_filter" | "budget_exceeded" | "rate_limited"
            | "auth_denied" | "policy_block" => Self::Blocked,
            _ => Self::Error,
        }
    }
}

/// What one rollup event contributes to its bucket.
#[derive(Debug, Clone)]
pub enum RollupKind {
    /// Token / cost usage from the billing choke point. Fired once
    /// per billed AI request.
    Usage {
        /// Prompt-side tokens.
        tokens_in: u64,
        /// Completion-side tokens.
        tokens_out: u64,
        /// Derived cost in micro-USD.
        cost_usd_micros: u64,
    },
    /// Request outcome from the end-of-request phase. Fired once per
    /// AI request (including blocked requests that never billed);
    /// carries the request count.
    Outcome(RollupOutcome),
}

/// One event to fold into the store.
#[derive(Debug, Clone)]
pub struct RollupEvent {
    /// Wall-clock seconds since the Unix epoch.
    pub ts_secs: u64,
    /// Attribution dimensions.
    pub dims: RollupDims,
    /// Contribution.
    pub kind: RollupKind,
}

/// Aggregate stored per bucket. All counters are additive.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RollupAgg {
    /// Requests observed (from outcome events).
    pub requests: u64,
    /// Prompt-side tokens.
    pub tokens_in: u64,
    /// Completion-side tokens.
    pub tokens_out: u64,
    /// Cost in micro-USD.
    pub cost_usd_micros: u64,
    /// Requests that completed ok.
    pub ok: u64,
    /// Requests blocked by governance.
    pub blocked: u64,
    /// Requests that errored.
    pub error: u64,
}

impl RollupAgg {
    fn merge(&mut self, other: &RollupAgg) {
        self.requests += other.requests;
        self.tokens_in += other.tokens_in;
        self.tokens_out += other.tokens_out;
        self.cost_usd_micros += other.cost_usd_micros;
        self.ok += other.ok;
        self.blocked += other.blocked;
        self.error += other.error;
    }

    fn apply(&mut self, kind: &RollupKind) {
        match kind {
            RollupKind::Usage {
                tokens_in,
                tokens_out,
                cost_usd_micros,
            } => {
                self.tokens_in += tokens_in;
                self.tokens_out += tokens_out;
                self.cost_usd_micros += cost_usd_micros;
            }
            RollupKind::Outcome(outcome) => {
                self.requests += 1;
                match outcome {
                    RollupOutcome::Ok => self.ok += 1,
                    RollupOutcome::Blocked => self.blocked += 1,
                    RollupOutcome::Error => self.error += 1,
                }
            }
        }
    }

    fn encode(&self) -> [u8; 56] {
        let mut out = [0u8; 56];
        for (i, v) in [
            self.requests,
            self.tokens_in,
            self.tokens_out,
            self.cost_usd_micros,
            self.ok,
            self.blocked,
            self.error,
        ]
        .into_iter()
        .enumerate()
        {
            out[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes());
        }
        out
    }

    fn decode(bytes: &[u8]) -> Self {
        let mut vals = [0u64; 7];
        for (i, v) in vals.iter_mut().enumerate() {
            let start = i * 8;
            if bytes.len() >= start + 8 {
                let mut b = [0u8; 8];
                b.copy_from_slice(&bytes[start..start + 8]);
                *v = u64::from_le_bytes(b);
            }
        }
        Self {
            requests: vals[0],
            tokens_in: vals[1],
            tokens_out: vals[2],
            cost_usd_micros: vals[3],
            ok: vals[4],
            blocked: vals[5],
            error: vals[6],
        }
    }
}

/// Dimension the query groups buckets by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupBy {
    /// One series per provider.
    Provider,
    /// One series per model.
    Model,
    /// One series per tenant.
    Tenant,
    /// One series per team.
    Team,
    /// One series per credential id.
    ApiKey,
    /// One series per project.
    Project,
    /// One series per origin hostname.
    Origin,
    /// A single total series.
    Total,
}

impl GroupBy {
    /// Parse the admin API's `group_by` query value.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "provider" => Self::Provider,
            "model" => Self::Model,
            "tenant" => Self::Tenant,
            "team" => Self::Team,
            "api_key" => Self::ApiKey,
            "project" => Self::Project,
            "origin" => Self::Origin,
            "total" | "" => Self::Total,
            _ => return None,
        })
    }

    fn key_of(self, dims: &RollupDims) -> String {
        match self {
            Self::Provider => dims.provider.clone(),
            Self::Model => dims.model.clone(),
            Self::Tenant => dims.tenant.clone(),
            Self::Team => dims.team.clone(),
            Self::ApiKey => dims.api_key_id.clone(),
            Self::Project => dims.project.clone(),
            Self::Origin => dims.origin.clone(),
            Self::Total => String::new(),
        }
    }
}

/// One grouped time bucket in a query result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RollupBucket {
    /// Bucket start, seconds since the Unix epoch.
    pub ts_secs: u64,
    /// Group key value (empty for the unattributed segment or the
    /// `total` grouping).
    pub group: String,
    /// Requests in the bucket.
    pub requests: u64,
    /// Prompt-side tokens.
    pub tokens_in: u64,
    /// Completion-side tokens.
    pub tokens_out: u64,
    /// Cost in micro-USD.
    pub cost_usd_micros: u64,
    /// Requests that completed ok.
    pub ok: u64,
    /// Requests blocked by governance.
    pub blocked: u64,
    /// Requests that errored.
    pub error: u64,
}

/// Query result: grouped buckets plus window totals.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RollupQueryResult {
    /// Bucket granularity in seconds (3600 hourly, 86400 daily).
    pub bucket_secs: u64,
    /// Grouped, time-ordered buckets.
    pub buckets: Vec<RollupBucket>,
    /// Totals across the window.
    pub totals: RollupTotals,
}

/// Window totals for a query.
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct RollupTotals {
    /// Requests across the window.
    pub requests: u64,
    /// Prompt-side tokens.
    pub tokens_in: u64,
    /// Completion-side tokens.
    pub tokens_out: u64,
    /// Cost in micro-USD.
    pub cost_usd_micros: u64,
    /// Ok requests.
    pub ok: u64,
    /// Blocked requests.
    pub blocked: u64,
    /// Errored requests.
    pub error: u64,
}

fn encode_key(bucket_start: u64, dims: &RollupDims) -> Vec<u8> {
    // Big-endian timestamp prefix so redb range scans by time work.
    let mut key = Vec::with_capacity(
        8 + 14
            + dims.provider.len()
            + dims.model.len()
            + dims.tenant.len()
            + dims.team.len()
            + dims.api_key_id.len()
            + dims.project.len()
            + dims.origin.len(),
    );
    key.extend_from_slice(&bucket_start.to_be_bytes());
    // `origin` is encoded LAST so rows written before the dimension
    // existed still decode (the trailing slot is optional on read) and
    // older binaries reading a newer file simply ignore the tail.
    for part in [
        &dims.provider,
        &dims.model,
        &dims.tenant,
        &dims.team,
        &dims.api_key_id,
        &dims.project,
        &dims.origin,
    ] {
        let len = u16::try_from(part.len()).unwrap_or(u16::MAX);
        key.extend_from_slice(&len.to_be_bytes());
        key.extend_from_slice(&part.as_bytes()[..usize::from(len).min(part.len())]);
    }
    key
}

fn decode_key(key: &[u8]) -> Option<(u64, RollupDims)> {
    if key.len() < 8 {
        return None;
    }
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&key[..8]);
    let ts = u64::from_be_bytes(ts);
    let mut dims = RollupDims::default();
    let mut cursor = 8usize;
    for slot in [
        &mut dims.provider,
        &mut dims.model,
        &mut dims.tenant,
        &mut dims.team,
        &mut dims.api_key_id,
        &mut dims.project,
    ] {
        if key.len() < cursor + 2 {
            return None;
        }
        let len = usize::from(u16::from_be_bytes([key[cursor], key[cursor + 1]]));
        cursor += 2;
        if key.len() < cursor + len {
            return None;
        }
        *slot = String::from_utf8_lossy(&key[cursor..cursor + len]).into_owned();
        cursor += len;
    }
    // Optional trailing origin slot: rows written before the dimension
    // existed end here and decode as origin = "" (unattributed).
    if key.len() >= cursor + 2 {
        let len = usize::from(u16::from_be_bytes([key[cursor], key[cursor + 1]]));
        cursor += 2;
        if key.len() >= cursor + len {
            dims.origin = String::from_utf8_lossy(&key[cursor..cursor + len]).into_owned();
        }
    }
    Some((ts, dims))
}

/// Durable rollup store over one redb database. Synchronous; the
/// request path talks to [`RollupWriter`] instead.
pub struct RollupStore {
    db: Database,
}

impl RollupStore {
    /// Open (or create) the store at `path`, creating both tables.
    pub fn open(path: &std::path::Path) -> anyhow::Result<Self> {
        let db = Database::create(path)?;
        let txn = db.begin_write()?;
        {
            txn.open_table(HOURLY)?;
            txn.open_table(DAILY)?;
        }
        txn.commit()?;
        Ok(Self { db })
    }

    /// Fold a batch of events into their hourly buckets in one write
    /// transaction. Deterministic: the same events always produce the
    /// same buckets.
    pub fn fold(&self, events: &[RollupEvent]) -> anyhow::Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(HOURLY)?;
            for ev in events {
                let bucket_start = ev.ts_secs - (ev.ts_secs % HOUR_SECS);
                let key = encode_key(bucket_start, &ev.dims);
                let mut agg = table
                    .get(key.as_slice())?
                    .map(|v| RollupAgg::decode(v.value()))
                    .unwrap_or_default();
                agg.apply(&ev.kind);
                table.insert(key.as_slice(), agg.encode().as_slice())?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// Query buckets in `[from_secs, to_secs)` grouped by `group_by`.
    /// Uses hourly buckets when `from_secs` is within the hourly
    /// retention horizon (`hourly_horizon_secs` before `now_secs`),
    /// daily buckets otherwise.
    pub fn query(
        &self,
        from_secs: u64,
        to_secs: u64,
        group_by: GroupBy,
        now_secs: u64,
        hourly_horizon_secs: u64,
    ) -> anyhow::Result<RollupQueryResult> {
        let use_daily = from_secs < now_secs.saturating_sub(hourly_horizon_secs);
        let (table_def, bucket_secs) = if use_daily {
            (DAILY, DAY_SECS)
        } else {
            (HOURLY, HOUR_SECS)
        };
        let txn = self.db.begin_read()?;
        let table = txn.open_table(table_def)?;
        // Include the bucket a mid-bucket `from` falls into: align the
        // scan's lower bound down to the bucket boundary.
        let from_aligned = from_secs - (from_secs % bucket_secs);
        let lo = from_aligned.to_be_bytes().to_vec();
        let hi = to_secs.to_be_bytes().to_vec();
        let mut grouped: std::collections::BTreeMap<(u64, String), RollupAgg> =
            std::collections::BTreeMap::new();
        let mut totals = RollupAgg::default();
        for row in table.range(lo.as_slice()..hi.as_slice())? {
            let (k, v) = row?;
            let Some((ts, dims)) = decode_key(k.value()) else {
                continue;
            };
            let agg = RollupAgg::decode(v.value());
            totals.merge(&agg);
            grouped
                .entry((ts, group_by.key_of(&dims)))
                .or_default()
                .merge(&agg);
        }
        let buckets = grouped
            .into_iter()
            .map(|((ts_secs, group), agg)| RollupBucket {
                ts_secs,
                group,
                requests: agg.requests,
                tokens_in: agg.tokens_in,
                tokens_out: agg.tokens_out,
                cost_usd_micros: agg.cost_usd_micros,
                ok: agg.ok,
                blocked: agg.blocked,
                error: agg.error,
            })
            .collect();
        Ok(RollupQueryResult {
            bucket_secs,
            buckets,
            totals: RollupTotals {
                requests: totals.requests,
                tokens_in: totals.tokens_in,
                tokens_out: totals.tokens_out,
                cost_usd_micros: totals.cost_usd_micros,
                ok: totals.ok,
                blocked: totals.blocked,
                error: totals.error,
            },
        })
    }

    /// Retention pass: fold hourly buckets older than
    /// `hourly_retention_secs` into daily buckets, then delete daily
    /// buckets older than `daily_retention_secs`. Deterministic given
    /// `now_secs`.
    pub fn prune(
        &self,
        now_secs: u64,
        hourly_retention_secs: u64,
        daily_retention_secs: u64,
    ) -> anyhow::Result<()> {
        let hourly_cutoff = now_secs.saturating_sub(hourly_retention_secs);
        let daily_cutoff = now_secs.saturating_sub(daily_retention_secs);
        let txn = self.db.begin_write()?;
        {
            let mut hourly = txn.open_table(HOURLY)?;
            let mut daily = txn.open_table(DAILY)?;
            // Collect expiring hourly rows first (can't mutate while
            // iterating).
            let mut expiring: Vec<(Vec<u8>, RollupAgg)> = Vec::new();
            let cutoff_key = hourly_cutoff.to_be_bytes().to_vec();
            for row in hourly.range(..cutoff_key.as_slice())? {
                let (k, v) = row?;
                expiring.push((k.value().to_vec(), RollupAgg::decode(v.value())));
            }
            for (key, agg) in &expiring {
                if let Some((ts, dims)) = decode_key(key) {
                    let day_start = ts - (ts % DAY_SECS);
                    let day_key = encode_key(day_start, &dims);
                    let mut day_agg = daily
                        .get(day_key.as_slice())?
                        .map(|v| RollupAgg::decode(v.value()))
                        .unwrap_or_default();
                    day_agg.merge(agg);
                    daily.insert(day_key.as_slice(), day_agg.encode().as_slice())?;
                }
                hourly.remove(key.as_slice())?;
            }
            // Drop day buckets past the daily retention.
            let daily_cutoff_key = daily_cutoff.to_be_bytes().to_vec();
            let old_days: Vec<Vec<u8>> = daily
                .range(..daily_cutoff_key.as_slice())?
                .filter_map(|r| r.ok().map(|(k, _)| k.value().to_vec()))
                .collect();
            for key in old_days {
                daily.remove(key.as_slice())?;
            }
        }
        txn.commit()?;
        Ok(())
    }
}

/// Non-blocking writer handle for the request path: a bounded channel
/// drained by one thread that folds batches into the store.
pub struct RollupWriter {
    tx: std::sync::mpsc::SyncSender<RollupEvent>,
    store: Arc<RollupStore>,
    hourly_retention_secs: u64,
    shutdown: Arc<AtomicBool>,
    handle: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl RollupWriter {
    /// Spawn the writer thread over `store`. `hourly_retention_secs` /
    /// `daily_retention_secs` drive the periodic retention pass.
    pub fn spawn(
        store: Arc<RollupStore>,
        hourly_retention_secs: u64,
        daily_retention_secs: u64,
    ) -> Arc<Self> {
        let (tx, rx) = std::sync::mpsc::sync_channel::<RollupEvent>(8_192);
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_store = store.clone();
        let thread_shutdown = shutdown.clone();
        let handle = std::thread::Builder::new()
            .name("sbproxy-usage-rollup".to_string())
            .spawn(move || {
                let mut batch: Vec<RollupEvent> = Vec::with_capacity(256);
                let mut last_prune = std::time::Instant::now();
                loop {
                    // Block briefly for the first event, then drain
                    // whatever else is queued into one transaction.
                    match rx.recv_timeout(std::time::Duration::from_millis(500)) {
                        Ok(ev) => {
                            batch.push(ev);
                            while batch.len() < 4_096 {
                                match rx.try_recv() {
                                    Ok(ev) => batch.push(ev),
                                    Err(_) => break,
                                }
                            }
                            if let Err(e) = thread_store.fold(&batch) {
                                tracing::warn!(error = %e, "usage rollup fold failed");
                                crate::metrics::record_telemetry_dropped(
                                    "usage_rollup",
                                    "fold_error",
                                );
                            }
                            batch.clear();
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                    if thread_shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                    // Retention pass every ~10 minutes; cheap when
                    // nothing expires.
                    if last_prune.elapsed() > std::time::Duration::from_secs(600) {
                        last_prune = std::time::Instant::now();
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        if let Err(e) =
                            thread_store.prune(now, hourly_retention_secs, daily_retention_secs)
                        {
                            tracing::warn!(error = %e, "usage rollup retention pass failed");
                        }
                    }
                }
            })
            .ok();
        Arc::new(Self {
            tx,
            store,
            hourly_retention_secs,
            shutdown,
            handle: Mutex::new(handle),
        })
    }

    /// The hourly-bucket horizon the writer compacts past. Queries
    /// pass this so windows older than the horizon read the daily
    /// table.
    pub fn hourly_retention_secs(&self) -> u64 {
        self.hourly_retention_secs
    }

    /// Enqueue an event; never blocks. A full queue drops the event
    /// and increments the dropped-telemetry counter.
    pub fn record(&self, ev: RollupEvent) {
        if self.tx.try_send(ev).is_err() {
            crate::metrics::record_telemetry_dropped("usage_rollup", "queue_full");
        }
    }

    /// The underlying store, for admin queries.
    pub fn store(&self) -> &Arc<RollupStore> {
        &self.store
    }

    /// Stop the writer thread (used by tests; production lets the
    /// process end take it down).
    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = h.join();
        }
    }
}

/// Process-global writer, installed at boot when
/// `proxy.observability.usage_rollups` is enabled and the store
/// opened. Absent means rollups are off and recording is a no-op.
static ROLLUP_WRITER: OnceLock<Arc<RollupWriter>> = OnceLock::new();

/// Install the process-global rollup writer. First install wins.
pub fn install_usage_rollup_writer(writer: Arc<RollupWriter>) {
    let _ = ROLLUP_WRITER.set(writer);
}

/// The installed writer, if rollups are on.
pub fn usage_rollup_writer() -> Option<&'static Arc<RollupWriter>> {
    ROLLUP_WRITER.get()
}

/// Record one event against the installed writer; no-op when rollups
/// are disabled.
pub fn record_usage_rollup(ev: RollupEvent) {
    if let Some(w) = ROLLUP_WRITER.get() {
        w.record(ev);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dims(provider: &str, model: &str, team: &str) -> RollupDims {
        RollupDims {
            origin: "ai.example".to_string(),
            provider: provider.to_string(),
            model: model.to_string(),
            tenant: "t1".to_string(),
            team: team.to_string(),
            api_key_id: "sk_1".to_string(),
            project: "p1".to_string(),
        }
    }

    #[test]
    fn decode_tolerates_keys_without_the_origin_slot() {
        // Rows written by builds that predate the origin dimension end
        // after the project slot; they must decode as origin = "".
        let with_origin = dims("openai", "gpt-4o", "growth");
        let legacy = RollupDims {
            origin: String::new(),
            ..with_origin.clone()
        };

        // A legacy key is exactly the modern key minus the trailing
        // origin slot.
        let modern_key = encode_key(3600, &with_origin);
        let legacy_key = modern_key[..modern_key.len() - 2 - with_origin.origin.len()].to_vec();

        let (ts, decoded) = decode_key(&legacy_key).expect("legacy key must decode");
        assert_eq!(ts, 3600);
        assert_eq!(decoded, legacy);
        assert_eq!(decoded.origin, "");

        let (_, decoded_modern) = decode_key(&modern_key).expect("modern key must decode");
        assert_eq!(decoded_modern, with_origin);
    }

    #[test]
    fn group_by_origin_parses_and_groups() {
        assert_eq!(GroupBy::parse("origin"), Some(GroupBy::Origin));
        let d = dims("openai", "gpt-4o", "growth");
        assert_eq!(GroupBy::Origin.key_of(&d), "ai.example");
    }

    fn usage(ts: u64, d: RollupDims, tin: u64, tout: u64, cost: u64) -> RollupEvent {
        RollupEvent {
            ts_secs: ts,
            dims: d,
            kind: RollupKind::Usage {
                tokens_in: tin,
                tokens_out: tout,
                cost_usd_micros: cost,
            },
        }
    }

    fn outcome(ts: u64, d: RollupDims, o: RollupOutcome) -> RollupEvent {
        RollupEvent {
            ts_secs: ts,
            dims: d,
            kind: RollupKind::Outcome(o),
        }
    }

    #[test]
    fn key_roundtrip_preserves_dims() {
        let d = dims("openai", "gpt-4o", "growth");
        let key = encode_key(1_700_000_000 - (1_700_000_000 % HOUR_SECS), &d);
        let (ts, decoded) = decode_key(&key).expect("key decodes");
        assert_eq!(ts % HOUR_SECS, 0);
        assert_eq!(decoded, d);
    }

    #[test]
    fn fold_and_query_group_by_model_sums_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let store = RollupStore::open(&dir.path().join("r.redb")).unwrap();
        // Base hour-aligned timestamp; three hours, two models.
        let t0 = 1_700_000_400; // inside hour H
        let h = 3_600;
        store
            .fold(&[
                usage(t0, dims("openai", "gpt-4o", "a"), 100, 50, 300),
                outcome(t0, dims("openai", "gpt-4o", "a"), RollupOutcome::Ok),
                usage(t0 + h, dims("openai", "gpt-4o", "a"), 10, 5, 30),
                outcome(t0 + h, dims("openai", "gpt-4o", "a"), RollupOutcome::Ok),
                usage(t0 + 2 * h, dims("openai", "gpt-4.1-mini", "a"), 7, 3, 9),
                outcome(
                    t0 + 2 * h,
                    dims("openai", "gpt-4.1-mini", "a"),
                    RollupOutcome::Blocked,
                ),
            ])
            .unwrap();

        let res = store
            .query(
                t0 - h,
                t0 + 3 * h,
                GroupBy::Model,
                t0 + 3 * h,
                90 * DAY_SECS,
            )
            .unwrap();
        assert_eq!(res.bucket_secs, HOUR_SECS);
        // Two models, three distinct (hour, group) buckets.
        assert_eq!(res.buckets.len(), 3);
        let gpt4o_tokens: u64 = res
            .buckets
            .iter()
            .filter(|b| b.group == "gpt-4o")
            .map(|b| b.tokens_in)
            .sum();
        assert_eq!(gpt4o_tokens, 110);
        assert_eq!(res.totals.tokens_in, 117);
        assert_eq!(res.totals.tokens_out, 58);
        assert_eq!(res.totals.cost_usd_micros, 339);
        assert_eq!(res.totals.requests, 3);
        assert_eq!(res.totals.ok, 2);
        assert_eq!(res.totals.blocked, 1);
    }

    #[test]
    fn query_window_excludes_outside_buckets() {
        let dir = tempfile::tempdir().unwrap();
        let store = RollupStore::open(&dir.path().join("r.redb")).unwrap();
        let t0 = 1_700_000_400;
        store
            .fold(&[
                usage(t0, dims("openai", "m", "a"), 1, 1, 1),
                usage(t0 + 10 * HOUR_SECS, dims("openai", "m", "a"), 100, 100, 100),
            ])
            .unwrap();
        let res = store
            .query(
                t0 - HOUR_SECS,
                t0 + HOUR_SECS,
                GroupBy::Total,
                t0 + 10 * HOUR_SECS,
                90 * DAY_SECS,
            )
            .unwrap();
        assert_eq!(res.totals.tokens_in, 1, "later bucket must not leak in");
    }

    #[test]
    fn prune_compacts_hourly_into_daily_and_drops_old_days() {
        let dir = tempfile::tempdir().unwrap();
        let store = RollupStore::open(&dir.path().join("r.redb")).unwrap();
        let day = DAY_SECS;
        let now = 100 * day;
        // Two hourly buckets on the same old day (beyond hourly
        // retention of 10 days), plus a fresh one.
        let old_day_start = 80 * day;
        store
            .fold(&[
                usage(old_day_start + HOUR_SECS, dims("p", "m", "t"), 10, 0, 5),
                usage(old_day_start + 2 * HOUR_SECS, dims("p", "m", "t"), 20, 0, 7),
                usage(now - HOUR_SECS, dims("p", "m", "t"), 1, 0, 1),
            ])
            .unwrap();
        store.prune(now, 10 * day, 90 * day).unwrap();

        // Hourly window near `now` still hourly and intact.
        let fresh = store
            .query(now - 2 * HOUR_SECS, now, GroupBy::Total, now, 10 * day)
            .unwrap();
        assert_eq!(fresh.totals.tokens_in, 1);

        // The old day is served from the daily table, compacted.
        let old = store
            .query(
                old_day_start,
                old_day_start + day,
                GroupBy::Total,
                now,
                10 * day,
            )
            .unwrap();
        assert_eq!(old.bucket_secs, DAY_SECS);
        assert_eq!(old.totals.tokens_in, 30);
        assert_eq!(old.totals.cost_usd_micros, 12);
        assert_eq!(old.buckets.len(), 1);

        // A second prune with a daily retention that expires the old
        // day removes it.
        store.prune(now, 10 * day, 15 * day).unwrap();
        let gone = store
            .query(
                old_day_start,
                old_day_start + day,
                GroupBy::Total,
                now,
                10 * day,
            )
            .unwrap();
        assert_eq!(gone.totals.tokens_in, 0);
    }

    #[test]
    fn outcome_label_mapping_is_closed() {
        assert_eq!(RollupOutcome::from_outcome_label("ok"), RollupOutcome::Ok);
        for blocked in [
            "guardrail_block",
            "content_filter",
            "budget_exceeded",
            "rate_limited",
            "auth_denied",
            "policy_block",
        ] {
            assert_eq!(
                RollupOutcome::from_outcome_label(blocked),
                RollupOutcome::Blocked,
                "{blocked} must map to Blocked"
            );
        }
        for err in ["timeout", "upstream_5xx", "client_error", "other", "??"] {
            assert_eq!(
                RollupOutcome::from_outcome_label(err),
                RollupOutcome::Error,
                "{err} must map to Error"
            );
        }
    }

    #[test]
    fn writer_records_through_channel_and_stops() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(RollupStore::open(&dir.path().join("r.redb")).unwrap());
        let writer = RollupWriter::spawn(store.clone(), 90 * DAY_SECS, 400 * DAY_SECS);
        let t0 = 1_700_000_400;
        writer.record(usage(t0, dims("p", "m", "t"), 5, 2, 3));
        writer.record(outcome(t0, dims("p", "m", "t"), RollupOutcome::Ok));
        // The writer thread folds within its 500ms poll cadence.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let res = writer
                .store()
                .query(t0 - 1, t0 + HOUR_SECS, GroupBy::Total, t0, 90 * DAY_SECS)
                .unwrap();
            if res.totals.requests == 1 && res.totals.tokens_in == 5 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "writer did not fold events in time"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        writer.stop();
    }
}

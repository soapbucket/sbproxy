// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Operating the meter: seven `sbproxy_meter_*` families, on the OTLP push
//! path and the Prometheus scrape at once.
//!
//! # Metrics are not the billing record
//!
//! The signed chain in [`sbproxy_meter::ledger`] is the authoritative
//! record of what was consumed. Everything in this module is operational
//! telemetry, and it is lossy by design in three separate ways that all
//! look like healthy data on a dashboard:
//!
//! - OTLP export is best effort. `PeriodicReader` drops a batch when the
//!   collector is unreachable, and the next batch carries on as though
//!   nothing happened.
//! - Cumulative counters reset to zero when the process restarts, so a
//!   `rate()` across a deploy window under-reports and an `increase()`
//!   across one is simply wrong.
//! - Aggregation destroys individual events. A window's worth of units is a
//!   sum, and no query recovers the receipts that went into it.
//!
//! So an invoice built from a Grafana panel is quietly wrong, and quietly
//! is the problem: it will agree with the chain most months. Reconcile
//! against the chain. Use these to find out whether the meter is healthy,
//! which is the one question the chain cannot answer about itself.
//!
//! # Route is not a label, on purpose
//!
//! Route lives on the receipt, where it is free, and stays off every label
//! set here, where it is not. `tenant x route x unit x source x outcome` is
//! a cardinality bomb and route is by far the largest factor in it: tenants
//! and unit names are bounded by an operator's own commercial vocabulary,
//! and routes are bounded by nothing. Somebody asking "which route drove
//! this spike" is asking a question the receipts answer exactly, reached
//! from the `claim_id` that the exemplar on the append histogram leads to.
//!
//! # Push is primary, scrape is secondary
//!
//! Both surfaces are wired and both carry the same seven families. They are
//! not equally trustworthy under load: `/metrics` is known to degrade at
//! peak volume, and billing visibility that vanishes exactly when volume is
//! highest is worse than no dashboard at all, because its absence reads as
//! quiet rather than as a gap. Treat the OTLP push path as the one that has
//! to work, and the scrape as the convenience.
//!
//! # Exemplars close the loop
//!
//! `sbproxy_meter_append_duration_seconds_bucket` carries W3C trace
//! exemplars (see [`crate::exemplars`]). A billing spike on a dashboard
//! reaches the trace, the trace carries `claim_id`, and `claim_id` resolves
//! to the exact signed receipt. That path is why the histogram is worth
//! having: append latency on its own is a number nobody can act on.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use opentelemetry::global;
use opentelemetry::metrics::{Counter, Gauge, Histogram};
use prometheus::{Histogram as PromHistogram, HistogramOpts, IntCounterVec, IntGauge, Opts};
use sbproxy_meter::{Billable, BillableOutcome, FailurePosture, MeterObserver, UnitSource};

use crate::exemplars::STANDARD_LATENCY_BUCKETS;
use crate::metrics::{current_trace_ids, metrics, sanitize_label};

/// Label value substituted when the meter reports a gap it cannot
/// attribute to a tenant.
///
/// An empty label value is legal Prometheus and useless to read: it renders
/// as an absent dimension and silently joins with every other series that
/// happens to omit the label. A named placeholder is at least something an
/// operator can select on and go looking for.
const UNATTRIBUTED_TENANT: &str = "unknown";

// --- Prometheus families ---
//
// All seven live on the `ProxyMetrics` registry rather than the process
// default, so `render()` emits each exactly once. A family on both
// registries is emitted twice, and the Prometheus text format rejects a
// repeated `# TYPE` for the whole scrape rather than for the one family.

/// `sbproxy_meter_units_total{tenant_id, unit, source}`.
fn units_total() -> &'static IntCounterVec {
    static FAMILY: OnceLock<IntCounterVec> = OnceLock::new();
    FAMILY.get_or_init(|| {
        let counter = IntCounterVec::new(
            Opts::new(
                "sbproxy_meter_units_total",
                "Units the meter counted, by tenant, operator-chosen unit name, and provenance.",
            ),
            &["tenant_id", "unit", "source"],
        )
        .expect("meter units counter constructs");
        let _ = metrics().registry.register(Box::new(counter.clone()));
        counter
    })
}

/// `sbproxy_meter_receipts_total{tenant_id, outcome, billable}`.
fn receipts_total() -> &'static IntCounterVec {
    static FAMILY: OnceLock<IntCounterVec> = OnceLock::new();
    FAMILY.get_or_init(|| {
        let counter = IntCounterVec::new(
            Opts::new(
                "sbproxy_meter_receipts_total",
                "Metered attempts, by tenant, outcome, and the operator's billing answer for it.",
            ),
            &["tenant_id", "outcome", "billable"],
        )
        .expect("meter receipts counter constructs");
        let _ = metrics().registry.register(Box::new(counter.clone()));
        counter
    })
}

/// `sbproxy_meter_chain_gap_total{tenant_id, failure_mode}`.
fn chain_gap_total() -> &'static IntCounterVec {
    static FAMILY: OnceLock<IntCounterVec> = OnceLock::new();
    FAMILY.get_or_init(|| {
        let counter = IntCounterVec::new(
            Opts::new(
                "sbproxy_meter_chain_gap_total",
                "Records the meter owed and could not write, by tenant and the posture in force.",
            ),
            &["tenant_id", "failure_mode"],
        )
        .expect("meter chain gap counter constructs");
        let _ = metrics().registry.register(Box::new(counter.clone()));
        counter
    })
}

/// `sbproxy_meter_incoherent_receipts_total{tenant_id, failure_mode}`.
///
/// The same label set as `sbproxy_meter_chain_gap_total`, so an operator
/// who has written one alert has written the other, and a separate family
/// rather than a third `failure_mode` value on that one. The two describe
/// different holes: a chain gap is a record that was owed and never
/// written, and this is a record that was written, is authentically signed,
/// and cannot be believed. A dashboard that could not tell them apart would
/// send somebody to check disk space over a laundered provenance claim.
fn incoherent_receipts_total() -> &'static IntCounterVec {
    static FAMILY: OnceLock<IntCounterVec> = OnceLock::new();
    FAMILY.get_or_init(|| {
        let counter = IntCounterVec::new(
            Opts::new(
                "sbproxy_meter_incoherent_receipts_total",
                "Receipts refused on decode because a unit's declared provenance contradicts \
                 its evidence, by tenant and the posture in force.",
            ),
            &["tenant_id", "failure_mode"],
        )
        .expect("meter incoherent receipts counter constructs");
        let _ = metrics().registry.register(Box::new(counter.clone()));
        counter
    })
}

/// `sbproxy_meter_divergence_total{tenant_id}`.
fn divergence_total() -> &'static IntCounterVec {
    static FAMILY: OnceLock<IntCounterVec> = OnceLock::new();
    FAMILY.get_or_init(|| {
        let counter = IntCounterVec::new(
            Opts::new(
                "sbproxy_meter_divergence_total",
                "Windows in which counted units and chained units disagreed, by tenant.",
            ),
            &["tenant_id"],
        )
        .expect("meter divergence counter constructs");
        let _ = metrics().registry.register(Box::new(counter.clone()));
        counter
    })
}

/// `sbproxy_meter_chain_seq`.
fn chain_seq() -> &'static IntGauge {
    static FAMILY: OnceLock<IntGauge> = OnceLock::new();
    FAMILY.get_or_init(|| {
        let gauge = IntGauge::new(
            "sbproxy_meter_chain_seq",
            "Head sequence number of the meter's signed chain.",
        )
        .expect("meter chain seq gauge constructs");
        let _ = metrics().registry.register(Box::new(gauge.clone()));
        gauge
    })
}

/// `sbproxy_meter_append_duration_seconds`.
///
/// Shares [`STANDARD_LATENCY_BUCKETS`] with every other sbproxy histogram,
/// which is what lets the exemplar side-store key on the same `le` values
/// the text encoder renders.
fn append_duration_seconds() -> &'static PromHistogram {
    static FAMILY: OnceLock<PromHistogram> = OnceLock::new();
    FAMILY.get_or_init(|| {
        let histogram = PromHistogram::with_opts(
            HistogramOpts::new(
                "sbproxy_meter_append_duration_seconds",
                "Time to append one entry to the meter's signed chain, including lock wait.",
            )
            .buckets(STANDARD_LATENCY_BUCKETS.to_vec()),
        )
        .expect("meter append duration histogram constructs");
        let _ = metrics().registry.register(Box::new(histogram.clone()));
        histogram
    })
}

// --- OpenTelemetry instruments ---
//
// Built lazily on first use, mirroring `crate::otel`. Before
// `init_otlp_metrics_pipeline` runs, `global::meter` hands back a no-op
// meter and every record below costs a vtable hop and nothing else, so a
// process that never enabled OTLP keeps the Prometheus surface at full
// fidelity and pays almost nothing for the one it did not ask for.
//
// Each instrument sits behind `OnceLock<Mutex<Option<..>>>` rather than a
// bare `OnceLock<..>` solely so `reset_otel_instruments_for_test` can clear
// it (WOR-2298): plain `cargo test` runs every test in this file in one
// process, so a handle bound to whatever meter provider was global when it
// was first built would otherwise survive past the test that built it,
// unlike under `cargo nextest`'s one-process-per-test isolation this
// module was originally written to assume.

fn otel_instrument<T: Clone>(
    cell: &'static OnceLock<Mutex<Option<T>>>,
    build: impl FnOnce() -> T,
) -> T {
    let mut guard = cell
        .get_or_init(|| Mutex::new(None))
        .lock()
        .expect("otel instrument mutex");
    if guard.is_none() {
        *guard = Some(build());
    }
    guard.clone().expect("initialized immediately above")
}

static OTEL_UNITS: OnceLock<Mutex<Option<Counter<u64>>>> = OnceLock::new();
static OTEL_RECEIPTS: OnceLock<Mutex<Option<Counter<u64>>>> = OnceLock::new();
static OTEL_CHAIN_GAP: OnceLock<Mutex<Option<Counter<u64>>>> = OnceLock::new();
static OTEL_INCOHERENT_RECEIPTS: OnceLock<Mutex<Option<Counter<u64>>>> = OnceLock::new();
static OTEL_DIVERGENCE: OnceLock<Mutex<Option<Counter<u64>>>> = OnceLock::new();
static OTEL_CHAIN_SEQ: OnceLock<Mutex<Option<Gauge<u64>>>> = OnceLock::new();
static OTEL_APPEND_DURATION: OnceLock<Mutex<Option<Histogram<f64>>>> = OnceLock::new();

/// OTel counter mirroring `sbproxy_meter_units_total`.
fn otel_units() -> Counter<u64> {
    otel_instrument(&OTEL_UNITS, || {
        global::meter("sbproxy")
            .u64_counter("sbproxy.meter.units")
            .with_description("Units the meter counted, by tenant, unit name, and provenance.")
            .with_unit("{unit}")
            .build()
    })
}

/// OTel counter mirroring `sbproxy_meter_receipts_total`.
fn otel_receipts() -> Counter<u64> {
    otel_instrument(&OTEL_RECEIPTS, || {
        global::meter("sbproxy")
            .u64_counter("sbproxy.meter.receipts")
            .with_description("Metered attempts, by tenant, outcome, and billing answer.")
            .with_unit("{receipt}")
            .build()
    })
}

/// OTel counter mirroring `sbproxy_meter_chain_gap_total`.
fn otel_chain_gap() -> Counter<u64> {
    otel_instrument(&OTEL_CHAIN_GAP, || {
        global::meter("sbproxy")
            .u64_counter("sbproxy.meter.chain_gap")
            .with_description("Records the meter owed and could not write.")
            .with_unit("{record}")
            .build()
    })
}

/// OTel counter mirroring `sbproxy_meter_incoherent_receipts_total`.
fn otel_incoherent_receipts() -> Counter<u64> {
    otel_instrument(&OTEL_INCOHERENT_RECEIPTS, || {
        global::meter("sbproxy")
            .u64_counter("sbproxy.meter.incoherent_receipts")
            .with_description("Receipts refused on decode for contradicting their own provenance.")
            .with_unit("{receipt}")
            .build()
    })
}

/// OTel counter mirroring `sbproxy_meter_divergence_total`.
fn otel_divergence() -> Counter<u64> {
    otel_instrument(&OTEL_DIVERGENCE, || {
        global::meter("sbproxy")
            .u64_counter("sbproxy.meter.divergence")
            .with_description("Windows in which counted units and chained units disagreed.")
            .with_unit("{window}")
            .build()
    })
}

/// OTel gauge mirroring `sbproxy_meter_chain_seq`.
fn otel_chain_seq() -> Gauge<u64> {
    otel_instrument(&OTEL_CHAIN_SEQ, || {
        global::meter("sbproxy")
            .u64_gauge("sbproxy.meter.chain_seq")
            .with_description("Head sequence number of the meter's signed chain.")
            .with_unit("{entry}")
            .build()
    })
}

/// OTel histogram mirroring `sbproxy_meter_append_duration_seconds`.
fn otel_append_duration() -> Histogram<f64> {
    otel_instrument(&OTEL_APPEND_DURATION, || {
        global::meter("sbproxy")
            .f64_histogram("sbproxy.meter.append.duration")
            .with_description("Time to append one entry to the meter's signed chain, in seconds.")
            .with_unit("s")
            .build()
    })
}

/// Test-only: clears every cached OTel instrument handle so the next call
/// rebuilds against whatever meter provider is currently global.
///
/// Call this AFTER `global::set_meter_provider(..)`, not before: an
/// instrument built earlier in the same process (plain `cargo test` shares
/// one process across every test in this file) stays bound to the
/// provider that was global when it was first built, and installing a new
/// provider does not retroactively rebind it (WOR-2298).
#[cfg(test)]
fn reset_otel_instruments_for_test() {
    for cell in [
        &OTEL_UNITS,
        &OTEL_RECEIPTS,
        &OTEL_CHAIN_GAP,
        &OTEL_INCOHERENT_RECEIPTS,
        &OTEL_DIVERGENCE,
    ] {
        if let Some(m) = cell.get() {
            *m.lock().expect("otel instrument mutex") = None;
        }
    }
    if let Some(m) = OTEL_CHAIN_SEQ.get() {
        *m.lock().expect("otel instrument mutex") = None;
    }
    if let Some(m) = OTEL_APPEND_DURATION.get() {
        *m.lock().expect("otel instrument mutex") = None;
    }
}

// --- Recorders ---
//
// Each of these is the `writer` that a `metric_registry::METRICS` row
// names, and each is called from the `MeterObserver` implementation at the
// bottom of this file. Keeping the pair in one module is deliberate: the
// registry's writer guard proves a call site exists, and a reader should be
// able to see that call site without leaving the file that declares the
// family.

/// Count units against a tenant, on both surfaces.
///
/// `unit` is whatever an operator named their billable quantity, so it goes
/// through the cardinality limiter. `source` is a closed enum and does not.
fn record_meter_units(tenant_id: &str, unit: &str, source: UnitSource, count: u64) {
    if count == 0 {
        // A zero-count unit is a resolver that ran and found nothing. That
        // is a real event and it is not a billable quantity, and emitting a
        // series for it puts a permanently flat line under a tenant's name.
        return;
    }
    let tenant_id = tenant(tenant_id);
    let unit = sanitize_label("unit", unit);
    units_total()
        .with_label_values(&[tenant_id.as_str(), unit.as_str(), source.as_str()])
        .inc_by(count);
    otel_units().add(
        count,
        &[
            opentelemetry::KeyValue::new("tenant_id", tenant_id.clone()),
            opentelemetry::KeyValue::new("unit", unit),
            opentelemetry::KeyValue::new("source", source.as_str()),
        ],
    );
    note_counted(&tenant_id, count);
}

/// Count one classified attempt on both surfaces.
fn record_meter_receipt(tenant_id: &str, outcome: BillableOutcome, billable: Billable) {
    let tenant_id = tenant(tenant_id);
    receipts_total()
        .with_label_values(&[tenant_id.as_str(), outcome.as_str(), billable.as_str()])
        .inc();
    otel_receipts().add(
        1,
        &[
            opentelemetry::KeyValue::new("tenant_id", tenant_id),
            opentelemetry::KeyValue::new("outcome", outcome.as_str()),
            opentelemetry::KeyValue::new("billable", billable.as_str()),
        ],
    );
    // The divergence comparison is driven from here rather than from a
    // background timer. Every settled event reports a receipt, so this runs
    // once per metered attempt, which is exactly as often as there is
    // anything new to compare.
    maybe_sweep();
}

/// Count one record the meter owed and could not write.
fn record_meter_chain_gap(tenant_id: &str, failure_mode: FailurePosture) {
    let tenant_id = tenant(tenant_id);
    chain_gap_total()
        .with_label_values(&[tenant_id.as_str(), failure_mode.as_str()])
        .inc();
    otel_chain_gap().add(
        1,
        &[
            opentelemetry::KeyValue::new("tenant_id", tenant_id),
            opentelemetry::KeyValue::new("failure_mode", failure_mode.as_str()),
        ],
    );
}

/// Count one receipt refused on decode for contradicting itself.
///
/// Refusals, not distinct receipts: one bad entry in a chain file is
/// refused again on every read that reaches it. The condition is permanent
/// until somebody acts on it, so an alert that went quiet while the entry
/// was still there would be worse than one that keeps firing.
fn record_meter_incoherent_receipt(tenant_id: &str, failure_mode: FailurePosture) {
    let tenant_id = tenant(tenant_id);
    incoherent_receipts_total()
        .with_label_values(&[tenant_id.as_str(), failure_mode.as_str()])
        .inc();
    otel_incoherent_receipts().add(
        1,
        &[
            opentelemetry::KeyValue::new("tenant_id", tenant_id),
            opentelemetry::KeyValue::new("failure_mode", failure_mode.as_str()),
        ],
    );
}

/// Count one window in which a tenant's counter and chain disagreed.
fn record_meter_divergence(tenant_id: &str) {
    let tenant_id = tenant(tenant_id);
    divergence_total()
        .with_label_values(&[tenant_id.as_str()])
        .inc();
    otel_divergence().add(1, &[opentelemetry::KeyValue::new("tenant_id", tenant_id)]);
}

/// Publish the chain head on both surfaces.
fn set_meter_chain_seq(seq: u64) {
    // Saturating rather than wrapping. The `prometheus` integer gauge is
    // `i64`, and a chain long enough to overflow would otherwise report a
    // negative head, which reads as a corrupted chain rather than as an
    // implausibly long one.
    chain_seq().set(i64::try_from(seq).unwrap_or(i64::MAX));
    otel_chain_seq().record(seq, &[]);
}

/// Observe one append duration, and stamp a trace exemplar on it.
fn record_meter_append_duration(seconds: f64) {
    append_duration_seconds().observe(seconds);
    otel_append_duration().record(seconds, &[]);

    // The exemplar is the whole operator story: dashboard spike, to trace,
    // to `claim_id`, to the signed receipt. Empty ids when no trace context
    // is active, which the splicer renders as an ordinary bucket line
    // rather than as a broken one.
    let (trace_id, span_id) = current_trace_ids();
    crate::exemplars::record(
        "sbproxy_meter_append_duration_seconds",
        &[],
        seconds,
        STANDARD_LATENCY_BUCKETS,
        &trace_id,
        &span_id,
    );
}

/// Keep a tenant label bounded, and never empty.
fn tenant(tenant_id: &str) -> String {
    if tenant_id.is_empty() {
        return UNATTRIBUTED_TENANT.to_string();
    }
    sanitize_label("tenant_id", tenant_id)
}

// --- Divergence ---

/// How long counted units and chained units are allowed to disagree before
/// the disagreement is real.
///
/// One minute, comfortably longer than the default 30 second OTLP export
/// interval and the usual 15 second scrape. The window is not a tolerance
/// for sloppiness, it is the gap between "a receipt is being written right
/// now" and "a receipt was never written": units are counted when an event
/// settles and chained when its append lands, and those are two different
/// instants. Comparing them with no window would report every in-flight
/// receipt as a divergence.
const DIVERGENCE_WINDOW: Duration = Duration::from_secs(60);

/// Per-tenant totals for the two sides of the comparison.
#[derive(Default)]
struct Reconciliation {
    /// Units reported through the counter path since the last sweep.
    counted: HashMap<String, u64>,
    /// Units reported as having reached the chain since the last sweep.
    chained: HashMap<String, u64>,
    /// When the last comparison ran. `None` until the first observation, so
    /// a process that meters nothing never sweeps.
    last_sweep: Option<Instant>,
}

fn reconciliation() -> &'static Mutex<Reconciliation> {
    static STATE: OnceLock<Mutex<Reconciliation>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(Reconciliation::default()))
}

/// Add to the counter side of the comparison.
fn note_counted(tenant_id: &str, count: u64) {
    let mut state = reconciliation().lock().expect("meter reconciliation mutex");
    *state.counted.entry(tenant_id.to_string()).or_insert(0) += count;
    state.last_sweep.get_or_insert_with(Instant::now);
}

/// Add to the chain side of the comparison.
fn note_chained(tenant_id: &str, count: u64) {
    let tenant_id = tenant(tenant_id);
    let mut state = reconciliation().lock().expect("meter reconciliation mutex");
    *state.chained.entry(tenant_id).or_insert(0) += count;
    state.last_sweep.get_or_insert_with(Instant::now);
}

/// Run the comparison if the window has elapsed.
///
/// Traffic-driven rather than timer-driven, which is the right trade for
/// something that only has an answer when there is traffic: a process with
/// no metered requests has nothing to reconcile, and a background task
/// waking every minute to compare two empty maps is a thread nobody asked
/// for.
fn maybe_sweep() {
    let due = {
        let state = reconciliation().lock().expect("meter reconciliation mutex");
        state
            .last_sweep
            .is_some_and(|at| at.elapsed() >= DIVERGENCE_WINDOW)
    };
    if due {
        sweep();
    }
}

/// Compare both sides for every tenant seen since the last sweep, count a
/// divergence for each tenant that disagrees, and re-baseline.
///
/// Returns how many tenants diverged.
///
/// Re-baselining rather than carrying the imbalance forward is deliberate.
/// A tenant that lost one receipt lost one receipt; leaving the difference
/// in place would make that tenant diverge again on every window until
/// somebody restarted the process, turning one lost receipt into an alert
/// that never clears and therefore into an alert nobody reads.
fn sweep() -> usize {
    let mut state = reconciliation().lock().expect("meter reconciliation mutex");
    state.last_sweep = Some(Instant::now());

    let mut tenants: Vec<String> = state.counted.keys().cloned().collect();
    tenants.extend(state.chained.keys().cloned());
    tenants.sort_unstable();
    tenants.dedup();

    let diverged: Vec<String> = tenants
        .into_iter()
        .filter(|tenant_id| {
            state.counted.get(tenant_id).copied().unwrap_or(0)
                != state.chained.get(tenant_id).copied().unwrap_or(0)
        })
        .collect();

    state.counted.clear();
    state.chained.clear();
    // Released before recording. `record_meter_divergence` touches the
    // Prometheus registry and the OTel pipeline, and holding the
    // reconciliation lock across either would serialise the metering path
    // behind a metrics backend.
    drop(state);

    for tenant_id in &diverged {
        record_meter_divergence(tenant_id);
    }
    diverged.len()
}

// --- Installation ---

/// The observer the meter reports through.
///
/// A unit struct rather than a value with state: everything it needs is in
/// a process-global `OnceLock` already, and a `&'static dyn MeterObserver`
/// has to come from a `static` regardless.
#[derive(Debug)]
struct MeterMetrics;

static METER_METRICS: MeterMetrics = MeterMetrics;

impl MeterObserver for MeterMetrics {
    fn units(&self, tenant_id: &str, unit: &str, source: UnitSource, count: u64) {
        record_meter_units(tenant_id, unit, source, count);
    }

    fn receipt(&self, tenant_id: &str, outcome: BillableOutcome, billable: Billable) {
        record_meter_receipt(tenant_id, outcome, billable);
    }

    fn chained(&self, tenant_id: &str, units: u64) {
        note_chained(tenant_id, units);
    }

    fn chain_gap(&self, tenant_id: &str, failure_mode: FailurePosture) {
        record_meter_chain_gap(tenant_id, failure_mode);
    }

    fn incoherent_receipt(&self, tenant_id: &str, failure_mode: FailurePosture) {
        record_meter_incoherent_receipt(tenant_id, failure_mode);
    }

    fn chain_head(&self, seq: u64) {
        set_meter_chain_seq(seq);
    }

    fn append_duration(&self, seconds: f64) {
        record_meter_append_duration(seconds);
    }
}

/// Route the meter's self-observation into the `sbproxy_meter_*` families.
///
/// Call once at boot, before any config is compiled. Returns `false` when
/// an observer was already installed, which is not an error: the meter
/// refuses a second install rather than accepting one, so a repeated call
/// leaves exactly one live observer instead of double-counting every unit.
///
/// At boot rather than lazily on first use, because the first metered
/// request of a deployment is the one most likely to be the one somebody is
/// watching, and an observer installed on its way past would miss it.
pub fn install() -> bool {
    sbproxy_meter::metrics::set_observer(&METER_METRICS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_sdk::metrics::data::ResourceMetrics;
    use opentelemetry_sdk::metrics::reader::MetricReader;
    use opentelemetry_sdk::metrics::{
        InstrumentKind, ManualReader, MetricResult, Pipeline, SdkMeterProvider, Temporality,
    };
    use opentelemetry_sdk::Resource;
    use std::sync::{Arc, Weak};

    /// A `ManualReader` that can be handed to a provider and still read
    /// from afterwards.
    ///
    /// `SdkMeterProvider::builder().with_reader(..)` takes the reader by
    /// value, and the SDK's `ManualReader` is neither `Clone` nor
    /// implemented for `Arc`, so there is no way to keep a handle without a
    /// delegating wrapper. Every method forwards; the wrapper adds nothing
    /// but shared ownership.
    #[derive(Debug, Clone)]
    struct SharedReader(Arc<ManualReader>);

    impl MetricReader for SharedReader {
        fn register_pipeline(&self, pipeline: Weak<Pipeline>) {
            self.0.register_pipeline(pipeline);
        }
        fn collect(&self, rm: &mut ResourceMetrics) -> MetricResult<()> {
            self.0.collect(rm)
        }
        fn force_flush(&self) -> MetricResult<()> {
            self.0.force_flush()
        }
        fn shutdown(&self) -> MetricResult<()> {
            self.0.shutdown()
        }
        fn temporality(&self, kind: InstrumentKind) -> Temporality {
            self.0.temporality(kind)
        }
    }

    /// Force the comparison without waiting out [`DIVERGENCE_WINDOW`].
    ///
    /// Rewinds the clock the production path reads rather than calling
    /// [`sweep`] directly, so the test exercises the same
    /// `maybe_sweep` to `sweep` path that traffic does. On a monotonic
    /// clock younger than the window (possible only in the first minutes
    /// after boot) there is nothing to rewind, so it goes straight to the
    /// comparison the windowed path would have reached.
    fn force_sweep() {
        match Instant::now().checked_sub(DIVERGENCE_WINDOW * 2) {
            Some(past) => {
                let mut state = reconciliation().lock().expect("meter reconciliation mutex");
                state.last_sweep = Some(past);
                drop(state);
                maybe_sweep();
            }
            None => {
                sweep();
            }
        }
    }

    fn divergence_count(tenant_id: &str) -> u64 {
        divergence_total().with_label_values(&[tenant_id]).get()
    }

    #[test]
    fn a_unit_recorded_outside_the_chain_moves_the_divergence_counter() {
        let before = divergence_count("acme");

        // Counted, never chained: exactly the shape of a receipt that was
        // resolved and then dropped on its way to the ledger.
        record_meter_units("acme", "api_call", UnitSource::RouteWeight, 3);

        // Inside the window nothing is claimed yet, because an append in
        // flight is not a gap.
        maybe_sweep();
        assert_eq!(
            divergence_count("acme"),
            before,
            "an in-flight receipt must not be reported as a divergence"
        );

        force_sweep();
        assert_eq!(
            divergence_count("acme"),
            before + 1,
            "counted units that never reached the chain are a divergence"
        );
    }

    #[test]
    fn counted_units_that_reach_the_chain_do_not_diverge() {
        let before = divergence_count("globex");

        record_meter_units("globex", "api_call", UnitSource::Measured, 5);
        note_chained("globex", 5);

        force_sweep();
        assert_eq!(
            divergence_count("globex"),
            before,
            "a balanced tenant must stay quiet"
        );
    }

    #[test]
    fn a_divergence_is_reported_once_rather_than_on_every_window_after() {
        let before = divergence_count("initech");

        record_meter_units("initech", "api_call", UnitSource::OriginHeader, 2);
        force_sweep();
        let after_first = divergence_count("initech");
        assert_eq!(after_first, before + 1);

        // The sweep re-baselined, so one lost receipt must not keep firing
        // an alert nobody can clear.
        force_sweep();
        assert_eq!(divergence_count("initech"), after_first);
    }

    #[test]
    fn every_family_reaches_the_prometheus_scrape() {
        record_meter_units("scrape-tenant", "api_call", UnitSource::Measured, 1);
        record_meter_receipt("scrape-tenant", BillableOutcome::Delivered, Billable::Yes);
        record_meter_chain_gap("scrape-tenant", FailurePosture::Degraded);
        record_meter_incoherent_receipt("scrape-tenant", FailurePosture::Closed);
        record_meter_divergence("scrape-tenant");
        set_meter_chain_seq(41);
        record_meter_append_duration(0.002);

        let rendered = metrics().render();
        for family in [
            "sbproxy_meter_units_total",
            "sbproxy_meter_receipts_total",
            "sbproxy_meter_chain_gap_total",
            "sbproxy_meter_incoherent_receipts_total",
            "sbproxy_meter_divergence_total",
            "sbproxy_meter_chain_seq",
            "sbproxy_meter_append_duration_seconds",
        ] {
            assert!(
                rendered.contains(family),
                "{family} is missing from the Prometheus scrape"
            );
        }
        assert!(
            rendered.contains("tenant_id=\"scrape-tenant\""),
            "the tenant dimension has to survive the scrape"
        );
        // Route is deliberately not a label anywhere in this namespace.
        for line in rendered.lines().filter(|l| l.contains("sbproxy_meter_")) {
            assert!(
                !line.contains("route="),
                "route must stay off every meter label set: {line}"
            );
        }
    }

    #[test]
    fn the_append_histogram_carries_a_trace_exemplar() {
        // A smaller value recorded by a sibling test earlier in this same
        // process can leave a stale exemplar in a lower bucket that this
        // recording never touches (buckets are cumulative), which
        // `last_recorded_for_test` would then return instead of the 0.004
        // recorded below. Clear first so this assertion holds regardless
        // of what ran before it in the shared process (WOR-2298).
        crate::exemplars::reset_store_for_test();
        record_meter_append_duration(0.004);

        let recorded =
            crate::exemplars::last_recorded_for_test("sbproxy_meter_append_duration_seconds", &[]);
        let exemplar = recorded.expect("the append histogram is in the exemplar allow-list");
        assert!((exemplar.value - 0.004).abs() < f64::EPSILON);

        // And the splicer recognises the family, which is the half that
        // needs the name in `leak_metric_base` rather than only in the
        // allow-list.
        let line = "sbproxy_meter_append_duration_seconds_bucket{le=\"0.005\"} 1\n";
        let spliced = crate::exemplars::splice_into_text(line);
        assert!(
            spliced.contains("# {"),
            "the splicer must attach the exemplar it recorded: {spliced}"
        );
    }

    #[test]
    fn every_family_reaches_the_otlp_push_path() {
        // A real SDK meter provider, so the instruments below bind to
        // something that aggregates rather than to the global no-op meter.
        // A `PeriodicReader` would need a runtime and a live collector; a
        // manual reader is the same pipeline with the timer taken out.
        //
        // Under nextest this test gets a process to itself, so the
        // instrument handles below always bind fresh. Plain `cargo test`
        // (the release-checks single-threaded lane) runs every test in
        // this file in one process instead, so a sibling test that
        // recorded first would have already bound them to the no-op
        // meter; reset after installing the new provider so the record
        // calls below rebuild against it instead (WOR-2298).
        let reader = SharedReader(Arc::new(ManualReader::builder().build()));
        let provider = SdkMeterProvider::builder()
            .with_reader(reader.clone())
            .build();
        global::set_meter_provider(provider);
        reset_otel_instruments_for_test();

        record_meter_units("otlp-tenant", "api_call", UnitSource::Measured, 7);
        record_meter_receipt("otlp-tenant", BillableOutcome::CacheHit, Billable::No);
        record_meter_chain_gap("otlp-tenant", FailurePosture::Open);
        record_meter_incoherent_receipt("otlp-tenant", FailurePosture::Closed);
        record_meter_divergence("otlp-tenant");
        set_meter_chain_seq(9);
        record_meter_append_duration(0.001);

        let mut collected = ResourceMetrics {
            resource: Resource::default(),
            scope_metrics: Vec::new(),
        };
        reader
            .collect(&mut collected)
            .expect("the manual reader collects from its provider");

        let names: Vec<String> = collected
            .scope_metrics
            .iter()
            .flat_map(|scope| scope.metrics.iter())
            .map(|metric| metric.name.to_string())
            .collect();

        for instrument in [
            "sbproxy.meter.units",
            "sbproxy.meter.receipts",
            "sbproxy.meter.chain_gap",
            "sbproxy.meter.incoherent_receipts",
            "sbproxy.meter.divergence",
            "sbproxy.meter.chain_seq",
            "sbproxy.meter.append.duration",
        ] {
            assert!(
                names.iter().any(|name| name == instrument),
                "{instrument} never reached the push path; collected {names:?}"
            );
        }
    }

    #[test]
    fn a_zero_count_unit_emits_no_series() {
        let before = units_total()
            .with_label_values(&["zero-tenant", "api_call", "measured"])
            .get();
        record_meter_units("zero-tenant", "api_call", UnitSource::Measured, 0);
        assert_eq!(
            units_total()
                .with_label_values(&["zero-tenant", "api_call", "measured"])
                .get(),
            before,
            "a resolver that found nothing is not a billable quantity"
        );
    }

    #[test]
    fn an_unattributed_gap_gets_a_selectable_label_rather_than_an_empty_one() {
        record_meter_chain_gap("", FailurePosture::Degraded);
        let gaps = chain_gap_total().with_label_values(&[UNATTRIBUTED_TENANT, "degraded"]);
        assert!(
            gaps.get() > 0,
            "an unattributable gap still has to be findable"
        );
    }

    #[test]
    fn installing_the_observer_is_idempotent() {
        let first = install();
        let second = install();
        assert!(
            !(first && second),
            "a second install must not create a second live observer"
        );
    }
}

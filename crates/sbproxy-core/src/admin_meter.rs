// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The meter's operator surface: what was metered, what the report
//! covers, and whether the chain still verifies (WOR-2131).
//!
//! Three routes, all behind the operator gate the rest of the admin
//! surface sits behind:
//!
//! | Route | Method | Answers |
//! | --- | --- | --- |
//! | `/api/meter/summary` | GET | Units by tenant, unit, and provenance, beside the mesh coverage this total was assembled from |
//! | `/api/meter/receipts` | GET | A cursor-paged window on this node's chain |
//! | `/api/meter/verify` | POST | Whether the chain still verifies, and the first sequence number where it does not |
//!
//! # Zero and off are different answers
//!
//! The one thing this surface has to get right is the empty case. A page
//! that renders zeros looks the same whether the operator switched
//! attestation off, switched it on and has served no billable traffic
//! yet, or switched it on and has a meter that silently stopped writing.
//! Those are three different situations with three different next steps,
//! and a dashboard that renders all three as `0` is the reason nobody
//! finds out about the third one for a quarter.
//!
//! So every response carries a `state` before it carries a number:
//!
//! - `off`: `proxy.attestation` is absent or its role is `off`. There is
//!   no chain, and the zeros are not a measurement.
//! - `idle`: attestation is configured and nothing has been recorded. The
//!   chain file may not exist yet. The zeros are a real reading of an
//!   empty chain.
//! - `reporting`: at least one entry exists, so the numbers describe
//!   traffic.
//!
//! Nothing here manufactures a sample to fill the page out. As of this
//! slice no production code opens the configured ledger or constructs a
//! receipt, so a correctly configured proxy serving real traffic still
//! reports `idle`, and that is the honest answer: the operator asked for
//! receipts and is not getting them.
//!
//! # A total says what it covers
//!
//! `/api/meter/summary` never quotes a cluster figure without the
//! coverage block that says which nodes are inside it. When a mesh is
//! configured the gather runs through
//! `sbproxy_core::meter_cluster::ClusterMeterView`, which keeps an
//! unreachable node in the report with the last chain head it was ever
//! seen at rather than dropping it or counting it as zero. When no mesh
//! is configured there is exactly one chain, this node's own, so
//! `coverage` is `null` rather than a block claiming a fan-out that never
//! happened.
//!
//! # Tenant scope comes from the operator, not the query string
//!
//! A receipt names one buyer's traffic, so reading somebody else's is a
//! disclosure rather than a reporting mistake. An operator configured
//! with `proxy.admin.operators[].tenant` is narrowed to that tenant on
//! all three routes: an absent `tenant=` parameter resolves to their own,
//! and a `tenant=` naming anybody else is refused with `403` rather than
//! quietly filtered, because silently returning a different tenant's
//! empty result reads as "that tenant used nothing".
//!
//! Chain-level facts are deliberately outside that boundary: sequence
//! numbers, head digests, per-node claim counts, and the verify verdict
//! are emitted to every operator, because they name no tenant and a
//! stalled meter is everybody's problem. Unit totals and receipts are
//! inside it, and are filtered at the source rather than at the edge.
//!
//! Verification is a `POST` even though it writes nothing, because it
//! walks the whole chain file and is an action an operator takes rather
//! than a panel that refreshes. The admin connection handler's RBAC gate
//! consequently restricts it to the admin role, the same way it restricts
//! the alert channel probe. A read-only operator sees every figure on the
//! page and cannot start a verification run.
//!
//! # Why the parameters are spelled the way `/api/usage/spend` spells them
//!
//! `group_by` carries the same meaning and the same error shape as it
//! does on the spend route, so an operator who has used one has used the
//! other. `window` is accepted as a name and refused as a request: a
//! chain segment carries a cumulative total with no time index, so there
//! is no honest way to answer a windowed question from it, and answering
//! it approximately would produce a figure nobody could reproduce from
//! the chain.
//!
//! Grouping selects the key rows are keyed and ordered by. It never folds
//! two provenances into one number: that fold is exactly what
//! `sbproxy_meter` exists to refuse, and undoing it at the point an
//! operator looks at the figures would defeat the whole design.

use std::collections::{BTreeMap, BTreeSet};
use std::io::BufRead;
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use sbproxy_meter::coverage::ClusterUsageSummary;
use sbproxy_meter::ledger::{verify_ledger, LedgerEntry, LedgerPayload};
use sbproxy_meter::segment::ChainSegment;
use sbproxy_modules::policy::receipt_token::ReceiptClaims;
use serde::{Deserialize, Serialize};

use crate::admin::AdminPrincipal;
use crate::meter_cluster::ClusterMeterView;

/// Cluster-wide unit and coverage report.
const SUMMARY_PATH: &str = "/api/meter/summary";
/// Cursor-paged window on this node's receipt chain.
const RECEIPTS_PATH: &str = "/api/meter/receipts";
/// Chain re-verification.
const VERIFY_PATH: &str = "/api/meter/verify";

/// Content type on every response here.
const JSON: &str = "application/json";

/// Status code, content type, body.
type Resp = (u16, &'static str, String);

/// Wire version of every document this module emits.
///
/// One number across all three routes rather than one each: they are read
/// together by one page, and a consumer that can parse the summary can
/// parse the receipts.
const SCHEMA_VERSION: u32 = 1;

/// Receipts returned when the caller does not ask for a page size.
const DEFAULT_RECEIPT_LIMIT: usize = 50;

/// Largest page a single receipts request may claim.
///
/// A bound on the response rather than on the chain: the chain is a
/// JSONL file with no index, so a page is a walk from the front, and an
/// unbounded page would let one admin request read an arbitrarily large
/// file into memory.
const MAX_RECEIPT_LIMIT: usize = 500;

/// How old a peer's published segment may be and still count toward the
/// total.
///
/// Peers republish on their own cadence, so this is a freshness bound
/// rather than a timeout. A record older than this is reported as a
/// coverage gap with its last known head instead of being summed, because
/// a reading from twenty minutes ago describes traffic up to that point
/// and nothing since.
const MAX_SEGMENT_AGE: Duration = Duration::from_secs(90);

/// The metric family carrying records the meter owed and could not write.
const CHAIN_GAP_FAMILY: &str = "sbproxy_meter_chain_gap_total";

/// The metric family carrying counted-versus-chained disagreement.
const DIVERGENCE_FAMILY: &str = "sbproxy_meter_divergence_total";

// --- State ---

/// What the meter can currently say about itself.
///
/// The distinction the whole surface is built around; see the module
/// documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MeterState {
    /// `proxy.attestation` is absent, or its role is `off`.
    Off,
    /// Attestation is configured and has recorded nothing.
    Idle,
    /// At least one chain entry exists.
    Reporting,
}

impl MeterState {
    /// Stable snake-case name, as it appears on the wire.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Idle => "idle",
            Self::Reporting => "reporting",
        }
    }

    /// One sentence an operator can act on, for the two states where a
    /// zero is not a measurement.
    const fn reason(self) -> Option<&'static str> {
        match self {
            Self::Off => Some(
                "proxy.attestation is not configured on this node, so nothing is being metered \
                 and these figures are not a reading",
            ),
            Self::Idle => Some(
                "attestation is configured and no receipt has been recorded yet, so the chain \
                 is empty rather than the traffic being zero",
            ),
            Self::Reporting => None,
        }
    }
}

// --- Grouping ---

/// The key summary rows are keyed and ordered by.
///
/// Presentation only. See the module documentation for why grouping never
/// folds two provenances together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GroupBy {
    /// The billing account a row is charged to.
    Tenant,
    /// The unit name that appears on the invoice line.
    Unit,
    /// Which mechanism produced the count.
    Source,
    /// Every row under one key.
    Total,
}

impl GroupBy {
    /// Parse the `group_by=` value, or `None` when it names no dimension.
    fn parse(value: &str) -> Option<Self> {
        match value {
            "tenant" => Some(Self::Tenant),
            "unit" => Some(Self::Unit),
            "source" => Some(Self::Source),
            "total" => Some(Self::Total),
            _ => None,
        }
    }

    /// Stable snake-case name, echoed back on every response.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Tenant => "tenant",
            Self::Unit => "unit",
            Self::Source => "source",
            Self::Total => "total",
        }
    }

    /// The key one row falls under.
    fn key(self, row: &UnitRow) -> String {
        match self {
            Self::Tenant => row.tenant.clone(),
            Self::Unit => row.unit.clone(),
            Self::Source => row.source.clone(),
            Self::Total => "total".to_string(),
        }
    }
}

// --- Chain payload ---

/// The document one receipt-chain entry attests to, as this view reads it.
///
/// A transparent newtype rather than an implementation of
/// `sbproxy_meter::ledger::LedgerPayload` on `ReceiptClaims` itself: the
/// claims type belongs to `sbproxy-modules`, the trait to `sbproxy-meter`,
/// and deciding on their behalf what a receipt's dedup key is would be
/// this crate legislating for two others. `serde(transparent)` means the
/// bytes on disk are `ReceiptClaims`' own bytes, which is what the
/// re-serialize check in `sbproxy_meter::ledger::verify_ledger` compares
/// against, so reading through this wrapper cannot change a verdict.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
struct ChainedReceipt(ReceiptClaims);

impl LedgerPayload for ChainedReceipt {
    /// The claim id, which every attempt at one unit of work shares.
    ///
    /// The same key the chain would dedup on when writing, so a page read
    /// back through this type folds retries the way the writer did.
    fn dedup_key(&self) -> Option<&str> {
        Some(self.0.claim_id.as_str())
    }
}

// --- Chain reading ---

/// One line of a unit total, with provenance kept apart from the count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct UnitRow {
    /// The key this row is grouped under, per `group_by`.
    group: String,
    /// The billing account the units are charged to.
    tenant: String,
    /// Operator-chosen unit name, as it appears on the invoice line.
    unit: String,
    /// Which mechanism produced the count, snake-case.
    source: String,
    /// How many of the unit were metered.
    count: u64,
}

/// What a full walk of one chain file found.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ChainReplay {
    /// Whether the ledger file exists at all. `false` is the normal state
    /// of a freshly configured node and is not an error.
    present: bool,
    /// Entries read, which is also the sequence the next entry takes.
    entries: u64,
    /// Digest of the most recent entry, or the genesis digest.
    head_hash: String,
    /// Distinct claims folded, counting a retry once.
    claims: u64,
    /// `(tenant, unit, source)` to the count metered under it, already
    /// narrowed to the caller's tenant scope.
    totals: BTreeMap<(String, String, String), u64>,
    /// Sequence number the replay stopped at, when a line would not parse.
    damaged_at_seq: Option<u64>,
    /// Why it stopped.
    damage_reason: Option<String>,
}

/// The genesis digest a chain starts from, mirrored here because
/// `sbproxy-meter` keeps its own copy private and a replay has to report
/// a head for an empty file.
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Walk a chain file end to end, folding units for `scope`.
///
/// Tolerant in the same way `sbproxy_meter::ledger::verify_ledger` is: a
/// line that will not parse stops the walk and is reported as damage
/// rather than raising, because an operator looking at this page wants to
/// know where the chain stopped being readable.
///
/// A missing file yields `present: false` and an empty replay, which is
/// what a configured node that has not written a receipt looks like.
fn replay_chain(path: &Path, scope: Option<&str>) -> ChainReplay {
    let mut replay = ChainReplay {
        head_hash: GENESIS_HASH.to_string(),
        ..ChainReplay::default()
    };
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return replay,
        Err(error) => {
            replay.damage_reason = Some(format!("cannot read the chain: {error}"));
            return replay;
        }
    };
    replay.present = true;
    let mut folded: BTreeSet<String> = BTreeSet::new();
    for line in std::io::BufReader::new(file).lines() {
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                replay.damaged_at_seq = Some(replay.entries);
                replay.damage_reason = Some(format!("cannot read the chain: {error}"));
                return replay;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let entry: LedgerEntry<ChainedReceipt> = match serde_json::from_str(&line) {
            Ok(entry) => entry,
            Err(error) => {
                replay.damaged_at_seq = Some(replay.entries);
                replay.damage_reason = Some(format!("unreadable entry: {error}"));
                return replay;
            }
        };
        // Chain facts advance whoever the entry belongs to. A scoped
        // operator still gets a truthful chain length, because a head that
        // moved only for other tenants is still a head that moved.
        replay.entries = replay.entries.saturating_add(1);
        replay.head_hash = entry.entry_hash;
        let claims = &entry.event.0;
        if !folded.insert(claims.claim_id.clone()) {
            continue;
        }
        replay.claims = replay.claims.saturating_add(1);
        if !tenant_in_scope(&claims.subject.tenant, scope) {
            continue;
        }
        for unit in &claims.units {
            let key = (
                claims.subject.tenant.clone(),
                unit.name.clone(),
                unit.source.clone(),
            );
            let slot = replay.totals.entry(key).or_insert(0);
            // Saturating rather than wrapping: a total that wraps to nearly
            // zero reads as a quiet month rather than as an overflow.
            *slot = slot.saturating_add(unit.count);
        }
    }
    replay
}

/// One receipt as the drill-down reads it: the chain link, then the
/// document the link attests to.
#[derive(Debug, Clone, Serialize)]
struct ReceiptRow {
    /// Zero-based position in this node's chain.
    seq: u64,
    /// RFC 3339 timestamp the entry was recorded at.
    recorded_at: String,
    /// Digest of the preceding entry.
    prev_hash: String,
    /// Digest of this entry.
    entry_hash: String,
    /// Hex Ed25519 signature over the entry digest, when the chain is
    /// signed. Absent on an unsigned chain, which is what the
    /// `proxy.attestation.ledger` block configures today.
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    /// The receipt itself, in the field order its signature covers.
    claims: ReceiptClaims,
}

/// One page of a chain, and where the next one starts.
#[derive(Debug, Default, Clone)]
struct ChainPage {
    /// Whether the ledger file exists at all.
    present: bool,
    /// Receipts in this page, oldest first.
    receipts: Vec<ReceiptRow>,
    /// Sequence number to pass as `since_seq` for the next page, or
    /// `None` when this page reached the end of the chain.
    next_since_seq: Option<u64>,
    /// Sequence number the walk stopped at, when a line would not parse.
    damaged_at_seq: Option<u64>,
    /// Why it stopped.
    damage_reason: Option<String>,
}

/// Read one page of a chain, from `since_seq`, narrowed to `scope`.
///
/// Walks from the front of the file every time. The chain is append-only
/// JSONL with no index, so there is nowhere to seek to; paging is a bound
/// on the response rather than on the work, and that is worth knowing
/// before pointing this at a chain with millions of entries.
fn read_page(path: &Path, scope: Option<&str>, since_seq: u64, limit: usize) -> ChainPage {
    let mut page = ChainPage::default();
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return page,
        Err(error) => {
            page.damage_reason = Some(format!("cannot read the chain: {error}"));
            return page;
        }
    };
    page.present = true;
    let mut seen = 0u64;
    for line in std::io::BufReader::new(file).lines() {
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                page.damaged_at_seq = Some(seen);
                page.damage_reason = Some(format!("cannot read the chain: {error}"));
                return page;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let entry: LedgerEntry<ChainedReceipt> = match serde_json::from_str(&line) {
            Ok(entry) => entry,
            Err(error) => {
                page.damaged_at_seq = Some(seen);
                page.damage_reason = Some(format!("unreadable entry: {error}"));
                return page;
            }
        };
        seen = seen.saturating_add(1);
        if entry.seq < since_seq {
            continue;
        }
        let claims = entry.event.0;
        if !tenant_in_scope(&claims.subject.tenant, scope) {
            continue;
        }
        if page.receipts.len() == limit {
            // One past the page: the cursor an operator resumes from,
            // rather than a count they have to add to `since_seq`
            // themselves and get wrong on a chain with gaps.
            page.next_since_seq = Some(entry.seq);
            return page;
        }
        page.receipts.push(ReceiptRow {
            seq: entry.seq,
            recorded_at: entry.recorded_at,
            prev_hash: entry.prev_hash,
            entry_hash: entry.entry_hash,
            signature: entry.signature,
            claims,
        });
    }
    page
}

/// Whether a receipt's tenant survives the caller's scope.
fn tenant_in_scope(tenant: &str, scope: Option<&str>) -> bool {
    scope.is_none_or(|scoped| scoped == tenant)
}

// --- Tenant scope ---

/// Narrow a requested tenant against what this operator may read.
///
/// Refusing a cross-tenant request rather than filtering it to nothing is
/// the point: an empty result for a tenant the caller may not see reads as
/// "that tenant consumed nothing", which is a worse answer than a refusal
/// because somebody will believe it.
fn scope_for(
    principal: Option<&AdminPrincipal>,
    requested: Option<&str>,
) -> Result<Option<String>, Resp> {
    let Some(principal) = principal else {
        return Err((
            401,
            JSON,
            r#"{"error":"authentication required"}"#.to_string(),
        ));
    };
    let requested = requested.map(str::trim).filter(|value| !value.is_empty());
    match (principal.tenant.as_deref(), requested) {
        (None, asked) => Ok(asked.map(str::to_string)),
        (Some(scoped), None) => Ok(Some(scoped.to_string())),
        (Some(scoped), Some(asked)) if asked == scoped => Ok(Some(scoped.to_string())),
        (Some(scoped), Some(_)) => Err((
            403,
            JSON,
            serde_json::json!({
                "error": format!(
                    "forbidden: this operator may read metered consumption for tenant `{scoped}` only"
                ),
            })
            .to_string(),
        )),
    }
}

// --- Gap markers ---

/// One `sbproxy_meter_chain_gap_total` sample: a record the meter owed and
/// could not write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct GapRow {
    /// The billing account the unwritten record belonged to.
    tenant: String,
    /// The posture in force when the write failed, snake-case. `degraded`
    /// is the one that means the request was served and the guarantee was
    /// marked as not made.
    failure_mode: String,
    /// How many records were owed and not written.
    count: u64,
}

/// One parsed exposition line: its label set, and its value.
type LabelledSample = (BTreeMap<String, String>, f64);

/// Pull the labelled samples of one counter family out of a Prometheus
/// exposition.
///
/// A text scan rather than a registry query because the metrics surface
/// exposes a per-family total and no labelled accessor, and folding every
/// tenant's gaps into one number would put another tenant's figure inside
/// a scoped operator's response. Label values are already passed through
/// `sbproxy_observe::metrics::sanitize_label`, so they carry neither
/// quotes nor commas and a split on those characters is safe here.
fn labelled_samples(exposition: &str, family: &str) -> Vec<LabelledSample> {
    let mut out = Vec::new();
    for line in exposition.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some(rest) = line.strip_prefix(family) else {
            continue;
        };
        let (labels, value) = match rest.strip_prefix('{') {
            Some(with_labels) => match with_labels.split_once('}') {
                Some((labels, value)) => (labels, value),
                None => continue,
            },
            None => {
                if !rest.starts_with(' ') {
                    // A longer family name that merely starts with this
                    // one, for example `_total` against `_total_bytes`.
                    continue;
                }
                ("", rest)
            }
        };
        let Some(value) = value.split_whitespace().next() else {
            continue;
        };
        let Ok(value) = value.parse::<f64>() else {
            continue;
        };
        let mut parsed = BTreeMap::new();
        for pair in labels.split(',').filter(|pair| !pair.trim().is_empty()) {
            if let Some((name, raw)) = pair.split_once('=') {
                parsed.insert(
                    name.trim().to_string(),
                    raw.trim().trim_matches('"').to_string(),
                );
            }
        }
        out.push((parsed, value));
    }
    out
}

/// Every gap the meter has reported, narrowed to `scope`.
fn gap_rows(exposition: &str, scope: Option<&str>) -> Vec<GapRow> {
    let mut folded: BTreeMap<(String, String), u64> = BTreeMap::new();
    for (labels, value) in labelled_samples(exposition, CHAIN_GAP_FAMILY) {
        let tenant = labels
            .get("tenant_id")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        if !tenant_in_scope(&tenant, scope) {
            continue;
        }
        let failure_mode = labels
            .get("failure_mode")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        let slot = folded.entry((tenant, failure_mode)).or_insert(0);
        *slot = slot.saturating_add(value.max(0.0) as u64);
    }
    folded
        .into_iter()
        .map(|((tenant, failure_mode), count)| GapRow {
            tenant,
            failure_mode,
            count,
        })
        .collect()
}

/// Counted-versus-chained disagreement, narrowed to `scope`.
fn divergence_total(exposition: &str, scope: Option<&str>) -> u64 {
    labelled_samples(exposition, DIVERGENCE_FAMILY)
        .into_iter()
        .filter(|(labels, _)| {
            tenant_in_scope(
                labels.get("tenant_id").map(String::as_str).unwrap_or(""),
                scope,
            )
        })
        .fold(0u64, |running, (_, value)| {
            running.saturating_add(value.max(0.0) as u64)
        })
}

// --- Process state ---

/// The process-wide cluster meter view.
///
/// One per process, because the memory inside it is the feature: its
/// `LastKnownHeads` never evicts, so a node that answered an earlier
/// gather and has since died still reports the head it was last seen at.
/// A view constructed per request would forget exactly the node an
/// operator opened this page to ask about.
fn cluster_view() -> &'static Arc<ClusterMeterView> {
    static VIEW: OnceLock<Arc<ClusterMeterView>> = OnceLock::new();
    VIEW.get_or_init(|| Arc::new(ClusterMeterView::new()))
}

/// The id this node's chain is attributed to.
///
/// The mesh node id when a mesh is configured, because that is the key a
/// gather files segments under. Otherwise the per-process instance id,
/// which is not a mesh identity and is not treated as one: with no mesh
/// there is one chain and nothing to attribute it against.
fn local_node_id(handle: Option<&sbproxy_mesh::ClusterHandle>) -> String {
    match handle {
        Some(handle) => handle.identity().node_id.clone(),
        None => crate::identity::instance_id().to_string(),
    }
}

// --- Routes ---

/// Handle the meter admin routes, or return `None` to fall through.
///
/// `principal` carries the tenant scope; a `None` principal is refused
/// rather than treated as unscoped, so a dispatch added before the auth
/// gate cannot open the surface by accident.
pub async fn dispatch(
    method: &str,
    path: &str,
    principal: Option<&AdminPrincipal>,
) -> Option<Resp> {
    let path_only = path.split('?').next().unwrap_or(path);
    match path_only {
        SUMMARY_PATH => {
            if !method.eq_ignore_ascii_case("GET") {
                return Some(method_not_allowed("GET"));
            }
            Some(summary_response(path, principal).await)
        }
        RECEIPTS_PATH => {
            if !method.eq_ignore_ascii_case("GET") {
                return Some(method_not_allowed("GET"));
            }
            Some(receipts_response(path, principal))
        }
        VERIFY_PATH => {
            if !method.eq_ignore_ascii_case("POST") {
                return Some(method_not_allowed("POST"));
            }
            Some(verify_response(path, principal))
        }
        _ => None,
    }
}

/// The cluster-wide report: units, coverage, chain heads, and gaps.
async fn summary_response(path: &str, principal: Option<&AdminPrincipal>) -> Resp {
    let scope = match scope_for(principal, decoded_query_param(path, "tenant").as_deref()) {
        Ok(scope) => scope,
        Err(response) => return response,
    };
    if query_param(path, "window").is_some() {
        return (
            400,
            JSON,
            r#"{"error":"window is not supported here: a chain segment carries a cumulative total with no time index, so a windowed figure could not be reproduced from the chain"}"#
                .to_string(),
        );
    }
    let group_by = match decoded_query_param(path, "group_by") {
        None => GroupBy::Tenant,
        Some(raw) => match GroupBy::parse(&raw) {
            Some(group_by) => group_by,
            None => {
                return (
                    400,
                    JSON,
                    r#"{"error":"unknown group_by (tenant|unit|source|total)"}"#.to_string(),
                )
            }
        },
    };

    // An owned handle on the attestation runtime rather than a borrow out
    // of the pipeline guard: the gather below is awaited, and a future that
    // holds a borrow of the live pipeline across an await pins a generation
    // a reload is trying to retire.
    let attestation = crate::reload::current_pipeline_full().attestation.clone();
    let handle = crate::cluster::current_cluster_handle();
    let node_id = local_node_id(handle.as_ref());
    let gathered_at = chrono::Utc::now().to_rfc3339();
    let exposition = sbproxy_observe::metrics::metrics().render();
    let gaps = gap_rows(&exposition, scope.as_deref());
    let gap_total = gaps
        .iter()
        .fold(0u64, |running, row| running.saturating_add(row.count));

    let Some(attestation) = attestation else {
        return json(
            200,
            serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "state": MeterState::Off.as_str(),
                "reason": MeterState::Off.reason(),
                "group_by": group_by.as_str(),
                "tenant": scope,
                "gathered_at": gathered_at,
                "attestation": { "configured": false },
                "chain": serde_json::Value::Null,
                "coverage": serde_json::Value::Null,
                "nodes": Vec::<serde_json::Value>::new(),
                "totals": Vec::<UnitRow>::new(),
                "claims": 0,
                "gaps": {
                    "total": gap_total,
                    "by_tenant": gaps,
                    "divergence_total": divergence_total(&exposition, scope.as_deref()),
                },
            }),
        );
    };

    let replay = replay_chain(&attestation.ledger_path, scope.as_deref());
    let local = ChainSegment {
        node_id: node_id.clone(),
        head_seq: replay.entries,
        head_hash: replay.head_hash.clone(),
        claims: replay.claims,
        totals: Vec::new(),
        observed_at: gathered_at.clone(),
    };

    // Peers contribute coverage and chain heads. Their unit totals are
    // read through the same tenant filter this node's own chain went
    // through, so a scoped operator never sees a row they may not read.
    let summary: Option<ClusterUsageSummary> = match handle.as_ref() {
        Some(handle) => Some(
            cluster_view()
                .gather(handle, Some(local.clone()), MAX_SEGMENT_AGE)
                .await,
        ),
        None => None,
    };

    let mut totals: BTreeMap<(String, String, String), u64> = replay.totals.clone();
    let mut nodes: Vec<serde_json::Value> = Vec::new();
    let mut claims = replay.claims;

    match summary.as_ref() {
        Some(summary) => {
            claims = summary.claims();
            for segment in &summary.segments {
                if segment.node_id != node_id {
                    for total in &segment.totals {
                        if !tenant_in_scope(&total.tenant, scope.as_deref()) {
                            continue;
                        }
                        let key = (
                            total.tenant.clone(),
                            total.unit.clone(),
                            total.source.as_str().to_string(),
                        );
                        let slot = totals.entry(key).or_insert(0);
                        *slot = slot.saturating_add(total.count);
                    }
                }
                nodes.push(serde_json::json!({
                    "node_id": segment.node_id,
                    "covered": true,
                    "head_seq": segment.head_seq,
                    "head_hash": segment.head_hash,
                    "claims": segment.claims,
                    "observed_at": segment.observed_at,
                    "local": segment.node_id == node_id,
                }));
            }
            for missing in &summary.coverage.uncovered {
                nodes.push(serde_json::json!({
                    "node_id": missing.node_id,
                    "covered": false,
                    "gap": missing.gap.as_str(),
                    "last_known_seq": missing.last_known_seq,
                    "last_seen_at": missing.last_seen_at,
                    "local": missing.node_id == node_id,
                }));
            }
        }
        None => nodes.push(serde_json::json!({
            "node_id": node_id,
            "covered": true,
            "head_seq": local.head_seq,
            "head_hash": local.head_hash,
            "claims": local.claims,
            "observed_at": local.observed_at,
            "local": true,
        })),
    }

    let chain_entries = match summary.as_ref() {
        Some(summary) => summary
            .segments
            .iter()
            .fold(0u64, |running, segment| {
                running.saturating_add(segment.head_seq)
            })
            .max(replay.entries),
        None => replay.entries,
    };
    let state = if chain_entries == 0 && claims == 0 {
        MeterState::Idle
    } else {
        MeterState::Reporting
    };

    let rows = unit_rows(&totals, group_by);
    let coverage = summary.as_ref().map(|summary| {
        serde_json::json!({
            "complete": summary.coverage.is_complete(),
            "expected": summary.coverage.expected(),
            "answered": summary.coverage.answered,
            "uncovered": summary.coverage.uncovered,
            "gathered_at": summary.gathered_at,
        })
    });

    json(
        200,
        serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "state": state.as_str(),
            "reason": state.reason(),
            "group_by": group_by.as_str(),
            "tenant": scope,
            "gathered_at": gathered_at,
            "attestation": {
                "configured": true,
                "role": attestation.role,
                "failure_mode": attestation.failure_mode,
                "signing_key_id": attestation.signing_key_id,
                "ledger_path": attestation.ledger_path.display().to_string(),
            },
            "chain": {
                "node_id": node_id,
                "present": replay.present,
                "entries": replay.entries,
                "head_hash": replay.head_hash,
                "damaged_at_seq": replay.damaged_at_seq,
                "damage_reason": replay.damage_reason,
            },
            "coverage": coverage,
            "nodes": nodes,
            "totals": rows,
            "claims": claims,
            "gaps": {
                "total": gap_total,
                "by_tenant": gaps,
                "divergence_total": divergence_total(&exposition, scope.as_deref()),
            },
        }),
    )
}

/// Turn folded totals into wire rows, keyed and ordered by `group_by`.
///
/// Rows are never folded below `(tenant, unit, source)`. Two provenances
/// under one number is the fold `sbproxy_meter` exists to refuse.
fn unit_rows(totals: &BTreeMap<(String, String, String), u64>, group_by: GroupBy) -> Vec<UnitRow> {
    let mut rows: Vec<UnitRow> = totals
        .iter()
        .map(|((tenant, unit, source), count)| {
            let mut row = UnitRow {
                group: String::new(),
                tenant: tenant.clone(),
                unit: unit.clone(),
                source: source.clone(),
                count: *count,
            };
            row.group = group_by.key(&row);
            row
        })
        .collect();
    rows.sort_by(|left, right| {
        left.group
            .cmp(&right.group)
            .then_with(|| left.tenant.cmp(&right.tenant))
            .then_with(|| left.unit.cmp(&right.unit))
            .then_with(|| left.source.cmp(&right.source))
    });
    rows
}

/// One page of this node's chain.
fn receipts_response(path: &str, principal: Option<&AdminPrincipal>) -> Resp {
    let scope = match scope_for(principal, decoded_query_param(path, "tenant").as_deref()) {
        Ok(scope) => scope,
        Err(response) => return response,
    };
    let since_seq: u64 = query_param(path, "since_seq")
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(0);
    let limit = query_param(path, "limit")
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(DEFAULT_RECEIPT_LIMIT)
        .clamp(1, MAX_RECEIPT_LIMIT);

    let attestation = crate::reload::current_pipeline_full().attestation.clone();
    let handle = crate::cluster::current_cluster_handle();
    let node_id = local_node_id(handle.as_ref());

    let Some(attestation) = attestation else {
        return json(
            200,
            serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "state": MeterState::Off.as_str(),
                "reason": MeterState::Off.reason(),
                "node_id": node_id,
                "tenant": scope,
                "since_seq": since_seq,
                "limit": limit,
                "receipts": Vec::<ReceiptRow>::new(),
                "next_since_seq": serde_json::Value::Null,
            }),
        );
    };

    let page = read_page(&attestation.ledger_path, scope.as_deref(), since_seq, limit);
    // A page can be empty because this tenant has no receipts on a chain
    // that is otherwise busy, which is a different statement from an empty
    // chain, so the state comes from the chain and not from the page.
    let state = if page.present {
        MeterState::Reporting
    } else {
        MeterState::Idle
    };
    json(
        200,
        serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "state": state.as_str(),
            "reason": state.reason(),
            "node_id": node_id,
            "tenant": scope,
            "since_seq": since_seq,
            "limit": limit,
            "receipts": page.receipts,
            "next_since_seq": page.next_since_seq,
            "damaged_at_seq": page.damaged_at_seq,
            "damage_reason": page.damage_reason,
        }),
    )
}

/// Re-verify this node's chain and report the first break.
///
/// Verification is chain-wide even for a tenant-scoped operator, and it
/// has to be: a hash chain proves that nothing was removed from between
/// two links, and a subset of the links proves nothing at all. Nothing
/// tenant-specific leaves through this route, because the verdict is a
/// sequence number and a reason that name no tenant.
fn verify_response(path: &str, principal: Option<&AdminPrincipal>) -> Resp {
    if let Err(response) = scope_for(principal, decoded_query_param(path, "tenant").as_deref()) {
        return response;
    }
    let attestation = crate::reload::current_pipeline_full().attestation.clone();
    let handle = crate::cluster::current_cluster_handle();
    let node_id = local_node_id(handle.as_ref());
    let verified_at = chrono::Utc::now().to_rfc3339();

    let Some(attestation) = attestation else {
        return json(
            404,
            serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "state": MeterState::Off.as_str(),
                "outcome": "not_started",
                "reason": MeterState::Off.reason(),
                "node_id": node_id,
                "verified_at": verified_at,
            }),
        );
    };
    if !attestation.ledger_path.exists() {
        return json(
            200,
            serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "state": MeterState::Idle.as_str(),
                "outcome": "not_started",
                "reason": MeterState::Idle.reason(),
                "node_id": node_id,
                "entries": 0,
                "verified_at": verified_at,
            }),
        );
    }
    match verify_ledger::<ChainedReceipt>(&attestation.ledger_path, None) {
        Ok(result) => {
            // A single verdict word rather than a boolean plus a nullable
            // index: an operator reading this reads one field, and a client
            // that grows a third outcome does not have to re-derive it from
            // two.
            let outcome = if result.ok { "ok" } else { "broken" };
            json(
                200,
                serde_json::json!({
                    "schema_version": SCHEMA_VERSION,
                    "state": MeterState::Reporting.as_str(),
                    "outcome": outcome,
                    "node_id": node_id,
                    "entries": result.entries,
                    "broken_seq": result.broken_seq,
                    "reason": result.reason,
                    "verified_at": verified_at,
                }),
            )
        }
        Err(error) => json(
            503,
            serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "state": MeterState::Reporting.as_str(),
                "outcome": "unreadable",
                "node_id": node_id,
                "reason": error.to_string(),
                "verified_at": verified_at,
            }),
        ),
    }
}

// --- Helpers ---

/// Serialize a response body, failing loudly rather than silently.
fn json(status: u16, body: serde_json::Value) -> Resp {
    match serde_json::to_string(&body) {
        Ok(text) => (status, JSON, text),
        Err(error) => (
            500,
            JSON,
            format!(r#"{{"error":"serialization failed: {error}"}}"#),
        ),
    }
}

/// The wrong verb on a real route.
fn method_not_allowed(expected: &str) -> Resp {
    (
        405,
        JSON,
        serde_json::json!({
            "error": format!("method not allowed; use {expected}"),
        })
        .to_string(),
    )
}

/// One raw query-string value.
fn query_param<'a>(path: &'a str, key: &str) -> Option<&'a str> {
    let query = path.split_once('?')?.1;
    query.split('&').find_map(|pair| {
        pair.split_once('=')
            .and_then(|(name, value)| (name == key).then_some(value))
    })
}

/// One percent-decoded query-string value.
///
/// Tenant names are operator data and can carry punctuation a browser
/// encodes, so the value that decides an authorization outcome is decoded
/// before it is compared. Comparing the raw form would let `acme%2Db` and
/// `acme-b` be two different tenants to this check and one tenant to the
/// filter underneath it.
fn decoded_query_param(path: &str, key: &str) -> Option<String> {
    let query = path.split_once('?')?.1;
    url::form_urlencoded::parse(query.as_bytes())
        .find_map(|(name, value)| (name == key).then(|| value.into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_config::types::AdminRole;
    use sbproxy_meter::ledger::UsageLedger;
    use sbproxy_modules::policy::receipt_token::{ReceiptEvidence, ReceiptSubject, ReceiptUnit};

    fn principal(tenant: Option<&str>) -> AdminPrincipal {
        AdminPrincipal {
            username: "operator-a".to_string(),
            role: AdminRole::Admin,
            via_session: false,
            csrf: None,
            tenant: tenant.map(str::to_string),
        }
    }

    fn claims(seq: u64, tenant: &str, unit: &str, count: u64) -> ReceiptClaims {
        ReceiptClaims {
            seq,
            prev: GENESIS_HASH.to_string(),
            node_id: "node-a".to_string(),
            claim_id: format!("{tenant}-claim-{seq}"),
            agreement_id: "agr-2026-04".to_string(),
            subject: ReceiptSubject {
                tenant: tenant.to_string(),
                key_id: None,
                agent: None,
            },
            route: "search".to_string(),
            request_digest: None,
            response_digest: None,
            units: vec![ReceiptUnit {
                name: unit.to_string(),
                count,
                source: "route_weight".to_string(),
                evidence: ReceiptEvidence::RouteWeight {
                    config_revision: "9f2c41a0be77".to_string(),
                },
            }],
            outcome: "delivered".to_string(),
            config_revision: "9f2c41a0be77".to_string(),
        }
    }

    fn temp_chain(tag: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("sb-admin-meter-{}-{tag}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    /// A two-tenant chain: acme at seq 0 and 2, globex at seq 1.
    ///
    /// Written through the real ledger rather than by hand, so these
    /// fixtures carry the digests and links a production writer would
    /// produce and a broken reader cannot pass by agreeing with itself.
    fn write_two_tenant_chain(path: &Path) {
        let ledger = UsageLedger::<ChainedReceipt>::open(path, None).expect("open chain");
        for receipt in [
            claims(0, "acme", "search_call", 3),
            claims(1, "globex", "search_call", 40),
            claims(2, "acme", "egress_kib", 12),
        ] {
            ledger.append(&ChainedReceipt(receipt));
        }
    }

    #[test]
    fn an_absent_chain_reads_as_empty_rather_than_as_an_error() {
        // The `idle` half of the empty state. A configured node that has
        // written nothing must not look like a broken one.
        let replay = replay_chain(Path::new("/nonexistent/sbproxy/receipts.jsonl"), None);

        assert!(!replay.present);
        assert_eq!(replay.entries, 0);
        assert_eq!(replay.claims, 0);
        assert!(replay.totals.is_empty());
        assert_eq!(replay.damage_reason, None);
        assert_eq!(replay.head_hash, GENESIS_HASH);
    }

    #[test]
    fn a_replay_folds_units_without_folding_tenants_or_provenance() {
        let path = temp_chain("replay");
        write_two_tenant_chain(&path);

        let replay = replay_chain(&path, None);

        assert!(replay.present);
        assert_eq!(replay.entries, 3);
        assert_eq!(replay.claims, 3);
        assert_eq!(replay.totals.len(), 3, "one line per tenant, unit, source");
        assert_eq!(
            replay.totals.get(&(
                "acme".to_string(),
                "search_call".to_string(),
                "route_weight".to_string()
            )),
            Some(&3)
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_scoped_replay_carries_no_other_tenants_units() {
        let path = temp_chain("scoped-replay");
        write_two_tenant_chain(&path);

        let replay = replay_chain(&path, Some("acme"));

        assert_eq!(
            replay.entries, 3,
            "the chain length is a chain fact and stays truthful"
        );
        assert!(
            replay.totals.keys().all(|(tenant, _, _)| tenant == "acme"),
            "{:?}",
            replay.totals
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_page_stops_at_the_limit_and_names_where_to_resume() {
        let path = temp_chain("page");
        write_two_tenant_chain(&path);

        let first = read_page(&path, None, 0, 2);
        assert_eq!(first.receipts.len(), 2);
        assert_eq!(first.receipts[0].seq, 0);
        assert_eq!(
            first.next_since_seq,
            Some(2),
            "the cursor is a sequence number, not a count the caller has to add up"
        );

        let second = read_page(&path, None, first.next_since_seq.expect("cursor"), 2);
        assert_eq!(second.receipts.len(), 1);
        assert_eq!(second.receipts[0].seq, 2);
        assert_eq!(second.next_since_seq, None, "the page reached the end");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_scoped_page_never_returns_another_tenants_receipt() {
        // The acceptance case for the receipts route: globex's entry sits
        // between two of acme's, so a filter applied to the page rather
        // than to the walk would leak it.
        let path = temp_chain("scoped-page");
        write_two_tenant_chain(&path);

        let page = read_page(&path, Some("acme"), 0, 50);

        assert_eq!(page.receipts.len(), 2);
        assert!(
            page.receipts
                .iter()
                .all(|row| row.claims.subject.tenant == "acme"),
            "a scoped read must not carry another tenant's receipt"
        );
        let rendered = serde_json::to_string(&page.receipts).expect("page serialises");
        assert!(!rendered.contains("globex"), "{rendered}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_damaged_chain_reports_where_it_stopped_rather_than_failing() {
        let path = temp_chain("damaged");
        write_two_tenant_chain(&path);
        let text = std::fs::read_to_string(&path).expect("read chain");
        let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
        lines[1] = "{not json".to_string();
        std::fs::write(&path, lines.join("\n") + "\n").expect("write chain");

        let replay = replay_chain(&path, None);

        assert_eq!(replay.entries, 1, "the walk stopped at the damage");
        assert_eq!(replay.damaged_at_seq, Some(1));
        assert!(replay
            .damage_reason
            .as_deref()
            .expect("a reason")
            .contains("unreadable entry"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn verification_names_the_first_broken_index_on_a_tampered_chain() {
        // The acceptance case for the verify route. A red cross tells an
        // operator nothing they can act on; a sequence number tells them
        // which receipt to go and look at.
        let path = temp_chain("tampered");
        write_two_tenant_chain(&path);
        let text = std::fs::read_to_string(&path).expect("read chain");
        let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
        lines[1] = lines[1].replace(r#""count":40"#, r#""count":4000"#);
        assert!(lines[1].contains("4000"), "the edit landed");
        std::fs::write(&path, lines.join("\n") + "\n").expect("write chain");

        let result = verify_ledger::<ChainedReceipt>(&path, None).expect("chain is readable");

        assert!(!result.ok);
        assert_eq!(result.broken_seq, Some(1));
        assert!(result.reason.is_some());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_clean_chain_verifies_through_the_transparent_payload() {
        // The wrapper must not change the bytes the chain hashed, or every
        // chain this build writes would fail verification on the next one.
        let path = temp_chain("clean");
        write_two_tenant_chain(&path);

        let result = verify_ledger::<ChainedReceipt>(&path, None).expect("chain is readable");

        assert!(result.ok, "{result:?}");
        assert_eq!(result.entries, 3);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_chained_payload_serialises_exactly_as_the_claims_do() {
        let receipt = claims(0, "acme", "search_call", 1);
        assert_eq!(
            serde_json::to_value(ChainedReceipt(receipt.clone())).expect("wrapper serialises"),
            serde_json::to_value(&receipt).expect("claims serialise"),
            "a transparent wrapper is the only kind that can read a chain it did not write"
        );
    }

    #[test]
    fn an_unscoped_operator_may_ask_for_any_tenant_or_none() {
        assert_eq!(scope_for(Some(&principal(None)), None), Ok(None));
        assert_eq!(
            scope_for(Some(&principal(None)), Some("globex")),
            Ok(Some("globex".to_string()))
        );
    }

    #[test]
    fn a_scoped_operator_is_narrowed_and_a_cross_tenant_ask_is_refused() {
        let scoped = principal(Some("acme"));

        assert_eq!(
            scope_for(Some(&scoped), None),
            Ok(Some("acme".to_string())),
            "no parameter resolves to their own tenant rather than to everything"
        );
        assert_eq!(
            scope_for(Some(&scoped), Some("acme")),
            Ok(Some("acme".to_string()))
        );

        let refused =
            scope_for(Some(&scoped), Some("globex")).expect_err("a cross-tenant read is refused");
        assert_eq!(refused.0, 403, "{refused:?}");
        assert!(
            refused.2.contains("acme"),
            "the refusal names their own scope: {}",
            refused.2
        );
        assert!(
            !refused.2.contains("globex"),
            "and does not echo the tenant they asked about: {}",
            refused.2
        );
    }

    #[test]
    fn an_unauthenticated_caller_is_refused_rather_than_treated_as_unscoped() {
        let refused = scope_for(None, None).expect_err("no principal is not an empty scope");
        assert_eq!(refused.0, 401);
    }

    #[test]
    fn a_blank_tenant_parameter_reads_as_absent() {
        assert_eq!(scope_for(Some(&principal(None)), Some("   ")), Ok(None));
        assert_eq!(
            scope_for(Some(&principal(Some("acme"))), Some("")),
            Ok(Some("acme".to_string()))
        );
    }

    #[tokio::test]
    async fn every_route_refuses_a_cross_tenant_read() {
        // The acceptance criterion, checked on all three routes at the
        // dispatch boundary rather than only on the helper they share.
        let scoped = principal(Some("acme"));
        for (method, path) in [
            ("GET", "/api/meter/summary?tenant=globex"),
            ("GET", "/api/meter/receipts?tenant=globex"),
            ("POST", "/api/meter/verify?tenant=globex"),
        ] {
            let (status, _, body) = dispatch(method, path, Some(&scoped))
                .await
                .unwrap_or_else(|| panic!("{path} is a route"));
            assert_eq!(status, 403, "{path}: {body}");
            assert!(!body.contains("globex"), "{path}: {body}");
        }
    }

    #[tokio::test]
    async fn every_route_refuses_an_unauthenticated_caller() {
        for (method, path) in [
            ("GET", SUMMARY_PATH),
            ("GET", RECEIPTS_PATH),
            ("POST", VERIFY_PATH),
        ] {
            let (status, _, _) = dispatch(method, path, None)
                .await
                .unwrap_or_else(|| panic!("{path} is a route"));
            assert_eq!(status, 401, "{path}");
        }
    }

    #[tokio::test]
    async fn verbs_are_enforced() {
        let operator = principal(None);
        let (status, _, _) = dispatch("POST", SUMMARY_PATH, Some(&operator))
            .await
            .expect("route exists");
        assert_eq!(status, 405);
        let (status, _, _) = dispatch("GET", VERIFY_PATH, Some(&operator))
            .await
            .expect("route exists");
        assert_eq!(status, 405);
    }

    #[tokio::test]
    async fn unknown_paths_fall_through() {
        let operator = principal(None);
        assert!(dispatch("GET", "/api/meter", Some(&operator))
            .await
            .is_none());
        assert!(dispatch("GET", "/api/other", Some(&operator))
            .await
            .is_none());
    }

    #[tokio::test]
    async fn an_unconfigured_meter_says_off_rather_than_reporting_zeros() {
        // The distinction the page exists to make. `off` and `idle` are
        // different sentences, and neither is a row of zeros.
        let operator = principal(None);
        let (status, _, body) = dispatch("GET", SUMMARY_PATH, Some(&operator))
            .await
            .expect("route exists");
        assert_eq!(status, 200);
        let value: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(value["state"], "off");
        assert_eq!(value["attestation"]["configured"], false);
        assert!(
            value["reason"]
                .as_str()
                .expect("a reason")
                .contains("not configured"),
            "{body}"
        );
        assert_eq!(value["coverage"], serde_json::Value::Null);
        assert_eq!(
            value["totals"].as_array().expect("totals").len(),
            0,
            "nothing is fabricated to fill the page out"
        );
    }

    #[tokio::test]
    async fn the_summary_validates_its_parameters_the_way_spend_does() {
        let operator = principal(None);
        let (status, _, body) = dispatch(
            "GET",
            "/api/meter/summary?group_by=nonsense",
            Some(&operator),
        )
        .await
        .expect("route exists");
        assert_eq!(status, 400);
        assert!(body.contains("unknown group_by"), "{body}");

        let (status, _, body) = dispatch("GET", "/api/meter/summary?window=24h", Some(&operator))
            .await
            .expect("route exists");
        assert_eq!(
            status, 400,
            "a windowed question a cumulative chain cannot answer is refused, not approximated"
        );
        assert!(body.contains("window is not supported"), "{body}");
    }

    #[test]
    fn grouping_keys_rows_without_folding_provenance_together() {
        let mut totals = BTreeMap::new();
        totals.insert(
            (
                "acme".to_string(),
                "api_call".to_string(),
                "measured".to_string(),
            ),
            3,
        );
        totals.insert(
            (
                "acme".to_string(),
                "api_call".to_string(),
                "route_weight".to_string(),
            ),
            40,
        );

        let rows = unit_rows(&totals, GroupBy::Tenant);

        assert_eq!(rows.len(), 2, "43 is not an answer anybody can dispute");
        assert!(rows.iter().all(|row| row.group == "acme"));
        assert_eq!(
            rows.iter().map(|row| row.count).collect::<Vec<_>>(),
            vec![3, 40]
        );

        let by_source = unit_rows(&totals, GroupBy::Source);
        assert_eq!(
            by_source
                .iter()
                .map(|row| row.group.as_str())
                .collect::<Vec<_>>(),
            vec!["measured", "route_weight"]
        );
    }

    #[test]
    fn gap_rows_are_parsed_per_tenant_and_narrowed_to_the_caller() {
        // The gap counter is the one number that means revenue went
        // unbilled, so a scoped operator has to get their own figure
        // rather than the fleet's.
        let exposition = concat!(
            "# HELP sbproxy_meter_chain_gap_total records owed and not written\n",
            "# TYPE sbproxy_meter_chain_gap_total counter\n",
            "sbproxy_meter_chain_gap_total{tenant_id=\"acme\",failure_mode=\"degraded\"} 3\n",
            "sbproxy_meter_chain_gap_total{tenant_id=\"globex\",failure_mode=\"degraded\"} 11\n",
            "sbproxy_meter_divergence_total{tenant_id=\"acme\"} 2\n",
        );

        let all = gap_rows(exposition, None);
        assert_eq!(all.len(), 2);
        assert_eq!(all.iter().map(|row| row.count).sum::<u64>(), 14);

        let scoped = gap_rows(exposition, Some("acme"));
        assert_eq!(
            scoped,
            vec![GapRow {
                tenant: "acme".to_string(),
                failure_mode: "degraded".to_string(),
                count: 3,
            }]
        );
        assert_eq!(divergence_total(exposition, Some("acme")), 2);
        assert_eq!(divergence_total(exposition, Some("globex")), 0);
    }

    #[test]
    fn an_unlabelled_sample_still_parses() {
        let exposition = "sbproxy_meter_divergence_total 7\n";
        assert_eq!(divergence_total(exposition, None), 7);
    }

    #[test]
    fn a_tenant_parameter_is_decoded_before_it_decides_anything() {
        assert_eq!(
            decoded_query_param("/api/meter/summary?tenant=acme%2Deu", "tenant").as_deref(),
            Some("acme-eu"),
        );
    }
}

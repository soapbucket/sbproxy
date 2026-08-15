// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Cutting the receipt: where a served request becomes a signed, chained
//! record on this node's disk (WOR-2145).
//!
//! Every layer under this one already existed and nothing called it.
//! `sbproxy-meter` owned the outcome table, the three unit resolvers, and
//! the hash chain; `sbproxy-modules` owned the receipt claims and the JWS
//! signer; [`crate::attestation`] lowered `proxy.attestation` into a
//! runtime. A request served under `role: receipt` still produced nothing,
//! and the operator surface at `/api/meter/*` correctly reported `idle`
//! forever. This module is the seam that was missing.
//!
//! # Two phases, because `logging()` cannot refuse anything
//!
//! A meter that discovers it cannot write is discovering it too late: the
//! Pingora `logging()` callback runs after the response has been written to
//! the client, and there is no way to recall bytes that have already
//! crossed the wire. So the work is split.
//!
//! `crate::meter_runtime::preflight_refuses` runs in `response_filter`,
//! before the body reaches the client, and answers exactly one question: is
//! this an origin that writes receipts, under a `closed` posture, with no
//! chain to write them to. That is the only case where refusing is both
//! possible and correct, and it is deliberately the cheapest check that can
//! answer it, because it runs on every response.
//!
//! `crate::meter_runtime::record_response` runs in `logging()`, where the
//! final status, the final byte counts, and the final outcome are all
//! known. Every other posture is decided there, after the fact, which is
//! the honest place to decide them: the request is over, and what is left
//! is whether the record of it is complete.
//!
//! `crate::meter_runtime::capture_origin_headers` bridges the two. The
//! upstream response header is in scope in `response_filter` and gone by
//! `logging()`, so whatever
//! [`sbproxy_meter::OriginHeaderRule`] names has to be copied across while
//! it still exists. Only the configured names are copied, so a deployment
//! with no origin-header rules allocates nothing.
//!
//! # The receipt is cut from the pinned pipeline, never from live config
//!
//! Everything a receipt cites comes from `ctx.pipeline`, the
//! [`std::sync::Arc`] pinned at ingress. A reload that lands between
//! `request_filter` and `logging()` must not reprice a call in flight, and
//! a `config_revision` on a receipt that names a document other than the
//! one that supplied the weights is worse than no evidence at all, because
//! it reads as proof.
//!
//! # Sequencing, and why there is a second lock
//!
//! [`sbproxy_modules::policy::receipt_token::ReceiptClaims::seq`] and
//! `prev` are inside the signed document, and they have to equal the `seq`
//! and `prev_hash` of the ledger entry that carries them, or a buyer
//! checking the chain against the receipts finds two different sequences
//! for the same traffic. `sbproxy_meter::ledger::UsageLedger` assigns those
//! inside its own mutex, so reading `head()` and then calling
//! `append_checked` is a race that two concurrent requests lose: both read
//! sequence 5, both sign a receipt claiming to be 5, and one of them is
//! filed at 6.
//!
//! [`crate::meter_runtime::ReceiptChain`] therefore holds a sequencing
//! mutex and takes it across read-head, build, sign, and append. Appends
//! were already serialized by the ledger's own mutex, so this widens an
//! existing critical section rather than introducing contention that was
//! not there before.
//!
//! # A chain that will not open is a runtime condition
//!
//! `crate::meter_runtime::ReceiptChain::open` cannot fail. A full disk,
//! an unwritable path, or a torn final line becomes an unavailable chain
//! recorded on the object itself, and `failure_mode` then decides what
//! happens to traffic. That is the entire justification for metering
//! defaulting to `degraded` rather than to the surface-wide `closed`:
//! billing is not a security boundary, and a full ledger disk must not take
//! the API down. The hole is still provable, because it is counted through
//! `sbproxy_meter::metrics::observe_chain_gap` and, wherever a chain
//! survives to be written to, marked in the chain itself.
//!
//! # A receipt on the chain still has to agree with itself (WOR-2211)
//!
//! Signing and chaining establish that a receipt is authentic and
//! unmodified. They do not establish that it is coherent: a unit declaring
//! `measured` while carrying an origin header passes both, and `measured`
//! is the top of the trust order, so that is the direction a laundered
//! number would travel. Nothing this module writes can be incoherent,
//! because `sbproxy_meter::Unit::new` derives a unit's declared source from
//! its evidence, but a chain file is bytes on a disk that outlive the
//! process that wrote them.
//!
//! `ChainedReceipt` therefore implements
//! `sbproxy_meter::ledger::LedgerPayload::provenance_conflict`, which the
//! ledger's replay and verification both call on every entry they decode.
//! An incoherent entry makes the chain refuse to open, which is the same
//! condition a torn final line produces and is handled by the same
//! `failure_mode` branch below.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use sbproxy_config::types::FailureMode;
use sbproxy_meter::ledger::UsageLedger;
use sbproxy_meter::metrics::FailurePosture;
use sbproxy_meter::{
    resolve_measured, resolve_origin_headers, BillableOutcome, LedgerPayload, Measurement,
    MeteredEvent, Subject, Unit,
};
use sbproxy_modules::policy::receipt_token::{
    outcome_wire_name, ReceiptClaims, ReceiptSubject, ReceiptTokenSigner, ReceiptUnit,
};
use serde::{Deserialize, Serialize};

use crate::attestation::{AttestationRuntime, ResolvedOriginAttestation};
use crate::context::{AdminCacheStatus, RequestContext};
use crate::meter_cluster::LocalMeter;

/// The outcome a gap marker carries.
///
/// `sbproxy_modules::policy::receipt_token::ReceiptClaims::outcome` is a
/// `String` on the wire precisely so the set can grow without invalidating
/// a verifier compiled last quarter, which is what lets the marker be an
/// ordinary chained, signed receipt rather than a second file format.
const CHAIN_GAP_OUTCOME: &str = "chain_gap";

/// Suffix that distinguishes a gap marker's dedup key from the receipt it
/// stands in for.
///
/// Load bearing. The chain dedups on
/// [`sbproxy_meter::ledger::LedgerPayload::dedup_key`], so a marker filed
/// under the bare claim id would poison that claim: a later attempt whose
/// receipt did write would be silently discarded as a duplicate of the
/// marker, and the gap would become permanent instead of being closed by
/// the retry.
const GAP_CLAIM_SUFFIX: &str = ":chain_gap";

/// The outcome a usage-bridge gap marker carries.
///
/// Distinct from [`CHAIN_GAP_OUTCOME`] because the two holes are
/// different holes. A chain gap says the signed record of a request could
/// not be written. A usage gap says the record was written and the
/// billable unit it describes never reached the durable provider queue,
/// so the receipt is right and the invoice will be short.
const USAGE_GAP_OUTCOME: &str = "usage_gap";

/// Suffix that distinguishes a usage-bridge gap marker's dedup key.
///
/// Load bearing for the same reason [`GAP_CLAIM_SUFFIX`] is, and it has
/// to be a *different* suffix rather than a shared one. The chain dedups
/// on [`sbproxy_meter::ledger::LedgerPayload::dedup_key`], so a request
/// that lost both its receipt and its billable unit would file its second
/// marker under a key the first already occupied and the second would be
/// silently discarded as a duplicate.
const USAGE_GAP_CLAIM_SUFFIX: &str = ":usage_gap";

// --- The chained payload ---

/// The document one receipt-chain entry attests to.
///
/// Shared by the writer here and the reader in [`crate::admin_meter`], so
/// the two cannot drift. It began life private to the reader, and moving it
/// rather than declaring a second wrapper is the point: the bytes on disk
/// are an on-disk contract, and a reader that agreed with itself instead of
/// with the writer would pass its own tests forever.
///
/// A transparent newtype rather than an implementation of
/// [`sbproxy_meter::ledger::LedgerPayload`] on `ReceiptClaims` itself: the
/// claims type belongs to `sbproxy-modules`, the trait to `sbproxy-meter`,
/// and deciding on their behalf what a receipt's dedup key is would be this
/// crate legislating for two others. `serde(transparent)` means the bytes
/// on disk are `ReceiptClaims`' own bytes, which is what the re-serialize
/// check in [`sbproxy_meter::verify_ledger`] compares against, so neither
/// writing through this wrapper nor reading through it can change a
/// verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct ChainedReceipt(pub(crate) ReceiptClaims);

impl LedgerPayload for ChainedReceipt {
    /// The claim id, which every attempt at one unit of work shares.
    ///
    /// The same key the chain dedups on when writing, so a page read back
    /// through this type folds retries the way the writer did.
    fn dedup_key(&self) -> Option<&str> {
        Some(self.0.claim_id.as_str())
    }

    /// The first unit on this receipt that cannot be true.
    ///
    /// This is what makes the coherence check reach every path that turns
    /// bytes back into a receipt rather than only the one somebody
    /// remembered. `sbproxy_meter::verify_ledger` and the replay behind
    /// `sbproxy_meter::ledger::UsageLedger::open` both ask the payload,
    /// so wiring it once here covers the boot-time replay, the
    /// `/api/meter/verify` route, and any future reader that goes through
    /// the ledger rather than around it. The two admin routes that walk the
    /// file themselves ask `ReceiptClaims::provenance_conflict` directly,
    /// for the same reason and against the same rule.
    fn provenance_conflict(&self) -> Option<sbproxy_meter::metrics::ProvenanceConflict<'_>> {
        let unit = self.0.provenance_conflict()?;
        Some(sbproxy_meter::metrics::ProvenanceConflict {
            tenant_id: self.0.subject.tenant.as_str(),
            unit: unit.name.as_str(),
            declared_source: unit.source.as_str(),
            evidence_source: unit.evidence_source(),
        })
    }

    /// What this receipt contributes to the meter's own reconciliation
    /// (WOR-2324).
    ///
    /// The precondition the trait's `None` default protects is met here,
    /// and it is the only payload in this workspace that meets it. Both
    /// sides of `sbproxy_meter_divergence_total` count the same quantity
    /// because they are computed once and used twice: [`record_response`]
    /// calls `sbproxy_meter::OutcomeTable::settle` once over the sale and
    /// any collapsed retry attempts, which reports each attempt through
    /// `sbproxy_meter::metrics::observe_settled_event` and yields the billed
    /// units mapped through
    /// `sbproxy_modules::policy::receipt_token::ReceiptUnit::from` into the
    /// document this reads back. A payload that answered one side and not
    /// the other would manufacture a disagreement instead of detecting one,
    /// which is why the AI gateway's usage event and the security audit
    /// entry both stay on the default: nothing counts their quantities
    /// through the meter's unit path.
    ///
    /// Until this existed the chained side of the comparison was always
    /// empty, so every tenant with billable units diverged in every window
    /// and `SBPROXY-METER-DIVERGENCE` fired continuously on any metering
    /// deployment with traffic.
    ///
    /// A gap marker carries no units and therefore contributes zero, which
    /// is exactly right: the receipt it stands in for was counted and never
    /// chained, and that imbalance is the one the counter exists to report.
    ///
    /// Summed rather than reported per unit, because the comparison is per
    /// tenant. The counted side folds every unit of every receipt into one
    /// per-tenant total, so a per-unit contribution would only have to be
    /// re-summed at the other end. Saturating, because a total that wrapped
    /// would report a healthy tenant.
    fn chain_contribution(&self) -> Option<sbproxy_meter::metrics::ChainContribution<'_>> {
        Some(sbproxy_meter::metrics::ChainContribution {
            tenant_id: self.0.subject.tenant.as_str(),
            units: self
                .0
                .units
                .iter()
                .fold(0u64, |total, unit| total.saturating_add(unit.count)),
        })
    }
}

// --- Bridging response_filter to logging ---

/// Copy the response headers this generation's attestation config names
/// into the context, for the receipt cut later in `logging`.
///
/// A no-op when the origin does not write receipts or declares no
/// origin-header rules, which is the overwhelmingly common case and the
/// reason the checks are ordered the way they are.
///
/// Only the configured names are copied. Capturing the whole header map
/// would allocate on every response for the benefit of the small number of
/// deployments that meter one, and capturing nothing would leave every
/// origin-header rule resolving as absent forever, which is exactly the
/// silent metering gap [`sbproxy_meter::origin_header`] is written to make
/// visible.
///
/// Values are stored exactly as they arrived. Not trimmed, not lowercased,
/// and never re-serialized from a parsed number: the raw bytes are the
/// evidence, and the disagreement a buyer raises may well be about the
/// parse rather than about the number.
pub(crate) fn capture_origin_headers(
    ctx: &mut RequestContext,
    response: &pingora_http::ResponseHeader,
) {
    let Some(runtime) = ctx.pipeline.attestation.as_deref() else {
        return;
    };
    if runtime.origin_headers.is_empty() {
        return;
    }
    let writes_receipts = ctx
        .origin_idx
        .and_then(|index| ctx.pipeline.origin_attestations.get(index))
        .is_some_and(|origin| origin.role.writes_receipts());
    if !writes_receipts {
        return;
    }

    let captured: Vec<(String, String)> = runtime
        .origin_headers
        .iter()
        .filter_map(|rule| {
            response
                .headers
                .get(rule.header.as_str())
                .and_then(|value| value.to_str().ok())
                .map(|value| (rule.header.clone(), value.to_string()))
        })
        .collect();
    ctx.meter_origin_headers = captured;
}

/// What the response carried under `header`, or `None` when it carried
/// nothing.
///
/// Absent and empty stay apart. A name with no entry is a header the origin
/// never sent, which is a different statement from one it sent empty, and
/// the receipt's evidence encodes that difference all the way to the buyer:
/// one is an upstream nobody wired up, the other is an upstream reporting
/// something unreadable.
///
/// Compared case-insensitively, because HTTP field names are.
fn observed_origin_header<'a>(captured: &'a [(String, String)], header: &str) -> Option<&'a str> {
    captured
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(header))
        .map(|(_, value)| value.as_str())
}

// --- The chain ---

/// This node's receipt chain: the ledger, the key that signs what goes into
/// it, and the lock that keeps a receipt's sequence honest.
///
/// One per pipeline generation, held behind an [`std::sync::Arc`] on
/// [`crate::attestation::AttestationRuntime`], so a request that pinned a
/// generation keeps writing to the chain that generation opened.
///
/// [`std::fmt::Debug`] is hand written rather than derived. The struct
/// holds a signing key, and while both the ledger and the receipt signer
/// already redact their own halves, a derive here would be one refactor
/// away from printing whatever a future field holds. The kid is the safe
/// identifier, and it is the same one
/// [`sbproxy_modules::policy::receipt_token::ReceiptTokenSigner`] prints.
pub struct ReceiptChain {
    /// The hash chain on disk. `None` when it could not be opened, which is
    /// a runtime condition and not a boot failure; see the module docs.
    ledger: Option<UsageLedger<ChainedReceipt>>,
    /// Signs the portable JWS half of every receipt. `None` when the seed
    /// would not parse, which makes the chain unwritable for the same
    /// reason a missing ledger does: an unsigned receipt is a log line.
    signer: Option<ReceiptTokenSigner>,
    /// The node this chain speaks for. Chains are per node and are never
    /// merged, so a `seq` is only meaningful next to this.
    node_id: String,
    /// Running totals for the segment this node publishes to the mesh.
    meter: LocalMeter,
    /// Held across read-head, build, sign, and append. See the module docs
    /// for why reading the head outside it is a race.
    sequencing: parking_lot::Mutex<()>,
    /// Whether receipts may still be admitted.
    ///
    /// An atomic rather than a field behind the sequencing lock because
    /// `crate::meter_runtime::preflight_refuses` reads it on every
    /// response and must not queue behind an append to do so.
    writable: AtomicBool,
    /// Test-only fault injection for the one failure that cannot be
    /// produced from outside the process.
    ///
    /// An append against an already-open file descriptor cannot be made to
    /// fail by an end-to-end test: filling the disk is not reliable, and
    /// revoking permissions does not affect a descriptor that is already
    /// open. The gap-marker path is the most important behaviour in this
    /// module and the least reachable, so it gets a seam. Compiled out
    /// entirely outside `cfg(test)`.
    #[cfg(test)]
    fail_next_append: AtomicBool,
}

impl std::fmt::Debug for ReceiptChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the seed and never the signing key; the kid is the public
        // identifier that selects the matching JWKS entry.
        f.debug_struct("ReceiptChain")
            .field("kid", &self.signer.as_ref().map(ReceiptTokenSigner::key_id))
            .field("node_id", &self.node_id)
            .field("open", &self.ledger.is_some())
            .field("writable", &self.is_writable())
            .finish()
    }
}

/// One entry this module wrote, and the portable artifact that goes with
/// it.
struct AppendedReceipt {
    /// The claims exactly as they were signed and filed.
    claims: ReceiptClaims,
    /// Compact JWS over those claims.
    token: String,
    /// `false` when the claim was already on the chain, which is the
    /// `Collapse` answer working rather than a failure.
    recorded: bool,
}

/// The fields every receipt for one request shares, owned once so the
/// receipt and any gap marker that follows it agree on all of them.
struct ReceiptFacts {
    /// Groups every attempt at one unit of work under one invoice line.
    claim_id: String,
    /// The commercial agreement the units are billed under, or the empty
    /// string when this origin names none.
    agreement_id: String,
    /// Who the consumption is charged to.
    subject: ReceiptSubject,
    /// The route that matched, as the operator named it.
    route: String,
    /// Which configuration priced the call.
    config_revision: String,
}

impl ReceiptFacts {
    /// Build one receipt from these facts plus what the chain assigned.
    ///
    /// `seq` and `prev` are parameters rather than something read here
    /// because only the sequencing lock knows them, and a receipt that
    /// guessed at either would contradict the entry carrying it.
    fn claims(
        &self,
        node_id: &str,
        seq: u64,
        prev: String,
        claim_id: String,
        outcome: String,
        units: Vec<ReceiptUnit>,
    ) -> ReceiptClaims {
        ReceiptClaims {
            seq,
            prev,
            node_id: node_id.to_string(),
            claim_id,
            agreement_id: self.agreement_id.clone(),
            subject: self.subject.clone(),
            route: self.route.clone(),
            // No request-side digest exists to reuse. The wired RFC 9421
            // egress signer covers `@authority`, `@method`, and `@path`
            // over an empty body because the auth phase does not buffer
            // request bodies, and hashing one here would mean buffering
            // bodies nothing else in the request path buffers.
            request_digest: None,
            // Never a digest over a partial body. Nothing on this path
            // holds the complete response bytes, so the honest receipt is
            // one with no response digest rather than one whose digest
            // reads as proof right up until somebody checks it.
            response_digest: None,
            units,
            outcome,
            config_revision: self.config_revision.clone(),
        }
    }
}

impl ReceiptChain {
    /// Open the chain at `ledger_path`, signing every entry with `seed_hex`.
    ///
    /// Never fails. A ledger that will not open is recorded as unavailable
    /// and logged once at `warn`, because taking the API down over a full
    /// disk is the outcome the `degraded` default exists to prevent; see
    /// the module docs.
    ///
    /// The ledger is signed with the same Ed25519 seed the receipt JWS is
    /// signed with, so every entry carries a signature over its own digest
    /// on the same key family as the quote token. A buyer fetches one JWKS
    /// and checks both halves of the invoice line with it rather than
    /// discovering a second key-distribution problem at the moment they
    /// were ready to pay.
    pub(crate) fn open(
        ledger_path: &Path,
        seed_hex: &str,
        signing_key_id: &str,
        node_id: &str,
    ) -> Self {
        let ledger = match UsageLedger::<ChainedReceipt>::open(ledger_path, Some(seed_hex)) {
            Ok(ledger) => Some(ledger),
            Err(error) => {
                tracing::warn!(
                    %error,
                    path = %ledger_path.display(),
                    "meter-runtime: receipt chain unavailable; proxy.attestation.failure_mode \
                     decides what happens to traffic"
                );
                None
            }
        };

        let signer = match seed_bytes(seed_hex) {
            Some(seed) => Some(ReceiptTokenSigner::from_seed_bytes(&seed, signing_key_id)),
            None => {
                tracing::warn!(
                    kid = %signing_key_id,
                    "meter-runtime: the receipt signing seed is not 32 bytes of hex, so no \
                     receipt can be signed; proxy.attestation.failure_mode decides what happens \
                     to traffic"
                );
                None
            }
        };

        // Both halves or neither. A chain that could be appended to but not
        // signed would produce entries nobody outside this process can
        // attribute, which is a log file wearing a receipt's clothes.
        let writable = ledger.is_some() && signer.is_some();

        Self {
            ledger,
            signer,
            node_id: node_id.to_string(),
            meter: LocalMeter::new(node_id),
            sequencing: parking_lot::Mutex::new(()),
            writable: AtomicBool::new(writable),
            #[cfg(test)]
            fail_next_append: AtomicBool::new(false),
        }
    }

    /// Whether a receipt written now would land.
    ///
    /// One relaxed atomic load. This is on the response path for every
    /// request an attesting origin serves.
    pub(crate) fn is_writable(&self) -> bool {
        self.writable.load(Ordering::Relaxed)
    }

    /// The node this chain speaks for.
    pub(crate) fn node_id(&self) -> &str {
        &self.node_id
    }

    /// This node's running totals, for the segment it publishes.
    pub(crate) fn local_meter(&self) -> &LocalMeter {
        &self.meter
    }

    /// A segment describing this chain as of its current head, or `None`
    /// when there is no chain to describe.
    ///
    /// The head is read here and passed straight through rather than being
    /// guessed at by the meter, because a segment quoting a head the chain
    /// does not support is a number nobody can reproduce from the file.
    pub(crate) fn segment(&self) -> Option<sbproxy_meter::segment::ChainSegment> {
        let ledger = self.ledger.as_ref()?;
        let (head_seq, head_hash) = ledger.head();
        Some(self.meter.segment(head_seq, &head_hash))
    }

    /// Stop admitting receipts.
    ///
    /// Called on the `closed` failure branch so the *next* request is
    /// refused by `crate::meter_runtime::preflight_refuses`. It does
    /// nothing for the request that just failed, which has already been
    /// served and cannot be recalled.
    fn close(&self) {
        self.writable.store(false, Ordering::Relaxed);
    }

    /// Arrange for the next append through this chain to fail.
    ///
    /// One shot: the flag clears itself, so the gap marker that follows a
    /// forced failure still lands and can be asserted on.
    #[cfg(test)]
    pub(crate) fn fail_next_append(&self) {
        self.fail_next_append.store(true, Ordering::Relaxed);
    }

    /// Read the head, build the receipt, sign it, and file it, all under
    /// the sequencing lock.
    ///
    /// `build` receives the sequence number and previous digest the entry
    /// will actually carry. Doing it any other way is the race the module
    /// docs describe: two concurrent requests both read sequence 5, both
    /// sign a receipt saying 5, and one of them gets filed at 6.
    ///
    /// `Ok` with `recorded: false` means the claim was already on the
    /// chain. That is the `Collapse` answer working, not a failure.
    fn append(
        &self,
        build: impl FnOnce(u64, String) -> ReceiptClaims,
    ) -> anyhow::Result<AppendedReceipt> {
        let ledger = self
            .ledger
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("receipt chain is not open"))?;
        let signer = self
            .signer
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("receipt chain has no signing identity"))?;

        // Appends are already serialized by the ledger's own mutex, so this
        // widens an existing critical section rather than adding a new
        // source of contention.
        let _sequencing = self.sequencing.lock();

        #[cfg(test)]
        {
            if self.fail_next_append.swap(false, Ordering::Relaxed) {
                anyhow::bail!("meter-runtime: injected append failure");
            }
        }

        let (seq, prev) = ledger.head();
        let claims = build(seq, prev);
        let token = signer
            .sign(&claims)
            .map_err(|error| anyhow::anyhow!("receipt would not sign: {error}"))?;
        // `append_checked` and never `append`. The best-effort variant
        // swallows the error and reports a `Degraded` gap itself, which is
        // the wrong posture for three of the four this module has to
        // honour.
        let entry = ledger.append_checked(&ChainedReceipt(claims.clone()))?;

        Ok(AppendedReceipt {
            claims,
            token,
            recorded: entry.is_some(),
        })
    }

    /// Write the marker that says a record was owed here and not made.
    ///
    /// Best effort by construction: this runs because an append already
    /// failed, so it may well fail too, and when it does the metric is the
    /// only record left. Deliberately does not consult
    /// `Self::is_writable`, because the `closed` branch flips that flag
    /// before it gets here and the marker is the last honest thing the
    /// chain can say about itself.
    fn write_gap_marker(&self, facts: &ReceiptFacts) {
        let marker = self.append(|seq, prev| {
            facts.claims(
                &self.node_id,
                seq,
                prev,
                format!("{}{GAP_CLAIM_SUFFIX}", facts.claim_id),
                CHAIN_GAP_OUTCOME.to_string(),
                Vec::new(),
            )
        });
        if let Err(error) = marker {
            tracing::warn!(
                %error,
                claim_id = %facts.claim_id,
                "meter-runtime: the gap marker could not be written either; \
                 sbproxy_meter_chain_gap_total is the only record of this one"
            );
        }
    }
}

// --- Preflight ---

/// Whether this response must be refused rather than served unmetered.
///
/// Called from `response_filter`, before the body reaches the client, and
/// the only place in this module where a receipt failure can refuse
/// anything: `logging()` runs after the response has been written and
/// cannot recall it.
///
/// True in exactly one situation, and each condition is checked in the
/// order that rejects fastest, because this runs on every response:
/// attestation is configured, the posture is
/// [`sbproxy_config::types::FailureMode::Closed`], this origin's resolved
/// role writes receipts, and the chain is absent or shut. Everything else
/// is false, including the three postures that admit.
pub(crate) fn preflight_refuses(ctx: &RequestContext) -> bool {
    let Some(runtime) = ctx.pipeline.attestation.as_deref() else {
        return false;
    };
    if !matches!(runtime.failure_mode, FailureMode::Closed) {
        return false;
    }
    if !resolved_origin(ctx).is_some_and(|origin| origin.role.writes_receipts()) {
        return false;
    }
    !runtime
        .chain
        .as_deref()
        .is_some_and(ReceiptChain::is_writable)
}

// --- Cutting the receipt ---

/// What the meter settled for one request.
///
/// Returned by [`record_response`] so that anything downstream which has to
/// agree with the receipt reads the receipt's own answer instead of
/// re-deriving it. The usage bridge (WOR-2169) is the first such consumer:
/// whether a cache hit, a policy block, or a cut stream is billable is the
/// operator's `proxy.attestation.billable` table's decision, taken once,
/// here, and a second derivation elsewhere would eventually disagree with
/// this one and put a charge on an invoice the receipt says is free.
///
/// `billed` is [`sbproxy_meter::OutcomeTable::billable_units`]'s output, so
/// an outcome the table prices at `no` arrives as an empty list rather than
/// as a list plus a flag somebody has to remember to check.
// Only the `payments` build has a consumer for these fields today. Gating
// the whole type instead would mean two `record_response` signatures, and a
// second signature is a second place for the outcome decision to drift.
#[cfg_attr(not(feature = "payments"), allow(dead_code))]
pub(crate) struct SettledRequest {
    /// Groups every attempt at one unit of work under one invoice line.
    pub(crate) claim_id: String,
    /// The route that matched, as the operator named it.
    pub(crate) route: String,
    /// What happened, in the terms the billing table is written in.
    pub(crate) outcome: BillableOutcome,
    /// Everything this attempt billed, after the outcome table ran.
    pub(crate) billed: Vec<Unit>,
}

/// Record what this request consumed.
///
/// Called from `logging()`, once, with the request line, the final status,
/// and whether the client hung up. Never fails, never panics, and never
/// propagates: it is on the request path, and a metering defect that took a
/// request down with it would be a worse bug than the one it was reporting.
///
/// `path` is the path with no query string, and it is used both to match
/// route weights and as the receipt's `route`. A query string would make
/// one endpoint match differently per call and would put caller-supplied
/// data on a signed document.
///
/// Everything else comes from `ctx.pipeline`, the generation pinned at
/// ingress. See the module docs for why a reload must not reach this.
///
/// Returns what the outcome table settled, or `None` when this origin
/// writes no receipts and there is therefore no operator answer about what
/// is billable. See [`SettledRequest`].
pub(crate) fn record_response(
    ctx: &RequestContext,
    method: &str,
    path: &str,
    status: u16,
    client_disconnected: bool,
) -> Option<SettledRequest> {
    let runtime = ctx.pipeline.attestation.as_deref()?;
    let origin = resolved_origin(ctx)?;
    if !origin.role.writes_receipts() {
        return None;
    }

    let tenant = ctx.tenant_id.as_str();
    let outcome = classify_outcome(ctx, status, client_disconnected);
    let accrued = resolve_units(runtime, ctx, method, path);
    // Prior attempts are their own events so `billable.retry: collapse`
    // has something to fold. The sale is still `outcome`: a successful
    // retry is delivered once, not a lone Retry that collapse zeros.
    // `settle` reports each attempt; do not observe the sale a second time.
    let events = attempt_events(ctx, method, path, outcome, accrued);
    let billed = runtime
        .outcomes
        .settle(&events)
        .into_iter()
        .next()
        .map(|claim| claim.units)
        .unwrap_or_default();

    let facts = ReceiptFacts {
        claim_id: ctx.request_id.to_string(),
        // `agreement_id` is a plain `String` on the wire, so an origin that
        // names no contract records consumption under an empty one rather
        // than changing the shape of the document.
        agreement_id: origin.agreement_id.clone().unwrap_or_default(),
        subject: ReceiptSubject::from(&Subject {
            tenant: tenant.to_string(),
            key_id: ctx.accountable_key_id().map(str::to_string),
            agent: None,
        }),
        route: path.to_string(),
        config_revision: ctx.pipeline.config_revision.clone(),
    };

    // The receipt carries the billed units rather than everything the
    // attempt accrued. An outcome the operator's table says is free still
    // gets a receipt, with an empty units list: "not billed, because the
    // table says origin_5xx is free" is exactly the evidence a dispute
    // needs, and a receipt that was simply omitted would be
    // indistinguishable from a call that never happened.
    let units: Vec<ReceiptUnit> = billed.iter().map(ReceiptUnit::from).collect();

    // Built before the chain is touched, and returned whatever the chain
    // does. A receipt that could not be written is still a request whose
    // billable units the operator's table settled, and the queue is a
    // different durability mechanism from the ledger: losing one is not a
    // reason to lose the other too.
    let settled = SettledRequest {
        claim_id: facts.claim_id.clone(),
        route: path.to_string(),
        outcome,
        billed: billed.clone(),
    };

    let Some(chain) = runtime.chain.as_deref().filter(|chain| chain.is_writable()) else {
        // No chain, or one already shut. There is nowhere to write a
        // marker, so the counter is the only record left of this one, and
        // the posture still decides what that record says.
        take_failure_branch(runtime.failure_mode, None, tenant, &facts);
        return Some(settled);
    };

    let appended = chain.append(|seq, prev| {
        facts.claims(
            chain.node_id(),
            seq,
            prev,
            facts.claim_id.clone(),
            outcome_wire_name(outcome),
            units,
        )
    });

    match appended {
        Ok(appended) => {
            // The JWS is the portable half: the ledger stores the claims,
            // and this is the artifact a buyer can be handed. Nothing
            // publishes it yet, so it is emitted at `trace` rather than
            // dropped, and a signing failure is treated as a chain failure
            // above so an unsigned receipt can never reach the chain.
            tracing::trace!(
                claim_id = %appended.claims.claim_id,
                seq = appended.claims.seq,
                recorded = appended.recorded,
                receipt = %appended.token,
                "meter-runtime: receipt cut"
            );
            // Folded rather than doubled when the claim was already on the
            // chain, which is how four attempts at a flaky origin stay one
            // sale.
            chain
                .local_meter()
                .record_claim(&facts.claim_id, tenant, &billed);
        }
        Err(error) => {
            tracing::warn!(
                %error,
                claim_id = %facts.claim_id,
                tenant_id = %tenant,
                "meter-runtime: the receipt for a served request could not be chained"
            );
            take_failure_branch(runtime.failure_mode, Some(chain), tenant, &facts);
        }
    }

    Some(settled)
}

/// Write the marker that says a billable unit was owed to the durable usage
/// queue and never got there (WOR-2169).
///
/// The billing queue has no chain of its own, so the hole is recorded on the
/// one chain this node already keeps. The marker is an ordinary chained,
/// signed receipt with no units and a `usage_gap` outcome, so a later
/// verification walks straight through it and an operator reconciling a
/// provider invoice against the ledger can see exactly which claim went
/// unbilled.
///
/// Best effort by construction, and silently a no-op when there is no chain
/// to write to: this runs because a durable write already failed, so the
/// next one may fail too, and the counter is the record that survives either
/// way.
// The usage queue this marker stands in for only exists in a `payments`
// build, so the only production caller is gated. The unit test below is not.
#[cfg_attr(not(feature = "payments"), allow(dead_code))]
pub(crate) fn write_usage_gap_marker(ctx: &RequestContext, settled: Option<&SettledRequest>) {
    let Some(runtime) = ctx.pipeline.attestation.as_deref() else {
        return;
    };
    let Some(chain) = runtime.chain.as_deref() else {
        return;
    };
    let Some(origin) = resolved_origin(ctx) else {
        return;
    };

    // The claim the receipt used when there was one, so the marker and the
    // receipt name the same unit of work. The request id otherwise, which
    // is what the meter itself mints a claim from.
    let claim_id = settled.map_or_else(
        || ctx.request_id.to_string(),
        |settled| settled.claim_id.clone(),
    );
    let route = settled.map_or_else(String::new, |settled| settled.route.clone());

    let facts = ReceiptFacts {
        claim_id,
        agreement_id: origin.agreement_id.clone().unwrap_or_default(),
        subject: ReceiptSubject {
            tenant: ctx.tenant_id.to_string(),
            key_id: ctx.accountable_key_id().map(str::to_string),
            agent: None,
        },
        route,
        config_revision: ctx.pipeline.config_revision.clone(),
    };

    let marker = chain.append(|seq, prev| {
        facts.claims(
            chain.node_id(),
            seq,
            prev,
            format!("{}{USAGE_GAP_CLAIM_SUFFIX}", facts.claim_id),
            USAGE_GAP_OUTCOME.to_string(),
            Vec::new(),
        )
    });
    if let Err(error) = marker {
        tracing::warn!(
            %error,
            claim_id = %facts.claim_id,
            tenant_id = %ctx.tenant_id,
            "meter-runtime: the usage gap marker could not be written either; \
             sbproxy_usage_bridge_gap_total is the only record of this one"
        );
    }
}

/// Do what the operator said to do when the meter owes a record it cannot
/// write.
///
/// Matched exhaustively with no wildcard arm: a fifth posture is a fifth
/// answer to "what happens to revenue that went unbilled", and inheriting
/// one of these four would be this module deciding it on the operator's
/// behalf.
fn take_failure_branch(
    posture: FailureMode,
    chain: Option<&ReceiptChain>,
    tenant: &str,
    facts: &ReceiptFacts,
) {
    match posture {
        FailureMode::Degraded => {
            // Admit, and leave the hole provable. The marker is a chained,
            // signed entry like any other, so a later verification walks
            // straight through it and an operator reconciling an invoice
            // can see which call went unbilled and why.
            if let Some(chain) = chain {
                chain.write_gap_marker(facts);
            }
            sbproxy_meter::metrics::observe_chain_gap(tenant, FailurePosture::Degraded);
        }
        FailureMode::Closed => {
            // This request is already served and cannot be recalled. What
            // closing the chain buys is the next one: `preflight_refuses`
            // reads the flag in `response_filter`, before a body goes out.
            // Reaching here at all under `closed` means the chain died
            // between that preflight and this response.
            if let Some(chain) = chain {
                chain.close();
                chain.write_gap_marker(facts);
            }
            sbproxy_meter::metrics::observe_chain_gap(tenant, FailurePosture::Closed);
        }
        FailureMode::Open => {
            // Admit and claim nothing. Cheapest, and the least recoverable
            // after the fact: the counter is the whole record.
            sbproxy_meter::metrics::observe_chain_gap(tenant, FailurePosture::Open);
        }
        FailureMode::Observe => {
            // Record and never touch traffic. Identical to `open` in what
            // reaches the client, and separately countable so an operator
            // rolling metering out can tell a tuning run from a real hole.
            sbproxy_meter::metrics::observe_chain_gap(tenant, FailurePosture::Observe);
        }
    }
}

/// The attestation posture in force for the origin this request routed to.
fn resolved_origin(ctx: &RequestContext) -> Option<&ResolvedOriginAttestation> {
    ctx.origin_idx
        .and_then(|index| ctx.pipeline.origin_attestations.get(index))
}

/// Classify what happened in the only terms a billing rule cares about.
///
/// Ordered most specific first, because several of these are true at once
/// on a real request. A cache hit the client then abandoned is a
/// disconnect, not a hit; a refused request is a policy block that happens
/// to carry a status, and an operator prices those separately.
///
/// [`sbproxy_meter::BillableOutcome::Retry`] is not produced here. It is
/// one attempt of a call that was retried, not the sale. `record_response`
/// emits those attempts as their own events so the outcome table's
/// Collapse answer can fold them under the same `claim_id`. The event this
/// function names is the final attempt: a 200 after failover is delivered,
/// and a retried call that ends in 500 is an origin failure.
fn classify_outcome(
    ctx: &RequestContext,
    status: u16,
    client_disconnected: bool,
) -> BillableOutcome {
    if client_disconnected {
        return BillableOutcome::ClientDisconnected;
    }
    if matches!(
        ctx.admin_cache_status,
        AdminCacheStatus::Hit | AdminCacheStatus::SemanticHit
    ) {
        return BillableOutcome::CacheHit;
    }
    if ctx.deny_reason.is_some() {
        // The proxy refused it, so the origin never did any work. The 429
        // split matters because an operator commonly prices a policy block
        // and a rate limit differently: one is the buyer asking for
        // something they may not have, the other is the buyer asking too
        // fast for something they may.
        return if status == 429 {
            BillableOutcome::RateLimited
        } else {
            BillableOutcome::PolicyBlocked
        };
    }
    if status == 429 {
        return BillableOutcome::RateLimited;
    }
    if (400..=499).contains(&status) {
        return BillableOutcome::Origin4xx;
    }
    if status >= 500 {
        return BillableOutcome::Origin5xx;
    }
    BillableOutcome::Delivered
}

/// Extra origin or provider attempts after the first.
///
/// `admin_retry_count` already folds HTTP origin retries and extra AI
/// attempts. A failover flag with that count still at zero is a handoff
/// that never incremented a counter, and still costs one collapsed
/// attempt.
fn prior_retry_count(ctx: &RequestContext) -> u32 {
    let retried = ctx.admin_retry_count();
    if retried > 0 {
        retried
    } else if ctx.admin_failover_engaged() {
        1
    } else {
        0
    }
}

/// One metered pass: the tenant, the route, the claim, the units, and
/// which attempt this was.
fn metered_event(
    ctx: &RequestContext,
    path: &str,
    outcome: BillableOutcome,
    units: Vec<Unit>,
) -> MeteredEvent {
    MeteredEvent {
        subject: Subject {
            tenant: ctx.tenant_id.to_string(),
            key_id: ctx.accountable_key_id().map(str::to_string),
            agent: None,
        },
        route: path.to_string(),
        // A plain `String` on this type, and empty because there is no
        // request-side digest to put in it. See `ReceiptFacts::claims`.
        request_digest: String::new(),
        response_digest: None,
        outcome,
        units,
        claim_id: ctx.request_id.to_string(),
    }
}

/// The final attempt, preceded by one Retry event per extra attempt.
///
/// Disconnects, cache hits, and proxy refusals are not origin retries, so
/// they stay a single event even if a counter happened to be set.
fn attempt_events(
    ctx: &RequestContext,
    _method: &str,
    path: &str,
    outcome: BillableOutcome,
    units: Vec<Unit>,
) -> Vec<MeteredEvent> {
    let retries = if ctx.deny_reason.is_some()
        || matches!(
            outcome,
            BillableOutcome::ClientDisconnected | BillableOutcome::CacheHit
        ) {
        0
    } else {
        prior_retry_count(ctx)
    };
    let mut events = Vec::with_capacity(retries as usize + 1);
    for _ in 0..retries {
        events.push(metered_event(
            ctx,
            path,
            BillableOutcome::Retry,
            units.clone(),
        ));
    }
    events.push(metered_event(ctx, path, outcome, units));
    events
}

/// Resolve every configured unit rule against this request.
///
/// All three resolvers run, in source order, and nothing is ever summed
/// across them. A route priced by a weight and reported by a header
/// contributes two lines to the receipt, because the two have different
/// provenance and one number that is their sum has parts nobody can check
/// separately. The breakdown is the product.
fn resolve_units(
    runtime: &AttestationRuntime,
    ctx: &RequestContext,
    method: &str,
    path: &str,
) -> Vec<Unit> {
    let measurement = Measurement {
        bytes_in: ctx.request_body_bytes,
        bytes_out: ctx.response_body_bytes,
        // Saturating rather than truncating. A duration that wrapped would
        // bill a very long request as a very short one, which is the shape
        // of error that still looks plausible on a dashboard.
        duration_ms: ctx
            .request_start
            .map(|start| u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0),
    };

    let mut units = resolve_measured(&runtime.measured, &measurement);
    units.extend(runtime.route_weights.resolve(method, path));
    units.extend(
        resolve_origin_headers(&runtime.origin_headers, |header| {
            observed_origin_header(&ctx.meter_origin_headers, header).map(str::to_string)
        })
        .into_iter()
        .map(|resolved| resolved.unit),
    );
    units
}

/// Parse a 32-byte Ed25519 seed from hex.
///
/// `None` for anything that is not exactly 32 bytes of hex, which the
/// caller turns into a chain that cannot sign rather than into a panic:
/// this is a runtime that must not assume its input was validated
/// elsewhere.
fn seed_bytes(seed_hex: &str) -> Option<[u8; 32]> {
    hex::decode(seed_hex.trim())
        .ok()?
        .as_slice()
        .try_into()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_config::types::{
        AttestationBillableConfig, AttestationConfig, AttestationLedgerConfig,
        AttestationMeasuredConfig, AttestationMeasuredQuantity, AttestationOriginHeaderConfig,
        AttestationQueueConfig, AttestationRole, AttestationRouteWeightConfig, BillableRule,
        WebBotAuthConfig, ATTESTATION_SIGN_WITH_WEB_BOT_AUTH,
    };
    use sbproxy_meter::ledger::LedgerEntry;
    use sbproxy_meter::{verify_ledger, verifying_key_from_seed_hex};
    use std::sync::Arc;

    /// The revision every fixture is lowered under.
    const REVISION: &str = "9f2c41a0be77";

    /// The seed both the ledger signature and the receipt JWS use here.
    const SEED: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    /// The node every fixture chain speaks for.
    const NODE: &str = "node-a";

    /// The route every fixture request takes.
    const METHOD: &str = "POST";
    /// Matches the fixture's route weight exactly.
    const PATH: &str = "/v1/search";

    fn signer() -> WebBotAuthConfig {
        WebBotAuthConfig {
            key_id: "sbproxy-2026".to_string(),
            ed25519_seed_hex: SEED.to_string(),
            directory_url: None,
        }
    }

    fn complete_billable() -> AttestationBillableConfig {
        AttestationBillableConfig {
            delivered: Some(BillableRule::Yes),
            client_disconnected: Some(BillableRule::Partial),
            origin_4xx: Some(BillableRule::No),
            origin_5xx: Some(BillableRule::No),
            policy_blocked: Some(BillableRule::No),
            rate_limited: Some(BillableRule::No),
            cache_hit: Some(BillableRule::Yes),
            retry: Some(BillableRule::Collapse),
        }
    }

    /// A complete receipt-writing block pointed at `ledger_path`.
    fn attestation_config(ledger_path: &Path, failure_mode: FailureMode) -> AttestationConfig {
        AttestationConfig {
            role: AttestationRole::Receipt,
            failure_mode,
            sign_with: Some(ATTESTATION_SIGN_WITH_WEB_BOT_AUTH.to_string()),
            queue: Some(AttestationQueueConfig {
                path: ledger_path
                    .parent()
                    .expect("the fixture ledger has a parent")
                    .join("claims.q")
                    .display()
                    .to_string(),
                max_entries: 16,
            }),
            ledger: Some(AttestationLedgerConfig {
                path: ledger_path.display().to_string(),
            }),
            billable: Some(complete_billable()),
            measured: vec![AttestationMeasuredConfig {
                name: "egress_kib".to_string(),
                quantity: AttestationMeasuredQuantity::BytesOut,
                per: 1024,
            }],
            route_weights: vec![AttestationRouteWeightConfig {
                name: "search_call".to_string(),
                method: Some(METHOD.to_string()),
                path: PATH.to_string(),
                weight: 5,
            }],
            origin_headers: vec![AttestationOriginHeaderConfig {
                name: "result_row".to_string(),
                header: "X-Rows-Returned".to_string(),
            }],
            ..AttestationConfig::default()
        }
    }

    fn runtime(ledger_path: &Path, failure_mode: FailureMode) -> Arc<AttestationRuntime> {
        crate::attestation::prepare_attestation(
            Some(&attestation_config(ledger_path, failure_mode)),
            Some(&signer()),
            REVISION,
            NODE,
        )
        .expect("a complete block builds")
        .expect("a receipt role yields a runtime")
    }

    /// A request context pinned to a pipeline whose one origin writes
    /// receipts.
    fn context(runtime: Arc<AttestationRuntime>) -> RequestContext {
        context_for_role(runtime, AttestationRole::Receipt)
    }

    fn context_for_role(runtime: Arc<AttestationRuntime>, role: AttestationRole) -> RequestContext {
        // Functional update rather than build-then-assign: the pipeline has
        // cfg-gated fields, and `clippy::field_reassign_with_default`
        // rejects the other shape.
        let pipeline = crate::pipeline::CompiledPipeline {
            attestation: Some(runtime),
            origin_attestations: vec![ResolvedOriginAttestation {
                role,
                agreement_id: Some("agr-2026-04".to_string()),
            }],
            config_revision: REVISION.to_string(),
            ..crate::pipeline::CompiledPipeline::default()
        };

        let mut ctx = RequestContext::new();
        ctx.pipeline = Arc::new(pipeline);
        ctx.origin_idx = Some(0);
        ctx.tenant_id = compact_str::CompactString::new("acme");
        ctx.request_id = compact_str::CompactString::new("01J9ZQ8N4T7WYQ4CQ9K5R2VXAB");
        ctx.request_body_bytes = 512;
        ctx.response_body_bytes = 12_043;
        ctx.meter_origin_headers = vec![("X-Rows-Returned".to_string(), "47".to_string())];
        ctx
    }

    /// A response carrying whatever the origin reported for the rows
    /// header.
    fn response(rows: Option<&str>) -> pingora_http::ResponseHeader {
        let mut header =
            pingora_http::ResponseHeader::build(200, Some(2)).expect("a 200 header builds");
        if let Some(rows) = rows {
            header
                .insert_header("X-Rows-Returned", rows)
                .expect("the fixture header is valid");
        }
        header
            .insert_header("X-Not-Metered", "ignored")
            .expect("the fixture header is valid");
        header
    }

    /// Every entry on a chain file, oldest first.
    fn entries(path: &Path) -> Vec<LedgerEntry<ChainedReceipt>> {
        let text = std::fs::read_to_string(path).expect("the chain file is readable");
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("every line is an entry"))
            .collect()
    }

    #[test]
    fn a_chain_on_a_good_path_is_writable_and_one_on_a_directory_is_not() {
        let dir = tempfile::tempdir().expect("temp dir");

        let good = ReceiptChain::open(&dir.path().join("receipts.ndjson"), SEED, "kid", NODE);
        assert!(good.is_writable());
        assert_eq!(good.node_id(), NODE);
        assert!(good.segment().is_some());

        // A path that is a directory cannot be a ledger. It must not panic
        // and it must not be a boot failure: `failure_mode` owns what
        // happens to traffic from here.
        let occupied = dir.path().join("occupied");
        std::fs::create_dir_all(&occupied).expect("make the path a directory");
        let bad = ReceiptChain::open(&occupied, SEED, "kid", NODE);
        assert!(!bad.is_writable());
        assert!(bad.segment().is_none());
    }

    #[test]
    fn a_seed_that_is_not_thirty_two_bytes_of_hex_leaves_the_chain_unwritable() {
        let dir = tempfile::tempdir().expect("temp dir");
        let chain =
            ReceiptChain::open(&dir.path().join("receipts.ndjson"), "nonsense", "kid", NODE);
        assert!(
            !chain.is_writable(),
            "a chain that cannot sign writes log lines, not receipts"
        );
    }

    #[test]
    fn a_receipt_is_written_and_its_sequence_matches_the_entry_carrying_it() {
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = dir.path().join("receipts.ndjson");
        let ctx = context(runtime(&ledger_path, FailureMode::Degraded));

        let _ = record_response(&ctx, METHOD, PATH, 200, false);

        let written = entries(&ledger_path);
        assert_eq!(written.len(), 1, "one served request, one receipt");
        let entry = &written[0];
        let claims = &entry.event.0;
        assert_eq!(
            claims.seq, entry.seq,
            "the receipt cannot disagree with its own entry"
        );
        assert_eq!(claims.prev, entry.prev_hash);
        assert_eq!(claims.node_id, NODE);
        assert_eq!(claims.outcome, "delivered");
        assert_eq!(claims.agreement_id, "agr-2026-04");
        assert_eq!(claims.subject.tenant, "acme");
        assert_eq!(claims.route, PATH);
        assert_eq!(claims.config_revision, REVISION);
        assert!(
            entry.signature.is_some(),
            "the ledger is signed on the same key family as the receipt"
        );
    }

    #[test]
    fn three_resolvers_produce_three_lines_and_never_their_sum() {
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = dir.path().join("receipts.ndjson");
        let ctx = context(runtime(&ledger_path, FailureMode::Degraded));

        let _ = record_response(&ctx, METHOD, PATH, 200, false);

        let written = entries(&ledger_path);
        let units = &written[0].event.0.units;
        let lines: Vec<(&str, u64, &str)> = units
            .iter()
            .map(|unit| (unit.name.as_str(), unit.count, unit.source.as_str()))
            .collect();
        assert_eq!(
            lines,
            vec![
                ("egress_kib", 12, "measured"),
                ("search_call", 5, "route_weight"),
                ("result_row", 47, "origin_header"),
            ],
            "64 is not an answer anybody can dispute a part of"
        );
    }

    #[test]
    fn a_second_receipt_chains_onto_the_first() {
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = dir.path().join("receipts.ndjson");
        let attestation = runtime(&ledger_path, FailureMode::Degraded);

        let first = context(Arc::clone(&attestation));
        let _ = record_response(&first, METHOD, PATH, 200, false);

        let mut second = context(Arc::clone(&attestation));
        second.request_id = compact_str::CompactString::new("01J9ZQ8N4T7WYQ4CQ9K5R2VXCD");
        let _ = record_response(&second, METHOD, PATH, 200, false);

        let written = entries(&ledger_path);
        assert_eq!(written.len(), 2);
        assert_eq!(written[1].event.0.seq, 1);
        assert_eq!(
            written[1].event.0.prev, written[0].entry_hash,
            "the second receipt names the first entry's digest"
        );
        assert_eq!(written[1].prev_hash, written[0].entry_hash);
    }

    #[test]
    fn a_chain_this_module_wrote_verifies_against_the_key_it_was_written_with() {
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = dir.path().join("receipts.ndjson");
        let attestation = runtime(&ledger_path, FailureMode::Degraded);

        for index in 0..4u32 {
            let mut ctx = context(Arc::clone(&attestation));
            ctx.request_id = compact_str::CompactString::new(format!("claim-{index}"));
            let _ = record_response(&ctx, METHOD, PATH, 200, false);
        }

        let unkeyed =
            verify_ledger::<ChainedReceipt>(&ledger_path, None).expect("the chain is readable");
        assert!(unkeyed.ok, "{unkeyed:?}");
        assert_eq!(unkeyed.entries, 4);

        let verifying = verifying_key_from_seed_hex(SEED).expect("the seed derives a public key");
        let keyed = verify_ledger::<ChainedReceipt>(&ledger_path, Some(&verifying))
            .expect("the chain is readable");
        assert!(
            keyed.ok,
            "every entry is signed by the seed the chain was opened with: {keyed:?}"
        );
    }

    #[test]
    fn every_entry_carries_the_sequence_it_was_filed_under() {
        // The invariant the sequencing lock exists to hold. Read back off
        // disk rather than off the writer, because a writer agreeing with
        // itself proves nothing.
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = dir.path().join("receipts.ndjson");
        let attestation = runtime(&ledger_path, FailureMode::Degraded);

        for index in 0..8u32 {
            let mut ctx = context(Arc::clone(&attestation));
            ctx.request_id = compact_str::CompactString::new(format!("claim-{index}"));
            let _ = record_response(&ctx, METHOD, PATH, 200, false);
        }

        let written = entries(&ledger_path);
        assert_eq!(written.len(), 8);
        let mut running = "0".repeat(64);
        for (position, entry) in written.iter().enumerate() {
            let claims = &entry.event.0;
            assert_eq!(claims.seq, entry.seq, "entry {position}");
            assert_eq!(u64::try_from(position).expect("small"), entry.seq);
            assert_eq!(claims.prev, running, "entry {position}");
            assert_eq!(entry.prev_hash, running, "entry {position}");
            running.clone_from(&entry.entry_hash);
        }
    }

    #[test]
    fn concurrent_writers_never_fork_the_chain() {
        // The sequential test above cannot see the defect this one exists
        // for. Reading the head and then appending is two operations, and
        // without the sequencing lock two requests that read the same head
        // both write that sequence number, leaving a file with two entries
        // claiming the same position and two claiming the same predecessor.
        //
        // That is a forked chain, and it is the precise failure the whole
        // design exists to prevent: once two entries share a sequence, the
        // chain no longer proves an absence, so "I made calls you never
        // credited" stops being answerable.
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = dir.path().join("receipts.ndjson");
        let attestation = runtime(&ledger_path, FailureMode::Degraded);

        const WRITERS: u32 = 24;
        std::thread::scope(|scope| {
            for index in 0..WRITERS {
                let attestation = Arc::clone(&attestation);
                scope.spawn(move || {
                    let mut ctx = context(attestation);
                    ctx.request_id = compact_str::CompactString::new(format!("claim-{index}"));
                    let _ = record_response(&ctx, METHOD, PATH, 200, false);
                });
            }
        });

        let written = entries(&ledger_path);
        assert_eq!(
            written.len(),
            WRITERS as usize,
            "every writer must land exactly one entry"
        );

        // Sequences are a permutation of 0..WRITERS with no repeats, and
        // each entry's own claims agree with the slot it occupies.
        let mut seen: Vec<u64> = written.iter().map(|entry| entry.seq).collect();
        seen.sort_unstable();
        let expected: Vec<u64> = (0..u64::from(WRITERS)).collect();
        assert_eq!(
            seen, expected,
            "a repeated sequence number is a forked chain"
        );

        let mut running = "0".repeat(64);
        for (position, entry) in written.iter().enumerate() {
            assert_eq!(entry.event.0.seq, entry.seq, "entry {position}");
            assert_eq!(entry.event.0.prev, running, "entry {position}");
            assert_eq!(entry.prev_hash, running, "entry {position}");
            running.clone_from(&entry.entry_hash);
        }

        // And the shipped verifier agrees, which is the only opinion that
        // matters to a buyer holding the file.
        let verdict = sbproxy_meter::verify_ledger::<ChainedReceipt>(&ledger_path, None)
            .expect("the chain is readable");
        assert!(verdict.ok, "chain must verify: {verdict:?}");
        assert_eq!(verdict.entries, u64::from(WRITERS));
    }

    #[test]
    fn a_free_outcome_still_gets_a_receipt_with_no_billed_units() {
        // The operator's table says `origin_5xx` is free. "Not billed,
        // because the table says so" is the evidence a dispute needs; an
        // omitted receipt is indistinguishable from a call that never
        // happened.
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = dir.path().join("receipts.ndjson");
        let ctx = context(runtime(&ledger_path, FailureMode::Degraded));

        let _ = record_response(&ctx, METHOD, PATH, 503, false);

        let written = entries(&ledger_path);
        assert_eq!(written.len(), 1);
        assert_eq!(written[0].event.0.outcome, "origin_5xx");
        assert!(written[0].event.0.units.is_empty());
    }

    // --- Capturing the response half ---

    #[test]
    fn only_the_configured_headers_are_carried_out_of_response_filter() {
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = dir.path().join("receipts.ndjson");
        let mut ctx = context(runtime(&ledger_path, FailureMode::Degraded));
        ctx.meter_origin_headers.clear();

        capture_origin_headers(&mut ctx, &response(Some(" 47 ")));

        assert_eq!(
            ctx.meter_origin_headers,
            vec![("X-Rows-Returned".to_string(), " 47 ".to_string())],
            "the raw value is the evidence; nothing here trims or normalises it"
        );
    }

    #[test]
    fn a_header_the_origin_never_sent_is_absent_rather_than_empty() {
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = dir.path().join("receipts.ndjson");
        let mut ctx = context(runtime(&ledger_path, FailureMode::Degraded));
        ctx.meter_origin_headers.clear();

        capture_origin_headers(&mut ctx, &response(None));
        assert!(ctx.meter_origin_headers.is_empty());

        let _ = record_response(&ctx, METHOD, PATH, 200, false);
        let written = entries(&ledger_path);
        let claimed = &written[0].event.0.units[2];
        assert_eq!(claimed.count, 0);
        let rendered = serde_json::to_value(claimed).expect("the unit serialises");
        assert!(
            rendered["evidence"].get("raw").is_none(),
            "a receipt must not show a value the origin never sent: {rendered}"
        );
    }

    #[test]
    fn an_origin_outside_the_role_captures_nothing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = dir.path().join("receipts.ndjson");
        let mut ctx = context_for_role(
            runtime(&ledger_path, FailureMode::Degraded),
            AttestationRole::Claim,
        );
        ctx.meter_origin_headers.clear();

        capture_origin_headers(&mut ctx, &response(Some("47")));

        assert!(ctx.meter_origin_headers.is_empty());
    }

    // --- Outcome classification ---

    #[test]
    fn a_client_that_hung_up_outranks_everything_else() {
        let mut ctx = RequestContext::new();
        ctx.record_admin_cache_status(AdminCacheStatus::Hit);
        ctx.deny_reason = Some("rate_limit".to_string());
        assert_eq!(
            classify_outcome(&ctx, 429, true),
            BillableOutcome::ClientDisconnected
        );
    }

    #[test]
    fn a_cache_hit_outranks_the_status_that_carried_it() {
        let mut ctx = RequestContext::new();
        ctx.record_admin_cache_status(AdminCacheStatus::Hit);
        assert_eq!(
            classify_outcome(&ctx, 200, false),
            BillableOutcome::CacheHit
        );

        let mut semantic = RequestContext::new();
        semantic.record_admin_cache_status(AdminCacheStatus::SemanticHit);
        assert_eq!(
            classify_outcome(&semantic, 200, false),
            BillableOutcome::CacheHit
        );
    }

    #[test]
    fn a_proxy_refusal_splits_on_the_status_it_carried() {
        let mut limited = RequestContext::new();
        limited.deny_reason = Some("rate_limit".to_string());
        assert_eq!(
            classify_outcome(&limited, 429, false),
            BillableOutcome::RateLimited
        );

        let mut blocked = RequestContext::new();
        blocked.deny_reason = Some("ai_crawl_payment".to_string());
        assert_eq!(
            classify_outcome(&blocked, 402, false),
            BillableOutcome::PolicyBlocked,
            "the proxy refused it, so the origin never did any work"
        );
    }

    #[test]
    fn an_upstream_status_classifies_when_nothing_more_specific_applies() {
        let ctx = RequestContext::new();
        assert_eq!(
            classify_outcome(&ctx, 429, false),
            BillableOutcome::RateLimited,
            "an upstream that rate limited us is still a rate limit"
        );
        assert_eq!(
            classify_outcome(&ctx, 404, false),
            BillableOutcome::Origin4xx
        );
        assert_eq!(
            classify_outcome(&ctx, 500, false),
            BillableOutcome::Origin5xx
        );
        assert_eq!(
            classify_outcome(&ctx, 200, false),
            BillableOutcome::Delivered
        );
        assert_eq!(
            classify_outcome(&ctx, 304, false),
            BillableOutcome::Delivered,
            "a redirect or a not-modified is a call that was served"
        );
    }

    #[test]
    fn a_successful_retry_or_failover_is_still_delivered() {
        let mut retried = RequestContext::new();
        retried.retry_count = 1;
        assert_eq!(
            classify_outcome(&retried, 200, false),
            BillableOutcome::Delivered,
            "Retry is an intermediate attempt, not the sale"
        );

        let mut ai_failover = RequestContext::new();
        ai_failover.record_admin_ai_attempt("bad-key");
        ai_failover.record_admin_ai_attempt("good-key");
        assert_eq!(
            classify_outcome(&ai_failover, 200, false),
            BillableOutcome::Delivered,
            "AI fallback_chain that lands on a later provider still sold the answer"
        );

        let mut fallback = RequestContext::new();
        fallback.fallback_triggered = true;
        assert_eq!(
            classify_outcome(&fallback, 200, false),
            BillableOutcome::Delivered
        );
    }

    #[test]
    fn extra_attempts_are_retry_events_folded_under_the_same_claim() {
        let mut retried = RequestContext::new();
        retried.retry_count = 2;
        retried.request_id = compact_str::CompactString::new("claim-retry");
        let events = attempt_events(
            &retried,
            METHOD,
            PATH,
            BillableOutcome::Delivered,
            Vec::new(),
        );
        assert_eq!(
            events.iter().map(|event| event.outcome).collect::<Vec<_>>(),
            vec![
                BillableOutcome::Retry,
                BillableOutcome::Retry,
                BillableOutcome::Delivered,
            ],
            "prior attempts exist so collapse has something to fold"
        );
        assert!(
            events
                .iter()
                .all(|event| event.claim_id == retried.request_id.as_str()),
            "retries share the claim so they settle as one sale"
        );

        let mut failed = RequestContext::new();
        failed.retry_count = 1;
        let exhausted = attempt_events(
            &failed,
            METHOD,
            PATH,
            BillableOutcome::Origin5xx,
            Vec::new(),
        );
        assert_eq!(
            exhausted
                .iter()
                .map(|event| event.outcome)
                .collect::<Vec<_>>(),
            vec![BillableOutcome::Retry, BillableOutcome::Origin5xx],
            "a call that never succeeded keeps the origin error as the sale"
        );
    }

    #[test]
    fn a_successful_retry_still_bills_under_collapse() {
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = dir.path().join("receipts.ndjson");
        let mut ctx = context(runtime(&ledger_path, FailureMode::Degraded));
        ctx.retry_count = 1;

        let settled = record_response(&ctx, METHOD, PATH, 200, false)
            .expect("a receipt-writing origin settles something");

        assert_eq!(
            settled.outcome,
            BillableOutcome::Delivered,
            "the signed receipt names the sale, not the collapsed attempts"
        );
        assert!(
            !settled.billed.is_empty(),
            "billable.retry: collapse drops Retry attempts, not the delivered sale"
        );
        let written = entries(&ledger_path);
        assert_eq!(written.len(), 1);
        assert_eq!(written[0].event.0.outcome, "delivered");
        assert!(
            !written[0].event.0.units.is_empty(),
            "the chain entry carries the billed units, not an emptied collapse"
        );
    }

    #[test]
    fn a_retry_that_still_fails_keeps_the_origin_error() {
        let mut ctx = RequestContext::new();
        ctx.retry_count = 2;
        ctx.record_admin_ai_attempt("primary");
        ctx.record_admin_ai_attempt("backup");
        assert_eq!(
            classify_outcome(&ctx, 500, false),
            BillableOutcome::Origin5xx,
            "exhausted retries that end in 5xx are an origin failure"
        );
        assert_eq!(
            classify_outcome(&ctx, 404, false),
            BillableOutcome::Origin4xx
        );
    }

    // --- What the meter hands downstream (WOR-2169) ---

    #[test]
    fn the_settlement_handed_downstream_is_the_one_the_receipt_was_cut_from() {
        // The usage bridge bills from this value rather than re-deriving
        // it. Two derivations of "is this billable" would eventually
        // disagree, and the disagreement would be a charge on an invoice
        // that the signed receipt beside it says is free.
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = dir.path().join("receipts.ndjson");
        let ctx = context(runtime(&ledger_path, FailureMode::Degraded));

        let settled = record_response(&ctx, METHOD, PATH, 200, false)
            .expect("a receipt-writing origin settles something");

        assert_eq!(settled.claim_id, ctx.request_id.as_str());
        assert_eq!(settled.route, PATH);
        assert_eq!(settled.outcome, BillableOutcome::Delivered);

        // And it agrees, name for name and count for count, with the units
        // that actually reached the signed receipt.
        let receipt = &entries(&ledger_path)[0].event.0;
        let receipt_units: Vec<(String, u64)> = receipt
            .units
            .iter()
            .map(|unit| (unit.name.clone(), unit.count))
            .collect();
        let settled_units: Vec<(String, u64)> = settled
            .billed
            .iter()
            .map(|unit| (unit.name.clone(), unit.count))
            .collect();
        assert_eq!(settled_units, receipt_units);
        assert!(!settled_units.is_empty(), "the fixture route is priced");
    }

    // --- Both sides of the divergence comparison (WOR-2324) ---

    #[test]
    fn a_chained_receipt_reports_the_units_the_counted_side_already_reported() {
        // The two halves of `sbproxy_meter_divergence_total`. The counted
        // half is `observe_settled_event`, which is handed
        // `SettledRequest::billed`; the chained half is this method, read
        // off the document that reached the disk. They have to name the
        // same tenant and add up to the same number, or the counter reports
        // a disagreement that only its own wiring created.
        //
        // Before this was implemented the method returned `None`, the
        // chained side of every window was empty, and a healthy tenant
        // diverged on every sweep.
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = dir.path().join("receipts.ndjson");
        let ctx = context(runtime(&ledger_path, FailureMode::Degraded));

        let settled = record_response(&ctx, METHOD, PATH, 200, false)
            .expect("a receipt-writing origin settles something");
        let counted: u64 = settled.billed.iter().map(|unit| unit.count).sum();
        assert!(counted > 0, "the fixture route is priced");

        // Bound before it is borrowed from: the contribution borrows the
        // receipt's own strings, so indexing a temporary vector here would
        // drop the entry out from under it.
        let written = entries(&ledger_path);
        let chained = written[0]
            .event
            .chain_contribution()
            .expect("a receipt is the payload the divergence check is built on");

        assert_eq!(
            chained.tenant_id, "acme",
            "the contribution is charged to the receipt's own subject"
        );
        assert_eq!(
            chained.units, counted,
            "the chained side has to add up to exactly what the counted side reported"
        );
    }

    #[test]
    fn a_gap_marker_contributes_nothing_so_the_receipt_it_stands_in_for_stays_unbalanced() {
        // The half that keeps the fix from silencing the real signal. A
        // request whose receipt could not be chained still counted its
        // units, and the marker written in its place carries none, so the
        // tenant ends the window counted-but-not-chained. That imbalance is
        // the thing `sbproxy_meter_divergence_total` is for.
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = dir.path().join("receipts.ndjson");
        let runtime = runtime(&ledger_path, FailureMode::Degraded);
        let ctx = context(runtime.clone());

        runtime
            .chain
            .as_deref()
            .expect("the fixture opens a chain")
            .fail_next_append();

        let settled = record_response(&ctx, METHOD, PATH, 200, false)
            .expect("a receipt-writing origin settles something");
        let counted: u64 = settled.billed.iter().map(|unit| unit.count).sum();
        assert!(counted > 0, "the fixture route is priced");

        let written = entries(&ledger_path);
        assert_eq!(written.len(), 1, "only the marker landed: {written:?}");
        let contribution = written[0]
            .event
            .chain_contribution()
            .expect("a marker is still a receipt");
        assert_eq!(
            contribution.units, 0,
            "a marker carries no units, so nothing balances the receipt that was lost"
        );
        assert_ne!(
            contribution.units, counted,
            "a marker must never look like the receipt it replaced"
        );
    }

    #[test]
    fn an_outcome_the_table_prices_at_free_settles_with_nothing_billable() {
        // The fixture table answers `origin_5xx: no`. Nothing downstream
        // needs a rule about 5xx responses: the empty list is the rule,
        // and it came from the operator's document.
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = dir.path().join("receipts.ndjson");
        let ctx = context(runtime(&ledger_path, FailureMode::Degraded));

        let settled = record_response(&ctx, METHOD, PATH, 500, false)
            .expect("a receipt-writing origin settles something");

        assert_eq!(settled.outcome, BillableOutcome::Origin5xx);
        assert!(
            settled.billed.is_empty(),
            "the table says origin_5xx is free: {:?}",
            settled.billed
        );
    }

    #[test]
    fn an_origin_that_writes_no_receipts_settles_nothing_at_all() {
        // No receipt means no outcome table ran, so there is no operator
        // answer about what is billable and nothing downstream may invent
        // one.
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = dir.path().join("receipts.ndjson");
        let ctx = context_for_role(
            runtime(&ledger_path, FailureMode::Degraded),
            AttestationRole::Claim,
        );

        assert!(record_response(&ctx, METHOD, PATH, 200, false).is_none());
    }

    #[test]
    fn a_usage_gap_marker_cannot_collide_with_the_receipt_or_with_a_chain_gap() {
        // Both markers key off the same claim, and the chain deduplicates
        // on that key. A shared suffix would mean a request that lost both
        // its receipt and its billable unit filed the second marker under
        // a key the first already occupied, and the second would vanish.
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = dir.path().join("receipts.ndjson");
        let ctx = context(runtime(&ledger_path, FailureMode::Degraded));

        let settled = record_response(&ctx, METHOD, PATH, 200, false).expect("a receipt is cut");
        write_usage_gap_marker(&ctx, Some(&settled));

        let written = entries(&ledger_path);
        assert_eq!(written.len(), 2, "the receipt, then the usage gap marker");

        let receipt = &written[0].event.0;
        let marker = &written[1].event.0;
        assert_eq!(receipt.claim_id, settled.claim_id);
        assert_eq!(
            marker.claim_id,
            format!("{}{USAGE_GAP_CLAIM_SUFFIX}", settled.claim_id)
        );
        assert_ne!(
            marker.claim_id,
            format!("{}{GAP_CLAIM_SUFFIX}", settled.claim_id),
            "a usage gap and a chain gap are different holes and cannot share a key"
        );
        assert_eq!(marker.outcome, USAGE_GAP_OUTCOME);
        assert!(
            marker.units.is_empty(),
            "a gap marker records an absence, never a charge"
        );
        assert_eq!(marker.route, PATH, "the route whose unit went unbilled");
        assert_eq!(marker.subject.tenant, "acme", "the tenant it was owed to");

        // It chains like any other entry, so a buyer verifying the file
        // walks straight through it.
        assert_eq!(marker.seq, 1);
        assert_eq!(marker.prev, written[0].entry_hash);
        assert!(written[1].signature.is_some(), "the marker is signed too");

        let verifying = verifying_key_from_seed_hex(SEED).expect("the seed derives a public key");
        let result = verify_ledger::<ChainedReceipt>(&ledger_path, Some(&verifying))
            .expect("the chain is readable");
        assert!(
            result.ok,
            "a chain carrying a usage gap marker still verifies: {result:?}"
        );
        assert_eq!(result.entries, 2);
    }

    // --- Failure postures ---

    #[test]
    fn a_forced_failure_under_degraded_leaves_a_signed_gap_marker_on_the_chain() {
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = dir.path().join("receipts.ndjson");
        let attestation = runtime(&ledger_path, FailureMode::Degraded);
        let ctx = context(Arc::clone(&attestation));

        attestation
            .chain
            .as_deref()
            .expect("a receipt role opens a chain")
            .fail_next_append();
        let _ = record_response(&ctx, METHOD, PATH, 200, false);

        let written = entries(&ledger_path);
        assert_eq!(written.len(), 1, "the receipt failed, the marker landed");
        let marker = &written[0].event.0;
        assert_eq!(marker.outcome, CHAIN_GAP_OUTCOME);
        assert!(
            marker.units.is_empty(),
            "a marker records that nothing was billed, not a number nobody counted"
        );
        assert_eq!(marker.route, PATH, "the route that went unbilled");
        assert_eq!(marker.subject.tenant, "acme", "the tenant it was owed to");
        assert!(
            marker.claim_id.ends_with(GAP_CLAIM_SUFFIX),
            "a marker filed under the bare claim id would dedup away the retry that fixed it: {}",
            marker.claim_id
        );
        assert!(written[0].signature.is_some(), "the marker is signed too");
    }

    #[test]
    fn a_gap_marker_chains_and_the_file_still_verifies() {
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = dir.path().join("receipts.ndjson");
        let attestation = runtime(&ledger_path, FailureMode::Degraded);

        let first = context(Arc::clone(&attestation));
        let _ = record_response(&first, METHOD, PATH, 200, false);

        let mut failing = context(Arc::clone(&attestation));
        failing.request_id = compact_str::CompactString::new("01J9ZQ8N4T7WYQ4CQ9K5R2VXCD");
        attestation
            .chain
            .as_deref()
            .expect("a receipt role opens a chain")
            .fail_next_append();
        let _ = record_response(&failing, METHOD, PATH, 200, false);

        let written = entries(&ledger_path);
        assert_eq!(written.len(), 2);
        assert_eq!(written[1].event.0.outcome, CHAIN_GAP_OUTCOME);
        assert_eq!(
            written[1].event.0.prev, written[0].entry_hash,
            "a marker is a link like any other"
        );

        let verifying = verifying_key_from_seed_hex(SEED).expect("the seed derives a public key");
        let result = verify_ledger::<ChainedReceipt>(&ledger_path, Some(&verifying))
            .expect("the chain is readable");
        assert!(
            result.ok,
            "a chain with a gap marker in it still verifies: {result:?}"
        );
        assert_eq!(result.entries, 2);
    }

    #[test]
    fn a_forced_failure_under_closed_shuts_the_chain_for_the_next_request() {
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = dir.path().join("receipts.ndjson");
        let attestation = runtime(&ledger_path, FailureMode::Closed);
        let ctx = context(Arc::clone(&attestation));

        assert!(!preflight_refuses(&ctx), "a healthy chain refuses nothing");

        attestation
            .chain
            .as_deref()
            .expect("a receipt role opens a chain")
            .fail_next_append();
        let _ = record_response(&ctx, METHOD, PATH, 200, false);

        assert!(
            preflight_refuses(&ctx),
            "this request is already served; the next one is what closing buys"
        );
        let written = entries(&ledger_path);
        assert_eq!(written.len(), 1);
        assert_eq!(
            written[0].event.0.outcome, CHAIN_GAP_OUTCOME,
            "closing the chain does not stop it recording why"
        );
    }

    #[test]
    fn an_unavailable_chain_under_degraded_admits_and_does_not_panic() {
        let dir = tempfile::tempdir().expect("temp dir");
        let occupied = dir.path().join("occupied");
        std::fs::create_dir_all(&occupied).expect("make the ledger path a directory");
        let attestation = runtime(&occupied, FailureMode::Degraded);
        let ctx = context(Arc::clone(&attestation));

        assert!(!attestation
            .chain
            .as_deref()
            .expect("a receipt role still builds a chain object")
            .is_writable());
        assert!(
            !preflight_refuses(&ctx),
            "degraded admits: a full disk must not take the API down"
        );

        // The counter is the only record left, and the call must return.
        let _ = record_response(&ctx, METHOD, PATH, 200, false);
    }

    #[test]
    fn an_unavailable_chain_under_closed_refuses_before_the_body_goes_out() {
        let dir = tempfile::tempdir().expect("temp dir");
        let occupied = dir.path().join("occupied");
        std::fs::create_dir_all(&occupied).expect("make the ledger path a directory");
        let ctx = context(runtime(&occupied, FailureMode::Closed));

        assert!(preflight_refuses(&ctx));
        // And recording it is still a return rather than a panic.
        let _ = record_response(&ctx, METHOD, PATH, 200, false);
    }

    #[test]
    fn preflight_refuses_nothing_outside_the_one_case_it_exists_for() {
        let dir = tempfile::tempdir().expect("temp dir");
        let occupied = dir.path().join("occupied");
        std::fs::create_dir_all(&occupied).expect("make the ledger path a directory");

        // No attestation at all.
        assert!(!preflight_refuses(&RequestContext::new()));

        // An unavailable chain under each of the three admitting postures.
        for posture in [
            FailureMode::Degraded,
            FailureMode::Open,
            FailureMode::Observe,
        ] {
            let ctx = context(runtime(&occupied, posture));
            assert!(!preflight_refuses(&ctx), "{posture:?} admits");
        }

        // Closed, unavailable chain, but this origin writes no receipts.
        let ctx = context_for_role(
            runtime(&occupied, FailureMode::Closed),
            AttestationRole::Claim,
        );
        assert!(!preflight_refuses(&ctx));
    }

    #[test]
    fn an_origin_that_writes_no_receipts_records_nothing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = dir.path().join("receipts.ndjson");
        let attestation = runtime(&ledger_path, FailureMode::Degraded);
        let ctx = context_for_role(attestation, AttestationRole::Off);

        let _ = record_response(&ctx, METHOD, PATH, 200, false);

        // The file exists: opening a ledger creates it. What matters is
        // that nothing was written into it, because an origin whose
        // resolved role is off is not being metered at all.
        assert!(
            entries(&ledger_path).is_empty(),
            "an origin outside the role contributes no entry"
        );
    }

    #[test]
    fn a_retry_of_one_claim_is_folded_rather_than_chained_twice() {
        // The `Collapse` path. Two attempts share a claim id, so the second
        // append is deduped and the chain still holds one entry.
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = dir.path().join("receipts.ndjson");
        let attestation = runtime(&ledger_path, FailureMode::Degraded);

        let ctx = context(Arc::clone(&attestation));
        let _ = record_response(&ctx, METHOD, PATH, 200, false);
        let _ = record_response(&ctx, METHOD, PATH, 200, false);

        assert_eq!(
            entries(&ledger_path).len(),
            1,
            "four attempts at a flaky origin stay one sale"
        );
    }

    #[test]
    fn an_origin_that_reported_nothing_is_a_different_receipt_from_one_reporting_zero() {
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = dir.path().join("receipts.ndjson");
        let attestation = runtime(&ledger_path, FailureMode::Degraded);

        let mut silent = context(Arc::clone(&attestation));
        silent.meter_origin_headers.clear();
        let _ = record_response(&silent, METHOD, PATH, 200, false);

        let mut reported_zero = context(Arc::clone(&attestation));
        reported_zero.request_id = compact_str::CompactString::new("claim-zero");
        reported_zero.meter_origin_headers = vec![("X-Rows-Returned".into(), "0".into())];
        let _ = record_response(&reported_zero, METHOD, PATH, 200, false);

        let written = entries(&ledger_path);
        assert_eq!(written.len(), 2);
        let absent = &written[0].event.0.units[2];
        let zero = &written[1].event.0.units[2];
        assert_eq!(absent.count, 0);
        assert_eq!(zero.count, 0);
        assert_ne!(
            absent.evidence, zero.evidence,
            "an upstream nobody wired up and an upstream reporting nothing consumed are two \
             different statements"
        );
    }

    #[test]
    fn a_route_the_operator_never_priced_still_gets_a_receipt() {
        // A weight is not emitted for a route it does not name, and that is
        // not ambiguous: which routes the rule covers is itself in the
        // config the receipt's revision points at. The measured and
        // origin-header lines still land.
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = dir.path().join("receipts.ndjson");
        let ctx = context(runtime(&ledger_path, FailureMode::Degraded));

        let _ = record_response(&ctx, "GET", "/v1/health", 200, false);

        let written = entries(&ledger_path);
        let names: Vec<&str> = written[0]
            .event
            .0
            .units
            .iter()
            .map(|unit| unit.name.as_str())
            .collect();
        assert_eq!(names, vec!["egress_kib", "result_row"]);
        assert_eq!(written[0].event.0.route, "/v1/health");
    }

    #[test]
    fn the_debug_impl_never_prints_the_key() {
        let dir = tempfile::tempdir().expect("temp dir");
        let chain = ReceiptChain::open(
            &dir.path().join("receipts.ndjson"),
            SEED,
            "sbproxy-2026",
            NODE,
        );
        let rendered = format!("{chain:?}");
        assert!(rendered.contains("sbproxy-2026"), "{rendered}");
        assert!(!rendered.contains(SEED), "{rendered}");
        assert!(!rendered.contains("1111"), "{rendered}");
    }
}

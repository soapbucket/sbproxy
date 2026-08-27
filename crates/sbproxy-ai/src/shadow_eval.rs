//! The comparison surface for shadow evaluation (WOR-2654).
//!
//! The dispatch half of shadow eval ships elsewhere: `client.rs` owns
//! sampling, bounded admission, and the per-target usage row. This
//! module owns the two things an operator does with the result.
//!
//! **Retention.** A shadow row carries numbers. Numbers say a target
//! cost less and answered faster; they never say it answered *worse*.
//! Reading that needs the two answers side by side, which means keeping
//! text, which means consent. [`ShadowResponseSink`] is the seam the
//! proxy installs when, and only when, the request already passed the
//! content-recording gate (the origin's `capture_content` AND the
//! governed key's `allow_content_capture`). No sink is installed when
//! either side of that gate is off, so the target's response body is
//! never kept rather than kept and then discarded, and the pair is
//! whole or absent: a shadow answer whose primary was not captured is
//! refused by the store rather than retained on its own.
//!
//! **Aggregation.** [`ShadowPairLedger`] is a bounded, process-local
//! ring of what a window's worth of requests did, joined on a
//! proxy-minted per-request identifier rather than on the correlation
//! id a caller can choose. [`TargetSummary`] is one row per target,
//! and it leads with provenance on purpose: requests seen, the sample rate that was
//! actually applied, pairs retained, and pairs dropped by reason. Every
//! delta below that is computed over the same paired subset and nothing
//! else, so the numbers are falsifiable against the counts above them.
//!
//! Latency is reported at p50 and p95 rather than as a mean, because a
//! mean hides the tail regression that is the usual reason a candidate
//! model should not be promoted, and a survey of the field found no
//! competitor reporting finish-reason distribution at all even though
//! it is the cheapest way to catch a candidate that silently truncates.
//!
//! Deliberately not durable and deliberately not a metric. The
//! per-target counters (`sbproxy_ai_shadow_calls_total`,
//! `sbproxy_ai_shadow_latency_seconds`) already carry the scrapeable
//! series; this answers what a PromQL query cannot, which is what one
//! target cost *relative to the primary that ran beside it*. It clears
//! on restart.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::Serialize;

/// Upper bound on primary requests tracked for pairing at once.
///
/// A slot is opened for **every** request that reached per-target
/// admission, including the ones every target sampled out, because
/// that is what makes `requests_seen` a real denominator. So this
/// bounds requests rather than admitted copies, and a busy route turns
/// it over at the route's own rate: at 200 AI requests per second the
/// ring holds about 2.5 seconds of traffic, while a completion takes
/// seconds to report its primary leg.
///
/// A slot evicted before its primary arrived is therefore a real
/// possibility rather than a corner, and it is counted:
/// [`TargetProvenance::evicted_before_primary`] is the number of them,
/// so a report over a saturated ring says so instead of certifying a
/// sample whose edges it cannot see.
const PAIR_LEDGER_CAPACITY: usize = 512;

/// Upper bound on target legs recorded against one primary.
///
/// `shadow.targets` is an operator-written list with no length limit of
/// its own, and every entry is refused at config load if it repeats a
/// provider, so this is a defensive ceiling rather than the real one.
const MAX_LEGS_PER_PAIR: usize = 16;

/// Label used for a call that produced no finish reason at all.
const NO_FINISH_REASON: &str = "none";

/// Why one target produced no comparable pair for one request.
///
/// The vocabulary is closed so the provenance block sums: every leg the
/// ledger holds is either retained or dropped for exactly one of these.
/// The shadow-eval section of `docs/ai-gateway.md` enumerates the same
/// set, because a dashboard has to be written against the whole
/// vocabulary rather than against whichever keys one sample produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PairDropReason {
    /// The request's single sampling draw did not select this target.
    SampledOut,
    /// The target names a provider this action does not declare.
    ProviderNotFound,
    /// The credential's provider policy forbids the target.
    ProviderNotAllowed,
    /// The request opted out of prompt training and the target's
    /// provider does not carry the same guarantee.
    PromptTrainingDisallowed,
    /// Purpose-scoped egress is active and shadow transport cannot
    /// honor it, so the copy fails closed.
    EgressDenied,
    /// Bounded admission had no free task or memory slot. Shared across
    /// targets, so this is what a config that added a target sees when
    /// the ceiling was already full.
    Saturated,
    /// Fair-share quota refused the copy before transport.
    QuotaDenied,
    /// The supervisor's wall-clock timeout dropped the target's future.
    ShadowTimeout,
    /// The target answered with a non-2xx status, or never answered.
    ShadowError,
    /// The primary leg never arrived, so there is nothing to compare
    /// against. A shadow that outlives its own request ends here.
    PrimaryMissing,
    /// The copy was admitted and has not reported back yet, or its
    /// task died without reporting at all.
    ///
    /// Deliberately off the error axis: a call still in flight has
    /// failed nothing, and counting it as an error would make
    /// `errors.shadow_rate` climb with concurrency on a target whose
    /// every call succeeds. A copy whose task died stays here rather
    /// than disappearing, so the provenance block still sums.
    NotReported,
}

impl PairDropReason {
    /// Stable snake_case label, used as the JSON key in the provenance
    /// block and nowhere else.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SampledOut => "sampled_out",
            Self::ProviderNotFound => "provider_not_found",
            Self::ProviderNotAllowed => "provider_not_allowed",
            Self::PromptTrainingDisallowed => "prompt_training_disallowed",
            Self::EgressDenied => "egress_denied",
            Self::Saturated => "saturated",
            Self::QuotaDenied => "quota_denied",
            Self::ShadowTimeout => "shadow_timeout",
            Self::ShadowError => "shadow_error",
            Self::PrimaryMissing => "primary_missing",
            Self::NotReported => "not_reported",
        }
    }
}

/// Where a retained shadow response goes.
///
/// The proxy implements this over its redacted content store. It is a
/// trait rather than a direct call because redaction (the always-on
/// secret redactor plus the origin's PII rules) lives above this crate,
/// and a response reaching the store unredacted would be exactly the
/// failure the consent gate exists to prevent.
///
/// Implementations are called from the shadow task, off the caller's
/// request path, and must not block.
///
/// The sink is built per request and carries its own store key, so
/// this crate never sees, holds, or passes the caller-controlled
/// correlation id that keys the content store. That is deliberate: the
/// only identifier crossing this seam is the one the proxy minted.
pub trait ShadowResponseSink: Send + Sync {
    /// Retain one target's answer against the primary this sink was
    /// built for, and report whether it landed.
    ///
    /// `response_body` is the target's response normalized to the
    /// OpenAI shape, so one extractor reads every vendor. The
    /// implementation redacts and caps before storing, and returns
    /// `false` when no primary sample exists for its request: half a
    /// pair is not a comparison, and retaining it would keep content
    /// whose counterpart the consent gate refused.
    fn retain(&self, target: &str, model: &str, status: u16, response_body: &[u8]) -> bool;
}

/// Request-scoped evaluation context handed to every shadow target of
/// one primary request.
///
/// Both fields are absent by default, which is the posture that keeps
/// nothing: no id means the pair ledger records nothing, and no sink
/// means no response text is retained.
#[derive(Clone, Default)]
pub struct ShadowEvalContext {
    /// The pair ledger's join key: a **proxy-minted** per-request
    /// identifier, never the inbound correlation header.
    ///
    /// `server.correlation_id` is on by default and adopts an inbound
    /// `X-Request-Id` verbatim, so a caller can choose it. Joining a
    /// ledger on a value the caller picks lets one client send every
    /// request under one id, open a single slot, and overwrite that
    /// slot's legs on every later request: the operator's comparison
    /// report would then show one pair whose cost, latency, finish
    /// reason and status the caller chose, and the rest of that
    /// caller's traffic would be invisible to the evaluation. The
    /// proxy mints an identifier of its own beside the correlation id
    /// for exactly this reason, and that is what this field carries.
    pub pair_key: Option<String>,
    /// Installed only when the request passed the content-recording
    /// gate. `None` means the target's response body is drained and
    /// never kept.
    pub retention: Option<Arc<dyn ShadowResponseSink>>,
}

impl ShadowEvalContext {
    /// The pair ledger's join key, when this request is being paired.
    #[must_use]
    pub fn pair_key(&self) -> Option<&str> {
        self.pair_key.as_deref()
    }
}

impl std::fmt::Debug for ShadowEvalContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowEvalContext")
            .field("pair_key", &self.pair_key)
            .field("retention", &self.retention.is_some())
            .finish()
    }
}

/// The primary half of one evaluated request.
#[derive(Debug, Clone)]
pub struct PrimaryLeg {
    /// Provider that served the caller.
    pub provider: String,
    /// Model the primary billed under.
    pub model: String,
    /// Realized cost of the primary call in USD.
    pub cost_usd: f64,
    /// Wall-clock latency of the primary request in milliseconds.
    pub latency_ms: u64,
    /// Status the caller was served.
    pub status: u16,
}

/// One target's completed call.
#[derive(Debug, Clone)]
pub struct ShadowLeg {
    /// Model the target billed under, after any `model:` override.
    pub model: String,
    /// Status the target answered with; `0` for a call that never
    /// produced a response and `504` for a supervisor timeout.
    pub status: u16,
    /// Estimated cost of the shadow call in USD.
    pub cost_usd: f64,
    /// Wall-clock latency of the shadow call in milliseconds.
    pub latency_ms: u64,
    /// The target's terminal finish reason, when it produced one.
    pub finish_reason: Option<String>,
    /// Whether the target's response text was retained under the
    /// content-recording consent. `false` is the ordinary case.
    pub response_retained: bool,
}

/// What one target did on one request.
#[derive(Debug, Clone)]
enum LegOutcome {
    /// The copy never ran.
    NotRun(PairDropReason),
    /// The copy ran and answered.
    Ran(ShadowLeg),
}

#[derive(Debug, Clone)]
struct TargetLeg {
    target: String,
    sample_rate: f32,
    outcome: LegOutcome,
}

struct PairSlot {
    pair_key: String,
    opened_at: Instant,
    primary: Option<PrimaryLeg>,
    legs: Vec<TargetLeg>,
}

/// Everything the ledger holds, behind one lock.
///
/// The eviction tally lives here rather than beside the ring so there
/// is no second lock to order against the first.
#[derive(Default)]
struct LedgerState {
    slots: std::collections::VecDeque<PairSlot>,
    /// Per target, requests whose slot left the ring before their
    /// primary leg arrived. Monotonic for the life of the process.
    evicted_before_primary: BTreeMap<String, u64>,
}

/// Bounded ring of primary/shadow pairs, joined on the proxy's own
/// per-request identifier.
#[derive(Default)]
pub struct ShadowPairLedger {
    state: Mutex<LedgerState>,
    /// Set by [`ShadowPairLedger::open`], cleared when the ring drains.
    ///
    /// The primary leg is recorded from the end-of-request hook on
    /// every AI request that reached a provider, and a deployment with
    /// no `shadow:` block anywhere should not pay a mutex and a scan
    /// for that. One relaxed load answers it. It is cleared again once
    /// the ring is empty, so removing every `shadow:` block on a reload
    /// stops costing the primary path a lock as soon as the last open
    /// slot ages out, rather than for the life of the process.
    armed: AtomicBool,
}

/// Where the pairs in one target's row came from.
///
/// This block leads the row because without it the deltas below are
/// unfalsifiable: a delta over four pairs and a delta over four
/// thousand read identically once they are a single number.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TargetProvenance {
    /// Requests on this route that reached per-target shadow admission.
    pub requests_seen: u64,
    /// The `sample_rate` this target was configured with, as applied.
    pub sample_rate: f32,
    /// Requests where both legs landed and the pair is comparable.
    pub pairs_retained: u64,
    /// Everything else, by reason. Sums with `pairs_retained` to
    /// `requests_seen`.
    pub pairs_dropped: BTreeMap<String, u64>,
    /// Requests dropped from the bounded ring before their primary leg
    /// arrived, counted since process start rather than over the
    /// window.
    ///
    /// Read it as the sample's error bar. The ring holds a fixed
    /// number of requests and a completion reports its primary leg
    /// seconds after the slot opened, so a route busy enough to turn
    /// the ring over inside that gap loses pairs the window's counts
    /// above can never mention. A non-zero value here says the counts
    /// above are a truncated sample biased toward the primaries that
    /// finished fastest, which is the direction that hides a tail
    /// regression, and that a narrower `window` will read truer than a
    /// wider one.
    pub evicted_before_primary: u64,
    /// Pairs whose response *text* was kept under the content-recording
    /// consent. Zero unless the origin sets `capture_content` and the
    /// key's policy sets `allow_content_capture`.
    pub responses_retained: u64,
}

/// Cost of the target against the primary, over the paired subset.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TargetCost {
    /// Total shadow cost over the retained pairs.
    pub shadow_usd: f64,
    /// Total primary cost over the same retained pairs.
    pub primary_usd: f64,
    /// `shadow_usd - primary_usd`. Negative means cheaper.
    pub delta_usd: f64,
    /// The same delta divided by the retained pair count.
    pub delta_usd_per_request: f64,
    /// `delta_usd_per_request` times `requests_seen`: what promoting
    /// this candidate would have cost or saved across the whole
    /// eligible population rather than the sampled slice.
    pub delta_usd_extrapolated: f64,
}

/// Latency of the target against the primary, at the two points that
/// decide a migration.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TargetLatency {
    /// Shadow p50 in milliseconds.
    pub shadow_p50_ms: u64,
    /// Shadow p95 in milliseconds.
    pub shadow_p95_ms: u64,
    /// Primary p50 over the same pairs.
    pub primary_p50_ms: u64,
    /// Primary p95 over the same pairs.
    pub primary_p95_ms: u64,
    /// `shadow_p50_ms - primary_p50_ms`. Negative means faster.
    pub delta_p50_ms: i64,
    /// `shadow_p95_ms - primary_p95_ms`, the tail the mean hides.
    pub delta_p95_ms: i64,
}

/// Error behavior of the target against the primary, over the same
/// pairs.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TargetErrors {
    /// Share of retained pairs where the target answered non-2xx.
    pub shadow_rate: f64,
    /// Share of the same pairs where the primary answered non-2xx.
    pub primary_rate: f64,
    /// Target status by class (`2xx`, `4xx`, `5xx`, `none`).
    pub shadow_status_classes: BTreeMap<String, u64>,
}

/// Whether the candidate answered *better*, and whether the judge that
/// said so can be believed.
///
/// The judging half is a batch job over retained pairs and is
/// deliberately never inline: the shadow leg exists precisely because
/// it is fire-and-forget, so by the time the candidate answers the
/// caller has already been served and there is nothing to block on.
/// Today this crate ships the job's budget and its deterministic
/// divergence pre-filter (see [`crate::shadow_judge`]); the prompt and
/// the scoring are a scoped follow-up, so `pairs_judged` reads zero and
/// `status` says which of the two it is.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TargetAgreement {
    /// One of `not_configured` (no `judge:` block) or `scoring_pending`
    /// (a judge is configured and its budget is live, but the scorer
    /// has not shipped).
    pub status: &'static str,
    /// Pairs the judge scored in this window.
    pub pairs_judged: u64,
    /// Judge spend in this window.
    pub judge_spend_usd: f64,
    /// The configured hard cap, when a judge is configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub judge_spend_cap_usd: Option<f64>,
    /// Whether the cap auto-paused judging.
    pub paused: bool,
    /// Verdicts, once the scorer ships.
    pub wins: u64,
    /// Verdicts, once the scorer ships.
    pub ties: u64,
    /// Verdicts, once the scorer ships.
    pub losses: u64,
    /// Share of judged pairs whose verdict flipped when the same pair
    /// was judged in the opposite order. High values mean the judge is
    /// reading position rather than quality. `None` until pairs are
    /// judged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverse_order_flip_rate: Option<f64>,
}

impl TargetAgreement {
    /// The row for a target with no `judge:` block.
    fn not_configured() -> Self {
        Self {
            status: "not_configured",
            pairs_judged: 0,
            judge_spend_usd: 0.0,
            judge_spend_cap_usd: None,
            paused: false,
            wins: 0,
            ties: 0,
            losses: 0,
            reverse_order_flip_rate: None,
        }
    }
}

/// One target's aggregate over the reporting window.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TargetSummary {
    /// Target name (the shadow provider's name).
    pub target: String,
    /// Where the pairs came from. Read this first.
    pub provenance: TargetProvenance,
    /// Cost against the primary, over the retained pairs.
    pub cost: TargetCost,
    /// Latency against the primary, over the retained pairs.
    pub latency: TargetLatency,
    /// Finish reasons over the retained pairs, by value. A pair whose
    /// target produced none is counted under `none`, so the
    /// distribution sums to `pairs_retained` and a transport failure
    /// cannot hide inside a real reason.
    pub finish_reasons: BTreeMap<String, u64>,
    /// Error behavior against the primary.
    pub errors: TargetErrors,
    /// Judged agreement, and whether to believe it.
    pub agreement: TargetAgreement,
    /// What running this evaluation cost: the target's own spend over
    /// the window plus whatever the judge spent on it. The shadow leg
    /// is a real second bill, and an operator choosing to keep it
    /// running should see the price of the decision beside the saving
    /// it is measuring.
    pub cost_to_decide_usd: f64,
}

impl ShadowPairLedger {
    /// The process-wide ledger.
    pub fn global() -> &'static Self {
        static LEDGER: OnceLock<ShadowPairLedger> = OnceLock::new();
        LEDGER.get_or_init(Self::default)
    }

    /// Arm pairing for one primary request and record what each target
    /// did with it, run or not.
    ///
    /// Called once per request that reached per-target admission, which
    /// is what makes `requests_seen` a real denominator rather than a
    /// count of the copies that happened to succeed. Re-arming an open
    /// id keeps what is already there rather than resetting it, because
    /// the three dispatch arms that spawn shadows can each reach this
    /// once per request.
    pub fn open(&self, pair_key: &str, legs: &[(String, f32, Option<PairDropReason>)]) {
        if pair_key.is_empty() || legs.is_empty() {
            return;
        }
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if state.slots.iter().any(|slot| slot.pair_key == pair_key) {
            return;
        }
        if state.slots.len() >= PAIR_LEDGER_CAPACITY {
            if let Some(evicted) = state.slots.pop_front() {
                // A slot that leaves the ring having never been paired
                // is a request the report would otherwise never
                // mention: not in `requests_seen`, not under any drop
                // reason, nowhere. Counting it here is what stops the
                // provenance block certifying a sample whose edges it
                // cannot see.
                if evicted.primary.is_none() {
                    for leg in &evicted.legs {
                        *state
                            .evicted_before_primary
                            .entry(leg.target.clone())
                            .or_default() += 1;
                    }
                }
            }
        }
        self.armed.store(true, Ordering::Relaxed);
        state.slots.push_back(PairSlot {
            pair_key: pair_key.to_string(),
            opened_at: Instant::now(),
            primary: None,
            legs: legs
                .iter()
                .take(MAX_LEGS_PER_PAIR)
                .map(|(target, sample_rate, drop)| TargetLeg {
                    target: target.clone(),
                    sample_rate: *sample_rate,
                    // A leg with no drop reason was admitted and is
                    // running. It stays `NotReported` until the task
                    // reports back, so a copy whose process died mid
                    // flight is never silently counted as a success and
                    // a copy still in flight is never counted as an
                    // error.
                    outcome: LegOutcome::NotRun(drop.unwrap_or(PairDropReason::NotReported)),
                })
                .collect(),
        });
    }

    /// Record the primary half. Ignored unless the request armed a slot.
    pub fn record_primary(&self, pair_key: &str, leg: PrimaryLeg) {
        if !self.armed.load(Ordering::Relaxed) {
            return;
        }
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if let Some(slot) = state
            .slots
            .iter_mut()
            .find(|slot| slot.pair_key == pair_key)
        {
            slot.primary = Some(leg);
        } else if state.slots.is_empty() {
            // Every slot has aged out and nothing has opened a new one,
            // which is what a reload that removed the last `shadow:`
            // block looks like from here. Disarm under the lock, so an
            // `open` that is mid-flight cannot have its arming undone.
            self.armed.store(false, Ordering::Relaxed);
        }
    }

    /// Record one target's completed call, replacing the placeholder
    /// `open` left for it. Ignored unless the request armed a slot and
    /// declared that target.
    pub fn record_shadow(&self, pair_key: &str, target: &str, leg: ShadowLeg) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let Some(slot) = state
            .slots
            .iter_mut()
            .find(|slot| slot.pair_key == pair_key)
        else {
            return;
        };
        if let Some(existing) = slot.legs.iter_mut().find(|entry| entry.target == target) {
            existing.outcome = LegOutcome::Ran(leg);
        }
    }

    /// Record that a target the ledger believed was running was
    /// refused before transport.
    pub fn record_drop(&self, pair_key: &str, target: &str, reason: PairDropReason) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let Some(slot) = state
            .slots
            .iter_mut()
            .find(|slot| slot.pair_key == pair_key)
        else {
            return;
        };
        if let Some(existing) = slot.legs.iter_mut().find(|entry| entry.target == target) {
            existing.outcome = LegOutcome::NotRun(reason);
        }
    }

    /// Fold every pair opened within `window` into one row per target,
    /// ordered by target name so two reads of an unchanged ledger
    /// render identically.
    ///
    /// `judge` supplies the agreement block per target; pass `None`
    /// where no judge is configured.
    pub fn report(
        &self,
        window: Duration,
        judge: &dyn Fn(&str) -> Option<TargetAgreement>,
    ) -> Vec<TargetSummary> {
        let Ok(state) = self.state.lock() else {
            return Vec::new();
        };
        let now = Instant::now();
        let mut folded: BTreeMap<String, Fold> = BTreeMap::new();
        // Seed from the eviction tally first, so a target whose every
        // slot was evicted still gets a row saying so instead of
        // vanishing from the report along with its evidence.
        for (target, count) in &state.evicted_before_primary {
            folded
                .entry(target.clone())
                .or_default()
                .evicted_before_primary = *count;
        }
        for slot in state.slots.iter() {
            if now.duration_since(slot.opened_at) > window {
                continue;
            }
            for leg in &slot.legs {
                let fold = folded.entry(leg.target.clone()).or_default();
                fold.requests_seen += 1;
                fold.sample_rate = leg.sample_rate;
                let ran = match &leg.outcome {
                    LegOutcome::NotRun(reason) => {
                        fold.drop(*reason);
                        continue;
                    }
                    LegOutcome::Ran(ran) => ran,
                };
                // A target that answered but whose primary never
                // reported is not a pair. Counting it would compare the
                // candidate against nothing.
                let Some(primary) = slot.primary.as_ref() else {
                    fold.drop(PairDropReason::PrimaryMissing);
                    continue;
                };
                if !(200..300).contains(&ran.status) {
                    // Still counted on the error axis below, but a
                    // failed call has no comparable cost or latency.
                    fold.drop(if ran.status == 504 {
                        PairDropReason::ShadowTimeout
                    } else {
                        PairDropReason::ShadowError
                    });
                    fold.status_class(ran.status);
                    continue;
                }
                fold.pairs_retained += 1;
                if ran.response_retained {
                    fold.responses_retained += 1;
                }
                fold.status_class(ran.status);
                fold.shadow_cost_usd += ran.cost_usd;
                fold.primary_cost_usd += primary.cost_usd;
                fold.shadow_latency_ms.push(ran.latency_ms);
                fold.primary_latency_ms.push(primary.latency_ms);
                if !(200..300).contains(&primary.status) {
                    fold.primary_errors += 1;
                }
                *fold
                    .finish_reasons
                    .entry(
                        ran.finish_reason
                            .clone()
                            .unwrap_or_else(|| NO_FINISH_REASON.to_string()),
                    )
                    .or_default() += 1;
            }
        }
        folded
            .into_iter()
            .map(|(target, fold)| {
                let agreement = judge(&target).unwrap_or_else(TargetAgreement::not_configured);
                fold.finish(target, agreement)
            })
            .collect()
    }

    /// Drop every slot. Test-only affordance so one test's pairs cannot
    /// leak into another's report through the process-global ledger.
    #[cfg(test)]
    fn clear(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.slots.clear();
            state.evicted_before_primary.clear();
        }
    }
}

#[derive(Default)]
struct Fold {
    requests_seen: u64,
    sample_rate: f32,
    pairs_retained: u64,
    responses_retained: u64,
    evicted_before_primary: u64,
    dropped: BTreeMap<PairDropReason, u64>,
    shadow_cost_usd: f64,
    primary_cost_usd: f64,
    shadow_latency_ms: Vec<u64>,
    primary_latency_ms: Vec<u64>,
    shadow_errors: u64,
    primary_errors: u64,
    status_classes: BTreeMap<String, u64>,
    finish_reasons: BTreeMap<String, u64>,
}

impl Fold {
    fn drop(&mut self, reason: PairDropReason) {
        *self.dropped.entry(reason).or_default() += 1;
        if matches!(
            reason,
            PairDropReason::ShadowError | PairDropReason::ShadowTimeout
        ) {
            self.shadow_errors += 1;
        }
    }

    fn status_class(&mut self, status: u16) {
        let class = match status {
            0 => "none",
            200..=299 => "2xx",
            300..=399 => "3xx",
            400..=499 => "4xx",
            _ => "5xx",
        };
        *self.status_classes.entry(class.to_string()).or_default() += 1;
    }

    fn finish(mut self, target: String, agreement: TargetAgreement) -> TargetSummary {
        let retained = self.pairs_retained;
        let per_request_divisor = if retained == 0 { 1.0 } else { retained as f64 };
        let delta_usd = self.shadow_cost_usd - self.primary_cost_usd;
        let delta_usd_per_request = delta_usd / per_request_divisor;
        self.shadow_latency_ms.sort_unstable();
        self.primary_latency_ms.sort_unstable();
        let shadow_p50 = percentile(&self.shadow_latency_ms, 50);
        let shadow_p95 = percentile(&self.shadow_latency_ms, 95);
        let primary_p50 = percentile(&self.primary_latency_ms, 50);
        let primary_p95 = percentile(&self.primary_latency_ms, 95);
        // The error rate's denominator is every call that ran, which is
        // the retained pairs plus the ones the errors themselves
        // knocked out. Dividing by the retained pairs alone would
        // report a rate above 1.0 for a target that mostly fails.
        let ran = retained + self.shadow_errors;
        let ran_divisor = if ran == 0 { 1.0 } else { ran as f64 };
        TargetSummary {
            provenance: TargetProvenance {
                requests_seen: self.requests_seen,
                sample_rate: self.sample_rate,
                pairs_retained: retained,
                pairs_dropped: self
                    .dropped
                    .into_iter()
                    .map(|(reason, count)| (reason.as_str().to_string(), count))
                    .collect(),
                responses_retained: self.responses_retained,
                evicted_before_primary: self.evicted_before_primary,
            },
            cost: TargetCost {
                shadow_usd: self.shadow_cost_usd,
                primary_usd: self.primary_cost_usd,
                delta_usd,
                delta_usd_per_request,
                delta_usd_extrapolated: delta_usd_per_request * self.requests_seen as f64,
            },
            latency: TargetLatency {
                shadow_p50_ms: shadow_p50,
                shadow_p95_ms: shadow_p95,
                primary_p50_ms: primary_p50,
                primary_p95_ms: primary_p95,
                delta_p50_ms: shadow_p50 as i64 - primary_p50 as i64,
                delta_p95_ms: shadow_p95 as i64 - primary_p95 as i64,
            },
            finish_reasons: self.finish_reasons,
            errors: TargetErrors {
                shadow_rate: self.shadow_errors as f64 / ran_divisor,
                primary_rate: self.primary_errors as f64 / per_request_divisor,
                shadow_status_classes: self.status_classes,
            },
            cost_to_decide_usd: self.shadow_cost_usd + agreement.judge_spend_usd,
            agreement,
            target,
        }
    }
}

/// Nearest-rank percentile over an already-sorted slice. `0` for empty,
/// which is what an operator should read as "no pairs", not as "zero
/// milliseconds": the provenance block above it carries the count.
fn percentile(sorted: &[u64], percent: u64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = percent.saturating_mul(sorted.len() as u64).div_ceil(100);
    let index = (rank.max(1) as usize - 1).min(sorted.len() - 1);
    sorted[index]
}

/// Fold the process-wide ledger over `window`, with no judge attached.
pub fn report(window: Duration) -> Vec<TargetSummary> {
    ShadowPairLedger::global().report(window, &|_| None)
}

/// Fold the process-wide ledger over `window`, attaching each target's
/// agreement block.
pub fn report_with_judge(
    window: Duration,
    judge: &dyn Fn(&str) -> Option<TargetAgreement>,
) -> Vec<TargetSummary> {
    ShadowPairLedger::global().report(window, judge)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_judge(_: &str) -> Option<TargetAgreement> {
        None
    }

    fn ran(cost: f64, latency: u64, finish: Option<&str>) -> ShadowLeg {
        ShadowLeg {
            model: "shadow-model".to_string(),
            status: 200,
            cost_usd: cost,
            latency_ms: latency,
            finish_reason: finish.map(str::to_string),
            response_retained: false,
        }
    }

    fn primary(cost: f64, latency: u64) -> PrimaryLeg {
        PrimaryLeg {
            provider: "primary".to_string(),
            model: "primary-model".to_string(),
            cost_usd: cost,
            latency_ms: latency,
            status: 200,
        }
    }

    fn legs(names: &[&str], rate: f32) -> Vec<(String, f32, Option<PairDropReason>)> {
        names
            .iter()
            .map(|name| ((*name).to_string(), rate, None))
            .collect()
    }

    /// The headline the admin view exists to answer: two targets, one
    /// window, and a signed delta against the primary that ran beside
    /// each of them.
    #[test]
    fn a_window_reports_cost_and_latency_deltas_per_target() {
        let ledger = ShadowPairLedger::default();
        ledger.open("req-a", &legs(&["cheap", "slow"], 1.0));
        ledger.record_primary("req-a", primary(0.010, 400));
        ledger.record_shadow("req-a", "cheap", ran(0.004, 250, Some("stop")));
        ledger.record_shadow("req-a", "slow", ran(0.020, 900, Some("stop")));

        let report = ledger.report(Duration::from_secs(60), &no_judge);
        assert_eq!(report.len(), 2, "one row per target: {report:?}");
        assert_eq!(report[0].target, "cheap", "ordered by target name");
        assert_eq!(report[1].target, "slow");

        let cheap = &report[0];
        assert_eq!(cheap.provenance.pairs_retained, 1);
        assert!(
            (cheap.cost.delta_usd - -0.006).abs() < 1e-9,
            "a cheaper target reports a negative cost delta: {cheap:?}"
        );
        assert_eq!(
            cheap.latency.delta_p50_ms, -150,
            "a faster target reports a negative p50 delta: {cheap:?}"
        );
        let slow = &report[1];
        assert!((slow.cost.delta_usd - 0.010).abs() < 1e-9, "{slow:?}");
        assert_eq!(slow.latency.delta_p50_ms, 500, "{slow:?}");
    }

    /// Provenance is the block the whole row is read against, so it has
    /// to account for every eligible request rather than only the
    /// copies that ran.
    #[test]
    fn provenance_accounts_for_every_eligible_request() {
        let ledger = ShadowPairLedger::default();
        // Two requests sampled out, one saturated, one that ran.
        for (index, drop) in [
            Some(PairDropReason::SampledOut),
            Some(PairDropReason::SampledOut),
            Some(PairDropReason::Saturated),
            None,
        ]
        .into_iter()
        .enumerate()
        {
            let id = format!("req-prov-{index}");
            ledger.open(&id, &[("t".to_string(), 0.25, drop)]);
            ledger.record_primary(&id, primary(0.01, 100));
            if drop.is_none() {
                ledger.record_shadow(&id, "t", ran(0.005, 80, Some("stop")));
            }
        }
        let report = ledger.report(Duration::from_secs(60), &no_judge);
        let provenance = &report[0].provenance;
        assert_eq!(provenance.requests_seen, 4);
        assert!((provenance.sample_rate - 0.25).abs() < 1e-6);
        assert_eq!(provenance.pairs_retained, 1);
        assert_eq!(provenance.pairs_dropped.get("sampled_out"), Some(&2));
        assert_eq!(provenance.pairs_dropped.get("saturated"), Some(&1));
        let dropped: u64 = provenance.pairs_dropped.values().sum();
        assert_eq!(
            dropped + provenance.pairs_retained,
            provenance.requests_seen,
            "the provenance block sums: {provenance:?}"
        );
        // And the extrapolation reaches past the sampled slice.
        let cost = &report[0].cost;
        assert!(
            (cost.delta_usd_extrapolated - cost.delta_usd_per_request * 4.0).abs() < 1e-9,
            "{cost:?}"
        );
    }

    /// p95, not the mean: a candidate whose tail is forty times slower
    /// while its median is identical is exactly the migration that
    /// should not happen, and a mean hides it.
    ///
    /// Two of twenty are slow rather than one, because nearest rank
    /// puts p95 of twenty samples at the nineteenth: a single outlier
    /// sits above that rank and is not what p95 reports. That is the
    /// definition working, not a rounding accident, and a test built on
    /// the other reading would have pinned the wrong percentile.
    #[test]
    fn the_tail_is_reported_separately_from_the_median() {
        let ledger = ShadowPairLedger::default();
        for index in 0..20u64 {
            let id = format!("req-tail-{index}");
            ledger.open(&id, &legs(&["t"], 1.0));
            ledger.record_primary(&id, primary(0.01, 100));
            let shadow_latency = if index >= 18 { 4_000 } else { 100 };
            ledger.record_shadow(&id, "t", ran(0.01, shadow_latency, Some("stop")));
        }
        let report = ledger.report(Duration::from_secs(60), &no_judge);
        let latency = &report[0].latency;
        assert_eq!(latency.delta_p50_ms, 0, "the medians agree: {latency:?}");
        assert_eq!(
            latency.shadow_p95_ms, 4_000,
            "and the tail does not: {latency:?}"
        );
        assert_eq!(latency.delta_p95_ms, 3_900, "{latency:?}");
    }

    /// The axis nobody else ships, including the arm that is easy to
    /// lose: a call that produced no reason at all is a signal too, and
    /// folding it into `stop` would hide it.
    #[test]
    fn finish_reasons_count_every_retained_pair_including_the_missing_ones() {
        let ledger = ShadowPairLedger::default();
        for (index, finish) in [Some("stop"), Some("length"), Some("stop"), None]
            .into_iter()
            .enumerate()
        {
            let id = format!("req-fr-{index}");
            ledger.open(&id, &legs(&["t"], 1.0));
            ledger.record_primary(&id, primary(0.01, 100));
            ledger.record_shadow(&id, "t", ran(0.01, 100, finish));
        }
        let row = &ledger.report(Duration::from_secs(60), &no_judge)[0];
        assert_eq!(row.finish_reasons.get("stop"), Some(&2));
        assert_eq!(row.finish_reasons.get("length"), Some(&1));
        assert_eq!(
            row.finish_reasons.get(NO_FINISH_REASON),
            Some(&1),
            "a call with no finish reason is counted, not dropped: {row:?}"
        );
        assert_eq!(
            row.finish_reasons.values().sum::<u64>(),
            row.provenance.pairs_retained,
            "the distribution sums to the retained pairs"
        );
    }

    /// A failed target is on the error axis and off the cost and
    /// latency ones, because a call that produced nothing has no
    /// comparable price.
    #[test]
    fn a_failed_target_moves_the_error_rate_and_not_the_deltas() {
        let ledger = ShadowPairLedger::default();
        ledger.open("req-ok", &legs(&["t"], 1.0));
        ledger.record_primary("req-ok", primary(0.010, 400));
        ledger.record_shadow("req-ok", "t", ran(0.004, 200, Some("stop")));
        ledger.open("req-bad", &legs(&["t"], 1.0));
        ledger.record_primary("req-bad", primary(0.010, 400));
        ledger.record_shadow(
            "req-bad",
            "t",
            ShadowLeg {
                status: 500,
                cost_usd: 99.0,
                latency_ms: 99_999,
                ..ran(0.0, 0, None)
            },
        );

        let row = &ledger.report(Duration::from_secs(60), &no_judge)[0];
        assert_eq!(row.provenance.requests_seen, 2);
        assert_eq!(row.provenance.pairs_retained, 1);
        assert_eq!(row.provenance.pairs_dropped.get("shadow_error"), Some(&1));
        assert!(
            (row.errors.shadow_rate - 0.5).abs() < 1e-9,
            "one of two calls failed: {row:?}"
        );
        assert_eq!(row.errors.shadow_status_classes.get("5xx"), Some(&1));
        assert!(
            (row.cost.delta_usd - -0.006).abs() < 1e-9,
            "the failure's 99 dollars stayed out of the delta: {row:?}"
        );
    }

    /// A shadow that outlived its own request is not a pair.
    #[test]
    fn a_shadow_without_a_primary_is_dropped_not_compared() {
        let ledger = ShadowPairLedger::default();
        ledger.open("req-orphan", &legs(&["t"], 1.0));
        ledger.record_shadow("req-orphan", "t", ran(999.0, 99_999, Some("stop")));
        let row = &ledger.report(Duration::from_secs(60), &no_judge)[0];
        assert_eq!(row.provenance.pairs_retained, 0);
        assert_eq!(
            row.provenance.pairs_dropped.get("primary_missing"),
            Some(&1)
        );
        assert_eq!(row.cost.delta_usd, 0.0, "{row:?}");
    }

    /// A target admitted but never reported on stays visible rather
    /// than becoming a silent success, and stays off the error axis
    /// rather than being counted as a failure it has not had. A shadow
    /// task runs for as long as the target takes, so at any instant a
    /// window holds copies still in flight; charging those to
    /// `errors.shadow_rate` would make the rate climb with concurrency
    /// on a target whose every call succeeds.
    #[test]
    fn an_admitted_target_that_never_reports_is_pending_not_an_error() {
        let ledger = ShadowPairLedger::default();
        ledger.open("req-lost", &legs(&["t"], 1.0));
        ledger.record_primary("req-lost", primary(0.01, 100));
        let row = &ledger.report(Duration::from_secs(60), &no_judge)[0];
        assert_eq!(row.provenance.pairs_retained, 0);
        assert_eq!(row.provenance.pairs_dropped.get("not_reported"), Some(&1));
        assert_eq!(
            row.provenance.pairs_dropped.get("shadow_error"),
            None,
            "a copy still in flight has failed nothing: {row:?}"
        );
        assert_eq!(
            row.errors.shadow_rate, 0.0,
            "and it must not move the error rate: {row:?}"
        );
    }

    /// The ring bounds requests, not admitted copies, and a primary leg
    /// lands seconds after its slot opens. A route busy enough to turn
    /// the ring over inside that gap loses pairs, and the report has to
    /// say so rather than certify the survivors.
    #[test]
    fn a_slot_evicted_before_its_primary_is_counted_and_reported() {
        let ledger = ShadowPairLedger::default();
        // One slot that never gets a primary, then enough traffic to
        // push it out of the ring.
        ledger.open("req-evicted", &legs(&["t"], 1.0));
        for index in 0..PAIR_LEDGER_CAPACITY {
            let id = format!("req-fill-{index}");
            ledger.open(&id, &legs(&["t"], 1.0));
            ledger.record_primary(&id, primary(0.01, 10));
            ledger.record_shadow(&id, "t", ran(0.01, 10, Some("stop")));
        }
        let row = &ledger.report(Duration::from_secs(60), &no_judge)[0];
        assert_eq!(
            row.provenance.evicted_before_primary, 1,
            "the evicted request is named rather than silently dropped: {row:?}"
        );
        assert_eq!(
            row.provenance.requests_seen as usize, PAIR_LEDGER_CAPACITY,
            "and the windowed counts still describe only what the ring holds: {row:?}"
        );
    }

    /// A saturated ring must not make a target disappear from the
    /// report along with the evidence that it was saturated.
    #[test]
    fn a_target_whose_every_slot_was_evicted_still_gets_a_row() {
        let ledger = ShadowPairLedger::default();
        ledger.open("req-vanish", &legs(&["ghost"], 1.0));
        for index in 0..PAIR_LEDGER_CAPACITY {
            let id = format!("req-other-{index}");
            ledger.open(&id, &legs(&["other"], 1.0));
            ledger.record_primary(&id, primary(0.01, 10));
            ledger.record_shadow(&id, "other", ran(0.01, 10, Some("stop")));
        }
        let report = ledger.report(Duration::from_secs(60), &no_judge);
        let ghost = report
            .iter()
            .find(|row| row.target == "ghost")
            .expect("the evicted target still has a row");
        assert_eq!(ghost.provenance.requests_seen, 0);
        assert_eq!(ghost.provenance.evicted_before_primary, 1);
    }

    /// Retention is counted, so an operator can tell a window with
    /// consent from one without.
    #[test]
    fn retained_responses_are_counted_in_provenance() {
        let ledger = ShadowPairLedger::default();
        ledger.open("req-retained", &legs(&["t"], 1.0));
        ledger.record_primary("req-retained", primary(0.01, 100));
        ledger.record_shadow(
            "req-retained",
            "t",
            ShadowLeg {
                response_retained: true,
                ..ran(0.01, 100, Some("stop"))
            },
        );
        let row = &ledger.report(Duration::from_secs(60), &no_judge)[0];
        assert_eq!(row.provenance.responses_retained, 1);
    }

    /// Nothing is recorded against a request that never armed a slot.
    #[test]
    fn an_unopened_request_records_nothing() {
        let ledger = ShadowPairLedger::default();
        ledger.record_primary("req-never-opened", primary(1.0, 1));
        ledger.record_shadow("req-never-opened", "t", ran(1.0, 1, Some("stop")));
        assert!(ledger.report(Duration::from_secs(60), &no_judge).is_empty());
    }

    /// The window is a filter, not decoration.
    #[test]
    fn a_pair_outside_the_window_is_excluded() {
        let ledger = ShadowPairLedger::default();
        ledger.open("req-old", &legs(&["t"], 1.0));
        ledger.record_primary("req-old", primary(0.01, 10));
        ledger.record_shadow("req-old", "t", ran(0.01, 10, Some("stop")));
        assert!(ledger.report(Duration::ZERO, &no_judge).is_empty());
        assert_eq!(ledger.report(Duration::from_secs(60), &no_judge).len(), 1);
    }

    /// The ring is bounded, and the oldest slot is the one that goes.
    #[test]
    fn the_ledger_is_bounded() {
        let ledger = ShadowPairLedger::default();
        for index in 0..(PAIR_LEDGER_CAPACITY + 8) {
            let id = format!("req-bound-{index}");
            ledger.open(&id, &legs(&["t"], 1.0));
            ledger.record_primary(&id, primary(0.01, 10));
            ledger.record_shadow(&id, "t", ran(0.01, 10, Some("stop")));
        }
        let report = ledger.report(Duration::from_secs(60), &no_judge);
        assert_eq!(
            report[0].provenance.requests_seen as usize, PAIR_LEDGER_CAPACITY,
            "the ring holds its capacity and no more: {report:?}"
        );
    }

    /// Three dispatch arms can each reach `open` for one request; the
    /// second call must not discard what the first one collected.
    #[test]
    fn reopening_a_request_keeps_what_was_already_recorded() {
        let ledger = ShadowPairLedger::default();
        ledger.open("req-reopen", &legs(&["t"], 1.0));
        ledger.record_shadow("req-reopen", "t", ran(0.01, 10, Some("stop")));
        ledger.open("req-reopen", &legs(&["t"], 1.0));
        ledger.record_primary("req-reopen", primary(0.02, 20));
        let report = ledger.report(Duration::from_secs(60), &no_judge);
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].provenance.pairs_retained, 1, "{report:?}");
    }

    /// One primary cannot be made to hold an unbounded number of legs.
    #[test]
    fn legs_per_pair_are_capped() {
        let ledger = ShadowPairLedger::default();
        let names: Vec<String> = (0..(MAX_LEGS_PER_PAIR + 5))
            .map(|index| format!("t{index}"))
            .collect();
        let declared: Vec<(String, f32, Option<PairDropReason>)> =
            names.iter().map(|name| (name.clone(), 1.0, None)).collect();
        ledger.open("req-legs", &declared);
        ledger.record_primary("req-legs", primary(0.01, 10));
        for name in &names {
            ledger.record_shadow("req-legs", name, ran(0.01, 10, Some("stop")));
        }
        assert_eq!(
            ledger.report(Duration::from_secs(60), &no_judge).len(),
            MAX_LEGS_PER_PAIR
        );
    }

    /// A quota refusal after admission overwrites the placeholder, so
    /// it is reported as its own reason rather than as an error.
    #[test]
    fn a_late_quota_refusal_is_recorded_by_name() {
        let ledger = ShadowPairLedger::default();
        ledger.open("req-quota", &legs(&["t"], 1.0));
        ledger.record_primary("req-quota", primary(0.01, 10));
        ledger.record_drop("req-quota", "t", PairDropReason::QuotaDenied);
        let row = &ledger.report(Duration::from_secs(60), &no_judge)[0];
        assert_eq!(row.provenance.pairs_dropped.get("quota_denied"), Some(&1));
        assert_eq!(row.errors.shadow_rate, 0.0, "a refusal is not an error");
    }

    /// Without a `judge:` block the agreement row says so rather than
    /// reporting a zero score that reads as a tie.
    #[test]
    fn a_target_with_no_judge_says_not_configured() {
        let ledger = ShadowPairLedger::default();
        ledger.open("req-nojudge", &legs(&["t"], 1.0));
        ledger.record_primary("req-nojudge", primary(0.01, 10));
        ledger.record_shadow("req-nojudge", "t", ran(0.01, 10, Some("stop")));
        let row = &ledger.report(Duration::from_secs(60), &no_judge)[0];
        assert_eq!(row.agreement.status, "not_configured");
        assert!(row.agreement.judge_spend_cap_usd.is_none());
        assert!(row.agreement.reverse_order_flip_rate.is_none());
        assert!(
            (row.cost_to_decide_usd - 0.01).abs() < 1e-9,
            "the cost to decide is the shadow leg's own bill: {row:?}"
        );
    }

    /// Nearest-rank, and an empty set is zero rather than a panic.
    #[test]
    fn percentiles_are_nearest_rank() {
        assert_eq!(percentile(&[], 50), 0);
        assert_eq!(percentile(&[7], 95), 7);
        let values: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&values, 50), 50);
        assert_eq!(percentile(&values, 95), 95);
        assert_eq!(percentile(&values, 100), 100);
    }

    /// The free function reads the process-global ledger, which is the
    /// one the admin endpoint folds.
    #[test]
    fn the_global_ledger_is_reachable_through_the_free_function() {
        ShadowPairLedger::global().clear();
        ShadowPairLedger::global().open("req-global", &legs(&["global-target"], 1.0));
        ShadowPairLedger::global().record_primary("req-global", primary(0.02, 40));
        ShadowPairLedger::global().record_shadow(
            "req-global",
            "global-target",
            ran(0.01, 20, Some("stop")),
        );
        let rows = report(Duration::from_secs(60));
        assert!(
            rows.iter().any(|row| row.target == "global-target"),
            "{rows:?}"
        );
        ShadowPairLedger::global().clear();
    }

    /// The end-of-request hook calls `record_primary` on every AI
    /// request, so a ledger nothing ever armed must not make that a
    /// lock and a scan. Asserted through the report rather than through
    /// the flag, because the flag is an optimization and the behavior
    /// is the contract.
    #[test]
    fn an_unarmed_ledger_short_circuits_the_primary_hook() {
        let ledger = ShadowPairLedger::default();
        ledger.record_primary("req-unarmed", primary(0.01, 10));
        assert!(
            ledger.report(Duration::from_secs(60), &no_judge).is_empty(),
            "a primary leg with no armed slot records nothing"
        );
        ledger.open("req-armed", &legs(&["t"], 1.0));
        ledger.record_primary("req-armed", primary(0.02, 20));
        ledger.record_shadow("req-armed", "t", ran(0.01, 10, Some("stop")));
        assert_eq!(
            ledger.report(Duration::from_secs(60), &no_judge)[0]
                .provenance
                .pairs_retained,
            1,
            "and one open arms the ledger"
        );
    }

    /// The arming flag exists to keep the primary hook free on a
    /// deployment with no `shadow:` block. A reload that removes every
    /// block should get that back, rather than paying a lock forever
    /// because one slot was opened once.
    #[test]
    fn a_drained_ledger_disarms_itself_again() {
        let ledger = ShadowPairLedger::default();
        ledger.open("req-drain", &legs(&["t"], 1.0));
        assert!(
            ledger.armed.load(Ordering::Relaxed),
            "an open arms the ledger"
        );
        ledger.clear();
        ledger.record_primary("req-after-drain", primary(0.01, 10));
        assert!(
            !ledger.armed.load(Ordering::Relaxed),
            "a primary hook that finds an empty ring disarms it again"
        );
    }

    /// A default context keeps nothing, which is the posture a request
    /// without content-recording consent has to land in.
    #[test]
    fn a_default_eval_context_retains_nothing() {
        let context = ShadowEvalContext::default();
        assert!(
            context.retention.is_none(),
            "no sink means the target's body is never kept"
        );
        assert!(context.pair_key().is_none());
    }
}

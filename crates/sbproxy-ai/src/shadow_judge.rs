//! The batch judge's budget and divergence pre-filter (WOR-2654).
//!
//! # Why this is a batch job and never inline
//!
//! A shadow copy exists *because* it is fire-and-forget: by the time
//! the candidate answers, the caller has already been served the
//! primary and there is nothing left to block on. Every gateway that
//! runs a judge inline pays user-visible latency to produce a score
//! nobody reads synchronously; a survey of the field on 2026-08-27
//! found exactly one product doing it that way, at about 1.5 seconds
//! per request, to score a single response rather than compare two.
//! Every other shipped judge (LiteLLM Shadow Evals, LangSmith,
//! Braintrust, Datadog, Langfuse, Arize) runs asynchronously and
//! controls cost with a sample rate. This one runs over retained pairs,
//! after the fact, under a hard spend cap.
//!
//! # What ships here, and what does not
//!
//! Two things a judge cannot be trusted without, both of them cheap:
//!
//! - **A deterministic divergence pre-filter.** Two answers that are
//!   byte-identical, or identical once whitespace and JSON key order
//!   are normalized, need no judge and must not be billed for one.
//!   Only pairs that actually differ reach [`JudgeBudget`].
//! - **A hard spend cap with auto-pause.** The judge is a real bill an
//!   operator chose to incur. `max_spend_usd` is required rather than
//!   defaulted, on the same reasoning as the request-timeout ceiling:
//!   an unbounded judge is the failure the key exists to prevent.
//!
//! The judge *prompt* and the scoring loop are deliberately not here.
//! They carry their own design questions, all of them load-bearing: the
//! two responses are untrusted data and must ride in structured fields
//! the prompt never interpolates as instructions; verdict rows have to
//! be stamped with judge model and prompt version so a suspect batch
//! can be re-judged; and each pair has to be judged in both orders,
//! because across 36 models the first-shown candidate is picked 64.3%
//! of the time and a content-free null model scores 86.5% on
//! AlpacaEval 2.0 by exploiting exactly that. [`JudgePlan`] already
//! budgets two calls per pair for the reverse run, so the shape is
//! fixed and only the scorer is outstanding.
//!
//! # Not the same thing as [`crate::judge`]
//!
//! That module is a *pointwise policy* judge: it scores one payload
//! against one prompt template and returns a
//! `sbproxy_plugin::PolicyDecision` that gates a live request, with a
//! token budget that hard-fails into `Deny` because failing open would
//! defeat the security control it implements. This one compares *two
//! retained answers* after the fact, gates nothing, and its budget is
//! denominated in dollars with a rolling window, because pausing an
//! evaluation costs an operator a report and not a policy bypass. The
//! two share a word and nothing else.
//!
//! Streaming shadows stay out of scope for the same reason they are out
//! of scope for shadow dispatch generally: a streamed answer is
//! committed to the caller frame by frame, so there is no complete
//! candidate text to compare until the stream ends, and buffering one
//! to get it would put the primary's memory ceiling under the
//! candidate's control.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::Serialize;

/// Judge calls billed per pair: one forward, one reverse.
///
/// The reverse run is not optional. It is the only thing that makes the
/// flip rate observable, and the flip rate is what tells an operator
/// the judge is reading position rather than quality.
pub const JUDGE_CALLS_PER_PAIR: u32 = 2;

/// Whether two answers differ enough to be worth a judge call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Divergence {
    /// The two answers are the same once whitespace and JSON key order
    /// are normalized. No judge call is made and no money is spent.
    Identical,
    /// The two answers differ. The reason is carried so a batch can be
    /// read without re-running the filter.
    Diverged(DivergenceKind),
}

/// Why a pair diverged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DivergenceKind {
    /// The two answers stopped for different reasons. The cheapest
    /// disagreement signal there is: a candidate that stopped on
    /// `length` where the primary stopped on `stop` truncated, and no
    /// amount of judging says that more cheaply.
    FinishReason,
    /// The answer texts differ.
    Text,
}

/// One side of a pair, as the pre-filter sees it.
#[derive(Debug, Clone)]
pub struct JudgeCandidate {
    /// The answer text.
    pub text: String,
    /// The terminal finish reason, when there was one.
    pub finish_reason: Option<String>,
}

/// Classify one retained pair.
///
/// Order matters: finish reason is checked first because two answers
/// can be textually identical and still have stopped differently, which
/// is a real disagreement a text comparison would call a match.
#[must_use]
pub fn classify_pair(primary: &JudgeCandidate, shadow: &JudgeCandidate) -> Divergence {
    if primary.finish_reason != shadow.finish_reason {
        return Divergence::Diverged(DivergenceKind::FinishReason);
    }
    if primary.text == shadow.text {
        return Divergence::Identical;
    }
    // Two JSON answers that differ only in key order or spacing are the
    // same answer. Compare parsed values before falling back to text.
    if let (Ok(left), Ok(right)) = (
        serde_json::from_str::<serde_json::Value>(&primary.text),
        serde_json::from_str::<serde_json::Value>(&shadow.text),
    ) {
        if left == right {
            return Divergence::Identical;
        }
    }
    if normalize_whitespace(&primary.text) == normalize_whitespace(&shadow.text) {
        return Divergence::Identical;
    }
    Divergence::Diverged(DivergenceKind::Text)
}

/// Collapse runs of ASCII whitespace and trim, so trailing newlines and
/// indentation differences are not billed as disagreement.
fn normalize_whitespace(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// How long a spend cap covers before it resets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JudgeSpendWindow {
    /// Reset 24 hours after the window opened.
    Daily,
    /// Reset 7 days after the window opened.
    Weekly,
}

impl JudgeSpendWindow {
    /// The window as a duration.
    #[must_use]
    pub const fn duration(self) -> Duration {
        match self {
            Self::Daily => Duration::from_secs(24 * 60 * 60),
            Self::Weekly => Duration::from_secs(7 * 24 * 60 * 60),
        }
    }
}

/// The outcome of asking the budget for one pair's worth of judging.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum JudgeAdmission {
    /// The estimate fits under the cap and has been reserved.
    Admitted,
    /// The cap is reached. Judging is paused until the window rolls.
    Paused {
        /// Spend so far in this window.
        spent_usd: f64,
        /// The configured cap.
        cap_usd: f64,
    },
}

/// What the admin report shows about the judge's money.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct JudgeSpendSnapshot {
    /// Spend so far in the current window.
    pub spent_usd: f64,
    /// The configured hard cap.
    pub cap_usd: f64,
    /// Whether the cap has auto-paused judging.
    pub paused: bool,
}

struct BudgetState {
    window_started: Instant,
    spent_usd: f64,
}

/// A hard, self-resetting spend cap on the judge.
///
/// Nothing here talks to a provider. It is the admission gate the batch
/// job asks before every pair, so a runaway job stops at a number the
/// operator wrote rather than at the end of the backlog.
pub struct JudgeBudget {
    cap_usd: f64,
    window: Duration,
    state: Mutex<BudgetState>,
}

impl JudgeBudget {
    /// A budget with `cap_usd` per `window`.
    #[must_use]
    pub fn new(cap_usd: f64, window: JudgeSpendWindow) -> Self {
        Self {
            cap_usd,
            window: window.duration(),
            state: Mutex::new(BudgetState {
                window_started: Instant::now(),
                spent_usd: 0.0,
            }),
        }
    }

    /// Reserve `estimate_usd` if it fits under the cap.
    ///
    /// The reservation is the charge: the estimate is what the caller
    /// is held to, and a job that spends less settles the difference
    /// back with [`Self::refund`]. Reserving first is deliberate, so a
    /// crash mid-batch leaves the budget conservative rather than open.
    pub fn admit(&self, estimate_usd: f64) -> JudgeAdmission {
        let Ok(mut state) = self.state.lock() else {
            // A poisoned budget cannot prove it is under its cap, so it
            // is treated as spent. Failing open here would mean an
            // unbounded bill on a lock error.
            return JudgeAdmission::Paused {
                spent_usd: f64::NAN,
                cap_usd: self.cap_usd,
            };
        };
        if state.window_started.elapsed() >= self.window {
            state.window_started = Instant::now();
            state.spent_usd = 0.0;
        }
        if state.spent_usd + estimate_usd > self.cap_usd {
            return JudgeAdmission::Paused {
                spent_usd: state.spent_usd,
                cap_usd: self.cap_usd,
            };
        }
        state.spent_usd += estimate_usd;
        JudgeAdmission::Admitted
    }

    /// Return the unspent part of a reservation.
    pub fn refund(&self, amount_usd: f64) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.spent_usd = (state.spent_usd - amount_usd).max(0.0);
    }

    /// What the report shows.
    #[must_use]
    pub fn snapshot(&self) -> JudgeSpendSnapshot {
        let Ok(state) = self.state.lock() else {
            return JudgeSpendSnapshot {
                spent_usd: f64::NAN,
                cap_usd: self.cap_usd,
                paused: true,
            };
        };
        let spent_usd = if state.window_started.elapsed() >= self.window {
            0.0
        } else {
            state.spent_usd
        };
        JudgeSpendSnapshot {
            spent_usd,
            cap_usd: self.cap_usd,
            paused: spent_usd >= self.cap_usd,
        }
    }
}

impl std::fmt::Debug for JudgeBudget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JudgeBudget")
            .field("cap_usd", &self.cap_usd)
            .field("window", &self.window)
            .finish_non_exhaustive()
    }
}

/// One retained pair offered to the batch.
#[derive(Debug, Clone)]
pub struct JudgePair {
    /// The primary's request id, which is the pair's join key.
    pub request_id: String,
    /// The target this pair belongs to.
    pub target: String,
    /// What the caller was served.
    pub primary: JudgeCandidate,
    /// What the candidate answered.
    pub shadow: JudgeCandidate,
}

/// What one pair's admission decided.
#[derive(Debug, Clone, PartialEq)]
pub enum PairPlan {
    /// The pre-filter found no disagreement; no judge call, no spend.
    SkippedIdentical,
    /// Admitted for judging in both orders.
    Judge {
        /// Why the pre-filter let it through.
        divergence: DivergenceKind,
    },
    /// The cap stopped this pair and everything after it.
    Paused,
}

/// The batch's plan: which retained pairs would be judged, which the
/// pre-filter answered for free, and where the cap stopped.
#[derive(Debug, Clone, PartialEq)]
pub struct JudgePlan {
    /// One entry per input pair, in input order.
    pub pairs: Vec<PairPlan>,
    /// Pairs the pre-filter resolved without a judge call.
    pub skipped_identical: usize,
    /// Pairs admitted for judging.
    pub admitted: usize,
    /// Index of the first pair the cap refused, when it fired.
    pub paused_at: Option<usize>,
    /// What the admitted pairs reserved against the cap.
    pub reserved_usd: f64,
}

/// Plan one batch: pre-filter, then admit under the cap.
///
/// `per_call_estimate_usd` is the cost of one judge call; every
/// admitted pair reserves [`JUDGE_CALLS_PER_PAIR`] of them, because the
/// reverse run is part of the method rather than an option.
///
/// Once the cap refuses one pair it refuses the rest of the batch too:
/// resuming after a pause and skipping into the middle of the backlog
/// would report a win rate over a sample nobody chose.
#[must_use]
pub fn plan_batch(
    pairs: &[JudgePair],
    budget: &JudgeBudget,
    per_call_estimate_usd: f64,
) -> JudgePlan {
    let per_pair = per_call_estimate_usd * f64::from(JUDGE_CALLS_PER_PAIR);
    let mut plan = JudgePlan {
        pairs: Vec::with_capacity(pairs.len()),
        skipped_identical: 0,
        admitted: 0,
        paused_at: None,
        reserved_usd: 0.0,
    };
    for (index, pair) in pairs.iter().enumerate() {
        if plan.paused_at.is_some() {
            plan.pairs.push(PairPlan::Paused);
            continue;
        }
        match classify_pair(&pair.primary, &pair.shadow) {
            Divergence::Identical => {
                plan.skipped_identical += 1;
                plan.pairs.push(PairPlan::SkippedIdentical);
            }
            Divergence::Diverged(kind) => match budget.admit(per_pair) {
                JudgeAdmission::Admitted => {
                    plan.admitted += 1;
                    plan.reserved_usd += per_pair;
                    plan.pairs.push(PairPlan::Judge { divergence: kind });
                }
                JudgeAdmission::Paused { .. } => {
                    plan.paused_at = Some(index);
                    plan.pairs.push(PairPlan::Paused);
                }
            },
        }
    }
    plan
}

/// Per-target judge budgets, installed at config load.
///
/// Keyed by target name and nothing else, which is the same key the
/// shadow metric families and the pair ledger already use: two routes
/// naming one candidate provider share its cap, because the operator's
/// bill for judging that candidate is one bill.
#[derive(Default)]
pub struct JudgeRegistry {
    budgets: Mutex<BTreeMap<String, Arc<JudgeBudget>>>,
}

impl JudgeRegistry {
    /// The process-wide registry.
    pub fn global() -> &'static Self {
        static REGISTRY: OnceLock<JudgeRegistry> = OnceLock::new();
        REGISTRY.get_or_init(Self::default)
    }

    /// Install (or re-cap) the budget for `target`.
    ///
    /// A reload that leaves the cap and window unchanged keeps the
    /// existing budget, so hot-reloading a config does not hand an
    /// exhausted judge a fresh allowance. A changed cap is a
    /// deliberate operator act and takes effect immediately, spend
    /// carried over.
    pub fn install(&self, target: &str, cap_usd: f64, window: JudgeSpendWindow) {
        let Ok(mut budgets) = self.budgets.lock() else {
            return;
        };
        match budgets.get(target) {
            Some(existing)
                if existing.cap_usd == cap_usd && existing.window == window.duration() => {}
            Some(existing) => {
                let carried = existing.snapshot().spent_usd;
                let replacement = JudgeBudget::new(cap_usd, window);
                replacement.admit(carried.min(cap_usd));
                budgets.insert(target.to_string(), Arc::new(replacement));
            }
            None => {
                budgets.insert(
                    target.to_string(),
                    Arc::new(JudgeBudget::new(cap_usd, window)),
                );
            }
        }
    }

    /// The budget for `target`, when one is configured.
    #[must_use]
    pub fn budget_for(&self, target: &str) -> Option<Arc<JudgeBudget>> {
        self.budgets.lock().ok()?.get(target).cloned()
    }

    /// Forget every installed budget. Test-only.
    #[cfg(test)]
    fn clear(&self) {
        if let Ok(mut budgets) = self.budgets.lock() {
            budgets.clear();
        }
    }
}

/// The agreement block for `target`, as the admin report renders it.
///
/// `None` when no `judge:` names this target, which the report renders
/// as `not_configured` rather than as a zero score that reads like a
/// tie. When a judge *is* configured the status is `scoring_pending`:
/// the budget and the pre-filter are live, and the prompt and scoring
/// loop are a scoped follow-up, so the honest thing to publish is the
/// cap and a zero count rather than a win rate nothing computed.
#[must_use]
pub fn agreement_for(target: &str) -> Option<crate::shadow_eval::TargetAgreement> {
    let budget = JudgeRegistry::global().budget_for(target)?;
    let snapshot = budget.snapshot();
    Some(crate::shadow_eval::TargetAgreement {
        status: "scoring_pending",
        pairs_judged: 0,
        judge_spend_usd: snapshot.spent_usd,
        judge_spend_cap_usd: Some(snapshot.cap_usd),
        paused: snapshot.paused,
        wins: 0,
        ties: 0,
        losses: 0,
        reverse_order_flip_rate: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(text: &str, finish: Option<&str>) -> JudgeCandidate {
        JudgeCandidate {
            text: text.to_string(),
            finish_reason: finish.map(str::to_string),
        }
    }

    fn pair(primary: JudgeCandidate, shadow: JudgeCandidate) -> JudgePair {
        JudgePair {
            request_id: "req-judge".to_string(),
            target: "candidate".to_string(),
            primary,
            shadow,
        }
    }

    /// The money the pre-filter exists to save.
    #[test]
    fn identical_answers_are_never_billed_for_a_judge_call() {
        let budget = JudgeBudget::new(10.0, JudgeSpendWindow::Daily);
        let batch = vec![pair(
            candidate("4", Some("stop")),
            candidate("4", Some("stop")),
        )];
        let plan = plan_batch(&batch, &budget, 0.01);
        assert_eq!(plan.skipped_identical, 1);
        assert_eq!(plan.admitted, 0);
        assert_eq!(plan.reserved_usd, 0.0);
        assert_eq!(budget.snapshot().spent_usd, 0.0);
    }

    /// Formatting is not disagreement.
    #[test]
    fn whitespace_and_json_key_order_are_not_disagreement() {
        assert_eq!(
            classify_pair(
                &candidate("the answer  is\n four", Some("stop")),
                &candidate("the answer is four", Some("stop"))
            ),
            Divergence::Identical
        );
        assert_eq!(
            classify_pair(
                &candidate(r#"{"a":1,"b":2}"#, Some("stop")),
                &candidate(r#"{"b": 2, "a": 1}"#, Some("stop"))
            ),
            Divergence::Identical
        );
    }

    /// The arm a text comparison alone would miss: two answers can read
    /// the same and still have stopped differently.
    #[test]
    fn identical_text_with_a_different_finish_reason_still_diverges() {
        assert_eq!(
            classify_pair(
                &candidate("a long answer", Some("stop")),
                &candidate("a long answer", Some("length"))
            ),
            Divergence::Diverged(DivergenceKind::FinishReason)
        );
    }

    /// A real disagreement reaches the budget and is charged for both
    /// orders.
    #[test]
    fn a_diverging_pair_reserves_two_calls() {
        let budget = JudgeBudget::new(10.0, JudgeSpendWindow::Daily);
        let batch = vec![pair(
            candidate("four", Some("stop")),
            candidate("five", Some("stop")),
        )];
        let plan = plan_batch(&batch, &budget, 0.01);
        assert_eq!(plan.admitted, 1);
        assert_eq!(
            plan.pairs[0],
            PairPlan::Judge {
                divergence: DivergenceKind::Text
            }
        );
        assert!(
            (plan.reserved_usd - 0.02).abs() < 1e-9,
            "the reverse run is budgeted too: {plan:?}"
        );
    }

    /// The cap is a stop, not a warning.
    #[test]
    fn the_cap_pauses_the_batch_and_everything_after_it() {
        // Room for exactly two pairs at 0.02 each.
        let budget = JudgeBudget::new(0.05, JudgeSpendWindow::Daily);
        let batch: Vec<JudgePair> = (0..5)
            .map(|index| {
                pair(
                    candidate(&format!("primary {index}"), Some("stop")),
                    candidate(&format!("shadow {index}"), Some("stop")),
                )
            })
            .collect();
        let plan = plan_batch(&batch, &budget, 0.01);
        assert_eq!(plan.admitted, 2, "{plan:?}");
        assert_eq!(plan.paused_at, Some(2), "{plan:?}");
        assert!(
            plan.pairs[2..]
                .iter()
                .all(|entry| *entry == PairPlan::Paused),
            "a paused batch does not skip ahead into its own backlog: {plan:?}"
        );
        assert!(
            (budget.snapshot().spent_usd - 0.04).abs() < 1e-9,
            "only the admitted pairs were charged: {:?}",
            budget.snapshot()
        );
    }

    /// A paused budget stays paused for the window.
    #[test]
    fn a_paused_budget_admits_nothing_more() {
        let budget = JudgeBudget::new(0.02, JudgeSpendWindow::Daily);
        assert_eq!(budget.admit(0.02), JudgeAdmission::Admitted);
        assert!(matches!(
            budget.admit(0.0001),
            JudgeAdmission::Paused { .. }
        ));
        assert!(budget.snapshot().paused);
    }

    /// The window rolls, and the cap comes back with it.
    #[test]
    fn the_window_resets_the_cap() {
        // A zero-length window is already elapsed, which is the
        // shortest way to prove the reset without sleeping.
        let budget = JudgeBudget {
            cap_usd: 0.02,
            window: Duration::ZERO,
            state: Mutex::new(BudgetState {
                window_started: Instant::now(),
                spent_usd: 0.02,
            }),
        };
        assert_eq!(
            budget.admit(0.02),
            JudgeAdmission::Admitted,
            "an elapsed window resets the spend before admitting"
        );
    }

    /// A settled underspend is returned rather than held.
    #[test]
    fn a_refund_returns_the_unspent_reservation() {
        let budget = JudgeBudget::new(1.0, JudgeSpendWindow::Daily);
        assert_eq!(budget.admit(0.50), JudgeAdmission::Admitted);
        budget.refund(0.30);
        assert!((budget.snapshot().spent_usd - 0.20).abs() < 1e-9);
        // And a refund cannot drive the budget negative.
        budget.refund(99.0);
        assert_eq!(budget.snapshot().spent_usd, 0.0);
    }

    /// A reload that changes nothing must not hand an exhausted judge
    /// a fresh allowance.
    #[test]
    fn reinstalling_an_unchanged_budget_keeps_its_spend() {
        let registry = JudgeRegistry::default();
        registry.install("candidate", 1.0, JudgeSpendWindow::Daily);
        let budget = registry.budget_for("candidate").expect("installed");
        assert_eq!(budget.admit(0.75), JudgeAdmission::Admitted);
        registry.install("candidate", 1.0, JudgeSpendWindow::Daily);
        let after = registry.budget_for("candidate").expect("still installed");
        assert!(
            (after.snapshot().spent_usd - 0.75).abs() < 1e-9,
            "a no-op reload reset the cap: {:?}",
            after.snapshot()
        );
    }

    /// A raised cap takes effect and carries the spend across.
    #[test]
    fn a_changed_cap_carries_the_spend_over() {
        let registry = JudgeRegistry::default();
        registry.install("candidate", 1.0, JudgeSpendWindow::Daily);
        registry
            .budget_for("candidate")
            .expect("installed")
            .admit(0.75);
        registry.install("candidate", 2.0, JudgeSpendWindow::Daily);
        let after = registry.budget_for("candidate").expect("reinstalled");
        let snapshot = after.snapshot();
        assert!((snapshot.cap_usd - 2.0).abs() < 1e-9, "{snapshot:?}");
        assert!((snapshot.spent_usd - 0.75).abs() < 1e-9, "{snapshot:?}");
    }

    /// The agreement block an operator reads before the scorer ships.
    #[test]
    fn a_configured_judge_reports_its_cap_and_a_pending_score() {
        JudgeRegistry::global().clear();
        assert!(
            agreement_for("unconfigured-target").is_none(),
            "an unconfigured target must not claim a judge"
        );
        JudgeRegistry::global().install("judged-target", 5.0, JudgeSpendWindow::Weekly);
        let agreement = agreement_for("judged-target").expect("configured");
        assert_eq!(agreement.status, "scoring_pending");
        assert_eq!(agreement.judge_spend_cap_usd, Some(5.0));
        assert_eq!(agreement.pairs_judged, 0);
        assert!(agreement.reverse_order_flip_rate.is_none());
        JudgeRegistry::global().clear();
    }

    /// A weekly window is seven daily ones, stated once so a reader
    /// does not have to count seconds.
    #[test]
    fn the_two_windows_are_a_day_and_a_week() {
        assert_eq!(
            JudgeSpendWindow::Daily.duration(),
            Duration::from_secs(86_400)
        );
        assert_eq!(
            JudgeSpendWindow::Weekly.duration(),
            JudgeSpendWindow::Daily.duration() * 7
        );
    }
}

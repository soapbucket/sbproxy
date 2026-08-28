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
///
/// Both windows roll from when the budget's own window opened, which
/// is process start or the last reset, and not from a calendar
/// boundary: `daily` is a rolling 24 hours rather than midnight UTC,
/// and `weekly` is a rolling 7 days rather than Monday. A restart
/// opens a fresh window, so a proxy that restarts more often than the
/// window rolls never reaches the cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JudgeSpendWindow {
    /// A rolling 24 hours from when the window opened.
    Daily,
    /// A rolling 7 days from when the window opened.
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
    /// Whether the cap has refused a pair in this window, which is
    /// what auto-pause means: `plan_batch` stops at the first refusal
    /// and refuses the rest of the batch behind it. True while the
    /// spend is still under the cap, when the next pair's reservation
    /// would not fit.
    pub paused: bool,
}

struct BudgetState {
    window_started: Instant,
    spent_usd: f64,
    /// Set the first time [`JudgeBudget::admit`] refuses in this
    /// window, cleared when the window rolls.
    ///
    /// This is the flag the report publishes, and it is recorded
    /// rather than derived because the derived form was wrong: judging
    /// pauses when the *next* pair's estimate does not fit under the
    /// cap, which happens while the spend is still below it, so
    /// `spent >= cap` reported `paused: false` on a budget that was
    /// already refusing every pair.
    paused: bool,
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
                paused: false,
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
            // unbounded bill on a lock error. Reported as the cap
            // rather than as `NaN`, which serializes to `null` and
            // would leave the operator's report with two blank money
            // fields and no explanation.
            return JudgeAdmission::Paused {
                spent_usd: self.cap_usd,
                cap_usd: self.cap_usd,
            };
        };
        if state.window_started.elapsed() >= self.window {
            state.window_started = Instant::now();
            state.spent_usd = 0.0;
            state.paused = false;
        }
        if state.spent_usd + estimate_usd > self.cap_usd {
            state.paused = true;
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
            // Same reading as `admit`'s: a budget that cannot prove it
            // is under its cap is spent, and it says so with numbers
            // rather than with `null`.
            return JudgeSpendSnapshot {
                spent_usd: self.cap_usd,
                cap_usd: self.cap_usd,
                paused: true,
            };
        };
        let rolled = state.window_started.elapsed() >= self.window;
        let spent_usd = if rolled { 0.0 } else { state.spent_usd };
        JudgeSpendSnapshot {
            spent_usd,
            cap_usd: self.cap_usd,
            // The flag `admit` actually set, not a re-derivation of it.
            paused: !rolled && state.paused,
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

/// Judge budgets, installed at config load and looked up by target.
///
/// The lookup is by target name, which is the same key the shadow
/// metric families and the pair ledger already use, but the *budget*
/// is one per `judge:` block: every target in one `shadow:` block
/// shares a single [`JudgeBudget`], so the one `max_spend_usd` the
/// operator wrote is one ceiling rather than a ceiling per target.
/// WOR-2654 demands that of shadow admission ("shared across targets,
/// not multiplied") and money is the axis where multiplying it matters
/// most: an operator who budgets five dollars against a two-target
/// block must not be exposed to ten.
///
/// Two routes naming one candidate provider still share that
/// candidate's budget, because the last block installed wins the key
/// and the bill for judging one candidate is one bill.
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

    /// Install (or re-cap) one budget covering every target in one
    /// `judge:` block.
    ///
    /// All of `targets` end up pointing at the same [`JudgeBudget`],
    /// which is what makes the block's single `max_spend_usd` a single
    /// ceiling.
    ///
    /// A reload that leaves the cap, the window, and the target set
    /// unchanged keeps the existing budget, so hot-reloading a config
    /// does not hand an exhausted judge a fresh allowance. A changed
    /// cap is a deliberate operator act and takes effect immediately,
    /// spend carried over.
    pub fn install(&self, targets: &[String], cap_usd: f64, window: JudgeSpendWindow) {
        if targets.is_empty() {
            return;
        }
        let Ok(mut budgets) = self.budgets.lock() else {
            return;
        };
        // The block's current budget, if every target already shares
        // one. `None` when a target is new, when a target was moved off
        // another block's budget, or when nothing is installed yet.
        let shared = budgets.get(&targets[0]).cloned().filter(|first| {
            targets.iter().all(|target| {
                budgets
                    .get(target)
                    .is_some_and(|held| Arc::ptr_eq(held, first))
            })
        });
        if let Some(existing) = shared.as_ref() {
            if existing.cap_usd == cap_usd && existing.window == window.duration() {
                return;
            }
        }
        // Carry the spend over so a re-cap is not a way to buy a fresh
        // allowance. When targets are being merged onto one budget the
        // carry is the *sum* of the distinct budgets they held, not the
        // largest: taking the largest would forget every other block's
        // spend and hand the judge back allowance it had already used.
        // Deduplicated by pointer, because two targets that already
        // shared a budget hold one spend between them and counting it
        // twice would be the opposite error.
        let mut distinct: Vec<&Arc<JudgeBudget>> = Vec::new();
        for target in targets {
            let Some(budget) = budgets.get(target) else {
                continue;
            };
            if !distinct.iter().any(|held| Arc::ptr_eq(held, budget)) {
                distinct.push(budget);
            }
        }
        let carried = distinct
            .iter()
            .map(|budget| budget.snapshot().spent_usd)
            .sum::<f64>()
            .min(cap_usd);
        drop(distinct);
        let replacement = Arc::new(JudgeBudget::new(cap_usd, window));
        if carried > 0.0 {
            replacement.admit(carried);
        }
        for target in targets {
            budgets.insert(target.clone(), Arc::clone(&replacement));
        }
    }

    /// The budget for `target`, when one is configured.
    #[must_use]
    pub fn budget_for(&self, target: &str) -> Option<Arc<JudgeBudget>> {
        self.budgets.lock().ok()?.get(target).cloned()
    }

    /// Forget every installed budget.
    ///
    /// Test-only affordance: the registry is process-global, so a test
    /// that installs a budget has to be able to put the process back.
    #[cfg(test)]
    pub(crate) fn clear_for_test(&self) {
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
                paused: true,
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
        let targets = vec!["candidate".to_string()];
        registry.install(&targets, 1.0, JudgeSpendWindow::Daily);
        let budget = registry.budget_for("candidate").expect("installed");
        assert_eq!(budget.admit(0.75), JudgeAdmission::Admitted);
        registry.install(&targets, 1.0, JudgeSpendWindow::Daily);
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
        let targets = vec!["candidate".to_string()];
        registry.install(&targets, 1.0, JudgeSpendWindow::Daily);
        registry
            .budget_for("candidate")
            .expect("installed")
            .admit(0.75);
        registry.install(&targets, 2.0, JudgeSpendWindow::Daily);
        let after = registry.budget_for("candidate").expect("reinstalled");
        let snapshot = after.snapshot();
        assert!((snapshot.cap_usd - 2.0).abs() < 1e-9, "{snapshot:?}");
        assert!((snapshot.spent_usd - 0.75).abs() < 1e-9, "{snapshot:?}");
    }

    /// WOR-2654 requires shadow admission to be shared across targets
    /// rather than multiplied by their number. Money is the axis where
    /// that matters most: one `max_spend_usd` written under one
    /// `judge:` key must be one ceiling for the block, not one per
    /// target name.
    #[test]
    fn one_cap_covers_every_target_in_the_block() {
        let registry = JudgeRegistry::default();
        let targets = vec!["anthropic".to_string(), "gemini".to_string()];
        registry.install(&targets, 5.0, JudgeSpendWindow::Daily);
        let first = registry.budget_for("anthropic").expect("installed");
        let second = registry.budget_for("gemini").expect("installed");
        assert_eq!(first.admit(5.0), JudgeAdmission::Admitted);
        assert!(
            matches!(second.admit(0.01), JudgeAdmission::Paused { .. }),
            "the second target must draw on the same five dollars, not a second five"
        );
        assert!(
            second.snapshot().paused,
            "and the report has to say the block is paused"
        );
    }

    /// The flag the report publishes is the one the cap actually set.
    /// Judging pauses when the next pair's reservation does not fit,
    /// which happens while the spend is still under the cap.
    #[test]
    fn a_budget_refusing_the_next_pair_reports_itself_paused() {
        let budget = JudgeBudget::new(1.0, JudgeSpendWindow::Daily);
        assert_eq!(budget.admit(0.9), JudgeAdmission::Admitted);
        assert!(
            matches!(budget.admit(0.2), JudgeAdmission::Paused { .. }),
            "0.9 + 0.2 is over the cap"
        );
        let snapshot = budget.snapshot();
        assert!(
            snapshot.spent_usd < snapshot.cap_usd,
            "the spend is still under the cap: {snapshot:?}"
        );
        assert!(
            snapshot.paused,
            "and judging is nonetheless paused: {snapshot:?}"
        );
    }

    /// The agreement block an operator reads before the scorer ships.
    #[test]
    fn a_configured_judge_reports_its_cap_and_a_pending_score() {
        JudgeRegistry::global().clear_for_test();
        assert!(
            agreement_for("unconfigured-target").is_none(),
            "an unconfigured target must not claim a judge"
        );
        JudgeRegistry::global().install(
            &["judged-target".to_string()],
            5.0,
            JudgeSpendWindow::Weekly,
        );
        let agreement = agreement_for("judged-target").expect("configured");
        assert_eq!(agreement.status, "scoring_pending");
        assert_eq!(agreement.judge_spend_cap_usd, Some(5.0));
        assert_eq!(agreement.pairs_judged, 0);
        assert!(agreement.reverse_order_flip_rate.is_none());
        JudgeRegistry::global().clear_for_test();
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

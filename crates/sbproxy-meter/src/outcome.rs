// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! What happened, and whether the operator charges for it.
//!
//! Metering a request is the easy half. The hard half is the eight or so
//! situations where the answer is genuinely arguable: the client hung up
//! mid-stream, the origin returned a 500, a policy refused the call before it
//! ever left the building, the response came from cache, the proxy retried
//! four times. Every one of those has a defensible yes and a defensible no,
//! and every deployment that has ever billed for API use has had a position
//! on all of them whether or not anybody wrote it down.
//!
//! The failure this module is built to prevent is not choosing wrong. It is
//! not choosing at all. An unstated rule still runs, it just runs as whatever
//! the code happened to do, and nobody discovers what that was until a buyer
//! asks. So [`OutcomeTable`] refuses to exist until every [`BillableOutcome`]
//! has an explicit answer, and the error names the ones that are missing.
//! There is no [`Default`], and there is deliberately no partial constructor
//! that fills in "the obvious ones" and leaves the rest, because the obvious
//! ones are the ones people disagree about after the fact.
//!
//! [`BillableOutcome::CacheHit`] is the sharpest case and gets no special
//! handling at all. A vendor selling compute can argue a cache hit cost them
//! nothing. A vendor selling answers can argue the answer is what was bought
//! and where it came from is their business. Both are real positions held by
//! real companies, so this crate holds neither.
//!
//! # Beyond yes and no
//!
//! Two of the four answers are not booleans, because two of the situations
//! are not boolean. [`Billable::Partial`] exists for the cut stream, and its
//! rule is that work done bills: a buyer hanging up partway through does not
//! un-run the search the origin already ran, and a measured count already
//! carries what crossed the wire rather than what was promised. Only a cut
//! where the origin produced nothing at all drops units, because then there is
//! no completed work to charge for. [`Billable::Collapse`] exists for the
//! retry, where four attempts are four events and one sale.

use crate::event::{MeteredEvent, Subject, Unit};
use serde::{Deserialize, Serialize};

/// How many outcomes there are. The table is a fixed array of this width.
///
/// Adding a variant to [`BillableOutcome`] makes its `index` and `as_str`
/// matches non-exhaustive, so the crate stops compiling until this number and
/// [`BillableOutcome::ALL`] move with it. That is the intent: a new outcome
/// should be impossible to add without every existing table being forced to
/// state what it costs.
const OUTCOME_COUNT: usize = 8;

/// What happened to the request, in the only terms a billing rule cares
/// about.
///
/// Not an HTTP status and not a proxy error code. The distinctions that
/// matter here are the ones an operator would price differently, which is why
/// a 4xx and a 5xx are separate (one is the buyer's fault, one is the
/// seller's) and why every 2xx collapses into [`BillableOutcome::Delivered`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BillableOutcome {
    /// The response was served to the client in full.
    Delivered,
    /// The client went away before the response finished.
    ///
    /// Work was done and bytes were delivered, but not all of them. The
    /// natural answer is [`Billable::Partial`].
    ClientDisconnected,
    /// The origin rejected the request as the caller's fault.
    ///
    /// Operators split on this one. The compute was spent either way, and a
    /// buyer who is not charged for malformed requests has no reason to stop
    /// sending them.
    #[serde(rename = "origin_4xx")]
    Origin4xx,
    /// The origin failed.
    ///
    /// Charging for a call the seller's own backend failed to serve is a hard
    /// position to defend, but it is still the operator's call to make.
    #[serde(rename = "origin_5xx")]
    Origin5xx,
    /// A policy refused the call before it reached the origin.
    ///
    /// Nothing was consumed downstream, but the proxy did the inspection work
    /// that produced the refusal.
    PolicyBlocked,
    /// A rate limit rejected the call.
    RateLimited,
    /// The response was served from cache without touching the origin.
    ///
    /// Has no default anywhere in this crate, on purpose. See the module
    /// documentation.
    CacheHit,
    /// One attempt of a call that was retried.
    ///
    /// Almost always [`Billable::Collapse`], so that a flaky origin costs the
    /// buyer once rather than once per attempt.
    Retry,
}

impl BillableOutcome {
    /// Every outcome, in declaration order.
    ///
    /// The completeness check in [`OutcomeTable::from_entries`] walks this, so
    /// a new variant becomes a required entry the moment it is added here and
    /// every existing table stops constructing until somebody decides what it
    /// costs.
    pub const ALL: [BillableOutcome; OUTCOME_COUNT] = [
        Self::Delivered,
        Self::ClientDisconnected,
        Self::Origin4xx,
        Self::Origin5xx,
        Self::PolicyBlocked,
        Self::RateLimited,
        Self::CacheHit,
        Self::Retry,
    ];

    /// Stable snake-case name used on the wire, in config, and in errors.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::ClientDisconnected => "client_disconnected",
            Self::Origin4xx => "origin_4xx",
            Self::Origin5xx => "origin_5xx",
            Self::PolicyBlocked => "policy_blocked",
            Self::RateLimited => "rate_limited",
            Self::CacheHit => "cache_hit",
            Self::Retry => "retry",
        }
    }

    /// Position in [`BillableOutcome::ALL`], used to index the table.
    const fn index(self) -> usize {
        match self {
            Self::Delivered => 0,
            Self::ClientDisconnected => 1,
            Self::Origin4xx => 2,
            Self::Origin5xx => 3,
            Self::PolicyBlocked => 4,
            Self::RateLimited => 5,
            Self::CacheHit => 6,
            Self::Retry => 7,
        }
    }
}

/// The billing answer for one outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Billable {
    /// Bill every unit on the event.
    Yes,
    /// Bill nothing. The event is still recorded, because a receipt that
    /// omits the calls that were free cannot be reconciled against a request
    /// log.
    No,
    /// Bill the work the origin actually performed, even though the request
    /// was cut short.
    ///
    /// A route weight or an origin-header count still bills in full, because a
    /// client hanging up does not undo work already done. A measured unit needs
    /// no adjustment either: it carries what crossed the wire, so it has
    /// prorated itself. Units are dropped only when the origin produced no
    /// response at all, which is the one case where nothing was computed to
    /// charge for. See [`OutcomeTable::billable_units`].
    Partial,
    /// Fold this attempt into the invoice line its `claim_id` names.
    ///
    /// The attempt is recorded, its units are dropped, and whatever else
    /// shares the claim id is billed once. Four tries at a flaky origin are
    /// one sale, and a buyer charged four times for the seller's instability
    /// is being charged for the seller's problem.
    Collapse,
}

impl Billable {
    /// Stable snake-case name used on the wire, in config, and in errors.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::No => "no",
            Self::Partial => "partial",
            Self::Collapse => "collapse",
        }
    }
}

/// Why an outcome table could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutcomeTableError {
    /// One or more outcomes were left without an entry.
    Incomplete {
        /// The outcomes with no answer, in [`BillableOutcome::ALL`] order.
        missing: Vec<BillableOutcome>,
    },
    /// The same outcome was given two answers.
    Duplicate {
        /// The outcome that was answered twice.
        outcome: BillableOutcome,
        /// The first answer given.
        first: Billable,
        /// The second answer given.
        second: Billable,
    },
}

impl std::fmt::Display for OutcomeTableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Incomplete { missing } => {
                let names: Vec<&str> = missing.iter().map(|outcome| outcome.as_str()).collect();
                write!(
                    f,
                    "outcome table has no entry for {}; every outcome needs one, \
                     because a billing rule left implicit is a billing rule nobody \
                     agreed to",
                    names.join(", ")
                )
            }
            Self::Duplicate {
                outcome,
                first,
                second,
            } => write!(
                f,
                "outcome '{}' was answered twice, first '{}' and then '{}'; \
                 pick the one you meant",
                outcome.as_str(),
                first.as_str(),
                second.as_str()
            ),
        }
    }
}

impl std::error::Error for OutcomeTableError {}

/// The operator's complete position on what they charge for.
///
/// Deliberately has no [`Default`] and no `Deserialize`. Either one would let
/// a table exist without somebody having answered every question, which is the
/// whole thing this type is for. Configuration builds one by handing
/// [`OutcomeTable::from_entries`] an explicit entry per outcome and surfacing
/// the error if it cannot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeTable {
    answers: [Billable; OUTCOME_COUNT],
}

impl OutcomeTable {
    /// Build a table from one explicit entry per outcome.
    ///
    /// Fails if any outcome is missing, naming the ones that are, and fails if
    /// any outcome is answered twice. Nothing is defaulted and nothing is
    /// inferred.
    pub fn from_entries(
        entries: &[(BillableOutcome, Billable)],
    ) -> Result<Self, OutcomeTableError> {
        let mut given: [Option<Billable>; OUTCOME_COUNT] = [None; OUTCOME_COUNT];

        for &(outcome, billable) in entries {
            if let Some(first) = given[outcome.index()] {
                return Err(OutcomeTableError::Duplicate {
                    outcome,
                    first,
                    second: billable,
                });
            }
            given[outcome.index()] = Some(billable);
        }

        let missing: Vec<BillableOutcome> = BillableOutcome::ALL
            .into_iter()
            .filter(|outcome| given[outcome.index()].is_none())
            .collect();
        if !missing.is_empty() {
            return Err(OutcomeTableError::Incomplete { missing });
        }

        let mut answers = [Billable::No; OUTCOME_COUNT];
        for outcome in BillableOutcome::ALL {
            answers[outcome.index()] =
                given[outcome.index()].expect("every slot is filled, checked immediately above");
        }
        Ok(Self { answers })
    }

    /// The operator's answer for one outcome.
    pub fn billable(&self, outcome: BillableOutcome) -> Billable {
        self.answers[outcome.index()]
    }

    /// The units of one event that survive its outcome.
    ///
    /// [`Billable::Partial`] is the interesting case, and the rule is **work
    /// done bills**. A buyer hanging up mid-response does not undo the work the
    /// origin already performed, so a route weight or an origin-header count
    /// still bills in full. Measured units need no adjustment either: they
    /// already carry what actually crossed the wire rather than what was
    /// promised, so they have prorated themselves.
    ///
    /// The one case that does drop units is a cut where the origin never
    /// produced a response at all. Nothing was computed, so there is no
    /// completed work to charge for, and only the continuously-accruing units
    /// survive. [`MeteredEvent::response_digest`] is what makes that decidable:
    /// it is `None` exactly when no complete response existed to digest.
    ///
    /// This keeps `Partial` genuinely distinct from [`Billable::Yes`] while
    /// staying auditable. A receipt records the outcome next to the rule that
    /// was applied, so a buyer can see both which case they landed in and why.
    pub fn billable_units(&self, event: &MeteredEvent) -> Vec<Unit> {
        match self.billable(event.outcome) {
            Billable::Yes => event.units.clone(),
            Billable::No | Billable::Collapse => Vec::new(),
            Billable::Partial if event.response_digest.is_some() => event.units.clone(),
            Billable::Partial => event
                .units
                .iter()
                .filter(|unit| unit.source.accrues_continuously())
                .cloned()
                .collect(),
        }
    }

    /// Fold a batch of events into invoice lines, one per `claim_id`.
    ///
    /// Claims come back in the order their first attempt was metered. Every
    /// attempt is recorded on the claim it belongs to, including the ones that
    /// bill nothing, because "you retried my call four times and charged me
    /// once" is a sentence an operator has to be able to prove rather than
    /// assert.
    ///
    /// A claim whose every attempt collapsed bills nothing and is still
    /// returned. That is the flaky-origin case, and a receipt that simply
    /// omitted it would be indistinguishable from one where the call never
    /// happened.
    pub fn settle(&self, events: &[MeteredEvent]) -> Vec<Claim> {
        let mut claims: Vec<Claim> = Vec::new();

        for event in events {
            // Resolved before the match so the borrow the search takes is
            // over by the time the miss arm pushes.
            let existing = claims
                .iter()
                .position(|claim| claim.claim_id == event.claim_id);
            let index = match existing {
                Some(index) => index,
                None => {
                    claims.push(Claim {
                        claim_id: event.claim_id.clone(),
                        subject: event.subject.clone(),
                        units: Vec::new(),
                        attempts: Vec::new(),
                    });
                    claims.len() - 1
                }
            };

            claims[index].attempts.push(event.outcome);
            claims[index].units.extend(self.billable_units(event));
        }

        claims
    }
}

/// One invoice line: every attempt at a unit of work, billed once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// The claim id every folded attempt shares.
    pub claim_id: String,
    /// Who is charged.
    ///
    /// Taken from the first attempt seen. A claim id shared across two
    /// subjects is a defect in whatever assigned it, not something this type
    /// can reconcile, and it would show up here as the wrong tenant on a
    /// bill.
    pub subject: Subject,
    /// The units this claim bills for, after every attempt's outcome has been
    /// applied. Empty is a legitimate answer.
    pub units: Vec<Unit>,
    /// Every attempt folded into this claim, in the order it was metered.
    pub attempts: Vec<BillableOutcome>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Evidence, UnitSource};

    /// Every outcome answered, so a test can vary the one it cares about.
    fn complete_entries() -> Vec<(BillableOutcome, Billable)> {
        vec![
            (BillableOutcome::Delivered, Billable::Yes),
            (BillableOutcome::ClientDisconnected, Billable::Partial),
            (BillableOutcome::Origin4xx, Billable::Yes),
            (BillableOutcome::Origin5xx, Billable::No),
            (BillableOutcome::PolicyBlocked, Billable::No),
            (BillableOutcome::RateLimited, Billable::No),
            (BillableOutcome::CacheHit, Billable::Yes),
            (BillableOutcome::Retry, Billable::Collapse),
        ]
    }

    /// A table built from [`complete_entries`].
    fn table() -> OutcomeTable {
        OutcomeTable::from_entries(&complete_entries()).expect("a complete table builds")
    }

    /// The subject every event in these tests is charged to.
    fn subject() -> Subject {
        Subject {
            tenant: "acme".to_string(),
            key_id: Some("key_7".to_string()),
            agent: None,
        }
    }

    /// One metered pass, varying only what a test cares about.
    fn event(outcome: BillableOutcome, claim_id: &str, units: Vec<Unit>) -> MeteredEvent {
        MeteredEvent {
            subject: subject(),
            route: "search".to_string(),
            request_digest: "sha-256=:req:".to_string(),
            response_digest: Some("sha-256=:res:".to_string()),
            outcome,
            units,
            claim_id: claim_id.to_string(),
        }
    }

    /// A unit asserting one whole completed search, priced by config.
    fn route_weight() -> Unit {
        Unit::new("search_call", 1, Evidence::RouteWeight { config_gen: 218 })
    }

    #[test]
    fn a_table_missing_an_outcome_fails_to_construct_and_names_what_is_missing() {
        let mut entries = complete_entries();
        entries.retain(|(outcome, _)| {
            !matches!(outcome, BillableOutcome::CacheHit | BillableOutcome::Retry)
        });

        let error =
            OutcomeTable::from_entries(&entries).expect_err("an incomplete table is not a table");

        assert_eq!(
            error,
            OutcomeTableError::Incomplete {
                missing: vec![BillableOutcome::CacheHit, BillableOutcome::Retry],
            }
        );
        let rendered = error.to_string();
        assert!(rendered.contains("cache_hit"), "{rendered}");
        assert!(rendered.contains("retry"), "{rendered}");
    }

    #[test]
    fn cache_hit_has_no_default_and_is_settable_either_way() {
        let without: Vec<(BillableOutcome, Billable)> = complete_entries()
            .into_iter()
            .filter(|(outcome, _)| *outcome != BillableOutcome::CacheHit)
            .collect();

        // Leaving it out is not "take the sensible default". There is none.
        let error = OutcomeTable::from_entries(&without).expect_err("cache_hit cannot be implied");
        assert_eq!(
            error,
            OutcomeTableError::Incomplete {
                missing: vec![BillableOutcome::CacheHit],
            }
        );

        // Both answers are reachable, and neither is privileged.
        for answer in [Billable::Yes, Billable::No] {
            let mut entries = without.clone();
            entries.push((BillableOutcome::CacheHit, answer));
            let built = OutcomeTable::from_entries(&entries).expect("a complete table builds");
            assert_eq!(built.billable(BillableOutcome::CacheHit), answer);
        }
    }

    #[test]
    fn answering_the_same_outcome_twice_is_rejected() {
        let mut entries = complete_entries();
        entries.push((BillableOutcome::CacheHit, Billable::No));

        let error =
            OutcomeTable::from_entries(&entries).expect_err("two answers are not an answer");

        assert_eq!(
            error,
            OutcomeTableError::Duplicate {
                outcome: BillableOutcome::CacheHit,
                first: Billable::Yes,
                second: Billable::No,
            }
        );
        assert!(error.to_string().contains("answered twice"));
    }

    #[test]
    fn a_complete_table_answers_every_outcome() {
        let table = table();

        for outcome in BillableOutcome::ALL {
            // The point is that this cannot fall through to a default: every
            // outcome has an answer somebody wrote down.
            let answer = table.billable(outcome);
            assert!(!answer.as_str().is_empty());
        }
        assert_eq!(table.billable(BillableOutcome::Delivered), Billable::Yes);
        assert_eq!(table.billable(BillableOutcome::Retry), Billable::Collapse);
    }

    /// The unit set a cut search produces: one continuously-accruing count and
    /// two that assert whole completed work.
    ///
    /// `written` is modelled the way a cut arrives on the wire rather than
    /// mocked: the writer loop stops early, so `bytes_out` is what actually
    /// crossed and not what was promised. The crate owns no transport by
    /// design, so this loop is the cut.
    fn cut_units() -> (u64, Vec<Unit>) {
        let promised_bytes: u64 = 12_043;
        let client_went_away_at: u64 = 8_192;
        let mut written: u64 = 0;
        for _ in 0..4 {
            if written >= client_went_away_at {
                break;
            }
            written = (written + 4_096).min(promised_bytes);
        }
        assert!(written < promised_bytes, "the stream really was cut short");

        let units = vec![
            Unit::new(
                "egress_kib",
                written.div_ceil(1024),
                Evidence::Measured {
                    bytes_in: 512,
                    bytes_out: written,
                    duration_ms: 40,
                },
            ),
            route_weight(),
            Unit::new(
                "result_row",
                47,
                Evidence::OriginHeader {
                    header: "x-rows-returned".to_string(),
                    raw: "47".to_string(),
                },
            ),
        ];
        (written, units)
    }

    #[test]
    fn a_cut_after_the_origin_responded_still_bills_the_work_it_did() {
        let (written, units) = cut_units();
        let table = table();

        // The origin ran the search and returned rows. The buyer hung up
        // partway through the transfer. That does not un-run the search.
        let cut = event(BillableOutcome::ClientDisconnected, "claim_1", units);
        assert!(cut.response_digest.is_some(), "the origin did respond");

        let billed = table.billable_units(&cut);

        assert_eq!(billed.len(), 3, "work the origin performed still bills");
        let egress = billed
            .iter()
            .find(|unit| unit.source == UnitSource::Measured)
            .expect("the measured unit is present");
        assert_eq!(
            egress.count,
            written.div_ceil(1024),
            "the measured count already carries what crossed the wire, so it \
             needs no further proration"
        );
    }

    #[test]
    fn a_cut_before_the_origin_responded_bills_only_what_accrued() {
        let (_, units) = cut_units();
        let table = table();

        // Nothing came back, so there is no completed work to charge for and
        // no complete response to digest. Only the bytes that really moved.
        let mut cut = event(BillableOutcome::ClientDisconnected, "claim_1", units);
        cut.response_digest = None;

        let billed = table.billable_units(&cut);

        assert_eq!(billed.len(), 1, "only the accruing unit survives");
        assert_eq!(billed[0].name, "egress_kib");
        assert_eq!(billed[0].source, UnitSource::Measured);
    }

    #[test]
    fn partial_and_yes_differ_only_when_the_origin_produced_nothing() {
        let (_, units) = cut_units();
        let table = table();

        let delivered = event(BillableOutcome::Delivered, "claim_1", units.clone());
        let cut_with_response = event(BillableOutcome::ClientDisconnected, "claim_2", units);
        let mut cut_without_response = cut_with_response.clone();
        cut_without_response.response_digest = None;

        assert_eq!(table.billable(delivered.outcome), Billable::Yes);
        assert_eq!(table.billable(cut_with_response.outcome), Billable::Partial);

        assert_eq!(
            table.billable_units(&delivered).len(),
            table.billable_units(&cut_with_response).len(),
            "partial and yes agree once the origin has done the work"
        );
        assert_ne!(
            table.billable_units(&delivered).len(),
            table.billable_units(&cut_without_response).len(),
            "partial is only distinct from yes when nothing was produced"
        );
    }

    #[test]
    fn retry_attempts_collapse_under_one_claim_id() {
        let table = table();
        let attempts = vec![
            event(BillableOutcome::Retry, "claim_1", vec![route_weight()]),
            event(BillableOutcome::Retry, "claim_1", vec![route_weight()]),
            event(BillableOutcome::Delivered, "claim_1", vec![route_weight()]),
            // A separate unit of work, so grouping is by claim id and not by
            // "everything in the batch".
            event(BillableOutcome::Delivered, "claim_2", vec![route_weight()]),
        ];

        let claims = table.settle(&attempts);

        assert_eq!(claims.len(), 2);
        assert_eq!(claims[0].claim_id, "claim_1");
        assert_eq!(
            claims[0].units,
            vec![route_weight()],
            "three attempts, one charge"
        );
        assert_eq!(
            claims[0].attempts,
            vec![
                BillableOutcome::Retry,
                BillableOutcome::Retry,
                BillableOutcome::Delivered,
            ],
            "the attempts that billed nothing are still on the record"
        );
        assert_eq!(claims[0].subject, subject());
        assert_eq!(claims[1].claim_id, "claim_2");
        assert_eq!(claims[1].units.len(), 1);
    }

    #[test]
    fn a_claim_that_never_succeeded_bills_nothing_and_is_still_reported() {
        let table = table();

        let claims = table.settle(&[
            event(BillableOutcome::Retry, "claim_1", vec![route_weight()]),
            event(BillableOutcome::Retry, "claim_1", vec![route_weight()]),
        ]);

        assert_eq!(claims.len(), 1);
        assert!(claims[0].units.is_empty());
        assert_eq!(claims[0].attempts.len(), 2, "the attempts happened");
    }

    #[test]
    fn outcome_names_are_stable_on_the_wire() {
        for outcome in BillableOutcome::ALL {
            let json = serde_json::to_string(&outcome).expect("outcome serialises");
            assert_eq!(json, format!("\"{}\"", outcome.as_str()));
        }
        assert_eq!(BillableOutcome::Origin4xx.as_str(), "origin_4xx");
        assert_eq!(
            serde_json::to_string(&Billable::Collapse).expect("billable serialises"),
            "\"collapse\""
        );
    }
}

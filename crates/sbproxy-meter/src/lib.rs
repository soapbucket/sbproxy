// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Attested consumption metering: the vocabulary a receipt is written in.
//!
//! An operator charging per use of an API has to answer two different
//! questions when a buyer disputes a bill, and they are not the same
//! question. "You billed me for calls I never made" is answered by a
//! signature over the bytes that crossed the wire. "I made calls you never
//! credited" is answered by an ordered chain, because a signature on each
//! record says nothing at all about records that were never written.
//!
//! Neither answer is worth anything if the number being signed cannot say
//! where it came from. That is what this crate is for. It owns the metered
//! event, the outcome table, the unit resolvers, and, in [`ledger`], the
//! hash chain and the signing that turn those records into something a
//! buyer can check. Chaining sits on top of the vocabulary rather than
//! inventing its own, so a buyer needs one verifier rather than two.
//!
//! # Provenance is the point
//!
//! A receipt reading `units: 5` is unfalsifiable, and an unfalsifiable
//! receipt is worthless in a dispute. Every [`Unit`] therefore carries a
//! [`UnitSource`] and the [`Evidence`] behind it, which splits "you
//! overcharged me" into three claims a person can check separately: the
//! origin lied, the proxy miscounted, or the config that priced the call was
//! not the config that was agreed. The source is an enum rather than a
//! string so that no resolver can quietly invent a provenance it does not
//! have, and so that adding a resolver forces a decision about how its
//! numbers behave rather than letting it inherit someone else's.
//!
//! # Nothing about billing is left implicit
//!
//! [`OutcomeTable`] refuses to be built until every [`BillableOutcome`] has
//! an answer. There is no default, and in particular no default for
//! [`BillableOutcome::CacheHit`]: billing a cache hit and not billing one
//! are both commercially defensible, and which position an operator holds is
//! a decision they have to state rather than one this crate can make for
//! them. A table that silently fills the gap is a billing rule nobody agreed
//! to, which is the defect the whole design exists to prevent.
//!
//! # A leaf of the workspace, not of the dependency tree
//!
//! The crate depends on no other crate in this workspace. It deliberately
//! does not depend on `sbproxy-core`, `sbproxy-modules`, `sbproxy-ai`, or
//! `sbproxy-config`, because an operator metering a plain REST API should
//! not have to compile the AI gateway to do it.
//!
//! It does take third-party crates, and [`ledger`] is why: hashing needs
//! `sha2` and `hex`, signing needs `ed25519-dalek`, an entry needs a
//! timestamp from `chrono`, and writing one under a lock needs
//! `parking_lot`, `serde_json`, `anyhow`, and `tracing`. The rule the crate
//! actually holds to is the one that matters for compile times and for
//! layering: nothing here reaches back into the proxy.
//!
//! # Three resolvers, and they are added rather than merged
//!
//! [`measured`] counts what the proxy saw, [`route_weight`] applies what the
//! operator wrote down, and [`origin_header`] records what the upstream
//! claimed. A route can have all three, and when it does the event carries
//! three entries in [`MeteredEvent::units`] rather than one number that is
//! their sum.
//!
//! That is not a formatting preference. The three have different provenance
//! and therefore different failure modes, and summing them produces a figure
//! whose parts can no longer be checked separately. "You billed me 53" is
//! one unfalsifiable complaint; "you billed me 12 you counted, 1 you priced,
//! and 40 your upstream asserted" is three claims a person can take apart.
//! The breakdown is the product, so nothing in this crate adds unit counts
//! together and nothing should.
//!
//! # The metrics are not the record
//!
//! [`metrics`] carries what the meter says about its own health: units
//! counted, receipts classified, chain head, append latency, and the gaps
//! where a record was owed and could not be written. None of it is the
//! billing record. The signed chain is, and the counters are lossy by
//! construction because a `PeriodicReader` drops a batch when export fails
//! and a cumulative counter resets when the process restarts. Reconcile
//! against the chain; operate off the counters.
//!
//! # What is not here yet
//!
//! The expression resolver, which subsumes all three, and which goes last on
//! purpose: ship it early and every deployment writes expressions, after
//! which no common case can be optimised or statically checked. The
//! [`origin_header`] resolver also reads response headers only, not JSON
//! body paths, because reading a body means buffering one, and what that
//! costs a streaming response is a decision that deserves its own slice.

#![deny(missing_docs)]

pub mod event;
pub mod ledger;
pub mod measured;
pub mod metrics;
pub mod origin_header;
pub mod outcome;
pub mod route_weight;

pub use event::{Evidence, MeteredEvent, Subject, Unit, UnitSource};
pub use ledger::{
    ledger_health, verify_ledger, verifying_key_from_seed_hex, LedgerEntry, LedgerHealth,
    LedgerPayload, LedgerVerifyResult, UsageLedger,
};
pub use measured::{resolve_measured, MeasuredQuantity, MeasuredRule, Measurement};
pub use metrics::{ChainContribution, FailurePosture, MeterObserver};
pub use origin_header::{
    parse_origin_count, resolve_origin_headers, OriginClaim, OriginHeaderRule, ResolvedOriginUnit,
};
pub use outcome::{Billable, BillableOutcome, Claim, OutcomeTable, OutcomeTableError};
pub use route_weight::{RouteWeightRule, RouteWeightTable};

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU64;

    #[test]
    fn one_route_metered_three_ways_bills_three_lines_and_not_their_sum() {
        // The shape of a real receipt for a search API that charges for
        // egress it delivered, a flat price per call, and the rows its
        // upstream says it returned.
        let measurement = Measurement {
            bytes_in: 512,
            bytes_out: 12_043,
            duration_ms: 91,
        };
        let measured = resolve_measured(
            &[MeasuredRule::new(
                "egress_kib",
                MeasuredQuantity::BytesOut,
                NonZeroU64::new(1024).expect("test divisors are non-zero"),
            )],
            &measurement,
        );
        let weights = RouteWeightTable::new(
            "9f2c41a0be77",
            vec![RouteWeightRule::new(
                "search_call",
                Some("POST".to_string()),
                "/v1/search",
                1,
            )],
        );
        let claimed = resolve_origin_headers(
            &[OriginHeaderRule::new("result_row", "X-Rows-Returned")],
            |_| Some("40".to_string()),
        );

        let mut units: Vec<Unit> = measured;
        units.extend(weights.resolve("POST", "/v1/search"));
        units.extend(claimed.into_iter().map(|resolved| resolved.unit));

        let lines: Vec<(&str, u64, UnitSource)> = units
            .iter()
            .map(|unit| (unit.name.as_str(), unit.count, unit.source))
            .collect();
        assert_eq!(
            lines,
            vec![
                ("egress_kib", 12, UnitSource::Measured),
                ("search_call", 1, UnitSource::RouteWeight),
                ("result_row", 40, UnitSource::OriginHeader),
            ],
            "53 is not an answer anybody can dispute a part of"
        );
        assert!(units.iter().all(Unit::provenance_is_consistent));
    }
}

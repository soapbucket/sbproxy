// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The measured resolver: units the proxy counted for itself.
//!
//! This is the first of the unit resolvers and deliberately the least
//! interesting one. It counts requests, bytes in either direction, and
//! elapsed time, all of which the proxy observes directly, so nothing outside
//! the process contributed to the number and there is no third party whose
//! word has to be taken.
//!
//! It ships first for that reason. The resolvers that follow (a route's
//! configured weight, then a header the origin sets, then eventually an
//! expression) each add a party who can be wrong or dishonest, and each of
//! them is easier to reason about once there is an unarguable baseline
//! sitting next to it on the same receipt. Shipping the most flexible
//! resolver first would have meant every deployment reaching for it before
//! anybody found out which of the simple cases were common.
//!
//! # Rounding
//!
//! A partial unit is billed as a whole one. Twelve thousand and forty-three
//! bytes against a kibibyte rule is twelve units, not eleven and a bit: the
//! operator delivered those bytes and there is no fraction of a kibibyte to
//! hand back. That is a real commercial rule rather than an implementation
//! detail, which is why it is written down here where a buyer reading the
//! receipt can find it.

use crate::event::{Evidence, Unit};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU64;

/// What the proxy observed on the wire for one request.
///
/// Every field is a fact about bytes and time that actually happened.
/// [`Measurement::bytes_out`] in particular is what was written, not what was
/// intended, so a response that was cut short arrives here already telling the
/// truth about itself and no separate truncation flag is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Measurement {
    /// Request bytes received from the client.
    pub bytes_in: u64,
    /// Response bytes written to the client.
    pub bytes_out: u64,
    /// Wall-clock milliseconds the request was in flight.
    pub duration_ms: u64,
}

impl Measurement {
    /// The evidence payload every unit resolved from this observation
    /// carries.
    ///
    /// The whole observation goes on the receipt, not just the field the rule
    /// happened to count, because the arithmetic a buyer wants to redo is
    /// "does this number follow from what you saw" and they need what was
    /// seen in order to do it.
    pub fn evidence(&self) -> Evidence {
        Evidence::Measured {
            bytes_in: self.bytes_in,
            bytes_out: self.bytes_out,
            duration_ms: self.duration_ms,
        }
    }
}

/// Which observed quantity a measured rule counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeasuredQuantity {
    /// The request itself. Always one, which is what a flat per-call charge
    /// is built from.
    Requests,
    /// Request bytes received from the client.
    BytesIn,
    /// Response bytes written to the client.
    BytesOut,
    /// Wall-clock milliseconds the request was in flight.
    DurationMs,
}

impl MeasuredQuantity {
    /// Stable snake-case name used on the wire, in config, and in errors.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requests => "requests",
            Self::BytesIn => "bytes_in",
            Self::BytesOut => "bytes_out",
            Self::DurationMs => "duration_ms",
        }
    }

    /// The raw observed amount, before the rule's divisor is applied.
    pub const fn amount(self, measurement: &Measurement) -> u64 {
        match self {
            Self::Requests => 1,
            Self::BytesIn => measurement.bytes_in,
            Self::BytesOut => measurement.bytes_out,
            Self::DurationMs => measurement.duration_ms,
        }
    }
}

/// One measured unit definition: a name, what it counts, and how much of the
/// raw quantity makes one unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeasuredRule {
    /// Unit name that appears on the invoice line, for example `egress_kib`.
    pub name: String,
    /// The observed quantity this rule counts.
    pub quantity: MeasuredQuantity,
    /// How much of the raw quantity makes one unit.
    ///
    /// `1024` against [`MeasuredQuantity::BytesOut`] gives kibibytes. Zero is
    /// unrepresentable rather than validated, because a rule that divides by
    /// nothing has no defensible answer to fall back on.
    pub per: NonZeroU64,
}

impl MeasuredRule {
    /// A rule that bills one unit per `per` of the quantity.
    pub fn new(name: impl Into<String>, quantity: MeasuredQuantity, per: NonZeroU64) -> Self {
        Self {
            name: name.into(),
            quantity,
            per,
        }
    }

    /// A rule that bills one unit per single observed item.
    pub fn each(name: impl Into<String>, quantity: MeasuredQuantity) -> Self {
        Self::new(name, quantity, NonZeroU64::MIN)
    }

    /// Resolve this rule against one observation.
    ///
    /// Rounds a partial unit up to a whole one. See the module documentation
    /// for why that is the rule.
    pub fn resolve(&self, measurement: &Measurement) -> Unit {
        let count = self.quantity.amount(measurement).div_ceil(self.per.get());
        Unit::new(self.name.clone(), count, measurement.evidence())
    }
}

/// Resolve every measured rule against one observation.
///
/// A rule that observed nothing still produces a unit with a count of zero. A
/// receipt that quietly omitted it would be indistinguishable from a receipt
/// written by a config that never had the rule, and telling those two apart is
/// the difference between "you did not use any egress" and "we stopped
/// metering your egress".
pub fn resolve_measured(rules: &[MeasuredRule], measurement: &Measurement) -> Vec<Unit> {
    rules.iter().map(|rule| rule.resolve(measurement)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::UnitSource;

    /// A divisor that is known to be non-zero at the call site.
    fn per(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).expect("test divisors are non-zero")
    }

    #[test]
    fn a_partial_unit_rounds_up_to_a_whole_one() {
        let rule = MeasuredRule::new("egress_kib", MeasuredQuantity::BytesOut, per(1024));
        let measurement = Measurement {
            bytes_in: 512,
            bytes_out: 12_043,
            duration_ms: 91,
        };

        let unit = rule.resolve(&measurement);

        assert_eq!(unit.count, 12, "11.76 kibibytes is billed as 12");
        assert_eq!(unit.name, "egress_kib");
        assert_eq!(unit.source, UnitSource::Measured);
    }

    #[test]
    fn a_measured_unit_carries_the_whole_observation_as_its_evidence() {
        let rule = MeasuredRule::each("api_call", MeasuredQuantity::Requests);
        let measurement = Measurement {
            bytes_in: 512,
            bytes_out: 12_043,
            duration_ms: 91,
        };

        let unit = rule.resolve(&measurement);

        assert_eq!(unit.count, 1);
        assert_eq!(
            unit.evidence,
            Evidence::Measured {
                bytes_in: 512,
                bytes_out: 12_043,
                duration_ms: 91,
            },
            "a buyer redoing the arithmetic needs everything that was seen"
        );
        assert!(unit.provenance_is_consistent());
    }

    #[test]
    fn a_rule_that_observed_nothing_still_reports_a_zero_count() {
        let rule = MeasuredRule::new("ingress_kib", MeasuredQuantity::BytesIn, per(1024));

        let unit = rule.resolve(&Measurement::default());

        assert_eq!(unit.count, 0, "silence and zero are different statements");
        assert_eq!(unit.name, "ingress_kib");
    }

    #[test]
    fn a_truncated_response_measures_only_what_crossed_the_wire() {
        let rule = MeasuredRule::new("egress_kib", MeasuredQuantity::BytesOut, per(1024));
        let whole = Measurement {
            bytes_in: 512,
            bytes_out: 12_043,
            duration_ms: 91,
        };
        let cut = Measurement {
            bytes_out: 8_192,
            duration_ms: 40,
            ..whole
        };

        assert_eq!(rule.resolve(&whole).count, 12);
        assert_eq!(rule.resolve(&cut).count, 8);
    }

    #[test]
    fn every_rule_resolves_against_one_observation() {
        let rules = vec![
            MeasuredRule::each("api_call", MeasuredQuantity::Requests),
            MeasuredRule::new("ingress_kib", MeasuredQuantity::BytesIn, per(1024)),
            MeasuredRule::new("egress_kib", MeasuredQuantity::BytesOut, per(1024)),
            MeasuredRule::new("compute_second", MeasuredQuantity::DurationMs, per(1000)),
        ];
        let measurement = Measurement {
            bytes_in: 2_048,
            bytes_out: 12_043,
            duration_ms: 1_500,
        };

        let units = resolve_measured(&rules, &measurement);

        let counts: Vec<(&str, u64)> = units
            .iter()
            .map(|unit| (unit.name.as_str(), unit.count))
            .collect();
        assert_eq!(
            counts,
            vec![
                ("api_call", 1),
                ("ingress_kib", 2),
                ("egress_kib", 12),
                ("compute_second", 2),
            ]
        );
        assert!(units.iter().all(|unit| unit.source == UnitSource::Measured));
    }

    #[test]
    fn quantity_names_are_stable_on_the_wire() {
        for quantity in [
            MeasuredQuantity::Requests,
            MeasuredQuantity::BytesIn,
            MeasuredQuantity::BytesOut,
            MeasuredQuantity::DurationMs,
        ] {
            let json = serde_json::to_string(&quantity).expect("quantity serialises");
            assert_eq!(json, format!("\"{}\"", quantity.as_str()));
        }
    }
}

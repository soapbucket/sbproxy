// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The origin-header resolver: units the upstream reported for itself.
//!
//! The origin is the only party that knows how many rows it returned, how
//! many documents it indexed, or how much work a query actually cost it. So
//! it says, in a response header, and the proxy writes down what it saw.
//!
//! This is the trust boundary. [`crate::measured`] and
//! [`crate::route_weight`] are wrong only if the proxy is wrong; this one can
//! be wrong while the proxy is entirely correct, because the party supplying
//! the number is also the party with an incentive to inflate it. Both of
//! those facts are true at once and neither is a reason to refuse the
//! number: a search API that cannot bill per result row is not a search API
//! anybody wants to sell. What the resolver owes instead is an honest record
//! of what arrived.
//!
//! # The proxy attests, it does not vouch
//!
//! Every unit produced here carries
//! [`crate::event::UnitSource::OriginHeader`] and the header value exactly
//! as it arrived. The proxy's claim is "the origin sent me this", which is a
//! claim the proxy can actually make. It never becomes "this is how much
//! work was done", which is a claim only the origin can make and which the
//! receipt therefore attributes to the origin.
//!
//! # Nothing here can launder its provenance
//!
//! An origin sending `forty-seven` where a count belongs must not turn into
//! a substituted number wearing [`crate::event::UnitSource::Measured`]. That
//! substitution is the failure that makes a whole receipt worthless, because
//! it destroys the distinction between "the origin lied" and "the proxy
//! miscounted", and those two have different people at fault and different
//! remedies. A dispute that cannot separate them is settled by whoever has
//! more lawyers.
//!
//! The guarantee is structural rather than a rule somebody has to remember.
//! [`OriginHeaderRule::resolve`] builds every unit through
//! [`crate::event::Unit::new`] over an
//! [`crate::event::Evidence::OriginHeader`] payload, and `Unit::new` derives
//! the declared source from the evidence. There is no path through this
//! module that can emit a measured unit, and there is no configuration that
//! makes one appear: a fallback that substituted a measured count for an
//! unparseable one would be exactly the laundering this design exists to
//! prevent, so it does not exist.
//!
//! # Three things the origin can do, and they are three
//!
//! - It sends a number. The count is that number, and the raw value is on
//!   the receipt so the parse can be checked.
//! - It sends something else. The count is zero, because the proxy has no
//!   defensible number to use and inventing one is the laundering above, and
//!   the raw value is on the receipt so a buyer can see it was the origin
//!   and not the proxy that produced nonsense.
//! - It sends nothing. The count is zero and the receipt records that no
//!   value arrived, which is a different statement from the origin having
//!   said zero. One is an upstream that was never taught to report; the
//!   other is an upstream reporting that this call consumed nothing. An
//!   operator chasing a metering gap has to know which one they have.
//!
//! [`OriginClaim`] carries that distinction back to the caller so the three
//! can be counted separately without re-parsing what is on the receipt.

use crate::event::{Evidence, Unit};
use serde::{Deserialize, Serialize};

/// One count the operator expects the origin to report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OriginHeaderRule {
    /// Unit name that appears on the invoice line, for example
    /// `result_row`.
    pub name: String,
    /// Response header the count is read from.
    ///
    /// Kept in the operator's spelling. HTTP field names are
    /// case-insensitive to match on, but the receipt quotes this one back,
    /// and quoting back `x-rows-returned` when the operator and the origin
    /// both wrote `X-Rows-Returned` invites an argument about whether the
    /// proxy was even looking at the right header.
    pub header: String,
}

impl OriginHeaderRule {
    /// A rule that reads one unit count from one response header.
    pub fn new(name: impl Into<String>, header: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            header: header.into(),
        }
    }

    /// Resolve this rule against what the proxy read off the response.
    ///
    /// `observed` is `None` when the origin set no such header and
    /// `Some(value)` when it set one, including when the value it set was
    /// empty. The caller does the reading because this crate owns no
    /// transport and deliberately depends on no HTTP types.
    pub fn resolve(&self, observed: Option<&str>) -> ResolvedOriginUnit {
        let (count, claim) = match observed {
            Some(raw) => match parse_origin_count(raw) {
                Some(count) => (count, OriginClaim::Counted),
                None => (0, OriginClaim::Malformed),
            },
            None => (0, OriginClaim::Absent),
        };

        ResolvedOriginUnit {
            unit: Unit::new(
                self.name.clone(),
                count,
                Evidence::OriginHeader {
                    header: self.header.clone(),
                    raw: observed.map(str::to_string),
                },
            ),
            claim,
        }
    }
}

/// What the origin did where a count was expected.
///
/// The in-process form, for a caller that wants to count the three cases
/// without picking the evidence apart again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginClaim {
    /// The origin reported a value the proxy could read as a whole number.
    Counted,
    /// The origin reported a value the proxy could not read as a count.
    ///
    /// Billed as zero. The raw value is on the receipt, so this is visibly
    /// the origin's failure and not the proxy's.
    Malformed,
    /// The origin reported nothing at all.
    ///
    /// Billed as zero, and distinct from the origin reporting zero. Usually
    /// an upstream that has not been taught to report its consumption.
    Absent,
}

impl OriginClaim {
    /// Stable snake-case name used on the wire, in metrics, and in errors.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Counted => "counted",
            Self::Malformed => "malformed",
            Self::Absent => "absent",
        }
    }

    /// Whether the proxy got a number it could read.
    ///
    /// False for both failure shapes, which are alike for billing (both cost
    /// zero) and unalike for operations (one is a broken origin, the other
    /// is an origin nobody wired up). Callers that care about the difference
    /// match on the variant.
    pub const fn is_counted(self) -> bool {
        matches!(self, Self::Counted)
    }
}

/// One unit resolved from the origin, and what the origin did to produce it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedOriginUnit {
    /// The billable unit. Always carries
    /// [`crate::event::UnitSource::OriginHeader`], whatever the origin sent.
    pub unit: Unit,
    /// What the origin did where the count was expected.
    ///
    /// Never travels to the receipt. The evidence on [`Self::unit`]
    /// already distinguishes all three cases, and a second field saying the
    /// same thing on a signed document is a field that can disagree with
    /// the one beside it.
    pub claim: OriginClaim,
}

/// Read a unit count out of a raw header value.
///
/// Surrounding whitespace is trimmed and the rest has to be entirely ASCII
/// digits that fit in a `u64`. That line is drawn where it is on purpose.
/// Padding around a header value is a transport artifact and RFC 9110 does
/// not consider it part of the value, so trimming it changes nothing the
/// origin meant. `47.0`, `47 rows`, and an empty value are the origin saying
/// something other than a count, and guessing what they meant would be the
/// proxy putting a number of its own on the invoice under the origin's name.
///
/// Being strict costs nothing a buyer can lose, because the raw value goes
/// on the receipt either way. An operator who finds their origin sending
/// `47 rows` can see exactly that and fix the origin.
pub fn parse_origin_count(raw: &str) -> Option<u64> {
    let trimmed = raw.trim_ascii();
    if trimmed.is_empty() || !trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    trimmed.parse::<u64>().ok()
}

/// Resolve every origin-header rule against one response.
///
/// `read` is handed each rule's header name and returns what the response
/// carried under it, or `None` when it carried nothing.
///
/// Every rule produces a unit, including the ones whose header never
/// arrived. A rule that quietly produced nothing would leave a receipt
/// indistinguishable from one written by a config that never had the rule,
/// and telling those apart is the difference between "the origin reported no
/// rows" and "we stopped asking the origin about rows".
pub fn resolve_origin_headers(
    rules: &[OriginHeaderRule],
    read: impl Fn(&str) -> Option<String>,
) -> Vec<ResolvedOriginUnit> {
    rules
        .iter()
        .map(|rule| rule.resolve(read(&rule.header).as_deref()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::UnitSource;
    use crate::measured::{MeasuredQuantity, MeasuredRule, Measurement};

    fn rule() -> OriginHeaderRule {
        OriginHeaderRule::new("result_row", "X-Rows-Returned")
    }

    #[test]
    fn a_reported_count_is_billed_and_its_raw_value_is_kept() {
        let resolved = rule().resolve(Some("47"));

        assert_eq!(resolved.claim, OriginClaim::Counted);
        assert_eq!(resolved.unit.count, 47);
        assert_eq!(resolved.unit.name, "result_row");
        assert_eq!(resolved.unit.source, UnitSource::OriginHeader);
        assert_eq!(
            resolved.unit.evidence,
            Evidence::OriginHeader {
                header: "X-Rows-Returned".to_string(),
                raw: Some("47".to_string()),
            }
        );
    }

    #[test]
    fn a_malformed_value_never_launders_into_a_measured_number() {
        // The failure this whole resolver is shaped to prevent. A proxy that
        // could not parse the origin's claim has a measurement of its own
        // sitting right there, and substituting it would produce a receipt
        // that reads as "the proxy counted 12" when what happened is "the
        // origin said something nobody can read". A buyer cannot then tell
        // whether they were lied to or miscounted, and that distinction is
        // the entire product.
        let per_kib = std::num::NonZeroU64::new(1024).expect("test divisors are non-zero");
        let substitute = MeasuredRule::new("result_row", MeasuredQuantity::BytesOut, per_kib)
            .resolve(&Measurement {
                bytes_in: 512,
                bytes_out: 12_043,
                duration_ms: 91,
            });
        assert_eq!(substitute.count, 12, "a plausible substitute does exist");

        for raw in [
            "forty-seven",
            "47.0",
            "47 rows",
            "",
            "-1",
            "18446744073709551616",
        ] {
            let resolved = rule().resolve(Some(raw));

            assert_eq!(
                resolved.claim,
                OriginClaim::Malformed,
                "{raw:?} is not a count"
            );
            assert_eq!(
                resolved.unit.source,
                UnitSource::OriginHeader,
                "{raw:?} must stay the origin's claim, not become the proxy's"
            );
            assert_ne!(
                resolved.unit.count, substitute.count,
                "{raw:?} must not pick up a number the proxy counted"
            );
            assert_eq!(resolved.unit.count, 0, "{raw:?} bills nothing");
            assert_eq!(
                resolved.unit.evidence,
                Evidence::OriginHeader {
                    header: "X-Rows-Returned".to_string(),
                    raw: Some(raw.to_string()),
                },
                "{raw:?} goes on the receipt exactly as it arrived"
            );
            assert!(resolved.unit.provenance_is_consistent());
        }
    }

    #[test]
    fn no_header_at_all_is_a_different_receipt_from_a_reported_zero() {
        let absent = rule().resolve(None);
        let reported_zero = rule().resolve(Some("0"));
        let empty = rule().resolve(Some(""));

        assert_eq!(absent.claim, OriginClaim::Absent);
        assert_eq!(reported_zero.claim, OriginClaim::Counted);
        assert_eq!(empty.claim, OriginClaim::Malformed);

        // All three bill nothing, and all three say something different
        // about why.
        for resolved in [&absent, &reported_zero, &empty] {
            assert_eq!(resolved.unit.count, 0);
            assert_eq!(resolved.unit.source, UnitSource::OriginHeader);
        }
        assert_ne!(absent.unit.evidence, reported_zero.unit.evidence);
        assert_ne!(absent.unit.evidence, empty.unit.evidence);
        assert_ne!(reported_zero.unit.evidence, empty.unit.evidence);

        let value: serde_json::Value = serde_json::to_value(&absent.unit).expect("unit serialises");
        assert!(
            value["evidence"].get("raw").is_none(),
            "a receipt must not show a value the origin never sent"
        );
    }

    #[test]
    fn surrounding_whitespace_is_transport_and_the_rest_is_the_claim() {
        for (raw, expected) in [
            ("47", 47),
            (" 47 ", 47),
            ("47\n", 47),
            ("\t47", 47),
            ("0047", 47),
            ("0", 0),
        ] {
            let resolved = rule().resolve(Some(raw));
            assert_eq!(resolved.unit.count, expected, "{raw:?}");
            assert_eq!(resolved.claim, OriginClaim::Counted, "{raw:?}");
            assert_eq!(
                resolved.unit.evidence,
                Evidence::OriginHeader {
                    header: "X-Rows-Returned".to_string(),
                    raw: Some(raw.to_string()),
                },
                "trimming for the parse must not trim what goes on the receipt"
            );
        }
    }

    #[test]
    fn every_rule_reports_even_when_its_header_never_arrived() {
        let rules = vec![
            OriginHeaderRule::new("result_row", "X-Rows-Returned"),
            OriginHeaderRule::new("index_doc", "X-Docs-Indexed"),
        ];

        let resolved = resolve_origin_headers(&rules, |header| match header {
            "X-Rows-Returned" => Some("47".to_string()),
            _ => None,
        });

        assert_eq!(
            resolved.len(),
            2,
            "silence from the origin is still something the receipt has to say"
        );
        assert_eq!(resolved[0].claim, OriginClaim::Counted);
        assert_eq!(resolved[1].claim, OriginClaim::Absent);
        assert_eq!(resolved[1].unit.name, "index_doc");
    }

    #[test]
    fn two_rules_on_one_response_produce_two_units_and_never_a_sum() {
        let rules = vec![
            OriginHeaderRule::new("result_row", "X-Rows-Returned"),
            OriginHeaderRule::new("index_doc", "X-Docs-Indexed"),
        ];

        let units: Vec<Unit> = resolve_origin_headers(&rules, |header| match header {
            "X-Rows-Returned" => Some("47".to_string()),
            "X-Docs-Indexed" => Some("3".to_string()),
            _ => None,
        })
        .into_iter()
        .map(|resolved| resolved.unit)
        .collect();

        let lines: Vec<(&str, u64)> = units
            .iter()
            .map(|unit| (unit.name.as_str(), unit.count))
            .collect();
        assert_eq!(lines, vec![("result_row", 47), ("index_doc", 3)]);
    }

    #[test]
    fn claim_names_are_stable_on_the_wire() {
        for claim in [
            OriginClaim::Counted,
            OriginClaim::Malformed,
            OriginClaim::Absent,
        ] {
            let json = serde_json::to_string(&claim).expect("claim serialises");
            assert_eq!(json, format!("\"{}\"", claim.as_str()));
        }
        assert!(OriginClaim::Counted.is_counted());
        assert!(!OriginClaim::Malformed.is_counted());
        assert!(!OriginClaim::Absent.is_counted());
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The metered event and the units it carries.
//!
//! This module answers one question: what does a receipt have to say for a
//! buyer to be able to disagree with it? A number on its own is not enough.
//! `units: 5` cannot be checked, cannot be reproduced, and cannot be
//! disputed on any ground more specific than "that feels wrong", so an
//! invoice built from bare numbers is settled by whoever has more patience
//! rather than by whoever is right.
//!
//! So every [`Unit`] carries two extra things. [`UnitSource`] says which
//! mechanism produced the count, and [`Evidence`] carries the raw material
//! that mechanism worked from. Together they turn one unfalsifiable
//! complaint into three separately answerable ones:
//!
//! - the origin lied, which [`UnitSource::OriginHeader`] localises, because
//!   the header name and its verbatim value are both on the receipt;
//! - the proxy miscounted, which [`UnitSource::Measured`] localises, because
//!   the byte counts and duration the count was derived from are on the
//!   receipt too;
//! - the config that priced the call was not the config that was agreed,
//!   which [`UnitSource::RouteWeight`] localises through `config_revision`.
//!
//! The source is an enum and not a string. A string would let a resolver
//! write whatever provenance flattered it, and would let a new resolver ship
//! without anyone deciding how its numbers survive a partial delivery.
//! Deciding that is [`crate::outcome`]'s job, and it decides per source.

use crate::outcome::BillableOutcome;
use serde::{Deserialize, Serialize};

/// Who the consumption is charged to.
///
/// Three fields rather than one opaque account id, because a dispute is
/// usually about a slice rather than the whole bill. An operator who can only
/// say "your account used 40,000 units" cannot answer "which key, and which
/// agent" without going back to raw logs, and raw logs are exactly what the
/// receipt was supposed to replace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    /// The billing account the units are charged to. Always present: a unit
    /// with nobody to charge is not a metering event, it is a bug.
    pub tenant: String,
    /// Identifier of the credential that authenticated the call.
    ///
    /// An identifier, never key material. Absent when the route admits
    /// unauthenticated traffic that is still metered against a tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// The calling agent, when one identified itself.
    ///
    /// One tenant commonly runs many agents against the same key, and
    /// "which of my agents burned the budget" is a question an operator gets
    /// asked before the invoice is ever disputed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
}

/// Where a unit count came from.
///
/// An enum rather than a string, on purpose. This is the field that makes a
/// receipt falsifiable, so it has to be a closed set that the type system
/// polices: a resolver cannot claim a provenance that does not exist, and a
/// new resolver cannot be added without every consumer of this enum being
/// told about it.
///
/// The ordering is declaration order, and declaration order is trust order:
/// what the proxy counted itself, then what the operator's own config
/// asserted, then what the upstream claimed. Sorting a summary by source
/// therefore puts the lines a buyer can check hardest first, and
/// [`crate::segment::SegmentRecorder`] relies on the ordering to emit its
/// totals in a form that is stable between two readings of the same node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnitSource {
    /// Counted by the proxy from bytes and time it observed itself.
    ///
    /// The most trustworthy source, because nothing outside the proxy
    /// contributed to it. See [`crate::measured`].
    Measured,
    /// Assigned by the matched route's configured weight.
    ///
    /// Trustworthy only insofar as the config that assigned it is the config
    /// the buyer agreed to, which is why its evidence pins the generation.
    RouteWeight,
    /// Taken from a response header the origin set.
    ///
    /// The origin is the only party that knows how many rows it returned or
    /// how much work it did, and it is also the party with an incentive to
    /// inflate the number. Both facts are true at once, so the header name
    /// and its unmodified value both go on the receipt.
    OriginHeader,
}

impl UnitSource {
    /// Stable snake-case name used on the wire, in config, and in errors.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Measured => "measured",
            Self::RouteWeight => "route_weight",
            Self::OriginHeader => "origin_header",
        }
    }

    /// Whether the count grows with delivery rather than landing all at once.
    ///
    /// A measured unit counts bytes that really crossed the wire, so a client
    /// that hangs up halfway simply produces a smaller number and the count is
    /// still true. A route weight or an origin header asserts one whole unit of
    /// completed work, so it is either earned or it is not.
    ///
    /// [`crate::outcome::Billable::Partial`] uses this to decide which units to
    /// keep when the origin never produced a response. It is deliberately not
    /// the whole rule: see [`crate::outcome::OutcomeTable::billable_units`] for
    /// why work the origin already performed still bills after a cut.
    pub const fn accrues_continuously(self) -> bool {
        match self {
            Self::Measured => true,
            Self::RouteWeight | Self::OriginHeader => false,
        }
    }
}

/// The raw material a unit count was derived from.
///
/// One variant per [`UnitSource`], carrying whatever a person auditing the
/// receipt would need in order to redo the arithmetic. Serialised untagged,
/// because the sibling `source` field already names the variant and
/// repeating it would let the two disagree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Evidence {
    /// What the proxy observed on the wire. Backs [`UnitSource::Measured`].
    Measured {
        /// Request bytes received from the client.
        bytes_in: u64,
        /// Response bytes written to the client. On a connection that was
        /// cut this is what actually crossed, not what was intended.
        bytes_out: u64,
        /// Wall-clock milliseconds the request was in flight.
        duration_ms: u64,
    },
    /// The config revision that supplied the weight. Backs
    /// [`UnitSource::RouteWeight`].
    RouteWeight {
        /// Short hex tag of the routable origin set that was live when the
        /// weight was read, as `sbproxy-core` computes it over the sorted
        /// hostname set. It scopes the receipt to a serving generation, so
        /// receipts from two different origin sets cannot be conflated. It
        /// is deliberately not a hash of the document's contents: a weight
        /// edit behind an unchanged hostname set does not move it, so it
        /// does not by itself answer "you priced my call under a rate I
        /// never agreed to". The number that answers that is the unit's
        /// `count`, the applied weight, checked against the signed config
        /// bundle the buyer holds.
        ///
        /// A tag rather than a counter. There is no monotonic generation
        /// number anywhere in this proxy, and inventing one would produce an
        /// identifier that says a config changed without saying to what.
        config_revision: String,
    },
    /// What the origin claimed, verbatim. Backs
    /// [`UnitSource::OriginHeader`].
    OriginHeader {
        /// Name of the response header the count was read from.
        header: String,
        /// The header value exactly as the origin sent it, or `None` when
        /// the origin sent no such header at all.
        ///
        /// Absent and empty are separate statements and the encoding keeps
        /// them separate. `None` is "we looked and the origin said nothing";
        /// `Some("")` is "the origin set the header and put nothing in it".
        /// The first is usually an origin that has not been taught to report
        /// its own consumption and the second is usually a bug in one that
        /// has, so an operator chasing a metering gap needs to tell them
        /// apart before they know who to talk to.
        ///
        /// A present value is never trimmed, never re-formatted, and never
        /// re-serialised from the parsed number. If the origin sent `" 47 "`
        /// or `47.0` or `forty-seven`, that is what a buyer needs to see,
        /// because the disagreement may be about the parse rather than the
        /// number. A normalising receipt destroys the only record of what
        /// actually arrived.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        raw: Option<String>,
    },
}

impl Evidence {
    /// The source this evidence can support.
    ///
    /// Used by [`Unit::new`] so that a unit's declared provenance is derived
    /// from its proof rather than asserted alongside it.
    pub fn source(&self) -> UnitSource {
        match self {
            Self::Measured { .. } => UnitSource::Measured,
            Self::RouteWeight { .. } => UnitSource::RouteWeight,
            Self::OriginHeader { .. } => UnitSource::OriginHeader,
        }
    }
}

/// One billable quantity on a metered event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unit {
    /// Operator-chosen unit name, for example `search_call` or `egress_kib`.
    /// This is the name that appears on the invoice line.
    pub name: String,
    /// How many of the unit were consumed.
    pub count: u64,
    /// Which mechanism produced [`Unit::count`].
    pub source: UnitSource,
    /// The raw material [`Unit::count`] was derived from.
    pub evidence: Evidence,
}

impl Unit {
    /// Build a unit whose declared source is taken from its evidence.
    ///
    /// Preferred over a struct literal everywhere, because it makes the one
    /// interesting way to get this wrong unreachable: a unit that says
    /// `measured` while carrying an origin header has laundered a number the
    /// origin supplied into one the proxy vouches for.
    pub fn new(name: impl Into<String>, count: u64, evidence: Evidence) -> Self {
        Self {
            name: name.into(),
            count,
            source: evidence.source(),
            evidence,
        }
    }

    /// Whether the declared source matches the evidence carried.
    ///
    /// Always true for anything [`Unit::new`] built, so on the write side
    /// this is an invariant rather than a check. It is the read side this
    /// exists for: the wire format carries the two fields separately, a
    /// signature and a hash chain both say only that nobody changed the
    /// bytes, and a receipt that disagrees with itself survives both while
    /// asserting something no arithmetic can check.
    ///
    /// # Where it is enforced
    ///
    /// Nowhere, for a while, which is the defect that produced this
    /// paragraph: the doc used to tell callers the check was worth running
    /// on anything deserialised, and no decode path ran it. Saying so is
    /// not enforcement.
    ///
    /// The rule now reaches the wire through
    /// [`crate::ledger::LedgerPayload::provenance_conflict`], which
    /// [`crate::verify_ledger`] and the replay behind
    /// [`crate::ledger::UsageLedger::open`] call on every entry they
    /// decode. This proxy's own receipt payload lifts each wire unit back
    /// into this type and asks this method, so the wire form and this one
    /// cannot come to different answers about the same receipt; see
    /// `sbproxy_modules::policy::receipt_token::ReceiptUnit::provenance_is_consistent`.
    /// A new decode path is expected to go through the ledger, or to make
    /// the same call itself.
    pub fn provenance_is_consistent(&self) -> bool {
        self.source == self.evidence.source()
    }
}

/// One completed pass through the proxy, in the terms a bill is written in.
///
/// The digests are the same `Content-Digest` values the RFC 9421 egress
/// signer computes, so the signature over the traffic and the receipt over
/// the traffic cover identically the same bytes. Anything else would let a
/// buyer verify both and still be unable to say they describe one call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeteredEvent {
    /// Who is charged.
    pub subject: Subject,
    /// The route that matched, as the operator named it in config.
    pub route: String,
    /// Digest of the request bytes.
    pub request_digest: String,
    /// Digest of the response bytes, when there was a complete response.
    ///
    /// Absent when there was not: a blocked, rate-limited, or cut-short
    /// request produced no complete response, and a digest over a partial
    /// body would claim to cover something it does not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_digest: Option<String>,
    /// What happened, in the only terms a billing rule cares about.
    pub outcome: BillableOutcome,
    /// Everything billable that this pass accrued.
    ///
    /// On a cut-short response this holds what accrued before the cut, not
    /// what would have accrued had it finished. See
    /// [`crate::outcome::Billable::Partial`].
    pub units: Vec<Unit>,
    /// Groups every attempt at one unit of work under a single invoice line.
    ///
    /// Retries share it, which is what lets [`crate::outcome::Billable::Collapse`]
    /// charge four attempts once.
    pub claim_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_unit_takes_its_declared_source_from_its_evidence() {
        let unit = Unit::new(
            "result_row",
            47,
            Evidence::OriginHeader {
                header: "x-rows-returned".to_string(),
                raw: Some("47".to_string()),
            },
        );

        assert_eq!(unit.source, UnitSource::OriginHeader);
        assert!(unit.provenance_is_consistent());
    }

    #[test]
    fn a_unit_that_claims_the_wrong_source_is_caught() {
        // The shape a compromised or careless resolver would produce: a
        // number the origin supplied, wearing the provenance of a number the
        // proxy counted itself.
        let laundered = Unit {
            name: "result_row".to_string(),
            count: 47,
            source: UnitSource::Measured,
            evidence: Evidence::OriginHeader {
                header: "x-rows-returned".to_string(),
                raw: Some("47".to_string()),
            },
        };

        assert!(!laundered.provenance_is_consistent());
    }

    #[test]
    fn origin_header_evidence_round_trips_a_malformed_raw_value_verbatim() {
        // Whitespace, a decimal point, a trailing unit, and a newline. Every
        // one of these is something a real origin has sent, and every one is
        // something a receipt is tempted to tidy up on the way out.
        for raw in [
            " 47 ",
            "47.0",
            "47 rows",
            "0047",
            "47\n",
            "",
            "not-a-number",
        ] {
            let unit = Unit::new(
                "result_row",
                47,
                Evidence::OriginHeader {
                    header: "X-Rows-Returned".to_string(),
                    raw: Some(raw.to_string()),
                },
            );

            let json = serde_json::to_string(&unit).expect("unit serialises");
            let back: Unit = serde_json::from_str(&json).expect("unit deserialises");

            assert_eq!(back, unit);
            let Evidence::OriginHeader { header, raw: got } = &back.evidence else {
                panic!("origin-header evidence must not change variant in transit");
            };
            assert_eq!(
                got.as_deref(),
                Some(raw),
                "the origin's bytes are the evidence; normalising them destroys it"
            );
            assert_eq!(
                header, "X-Rows-Returned",
                "the header name is not lowercased either"
            );
        }
    }

    #[test]
    fn a_header_the_origin_never_set_is_not_a_header_it_set_to_nothing() {
        // The two live one field apart on the wire and mean different
        // things. `raw` absent is "we looked and found no header"; `raw: ""`
        // is "the origin set the header and left it blank". An encoding that
        // rendered both as the empty string would erase the only evidence of
        // which one happened.
        let absent = Unit::new(
            "result_row",
            0,
            Evidence::OriginHeader {
                header: "X-Rows-Returned".to_string(),
                raw: None,
            },
        );
        let blank = Unit::new(
            "result_row",
            0,
            Evidence::OriginHeader {
                header: "X-Rows-Returned".to_string(),
                raw: Some(String::new()),
            },
        );

        assert_ne!(absent, blank);

        let absent_json: serde_json::Value =
            serde_json::to_value(&absent).expect("unit serialises");
        let blank_json: serde_json::Value = serde_json::to_value(&blank).expect("unit serialises");

        assert!(
            absent_json["evidence"].get("raw").is_none(),
            "a value the origin never sent must not appear on the receipt as one it did"
        );
        assert_eq!(blank_json["evidence"]["raw"], "");

        for unit in [absent, blank] {
            let json = serde_json::to_string(&unit).expect("unit serialises");
            let back: Unit = serde_json::from_str(&json).expect("unit deserialises");
            assert_eq!(back, unit);
            assert_eq!(back.source, UnitSource::OriginHeader);
        }
    }

    #[test]
    fn route_weight_evidence_names_the_document_that_priced_the_call() {
        let unit = Unit::new(
            "search_call",
            5,
            Evidence::RouteWeight {
                config_revision: "9f2c41a0be77".to_string(),
            },
        );

        let json = serde_json::to_string(&unit).expect("unit serialises");
        let back: Unit = serde_json::from_str(&json).expect("unit deserialises");

        assert_eq!(back, unit);
        assert_eq!(back.source, UnitSource::RouteWeight);
        let Evidence::RouteWeight { config_revision } = &back.evidence else {
            panic!("route-weight evidence must not change variant in transit");
        };
        assert_eq!(config_revision, "9f2c41a0be77");
    }

    #[test]
    fn a_unit_serialises_its_source_beside_its_untagged_evidence() {
        let unit = Unit::new(
            "egress_kib",
            12,
            Evidence::Measured {
                bytes_in: 512,
                bytes_out: 12_043,
                duration_ms: 91,
            },
        );

        let value: serde_json::Value = serde_json::to_value(&unit).expect("unit serialises");

        assert_eq!(value["source"], "measured");
        assert_eq!(value["evidence"]["bytes_out"], 12_043);
        assert!(
            value["evidence"].get("config_revision").is_none(),
            "untagged evidence must not leak a sibling variant's fields"
        );
    }

    #[test]
    fn an_event_without_a_complete_response_carries_no_response_digest() {
        let event = MeteredEvent {
            subject: Subject {
                tenant: "acme".to_string(),
                key_id: Some("key_7".to_string()),
                agent: None,
            },
            route: "search".to_string(),
            request_digest: "sha-256=:abc:".to_string(),
            response_digest: None,
            outcome: BillableOutcome::PolicyBlocked,
            units: Vec::new(),
            claim_id: "claim_1".to_string(),
        };

        let value: serde_json::Value = serde_json::to_value(&event).expect("event serialises");

        assert!(
            value.get("response_digest").is_none(),
            "a digest over a response that never existed is a claim about nothing"
        );
        assert!(value["subject"].get("agent").is_none());
        assert_eq!(value["subject"]["key_id"], "key_7");
    }
}

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
//! event, the outcome table, and the unit resolvers. Chaining and signing
//! land on top of it later and sign this vocabulary rather than inventing
//! their own, so a buyer needs one verifier rather than two.
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
//! # A true leaf
//!
//! The crate depends on `serde` and nothing else. It deliberately does not
//! depend on `sbproxy-core`, `sbproxy-modules`, `sbproxy-ai`, or
//! `sbproxy-config`. An operator metering a plain REST API should not have to
//! compile the AI gateway to do it, and the existing usage ledger is typed to
//! LLM tokens for exactly that reason.
//!
//! # What is not here yet
//!
//! No hash chain, no receipt signing, no configuration surface, and no
//! resolvers beyond [`measured`]. Those arrive in later slices and build on
//! these types.

#![deny(missing_docs)]

pub mod event;
pub mod measured;
pub mod outcome;

pub use event::{Evidence, MeteredEvent, Subject, Unit, UnitSource};
pub use measured::{resolve_measured, MeasuredQuantity, MeasuredRule, Measurement};
pub use outcome::{Billable, BillableOutcome, Claim, OutcomeTable, OutcomeTableError};

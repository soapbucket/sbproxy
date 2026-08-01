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
//! # What is not here yet
//!
//! No configuration surface, and no resolvers beyond [`measured`]. Those
//! arrive in later slices and build on these types.

#![deny(missing_docs)]

pub mod event;
pub mod ledger;
pub mod measured;
pub mod outcome;

pub use event::{Evidence, MeteredEvent, Subject, Unit, UnitSource};
pub use ledger::{
    ledger_health, verify_ledger, verifying_key_from_seed_hex, LedgerEntry, LedgerHealth,
    LedgerPayload, LedgerVerifyResult, UsageLedger,
};
pub use measured::{resolve_measured, MeasuredQuantity, MeasuredRule, Measurement};
pub use outcome::{Billable, BillableOutcome, Claim, OutcomeTable, OutcomeTableError};

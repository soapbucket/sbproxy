//! The production transports the rail adapters dial providers through.
//!
//! Every adapter in this crate takes its transport as an injectable trait, so
//! the contract tests drive verify, settle, create, capture, retrieve, and
//! `listinvoices` deterministically without a socket. This module holds the
//! other implementation of those same traits: the one that actually reaches a
//! provider.
//!
//! Splitting it this way is what keeps the protocol rules and the socket
//! rules apart. An adapter decides what an answer has to say before it
//! authorizes; a transport decides nothing at all. It sends bytes, bounds the
//! response, and reports a timeout, a lost connection, or an oversized body
//! as one of three non-secret failures.
//!
//! | Transport | Trait | Reaches |
//! | --- | --- | --- |
//! | [`HttpFacilitatorTransport`] | [`FacilitatorTransport`](crate::x402::FacilitatorTransport) | The x402 facilitator API root |
//! | [`HttpStripeTransport`] | [`StripeTransport`](crate::stripe_payment::StripeTransport) and [`StripeMeterTransport`](crate::stripe_meter::StripeMeterTransport) | The Stripe API |
//! | [`UnixClnTransport`] | [`ClnTransport`](crate::lightning::cln::ClnTransport) | A local `lightning-rpc` socket |
//!
//! # LND has no production transport yet
//!
//! [`LndSettler`](crate::lightning::lnd::LndSettler) is complete and its
//! contract tests pass against a recording service, but the generated gRPC
//! client and the vendored upstream protobufs are a separate slice, so
//! nothing here implements
//! [`LndTransport`](crate::lightning::lnd::LndTransport). A build that
//! compiles `lightning-lnd` and configures `proxy.payments.rails.lightning_lnd`
//! registers no adapter and fails startup naming the rail, which is the same
//! path a rail whose feature is missing already takes. It cannot silently
//! accept a Lightning payment it has no way to settle.

#[cfg(any(feature = "x402", feature = "stripe"))]
mod http;

#[cfg(feature = "x402")]
mod facilitator;
#[cfg(feature = "x402")]
pub use facilitator::HttpFacilitatorTransport;

#[cfg(feature = "stripe")]
mod stripe;
#[cfg(feature = "stripe")]
pub use stripe::HttpStripeTransport;

// Core Lightning speaks JSON-RPC over a Unix domain socket, so this
// transport exists only where those exist. A Windows build that enables
// `lightning-cln` compiles, registers no adapter, and fails startup naming
// the rail rather than failing to build.
#[cfg(all(feature = "lightning-cln", unix))]
mod cln;
#[cfg(all(feature = "lightning-cln", unix))]
pub use cln::UnixClnTransport;

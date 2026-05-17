//! sbproxy-middleware: CORS, HSTS, compression, callback, and header modifier middleware.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod callback;
pub mod compression;
pub mod cors;
/// RFC 9530 Content-Digest / Repr-Digest compute, parse, and verify
/// helpers. The streaming `DigestSink` is the integration point for
/// the WOR-519 sign-on-egress wiring.
pub mod digest;
pub mod error_pages;
pub mod hsts;
/// Idempotency-Key middleware with cached-retry vs conflict semantics
/// (Wave 3 / R3.2, A3.4).
pub mod idempotency;
pub mod modifiers;
pub mod problem_details;
pub mod proxy_status;
/// Per-origin rate-limit middleware (WOR-66). Consumes the
/// `rate_limits:` block on `CompiledOrigin` and gates traffic ahead of
/// the per-origin policy chain.
pub mod rate_limit;
pub mod signatures;

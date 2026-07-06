//! sbproxy-middleware: CORS, HSTS, compression, and header modifier middleware.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod compression;
pub mod cors;
/// RFC 9530 Content-Digest / Repr-Digest compute, parse, and verify
/// helpers. The streaming `DigestSink` is the integration point for
/// the WOR-519 sign-on-egress wiring.
pub mod digest;
pub mod hsts;
/// Idempotency-Key middleware with cached-retry vs conflict semantics.
pub mod idempotency;
pub mod modifiers;
pub mod proxy_status;
pub mod signatures;
/// RFC 9421 HTTP Message Signatures: outbound signing path (sign on
/// egress). Companion to [`signatures`], which implements the inbound
/// verification half.
pub mod signatures_egress;
/// Web Bot Auth hosted key directory: publish SBproxy's own Ed25519
/// public keys as an HTTP Message Signatures directory (WOR-805).
pub mod web_bot_auth;

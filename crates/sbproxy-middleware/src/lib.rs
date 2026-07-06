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
/// Idempotency-Key middleware with cached-retry vs conflict semantics.
pub mod idempotency;
/// L402 (Lightning HTTP 402) bearer credential surface: issuer side
/// builds the `WWW-Authenticate: L402 macaroon=..., invoice=...`
/// challenge; verifier side accepts
/// `Authorization: L402 <macaroon>:<preimage>` and confirms the
/// preimage hash matches the macaroon's `payment_hash` caveat.
/// Stateless once the root key is fixed. WOR-807.
pub mod l402;
/// Macaroon bearer credentials (Birgisson et al. 2014). HMAC-SHA256
/// chained signature with first-party caveat attenuation. Backs the
/// L402 flow above and is reusable as a stand-alone token primitive.
pub mod macaroon;
pub mod modifiers;
pub mod problem_details;
pub mod proxy_status;
pub mod signatures;
/// RFC 9421 HTTP Message Signatures: outbound signing path (sign on
/// egress). Companion to [`signatures`], which implements the inbound
/// verification half.
pub mod signatures_egress;
/// Web Bot Auth hosted key directory: publish SBproxy's own Ed25519
/// public keys as an HTTP Message Signatures directory (WOR-805).
pub mod web_bot_auth;

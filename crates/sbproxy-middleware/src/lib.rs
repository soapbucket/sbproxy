//! sbproxy-middleware: CORS, HSTS, compression, callback, and header modifier middleware.

#![warn(missing_docs)]

pub mod callback;
pub mod compression;
pub mod cors;
pub mod error_pages;
pub mod hsts;
/// Idempotency-Key middleware with cached-retry vs conflict semantics
/// (Wave 3 / R3.2, A3.4).
pub mod idempotency;
pub mod modifiers;
pub mod problem_details;
pub mod proxy_status;
pub mod signatures;

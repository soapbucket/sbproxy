//! sbproxy-security: Cryptography, IP utilities, host filtering, PII masking, and SSRF protection.

#![warn(missing_docs)]

#[cfg(feature = "agent-class")]
pub mod agent_verify;
pub mod crypto;
#[cfg(feature = "tls-fingerprint")]
pub mod headless_detect;
pub mod hostfilter;
pub mod ip;
pub mod pii;
pub mod ssrf;

#[cfg(feature = "agent-class")]
pub use agent_verify::{
    verify_reverse_dns, Resolver, ReverseDnsCache, ReverseDnsVerdict, StubResolver, SystemResolver,
};
pub use crypto::hkdf_derive;
#[cfg(feature = "tls-fingerprint")]
pub use headless_detect::{
    detect as detect_headless, HeadlessSignal as HeadlessDetectSignal, TlsFingerprintCatalog,
    TlsFingerprintEntry,
};
pub use hostfilter::HostFilter;
pub use ip::{ip_in_cidrs, is_private_ip, parse_cidrs};
pub use pii::{mask_credit_card, mask_email, mask_ip, PiiConfig, PiiRedactor, PiiRule};
pub use ssrf::{validate_url, validate_url_resolved, validate_url_with_allowlist, ResolvedUrl};

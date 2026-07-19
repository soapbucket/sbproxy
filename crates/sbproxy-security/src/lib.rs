//! sbproxy-security: Cryptography, IP utilities, host filtering, PII masking, and SSRF protection.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "agent-class")]
pub mod agent_verify;
pub mod cookie;
pub mod crypto;
pub mod egress;
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
#[allow(deprecated)]
pub use crypto::hkdf_derive;
pub use crypto::{
    aes256gcm_decrypt, aes256gcm_encrypt, hkdf_derive_purpose, random_aes256_key,
    random_aes_gcm_nonce, HkdfPurpose, AES256_KEY_LEN, AES_GCM_NONCE_LEN,
};
#[cfg(feature = "tls-fingerprint")]
pub use headless_detect::{
    detect as detect_headless, HeadlessSignal as HeadlessDetectSignal, TlsFingerprintCatalog,
    TlsFingerprintEntry,
};
pub use egress::{
    AuthorizedDestination, EgressAuthorizer, EgressConfig, EgressDenied, EgressPurpose,
    GovernedHttpClient, GovernedHttpResponse, GovernedRedirectSeam, HostResolver,
    PurposeAllowlist, RedirectDecision,
};
pub use hostfilter::HostFilter;
pub use ip::{ip_in_cidrs, is_private_ip, parse_cidrs};
pub use pii::{mask_credit_card, mask_email, mask_ip, PiiConfig, PiiRedactor, PiiRule};
pub use ssrf::{validate_url, validate_url_resolved, validate_url_with_allowlist, ResolvedUrl};

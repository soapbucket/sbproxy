//! sbproxy-security: Cryptography, IP utilities, host filtering, PII
//! masking, URL redaction, and SSRF protection.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "agent-class")]
pub mod agent_verify;
pub mod cookie;
pub mod crypto;
pub mod egress;
pub mod governed_egress;
#[cfg(feature = "tls-fingerprint")]
pub mod headless_detect;
pub mod hostfilter;
pub mod ip;
pub mod pii;
pub mod sealed_record;
pub mod span;
pub mod ssrf;
pub mod url_redact;

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
// WOR-2165's additions (`evaluate_hop`, `record_egress_refused`,
// `CachedSystemResolver`, `SystemHostResolver`, `RedirectRule`,
// `RedirectHop`, `MAX_REDIRECT_HOPS`) are reached through
// `sbproxy_security::egress::` rather than re-exported here: every
// consumer already imports from the module path, and a root re-export
// nobody names is exactly the write-only surface the pub-item ratchet
// exists to stop.
pub use egress::{
    AuthorizedDestination, EgressAuthorizer, EgressConfig, EgressDenied, EgressPurpose,
    GovernedHttpClient, GovernedHttpResponse, GovernedRedirectSeam, HostResolver, PurposeAllowlist,
    RedirectDecision,
};
#[cfg(feature = "tls-fingerprint")]
pub use headless_detect::{
    detect as detect_headless, HeadlessSignal as HeadlessDetectSignal, TlsFingerprintCatalog,
    TlsFingerprintEntry,
};
pub use hostfilter::HostFilter;
pub use ip::{ip_in_cidrs, is_private_ip, parse_cidrs};
pub use pii::{mask_credit_card, mask_email, mask_ip, PiiConfig, PiiRedactor, PiiRule};
pub use sealed_record::{
    OpenOutcome, SealKey, SealKeyRing, SealScheme, SealedEnvelope, HEADER_LEN as SEAL_HEADER_LEN,
    KEY_FP_LEN as SEAL_KEY_FP_LEN, MIN_KEY_MATERIAL_BYTES as SEAL_MIN_KEY_MATERIAL_BYTES,
    SALT_LEN as SEAL_SALT_LEN,
};
pub use span::{cap_spans, DetectionSpan, MAX_DETECTION_SPANS};
pub use ssrf::{validate_url, validate_url_resolved, validate_url_with_allowlist, ResolvedUrl};

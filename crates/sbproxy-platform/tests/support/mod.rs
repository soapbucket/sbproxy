pub mod redis_server;

/// Select the process-level rustls `CryptoProvider` before any TLS type is
/// constructed.
///
/// rustls 0.23 only auto-detects a provider when exactly one backend feature
/// is enabled. The workspace-wide feature union enables both `ring` (via
/// sbproxy-vault and sbproxy-tls) and `aws-lc-rs` (via the AWS SDK), so
/// auto-detection panics with "Could not automatically determine the
/// process-level CryptoProvider". The binary handles this by installing
/// `ring` at the top of `main` (see `crates/sbproxy/src/main.rs`); a test
/// binary has no `main` of its own, so it has to do the same thing.
///
/// This used to be invisible because the Redis TLS lane ran as
/// `cargo test -p sbproxy-platform`, whose narrower package selection left
/// only one backend enabled. Do not rely on that: the check should hold
/// under whatever feature union the caller happens to resolve.
///
/// Idempotent, and cheap to call from every helper that builds a client.
pub fn install_default_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // `install_default` errors only if a provider is already installed,
        // which is a fine outcome here.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

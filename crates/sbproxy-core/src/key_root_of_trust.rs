// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Customer-managed root of trust for the upstream-credential envelope
//! (WOR-2568).
//!
//! # What this changes
//!
//! `key_management.crypto.master_key` resolves once at boot into a byte
//! string this process then holds for its whole life. A `vault://` reference
//! can point it at an external system, but that is the general secret-read
//! capability applied incidentally: the read happens once, the copy is
//! sbproxy's, and revoking the customer's grant afterwards does not take it
//! back. Every "the customer holds the key" claim built on that shape is
//! really "the customer held the key, once, at 03:14 on the day we booted".
//!
//! With `key_management.crypto.root_of_trust` configured, the envelope's
//! per-record data key is wrapped by an external key service and sbproxy
//! never receives the key that wrapped it. Opening a credential means asking
//! that service to unwrap, which means the service has to be reachable and
//! has to still authorize this caller. Revoking the grant stops decryption.
//!
//! # The number that is the product claim
//!
//! An unwrap per request would put a network round trip on the credential
//! path, so unwrapped data keys are cached for
//! `root_of_trust.unwrap_cache_ttl_secs`. That value is the deployment's
//! revocation-latency bound: however long the cache holds, that is how long
//! a revoked grant keeps working. `RootOfTrust::revocation_window` reports
//! it, `GET /admin/crypto/root-of-trust` prints it, and
//! `docs/key-management.md` states it. Nothing here rounds it down or
//! describes it as "immediate".
//!
//! Two other caches sit in front of this one and both are clamped so they
//! cannot quietly extend that bound:
//!
//! * the resolved-credential cache in [`crate::key_plane`], clamped to this
//!   window for customer-managed envelopes;
//! * this module's own unwrap cache, which is keyed by ciphertext and holds
//!   the data key, never the root key.
//!
//! # Fail-closed
//!
//! An unwrap that the external service refuses or cannot answer is an error.
//! There is no stale-serve arm here and deliberately so: the grace window in
//! `proxy.secrets.rotation` exists for a briefly unreachable *secret* store,
//! and applying it to the root of trust would mean a revoked grant keeps
//! working for the grace period on top of the cache window, which is exactly
//! the guarantee this feature exists to make true.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use sbproxy_config::types::{RootOfTrustConfig, RootOfTrustProvider};
use sbproxy_keystore::crypto::{RootOfTrust, UnwrappedDek};

/// How many unwrapped data keys this root caches at once.
///
/// Each entry is a plaintext data key held for at most the revocation
/// window, so this is a ceiling on how much decrypt capability a revocation
/// has to age out, and on what a heap dump yields.
const MAX_CACHED_DEKS: usize = 1024;

/// One cached unwrap: the data key and when it was obtained.
struct CachedDek {
    dek: Vec<u8>,
    at: Instant,
}

/// A root of trust backed by an external key service.
pub struct CustomerManagedRoot {
    client: sbproxy_vault::TransitClient,
    kek_name: String,
    window: Duration,
    cache: parking_lot::Mutex<std::collections::HashMap<String, CachedDek>>,
    /// Seconds since the unix epoch of the last successful liveness probe,
    /// or zero when none has succeeded yet. An atomic rather than a lock
    /// because the admin surface reads it on an unrelated thread and a
    /// stale read is harmless.
    last_liveness_unix: AtomicU64,
    /// Whether the most recent probe succeeded. Separate from the
    /// timestamp so "checked a minute ago and it failed" is
    /// distinguishable from "never checked".
    last_liveness_ok: AtomicBool,
}

impl std::fmt::Debug for CustomerManagedRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomerManagedRoot")
            .field("kek_name", &self.kek_name)
            .field("revocation_window_secs", &self.window.as_secs())
            .finish()
    }
}

impl CustomerManagedRoot {
    /// Build a root of trust from config, with `token` already resolved by
    /// the caller.
    ///
    /// The token arrives resolved rather than as a reference on purpose: the
    /// one crypto-material bug this codebase has actually shipped was a
    /// reference string used verbatim as key material, and a constructor
    /// that cannot see a reference cannot repeat it.
    ///
    /// # Errors
    ///
    /// An incomplete connection block, or a zero `unwrap_cache_ttl_secs`
    /// paired with nothing to bound it. A zero TTL is allowed and means
    /// every open consults the key service.
    pub fn new(cfg: &RootOfTrustConfig, token: String) -> Result<Self> {
        let RootOfTrustProvider::VaultTransit = cfg.provider;
        let client = sbproxy_vault::TransitClient::new(sbproxy_vault::TransitConfig {
            address: cfg.address.clone(),
            mount: cfg.mount.clone(),
            key_name: cfg.key_name.clone(),
            token,
            namespace: cfg.namespace.clone(),
        })?;
        let kek_name = client.kek_name();
        Ok(Self {
            client,
            kek_name,
            window: Duration::from_secs(cfg.unwrap_cache_ttl_secs),
            cache: parking_lot::Mutex::new(std::collections::HashMap::new()),
            last_liveness_unix: AtomicU64::new(0),
            last_liveness_ok: AtomicBool::new(false),
        })
    }

    /// A cached data key and the time left on it, or `None` when the entry
    /// is absent or its window has closed.
    ///
    /// Returning the *remaining* window rather than the full one is what
    /// stops this cache and the resolved-credential cache downstream from
    /// composing into two consecutive windows.
    fn cached(&self, wrapped: &str) -> Option<UnwrappedDek> {
        let cache = self.cache.lock();
        let entry = cache.get(wrapped)?;
        let elapsed = entry.at.elapsed();
        let valid_for = self.window.checked_sub(elapsed)?;
        (!valid_for.is_zero()).then(|| UnwrappedDek {
            dek: entry.dek.clone(),
            valid_for,
        })
    }

    /// Cache one unwrapped data key, evicting what has lapsed first.
    ///
    /// Bounded, and the bound matters more here than on the other maps this
    /// change added: every entry is a plaintext data key, and an unbounded
    /// map of them means a heap dump long after a revocation still yields
    /// keys the customer believes they took away. Lapsed entries are swept
    /// before each insert, so steady state is the working set rather than
    /// every ciphertext ever seen.
    fn remember(&self, wrapped: &str, dek: &[u8]) {
        let now = Instant::now();
        let mut cache = self.cache.lock();
        cache.retain(|_, entry| now.duration_since(entry.at) < self.window);
        if cache.len() >= MAX_CACHED_DEKS {
            // Everything present is still inside its window. Decline to
            // cache rather than evict a live entry: the cost is an extra
            // Transit round trip, and the alternative is a longer hold on
            // material somebody else is about to stop being allowed to read.
            return;
        }
        cache.insert(
            wrapped.to_string(),
            CachedDek {
                dek: dek.to_vec(),
                at: now,
            },
        );
    }
}

#[async_trait::async_trait]
impl RootOfTrust for CustomerManagedRoot {
    fn kek_name(&self) -> &str {
        &self.kek_name
    }

    async fn wrap_dek(&self, dek: &[u8]) -> Result<String> {
        let client = self.client.clone();
        let dek = dek.to_vec();
        // Captured here, on the async side, inside the request's span.
        // `spawn_blocking` loses the ambient context across the thread
        // boundary, so reading it inside the closure would read it on the
        // wrong thread and produce nothing.
        let trace = sbproxy_observe::telemetry::outbound_trace_headers(None);
        let wrapped = tokio::task::spawn_blocking(move || client.wrap(&dek, &trace))
            .await
            .context("root-of-trust wrap task panicked")?;
        sbproxy_observe::metrics::record_root_of_trust_operation("wrap", wrapped.is_ok());
        wrapped
    }

    async fn unwrap_dek(&self, wrapped: &str) -> Result<UnwrappedDek> {
        if let Some(hit) = self.cached(wrapped) {
            sbproxy_observe::metrics::record_root_of_trust_operation("unwrap_cached", true);
            return Ok(hit);
        }
        let client = self.client.clone();
        let ciphertext = wrapped.to_string();
        let trace = sbproxy_observe::telemetry::outbound_trace_headers(None);
        let result = tokio::task::spawn_blocking(move || client.unwrap(&ciphertext, &trace))
            .await
            .context("root-of-trust unwrap task panicked")?;
        sbproxy_observe::metrics::record_root_of_trust_operation("unwrap", result.is_ok());
        let dek = result?;
        self.remember(wrapped, &dek);
        Ok(UnwrappedDek {
            dek,
            // A fresh unwrap gets the whole window; a cache hit above gets
            // whatever is left of it.
            valid_for: self.window,
        })
    }

    fn revocation_window(&self) -> Duration {
        self.window
    }

    // The five below are why this impl block exists in the shape it does.
    // They are not defaults worth inheriting: the trait's defaults answer
    // "no liveness story", and every runtime caller holds an
    // `Arc<dyn RootOfTrust>`, so an inherent method with the same name is
    // invisible to all of them. Leaving these off the trait is what made
    // the background probe a no-op, the cache un-purgeable, and the admin
    // surface report a healthy root as never-probed.

    async fn probe_liveness(&self) -> Result<()> {
        let client = self.client.clone();
        // Empty trace: the probe runs on a timer with no request behind it,
        // so there is no trace for it to join. The wrap and unwrap paths do
        // have one and carry it.
        let result = tokio::task::spawn_blocking(move || client.liveness(&[]))
            .await
            .context("root-of-trust liveness probe task panicked")?;
        let ok = result.is_ok();
        self.last_liveness_ok.store(ok, Ordering::Relaxed);
        if ok {
            self.last_liveness_unix.store(now_unix(), Ordering::Relaxed);
        }
        sbproxy_observe::metrics::record_root_of_trust_liveness(ok);
        result
    }

    fn last_liveness_unix(&self) -> Option<u64> {
        match self.last_liveness_unix.load(Ordering::Relaxed) {
            0 => None,
            v => Some(v),
        }
    }

    fn last_liveness_ok(&self) -> bool {
        self.last_liveness_ok.load(Ordering::Relaxed)
    }

    fn cached_dek_count(&self) -> usize {
        let now = Instant::now();
        self.cache
            .lock()
            .values()
            .filter(|e| now.duration_since(e.at) < self.window)
            .count()
    }

    fn purge_cache(&self) {
        self.cache.lock().clear();
    }
}

/// Describe an installed root's liveness for the admin surface.
///
/// Reads the trait rather than a concrete type, because that is what the
/// crypto handle carries and what the admin route holds. A root with no
/// liveness story of its own answers through the trait's defaults.
pub fn describe(root: &Arc<dyn RootOfTrust>) -> serde_json::Value {
    serde_json::json!({
        "probe": if root.last_liveness_ok() { "ok" } else { "failed_or_never_run" },
        "last_success_unix": root.last_liveness_unix(),
        "cached_data_keys": root.cached_dek_count(),
        "detail": "cached data keys are what a revoked grant still has to age out; a failed \
                   probe purges them immediately",
    })
}

/// How often to probe the external key service, from config.
///
/// A free function taking `&RootOfTrustConfig` rather than a field read at
/// the call site: the caller holds the field behind an `Option` and across
/// a module boundary, and the config-reader guard proves a key is wired by
/// finding a typed field access. Zero disables the probe.
pub fn liveness_interval(cfg: &RootOfTrustConfig) -> Duration {
    Duration::from_secs(cfg.liveness_interval_secs)
}

/// Run the background liveness probe for an installed customer-managed
/// root. Driven on the key plane's own runtime by `activate_key_plane`.
///
/// A failed probe purges the unwrap cache. That is what turns the stated
/// revocation window into an upper bound rather than a per-entry lottery: a
/// grant revoked one second after an entry was cached would otherwise keep
/// that entry usable for the whole window, and the probe cuts it short.
pub async fn run_liveness_probe(root: Arc<dyn RootOfTrust>, interval: Duration) {
    if interval.is_zero() {
        return;
    }
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        if let Err(error) = root.probe_liveness().await {
            // The mount and the key name are operator-chosen non-secrets;
            // the token never appears.
            tracing::warn!(
                kek = %root.kek_name(),
                error = %error,
                "customer-managed root of trust is not answering; purging cached data keys so \
                 credential decryption stops now rather than at the end of each cache window"
            );
            root.purge_cache();
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> RootOfTrustConfig {
        RootOfTrustConfig {
            provider: RootOfTrustProvider::VaultTransit,
            address: "https://vault.example:8200".to_string(),
            mount: "transit".to_string(),
            key_name: "sbproxy-root".to_string(),
            token: "env:UNUSED".to_string(),
            namespace: None,
            unwrap_cache_ttl_secs: 60,
            liveness_interval_secs: 30,
        }
    }

    /// The stated revocation window is the configured cache TTL and
    /// nothing else. A test rather than a comment because this number is
    /// the product claim, and the easiest way to break the claim is for
    /// some later default to disagree with the field an operator set.
    #[test]
    fn the_revocation_window_is_the_configured_unwrap_ttl() {
        let mut c = cfg();
        c.unwrap_cache_ttl_secs = 17;
        let root: Arc<dyn RootOfTrust> =
            Arc::new(CustomerManagedRoot::new(&c, "s.token".to_string()).expect("builds"));
        assert_eq!(root.revocation_window(), Duration::from_secs(17));
        assert_eq!(root.kek_name(), "transit/sbproxy-root");
        assert_eq!(root.last_liveness_unix(), None);
        assert!(!root.last_liveness_ok());
        // The admin surface reads exactly these, through the trait. A
        // never-probed root genuinely reports this; see the test below for
        // why asserting only this shape is not enough.
        let described = describe(&root);
        assert_eq!(described["probe"], "failed_or_never_run");
        assert_eq!(described["cached_data_keys"], 0);
    }

    /// The liveness half of the product claim has to run *through the
    /// `dyn`*, because that is the only thing the runtime ever holds.
    ///
    /// This shipped once with `probe_liveness`, `last_liveness_ok`,
    /// `cached_dek_count`, and `purge_cache` as inherent methods that were
    /// never put on the trait. Every caller went through
    /// `Arc<dyn RootOfTrust>` and therefore hit the trait's "no liveness
    /// story" defaults: the background probe returned `Ok(())` without
    /// contacting Vault, the cache was never purged, and
    /// `GET /admin/crypto/root-of-trust` reported a healthy root with a
    /// warm cache as never-probed with zero cached keys. The test that
    /// existed asserted exactly those defaults through a `dyn` and passed
    /// for the wrong reason.
    ///
    /// So this one asserts the opposite: state recorded through the trait
    /// object is state the trait object reports back. Any method that
    /// slips off the impl block reddens it.
    #[tokio::test]
    async fn liveness_state_recorded_through_the_dyn_is_reported_through_the_dyn() {
        let mut c = cfg();
        c.unwrap_cache_ttl_secs = 600;
        let root: Arc<dyn RootOfTrust> =
            Arc::new(CustomerManagedRoot::new(&c, "s.token".to_string()).expect("builds"));

        // The address is unroutable, so this probe fails rather than
        // reaching a real Vault, which is all this needs: a *default*
        // `probe_liveness` returns `Ok(())` and records nothing, and a
        // forwarded one returns `Err` and records the failure.
        let probed = root.probe_liveness().await;
        assert!(
            probed.is_err(),
            "the probe must actually dial the key service; a trait default returns Ok(())              without contacting anything, which is what made the liveness half a no-op"
        );
        assert!(!root.last_liveness_ok());

        // Warm the cache through the trait, then confirm the trait reports
        // it and can clear it. With `cached_dek_count` and `purge_cache`
        // left off the impl these are 0 and a no-op, and an operator
        // watching a revocation reads "no decrypt capability left to age
        // out" on a cache that is full.
        root.purge_cache();
        assert_eq!(root.cached_dek_count(), 0);
        let concrete = CustomerManagedRoot::new(&c, "s.token".to_string()).expect("builds");
        concrete.remember("stub:v1:aa", b"0123456789abcdef0123456789abcdef");
        let warm: Arc<dyn RootOfTrust> = Arc::new(concrete);
        assert_eq!(
            warm.cached_dek_count(),
            1,
            "a warm cache must be visible through the trait, because that is what the admin              surface holds"
        );
        assert_eq!(describe(&warm)["cached_data_keys"], 1);
        warm.purge_cache();
        assert_eq!(
            warm.cached_dek_count(),
            0,
            "purge must reach the real cache through the trait, or a failed probe cannot cut a              revocation short"
        );
    }

    /// The cache hands back the time *left*, not a fresh window. This is
    /// the other half of the two-caches-compose bug: a downstream cache
    /// that inherits a full window from a nearly-expired data key extends
    /// the deployment's revocation bound without saying so.
    #[test]
    fn a_cached_data_key_reports_its_remaining_window() {
        let mut c = cfg();
        c.unwrap_cache_ttl_secs = 600;
        let root = CustomerManagedRoot::new(&c, "s.token".to_string()).expect("builds");
        root.remember("stub:v1:bb", b"0123456789abcdef0123456789abcdef");
        let hit = root.cached("stub:v1:bb").expect("a fresh entry is served");
        assert!(
            hit.valid_for <= Duration::from_secs(600),
            "the remaining window can never exceed the configured one: {:?}",
            hit.valid_for
        );
        assert!(
            hit.valid_for > Duration::from_secs(590),
            "a just-cached entry has nearly the whole window left: {:?}",
            hit.valid_for
        );

        // An entry past its window is not served at all.
        let expired = CustomerManagedRoot::new(
            &RootOfTrustConfig {
                unwrap_cache_ttl_secs: 0,
                ..cfg()
            },
            "s.token".to_string(),
        )
        .expect("builds");
        expired.remember("stub:v1:cc", b"0123456789abcdef0123456789abcdef");
        assert!(
            expired.cached("stub:v1:cc").is_none(),
            "a zero window means every unwrap consults the key service"
        );
    }

    #[test]
    fn an_unresolvable_token_never_reaches_the_client_as_a_reference() {
        // The constructor takes a resolved token, so the only way a
        // reference string could become the token is a caller that skipped
        // resolution. An empty token is what a failed resolution leaves,
        // and it is refused.
        let err = CustomerManagedRoot::new(&cfg(), String::new())
            .expect_err("an empty token must be refused");
        assert!(err.to_string().contains("token"), "{err}");
    }
}

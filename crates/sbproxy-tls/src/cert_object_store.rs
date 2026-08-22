// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Cloud object-storage cert backend (WOR-1775).
//!
//! An [`object_store`]-backed [`KVStore`] for the ACME cert store, so a
//! fleet can share certificates on S3, GCS, or Azure without running Redis
//! or a shared filesystem. Keys are hex-encoded object names under a
//! prefix. The distributed issuance lock uses object_store's atomic
//! `PutMode::Create` (S3 `If-None-Match`, GCS generation precondition), so
//! a fleet issues a cert once instead of stampeding the ACME CA.
//!
//! The [`KVStore`] trait is synchronous but object_store is async, so the
//! ops run on a dedicated runtime driven from a fresh thread. That never
//! calls `block_on` inside a caller's runtime (the ACME renewal task runs
//! in an async context), which would panic.

use std::future::Future;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use bytes::Bytes;
use futures::StreamExt;
use object_store::path::Path as ObjectPath;
use object_store::{ObjectStore, PutMode, PutOptions, PutPayload};
use sbproxy_platform::KVStore;
use sbproxy_security::url_redact::redacted_url;

/// Dedicated multi-thread runtime for the async object_store ops.
fn rt() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("sbproxy-certstore-os")
            .build()
            .expect("build object-store cert runtime")
    })
}

/// Drive an object_store future from a synchronous caller. A fresh scoped
/// thread calls `block_on`, so this never nests inside a caller's tokio
/// runtime (which would panic) - the ACME task calls the cert store from an
/// async context.
fn block_on<F>(fut: F) -> F::Output
where
    F: Future + Send,
    F::Output: Send,
{
    std::thread::scope(|s| {
        s.spawn(|| rt().block_on(fut))
            .join()
            .expect("object-store op thread panicked")
    })
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// An object-storage [`KVStore`] for ACME certs (S3 / GCS / Azure).
pub struct ObjectStoreCertKv {
    store: Arc<dyn ObjectStore>,
    prefix: ObjectPath,
}

impl ObjectStoreCertKv {
    /// Build from a URL such as `s3://bucket/prefix` or `gs://bucket/prefix`.
    /// Credentials are read from the environment (object_store `from_env`).
    ///
    /// Neither failure names more than the origin. `object_store` reads
    /// credentials from the environment, but nothing stops an operator
    /// writing `s3://key:secret@bucket/prefix`, and both of these errors
    /// are reported at boot where they get logged (WOR-2640).
    pub fn from_url(url: &str) -> Result<Self> {
        let mut parsed = url::Url::parse(url).context("cert store url did not parse")?;
        // Redacting our own context string is not enough on its own:
        // `object_store` echoes the URL it was handed back out of several
        // of its own errors (`Unable to recognise URL "..."`), and anyhow
        // prints the whole chain. So the credential is removed before the
        // URL is handed over.
        //
        // The password only. The username is not a credential here and
        // for one backend it is load bearing: `object_store`'s Azure
        // builder reads the username of an `abfs`/`abfss` URL as the ADLS
        // Gen2 filesystem name, so `abfss://fs@acct.dfs.core.windows.net`
        // means container `fs` on account `acct`. Clearing it sends the
        // builder down its fsspec branch, where `acct.dfs.core.windows.net`
        // is rejected as a container name for containing a dot, and the
        // whole cert store silently falls back to memory. The aws and gcp
        // builders never read the username at all, so leaving it costs
        // them nothing.
        let _ = parsed.set_password(None);
        let (store, prefix) = object_store::parse_url(&parsed)
            .with_context(|| format!("open object store {}", redacted_url(url)))?;
        Ok(Self {
            store: Arc::from(store),
            prefix,
        })
    }

    fn path(&self, key: &[u8]) -> ObjectPath {
        self.prefix.child(hex::encode(key))
    }
}

/// A lock object's payload: `"<expiry_unix>:<generation>:<hex(token)>"`.
///
/// An empty token with expiry 0 is a released lease. The object survives the
/// release rather than being deleted, because the generation in it is the
/// fencing token a bundle publication is checked against, and a deleted
/// object would restart the count at one (WOR-2633).
fn encode_lock(token: &[u8], expiry: u64, generation: u64) -> Vec<u8> {
    format!("{expiry}:{generation}:{}", hex::encode(token)).into_bytes()
}

/// Parse `(expiry, generation, hex_token)`. A payload written before
/// WOR-2633 has two fields and decodes as generation zero.
fn decode_lock(bytes: &[u8]) -> Option<(u64, u64, String)> {
    let s = std::str::from_utf8(bytes).ok()?;
    let mut parts = s.splitn(3, ':');
    let expiry: u64 = parts.next()?.parse().ok()?;
    let second = parts.next()?;
    match parts.next() {
        Some(token) => Some((expiry, second.parse().ok()?, token.to_string())),
        None => Some((expiry, 0, second.to_string())),
    }
}

/// A lease is expired the moment its deadline is reached, so a zero TTL is a
/// lease nobody holds. That makes "already expired" expressible without a
/// test having to sleep through a whole second.
fn lease_expired(expiry: u64) -> bool {
    unix_now() >= expiry
}

impl KVStore for ObjectStoreCertKv {
    fn get(&self, key: &[u8]) -> Result<Option<Bytes>> {
        let path = self.path(key);
        block_on(async {
            match self.store.get(&path).await {
                Ok(r) => Ok(Some(r.bytes().await?)),
                Err(object_store::Error::NotFound { .. }) => Ok(None),
                Err(e) => Err(e.into()),
            }
        })
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let path = self.path(key);
        let payload = PutPayload::from(value.to_vec());
        block_on(async {
            self.store
                .put(&path, payload)
                .await
                .map(|_| ())
                .map_err(Into::into)
        })
    }

    fn delete(&self, key: &[u8]) -> Result<()> {
        let path = self.path(key);
        block_on(async {
            match self.store.delete(&path).await {
                Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
                Err(e) => Err(e.into()),
            }
        })
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Bytes, Bytes)>> {
        block_on(async {
            let mut out = Vec::new();
            let mut stream = self.store.list(Some(&self.prefix));
            while let Some(meta) = stream.next().await {
                let meta = meta?;
                let name = meta.location.filename().unwrap_or_default();
                let Ok(key) = hex::decode(name) else { continue };
                if !key.starts_with(prefix) {
                    continue;
                }
                let value = self.store.get(&meta.location).await?.bytes().await?;
                out.push((Bytes::from(key), value));
            }
            Ok(out)
        })
    }

    fn try_lock(&self, key: &[u8], token: &[u8], ttl_secs: u64) -> Result<bool> {
        Ok(self.try_lock_fenced(key, token, ttl_secs)?.is_some())
    }

    fn try_lock_fenced(&self, key: &[u8], token: &[u8], ttl_secs: u64) -> Result<Option<u64>> {
        // WOR-1775 made first acquisition atomic with `PutMode::Create`
        // (S3 `If-None-Match`, GCS generation precondition). WOR-2633 does
        // the same for the other half: taking over an expired lease used to
        // read the object and then overwrite it unconditionally, so two
        // replicas that read the same stale lease both wrote and both
        // returned success. The takeover is now a conditional update against
        // the version the staleness decision was made on, which is the same
        // precondition the create path already relied on, and it publishes a
        // strictly higher generation so the superseded holder is fenced out
        // of the bundle store rather than trusted to notice.
        let path = self.path(key);
        block_on(async {
            let first = encode_lock(token, unix_now() + ttl_secs, 1);
            let opts = PutOptions {
                mode: PutMode::Create,
                ..Default::default()
            };
            match self
                .store
                .put_opts(&path, PutPayload::from(first), opts)
                .await
            {
                Ok(_) => return Ok(Some(1)),
                Err(object_store::Error::AlreadyExists { .. }) => {}
                Err(e) => return Err(e.into()),
            }

            let existing = match self.store.get(&path).await {
                Ok(r) => r,
                // Released between the create and the read. Report
                // contention; the caller retries on its next tick.
                Err(object_store::Error::NotFound { .. }) => return Ok(None),
                Err(e) => return Err(e.into()),
            };
            let version = object_store::UpdateVersion {
                e_tag: existing.meta.e_tag.clone(),
                version: existing.meta.version.clone(),
            };
            let bytes = existing.bytes().await?;
            let (expiry, generation, _) = decode_lock(&bytes).unwrap_or((0, 0, String::new()));
            if !lease_expired(expiry) {
                return Ok(None);
            }

            let next = generation.saturating_add(1);
            let payload = encode_lock(token, unix_now() + ttl_secs, next);
            match self
                .store
                .put_opts(
                    &path,
                    PutPayload::from(payload),
                    PutOptions {
                        mode: PutMode::Update(version),
                        ..Default::default()
                    },
                )
                .await
            {
                Ok(_) => Ok(Some(next)),
                // A peer changed the object between our read and our write.
                // Losing here is the whole point of the precondition.
                Err(object_store::Error::Precondition { .. })
                | Err(object_store::Error::AlreadyExists { .. }) => Ok(None),
                // No conditional write, no fence. Refusing the takeover is
                // the honest outcome: an unconditional overwrite here is
                // exactly the double acquisition WOR-2633 is about, and a
                // lock that quietly stops being a lock is worse than one
                // that says it cannot proceed. S3, GCS, and Azure all
                // support the precondition; `object_store`'s local
                // filesystem does not, and a single host should be using
                // the `file` backend anyway.
                Err(object_store::Error::NotImplemented) => {
                    tracing::warn!(
                        "this object store has no conditional write, so an expired ACME \
                         issuance lease cannot be taken over safely; use acme.storage_backend \
                         'file' for a single host or a bucket on s3/gcs/azure for a fleet"
                    );
                    Ok(None)
                }
                Err(e) => Err(e.into()),
            }
        })
    }

    fn renew_lock(&self, key: &[u8], token: &[u8], ttl_secs: u64) -> Result<bool> {
        // Conditional on the version we read, so a renewal can never extend
        // a lease a peer took over after ours lapsed.
        let path = self.path(key);
        let want = hex::encode(token);
        block_on(async {
            let existing = match self.store.get(&path).await {
                Ok(r) => r,
                Err(object_store::Error::NotFound { .. }) => return Ok(false),
                Err(e) => return Err(e.into()),
            };
            let version = object_store::UpdateVersion {
                e_tag: existing.meta.e_tag.clone(),
                version: existing.meta.version.clone(),
            };
            let bytes = existing.bytes().await?;
            let Some((_, generation, holder)) = decode_lock(&bytes) else {
                return Ok(false);
            };
            if holder != want {
                return Ok(false);
            }
            let payload = encode_lock(token, unix_now() + ttl_secs, generation);
            match self
                .store
                .put_opts(
                    &path,
                    PutPayload::from(payload),
                    PutOptions {
                        mode: PutMode::Update(version),
                        ..Default::default()
                    },
                )
                .await
            {
                Ok(_) => Ok(true),
                Err(object_store::Error::Precondition { .. })
                | Err(object_store::Error::AlreadyExists { .. })
                | Err(object_store::Error::NotImplemented) => Ok(false),
                Err(e) => Err(e.into()),
            }
        })
    }

    fn unlock(&self, key: &[u8], token: &[u8]) -> Result<()> {
        // Compare-and-release: rewrite as an expired, unheld lease while it
        // still carries our token, so we never release a lease a peer
        // acquired after ours expired. The generation survives the release.
        let path = self.path(key);
        let want = hex::encode(token);
        block_on(async {
            let existing = match self.store.get(&path).await {
                Ok(r) => r,
                Err(object_store::Error::NotFound { .. }) => return Ok(()),
                Err(e) => return Err(e.into()),
            };
            let version = object_store::UpdateVersion {
                e_tag: existing.meta.e_tag.clone(),
                version: existing.meta.version.clone(),
            };
            let bytes = existing.bytes().await?;
            let Some((_, generation, holder)) = decode_lock(&bytes) else {
                return Ok(());
            };
            if holder != want {
                return Ok(());
            }
            let released = PutPayload::from(encode_lock(b"", 0, generation));
            let conditional = self
                .store
                .put_opts(
                    &path,
                    released.clone(),
                    PutOptions {
                        mode: PutMode::Update(version),
                        ..Default::default()
                    },
                )
                .await;
            if matches!(conditional, Err(object_store::Error::NotImplemented)) {
                // No precondition available. An unconditional release is
                // still safe here in a way an unconditional takeover is not:
                // we verified our own token is on the object, and the only
                // writer that could have replaced it since is one that took
                // the lease over, which is a state we are releasing into
                // anyway.
                let _ = self.store.put(&path, released).await;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An in-memory object store exercises the same codepath as S3/GCS: it
    /// implements both `PutMode::Create` and the `PutMode::Update`
    /// precondition the fenced lease is built on, so the lock is testable
    /// without a cloud account. `object_store`'s local filesystem implements
    /// only the first, which is why it is not the harness here.
    fn local_kv() -> (ObjectStoreCertKv, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        (
            ObjectStoreCertKv {
                store,
                prefix: ObjectPath::from("certs"),
            },
            dir,
        )
    }

    #[test]
    fn from_url_reports_the_origin_and_never_the_password() {
        // `object_store` quotes the URL it was handed in its own error,
        // so this pins both halves: our context is redacted, and the
        // inner error has no password left to quote (WOR-2640).
        let url = "ftp://aclname:topsecret@bucket.test/certs";
        // `expect_err` would demand `Debug` on the store, which holds a
        // `dyn ObjectStore` and deliberately does not implement it.
        let Err(err) = ObjectStoreCertKv::from_url(url) else {
            unreachable!("ftp is not an object store");
        };
        let msg = format!("{err:#}");
        assert!(!msg.contains("topsecret"), "password leaked: {msg}");
        assert!(
            msg.contains("ftp://bucket.test"),
            "expected the redacted origin in the error, got: {msg}"
        );
    }

    /// The username is deliberately left on the URL, because for one
    /// backend it is not userinfo at all. `object_store`'s Azure builder
    /// reads the username of an `abfs`/`abfss` URL as the ADLS Gen2
    /// filesystem name. Clearing it takes the builder down its fsspec
    /// branch, where the account host is rejected as a container name for
    /// containing a dot, `parse_url` returns `Unable to recognise URL`,
    /// and `open_cert_backend` refuses to start (azure is a shared backend,
    /// so a failure to open it is fatal rather than a fallback).
    #[test]
    fn an_azure_filesystem_name_survives_into_the_builder() {
        // No credentials are needed to reach this point: the Azure
        // builder falls through to the managed-identity provider, which
        // constructs without a network call. What fails, and what this
        // pins, is URL recognition.
        for url in [
            "abfss://certs@myacct.dfs.core.windows.net/sbproxy",
            // The same shape with a password, which is stripped. The
            // builder never reads it, so the store still opens.
            "abfss://certs:hunter2@myacct.dfs.core.windows.net/sbproxy",
            "abfs://certs@myacct.dfs.core.windows.net/sbproxy",
        ] {
            if let Err(err) = ObjectStoreCertKv::from_url(url) {
                panic!("the azure filesystem name did not reach the builder: {err:#}");
            }
        }
    }

    #[test]
    fn from_url_does_not_echo_an_unparseable_value() {
        let Err(err) = ObjectStoreCertKv::from_url("hunter2") else {
            unreachable!("`hunter2` is not a url");
        };
        let msg = format!("{err:#}");
        assert!(!msg.contains("hunter2"), "input echoed back: {msg}");
    }

    /// A store with no conditional write, to pin the refusal.
    fn unconditional_kv() -> (ObjectStoreCertKv, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn ObjectStore> =
            Arc::new(object_store::local::LocalFileSystem::new_with_prefix(dir.path()).unwrap());
        (
            ObjectStoreCertKv {
                store,
                prefix: ObjectPath::from("certs"),
            },
            dir,
        )
    }

    #[test]
    fn a_store_without_a_conditional_write_refuses_to_take_over() {
        // WOR-2633: an unconditional overwrite here is the double
        // acquisition, so a backend that cannot fence declines instead.
        let (kv, _d) = unconditional_kv();
        let key = b"acme:lock:unfenced.com";
        assert!(kv.try_lock(key, b"old", 0).unwrap(), "first acquire");
        assert!(
            !kv.try_lock(key, b"new", 60).unwrap(),
            "an expired lease must not be taken over without a precondition"
        );
    }

    #[test]
    fn data_roundtrip_and_scan() {
        let (kv, _d) = local_kv();
        assert!(kv.get(b"acme:cert:a.com").unwrap().is_none());
        kv.put(b"acme:cert:a.com", b"CERT-A").unwrap();
        kv.put(b"acme:cert:b.com", b"CERT-B").unwrap();
        kv.put(b"acme:key:a.com", b"KEY-A").unwrap();
        assert_eq!(kv.get(b"acme:cert:a.com").unwrap().unwrap(), &b"CERT-A"[..]);
        let mut hosts: Vec<_> = kv
            .scan_prefix(b"acme:cert:")
            .unwrap()
            .into_iter()
            .map(|(k, _)| String::from_utf8(k.to_vec()).unwrap())
            .collect();
        hosts.sort();
        assert_eq!(hosts, vec!["acme:cert:a.com", "acme:cert:b.com"]);
        kv.delete(b"acme:cert:a.com").unwrap();
        assert!(kv.get(b"acme:cert:a.com").unwrap().is_none());
    }

    #[test]
    fn lock_is_exclusive_and_token_scoped() {
        let (kv, _d) = local_kv();
        let key = b"acme:lock:x.com";
        assert!(kv.try_lock(key, b"A", 60).unwrap(), "A acquires");
        assert!(!kv.try_lock(key, b"B", 60).unwrap(), "B blocked");
        kv.unlock(key, b"B").unwrap(); // non-owner: no-op
        assert!(!kv.try_lock(key, b"C", 60).unwrap(), "still held");
        kv.unlock(key, b"A").unwrap(); // owner: frees it
        assert!(kv.try_lock(key, b"D", 60).unwrap(), "free after release");
        kv.unlock(key, b"D").unwrap();
    }

    #[test]
    fn lock_steals_expired_lease() {
        let (kv, _d) = local_kv();
        let key = b"acme:lock:stale.com";
        assert!(kv.try_lock(key, b"old", 0).unwrap());
        assert!(
            kv.try_lock(key, b"new", 60).unwrap(),
            "expired lease stolen"
        );
        kv.unlock(key, b"old").unwrap(); // stale owner cannot free the new lock
        assert!(!kv.try_lock(key, b"other", 60).unwrap(), "new holder holds");
    }

    #[test]
    fn takeover_generations_strictly_increase_and_renewal_is_owner_only() {
        // WOR-2633: the generation is the fencing token a publication is
        // checked against, so it has to keep climbing across release and
        // across takeover, and renewal has to refuse a superseded holder.
        let (kv, _d) = local_kv();
        let key = b"acme:lock:fenced.com";
        let first = kv.try_lock_fenced(key, b"a", 60).unwrap().unwrap();
        assert!(kv.renew_lock(key, b"a", 60).unwrap(), "owner renews");
        assert!(!kv.renew_lock(key, b"b", 60).unwrap(), "non-owner does not");
        kv.unlock(key, b"a").unwrap();
        let second = kv.try_lock_fenced(key, b"b", 0).unwrap().unwrap();
        assert!(second > first, "{second} must exceed {first}");
        let third = kv.try_lock_fenced(key, b"c", 60).unwrap().unwrap();
        assert!(third > second, "{third} must exceed {second}");
        assert!(
            !kv.renew_lock(key, b"b", 60).unwrap(),
            "a superseded holder must not renew"
        );
    }

    #[test]
    fn two_barriered_stealers_of_a_stale_object_lease_hand_it_to_exactly_one() {
        // WOR-2633: the takeover is a conditional update against the
        // version the staleness decision was made on, so of two contenders
        // racing the same expired lease, the second write must lose its
        // precondition. Before the fix both overwrote and both returned
        // success. Barriered and repeated, because a single round can
        // interleave safely by accident.
        let key = b"acme:lock:contended.com";
        for round in 0..50usize {
            let (kv, _d) = local_kv();
            let kv = std::sync::Arc::new(kv);
            // A zero TTL is a lease that is expired the moment it lands.
            assert!(kv.try_lock(key, b"crashed-owner", 0).unwrap());

            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let mut handles = Vec::new();
            for token in [b"contender-b".as_slice(), b"contender-c".as_slice()] {
                let kv = std::sync::Arc::clone(&kv);
                let barrier = std::sync::Arc::clone(&barrier);
                handles.push(std::thread::spawn(move || {
                    barrier.wait();
                    kv.try_lock_fenced(key, token, 60).unwrap()
                }));
            }
            let generations: Vec<u64> = handles
                .into_iter()
                .filter_map(|h| h.join().unwrap())
                .collect();
            assert_eq!(
                generations.len(),
                1,
                "round {round}: an expired lease must go to exactly one \
                 contender, got {generations:?}"
            );
            assert!(
                generations[0] > 1,
                "round {round}: the takeover must supersede the crashed \
                 owner's generation"
            );
        }
    }
}

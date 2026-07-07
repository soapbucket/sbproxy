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
    pub fn from_url(url: &str) -> Result<Self> {
        let parsed = url::Url::parse(url).with_context(|| format!("parse cert store url {url}"))?;
        let (store, prefix) =
            object_store::parse_url(&parsed).with_context(|| format!("open object store {url}"))?;
        Ok(Self {
            store: Arc::from(store),
            prefix,
        })
    }

    fn path(&self, key: &[u8]) -> ObjectPath {
        self.prefix.child(hex::encode(key))
    }
}

/// A lock object's payload: `"<expiry_unix>:<hex(token)>"`.
fn encode_lock(token: &[u8], expiry: u64) -> Vec<u8> {
    format!("{expiry}:{}", hex::encode(token)).into_bytes()
}

/// Parse `(expiry, hex_token)` from a lock object's payload.
fn decode_lock(bytes: &[u8]) -> Option<(u64, String)> {
    let s = std::str::from_utf8(bytes).ok()?;
    let (exp, tok) = s.split_once(':')?;
    Some((exp.parse().ok()?, tok.to_string()))
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
        // WOR-1775: atomic create-if-absent (PutMode::Create) is the lease.
        // On contention, steal only an expired lease (crashed holder); the
        // ACME task re-checks the cert under the lock, so a rare double
        // acquire does not double-issue.
        let path = self.path(key);
        let payload = encode_lock(token, unix_now() + ttl_secs);
        block_on(async {
            let opts = PutOptions {
                mode: PutMode::Create,
                ..Default::default()
            };
            match self
                .store
                .put_opts(&path, PutPayload::from(payload.clone()), opts)
                .await
            {
                Ok(_) => Ok(true),
                Err(object_store::Error::AlreadyExists { .. }) => {
                    match self.store.get(&path).await {
                        Ok(r) => {
                            let existing = r.bytes().await?;
                            let expired = decode_lock(&existing)
                                .map(|(exp, _)| unix_now() > exp)
                                .unwrap_or(true);
                            if expired {
                                // Overwrite the stale lease with ours.
                                self.store
                                    .put_opts(
                                        &path,
                                        PutPayload::from(payload),
                                        PutOptions {
                                            mode: PutMode::Overwrite,
                                            ..Default::default()
                                        },
                                    )
                                    .await?;
                                Ok(true)
                            } else {
                                Ok(false)
                            }
                        }
                        Err(object_store::Error::NotFound { .. }) => Ok(false),
                        Err(e) => Err(e.into()),
                    }
                }
                Err(e) => Err(e.into()),
            }
        })
    }

    fn unlock(&self, key: &[u8], token: &[u8]) -> Result<()> {
        // Compare-and-delete: only remove the lock while it still holds our
        // token, so we never release a lease a peer acquired after ours
        // expired.
        let path = self.path(key);
        let want = hex::encode(token);
        block_on(async {
            match self.store.get(&path).await {
                Ok(r) => {
                    let existing = r.bytes().await?;
                    if decode_lock(&existing)
                        .map(|(_, t)| t == want)
                        .unwrap_or(false)
                    {
                        let _ = self.store.delete(&path).await;
                    }
                    Ok(())
                }
                Err(object_store::Error::NotFound { .. }) => Ok(()),
                Err(e) => Err(e.into()),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A local-filesystem object store exercises the same codepath as S3/GCS
    /// (object_store's `LocalFileSystem` supports `PutMode::Create`), so the
    /// data ops and the lock are testable without a cloud account.
    fn local_kv() -> (ObjectStoreCertKv, tempfile::TempDir) {
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
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(
            kv.try_lock(key, b"new", 60).unwrap(),
            "expired lease stolen"
        );
        kv.unlock(key, b"old").unwrap(); // stale owner cannot free the new lock
        assert!(!kv.try_lock(key, b"other", 60).unwrap(), "new holder holds");
    }
}

//! Mutable system-of-record for sbproxy's inbound virtual keys and upstream
//! provider credentials.
//!
//! This crate is distinct from `sbproxy-vault`: the vault reads *external*
//! secrets (HashiCorp, AWS/GCP Secrets Manager, ...), whereas the key store is
//! sbproxy's own *mutable* system-of-record that operators assign, revoke, and
//! rotate at runtime. A key becomes a live governed resource instead of a line
//! of YAML.
//!
//! Layers:
//!
//! * [`KeyStore`] - a pluggable async trait over two record kinds
//!   ([`KeyRecord`], [`CredentialRecord`]). Backends: [`MemoryKeyStore`]
//!   (tests / ephemeral), [`EmbeddedKeyStore`] (redb, the default), plus Redis
//!   and secrets-manager-direct behind feature flags.
//! * `TtlCache` - a fail-closed, in-memory TTL cache in front of any
//!   `KeyStore`, with an invalidation API and an optional second tier.
//! * [`crypto`] - inbound keys are hashed at rest (HMAC-SHA256 + pepper);
//!   upstream credentials are sealed in an AEAD [`crypto::Envelope`].

pub mod cache;
pub mod crypto;
pub mod memory;
pub mod record;

#[cfg(feature = "embedded")]
pub mod embedded;

#[cfg(feature = "redis-backend")]
pub mod redis_store;

#[cfg(feature = "secrets-manager")]
pub mod secrets_manager;

use anyhow::Result;
use async_trait::async_trait;

pub use cache::{CacheTier, TtlCache, TtlCacheConfig};
pub use memory::MemoryKeyStore;
pub use record::{
    CredentialMaterial, CredentialRecord, KeyRecord, RecordBudget, RecordSource, RecordStatus,
};

#[cfg(feature = "embedded")]
pub use embedded::EmbeddedKeyStore;

/// Result of an optimistic key-policy mutation.
///
/// Conflict and unsupported outcomes never carry the key record, verifier
/// hashes, or bearer material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPolicyCasResult {
    /// The record was atomically written at the returned revision.
    Applied {
        /// New monotonic per-record policy revision.
        policy_revision: u64,
    },
    /// The stored record changed after the caller read it.
    Conflict {
        /// Current stored revision. No record contents are disclosed.
        actual_revision: u64,
    },
    /// No key exists at the candidate record's `key_id`.
    NotFound,
    /// This backend cannot provide an atomic compare-and-swap primitive.
    Unsupported,
}

fn next_policy_revision(expected_revision: u64) -> Result<u64> {
    expected_revision
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("key policy revision overflow"))
}

/// A pluggable, mutable store of inbound virtual keys and upstream credentials.
///
/// Implementations are the system-of-record. Lookups are by stable id: inbound
/// keys by their public `key_id` (the token prefix), credentials by their `id`.
/// Secret verification happens above the store (see [`crypto::verify_secret`]
/// and [`KeyRecord::verify_secret`]); the store only persists hashes/envelopes.
#[async_trait]
pub trait KeyStore: Send + Sync {
    /// Fetch a key record by its public id.
    async fn get_key(&self, key_id: &str) -> Result<Option<KeyRecord>>;

    /// List all key records.
    async fn list_keys(&self) -> Result<Vec<KeyRecord>>;

    /// Insert or replace a key record (keyed on `key_id`).
    async fn put_key(&self, record: KeyRecord) -> Result<()>;

    /// Atomically replace an existing key when its policy revision matches.
    ///
    /// Implementations set the stored revision to `expected_revision + 1` in
    /// the same atomic operation as the record write and global revision bump.
    /// Backends without a safe primitive return
    /// [`KeyPolicyCasResult::Unsupported`] without writing.
    async fn put_key_if_revision(
        &self,
        record: KeyRecord,
        expected_revision: u64,
    ) -> Result<KeyPolicyCasResult>;

    /// Delete a key record. Deleting an absent id is not an error.
    async fn delete_key(&self, key_id: &str) -> Result<()>;

    /// Fetch a credential record by its id.
    async fn get_credential(&self, id: &str) -> Result<Option<CredentialRecord>>;

    /// List all credential records.
    async fn list_credentials(&self) -> Result<Vec<CredentialRecord>>;

    /// Insert or replace a credential record (keyed on `id`).
    async fn put_credential(&self, record: CredentialRecord) -> Result<()>;

    /// Delete a credential record. Deleting an absent id is not an error.
    async fn delete_credential(&self, id: &str) -> Result<()>;

    /// A monotonic revision number, bumped on every mutation. The cache uses it
    /// to cheaply detect that a peer changed the store underneath it.
    async fn revision(&self) -> Result<u64>;
}

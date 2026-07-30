//! Where a cache keeps its entries, and whether that is protected.
//!
//! Several caches in this workspace are memory-only today and one
//! backend swap away from becoming at-rest surfaces. The prompt cache in
//! [`crate::two_tier`] says outright that real embedding caching with
//! cluster-wide replication comes from an out-of-tree backend, and the
//! judge cache is `pub` specifically so an out-of-tree crate can swap
//! its in-memory backing for Redis. Neither swap would fail any check
//! that exists today, so the day one lands, prompts and verdicts start
//! being written somewhere they were never written before and nothing
//! says so.
//!
//! Encrypting a memory-only cache is not the answer. An attacker who can
//! read process heap can read the derived key out of the same heap, so
//! it buys close to nothing and adds a key-management surface. What is
//! worth having is a declaration: every cache says where its entries
//! live and whether it seals them, and a boot-time check refuses the
//! combination that would store plaintext somewhere durable.
//!
//! The declaration is a default-implemented trait method, so an
//! out-of-tree backend that does nothing inherits [`Ephemeral`] and is
//! believed. That is deliberate: this guard catches the honest
//! implementation that forgot, which is the realistic failure. It is not
//! a defence against a backend that lies about itself, and it is not
//! trying to be.
//!
//! [`Ephemeral`]: CacheDurability::Ephemeral

/// Where a cache's entries live once written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheDurability {
    /// Process heap only. Entries die with the process and never reach
    /// disk, a network peer, or another replica.
    Ephemeral,
    /// Written to local storage and readable after a restart, or by
    /// anything else with access to the same path.
    Persistent,
    /// Sent to a shared server or to peer replicas, so entries exist on
    /// machines other than the one that wrote them.
    Replicated,
}

impl CacheDurability {
    /// Whether entries outlive the process or leave the machine.
    ///
    /// This is the question that decides whether at-rest encryption is
    /// meaningful, so it is one method rather than two comparisons at
    /// every call site.
    pub fn leaves_the_process(self) -> bool {
        !matches!(self, CacheDurability::Ephemeral)
    }

    /// Short name for logs and error messages.
    pub fn as_str(self) -> &'static str {
        match self {
            CacheDurability::Ephemeral => "ephemeral",
            CacheDurability::Persistent => "persistent",
            CacheDurability::Replicated => "replicated",
        }
    }
}

/// One cache surface's durability plus whether it seals what it stores.
#[derive(Debug, Clone, Copy)]
pub struct AtRestPosture {
    /// Where this cache's entries live.
    pub durability: CacheDurability,
    /// Whether entries are sealed before they leave the process.
    pub encrypted: bool,
}

impl AtRestPosture {
    /// The posture of a cache that never leaves process heap. The
    /// default for every surface that does not say otherwise.
    pub const fn memory_only() -> Self {
        Self {
            durability: CacheDurability::Ephemeral,
            encrypted: false,
        }
    }

    /// Declare a posture explicitly.
    pub const fn new(durability: CacheDurability, encrypted: bool) -> Self {
        Self {
            durability,
            encrypted,
        }
    }

    /// Whether this cache writes plaintext somewhere it outlives the
    /// process or leaves the machine.
    pub fn stores_plaintext_at_rest(&self) -> bool {
        self.durability.leaves_the_process() && !self.encrypted
    }
}

impl Default for AtRestPosture {
    fn default() -> Self {
        Self::memory_only()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_non_ephemeral_unencrypted_cache_is_exposed() {
        assert!(!AtRestPosture::memory_only().stores_plaintext_at_rest());
        assert!(
            AtRestPosture::new(CacheDurability::Persistent, false).stores_plaintext_at_rest(),
            "a cache that survives a restart in the clear is the case this exists for"
        );
        assert!(AtRestPosture::new(CacheDurability::Replicated, false).stores_plaintext_at_rest());
        assert!(!AtRestPosture::new(CacheDurability::Persistent, true).stores_plaintext_at_rest());
        assert!(!AtRestPosture::new(CacheDurability::Replicated, true).stores_plaintext_at_rest());
    }

    #[test]
    fn an_encrypted_ephemeral_cache_is_not_exposed_either() {
        // Encrypting memory buys nothing, but declaring it does not make
        // the surface exposed. The check is about durability first.
        assert!(!AtRestPosture::new(CacheDurability::Ephemeral, true).stores_plaintext_at_rest());
    }

    #[test]
    fn the_default_is_memory_only() {
        let posture = AtRestPosture::default();
        assert_eq!(posture.durability, CacheDurability::Ephemeral);
        assert!(!posture.encrypted);
    }
}

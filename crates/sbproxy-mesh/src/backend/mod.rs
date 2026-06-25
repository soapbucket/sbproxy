//! Optional centralized backend adapters.
//!
//! For teams that prefer centralized state management over pure CRDTs,
//! these backends provide a familiar key-value interface. The mesh can
//! operate without any backend (pure gossip + CRDTs), but these adapters
//! allow gradual migration or hybrid deployments.

pub mod redis;

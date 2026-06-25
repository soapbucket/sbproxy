//! Peer discovery: find other mesh nodes to join.

pub mod cloud;
pub mod consul;
pub mod dns;
pub mod kubernetes;
pub mod seeds;

use anyhow::Result;

/// Trait for peer discovery backends.
pub trait Discovery: Send + Sync {
    /// Discover peer addresses to attempt joining.
    fn discover(&self) -> Result<Vec<String>>;
}

//! Agent identity: a signed catalog of known agents, and an owner-approval
//! queue for agents that want to register themselves.
//!
//! # What this is for
//!
//! An operator running a proxy in front of anything an automated client
//! reaches has two questions about a caller that claims to be an agent.
//! Which agent is this, and did we agree to let it in? The catalog answers
//! the first from a feed a publisher signs. The registration queue answers
//! the second, by making admission a decision a human made rather than a
//! side effect of a request arriving.
//!
//! # No database, and no sidecar
//!
//! Both halves keep their state in the shared embedded store,
//! [`sbproxy_platform::storage::PersistentKv`] over redb, with the
//! duplicate-submission window in the ephemeral half of that same pair. The
//! implementation this replaces kept the catalog cache and the registration
//! queue in Postgres, and had the Postgres feature in its default set, so
//! there was no build of it that ran without one. Nothing here needs a
//! database, a broker, or a process the deployment has to keep alive.
//!
//! # Module map
//!
//! * [`feed`] is the wire format and the two-tier Ed25519 verification that
//!   decides whether a document is allowed to become a catalog.
//! * [`catalog`] is the hot-swapped in-memory catalog plus its durable
//!   last-good copy.
//! * [`registration`] is the submission shape, the minted credentials, and
//!   the approval state machine.
//! * [`service`] is the facade that owns both and produces everything an
//!   operator sees.
//! * [`admin`] is the HTTP surface, as one pure dispatcher.
//!
//! # Getting started
//!
//! ```no_run
//! use std::sync::Arc;
//! use sbproxy_agent_registry::{AgentRegistry, AgentRegistryOptions};
//! use sbproxy_platform::storage::{EmbeddedKvStore, MemoryKv};
//!
//! # async fn example() -> anyhow::Result<()> {
//! let store = Arc::new(EmbeddedKvStore::open(
//!     "/var/lib/sbproxy/agent-registry.redb",
//!     "agent_registry",
//! )?);
//! let registry = AgentRegistry::new(
//!     store,
//!     Arc::new(MemoryKv::new("agent_registry")),
//!     AgentRegistryOptions::default(),
//! )?;
//! registry.boot().await?;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod admin;
pub mod catalog;
pub mod error;
pub mod feed;
pub mod metrics;
pub mod registration;
pub mod service;

pub use catalog::{Catalog, CatalogApplied, CatalogHealth};
pub use error::{RegistryError, Result};
pub use feed::{AgentFeed, BootstrapKeys, FeedEntry};
pub use registration::{
    AgentMetadata, ApprovalState, Purpose, RegistrationSecrets, RegistrationView, RequestedScope,
    RotatedSecret, TenantScope, DEFAULT_TENANT,
};
pub use service::{AgentRegistry, AgentRegistryOptions, RegistrySummary};

//! Distributed clustering layer for sbproxy.
//!
//! This crate turns a pool of sbproxy instances into a single logical mesh
//! with shared identity, membership, liveness, and typed state. Keys, fleet
//! metrics, and managed models consume one [`ClusterHandle`] instead of
//! bootstrapping separate meshes. High-level components:
//!
//! * [`bootstrap`] wires everything together and returns a [`MeshNode`]
//!   owned by the distributed [`ClusterHandle`] implementation.
//! * [`cluster_handle`] exposes the shared local or distributed substrate and
//!   its generation-fenced typed state.
//! * [`node`] / [`node_handle`] model the local node and expose the
//!   runtime handle that the rest of sbproxy holds.
//! * [`config`] defines the typed configuration the node consumes.
//! * [`gossip`] / [`gossip_loop`] implement the SWIM-style heartbeat
//!   protocol: random probes, PING-REQ witnesses, state-change
//!   piggybacking for dissemination.
//! * [`isolation`] / [`split_brain`] detect network partitions and
//!   quarantine an isolated node until it rejoins a majority.
//! * [`transport`] carries gossip and request traffic over encrypted UDP
//!   + TCP endpoints.
//! * [`crypto`] / [`encryption`] / [`peer_auth`] secure the wire ([`peer_auth`]
//!   adds X.509 mutual TLS; its verifier is permissively licensed).
//! * [`state`] owns the CRDT-backed distributed cache and its sharding
//!   logic.
//! * [`discovery`] / [`persistence`] / [`backend`] plug into DNS,
//!   Kubernetes, on-disk snapshots, and pluggable storage backends.
//! * [`metrics`] / [`cluster_metrics`] expose Prometheus counters.
//!
//! Most consumers use a clone of [`ClusterHandle`]. Direct [`MeshNode`] access
//! remains available to compatibility adapters during the ownership migration.

#![deny(missing_docs)]

pub mod backend;
pub mod bootstrap;
pub mod bridge;
pub mod cluster_handle;
pub mod cluster_metrics;
pub mod config;
pub mod crypto;
pub mod discovery;
pub mod encryption;
pub mod enrollment;
pub mod federation;
pub mod gossip;
pub mod gossip_loop;
pub mod isolation;
pub mod metrics;
pub mod node;
pub mod node_handle;
pub mod peer_auth;
pub mod peer_eviction;
pub mod peer_identity;
pub mod persistence;
pub mod split_brain;
pub mod state;
pub mod transport;

// --- Re-exports ---

pub use cluster_handle::{
    ClusterHandle, ClusterIdentity, ClusterMember, ClusterMemberState, ClusterMode,
    ClusterNodeRole, ClusterStateError, ClusterStateKeySnapshot, ClusterStateRead,
    ClusterStateRecord, ClusterVersionedStateKind, ClusterVersionedStateRead,
    ClusterVersionedStateRecord,
};
pub use node_handle::MeshNode;
pub use state::register::VersionedLwwMergeOutcome;

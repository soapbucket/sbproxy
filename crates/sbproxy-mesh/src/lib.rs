//! Distributed clustering layer for sbproxy.
//!
//! This crate turns a pool of sbproxy instances into a single logical mesh
//! with shared state (rate-limit counters, session tracking, cache entries)
//! replicated via gossip + CRDTs. It backs the dynamic key plane's clusterwide
//! cache tier and cross-replica spend counters. High-level components:
//!
//! * [`bootstrap`] wires everything together and returns a [`MeshNode`]
//!   handle. Most callers only need this entry point.
//! * [`node`] / [`node_handle`] model the local node and expose the
//!   runtime handle that the rest of sbproxy holds.
//! * [`config`] defines the typed configuration the node consumes.
//! * [`gossip`] / [`gossip_loop`] implement the SWIM-style heartbeat
//!   protocol: random probes, PING-REQ witnesses, state-change
//!   piggybacking for dissemination.
//! * [`membership_protocol`] / [`consistency`] / [`split_brain`] /
//!   [`leader`] handle cluster-wide coordination concerns.
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
//! The single public re-export is [`MeshNode`], a lightweight handle
//! returned from [`bootstrap::bootstrap`].

#![deny(missing_docs)]

pub mod backend;
pub mod backoff;
pub mod bootstrap;
pub mod bridge;
pub mod cluster_metrics;
pub mod config;
pub mod consistency;
pub mod crypto;
pub mod discovery;
pub mod encryption;
pub mod federation;
pub mod gossip;
pub mod gossip_loop;
pub mod health_monitor;
pub mod isolation;
pub mod leader;
pub mod membership_protocol;
pub mod metrics;
pub mod node;
pub mod node_handle;
pub mod peer_auth;
pub mod peer_eviction;
pub mod persistence;
pub mod split_brain;
pub mod state;
pub mod transport;

// --- Re-exports ---

pub use node_handle::MeshNode;

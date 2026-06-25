//! Inter-node transports for CRDT state replication and cross-node cache RPCs.
//!
//! Two wire formats live side-by-side in this module:
//!
//! * The legacy gossip wire format ([`MeshMessage`], [`StateDelta`], and
//!   the [`encode`] / [`decode`] helpers) used for CRDT-backed
//!   membership/state deltas and simple ping/pong liveness.
//! * The J2 cross-node cache RPC transport ([`frame`], [`server`],
//!   [`client`]) used by the distributed cache for routed get/put/delete
//!   against a peer's shard.
//!
//! Submodules:
//! * [`frame`] - length-prefixed framing + request/response types.
//! * [`server`] - TCP listener that answers cache RPCs on this node.
//! * [`client`] - persistent client + pool used for outbound cache RPCs.
//! * [`tcp`] / [`websocket`] / [`quic_transport`] - transport variants for
//!   UDP-restricted environments.

pub mod client;
pub mod frame;
pub mod quic_transport;
pub mod server;
pub mod tcp;
pub mod websocket;

// --- Re-exports for the cross-node cache RPC transport (J2) ---

pub use client::{PeerClient, TransportClientPool};
pub use frame::{CacheOp, CacheResult, Request, Response};
pub use server::TransportServer;

use serde::{Deserialize, Serialize};

/// Messages exchanged between mesh nodes.
#[derive(Debug, Serialize, Deserialize)]
pub enum MeshMessage {
    /// Membership update (gossip).
    MembershipUpdate(crate::node::NodeInfo),
    /// CRDT state delta.
    StateDelta(StateDelta),
    /// Ping for failure detection; carries a correlation ID.
    Ping(String),
    /// Pong reply to a ping; echoes the same correlation ID.
    Pong(String),
}

/// A bundle of CRDT deltas to be replicated to peers.
#[derive(Debug, Serialize, Deserialize)]
pub struct StateDelta {
    /// (name, counter delta) pairs.
    pub counter_deltas: Vec<(String, crate::state::counter::GCounter)>,
    /// (name, set delta) pairs.
    pub set_deltas: Vec<(String, crate::state::set::ORSet)>,
    /// (name, register delta) pairs.
    pub register_deltas: Vec<(String, crate::state::register::LWWRegister)>,
}

/// JSON-encode a [`MeshMessage`] for transmission on the wire.
///
/// JSON is used over the wire for human debuggability; the throughput
/// profile of gossip membership traffic doesn't benefit meaningfully from
/// a binary encoding. The J2 cache RPC transport uses `bincode` via
/// [`frame`] instead.
pub fn encode(msg: &MeshMessage) -> anyhow::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(msg)?;
    Ok(bytes)
}

/// Counterpart to [`encode`]: deserialize a [`MeshMessage`] from a
/// received payload. Returns `Err` on malformed input; callers typically
/// log and drop the frame.
pub fn decode(data: &[u8]) -> anyhow::Result<MeshMessage> {
    let msg = serde_json::from_slice(data)?;
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{NodeId, NodeInfo};
    use crate::state::{counter::GCounter, register::LWWRegister, set::ORSet};

    fn make_node_info(name: &str) -> NodeInfo {
        NodeInfo::new(
            NodeId::new(name),
            format!("{name}:8080"),
            7946,
            8946,
            "2026-01-01T00:00:00Z".to_string(),
        )
    }

    #[test]
    fn ping_roundtrip() {
        let msg = MeshMessage::Ping("corr-id-123".to_string());
        let bytes = encode(&msg).expect("encode");
        let back = decode(&bytes).expect("decode");
        match back {
            MeshMessage::Ping(id) => assert_eq!(id, "corr-id-123"),
            other => panic!("expected Ping, got {other:?}"),
        }
    }

    #[test]
    fn pong_roundtrip() {
        let msg = MeshMessage::Pong("corr-id-456".to_string());
        let bytes = encode(&msg).expect("encode");
        let back = decode(&bytes).expect("decode");
        match back {
            MeshMessage::Pong(id) => assert_eq!(id, "corr-id-456"),
            other => panic!("expected Pong, got {other:?}"),
        }
    }

    #[test]
    fn membership_update_roundtrip() {
        let info = make_node_info("peer-1");
        let msg = MeshMessage::MembershipUpdate(info.clone());
        let bytes = encode(&msg).expect("encode");
        let back = decode(&bytes).expect("decode");
        match back {
            MeshMessage::MembershipUpdate(ni) => {
                assert_eq!(ni.id, info.id);
                assert_eq!(ni.gossip_port, 7946);
            }
            other => panic!("expected MembershipUpdate, got {other:?}"),
        }
    }

    #[test]
    fn state_delta_with_counter_roundtrip() {
        let mut counter = GCounter::new();
        counter.increment("node-a", 42);

        let delta = StateDelta {
            counter_deltas: vec![("rate-limit:api".to_string(), counter)],
            set_deltas: vec![],
            register_deltas: vec![],
        };
        let msg = MeshMessage::StateDelta(delta);
        let bytes = encode(&msg).expect("encode");
        let back = decode(&bytes).expect("decode");
        match back {
            MeshMessage::StateDelta(d) => {
                assert_eq!(d.counter_deltas.len(), 1);
                assert_eq!(d.counter_deltas[0].0, "rate-limit:api");
                assert_eq!(d.counter_deltas[0].1.value(), 42);
            }
            other => panic!("expected StateDelta, got {other:?}"),
        }
    }

    #[test]
    fn state_delta_with_set_roundtrip() {
        let mut set = ORSet::new();
        set.add("10.0.0.1", "node-a");

        let delta = StateDelta {
            counter_deltas: vec![],
            set_deltas: vec![("blocked-ips".to_string(), set)],
            register_deltas: vec![],
        };
        let msg = MeshMessage::StateDelta(delta);
        let bytes = encode(&msg).expect("encode");
        let back = decode(&bytes).expect("decode");
        match back {
            MeshMessage::StateDelta(d) => {
                assert_eq!(d.set_deltas.len(), 1);
                assert!(d.set_deltas[0].1.contains("10.0.0.1"));
            }
            other => panic!("expected StateDelta, got {other:?}"),
        }
    }

    #[test]
    fn state_delta_with_register_roundtrip() {
        let mut reg = LWWRegister::new();
        reg.set_at("session-data".to_string(), "node-a", 12345);

        let delta = StateDelta {
            counter_deltas: vec![],
            set_deltas: vec![],
            register_deltas: vec![("session:abc".to_string(), reg)],
        };
        let msg = MeshMessage::StateDelta(delta);
        let bytes = encode(&msg).expect("encode");
        let back = decode(&bytes).expect("decode");
        match back {
            MeshMessage::StateDelta(d) => {
                assert_eq!(d.register_deltas.len(), 1);
                assert_eq!(d.register_deltas[0].1.get(), Some("session-data"));
                assert_eq!(d.register_deltas[0].1.timestamp(), 12345);
            }
            other => panic!("expected StateDelta, got {other:?}"),
        }
    }

    #[test]
    fn decode_invalid_bytes_returns_error() {
        let result = decode(b"not valid json {{{{");
        assert!(result.is_err());
    }

    #[test]
    fn encode_produces_non_empty_bytes() {
        let msg = MeshMessage::Ping("test".to_string());
        let bytes = encode(&msg).expect("encode");
        assert!(!bytes.is_empty());
    }
}

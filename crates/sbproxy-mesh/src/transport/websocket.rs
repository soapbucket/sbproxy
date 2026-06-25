//! WebSocket transport fallback for UDP-restricted environments.
//!
//! Encodes mesh messages as JSON strings suitable for sending over a WebSocket
//! connection. This is a fallback for environments where UDP is blocked.

use super::MeshMessage;

/// Configuration for the WebSocket transport listener.
pub struct WebSocketTransportConfig {
    pub bind_addr: String,
    pub port: u16,
}

impl WebSocketTransportConfig {
    /// Create a new WebSocket transport config.
    pub fn new(bind_addr: &str, port: u16) -> Self {
        Self {
            bind_addr: bind_addr.to_string(),
            port,
        }
    }

    /// Return the full bind address string (addr:port).
    pub fn listen_addr(&self) -> String {
        format!("{}:{}", self.bind_addr, self.port)
    }
}

/// Encode a mesh message for WebSocket transport (JSON string).
pub fn ws_encode(msg: &MeshMessage) -> anyhow::Result<String> {
    Ok(serde_json::to_string(msg)?)
}

/// Decode a mesh message from WebSocket transport (JSON string).
pub fn ws_decode(data: &str) -> anyhow::Result<MeshMessage> {
    Ok(serde_json::from_str(data)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{NodeId, NodeInfo};

    fn make_ping() -> MeshMessage {
        MeshMessage::Ping("ws-corr-id".to_string())
    }

    fn make_node_info() -> NodeInfo {
        NodeInfo::new(
            NodeId::new("ws-node"),
            "10.0.0.1:8080".to_string(),
            7946,
            8946,
            "2026-01-01T00:00:00Z".to_string(),
        )
    }

    #[test]
    fn ping_encode_decode_roundtrip() {
        let msg = make_ping();
        let encoded = ws_encode(&msg).expect("encode");
        let decoded = ws_decode(&encoded).expect("decode");
        match decoded {
            MeshMessage::Ping(id) => assert_eq!(id, "ws-corr-id"),
            other => panic!("expected Ping, got {other:?}"),
        }
    }

    #[test]
    fn pong_encode_decode_roundtrip() {
        let msg = MeshMessage::Pong("ws-pong-id".to_string());
        let encoded = ws_encode(&msg).expect("encode");
        let decoded = ws_decode(&encoded).expect("decode");
        match decoded {
            MeshMessage::Pong(id) => assert_eq!(id, "ws-pong-id"),
            other => panic!("expected Pong, got {other:?}"),
        }
    }

    #[test]
    fn membership_update_roundtrip() {
        let info = make_node_info();
        let msg = MeshMessage::MembershipUpdate(info);
        let encoded = ws_encode(&msg).expect("encode");
        let decoded = ws_decode(&encoded).expect("decode");
        match decoded {
            MeshMessage::MembershipUpdate(ni) => {
                assert_eq!(ni.id, NodeId::new("ws-node"));
            }
            other => panic!("expected MembershipUpdate, got {other:?}"),
        }
    }

    #[test]
    fn encoded_is_valid_json_string() {
        let msg = make_ping();
        let encoded = ws_encode(&msg).expect("encode");
        // JSON strings should not be empty and should parse
        assert!(!encoded.is_empty());
        let _: serde_json::Value = serde_json::from_str(&encoded).expect("should be valid JSON");
    }

    #[test]
    fn decode_invalid_json_returns_error() {
        let result = ws_decode("not valid json {{{{");
        assert!(result.is_err());
    }

    #[test]
    fn config_listen_addr() {
        let cfg = WebSocketTransportConfig::new("0.0.0.0", 9000);
        assert_eq!(cfg.listen_addr(), "0.0.0.0:9000");
    }
}

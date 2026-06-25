//! Plain TCP transport for simplest environments.
//!
//! Uses a 4-byte big-endian length prefix followed by JSON-encoded message
//! bytes. This framing allows reliable message boundaries over a TCP stream.

use super::MeshMessage;

/// Configuration for the TCP transport listener.
pub struct TcpTransportConfig {
    /// Address the TCP listener binds.
    pub bind_addr: String,
    /// TCP port the listener binds.
    pub port: u16,
}

impl TcpTransportConfig {
    /// Create a new TCP transport config.
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

/// Encode for TCP: 4-byte big-endian length prefix + JSON message bytes.
pub fn tcp_encode(msg: &MeshMessage) -> anyhow::Result<Vec<u8>> {
    let json = serde_json::to_vec(msg)?;
    let len = (json.len() as u32).to_be_bytes();
    let mut buf = Vec::with_capacity(4 + json.len());
    buf.extend_from_slice(&len);
    buf.extend_from_slice(&json);
    Ok(buf)
}

/// Decode from TCP: read 4-byte big-endian length, then parse that many bytes.
pub fn tcp_decode(data: &[u8]) -> anyhow::Result<MeshMessage> {
    if data.len() < 4 {
        anyhow::bail!("data too short for length prefix");
    }
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() < 4 + len {
        anyhow::bail!("data too short for message body");
    }
    Ok(serde_json::from_slice(&data[4..4 + len])?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{NodeId, NodeInfo};

    fn make_node_info() -> NodeInfo {
        NodeInfo::new(
            NodeId::new("tcp-node"),
            "10.0.0.2:8080".to_string(),
            7946,
            8946,
            "2026-01-01T00:00:00Z".to_string(),
        )
    }

    #[test]
    fn ping_encode_decode_roundtrip() {
        let msg = MeshMessage::Ping("tcp-corr-id".to_string());
        let bytes = tcp_encode(&msg).expect("encode");
        let decoded = tcp_decode(&bytes).expect("decode");
        match decoded {
            MeshMessage::Ping(id) => assert_eq!(id, "tcp-corr-id"),
            other => panic!("expected Ping, got {other:?}"),
        }
    }

    #[test]
    fn pong_encode_decode_roundtrip() {
        let msg = MeshMessage::Pong("tcp-pong-id".to_string());
        let bytes = tcp_encode(&msg).expect("encode");
        let decoded = tcp_decode(&bytes).expect("decode");
        match decoded {
            MeshMessage::Pong(id) => assert_eq!(id, "tcp-pong-id"),
            other => panic!("expected Pong, got {other:?}"),
        }
    }

    #[test]
    fn membership_update_roundtrip() {
        let info = make_node_info();
        let msg = MeshMessage::MembershipUpdate(info);
        let bytes = tcp_encode(&msg).expect("encode");
        let decoded = tcp_decode(&bytes).expect("decode");
        match decoded {
            MeshMessage::MembershipUpdate(ni) => {
                assert_eq!(ni.id, NodeId::new("tcp-node"));
            }
            other => panic!("expected MembershipUpdate, got {other:?}"),
        }
    }

    #[test]
    fn encoded_has_correct_length_prefix() {
        let msg = MeshMessage::Ping("hello".to_string());
        let bytes = tcp_encode(&msg).expect("encode");
        assert!(bytes.len() >= 4);
        let prefix_len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        // Total length should be 4 (prefix) + body length
        assert_eq!(bytes.len(), 4 + prefix_len);
    }

    #[test]
    fn decode_too_short_for_prefix_returns_error() {
        let result = tcp_decode(&[0u8, 1u8, 2u8]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("too short"));
    }

    #[test]
    fn decode_too_short_for_body_returns_error() {
        // Claim body is 100 bytes but provide only 4 header bytes
        let data: Vec<u8> = vec![0, 0, 0, 100]; // says 100-byte body
        let result = tcp_decode(&data);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("too short"));
    }

    #[test]
    fn decode_invalid_json_body_returns_error() {
        let body = b"not valid json";
        let len = (body.len() as u32).to_be_bytes();
        let mut data = vec![0u8; 4 + body.len()];
        data[..4].copy_from_slice(&len);
        data[4..].copy_from_slice(body);
        let result = tcp_decode(&data);
        assert!(result.is_err());
    }

    #[test]
    fn config_listen_addr() {
        let cfg = TcpTransportConfig::new("127.0.0.1", 9001);
        assert_eq!(cfg.listen_addr(), "127.0.0.1:9001");
    }
}

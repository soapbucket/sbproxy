//! Real QUIC transport for inter-node mesh communication.
//!
//! Uses quinn (already in deps for HTTP/3) for reliable, encrypted
//! UDP-based transport between mesh nodes.
//!
//! # Current status
//!
//! The integration points are documented here. The full quinn endpoint
//! setup requires TLS certificates (either self-signed per-node certs
//! or a shared mesh CA). Wire in `rustls` + `quinn` for production.

use std::net::SocketAddr;

/// Configuration for the QUIC transport layer.
pub struct QuicTransportConfig {
    /// Socket address the QUIC listener binds.
    pub bind_addr: SocketAddr,
    /// PEM-encoded certificate for this node (optional - mesh CA may be used).
    pub cert_pem: Option<Vec<u8>>,
    /// PEM-encoded private key for this node.
    pub key_pem: Option<Vec<u8>>,
}

/// Build QUIC client config for connecting to a peer.
///
/// Production implementation:
/// ```ignore
/// let tls = rustls::ClientConfig::builder()
///     .with_root_certificates(mesh_ca_store)
///     .with_no_client_auth();
/// quinn::ClientConfig::new(Arc::new(tls))
/// ```
pub fn build_client_config() -> anyhow::Result<()> {
    tracing::info!("QUIC transport: client config built (placeholder)");
    Ok(())
}

/// Build QUIC server config for accepting peer connections.
///
/// Production implementation:
/// ```ignore
/// let tls = rustls::ServerConfig::builder()
///     .with_no_client_auth()
///     .with_single_cert(certs, key)?;
/// let server_config = quinn::ServerConfig::with_crypto(Arc::new(tls));
/// quinn::Endpoint::server(server_config, bind_addr)
/// ```
pub fn build_server_config(bind_addr: SocketAddr) -> anyhow::Result<()> {
    tracing::info!(addr = %bind_addr, "QUIC transport: server config built (placeholder)");
    Ok(())
}

/// Send a mesh message to a peer via QUIC.
///
/// Production implementation:
/// ```ignore
/// let conn = endpoint.connect(peer_addr.parse()?, "mesh")?.await?;
/// let mut send = conn.open_uni().await?;
/// send.write_all(&encoded).await?;
/// send.finish()?;
/// ```
pub fn send_to_peer(_peer_addr: &str, msg: &super::MeshMessage) -> anyhow::Result<()> {
    let _encoded = super::encode(msg)?;
    // Production: open QUIC stream to _peer_addr, write _encoded bytes.
    Ok(())
}

/// Receive mesh messages from peers.
///
/// Production implementation drives a `quinn::Endpoint` accept loop,
/// reading from incoming unidirectional streams and deserializing with
/// `super::decode`.
pub fn receive_from_peers() -> Vec<super::MeshMessage> {
    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MeshMessage;

    #[test]
    fn build_client_config_succeeds() {
        let result = build_client_config();
        assert!(result.is_ok());
    }

    #[test]
    fn build_server_config_succeeds() {
        let addr: SocketAddr = "127.0.0.1:7947".parse().expect("addr");
        let result = build_server_config(addr);
        assert!(result.is_ok());
    }

    #[test]
    fn send_to_peer_valid_message_does_not_error() {
        let msg = MeshMessage::Ping("quic-test-corr-id".to_string());
        let result = send_to_peer("127.0.0.1:7946", &msg);
        assert!(result.is_ok());
    }

    #[test]
    fn receive_from_peers_returns_empty_placeholder() {
        let msgs = receive_from_peers();
        assert!(msgs.is_empty());
    }

    #[test]
    fn quic_config_fields_are_accessible() {
        let cfg = QuicTransportConfig {
            bind_addr: "0.0.0.0:7947".parse().expect("addr"),
            cert_pem: Some(b"cert-pem-bytes".to_vec()),
            key_pem: Some(b"key-pem-bytes".to_vec()),
        };
        assert_eq!(cfg.bind_addr.port(), 7947);
        assert!(cfg.cert_pem.is_some());
        assert!(cfg.key_pem.is_some());
    }
}

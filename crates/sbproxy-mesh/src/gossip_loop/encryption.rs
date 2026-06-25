//! Per-message AEAD seal/send helper for the SWIM gossip loop.
//!
//! When `GossipLoopConfig::cipher` is `Some`, every outbound message is
//! passed through `Cipher::seal` before `UdpSocket::send_to`. The decrypt
//! side is inlined into the recv task in [`super`] so the inbound buffer
//! can be reused across iterations without allocating an extra buffer
//! per datagram. See the module preamble in [`super`] for the wire
//! format and key derivation contract.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::crypto::Cipher;

use super::GossipMsg;

/// Serialize, optionally seal, and send `msg` to `addr`. Errors are
/// logged at debug; the caller does not care which peer drop failed.
pub(super) async fn send_msg(
    socket: &Arc<UdpSocket>,
    cipher: Option<&Cipher>,
    msg: &GossipMsg,
    addr: SocketAddr,
) {
    let plaintext = match crate::transport::wire::encode(msg) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "gossip: serialization failed");
            return;
        }
    };
    let on_wire: Vec<u8> = match cipher {
        Some(c) => c.seal(&plaintext),
        None => plaintext,
    };
    if let Err(e) = socket.send_to(&on_wire, addr).await {
        tracing::debug!(peer = %addr, error = %e, "gossip: send failed");
    }
}

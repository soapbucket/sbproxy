//! The Unix socket Core Lightning is reached through.
//!
//! [`ClnSettler`](crate::lightning::cln::ClnSettler) owns the protocol: the
//! JSON-RPC envelope, the rune, the version floor, the durable labels, and
//! every rule about which invoice status authorizes. This type owns one
//! socket. It writes the newline-terminated request it is handed and reads
//! back one newline-delimited response.
//!
//! # One connection per call
//!
//! `lightning-rpc` is a local Unix socket, so a connect costs a syscall
//! rather than a handshake, and a fresh connection per call is what keeps a
//! partial read from poisoning the next request. A pooled connection whose
//! previous response was truncated would hand its leftover bytes to the
//! following caller, and on this path that would mean reading one invoice's
//! status as another's.
//!
//! # The rune is not here
//!
//! The rune is a bearer credential and it belongs to the settler, which
//! places it inside the JSON-RPC request object and nowhere else. This module
//! never sees it as a distinct value: it writes an opaque byte slice that
//! already contains whatever the settler put there, and it never logs those
//! bytes.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;

use crate::error::BillingError;
use crate::lightning::cln::{ClnTransport, MAX_CLN_RESPONSE_BYTES};
use crate::lightning::LightningTransportFailure;

/// Bytes pulled from the socket per read.
const READ_CHUNK: usize = 8 * 1024;

/// The Unix socket client for one Core Lightning node.
#[derive(Debug, Clone)]
pub struct UnixClnTransport {
    socket_path: PathBuf,
}

impl UnixClnTransport {
    /// Binds to a configured `lightning-rpc` socket path.
    ///
    /// The path is not dialed here. Startup proves the node answers by
    /// calling [`ClnSettler::probe_version`](crate::lightning::cln::ClnSettler::probe_version),
    /// which fails the whole runtime rather than one request, so a dial in
    /// the constructor would only duplicate that check less usefully.
    ///
    /// # Errors
    ///
    /// Returns [`BillingError::InvalidRequirement`] for a relative path. An
    /// absolute path is what the configuration crate already requires; this
    /// is the runtime backstop, because a relative socket path would resolve
    /// against whatever directory the process happens to be started from.
    pub fn new(socket_path: &Path) -> Result<Self, BillingError> {
        if !socket_path.is_absolute() {
            return Err(BillingError::InvalidRequirement(
                "proxy.payments.rails.lightning_cln.socket_path must be absolute",
            ));
        }
        Ok(Self {
            socket_path: socket_path.to_path_buf(),
        })
    }

    /// Writes one request and reads one newline-delimited response.
    async fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, LightningTransportFailure> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|_| LightningTransportFailure::Connection)?;

        stream
            .write_all(request)
            .await
            .map_err(|_| LightningTransportFailure::Connection)?;
        stream
            .flush()
            .await
            .map_err(|_| LightningTransportFailure::Connection)?;

        let mut response: Vec<u8> = Vec::new();
        let mut chunk = [0_u8; READ_CHUNK];
        loop {
            let read = stream
                .read(&mut chunk)
                .await
                .map_err(|_| LightningTransportFailure::Connection)?;
            if read == 0 {
                // The node closed without terminating the response. An
                // truncated JSON object is not a refusal, so this stays a
                // transport failure and the caller decides what an
                // unanswered call means for the operation it was running.
                break;
            }
            if response.len().saturating_add(read) > MAX_CLN_RESPONSE_BYTES {
                return Err(LightningTransportFailure::TooLarge);
            }
            response.extend_from_slice(&chunk[..read]);
            // One response per connection, so the first newline ends the
            // read. Waiting for EOF instead would block until the node
            // decided to close.
            if response.contains(&b'\n') {
                break;
            }
        }
        Ok(response)
    }
}

#[async_trait::async_trait]
impl ClnTransport for UnixClnTransport {
    async fn call(
        &self,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, LightningTransportFailure> {
        match tokio::time::timeout(timeout, self.exchange(request)).await {
            Ok(result) => result,
            Err(_) => Err(LightningTransportFailure::Timeout),
        }
    }
}

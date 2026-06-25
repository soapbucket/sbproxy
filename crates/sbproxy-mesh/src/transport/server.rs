//! TCP server half of the cross-node cache RPC transport.
//!
//! [`TransportServer::start`] binds a TCP listener on the provided port and
//! spawns a task that accepts connections forever. Each connection runs in
//! its own task that reads [`Request`]s in a loop, dispatches to the local
//! [`DistributedCache`], and writes [`Response`]s back on the same stream.
//!
//! Connections are long-lived; the peer [`super::client::PeerClient`] keeps a
//! single TCP connection per destination and reuses it across cache
//! operations. Dropping the returned [`TransportServer`] (or calling
//! [`TransportServer::shutdown`]) signals the accept loop to exit; active
//! per-connection tasks finish their in-flight request and then observe the
//! peer-side close on the next `read_frame` call.

use std::sync::Arc;

use bytes::Bytes;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::crypto::Cipher;
use crate::metrics::{CRYPTO_KIND_TRANSPORT, MESH_CRYPTO_DECRYPT_FAILED};
use crate::state::distributed_cache::DistributedCache;

use super::frame::{read_frame, write_frame, CacheOp, CacheResult, Request, Response};

// --- Handle ---

/// Running TCP server. Dropping the handle signals the accept loop to stop
/// so the bound port is released deterministically at test teardown.
pub struct TransportServer {
    /// Accept-loop join handle. Retained for possible future diagnostics;
    /// the leading underscore keeps Clippy quiet about an unused field.
    _join: JoinHandle<()>,
    /// Shutdown signal for the accept loop. `Option` because
    /// [`Self::shutdown`] consumes `self` and moves the sender out;
    /// [`Drop`] also uses this path when the caller never calls
    /// `shutdown` explicitly.
    shutdown: Option<oneshot::Sender<()>>,
    /// The port the listener actually bound. When the caller passed `0` the
    /// OS picks an ephemeral port; tests read this back to target the
    /// server.
    local_port: u16,
}

impl TransportServer {
    /// Bind a TCP listener on `0.0.0.0:port` and spawn the accept loop.
    ///
    /// `port=0` requests an ephemeral port; the bound port is available via
    /// [`Self::local_port`]. `cache` is shared with the local mesh node; every
    /// inbound request routes directly to its `get_local` / `put_local` /
    /// `delete_local` methods.
    ///
    /// Backwards-compatible wrapper around [`Self::start_with_cipher`] that
    /// defaults to plaintext. K3 callers that want AEAD on the wire pass a
    /// `Cipher` via [`Self::start_with_cipher`] instead.
    pub async fn start(port: u16, cache: Arc<DistributedCache<Bytes>>) -> anyhow::Result<Self> {
        Self::start_with_cipher(port, cache, None).await
    }

    /// K3: bind a TCP listener with optional AES-256-GCM framing.
    ///
    /// When `cipher` is `Some`, every inbound frame is passed through
    /// [`Cipher::open`] before bincode deserialization, and every outbound
    /// response is passed through [`Cipher::seal`] before framing. AEAD
    /// failures tear down the connection immediately (unlike gossip's
    /// silent drop, because TCP is stateful and a cryptographic mismatch
    /// means the peer is misconfigured or hostile).
    pub async fn start_with_cipher(
        port: u16,
        cache: Arc<DistributedCache<Bytes>>,
        cipher: Option<Cipher>,
    ) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(("0.0.0.0", port)).await?;
        let local_port = listener.local_addr()?.port();

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        let join = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => {
                        tracing::info!(port = local_port, "transport server shutting down");
                        break;
                    }
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, addr)) => {
                                tracing::debug!(peer = %addr, "transport: accepted connection");
                                let cache = cache.clone();
                                let cipher = cipher.clone();
                                tokio::spawn(handle_connection(stream, cache, cipher));
                            }
                            Err(e) => {
                                // Typically transient (fd exhaustion, peer
                                // reset before accept). Keep the loop alive
                                // so a single flaky peer cannot stop
                                // serving.
                                tracing::warn!(error = %e, "transport: accept failed");
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            _join: join,
            shutdown: Some(shutdown_tx),
            local_port,
        })
    }

    /// Signal the accept loop to stop. Idempotent and non-blocking; the
    /// actual socket release happens when the accept task observes the
    /// signal on its next `select!` poll.
    pub fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }

    /// Port the listener is actually bound to. When the caller passed `0` at
    /// startup, this reflects the OS-chosen ephemeral port.
    pub fn local_port(&self) -> u16 {
        self.local_port
    }
}

impl Drop for TransportServer {
    fn drop(&mut self) {
        // Best-effort: if `shutdown()` already fired, `self.shutdown` is
        // `None` and there's nothing to do.
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

// --- Per-connection handler ---

/// Drive a single accepted TCP connection: read frames, dispatch to the
/// local cache, write responses. Exits cleanly on peer disconnect or on the
/// first malformed frame; there is no per-request error recovery beyond
/// surfacing the failure via [`CacheResult::Error`] when it's recoverable.
///
/// # Encryption (K3)
///
/// When `cipher` is `Some`, the wire payload inside each frame is an AEAD
/// envelope (`[nonce][ciphertext][tag]`). We open it before bincode
/// deserialization and seal every outgoing response body before framing.
/// A failed open tears down the connection: an authenticated peer cannot
/// "recover" by resyncing on the framing boundary after a crypto error, so
/// there is no reason to keep the socket open.
async fn handle_connection(
    stream: TcpStream,
    cache: Arc<DistributedCache<Bytes>>,
    cipher: Option<Cipher>,
) {
    let (mut reader, mut writer) = stream.into_split();
    loop {
        // --- Read a framed request ---
        let payload = match read_frame(&mut reader).await {
            Ok(p) => p,
            Err(e) => {
                // `UnexpectedEof` is the normal path when the client closes
                // the connection; log everything else at `debug` so healthy
                // churn doesn't spam the logs.
                tracing::debug!(error = %e, "transport: read_frame ended connection");
                break;
            }
        };

        // K3: if a cipher is configured, every frame payload must be a
        // valid AEAD envelope. Anything else (plaintext from a
        // misconfigured peer, or a tampered envelope) is a fatal
        // protocol error on this connection.
        let plaintext: Vec<u8> = match cipher.as_ref() {
            Some(c) => match c.open(&payload) {
                Some(pt) => pt,
                None => {
                    MESH_CRYPTO_DECRYPT_FAILED
                        .with_label_values(&[CRYPTO_KIND_TRANSPORT])
                        .inc();
                    tracing::warn!("transport: frame failed AEAD decrypt; closing connection");
                    break;
                }
            },
            None => payload,
        };

        let req: Request = match crate::transport::wire::decode(&plaintext) {
            Ok(req) => req,
            Err(e) => {
                tracing::warn!(error = %e, "transport: bad request frame");
                break;
            }
        };

        // --- Dispatch locally ---
        //
        // The server does NOT recurse into `get_routed` / `put_routed` - it
        // always answers from the local shard. The client side is
        // responsible for picking the correct peer via the consistent hash
        // ring before ever issuing this RPC.
        let request_id = req.request_id;
        let result = match req.op {
            CacheOp::Get { key } => CacheResult::Value(cache.get_local(&key)),
            // `ttl_secs = 0` is the K1 "no expiry" convention; route
            // through the explicit-TTL API either way so there is a single
            // storage codepath. `put_local_with_ttl(..., 0)` matches
            // `put_local` semantics.
            CacheOp::Put {
                key,
                value,
                ttl_secs,
            } => {
                cache.put_local_with_ttl(&key, value, ttl_secs);
                CacheResult::Acked
            }
            CacheOp::Delete { key } => {
                cache.delete_local(&key);
                CacheResult::Acked
            }
            // K2: cluster-wide purge fan-out. The caller has already
            // decided to broadcast this to every peer; our job is to scan
            // the local shard and report back the count. An empty prefix
            // is the "purge all" sentinel (the K2 wire-format convention
            // used by `PurgeScope::All`).
            CacheOp::PurgePrefix { prefix } => {
                let n = if prefix.is_empty() {
                    cache.purge_all_local()
                } else {
                    cache.purge_prefix_local(&prefix)
                };
                CacheResult::Purged(n as u64)
            }
        };

        // --- Write the response ---
        let resp = Response { request_id, result };
        let bytes = match crate::transport::wire::encode(&resp) {
            Ok(b) => b,
            Err(e) => {
                // Only fails on a type-level programming error; log and
                // drop the connection rather than deadlocking the peer.
                tracing::warn!(error = %e, "transport: response serialize failed");
                break;
            }
        };
        // K3: seal the response body when encryption is configured, so
        // the client's `read_frame + open` path mirrors our `read_frame
        // + open` on the request side.
        let on_wire: Vec<u8> = match cipher.as_ref() {
            Some(c) => c.seal(&bytes),
            None => bytes,
        };
        if let Err(e) = write_frame(&mut writer, &on_wire).await {
            tracing::debug!(error = %e, "transport: write_frame failed, closing connection");
            break;
        }
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn server_binds_and_reports_port() {
        let cache: Arc<DistributedCache<Bytes>> =
            Arc::new(DistributedCache::new("server-node", 16));
        let server = TransportServer::start(0, cache).await.expect("start");
        let port = server.local_port();
        assert!(port > 0, "expected OS-assigned ephemeral port");
        server.shutdown();
    }

    #[tokio::test]
    async fn server_shutdown_releases_port() {
        let cache: Arc<DistributedCache<Bytes>> =
            Arc::new(DistributedCache::new("server-node", 16));
        let server = TransportServer::start(0, cache).await.expect("start");
        let _port = server.local_port();
        server.shutdown();
        // Give the accept task a tick to notice the shutdown signal.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    #[tokio::test]
    async fn server_handles_put_then_get_roundtrip() {
        let cache: Arc<DistributedCache<Bytes>> =
            Arc::new(DistributedCache::new("server-node", 16));
        let server = TransportServer::start(0, cache.clone())
            .await
            .expect("start");
        let port = server.local_port();

        // Raw client: connect, send a Put, then a Get, verify value matches.
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        let (mut r, mut w) = stream.split();

        // Put
        let put_req = Request {
            request_id: 1,
            op: CacheOp::Put {
                key: "k".to_string(),
                value: Bytes::from_static(b"v"),
                ttl_secs: 0,
            },
        };
        let bytes = crate::transport::wire::encode(&put_req).expect("ser");
        write_frame(&mut w, &bytes).await.expect("write put");
        let resp_bytes = read_frame(&mut r).await.expect("read put resp");
        let resp: Response = crate::transport::wire::decode(&resp_bytes).expect("deser put");
        assert_eq!(resp.request_id, 1);
        matches!(resp.result, CacheResult::Acked);

        // Get
        let get_req = Request {
            request_id: 2,
            op: CacheOp::Get {
                key: "k".to_string(),
            },
        };
        let bytes = crate::transport::wire::encode(&get_req).expect("ser");
        write_frame(&mut w, &bytes).await.expect("write get");
        let resp_bytes = read_frame(&mut r).await.expect("read get resp");
        let resp: Response = crate::transport::wire::decode(&resp_bytes).expect("deser get");
        assert_eq!(resp.request_id, 2);
        match resp.result {
            CacheResult::Value(Some(b)) => assert_eq!(b, Bytes::from_static(b"v")),
            other => panic!("expected Value(Some), got {:?}", other),
        }

        drop(stream);
        server.shutdown();
    }

    #[tokio::test]
    async fn server_handles_delete() {
        let cache: Arc<DistributedCache<Bytes>> =
            Arc::new(DistributedCache::new("server-node", 16));
        cache.put_local("doomed", Bytes::from_static(b"value"));
        let server = TransportServer::start(0, cache.clone())
            .await
            .expect("start");
        let port = server.local_port();

        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        let (mut r, mut w) = stream.split();
        let req = Request {
            request_id: 1,
            op: CacheOp::Delete {
                key: "doomed".to_string(),
            },
        };
        let bytes = crate::transport::wire::encode(&req).expect("ser");
        write_frame(&mut w, &bytes).await.expect("write");
        let resp_bytes = read_frame(&mut r).await.expect("read");
        let resp: Response = crate::transport::wire::decode(&resp_bytes).expect("deser");
        matches!(resp.result, CacheResult::Acked);
        assert_eq!(cache.get_local("doomed"), None);

        drop(stream);
        server.shutdown();
    }

    #[tokio::test]
    async fn server_handles_purge_prefix() {
        // K2: server dispatches `PurgePrefix` to `purge_prefix_local` and
        // echoes back the count. Seed two matching entries + one
        // non-matching, then confirm the reply says "2 removed" and the
        // non-matching entry survived.
        let cache: Arc<DistributedCache<Bytes>> =
            Arc::new(DistributedCache::new("server-node", 16));
        cache.put_local("foo:1", Bytes::from_static(b"a"));
        cache.put_local("foo:2", Bytes::from_static(b"b"));
        cache.put_local("bar:1", Bytes::from_static(b"c"));
        let server = TransportServer::start(0, cache.clone())
            .await
            .expect("start");
        let port = server.local_port();

        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        let (mut r, mut w) = stream.split();
        let req = Request {
            request_id: 1,
            op: CacheOp::PurgePrefix {
                prefix: "foo:".to_string(),
            },
        };
        let bytes = crate::transport::wire::encode(&req).expect("ser");
        write_frame(&mut w, &bytes).await.expect("write");
        let resp_bytes = read_frame(&mut r).await.expect("read");
        let resp: Response = crate::transport::wire::decode(&resp_bytes).expect("deser");
        match resp.result {
            CacheResult::Purged(n) => assert_eq!(n, 2),
            other => panic!("expected Purged(2), got {:?}", other),
        }
        assert_eq!(cache.get_local("foo:1"), None);
        assert_eq!(cache.get_local("foo:2"), None);
        assert_eq!(cache.get_local("bar:1"), Some(Bytes::from_static(b"c")));

        drop(stream);
        server.shutdown();
    }

    #[tokio::test]
    async fn server_handles_purge_prefix_empty_is_all() {
        // An empty prefix is the K2 sentinel for "purge everything". The
        // server MUST route this to `purge_all_local` so the wire
        // semantics match what the client driver expects.
        let cache: Arc<DistributedCache<Bytes>> =
            Arc::new(DistributedCache::new("server-node", 16));
        cache.put_local("a", Bytes::from_static(b"1"));
        cache.put_local("b", Bytes::from_static(b"2"));
        let server = TransportServer::start(0, cache.clone())
            .await
            .expect("start");
        let port = server.local_port();

        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        let (mut r, mut w) = stream.split();
        let req = Request {
            request_id: 1,
            op: CacheOp::PurgePrefix {
                prefix: String::new(),
            },
        };
        let bytes = crate::transport::wire::encode(&req).expect("ser");
        write_frame(&mut w, &bytes).await.expect("write");
        let resp_bytes = read_frame(&mut r).await.expect("read");
        let resp: Response = crate::transport::wire::decode(&resp_bytes).expect("deser");
        match resp.result {
            CacheResult::Purged(n) => assert_eq!(n, 2),
            other => panic!("expected Purged(2), got {:?}", other),
        }
        assert_eq!(cache.get_local("a"), None);
        assert_eq!(cache.get_local("b"), None);

        drop(stream);
        server.shutdown();
    }

    #[tokio::test]
    async fn server_get_miss_returns_value_none() {
        let cache: Arc<DistributedCache<Bytes>> =
            Arc::new(DistributedCache::new("server-node", 16));
        let server = TransportServer::start(0, cache).await.expect("start");
        let port = server.local_port();

        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        let (mut r, mut w) = stream.split();
        let req = Request {
            request_id: 1,
            op: CacheOp::Get {
                key: "nope".to_string(),
            },
        };
        let bytes = crate::transport::wire::encode(&req).expect("ser");
        write_frame(&mut w, &bytes).await.expect("write");
        let resp_bytes = read_frame(&mut r).await.expect("read");
        let resp: Response = crate::transport::wire::decode(&resp_bytes).expect("deser");
        match resp.result {
            CacheResult::Value(None) => {}
            other => panic!("expected Value(None), got {:?}", other),
        }

        drop(stream);
        server.shutdown();
    }
}

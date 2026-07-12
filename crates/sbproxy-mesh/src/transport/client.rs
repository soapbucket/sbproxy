//! TCP client half of the cross-node cache RPC transport.
//!
//! [`PeerClient`] owns a single persistent TCP connection to one peer and
//! serialises cache operations over it. The J2 MVP is deliberately serial:
//! one in-flight request at a time per peer. The wire protocol already
//! carries a `request_id`, so a later change can pipeline multiple in-flight
//! operations without a breaking change to either peer.
//!
//! [`TransportClientPool`] caches `Arc<PeerClient>` instances keyed by
//! target identity plus `host:port` when enrolled mTLS is active. Callers (the [`crate::state::distributed_cache::DistributedCache`]
//! routing layer and the enterprise-AI semantic cache adapter) ask the pool
//! for a client instead of constructing one directly, so every outbound
//! request for a given peer reuses the same TCP connection.
//!
//! Connection failures take the current connection down and return the error
//! to the caller; the next call transparently reconnects on demand. There is
//! no background reconnect task in the MVP - reconnection is lazy.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::crypto::Cipher;

use super::frame::{read_frame, write_frame, CacheOp, CacheResult, Request, Response};

use std::pin::Pin;
use std::task::{Context, Poll};

use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

// --- Connection security ---

/// The TLS client side for a [`PeerClient`]: a connector plus the logical
/// certificate name to verify while dialing a peer by address.
#[derive(Clone)]
pub struct MeshTlsClient {
    /// rustls connector that presents this node's cert and verifies the peer's.
    pub connector: TlsConnector,
    /// Logical server name to verify the peer certificate against.
    pub server_name: ServerName<'static>,
    /// Replace the shared server name with the target node ID for canonical
    /// enrolled clusters.
    pub verify_node_id: bool,
}

/// A live mesh connection: a plain TCP stream, or a mutually-authenticated
/// TLS session over one. Implements `AsyncRead`/`AsyncWrite` by delegating to
/// the active variant so the framing code is transport-agnostic.
enum MeshConn {
    /// Plaintext TCP (no peer mTLS configured).
    Plain(TcpStream),
    /// TLS-wrapped TCP. Boxed because `TlsStream` is comparatively large.
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for MeshConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MeshConn::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MeshConn::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MeshConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            MeshConn::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MeshConn::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MeshConn::Plain(s) => Pin::new(s).poll_flush(cx),
            MeshConn::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MeshConn::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MeshConn::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

// --- PeerClient ---

/// Per-peer RPC client. Holds exactly one TCP connection; reconnects lazily
/// the next time a request is issued after a transport error.
pub struct PeerClient {
    /// Destination `host:port` for outbound connects. Immutable after
    /// construction.
    addr: String,
    /// Optional AEAD cipher. When `Some`, every outbound request is
    /// sealed before framing and every inbound response is opened after
    /// unframing. `None` preserves K2 plaintext wire behavior.
    cipher: Option<Cipher>,
    /// Optional client-side peer mTLS. When `Some`, the connection is wrapped
    /// in a mutually-authenticated TLS session right after the TCP connect.
    tls: Option<MeshTlsClient>,
    /// Shared inner state: current stream (if any) + monotonic request id
    /// counter. The `Mutex` also serialises send/recv so the MVP is always
    /// at most one request in flight per peer.
    inner: Arc<Mutex<InnerClient>>,
}

/// Internal state guarded by `PeerClient::inner`.
struct InnerClient {
    /// Live connection (plain TCP or TLS). `None` before the first request or
    /// after any transport failure; the next `send_request` reconnects.
    stream: Option<MeshConn>,
    /// Monotonic per-connection request id. Reset on reconnect.
    next_id: u64,
}

impl PeerClient {
    /// Construct a new peer client targeting `addr` (e.g. `"10.0.0.2:8946"`).
    /// The connection is **not** opened eagerly; the first [`Self::get`], [`Self::put`],
    /// or [`Self::delete`] call triggers the connect.
    ///
    /// Backwards-compatible wrapper around [`Self::with_cipher`] that
    /// defaults to plaintext wire format.
    pub fn new(addr: String) -> Self {
        Self::with_cipher(addr, None)
    }

    /// K3: construct a peer client with an optional AEAD cipher.
    ///
    /// When `cipher` is `Some`, every outbound request is sealed before
    /// framing and every inbound response is opened after unframing. A
    /// decrypt failure invalidates the connection and is returned as an
    /// error to the caller; the next call transparently reconnects.
    pub fn with_cipher(addr: String, cipher: Option<Cipher>) -> Self {
        Self::with_security(addr, cipher, None)
    }

    /// Construct a peer client with optional AEAD framing and optional peer
    /// mTLS. When `tls` is `Some`, every connection to this peer is wrapped in
    /// a mutually-authenticated TLS session after the TCP connect, so an
    /// untrusted peer (or a man-in-the-middle) cannot serve mesh RPCs.
    pub fn with_security(addr: String, cipher: Option<Cipher>, tls: Option<MeshTlsClient>) -> Self {
        Self {
            addr,
            cipher,
            tls,
            inner: Arc::new(Mutex::new(InnerClient {
                stream: None,
                next_id: 1,
            })),
        }
    }

    /// Peer address this client targets (debug / diagnostics).
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// Fetch `key` from the remote peer. Returns `Ok(None)` on remote miss,
    /// `Ok(Some(bytes))` on hit, and `Err` on any transport-level failure
    /// (connect refused, read timeout, malformed frame, etc.).
    pub async fn get(&self, key: String) -> anyhow::Result<Option<Bytes>> {
        match self.send_request(CacheOp::Get { key }).await? {
            CacheResult::Value(v) => Ok(v),
            CacheResult::Error(e) => Err(anyhow::anyhow!("remote error: {}", e)),
            other => Err(anyhow::anyhow!("unexpected cache result: {:?}", other)),
        }
    }

    /// Store `value` under `key` on the remote peer with no expiry.
    ///
    /// Convenience wrapper around [`Self::put_with_ttl`] with `ttl_secs = 0`
    /// (K1's "no expiry" convention). Retained for back-compat with
    /// callers that do not need TTL semantics.
    pub async fn put(&self, key: String, value: Bytes) -> anyhow::Result<()> {
        self.put_with_ttl(key, value, 0).await
    }

    /// Store `value` under `key` on the remote peer with an optional TTL.
    ///
    /// `ttl_secs = 0` means "no expiry" and matches the pre-K1 `put`
    /// semantics. Any positive value instructs the remote peer to drop
    /// the entry after that many seconds (see
    /// [`crate::state::distributed_cache::DistributedCache::put_local_with_ttl`]).
    pub async fn put_with_ttl(
        &self,
        key: String,
        value: Bytes,
        ttl_secs: u64,
    ) -> anyhow::Result<()> {
        match self
            .send_request(CacheOp::Put {
                key,
                value,
                ttl_secs,
            })
            .await?
        {
            CacheResult::Acked => Ok(()),
            CacheResult::Error(e) => Err(anyhow::anyhow!("remote error: {}", e)),
            other => Err(anyhow::anyhow!("unexpected cache result: {:?}", other)),
        }
    }

    /// Delete `key` on the remote peer. Returns `Ok(())` on ack; the peer
    /// does not distinguish between hit and miss, matching the semantics of
    /// the semantic cache purge API.
    pub async fn delete(&self, key: String) -> anyhow::Result<()> {
        match self.send_request(CacheOp::Delete { key }).await? {
            CacheResult::Acked => Ok(()),
            CacheResult::Error(e) => Err(anyhow::anyhow!("remote error: {}", e)),
            other => Err(anyhow::anyhow!("unexpected cache result: {:?}", other)),
        }
    }

    /// Delete every remote entry whose key starts with `prefix`, returning
    /// the number of entries removed on the peer's local shard.
    ///
    /// An empty `prefix` is the K2 wire-format convention for "purge
    /// everything". Callers implementing `PurgeScope::All` pass `""`;
    /// `PurgeScope::KeyPrefix` and `PurgeScope::Origin` pass the concrete
    /// prefix they want scanned.
    ///
    /// The caller is responsible for broadcasting this RPC to every peer
    /// (purge is cluster-wide, not consistent-hash-routed) and summing the
    /// per-peer counts. See
    /// [`crate::state::distributed_cache::DistributedCache::purge_prefix_local`]
    /// for the local half of the operation.
    pub async fn purge_prefix(&self, prefix: String) -> anyhow::Result<u64> {
        match self.send_request(CacheOp::PurgePrefix { prefix }).await? {
            CacheResult::Purged(n) => Ok(n),
            CacheResult::Error(e) => Err(anyhow::anyhow!("remote error: {}", e)),
            other => Err(anyhow::anyhow!("unexpected cache result: {:?}", other)),
        }
    }

    /// Inner engine for all three public RPCs. Locks `inner`, opens the TCP
    /// connection on demand, serialises the request, writes it, reads the
    /// paired response, and returns the result.
    ///
    /// Any transport error clears `inner.stream` so the next call starts by
    /// reconnecting.
    async fn send_request(&self, op: CacheOp) -> anyhow::Result<CacheResult> {
        let mut guard = self.inner.lock().await;

        // --- Ensure we're connected ---
        if guard.stream.is_none() {
            let tcp = TcpStream::connect(&self.addr)
                .await
                .map_err(|e| anyhow::anyhow!("connect to {} failed: {}", self.addr, e))?;
            // Small perf win on the wire side: coalescing is almost never
            // beneficial for a request/response RPC.
            let _ = tcp.set_nodelay(true);
            let conn = match &self.tls {
                Some(t) => MeshConn::Tls(Box::new(
                    t.connector
                        .connect(t.server_name.clone(), tcp)
                        .await
                        .map_err(|e| {
                            anyhow::anyhow!("TLS handshake to {} failed: {}", self.addr, e)
                        })?,
                )),
                None => MeshConn::Plain(tcp),
            };
            guard.stream = Some(conn);
        }

        let request_id = guard.next_id;
        guard.next_id = guard.next_id.wrapping_add(1);
        let req = Request { request_id, op };
        let plaintext = crate::transport::wire::encode(&req)
            .map_err(|e| anyhow::anyhow!("request serialize failed: {}", e))?;

        // K3: seal the request body when encryption is configured. The
        // server's matching `read_frame + open` step mirrors this.
        let on_wire: Vec<u8> = match self.cipher.as_ref() {
            Some(c) => c.seal(&plaintext),
            None => plaintext,
        };

        // --- Send request and read response ---
        //
        // The split borrows on `guard.stream` are confined to the inner
        // block so they end before we touch `guard.stream = None`. Any I/O
        // error tears the connection down so the next call reconnects.
        let io_result: anyhow::Result<Vec<u8>> = {
            // `MeshConn` is `AsyncRead + AsyncWrite`; write then read run
            // sequentially on the same connection, so no split is needed.
            let conn = guard.stream.as_mut().expect("connected above");
            match write_frame(conn, &on_wire).await {
                Ok(()) => match read_frame(conn).await {
                    Ok(b) => Ok(b),
                    Err(e) => Err(anyhow::anyhow!("read from {} failed: {}", self.addr, e)),
                },
                Err(e) => Err(anyhow::anyhow!("write to {} failed: {}", self.addr, e)),
            }
        };
        let resp_bytes = match io_result {
            Ok(b) => b,
            Err(e) => {
                guard.stream = None;
                return Err(e);
            }
        };

        // K3: open the sealed response body. A decrypt failure is fatal
        // for this connection; we drop the stream so the next call
        // reconnects (and, on a key mismatch, fails again cleanly).
        let resp_plain: Vec<u8> = match self.cipher.as_ref() {
            Some(c) => match c.open(&resp_bytes) {
                Some(pt) => pt,
                None => {
                    guard.stream = None;
                    return Err(anyhow::anyhow!(
                        "response from {} failed AEAD decrypt",
                        self.addr
                    ));
                }
            },
            None => resp_bytes,
        };

        let resp: Response = crate::transport::wire::decode(&resp_plain)
            .map_err(|e| anyhow::anyhow!("response deserialize failed: {}", e))?;
        if resp.request_id != request_id {
            // Pipelined implementations would fix this up via a pending
            // map. In the serial MVP a mismatch is a bug; tear the
            // connection down so state resyncs on the next call.
            guard.stream = None;
            return Err(anyhow::anyhow!(
                "request/response id mismatch: sent {}, got {}",
                request_id,
                resp.request_id
            ));
        }
        Ok(resp.result)
    }
}

// --- Client pool ---

/// Thread-safe pool of [`PeerClient`] instances keyed by `host:port`.
///
/// The pool lazily constructs a client on first lookup and reuses it for
/// every subsequent call. Lookups take a read lock on the hot path and only
/// escalate to a write lock on insert, so contention is bounded by the
/// number of distinct peers rather than the request rate.
///
/// K3: an optional cluster-wide [`Cipher`] is stamped into every newly
/// constructed client. Plaintext behavior is preserved when `cipher` is
/// `None` (the pre-K3 default for `TransportClientPool::new`).
#[derive(Default)]
pub struct TransportClientPool {
    clients: RwLock<HashMap<String, Arc<PeerClient>>>,
    /// Shared cipher handed to every newly constructed `PeerClient`.
    /// `None` means plaintext; `Some` means every outbound RPC is sealed
    /// and every response is opened before deserialization.
    cipher: Option<Cipher>,
    /// Optional client-side peer mTLS handed to every newly constructed
    /// `PeerClient`. `None` means plaintext connects.
    tls: Option<MeshTlsClient>,
}

impl TransportClientPool {
    /// Construct an empty pool with plaintext clients.
    pub fn new() -> Self {
        Self::with_security(None, None)
    }

    /// K3: construct an empty pool that builds AEAD-encrypted peer clients.
    pub fn with_cipher(cipher: Option<Cipher>) -> Self {
        Self::with_security(cipher, None)
    }

    /// Construct an empty pool whose clients use the given optional AEAD
    /// cipher and/or peer mTLS. Every client created via [`Self::client_for`]
    /// carries a clone of both, so all outbound RPCs share the same transport
    /// security as the server on the other end.
    pub fn with_security(cipher: Option<Cipher>, tls: Option<MeshTlsClient>) -> Self {
        Self {
            clients: RwLock::new(HashMap::new()),
            cipher,
            tls,
        }
    }

    /// Return the [`PeerClient`] for `peer_addr`, constructing it if this is
    /// the first request for that address. The returned `Arc` can be cloned
    /// freely; callers share the same underlying TCP connection.
    pub fn client_for(&self, peer_addr: &str) -> Arc<PeerClient> {
        self.client_for_key(peer_addr, peer_addr, None)
    }

    /// Return a client for one stable node identity and transport address.
    /// Canonical enrolled clusters verify the target node ID as a certificate
    /// SAN; compatibility transports retain their configured shared SAN.
    pub fn client_for_node(&self, node_id: &str, peer_addr: &str) -> Arc<PeerClient> {
        self.try_client_for_node(node_id, peer_addr)
            .expect("validated cluster node ID is a DNS-compatible certificate SAN")
    }

    /// Return a node-specific client, or `None` while the ring still contains a seed alias.
    pub fn try_client_for_node(&self, node_id: &str, peer_addr: &str) -> Option<Arc<PeerClient>> {
        let node_specific = self.tls.as_ref().is_some_and(|tls| tls.verify_node_id);
        let cache_key = if node_specific {
            format!("{node_id}\0{peer_addr}")
        } else {
            peer_addr.to_string()
        };
        if node_specific && ServerName::try_from(node_id.to_string()).is_err() {
            return None;
        }
        Some(self.client_for_key(&cache_key, peer_addr, node_specific.then_some(node_id)))
    }

    fn client_for_key(
        &self,
        cache_key: &str,
        peer_addr: &str,
        node_id: Option<&str>,
    ) -> Arc<PeerClient> {
        // Fast path: read lock, cheap clone of the `Arc`.
        if let Ok(guard) = self.clients.read() {
            if let Some(c) = guard.get(cache_key) {
                return c.clone();
            }
        }
        // Slow path: escalate to a write lock and insert.
        let mut guard = match self.clients.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let cipher = self.cipher.clone();
        let tls = self.tls.clone().map(|mut tls| {
            if let Some(node_id) = node_id {
                tls.server_name = ServerName::try_from(node_id.to_string())
                    .expect("validated cluster node ID is a DNS-compatible certificate SAN");
            }
            tls
        });
        guard
            .entry(cache_key.to_string())
            .or_insert_with(|| {
                Arc::new(PeerClient::with_security(
                    peer_addr.to_string(),
                    cipher,
                    tls,
                ))
            })
            .clone()
    }

    /// Number of peer clients currently cached. Test / diagnostics only.
    pub fn len(&self) -> usize {
        self.clients.read().map(|g| g.len()).unwrap_or(0)
    }

    /// Whether the pool has no clients cached. Test / diagnostics only.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::distributed_cache::DistributedCache;
    use crate::transport::server::TransportServer;

    async fn spawn_server() -> (TransportServer, Arc<DistributedCache<Bytes>>, u16) {
        let cache: Arc<DistributedCache<Bytes>> =
            Arc::new(DistributedCache::new("server-node", 16));
        let server = TransportServer::start(0, cache.clone())
            .await
            .expect("start");
        let port = server.local_port();
        (server, cache, port)
    }

    #[tokio::test]
    async fn client_put_then_get_roundtrip() {
        let (server, _cache, port) = spawn_server().await;
        let client = PeerClient::new(format!("127.0.0.1:{port}"));

        client
            .put("k".to_string(), Bytes::from_static(b"v"))
            .await
            .expect("put");
        let got = client.get("k".to_string()).await.expect("get");
        assert_eq!(got, Some(Bytes::from_static(b"v")));

        server.shutdown();
    }

    #[tokio::test]
    async fn client_get_miss_returns_none() {
        let (server, _cache, port) = spawn_server().await;
        let client = PeerClient::new(format!("127.0.0.1:{port}"));
        let got = client.get("missing".to_string()).await.expect("get");
        assert_eq!(got, None);
        server.shutdown();
    }

    #[tokio::test]
    async fn client_delete_removes_key_on_server() {
        let (server, cache, port) = spawn_server().await;
        cache.put_local("doomed", Bytes::from_static(b"val"));
        assert!(cache.get_local("doomed").is_some());

        let client = PeerClient::new(format!("127.0.0.1:{port}"));
        client.delete("doomed".to_string()).await.expect("delete");
        assert_eq!(cache.get_local("doomed"), None);

        server.shutdown();
    }

    #[tokio::test]
    async fn client_multiple_sequential_requests_reuse_connection() {
        let (server, _cache, port) = spawn_server().await;
        let client = PeerClient::new(format!("127.0.0.1:{port}"));

        for i in 0..5u32 {
            let key = format!("k-{i}");
            let val = Bytes::from(format!("v-{i}"));
            client.put(key.clone(), val.clone()).await.expect("put");
            assert_eq!(client.get(key).await.expect("get"), Some(val));
        }
        server.shutdown();
    }

    #[tokio::test]
    async fn client_purge_prefix_returns_remote_count() {
        let (server, cache, port) = spawn_server().await;
        cache.put_local("p:1", Bytes::from_static(b"a"));
        cache.put_local("p:2", Bytes::from_static(b"b"));
        cache.put_local("q:1", Bytes::from_static(b"c"));

        let client = PeerClient::new(format!("127.0.0.1:{port}"));
        let n = client.purge_prefix("p:".to_string()).await.expect("purge");
        assert_eq!(n, 2);
        assert_eq!(cache.get_local("p:1"), None);
        assert_eq!(cache.get_local("p:2"), None);
        assert_eq!(cache.get_local("q:1"), Some(Bytes::from_static(b"c")));

        server.shutdown();
    }

    #[tokio::test]
    async fn client_purge_prefix_empty_drops_all() {
        let (server, cache, port) = spawn_server().await;
        cache.put_local("x", Bytes::from_static(b"1"));
        cache.put_local("y", Bytes::from_static(b"2"));

        let client = PeerClient::new(format!("127.0.0.1:{port}"));
        let n = client.purge_prefix(String::new()).await.expect("purge");
        assert_eq!(n, 2);
        assert_eq!(cache.get_local("x"), None);
        assert_eq!(cache.get_local("y"), None);

        server.shutdown();
    }

    #[tokio::test]
    async fn client_connection_refused_propagates_error_and_recovers() {
        // Point at a port with nothing listening.
        let client = PeerClient::new("127.0.0.1:1".to_string());
        let err = client.get("k".to_string()).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("connect") || msg.contains("refused") || msg.contains("127.0.0.1:1"),
            "unexpected error message: {msg}"
        );
        // A subsequent call must not hang; it should fail with the same
        // kind of error rather than panic or deadlock.
        let err2 = client.get("k".to_string()).await.unwrap_err();
        let _ = err2.to_string(); // just verify we got a second error
    }

    #[tokio::test]
    async fn pool_returns_same_client_for_same_addr() {
        let pool = TransportClientPool::new();
        let a = pool.client_for("10.0.0.1:8946");
        let b = pool.client_for("10.0.0.1:8946");
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(pool.len(), 1);
    }

    #[tokio::test]
    async fn pool_constructs_distinct_clients_for_distinct_addrs() {
        let pool = TransportClientPool::new();
        let a = pool.client_for("10.0.0.1:8946");
        let b = pool.client_for("10.0.0.2:8946");
        assert!(!Arc::ptr_eq(&a, &b));
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn canonical_pool_pins_each_client_to_its_target_node_san() {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

        let ca_key = KeyPair::generate().unwrap();
        let mut ca = CertificateParams::new(Vec::new()).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca.self_signed(&ca_key).unwrap();
        let peer_key = KeyPair::generate().unwrap();
        let peer = CertificateParams::new(vec!["local-node".to_string()]).unwrap();
        let peer_cert = peer.signed_by(&peer_key, &ca_cert, &ca_key).unwrap();
        let connector =
            crate::transport::tls::build_connector(&crate::transport::tls::MeshTlsConfig {
                cert_pem: peer_cert.pem(),
                key_pem: peer_key.serialize_pem(),
                ca_pem: ca_cert.pem(),
            })
            .unwrap();
        let pool = TransportClientPool::with_security(
            None,
            Some(MeshTlsClient {
                connector,
                server_name: ServerName::try_from("shared-name").unwrap(),
                verify_node_id: true,
            }),
        );
        let worker_a = pool.client_for_node("worker-a", "10.0.0.2:8946");
        let worker_b = pool.client_for_node("worker-b", "10.0.0.2:8946");
        assert!(pool
            .try_client_for_node("127.0.0.1:7946", "127.0.0.1:8946")
            .is_none());
        assert!(!Arc::ptr_eq(&worker_a, &worker_b));
        assert_eq!(
            worker_a.tls.as_ref().unwrap().server_name,
            ServerName::try_from("worker-a").unwrap()
        );
        assert_eq!(
            worker_b.tls.as_ref().unwrap().server_name,
            ServerName::try_from("worker-b").unwrap()
        );
    }

    #[tokio::test]
    async fn pool_is_empty_on_construction() {
        let pool = TransportClientPool::new();
        assert!(pool.is_empty());
    }

    // --- K3 encryption tests ---

    /// Spawn a transport server bound with the supplied cipher. Used by
    /// the K3 integration tests below.
    async fn spawn_server_with_cipher(
        cipher: Option<Cipher>,
    ) -> (TransportServer, Arc<DistributedCache<Bytes>>, u16) {
        let cache: Arc<DistributedCache<Bytes>> =
            Arc::new(DistributedCache::new("server-node", 16));
        let server = TransportServer::start_with_cipher(0, cache.clone(), cipher)
            .await
            .expect("start");
        let port = server.local_port();
        (server, cache, port)
    }

    #[tokio::test]
    async fn encrypted_put_get_roundtrip_matching_keys() {
        // Both sides share the same cipher: a put/get cycle completes
        // exactly as it does in plaintext mode, proving the frame
        // wrapper is symmetric.
        let cipher = Cipher::from_shared_key("cluster-secret");
        let (server, _cache, port) = spawn_server_with_cipher(Some(cipher.clone())).await;
        let client = PeerClient::with_cipher(format!("127.0.0.1:{port}"), Some(cipher));

        client
            .put("k".to_string(), Bytes::from_static(b"v"))
            .await
            .expect("put");
        let got = client.get("k".to_string()).await.expect("get");
        assert_eq!(got, Some(Bytes::from_static(b"v")));

        server.shutdown();
    }

    #[tokio::test]
    async fn encrypted_purge_prefix_returns_remote_count() {
        // Exercises the full AEAD-wrapped request/response for a
        // non-Get/Put op.
        let cipher = Cipher::from_shared_key("k");
        let (server, cache, port) = spawn_server_with_cipher(Some(cipher.clone())).await;
        cache.put_local("p:1", Bytes::from_static(b"a"));
        cache.put_local("p:2", Bytes::from_static(b"b"));
        cache.put_local("q:1", Bytes::from_static(b"c"));

        let client = PeerClient::with_cipher(format!("127.0.0.1:{port}"), Some(cipher));
        let n = client.purge_prefix("p:".to_string()).await.expect("purge");
        assert_eq!(n, 2);
        assert_eq!(cache.get_local("p:1"), None);
        assert_eq!(cache.get_local("p:2"), None);
        assert_eq!(cache.get_local("q:1"), Some(Bytes::from_static(b"c")));

        server.shutdown();
    }

    #[tokio::test]
    async fn mismatched_cipher_tears_down_connection() {
        // Client and server use different shared keys. The server
        // should drop the connection on the first request because the
        // request body fails AEAD open; the client observes an error.
        let server_cipher = Cipher::from_shared_key("key-server");
        let client_cipher = Cipher::from_shared_key("key-client-different");
        let (server, _cache, port) = spawn_server_with_cipher(Some(server_cipher)).await;
        let client = PeerClient::with_cipher(format!("127.0.0.1:{port}"), Some(client_cipher));

        let err = client.get("k".to_string()).await.unwrap_err();
        let _ = err.to_string(); // surface the message for test logs
        server.shutdown();
    }

    #[tokio::test]
    async fn plaintext_client_against_encrypted_server_fails() {
        // Mixed-mode deployment: the server is encrypted, the client
        // is not. The server must reject the unauthenticated frame and
        // close the connection.
        let server_cipher = Cipher::from_shared_key("cluster-secret");
        let (server, _cache, port) = spawn_server_with_cipher(Some(server_cipher)).await;
        let client = PeerClient::with_cipher(format!("127.0.0.1:{port}"), None);

        // The client sends plaintext postcard; the server fails AEAD
        // open and closes the connection. The client's read of the
        // response will then surface as a transport error.
        let err = client.get("k".to_string()).await.unwrap_err();
        let _ = err.to_string();
        server.shutdown();
    }

    #[tokio::test]
    async fn encrypted_client_against_plaintext_server_fails() {
        // Reverse asymmetry: client sends AEAD-wrapped frames to a
        // server that isn't expecting them. The server's postcard
        // deserialize will fail on the random AEAD bytes, it closes
        // the connection, the client surfaces a read error.
        let client_cipher = Cipher::from_shared_key("cluster-secret");
        let (server, _cache, port) = spawn_server_with_cipher(None).await;
        let client = PeerClient::with_cipher(format!("127.0.0.1:{port}"), Some(client_cipher));

        let err = client.get("k".to_string()).await.unwrap_err();
        let _ = err.to_string();
        server.shutdown();
    }

    #[tokio::test]
    async fn pool_stamps_cipher_onto_clients() {
        // Pool built with `with_cipher(Some(..))` must hand out
        // encrypted clients that interoperate with a matching server.
        let cipher = Cipher::from_shared_key("pool-key");
        let (server, _cache, port) = spawn_server_with_cipher(Some(cipher.clone())).await;
        let pool = TransportClientPool::with_cipher(Some(cipher));
        let client = pool.client_for(&format!("127.0.0.1:{port}"));

        client
            .put("pk".to_string(), Bytes::from_static(b"pv"))
            .await
            .expect("put via pool");
        let got = client.get("pk".to_string()).await.expect("get via pool");
        assert_eq!(got, Some(Bytes::from_static(b"pv")));

        server.shutdown();
    }
}

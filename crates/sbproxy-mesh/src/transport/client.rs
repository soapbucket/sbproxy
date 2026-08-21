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
//!
//! # Deadlines (WOR-2637)
//!
//! Every await in the request engine below is bounded twice: by its own
//! phase cap, and by one overall deadline for the whole call that is fixed
//! before the per-peer lock is even taken. The second bound is the load
//! bearing one. Five phase timeouts that each restart the clock add up to
//! five times the number an operator thinks they configured, and a request
//! path that waits that long is indistinguishable from one that hangs. See
//! the `PeerTimeouts` constants in this module for the numbers and the
//! reasoning behind each.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::error::Elapsed;
use tokio::time::Instant as Deadline;

use crate::crypto::Cipher;
use crate::metrics::{
    MESH_TRANSPORT_RPC_DURATION, MESH_TRANSPORT_RPC_ERRORS, TRANSPORT_RPC_KIND_CONNECT,
    TRANSPORT_RPC_KIND_DECODE, TRANSPORT_RPC_KIND_DECRYPT, TRANSPORT_RPC_KIND_ENCODE,
    TRANSPORT_RPC_KIND_IO, TRANSPORT_RPC_KIND_REMOTE, TRANSPORT_RPC_KIND_TIMEOUT_CONNECT,
    TRANSPORT_RPC_KIND_TIMEOUT_LOCK, TRANSPORT_RPC_KIND_TIMEOUT_READ,
    TRANSPORT_RPC_KIND_TIMEOUT_TLS, TRANSPORT_RPC_KIND_TIMEOUT_WRITE, TRANSPORT_RPC_KIND_TLS,
};
use crate::state::register::VersionedLwwMergeOutcome;

use super::frame::{
    read_frame, write_frame, CacheOp, CacheResult, CacheSnapshot, Request, Response,
};

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

/// Bounded `op` label for [`MESH_TRANSPORT_RPC_DURATION`], derived from
/// the [`CacheOp`] variant.
fn cache_op_label(op: &CacheOp) -> &'static str {
    match op {
        CacheOp::Get { .. } => "get",
        CacheOp::Put { .. } => "put",
        CacheOp::Delete { .. } => "delete",
        CacheOp::PurgePrefix { .. } => "purge_prefix",
        CacheOp::MergeVersioned { .. } => "merge_versioned",
        CacheOp::ReplicaApply { .. } => "replica_apply",
        CacheOp::ReplicaFetch { .. } => "replica_fetch",
        CacheOp::SyncDigest { .. } => "sync_digest",
        CacheOp::SnapshotPrefix { .. } => "snapshot_prefix",
    }
}

// --- Outbound deadlines ---

/// How long a caller waits for the per-peer RPC lock before giving up.
///
/// The transport is one connection per peer with one request in flight, so
/// callers queue behind each other by design. Five seconds is far past the
/// sub-millisecond round trip a healthy peer answers in, which means a wait
/// this long is never contention, it is a peer that has stopped answering
/// while holding the lane. Failing the queued callers fast is what keeps a
/// single wedged peer from wedging every task that wants it.
const RPC_LOCK_WAIT: Duration = Duration::from_secs(5);

/// Deadline on the TCP connect.
///
/// Three seconds is roughly ten times the worst plausible cross-region
/// round trip and a small fraction of the kernel's SYN retry schedule,
/// which on Linux gives up after about two minutes. Without this the OS
/// timer is the timer, and two minutes on a cache read is a hang.
const RPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Deadline on the peer mTLS handshake, after the TCP connect.
///
/// Two round trips plus certificate chain verification. Five seconds is
/// generous for a cross-region handshake on a loaded node and still bounded.
const RPC_TLS_TIMEOUT: Duration = Duration::from_secs(5);

/// Deadline on writing one request frame.
///
/// A request is small for every operation except a `Put` or `ReplicaApply`
/// of a large value, which the frame cap allows up to 16 MiB of. Ten seconds
/// clears that at roughly 13 Mbps, which no mesh link is below. This is also
/// the bound that catches a peer that accepts a connection and then stops
/// reading: the send buffer fills and the write parks.
const RPC_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Deadline on reading one response frame for a point operation.
///
/// `Get`, `Put`, `Delete`, `MergeVersioned`, `ReplicaApply`, and
/// `ReplicaFetch` all answer out of the peer's in-memory shard, so a healthy
/// reply is sub-millisecond. Ten seconds is four orders of magnitude of
/// headroom and still short enough that a request path waiting on one is not
/// simply hung.
const RPC_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Deadline on reading one response frame for a scanning operation.
///
/// `PurgePrefix`, `SyncDigest`, and `SnapshotPrefix` walk the peer's shard
/// rather than looking one key up, so seconds are a normal answer on a large
/// one and the point-operation deadline would shed real work. Sixty seconds
/// is sized for the scan, not for the request path; nothing on a request
/// path issues these.
const RPC_SCAN_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Overall deadline for one point-operation RPC, lock wait included.
///
/// A per-phase timeout is not a bound on the call. Lock, connect, TLS,
/// write, and read each restarting their own clock is how a "10 second
/// timeout" becomes a thirty-something second stall. This is the number that
/// actually holds, and every phase is clamped to whichever of the two
/// expires first.
const RPC_TOTAL_TIMEOUT: Duration = Duration::from_secs(15);

/// Overall deadline for one scanning RPC, lock wait included.
const RPC_SCAN_TOTAL_TIMEOUT: Duration = Duration::from_secs(90);

/// How long a cached connection may sit unused before the next request opens
/// a fresh one instead.
///
/// This exists to keep the server's idle reaper from ever being felt. The
/// serving side reclaims an admission slot from a connection that starts no
/// frame for five minutes; if the client only found out by writing into a
/// socket the peer had already closed, every quiet period would cost one
/// failed RPC. Recycling at a fifth of that window moves the reconnect to
/// this side, where it is a fresh connect on a call that then succeeds,
/// and costs one extra handshake per idle peer per minute.
const CLIENT_IDLE_REUSE_MAX: Duration = Duration::from_secs(60);

/// Network deadlines for one [`PeerClient`].
///
/// Not operator-configurable; the reasoning for each default lives at its
/// constant. Tests construct narrow values through
/// [`PeerClient::with_timeouts`] so a deadline is observable in
/// milliseconds instead of seconds.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PeerTimeouts {
    /// Cap on waiting for the per-peer RPC lock. See [`RPC_LOCK_WAIT`].
    pub(crate) lock_wait: Duration,
    /// Cap on the TCP connect. See [`RPC_CONNECT_TIMEOUT`].
    pub(crate) connect: Duration,
    /// Cap on the peer mTLS handshake. See [`RPC_TLS_TIMEOUT`].
    pub(crate) tls: Duration,
    /// Cap on writing the request frame. See [`RPC_WRITE_TIMEOUT`].
    pub(crate) write: Duration,
    /// Cap on reading a point operation's response. See [`RPC_READ_TIMEOUT`].
    pub(crate) read: Duration,
    /// Cap on reading a scanning operation's response. See
    /// [`RPC_SCAN_READ_TIMEOUT`].
    pub(crate) scan_read: Duration,
    /// Overall cap on a point operation. See [`RPC_TOTAL_TIMEOUT`].
    pub(crate) total: Duration,
    /// Overall cap on a scanning operation. See [`RPC_SCAN_TOTAL_TIMEOUT`].
    pub(crate) scan_total: Duration,
    /// Idle window past which a cached connection is replaced rather than
    /// reused. See [`CLIENT_IDLE_REUSE_MAX`].
    pub(crate) idle_reuse_max: Duration,
}

impl Default for PeerTimeouts {
    fn default() -> Self {
        Self {
            lock_wait: RPC_LOCK_WAIT,
            connect: RPC_CONNECT_TIMEOUT,
            tls: RPC_TLS_TIMEOUT,
            write: RPC_WRITE_TIMEOUT,
            read: RPC_READ_TIMEOUT,
            scan_read: RPC_SCAN_READ_TIMEOUT,
            total: RPC_TOTAL_TIMEOUT,
            scan_total: RPC_SCAN_TOTAL_TIMEOUT,
            idle_reuse_max: CLIENT_IDLE_REUSE_MAX,
        }
    }
}

impl PeerTimeouts {
    /// Overall deadline and response cap for `op`.
    ///
    /// Two classes, because one number cannot serve both. A point operation
    /// is a hash lookup on the peer and belongs to a request path; a scan
    /// walks the peer's shard and legitimately takes seconds. Sizing both by
    /// the scan would leave a request path waiting a minute on a dead peer,
    /// and sizing both by the point op would fail every large purge.
    fn budget_for(&self, op: &CacheOp) -> (Duration, Duration) {
        match op {
            CacheOp::PurgePrefix { .. }
            | CacheOp::SyncDigest { .. }
            | CacheOp::SnapshotPrefix { .. } => (self.scan_total, self.scan_read),
            CacheOp::Get { .. }
            | CacheOp::Put { .. }
            | CacheOp::Delete { .. }
            | CacheOp::MergeVersioned { .. }
            | CacheOp::ReplicaApply { .. }
            | CacheOp::ReplicaFetch { .. } => (self.total, self.read),
        }
    }
}

/// Await `future` under both its own phase cap and the request's overall
/// deadline, whichever comes first.
///
/// Neither clock restarts inside the call, and the overall deadline is a
/// fixed point in time rather than a duration, so the phases cannot add up
/// past it however many of them run.
async fn under_deadline<F>(
    deadline: Deadline,
    cap: Duration,
    future: F,
) -> Result<F::Output, Elapsed>
where
    F: Future,
{
    tokio::time::timeout_at(deadline.min(Deadline::now() + cap), future).await
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
    /// Network deadlines for every phase of an outbound RPC.
    timeouts: PeerTimeouts,
}

/// Internal state guarded by `PeerClient::inner`.
struct InnerClient {
    /// Live connection (plain TCP or TLS). `None` before the first request or
    /// after any transport failure; the next `send_request` reconnects.
    stream: Option<MeshConn>,
    /// Monotonic per-connection request id. Reset on reconnect.
    next_id: u64,
    /// When the current connection last completed a round trip. `None`
    /// before the first one. Drives the idle recycle that keeps this side
    /// ahead of the peer's idle reaper.
    last_used: Option<Instant>,
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
        Self::with_timeouts(addr, cipher, tls, PeerTimeouts::default())
    }

    /// [`Self::with_security`] with explicit network deadlines.
    ///
    /// In-crate only. The deadlines are not config keys on purpose: each
    /// default carries its reasoning at its constant, and a deadline an
    /// operator can raise to "none" is not a deadline. Tests use this to
    /// watch a bound fire in milliseconds.
    pub(crate) fn with_timeouts(
        addr: String,
        cipher: Option<Cipher>,
        tls: Option<MeshTlsClient>,
        timeouts: PeerTimeouts,
    ) -> Self {
        Self {
            addr,
            cipher,
            tls,
            inner: Arc::new(Mutex::new(InnerClient {
                stream: None,
                next_id: 1,
                last_used: None,
            })),
            timeouts,
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
            CacheResult::Error(e) => {
                MESH_TRANSPORT_RPC_ERRORS
                    .with_label_values(&[TRANSPORT_RPC_KIND_REMOTE])
                    .inc();
                Err(anyhow::anyhow!("remote error: {}", e))
            }
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
            CacheResult::Error(e) => {
                MESH_TRANSPORT_RPC_ERRORS
                    .with_label_values(&[TRANSPORT_RPC_KIND_REMOTE])
                    .inc();
                Err(anyhow::anyhow!("remote error: {}", e))
            }
            other => Err(anyhow::anyhow!("unexpected cache result: {:?}", other)),
        }
    }

    /// Atomically merge one versioned LWW candidate on the remote owner.
    pub async fn merge_versioned(
        &self,
        key: String,
        value: Bytes,
        ttl_secs: u64,
    ) -> anyhow::Result<VersionedLwwMergeOutcome> {
        match self
            .send_request(CacheOp::MergeVersioned {
                key,
                value,
                ttl_secs,
            })
            .await?
        {
            CacheResult::VersionedMerged(outcome) => Ok(outcome),
            CacheResult::Error(error) => {
                MESH_TRANSPORT_RPC_ERRORS
                    .with_label_values(&[TRANSPORT_RPC_KIND_REMOTE])
                    .inc();
                Err(anyhow::anyhow!("remote error: {error}"))
            }
            other => Err(anyhow::anyhow!("unexpected cache result: {other:?}")),
        }
    }

    /// Apply a replicated-record candidate on the remote peer's durable
    /// replica shard (WOR-1947). The peer persists the winning record
    /// before replying, so an `Ok` outcome means the record is durable
    /// there, not merely resident in memory.
    pub async fn replica_apply(
        &self,
        key: String,
        value: Bytes,
        ttl_secs: u64,
    ) -> anyhow::Result<VersionedLwwMergeOutcome> {
        match self
            .send_request(CacheOp::ReplicaApply {
                key,
                value,
                ttl_secs,
            })
            .await?
        {
            CacheResult::VersionedMerged(outcome) => Ok(outcome),
            CacheResult::Error(error) => {
                MESH_TRANSPORT_RPC_ERRORS
                    .with_label_values(&[TRANSPORT_RPC_KIND_REMOTE])
                    .inc();
                Err(anyhow::anyhow!("remote error: {error}"))
            }
            other => Err(anyhow::anyhow!("unexpected cache result: {other:?}")),
        }
    }

    /// Fetch the full stored replica record (register plus expiry) for
    /// `key` from the remote peer's replica shard. `Ok(None)` means the
    /// peer holds no record for the key.
    pub async fn replica_fetch(&self, key: String) -> anyhow::Result<Option<Bytes>> {
        match self.send_request(CacheOp::ReplicaFetch { key }).await? {
            CacheResult::Value(value) => Ok(value),
            CacheResult::Error(error) => {
                MESH_TRANSPORT_RPC_ERRORS
                    .with_label_values(&[TRANSPORT_RPC_KIND_REMOTE])
                    .inc();
                Err(anyhow::anyhow!("remote error: {error}"))
            }
            other => Err(anyhow::anyhow!("unexpected cache result: {other:?}")),
        }
    }

    /// Request one bounded digest page of the remote peer's replica shard
    /// for anti-entropy comparison.
    pub async fn sync_digest(
        &self,
        prefix: String,
        page_token: Option<String>,
        limit: u32,
    ) -> anyhow::Result<crate::transport::frame::DigestPage> {
        match self
            .send_request(CacheOp::SyncDigest {
                prefix,
                page_token,
                limit,
            })
            .await?
        {
            CacheResult::DigestPage(page) => Ok(page),
            CacheResult::Error(error) => {
                MESH_TRANSPORT_RPC_ERRORS
                    .with_label_values(&[TRANSPORT_RPC_KIND_REMOTE])
                    .inc();
                Err(anyhow::anyhow!("remote error: {error}"))
            }
            other => Err(anyhow::anyhow!("unexpected cache result: {other:?}")),
        }
    }

    /// Read one bounded lexicographic page of `prefix` from the remote
    /// peer's local shard.
    ///
    /// The request carries no routing key: the caller has already resolved
    /// the consistent-hash owner and dialled it. `maximum` must be in
    /// `1..=4096` and `prefix` must be non-empty and at most
    /// [`crate::transport::frame::MAX_ROUTED_SNAPSHOT_PREFIX_BYTES`] bytes;
    /// the peer answers an out-of-bounds request with a fixed non-secret
    /// error that never echoes the prefix.
    ///
    /// Only [`CacheResult::Snapshot`] is accepted. Every other result,
    /// including a remote error, is a transport-level failure for this call.
    ///
    /// A caller must verify the authenticated `semantic_cache_snapshot_v1`
    /// fleet capability before sending this operation. Postcard enum
    /// variants are not self-describing, so an older peer would decode the
    /// appended discriminant as garbage rather than as an unknown operation.
    pub async fn snapshot_prefix(
        &self,
        prefix: String,
        maximum: u32,
    ) -> anyhow::Result<CacheSnapshot> {
        match self
            .send_request(CacheOp::SnapshotPrefix { prefix, maximum })
            .await?
        {
            CacheResult::Snapshot(snapshot) => Ok(snapshot),
            CacheResult::Error(error) => {
                MESH_TRANSPORT_RPC_ERRORS
                    .with_label_values(&[TRANSPORT_RPC_KIND_REMOTE])
                    .inc();
                Err(anyhow::anyhow!("remote error: {error}"))
            }
            CacheResult::Value(_) => Err(anyhow::anyhow!(
                "unexpected cache result for snapshot_prefix"
            )),
            other => Err(anyhow::anyhow!(
                "unexpected cache result for snapshot_prefix: {other:?}"
            )),
        }
    }

    /// Delete `key` on the remote peer. Returns `Ok(())` on ack; the peer
    /// does not distinguish between hit and miss, matching the semantics of
    /// the semantic cache purge API.
    pub async fn delete(&self, key: String) -> anyhow::Result<()> {
        match self.send_request(CacheOp::Delete { key }).await? {
            CacheResult::Acked => Ok(()),
            CacheResult::Error(e) => {
                MESH_TRANSPORT_RPC_ERRORS
                    .with_label_values(&[TRANSPORT_RPC_KIND_REMOTE])
                    .inc();
                Err(anyhow::anyhow!("remote error: {}", e))
            }
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
            CacheResult::Error(e) => {
                MESH_TRANSPORT_RPC_ERRORS
                    .with_label_values(&[TRANSPORT_RPC_KIND_REMOTE])
                    .inc();
                Err(anyhow::anyhow!("remote error: {}", e))
            }
            other => Err(anyhow::anyhow!("unexpected cache result: {:?}", other)),
        }
    }

    /// Inner engine for all three public RPCs. Locks `inner`, opens the TCP
    /// connection on demand, serialises the request, writes it, reads the
    /// paired response, and returns the result.
    ///
    /// Any transport error clears `inner.stream` so the next call starts by
    /// reconnecting, and so does any deadline: a connection that missed a
    /// deadline has an unread response or half a request still on it, and
    /// reusing it would pair the next caller's request with this caller's
    /// answer.
    async fn send_request(&self, op: CacheOp) -> anyhow::Result<CacheResult> {
        let started = Instant::now();
        let op_label = cache_op_label(&op);
        // Fixed before the lock, so the whole call is bounded rather than
        // each of its phases separately.
        let (total, read_cap) = self.timeouts.budget_for(&op);
        let deadline = Deadline::now() + total;

        let Ok(mut guard) =
            under_deadline(deadline, self.timeouts.lock_wait, self.inner.lock()).await
        else {
            MESH_TRANSPORT_RPC_ERRORS
                .with_label_values(&[TRANSPORT_RPC_KIND_TIMEOUT_LOCK])
                .inc();
            return Err(anyhow::anyhow!(
                "peer {} is busy: no RPC slot within {:?}",
                self.addr,
                self.timeouts.lock_wait
            ));
        };

        // --- Recycle a connection the peer is about to reap ---
        //
        // The serving side reclaims an admission slot from a connection that
        // starts no frame for its idle window. Finding that out by writing
        // into a socket the peer already closed would cost one failed RPC
        // per quiet period, so the reconnect happens here instead, on a call
        // that then succeeds.
        if guard
            .last_used
            .is_some_and(|last| last.elapsed() >= self.timeouts.idle_reuse_max)
        {
            guard.stream = None;
            guard.last_used = None;
        }

        // --- Ensure we're connected ---
        if guard.stream.is_none() {
            let tcp = match under_deadline(
                deadline,
                self.timeouts.connect,
                TcpStream::connect(&self.addr),
            )
            .await
            {
                Err(_elapsed) => {
                    MESH_TRANSPORT_RPC_ERRORS
                        .with_label_values(&[TRANSPORT_RPC_KIND_TIMEOUT_CONNECT])
                        .inc();
                    return Err(anyhow::anyhow!(
                        "connect to {} timed out after {:?}",
                        self.addr,
                        self.timeouts.connect
                    ));
                }
                Ok(Err(e)) => {
                    MESH_TRANSPORT_RPC_ERRORS
                        .with_label_values(&[TRANSPORT_RPC_KIND_CONNECT])
                        .inc();
                    return Err(anyhow::anyhow!("connect to {} failed: {}", self.addr, e));
                }
                Ok(Ok(tcp)) => tcp,
            };
            // Small perf win on the wire side: coalescing is almost never
            // beneficial for a request/response RPC.
            let _ = tcp.set_nodelay(true);
            let conn = match &self.tls {
                Some(t) => {
                    let handshake = t.connector.connect(t.server_name.clone(), tcp);
                    match under_deadline(deadline, self.timeouts.tls, handshake).await {
                        Err(_elapsed) => {
                            MESH_TRANSPORT_RPC_ERRORS
                                .with_label_values(&[TRANSPORT_RPC_KIND_TIMEOUT_TLS])
                                .inc();
                            return Err(anyhow::anyhow!(
                                "TLS handshake to {} timed out after {:?}",
                                self.addr,
                                self.timeouts.tls
                            ));
                        }
                        Ok(Err(e)) => {
                            MESH_TRANSPORT_RPC_ERRORS
                                .with_label_values(&[TRANSPORT_RPC_KIND_TLS])
                                .inc();
                            return Err(anyhow::anyhow!(
                                "TLS handshake to {} failed: {}",
                                self.addr,
                                e
                            ));
                        }
                        Ok(Ok(tls_stream)) => MeshConn::Tls(Box::new(tls_stream)),
                    }
                }
                None => MeshConn::Plain(tcp),
            };
            guard.stream = Some(conn);
        }

        let request_id = guard.next_id;
        guard.next_id = guard.next_id.wrapping_add(1);
        let req = Request { request_id, op };
        let plaintext = crate::transport::wire::encode(&req).map_err(|e| {
            MESH_TRANSPORT_RPC_ERRORS
                .with_label_values(&[TRANSPORT_RPC_KIND_ENCODE])
                .inc();
            anyhow::anyhow!("request serialize failed: {}", e)
        })?;

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
        //
        // Each arm carries the metric `kind` it should be counted under, so
        // there is one place that increments and the closed set cannot grow
        // a value in a branch nobody reviewed.
        let io_result: Result<Vec<u8>, (&'static str, anyhow::Error)> = {
            // `MeshConn` is `AsyncRead + AsyncWrite`; write then read run
            // sequentially on the same connection, so no split is needed.
            let conn = guard.stream.as_mut().expect("connected above");
            match under_deadline(deadline, self.timeouts.write, write_frame(conn, &on_wire)).await {
                Err(_elapsed) => Err((
                    TRANSPORT_RPC_KIND_TIMEOUT_WRITE,
                    anyhow::anyhow!(
                        "write to {} timed out after {:?}",
                        self.addr,
                        self.timeouts.write
                    ),
                )),
                Ok(Err(e)) => Err((
                    TRANSPORT_RPC_KIND_IO,
                    anyhow::anyhow!("write to {} failed: {}", self.addr, e),
                )),
                Ok(Ok(())) => match under_deadline(deadline, read_cap, read_frame(conn)).await {
                    Err(_elapsed) => Err((
                        TRANSPORT_RPC_KIND_TIMEOUT_READ,
                        anyhow::anyhow!(
                            "no response from {} within {:?}",
                            self.addr,
                            read_cap.min(total)
                        ),
                    )),
                    Ok(Err(e)) => Err((
                        TRANSPORT_RPC_KIND_IO,
                        anyhow::anyhow!("read from {} failed: {}", self.addr, e),
                    )),
                    Ok(Ok(b)) => Ok(b),
                },
            }
        };
        let resp_bytes = match io_result {
            Ok(b) => b,
            Err((kind, e)) => {
                MESH_TRANSPORT_RPC_ERRORS.with_label_values(&[kind]).inc();
                guard.stream = None;
                guard.last_used = None;
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
                    MESH_TRANSPORT_RPC_ERRORS
                        .with_label_values(&[TRANSPORT_RPC_KIND_DECRYPT])
                        .inc();
                    guard.stream = None;
                    guard.last_used = None;
                    return Err(anyhow::anyhow!(
                        "response from {} failed AEAD decrypt",
                        self.addr
                    ));
                }
            },
            None => resp_bytes,
        };

        let resp: Response = crate::transport::wire::decode(&resp_plain).map_err(|e| {
            MESH_TRANSPORT_RPC_ERRORS
                .with_label_values(&[TRANSPORT_RPC_KIND_DECODE])
                .inc();
            anyhow::anyhow!("response deserialize failed: {}", e)
        })?;
        if resp.request_id != request_id {
            // Pipelined implementations would fix this up via a pending
            // map. In the serial MVP a mismatch is a bug; tear the
            // connection down so state resyncs on the next call.
            guard.stream = None;
            guard.last_used = None;
            return Err(anyhow::anyhow!(
                "request/response id mismatch: sent {}, got {}",
                request_id,
                resp.request_id
            ));
        }
        // A completed round trip is what the idle recycle measures from.
        guard.last_used = Some(Instant::now());
        MESH_TRANSPORT_RPC_DURATION
            .with_label_values(&[op_label])
            .observe(started.elapsed().as_secs_f64());
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
    use crate::state::register::{VersionedLwwMergeOutcome, VersionedLwwRegister};
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
    async fn sequential_rpcs_avoid_delayed_ack_stalls() {
        // WOR-1949 regression guard. A healthy loopback RPC costs well under
        // a millisecond; the delayed-ACK/Nagle write-write-read stall costs
        // ~40ms per RPC. The 20ms mean threshold sits far above any
        // plausible loaded-runner jitter for a loopback roundtrip and far
        // below the 40ms failure signature.
        use std::time::{Duration, Instant};

        let (server, cache, port) = spawn_server().await;
        cache.put_local("hot", Bytes::from_static(b"value"));
        let client = PeerClient::new(format!("127.0.0.1:{port}"));

        // First call connects; keep it out of the timed window.
        client.get("hot".to_string()).await.expect("warmup get");

        const N: u32 = 30;
        let started = Instant::now();
        for _ in 0..N {
            client.get("hot".to_string()).await.expect("get");
        }
        let mean = started.elapsed() / N;
        assert!(
            mean < Duration::from_millis(20),
            "mean loopback RPC took {mean:?}; smells like the delayed-ACK/Nagle stall"
        );

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
    async fn client_versioned_merge_runs_atomically_on_remote_owner() {
        let (server, cache, port) = spawn_server().await;
        let client = PeerClient::new(format!("127.0.0.1:{port}"));
        let candidate = |value: &str, version: u64| {
            Bytes::from(
                serde_json::to_vec(&VersionedLwwRegister::live(
                    value.to_string(),
                    "node-a",
                    version * 100,
                    version,
                    version.checked_sub(1),
                ))
                .unwrap(),
            )
        };

        assert_eq!(
            client
                .merge_versioned("state:one".to_string(), candidate("new", 2), 60)
                .await
                .unwrap(),
            VersionedLwwMergeOutcome::Replaced
        );
        assert_eq!(
            client
                .merge_versioned("state:one".to_string(), candidate("stale", 1), 60)
                .await
                .unwrap(),
            VersionedLwwMergeOutcome::StaleRejected
        );
        let stored: VersionedLwwRegister =
            serde_json::from_slice(&cache.get_local("state:one").unwrap()).unwrap();
        assert_eq!(stored.value(), Some("new"));

        server.shutdown();
    }

    #[tokio::test]
    async fn client_snapshot_prefix_maps_only_snapshot_result() {
        let (server, cache, port) = spawn_server().await;
        cache.put_local("member:b", Bytes::from_static(b"two"));
        cache.put_local("member:a", Bytes::from_static(b"one"));
        cache.put_local("other:a", Bytes::from_static(b"skip"));

        let client = PeerClient::new(format!("127.0.0.1:{port}"));
        let snapshot = client
            .snapshot_prefix("member:".to_string(), 16)
            .await
            .expect("snapshot");
        assert_eq!(
            snapshot.entries,
            vec![
                ("member:a".to_string(), Bytes::from_static(b"one")),
                ("member:b".to_string(), Bytes::from_static(b"two")),
            ]
        );
        assert!(!snapshot.truncated);

        server.shutdown();
    }

    #[tokio::test]
    async fn client_snapshot_prefix_rejects_an_unexpected_result() {
        // The server answers an out-of-bounds request with `CacheResult::Error`,
        // which is not a snapshot. The client must surface that as an error
        // rather than inventing an empty page.
        let (server, _cache, port) = spawn_server().await;
        let client = PeerClient::new(format!("127.0.0.1:{port}"));

        let err = client
            .snapshot_prefix("member:".to_string(), 0)
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("remote error"), "{message}");
        assert!(!message.contains("member:"), "{message}");

        server.shutdown();
    }

    #[test]
    fn snapshot_prefix_uses_the_closed_transport_operation_label() {
        // The transport duration metric labels on `op`, so the label set has
        // to stay a fixed closed vocabulary.
        assert_eq!(
            cache_op_label(&CacheOp::SnapshotPrefix {
                prefix: "member:".to_string(),
                maximum: 16,
            }),
            "snapshot_prefix"
        );
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

    // --- Outbound deadlines (WOR-2637) ---

    /// A peer that completes the TCP handshake, holds the socket, and never
    /// writes a byte. This is the shape the two existing "unreachable peer"
    /// tests do *not* cover: they point at `127.0.0.1:1`, which refuses, and
    /// a refusal returns on its own. Nothing here ever returns on its own.
    async fn silent_peer() -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();
        let task = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                // Held, not dropped: dropping would send a FIN and let the
                // client off the hook.
                held.push(stream);
            }
        });
        (addr, task)
    }

    /// A peer that answers every framed request with `Value(None)` and
    /// counts the connections it accepted.
    async fn counting_peer() -> (
        String,
        Arc<std::sync::atomic::AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        use std::sync::atomic::AtomicUsize;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&accepted);
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::spawn(async move {
                    while let Ok(payload) = read_frame(&mut stream).await {
                        let Ok(request) = crate::transport::wire::decode::<Request>(&payload)
                        else {
                            break;
                        };
                        let response = Response {
                            request_id: request.request_id,
                            result: CacheResult::Value(None),
                        };
                        let Ok(bytes) = crate::transport::wire::encode(&response) else {
                            break;
                        };
                        if write_frame(&mut stream, &bytes).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        (addr, accepted, task)
    }

    #[tokio::test]
    async fn a_peer_that_accepts_and_never_answers_loses_to_the_read_deadline() {
        let (addr, peer) = silent_peer().await;
        let client = PeerClient::with_timeouts(
            addr,
            None,
            None,
            PeerTimeouts {
                read: Duration::from_millis(200),
                total: Duration::from_millis(500),
                ..PeerTimeouts::default()
            },
        );

        // The outer timeout is the assertion. Without a read deadline this
        // call never returns and the harness limit is what ends the test.
        let outcome =
            tokio::time::timeout(Duration::from_secs(10), client.get("k".to_string())).await;
        let error = outcome
            .expect("the RPC must return on its own, not on the harness limit")
            .expect_err("a peer that never answers is not a successful get");
        assert!(
            error.to_string().contains("no response from"),
            "expected a read-deadline error, got: {error}"
        );

        peer.abort();
    }

    #[tokio::test]
    async fn one_wedged_peer_does_not_wedge_every_caller() {
        // The transport is one connection per peer, so callers queue on the
        // lock. Bounding only the network leaves the hundredth caller
        // waiting a hundred read deadlines; the lock deadline is what keeps
        // the lane from being the wedge.
        let (addr, peer) = silent_peer().await;
        let client = Arc::new(PeerClient::with_timeouts(
            addr,
            None,
            None,
            PeerTimeouts {
                lock_wait: Duration::from_millis(100),
                read: Duration::from_millis(200),
                total: Duration::from_millis(500),
                ..PeerTimeouts::default()
            },
        ));

        let started = Instant::now();
        let mut callers = Vec::new();
        for index in 0..100u32 {
            let client = Arc::clone(&client);
            callers.push(tokio::spawn(async move {
                client.get(format!("k-{index}")).await
            }));
        }
        let mut failures = 0usize;
        let joined = tokio::time::timeout(Duration::from_secs(20), async {
            for caller in callers {
                if caller.await.expect("caller task").is_err() {
                    failures += 1;
                }
            }
        })
        .await;

        assert!(
            joined.is_ok(),
            "100 callers against one silent peer never came back"
        );
        assert_eq!(failures, 100, "a silent peer cannot serve anybody");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the queue behind a wedged peer must not serialise 100 full deadlines, took {:?}",
            started.elapsed()
        );

        peer.abort();
    }

    #[tokio::test]
    async fn an_idle_connection_is_replaced_before_the_peer_reaps_it() {
        // The serving side reclaims a slot from a connection that goes quiet.
        // Discovering that by writing into an already-closed socket would
        // cost one failed RPC per quiet period, so this side recycles first.
        use std::sync::atomic::Ordering;

        let (addr, accepted, peer) = counting_peer().await;
        let client = PeerClient::with_timeouts(
            addr,
            None,
            None,
            PeerTimeouts {
                idle_reuse_max: Duration::from_millis(100),
                ..PeerTimeouts::default()
            },
        );

        client.get("a".to_string()).await.expect("first get");
        client.get("b".to_string()).await.expect("second get");
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "back-to-back requests must share one connection"
        );

        tokio::time::sleep(Duration::from_millis(200)).await;
        client.get("c".to_string()).await.expect("third get");
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            2,
            "a connection idle past the reuse window must be replaced"
        );

        peer.abort();
    }

    #[tokio::test]
    async fn a_phase_cannot_outlive_the_whole_request_budget() {
        // The mechanism behind the connect and TLS bounds: a generous phase
        // cap is still clamped by the overall deadline, so five phases
        // cannot add up to five times the number an operator was promised.
        let deadline = Deadline::now() + Duration::from_millis(100);
        let started = Instant::now();
        let outcome = under_deadline(
            deadline,
            Duration::from_secs(60),
            std::future::pending::<()>(),
        )
        .await;
        assert!(outcome.is_err(), "the overall deadline must win");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "waited {:?}, so the phase cap was used instead of the deadline",
            started.elapsed()
        );
    }

    #[test]
    fn the_shipped_outbound_deadlines_are_the_documented_ones() {
        // A default that drifts is a bound nobody reviewed.
        let timeouts = PeerTimeouts::default();
        assert_eq!(timeouts.lock_wait, Duration::from_secs(5));
        assert_eq!(timeouts.connect, Duration::from_secs(3));
        assert_eq!(timeouts.tls, Duration::from_secs(5));
        assert_eq!(timeouts.write, Duration::from_secs(10));
        assert_eq!(timeouts.read, Duration::from_secs(10));
        assert_eq!(timeouts.scan_read, Duration::from_secs(60));
        assert_eq!(timeouts.total, Duration::from_secs(15));
        assert_eq!(timeouts.scan_total, Duration::from_secs(90));
        assert_eq!(timeouts.idle_reuse_max, Duration::from_secs(60));
    }

    #[test]
    fn a_scan_gets_the_scan_budget_and_a_point_op_does_not() {
        // One number cannot serve both: a purge legitimately walks the
        // peer's shard, a get is a hash lookup on a request path.
        let timeouts = PeerTimeouts::default();
        assert_eq!(
            timeouts.budget_for(&CacheOp::Get {
                key: "k".to_string()
            }),
            (timeouts.total, timeouts.read)
        );
        assert_eq!(
            timeouts.budget_for(&CacheOp::PurgePrefix {
                prefix: String::new()
            }),
            (timeouts.scan_total, timeouts.scan_read)
        );
        assert_eq!(
            timeouts.budget_for(&CacheOp::SnapshotPrefix {
                prefix: "member:".to_string(),
                maximum: 16,
            }),
            (timeouts.scan_total, timeouts.scan_read)
        );
    }
}

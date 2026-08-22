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
//! peer-side close on the next frame read.
//!
//! # Inbound admission
//!
//! Everything a peer can make this node spend is bounded before it is spent.
//! `TransportLimits` carries the whole set: a hard cap on connections
//! served at once, a narrower cap on connections in the TLS admission phase,
//! and deadlines on the handshake, on going idle, on delivering a frame body,
//! and on draining a response. A connection that trips any of them is closed
//! and counted on [`crate::metrics::MESH_TRANSPORT_INBOUND_REJECTED`] through
//! a single chokepoint, so the reason set stays closed and a refusal storm
//! cannot also be a log flood.
//!
//! The admission permit is taken before the per-connection task is spawned
//! and then *moved into* that task, so it is returned when the task ends for
//! any reason at all, including a panic unwind or the runtime dropping the
//! future at shutdown. A permit released on the happy path only is a slow
//! leak that ends in a node that refuses every peer while serving none.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use bytes::Bytes;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Semaphore};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::crypto::Cipher;
use crate::metrics::{
    CRYPTO_KIND_TRANSPORT, INBOUND_REJECT_CONNECTION_LIMIT, INBOUND_REJECT_FRAME_TIMEOUT,
    INBOUND_REJECT_HANDSHAKE_FAILED, INBOUND_REJECT_HANDSHAKE_TIMEOUT, INBOUND_REJECT_IDLE_TIMEOUT,
    INBOUND_REJECT_WRITE_TIMEOUT, MESH_CRYPTO_DECRYPT_FAILED, MESH_TRANSPORT_INBOUND_REJECTED,
};
use crate::state::distributed_cache::DistributedCache;
use crate::state::replicated::ReplicaShard;

use super::frame::{
    read_frame_bounded, write_frame, CacheOp, CacheResult, CacheSnapshot, FrameReadError, Request,
    Response, MAX_ROUTED_SNAPSHOT_BYTES,
};

/// Fixed reply text for a snapshot request that violates its bounds.
///
/// The string is a constant so a rejection can never echo the requested
/// prefix, a stored key, or a stored value back to the peer or into a log.
const SNAPSHOT_REJECTED: &str = "invalid cache snapshot request";

// --- Inbound admission bounds ---

/// Maximum inbound cache RPC connections served at once.
///
/// The sizing rule is cluster shape, not request rate: [`PeerClient`] holds
/// exactly one connection per destination and serializes every operation
/// over it, so a healthy node's inbound count tracks how many peers exist,
/// not how busy they are. A 200-node cluster needs 200 even under saturation.
/// 1024 is therefore several times the largest mesh anyone runs here, which
/// is deliberate: a bound that a working fleet can reach is an outage
/// scheduled for the day the fleet grows. It is still small enough to be a
/// bound, because it caps the per-connection tasks and the in-flight frame
/// buffers behind them.
///
/// [`PeerClient`]: super::client::PeerClient
const MAX_INBOUND_CONNECTIONS: usize = 1_024;

/// Maximum inbound connections inside the TLS admission phase at once.
///
/// The handshake is the only inbound work a peer can make expensive before
/// it has proved anything: each one costs a signature verification and a key
/// agreement, on the runtime's threads, for a peer that may turn out to have
/// no certificate at all. Serving 64 at a time keeps a handshake flood from
/// becoming a CPU stall that starves the connections already admitted. It
/// does not slow a real cluster down: a whole fleet restarting reconnects at
/// most [`MAX_INBOUND_CONNECTIONS`] at once, each handshake is sub-
/// millisecond, so even the full queue drains inside a fraction of
/// [`INBOUND_HANDSHAKE_TIMEOUT`].
const MAX_INBOUND_HANDSHAKES: usize = 64;

/// Deadline covering the whole TLS admission phase: the wait for a handshake
/// slot plus the handshake itself.
///
/// Both halves are inside one deadline on purpose. Bounding only the
/// handshake would leave the queue in front of it unbounded, which just
/// moves the wedge one step earlier. Ten seconds is far past any real
/// handshake (sub-millisecond on loopback, a couple of round trips across a
/// region) and far short of forever, which is what it replaces.
const INBOUND_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long an admitted connection may hold its slot without starting a
/// request frame.
///
/// This is the bound the ticket is actually about: a peer that connects and
/// then says nothing used to hold a task and a slot forever, and enough of
/// them held all of them. Five minutes is chosen against how quiet a *legitimate*
/// mesh connection gets, not against how quiet a request looks. Routed cache
/// traffic is bursty and key-dependent, gossip runs on a different socket
/// entirely, and a node owning no hot keys can sit still for minutes without
/// anything being wrong. A cap chosen by analogy with an HTTP request path
/// would evict healthy peers on a schedule.
///
/// The client half recycles its own connections at a fifth of this
/// (`CLIENT_IDLE_REUSE_MAX`), which is what makes the reclaim free rather
/// than what prevents it. That recycle is evaluated when the client next
/// issues a request, not from a timer, so a link quiet for longer than this
/// whole window is reaped here. What the fifth buys is that the client's next
/// request after such a gap is past its own 60-second mark too, so it opens a
/// fresh connection instead of writing into the socket this side already
/// closed: the reclaim costs a handshake, never a failed RPC. A steady
/// `idle_timeout` rate on a quiet cluster is therefore normal, and only the
/// other five reasons on
/// [`crate::metrics::MESH_TRANSPORT_INBOUND_REJECTED`] are worth an alert.
const INBOUND_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// How long a frame has to finish arriving once its length prefix has landed.
///
/// Distinct from the idle deadline because the two describe different peers.
/// Quiet is normal; announcing 16 MiB and then delivering it a byte at a
/// minute is not. Thirty seconds clears the 16 MiB frame cap at roughly
/// 4.5 Mbps, which is well under any link a mesh runs over and well over
/// what a dribbling peer can sustain.
const INBOUND_FRAME_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a response has to drain into the socket before the connection is
/// abandoned.
///
/// This is the other half of the ticket's scenario. A peer that issues a
/// request and then stops reading fills the send buffer and parks the
/// per-connection task inside `write_all` with no timer on it. The same 30
/// seconds applies for the same bandwidth reason as [`INBOUND_FRAME_TIMEOUT`];
/// responses are smaller than requests in every operation the transport has.
const INBOUND_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Minimum gap between inbound-refusal warn lines, in milliseconds.
///
/// A refusal storm is exactly what the counter is for, and exactly the
/// situation in which one log line per refused connection hands the peer a
/// log-flood primitive on top of the connection flood. The counter carries
/// the volume; the log carries one line per window plus the number of
/// refusals it stands for.
const REFUSAL_LOG_INTERVAL_MS: u64 = 5_000;

/// Admission and deadline bounds for the inbound half of the transport.
///
/// Not operator-configurable. Every field has a defensible fleet-scale
/// default documented at its constant, and a bound that only exists when
/// someone remembers to configure it is not a bound. Tests construct narrow
/// values through [`TransportServer::start_with_limits`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct TransportLimits {
    /// Cap on connections served at once. See [`MAX_INBOUND_CONNECTIONS`].
    pub(crate) max_connections: usize,
    /// Cap on connections inside the TLS admission phase at once. See
    /// [`MAX_INBOUND_HANDSHAKES`].
    pub(crate) max_handshakes: usize,
    /// Deadline on the TLS admission phase. See [`INBOUND_HANDSHAKE_TIMEOUT`].
    pub(crate) handshake: Duration,
    /// Deadline on going idle between frames. See [`INBOUND_IDLE_TIMEOUT`].
    pub(crate) idle: Duration,
    /// Deadline on delivering a frame body. See [`INBOUND_FRAME_TIMEOUT`].
    pub(crate) frame: Duration,
    /// Deadline on draining a response. See [`INBOUND_WRITE_TIMEOUT`].
    pub(crate) write: Duration,
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            max_connections: MAX_INBOUND_CONNECTIONS,
            max_handshakes: MAX_INBOUND_HANDSHAKES,
            handshake: INBOUND_HANDSHAKE_TIMEOUT,
            idle: INBOUND_IDLE_TIMEOUT,
            frame: INBOUND_FRAME_TIMEOUT,
            write: INBOUND_WRITE_TIMEOUT,
        }
    }
}

/// The single chokepoint every inbound refusal goes through.
///
/// One place that increments the counter, so the `reason` set cannot quietly
/// grow a seventh value in a branch nobody reviewed, and one rate-limited
/// `warn` for the five reasons an operator should read, so the log stays
/// bounded no matter how many refusals arrive. The sixth, the idle reclaim, a
/// healthy cluster produces on its own and it logs at `debug` outside that
/// limiter; see `reject` below.
struct RefusalSink {
    /// Refusals counted since the last line was emitted.
    suppressed: AtomicU64,
    /// Milliseconds since [`Self::started`] at the last emitted line. Zero
    /// means "nothing emitted yet".
    last_log_ms: AtomicU64,
    /// Origin for the millisecond clock above.
    started: Instant,
}

impl RefusalSink {
    fn new() -> Self {
        Self {
            suppressed: AtomicU64::new(0),
            last_log_ms: AtomicU64::new(0),
            started: Instant::now(),
        }
    }

    /// Count one refused or torn-down inbound connection, and log it: at
    /// `warn` if the rate limiter allows, or at `debug` and unlimited when
    /// the reason is the routine idle reclaim. `detail` is free text for the
    /// log line only; it never reaches a label.
    fn reject(&self, reason: &'static str, peer: SocketAddr, detail: &str) {
        // `None` only if the family failed to register at startup; the
        // refusal still closes the connection and still logs.
        if let Some(counter) = &*MESH_TRANSPORT_INBOUND_REJECTED {
            counter.with_label_values(&[reason]).inc();
        }

        // An idle reclaim is the one member of the set a healthy cluster
        // reaches on its own. The client half recycles at a fifth of the idle
        // window, but it evaluates that lazily on its next request rather
        // than from a timer, so a link with nothing to say for the whole
        // window is reaped here rather than replaced ahead of time, and a
        // node owning no hot keys goes that quiet routinely. It leaves before
        // the rate limiter, not inside it, for two reasons: warning about a
        // normal reclaim is how a channel gets tuned out, and letting one
        // take the shared window would defer the refusal that mattered by a
        // whole interval and discard the suppressed count it was standing
        // for. Nothing is lost, because the counter above carries every one.
        if reason == INBOUND_REJECT_IDLE_TIMEOUT {
            tracing::debug!(
                reason,
                peer = %peer,
                "transport: inbound connection reclaimed after its idle window"
            );
            return;
        }

        let now_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let last = self.last_log_ms.load(Ordering::Relaxed);
        let due = last == 0 || now_ms.saturating_sub(last) >= REFUSAL_LOG_INTERVAL_MS;
        if due
            && self
                .last_log_ms
                .compare_exchange(last, now_ms.max(1), Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            let suppressed = self.suppressed.swap(0, Ordering::Relaxed);
            tracing::warn!(
                reason,
                peer = %peer,
                detail,
                also_suppressed = suppressed,
                "transport: inbound connection refused by an admission or deadline bound"
            );
        } else {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Everything a per-connection task needs that is identical for every
/// connection one server accepts. Cloned per connection so the accept loop
/// stays a handful of lines and the admission decision is readable in one
/// screen.
#[derive(Clone)]
struct ConnectionContext {
    /// Local shard every inbound request dispatches against.
    cache: Arc<DistributedCache<Bytes>>,
    /// Optional AEAD applied to frame bodies.
    cipher: Option<Cipher>,
    /// Optional peer mTLS. `Some` puts every connection through the
    /// bounded admission phase before it can send a frame.
    tls: Option<TlsAcceptor>,
    /// Durable replica shard behind the replicated operations.
    replica: Arc<ArcSwapOption<ReplicaShard>>,
    /// Bound on connections inside the TLS admission phase at once.
    handshakes: Arc<Semaphore>,
    /// The one place inbound refusals are counted and logged.
    refusals: Arc<RefusalSink>,
    /// Admission caps and network deadlines for this server.
    limits: TransportLimits,
}

/// Hand one admitted connection to its own task, carrying its admission
/// permit with it.
///
/// The permit is taken by the caller (before this is reached, so the bound
/// is enforced before any allocation) and moved into the task here, which is
/// what makes the release unconditional: the task ending for any reason
/// drops it, including a panic unwind and the runtime dropping the future at
/// shutdown. A permit released on the happy path only is a slow leak that
/// ends in a node refusing every peer while serving none.
fn spawn_connection(
    context: ConnectionContext,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    permit: tokio::sync::OwnedSemaphorePermit,
) {
    tokio::spawn(async move {
        let _permit = permit;
        let ConnectionContext {
            cache,
            cipher,
            tls,
            replica,
            handshakes,
            refusals,
            limits,
        } = context;

        let Some(acceptor) = tls else {
            handle_connection(stream, cache, cipher, replica, limits, peer, &refusals).await;
            return;
        };

        // The wait for a handshake slot is inside the same deadline as the
        // handshake itself. Bounding only the handshake would leave an
        // unbounded queue in front of it, which moves the wedge one step
        // earlier rather than removing it.
        let admitted = tokio::time::timeout(limits.handshake, async {
            match handshakes.acquire_owned().await {
                Ok(slot) => {
                    let outcome = acceptor.accept(stream).await;
                    drop(slot);
                    Some(outcome)
                }
                // Only reachable once the semaphore is closed, which nothing
                // in this crate does.
                Err(_closed) => None,
            }
        })
        .await;

        match admitted {
            Err(_elapsed) => refusals.reject(INBOUND_REJECT_HANDSHAKE_TIMEOUT, peer, ""),
            Ok(None) => {}
            Ok(Some(Err(error))) => {
                refusals.reject(INBOUND_REJECT_HANDSHAKE_FAILED, peer, &error.to_string());
            }
            Ok(Some(Ok(tls_stream))) => {
                handle_connection(tls_stream, cache, cipher, replica, limits, peer, &refusals)
                    .await;
            }
        }
    });
}

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
    /// Replica shard behind the WOR-1947 replicated ops. Installed after
    /// construction (the shard needs the node's durable directory, which
    /// bootstrap wires later); requests arriving before installation get
    /// a clean "not enabled" error rather than a hang.
    replica_shard: Arc<ArcSwapOption<ReplicaShard>>,
}

impl TransportServer {
    /// Bind a TCP listener on `0.0.0.0:port` and spawn the accept loop.
    ///
    /// `port=0` requests an ephemeral port; the bound port is available via
    /// [`Self::local_port`]. `cache` is shared with the local mesh node; every
    /// inbound request routes directly to its `get_local` / `put_local` /
    /// `delete_local` methods.
    ///
    /// Backwards-compatible wrapper that defaults to plaintext. K3 callers
    /// that want AEAD on the wire pass a `Cipher` to
    /// [`Self::start_with_security`] instead.
    pub async fn start(port: u16, cache: Arc<DistributedCache<Bytes>>) -> anyhow::Result<Self> {
        Self::start_with_cipher(port, cache, None).await
    }

    /// K3: bind a TCP listener with optional AES-256-GCM framing.
    ///
    /// When `cipher` is `Some`, every inbound frame is passed through
    /// [`Cipher::open`] before postcard deserialization, and every outbound
    /// response is passed through [`Cipher::seal`] before framing. AEAD
    /// failures tear down the connection immediately (unlike gossip's
    /// silent drop, because TCP is stateful and a cryptographic mismatch
    /// means the peer is misconfigured or hostile).
    pub(crate) async fn start_with_cipher(
        port: u16,
        cache: Arc<DistributedCache<Bytes>>,
        cipher: Option<Cipher>,
    ) -> anyhow::Result<Self> {
        Self::start_with_security(port, cache, cipher, None).await
    }

    /// Bind a TCP listener with optional AEAD framing and optional peer mTLS.
    ///
    /// When `tls` is `Some`, each accepted connection is wrapped in a
    /// mutually-authenticated TLS session before any frame is read, so a peer
    /// that fails the handshake (no certificate, or one not signed by the mesh
    /// CA) is dropped before it can issue an RPC. The handshake runs inside the
    /// per-connection task, so a slow or hostile peer cannot stall the accept
    /// loop. `cipher` still applies to the frames inside the TLS session; in
    /// practice an operator picks one transport-security layer or the other.
    ///
    /// Inbound admission and network deadlines come from the in-crate
    /// `TransportLimits` defaults; see the module docs for what each bound is
    /// and why it is set where it is.
    pub async fn start_with_security(
        port: u16,
        cache: Arc<DistributedCache<Bytes>>,
        cipher: Option<Cipher>,
        tls: Option<TlsAcceptor>,
    ) -> anyhow::Result<Self> {
        Self::start_with_limits(port, cache, cipher, tls, TransportLimits::default()).await
    }

    /// [`Self::start_with_security`] with explicit inbound bounds.
    ///
    /// In-crate only, and deliberately not reachable from config: the
    /// defaults are fleet-scale reasoning that belongs at the constants, not
    /// a knob an operator can set to "unlimited" on the day it matters. Tests
    /// use it to make a bound observable in milliseconds instead of minutes.
    pub(crate) async fn start_with_limits(
        port: u16,
        cache: Arc<DistributedCache<Bytes>>,
        cipher: Option<Cipher>,
        tls: Option<TlsAcceptor>,
        limits: TransportLimits,
    ) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(("0.0.0.0", port)).await?;
        let local_port = listener.local_addr()?.port();

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let replica_shard: Arc<ArcSwapOption<ReplicaShard>> = Arc::new(ArcSwapOption::empty());
        let connections = Arc::new(Semaphore::new(limits.max_connections));
        let context = ConnectionContext {
            cache,
            cipher,
            tls,
            replica: replica_shard.clone(),
            handshakes: Arc::new(Semaphore::new(limits.max_handshakes)),
            refusals: Arc::new(RefusalSink::new()),
            limits,
        };

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
                            // Admission is the first thing that happens to an
                            // accepted socket, and it never parks: the cheap
                            // bound is checked before a task, a handshake, or
                            // a frame buffer exists for this peer, and
                            // `try_acquire_owned` cannot queue a flood inside
                            // the accept loop.
                            Ok((stream, addr)) => match Arc::clone(&connections).try_acquire_owned() {
                                Err(_at_capacity) => {
                                    context
                                        .refusals
                                        .reject(INBOUND_REJECT_CONNECTION_LIMIT, addr, "");
                                    // Closing is the refusal a peer can act
                                    // on. It sees an immediate FIN on its
                                    // next RPC rather than a hang, treats it
                                    // as a transport error, and reconnects
                                    // lazily on the call after that.
                                    drop(stream);
                                }
                                Ok(permit) => {
                                    tracing::debug!(peer = %addr, "transport: accepted connection");
                                    // Mirror the client-side connect: the
                                    // response leg is a small write followed
                                    // by a read, so leaving Nagle on stalls
                                    // it against the client's delayed ACK
                                    // (WOR-1949).
                                    let _ = stream.set_nodelay(true);
                                    spawn_connection(context.clone(), stream, addr, permit);
                                }
                            },
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
            replica_shard,
        })
    }

    /// Install the durable replica shard behind the replicated ops
    /// (`ReplicaApply` / `ReplicaFetch` / `SyncDigest`). Until this is
    /// called those ops answer with a "not enabled" error. Existing
    /// connections pick the shard up on their next request.
    pub fn install_replica_shard(&self, shard: Arc<ReplicaShard>) {
        self.replica_shard.store(Some(shard));
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
/// envelope (`[nonce][ciphertext][tag]`). We open it before postcard
/// deserialization and seal every outgoing response body before framing.
/// A failed open tears down the connection: an authenticated peer cannot
/// "recover" by resyncing on the framing boundary after a crypto error, so
/// there is no reason to keep the socket open.
///
/// # Deadlines
///
/// Every await in the loop below is bounded. The read is bounded twice, by
/// an idle deadline on starting a frame and a frame deadline on finishing
/// one, neither of which restarts mid-frame. The write is bounded so a peer
/// that issues a request and then stops reading cannot park this task inside
/// `write_all` while it holds an admission slot. Dispatch itself is local and
/// synchronous, so the loop has no unbounded await left in it. Breaking out
/// on a deadline drops the connection whole, which is also what makes the
/// mid-frame cancellation safe: no partially read request is ever dispatched.
async fn handle_connection<S>(
    stream: S,
    cache: Arc<DistributedCache<Bytes>>,
    cipher: Option<Cipher>,
    replica: Arc<ArcSwapOption<ReplicaShard>>,
    limits: TransportLimits,
    peer: SocketAddr,
    refusals: &RefusalSink,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    loop {
        // --- Read a framed request, under both deadlines ---
        let payload = match read_frame_bounded(&mut reader, limits.idle, limits.frame).await {
            Ok(p) => p,
            Err(FrameReadError::Idle) => {
                refusals.reject(INBOUND_REJECT_IDLE_TIMEOUT, peer, "");
                break;
            }
            Err(FrameReadError::Stalled) => {
                refusals.reject(INBOUND_REJECT_FRAME_TIMEOUT, peer, "");
                break;
            }
            Err(FrameReadError::Io(e)) => {
                // `UnexpectedEof` is the normal path when the client closes
                // the connection; log everything else at `debug` so healthy
                // churn doesn't spam the logs.
                tracing::debug!(error = %e, "transport: frame read ended connection");
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
            CacheOp::MergeVersioned {
                key,
                value,
                ttl_secs,
            } => match cache.merge_versioned_local_with_ttl(&key, value, ttl_secs) {
                Ok(outcome) => CacheResult::VersionedMerged(outcome),
                Err(_) => CacheResult::Error("invalid versioned mesh state".to_string()),
            },
            // WOR-1947 replicated substrate. Dispatch stays local, like
            // every other arm: the sending coordinator picked this node
            // as a replica; recursing here would amplify writes.
            CacheOp::ReplicaApply {
                key,
                value,
                ttl_secs,
            } => match replica.load_full() {
                Some(shard) => match shard.apply_encoded(&key, &value, ttl_secs) {
                    Ok(outcome) => CacheResult::VersionedMerged(outcome),
                    Err(e) => CacheResult::Error(e.to_string()),
                },
                None => CacheResult::Error("replicated substrate not enabled".to_string()),
            },
            CacheOp::ReplicaFetch { key } => match replica.load_full() {
                Some(shard) => CacheResult::Value(shard.fetch_encoded(&key)),
                None => CacheResult::Error("replicated substrate not enabled".to_string()),
            },
            CacheOp::SyncDigest {
                prefix,
                page_token,
                limit,
            } => match replica.load_full() {
                Some(shard) => CacheResult::DigestPage(shard.digest_page(
                    &prefix,
                    page_token.as_deref(),
                    limit as usize,
                )),
                None => CacheResult::Error("replicated substrate not enabled".to_string()),
            },
            // Bounded routed-prefix snapshot. Dispatch stays local like every
            // other arm: the client already resolved the consistent-hash
            // owner, so recursing into a routed method here would amplify the
            // read. The bounded helper is the only entry point, so the reply
            // can never exceed the fixed entry and byte caps.
            CacheOp::SnapshotPrefix { prefix, maximum } => {
                match cache.snapshot_prefix_local_bounded(
                    &prefix,
                    maximum as usize,
                    MAX_ROUTED_SNAPSHOT_BYTES,
                ) {
                    Ok(snapshot) => CacheResult::Snapshot(CacheSnapshot {
                        entries: snapshot.entries,
                        truncated: snapshot.truncated,
                    }),
                    Err(_) => CacheResult::Error(SNAPSHOT_REJECTED.to_string()),
                }
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
        match tokio::time::timeout(limits.write, write_frame(&mut writer, &on_wire)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "transport: write_frame failed, closing connection");
                break;
            }
            Err(_elapsed) => {
                // The peer asked and then stopped reading. Half a frame is
                // on the wire; dropping the connection is the only clean
                // exit, and the peer's next RPC reconnects.
                refusals.reject(INBOUND_REJECT_WRITE_TIMEOUT, peer, "");
                break;
            }
        }
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::frame::read_frame;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// Delta reader for the inbound-rejection counter. The registry is
    /// process-wide and the test binary shares it, so every assertion here
    /// is against a before/after difference rather than an absolute.
    fn rejected(reason: &str) -> u64 {
        MESH_TRANSPORT_INBOUND_REJECTED
            .as_ref()
            .expect("the inbound-rejection family registers")
            .with_label_values(&[reason])
            .get()
    }

    /// Narrow bounds so a deadline is observable in milliseconds. Every
    /// field is set explicitly: a test that inherits a production default
    /// for the bound it is pinning proves nothing.
    fn tight_limits() -> TransportLimits {
        TransportLimits {
            max_connections: 64,
            max_handshakes: 8,
            handshake: Duration::from_millis(200),
            idle: Duration::from_millis(200),
            frame: Duration::from_millis(200),
            write: Duration::from_millis(200),
        }
    }

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
    async fn mtls_server_and_peer_client_roundtrip() {
        use crate::transport::client::MeshTlsClient;
        use crate::transport::tls::{build_acceptor, build_connector, MeshTlsConfig};
        use crate::transport::PeerClient;
        use rustls::pki_types::ServerName;

        // Test PKI: a CA plus one peer cert valid as both TLS server and
        // client (SAN `localhost`), used by both ends of the connection.
        let tls_cfg = {
            use rcgen::{
                BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
            };
            let ca_key = KeyPair::generate().unwrap();
            let mut ca = CertificateParams::new(Vec::new()).unwrap();
            ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let ca_cert = ca.self_signed(&ca_key).unwrap();
            let peer_key = KeyPair::generate().unwrap();
            let mut peer = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
            peer.extended_key_usages = vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ];
            let peer_cert = peer.signed_by(&peer_key, &ca_cert, &ca_key).unwrap();
            MeshTlsConfig {
                cert_pem: peer_cert.pem(),
                key_pem: peer_key.serialize_pem(),
                ca_pem: ca_cert.pem(),
            }
        };

        // TLS-enabled server.
        let cache: Arc<DistributedCache<Bytes>> = Arc::new(DistributedCache::new("mtls-node", 16));
        let acceptor = build_acceptor(&tls_cfg).expect("acceptor");
        let server = TransportServer::start_with_security(0, cache.clone(), None, Some(acceptor))
            .await
            .expect("start tls server");
        let port = server.local_port();

        // TLS peer client, connecting to the fixed logical name in the cert.
        let connector = build_connector(&tls_cfg).expect("connector");
        let client = PeerClient::with_security(
            format!("127.0.0.1:{port}"),
            None,
            Some(MeshTlsClient {
                connector,
                server_name: ServerName::try_from("localhost").unwrap(),
                verify_node_id: false,
            }),
        );

        // A put then a get round-trip through the mutually-authenticated TLS
        // session and the server's local cache.
        client
            .put("k".to_string(), Bytes::from_static(b"v"))
            .await
            .expect("put over mtls");
        let got = client.get("k".to_string()).await.expect("get over mtls");
        assert_eq!(got, Some(Bytes::from_static(b"v")));

        server.shutdown();
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

    /// Send one request over a fresh raw connection and return the reply.
    async fn round_trip(port: u16, op: CacheOp) -> CacheResult {
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        let (mut r, mut w) = stream.split();
        let req = Request { request_id: 1, op };
        let bytes = crate::transport::wire::encode(&req).expect("ser");
        write_frame(&mut w, &bytes).await.expect("write");
        let resp_bytes = read_frame(&mut r).await.expect("read");
        let resp: Response = crate::transport::wire::decode(&resp_bytes).expect("deser");
        assert_eq!(resp.request_id, 1);
        resp.result
    }

    #[tokio::test]
    async fn server_handles_snapshot_prefix_in_lexicographic_order() {
        let cache: Arc<DistributedCache<Bytes>> =
            Arc::new(DistributedCache::new("server-node", 16));
        cache.put_local("member:c", Bytes::from_static(b"three"));
        cache.put_local("member:a", Bytes::from_static(b"one"));
        cache.put_local("member:b", Bytes::from_static(b"two"));
        cache.put_local("other:a", Bytes::from_static(b"skip"));
        let server = TransportServer::start(0, cache.clone())
            .await
            .expect("start");
        let port = server.local_port();

        let result = round_trip(
            port,
            CacheOp::SnapshotPrefix {
                prefix: "member:".to_string(),
                maximum: 16,
            },
        )
        .await;
        match result {
            CacheResult::Snapshot(snapshot) => {
                assert_eq!(
                    snapshot
                        .entries
                        .iter()
                        .map(|(key, _)| key.as_str())
                        .collect::<Vec<_>>(),
                    vec!["member:a", "member:b", "member:c"]
                );
                assert!(!snapshot.truncated);
            }
            other => panic!("expected Snapshot, got {other:?}"),
        }

        server.shutdown();
    }

    #[tokio::test]
    async fn server_snapshot_prefix_omits_expired_entries() {
        let cache: Arc<DistributedCache<Bytes>> =
            Arc::new(DistributedCache::new("server-node", 16));
        cache.put_local("member:live", Bytes::from_static(b"live"));
        cache.put_local_with_ttl("member:gone", Bytes::from_static(b"gone"), 1);
        let server = TransportServer::start(0, cache.clone())
            .await
            .expect("start");
        let port = server.local_port();
        tokio::time::sleep(Duration::from_millis(1_100)).await;

        let result = round_trip(
            port,
            CacheOp::SnapshotPrefix {
                prefix: "member:".to_string(),
                maximum: 16,
            },
        )
        .await;
        match result {
            CacheResult::Snapshot(snapshot) => {
                assert_eq!(
                    snapshot.entries,
                    vec![("member:live".to_string(), Bytes::from_static(b"live"))]
                );
            }
            other => panic!("expected Snapshot, got {other:?}"),
        }

        server.shutdown();
    }

    #[tokio::test]
    async fn server_snapshot_prefix_sets_truncated() {
        let cache: Arc<DistributedCache<Bytes>> =
            Arc::new(DistributedCache::new("server-node", 16));
        for index in 0..5u32 {
            cache.put_local(&format!("member:{index}"), Bytes::from_static(b"v"));
        }
        let server = TransportServer::start(0, cache.clone())
            .await
            .expect("start");
        let port = server.local_port();

        let result = round_trip(
            port,
            CacheOp::SnapshotPrefix {
                prefix: "member:".to_string(),
                maximum: 2,
            },
        )
        .await;
        match result {
            CacheResult::Snapshot(snapshot) => {
                assert_eq!(snapshot.entries.len(), 2);
                assert!(snapshot.truncated, "a bounded page must report truncation");
            }
            other => panic!("expected Snapshot, got {other:?}"),
        }

        server.shutdown();
    }

    #[tokio::test]
    async fn server_snapshot_prefix_rejects_invalid_limit_without_echoing_prefix() {
        let cache: Arc<DistributedCache<Bytes>> =
            Arc::new(DistributedCache::new("server-node", 16));
        cache.put_local("member:secret-suffix", Bytes::from_static(b"secret-value"));
        let server = TransportServer::start(0, cache.clone())
            .await
            .expect("start");
        let port = server.local_port();

        for (prefix, maximum) in [
            ("member:secret-suffix".to_string(), 0u32),
            ("member:secret-suffix".to_string(), 4_097),
            (String::new(), 16),
        ] {
            let result = round_trip(port, CacheOp::SnapshotPrefix { prefix, maximum }).await;
            match result {
                CacheResult::Error(message) => {
                    assert_eq!(message, SNAPSHOT_REJECTED);
                    assert!(!message.contains("secret-suffix"), "{message}");
                    assert!(!message.contains("secret-value"), "{message}");
                }
                other => panic!("expected Error, got {other:?}"),
            }
        }

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

    // --- Inbound admission and deadlines (WOR-2637) ---

    /// Drive one Get to completion so the connection is provably admitted
    /// and holding a permit, then hand the live socket back to the caller.
    async fn admitted_connection(port: u16) -> TcpStream {
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        {
            let (mut r, mut w) = stream.split();
            let req = Request {
                request_id: 1,
                op: CacheOp::Get {
                    key: "probe".to_string(),
                },
            };
            let bytes = crate::transport::wire::encode(&req).expect("ser");
            write_frame(&mut w, &bytes).await.expect("write probe");
            read_frame(&mut r).await.expect("read probe");
        }
        stream
    }

    #[tokio::test]
    async fn inbound_connections_are_refused_past_the_admission_cap() {
        let cache: Arc<DistributedCache<Bytes>> =
            Arc::new(DistributedCache::new("server-node", 16));
        let limits = TransportLimits {
            max_connections: 2,
            // Long enough that nothing else can be what closed the third
            // connection inside this test.
            idle: Duration::from_secs(60),
            ..tight_limits()
        };
        let server = TransportServer::start_with_limits(0, cache, None, None, limits)
            .await
            .expect("start");
        let port = server.local_port();

        let _first = admitted_connection(port).await;
        let _second = admitted_connection(port).await;
        let before = rejected(INBOUND_REJECT_CONNECTION_LIMIT);

        // The third has nowhere to go. The kernel completes the TCP
        // handshake regardless, so the refusal shows up as a prompt EOF.
        let mut third = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), third.read(&mut buf))
            .await
            .expect("a refused peer must be closed, not hung");
        assert_eq!(read.expect("read"), 0, "expected an immediate close");
        assert!(
            rejected(INBOUND_REJECT_CONNECTION_LIMIT) > before,
            "the refusal must be counted"
        );

        server.shutdown();
    }

    #[tokio::test]
    async fn an_admission_permit_comes_back_when_the_connection_ends() {
        // A permit released only on the happy path is a slow leak that ends
        // in a node refusing every peer while serving none. One slot, used
        // twice in a row, is the smallest proof it comes back.
        let cache: Arc<DistributedCache<Bytes>> =
            Arc::new(DistributedCache::new("server-node", 16));
        let limits = TransportLimits {
            max_connections: 1,
            idle: Duration::from_secs(60),
            ..tight_limits()
        };
        let server = TransportServer::start_with_limits(0, cache, None, None, limits)
            .await
            .expect("start");
        let port = server.local_port();

        let first = admitted_connection(port).await;
        drop(first);

        // Give the per-connection task a moment to observe the peer close
        // and unwind, returning the permit.
        let mut reused = None;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let mut candidate = TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("connect");
            let mut probe = [0u8; 1];
            // A refused connection is closed immediately; a readable-nothing
            // socket that stays open is an admitted one.
            match tokio::time::timeout(Duration::from_millis(50), candidate.read(&mut probe)).await
            {
                // Still refused: the server closed it straight away.
                Ok(Ok(0)) => continue,
                // Admitted: an open connection with nothing to say blocks.
                Err(_still_open) => {
                    reused = Some(candidate);
                    break;
                }
                // Neither shape. Keep trying rather than call it a pass.
                Ok(_) => continue,
            }
        }
        assert!(
            reused.is_some(),
            "the only admission slot never came back after the first peer left"
        );

        server.shutdown();
    }

    #[tokio::test]
    async fn an_idle_connection_gives_its_slot_back() {
        let cache: Arc<DistributedCache<Bytes>> =
            Arc::new(DistributedCache::new("server-node", 16));
        let server = TransportServer::start_with_limits(0, cache, None, None, tight_limits())
            .await
            .expect("start");
        let port = server.local_port();
        let before = rejected(INBOUND_REJECT_IDLE_TIMEOUT);

        // Connect and say nothing at all. Before the idle deadline this
        // socket held a task and a slot for as long as the peer cared to
        // keep it, which is the whole defect.
        let mut quiet = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), quiet.read(&mut buf))
            .await
            .expect("an idle peer must be reaped, not held forever");
        assert_eq!(read.expect("read"), 0, "expected the server to close");
        assert!(
            rejected(INBOUND_REJECT_IDLE_TIMEOUT) > before,
            "the reaped connection must be counted"
        );

        server.shutdown();
    }

    #[tokio::test]
    async fn a_frame_that_starts_and_stalls_is_dropped() {
        let cache: Arc<DistributedCache<Bytes>> =
            Arc::new(DistributedCache::new("server-node", 16));
        let server = TransportServer::start_with_limits(0, cache, None, None, tight_limits())
            .await
            .expect("start");
        let port = server.local_port();
        let before = rejected(INBOUND_REJECT_FRAME_TIMEOUT);

        // Announce a body and never send it. `read_exact` used to wait for
        // the rest of it with no timer on it at all.
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        stream.write_u32(4_096).await.expect("write prefix");
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("a stalled frame must be abandoned, not awaited forever");
        assert_eq!(read.expect("read"), 0, "expected the server to close");
        assert!(
            rejected(INBOUND_REJECT_FRAME_TIMEOUT) > before,
            "the stalled frame must be counted"
        );

        server.shutdown();
    }

    #[tokio::test]
    async fn a_peer_that_stops_reading_does_not_park_the_handler() {
        // The other half of the ticket's scenario, driven straight at the
        // handler over a duplex pipe so the send buffer is small enough to
        // fill deterministically. Without the write deadline this call never
        // returns.
        let cache: Arc<DistributedCache<Bytes>> =
            Arc::new(DistributedCache::new("server-node", 16));
        cache.put_local("fat", Bytes::from(vec![b'v'; 64 * 1024]));
        let before = rejected(INBOUND_REJECT_WRITE_TIMEOUT);

        let (mut peer, server_side) = tokio::io::duplex(256);
        let handler = tokio::spawn({
            let cache = Arc::clone(&cache);
            let refusals = Arc::new(RefusalSink::new());
            let limits = tight_limits();
            async move {
                handle_connection(
                    server_side,
                    cache,
                    None,
                    Arc::new(ArcSwapOption::empty()),
                    limits,
                    "127.0.0.1:9".parse().expect("literal socket address"),
                    &refusals,
                )
                .await;
            }
        });

        let req = Request {
            request_id: 1,
            op: CacheOp::Get {
                key: "fat".to_string(),
            },
        };
        let bytes = crate::transport::wire::encode(&req).expect("ser");
        write_frame(&mut peer, &bytes).await.expect("write request");
        // Now stop reading. The 64 KiB response cannot fit in a 256-byte
        // pipe, so the handler blocks inside `write_all`.

        tokio::time::timeout(Duration::from_secs(5), handler)
            .await
            .expect("the handler must give up on a peer that stopped reading")
            .expect("handler task");
        assert!(
            rejected(INBOUND_REJECT_WRITE_TIMEOUT) > before,
            "the undrained response must be counted"
        );
    }

    #[tokio::test]
    async fn a_tls_peer_that_never_speaks_is_not_waited_on() {
        use crate::transport::tls::{build_acceptor, MeshTlsConfig};
        use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};

        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca = CertificateParams::new(Vec::new()).expect("ca params");
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca.self_signed(&ca_key).expect("ca cert");
        let peer_key = KeyPair::generate().expect("peer key");
        let mut peer = CertificateParams::new(vec!["localhost".to_string()]).expect("peer params");
        peer.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let peer_cert = peer
            .signed_by(&peer_key, &ca_cert, &ca_key)
            .expect("peer cert");
        let acceptor = build_acceptor(&MeshTlsConfig {
            cert_pem: peer_cert.pem(),
            key_pem: peer_key.serialize_pem(),
            ca_pem: ca_cert.pem(),
        })
        .expect("acceptor");

        let cache: Arc<DistributedCache<Bytes>> = Arc::new(DistributedCache::new("mtls-node", 16));
        let server =
            TransportServer::start_with_limits(0, cache, None, Some(acceptor), tight_limits())
                .await
                .expect("start");
        let port = server.local_port();
        let before = rejected(INBOUND_REJECT_HANDSHAKE_TIMEOUT);

        // Open the socket and send no ClientHello. `acceptor.accept` has no
        // deadline of its own, so this used to hold a task indefinitely.
        let mut silent = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), silent.read(&mut buf))
            .await
            .expect("a silent TLS peer must be dropped, not awaited forever");
        assert_eq!(read.expect("read"), 0, "expected the server to close");
        assert!(
            rejected(INBOUND_REJECT_HANDSHAKE_TIMEOUT) > before,
            "the abandoned handshake must be counted"
        );

        server.shutdown();
    }

    #[test]
    fn the_shipped_inbound_bounds_are_the_documented_ones() {
        // A default that drifts is a bound nobody reviewed. These are the
        // numbers the changelog and docs/key-management.md publish.
        let limits = TransportLimits::default();
        assert_eq!(limits.max_connections, 1_024);
        assert_eq!(limits.max_handshakes, 64);
        assert_eq!(limits.handshake, Duration::from_secs(10));
        assert_eq!(limits.idle, Duration::from_secs(300));
        assert_eq!(limits.frame, Duration::from_secs(30));
        assert_eq!(limits.write, Duration::from_secs(30));
    }

    #[test]
    fn the_client_recycles_well_inside_the_inbound_idle_window() {
        // The two halves are tuned against each other across two modules, and
        // each module's own default test would stay green while the pairing
        // broke. What the pairing buys: because the client re-checks its
        // recycle mark on its next request, and that mark is shorter than
        // this window, a request arriving after the peer reclaimed the
        // connection is guaranteed to dial fresh instead of writing into a
        // socket the peer already closed. Raise the client's mark past this
        // window, or drop this window below it, and every quiet period costs
        // a failed RPC instead of a handshake.
        let client = crate::transport::client::PeerTimeouts::default();
        let inbound = TransportLimits::default();
        assert!(
            client.idle_reuse_max < inbound.idle,
            "the client recycle ({:?}) must fire before the inbound idle reclaim ({:?})",
            client.idle_reuse_max,
            inbound.idle
        );
        // Not merely shorter: shorter with room for a slow round trip and a
        // reconnect, so the ordering does not depend on scheduling luck.
        assert!(
            client.idle_reuse_max * 2 < inbound.idle,
            "the recycle needs real margin under the reclaim, not a hair"
        );
    }
}

//! Two optional destinations for the request-event stream: a NATS subject
//! tree, and a ClickHouse table.
//!
//! # Why these are optional, and what "optional" means here
//!
//! [`crate::request_sink`] says, in its own module docs, that it does no
//! network egress because a broker needs retry, backpressure, and auth
//! decisions it deliberately does not make. This module makes them, for two
//! destinations, and keeps the promise that the embedded path stays the
//! default: `request_events.sink` is `none` unless an operator says
//! otherwise, and neither of these runs, dials, or allocates a queue until
//! one is configured.
//!
//! That is the OpenTelemetry Collector's distribution model, and it is
//! worth naming because it is the design being copied. The Collector ships
//! a small core and a much larger contrib build, and configuring an
//! exporter does not enable it: it runs only when a pipeline names it. What
//! this module does differently is refuse to pay for the split at build
//! time. Both destinations are always compiled, so `cargo check` sees them
//! and a release cannot ship a binary whose config schema advertises a sink
//! it cannot construct.
//!
//! # No client libraries
//!
//! Neither destination adds a dependency.
//!
//! NATS's core protocol is a handful of text commands over TCP, stable
//! since NATS 1.x and specified in the protocol documentation. Publishing
//! is `PUB <subject> <len>\r\n<payload>\r\n`, and a `PING` that comes back
//! `PONG` is the documented flush idiom: the server processes commands in
//! order, so a `PONG` after N publishes says the server took all N. That is
//! about two hundred lines here, against a client library whose reconnect
//! policy, JetStream surface, and TLS stack this crate would then own the
//! behavior of without controlling it.
//!
//! ClickHouse's HTTP interface takes `INSERT INTO t FORMAT JSONEachRow`
//! with the rows as the body, which is one POST through
//! [`sbproxy_security::governed_egress`], the same bounded, re-authorizing
//! loop every other credential-carrying outbound path in this workspace
//! uses. A native-protocol client would bypass that loop.
//!
//! # Backpressure is a drop, and the drop is counted
//!
//! Publishing is one `try_send` on a bounded queue. A full queue discards
//! the event and ticks
//! `sbproxy_event_ingest_events_total{target,outcome="dropped"}`. Nothing
//! on the request path waits for a broker.
//!
//! # The watermark
//!
//! After every batch the sink accepts, it records the last event's id and
//! timestamp in the shared embedded store. That is what replaces the
//! Postgres `reconciliation_state` table the enterprise ingest crate used:
//! an operator reconciling their warehouse against the proxy needs a
//! checkpoint that survives a restart, and a checkpoint is one row, which
//! is not a reason to run a database.

use std::io::Write as _;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use sbproxy_platform::storage::{KvNamespace, PersistentKv};

use crate::request_event::RequestEvent;
use crate::request_sink::RequestEventSink;

/// Bound on the hand-off queue between the request path and the worker.
pub const DEFAULT_QUEUE_CAPACITY: usize = 8_192;

/// How many queued events the worker folds into one publish batch.
const DRAIN_BATCH: usize = 256;

/// Per-attempt network timeout, for the connect, the flush, and the POST.
const NETWORK_TIMEOUT: Duration = Duration::from_secs(5);

/// Ceiling on the bytes read from a ClickHouse reply. Only the status
/// decides whether the batch landed; the cap exists because something has
/// to bound the read.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// The attribution every egress refusal from this subsystem carries.
const INGEST_EGRESS_ORIGIN: &str = "event_ingest";

/// Namespace holding the delivery watermark.
const WATERMARK_NAMESPACE: &str = "event_ingest_watermark";
/// The single key inside it.
const WATERMARK_KEY: &str = "current";

/// Longest subject component this module will build, in bytes.
///
/// A workspace id reaches the subject, and a workspace id is
/// operator-controlled but not necessarily short. NATS has no hard subject
/// limit worth relying on, so this one is stated here.
const MAX_SUBJECT_TOKEN_BYTES: usize = 128;

/// Where the request-event stream goes.
#[derive(Clone)]
pub enum IngestTarget {
    /// Publish one JSON message per event to a NATS subject tree.
    Nats {
        /// `host:port` of the broker. No scheme: the core protocol is
        /// plain TCP, and a `nats://` string would suggest a URL parser
        /// that is not here.
        address: String,
        /// Prefix every subject starts with, for example `sb.events`.
        subject_prefix: String,
        /// Resolved authentication token, or `None` for an unauthenticated
        /// broker. Comes from the secret-reference machinery; a literal
        /// never reaches here from a config field.
        token: Option<String>,
    },
    /// Insert batches into a ClickHouse table over its HTTP interface.
    ClickHouse {
        /// HTTP endpoint, for example `http://clickhouse.internal:8123`.
        url: String,
        /// Database name.
        database: String,
        /// Table name.
        table: String,
        /// Optional user.
        user: Option<String>,
        /// Resolved password, from the secret-reference machinery.
        password: Option<String>,
    },
}

impl std::fmt::Debug for IngestTarget {
    /// Hand written. A derive would print the token and the password, and
    /// this type is reachable from a line that describes boot.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nats {
                address,
                subject_prefix,
                token,
            } => formatter
                .debug_struct("IngestTarget::Nats")
                .field("address", address)
                .field("subject_prefix", subject_prefix)
                .field("authenticated", &token.is_some())
                .finish(),
            Self::ClickHouse {
                url,
                database,
                table,
                user,
                password,
            } => formatter
                .debug_struct("IngestTarget::ClickHouse")
                .field("url", url)
                .field("database", database)
                .field("table", table)
                .field("user", user)
                .field("authenticated", &password.is_some())
                .finish(),
        }
    }
}

impl IngestTarget {
    /// Stable, low-cardinality label this target is counted under.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Nats { .. } => "nats",
            Self::ClickHouse { .. } => "clickhouse",
        }
    }

    /// Refuse a target that cannot work before a worker is started for it.
    pub fn validate(&self) -> anyhow::Result<()> {
        match self {
            Self::Nats {
                address,
                subject_prefix,
                ..
            } => {
                if address.contains("://") {
                    anyhow::bail!(
                        "event ingest nats address is host:port, not a URL; got {address:?}"
                    );
                }
                if !address.contains(':') {
                    anyhow::bail!("event ingest nats address needs a port; got {address:?}");
                }
                if subject_prefix.is_empty() {
                    anyhow::bail!("event ingest nats subject_prefix must not be empty");
                }
                for token in subject_prefix.split('.') {
                    if token.is_empty() || token != sanitize_subject_token(token) {
                        anyhow::bail!(
                            "event ingest nats subject_prefix must be dot-separated \
                             [A-Za-z0-9_-] tokens; got {subject_prefix:?}"
                        );
                    }
                }
                Ok(())
            }
            Self::ClickHouse {
                url,
                database,
                table,
                ..
            } => {
                if !url.starts_with("http://") && !url.starts_with("https://") {
                    anyhow::bail!("event ingest clickhouse url must be http:// or https://");
                }
                for (field, value) in [("database", database), ("table", table)] {
                    if value.is_empty() || !value.bytes().all(is_sql_ident_byte) {
                        anyhow::bail!(
                            "event ingest clickhouse {field} must match [A-Za-z0-9_]+; got {value:?}"
                        );
                    }
                }
                Ok(())
            }
        }
    }
}

fn is_sql_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Collapse anything that is not a legal NATS subject token to `_`, and cap
/// the length.
///
/// This is the one place a caller-influenced value reaches the subject
/// tree. A workspace id containing a `.` would otherwise create a subject
/// one level deeper than intended, and one containing `*` or `>` would name
/// a wildcard: a subscriber filtering on `sb.events.acme.>` would then
/// receive another workspace's traffic, or miss its own.
fn sanitize_subject_token(token: &str) -> String {
    let mut out = String::with_capacity(token.len().min(MAX_SUBJECT_TOKEN_BYTES));
    for character in token.chars() {
        if out.len() >= MAX_SUBJECT_TOKEN_BYTES {
            break;
        }
        if character.is_ascii_alphanumeric() || character == '_' || character == '-' {
            out.push(character);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "unknown".to_string()
    } else {
        out
    }
}

/// The last event this sink is known to have delivered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Watermark {
    /// Which destination the checkpoint is for, so a deployment that
    /// switches targets does not read the old one's position as its own.
    pub target: String,
    /// The last delivered event's request id.
    pub last_request_id: String,
    /// The last delivered event's timestamp, in Unix epoch milliseconds.
    pub last_timestamp_ms: u64,
    /// How many events this store has seen delivered, across restarts.
    pub delivered_total: u64,
}

/// A running ingest sink: a bounded queue, a worker draining it, and an
/// optional durable watermark.
pub struct EventIngest {
    tx: Option<SyncSender<RequestEvent>>,
    handle: Option<std::thread::JoinHandle<()>>,
    target_label: &'static str,
}

impl std::fmt::Debug for EventIngest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EventIngest")
            .field("target", &self.target_label)
            .field("running", &self.handle.is_some())
            .finish()
    }
}

impl EventIngest {
    /// Start a sink for `target`.
    ///
    /// Fails only on what the caller can report at boot: a malformed
    /// target, a runtime or a thread that will not start. Everything after
    /// that is a counted drop, because by then the caller is a request that
    /// has nothing useful to do with an error.
    ///
    /// The dial is not part of startup. A broker that is down when the
    /// proxy boots must not stop the proxy from booting, so the first
    /// connection happens on the first batch and a failure there is a
    /// counted, logged reconnect rather than a refused startup.
    pub fn start(
        target: IngestTarget,
        queue_capacity: usize,
        watermark_store: Option<Arc<dyn PersistentKv>>,
    ) -> anyhow::Result<Self> {
        target.validate()?;
        let target_label = target.label();
        let watermark = match watermark_store {
            Some(store) => Some(WatermarkStore::new(store, target_label)?),
            None => None,
        };
        let (tx, rx) = sync_channel(queue_capacity.max(1));
        let handle = std::thread::Builder::new()
            .name(format!("sbproxy-ingest-{target_label}"))
            .spawn(move || run_worker(rx, target, watermark))?;
        Ok(Self {
            tx: Some(tx),
            handle: Some(handle),
            target_label,
        })
    }
}

impl RequestEventSink for EventIngest {
    fn publish(&self, event: RequestEvent) {
        let Some(tx) = self.tx.as_ref() else {
            metrics::record_ingest(self.target_label, "worker_stopped");
            return;
        };
        match tx.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => metrics::record_ingest(self.target_label, "dropped"),
            Err(TrySendError::Disconnected(_)) => {
                metrics::record_ingest(self.target_label, "worker_stopped")
            }
        }
    }
}

impl Drop for EventIngest {
    /// Dropping drains: closing the sender ends the worker's receive loop
    /// and joining waits for the batch in flight. A process exit does not
    /// do this, because the installed sink lives in a process-global that is
    /// never dropped.
    fn drop(&mut self) {
        self.tx = None;
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// The durable delivery checkpoint.
struct WatermarkStore {
    store: Arc<dyn PersistentKv>,
    namespace: KvNamespace,
    target: &'static str,
    delivered_total: u64,
}

impl WatermarkStore {
    fn new(store: Arc<dyn PersistentKv>, target: &'static str) -> anyhow::Result<Self> {
        Ok(Self {
            store,
            namespace: KvNamespace::new(WATERMARK_NAMESPACE)?,
            target,
            delivered_total: 0,
        })
    }

    /// Read the stored checkpoint, ignoring one written for a different
    /// target: a deployment that switched from NATS to ClickHouse has not
    /// delivered anything to ClickHouse yet, and reading the old position
    /// as its own would tell an operator it had.
    async fn load(&mut self) -> Option<Watermark> {
        let entry = self
            .store
            .get(&self.namespace, WATERMARK_KEY)
            .await
            .ok()??;
        let watermark: Watermark = serde_json::from_slice(&entry.value).ok()?;
        if watermark.target != self.target {
            return None;
        }
        self.delivered_total = watermark.delivered_total;
        Some(watermark)
    }

    async fn advance(&mut self, last: &RequestEvent, count: u64) {
        self.delivered_total = self.delivered_total.saturating_add(count);
        let watermark = Watermark {
            target: self.target.to_string(),
            last_request_id: last.request_id.to_string(),
            last_timestamp_ms: last.timestamp_ms,
            delivered_total: self.delivered_total,
        };
        let Ok(bytes) = serde_json::to_vec(&watermark) else {
            return;
        };
        if let Err(error) = self.store.put(&self.namespace, WATERMARK_KEY, &bytes).await {
            // warn rather than error: the batch landed, and what failed is
            // the bookkeeping about it. An operator reconciling later gets
            // a stale checkpoint, not a lost event.
            tracing::warn!(
                target: "event_ingest",
                error = %error,
                "event ingest could not record its delivery watermark"
            );
        }
    }
}

/// Read `count` events off the queue, blocking for the first.
fn drain_batch(rx: &Receiver<RequestEvent>) -> Vec<RequestEvent> {
    let mut batch = Vec::new();
    match rx.recv() {
        Ok(event) => batch.push(event),
        Err(_) => return batch,
    }
    while batch.len() < DRAIN_BATCH {
        match rx.try_recv() {
            Ok(event) => batch.push(event),
            Err(_) => break,
        }
    }
    batch
}

fn run_worker(
    rx: Receiver<RequestEvent>,
    target: IngestTarget,
    mut watermark: Option<WatermarkStore>,
) {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        tracing::error!(
            target: "event_ingest",
            "event ingest runtime would not build; no event will be delivered"
        );
        return;
    };
    if let Some(store) = watermark.as_mut() {
        if let Some(loaded) = runtime.block_on(store.load()) {
            tracing::info!(
                target: "event_ingest",
                ingest_target = store.target,
                delivered_total = loaded.delivered_total,
                last_timestamp_ms = loaded.last_timestamp_ms,
                "event ingest resumed from its stored watermark"
            );
        }
    }

    let label = target.label();
    let mut nats: Option<NatsConnection> = None;
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(NETWORK_TIMEOUT)
        .build()
        .ok();

    loop {
        let batch = drain_batch(&rx);
        if batch.is_empty() {
            break;
        }
        let count = batch.len() as u64;
        let delivered = match &target {
            IngestTarget::Nats {
                address,
                subject_prefix,
                token,
            } => runtime.block_on(publish_to_nats(
                &mut nats,
                address,
                subject_prefix,
                token.as_deref(),
                &batch,
            )),
            IngestTarget::ClickHouse {
                url,
                database,
                table,
                user,
                password,
            } => match http.as_ref() {
                Some(client) => runtime.block_on(insert_into_clickhouse(
                    client,
                    url,
                    database,
                    table,
                    user.as_deref(),
                    password.as_deref(),
                    &batch,
                )),
                None => false,
            },
        };
        if delivered {
            metrics::record_ingest_by(label, "published", count);
            if let (Some(store), Some(last)) = (watermark.as_mut(), batch.last()) {
                runtime.block_on(store.advance(last, count));
            }
        } else {
            metrics::record_ingest_by(label, "error", count);
        }
    }
}

// --- NATS ---

/// One live NATS connection, in the core text protocol.
struct NatsConnection {
    stream: tokio::net::TcpStream,
    buffer: Vec<u8>,
}

impl NatsConnection {
    /// Dial, read the server's `INFO`, send `CONNECT`, and confirm with a
    /// `PING`/`PONG` round trip.
    ///
    /// The round trip is what makes a bad token a connect failure rather
    /// than a silent hole: NATS answers a rejected `CONNECT` with `-ERR`
    /// instead of `PONG`, and without the ping the first publish would be
    /// written into a socket the server is about to close.
    async fn connect(address: &str, token: Option<&str>) -> anyhow::Result<Self> {
        use tokio::io::AsyncWriteExt;

        let stream = tokio::time::timeout(NETWORK_TIMEOUT, tokio::net::TcpStream::connect(address))
            .await
            .map_err(|_| anyhow::anyhow!("nats connect timed out"))??;
        let mut connection = Self {
            stream,
            buffer: Vec::with_capacity(1024),
        };

        let info = connection.read_line().await?;
        if !info.starts_with("INFO") {
            anyhow::bail!("nats server did not greet with INFO");
        }

        // `verbose: false` turns off the per-command `+OK`, which would
        // otherwise put one line on the socket per published message for
        // nobody to read. The ping below is the acknowledgement instead.
        let connect = serde_json::json!({
            "verbose": false,
            "pedantic": false,
            "tls_required": false,
            "name": "sbproxy",
            "lang": "rust",
            "version": env!("CARGO_PKG_VERSION"),
            "protocol": 1,
            "auth_token": token,
        });
        let mut line = serde_json::to_vec(&connect)?;
        let mut command = b"CONNECT ".to_vec();
        command.append(&mut line);
        command.extend_from_slice(b"\r\nPING\r\n");
        connection.stream.write_all(&command).await?;
        connection.stream.flush().await?;
        connection.expect_pong().await?;
        Ok(connection)
    }

    async fn read_line(&mut self) -> anyhow::Result<String> {
        use tokio::io::AsyncReadExt;

        loop {
            if let Some(index) = self.buffer.windows(2).position(|window| window == b"\r\n") {
                let line = String::from_utf8_lossy(&self.buffer[..index]).to_string();
                self.buffer.drain(..index + 2);
                return Ok(line);
            }
            if self.buffer.len() > 64 * 1024 {
                anyhow::bail!("nats server sent an oversized line");
            }
            let mut chunk = [0u8; 4096];
            let read = tokio::time::timeout(NETWORK_TIMEOUT, self.stream.read(&mut chunk))
                .await
                .map_err(|_| anyhow::anyhow!("nats read timed out"))??;
            if read == 0 {
                anyhow::bail!("nats connection closed");
            }
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }

    /// Read until the server answers `PONG`, replying to any `PING` of its
    /// own along the way and failing loudly on `-ERR`.
    async fn expect_pong(&mut self) -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt;

        for _ in 0..64 {
            let line = self.read_line().await?;
            let head = line.split_whitespace().next().unwrap_or("");
            match head {
                "PONG" => return Ok(()),
                "PING" => {
                    self.stream.write_all(b"PONG\r\n").await?;
                    self.stream.flush().await?;
                }
                "-ERR" => anyhow::bail!("nats server refused the connection"),
                // `INFO`, `+OK`, and anything else are informational here.
                _ => {}
            }
        }
        anyhow::bail!("nats server did not answer a ping")
    }

    /// Publish a batch and flush it with one ping.
    ///
    /// NATS processes commands in order, so a `PONG` after N publishes says
    /// the server took all N. That is the documented flush idiom and it is
    /// what makes a batch either delivered or counted as an error, rather
    /// than written into a socket and forgotten.
    async fn publish_batch(&mut self, messages: &[(String, Vec<u8>)]) -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt;

        let mut out = Vec::with_capacity(messages.len() * 512);
        for (subject, payload) in messages {
            write!(out, "PUB {subject} {}\r\n", payload.len())?;
            out.extend_from_slice(payload);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"PING\r\n");
        tokio::time::timeout(NETWORK_TIMEOUT, self.stream.write_all(&out))
            .await
            .map_err(|_| anyhow::anyhow!("nats write timed out"))??;
        self.stream.flush().await?;
        self.expect_pong().await
    }
}

/// Build the subject one event publishes to.
fn nats_subject(prefix: &str, event: &RequestEvent) -> String {
    format!(
        "{prefix}.{}.{}",
        sanitize_subject_token(&event.workspace_id),
        sanitize_subject_token(event.event_type.as_str())
    )
}

async fn publish_to_nats(
    connection: &mut Option<NatsConnection>,
    address: &str,
    subject_prefix: &str,
    token: Option<&str>,
    batch: &[RequestEvent],
) -> bool {
    let mut messages = Vec::with_capacity(batch.len());
    for event in batch {
        match serde_json::to_vec(event) {
            Ok(payload) => messages.push((nats_subject(subject_prefix, event), payload)),
            Err(error) => {
                tracing::error!(
                    target: "event_ingest",
                    error = %error,
                    "request event would not serialize for nats"
                );
                return false;
            }
        }
    }

    // Two passes: use the live connection, and on failure drop it, redial
    // once, and try again. A broker restart is normal and should cost one
    // reconnect rather than a batch.
    for attempt in 0..2 {
        if connection.is_none() {
            match NatsConnection::connect(address, token).await {
                Ok(fresh) => {
                    metrics::record_ingest("nats", "reconnected");
                    *connection = Some(fresh);
                }
                Err(error) => {
                    // The address is a host:port an operator wrote, not a
                    // URL with a credential in it, so it is safe to name.
                    tracing::warn!(
                        target: "event_ingest",
                        address = %address,
                        error = %error,
                        "could not connect to the nats broker"
                    );
                    return false;
                }
            }
        }
        let Some(live) = connection.as_mut() else {
            return false;
        };
        match live.publish_batch(&messages).await {
            Ok(()) => return true,
            Err(error) => {
                *connection = None;
                if attempt == 1 {
                    tracing::warn!(
                        target: "event_ingest",
                        address = %address,
                        error = %error,
                        count = batch.len(),
                        "nats publish failed after a reconnect; the batch was dropped"
                    );
                    return false;
                }
            }
        }
    }
    false
}

// --- ClickHouse ---

/// The table this sink writes to is the operator's to create.
///
/// The DDL lives in `docs/event-ingest.md` rather than in a constant here,
/// and there is no migration path: applying schema to somebody's warehouse
/// from a proxy is a privilege nobody asked it to have, and an operator
/// running ClickHouse already has a way to run DDL. A constant nothing
/// executes would also be a second copy of the schema to keep in step with
/// the page an operator actually reads. The sink fails loudly against a
/// missing table instead.
#[allow(clippy::too_many_arguments)]
async fn insert_into_clickhouse(
    client: &reqwest::Client,
    url: &str,
    database: &str,
    table: &str,
    user: Option<&str>,
    password: Option<&str>,
    batch: &[RequestEvent],
) -> bool {
    let mut body = Vec::with_capacity(batch.len() * 512);
    for event in batch {
        match serde_json::to_vec(event) {
            Ok(mut row) => {
                body.append(&mut row);
                body.push(b'\n');
            }
            Err(error) => {
                tracing::error!(
                    target: "event_ingest",
                    error = %error,
                    "request event would not serialize for clickhouse"
                );
                return false;
            }
        }
    }

    // `database` and `table` are validated to `[A-Za-z0-9_]+` at
    // construction, so this interpolation cannot be turned into a second
    // statement by a hostile config.
    let query = format!("INSERT INTO {database}.{table} FORMAT JSONEachRow");
    let mut request = client
        .post(url)
        .query(&[("query", query.as_str())])
        .header("Content-Type", "application/x-ndjson")
        .header("User-Agent", concat!("sbproxy/", env!("CARGO_PKG_VERSION")));
    if let Some(user) = user {
        request = request.header("X-ClickHouse-User", user);
    }
    if let Some(password) = password {
        request = request.header("X-ClickHouse-Key", password);
    }
    let request = match request.body(body).build() {
        Ok(request) => request,
        Err(_) => return false,
    };

    let gate = crate::event_sink::webhook_egress_gate();
    let governed = sbproxy_security::governed_egress::GovernedEgress {
        purpose: sbproxy_security::egress::EgressPurpose::Webhook,
        authorizer: gate.as_ref(),
        resolver: &sbproxy_security::egress::CachedSystemResolver,
        origin: INGEST_EGRESS_ORIGIN,
        // One ingest sink serves the whole process, so there is no
        // per-tenant attribution to give a refusal here.
        tenant: "unset",
        // The ClickHouse credential rides two custom headers no HTTP
        // client's built-in credential stripping has heard of, and a 307
        // replays a body verbatim.
        sensitive_headers: &["x-clickhouse-key", "x-clickhouse-user"],
        max_response_bytes: MAX_RESPONSE_BYTES,
        no_redirect_client: client,
        timeout: NETWORK_TIMEOUT,
    };

    match governed.send(request).await {
        Ok(response) if (200u16..300).contains(&response.status) => true,
        Ok(response) => {
            tracing::warn!(
                target: "event_ingest",
                status = response.status,
                count = batch.len(),
                "clickhouse refused an insert; the batch was dropped"
            );
            false
        }
        Err(sbproxy_security::governed_egress::GovernedEgressError::Denied(reason)) => {
            tracing::warn!(
                target: "event_ingest",
                reason = reason.as_label(),
                count = batch.len(),
                "clickhouse destination refused by egress authorization"
            );
            false
        }
        Err(error) => {
            // A closed label off the error rather than its Display: the
            // governed client's error never holds a URL, so the endpoint
            // cannot reach this line by construction.
            tracing::warn!(
                target: "event_ingest",
                reason = error.as_label(),
                count = batch.len(),
                "clickhouse insert failed; the batch was dropped"
            );
            false
        }
    }
}

pub(crate) mod metrics {
    //! The one family the ingest sinks emit.
    //!
    //! `target` is `nats` or `clickhouse`; `outcome` is `published`,
    //! `dropped`, `error`, `reconnected`, or `worker_stopped`. Both closed
    //! sets fixed at compile time. Nothing is labeled by workspace,
    //! subject, or table: the first is unbounded and the other two are
    //! derived from it.

    use std::sync::LazyLock;

    use prometheus::{register_int_counter_vec, IntCounterVec, Opts};

    static EVENT_INGEST_EVENTS: LazyLock<Option<IntCounterVec>> = LazyLock::new(|| {
        register_int_counter_vec!(
            Opts::new(
                "sbproxy_event_ingest_events_total",
                "Request events handed to an optional ingest sink, by target and outcome"
            ),
            &["target", "outcome"]
        )
        .map_err(|error| {
            // Only a duplicate or malformed name reaches here, and both
            // are bugs in this file. An `expect` would turn one into a
            // panic inside whichever request first touched the new code
            // path, which is a larger failure than a family that does
            // not record.
            tracing::error!(family = "sbproxy_event_ingest_events_total", error = %error, "metric family would not register");
        })
        .ok()
    });

    /// Count one event.
    pub(crate) fn record_ingest(target: &'static str, outcome: &'static str) {
        if let Some(family) = EVENT_INGEST_EVENTS.as_ref() {
            family.with_label_values(&[target, outcome]).inc();
        }
    }

    /// Count a whole batch at once.
    pub(crate) fn record_ingest_by(target: &'static str, outcome: &'static str, count: u64) {
        if let Some(family) = EVENT_INGEST_EVENTS.as_ref() {
            family.with_label_values(&[target, outcome]).inc_by(count);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn every_recorder_matches_the_declared_label_arity() {
            record_ingest("nats", "reconnected");
            record_ingest_by("clickhouse", "published", 5);
            assert_eq!(
                EVENT_INGEST_EVENTS
                    .as_ref()
                    .expect("the family registers in a fresh process")
                    .with_label_values(&["clickhouse", "published"])
                    .get(),
                5
            );
        }
    }
}

#[cfg(test)]
mod tests;

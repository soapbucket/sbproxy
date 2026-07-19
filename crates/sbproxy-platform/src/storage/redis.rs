//! Redis KVStore backend using a small blocking connection pool.
//!
//! A pool of validated Redis connections (default 8) is maintained so that
//! concurrent operations do not serialize on a single connection.
//!
//! Connections are lazily opened, up to `pool_size` total, and returned to the
//! idle list on drop. Connections with transport, timeout, or protocol failures
//! are discarded so a subsequent checkout opens a fresh one.
//!
//! Supported commands: GET, SET, DEL, SCAN (with MATCH + COUNT).

use std::error::Error as StdError;
use std::fmt;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;
use prometheus::{HistogramVec, IntCounterVec};
use redis::{Connection, ErrorKind, RedisError};

use super::{
    redis_connection::{RedisTlsConfig, ValidatedRedisConnection},
    KVStore,
};

const HEALTH_UNKNOWN: u8 = 0;
const HEALTH_HEALTHY: u8 = 1;
const HEALTH_FAILED: u8 = 2;

// --- RedisKVStore ---

/// Configuration for [`RedisKVStore`].
pub struct RedisConfig {
    /// Prevalidated Redis client configuration.
    pub connection: ValidatedRedisConnection,
    /// Maximum number of connections held in the pool. Connections are opened
    /// lazily up to this bound. Default: 8.
    pub pool_size: usize,
    /// Timeout when acquiring a connection from the pool before erroring out.
    /// Default: 5 seconds.
    pub acquire_timeout: Duration,
    /// Timeout for establishing a connection, including AUTH and SELECT.
    /// Default: 5 seconds.
    pub connect_timeout: Duration,
    /// Read and write timeout for Redis commands. Default: 5 seconds.
    pub command_timeout: Duration,
}

impl RedisConfig {
    /// Build a blocking-store configuration from a validated connection.
    pub fn new(connection: ValidatedRedisConnection) -> Self {
        Self {
            connection,
            pool_size: 8,
            acquire_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(5),
            command_timeout: Duration::from_secs(5),
        }
    }

    /// Validate a Redis DSN without opening a network connection.
    pub fn from_dsn(dsn: &str) -> Result<Self> {
        ValidatedRedisConnection::new(dsn, RedisTlsConfig::default()).map(Self::new)
    }
}

impl Default for RedisConfig {
    fn default() -> Self {
        let connection = ValidatedRedisConnection::new("127.0.0.1:6379", RedisTlsConfig::default())
            .expect("default Redis connection configuration must be valid");
        Self::new(connection)
    }
}

// --- Pool internals ---

/// Shared pool state: the idle connection list and the count of connections
/// that have been handed out (and not yet returned). The invariant
/// `idle.len() + in_use <= pool_size` holds at all times.
struct PoolState {
    idle: Vec<Connection>,
    in_use: usize,
}

/// Redis-backed key-value store. Keys and values are stored as Redis byte
/// strings. Keys are hex-encoded before being sent to Redis to avoid
/// characters that are problematic with SCAN MATCH glob patterns.
pub struct RedisKVStore {
    connection: ValidatedRedisConnection,
    pool_size: usize,
    acquire_timeout: Duration,
    connect_timeout: Duration,
    command_timeout: Duration,
    // Pool state: a Mutex holding idle connections and the in-use count.
    state: Mutex<PoolState>,
    // Signaled when a connection is returned to idle or when in_use drops,
    // so a waiting checkout can make progress.
    available: Condvar,
    health: AtomicU8,
}

/// RAII guard that returns a healthy connection to the pool on drop.
struct PooledConnection<'a> {
    pool: &'a RedisKVStore,
    conn: Option<Connection>,
}

impl PooledConnection<'_> {
    fn connection(&mut self) -> &mut Connection {
        self.conn.as_mut().expect("connection already invalidated")
    }

    /// Mark the connection as broken so it is discarded on drop instead of
    /// being returned to the idle pool.
    fn invalidate(&mut self) {
        self.conn = None;
    }
}

impl Drop for PooledConnection<'_> {
    fn drop(&mut self) {
        let mut guard = self.pool.state.lock().expect("lock poisoned");
        // The connection was checked out; decrement the in-use count.
        guard.in_use = guard.in_use.saturating_sub(1);
        if let Some(conn) = self.conn.take() {
            // Healthy connection: return to idle pool.
            guard.idle.push(conn);
        }
        // Wake exactly one waiter; either an idle conn is now available or a
        // new-connection slot just opened up.
        self.pool.available.notify_one();
    }
}

impl RedisKVStore {
    /// Create a new Redis store. Connections are established lazily on
    /// demand, up to `config.pool_size` concurrent connections.
    pub fn new(config: RedisConfig) -> Self {
        let pool_size = config.pool_size.max(1);
        Self {
            connection: config.connection,
            pool_size,
            acquire_timeout: config.acquire_timeout,
            connect_timeout: config.connect_timeout,
            command_timeout: config.command_timeout,
            state: Mutex::new(PoolState {
                idle: Vec::with_capacity(pool_size),
                in_use: 0,
            }),
            available: Condvar::new(),
            health: AtomicU8::new(HEALTH_UNKNOWN),
        }
    }

    /// Borrow a connection from the pool, opening a new one if the pool has
    /// spare capacity. Blocks up to `acquire_timeout` waiting for a connection
    /// to become available; returns an error on timeout.
    fn checkout(&self, operation: RedisOperation) -> Result<PooledConnection<'_>> {
        let deadline = Instant::now() + self.acquire_timeout;
        let mut guard = self.state.lock().expect("lock poisoned");
        loop {
            // Fast path: hand back an already-open idle connection.
            if let Some(conn) = guard.idle.pop() {
                guard.in_use += 1;
                return Ok(PooledConnection {
                    pool: self,
                    conn: Some(conn),
                });
            }

            // Spare capacity: open a new connection. Reserve the slot by
            // bumping `in_use` before dropping the lock so another thread
            // cannot oversubscribe the pool. If `connect` fails, the slot is
            // released before propagating the error.
            if guard.in_use < self.pool_size {
                guard.in_use += 1;
                let client = self.connection.client();
                drop(guard);
                let connection = client
                    .get_connection_with_timeout(self.connect_timeout)
                    .and_then(|connection| {
                        connection.set_read_timeout(Some(self.command_timeout))?;
                        connection.set_write_timeout(Some(self.command_timeout))?;
                        Ok(connection)
                    });
                match connection {
                    Ok(conn) => {
                        redis_connection_results()
                            .with_label_values(&["success"])
                            .inc();
                        return Ok(PooledConnection {
                            pool: self,
                            conn: Some(conn),
                        });
                    }
                    Err(err) => {
                        redis_connection_results()
                            .with_label_values(&["error"])
                            .inc();
                        self.release_reserved_slot();
                        let reason = classify_redis_error(
                            &err,
                            ErrorPhase::Connect,
                            self.connection.uses_tls(),
                        );
                        return Err(safe_error(operation, reason));
                    }
                }
            }

            // Pool saturated: wait for a connection to be returned.
            let now = Instant::now();
            if now >= deadline {
                return Err(safe_error(operation, RedisFailureReason::PoolTimeout));
            }
            let remaining = deadline - now;
            let (g, timeout) = self
                .available
                .wait_timeout(guard, remaining)
                .expect("condvar wait failed");
            guard = g;
            if timeout.timed_out() {
                return Err(safe_error(operation, RedisFailureReason::PoolTimeout));
            }
        }
    }

    fn release_reserved_slot(&self) {
        let mut guard = self.state.lock().expect("lock poisoned");
        guard.in_use = guard.in_use.saturating_sub(1);
        self.available.notify_one();
    }

    /// Checkout a connection, run `f` against it, and invalidate the
    /// connection if `f` returns an error so a broken conn is not returned
    /// to the pool.
    fn with_conn<F, T>(&self, operation: RedisOperation, f: F) -> Result<T>
    where
        F: FnOnce(&mut Connection) -> redis::RedisResult<T>,
    {
        let mut conn = self.checkout(operation)?;
        match f(conn.connection()) {
            Ok(v) => Ok(v),
            Err(error) => {
                if should_invalidate(&error) {
                    conn.invalidate();
                }
                let reason =
                    classify_redis_error(&error, ErrorPhase::Command, self.connection.uses_tls());
                Err(safe_error(operation, reason))
            }
        }
    }

    fn execute<T>(
        &self,
        operation: RedisOperation,
        function: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let started_at = Instant::now();
        let result = function();
        redis_operation_duration()
            .with_label_values(&[operation.as_str()])
            .observe(started_at.elapsed().as_secs_f64());

        match &result {
            Ok(_) => self.record_success(operation),
            Err(error) => {
                let reason = error
                    .downcast_ref::<SafeRedisError>()
                    .map_or(RedisFailureReason::Protocol, |error| error.reason);
                redis_operation_errors()
                    .with_label_values(&[operation.as_str(), reason.as_str()])
                    .inc();
                self.record_failure(operation, reason);
            }
        }
        result
    }

    fn record_success(&self, operation: RedisOperation) {
        let previous = self.health.swap(HEALTH_HEALTHY, Ordering::AcqRel);
        if previous == HEALTH_FAILED {
            tracing::info!(
                operation = operation.as_str(),
                "redis store health recovered"
            );
        }
    }

    fn record_failure(&self, operation: RedisOperation, reason: RedisFailureReason) {
        let previous = self.health.swap(HEALTH_FAILED, Ordering::AcqRel);
        if matches!(previous, HEALTH_UNKNOWN | HEALTH_HEALTHY) {
            tracing::warn!(
                operation = operation.as_str(),
                reason = reason.as_str(),
                "redis store health failed"
            );
        } else {
            tracing::debug!(
                operation = operation.as_str(),
                reason = reason.as_str(),
                "redis store health remains failed"
            );
        }
    }

    /// Hex-encode the raw key for safe use in Redis key names and SCAN patterns.
    fn encode_key(key: &[u8]) -> String {
        hex::encode(key)
    }
}

impl KVStore for RedisKVStore {
    fn get(&self, key: &[u8]) -> Result<Option<Bytes>> {
        self.execute(RedisOperation::Get, || {
            let encoded = Self::encode_key(key);
            self.with_conn(RedisOperation::Get, |connection| {
                let value: Option<Vec<u8>> = redis::cmd("GET").arg(&encoded).query(connection)?;
                Ok(value.map(Bytes::from))
            })
        })
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        self.execute(RedisOperation::Set, || {
            let encoded = Self::encode_key(key);
            self.with_conn(RedisOperation::Set, |connection| {
                redis::cmd("SET")
                    .arg(&encoded)
                    .arg(value)
                    .query::<()>(connection)?;
                Ok(())
            })
        })
    }

    fn delete(&self, key: &[u8]) -> Result<()> {
        self.execute(RedisOperation::Delete, || {
            let encoded = Self::encode_key(key);
            self.with_conn(RedisOperation::Delete, |connection| {
                redis::cmd("DEL").arg(&encoded).query::<u64>(connection)?;
                Ok(())
            })
        })
    }

    fn put_with_ttl(&self, key: &[u8], value: &[u8], ttl_secs: u64) -> Result<()> {
        self.execute(RedisOperation::SetTtl, || {
            // SET <key> <value> EX <ttl>
            let encoded = Self::encode_key(key);
            self.with_conn(RedisOperation::SetTtl, |connection| {
                redis::cmd("SET")
                    .arg(&encoded)
                    .arg(value)
                    .arg("EX")
                    .arg(ttl_secs)
                    .query::<()>(connection)?;
                Ok(())
            })
        })
    }

    fn incr_with_ttl(&self, key: &[u8], ttl_secs: u64) -> Result<i64> {
        self.execute(RedisOperation::Increment, || {
            // Use MULTI / INCR / EXPIRE / EXEC so both commands land atomically.
            // The EXEC reply is an array whose first element is the INCR result
            // (new counter value) and second is the EXPIRE reply (1 when applied).
            let encoded = Self::encode_key(key);
            self.with_conn(RedisOperation::Increment, |connection| {
                let (counter, _expiry_applied): (i64, bool) = redis::pipe()
                    .atomic()
                    .cmd("INCR")
                    .arg(&encoded)
                    .cmd("EXPIRE")
                    .arg(&encoded)
                    .arg(ttl_secs)
                    .query(connection)?;
                Ok(counter)
            })
        })
    }

    fn try_lock(&self, key: &[u8], token: &[u8], ttl_secs: u64) -> Result<bool> {
        self.execute(RedisOperation::Lock, || {
            // Atomic lease: SET <key> <token> NX PX <ttl_ms>. The reply is "OK"
            // when the key was set (lock acquired) or nil when it already
            // exists (another holder has it). WOR-1774.
            let encoded = Self::encode_key(key);
            let ttl_ms = ttl_secs.saturating_mul(1000);
            self.with_conn(RedisOperation::Lock, |connection| {
                let response: Option<String> = redis::cmd("SET")
                    .arg(&encoded)
                    .arg(token)
                    .arg("NX")
                    .arg("PX")
                    .arg(ttl_ms)
                    .query(connection)?;
                match response.as_deref() {
                    Some("OK") => Ok(true),
                    None => Ok(false),
                    Some(_) => Err((ErrorKind::TypeError, "unexpected SET NX response").into()),
                }
            })
        })
    }

    fn unlock(&self, key: &[u8], token: &[u8]) -> Result<()> {
        self.execute(RedisOperation::Unlock, || {
            // Compare-and-delete via EVAL so we only delete the lock while it is
            // still ours: a bare DEL could remove a lock a different node
            // acquired after this one's lease had expired.
            const RELEASE: &[u8] = b"if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end";
            let encoded = Self::encode_key(key);
            self.with_conn(RedisOperation::Unlock, |connection| {
                redis::cmd("EVAL")
                    .arg(RELEASE)
                    .arg(1)
                    .arg(&encoded)
                    .arg(token)
                    .query::<i64>(connection)?;
                Ok(())
            })
        })
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Bytes, Bytes)>> {
        self.execute(RedisOperation::Scan, || {
            // Build a SCAN MATCH glob: hex(prefix)* (safe because hex output
            // contains only [0-9a-f] which has no glob special characters).
            let pattern = format!("{}*", Self::encode_key(prefix));

            let mut results = Vec::new();
            let mut cursor = 0_u64;

            loop {
                let (next_cursor, keys): (u64, Vec<Vec<u8>>) =
                    self.with_conn(RedisOperation::Scan, |connection| {
                        redis::cmd("SCAN")
                            .arg(cursor)
                            .arg("MATCH")
                            .arg(&pattern)
                            .arg("COUNT")
                            .arg(100)
                            .query(connection)
                    })?;

                for encoded_key in keys {
                    let raw_key = hex::decode(&encoded_key).map_err(|_| {
                        safe_error(RedisOperation::Scan, RedisFailureReason::Protocol)
                    })?;

                    // Fetch one value for each key returned by SCAN.
                    let value = self.with_conn(RedisOperation::Scan, |connection| {
                        let value: Option<Vec<u8>> =
                            redis::cmd("GET").arg(&encoded_key).query(connection)?;
                        Ok(value.map(Bytes::from))
                    })?;

                    if let Some(value) = value {
                        results.push((Bytes::from(raw_key), value));
                    }
                }

                if next_cursor == 0 {
                    break;
                }
                cursor = next_cursor;
            }

            Ok(results)
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RedisOperation {
    Get,
    Set,
    SetTtl,
    Delete,
    Increment,
    Lock,
    Unlock,
    Scan,
}

impl RedisOperation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Set => "set",
            Self::SetTtl => "set_ttl",
            Self::Delete => "delete",
            Self::Increment => "increment",
            Self::Lock => "lock",
            Self::Unlock => "unlock",
            Self::Scan => "scan",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RedisFailureReason {
    PoolTimeout,
    ConnectTimeout,
    CommandTimeout,
    Tls,
    Auth,
    Transport,
    Server,
    Protocol,
}

impl RedisFailureReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PoolTimeout => "pool_timeout",
            Self::ConnectTimeout => "connect_timeout",
            Self::CommandTimeout => "command_timeout",
            Self::Tls => "tls",
            Self::Auth => "auth",
            Self::Transport => "transport",
            Self::Server => "server",
            Self::Protocol => "protocol",
        }
    }
}

fn redis_connection_results() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        prometheus::register_int_counter_vec!(
            "sbproxy_redis_kv_connections_total",
            "Redis KV connection attempts by result.",
            &["result"]
        )
        .expect("Redis connection metric must register")
    })
}

fn redis_operation_duration() -> &'static HistogramVec {
    static HISTOGRAM: OnceLock<HistogramVec> = OnceLock::new();
    HISTOGRAM.get_or_init(|| {
        prometheus::register_histogram_vec!(
            "sbproxy_redis_kv_operation_duration_seconds",
            "Redis KV operation duration in seconds.",
            &["operation"]
        )
        .expect("Redis operation duration metric must register")
    })
}

fn redis_operation_errors() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        prometheus::register_int_counter_vec!(
            "sbproxy_redis_kv_operation_errors_total",
            "Redis KV operation failures by operation and reason.",
            &["operation", "reason"]
        )
        .expect("Redis operation error metric must register")
    })
}

#[derive(Debug)]
struct SafeRedisError {
    operation: RedisOperation,
    reason: RedisFailureReason,
}

impl fmt::Display for SafeRedisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "redis {} failed: {}",
            self.operation.as_str(),
            self.reason.as_str()
        )
    }
}

impl StdError for SafeRedisError {}

fn safe_error(operation: RedisOperation, reason: RedisFailureReason) -> anyhow::Error {
    anyhow::Error::new(SafeRedisError { operation, reason })
}

#[derive(Clone, Copy)]
enum ErrorPhase {
    Connect,
    Command,
}

fn classify_redis_error(
    error: &RedisError,
    phase: ErrorPhase,
    uses_tls: bool,
) -> RedisFailureReason {
    if error.is_timeout() {
        return match phase {
            ErrorPhase::Connect => RedisFailureReason::ConnectTimeout,
            ErrorPhase::Command => RedisFailureReason::CommandTimeout,
        };
    }

    match error.kind() {
        ErrorKind::AuthenticationFailed => RedisFailureReason::Auth,
        ErrorKind::IoError => {
            if uses_tls && has_tls_error_source(error) {
                RedisFailureReason::Tls
            } else {
                RedisFailureReason::Transport
            }
        }
        ErrorKind::InvalidClientConfig if uses_tls && matches!(phase, ErrorPhase::Connect) => {
            RedisFailureReason::Tls
        }
        ErrorKind::InvalidClientConfig
        | ErrorKind::ParseError
        | ErrorKind::TypeError
        | ErrorKind::ClientError
        | ErrorKind::RESP3NotSupported => RedisFailureReason::Protocol,
        _ => RedisFailureReason::Server,
    }
}

fn has_tls_error_source(error: &RedisError) -> bool {
    let mut source = StdError::source(error);
    while let Some(cause) = source {
        if cause.is::<rustls::Error>() {
            return true;
        }
        if cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_error| io_error.kind() == std::io::ErrorKind::InvalidData)
        {
            return true;
        }
        source = cause.source();
    }
    false
}

fn should_invalidate(error: &RedisError) -> bool {
    error.is_timeout()
        || error.is_io_error()
        || error.is_connection_dropped()
        || error.is_unrecoverable_error()
        || matches!(
            error.kind(),
            ErrorKind::InvalidClientConfig
                | ErrorKind::ParseError
                | ErrorKind::TypeError
                | ErrorKind::ClientError
                | ErrorKind::RESP3NotSupported
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::{self, BufRead, BufReader, Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, MutexGuard};
    use std::thread::{self, JoinHandle};

    use crate::storage::{RedisTlsConfig, ValidatedRedisConnection};
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Level, Metadata, Subscriber};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    const RELEASE_LOCK_SCRIPT: &[u8] = b"if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end";

    #[derive(Debug)]
    enum ScriptedReply {
        Resp(Vec<u8>),
        Close,
    }

    #[derive(Default)]
    struct ScriptedState {
        accepts: usize,
        commands: Vec<Vec<Vec<u8>>>,
        replies: VecDeque<ScriptedReply>,
        problems: Vec<String>,
    }

    struct ScriptedRedis {
        address: String,
        state: Arc<Mutex<ScriptedState>>,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl ScriptedRedis {
        fn start(replies: Vec<ScriptedReply>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap().to_string();
            let state = Arc::new(Mutex::new(ScriptedState {
                replies: replies.into(),
                ..ScriptedState::default()
            }));
            let stop = Arc::new(AtomicBool::new(false));
            let thread_state = Arc::clone(&state);
            let thread_stop = Arc::clone(&stop);
            let thread = thread::spawn(move || {
                while !thread_stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            thread_state.lock().unwrap().accepts += 1;
                            serve_connection(stream, &thread_state, &thread_stop);
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) => {
                            thread_state
                                .lock()
                                .unwrap()
                                .problems
                                .push(format!("accept failed: {error}"));
                            break;
                        }
                    }
                }
            });

            Self {
                address,
                state,
                stop,
                thread: Some(thread),
            }
        }

        fn address(&self) -> &str {
            &self.address
        }

        fn accepts(&self) -> usize {
            self.state.lock().unwrap().accepts
        }

        fn commands(&self) -> Vec<Vec<Vec<u8>>> {
            self.state.lock().unwrap().commands.clone()
        }

        fn enqueue(&self, replies: Vec<ScriptedReply>) {
            self.state.lock().unwrap().replies.extend(replies);
        }

        fn application_commands(&self) -> Vec<Vec<Vec<u8>>> {
            self.commands()
                .into_iter()
                .filter(|command| {
                    !matches!(
                        command.first().map(Vec::as_slice),
                        Some(b"AUTH" | b"SELECT" | b"CLIENT" | b"HELLO")
                    )
                })
                .collect()
        }

        fn assert_finished(&self) {
            let state = self.state.lock().unwrap();
            assert!(
                state.replies.is_empty(),
                "unused replies: {:?}",
                state.replies
            );
            assert!(
                state.problems.is_empty(),
                "server problems: {:?}",
                state.problems
            );
        }
    }

    impl Drop for ScriptedRedis {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            let _ = TcpStream::connect(&self.address);
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    fn serve_connection(stream: TcpStream, state: &Arc<Mutex<ScriptedState>>, stop: &AtomicBool) {
        stream
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let mut reader = BufReader::new(stream);
        loop {
            match read_command(&mut reader) {
                Ok(Some(command)) => {
                    let is_setup = matches!(
                        command.first().map(Vec::as_slice),
                        Some(b"AUTH" | b"SELECT" | b"CLIENT" | b"HELLO")
                    );
                    let reply = {
                        let mut state = state.lock().unwrap();
                        state.commands.push(command);
                        if is_setup {
                            ScriptedReply::Resp(b"+OK\r\n".to_vec())
                        } else {
                            match state.replies.pop_front() {
                                Some(reply) => reply,
                                None => {
                                    state.problems.push("missing scripted reply".to_string());
                                    ScriptedReply::Resp(b"-ERR unscripted command\r\n".to_vec())
                                }
                            }
                        }
                    };
                    match reply {
                        ScriptedReply::Resp(bytes) => {
                            if let Err(error) = reader.get_mut().write_all(&bytes) {
                                state
                                    .lock()
                                    .unwrap()
                                    .problems
                                    .push(format!("reply failed: {error}"));
                                return;
                            }
                        }
                        ScriptedReply::Close => {
                            let _ = reader.get_mut().shutdown(Shutdown::Both);
                            return;
                        }
                    }
                }
                Ok(None) => return,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    if stop.load(Ordering::Acquire) {
                        return;
                    }
                }
                Err(error) => {
                    state
                        .lock()
                        .unwrap()
                        .problems
                        .push(format!("command read failed: {error}"));
                    return;
                }
            }
        }
    }

    fn read_command(reader: &mut BufReader<TcpStream>) -> io::Result<Option<Vec<Vec<u8>>>> {
        let mut marker = [0_u8; 1];
        match reader.read_exact(&mut marker) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(error),
        }
        if marker != [b'*'] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected RESP array",
            ));
        }
        let count = read_resp_len(reader)?;
        let mut command = Vec::with_capacity(count);
        for _ in 0..count {
            reader.read_exact(&mut marker)?;
            if marker != [b'$'] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected RESP bulk string",
                ));
            }
            let length = read_resp_len(reader)?;
            let mut argument = vec![0_u8; length];
            reader.read_exact(&mut argument)?;
            let mut ending = [0_u8; 2];
            reader.read_exact(&mut ending)?;
            if ending != *b"\r\n" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid RESP bulk ending",
                ));
            }
            command.push(argument);
        }
        Ok(Some(command))
    }

    fn read_resp_len(reader: &mut BufReader<TcpStream>) -> io::Result<usize> {
        let mut line = Vec::new();
        reader.read_until(b'\n', &mut line)?;
        let digits = line
            .strip_suffix(b"\r\n")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid RESP line"))?;
        std::str::from_utf8(digits)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF8 RESP length"))?
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid RESP length"))
    }

    fn reply(bytes: &[u8]) -> ScriptedReply {
        ScriptedReply::Resp(bytes.to_vec())
    }

    fn bulk_reply(bytes: &[u8]) -> ScriptedReply {
        let mut response = format!("${}\r\n", bytes.len()).into_bytes();
        response.extend_from_slice(bytes);
        response.extend_from_slice(b"\r\n");
        ScriptedReply::Resp(response)
    }

    fn scan_reply(cursor: &[u8], keys: &[&[u8]]) -> ScriptedReply {
        let mut response = format!("*2\r\n${}\r\n", cursor.len()).into_bytes();
        response.extend_from_slice(cursor);
        response.extend_from_slice(b"\r\n");
        response.extend_from_slice(format!("*{}\r\n", keys.len()).as_bytes());
        for key in keys {
            response.extend_from_slice(format!("${}\r\n", key.len()).as_bytes());
            response.extend_from_slice(key);
            response.extend_from_slice(b"\r\n");
        }
        ScriptedReply::Resp(response)
    }

    fn test_guard() -> MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn store_for(server: &ScriptedRedis) -> RedisKVStore {
        let connection = ValidatedRedisConnection::new(
            &format!("redis://{}/0", server.address()),
            RedisTlsConfig::default(),
        )
        .unwrap();
        RedisKVStore::new(RedisConfig::new(connection))
    }

    #[test]
    fn construction_is_lazy_and_first_operation_uses_validated_client() {
        let _guard = test_guard();
        let server = ScriptedRedis::start(vec![reply(b"$-1\r\n")]);
        let dsn = format!(
            "redis://sentinel-user:sentinel-password@{}/7",
            server.address()
        );
        let store = RedisKVStore::new(RedisConfig::from_dsn(&dsn).unwrap());

        assert_eq!(server.accepts(), 0, "construction must not open a socket");
        assert_eq!(store.get(b"sentinel-first-key").unwrap(), None);
        assert_eq!(server.accepts(), 1);
        assert_eq!(
            server.application_commands(),
            vec![vec![
                b"GET".to_vec(),
                hex::encode(b"sentinel-first-key").into_bytes()
            ]]
        );

        let setup = server.commands();
        assert!(setup.iter().any(|command| command[0] == b"AUTH"));
        assert!(setup
            .iter()
            .any(|command| command == &[b"SELECT".to_vec(), b"7".to_vec()]));
        server.assert_finished();
    }

    #[test]
    fn pool_exhaustion_uses_the_bounded_acquisition_deadline() {
        let _guard = test_guard();
        let server = ScriptedRedis::start(Vec::new());
        let connection = ValidatedRedisConnection::new(
            &format!("redis://{}/0", server.address()),
            RedisTlsConfig::default(),
        )
        .unwrap();
        let mut config = RedisConfig::new(connection);
        config.pool_size = 1;
        config.acquire_timeout = Duration::from_millis(50);
        let store = RedisKVStore::new(config);
        let held = store.checkout(RedisOperation::Get).unwrap();

        let started_at = Instant::now();
        let error = store
            .checkout(RedisOperation::Set)
            .err()
            .expect("second checkout must time out");
        let elapsed = started_at.elapsed();
        assert_eq!(error.to_string(), "redis set failed: pool_timeout");
        assert!(elapsed >= Duration::from_millis(40), "elapsed: {elapsed:?}");
        assert!(elapsed < Duration::from_millis(500), "elapsed: {elapsed:?}");
        assert!(!format_error_chain(&error).contains(server.address()));

        drop(held);
        drop(store.checkout(RedisOperation::Get).unwrap());
        assert_eq!(server.accepts(), 1);
        server.assert_finished();
    }

    #[test]
    fn kv_commands_keep_hex_keys_and_typed_results() {
        let _guard = test_guard();
        let server = ScriptedRedis::start(vec![
            bulk_reply(b"typed-value"),
            reply(b"+OK\r\n"),
            reply(b":1\r\n"),
            reply(b"+OK\r\n"),
        ]);
        let store = store_for(&server);
        let raw_key = b"sentinel:key:\x00\xff";
        let encoded = hex::encode(raw_key).into_bytes();

        assert_eq!(
            store.get(raw_key).unwrap(),
            Some(Bytes::from_static(b"typed-value"))
        );
        store.put(raw_key, b"sentinel-value").unwrap();
        store.delete(raw_key).unwrap();
        store
            .put_with_ttl(raw_key, b"sentinel-ttl-value", 73)
            .unwrap();

        assert_eq!(
            server.application_commands(),
            vec![
                vec![b"GET".to_vec(), encoded.clone()],
                vec![b"SET".to_vec(), encoded.clone(), b"sentinel-value".to_vec()],
                vec![b"DEL".to_vec(), encoded.clone()],
                vec![
                    b"SET".to_vec(),
                    encoded,
                    b"sentinel-ttl-value".to_vec(),
                    b"EX".to_vec(),
                    b"73".to_vec(),
                ],
            ]
        );
        server.assert_finished();
    }

    #[test]
    fn increment_remains_one_atomic_multi_exec_pipeline() {
        let _guard = test_guard();
        let server = ScriptedRedis::start(vec![
            reply(b"+OK\r\n"),
            reply(b"+QUEUED\r\n"),
            reply(b"+QUEUED\r\n"),
            reply(b"*2\r\n:41\r\n:1\r\n"),
        ]);
        let store = store_for(&server);
        let raw_key = b"sentinel-increment-key";
        let encoded = hex::encode(raw_key).into_bytes();

        assert_eq!(store.incr_with_ttl(raw_key, 29).unwrap(), 41);
        assert_eq!(
            server.application_commands(),
            vec![
                vec![b"MULTI".to_vec()],
                vec![b"INCR".to_vec(), encoded.clone()],
                vec![b"EXPIRE".to_vec(), encoded, b"29".to_vec()],
                vec![b"EXEC".to_vec()],
            ]
        );
        server.assert_finished();
    }

    #[test]
    fn locks_and_scan_keep_existing_wire_contract() {
        let _guard = test_guard();
        let prefix = b"sentinel-scan-prefix:";
        let raw_key_a = b"sentinel-scan-prefix:a";
        let raw_key_b = b"sentinel-scan-prefix:b";
        let encoded_a = hex::encode(raw_key_a).into_bytes();
        let encoded_b = hex::encode(raw_key_b).into_bytes();
        let server = ScriptedRedis::start(vec![
            reply(b"+OK\r\n"),
            reply(b"$-1\r\n"),
            reply(b":1\r\n"),
            scan_reply(b"0", &[&encoded_a, &encoded_b]),
            bulk_reply(b"sentinel-scan-value"),
            reply(b"$-1\r\n"),
        ]);
        let store = store_for(&server);
        let lock_key = b"sentinel-lock-key";
        let encoded_lock = hex::encode(lock_key).into_bytes();

        assert!(store
            .try_lock(lock_key, b"sentinel-lock-token-a", 11)
            .unwrap());
        assert!(!store
            .try_lock(lock_key, b"sentinel-lock-token-b", 11)
            .unwrap());
        store.unlock(lock_key, b"sentinel-lock-token-a").unwrap();
        assert_eq!(
            store.scan_prefix(prefix).unwrap(),
            vec![(
                Bytes::from_static(raw_key_a),
                Bytes::from_static(b"sentinel-scan-value")
            )]
        );

        assert_eq!(
            server.application_commands(),
            vec![
                vec![
                    b"SET".to_vec(),
                    encoded_lock.clone(),
                    b"sentinel-lock-token-a".to_vec(),
                    b"NX".to_vec(),
                    b"PX".to_vec(),
                    b"11000".to_vec(),
                ],
                vec![
                    b"SET".to_vec(),
                    encoded_lock.clone(),
                    b"sentinel-lock-token-b".to_vec(),
                    b"NX".to_vec(),
                    b"PX".to_vec(),
                    b"11000".to_vec(),
                ],
                vec![
                    b"EVAL".to_vec(),
                    RELEASE_LOCK_SCRIPT.to_vec(),
                    b"1".to_vec(),
                    encoded_lock,
                    b"sentinel-lock-token-a".to_vec(),
                ],
                vec![
                    b"SCAN".to_vec(),
                    b"0".to_vec(),
                    b"MATCH".to_vec(),
                    format!("{}*", hex::encode(prefix)).into_bytes(),
                    b"COUNT".to_vec(),
                    b"100".to_vec(),
                ],
                vec![b"GET".to_vec(), encoded_a],
                vec![b"GET".to_vec(), encoded_b],
            ]
        );
        server.assert_finished();
    }

    #[test]
    fn transport_failure_discards_connection_and_next_operation_reconnects() {
        let _guard = test_guard();
        let server = ScriptedRedis::start(vec![ScriptedReply::Close, reply(b"$-1\r\n")]);
        let store = store_for(&server);
        let key = b"sentinel-reconnect-key";

        let error = store.get(key).unwrap_err();
        let rendered = format_error_chain(&error);
        for forbidden in [server.address(), "sentinel-reconnect-key"] {
            assert!(
                !rendered.contains(forbidden),
                "leaked {forbidden}: {rendered}"
            );
        }
        assert_eq!(store.get(key).unwrap(), None);
        assert_eq!(server.accepts(), 2);
        assert_eq!(server.application_commands().len(), 2);
        server.assert_finished();
    }

    #[test]
    fn server_error_is_sanitized_and_does_not_expose_command_or_key() {
        let _guard = test_guard();
        let raw_key = b"sentinel-server-error-key";
        let encoded = hex::encode(raw_key);
        let server_error = format!(
            "-ERR sentinel-server-error sentinel-command sentinel-server-error-key {encoded}\r\n"
        );
        let server = ScriptedRedis::start(vec![ScriptedReply::Resp(server_error.into_bytes())]);
        let dsn = format!(
            "redis://sentinel-user:sentinel-password@{}/0",
            server.address()
        );
        let store = RedisKVStore::new(RedisConfig::from_dsn(&dsn).unwrap());

        let error = store.get(raw_key).unwrap_err();
        let rendered = format_error_chain(&error);
        assert_eq!(error.to_string(), "redis get failed: server");
        assert_eq!(error.chain().count(), 1, "must not retain a source error");
        for forbidden in [
            dsn.as_str(),
            server.address(),
            "sentinel-user",
            "sentinel-password",
            "sentinel-command",
            "sentinel-server-error",
            "sentinel-server-error-key",
            encoded.as_str(),
        ] {
            assert!(
                !rendered.contains(forbidden),
                "leaked {forbidden}: {rendered}"
            );
        }
        server.assert_finished();
    }

    #[test]
    fn records_only_closed_connection_and_operation_labels() {
        let _guard = test_guard();
        let server = ScriptedRedis::start(Vec::new());
        let key = b"sentinel-metric-key";
        let encoded_key = hex::encode(key);
        let endpoint = server.address().to_string();
        let dsn = format!("redis://sentinel-metric-user:sentinel-metric-password@{endpoint}/7");
        let sentinel_error = "sentinel-metric-server-error";
        server.enqueue(vec![
            reply(b"$-1\r\n"),
            ScriptedReply::Resp(
                format!(
                    "-ERR {sentinel_error} {endpoint} sentinel-metric-key sentinel-metric-value\r\n"
                )
                .into_bytes(),
            ),
        ]);
        let store = RedisKVStore::new(RedisConfig::from_dsn(&dsn).unwrap());
        let connection_before = metric_counter(
            "sbproxy_redis_kv_connections_total",
            &[("result", "success")],
        );
        let get_before = metric_histogram_count(
            "sbproxy_redis_kv_operation_duration_seconds",
            &[("operation", "get")],
        );
        let set_before = metric_histogram_count(
            "sbproxy_redis_kv_operation_duration_seconds",
            &[("operation", "set")],
        );
        let error_before = metric_counter(
            "sbproxy_redis_kv_operation_errors_total",
            &[("operation", "set"), ("reason", "server")],
        );

        let (error, events) = capture_events(|| {
            assert_eq!(store.get(key).unwrap(), None);
            store.put(key, b"sentinel-metric-value").unwrap_err()
        });

        assert_eq!(
            metric_counter(
                "sbproxy_redis_kv_connections_total",
                &[("result", "success")],
            ),
            connection_before + 1.0
        );
        assert_eq!(
            metric_histogram_count(
                "sbproxy_redis_kv_operation_duration_seconds",
                &[("operation", "get")],
            ),
            get_before + 1
        );
        assert_eq!(
            metric_histogram_count(
                "sbproxy_redis_kv_operation_duration_seconds",
                &[("operation", "set")],
            ),
            set_before + 1
        );
        assert_eq!(
            metric_counter(
                "sbproxy_redis_kv_operation_errors_total",
                &[("operation", "set"), ("reason", "server")],
            ),
            error_before + 1.0
        );

        let forbidden = [
            dsn.as_str(),
            endpoint.as_str(),
            "127.0.0.1",
            "sentinel-metric-user",
            "sentinel-metric-password",
            "sentinel-metric-key",
            encoded_key.as_str(),
            "sentinel-metric-value",
            sentinel_error,
        ];
        assert_closed_metric_labels(&forbidden);
        assert_private_observations(&[error], &events, &forbidden);
        server.assert_finished();
    }

    #[test]
    fn repeated_failure_does_not_repeat_warning_transition() {
        let _guard = test_guard();
        let server = ScriptedRedis::start(Vec::new());
        let endpoint = server.address().to_string();
        let dsn = format!("redis://sentinel-repeated-user:sentinel-repeated-password@{endpoint}/7");
        let key = b"sentinel-repeated-failure-key";
        let encoded_key = hex::encode(key);
        let sentinel_error = "sentinel-repeated-server-error";
        let error_reply = format!(
            "-ERR {sentinel_error} {endpoint} sentinel-repeated-failure-key {encoded_key}\r\n"
        )
        .into_bytes();
        server.enqueue(vec![
            ScriptedReply::Resp(error_reply.clone()),
            ScriptedReply::Resp(error_reply),
        ]);
        let store = RedisKVStore::new(RedisConfig::from_dsn(&dsn).unwrap());

        let (errors, events) =
            capture_events(|| vec![store.get(key).unwrap_err(), store.get(key).unwrap_err()]);
        let redis_events = redis_events(&events);
        assert_eq!(count_level(&redis_events, Level::WARN), 1);
        assert_eq!(count_level(&redis_events, Level::DEBUG), 1);
        assert_eq!(count_level(&redis_events, Level::INFO), 0);
        assert_eq!(
            server.accepts(),
            1,
            "server errors keep the connection idle"
        );

        let forbidden = [
            dsn.as_str(),
            endpoint.as_str(),
            "127.0.0.1",
            "sentinel-repeated-user",
            "sentinel-repeated-password",
            "sentinel-repeated-failure-key",
            encoded_key.as_str(),
            sentinel_error,
        ];
        assert_private_observations(&errors, &events, &forbidden);
        server.assert_finished();
    }

    #[test]
    fn recovery_moves_failed_health_back_to_healthy_once() {
        let _guard = test_guard();
        let server = ScriptedRedis::start(Vec::new());
        let endpoint = server.address().to_string();
        let dsn = format!("redis://sentinel-recovery-user:sentinel-recovery-password@{endpoint}/7");
        let key = b"sentinel-recovery-key";
        let encoded_key = hex::encode(key);
        let sentinel_error = "sentinel-recovery-server-error";
        server.enqueue(vec![
            ScriptedReply::Resp(
                format!("-ERR {sentinel_error} {endpoint} sentinel-recovery-key {encoded_key}\r\n")
                    .into_bytes(),
            ),
            reply(b"$-1\r\n"),
            reply(b"$-1\r\n"),
        ]);
        let store = RedisKVStore::new(RedisConfig::from_dsn(&dsn).unwrap());

        let (errors, events) = capture_events(|| {
            let error = store.get(key).unwrap_err();
            assert_eq!(store.get(key).unwrap(), None);
            assert_eq!(store.get(key).unwrap(), None);
            vec![error]
        });
        let redis_events = redis_events(&events);
        assert_eq!(count_level(&redis_events, Level::WARN), 1);
        assert_eq!(count_level(&redis_events, Level::INFO), 1);
        assert_eq!(count_level(&redis_events, Level::DEBUG), 0);

        let forbidden = [
            dsn.as_str(),
            endpoint.as_str(),
            "127.0.0.1",
            "sentinel-recovery-user",
            "sentinel-recovery-password",
            "sentinel-recovery-key",
            encoded_key.as_str(),
            sentinel_error,
        ];
        assert_private_observations(&errors, &events, &forbidden);
        server.assert_finished();
    }

    #[derive(Clone, Debug)]
    struct CapturedEvent {
        level: Level,
        target: String,
        fields: String,
    }

    struct CaptureSubscriber {
        events: Arc<Mutex<Vec<CapturedEvent>>>,
        next_span: AtomicU64,
    }

    impl Subscriber for CaptureSubscriber {
        fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _span: &Attributes<'_>) -> Id {
            Id::from_u64(self.next_span.fetch_add(1, Ordering::Relaxed) + 1)
        }

        fn record(&self, _span: &Id, _values: &Record<'_>) {}

        fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

        fn event(&self, event: &Event<'_>) {
            let mut visitor = FieldVisitor::default();
            event.record(&mut visitor);
            self.events.lock().unwrap().push(CapturedEvent {
                level: *event.metadata().level(),
                target: event.metadata().target().to_string(),
                fields: visitor.fields,
            });
        }

        fn enter(&self, _span: &Id) {}

        fn exit(&self, _span: &Id) {}

        fn max_level_hint(&self) -> Option<tracing::metadata::LevelFilter> {
            Some(tracing::metadata::LevelFilter::TRACE)
        }
    }

    #[derive(Default)]
    struct FieldVisitor {
        fields: String,
    }

    impl Visit for FieldVisitor {
        fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
            use fmt::Write as _;
            let _ = write!(&mut self.fields, "{}={value:?};", field.name());
        }
    }

    fn capture_events<T>(function: impl FnOnce() -> T) -> (T, Vec<CapturedEvent>) {
        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = CaptureSubscriber {
            events: Arc::clone(&events),
            next_span: AtomicU64::new(0),
        };
        let value = tracing::subscriber::with_default(subscriber, function);
        let captured = events.lock().unwrap().clone();
        (value, captured)
    }

    fn redis_events(events: &[CapturedEvent]) -> Vec<&CapturedEvent> {
        events
            .iter()
            .filter(|event| event.target.ends_with("storage::redis"))
            .collect()
    }

    fn count_level(events: &[&CapturedEvent], level: Level) -> usize {
        events.iter().filter(|event| event.level == level).count()
    }

    fn assert_private_observations(
        errors: &[anyhow::Error],
        events: &[CapturedEvent],
        forbidden: &[&str],
    ) {
        let errors = errors
            .iter()
            .map(format_error_chain)
            .collect::<Vec<_>>()
            .join(" | ");
        let logs = events
            .iter()
            .map(|event| format!("{} {} {}", event.level, event.target, event.fields))
            .collect::<Vec<_>>()
            .join(" | ");
        for sentinel in forbidden {
            assert!(
                !errors.contains(sentinel),
                "error leaked {sentinel}: {errors}"
            );
            assert!(!logs.contains(sentinel), "log leaked {sentinel}: {logs}");
        }
    }

    fn assert_closed_metric_labels(forbidden: &[&str]) {
        let expected = [
            ("sbproxy_redis_kv_connections_total", &["result"][..]),
            (
                "sbproxy_redis_kv_operation_duration_seconds",
                &["operation"][..],
            ),
            (
                "sbproxy_redis_kv_operation_errors_total",
                &["operation", "reason"][..],
            ),
        ];
        let families = prometheus::gather();
        for (family_name, expected_names) in expected {
            let family = families
                .iter()
                .find(|family| family.name() == family_name)
                .unwrap_or_else(|| panic!("missing metric family {family_name}"));
            assert!(!family.get_metric().is_empty());
            for metric in family.get_metric() {
                let mut names = metric
                    .get_label()
                    .iter()
                    .map(|label| label.name())
                    .collect::<Vec<_>>();
                names.sort_unstable();
                let mut expected_names = expected_names.to_vec();
                expected_names.sort_unstable();
                assert_eq!(names, expected_names, "labels for {family_name}");
                for label in metric.get_label() {
                    let allowed = match label.name() {
                        "result" => matches!(label.value(), "success" | "error"),
                        "operation" => matches!(
                            label.value(),
                            "get"
                                | "set"
                                | "set_ttl"
                                | "delete"
                                | "increment"
                                | "lock"
                                | "unlock"
                                | "scan"
                        ),
                        "reason" => matches!(
                            label.value(),
                            "pool_timeout"
                                | "connect_timeout"
                                | "command_timeout"
                                | "tls"
                                | "auth"
                                | "transport"
                                | "server"
                                | "protocol"
                        ),
                        _ => false,
                    };
                    assert!(
                        allowed,
                        "unbounded label {}={}",
                        label.name(),
                        label.value()
                    );
                    for sentinel in forbidden {
                        assert!(
                            !label.name().contains(sentinel) && !label.value().contains(sentinel),
                            "metric label leaked {sentinel}"
                        );
                    }
                }
            }
        }
    }

    fn metric_counter(name: &str, labels: &[(&str, &str)]) -> f64 {
        prometheus::gather()
            .into_iter()
            .find(|family| family.name() == name)
            .and_then(|family| {
                family
                    .get_metric()
                    .iter()
                    .find(|metric| metric_has_labels(metric, labels))
                    .map(|metric| metric.get_counter().value())
            })
            .unwrap_or(0.0)
    }

    fn metric_histogram_count(name: &str, labels: &[(&str, &str)]) -> u64 {
        prometheus::gather()
            .into_iter()
            .find(|family| family.name() == name)
            .and_then(|family| {
                family
                    .get_metric()
                    .iter()
                    .find(|metric| metric_has_labels(metric, labels))
                    .map(|metric| metric.get_histogram().get_sample_count())
            })
            .unwrap_or(0)
    }

    fn metric_has_labels(metric: &prometheus::proto::Metric, labels: &[(&str, &str)]) -> bool {
        labels.iter().all(|(name, value)| {
            metric
                .get_label()
                .iter()
                .any(|label| label.name() == *name && label.value() == *value)
        })
    }

    fn format_error_chain(error: &anyhow::Error) -> String {
        error
            .chain()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" | ")
    }
}

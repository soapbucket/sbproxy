//! Async Redis implementation of [`AsyncKVStore`].
//!
//! Uses the `redis` crate with `tokio-rustls-comp` so each call awaits directly
//! on the tokio reactor instead of round-tripping through
//! `spawn_blocking`. Connection sharing and reconnects are handled by
//! `redis::aio::ConnectionManager`, which wraps a multiplexed connection so
//! concurrent logical requests can share Redis' pipelineable RESP transport.
//! Connection setup, command responses, and complete operations all have
//! finite deadlines.
//!
//! See matrix-v6 MATRIX_V6_C3_RESULTS §9.7 for the performance gap this
//! closes: rate-limit throughput was 98 rps on the sync bridge,
//! projected to 5-10k rps on the async client.

use std::{
    collections::HashMap,
    future::Future,
    sync::{atomic::AtomicU64, atomic::Ordering, Arc},
    time::Duration,
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use redis::{
    aio::{ConnectionManager, ConnectionManagerConfig},
    Client, ErrorKind, FromRedisValue,
};
use tokio::sync::Mutex;

use super::async_kv::AsyncKVStore;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const DEFAULT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(2);
const RECONNECT_EXPONENT_BASE: u64 = 2;
const RECONNECT_DELAY_FACTOR_MS: u64 = 25;
const RECONNECT_RETRIES: usize = 2;

#[derive(Debug, Clone, Copy)]
struct RedisTimeouts {
    connect: Duration,
    response: Duration,
    operation: Duration,
}

impl Default for RedisTimeouts {
    fn default() -> Self {
        Self {
            connect: DEFAULT_CONNECT_TIMEOUT,
            response: DEFAULT_RESPONSE_TIMEOUT,
            operation: DEFAULT_OPERATION_TIMEOUT,
        }
    }
}

/// Configuration for [`AsyncRedisKVStore`].
#[derive(Debug, Clone)]
pub struct AsyncRedisConfig {
    /// Connection URL (`redis://host:6379/0` or `rediss://host:6380/0`).
    pub url: String,
}

/// One bounded Redis `SCAN` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisScanPage {
    /// Cursor to pass to the next scan call. Zero means the iteration ended.
    pub next_cursor: u64,
    /// Raw Redis keys returned by this bounded scan step.
    pub keys: Vec<String>,
}

impl AsyncRedisConfig {
    /// Construct a new config from a Redis connection URL.
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
        }
    }

    /// Validate Redis-specific URL semantics without opening a connection.
    pub fn validate(&self) -> Result<()> {
        let client = Client::open(self.url.as_str()).context("invalid Redis connection URL")?;
        anyhow::ensure!(
            client.get_connection_info().redis.db >= 0,
            "invalid Redis database selection"
        );
        Ok(())
    }
}

/// Async-native Redis KV store.
///
/// Lazily connects on first use. The connection manager reconnects after
/// dropped transports, while I/O failures and whole-operation timeouts evict
/// the cached manager so the next operation starts with a fresh connection.
pub struct AsyncRedisKVStore {
    config: AsyncRedisConfig,
    conn: Mutex<Option<CachedConnection>>,
    next_connection_generation: AtomicU64,
    script_hashes: Mutex<HashMap<String, String>>,
    timeouts: RedisTimeouts,
}

#[derive(Clone)]
struct CachedConnection {
    generation: u64,
    manager: ConnectionManager,
}

impl AsyncRedisKVStore {
    /// Build a new store wrapped in an `Arc`, deferring connection until first use.
    pub fn new(config: AsyncRedisConfig) -> Arc<Self> {
        Self::new_with_timeouts(config, RedisTimeouts::default())
    }

    fn new_with_timeouts(config: AsyncRedisConfig, timeouts: RedisTimeouts) -> Arc<Self> {
        Arc::new(Self {
            config,
            conn: Mutex::new(None),
            next_connection_generation: AtomicU64::new(1),
            script_hashes: Mutex::new(HashMap::new()),
            timeouts,
        })
    }

    async fn with_operation_deadline<T, F>(&self, operation: &str, future: F) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        match tokio::time::timeout(self.timeouts.operation, future).await {
            Ok(result) => result,
            Err(_) => {
                // The cancelled future may have left a command in flight. Do
                // not let a later operation reuse that connection.
                *self.conn.lock().await = None;
                Err(anyhow::anyhow!(
                    "Redis {operation} exceeded the {} ms whole-operation deadline",
                    self.timeouts.operation.as_millis()
                ))
            }
        }
    }

    async fn conn(&self) -> Result<CachedConnection> {
        // Fast path: return the cached multiplexed connection. The guard is
        // released at the end of this block so it is never held across the
        // connection-setup await below. Holding it there would
        // serialize every concurrent caller behind whichever one is
        // currently establishing the connection.
        {
            let guard = self.conn.lock().await;
            if let Some(c) = guard.as_ref() {
                return Ok(c.clone());
            }
        }
        // Slow path: establish the connection without holding the lock.
        let client =
            Client::open(self.config.url.as_str()).context("invalid Redis connection URL")?;
        let manager_config = ConnectionManagerConfig::new()
            .set_exponent_base(RECONNECT_EXPONENT_BASE)
            .set_factor(RECONNECT_DELAY_FACTOR_MS)
            .set_number_of_retries(RECONNECT_RETRIES)
            .set_response_timeout(self.timeouts.response)
            .set_connection_timeout(self.timeouts.connect);
        let manager = tokio::time::timeout(
            self.timeouts.connect,
            ConnectionManager::new_with_config(client, manager_config),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "connecting to Redis exceeded the {} ms connection-setup deadline",
                self.timeouts.connect.as_millis()
            )
        })?
        .context("connecting to Redis")?;
        let candidate = CachedConnection {
            generation: self
                .next_connection_generation
                .fetch_add(1, Ordering::Relaxed),
            manager,
        };
        // Cache it under a brief lock. If another caller raced us and already
        // stored a connection, keep theirs (multiplexed handles are
        // equivalent) and drop ours.
        let mut guard = self.conn.lock().await;
        if let Some(existing) = guard.as_ref() {
            return Ok(existing.clone());
        }
        *guard = Some(candidate.clone());
        Ok(candidate)
    }

    async fn invalidate_connection(&self, generation: u64) {
        let mut guard = self.conn.lock().await;
        if guard
            .as_ref()
            .is_some_and(|cached| cached.generation == generation)
        {
            *guard = None;
        }
    }

    async fn query_redis<T>(&self, command: &mut redis::Cmd) -> redis::RedisResult<T>
    where
        T: FromRedisValue,
    {
        let mut cached = self.conn().await.map_err(|error| {
            redis::RedisError::from((
                ErrorKind::IoError,
                "opening managed Redis connection",
                error.to_string(),
            ))
        })?;
        let result = command.query_async(&mut cached.manager).await;
        if result
            .as_ref()
            .is_err_and(|error| error.is_io_error() || error.is_unrecoverable_error())
        {
            self.invalidate_connection(cached.generation).await;
        }
        result
    }

    async fn query<T>(&self, command: &mut redis::Cmd, context: &'static str) -> Result<T>
    where
        T: FromRedisValue,
    {
        self.query_redis(command).await.context(context)
    }

    /// Execute a Lua script through `EVALSHA`, loading or reloading it as needed.
    ///
    /// Script source is cached with the SHA returned by Redis. A missing cache
    /// entry is loaded before execution. If Redis loses its script cache after
    /// a restart or `SCRIPT FLUSH`, a `NOSCRIPT` response reloads the source and
    /// retries `EVALSHA` once. Results must be a flat array of string-compatible
    /// values so this seam does not expose Redis crate types to callers.
    pub async fn evalsha_with_reload(
        &self,
        script_source: &str,
        keys: &[String],
        args: &[String],
    ) -> Result<Vec<String>> {
        self.with_operation_deadline(
            "script evaluation",
            self.evalsha_with_reload_inner(script_source, keys, args),
        )
        .await
    }

    async fn evalsha_with_reload_inner(
        &self,
        script_source: &str,
        keys: &[String],
        args: &[String],
    ) -> Result<Vec<String>> {
        let cached_hash = {
            let hashes = self.script_hashes.lock().await;
            hashes.get(script_source).cloned()
        };
        let script_hash = match cached_hash {
            Some(value) => value,
            None => self.load_script(script_source).await?,
        };

        match self.evalsha(&script_hash, keys, args).await {
            Ok(value) => Ok(value),
            Err(error) if error.kind() == ErrorKind::NoScriptError => {
                let reloaded_hash = self.load_script(script_source).await?;
                self.evalsha(&reloaded_hash, keys, args)
                    .await
                    .context("redis EVALSHA failed after NOSCRIPT reload")
            }
            Err(error) => Err(error).context("redis EVALSHA failed"),
        }
    }

    async fn load_script(&self, script_source: &str) -> Result<String> {
        let script_hash: String = self
            .query(
                redis::cmd("SCRIPT").arg("LOAD").arg(script_source),
                "redis SCRIPT LOAD failed",
            )
            .await?;
        self.script_hashes
            .lock()
            .await
            .insert(script_source.to_string(), script_hash.clone());
        Ok(script_hash)
    }

    async fn evalsha(
        &self,
        script_hash: &str,
        keys: &[String],
        args: &[String],
    ) -> redis::RedisResult<Vec<String>> {
        let mut command = redis::cmd("EVALSHA");
        command.arg(script_hash).arg(keys.len());
        for key in keys {
            command.arg(key);
        }
        for arg in args {
            command.arg(arg);
        }
        self.query_redis(&mut command).await
    }

    /// Execute one bounded `SCAN MATCH COUNT` step.
    ///
    /// Redis treats `COUNT` as a work hint rather than a strict result cap.
    /// Callers must therefore retain any unconsumed keys in their own bounded
    /// pagination cursor. This method never falls back to `KEYS`.
    pub async fn scan_page(&self, cursor: u64, pattern: &str, count: u16) -> Result<RedisScanPage> {
        if !(1..=1_000).contains(&count) {
            anyhow::bail!("redis scan count must be between 1 and 1000");
        }
        self.with_operation_deadline("SCAN", async {
            let (next_cursor, keys): (u64, Vec<String>) = self
                .query(
                    redis::cmd("SCAN")
                        .arg(cursor)
                        .arg("MATCH")
                        .arg(pattern)
                        .arg("COUNT")
                        .arg(count),
                    "redis SCAN failed",
                )
                .await?;
            Ok(RedisScanPage { next_cursor, keys })
        })
        .await
    }
}

#[async_trait]
impl AsyncKVStore for AsyncRedisKVStore {
    async fn get(&self, key: &[u8]) -> Result<Option<Bytes>> {
        self.with_operation_deadline("GET", async {
            let value: Option<Vec<u8>> = self
                .query(redis::cmd("GET").arg(key), "redis GET failed")
                .await?;
            Ok(value.map(Bytes::from))
        })
        .await
    }

    async fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        self.with_operation_deadline("SET", async {
            self.query::<()>(redis::cmd("SET").arg(key).arg(value), "redis SET failed")
                .await?;
            Ok(())
        })
        .await
    }

    async fn put_with_ttl(&self, key: &[u8], value: &[u8], ttl_secs: u64) -> Result<()> {
        self.with_operation_deadline("SET with TTL", async {
            if ttl_secs == 0 {
                self.query::<()>(redis::cmd("SET").arg(key).arg(value), "redis SET failed")
                    .await?;
            } else {
                self.query::<()>(
                    redis::cmd("SET")
                        .arg(key)
                        .arg(value)
                        .arg("EX")
                        .arg(ttl_secs),
                    "redis SET EX failed",
                )
                .await?;
            }
            Ok(())
        })
        .await
    }

    async fn incr_with_ttl(&self, key: &[u8], ttl_secs: u64) -> Result<i64> {
        self.with_operation_deadline("INCR with TTL", async {
            // Issue INCR + EXPIRE. The two commands are not atomic against
            // each other; between them, another client could observe a
            // fresh key without the TTL set. For rate-limit use cases that
            // is acceptable: the next incr_with_ttl call re-asserts the
            // TTL. If stricter atomicity is needed later, switch to a Lua
            // script via EVAL.
            let value: i64 = self
                .query(redis::cmd("INCR").arg(key), "redis INCR failed")
                .await?;
            if ttl_secs > 0 {
                self.query::<bool>(
                    redis::cmd("EXPIRE").arg(key).arg(ttl_secs),
                    "redis EXPIRE failed",
                )
                .await?;
            }
            Ok(value)
        })
        .await
    }

    async fn incr_by_with_ttl(&self, key: &[u8], amount: i64, ttl_secs: u64) -> Result<i64> {
        self.with_operation_deadline("INCRBY with TTL", async {
            // Redis INCRBY (via `incr` with a non-1 amount) then EXPIRE. Same
            // non-atomicity note as incr_with_ttl: the next call re-asserts
            // the TTL. Accumulates arbitrary spend into a shared counter.
            let value: i64 = self
                .query(
                    redis::cmd("INCRBY").arg(key).arg(amount),
                    "redis INCRBY failed",
                )
                .await?;
            if ttl_secs > 0 {
                self.query::<bool>(
                    redis::cmd("EXPIRE").arg(key).arg(ttl_secs),
                    "redis EXPIRE failed",
                )
                .await?;
            }
            Ok(value)
        })
        .await
    }

    async fn delete(&self, key: &[u8]) -> Result<()> {
        self.with_operation_deadline("DEL", async {
            self.query::<i64>(redis::cmd("DEL").arg(key), "redis DEL failed")
                .await?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    async fn complete_client_setup(socket: &mut TcpStream) {
        let mut setup = Vec::new();
        let mut chunk = [0_u8; 512];
        while !setup
            .windows(b"LIB-VER".len())
            .any(|part| part == b"LIB-VER")
        {
            let read = socket.read(&mut chunk).await.unwrap();
            assert_ne!(read, 0, "client disconnected during Redis setup");
            setup.extend_from_slice(&chunk[..read]);
        }
        socket.write_all(b"+OK\r\n+OK\r\n").await.unwrap();
    }

    #[test]
    fn config_constructs() {
        let cfg = AsyncRedisConfig::new("redis://127.0.0.1:6379/0");
        assert_eq!(cfg.url, "redis://127.0.0.1:6379/0");
        cfg.validate().unwrap();
        assert!(AsyncRedisConfig::new("redis://127.0.0.1/not-a-database")
            .validate()
            .is_err());
        assert!(AsyncRedisConfig::new("redis://127.0.0.1/-1")
            .validate()
            .is_err());
    }

    #[test]
    fn tls_url_is_accepted_by_the_redis_client() {
        AsyncRedisConfig::new("rediss://127.0.0.1:6380/0")
            .validate()
            .unwrap();
    }

    #[test]
    fn new_defers_connection() {
        // Bad URL is fine until we actually try to connect.
        let store = AsyncRedisKVStore::new(AsyncRedisConfig::new("redis://127.0.0.1:1"));
        // Invariant: constructor never panics and never opens a socket.
        assert!(Arc::strong_count(&store) >= 1);
    }

    #[tokio::test]
    async fn scan_page_rejects_unbounded_count_before_connecting() {
        let store = AsyncRedisKVStore::new(AsyncRedisConfig::new("redis://127.0.0.1:1"));

        let zero = store.scan_page(0, "sbproxy:test:*", 0).await.unwrap_err();
        assert!(zero.to_string().contains("between 1 and 1000"));
        let excessive = store
            .scan_page(0, "sbproxy:test:*", 1_001)
            .await
            .unwrap_err();
        assert!(excessive.to_string().contains("between 1 and 1000"));
    }

    #[tokio::test]
    async fn connection_errors_do_not_expose_credentials() {
        let store = AsyncRedisKVStore::new(AsyncRedisConfig::new(
            "redis://sensitive-user:sensitive-password@127.0.0.1:1/0",
        ));

        let error = store.get(b"redaction-test").await.unwrap_err();
        let rendered = format!("{error:#}");

        assert!(!rendered.contains("sensitive-user"), "{rendered}");
        assert!(!rendered.contains("sensitive-password"), "{rendered}");
        assert!(!rendered.contains("redis://"), "{rendered}");
    }

    #[tokio::test]
    async fn connection_acquisition_has_a_finite_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _socket = socket;
                    std::future::pending::<()>().await;
                });
            }
        });
        let store = AsyncRedisKVStore::new_with_timeouts(
            AsyncRedisConfig::new(&format!("redis://{address}/0")),
            RedisTimeouts {
                connect: Duration::from_millis(25),
                response: Duration::from_secs(5),
                operation: Duration::from_secs(1),
            },
        );

        let started = Instant::now();
        let error = store.get(b"connection-deadline").await.unwrap_err();
        let elapsed = started.elapsed();
        server.abort();

        assert!(elapsed < Duration::from_secs(1), "elapsed {elapsed:?}");
        assert!(
            format!("{error:#}").contains("connecting to Redis"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn command_response_has_a_finite_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut chunk = [0_u8; 512];
            complete_client_setup(&mut socket).await;
            let read = socket.read(&mut chunk).await.unwrap();
            assert_ne!(read, 0, "client never sent a Redis command");
            std::future::pending::<()>().await;
        });
        let store = AsyncRedisKVStore::new_with_timeouts(
            AsyncRedisConfig::new(&format!("redis://{address}/0")),
            RedisTimeouts {
                connect: Duration::from_millis(250),
                response: Duration::from_millis(40),
                operation: Duration::from_millis(200),
            },
        );

        let result =
            tokio::time::timeout(Duration::from_millis(200), store.get(b"slow-command")).await;
        server.abort();

        let error = result
            .expect("Redis command escaped the adapter response deadline")
            .unwrap_err();
        assert!(format!("{error:#}").contains("redis GET failed"));
    }

    #[tokio::test]
    async fn multi_command_operation_has_one_finite_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut chunk = [0_u8; 512];
            complete_client_setup(&mut socket).await;
            assert_ne!(socket.read(&mut chunk).await.unwrap(), 0);
            socket.write_all(b":1\r\n").await.unwrap();
            assert_ne!(socket.read(&mut chunk).await.unwrap(), 0);
            std::future::pending::<()>().await;
        });
        let store = AsyncRedisKVStore::new_with_timeouts(
            AsyncRedisConfig::new(&format!("redis://{address}/0")),
            RedisTimeouts {
                connect: Duration::from_millis(250),
                response: Duration::from_millis(200),
                operation: Duration::from_millis(100),
            },
        );

        let result = tokio::time::timeout(
            Duration::from_millis(125),
            store.incr_with_ttl(b"whole-operation", 60),
        )
        .await;
        server.abort();

        let error = result
            .expect("multi-command Redis operation escaped its whole-operation deadline")
            .unwrap_err();
        assert!(format!("{error:#}").contains("operation deadline"));
    }

    #[tokio::test]
    async fn failed_cached_connection_is_replaced_on_the_next_operation() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            let mut chunk = [0_u8; 512];
            complete_client_setup(&mut first).await;
            assert_ne!(first.read(&mut chunk).await.unwrap(), 0);

            let (mut second, _) = listener.accept().await.unwrap();
            complete_client_setup(&mut second).await;
            assert_ne!(second.read(&mut chunk).await.unwrap(), 0);
            second.write_all(b"$-1\r\n").await.unwrap();
        });
        let store = AsyncRedisKVStore::new_with_timeouts(
            AsyncRedisConfig::new(&format!("redis://{address}/0")),
            RedisTimeouts {
                connect: Duration::from_millis(250),
                response: Duration::from_millis(40),
                operation: Duration::from_millis(200),
            },
        );

        store.get(b"first-connection").await.unwrap_err();
        let recovered = store.get(b"replacement-connection").await.unwrap();
        server.await.unwrap();

        assert_eq!(recovered, None);
    }

    #[tokio::test]
    async fn whole_operation_timeout_discards_the_cached_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            let mut chunk = [0_u8; 512];
            complete_client_setup(&mut first).await;
            assert_ne!(first.read(&mut chunk).await.unwrap(), 0);
            first.write_all(b":1\r\n").await.unwrap();
            assert_ne!(first.read(&mut chunk).await.unwrap(), 0);

            let (mut second, _) = listener.accept().await.unwrap();
            complete_client_setup(&mut second).await;
            assert_ne!(second.read(&mut chunk).await.unwrap(), 0);
            second.write_all(b"$-1\r\n").await.unwrap();
        });
        let store = AsyncRedisKVStore::new_with_timeouts(
            AsyncRedisConfig::new(&format!("redis://{address}/0")),
            RedisTimeouts {
                connect: Duration::from_millis(250),
                response: Duration::from_millis(200),
                operation: Duration::from_millis(100),
            },
        );

        let error = store
            .incr_with_ttl(b"timed-out-operation", 60)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("operation deadline"));
        let recovered = store.get(b"replacement-after-timeout").await.unwrap();
        server.await.unwrap();

        assert_eq!(recovered, None);
    }

    struct DisposableRedis {
        child: Option<Child>,
    }

    impl DisposableRedis {
        fn start(port: u16, directory: &std::path::Path) -> std::io::Result<Self> {
            let child = Command::new("redis-server")
                .arg("--port")
                .arg(port.to_string())
                .arg("--bind")
                .arg("127.0.0.1")
                .arg("--protected-mode")
                .arg("no")
                .arg("--save")
                .arg("")
                .arg("--appendonly")
                .arg("no")
                .arg("--daemonize")
                .arg("no")
                .arg("--dir")
                .arg(directory)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            Ok(Self { child: Some(child) })
        }

        fn stop(&mut self) {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    impl Drop for DisposableRedis {
        fn drop(&mut self) {
            self.stop();
        }
    }

    #[tokio::test]
    #[ignore = "requires redis-server executable on PATH"]
    async fn redis_connection_recovers_after_server_restart() {
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let directory = tempfile::tempdir().unwrap();
        let mut server = DisposableRedis::start(port, directory.path()).unwrap();
        let store = AsyncRedisKVStore::new(AsyncRedisConfig::new(&format!(
            "redis://127.0.0.1:{port}/0"
        )));

        let startup_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match store.put(b"restart-probe", b"before").await {
                Ok(()) => break,
                Err(error) if Instant::now() < startup_deadline => {
                    let _ = error;
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Err(error) => panic!("disposable Redis did not start: {error:#}"),
            }
        }

        server.stop();
        let failure_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match store.get(b"restart-probe").await {
                Err(_) => break,
                Ok(_) if Instant::now() < failure_deadline => {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Ok(_) => panic!("cached Redis connection did not observe server shutdown"),
            }
        }

        server = DisposableRedis::start(port, directory.path()).unwrap();
        let recovery_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match store.put(b"restart-probe", b"after").await {
                Ok(()) => break,
                Err(error) if Instant::now() < recovery_deadline => {
                    let _ = error;
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Err(error) => panic!("Redis connection did not recover: {error:#}"),
            }
        }
        assert_eq!(
            store.get(b"restart-probe").await.unwrap().as_deref(),
            Some(&b"after"[..])
        );
        server.stop();
    }

    #[tokio::test]
    #[ignore = "requires live redis; set REDIS_URL env"]
    async fn e2e_roundtrip() {
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let store = AsyncRedisKVStore::new(AsyncRedisConfig::new(&url));
        let key = format!("sbproxy:async:test:{}", std::process::id());
        let kb = key.as_bytes();
        store.put_with_ttl(kb, b"hi", 10).await.unwrap();
        assert_eq!(store.get(kb).await.unwrap().as_deref(), Some(&b"hi"[..]));
        let n1 = store.incr_with_ttl(b"cnt-test", 30).await.unwrap();
        let n2 = store.incr_with_ttl(b"cnt-test", 30).await.unwrap();
        assert_eq!(n2, n1 + 1);
        store.delete(kb).await.unwrap();
        store.delete(b"cnt-test").await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires live redis; set REDIS_URL env"]
    async fn script_uses_evalsha_and_loads_after_noscript() {
        let url = std::env::var("REDIS_URL").expect("REDIS_URL must name a disposable Redis");
        let store = AsyncRedisKVStore::new(AsyncRedisConfig::new(&url));
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let script = format!("-- unique {nonce}\nreturn {{ARGV[1], tostring(#KEYS)}}");
        let keys = vec!["script-test-key".to_string()];
        let args = vec!["loaded".to_string()];

        let first = store
            .evalsha_with_reload(&script, &keys, &args)
            .await
            .unwrap();
        let mut conn = store.conn().await.unwrap();
        let _: () = redis::cmd("SCRIPT")
            .arg("FLUSH")
            .query_async(&mut conn.manager)
            .await
            .unwrap();
        let reloaded = store
            .evalsha_with_reload(&script, &keys, &args)
            .await
            .unwrap();
        let cached = store
            .evalsha_with_reload(&script, &keys, &args)
            .await
            .unwrap();

        assert_eq!(first, vec!["loaded".to_string(), "1".to_string()]);
        assert_eq!(reloaded, first);
        assert_eq!(cached, first);
    }
}

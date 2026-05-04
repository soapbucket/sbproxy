//! Redis KVStore backend using raw RESP protocol over a small connection pool.
//!
//! This implementation speaks the Redis Serialization Protocol (RESP2) directly
//! over blocking `TcpStream`s. A pool of connections (default 8) is maintained
//! so that concurrent operations do not serialize on a single connection.
//!
//! Connections are lazily opened, up to `pool_size` total, and returned to the
//! idle list on drop. Broken connections (those that return an error during
//! use) are discarded rather than returned to the pool so a subsequent checkout
//! will open a fresh one.
//!
//! Supported commands: GET, SET, DEL, SCAN (with MATCH + COUNT).
//!
//! # Limitations
//! - Only RESP2 simple strings, bulk strings, integers, and arrays are decoded.
//! - Pool size is fixed after construction.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use bytes::Bytes;

use super::KVStore;

// --- RESP protocol helpers ---

/// Write a RESP bulk-string array (the standard command format) to `w`.
fn write_command(w: &mut impl Write, args: &[&[u8]]) -> Result<()> {
    write!(w, "*{}\r\n", args.len())?;
    for arg in args {
        write!(w, "${}\r\n", arg.len())?;
        w.write_all(arg)?;
        w.write_all(b"\r\n")?;
    }
    w.flush()?;
    Ok(())
}

/// Read one RESP value from `r` and return it as raw bytes (for bulk strings),
/// an integer string, or a simple string. Arrays are returned as a flat list
/// of their element values.
#[derive(Debug)]
#[allow(dead_code)] // Integer is part of the RESP spec; kept for completeness.
enum RespValue {
    Nil,
    Bytes(Vec<u8>),
    Integer(i64),
    Array(Vec<RespValue>),
}

fn read_resp(r: &mut BufReader<TcpStream>) -> Result<RespValue> {
    let mut line = String::new();
    r.read_line(&mut line)?;
    let line = line.trim_end_matches("\r\n");

    let (prefix, rest) = line.split_at(1);
    match prefix {
        "+" => Ok(RespValue::Bytes(rest.as_bytes().to_vec())),
        "-" => bail!("Redis error: {}", rest),
        ":" => {
            let n: i64 = rest.parse().context("parse integer")?;
            Ok(RespValue::Integer(n))
        }
        "$" => {
            let len: i64 = rest.parse().context("parse bulk length")?;
            if len < 0 {
                return Ok(RespValue::Nil);
            }
            let len = len as usize;
            let mut buf = vec![0u8; len + 2]; // +2 for \r\n
            r.read_exact(&mut buf)?;
            buf.truncate(len);
            Ok(RespValue::Bytes(buf))
        }
        "*" => {
            let count: i64 = rest.parse().context("parse array length")?;
            if count < 0 {
                return Ok(RespValue::Nil);
            }
            let mut items = Vec::with_capacity(count as usize);
            for _ in 0..count {
                items.push(read_resp(r)?);
            }
            Ok(RespValue::Array(items))
        }
        _ => bail!("unexpected RESP prefix {:?}", prefix),
    }
}

// --- Connection management ---

struct Connection {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
}

impl Connection {
    fn connect(addr: &str) -> Result<Self> {
        let stream =
            TcpStream::connect(addr).with_context(|| format!("connect to Redis at {}", addr))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let writer = stream.try_clone()?;
        let reader = BufReader::new(stream);
        Ok(Self { reader, writer })
    }

    fn call(&mut self, args: &[&[u8]]) -> Result<RespValue> {
        write_command(&mut self.writer, args)?;
        read_resp(&mut self.reader)
    }
}

// --- RedisKVStore ---

/// Configuration for [`RedisKVStore`].
pub struct RedisConfig {
    /// Redis server address, e.g. `"127.0.0.1:6379"`.
    pub addr: String,
    /// Maximum number of connections held in the pool. Connections are opened
    /// lazily up to this bound. Default: 8.
    pub pool_size: usize,
    /// Timeout when acquiring a connection from the pool before erroring out.
    /// Default: 5 seconds.
    pub acquire_timeout: Duration,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1:6379".into(),
            pool_size: 8,
            acquire_timeout: Duration::from_secs(5),
        }
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
    addr: String,
    pool_size: usize,
    acquire_timeout: Duration,
    // Pool state: a Mutex holding idle connections and the in-use count.
    state: Mutex<PoolState>,
    // Signaled when a connection is returned to idle or when in_use drops,
    // so a waiting checkout can make progress.
    available: Condvar,
}

/// RAII guard returned by [`RedisKVStore::checkout`]. Holds a live connection
/// and returns it to the pool on drop. If the caller observes an I/O error
/// while using the connection, they should call [`PooledConnection::invalidate`]
/// to prevent a broken connection from being returned to the pool.
pub struct PooledConnection<'a> {
    pool: &'a RedisKVStore,
    conn: Option<Connection>,
}

impl PooledConnection<'_> {
    /// Execute a RESP command on the borrowed connection.
    fn call(&mut self, args: &[&[u8]]) -> Result<RespValue> {
        self.conn
            .as_mut()
            .expect("connection already invalidated")
            .call(args)
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
            addr: config.addr,
            pool_size,
            acquire_timeout: config.acquire_timeout,
            state: Mutex::new(PoolState {
                idle: Vec::with_capacity(pool_size),
                in_use: 0,
            }),
            available: Condvar::new(),
        }
    }

    /// Borrow a connection from the pool, opening a new one if the pool has
    /// spare capacity. Blocks up to `acquire_timeout` waiting for a connection
    /// to become available; returns an error on timeout.
    fn checkout(&self) -> Result<PooledConnection<'_>> {
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
                drop(guard);
                match Connection::connect(&self.addr) {
                    Ok(conn) => {
                        return Ok(PooledConnection {
                            pool: self,
                            conn: Some(conn),
                        });
                    }
                    Err(err) => {
                        // Connect failed; release the reserved slot and wake a
                        // waiter so they can retry.
                        let mut g = self.state.lock().expect("lock poisoned");
                        g.in_use = g.in_use.saturating_sub(1);
                        self.available.notify_one();
                        return Err(err);
                    }
                }
            }

            // Pool saturated: wait for a connection to be returned.
            let now = Instant::now();
            if now >= deadline {
                bail!("timed out acquiring Redis connection (pool exhausted)");
            }
            let remaining = deadline - now;
            let (g, timeout) = self
                .available
                .wait_timeout(guard, remaining)
                .expect("condvar wait failed");
            guard = g;
            if timeout.timed_out() {
                bail!("timed out acquiring Redis connection (pool exhausted)");
            }
        }
    }

    /// Checkout a connection, run `f` against it, and invalidate the
    /// connection if `f` returns an error so a broken conn is not returned
    /// to the pool.
    fn with_conn<F, T>(&self, mut f: F) -> Result<T>
    where
        F: FnMut(&mut PooledConnection<'_>) -> Result<T>,
    {
        let mut conn = self.checkout()?;
        match f(&mut conn) {
            Ok(v) => Ok(v),
            Err(e) => {
                // Connection may be in an inconsistent state; discard it.
                conn.invalidate();
                Err(e)
            }
        }
    }

    /// Hex-encode the raw key for safe use in Redis key names and SCAN patterns.
    fn encode_key(key: &[u8]) -> String {
        hex::encode(key)
    }
}

impl KVStore for RedisKVStore {
    fn get(&self, key: &[u8]) -> Result<Option<Bytes>> {
        let encoded = Self::encode_key(key);
        self.with_conn(|c| match c.call(&[b"GET", encoded.as_bytes()])? {
            RespValue::Nil => Ok(None),
            RespValue::Bytes(b) => Ok(Some(Bytes::from(b))),
            other => bail!("unexpected GET response: {:?}", other),
        })
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let encoded = Self::encode_key(key);
        self.with_conn(|c| {
            c.call(&[b"SET", encoded.as_bytes(), value])?;
            Ok(())
        })
    }

    fn delete(&self, key: &[u8]) -> Result<()> {
        let encoded = Self::encode_key(key);
        self.with_conn(|c| {
            c.call(&[b"DEL", encoded.as_bytes()])?;
            Ok(())
        })
    }

    fn put_with_ttl(&self, key: &[u8], value: &[u8], ttl_secs: u64) -> Result<()> {
        // SET <key> <value> EX <ttl>
        let encoded = Self::encode_key(key);
        let ttl_str = ttl_secs.to_string();
        self.with_conn(|c| {
            c.call(&[b"SET", encoded.as_bytes(), value, b"EX", ttl_str.as_bytes()])?;
            Ok(())
        })
    }

    fn incr_with_ttl(&self, key: &[u8], ttl_secs: u64) -> Result<i64> {
        // Use MULTI / INCR / EXPIRE / EXEC so both commands land atomically.
        // The EXEC reply is an array whose first element is the INCR result
        // (new counter value) and second is the EXPIRE reply (1 when applied).
        let encoded = Self::encode_key(key);
        let ttl_str = ttl_secs.to_string();

        self.with_conn(|c| {
            // Start transaction.
            match c.call(&[b"MULTI"])? {
                RespValue::Bytes(b) if b == b"OK" => {}
                other => bail!("unexpected MULTI response: {:?}", other),
            }

            // Queued INCR.
            match c.call(&[b"INCR", encoded.as_bytes()])? {
                RespValue::Bytes(b) if b == b"QUEUED" => {}
                other => bail!("unexpected INCR-queue response: {:?}", other),
            }

            // Queued EXPIRE.
            match c.call(&[b"EXPIRE", encoded.as_bytes(), ttl_str.as_bytes()])? {
                RespValue::Bytes(b) if b == b"QUEUED" => {}
                other => bail!("unexpected EXPIRE-queue response: {:?}", other),
            }

            // Execute. Reply is an array of per-command replies.
            match c.call(&[b"EXEC"])? {
                RespValue::Array(results) => {
                    // First reply is the INCR integer.
                    match results.into_iter().next() {
                        Some(RespValue::Integer(n)) => Ok(n),
                        Some(other) => {
                            bail!("unexpected INCR reply inside EXEC: {:?}", other)
                        }
                        None => bail!("empty EXEC reply"),
                    }
                }
                other => bail!("unexpected EXEC response: {:?}", other),
            }
        })
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Bytes, Bytes)>> {
        // Build a SCAN MATCH glob: hex(prefix)* (safe because hex output
        // contains only [0-9a-f] which has no glob special characters).
        let pattern = format!("{}*", Self::encode_key(prefix));

        let mut results = Vec::new();
        let mut cursor = b"0".to_vec();

        loop {
            let (next_cursor, keys) = self.with_conn(|c| {
                let resp = c.call(&[
                    b"SCAN",
                    &cursor,
                    b"MATCH",
                    pattern.as_bytes(),
                    b"COUNT",
                    b"100",
                ])?;
                match resp {
                    RespValue::Array(mut elems) if elems.len() == 2 => {
                        let keys_resp = elems.pop().unwrap();
                        let cursor_resp = elems.pop().unwrap();

                        let next_cursor = match cursor_resp {
                            RespValue::Bytes(b) => b,
                            _ => bail!("unexpected cursor type"),
                        };

                        let keys = match keys_resp {
                            RespValue::Array(items) => items
                                .into_iter()
                                .filter_map(|v| match v {
                                    RespValue::Bytes(b) => Some(b),
                                    _ => None,
                                })
                                .collect::<Vec<_>>(),
                            _ => bail!("unexpected keys type"),
                        };

                        Ok((next_cursor, keys))
                    }
                    _ => bail!("unexpected SCAN response format"),
                }
            })?;

            for hex_key in keys {
                let raw_key = hex::decode(&hex_key).with_context(|| "decode hex key")?;

                // Fetch the value.
                let value = self.with_conn(|c| match c.call(&[b"GET", &hex_key])? {
                    RespValue::Bytes(b) => Ok(Some(Bytes::from(b))),
                    RespValue::Nil => Ok(None),
                    other => bail!("unexpected GET response: {:?}", other),
                })?;

                if let Some(value) = value {
                    results.push((Bytes::from(raw_key), value));
                }
            }

            if next_cursor == b"0" {
                break;
            }
            cursor = next_cursor;
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn store() -> RedisKVStore {
        RedisKVStore::new(RedisConfig::default())
    }

    #[test]
    #[ignore = "requires a running Redis instance on 127.0.0.1:6379"]
    fn test_get_put_delete_roundtrip() {
        let s = store();
        s.delete(b"redis:test:k1").unwrap(); // clean up if leftover

        assert!(s.get(b"redis:test:k1").unwrap().is_none());

        s.put(b"redis:test:k1", b"hello").unwrap();
        assert_eq!(s.get(b"redis:test:k1").unwrap().unwrap(), &b"hello"[..]);

        s.put(b"redis:test:k1", b"world").unwrap();
        assert_eq!(s.get(b"redis:test:k1").unwrap().unwrap(), &b"world"[..]);

        s.delete(b"redis:test:k1").unwrap();
        assert!(s.get(b"redis:test:k1").unwrap().is_none());

        s.delete(b"redis:test:k1").unwrap(); // no-op
    }

    #[test]
    #[ignore = "requires a running Redis instance on 127.0.0.1:6379"]
    fn test_scan_prefix() {
        let s = store();
        let keys: &[&[u8]] = &[b"redis:scan:a", b"redis:scan:b", b"redis:other:c"];
        for k in keys {
            s.delete(k).unwrap();
        }

        s.put(b"redis:scan:a", b"1").unwrap();
        s.put(b"redis:scan:b", b"2").unwrap();
        s.put(b"redis:other:c", b"3").unwrap();

        let results = s.scan_prefix(b"redis:scan:").unwrap();
        assert_eq!(results.len(), 2);

        for k in keys {
            s.delete(k).unwrap();
        }
    }

    #[test]
    #[ignore = "requires a running Redis instance on 127.0.0.1:6379"]
    fn concurrent_ops_use_pool() {
        // Many threads hitting the store concurrently should succeed without
        // deadlocking or serializing on a single connection.
        let s = Arc::new(store());
        let mut handles = Vec::new();
        for i in 0..32 {
            let s = s.clone();
            handles.push(std::thread::spawn(move || {
                let k = format!("redis:pool:k{}", i);
                s.put(k.as_bytes(), b"v").unwrap();
                assert_eq!(
                    s.get(k.as_bytes()).unwrap().unwrap(),
                    Bytes::from_static(b"v")
                );
                s.delete(k.as_bytes()).unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn pool_exhaustion_times_out() {
        // A pool of size 1 with a held checkout must time out any second
        // checkout after `acquire_timeout`. This test does not need a running
        // Redis because we never execute a command on the held connection.
        //
        // However, `checkout()` does call `Connection::connect()` which does
        // require a reachable TCP listener. If Redis is not running locally,
        // the first `checkout()` itself will fail with a connect error, which
        // is still a valid exhaustion-prevention behavior but not the path we
        // want to exercise. Skip gracefully in that case.
        let cfg = RedisConfig {
            pool_size: 1,
            acquire_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let s = RedisKVStore::new(cfg);

        let held = match s.checkout() {
            Ok(c) => c,
            Err(_) => {
                // No Redis running; nothing to exhaust.
                return;
            }
        };

        let start = Instant::now();
        let err = s.checkout();
        let elapsed = start.elapsed();
        assert!(err.is_err(), "second checkout should fail");
        assert!(
            elapsed >= Duration::from_millis(90),
            "expected to wait ~100ms, waited {:?}",
            elapsed
        );
        assert!(
            elapsed < Duration::from_millis(500),
            "waited too long: {:?}",
            elapsed
        );

        // Dropping the held guard returns the connection to the pool so a
        // subsequent checkout succeeds.
        drop(held);
        let _ = s.checkout().expect("checkout after release");
    }
}

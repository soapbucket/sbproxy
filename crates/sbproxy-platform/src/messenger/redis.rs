//! Redis Streams messenger backend using raw RESP protocol over TCP.
//!
//! Publishes messages with `XADD` and consumes them with `XREAD BLOCK`.
//! A single TCP connection is kept open per instance and protected by a
//! `Mutex` for thread safety.
//!
//! # Limitations
//! - One connection per instance. Not suitable for high-throughput use.
//! - The blocking `subscribe` iterator holds a dedicated connection for the
//!   duration of the subscription (connection is established on first `next()`).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use super::{Message, Messenger};

// --- RESP helpers (duplicated from storage/redis.rs to avoid cross-module coupling) ---

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

#[derive(Debug)]
enum RespValue {
    Nil,
    Bytes(Vec<u8>),
    #[allow(dead_code)]
    Integer(i64),
    Array(Vec<RespValue>),
}

fn read_resp(r: &mut BufReader<TcpStream>) -> Result<RespValue> {
    let mut line = String::new();
    r.read_line(&mut line)?;
    let trimmed = line.trim_end_matches("\r\n");

    let (prefix, rest) = trimmed.split_at(1);
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
            let mut buf = vec![0u8; len + 2];
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

// --- Connection ---

struct Connection {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
}

impl Connection {
    fn connect(addr: &str) -> Result<Self> {
        let stream =
            TcpStream::connect(addr).with_context(|| format!("connect to Redis at {}", addr))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let writer = stream.try_clone()?;
        let reader = BufReader::new(stream);
        Ok(Self { reader, writer })
    }

    /// Connect without a read timeout (for blocking XREAD subscriptions).
    fn connect_blocking(addr: &str) -> Result<Self> {
        let stream =
            TcpStream::connect(addr).with_context(|| format!("connect to Redis at {}", addr))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        // No read timeout: XREAD BLOCK 0 waits indefinitely.
        let writer = stream.try_clone()?;
        let reader = BufReader::new(stream);
        Ok(Self { reader, writer })
    }

    fn call(&mut self, args: &[&[u8]]) -> Result<RespValue> {
        write_command(&mut self.writer, args)?;
        read_resp(&mut self.reader)
    }
}

// --- Config ---

/// Configuration for [`RedisMessenger`].
pub struct RedisMessengerConfig {
    /// Redis server address, e.g. `"127.0.0.1:6379"`.
    pub addr: String,
}

impl Default for RedisMessengerConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1:6379".into(),
        }
    }
}

// --- RedisMessenger ---

/// Redis Streams-backed messenger.
///
/// `publish` uses `XADD {topic} * payload {json}`.
/// `subscribe` opens a dedicated blocking connection and issues
/// `XREAD BLOCK 0 STREAMS {topic} $` to receive new entries.
pub struct RedisMessenger {
    addr: String,
    conn: Mutex<Option<Connection>>,
}

impl RedisMessenger {
    /// Create a new Redis Streams messenger.
    pub fn new(config: RedisMessengerConfig) -> Self {
        Self {
            addr: config.addr,
            conn: Mutex::new(None),
        }
    }

    /// Execute a command on the shared (non-blocking) connection, reconnecting
    /// once on error.
    fn with_conn<F, T>(&self, mut f: F) -> Result<T>
    where
        F: FnMut(&mut Connection) -> Result<T>,
    {
        let mut guard = self.conn.lock().expect("lock poisoned");
        if guard.is_none() {
            *guard = Some(Connection::connect(&self.addr)?);
        }
        let conn = guard.as_mut().unwrap();
        match f(conn) {
            Ok(v) => Ok(v),
            Err(_) => {
                *guard = None;
                let mut fresh = Connection::connect(&self.addr)?;
                let v = f(&mut fresh)?;
                *guard = Some(fresh);
                Ok(v)
            }
        }
    }
}

impl Messenger for RedisMessenger {
    /// Publish by appending a new entry to the Redis Stream for the topic.
    ///
    /// Command: `XADD {topic} * payload {json_bytes}`
    fn publish(&self, msg: &Message) -> Result<()> {
        let topic = msg.topic.as_bytes().to_vec();
        let payload = serde_json::to_vec(msg).context("serialize message")?;
        self.with_conn(|c| {
            c.call(&[b"XADD", &topic, b"*", b"payload", &payload])?;
            Ok(())
        })
    }

    /// Subscribe to a topic via a dedicated blocking XREAD connection.
    ///
    /// The returned iterator blocks until a new entry arrives and terminates
    /// when the connection is closed or an error occurs.
    fn subscribe(&self, topic: &str) -> Result<Box<dyn Iterator<Item = Message> + Send>> {
        let addr = self.addr.clone();
        let topic = topic.to_string();
        Ok(Box::new(RedisStreamIterator::new(addr, topic)))
    }
}

// --- Iterator ---

/// Blocking iterator that reads from a Redis Stream using `XREAD BLOCK 0`.
struct RedisStreamIterator {
    addr: String,
    topic: String,
    /// Lazily initialised connection.
    conn: Option<Connection>,
    /// The last-seen stream entry ID; starts as `$` (only new entries).
    last_id: String,
}

impl RedisStreamIterator {
    fn new(addr: String, topic: String) -> Self {
        Self {
            addr,
            topic,
            conn: None,
            last_id: "$".to_string(),
        }
    }

    fn ensure_connected(&mut self) -> Result<()> {
        if self.conn.is_none() {
            self.conn = Some(Connection::connect_blocking(&self.addr)?);
        }
        Ok(())
    }

    /// Read the next batch from the stream.  Returns `None` on connection error.
    fn read_next(&mut self) -> Option<Vec<Message>> {
        if self.ensure_connected().is_err() {
            return None;
        }
        let topic_bytes = self.topic.as_bytes().to_vec();
        let last_id_bytes = self.last_id.as_bytes().to_vec();

        let conn = self.conn.as_mut()?;
        let resp = conn
            .call(&[
                b"XREAD",
                b"BLOCK",
                b"0",
                b"STREAMS",
                &topic_bytes,
                &last_id_bytes,
            ])
            .ok()?;

        self.parse_xread_response(resp)
    }

    /// Parse the nested RESP array returned by XREAD.
    ///
    /// Response shape:
    /// ```text
    /// *1                          ; one stream
    ///   *2
    ///     $<topic>                ; stream key
    ///     *N                      ; N entries
    ///       *2
    ///         $<id>               ; entry ID
    ///         *2
    ///           $"payload"        ; field name
    ///           $<json>           ; field value
    /// ```
    fn parse_xread_response(&mut self, resp: RespValue) -> Option<Vec<Message>> {
        let streams = match resp {
            RespValue::Array(a) => a,
            _ => return None,
        };

        let mut messages = Vec::new();

        for stream in streams {
            let stream_parts = match stream {
                RespValue::Array(a) if a.len() == 2 => a,
                _ => continue,
            };

            // stream_parts[0] = stream key (ignored; we subscribed to one topic)
            let entries = match &stream_parts[1] {
                RespValue::Array(a) => a,
                _ => continue,
            };

            for entry in entries {
                let entry_parts = match entry {
                    RespValue::Array(a) if a.len() == 2 => a,
                    _ => continue,
                };

                // Update last_id to this entry's ID.
                if let RespValue::Bytes(id_bytes) = &entry_parts[0] {
                    self.last_id = String::from_utf8_lossy(id_bytes).to_string();
                }

                // Fields array: [field_name, field_value, ...]
                let fields = match &entry_parts[1] {
                    RespValue::Array(a) => a,
                    _ => continue,
                };

                // Find the "payload" field.
                let mut i = 0;
                while i + 1 < fields.len() {
                    let is_payload = matches!(&fields[i], RespValue::Bytes(b) if b == b"payload");
                    if is_payload {
                        if let RespValue::Bytes(json_bytes) = &fields[i + 1] {
                            if let Ok(msg) = serde_json::from_slice::<Message>(json_bytes) {
                                messages.push(msg);
                            }
                        }
                        break;
                    }
                    i += 2;
                }
            }
        }

        Some(messages)
    }
}

impl Iterator for RedisStreamIterator {
    type Item = Message;

    fn next(&mut self) -> Option<Message> {
        loop {
            // Read a batch; if the connection died, stop iteration.
            let batch = self.read_next()?;
            if !batch.is_empty() {
                // We process one at a time. Buffer the rest in a simple way
                // by re-using the iterator state: just return the first and
                // the next call will issue another XREAD with the updated ID.
                // This trades latency for simplicity: extra RTTs are fine for
                // a single-connection implementation.
                return Some(batch.into_iter().next().unwrap());
            }
            // Empty batch (shouldn't happen with BLOCK 0) - retry.
        }
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_msg(topic: &str, payload: serde_json::Value) -> Message {
        Message {
            topic: topic.to_string(),
            payload,
            timestamp: 1000,
        }
    }

    #[test]
    fn config_defaults() {
        let cfg = RedisMessengerConfig::default();
        assert_eq!(cfg.addr, "127.0.0.1:6379");
    }

    #[test]
    fn parse_xread_response_valid() {
        // Build a synthetic XREAD response: one stream, one entry, one payload field.
        let msg = make_msg("events", json!({"action": "created"}));
        let json_bytes = serde_json::to_vec(&msg).unwrap();

        // Construct the nested RespValue that XREAD would return.
        let fields = RespValue::Array(vec![
            RespValue::Bytes(b"payload".to_vec()),
            RespValue::Bytes(json_bytes),
        ]);
        let entry = RespValue::Array(vec![RespValue::Bytes(b"1700000000000-0".to_vec()), fields]);
        let entries = RespValue::Array(vec![entry]);
        let stream = RespValue::Array(vec![RespValue::Bytes(b"events".to_vec()), entries]);
        let response = RespValue::Array(vec![stream]);

        let mut iter = RedisStreamIterator::new("127.0.0.1:6379".to_string(), "events".to_string());
        let messages = iter.parse_xread_response(response).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].topic, "events");
        assert_eq!(messages[0].payload["action"], "created");
        assert_eq!(iter.last_id, "1700000000000-0");
    }

    #[test]
    fn parse_xread_response_nil_returns_none() {
        let mut iter = RedisStreamIterator::new("127.0.0.1:6379".to_string(), "events".to_string());
        assert!(iter.parse_xread_response(RespValue::Nil).is_none());
    }

    #[test]
    #[ignore = "requires a running Redis instance on 127.0.0.1:6379"]
    fn live_publish_subscribe() {
        use std::sync::Arc;
        use std::thread;

        let messenger = Arc::new(RedisMessenger::new(RedisMessengerConfig::default()));
        let mut sub = messenger.subscribe("test.events").unwrap();

        let m = messenger.clone();
        let producer = thread::spawn(move || {
            // Small delay to let subscriber get ready.
            thread::sleep(Duration::from_millis(100));
            m.publish(&make_msg("test.events", json!({"action": "created"})))
                .unwrap();
        });

        let msg = sub.next().unwrap();
        assert_eq!(msg.payload["action"], "created");
        producer.join().unwrap();
    }
}

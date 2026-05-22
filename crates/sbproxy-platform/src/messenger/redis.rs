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

use std::io::BufReader;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};

use super::{Message, Messenger};
use crate::resp::{read_resp, write_command, RespValue};

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

    /// Connect for a blocking XREAD subscription with a bounded read timeout.
    ///
    /// The timeout is longer than the XREAD block window, so a normal idle
    /// period returns a nil reply first; the socket timeout only fires when
    /// Redis itself stops responding, which keeps the subscriber thread from
    /// wedging forever in an uninterruptible read (WOR-649).
    fn connect_blocking(addr: &str) -> Result<Self> {
        let stream =
            TcpStream::connect(addr).with_context(|| format!("connect to Redis at {}", addr))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        stream.set_read_timeout(Some(XREAD_SOCKET_READ_TIMEOUT))?;
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
/// `XREAD BLOCK {ms} STREAMS {topic} $` on a bounded window so the
/// subscriber can observe cancellation between reads.
pub struct RedisMessenger {
    addr: String,
    conn: Mutex<Option<Connection>>,
    /// Shared cancel flag handed to every subscription iterator. Set on drop
    /// (or via [`RedisMessenger::stop`]) so an idle subscriber exits within
    /// one XREAD block window instead of parking forever (WOR-649).
    stop: Arc<AtomicBool>,
}

impl RedisMessenger {
    /// Create a new Redis Streams messenger.
    pub fn new(config: RedisMessengerConfig) -> Self {
        Self {
            addr: config.addr,
            conn: Mutex::new(None),
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Signal every live subscription iterator to stop. After this, each
    /// iterator's `next` returns `None` within one XREAD block window. Called
    /// automatically on drop; exposed for callers that want to stop
    /// subscriptions while keeping the messenger alive.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
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
    /// The returned iterator blocks (in bounded windows) until a new entry
    /// arrives and terminates when the messenger is dropped or stopped, the
    /// connection cannot be re-established, or a malformed reply is seen.
    fn subscribe(&self, topic: &str) -> Result<Box<dyn Iterator<Item = Message> + Send>> {
        let addr = self.addr.clone();
        let topic = topic.to_string();
        Ok(Box::new(RedisStreamIterator::new(
            addr,
            topic,
            self.stop.clone(),
        )))
    }
}

impl Drop for RedisMessenger {
    fn drop(&mut self) {
        // Stop any iterators that outlive the messenger so they unwind on the
        // next block-window boundary rather than blocking a thread forever.
        self.stop();
    }
}

// --- Iterator ---

/// Milliseconds XREAD blocks before returning a nil reply when no new entries
/// arrive. Bounded (not `0`) so the subscriber loop regains control roughly
/// once per window and can observe shutdown between reads (WOR-649).
const XREAD_BLOCK_MS: &[u8] = b"1000";

/// Socket read timeout for the blocking subscription. Longer than the XREAD
/// block window so a normal block expiry returns first; this only fires when
/// Redis stops responding entirely.
const XREAD_SOCKET_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Blocking iterator that reads from a Redis Stream using a bounded `XREAD
/// BLOCK` window.
struct RedisStreamIterator {
    addr: String,
    topic: String,
    /// Lazily initialised connection.
    conn: Option<Connection>,
    /// The last-seen stream entry ID; starts as `$` (only new entries).
    last_id: String,
    /// Shared cancel flag. When set, `next` returns `None` (ending iteration)
    /// at the next block-window boundary (WOR-649).
    stop: Arc<AtomicBool>,
}

impl RedisStreamIterator {
    fn new(addr: String, topic: String, stop: Arc<AtomicBool>) -> Self {
        Self {
            addr,
            topic,
            conn: None,
            last_id: "$".to_string(),
            stop,
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
        match conn.call(&[
            b"XREAD",
            b"BLOCK",
            XREAD_BLOCK_MS,
            b"STREAMS",
            &topic_bytes,
            &last_id_bytes,
        ]) {
            // Block window expired with no new entries (RESP nil): hand back an
            // empty batch so `next` loops and re-issues, giving the caller a
            // chance to observe shutdown between reads instead of parking.
            Ok(RespValue::Nil) => Some(Vec::new()),
            Ok(resp) => self.parse_xread_response(resp),
            // Read timeout or transient I/O error: drop the connection so the
            // next read reconnects (last_id is preserved on the iterator), and
            // retry rather than silently ending the subscription. A genuinely
            // unreachable Redis surfaces when the reconnect in `ensure_connected`
            // fails, which ends iteration cleanly.
            Err(_) => {
                self.conn = None;
                Some(Vec::new())
            }
        }
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
            // Cancellation check (WOR-649). The bounded XREAD block returns at
            // least once per window, so a stop signalled mid-wait is observed
            // here within ~one block window and ends iteration cleanly.
            if self.stop.load(Ordering::Relaxed) {
                return None;
            }
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
            // Empty batch: the bounded block expired (or a transient error
            // dropped the connection). Loop and re-issue; this is the point
            // where a caller driving the iterator can step out on shutdown.
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
    fn xread_block_is_bounded_and_under_socket_timeout() {
        // WOR-649: XREAD must use a bounded, non-zero block so the subscriber
        // loop regains control periodically, and that window must be shorter
        // than the socket read timeout so a normal idle period returns a nil
        // reply (handled as "retry") instead of tripping the timeout.
        let block_ms: u64 = std::str::from_utf8(XREAD_BLOCK_MS)
            .unwrap()
            .parse()
            .unwrap();
        assert!(block_ms > 0, "XREAD block must be bounded, not 0");
        assert!(
            Duration::from_millis(block_ms) < XREAD_SOCKET_READ_TIMEOUT,
            "block window must be shorter than the socket read timeout"
        );
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

        let mut iter = RedisStreamIterator::new(
            "127.0.0.1:6379".to_string(),
            "events".to_string(),
            Arc::new(AtomicBool::new(false)),
        );
        let messages = iter.parse_xread_response(response).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].topic, "events");
        assert_eq!(messages[0].payload["action"], "created");
        assert_eq!(iter.last_id, "1700000000000-0");
    }

    #[test]
    fn parse_xread_response_nil_returns_none() {
        let mut iter = RedisStreamIterator::new(
            "127.0.0.1:6379".to_string(),
            "events".to_string(),
            Arc::new(AtomicBool::new(false)),
        );
        assert!(iter.parse_xread_response(RespValue::Nil).is_none());
    }

    #[test]
    fn subscribe_iterator_stops_when_cancelled() {
        // WOR-649: a cancelled subscription ends iteration without needing a
        // live connection. The stop flag is checked before any read, so a
        // pre-cancelled iterator returns None immediately (no socket attempt).
        let stop = Arc::new(AtomicBool::new(true));
        let mut iter = RedisStreamIterator::new(
            "127.0.0.1:1".to_string(), // unreachable port; must not be dialed
            "events".to_string(),
            stop,
        );
        assert!(
            iter.next().is_none(),
            "a cancelled subscription must end iteration"
        );
    }

    #[test]
    fn dropping_messenger_signals_subscriptions_to_stop() {
        // The messenger's drop sets the shared stop flag, so an iterator that
        // outlives it ends iteration rather than blocking a thread forever.
        let messenger = RedisMessenger::new(RedisMessengerConfig::default());
        let stop = messenger.stop.clone();
        assert!(!stop.load(Ordering::Relaxed));
        drop(messenger);
        assert!(stop.load(Ordering::Relaxed), "drop must signal stop");
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

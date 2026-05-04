//! Request coalescing - deduplicates concurrent identical requests.
//!
//! When multiple clients request the same resource simultaneously, only one
//! upstream request is made and the response is shared with all waiters.

use bytes::Bytes;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

/// Hard cap on distinct in-flight keys. The coalescer's map is keyed by
/// request-derived strings; without a cap, an attacker could send a stream
/// of unique URLs to grow the map without bound and exhaust memory. When
/// the cap is reached, new distinct keys fall through as uncoalesced
/// requests (the leader proceeds without deduping), which degrades
/// throughput but never crashes the proxy.
pub const DEFAULT_MAX_IN_FLIGHT_KEYS: usize = 10_000;

/// Response from a coalesced request.
#[derive(Debug, Clone)]
pub struct CoalescedResponse {
    /// HTTP status code from the upstream response.
    pub status: u16,
    /// Response headers as `(name, value)` pairs.
    pub headers: Vec<(String, String)>,
    /// Response body bytes.
    pub body: Bytes,
}

/// Request coalescer - deduplicates in-flight identical requests.
///
/// The first request for a given key becomes the "leader" and proceeds upstream.
/// Subsequent requests for the same key receive a broadcast receiver and wait
/// for the leader to complete.
pub struct RequestCoalescer {
    in_flight: Mutex<HashMap<String, broadcast::Sender<Arc<CoalescedResponse>>>>,
    max_waiters: usize,
    max_keys: usize,
}

impl RequestCoalescer {
    /// Create a new coalescer with the given maximum number of waiters per key.
    pub fn new(max_waiters: usize) -> Self {
        Self::with_max_keys(max_waiters, DEFAULT_MAX_IN_FLIGHT_KEYS)
    }

    /// Create a coalescer with an explicit cap on distinct in-flight keys.
    pub fn with_max_keys(max_waiters: usize, max_keys: usize) -> Self {
        Self {
            in_flight: Mutex::new(HashMap::new()),
            max_waiters,
            max_keys,
        }
    }

    /// Check if a request is already in flight.
    ///
    /// Returns `Some(receiver)` if we should wait for an existing request,
    /// or `None` if we should proceed (we are the leader or the coalescer
    /// is at capacity; in both cases the caller should issue its own
    /// upstream request).
    pub fn check_or_register(
        &self,
        key: &str,
    ) -> Option<broadcast::Receiver<Arc<CoalescedResponse>>> {
        let mut in_flight = self.in_flight.lock().unwrap();
        if let Some(sender) = in_flight.get(key) {
            // Request already in flight - subscribe to its result
            return Some(sender.subscribe());
        }
        if in_flight.len() >= self.max_keys {
            // Capacity reached. Rather than blow memory, disable
            // coalescing for this request: the caller proceeds as an
            // uncoalesced leader and we simply don't track it.
            return None;
        }
        // We are the leader - register ourselves
        let (tx, _) = broadcast::channel(self.max_waiters);
        in_flight.insert(key.to_string(), tx);
        None
    }

    /// Complete a coalesced request, notifying all waiters with the response.
    pub fn complete(&self, key: &str, response: CoalescedResponse) {
        let mut in_flight = self.in_flight.lock().unwrap();
        if let Some(sender) = in_flight.remove(key) {
            // Ignore send errors (no receivers is fine)
            let _ = sender.send(Arc::new(response));
        }
    }

    /// Cancel a coalesced request (e.g., on upstream error).
    ///
    /// Removes the key from the in-flight map. Any waiters that subscribed
    /// will receive a `RecvError` when the sender is dropped.
    pub fn cancel(&self, key: &str) {
        self.in_flight.lock().unwrap().remove(key);
    }

    /// Return the number of currently in-flight coalesced keys.
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_request_becomes_leader() {
        let coalescer = RequestCoalescer::new(16);
        let result = coalescer.check_or_register("GET:/api/data");
        assert!(result.is_none(), "First request should be the leader");
        assert_eq!(coalescer.in_flight_count(), 1);
    }

    #[test]
    fn second_request_gets_receiver() {
        let coalescer = RequestCoalescer::new(16);
        let _ = coalescer.check_or_register("GET:/api/data");
        let result = coalescer.check_or_register("GET:/api/data");
        assert!(result.is_some(), "Second request should get a receiver");
        assert_eq!(coalescer.in_flight_count(), 1);
    }

    #[test]
    fn different_keys_are_independent() {
        let coalescer = RequestCoalescer::new(16);
        let r1 = coalescer.check_or_register("GET:/api/a");
        let r2 = coalescer.check_or_register("GET:/api/b");
        assert!(r1.is_none());
        assert!(r2.is_none());
        assert_eq!(coalescer.in_flight_count(), 2);
    }

    #[tokio::test]
    async fn complete_notifies_waiters() {
        let coalescer = Arc::new(RequestCoalescer::new(16));

        // Leader registers
        let _ = coalescer.check_or_register("key1");

        // Waiter subscribes
        let mut rx = coalescer.check_or_register("key1").unwrap();

        // Leader completes
        coalescer.complete(
            "key1",
            CoalescedResponse {
                status: 200,
                headers: vec![("content-type".to_string(), "text/plain".to_string())],
                body: Bytes::from("hello"),
            },
        );

        let response = rx.recv().await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, Bytes::from("hello"));
        assert_eq!(coalescer.in_flight_count(), 0);
    }

    #[test]
    fn cancel_removes_key() {
        let coalescer = RequestCoalescer::new(16);
        let _ = coalescer.check_or_register("key1");
        assert_eq!(coalescer.in_flight_count(), 1);
        coalescer.cancel("key1");
        assert_eq!(coalescer.in_flight_count(), 0);
    }

    #[test]
    fn cancel_nonexistent_key_is_noop() {
        let coalescer = RequestCoalescer::new(16);
        coalescer.cancel("nonexistent");
        assert_eq!(coalescer.in_flight_count(), 0);
    }

    #[test]
    fn cap_stops_map_growth_and_disables_coalescing() {
        // With max_keys = 2, the third distinct key should fall through
        // as uncoalesced (None returned) without inserting anything.
        let coalescer = RequestCoalescer::with_max_keys(16, 2);
        assert!(coalescer.check_or_register("a").is_none());
        assert!(coalescer.check_or_register("b").is_none());
        assert_eq!(coalescer.in_flight_count(), 2);
        // Third distinct key: at capacity -> None, but map size unchanged.
        assert!(coalescer.check_or_register("c").is_none());
        assert_eq!(coalescer.in_flight_count(), 2);
        // Existing key still coalesces.
        assert!(coalescer.check_or_register("a").is_some());
        assert_eq!(coalescer.in_flight_count(), 2);
    }

    #[tokio::test]
    async fn cancel_causes_recv_error_for_waiters() {
        let coalescer = RequestCoalescer::new(16);
        let _ = coalescer.check_or_register("key1");
        let mut rx = coalescer.check_or_register("key1").unwrap();

        // Cancel drops the sender
        coalescer.cancel("key1");

        // Waiter should get an error
        let result = rx.recv().await;
        assert!(result.is_err());
    }
}

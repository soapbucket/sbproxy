use std::collections::BTreeMap;

use parking_lot::Mutex;

use super::DispatchEnvelopeError;

/// Bounded, expiry-aware replay protection keyed by issuer and nonce.
pub struct DispatchReplayFence {
    capacity: usize,
    entries: Mutex<BTreeMap<(String, String), u64>>,
}

impl std::fmt::Debug for DispatchReplayFence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DispatchReplayFence")
            .field("capacity", &self.capacity)
            .field("live_entries", &self.entries.lock().len())
            .finish()
    }
}

impl DispatchReplayFence {
    /// Create a fence with a fixed maximum number of live entries.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(BTreeMap::new()),
        }
    }

    /// Atomically reject a live duplicate or record a new issuer and nonce.
    pub fn check_and_record(
        &self,
        issuer: &str,
        nonce: &str,
        expires_at_unix_ms: u64,
        now_unix_ms: u64,
    ) -> Result<(), DispatchEnvelopeError> {
        if issuer.is_empty()
            || issuer.len() > 128
            || nonce.is_empty()
            || nonce.len() > 128
            || expires_at_unix_ms <= now_unix_ms
        {
            return Err(DispatchEnvelopeError::InvalidEnvelope);
        }
        let mut entries = self.entries.lock();
        entries.retain(|_, expiry| *expiry > now_unix_ms);
        let key = (issuer.to_string(), nonce.to_string());
        if entries.contains_key(&key) {
            return Err(DispatchEnvelopeError::ReplayDetected);
        }
        if entries.len() >= self.capacity {
            return Err(DispatchEnvelopeError::ReplayFenceFull);
        }
        entries.insert(key, expires_at_unix_ms);
        Ok(())
    }
}

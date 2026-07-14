use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use parking_lot::Mutex;

use super::DispatchEnvelopeError;

/// Bounded, expiry-aware replay protection keyed by issuer and nonce.
pub struct DispatchReplayFence {
    capacity: usize,
    entries: Mutex<ReplayEntries>,
    #[cfg(test)]
    prune_visits: AtomicUsize,
}

type ReplayKey = (String, String);

#[derive(Default)]
struct ReplayEntries {
    by_key: HashMap<ReplayKey, u64>,
    by_expiry: BinaryHeap<Reverse<(u64, ReplayKey)>>,
}

impl std::fmt::Debug for DispatchReplayFence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DispatchReplayFence")
            .field("capacity", &self.capacity)
            .field("live_entries", &self.entries.lock().by_key.len())
            .finish()
    }
}

impl DispatchReplayFence {
    /// Create a fence with a fixed maximum number of live entries.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(ReplayEntries::default()),
            #[cfg(test)]
            prune_visits: AtomicUsize::new(0),
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
        while let Some(Reverse((expiry, _))) = entries.by_expiry.peek() {
            #[cfg(test)]
            self.prune_visits.fetch_add(1, Ordering::Relaxed);
            if *expiry > now_unix_ms {
                break;
            }
            let Reverse((expiry, key)) = entries
                .by_expiry
                .pop()
                .expect("peeked replay expiry must remain present under the lock");
            if entries.by_key.get(&key) == Some(&expiry) {
                entries.by_key.remove(&key);
            }
        }
        let key = (issuer.to_string(), nonce.to_string());
        if entries.by_key.contains_key(&key) {
            return Err(DispatchEnvelopeError::ReplayDetected);
        }
        if entries.by_key.len() >= self.capacity {
            return Err(DispatchEnvelopeError::ReplayFenceFull);
        }
        entries.by_key.insert(key.clone(), expires_at_unix_ms);
        entries.by_expiry.push(Reverse((expires_at_unix_ms, key)));
        Ok(())
    }

    #[cfg(test)]
    fn reset_prune_visits(&self) {
        self.prune_visits.store(0, Ordering::Relaxed);
    }

    #[cfg(test)]
    fn prune_visits(&self) -> usize {
        self.prune_visits.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pruning_visits_only_the_expired_prefix_and_next_live_entry() {
        const EXPIRED: usize = 8;
        const LIVE: usize = 512;
        let fence = DispatchReplayFence::new(EXPIRED + LIVE + 1);

        for index in 0..EXPIRED {
            fence
                .check_and_record("gateway", &format!("expired-{index}"), 10, 0)
                .unwrap();
        }
        for index in 0..LIVE {
            fence
                .check_and_record("gateway", &format!("live-{index}"), 1_000, 0)
                .unwrap();
        }

        fence.reset_prune_visits();
        fence.check_and_record("gateway", "new", 1_000, 10).unwrap();

        assert!(
            fence.prune_visits() <= EXPIRED + 1,
            "pruning inspected {} entries for an expired prefix of {EXPIRED}",
            fence.prune_visits()
        );
    }
}

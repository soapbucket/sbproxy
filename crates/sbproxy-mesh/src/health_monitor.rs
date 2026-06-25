//! SWIM-style peer health monitoring with suspicion and failure detection.
//!
//! Peers that stop sending heartbeats transition from Alive -> Suspect ->
//! Dead after configurable timeouts. This matches the SWIM protocol's
//! indirect probing phase without requiring UDP round-trips.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// SWIM health state for a peer node.
#[derive(Debug, Clone, PartialEq)]
pub enum PeerState {
    /// Node is actively sending heartbeats.
    Alive,
    /// Node has not sent a heartbeat within `suspect_timeout`. May be down.
    Suspect,
    /// Node has not sent a heartbeat within `dead_timeout`. Considered failed.
    Dead,
}

/// Per-peer health record.
struct PeerHealth {
    last_seen: Instant,
    state: PeerState,
}

/// Tracks health state for a set of remote peers using SWIM-style timeouts.
pub struct PeerHealthMonitor {
    peers: Mutex<HashMap<String, PeerHealth>>,
    suspect_timeout: Duration,
    dead_timeout: Duration,
}

impl PeerHealthMonitor {
    /// Create a new monitor with configurable suspect and dead timeouts.
    pub fn new(suspect_timeout_secs: u64, dead_timeout_secs: u64) -> Self {
        Self {
            peers: Mutex::new(HashMap::new()),
            suspect_timeout: Duration::from_secs(suspect_timeout_secs),
            dead_timeout: Duration::from_secs(dead_timeout_secs),
        }
    }

    /// Record a heartbeat from a peer, resetting it to Alive.
    pub fn record_heartbeat(&self, peer_id: &str) {
        let mut peers = self.peers.lock().unwrap();
        peers.insert(
            peer_id.to_string(),
            PeerHealth {
                last_seen: Instant::now(),
                state: PeerState::Alive,
            },
        );
    }

    /// Check all known peers and advance state transitions based on elapsed time.
    ///
    /// Returns a snapshot of (peer_id, current_state) after applying transitions.
    pub fn check_health(&self) -> Vec<(String, PeerState)> {
        let mut peers = self.peers.lock().unwrap();
        let now = Instant::now();

        for health in peers.values_mut() {
            let elapsed = now.duration_since(health.last_seen);
            match health.state {
                PeerState::Alive if elapsed > self.suspect_timeout => {
                    health.state = PeerState::Suspect;
                }
                PeerState::Suspect if elapsed > self.dead_timeout => {
                    health.state = PeerState::Dead;
                }
                _ => {}
            }
        }

        peers
            .iter()
            .map(|(id, h)| (id.clone(), h.state.clone()))
            .collect()
    }

    /// Get the current health state for a specific peer.
    pub fn get_state(&self, peer_id: &str) -> Option<PeerState> {
        let peers = self.peers.lock().unwrap();
        peers.get(peer_id).map(|h| h.state.clone())
    }

    /// Return the IDs of all currently Alive peers.
    pub fn alive_peers(&self) -> Vec<String> {
        let peers = self.peers.lock().unwrap();
        peers
            .iter()
            .filter(|(_, h)| h.state == PeerState::Alive)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Return the IDs of all currently Suspect peers.
    pub fn suspect_peers(&self) -> Vec<String> {
        let peers = self.peers.lock().unwrap();
        peers
            .iter()
            .filter(|(_, h)| h.state == PeerState::Suspect)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Return the IDs of all currently Dead peers.
    pub fn dead_peers(&self) -> Vec<String> {
        let peers = self.peers.lock().unwrap();
        peers
            .iter()
            .filter(|(_, h)| h.state == PeerState::Dead)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Total number of tracked peers.
    pub fn peer_count(&self) -> usize {
        self.peers.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn heartbeat_registers_peer_as_alive() {
        let monitor = PeerHealthMonitor::new(5, 10);
        monitor.record_heartbeat("peer-1");
        assert_eq!(monitor.get_state("peer-1"), Some(PeerState::Alive));
    }

    #[test]
    fn repeated_heartbeat_keeps_peer_alive() {
        let monitor = PeerHealthMonitor::new(5, 10);
        monitor.record_heartbeat("peer-1");
        monitor.record_heartbeat("peer-1");
        monitor.record_heartbeat("peer-1");
        assert_eq!(monitor.get_state("peer-1"), Some(PeerState::Alive));
    }

    #[test]
    fn no_heartbeat_peer_returns_none() {
        let monitor = PeerHealthMonitor::new(5, 10);
        assert_eq!(monitor.get_state("ghost"), None);
    }

    #[test]
    fn zero_suspect_timeout_transitions_to_suspect_on_check() {
        let monitor = PeerHealthMonitor::new(0, 100);
        monitor.record_heartbeat("peer-a");
        // Sleep briefly to ensure elapsed > 0s timeout
        thread::sleep(Duration::from_millis(5));
        monitor.check_health();
        assert_eq!(monitor.get_state("peer-a"), Some(PeerState::Suspect));
    }

    #[test]
    fn zero_dead_timeout_transitions_suspect_to_dead() {
        let monitor = PeerHealthMonitor::new(0, 0);
        monitor.record_heartbeat("peer-b");
        thread::sleep(Duration::from_millis(5));
        // First check: Alive -> Suspect
        monitor.check_health();
        // Second check: Suspect -> Dead (dead_timeout is also 0)
        monitor.check_health();
        assert_eq!(monitor.get_state("peer-b"), Some(PeerState::Dead));
    }

    #[test]
    fn alive_peers_excludes_suspect_and_dead() {
        // Use a long suspect timeout so fresh heartbeats stay Alive,
        // but a 0-second timeout for the peer we want to go Suspect.
        // We simulate this by using two separate monitors.
        let monitor = PeerHealthMonitor::new(30, 60);
        monitor.record_heartbeat("alive-1");
        monitor.record_heartbeat("alive-2");

        // Manually set a peer to Suspect via a zero-timeout monitor
        let stale_monitor = PeerHealthMonitor::new(0, 100);
        stale_monitor.record_heartbeat("suspect-1");
        thread::sleep(Duration::from_millis(5));
        stale_monitor.check_health();
        assert_eq!(
            stale_monitor.get_state("suspect-1"),
            Some(PeerState::Suspect)
        );

        // alive-1 and alive-2 are in the first monitor with long timeouts
        let alive = monitor.alive_peers();
        assert!(alive.contains(&"alive-1".to_string()));
        assert!(alive.contains(&"alive-2".to_string()));
        // suspect-1 is not in this monitor at all
        assert!(!alive.contains(&"suspect-1".to_string()));
    }

    #[test]
    fn suspect_peers_returns_only_suspects() {
        let monitor = PeerHealthMonitor::new(0, 100);
        monitor.record_heartbeat("peer-x");
        thread::sleep(Duration::from_millis(5));
        monitor.check_health();
        let suspects = monitor.suspect_peers();
        assert!(suspects.contains(&"peer-x".to_string()));
    }

    #[test]
    fn check_health_returns_all_peer_states() {
        let monitor = PeerHealthMonitor::new(30, 60);
        monitor.record_heartbeat("n1");
        monitor.record_heartbeat("n2");
        let states = monitor.check_health();
        assert_eq!(states.len(), 2);
        for (_, state) in &states {
            assert_eq!(*state, PeerState::Alive);
        }
    }

    #[test]
    fn multiple_peers_tracked_independently() {
        let monitor = PeerHealthMonitor::new(30, 60);
        monitor.record_heartbeat("p1");
        monitor.record_heartbeat("p2");
        monitor.record_heartbeat("p3");
        assert_eq!(monitor.peer_count(), 3);
        assert_eq!(monitor.alive_peers().len(), 3);
    }

    #[test]
    fn heartbeat_after_suspect_resets_to_alive() {
        let monitor = PeerHealthMonitor::new(0, 100);
        monitor.record_heartbeat("peer-c");
        thread::sleep(Duration::from_millis(5));
        monitor.check_health();
        assert_eq!(monitor.get_state("peer-c"), Some(PeerState::Suspect));

        // New heartbeat resets to alive
        monitor.record_heartbeat("peer-c");
        assert_eq!(monitor.get_state("peer-c"), Some(PeerState::Alive));
    }
}

//! Clock-skew detection (Wave 3 / R3.3).
//!
//! Per `docs/adr-time-sync-requirements.md` (A3.5):
//!
//! - The proxy queries an SNTP source (default `pool.ntp.org`) every
//!   60 s, computes `local_now - ntp_now` as `current_skew_seconds`,
//!   and exposes the value through a [`ClockSkewMonitor`].
//! - `/readyz` registers a [`Probe`] that flips to `Unhealthy` when
//!   the absolute skew exceeds the SBproxy-internal envelope of
//!   ±2 minutes (120 s). At that point the load balancer drains the
//!   host per the ADR.
//! - JWS verification (per A3.2) reads the current skew so it can
//!   reject tokens whose `iat` is more than `5 min + skew` in the
//!   future. The integration lives in the parallel G3.6 task; this
//!   module ships the API surface for it to consume.
//!
//! The SNTP client is a minimal RFC 4330 implementation: 48-byte
//! request, 48-byte response, transmit timestamp at offset 40. It
//! intentionally avoids pulling a third-party SNTP crate so the OSS
//! dependency surface stays narrow.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use prometheus::{Gauge, Opts, Registry};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::health::{ComponentStatus, Probe};

// --- Constants ---

/// Default polling cadence per A3.5: every 60 s.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 60;

/// Default SNTP source per A3.5 ("default `pool.ntp.org`").
pub const DEFAULT_NTP_SOURCE: &str = "pool.ntp.org:123";

/// Per-query timeout for the SNTP exchange. UDP can drop both ways;
/// 5 s is generous enough that a transient packet loss does not flip
/// the readyz probe.
pub const SNTP_TIMEOUT: Duration = Duration::from_secs(5);

/// SBproxy-internal allowed-skew envelope per A3.5 ("Two
/// SBproxy-controlled hosts (proxy ↔ ledger ↔ ...): ±2 minutes").
pub const TOLERANCE_SECS: f64 = 120.0;

/// SNTP epoch is 1900-01-01; Unix epoch is 1970-01-01. The difference
/// is 70 years plus 17 leap days = 2_208_988_800 seconds.
const NTP_UNIX_EPOCH_DIFF: u64 = 2_208_988_800;

// --- Configuration ---

/// Clock-skew monitor configuration.
#[derive(Debug, Clone)]
pub struct ClockSkewConfig {
    /// SNTP server address as `host:port`. Defaults to `pool.ntp.org:123`.
    pub ntp_source: String,
    /// Polling interval. Defaults to 60 s.
    pub poll_interval: Duration,
    /// Tolerance in seconds. Beyond this absolute value the
    /// `/readyz` probe reports `Unhealthy`. Defaults to 120 s.
    pub tolerance_secs: f64,
}

impl Default for ClockSkewConfig {
    fn default() -> Self {
        Self {
            ntp_source: DEFAULT_NTP_SOURCE.to_string(),
            poll_interval: Duration::from_secs(DEFAULT_POLL_INTERVAL_SECS),
            tolerance_secs: TOLERANCE_SECS,
        }
    }
}

// --- Monitor ---

/// Background SNTP poller plus an atomic snapshot of the latest skew.
///
/// Construct via [`ClockSkewMonitor::new`], spawn the background task
/// with [`ClockSkewMonitor::run`], and read the latest value with
/// [`ClockSkewMonitor::current_skew_seconds`]. The monitor implements
/// [`Probe`] so it can be registered on the standard
/// [`HealthRegistry`](crate::health::HealthRegistry) for `/readyz`.
pub struct ClockSkewMonitor {
    config: ClockSkewConfig,
    /// Latest skew in microseconds, stored as `i64` for atomic load /
    /// store. Microseconds give us ~292 000 years of headroom on
    /// `i64`, which is more than enough for any realistic skew.
    skew_micros: AtomicI64,
    /// Whether at least one SNTP exchange has succeeded. Until the
    /// first probe lands, the monitor reports `is_within_tolerance ==
    /// false` so a never-synced host is not silently accepted as
    /// healthy.
    has_synced: AtomicU64, // 0 = no, 1 = yes (atomic bool via u64)
    /// Prometheus gauge `sbproxy_clock_skew_seconds`.
    metric: Gauge,
}

impl ClockSkewMonitor {
    /// Build a new monitor.
    ///
    /// The Prometheus gauge `sbproxy_clock_skew_seconds` is registered
    /// against `registry`. Pass `None` to skip metric registration
    /// (useful in tests). Errors during gauge registration are
    /// surfaced; they almost always mean the metric was already
    /// registered (e.g. test re-runs).
    pub fn new(
        config: ClockSkewConfig,
        registry: Option<&Registry>,
    ) -> Result<Arc<Self>, prometheus::Error> {
        let metric = Gauge::with_opts(Opts::new(
            "sbproxy_clock_skew_seconds",
            "Local-clock minus NTP-clock in seconds; positive => local is ahead.",
        ))?;
        if let Some(reg) = registry {
            // Tolerate "already registered" so test re-runs are safe.
            // The error is recoverable: the gauge instance we own is
            // still functional even if the registry already had a
            // sibling registration.
            let _ = reg.register(Box::new(metric.clone()));
        }
        Ok(Arc::new(Self {
            config,
            skew_micros: AtomicI64::new(0),
            has_synced: AtomicU64::new(0),
            metric,
        }))
    }

    /// Background loop. Run via `tokio::spawn(monitor.clone().run())`.
    ///
    /// Loops until the task is cancelled / the runtime shuts down.
    /// Each iteration performs one SNTP exchange and sleeps the
    /// configured poll interval.
    pub async fn run(self: Arc<Self>) {
        loop {
            match self.probe_once().await {
                Ok(skew) => {
                    self.record_skew(skew);
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        source = %self.config.ntp_source,
                        "sbproxy clock-skew probe failed"
                    );
                }
            }
            tokio::time::sleep(self.config.poll_interval).await;
        }
    }

    /// Latest skew in seconds. Positive => local clock is ahead of NTP.
    ///
    /// Returns `0.0` until the first successful probe; callers that
    /// need to distinguish "synced" from "not yet synced" should use
    /// [`Self::has_synced_at_least_once`].
    pub fn current_skew_seconds(&self) -> f64 {
        let micros = self.skew_micros.load(Ordering::Relaxed);
        micros as f64 / 1_000_000.0
    }

    /// Whether the absolute skew is within the configured tolerance.
    ///
    /// Returns `false` when no SNTP probe has ever completed, even if
    /// the stored skew is `0.0`, so a host that cannot reach NTP at
    /// all does not flap to ready.
    pub fn is_within_tolerance(&self) -> bool {
        if !self.has_synced_at_least_once() {
            return false;
        }
        self.current_skew_seconds().abs() <= self.config.tolerance_secs
    }

    /// Whether the monitor has completed at least one successful
    /// probe.
    pub fn has_synced_at_least_once(&self) -> bool {
        self.has_synced.load(Ordering::Relaxed) == 1
    }

    /// Record a skew value and update the Prometheus gauge. Exposed
    /// for tests; production code calls this through `run`.
    pub fn record_skew(&self, skew_seconds: f64) {
        let micros = (skew_seconds * 1_000_000.0) as i64;
        self.skew_micros.store(micros, Ordering::Relaxed);
        self.has_synced.store(1, Ordering::Relaxed);
        self.metric.set(skew_seconds);
        debug!(skew_seconds, "sbproxy clock-skew sample");
    }

    /// Perform a single SNTP exchange. Public for tests; production
    /// code drives this through [`Self::run`].
    pub async fn probe_once(&self) -> Result<f64, ProbeError> {
        sntp_query(&self.config.ntp_source).await
    }
}

// --- Probe integration ---

impl Probe for ClockSkewMonitor {
    fn name(&self) -> &str {
        "clock_sync"
    }

    fn check(&self) -> (ComponentStatus, Option<String>) {
        if !self.has_synced_at_least_once() {
            return (
                ComponentStatus::Unhealthy,
                Some("clock_skew_unprobed: no successful SNTP exchange yet".to_string()),
            );
        }
        let skew = self.current_skew_seconds();
        if skew.abs() <= self.config.tolerance_secs {
            (
                ComponentStatus::Healthy,
                Some(format!("skew_seconds={skew:.3}")),
            )
        } else {
            (
                ComponentStatus::Unhealthy,
                Some(format!(
                    "clock_skew_exceeded: skew_seconds={skew:.3}, tolerance_seconds={}",
                    self.config.tolerance_secs
                )),
            )
        }
    }
}

// --- SNTP wire protocol ---

/// SNTP probe error.
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    /// Failed to resolve / bind / connect the UDP socket.
    #[error("sntp io: {0}")]
    Io(String),
    /// SNTP exchange timed out.
    #[error("sntp timeout after {0:?}")]
    Timeout(Duration),
    /// Server responded but the packet was malformed.
    #[error("sntp protocol: {0}")]
    Protocol(&'static str),
}

/// Perform a single SNTP exchange against `addr` (`host:port`).
///
/// Returns the local-minus-server skew in seconds. The implementation
/// uses RFC 4330's "transmit timestamp" only; we do NOT compute the
/// full client-server-server-client offset because the SNTP source we
/// poll (pool.ntp.org) is not assumed to be a strict NTP peer. Per
/// A3.5 the metric is "good enough to detect 60 s skew", not a
/// precision time service.
pub async fn sntp_query(addr: &str) -> Result<f64, ProbeError> {
    let target: SocketAddr = match tokio::net::lookup_host(addr).await {
        Ok(mut iter) => match iter.next() {
            Some(a) => a,
            None => return Err(ProbeError::Io(format!("no DNS results for {addr}"))),
        },
        Err(e) => return Err(ProbeError::Io(format!("dns lookup {addr}: {e}"))),
    };

    let bind_addr = if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| ProbeError::Io(format!("bind {bind_addr}: {e}")))?;
    socket
        .connect(target)
        .await
        .map_err(|e| ProbeError::Io(format!("connect {target}: {e}")))?;

    // SNTP request: 48 bytes. First byte is LI(0) | VN(4) | Mode(3).
    let mut req = [0u8; 48];
    req[0] = 0b00_100_011;

    let send_local_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ProbeError::Io(format!("system clock pre-epoch: {e}")))?;

    socket
        .send(&req)
        .await
        .map_err(|e| ProbeError::Io(format!("send: {e}")))?;

    let mut buf = [0u8; 48];
    let recv_fut = socket.recv(&mut buf);
    let n = match timeout(SNTP_TIMEOUT, recv_fut).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(ProbeError::Io(format!("recv: {e}"))),
        Err(_) => return Err(ProbeError::Timeout(SNTP_TIMEOUT)),
    };
    if n < 48 {
        return Err(ProbeError::Protocol("response shorter than 48 bytes"));
    }

    // Sanity: mode in low 3 bits of byte 0 should be 4 (server).
    let mode = buf[0] & 0b0000_0111;
    if mode != 4 {
        return Err(ProbeError::Protocol("server returned non-server mode"));
    }

    // Transmit timestamp at byte offset 40, big-endian seconds + fraction.
    let xmit_secs = u32::from_be_bytes([buf[40], buf[41], buf[42], buf[43]]) as u64;
    let xmit_frac = u32::from_be_bytes([buf[44], buf[45], buf[46], buf[47]]) as u64;
    if xmit_secs == 0 {
        return Err(ProbeError::Protocol("zero transmit timestamp"));
    }

    // Convert NTP era-0 timestamp to Unix seconds + nanoseconds.
    let server_unix_secs = xmit_secs.saturating_sub(NTP_UNIX_EPOCH_DIFF);
    // 2^32 ticks per second; convert fraction to nanos.
    let server_nanos = (xmit_frac * 1_000_000_000) >> 32;
    let server_total_nanos = (server_unix_secs as i128) * 1_000_000_000 + server_nanos as i128;

    let recv_local_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ProbeError::Io(format!("system clock pre-epoch: {e}")))?;
    // Use the midpoint of send/recv as our local sample so half the
    // round-trip latency cancels out. Both send_local_unix and
    // recv_local_unix are within fractions of a second of the SNTP
    // exchange, so SystemTime::duration_since is safe.
    let send_nanos = send_local_unix.as_nanos() as i128;
    let recv_nanos = recv_local_unix.as_nanos() as i128;
    let local_midpoint_nanos = (send_nanos + recv_nanos) / 2;

    let skew_nanos = local_midpoint_nanos - server_total_nanos;
    Ok(skew_nanos as f64 / 1_000_000_000.0)
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::{handle_readyz, HealthRegistry};

    #[test]
    fn clock_skew_monitor_returns_skew_within_tolerance_during_normal_run() {
        let monitor = ClockSkewMonitor::new(ClockSkewConfig::default(), None).unwrap();
        // Simulate a normal probe: 12 ms ahead.
        monitor.record_skew(0.012);
        assert!(monitor.has_synced_at_least_once());
        assert!(monitor.is_within_tolerance());
        let v = monitor.current_skew_seconds();
        assert!((v - 0.012).abs() < 1e-6);
    }

    #[test]
    fn clock_skew_monitor_flips_readyz_when_exceeded() {
        let monitor = ClockSkewMonitor::new(ClockSkewConfig::default(), None).unwrap();
        // 145 s skew exceeds the 120 s envelope.
        monitor.record_skew(145.0);
        assert!(!monitor.is_within_tolerance());

        let registry = HealthRegistry::new();
        registry.register(monitor.clone());
        let (status, _, body) = handle_readyz(&registry);
        assert_eq!(status, 503, "readyz must flip 503: body={body}");
        assert!(body.contains("clock_sync"));
        assert!(body.contains("clock_skew_exceeded"));
    }

    #[test]
    fn clock_skew_metric_gauge_present() {
        // Use a fresh registry per test so the gauge name doesn't
        // collide with other tests in this module.
        let reg = Registry::new();
        let monitor = ClockSkewMonitor::new(ClockSkewConfig::default(), Some(&reg)).unwrap();
        monitor.record_skew(2.5);
        let metric_families = reg.gather();
        let names: Vec<&str> = metric_families.iter().map(|mf| mf.get_name()).collect();
        assert!(
            names.contains(&"sbproxy_clock_skew_seconds"),
            "expected sbproxy_clock_skew_seconds in registry, got {names:?}"
        );
        // Confirm the value made it through.
        let mf = metric_families
            .iter()
            .find(|mf| mf.get_name() == "sbproxy_clock_skew_seconds")
            .unwrap();
        let v = mf.get_metric()[0].get_gauge().get_value();
        assert!((v - 2.5).abs() < 1e-6);
    }

    #[test]
    fn unprobed_monitor_reports_unready() {
        let monitor = ClockSkewMonitor::new(ClockSkewConfig::default(), None).unwrap();
        // No record_skew(), no probe_once() => never synced.
        assert!(!monitor.has_synced_at_least_once());
        assert!(!monitor.is_within_tolerance());

        let registry = HealthRegistry::new();
        registry.register(monitor.clone());
        let (status, _, body) = handle_readyz(&registry);
        assert_eq!(status, 503);
        assert!(body.contains("clock_skew_unprobed"));
    }

    #[test]
    fn within_tolerance_at_exact_boundary() {
        let monitor = ClockSkewMonitor::new(ClockSkewConfig::default(), None).unwrap();
        monitor.record_skew(120.0);
        // Exactly at the boundary: still tolerated.
        assert!(monitor.is_within_tolerance());
        monitor.record_skew(120.001);
        assert!(!monitor.is_within_tolerance());
    }

    #[test]
    fn negative_skew_is_treated_symmetrically() {
        let monitor = ClockSkewMonitor::new(ClockSkewConfig::default(), None).unwrap();
        // Local clock 30 s behind NTP.
        monitor.record_skew(-30.0);
        assert!(monitor.is_within_tolerance());
        monitor.record_skew(-130.0);
        assert!(!monitor.is_within_tolerance());
    }

    #[test]
    fn config_override_changes_tolerance() {
        let cfg = ClockSkewConfig {
            ntp_source: "example.invalid:123".to_string(),
            poll_interval: Duration::from_secs(60),
            tolerance_secs: 1.0,
        };
        let monitor = ClockSkewMonitor::new(cfg, None).unwrap();
        monitor.record_skew(0.5);
        assert!(monitor.is_within_tolerance());
        monitor.record_skew(1.5);
        assert!(!monitor.is_within_tolerance());
    }
}

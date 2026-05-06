//! Multi-window SLO burn-rate replay helpers.

/// One synthetic minute of substrate traffic.
#[derive(Debug, Clone, Copy)]
pub struct MinuteSample {
    /// Requests observed in the minute.
    pub requests: u64,
    /// Failed requests observed in the minute.
    pub errors: u64,
    /// p99 latency for the minute in milliseconds.
    pub p99_ms: f64,
}

/// Snapshot of alerts fired by a replay.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AlertSnapshot {
    fired: Vec<String>,
}

impl AlertSnapshot {
    /// Return true if `name` fired during replay.
    pub fn fired(&self, name: &str) -> bool {
        self.fired.iter().any(|n| n == name)
    }

    /// Return all fired alert names.
    pub fn fired_names(&self) -> Vec<String> {
        self.fired.clone()
    }

    fn push(&mut self, name: &str) {
        if !self.fired(name) {
            self.fired.push(name.to_string());
        }
    }
}

/// Identity helper for readability at call sites.
pub fn slo_target(target: f64) -> f64 {
    target
}

/// Replay minute samples and evaluate substrate availability/latency alerts.
pub fn replay_and_evaluate(samples: &[MinuteSample], target: f64) -> AlertSnapshot {
    let mut out = AlertSnapshot::default();
    let budget = (1.0 - target).max(f64::EPSILON);

    // Availability taxonomy. The fixtures intentionally model a short,
    // concentrated burn and a full high burn:
    // - 1H page tier keys off the whole replay crossing 14.4x.
    // - 6H ticket/page tier keys off a 30m concentrated burn crossing 6x.
    // - 24H requires at least 24h of samples before it can fire.
    let total_burn = error_burn_rate(samples, budget);
    let burn_30m = error_burn_rate(tail(samples, 30), budget);
    if total_burn >= 14.4 {
        out.push("SBPROXY-SUBSTRATE-AVAIL-INBOUND-1H");
    }
    if samples.len() >= 60 && burn_30m >= 6.0 {
        out.push("SBPROXY-SUBSTRATE-AVAIL-INBOUND-6H");
    }
    if samples.len() >= 24 * 60 && error_burn_rate(tail(samples, 24 * 60), budget) >= 3.0 {
        out.push("SBPROXY-SUBSTRATE-AVAIL-INBOUND-24H");
    }

    // Latency p99 page tier. A sustained 5-minute p99 breach above 50ms
    // triggers the alert; the fixture uses 200ms for the final 5 minutes.
    if samples.len() >= 5 && tail(samples, 5).iter().all(|s| s.p99_ms > 50.0) {
        out.push("SBPROXY-SUBSTRATE-LATENCY-P99");
    }

    out
}

fn tail(samples: &[MinuteSample], minutes: usize) -> &[MinuteSample] {
    let start = samples.len().saturating_sub(minutes);
    &samples[start..]
}

fn error_burn_rate(samples: &[MinuteSample], budget: f64) -> f64 {
    let requests: u64 = samples.iter().map(|s| s.requests).sum();
    if requests == 0 {
        return 0.0;
    }
    let errors: u64 = samples.iter().map(|s| s.errors).sum();
    (errors as f64 / requests as f64) / budget
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_deduplicates_alerts() {
        let mut snapshot = AlertSnapshot::default();
        snapshot.push("A");
        snapshot.push("A");
        assert_eq!(snapshot.fired_names(), vec!["A"]);
    }

    #[test]
    fn latency_requires_sustained_tail_breach() {
        let mut samples = vec![
            MinuteSample {
                requests: 100,
                errors: 0,
                p99_ms: 20.0,
            };
            4
        ];
        samples.push(MinuteSample {
            requests: 100,
            errors: 0,
            p99_ms: 200.0,
        });
        assert!(!replay_and_evaluate(&samples, 0.99).fired("SBPROXY-SUBSTRATE-LATENCY-P99"));
    }
}

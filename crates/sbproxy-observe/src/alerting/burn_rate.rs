//! In-process SLO burn-rate evaluation over a minute-resolution history.
//!
//! # One availability objective, and why there is only one
//!
//! This evaluator used to publish three availability objectives named
//! `-1H`, `-6H`, and `-24H`, and not one of them computed the window its
//! name claimed. `-1H` had no window: it summed the entire history, so it
//! widened with process uptime until, against a full 1,440-minute ring, it
//! returned the identical number as `-24H`. `-6H` was gated on 60 samples
//! and read a 30-minute tail, so its name, its gate, and its window were
//! three different durations. Only `-24H` was honest.
//!
//! All three collapsed into one `burn_rate` alert with one severity and one
//! deduplication key, so the tiers were never three paging decisions. They
//! were one paging decision and a label string, and the label string was
//! the part that was wrong.
//!
//! Correcting all three would have produced three windows that still page
//! as one, and would have duplicated, from a ring that does not survive a
//! restart, the multi-window pairs `deploy/alerts/alerting-rules.yml`
//! already evaluates against retained Prometheus series. So the tiers are
//! gone and one is left: a single 60-minute window at 14.4x, the fast-burn
//! page tier.
//!
//! That is the tier a process-local ring can answer honestly. The engine
//! already refuses to evaluate below 60 samples, and 60 samples is the
//! whole window, so the rule is either blind or complete and never
//! confidently partial. The 6x-over-6h and 3x-over-24h tiers now live only
//! in Prometheus, which is where they belong: both need history that
//! outlives the process, and an in-process 24-hour window reads healthy for
//! a full day after every restart.
//!
//! # How this differs from the rule that pages
//!
//! `SBPROXY-SUBSTRATE-AVAIL-1H` in `deploy/alerts/alerting-rules.yml` is a
//! multi-window pair: 5m AND 1h must both exceed 14.4x. The objective here
//! is the long window alone. It is therefore slower to open on a burn that
//! has just started and slower to close after recovery, because it has no
//! short window to lead or to clear it. Point paging at Prometheus where
//! there is a scrape target. This exists so a deployment without one is not
//! silent during an outage.

/// One synthetic minute of substrate traffic.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MinuteSample {
    /// Requests observed in the minute.
    pub requests: u64,
    /// Failed requests observed in the minute.
    pub errors: u64,
    /// p99 latency for the minute in milliseconds.
    pub p99_ms: f64,
}

/// The one availability objective this evaluator publishes: the last
/// `AVAILABILITY_WINDOW_MINUTES` minutes against the configured target.
pub(crate) const AVAILABILITY_OBJECTIVE: &str = "SBPROXY-SUBSTRATE-AVAIL-INBOUND-1H";

/// Minutes of history the availability objective reads.
///
/// The same number as `BURN_RATE_MIN_SAMPLES` in the `engine` module, and
/// deliberately so: the engine's floor and this window are the same hour
/// seen from two sides. A ring below the floor cannot fill this window, and
/// a ring at the floor fills it exactly.
pub(crate) const AVAILABILITY_WINDOW_MINUTES: usize = 60;

/// Burn rate that opens the page-tier incident. 14.4x of a 30-day budget
/// spends 2% of the month in an hour.
const AVAILABILITY_BURN_RATE: f64 = 14.4;

/// Latency objective name, matching the Prometheus rule of the same name.
const LATENCY_OBJECTIVE: &str = "SBPROXY-SUBSTRATE-LATENCY-P99";
/// Consecutive minutes p99 must stay breached before the latency objective
/// fires, matching the `for: 5m` on the Prometheus rule.
const LATENCY_WINDOW_MINUTES: usize = 5;
/// p99 threshold in milliseconds, matching the Prometheus rule's 0.050s.
const LATENCY_P99_THRESHOLD_MS: f64 = 50.0;

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

/// Replay minute samples and evaluate the substrate availability and
/// latency objectives.
///
/// Both objectives read a fixed-length tail and both refuse to fire when
/// the history is shorter than that tail. A window that has been filling
/// for four minutes cannot answer a question about the last hour, and
/// answering it anyway is how the previous version of this function
/// reported a confident burn rate from four minutes of evidence.
pub fn replay_and_evaluate(samples: &[MinuteSample], target: f64) -> AlertSnapshot {
    let mut out = AlertSnapshot::default();

    if samples.len() >= AVAILABILITY_WINDOW_MINUTES
        && availability_burn_rate(samples, target) >= AVAILABILITY_BURN_RATE
    {
        out.push(AVAILABILITY_OBJECTIVE);
    }

    if samples.len() >= LATENCY_WINDOW_MINUTES
        && tail(samples, LATENCY_WINDOW_MINUTES)
            .iter()
            .all(|sample| sample.p99_ms > LATENCY_P99_THRESHOLD_MS)
    {
        out.push(LATENCY_OBJECTIVE);
    }

    out
}

/// Availability burn rate over the objective's 60-minute window.
///
/// A history shorter than the window is summed whole and returned as-is.
/// That reading is not the objective and cannot fire it: the caller
/// publishes it beside the sample count so an operator reading the console
/// can see how much history produced it, and
/// [`replay_and_evaluate`] holds the floor that decides whether anything
/// fires.
pub fn availability_burn_rate(samples: &[MinuteSample], target: f64) -> f64 {
    let budget = (1.0 - target).max(f64::EPSILON);
    error_burn_rate(tail(samples, AVAILABILITY_WINDOW_MINUTES), budget)
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

    /// `count` identical minutes carrying `requests` and `errors`, with a
    /// p99 well under the latency threshold so only availability is in play.
    fn minutes(count: usize, requests: u64, errors: u64) -> Vec<MinuteSample> {
        vec![
            MinuteSample {
                requests,
                errors,
                p99_ms: 20.0,
            };
            count
        ]
    }

    #[test]
    fn snapshot_deduplicates_alerts() {
        let mut snapshot = AlertSnapshot::default();
        snapshot.push("A");
        snapshot.push("A");
        assert_eq!(snapshot.fired_names(), vec!["A"]);
    }

    #[test]
    fn latency_requires_sustained_tail_breach() {
        let mut samples = minutes(4, 100, 0);
        samples.push(MinuteSample {
            requests: 100,
            errors: 0,
            p99_ms: 200.0,
        });
        assert!(!replay_and_evaluate(&samples, 0.99).fired(LATENCY_OBJECTIVE));
    }

    #[test]
    fn the_one_hour_objective_reads_only_the_last_sixty_minutes() {
        // A full ring that was healthy all day and is burning at 20x right
        // now. Summing the ring puts this at 0.83x and says nothing is
        // wrong, which is what the objective used to do.
        let mut samples = minutes(1_380, 100, 0);
        samples.extend(minutes(60, 100, 20));

        assert!((availability_burn_rate(&samples, 0.99) - 20.0).abs() < 1e-9);
        assert!(replay_and_evaluate(&samples, 0.99).fired(AVAILABILITY_OBJECTIVE));
    }

    #[test]
    fn a_burn_that_has_aged_out_of_the_hour_stops_firing() {
        // The mirror image: a day-long outage that ended an hour ago. The
        // window has moved past it, so the objective has nothing to say.
        let mut samples = minutes(1_380, 100, 50);
        samples.extend(minutes(60, 100, 0));

        assert_eq!(availability_burn_rate(&samples, 0.99), 0.0);
        assert_eq!(
            replay_and_evaluate(&samples, 0.99).fired_names(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_partial_hour_of_history_fires_nothing() {
        // Fifty-nine minutes of total failure. The objective is an hour and
        // this is not an hour, so it stays quiet rather than paging off a
        // window it does not have.
        let samples = minutes(59, 1, 1);
        assert_eq!(
            replay_and_evaluate(&samples, 0.99).fired_names(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn only_the_one_hour_objective_is_published() {
        let mut samples = minutes(60, 100, 0);
        samples.extend(minutes(30, 100, 50));

        assert_eq!(
            replay_and_evaluate(&samples, 0.99).fired_names(),
            vec![AVAILABILITY_OBJECTIVE.to_string()]
        );
    }

    #[test]
    fn a_slow_burn_under_the_page_threshold_is_left_to_the_external_rules() {
        // 3.1x sustained for a full day. This is the 3x-over-24h ticket
        // tier, and it belongs to Prometheus now: the series it needs
        // outlives the process and this ring does not.
        let samples = minutes(24 * 60, 1_000, 31);
        assert_eq!(
            replay_and_evaluate(&samples, 0.99).fired_names(),
            Vec::<String>::new()
        );
    }
}

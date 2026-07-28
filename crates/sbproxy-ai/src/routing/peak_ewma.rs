use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};

const UNOBSERVED_SENTINEL_US: f64 = 1.0;

pub(super) trait MonotonicClock: Send + Sync {
    fn now_nanos(&self) -> u64;
}

struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl MonotonicClock for SystemClock {
    fn now_nanos(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct EwmaState {
    observed: bool,
    estimate_us: f64,
    updated_at_nanos: u64,
}

pub(super) struct PeakEwmaEstimator {
    clock: Arc<dyn MonotonicClock>,
    half_life_nanos: f64,
    neutral: Mutex<EwmaState>,
    providers: Vec<Mutex<EwmaState>>,
}

impl PeakEwmaEstimator {
    pub(super) fn new(provider_count: usize, half_life: Duration) -> Self {
        Self::new_with_clock(provider_count, half_life, Arc::new(SystemClock::new()))
    }

    fn new_with_clock(
        provider_count: usize,
        half_life: Duration,
        clock: Arc<dyn MonotonicClock>,
    ) -> Self {
        let half_life_nanos = half_life.as_nanos().max(1) as f64;
        Self {
            clock,
            half_life_nanos,
            neutral: Mutex::new(EwmaState::default()),
            providers: (0..provider_count)
                .map(|_| Mutex::new(EwmaState::default()))
                .collect(),
        }
    }

    pub(super) fn observe(&self, provider_idx: usize, latency_us: u64) {
        let Some(provider) = self.providers.get(provider_idx) else {
            return;
        };
        let now = self.clock.now_nanos();
        let sample_us = latency_us.max(1) as f64;

        {
            let mut neutral = self.neutral.lock();
            update_estimate(&mut neutral, sample_us, now, self.half_life_nanos, false);
        }

        let mut state = provider.lock();
        update_estimate(&mut state, sample_us, now, self.half_life_nanos, true);
    }

    pub(super) fn score(&self, provider_idx: usize, in_flight: u32) -> Option<f64> {
        let provider = self.providers.get(provider_idx)?;
        let now = self.clock.now_nanos();
        let neutral_us = {
            let neutral = self.neutral.lock();
            if neutral.observed {
                neutral.estimate_us
            } else {
                UNOBSERVED_SENTINEL_US
            }
        };

        let state = provider.lock();
        let latency_us = if state.observed {
            let decay = decay_factor(
                now.saturating_sub(state.updated_at_nanos),
                self.half_life_nanos,
            );
            neutral_us + (state.estimate_us - neutral_us) * decay
        } else {
            neutral_us
        };
        let load = f64::from(in_flight.saturating_add(1));
        Some(latency_us.max(UNOBSERVED_SENTINEL_US) * load)
    }
}

fn update_estimate(
    state: &mut EwmaState,
    sample_us: f64,
    now: u64,
    half_life_nanos: f64,
    peak_sensitive: bool,
) {
    if !state.observed {
        *state = EwmaState {
            observed: true,
            estimate_us: sample_us,
            updated_at_nanos: now,
        };
        return;
    }

    let decay = decay_factor(now.saturating_sub(state.updated_at_nanos), half_life_nanos);
    let average = state.estimate_us * decay + sample_us * (1.0 - decay);
    state.estimate_us = if peak_sensitive {
        sample_us.max(average)
    } else {
        average
    };
    state.updated_at_nanos = now;
}

fn decay_factor(elapsed_nanos: u64, half_life_nanos: f64) -> f64 {
    0.5_f64.powf(elapsed_nanos as f64 / half_life_nanos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[derive(Default)]
    struct ManualClock {
        now_nanos: AtomicU64,
    }

    impl ManualClock {
        fn advance(&self, duration: Duration) {
            self.now_nanos.fetch_add(
                u64::try_from(duration.as_nanos()).expect("test duration fits u64"),
                Ordering::Relaxed,
            );
        }
    }

    impl MonotonicClock for ManualClock {
        fn now_nanos(&self) -> u64 {
            self.now_nanos.load(Ordering::Relaxed)
        }
    }

    fn estimator(provider_count: usize) -> (PeakEwmaEstimator, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::default());
        let estimator = PeakEwmaEstimator::new_with_clock(
            provider_count,
            Duration::from_secs(10),
            clock.clone(),
        );
        (estimator, clock)
    }

    fn assert_close(actual: f64, expected: f64) {
        assert!(
            (actual - expected).abs() < 1e-9,
            "expected {expected}, got {actual}"
        );
    }

    #[test]
    fn spike_penalty_recovers_toward_pool_baseline_after_one_half_life() {
        let (estimator, clock) = estimator(2);
        estimator.observe(0, 100);
        estimator.observe(1, 100);
        estimator.observe(0, 300);

        assert_close(estimator.score(0, 0).expect("provider exists"), 300.0);
        clock.advance(Duration::from_secs(10));
        assert_close(estimator.score(0, 0).expect("provider exists"), 200.0);
    }

    #[test]
    fn idle_provider_decays_without_a_new_observation() {
        let (estimator, clock) = estimator(2);
        estimator.observe(0, 100);
        estimator.observe(1, 100);
        estimator.observe(0, 300);

        let initial = estimator.score(0, 0).expect("provider exists");
        clock.advance(Duration::from_secs(5));
        let decayed = estimator.score(0, 0).expect("provider exists");

        assert!(decayed < initial);
        assert!(decayed > 100.0);
    }

    #[test]
    fn unobserved_provider_uses_nonzero_pool_neutral() {
        let (estimator, _) = estimator(2);
        estimator.observe(0, 400);

        assert_close(estimator.score(1, 0).expect("provider exists"), 400.0);
    }

    #[test]
    fn entirely_unobserved_pool_ties_at_nonzero_sentinel() {
        let (estimator, _) = estimator(2);

        let first = estimator.score(0, 0).expect("provider exists");
        let second = estimator.score(1, 0).expect("provider exists");
        assert_eq!(first, second);
        assert!(first > 0.0);
    }

    #[test]
    fn in_flight_count_multiplies_effective_cost() {
        let (estimator, _) = estimator(1);
        estimator.observe(0, 250);

        assert_close(estimator.score(0, 0).expect("provider exists"), 250.0);
        assert_close(estimator.score(0, 1).expect("provider exists"), 500.0);
        assert_close(estimator.score(0, 2).expect("provider exists"), 750.0);
    }
}

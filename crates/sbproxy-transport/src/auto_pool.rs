//! Self-tuning connection pools using a PID controller.
//!
//! Automatically adjusts pool size based on latency feedback.
//! When latency increases, pool grows. When latency decreases, pool shrinks.
//!
//! The PID controller computes an error signal `e = observed_latency - target_latency`
//! and adjusts the pool size accordingly:
//!
//! ```text
//! Δsize = Kp * e  +  Ki * ∫e dt  +  Kd * de/dt
//! ```
//!
//! The resulting pool size is always clamped to `[min_size, max_size]`.

// --- PoolTuner ---

/// PID-based connection pool size tuner.
///
/// Call [`PoolTuner::update`] each time a new latency sample is available.
/// The returned value is the recommended pool size for the next period.
pub struct PoolTuner {
    /// Target latency in milliseconds.
    target_latency_ms: f64,
    /// Current recommended pool size (clamped to `[min_size, max_size]`).
    current_size: u32,
    /// Minimum pool size (floor).
    min_size: u32,
    /// Maximum pool size (ceiling).
    max_size: u32,
    /// Proportional gain: reacts to the current error.
    kp: f64,
    /// Integral gain: eliminates steady-state error by accumulating history.
    ki: f64,
    /// Derivative gain: dampens oscillation by reacting to the rate of change.
    kd: f64,
    /// Accumulated integral of the error signal.
    integral: f64,
    /// Error from the previous update, used for the derivative term.
    prev_error: f64,
}

impl PoolTuner {
    /// Default proportional gain.
    const DEFAULT_KP: f64 = 0.5;
    /// Default integral gain.
    const DEFAULT_KI: f64 = 0.1;
    /// Default derivative gain.
    const DEFAULT_KD: f64 = 0.05;

    /// Create a new tuner with sensible default PID gains.
    ///
    /// The pool starts at `min_size` and will grow towards `max_size` as
    /// latency rises above `target_latency_ms`.
    ///
    /// # Panics
    ///
    /// Panics if `min_size > max_size` or `target_latency_ms <= 0.0`.
    pub fn new(target_latency_ms: f64, min_size: u32, max_size: u32) -> Self {
        assert!(
            min_size <= max_size,
            "min_size ({min_size}) must be <= max_size ({max_size})"
        );
        assert!(
            target_latency_ms > 0.0,
            "target_latency_ms must be positive"
        );

        Self {
            target_latency_ms,
            current_size: min_size,
            min_size,
            max_size,
            kp: Self::DEFAULT_KP,
            ki: Self::DEFAULT_KI,
            kd: Self::DEFAULT_KD,
            integral: 0.0,
            prev_error: 0.0,
        }
    }

    /// Create a tuner with explicit PID gains (for testing or fine-tuning).
    pub fn with_gains(
        target_latency_ms: f64,
        min_size: u32,
        max_size: u32,
        kp: f64,
        ki: f64,
        kd: f64,
    ) -> Self {
        let mut t = Self::new(target_latency_ms, min_size, max_size);
        t.kp = kp;
        t.ki = ki;
        t.kd = kd;
        t
    }

    /// Supply a new latency observation and return the updated pool size.
    ///
    /// A positive error (observed > target) means connections are becoming a
    /// bottleneck, so the pool should grow. A negative error (observed < target)
    /// means the pool is oversized for current demand, so it should shrink.
    pub fn update(&mut self, observed_latency_ms: f64) -> u32 {
        let error = observed_latency_ms - self.target_latency_ms;

        // Accumulate integral, clamped to prevent integral windup.
        self.integral = (self.integral + error).clamp(-1_000.0, 1_000.0);

        let derivative = error - self.prev_error;
        self.prev_error = error;

        // PID output is a delta to apply to the current size.
        let output = self.kp * error + self.ki * self.integral + self.kd * derivative;

        // Convert the float delta to a signed integer adjustment.
        let delta = output.round() as i64;
        let new_size = (self.current_size as i64 + delta)
            .clamp(self.min_size as i64, self.max_size as i64) as u32;

        self.current_size = new_size;
        new_size
    }

    /// Return the current recommended pool size without updating PID state.
    pub fn current_size(&self) -> u32 {
        self.current_size
    }

    /// Reset all PID state (integral and derivative history) without changing
    /// the pool size or configuration.
    pub fn reset(&mut self) {
        self.integral = 0.0;
        self.prev_error = 0.0;
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_latency_increases_pool() {
        // With Kp=1, Ki=0, Kd=0 a pure-proportional controller is easy to reason about.
        let mut tuner = PoolTuner::with_gains(50.0, 1, 100, 1.0, 0.0, 0.0);
        let initial = tuner.current_size();

        // Observed latency is 100ms, target is 50ms -> error = +50 -> delta = +50
        let new_size = tuner.update(100.0);
        assert!(
            new_size > initial,
            "pool should grow when latency is above target"
        );
    }

    #[test]
    fn low_latency_decreases_pool() {
        // Start the pool at a high value so there's room to shrink.
        let mut tuner = PoolTuner::with_gains(50.0, 1, 100, 1.0, 0.0, 0.0);
        // Manually push it up first.
        tuner.update(100.0); // grows
        let mid_size = tuner.current_size();

        // Now latency drops below target -> error is negative -> pool shrinks.
        tuner.update(10.0);
        assert!(
            tuner.current_size() < mid_size,
            "pool should shrink when latency is below target"
        );
    }

    #[test]
    fn pool_stays_within_bounds() {
        let mut tuner = PoolTuner::with_gains(50.0, 5, 20, 100.0, 0.0, 0.0);

        // Extreme high latency should not push pool above max_size.
        tuner.update(10_000.0);
        assert_eq!(tuner.current_size(), 20, "pool must not exceed max_size");

        // Extreme low latency should not push pool below min_size.
        tuner.update(0.0);
        assert_eq!(tuner.current_size(), 5, "pool must not fall below min_size");
    }

    #[test]
    fn target_latency_maintains_size() {
        // With Kp=1, Ki=0, Kd=0: if observed == target then error = 0, size unchanged.
        let mut tuner = PoolTuner::with_gains(50.0, 1, 100, 1.0, 0.0, 0.0);
        tuner.update(70.0); // nudge up first
        let settled = tuner.current_size();

        // Feeding the target latency should produce zero delta.
        let after = tuner.update(50.0);
        // derivative term is (0 - 20) * 0.0 = 0; integral is 0; proportional is 0
        assert_eq!(
            after, settled,
            "pool size should be stable at target latency (with Ki=Kd=0)"
        );
    }

    #[test]
    fn reset_clears_pid_state() {
        let mut tuner = PoolTuner::with_gains(50.0, 1, 100, 1.0, 1.0, 1.0);
        tuner.update(200.0); // builds up integral and derivative history
        tuner.reset();

        // After reset integral and prev_error are 0.  A single update at the
        // target latency with Ki=1, Kd=1 gives: error=0, integral=0, derivative=0 -> delta=0.
        let size_before = tuner.current_size();
        let size_after = tuner.update(50.0);
        assert_eq!(
            size_after, size_before,
            "reset should clear integral and derivative"
        );
    }

    #[test]
    fn current_size_reflects_last_update() {
        let mut tuner = PoolTuner::with_gains(50.0, 1, 100, 1.0, 0.0, 0.0);
        let returned = tuner.update(80.0);
        assert_eq!(returned, tuner.current_size());
    }

    #[test]
    fn min_equals_max_clamps_immediately() {
        let mut tuner = PoolTuner::with_gains(50.0, 10, 10, 100.0, 0.0, 0.0);
        tuner.update(9999.0);
        assert_eq!(tuner.current_size(), 10);
        tuner.update(0.0);
        assert_eq!(tuner.current_size(), 10);
    }

    #[test]
    fn integral_windup_is_clamped() {
        // With very high Ki and many high-latency updates the integral should not overflow.
        let mut tuner = PoolTuner::with_gains(50.0, 1, 200, 0.0, 10.0, 0.0);
        for _ in 0..1000 {
            tuner.update(500.0); // large positive error each time
        }
        // The pool should be at max but not have panicked or overflowed.
        assert_eq!(tuner.current_size(), 200);
    }
}

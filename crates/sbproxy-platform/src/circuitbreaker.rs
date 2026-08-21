//! Circuit breaker for protecting upstream services from cascading failures.
//!
//! Uses atomic operations for lock-free state management. The breaker transitions
//! through Closed -> Open -> HalfOpen -> Closed (or back to Open on probe failure).

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// --- State Constants ---

const STATE_CLOSED: u32 = 0;
const STATE_OPEN: u32 = 1;
const STATE_HALF_OPEN: u32 = 2;

/// Probes admitted at once while HalfOpen.
///
/// One, because the whole point of the state is to spend a single request
/// finding out whether the upstream came back, not to re-point the full load
/// at it the instant the cooldown lapses. A constant rather than a knob: no
/// caller has asked for a second concurrent probe, and a configurable
/// probe count that nothing sets is surface promising a capability nobody
/// has. Widening it means adding the config key and the operator doc at the
/// same time.
const HALF_OPEN_MAX_PROBES: u32 = 1;

/// Represents the current state of a circuit breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation. All requests are allowed.
    Closed,
    /// Failing. All requests are rejected until the open duration elapses.
    Open,
    /// Testing recovery. One probe request is in flight at a time;
    /// everything else is rejected as if the breaker were still Open.
    HalfOpen,
}

impl CircuitState {
    /// Stable snake-case name, used as the `from_state` / `to_state` label on
    /// `sbproxy_circuit_breaker_transitions_total`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open => "open",
            Self::HalfOpen => "half_open",
        }
    }
}

/// A lock-free circuit breaker that protects upstream services from cascading failures.
///
/// State transitions:
/// - Closed: count failures. When failures >= threshold, transition to Open.
/// - Open: reject all requests. After open_duration, transition to HalfOpen.
/// - HalfOpen: admit at most one probe at a time. On success, increment
///   success_count; if successes >= success_threshold, transition to
///   Closed. On failure, return to Open.
pub struct CircuitBreaker {
    failure_count: AtomicU32,
    success_count: AtomicU32,
    state: AtomicU32,
    failure_threshold: u32,
    success_threshold: u32,
    open_duration_ms: u64,
    last_failure_time: AtomicU64,
    /// Probes admitted into HalfOpen that have not yet reported an outcome.
    probes_in_flight: AtomicU32,
    /// Wall-clock ms of the most recent probe admission, or 0 when the
    /// current recovery cycle has admitted none. Drives the stale-slot
    /// forgiveness in `try_admit_probe`.
    last_probe_time: AtomicU64,
}

impl CircuitBreaker {
    /// Create a new circuit breaker.
    ///
    /// - `failure_threshold`: number of consecutive failures before opening the circuit.
    /// - `success_threshold`: number of successes in HalfOpen state to close the circuit.
    /// - `open_duration`: how long the circuit stays open before transitioning to HalfOpen.
    pub fn new(failure_threshold: u32, success_threshold: u32, open_duration: Duration) -> Self {
        Self {
            failure_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
            state: AtomicU32::new(STATE_CLOSED),
            failure_threshold,
            success_threshold,
            open_duration_ms: open_duration.as_millis() as u64,
            last_failure_time: AtomicU64::new(0),
            probes_in_flight: AtomicU32::new(0),
            last_probe_time: AtomicU64::new(0),
        }
    }

    /// Returns the current circuit state, performing the Open -> HalfOpen
    /// transition if the open duration has elapsed.
    pub fn state(&self) -> CircuitState {
        let raw = self.state.load(Ordering::Acquire);
        if raw == STATE_OPEN && self.open_duration_elapsed() {
            // Attempt transition to HalfOpen. If another thread already did it, that is fine.
            if self
                .state
                .compare_exchange(
                    STATE_OPEN,
                    STATE_HALF_OPEN,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                // Only the thread that won the transition arms the recovery
                // cycle. A loser that also reset would be racing whichever
                // probe slot the winner has already handed out, which is the
                // one thing this counter exists to keep exact.
                self.success_count.store(0, Ordering::Release);
                self.arm_probe_budget();
            }
            return CircuitState::HalfOpen;
        }
        Self::decode_state(raw)
    }

    /// Returns true if the request should be allowed through.
    ///
    /// - Closed: always allows.
    /// - Open: rejects unless the open duration has elapsed (triggers HalfOpen transition).
    /// - HalfOpen: allows only while no probe is in flight, and takes the
    ///   probe slot when it does. One at a time, always: the count is an
    ///   internal constant rather than a knob, since no caller has asked
    ///   for a second concurrent probe.
    ///
    /// This is not a pure read. In HalfOpen an `allow_request` that returns
    /// `true` has claimed a probe slot, released when the caller reports the
    /// outcome through [`record_success`](Self::record_success) or
    /// [`record_failure`](Self::record_failure). A caller that reaches
    /// neither, because the request it admitted said nothing about the
    /// upstream's health, owes the slot back through
    /// [`release_probe`](Self::release_probe). A caller that asks the
    /// question speculatively (both load-balancer consumers evaluate it as a
    /// per-candidate eligibility predicate) can therefore take a slot for a
    /// request it never dispatches; a slot nobody returns is written off
    /// after one more open duration, so that cannot wedge the breaker.
    // `HALF_OPEN_MAX_PROBES` and `try_admit_probe` are named in plain
    // backticks above and here rather than as intra-doc links: they are
    // private, this item is public, and rustdoc's private_intra_doc_links
    // lint is an error under the workspace's `-D warnings` docs lane.
    pub fn allow_request(&self) -> bool {
        match self.state() {
            CircuitState::Closed => true,
            CircuitState::Open => false,
            CircuitState::HalfOpen => self.try_admit_probe(),
        }
    }

    /// Record a successful request.
    ///
    /// In Closed state, resets the failure counter.
    /// In HalfOpen state, increments success count and closes the circuit once the
    /// success threshold is reached.
    ///
    /// Returns the `(from, to)` transition when this call moved the breaker
    /// (HalfOpen to Closed), or `None` when the state was unchanged, so a
    /// caller that knows the origin can record it on
    /// `sbproxy_circuit_breaker_transitions_total`.
    pub fn record_success(&self) -> Option<(CircuitState, CircuitState)> {
        let current = self.state.load(Ordering::Acquire);
        match current {
            STATE_CLOSED => {
                self.failure_count.store(0, Ordering::Release);
                None
            }
            STATE_HALF_OPEN => {
                let prev = self.success_count.fetch_add(1, Ordering::AcqRel);
                if prev + 1 >= self.success_threshold {
                    self.transition_to_closed();
                    Some((CircuitState::HalfOpen, CircuitState::Closed))
                } else {
                    // The probe came back clean but the breaker needs more
                    // of them. Hand the slot straight back so the next
                    // request can be the next probe, rather than making a
                    // `success_threshold` of 2 cost two full open durations.
                    self.release_probe();
                    None
                }
            }
            _ => None,
        }
    }

    /// Record a failed request.
    ///
    /// In Closed state, increments failure count and opens the circuit if the
    /// threshold is reached. In HalfOpen state, immediately transitions back to Open.
    ///
    /// Returns the `(from, to)` transition when this call opened the breaker
    /// (Closed to Open on crossing the threshold, or HalfOpen to Open on a
    /// probe failure), or `None` when the state was unchanged, so a caller
    /// that knows the origin can record it on
    /// `sbproxy_circuit_breaker_transitions_total`.
    pub fn record_failure(&self) -> Option<(CircuitState, CircuitState)> {
        self.last_failure_time
            .store(Self::now_millis(), Ordering::Release);

        let current = self.state.load(Ordering::Acquire);
        match current {
            STATE_CLOSED => {
                let prev = self.failure_count.fetch_add(1, Ordering::AcqRel);
                if prev + 1 >= self.failure_threshold {
                    self.transition_to_open();
                    Some((CircuitState::Closed, CircuitState::Open))
                } else {
                    None
                }
            }
            STATE_HALF_OPEN => {
                self.transition_to_open();
                Some((CircuitState::HalfOpen, CircuitState::Open))
            }
            _ => None,
        }
    }

    /// Reset the circuit breaker to Closed state with zeroed counters.
    pub fn reset(&self) {
        self.failure_count.store(0, Ordering::Release);
        self.success_count.store(0, Ordering::Release);
        self.last_failure_time.store(0, Ordering::Release);
        self.arm_probe_budget();
        self.state.store(STATE_CLOSED, Ordering::Release);
    }

    // --- Internal Helpers ---

    /// Claim one of the [`HALF_OPEN_MAX_PROBES`] probe slots, or refuse.
    ///
    /// Two things are going on, and the second exists because of how the
    /// consumers actually call `allow_request`:
    ///
    /// 1. The CAS loop is the limit itself. Without it every concurrent
    ///    request that arrives in the instant HalfOpen opens is admitted, so
    ///    a breaker at 4000 rps points full traffic at a still-dead upstream
    ///    once per `open_duration`, which is exactly what the state exists
    ///    to prevent.
    /// 2. The forgiveness above it covers slots that are never returned. A
    ///    slot is released on `record_success` / `record_failure`, or by
    ///    hand through [`Self::release_probe`], and a caller can reach
    ///    none of the three: the load balancer and the AI router both call
    ///    `allow_request` as a per-candidate eligibility predicate, so a
    ///    candidate that is evaluated and then not selected takes a slot
    ///    and reports nothing, with no later call that knows to give it
    ///    back. Without forgiveness the first such request would pin the
    ///    breaker in HalfOpen-rejects for the life of the process. Once a
    ///    full `open_duration` has passed with no state change, the
    ///    outstanding slots are written off and one probe goes through, so
    ///    the worst case degrades to one probe per recovery cycle rather
    ///    than a permanent wedge. Forgiveness is the backstop, not the
    ///    plan: a caller that knows it produced no verdict should say so
    ///    with `release_probe` rather than wait out an open duration.
    ///
    /// The CAS on `last_probe_time` makes exactly one caller the forgiver.
    /// What this does *not* guarantee is an exact cap at the forgiveness
    /// boundary: a caller mid-CAS in the loop below can land its increment
    /// just after the forgiver's store, admitting one extra probe for that
    /// cycle. The invariant the fix carries is "bounded by roughly
    /// [`HALF_OPEN_MAX_PROBES`]", never "unbounded", which is the failure
    /// being fixed.
    fn try_admit_probe(&self) -> bool {
        let now = Self::now_millis();
        let last = self.last_probe_time.load(Ordering::Acquire);
        // `max(1)` so a zero `open_duration` (no cooldown at all) does not
        // make every call a forgiveness and defeat the limit outright.
        let forgive_after = self.open_duration_ms.max(1);
        if last != 0
            && now.saturating_sub(last) >= forgive_after
            && self
                .last_probe_time
                .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            self.probes_in_flight.store(1, Ordering::Release);
            return true;
        }

        loop {
            let current = self.probes_in_flight.load(Ordering::Acquire);
            if current >= HALF_OPEN_MAX_PROBES {
                return false;
            }
            if self
                .probes_in_flight
                .compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.last_probe_time.store(now, Ordering::Release);
                return true;
            }
        }
    }

    /// Hand back a probe slot the caller took and cannot report on.
    ///
    /// [`record_success`](Self::record_success) and
    /// [`record_failure`](Self::record_failure) already release the slot,
    /// so this is for the third case: an admitted request that produced no
    /// verdict about the upstream's health at all. The AI-crawl ledger
    /// client is the one in tree. Its redeem returns early on a hard,
    /// non-retryable error (`ledger.token_already_spent`,
    /// `ledger.signature_invalid`), which a perfectly healthy ledger
    /// answers with; deliberately, that does not flap the breaker. Without
    /// this the slot would only come back through the stale-slot
    /// forgiveness inside the admission path, so one refused token would
    /// leave every other redeem answered with a synthetic
    /// `ledger.unavailable` for a whole open duration, which the crawl
    /// policy turns into a fail-closed 503.
    ///
    /// Saturating, so an extra call on a breaker with nothing outstanding
    /// is a no-op rather than an underflow that would hand out an
    /// unbounded number of probes.
    pub fn release_probe(&self) {
        let _ =
            self.probes_in_flight
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |in_flight| {
                    Some(in_flight.saturating_sub(1))
                });
    }

    /// Start a fresh recovery cycle: no probes outstanding, no admission to
    /// forgive yet.
    fn arm_probe_budget(&self) {
        self.probes_in_flight.store(0, Ordering::Release);
        self.last_probe_time.store(0, Ordering::Release);
    }

    fn transition_to_open(&self) {
        self.state.store(STATE_OPEN, Ordering::Release);
        self.success_count.store(0, Ordering::Release);
        self.arm_probe_budget();
    }

    fn transition_to_closed(&self) {
        self.failure_count.store(0, Ordering::Release);
        self.success_count.store(0, Ordering::Release);
        self.arm_probe_budget();
        self.state.store(STATE_CLOSED, Ordering::Release);
    }

    fn open_duration_elapsed(&self) -> bool {
        let last = self.last_failure_time.load(Ordering::Acquire);
        if last == 0 {
            return false;
        }
        let now = Self::now_millis();
        now.saturating_sub(last) >= self.open_duration_ms
    }

    fn now_millis() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    fn decode_state(raw: u32) -> CircuitState {
        match raw {
            STATE_CLOSED => CircuitState::Closed,
            STATE_OPEN => CircuitState::Open,
            STATE_HALF_OPEN => CircuitState::HalfOpen,
            _ => CircuitState::Closed,
        }
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn starts_closed() {
        let cb = CircuitBreaker::new(3, 2, Duration::from_secs(5));
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow_request());
    }

    #[test]
    fn transitions_to_open_on_failures() {
        let cb = CircuitBreaker::new(3, 2, Duration::from_secs(60));
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow_request());

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.allow_request());
    }

    #[test]
    fn open_rejects_requests_before_timeout() {
        let cb = CircuitBreaker::new(2, 1, Duration::from_secs(60));
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.allow_request());
    }

    #[test]
    fn open_transitions_to_half_open_after_timeout() {
        let cb = CircuitBreaker::new(2, 1, Duration::from_millis(0));
        cb.record_failure();
        cb.record_failure();

        // open_duration is 0ms, so it should immediately transition to HalfOpen.
        // (With 0ms timeout, we may never observe Open from state().)
        std::thread::sleep(Duration::from_millis(1));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        assert!(cb.allow_request());
    }

    #[test]
    fn half_open_closes_on_success_threshold() {
        let cb = CircuitBreaker::new(2, 2, Duration::from_millis(0));
        cb.record_failure();
        cb.record_failure();

        // Force HalfOpen by checking state (0ms open_duration).
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        cb.record_success();
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow_request());
    }

    #[test]
    fn half_open_reopens_on_failure() {
        // Use a long open_duration so we can observe the Open state after HalfOpen failure.
        let cb = CircuitBreaker::new(2, 2, Duration::from_secs(60));
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // Manually force HalfOpen by setting state directly.
        cb.state.store(2, Ordering::Release); // STATE_HALF_OPEN
        cb.success_count.store(0, Ordering::Release);
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Failure in HalfOpen should transition back to Open.
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.allow_request());
    }

    #[test]
    fn success_in_closed_resets_failure_count() {
        let cb = CircuitBreaker::new(3, 1, Duration::from_secs(60));
        cb.record_failure();
        cb.record_failure();
        cb.record_success();
        // Failure count reset, so one more failure should not trip the breaker.
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    /// Rewind the last-failure stamp past the cooldown so the next
    /// `state()` performs the Open to HalfOpen transition, without the test
    /// sleeping through a real open duration.
    fn cool_down(cb: &CircuitBreaker) {
        cb.last_failure_time.store(
            CircuitBreaker::now_millis() - cb.open_duration_ms - 1,
            Ordering::Release,
        );
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    /// Drive a breaker to Open, then into HalfOpen with a fresh probe budget.
    fn open_then_cool_down(cb: &CircuitBreaker, failures: u32) {
        for _ in 0..failures {
            cb.record_failure();
        }
        assert_eq!(cb.state(), CircuitState::Open);
        cool_down(cb);
    }

    #[test]
    fn half_open_admits_one_probe_and_refuses_the_rest() {
        // The seam: `allow_request` in HalfOpen. Before the probe gate it
        // returned true unconditionally, so every concurrent request in the
        // instant the cooldown lapsed was dispatched at a still-dead
        // upstream. A long open duration keeps the stale-slot forgiveness
        // out of the way, so what this measures is the limit itself.
        let cb = CircuitBreaker::new(2, 5, Duration::from_secs(30));
        open_then_cool_down(&cb, 2);

        assert!(cb.allow_request(), "the first probe must get through");
        for _ in 0..100 {
            assert!(
                !cb.allow_request(),
                "a HalfOpen breaker must not admit a second concurrent probe"
            );
        }
    }

    #[test]
    fn a_clean_probe_returns_its_slot_for_the_next_one() {
        let cb = CircuitBreaker::new(2, 3, Duration::from_secs(30));
        open_then_cool_down(&cb, 2);

        assert!(cb.allow_request());
        assert!(!cb.allow_request(), "the slot is still out");
        assert_eq!(
            cb.record_success(),
            None,
            "one success out of three closes nothing"
        );
        assert!(
            cb.allow_request(),
            "the returned slot must admit the next probe immediately, not \
             after another whole open duration"
        );
    }

    #[test]
    fn a_probe_slot_its_caller_never_returns_is_forgiven() {
        // Both load-balancer consumers call `allow_request` as a
        // per-candidate eligibility predicate, so a candidate can take a
        // probe slot and then never be dispatched: no `record_success`, no
        // `record_failure`, no release. Forgiveness is what keeps that from
        // pinning the breaker in HalfOpen-rejects for the whole process.
        let cb = CircuitBreaker::new(2, 1, Duration::from_millis(100));
        open_then_cool_down(&cb, 2);

        assert!(cb.allow_request());
        assert!(!cb.allow_request());
        std::thread::sleep(Duration::from_millis(150));
        assert!(
            cb.allow_request(),
            "an abandoned probe slot must not wedge the breaker"
        );
    }

    #[test]
    fn a_probe_that_learned_nothing_can_hand_its_slot_straight_back() {
        // The AI-crawl ledger client's case: the probe was dispatched, the
        // ledger answered, and the answer was a hard business refusal that
        // says nothing about whether the endpoint is healthy. It reports
        // neither success nor failure, so without an explicit return the
        // slot would sit out a whole open duration and every other redeem
        // in that window would be refused as if the ledger were down.
        let cb = CircuitBreaker::new(2, 1, Duration::from_secs(30));
        open_then_cool_down(&cb, 2);

        assert!(cb.allow_request());
        assert!(!cb.allow_request(), "the slot is out");
        cb.release_probe();
        assert!(
            cb.allow_request(),
            "a returned slot must admit the next probe now, not after \
             another open duration"
        );

        // Still exactly one at a time, and an over-release cannot mint
        // extra probes out of a saturating decrement.
        assert!(!cb.allow_request());
        cb.release_probe();
        cb.release_probe();
        cb.release_probe();
        assert!(cb.allow_request());
        assert!(
            !cb.allow_request(),
            "three releases of one slot must not widen the budget"
        );
    }

    #[test]
    fn reopening_rearms_the_probe_budget() {
        let cb = CircuitBreaker::new(2, 1, Duration::from_secs(30));
        open_then_cool_down(&cb, 2);
        assert!(cb.allow_request());
        // Probe fails: back to Open, and the next cooldown must hand out a
        // fresh slot rather than inherit the spent one.
        assert_eq!(
            cb.record_failure(),
            Some((CircuitState::HalfOpen, CircuitState::Open))
        );
        cool_down(&cb);
        assert!(cb.allow_request(), "each recovery cycle gets its own probe");
    }

    #[test]
    fn reset_restores_closed() {
        let cb = CircuitBreaker::new(2, 1, Duration::from_secs(60));
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        cb.reset();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow_request());
    }
}

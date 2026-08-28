// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! How much of a Pingora worker's stack the request path actually uses.
//!
//! A stack overflow does not unwind. It aborts, mid-request, with no
//! backtrace and no chance to log anything, and the only clue it leaves
//! is a line naming the thread:
//!
//! ```text
//! thread 'Pingora HTTP Proxy Service' has overflowed its stack
//! fatal runtime error: stack overflow, aborting
//! ```
//!
//! CI's request-path smoke lane has produced that line twice in two days
//! on ordinary feature branches. Both times every stack guard in the
//! tree was green, because each of them measured `size_of` on a single
//! future. A future's size is the state it holds between polls; the
//! stack is the whole chain of frames live while it is being polled,
//! and one says almost nothing about the other. A 36 KiB future can sit
//! at the top of a megabyte of frames.
//!
//! This module measures the second thing. Pingora's runtime records the
//! address of a local in each worker thread's entry frame; the request
//! path takes the address of a local at its deepest point; the
//! difference is the number of bytes of stack actually in use there.
//! That number is a budget a ratchet can hold, and it moves when the
//! path grows.
//!
//! # What it costs
//!
//! Per probe: one call, two thread-local reads, a subtraction, a
//! comparison, and a branch that is not taken once the thread has
//! settled. The process-wide maximum is only written on the rare
//! occasion a thread beats its own record, so the steady state touches
//! no shared memory and no lock. Probes are placed once per request
//! rather than once per chunk.
//!
//! No `unsafe`. Taking the address of a local, casting a reference to a
//! raw pointer, and casting that pointer to an integer are all safe;
//! only a dereference would not be, and nothing here dereferences.
//!
//! # What it cannot see
//!
//! It reports the deepest point the probes are placed at, not the
//! deepest point reached. Frames below a probe, inside TLS, inside a
//! JSON parser, inside the guardrail pipeline, are not counted. The
//! number is therefore a floor on stack usage and a trend, and the
//! budget it is held against leaves room for the difference.
//!
//! A thread that no Pingora runtime started has no recorded base, and
//! every probe on it is a no-op that reports nothing. That covers the
//! main thread, the admin runtime, and any `#[tokio::test]`, which is
//! why the stack budget tests run their dispatch on a real Pingora
//! runtime rather than on the test harness thread.

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Deepest stack usage any request in this process has reached, bytes.
///
/// Zero until the first probe on a thread with a recorded base.
static PROCESS_HIGH_WATER: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    /// Deepest usage this thread has reached.
    ///
    /// Const-initialized so a read is a plain thread-local load with no
    /// lazy-initialization branch. This is what makes the probe cheap
    /// enough to leave on: after a thread settles, every later probe
    /// compares against this and stops.
    static THREAD_HIGH_WATER: Cell<usize> = const { Cell::new(0) };
}

/// Record how deep the stack is at the caller.
///
/// Call it at the deepest point of a path worth measuring, once per
/// request rather than once per chunk: the depth of a loop body does not
/// change between iterations, and the probe is only free if it is not in
/// the inner loop.
///
/// `#[inline]` so the call folds into the caller and the measured frame
/// is the caller's own.
#[inline]
pub(crate) fn record_depth() {
    // `here()` is `#[inline(never)]` in pingora-runtime, so its frame
    // sits one call below this one. That constant offset is counted in
    // the reported number, which is the conservative direction.
    let Some(used) =
        pingora_runtime::worker_stack::used_here(pingora_runtime::worker_stack::here())
    else {
        // Not a Pingora runtime thread: nothing to measure against.
        return;
    };
    if used <= THREAD_HIGH_WATER.get() {
        return;
    }
    THREAD_HIGH_WATER.set(used);
    publish(used, pingora_runtime::worker_stack::size());
}

/// Fraction of a worker's stack that warrants telling an operator.
///
/// Three quarters, because the remaining quarter is what a request with
/// TLS, a guardrail pipeline and a format translator wired needs over
/// one without them. A proxy that reaches this is not failing, but it is
/// one feature away from an abort that will leave no diagnosis behind,
/// and that is worth a line in the log while there is still a log.
const STACK_WARN_FRACTION: f64 = 0.75;

/// Whether the crossing warning has been emitted in this process.
static WARNED: AtomicBool = AtomicBool::new(false);

/// Push a new per-thread record out to the process-wide maximum.
///
/// Out of line and never inlined: it runs only when a thread beats its
/// own record, which after warmup is never, and keeping it out of the
/// caller keeps the hot path to a load, a compare and a branch.
#[inline(never)]
fn publish(used: usize, stack: usize) {
    if PROCESS_HIGH_WATER.fetch_max(used, Ordering::Relaxed) >= used {
        return;
    }
    if stack == 0 {
        return;
    }
    let fraction = used as f64 / stack as f64;
    if fraction < STACK_WARN_FRACTION || WARNED.swap(true, Ordering::Relaxed) {
        return;
    }
    // Once per process. A stack overflow aborts without unwinding, so
    // this is the last chance to say anything at all about it, and
    // repeating it per request would bury the one line that matters.
    tracing::warn!(
        stack_used_bytes = used,
        worker_stack_bytes = stack,
        stack_used_percent = format_args!("{:.1}", fraction * 100.0),
        "the request path is using most of a worker's stack; raise runtime_thread_stack_size before it aborts"
    );
}

/// The deepest stack usage this thread has reached, in bytes.
///
/// Zero on a thread that has never probed, or that no Pingora runtime
/// started. This is the number a stack budget test reads, because it is
/// the one measurement that belongs to the caller alone: the
/// process-wide maximum is shared with every other test in the binary.
#[cfg(test)]
pub(crate) fn thread_high_water_bytes() -> usize {
    THREAD_HIGH_WATER.get()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A thread the harness started, not a Pingora runtime, reports
    /// nothing and does not panic.
    #[test]
    fn a_thread_with_no_recorded_base_measures_nothing() {
        record_depth();
        assert_eq!(
            thread_high_water_bytes(),
            0,
            "a thread no Pingora runtime started has no base to measure against"
        );
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! SLO priority admission (WOR-1679 core).
//!
//! When one local engine serves several tenants, an interactive
//! request must not sit behind a batch job. This is the pure admission
//! policy: given the priority classes of the in-flight requests and
//! the engine's concurrency, decide whether a new request is admitted,
//! queued, or admitted by preempting a lower-priority one (ProServe's
//! single-queue, selective-preemption approach). Binding a class to a
//! virtual key and driving real preemption is the request-path wiring
//! (enterprise), which reuses this decision.

/// A request's SLO priority, highest first.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PriorityClass {
    /// Latency-critical interactive traffic (chat UIs, agents).
    Interactive,
    /// The default class.
    Standard,
    /// Best-effort bulk work; yields to everything above.
    Batch,
}

impl PriorityClass {
    /// Stable snake-case label.
    pub const fn as_str(self) -> &'static str {
        match self {
            PriorityClass::Interactive => "interactive",
            PriorityClass::Standard => "standard",
            PriorityClass::Batch => "batch",
        }
    }

    /// Rank, lower is higher priority (Interactive = 0).
    pub(crate) const fn rank(self) -> u8 {
        match self {
            PriorityClass::Interactive => 0,
            PriorityClass::Standard => 1,
            PriorityClass::Batch => 2,
        }
    }
}

/// What to do with an arriving request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchedulingDecision {
    /// Run it now (there was free capacity).
    Admit,
    /// Run it now by preempting the running request at this index (a
    /// strictly lower-priority one).
    Preempt {
        /// Index into the `running` slice of the request to preempt.
        victim: usize,
    },
    /// No room and nothing lower-priority to preempt; wait in the queue.
    Queue,
}

/// Decide admission for a `candidate` against the `running` requests
/// and the engine `capacity` (max concurrent). Admits into free
/// capacity; otherwise preempts the lowest-priority running request
/// when the candidate outranks it (ties do not preempt); otherwise
/// queues. When several running requests tie for lowest priority, the
/// last one (most recently admitted) is chosen as the victim so the
/// oldest work is more likely to finish.
pub fn admit(
    candidate: PriorityClass,
    running: &[PriorityClass],
    capacity: usize,
) -> SchedulingDecision {
    if running.len() < capacity {
        return SchedulingDecision::Admit;
    }
    // Find the lowest-priority (highest rank) running request; on ties,
    // prefer the latest index.
    let mut victim: Option<usize> = None;
    let mut worst_rank = 0u8;
    for (i, r) in running.iter().enumerate() {
        if victim.is_none() || r.rank() >= worst_rank {
            worst_rank = r.rank();
            victim = Some(i);
        }
    }
    match victim {
        Some(i) if candidate.rank() < running[i].rank() => {
            SchedulingDecision::Preempt { victim: i }
        }
        _ => SchedulingDecision::Queue,
    }
}

/// Pick the next queued request to admit: highest priority, and FIFO
/// within a class (lowest arrival tick). Returns the index into
/// `waiting` of `(class, arrival_tick)` pairs, or `None` when empty.
pub fn next_to_admit(waiting: &[(PriorityClass, u64)]) -> Option<usize> {
    waiting
        .iter()
        .enumerate()
        .min_by_key(|(_, (class, arrival))| (class.rank(), *arrival))
        .map(|(i, _)| i)
}

#[cfg(test)]
mod tests {
    use super::*;
    use PriorityClass::*;

    #[test]
    fn admits_into_free_capacity() {
        assert_eq!(
            admit(Standard, &[Interactive], 2),
            SchedulingDecision::Admit
        );
    }

    #[test]
    fn interactive_preempts_a_batch_when_full() {
        // Full at capacity 2, running a batch and a standard; an
        // interactive request preempts the batch (lowest priority).
        let running = [Standard, Batch];
        assert_eq!(
            admit(Interactive, &running, 2),
            SchedulingDecision::Preempt { victim: 1 }
        );
    }

    #[test]
    fn no_preempt_on_equal_or_higher_priority() {
        // A batch request cannot preempt other batches; it queues.
        assert_eq!(admit(Batch, &[Batch, Batch], 2), SchedulingDecision::Queue);
        // A standard cannot preempt interactives; it queues.
        assert_eq!(
            admit(Standard, &[Interactive, Interactive], 2),
            SchedulingDecision::Queue
        );
    }

    #[test]
    fn preempts_latest_among_tied_victims() {
        // Two batches tied for lowest; the later index is chosen.
        let running = [Batch, Standard, Batch];
        assert_eq!(
            admit(Interactive, &running, 3),
            SchedulingDecision::Preempt { victim: 2 }
        );
    }

    #[test]
    fn next_to_admit_is_priority_then_fifo() {
        // Interactive beats standard; among standards, earliest arrival.
        let waiting = [(Standard, 5), (Interactive, 9), (Standard, 2)];
        assert_eq!(next_to_admit(&waiting), Some(1)); // the interactive
        let standards = [(Standard, 5), (Batch, 1), (Standard, 2)];
        assert_eq!(next_to_admit(&standards), Some(2)); // earliest standard
        assert_eq!(next_to_admit(&[]), None);
    }
}

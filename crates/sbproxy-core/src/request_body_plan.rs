//! Request-local planning for dynamic extension body consumers.

use sbproxy_config::BundleBodyMode;
use sbproxy_modules::DynamicHookMetadata;

/// Host-wide ceiling for one dynamically planned request-body buffer.
pub(crate) const DYNAMIC_REQUEST_BODY_HARD_CAP: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
struct BufferedPolicy {
    policy_index: usize,
    metadata: DynamicHookMetadata,
    active: bool,
}

/// Per-request state for dynamic hooks that need a complete request body.
#[derive(Debug, Clone, Default)]
pub(crate) struct DynamicRequestBodyPlan {
    policies: Vec<BufferedPolicy>,
    other_buffering_required: bool,
}

impl DynamicRequestBodyPlan {
    /// Build a plan from policies in configured chain order.
    pub(crate) fn from_policy_metadata<'a>(
        metadata: impl IntoIterator<Item = (usize, Option<&'a DynamicHookMetadata>)>,
    ) -> Self {
        let policies = metadata
            .into_iter()
            .filter_map(|(policy_index, metadata)| {
                let metadata = metadata?;
                (metadata.body_mode() == BundleBodyMode::Buffered).then(|| BufferedPolicy {
                    policy_index,
                    metadata: metadata.clone(),
                    active: true,
                })
            })
            .collect();
        Self {
            policies,
            other_buffering_required: false,
        }
    }

    /// Return true while at least one buffered policy still needs the body.
    pub(crate) fn has_active_buffered_policies(&self) -> bool {
        self.policies.iter().any(|policy| policy.active)
    }

    /// Return active policy indexes in configured chain order.
    pub(crate) fn active_policy_indexes(&self) -> Vec<usize> {
        self.policies
            .iter()
            .filter(|policy| policy.active)
            .map(|policy| policy.policy_index)
            .collect()
    }

    /// Record whether a non-dynamic consumer independently needs buffering.
    pub(crate) fn set_other_buffering_required(&mut self, required: bool) {
        self.other_buffering_required = required;
    }

    /// Return whether a non-dynamic consumer independently needs buffering.
    pub(crate) const fn other_buffering_required(&self) -> bool {
        self.other_buffering_required
    }

    /// Apply all currently applicable hook caps before a proposed allocation.
    ///
    /// Admitting policies are removed from this request's active set. Closed
    /// policies and buffered actions return an overflow without changing the
    /// buffer. Action manifests are validated as closed, so an action is never
    /// a skippable consumer here.
    pub(crate) fn before_growth(
        &mut self,
        proposed_len: usize,
        action: Option<&DynamicHookMetadata>,
    ) -> Result<Vec<SkippedHook>, ClosedOverflow> {
        #[derive(Clone, Copy)]
        enum Consumer {
            Policy(usize),
            Action,
        }

        let mut consumers = self
            .policies
            .iter()
            .enumerate()
            .filter(|(_, policy)| policy.active)
            .map(|(slot, policy)| {
                (
                    policy
                        .metadata
                        .max_buffer_bytes()
                        .min(DYNAMIC_REQUEST_BODY_HARD_CAP),
                    Consumer::Policy(slot),
                )
            })
            .collect::<Vec<_>>();
        if let Some(action) = action.filter(|hook| hook.body_mode() == BundleBodyMode::Buffered) {
            consumers.push((
                action.max_buffer_bytes().min(DYNAMIC_REQUEST_BODY_HARD_CAP),
                Consumer::Action,
            ));
        }
        consumers.sort_by_key(|(cap, _)| *cap);

        let mut skipped = Vec::new();
        for (cap, consumer) in consumers {
            if proposed_len <= cap {
                continue;
            }
            match consumer {
                Consumer::Policy(slot) => {
                    let policy = &mut self.policies[slot];
                    if policy.metadata.failure_posture().admits() {
                        policy.active = false;
                        skipped.push(SkippedHook {
                            policy_index: policy.policy_index,
                            metadata: policy.metadata.clone(),
                            cap,
                        });
                    } else {
                        return Err(ClosedOverflow {
                            policy_index: Some(policy.policy_index),
                            metadata: policy.metadata.clone(),
                            cap,
                        });
                    }
                }
                Consumer::Action => {
                    let metadata = action.expect("action consumer keeps its metadata");
                    return Err(ClosedOverflow {
                        policy_index: None,
                        metadata: metadata.clone(),
                        cap,
                    });
                }
            }
        }
        Ok(skipped)
    }
}

/// One admitting buffered policy skipped because its body exceeded its cap.
#[derive(Debug, Clone)]
pub(crate) struct SkippedHook {
    policy_index: usize,
    metadata: DynamicHookMetadata,
    cap: usize,
}

impl SkippedHook {
    /// Return the configured policy-chain index.
    pub(crate) const fn policy_index(&self) -> usize {
        self.policy_index
    }

    /// Return the skipped hook's manifest metadata.
    pub(crate) const fn metadata(&self) -> &DynamicHookMetadata {
        &self.metadata
    }

    /// Return the effective per-request buffering cap.
    pub(crate) const fn cap(&self) -> usize {
        self.cap
    }
}

/// A closed body consumer whose cap would be exceeded by an allocation.
#[derive(Debug, Clone)]
pub(crate) struct ClosedOverflow {
    policy_index: Option<usize>,
    metadata: DynamicHookMetadata,
    cap: usize,
}

impl ClosedOverflow {
    /// Return the policy index, or none when the consumer is an action.
    pub(crate) const fn policy_index(&self) -> Option<usize> {
        self.policy_index
    }

    /// Return the overflowing hook's manifest metadata.
    pub(crate) const fn metadata(&self) -> &DynamicHookMetadata {
        &self.metadata
    }

    /// Return the effective per-request buffering cap.
    pub(crate) const fn cap(&self) -> usize {
        self.cap
    }
}

#[cfg(test)]
mod tests {
    use sbproxy_config::{BundleBodyMode, FailureMode};
    use sbproxy_modules::DynamicHookMetadata;

    use super::*;

    fn metadata(
        hook_type: &str,
        body_mode: BundleBodyMode,
        cap: usize,
        posture: FailureMode,
    ) -> DynamicHookMetadata {
        DynamicHookMetadata::new(
            "fixture-bundle",
            hook_type,
            sbproxy_config::BundleRuntime::Wasm,
            body_mode,
            cap,
            posture,
        )
    }

    #[test]
    fn request_body_plan_advances_caps_only_after_admitting_policy_is_skipped() {
        let none = metadata(
            "none-policy",
            BundleBodyMode::None,
            128,
            FailureMode::Closed,
        );
        let open = metadata(
            "open-policy",
            BundleBodyMode::Buffered,
            1024,
            FailureMode::Open,
        );
        let closed = metadata(
            "closed-policy",
            BundleBodyMode::Buffered,
            4096,
            FailureMode::Closed,
        );
        let mut plan = DynamicRequestBodyPlan::from_policy_metadata([
            (0, Some(&none)),
            (1, Some(&open)),
            (2, None),
            (3, Some(&closed)),
        ]);

        assert_eq!(plan.active_policy_indexes(), vec![1, 3]);

        let skipped = plan
            .before_growth(2048, None)
            .expect("an admitting policy should not reject the request");
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].policy_index(), 1);
        assert_eq!(skipped[0].metadata().hook_type(), "open-policy");
        assert_eq!(plan.active_policy_indexes(), vec![3]);

        let overflow = plan
            .before_growth(4097, None)
            .expect_err("the remaining closed policy should reject");
        assert_eq!(overflow.metadata().hook_type(), "closed-policy");
        assert_eq!(overflow.metadata().max_buffer_bytes(), 4096);
        assert_eq!(plan.active_policy_indexes(), vec![3]);
    }

    #[test]
    fn request_body_plan_ignores_none_and_linked_plugins() {
        let none = metadata("none-policy", BundleBodyMode::None, 1, FailureMode::Closed);
        let plan = DynamicRequestBodyPlan::from_policy_metadata([(0, Some(&none)), (1, None)]);

        assert!(!plan.has_active_buffered_policies());
        assert!(plan.active_policy_indexes().is_empty());
    }

    #[test]
    fn every_admitting_posture_skips_an_oversize_buffered_policy() {
        for posture in [
            FailureMode::Open,
            FailureMode::Degraded,
            FailureMode::Observe,
        ] {
            let policy = metadata("admitting-policy", BundleBodyMode::Buffered, 1024, posture);
            let mut plan = DynamicRequestBodyPlan::from_policy_metadata([(0, Some(&policy))]);

            let skipped = plan
                .before_growth(1025, None)
                .expect("admitting posture should skip the policy");

            assert_eq!(skipped.len(), 1, "posture: {posture:?}");
            assert_eq!(skipped[0].metadata().failure_posture(), posture);
            assert!(!plan.has_active_buffered_policies());
        }
    }

    #[test]
    fn request_body_plan_applies_the_host_cap_with_each_hooks_posture() {
        let open = metadata(
            "open-policy",
            BundleBodyMode::Buffered,
            DYNAMIC_REQUEST_BODY_HARD_CAP * 2,
            FailureMode::Open,
        );
        let action = metadata(
            "closed-action",
            BundleBodyMode::Buffered,
            DYNAMIC_REQUEST_BODY_HARD_CAP * 2,
            FailureMode::Closed,
        );
        let mut plan = DynamicRequestBodyPlan::from_policy_metadata([(0, Some(&open))]);

        let overflow = plan
            .before_growth(DYNAMIC_REQUEST_BODY_HARD_CAP + 1, Some(&action))
            .expect_err("the terminal action should reject after the open policy is skipped");

        assert_eq!(overflow.policy_index(), None);
        assert_eq!(overflow.metadata().hook_type(), "closed-action");
        assert_eq!(overflow.cap(), DYNAMIC_REQUEST_BODY_HARD_CAP);
        assert!(!plan.has_active_buffered_policies());
    }
}

//! Verdict combiner for multi-policy [`PolicyDecision`] aggregation.
//!
//! When several policies match the same request (typical for MCP tool
//! calls that fan out across allow-lists, AI guardrails, and tenant
//! rules), the runtime needs a single terminal verdict per request.
//! [`combine_verdicts`] implements the WOR-152 combination matrix:
//!
//! - Any [`PolicyDecision::Deny`] in the set means the combined
//!   decision is `Deny`.
//! - Otherwise, any [`PolicyDecision::Confirm`] means the combined
//!   decision is `Confirm`.
//! - Otherwise the combined decision is [`PolicyDecision::Allow`],
//!   including the empty-iterator case (no policies means no
//!   constraint).
//!
//! The chosen `Deny` or `Confirm` is the first one encountered in
//! iteration order; the function is otherwise pure and deterministic.
//! Every contributing `Deny` reason and every contributing `Confirm`
//! reason is retained on the returned [`CombinedVerdict`] so audit
//! events and dashboards can surface the full set of policies that
//! voted to block or to require approval, not just the first.
//!
//! See `docs/adr-policy-verdict-shape.md` for the broader verdict
//! design and WOR-152 for the acceptance gate (allow / confirm / deny
//! matrix documented and unit-tested).
//!
//! [`PolicyDecision::Deny`]: crate::PolicyDecision::Deny
//! [`PolicyDecision::Confirm`]: crate::PolicyDecision::Confirm
//! [`PolicyDecision::Allow`]: crate::PolicyDecision::Allow

use crate::PolicyDecision;

/// Result of combining multiple per-policy verdicts.
///
/// The `decision` field is the single terminal verdict that the
/// runtime acts on. The two `*_reasons` vectors carry every
/// contributing reason in iteration order so audit pipelines can
/// surface which policies voted to block or require approval; they
/// are populated independently of `decision`.
///
/// - When `decision` is [`PolicyDecision::Deny`], `deny_reasons` lists
///   every `Deny` reason observed (length >= 1) and `confirm_reasons`
///   is empty (a `Deny` outcome means the runtime will not ask for
///   approval, so propagating those reasons here would be
///   misleading; if you need the pre-deny signal for audit, read it
///   from the per-policy verdicts before combining).
/// - When `decision` is [`PolicyDecision::Confirm`], `deny_reasons` is
///   empty and `confirm_reasons` lists every `Confirm` reason (length
///   >= 1).
/// - When `decision` is [`PolicyDecision::Allow`], both reason vectors
///   are empty.
///
/// `policy_count` reports the total number of decisions consumed from
/// the iterator, including `Allow` and `AllowWithHeaders` votes that
/// do not appear in either reason vector. It is useful for log
/// messages of the form "12 policies evaluated, 2 voted deny".
///
/// [`PolicyDecision::Deny`]: crate::PolicyDecision::Deny
/// [`PolicyDecision::Confirm`]: crate::PolicyDecision::Confirm
/// [`PolicyDecision::Allow`]: crate::PolicyDecision::Allow
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CombinedVerdict {
    /// The terminal verdict the runtime should act on.
    pub decision: PolicyDecision,
    /// Every `Deny` reason observed, in iteration order. Empty when
    /// `decision` is not `Deny`.
    pub deny_reasons: Vec<String>,
    /// Every `Confirm` reason observed, in iteration order. Empty when
    /// `decision` is `Allow` or `Deny`. Note: a `Deny` outcome
    /// suppresses these because the runtime never asks for approval
    /// once any policy has voted deny; if you need the pre-deny
    /// signal for audit, read it from the per-policy verdicts before
    /// combining.
    pub confirm_reasons: Vec<String>,
    /// Total number of decisions consumed (including `Allow` votes).
    pub policy_count: usize,
}

impl CombinedVerdict {
    /// Convenience constructor for the empty-input case (and any case
    /// that resolves to a plain `Allow`).
    fn allow(policy_count: usize) -> Self {
        Self {
            decision: PolicyDecision::Allow,
            deny_reasons: Vec::new(),
            confirm_reasons: Vec::new(),
            policy_count,
        }
    }
}

/// Combine multiple per-policy [`PolicyDecision`] values into a single
/// terminal verdict per the WOR-152 matrix.
///
/// # Semantics
///
/// 1. Any [`PolicyDecision::Deny`] in the input means the combined
///    decision is `Deny`. The chosen `Deny` is the first one
///    encountered; every `Deny` reason in the input is recorded on
///    `CombinedVerdict::deny_reasons`.
/// 2. Otherwise, any [`PolicyDecision::Confirm`] in the input means
///    the combined decision is `Confirm`. The chosen `Confirm` is the
///    first one encountered; its `reason`, `webhook_url`, and
///    `expires_at` fields are taken wholesale (no merging across
///    multiple `Confirm` votes). Every `Confirm` reason in the input
///    is recorded on `CombinedVerdict::confirm_reasons`.
/// 3. Otherwise (including the empty-iterator case) the combined
///    decision is [`PolicyDecision::Allow`].
///
/// [`PolicyDecision::AllowWithHeaders`] is treated as an `Allow` for
/// the purpose of combination. The headers it carries are not merged
/// here; callers that need the response-header side effects apply
/// them per-policy before combining, since header rewriting is not
/// part of the verdict-combination contract.
///
/// # Determinism
///
/// The combiner consumes the input iterator in order and is otherwise
/// pure. Given the same sequence of inputs it always returns the same
/// [`CombinedVerdict`]. This matters for replayable audit chains and
/// for tests that snapshot a verdict by its reason strings.
///
/// # Examples
///
/// Allow when every policy votes allow:
///
/// ```
/// use sbproxy_plugin::{combine_verdicts, PolicyDecision};
///
/// let verdict = combine_verdicts([PolicyDecision::Allow, PolicyDecision::Allow]);
/// assert_eq!(verdict.decision, PolicyDecision::Allow);
/// assert!(verdict.deny_reasons.is_empty());
/// assert!(verdict.confirm_reasons.is_empty());
/// assert_eq!(verdict.policy_count, 2);
/// ```
///
/// Deny wins over Confirm and Allow, and every contributing reason
/// is retained:
///
/// ```
/// use sbproxy_plugin::{combine_verdicts, PolicyDecision};
///
/// let decisions = vec![
///     PolicyDecision::confirm("needs approval", None, None),
///     PolicyDecision::Deny {
///         status: 403,
///         message: "blocked by tenant rule".into(),
///     },
///     PolicyDecision::Deny {
///         status: 403,
///         message: "blocked by AI guardrail".into(),
///     },
/// ];
/// let verdict = combine_verdicts(decisions);
/// assert!(matches!(verdict.decision, PolicyDecision::Deny { .. }));
/// assert_eq!(verdict.deny_reasons.len(), 2);
/// ```
///
/// Confirm wins when there is no `Deny`:
///
/// ```
/// use sbproxy_plugin::{combine_verdicts, PolicyDecision};
///
/// let decisions = vec![
///     PolicyDecision::Allow,
///     PolicyDecision::confirm("manager approval required", None, None),
/// ];
/// let verdict = combine_verdicts(decisions);
/// assert!(matches!(verdict.decision, PolicyDecision::Confirm { .. }));
/// assert_eq!(verdict.confirm_reasons, vec!["manager approval required".to_string()]);
/// ```
///
/// [`PolicyDecision`]: crate::PolicyDecision
/// [`PolicyDecision::Deny`]: crate::PolicyDecision::Deny
/// [`PolicyDecision::Confirm`]: crate::PolicyDecision::Confirm
/// [`PolicyDecision::Allow`]: crate::PolicyDecision::Allow
/// [`PolicyDecision::AllowWithHeaders`]: crate::PolicyDecision::AllowWithHeaders
pub fn combine_verdicts<I>(decisions: I) -> CombinedVerdict
where
    I: IntoIterator<Item = PolicyDecision>,
{
    // We walk the iterator once and stash:
    //   - the first Deny we see (full PolicyDecision, so its status +
    //     message survive into the combined decision)
    //   - the first Confirm we see (likewise, for its webhook_url and
    //     expires_at)
    //   - every Deny reason and every Confirm reason in order
    //   - the total count
    let mut first_deny: Option<PolicyDecision> = None;
    let mut first_confirm: Option<PolicyDecision> = None;
    let mut deny_reasons: Vec<String> = Vec::new();
    let mut confirm_reasons: Vec<String> = Vec::new();
    let mut policy_count: usize = 0;

    for d in decisions {
        policy_count += 1;
        match &d {
            PolicyDecision::Allow | PolicyDecision::AllowWithHeaders { .. } => {}
            PolicyDecision::Deny { message, .. } => {
                deny_reasons.push(message.clone());
                if first_deny.is_none() {
                    first_deny = Some(d);
                }
            }
            PolicyDecision::Confirm { reason, .. } => {
                confirm_reasons.push(reason.clone());
                if first_confirm.is_none() {
                    first_confirm = Some(d);
                }
            }
        }
    }

    if let Some(deny) = first_deny {
        // Deny outcome suppresses confirm_reasons in the returned
        // verdict: the runtime will not ask for approval once any
        // policy has voted deny, so propagating those reasons here
        // would be misleading. Callers that need the pre-deny signal
        // can inspect the raw per-policy decisions.
        return CombinedVerdict {
            decision: deny,
            deny_reasons,
            confirm_reasons: Vec::new(),
            policy_count,
        };
    }

    if let Some(confirm) = first_confirm {
        return CombinedVerdict {
            decision: confirm,
            deny_reasons: Vec::new(),
            confirm_reasons,
            policy_count,
        };
    }

    CombinedVerdict::allow(policy_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deny(msg: &str) -> PolicyDecision {
        PolicyDecision::Deny {
            status: 403,
            message: msg.to_string(),
        }
    }

    fn confirm(reason: &str) -> PolicyDecision {
        PolicyDecision::confirm(reason, None, None)
    }

    // ------------------------------------------------------------------
    // Zero-policy row
    // ------------------------------------------------------------------

    #[test]
    fn empty_iterator_is_allow() {
        let v = combine_verdicts(std::iter::empty::<PolicyDecision>());
        assert_eq!(v.decision, PolicyDecision::Allow);
        assert!(v.deny_reasons.is_empty());
        assert!(v.confirm_reasons.is_empty());
        assert_eq!(v.policy_count, 0);
    }

    // ------------------------------------------------------------------
    // Single-policy rows
    // ------------------------------------------------------------------

    #[test]
    fn single_allow_is_allow() {
        let v = combine_verdicts([PolicyDecision::Allow]);
        assert_eq!(v.decision, PolicyDecision::Allow);
        assert_eq!(v.policy_count, 1);
        assert!(v.deny_reasons.is_empty());
        assert!(v.confirm_reasons.is_empty());
    }

    #[test]
    fn single_allow_with_headers_is_allow() {
        // AllowWithHeaders is treated as an Allow vote for combination
        // purposes; the header side effects are applied per-policy
        // outside the combiner.
        let v = combine_verdicts([PolicyDecision::AllowWithHeaders {
            headers: vec![("X-Test".into(), "1".into())],
        }]);
        assert_eq!(v.decision, PolicyDecision::Allow);
        assert_eq!(v.policy_count, 1);
        assert!(v.deny_reasons.is_empty());
        assert!(v.confirm_reasons.is_empty());
    }

    #[test]
    fn single_deny_propagates_status_and_message() {
        let v = combine_verdicts([deny("r1")]);
        assert_eq!(
            v.decision,
            PolicyDecision::Deny {
                status: 403,
                message: "r1".into(),
            }
        );
        assert_eq!(v.deny_reasons, vec!["r1".to_string()]);
        assert!(v.confirm_reasons.is_empty());
        assert_eq!(v.policy_count, 1);
    }

    #[test]
    fn single_confirm_propagates_full_fields() {
        let url = url::Url::parse("https://approver.example.com/notify").unwrap();
        let when = chrono::Utc::now();
        let dec = PolicyDecision::confirm("needs nod", Some(url.clone()), Some(when));
        let v = combine_verdicts([dec.clone()]);
        assert_eq!(v.decision, dec);
        assert!(v.deny_reasons.is_empty());
        assert_eq!(v.confirm_reasons, vec!["needs nod".to_string()]);
        assert_eq!(v.policy_count, 1);
    }

    // ------------------------------------------------------------------
    // Multi-policy rows: pairs
    // ------------------------------------------------------------------

    #[test]
    fn allow_then_allow_is_allow() {
        let v = combine_verdicts([PolicyDecision::Allow, PolicyDecision::Allow]);
        assert_eq!(v.decision, PolicyDecision::Allow);
        assert_eq!(v.policy_count, 2);
    }

    #[test]
    fn allow_then_deny_is_deny() {
        let v = combine_verdicts([PolicyDecision::Allow, deny("r1")]);
        assert!(matches!(v.decision, PolicyDecision::Deny { .. }));
        assert_eq!(v.deny_reasons, vec!["r1".to_string()]);
        assert!(v.confirm_reasons.is_empty());
        assert_eq!(v.policy_count, 2);
    }

    #[test]
    fn deny_then_deny_keeps_first_decision_and_both_reasons() {
        let v = combine_verdicts([deny("r1"), deny("r2")]);
        match v.decision {
            PolicyDecision::Deny { ref message, .. } => assert_eq!(message, "r1"),
            other => panic!("expected Deny, got {other:?}"),
        }
        assert_eq!(v.deny_reasons, vec!["r1".to_string(), "r2".to_string()]);
        assert!(v.confirm_reasons.is_empty());
        assert_eq!(v.policy_count, 2);
    }

    #[test]
    fn allow_then_confirm_is_confirm() {
        let v = combine_verdicts([PolicyDecision::Allow, confirm("r1")]);
        match v.decision {
            PolicyDecision::Confirm { ref reason, .. } => assert_eq!(reason, "r1"),
            other => panic!("expected Confirm, got {other:?}"),
        }
        assert!(v.deny_reasons.is_empty());
        assert_eq!(v.confirm_reasons, vec!["r1".to_string()]);
        assert_eq!(v.policy_count, 2);
    }

    #[test]
    fn confirm_then_confirm_keeps_first_decision_and_both_reasons() {
        let url1 = url::Url::parse("https://a.example.com/").unwrap();
        let url2 = url::Url::parse("https://b.example.com/").unwrap();
        let c1 = PolicyDecision::confirm("r1", Some(url1.clone()), None);
        let c2 = PolicyDecision::confirm("r2", Some(url2), None);

        let v = combine_verdicts([c1.clone(), c2]);

        // Decision is the first Confirm wholesale: webhook_url is
        // url1, not a merge of url1 and url2.
        assert_eq!(v.decision, c1);
        assert!(v.deny_reasons.is_empty());
        assert_eq!(v.confirm_reasons, vec!["r1".to_string(), "r2".to_string()]);
        assert_eq!(v.policy_count, 2);
    }

    #[test]
    fn confirm_then_deny_is_deny_and_suppresses_confirm_reasons() {
        // Deny outcome means confirm_reasons on the combined verdict
        // is empty, even though a Confirm appeared in the input. The
        // policy_count still reflects both votes.
        let v = combine_verdicts([confirm("c1"), deny("d1")]);
        match v.decision {
            PolicyDecision::Deny { ref message, .. } => assert_eq!(message, "d1"),
            other => panic!("expected Deny, got {other:?}"),
        }
        assert_eq!(v.deny_reasons, vec!["d1".to_string()]);
        assert!(v.confirm_reasons.is_empty());
        assert_eq!(v.policy_count, 2);
    }

    #[test]
    fn deny_then_confirm_is_deny_and_suppresses_confirm_reasons() {
        // Order does not matter for the Deny-wins rule.
        let v = combine_verdicts([deny("d1"), confirm("c1")]);
        match v.decision {
            PolicyDecision::Deny { ref message, .. } => assert_eq!(message, "d1"),
            other => panic!("expected Deny, got {other:?}"),
        }
        assert_eq!(v.deny_reasons, vec!["d1".to_string()]);
        assert!(v.confirm_reasons.is_empty());
        assert_eq!(v.policy_count, 2);
    }

    // ------------------------------------------------------------------
    // Multi-policy rows: three or more
    // ------------------------------------------------------------------

    #[test]
    fn deny_confirm_allow_is_deny_first_wins() {
        let v = combine_verdicts([deny("d1"), confirm("c1"), PolicyDecision::Allow]);
        match v.decision {
            PolicyDecision::Deny { ref message, .. } => assert_eq!(message, "d1"),
            other => panic!("expected Deny, got {other:?}"),
        }
        assert_eq!(v.deny_reasons, vec!["d1".to_string()]);
        assert!(v.confirm_reasons.is_empty());
        assert_eq!(v.policy_count, 3);
    }

    #[test]
    fn allow_confirm_confirm_allow_is_first_confirm() {
        let v = combine_verdicts([
            PolicyDecision::Allow,
            confirm("c1"),
            confirm("c2"),
            PolicyDecision::Allow,
        ]);
        match v.decision {
            PolicyDecision::Confirm { ref reason, .. } => assert_eq!(reason, "c1"),
            other => panic!("expected Confirm, got {other:?}"),
        }
        assert!(v.deny_reasons.is_empty());
        assert_eq!(v.confirm_reasons, vec!["c1".to_string(), "c2".to_string()]);
        assert_eq!(v.policy_count, 4);
    }

    #[test]
    fn many_allows_only_is_allow() {
        let decisions: Vec<PolicyDecision> = std::iter::repeat_with(|| PolicyDecision::Allow)
            .take(100)
            .collect();
        let v = combine_verdicts(decisions);
        assert_eq!(v.decision, PolicyDecision::Allow);
        assert_eq!(v.policy_count, 100);
        assert!(v.deny_reasons.is_empty());
        assert!(v.confirm_reasons.is_empty());
    }

    #[test]
    fn many_denies_keeps_first_and_all_reasons_in_order() {
        let decisions: Vec<PolicyDecision> = (0..10).map(|i| deny(&format!("r{i}"))).collect();
        let v = combine_verdicts(decisions);
        match v.decision {
            PolicyDecision::Deny { ref message, .. } => assert_eq!(message, "r0"),
            other => panic!("expected Deny, got {other:?}"),
        }
        let expected: Vec<String> = (0..10).map(|i| format!("r{i}")).collect();
        assert_eq!(v.deny_reasons, expected);
        assert_eq!(v.policy_count, 10);
    }

    #[test]
    fn many_confirms_keeps_first_and_all_reasons_in_order() {
        let decisions: Vec<PolicyDecision> = (0..10).map(|i| confirm(&format!("r{i}"))).collect();
        let v = combine_verdicts(decisions);
        match v.decision {
            PolicyDecision::Confirm { ref reason, .. } => assert_eq!(reason, "r0"),
            other => panic!("expected Confirm, got {other:?}"),
        }
        let expected: Vec<String> = (0..10).map(|i| format!("r{i}")).collect();
        assert_eq!(v.confirm_reasons, expected);
        assert_eq!(v.policy_count, 10);
    }

    #[test]
    fn mixed_allow_with_headers_and_confirm_is_confirm() {
        // AllowWithHeaders is an Allow vote; Confirm should still win.
        let v = combine_verdicts([
            PolicyDecision::AllowWithHeaders {
                headers: vec![("X-A".into(), "1".into())],
            },
            confirm("need approval"),
            PolicyDecision::AllowWithHeaders {
                headers: vec![("X-B".into(), "2".into())],
            },
        ]);
        match v.decision {
            PolicyDecision::Confirm { ref reason, .. } => assert_eq!(reason, "need approval"),
            other => panic!("expected Confirm, got {other:?}"),
        }
        assert_eq!(v.policy_count, 3);
        assert_eq!(v.confirm_reasons, vec!["need approval".to_string()]);
    }

    // ------------------------------------------------------------------
    // Edge cases beyond the truth table
    // ------------------------------------------------------------------

    #[test]
    fn duplicate_deny_reasons_are_retained_not_deduplicated() {
        // The combiner is not in the business of dedup; if two
        // distinct policies both emit "exfil risk" we want both
        // entries so the audit chain shows two policies fired.
        let v = combine_verdicts([deny("exfil risk"), deny("exfil risk")]);
        assert_eq!(
            v.deny_reasons,
            vec!["exfil risk".to_string(), "exfil risk".to_string()]
        );
        assert_eq!(v.policy_count, 2);
    }

    #[test]
    fn very_long_reason_string_is_passed_through_unchanged() {
        // Defensive: no length cap inside the combiner. Trimming, if
        // wanted, happens at the audit-event boundary.
        let long = "x".repeat(8192);
        let v = combine_verdicts([deny(&long)]);
        assert_eq!(v.deny_reasons, vec![long.clone()]);
        match v.decision {
            PolicyDecision::Deny { ref message, .. } => assert_eq!(message.len(), 8192),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn first_confirm_webhook_and_expiry_are_taken_wholesale() {
        // Documented contract: the combiner picks the first Confirm's
        // fields wholesale and does not merge across Confirm votes.
        let url1 = url::Url::parse("https://first.example.com/").unwrap();
        let url2 = url::Url::parse("https://second.example.com/").unwrap();
        let t1 = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let t2 = chrono::DateTime::parse_from_rfc3339("2027-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let c1 = PolicyDecision::confirm("first", Some(url1.clone()), Some(t1));
        let c2 = PolicyDecision::confirm("second", Some(url2), Some(t2));
        let v = combine_verdicts([c1.clone(), c2]);

        match v.decision {
            PolicyDecision::Confirm {
                ref reason,
                ref webhook_url,
                ref expires_at,
            } => {
                assert_eq!(reason, "first");
                assert_eq!(webhook_url.as_ref(), Some(&url1));
                assert_eq!(expires_at.as_ref(), Some(&t1));
            }
            other => panic!("expected Confirm, got {other:?}"),
        }
    }

    #[test]
    fn first_deny_status_and_message_are_taken_wholesale() {
        // Mirror of the Confirm-first-wins test: the first Deny's
        // status code and message survive into the combined decision
        // even though later Denies use different status codes.
        let d1 = PolicyDecision::Deny {
            status: 401,
            message: "first".into(),
        };
        let d2 = PolicyDecision::Deny {
            status: 429,
            message: "second".into(),
        };
        let v = combine_verdicts([d1.clone(), d2]);
        match v.decision {
            PolicyDecision::Deny {
                status,
                ref message,
                ..
            } => {
                assert_eq!(status, 401);
                assert_eq!(message, "first");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
        assert_eq!(
            v.deny_reasons,
            vec!["first".to_string(), "second".to_string()]
        );
    }

    #[test]
    fn iterator_is_consumed_only_once_via_intoiterator() {
        // Smoke test that the function accepts any IntoIterator, not
        // just Vec. If this compiles and passes we have the right
        // bound.
        let arr = [PolicyDecision::Allow, confirm("c1")];
        let v = combine_verdicts(arr.iter().cloned());
        match v.decision {
            PolicyDecision::Confirm { ref reason, .. } => assert_eq!(reason, "c1"),
            other => panic!("expected Confirm, got {other:?}"),
        }
        assert_eq!(v.policy_count, 2);
    }

    #[test]
    fn policy_count_includes_allow_votes_even_when_decision_is_deny() {
        // policy_count is the total decisions consumed, not just the
        // ones that contributed reasons. Useful for log lines like
        // "12 policies evaluated, 2 voted deny".
        let v = combine_verdicts([
            PolicyDecision::Allow,
            PolicyDecision::Allow,
            confirm("c1"),
            deny("d1"),
            PolicyDecision::Allow,
        ]);
        match v.decision {
            PolicyDecision::Deny { ref message, .. } => assert_eq!(message, "d1"),
            other => panic!("expected Deny, got {other:?}"),
        }
        assert_eq!(v.policy_count, 5);
        assert_eq!(v.deny_reasons, vec!["d1".to_string()]);
        // Confirm reasons suppressed on Deny outcome.
        assert!(v.confirm_reasons.is_empty());
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Making a caller-supplied string safe to put in a log line.
//!
//! Distinct from `sbproxy_observe::metrics::sanitize_label`, which
//! bounds a metric label's cardinality. This bounds a log record's *shape*: the
//! failure it prevents is a newline in an attacker-chosen value forging
//! a whole record in any collector that reads newline-delimited output,
//! which is how a fabricated decision gets into an audit trail that is
//! otherwise trustworthy.
//!
//! Two surfaces need it for the same reason and used to each have their
//! own answer, or none: the CoMP marketplace router logs `tier_id` and
//! `quote_id` from an unauthenticated POST body, and the federation
//! peer-trust decision logs an entity id, a metadata block name, and a
//! rendered error, all of which come out of a document a peer
//! published.
//!
//! Only the second calls this. `sbproxy-licensing` keeps a
//! byte-identical private copy in `comp/router.rs`: it depends on
//! `sbproxy-storage` and nothing else in the workspace, and it is
//! unlinked from every binary, so taking a dependency on `sbproxy-security` for
//! ten lines would be the larger mistake. A third caller is the signal
//! to move this somewhere all three already depend on.

/// Longest value that reaches a log line.
///
/// One request must not be able to write a megabyte into the log, and
/// nothing legitimate on these surfaces is near 200 characters: an
/// entity id is a URL, a tier id is a slug, a metadata block name is a
/// JSON key.
const MAX: usize = 200;

/// Make a caller-supplied string safe to put in a log line.
///
/// Control characters (newline and carriage return among them) become
/// spaces, and the value is truncated with an ellipsis. The result is
/// still attacker-influenced text and should be read as data; what it
/// can no longer do is end the record it sits in.
///
/// ```
/// # use sbproxy_security::log_safe::log_safe;
/// assert_eq!(log_safe("a\nb"), "a b");
/// assert_eq!(log_safe("plain"), "plain");
/// ```
pub fn log_safe(value: &str) -> String {
    let mut out: String = value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX)
        .collect();
    if value.chars().count() > MAX {
        out.push_str("...");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_newline_cannot_forge_a_second_record() {
        let forged = log_safe("ok\nlevel=INFO event=\"approved\"");
        assert!(
            !forged.contains('\n'),
            "a newline must not survive into a log line: {forged:?}"
        );
    }

    #[test]
    fn every_control_character_is_replaced() {
        for c in ['\n', '\r', '\t', '\u{0}', '\u{1b}'] {
            let out = log_safe(&format!("a{c}b"));
            assert_eq!(out, "a b", "control character {c:?} survived");
        }
    }

    #[test]
    fn a_long_value_is_truncated_and_says_so() {
        let out = log_safe(&"x".repeat(MAX + 50));
        assert_eq!(out.chars().count(), MAX + 3);
        assert!(out.ends_with("..."));
    }

    #[test]
    fn a_value_at_the_cap_is_not_marked_truncated() {
        let out = log_safe(&"x".repeat(MAX));
        assert_eq!(out.chars().count(), MAX);
        assert!(!out.ends_with("..."));
    }
}

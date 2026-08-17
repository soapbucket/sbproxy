// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Strip a known config path out of an error string (WOR-2094, promoted
//! to a shared module in WOR-2486 fix round 1, I5).
//!
//! `anyhow` error chains built from a filesystem or compile failure
//! routinely embed the full path they were reading, and that path is
//! this node's local filesystem layout: a deployment directory
//! structure, a username in a home directory, a mount point. The admin
//! `/admin/reload` and `/admin/config` handlers have always scrubbed
//! this before it reaches an HTTP response body. WOR-2486 widened the
//! non-admin reload paths (file watcher, SIGHUP, config-authority
//! bundle apply, config-source refresh poller, extension-bundle
//! refresh) to record a rejection reason in `config_audit` too, which
//! is a second place the same unscrubbed path could leak to, this time
//! into a record that, with `audit.sink: chain`, is durable. One
//! scrubber, used by both.

use std::path::Path;

/// Replace every occurrence of `full_path` in `msg` with just its file
/// name.
///
/// `full_path` is the config path this process was told to read, known
/// in advance at every call site (it is always the argument a reload
/// function was itself called with), so this is a literal substring
/// replacement rather than a path-shaped heuristic: it removes exactly
/// the path this node's own config, not every string that merely looks
/// like a filesystem path.
///
/// An empty `full_path` (no config path configured, or a synthetic path
/// used in a test fixture) is a no-op: there is nothing to redact
/// against.
pub(crate) fn sanitise_path_in_error(msg: &str, full_path: &Path) -> String {
    let full = full_path.to_string_lossy();
    if full.is_empty() {
        return msg.to_string();
    }
    let file_name = full_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<config>".to_string());
    msg.replace(full.as_ref(), &file_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_the_full_path_with_its_file_name() {
        let msg = "failed to read config file: /home/deploy/configs/prod/sb.yml: permission denied";
        let redacted = sanitise_path_in_error(msg, Path::new("/home/deploy/configs/prod/sb.yml"));
        assert_eq!(
            redacted,
            "failed to read config file: sb.yml: permission denied"
        );
        assert!(!redacted.contains("/home/deploy"));
    }

    #[test]
    fn a_message_with_no_occurrence_of_the_path_is_unchanged() {
        let msg = "unrelated error text";
        let redacted = sanitise_path_in_error(msg, Path::new("/home/deploy/sb.yml"));
        assert_eq!(redacted, msg);
    }

    #[test]
    fn an_empty_path_is_a_no_op() {
        let msg = "some error containing /home/deploy/sb.yml";
        let redacted = sanitise_path_in_error(msg, Path::new(""));
        assert_eq!(redacted, msg);
    }
}

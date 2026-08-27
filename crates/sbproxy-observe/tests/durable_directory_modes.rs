//! The directory a durable sink creates for itself is owner-only, on a
//! runner whose umask would otherwise have left it wider (WOR-2626).
//!
//! # Why this is not a unit test
//!
//! The three in-crate tests that assert a sink's own directory is
//! `0o700` are umask-dependent, and it is the assertion whose failure
//! was quoted as the red evidence for the fix. Their *file* half is
//! genuinely environment-independent: each pre-creates its fixture at
//! `0o644`, `open(2)` masks the mode it is given but `fchmod` does not,
//! so the tightening is proved whatever the umask is. The directory
//! half has nowhere to put a starting mode, because the mode a
//! directory is *created* at is the whole claim. With the fix backed
//! out, `create_dir_all` under a `0o077` umask produces `0o700` and the
//! assertion passes green.
//!
//! The only way to close that is to pin the umask, and the umask is
//! process-wide state set through `libc::umask`, which
//! `sbproxy-observe`'s `#![forbid(unsafe_code)]` refuses. An
//! integration test is its own crate and does not inherit that, which
//! is the same reason `key_audit_write_failure.rs` lives here.
//!
//! `0o022` is the value pinned: the near-universal default, and the one
//! `sbproxy_util::secure_fs`'s module documentation names as the reason
//! the whole change exists. Under it a plainly created directory is
//! `0o755` and one the helper creates is `0o700`, so the assertion is
//! about the code rather than about the runner.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use sbproxy_observe::access_log::AccessLogEntry;

/// Holds the process umask for the duration of the test.
///
/// Restored on drop, including on a panic, so a failure here does not
/// change what every later test in this binary sees.
struct PinnedUmask(libc::mode_t);

impl PinnedUmask {
    fn at_022() -> Self {
        // SAFETY: `umask` cannot fail and returns the previous value.
        // Each integration test file is its own binary and this is the
        // only test in it, so there is no other thread to race.
        Self(unsafe { libc::umask(0o022) })
    }
}

impl Drop for PinnedUmask {
    fn drop(&mut self) {
        // SAFETY: as above.
        unsafe {
            libc::umask(self.0);
        }
    }
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path)
        .expect("stat the path under test")
        .permissions()
        .mode()
        & 0o7777
}

fn entry() -> AccessLogEntry {
    AccessLogEntry::builder()
        .timestamp("2026-08-27T12:00:00Z")
        .request_id("req-1")
        .origin("api.example.com")
        .method("POST")
        .path("/v1/orders")
        .status(201)
        .build()
}

#[test]
fn a_sink_creating_its_own_directory_makes_it_owner_only() {
    let _umask = PinnedUmask::at_022();

    let dir = tempfile::tempdir().expect("temp dir");

    // The control: what a plain `create_dir_all` leaves at this umask.
    // Asserted rather than assumed, because if it ever came back
    // `0o700` the assertion below would be proving nothing.
    let control = dir.path().join("control/nested");
    std::fs::create_dir_all(&control).expect("control directory");
    assert_eq!(
        mode_of(&control),
        0o755,
        "the pinned umask is not in effect, so this test proves nothing"
    );

    let nested = dir.path().join("sink");
    let log = nested.join("access.log");
    entry()
        .emit_to_file(&log, 1024 * 1024, 3, false)
        .expect("first write creates the directory and the file");

    assert_eq!(
        mode_of(&nested),
        0o700,
        "the access log sink's own directory is traversable by every account on the host"
    );
    assert_eq!(
        mode_of(&log),
        0o600,
        "the access log itself is readable by every account on the host"
    );
}

#[test]
fn rotated_backups_left_by_an_older_build_are_tightened() {
    let dir = tempfile::tempdir().expect("temp dir");
    let log = dir.path().join("access.log");

    // Two backups an older build rotated out at the default umask,
    // each holding a week of every request's path, identity and
    // decision. `fs::rename` preserves the inode, so nothing in the
    // rotation path ever changed their mode.
    for idx in [1usize, 2] {
        let backup = dir.path().join(format!("access.log.{idx}"));
        std::fs::write(&backup, b"{\"path\":\"/v1/orders\"}\n").expect("seed a backup");
        std::fs::set_permissions(&backup, std::fs::Permissions::from_mode(0o644))
            .expect("loosen the backup");
    }

    // First write creates the live log; the second is over the
    // one-byte threshold and rotates.
    entry()
        .emit_to_file(&log, 1, 5, false)
        .expect("first write");
    entry()
        .emit_to_file(&log, 1, 5, false)
        .expect("rotating write");

    for idx in 1..=3usize {
        let backup = dir.path().join(format!("access.log.{idx}"));
        assert!(
            backup.exists(),
            "expected {} after rotation",
            backup.display()
        );
        assert_eq!(
            mode_of(&backup),
            0o600,
            "rotated backup {} is {:o}, not owner-only",
            backup.display(),
            mode_of(&backup)
        );
    }
}

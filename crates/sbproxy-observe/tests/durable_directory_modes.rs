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
        // It is process-wide state, so what makes this sound is not an
        // absence of other tests but that the previous value is restored
        // on drop, panic included, and that no other test in this binary
        // reads or depends on the umask: the two rotation tests seed
        // every fixture with an explicit `set_permissions`, which
        // `fchmod` applies unmasked. nextest runs a process per test as
        // well, so in the default configuration there is no concurrent
        // reader at all; that is a second line of defense rather than
        // the argument.
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

/// An operator who turns compression on after upgrading leaves plain
/// `.N` backups behind that the rotation loop never touches again
/// (WOR-2606).
///
/// Nothing renames them, because the loop only shifts names in the
/// configured mode, and nothing deletes them for the same reason. Under
/// a sweep that followed the setting they stayed at whatever mode the
/// old build left them at, holding the same request records as the
/// `.gz` files beside them. Red without the two-suffix sweep: the two
/// seeded plain backups stay `0o644`.
#[test]
fn plain_backups_are_tightened_after_compression_is_turned_on() {
    let dir = tempfile::tempdir().expect("temp dir");
    let log = dir.path().join("access.log");

    // What the pre-upgrade build left behind, uncompressed.
    for idx in [1usize, 2] {
        let backup = dir.path().join(format!("access.log.{idx}"));
        std::fs::write(&backup, b"{\"path\":\"/v1/orders\"}\n").expect("seed a plain backup");
        std::fs::set_permissions(&backup, std::fs::Permissions::from_mode(0o644))
            .expect("loosen the backup");
    }

    // The operator flips `compress: true`. Rotation now writes `.1.gz`
    // and shifts only the `.gz` names.
    entry().emit_to_file(&log, 1, 5, true).expect("first write");
    entry()
        .emit_to_file(&log, 1, 5, true)
        .expect("rotating write");

    for idx in [1usize, 2] {
        let backup = dir.path().join(format!("access.log.{idx}"));
        assert!(
            backup.exists(),
            "the plain backup {} must still be there: nothing in the compressed \
             rotation path removes it, which is the whole point",
            backup.display()
        );
        assert_eq!(
            mode_of(&backup),
            0o600,
            "the plain backup {} is {:o}: the sweep followed the configured \
             compression mode and never looked at it",
            backup.display(),
            mode_of(&backup)
        );
    }

    let compressed = dir.path().join("access.log.1.gz");
    assert!(
        compressed.exists(),
        "the compressed rotation must have produced {}",
        compressed.display()
    );
    assert_eq!(
        mode_of(&compressed),
        0o600,
        "the compressed backup must stay owner-only"
    );
}

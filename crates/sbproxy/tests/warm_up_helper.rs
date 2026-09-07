// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The shared warm-up has to actually exec the file.
//!
//! `common::warm_shipped_binary` is what eight integration tests in this
//! directory lean on to keep macOS's first-exec assessment out of their
//! wall-clock bounds, and until this file existed nothing could tell a
//! warm-up that ran from one that returned: empty its body and every test in
//! the workspace stays green while those eight quietly go back to containing
//! the assessment inside their 10s, 20s and 30s deadlines. The symptom it
//! prevents is a flake, which nobody reads as a regression, so the check has
//! to be here rather than in the suites it protects (WOR-2946).

mod common;

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// A scratch directory of this file's own, named the way the rest of this
/// suite names them. `tempfile` is not a dev-dependency of this package.
fn temp_dir(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "sbproxy-warm-up-helper-{label}-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).expect("create test directory");
    path
}

/// The exec half runs the file, and the fixture records that it did.
#[cfg(unix)]
#[test]
fn warming_execs_the_named_binary() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = temp_dir("execs");
    let script = dir.join("fake-sbproxy");
    let record = dir.join("execs");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf 'ran %s\\n' \"$1\" >> {}\nexit 0\n",
            record.display()
        ),
    )
    .expect("write fixture");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");

    common::warm_executable_once(&script, "fixture").expect("the fixture warms");

    let ran = std::fs::read_to_string(&record).expect("the warm-up must have exec'd the fixture");
    assert_eq!(
        ran.lines().count(),
        1,
        "the warm-up must exec the file exactly once: {ran:?}"
    );
    assert_eq!(
        ran.trim(),
        "ran --version",
        "the warm-up must use a flag the binary answers and exits on, so it \
         binds no port and writes nothing: {ran:?}"
    );
    std::fs::remove_dir_all(&dir).expect("remove the scratch directory");
}

/// A file that cannot be exec'd is reported, not swallowed.
///
/// The caller turns this into a panic naming the binary. Without it a missing
/// or non-executable binary would warm silently and the failure would surface
/// later as whatever deadline happened to be nearest.
#[cfg(unix)]
#[test]
fn warming_reports_a_binary_it_cannot_execute() {
    let dir = temp_dir("missing");
    let missing = dir.join("not-here");

    let error = common::warm_executable_once(&missing, "fixture")
        .expect_err("a missing binary must not warm silently");
    assert!(
        error.contains("could not be executed at all"),
        "the diagnosis must say the exec failed: {error}"
    );
    assert!(
        error.contains("fixture"),
        "the diagnosis must name which binary: {error}"
    );
    std::fs::remove_dir_all(&dir).expect("remove the scratch directory");
}

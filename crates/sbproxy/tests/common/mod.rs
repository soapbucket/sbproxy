// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Shared setup for the integration tests that spawn the shipped
//! `sbproxy` binary and then put a wall-clock bound on its startup.
//!
//! This is the canonical explanation of macOS's first-exec cost for this
//! workspace. The other three places that carry the same mitigation name
//! this module rather than restating it: `e2e/src/lib.rs`,
//! `crates/sbproxy-config/tests/config_source_git.rs`, and
//! `crates/sbproxy-classifier/tests/group_b_startup.rs`. They are separate
//! packages, and one of them is library code rather than a test, so none of
//! them can `mod common;` this file (WOR-2946).

// Each integration test binary uses a different subset of this module, and an
// unused helper in one binary is not dead code in the suite.
#![allow(dead_code)]

use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// A hang guard for [`warm_shipped_binary`], and deliberately not a budget
/// for the work it guards.
///
/// The measurements in [`warm_shipped_binary`] are samples of a
/// load-dependent quantity, not a ceiling: the worst seen while measuring
/// this ticket was 57.2s, against a 2.8s median for the same file minutes
/// earlier. So this is sized for a warm-up that has genuinely wedged (a
/// stuck `syspolicyd` turns it into tens of minutes), not for a slow one.
/// It is five times the worst measured cost and four orders of magnitude
/// above a warm exec.
///
/// A bound *near* the cost would be worse than none. An assessment killed
/// part-way is charged to the next run of the same file, so a tight warm-up
/// hands its cost straight to the run it exists to protect.
const WARM_UP_HANG_GUARD: Duration = Duration::from_secs(300);

/// Above this, the warm-up says how long it took. Well clear of a warm exec
/// (0.021s measured) and of an idle first exec, so a normal run stays quiet
/// and only a run worth explaining prints.
const SLOW_WARM_UP: Duration = Duration::from_secs(2);

/// Pay the shipped `sbproxy` binary's first-exec cost once per test
/// process, outside every wall-clock bound in the caller.
///
/// macOS assesses a freshly written executable the first time it is exec'd.
/// The cost lands on whoever **waits** for the process, not on the spawn:
/// measured apart, `Command::spawn` returns in 0.000-0.001s and the entire
/// cost falls in `wait()`. So every deadline a test wraps around "spawn the
/// proxy and wait for it to serve" contains the assessment, and a test that
/// fails to it reports a proxy that would not start.
///
/// Two things make it worse than it sounds here. The debug `sbproxy` this
/// suite spawns is 708 MB, and the assessment scales with what it has to
/// hash: a bare `--version` on a freshly linked one took **9.311s** on an
/// idle machine, against 0.021s on the next run of the same file. And the
/// load average *falls* while this is happening, because a process blocked
/// on the assessment is blocked rather than runnable, so nothing in a
/// normal load check reveals the contention.
///
/// Copying does not dodge it either: a copy of an already-assessed file
/// paid full price under concurrent first-exec load (27.7s median against
/// 44.2s for a fresh extract), so moving a binary into a temp root creates a
/// first exec rather than avoiding one.
///
/// `--version` is what gets executed: clap answers it and exits before the
/// binary reads a config or binds anything, so warming has no side effects
/// and leaves no listener behind even if this process is killed mid-warm.
///
/// This never skips anything. On the hang guard it fails, loudly, with the
/// diagnosis, and the run that follows finds a warm cache.
pub fn warm_shipped_binary() {
    static WARM: OnceLock<()> = OnceLock::new();
    WARM.get_or_init(|| {
        let started = Instant::now();
        let (sender, receiver) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let status = Command::new(env!("CARGO_BIN_EXE_sbproxy"))
                .arg("--version")
                // The runner's own environment must not be able to send
                // this anywhere but clap's version path.
                .env_remove("SB_CONFIG_FILE")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = sender.send(status);
        });
        match receiver.recv_timeout(WARM_UP_HANG_GUARD) {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                panic!("the shipped sbproxy binary could not be executed at all: {error}")
            }
            Err(_) => panic!(
                "the shipped sbproxy binary did not answer `--version` within {}s \
                 (waited {}s).\n\
                 \n\
                 This is almost certainly not a bug in this test. On macOS the first \
                 exec of a freshly written binary blocks while syspolicyd assesses \
                 it, and the cost lands on the wait rather than on the spawn. A \
                 wedged daemon turns that into tens of minutes. Confirm it with \
                 `ps aux | grep -iE 'syspolicyd|XprotectService'` (sustained CPU) \
                 and `sample <pid>` on a stuck child.\n\
                 \n\
                 Clear it with `sudo spctl --global-disable` (no reboot; re-enable \
                 with --global-enable) or by rebooting, then run this test again. \
                 The verdict is cached by cdhash, so the second exec is instant.",
                WARM_UP_HANG_GUARD.as_secs(),
                started.elapsed().as_secs()
            ),
        }
        let elapsed = started.elapsed();
        // Silent by default, because the usual case is milliseconds. A slow
        // one is worth a line: this is the only step here that can take
        // minutes, and a run killed while sitting in it should say what it
        // was waiting on rather than looking hung.
        if elapsed >= SLOW_WARM_UP {
            eprintln!(
                "warm_shipped_binary: sbproxy --version took {:.1}s \
                 (macOS first-exec assessment; see WOR-2946)",
                elapsed.as_secs_f64()
            );
        }
    });
}

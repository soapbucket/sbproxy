//! Build script that embeds the git revision and the UTC build date as
//! compile-time env vars. `main.rs` reads them via `env!()` to produce a
//! `--version` line of the form:
//!
//!     sbproxy 1.0.0 (rev abcd123, built 2026-05-03)
//!
//! The output shape is load-bearing: the marketing site advertises it and
//! Homebrew's `test do` block asserts on it. If you change the format, fix
//! the website's Hero.vue and the homebrew formula in lockstep.

use std::process::Command;

fn main() {
    // Release jobs validate their checkout before supplying this revision.
    // Git lookup can fail inside a job container even after checkout succeeds;
    // an explicit input must never silently degrade to an unknown revision.
    println!("cargo:rerun-if-env-changed=SBPROXY_BUILD_REVISION");
    let sha = match std::env::var("SBPROXY_BUILD_REVISION") {
        Ok(revision) => {
            assert!(
                revision.len() == 40
                    && revision
                        .bytes()
                        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')),
                "SBPROXY_BUILD_REVISION must be a full 40-character lowercase hexadecimal git SHA"
            );
            revision
        }
        Err(std::env::VarError::NotPresent) => {
            run("git", &["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "unknown".into())
        }
        Err(_) => panic!("SBPROXY_BUILD_REVISION must contain valid UTF-8"),
    };
    let date = run("date", &["-u", "+%Y-%m-%d"]).unwrap_or_else(|| "unknown".into());

    // The year, for the copyright footer in `--help`. Derived from the
    // build date so it never goes stale (and needs no hand-edit each year).
    let year = date.split('-').next().unwrap_or("").to_string();

    println!("cargo:rustc-env=SBPROXY_GIT_SHA={sha}");
    println!("cargo:rustc-env=SBPROXY_BUILD_DATE={date}");
    println!("cargo:rustc-env=SBPROXY_BUILD_YEAR={year}");

    // Re-run when HEAD or any branch ref changes, so amends and new tags
    // refresh the embedded SHA on the next incremental build.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/heads");
    println!("cargo:rerun-if-changed=../../.git/refs/tags");
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

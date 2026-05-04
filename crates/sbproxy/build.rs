//! Build script that embeds the git short SHA and the UTC build date as
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
    let sha = run("git", &["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let date = run("date", &["-u", "+%Y-%m-%d"]).unwrap_or_else(|| "unknown".into());

    println!("cargo:rustc-env=SBPROXY_GIT_SHA={sha}");
    println!("cargo:rustc-env=SBPROXY_BUILD_DATE={date}");

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

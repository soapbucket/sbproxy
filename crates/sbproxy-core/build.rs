// SPDX-License-Identifier: Apache-2.0
//! Tell cargo that the embedded admin UI is an input to this crate.
//!
//! `admin_ui.rs` pulls `ui/dist` into the binary with `include_dir!`. Cargo
//! cannot see through a macro to the files it reads, so before this script
//! existed, `npm run build` followed by `cargo build` produced a binary
//! carrying the *previous* UI. Nothing failed and nothing warned; the browser
//! just served a stale page, and the obvious next move (rebuild again) did not
//! help because cargo still considered the crate fresh.
//!
//! The workaround was to remember to `touch crates/sbproxy-core/src/admin_ui.rs`
//! after every UI build. That is not a thing anyone remembers, and it was
//! documented nowhere.

use std::path::Path;

fn main() {
    // Relative to this crate's root, which is where cargo runs a build
    // script. Cargo walks a directory given here, so a change to any file
    // under it invalidates the crate.
    let dist = Path::new("../../ui/dist");
    println!("cargo:rerun-if-changed=build.rs");
    if dist.exists() {
        println!("cargo:rerun-if-changed={}", dist.display());
    }
    // A missing directory is deliberately not declared. Cargo re-runs a build
    // script on every build when a declared path does not exist, and a repo
    // checked out without the UI built would pay that on every compile for no
    // benefit. `ui/dist/.gitkeep` is committed, so in a git checkout the
    // directory is there.
}

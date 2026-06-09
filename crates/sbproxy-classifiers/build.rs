// SPDX-License-Identifier: Apache-2.0
//
//! Build script for `sbproxy-classifiers`.
//!
//! Compiles `proto/judge.proto` into Rust types via `tonic-build` so
//! `src/judge_rpc.rs` can implement the generated `Judge` server trait
//! and the unit tests can stand up an in-process `tonic` server. The
//! generated module lands in `OUT_DIR` and is pulled in via
//! `tonic::include_proto!`.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Re-run only when the proto file changes. Without this, every
    // edit elsewhere in the crate triggers protoc, which is slow on
    // cold caches.
    println!("cargo:rerun-if-changed=proto/judge.proto");

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/judge.proto"], &["proto"])?;

    Ok(())
}

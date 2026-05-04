//! Build script for the e2e test crate.
//!
//! Compiles `proto/echo.proto` into Rust types via `tonic-build` so
//! `tests/action_grpc.rs` can stand up a real tonic Echo service and
//! drive RPCs through the proxy. The generated module lands in
//! `OUT_DIR` and is pulled in via `tonic::include_proto!`.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Re-run only when the proto file changes. Without this, every
    // edit to a test file triggers protoc, which is slow on cold
    // caches.
    println!("cargo:rerun-if-changed=proto/echo.proto");

    tonic_build::configure()
        // The e2e test spawns the server in-process; we do not need
        // a generated client transport, but generating both keeps the
        // ergonomics simple and the cost is negligible.
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/echo.proto"], &["proto"])?;

    Ok(())
}

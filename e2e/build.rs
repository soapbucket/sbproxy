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

    // Emit a compiled FileDescriptorSet alongside the generated Rust
    // types. `tests/grpc_transcode.rs` feeds this file to the `grpc`
    // action's `transcode.descriptor_set` so the REST <-> gRPC
    // transcoder resolves the Echo method at config load. The path is
    // exported to the test via the `ECHO_DESCRIPTOR_SET` env var.
    let descriptor_path =
        std::path::PathBuf::from(std::env::var("OUT_DIR")?).join("echo_descriptor.bin");

    tonic_build::configure()
        // The e2e test spawns the server in-process; we do not need
        // a generated client transport, but generating both keeps the
        // ergonomics simple and the cost is negligible.
        .build_server(true)
        .build_client(true)
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(&["proto/echo.proto"], &["proto"])?;

    println!(
        "cargo:rustc-env=ECHO_DESCRIPTOR_SET={}",
        descriptor_path.display()
    );

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile the shared InferenceService contract into both a client (used by
    // the proxy) and a server (used by the minimal OSS sidecar). The proto is
    // self-contained, so the include path is just its own directory.
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&["proto/classifier.proto"], &["proto"])?;

    println!("cargo:rerun-if-changed=proto/classifier.proto");
    Ok(())
}

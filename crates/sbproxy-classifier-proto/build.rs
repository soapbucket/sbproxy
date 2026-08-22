fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile the shared InferenceService contract, plus the rich-sidecar-only
    // ClassifierService (WOR-2665), into both a client (used by the proxy and
    // by sbproxy-classifier-client) and a server (used by the minimal OSS
    // sidecar and sbproxy-classifier respectively). One proto file, one
    // codegen pass; the proto has no imports, so the include path is just its
    // own directory.
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&["proto/classifier.proto"], &["proto"])?;

    println!("cargo:rerun-if-changed=proto/classifier.proto");
    Ok(())
}

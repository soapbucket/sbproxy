//! Snapshot test: load the published example config end-to-end and
//! assert the emitted OpenAPI document matches the contract documented
//! in `sbproxy-enterprise/docs/openapi-emission.md`.
//!
//! The example file is the user-facing documentation surface; keeping a
//! test that fails when its emitted shape drifts catches regressions
//! before a buyer notices.

use std::path::PathBuf;

fn load_example() -> sbproxy_config::CompiledConfig {
    // Locate the canonical OSS example via a path relative to this
    // crate's manifest so the test works regardless of cargo's working
    // directory.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let example = manifest.join("../../examples/96-openapi-emission/sb.yml");
    if !example.exists() {
        // The example is part of the OSS tree; if it is missing in a
        // partial checkout we skip rather than fail.
        return sbproxy_config::CompiledConfig::default();
    }
    let yaml = std::fs::read_to_string(&example).expect("read example sb.yml");
    sbproxy_config::compile_config(&yaml).expect("example sb.yml should compile")
}

#[test]
fn example_emits_expected_paths() {
    let cfg = load_example();
    if cfg.origins.is_empty() {
        eprintln!("skipping: example file not present");
        return;
    }
    let spec = sbproxy_openapi::build(&cfg, Some("api.localhost"));
    let paths = spec["paths"].as_object().expect("paths object");

    // Template path lands as-is.
    assert!(
        paths.contains_key("/users/{id:[0-9]+}/posts/{post_id}"),
        "missing template path; got {:?}",
        paths.keys().collect::<Vec<_>>()
    );

    // Catch-all template lands as-is.
    assert!(paths.contains_key("/static/{*rest}"));

    // Exact path lands as-is.
    assert!(paths.contains_key("/health"));

    // Prefix path is annotated with the x-sbproxy-prefix-match extension.
    assert_eq!(
        paths["/api/"]["x-sbproxy-prefix-match"],
        serde_json::json!(true)
    );

    // Regex path lands under a synthetic key with the original pattern
    // preserved as an extension.
    let regex_key = paths
        .keys()
        .find(|k| k.starts_with("/__regex__/"))
        .expect("regex path key");
    assert!(paths[regex_key]["x-sbproxy-regex-path"]
        .as_str()
        .unwrap()
        .contains("version"));
}

#[test]
fn example_emits_expected_parameters() {
    let cfg = load_example();
    if cfg.origins.is_empty() {
        eprintln!("skipping: example file not present");
        return;
    }
    let spec = sbproxy_openapi::build(&cfg, Some("api.localhost"));
    let params = spec["paths"]["/users/{id:[0-9]+}/posts/{post_id}"]["get"]["parameters"]
        .as_array()
        .expect("parameters array");

    // The example declares three parameters: id (path, required, integer),
    // post_id (path, required, string), include (query, optional).
    assert_eq!(params.len(), 3);

    let by_name: std::collections::HashMap<&str, &serde_json::Value> = params
        .iter()
        .map(|p| (p["name"].as_str().unwrap(), p))
        .collect();
    assert_eq!(by_name["id"]["in"], "path");
    assert_eq!(by_name["id"]["required"], true);
    assert_eq!(by_name["id"]["schema"]["type"], "integer");
    assert_eq!(by_name["post_id"]["in"], "path");
    assert_eq!(by_name["include"]["in"], "query");
    assert_eq!(by_name["include"]["required"], false);
}

#[test]
fn example_restricts_methods_to_allowed_set() {
    let cfg = load_example();
    if cfg.origins.is_empty() {
        eprintln!("skipping: example file not present");
        return;
    }
    let spec = sbproxy_openapi::build(&cfg, Some("api.localhost"));
    let path = &spec["paths"]["/users/{id:[0-9]+}/posts/{post_id}"];
    // allowed_methods: [GET, POST] in the example config.
    assert!(path["get"].is_object());
    assert!(path["post"].is_object());
    assert!(path.get("put").is_none());
    assert!(path.get("delete").is_none());
}

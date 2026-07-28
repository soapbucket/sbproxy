//! Process-owned configuration contract for the embedded compression store.

use sbproxy_config::{
    compile_config, denied_paths_in, BlastRadius, ProxyServerConfig, BLAST_RADIUS_MATRIX,
};

fn parse_proxy(yaml: &str) -> ProxyServerConfig {
    serde_yaml::from_str(yaml).expect("proxy config should deserialize")
}

fn compile_with_path(path: &str) -> anyhow::Result<sbproxy_config::CompiledConfig> {
    compile_config(&format!(
        "proxy:\n  compression_state:\n    local_path: {path}\n"
    ))
}

#[test]
fn compression_state_block_is_optional() {
    let proxy = parse_proxy("http_bind_port: 8080\n");
    assert!(proxy.compression_state.is_none());
}

#[test]
fn explicit_absolute_local_path_parses_without_touching_the_filesystem() {
    let path = "/definitely/not/a/real/directory/wor-1994.redb";
    let compiled = compile_with_path(path).expect("an absent path is still valid configuration");
    assert_eq!(
        compiled
            .server
            .compression_state
            .as_ref()
            .and_then(|config| config.local_path.as_deref()),
        Some(path)
    );
}

#[test]
fn local_path_rejects_empty_relative_oversized_and_control_values() {
    let oversized = format!("/{}", "a".repeat(4_096));
    let cases = [
        ("\"\"", "must not be empty"),
        ("relative/state.redb", "absolute"),
        (oversized.as_str(), "4096"),
        ("\"/tmp/bad\\u0001path\"", "control"),
    ];

    for (path, expected) in cases {
        let error = match compile_with_path(path) {
            Ok(_) => panic!("{path:?} unexpectedly compiled"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("proxy.compression_state.local_path") && error.contains(expected),
            "{path:?}: {error}"
        );
    }
}

#[test]
fn config_authority_cannot_select_a_process_local_database_path() {
    let denied = denied_paths_in(
        "proxy:\n  compression_state:\n    local_path: /var/lib/sbproxy/compression-state.redb\n",
    )
    .expect("remote YAML parses");
    assert_eq!(denied, vec!["proxy.compression_state"]);
}

#[test]
fn local_database_path_changes_are_restart_class_before_proxy_catchalls() {
    let exact = BLAST_RADIUS_MATRIX
        .iter()
        .position(|rule| rule.pattern == "proxy.compression_state")
        .expect("exact process-owned block rule");
    let subtree = BLAST_RADIUS_MATRIX
        .iter()
        .position(|rule| rule.pattern == "proxy.compression_state.**")
        .expect("subtree process-owned block rule");
    let proxy_catchall = BLAST_RADIUS_MATRIX
        .iter()
        .position(|rule| rule.pattern == "proxy.**")
        .expect("proxy catchall");

    assert_eq!(BLAST_RADIUS_MATRIX[exact].radius, BlastRadius::Restart);
    assert_eq!(BLAST_RADIUS_MATRIX[subtree].radius, BlastRadius::Restart);
    assert!(exact < proxy_catchall);
    assert!(subtree < proxy_catchall);
}

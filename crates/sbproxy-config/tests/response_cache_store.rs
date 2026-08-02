//! Parse contract for the `proxy.response_cache_store` block.

use sbproxy_config::{ProxyServerConfig, ResponseCacheBackendConfig};

fn parse(yaml: &str) -> ProxyServerConfig {
    serde_yaml::from_str(yaml).expect("response_cache_store config should deserialize")
}

#[test]
fn absent_block_stays_none_so_legacy_selection_is_untouched() {
    // An operator with only proxy.l2_cache set must keep getting Redis
    // after this change. The pipeline distinguishes "no block" from
    // "explicit memory", so the absent case has to stay None.
    let proxy = parse("http_bind_port: 8080\n");
    assert!(proxy.response_cache_store.is_none());
}

#[test]
fn empty_block_defaults_to_memory_with_no_encryption() {
    let proxy = parse(
        r#"
response_cache_store: {}
"#,
    );
    let store = proxy.response_cache_store.expect("block present");
    assert!(matches!(store.backend, ResponseCacheBackendConfig::Memory));
    assert!(store.encryption.is_none());
}

#[test]
fn file_backend_parses_path_and_size_cap() {
    let proxy = parse(
        r#"
response_cache_store:
  backend:
    type: file
    path: /var/cache/sbproxy/responses
    max_size_mb: 512
"#,
    );
    let store = proxy.response_cache_store.expect("block present");
    match store.backend {
        ResponseCacheBackendConfig::File { path, max_size_mb } => {
            assert_eq!(path, "/var/cache/sbproxy/responses");
            assert_eq!(max_size_mb, 512);
        }
        other => panic!("expected the file backend, got {other:?}"),
    }
}

#[test]
fn file_backend_size_cap_defaults_to_unlimited() {
    let proxy = parse(
        r#"
response_cache_store:
  backend:
    type: file
    path: /var/cache/sbproxy/responses
"#,
    );
    match proxy.response_cache_store.expect("block present").backend {
        ResponseCacheBackendConfig::File { max_size_mb, .. } => {
            assert_eq!(max_size_mb, 0, "0 means no cap");
        }
        other => panic!("expected the file backend, got {other:?}"),
    }
}

#[test]
fn memcached_backend_has_the_standard_defaults() {
    let proxy = parse(
        r#"
response_cache_store:
  backend:
    type: memcached
"#,
    );
    match proxy.response_cache_store.expect("block present").backend {
        ResponseCacheBackendConfig::Memcached { host, port } => {
            assert_eq!(host, "127.0.0.1");
            assert_eq!(port, 11211);
        }
        other => panic!("expected the memcached backend, got {other:?}"),
    }
}

#[test]
fn memcached_backend_accepts_an_explicit_endpoint() {
    let proxy = parse(
        r#"
response_cache_store:
  backend:
    type: memcached
    host: memcached.internal
    port: 11212
"#,
    );
    match proxy.response_cache_store.expect("block present").backend {
        ResponseCacheBackendConfig::Memcached { host, port } => {
            assert_eq!(host, "memcached.internal");
            assert_eq!(port, 11212);
        }
        other => panic!("expected the memcached backend, got {other:?}"),
    }
}

#[test]
fn redis_backend_parses_as_a_bare_type() {
    let proxy = parse(
        r#"
response_cache_store:
  backend:
    type: redis
"#,
    );
    assert!(matches!(
        proxy.response_cache_store.expect("block present").backend,
        ResponseCacheBackendConfig::Redis
    ));
}

#[test]
fn encryption_block_parses_key_and_rotation_list() {
    let proxy = parse(
        r#"
response_cache_store:
  backend:
    type: file
    path: /var/cache/sbproxy/responses
  encryption:
    enabled: true
    key: "secret://local/response-cache"
    previous_keys:
      - "file:/etc/sbproxy/response-cache.key.old"
"#,
    );
    let enc = proxy
        .response_cache_store
        .expect("block present")
        .encryption
        .expect("encryption block present");
    assert!(enc.enabled);
    assert_eq!(enc.key.as_deref(), Some("secret://local/response-cache"));
    assert_eq!(enc.previous_keys.len(), 1);
    assert_eq!(
        enc.previous_keys[0],
        "file:/etc/sbproxy/response-cache.key.old"
    );
}

#[test]
fn encryption_defaults_to_disabled_with_no_key_and_no_rotation() {
    let proxy = parse(
        r#"
response_cache_store:
  encryption: {}
"#,
    );
    let enc = proxy
        .response_cache_store
        .expect("block present")
        .encryption
        .expect("encryption block present");
    assert!(!enc.enabled);
    assert!(enc.key.is_none());
    assert!(enc.previous_keys.is_empty());
}

#[test]
fn an_unknown_backend_type_is_rejected() {
    // Backends are a closed set here, unlike cache_reserve, because the
    // response-cache store has no out-of-tree registration path. A typo
    // must be loud rather than silently falling back to memory.
    let err = serde_yaml::from_str::<ProxyServerConfig>(
        r#"
response_cache_store:
  backend:
    type: memcachd
"#,
    )
    .expect_err("a typo in the backend type must not parse");
    assert!(
        err.to_string().contains("memcachd"),
        "the error should name the bad type: {err}"
    );
}

//! Two proxy processes, one shared cache store, different configs
//! (WOR-2407).
//!
//! This is the shape the fingerprint exists for. A mesh deployment
//! points every node at one store, and a rolling config change means
//! two configs are live at once. Without a config segment in the key,
//! whichever node writes first decides what every node serves until the
//! TTL expires.
//!
//! The store here is the file backend on a directory both processes
//! open, rather than Redis. It is the same shared key space with the
//! same failure mode and no daemon to depend on. `docs/configuration.md`
//! lists both as shared stores for exactly this reason.
//!
//! The pair of tests matters more than either one alone.
//! `two_nodes_on_one_config_do_share_entries` proves the store really
//! is shared between the two processes, so when the other test sees no
//! cross-serving it is because the key partitioned and not because each
//! process quietly had a cache of its own.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

const HOST: &str = "cache.localhost";

/// Both nodes cache to `store_dir`; only `upstream_url` differs.
fn config_yaml(upstream_url: &str, store_dir: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  response_cache_store:
    backend:
      type: file
      path: '{store_dir}'
origins:
  "{HOST}":
    action:
      type: proxy
      url: "{upstream_url}"
    response_cache:
      enabled: true
      ttl: 60
      cacheable_methods: [GET]
      cacheable_status: [200]
"#
    )
}

/// Drive `proxy` until it replays a cached response, then return it.
fn warm_until_hit(proxy: &ProxyHarness, path: &str) -> sbproxy_e2e::Response {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let response = proxy.get(path, HOST).expect("cache poll");
        if response
            .headers
            .get("x-sbproxy-cache")
            .is_some_and(|value| value == "HIT")
        {
            return response;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "cache did not warm within five seconds; last response: {response:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[test]
fn two_nodes_on_different_configs_do_not_share_cache_entries() {
    let store = tempfile::tempdir().expect("shared cache dir");
    let store_dir = store.path().to_string_lossy().into_owned();

    let upstream_a = MockUpstream::start(json!({"served_by": "a"})).expect("upstream a");
    let upstream_b = MockUpstream::start(json!({"served_by": "b"})).expect("upstream b");

    let node_a = ProxyHarness::start_with_yaml(&config_yaml(&upstream_a.base_url(), &store_dir))
        .expect("start node a");
    let node_b = ProxyHarness::start_with_yaml(&config_yaml(&upstream_b.base_url(), &store_dir))
        .expect("start node b");

    // Node A warms the shared store for /thing.
    let warmed = warm_until_hit(&node_a, "/thing");
    assert_eq!(
        warmed.json().expect("node a body")["served_by"],
        "a",
        "node A must be serving its own upstream"
    );

    // Node B asks for the same path. Same workspace, hostname, method,
    // path, query, and Vary, so every segment of the old key format
    // matches what node A wrote.
    let from_b = node_b.get("/thing", HOST).expect("node b GET");
    assert_eq!(from_b.status, 200);
    assert_eq!(
        from_b.json().expect("node b body")["served_by"],
        "b",
        "node B served node A's cached response: the key did not partition on config"
    );
    assert!(
        !upstream_b.captured().is_empty(),
        "node B answered without ever contacting its own upstream"
    );

    // And the partition holds in both directions: A keeps its entries.
    let from_a = node_a.get("/thing", HOST).expect("node a GET");
    assert_eq!(
        from_a.json().expect("node a body")["served_by"],
        "a",
        "node A's entries must survive node B writing under the same path"
    );
}

#[test]
fn two_nodes_on_one_config_do_share_entries() {
    // The control. If this fails, the file store is not actually shared
    // across the two processes and the test above proves nothing.
    let store = tempfile::tempdir().expect("shared cache dir");
    let store_dir = store.path().to_string_lossy().into_owned();

    let upstream = MockUpstream::start(json!({"served_by": "shared"})).expect("upstream");
    let yaml = config_yaml(&upstream.base_url(), &store_dir);

    let node_a = ProxyHarness::start_with_yaml(&yaml).expect("start node a");
    let node_b = ProxyHarness::start_with_yaml(&yaml).expect("start node b");

    warm_until_hit(&node_a, "/shared-thing");
    let before = upstream.captured().len();

    let from_b = node_b.get("/shared-thing", HOST).expect("node b GET");
    assert_eq!(from_b.status, 200);
    assert_eq!(
        from_b.headers.get("x-sbproxy-cache").map(String::as_str),
        Some("HIT"),
        "identical configs must share one entry set, or the store is not shared"
    );
    assert_eq!(
        upstream.captured().len(),
        before,
        "node B reached the upstream for an entry node A had already cached"
    );
}

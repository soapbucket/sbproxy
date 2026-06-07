//! End-to-end coverage for the `object_authz` BOLA/BFLA policy (WOR-816).
//!
//! Drives requests through the proxy with the caller's owner + roles
//! supplied via trusted headers and asserts:
//! - a caller accessing its own object scope is served (200, reaches
//!   the upstream);
//! - a cross-tenant object access is blocked (403, upstream untouched);
//! - a privileged operation without the required role is blocked (BFLA);
//! - sequential object-id enumeration by one principal trips the
//!   anomaly threshold.
//!
//! The owner identity is read from `x-owner-id` here for test
//! simplicity; production configs default to the verified auth subject.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn config(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "authz.localhost":
    action:
      type: proxy
      url: "{upstream_url}"
    policies:
      - type: object_authz
        principal:
          owner_from: header
          owner_header: x-owner-id
          role_header: x-roles
          # The suite models a trusted upstream auth layer that populates
          # x-roles (see the module doc). WOR-1139 made role headers
          # untrusted by default, so the role-based BFLA cases must opt in.
          trust_role_header: true
        object_rules:
          - path: /tenants/{{owner}}/orders/{{id}}
            owner_param: owner
            object_param: id
        function_rules:
          - path: /admin/**
            methods: [POST, DELETE]
            require_role: admin
        enumeration:
          enabled: true
          max_distinct: 3
          window_secs: 60
"#
    )
}

#[test]
fn owner_accesses_own_object_is_served() {
    let upstream = MockUpstream::start(json!({"ok": true})).unwrap();
    let harness = ProxyHarness::start_with_yaml(&config(&upstream.base_url())).expect("proxy");

    let resp = harness
        .get_with_headers(
            "/tenants/tenant-a/orders/1",
            "authz.localhost",
            &[("x-owner-id", "tenant-a")],
        )
        .expect("send");

    assert_eq!(resp.status, 200, "owner reaches its own object");
    assert!(
        !upstream.captured().is_empty(),
        "an in-scope request must reach the upstream"
    );
}

#[test]
fn cross_tenant_object_access_is_blocked() {
    let upstream = MockUpstream::start(json!({"ok": true})).unwrap();
    let harness = ProxyHarness::start_with_yaml(&config(&upstream.base_url())).expect("proxy");

    let resp = harness
        .get_with_headers(
            "/tenants/tenant-b/orders/1",
            "authz.localhost",
            &[("x-owner-id", "tenant-a")],
        )
        .expect("send");

    assert_eq!(resp.status, 403, "cross-tenant access is a BOLA violation");
    assert!(
        upstream.captured().is_empty(),
        "a blocked request must not reach the upstream"
    );
}

#[test]
fn privileged_operation_requires_role() {
    let upstream = MockUpstream::start(json!({"ok": true})).unwrap();
    let harness = ProxyHarness::start_with_yaml(&config(&upstream.base_url())).expect("proxy");

    // Missing the admin role: blocked (BFLA).
    let denied = harness
        .post_json(
            "/admin/users/1",
            "authz.localhost",
            &json!({}),
            &[("x-owner-id", "u1"), ("x-roles", "viewer")],
        )
        .expect("send");
    assert_eq!(denied.status, 403, "privileged op without role is BFLA");

    // Holding the admin role: served.
    let allowed = harness
        .post_json(
            "/admin/users/1",
            "authz.localhost",
            &json!({}),
            &[("x-owner-id", "u1"), ("x-roles", "viewer,admin")],
        )
        .expect("send");
    assert_eq!(allowed.status, 200, "admin role is served");
}

#[test]
fn sequential_object_id_enumeration_trips_anomaly() {
    let upstream = MockUpstream::start(json!({"ok": true})).unwrap();
    let harness = ProxyHarness::start_with_yaml(&config(&upstream.base_url())).expect("proxy");

    // The first three distinct object ids are in-scope and served.
    for id in 1..=3 {
        let resp = harness
            .get_with_headers(
                &format!("/tenants/tenant-a/orders/{id}"),
                "authz.localhost",
                &[("x-owner-id", "tenant-a")],
            )
            .expect("send");
        assert_eq!(resp.status, 200, "id {id} is in-scope and under threshold");
    }

    // The fourth distinct id within the window trips the sweep detector.
    let resp = harness
        .get_with_headers(
            "/tenants/tenant-a/orders/4",
            "authz.localhost",
            &[("x-owner-id", "tenant-a")],
        )
        .expect("send");
    assert_eq!(
        resp.status, 403,
        "enumeration past the threshold is blocked"
    );
}

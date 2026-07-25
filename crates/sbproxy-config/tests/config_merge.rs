//! The merge engine is schema-agnostic on purpose, so nothing inside it
//! can notice when it emits a document the config compiler will reject.
//! These tests close that gap: a realistic base plus a realistic
//! authority document must still compile through `compile_config` in both
//! merge modes, with the locally owned blocks intact.

use sbproxy_config::{compile_config, merge_config, BaseOrigin, MergeError, MergeMode, Provenance};

/// A locally owned `sb.yml`: one real origin plus the blocks the
/// subscriber never lets an authority touch.
const BASE: &str = r#"
proxy:
  http_bind_port: 8081
  admin:
    enabled: true
    port: 9099
    username: operator
    password: local-only-secret
    allow_ips:
      - 127.0.0.1/32
origins:
  api.example.com:
    action:
      type: proxy
      url: https://test.sbproxy.dev
    allowed_methods: [GET, POST]
    force_ssl: true
"#;

/// What a fleet authority would publish: origin policy only. Exercises
/// a nested-map merge, a sequence replacement, an explicit null, and a
/// brand new origin all in one document.
const REMOTE: &str = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://test.sbproxy.dev
    allowed_methods: [GET, POST, PUT]
    tenant_id: null
  internal.example.com:
    action:
      type: proxy
      url: https://test.sbproxy.dev
    force_ssl: true
"#;

fn git_origin() -> BaseOrigin {
    BaseOrigin::Git {
        repo: "git@github.com:soapbucket/fleet-config.git".to_string(),
        reference: "main".to_string(),
        commit: "3c1f7b2a9e5d4086c1b7f0a2d6e8c4b90f1a2d3e".to_string(),
    }
}

#[test]
fn an_overlay_merged_document_compiles() {
    let outcome = merge_config(BASE, BaseOrigin::Local, REMOTE, MergeMode::Overlay)
        .expect("overlay merge should succeed");
    let compiled = compile_config(&outcome.merged_yaml).unwrap_or_else(|error| {
        panic!(
            "merged config must compile: {error}\n{}",
            outcome.merged_yaml
        )
    });

    assert!(compiled.host_map.contains_key("api.example.com"));
    assert!(
        compiled.host_map.contains_key("internal.example.com"),
        "the authority's new origin survives into the compiled config"
    );
    assert_eq!(
        compiled.server.http_bind_port, 8081,
        "a base key the authority did not mention is kept by overlay, \
         and 8081 is not the schema default so this cannot pass vacuously"
    );
}

#[test]
fn a_replace_merged_document_compiles() {
    let outcome = merge_config(BASE, git_origin(), REMOTE, MergeMode::Replace)
        .expect("replace merge should succeed");
    let compiled = compile_config(&outcome.merged_yaml).unwrap_or_else(|error| {
        panic!(
            "merged config must compile: {error}\n{}",
            outcome.merged_yaml
        )
    });

    assert_eq!(compiled.host_map.len(), 2);
    assert!(compiled.host_map.contains_key("internal.example.com"));
}

#[test]
fn the_local_admin_block_survives_the_compiler_in_both_modes() {
    for mode in [MergeMode::Overlay, MergeMode::Replace] {
        let outcome =
            merge_config(BASE, BaseOrigin::Local, REMOTE, mode).expect("merge should succeed");
        let compiled = compile_config(&outcome.merged_yaml)
            .unwrap_or_else(|error| panic!("{mode:?}: merged config must compile: {error}"));

        let admin = compiled
            .server
            .admin
            .as_ref()
            .unwrap_or_else(|| panic!("{mode:?}: the deny-listed admin block must be present"));
        assert_eq!(admin.port, 9099, "{mode:?}");
        assert_eq!(admin.username, "operator", "{mode:?}");
        assert_eq!(admin.password, "local-only-secret", "{mode:?}");
        assert_eq!(
            admin.allow_ips,
            vec!["127.0.0.1/32".to_string()],
            "{mode:?}"
        );
    }
}

#[test]
fn provenance_over_a_realistic_document_matches_who_set_what() {
    let outcome = merge_config(BASE, git_origin(), REMOTE, MergeMode::Overlay)
        .expect("overlay merge should succeed");

    assert_eq!(
        outcome.provenance.get("proxy.admin.port"),
        Some(&git_origin().provenance()),
        "deny-listed leaves are attributed to the base"
    );
    assert_eq!(
        outcome.provenance.get("proxy.http_bind_port"),
        Some(&git_origin().provenance())
    );
    assert_eq!(
        outcome
            .provenance
            .get("origins.internal.example.com.force_ssl"),
        Some(&Provenance::Authority),
        "an origin the authority introduced is attributed to it"
    );
}

#[test]
fn an_authority_document_naming_a_denied_path_never_reaches_the_compiler() {
    let hostile = r#"
proxy:
  admin:
    username: fleet
    password: fleet-wide
origins:
  api.example.com:
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;
    for mode in [MergeMode::Overlay, MergeMode::Replace] {
        let error = merge_config(BASE, BaseOrigin::Local, hostile, mode)
            .expect_err("a remote naming proxy.admin must be rejected outright");
        match error {
            MergeError::DeniedPaths(paths) => {
                assert_eq!(paths, vec!["proxy.admin".to_string()], "{mode:?}");
            }
            other => panic!("{mode:?}: expected a denied-path rejection, got {other}"),
        }
    }

    // The base is still compilable on its own, so the rejection above is
    // the merge declining to act rather than a broken input.
    compile_config(BASE).expect("the base config compiles unchanged");
}

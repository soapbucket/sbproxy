//! Contract for `proxy.cache_reserve.backend` after the two
//! object-storage backends were consolidated onto one (WOR-2673).
//!
//! Two backends briefly shipped for the same job: `type: s3`, written
//! against the AWS SDK with KMS-wrapped envelope encryption, and
//! `type: object_store`, written against the `object_store` crate the
//! workspace already carries, covering S3, GCS, Azure Blob, a local
//! directory, and every S3-compatible store reachable through an
//! `endpoint` override. Only the second one survives.
//!
//! What these tests pin is the part of that removal an operator can
//! feel. `CacheReserveBackendConfig` carries `#[serde(other)]`, so
//! simply deleting the variant would have made an existing `type: s3`
//! block deserialize as "some backend registered out of tree", which
//! the pipeline answers with a `warn!` and no reserve at all. The
//! config would still load, the proxy would still serve, and the cold
//! tier would silently be gone. A refusal that names the replacement is
//! the whole difference.

use sbproxy_config::compile_config;

/// A complete config whose `proxy:` block carries `reserve_block`.
fn config_with_reserve(reserve_block: &str) -> String {
    format!(
        "proxy:\n  http_bind_port: 8080\n{reserve_block}\
         origins:\n  \"cached.local\":\n    action:\n      type: proxy\n      \
         url: https://test.sbproxy.dev\n    response_cache:\n      enabled: true\n      \
         ttl_secs: 60\n"
    )
}

/// The retired AWS-SDK block, exactly as `docs/cache-reserve.md`
/// documented it before this change.
const RETIRED_S3_BLOCK: &str = "  cache_reserve:\n    enabled: true\n    backend:\n      \
     type: s3\n      bucket: my-reserve-bucket\n      region: us-east-1\n      \
     kms_key_id: alias/sbproxy-cache-reserve\n      prefix: reserve/\n";

#[test]
fn the_retired_s3_backend_is_refused_by_name() {
    let Err(error) = compile_config(&config_with_reserve(RETIRED_S3_BLOCK)) else {
        panic!("the retired AWS-SDK reserve backend must not compile");
    };
    let message = error.to_string();
    assert!(
        message.contains("cache_reserve"),
        "the refusal must name the block an operator has to edit: {message}"
    );
    assert!(
        message.contains("type: object_store"),
        "the refusal must name the replacement backend: {message}"
    );
    assert!(
        message.contains("backend: s3"),
        "the refusal must show the field that keeps the operator on S3: {message}"
    );
}

#[test]
fn the_refusal_says_what_happens_to_kms_envelope_encryption() {
    // The one capability that does not carry over. An operator whose
    // bucket policy assumed client-side KMS envelopes needs to read
    // that here, not discover it from a bucket full of objects sealed
    // under a key they did not pick.
    let Err(error) = compile_config(&config_with_reserve(RETIRED_S3_BLOCK)) else {
        panic!("the retired AWS-SDK reserve backend must not compile");
    };
    let message = error.to_string();
    assert!(
        message.contains("kms_key_id"),
        "the refusal must name the field whose behavior changes: {message}"
    );
}

#[test]
fn the_retired_backend_does_not_fall_through_to_the_out_of_tree_catch_all() {
    // `#[serde(other)]` is what makes this test necessary: without an
    // explicit variant, `type: s3` parses as `Other`, the pipeline logs
    // a warning, and an operator gets a config that loads with no cold
    // tier behind it. Deserializing to `Other` here would make the
    // refusal above unreachable in a future refactor.
    let proxy: sbproxy_config::ProxyServerConfig = serde_yaml::from_str(
        "http_bind_port: 8080\ncache_reserve:\n  enabled: true\n  backend:\n    type: s3\n    \
         bucket: my-reserve-bucket\n    region: us-east-1\n    \
         kms_key_id: alias/sbproxy-cache-reserve\n",
    )
    .expect("the retired shape must still parse so the compiler can refuse it by name");
    let backend = proxy
        .cache_reserve
        .expect("the block is present")
        .backend
        .expect("the backend is present");
    assert!(
        !matches!(backend, sbproxy_config::CacheReserveBackendConfig::Other),
        "the retired shape must keep its own variant, not degrade into the out-of-tree catch-all"
    );
}

#[test]
fn the_surviving_object_store_backend_still_compiles_against_s3() {
    let block =
        "  cache_reserve:\n    enabled: true\n    backend:\n      type: object_store\n      \
                 backend: s3\n      bucket: my-reserve-bucket\n      region: us-east-1\n      \
                 prefix: sbproxy/reserve/\n";
    compile_config(&config_with_reserve(block))
        .expect("the surviving object-store backend must still compile");
}

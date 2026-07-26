// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Reload atomicity.
//!
//! A reload that returns `Err` must leave the node exactly as it was:
//! same pipeline, same AI provider catalog, same request-path process
//! globals. The historical bug was the opposite - the reload installed
//! most of its process globals up front, and a config that compiled but
//! failed to construct a pipeline left the node running new sandbox
//! limits, new redaction rules, a new catalog, and a new sink
//! dispatcher against the old pipeline while reporting that nothing had
//! been applied.
//!
//! Every test here drives the same process globals, so they run one at
//! a time behind [`SERIAL`].

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

/// Serializes the tests in this binary. The reload path is a
/// process-wide transaction (live pipeline, provider catalog, sink
/// dispatcher), so two tests running at once would observe each other's
/// installs.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A one-provider override catalog. The names are fixtures that do not
/// exist in the embedded catalog, so an assertion on them cannot pass
/// by accident.
fn catalog_yaml(provider: &str) -> String {
    format!(
        r#"providers:
  - name: {provider}
    display_name: Fixture {provider}
    default_base_url: https://{provider}.invalid/v1
    auth_header: Authorization
    auth_prefix: "Bearer "
    format: openai
    supports_streaming: true
    supports_embeddings: false
"#
    )
}

/// A config whose single AI origin names `declared_provider`, backed by
/// the override catalog at `catalog`. `declared_provider` must be the
/// exact (lowercase) catalog key for the pipeline to construct.
fn ai_config(host: &str, catalog: &Path, declared_provider: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  ai_providers_file: {catalog}
origins:
  "{host}":
    action:
      type: ai_proxy
      providers:
        - name: {declared_provider}
          models: [demo]
"#,
        catalog = catalog.display(),
    )
}

/// A plain static-origin config with no AI, no sinks, and no secrets.
fn static_config(host: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "{host}":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: ok
"#
    )
}

/// The same static config plus one declared telemetry sink, so a test
/// can watch the sink dispatcher move from absent to installed.
fn static_config_with_sink(host: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  observability:
    log:
      sinks:
        - name: stdout-access
          target: access_log
          output: {{ type: stdout }}
origins:
  "{host}":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: ok
"#
    )
}

/// The same static config plus a `proxy.secrets:` block. The secret
/// resolver is process-owned and set-once, so introducing this block on
/// a reload has to be refused.
fn static_config_with_secrets(host: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  secrets:
    backend: local
    backends:
      - type: local
        name: fixture
        entries:
          demo: value
origins:
  "{host}":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: ok
"#
    )
}

fn reload(path: &Path) -> anyhow::Result<sbproxy_core::server::ReloadOutcome> {
    sbproxy_core::server::reload_from_config_path(path.to_str().expect("utf-8 config path"))
}

fn live_hostnames() -> Vec<String> {
    sbproxy_core::reload::current_pipeline()
        .config
        .origins
        .iter()
        .map(|origin| origin.hostname.to_string())
        .collect()
}

fn live_revision() -> String {
    sbproxy_core::reload::current_pipeline()
        .config_revision
        .clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_construction_leaves_the_provider_catalog_and_pipeline_untouched() {
    let _serial = serial();
    let temp = tempfile::tempdir().expect("temp dir");
    let config_path = temp.path().join("sb.yml");

    // The catalog the node should still be serving after the failure.
    let alpha_catalog = temp.path().join("alpha-catalog.yml");
    std::fs::write(&alpha_catalog, catalog_yaml("alpha_fixture")).expect("write alpha catalog");
    std::fs::write(
        &config_path,
        ai_config("alpha.test", &alpha_catalog, "alpha_fixture"),
    )
    .expect("write alpha config");
    reload(&config_path).expect("alpha reload");

    assert!(
        sbproxy_ai::get_provider_info("alpha_fixture").is_some(),
        "the alpha catalog must be live before the failing reload",
    );
    let revision_before = live_revision();
    assert!(live_hostnames().iter().any(|host| host == "alpha.test"));
    assert!(
        sbproxy_observe::sink_dispatcher::current_sink_dispatcher().is_none(),
        "no sinks are declared yet",
    );

    // This config compiles. It points at a different catalog and then
    // names that catalog's provider with the wrong casing, which AI
    // handler construction rejects. The rejection happens after the new
    // catalog is already installed, which is exactly the window the
    // rollback covers. It also declares a sink, so a leaked commit
    // phase would be visible in the dispatcher.
    let beta_catalog = temp.path().join("beta-catalog.yml");
    std::fs::write(&beta_catalog, catalog_yaml("beta_fixture")).expect("write beta catalog");
    let failing = format!(
        r#"
proxy:
  http_bind_port: 0
  ai_providers_file: {catalog}
  observability:
    log:
      sinks:
        - name: stdout-access
          target: access_log
          output: {{ type: stdout }}
origins:
  "beta.test":
    action:
      type: ai_proxy
      providers:
        - name: Beta_Fixture
          models: [demo]
"#,
        catalog = beta_catalog.display(),
    );
    std::fs::write(&config_path, &failing).expect("write failing config");
    let error = reload(&config_path).expect_err("case-mismatched provider must fail to construct");
    let message = format!("{error:#}");
    assert!(
        message.contains("beta_fixture"),
        "the failure must come from provider-name resolution: {message}",
    );

    // The catalog is exactly what it was before the reload.
    assert!(
        sbproxy_ai::get_provider_info("alpha_fixture").is_some(),
        "a failed reload must restore the previous AI provider catalog",
    );
    assert!(
        sbproxy_ai::get_provider_info("beta_fixture").is_none(),
        "a failed reload must not leave the candidate catalog installed",
    );

    // The previously loaded pipeline is still the one serving.
    assert_eq!(
        live_revision(),
        revision_before,
        "a failed reload must not publish a pipeline",
    );
    let hostnames = live_hostnames();
    assert!(
        hostnames.iter().any(|host| host == "alpha.test"),
        "the prior pipeline must still be serving: {hostnames:?}",
    );
    assert!(
        !hostnames.iter().any(|host| host == "beta.test"),
        "the candidate pipeline must not be serving: {hostnames:?}",
    );

    // And no commit-phase process global moved.
    assert!(
        sbproxy_observe::sink_dispatcher::current_sink_dispatcher().is_none(),
        "a failed reload must not install the candidate's sink dispatcher",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn successful_reload_reports_fully_applied() {
    let _serial = serial();
    let temp = tempfile::tempdir().expect("temp dir");
    let config_path = temp.path().join("sb.yml");
    std::fs::write(&config_path, static_config("applied.test")).expect("write config");

    let outcome = reload(&config_path).expect("reload");
    assert!(
        outcome.is_fully_applied(),
        "a clean reload must not report degraded subsystems: {:?}",
        outcome.degraded(),
    );
    assert!(outcome.degraded().is_empty());
    assert_eq!(outcome.to_string(), "fully applied");
    assert!(live_hostnames().iter().any(|host| host == "applied.test"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn successful_reload_installs_the_request_path_subsystems() {
    let _serial = serial();
    let temp = tempfile::tempdir().expect("temp dir");
    let config_path = temp.path().join("sb.yml");

    // Start from a config with no declared sinks so the dispatcher slot
    // is observably empty.
    std::fs::write(&config_path, static_config("sinkless.test")).expect("write sinkless config");
    reload(&config_path).expect("sinkless reload");
    assert!(
        sbproxy_observe::sink_dispatcher::current_sink_dispatcher().is_none(),
        "a config with no sinks must leave the dispatcher empty",
    );

    // A successful reload has to move the commit-phase globals, not just
    // the pipeline.
    std::fs::write(&config_path, static_config_with_sink("sinkful.test"))
        .expect("write sink config");
    let outcome = reload(&config_path).expect("sink reload");
    assert!(outcome.is_fully_applied(), "{outcome}");
    assert!(
        sbproxy_observe::sink_dispatcher::current_sink_dispatcher().is_some(),
        "a successful reload must install the declared sink dispatcher",
    );

    // And a later reload that drops the sinks takes it away again.
    std::fs::write(&config_path, static_config("sinkless.test")).expect("write sinkless config");
    reload(&config_path).expect("sinkless reload");
    assert!(
        sbproxy_observe::sink_dispatcher::current_sink_dispatcher().is_none(),
        "dropping the sinks block must clear the dispatcher",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changing_proxy_secrets_is_refused_and_installs_nothing() {
    let _serial = serial();
    let temp = tempfile::tempdir().expect("temp dir");
    let config_path = temp.path().join("sb.yml");

    // Pin the process-owned secrets block (absent) with a first reload.
    std::fs::write(&config_path, static_config("secrets-before.test")).expect("write config");
    reload(&config_path).expect("baseline reload");
    let revision_before = live_revision();
    assert!(
        sbproxy_observe::sink_dispatcher::current_sink_dispatcher().is_none(),
        "the baseline config declares no sinks",
    );

    std::fs::write(
        &config_path,
        static_config_with_secrets("secrets-after.test"),
    )
    .expect("write secrets config");
    let error = reload(&config_path).expect_err("a changed proxy.secrets block must be refused");
    let message = format!("{error:#}");
    assert!(
        message.contains("restart"),
        "the refusal must tell the operator to restart: {message}",
    );
    assert!(
        message.contains("proxy.secrets"),
        "the refusal must name the offending block: {message}",
    );

    assert_eq!(
        live_revision(),
        revision_before,
        "a refused reload must not publish a pipeline",
    );
    let hostnames = live_hostnames();
    assert!(
        hostnames.iter().any(|host| host == "secrets-before.test"),
        "the prior pipeline must still be serving: {hostnames:?}",
    );
    assert!(
        !hostnames.iter().any(|host| host == "secrets-after.test"),
        "the refused pipeline must not be serving: {hostnames:?}",
    );

    // Removing the block again is accepted: the fingerprint matches the
    // one this process owns.
    std::fs::write(&config_path, static_config("secrets-restored.test")).expect("write config");
    reload(&config_path).expect("reload back to the owned secrets block");
    assert!(live_hostnames()
        .iter()
        .any(|host| host == "secrets-restored.test"));
}

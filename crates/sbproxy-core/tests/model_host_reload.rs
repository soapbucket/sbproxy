// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

use std::path::Path;
use std::sync::Arc;

use sbproxy_core::model_runtime::model_runtime_manager;

fn empty_yaml() -> &'static str {
    r#"
proxy:
  http_bind_port: 0
origins:
  "empty.test":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: ok
"#
}

fn managed_yaml(cache: &Path, coder_keep_alive: u64) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  model_host:
    shutdown_deadline_ms: 200
    cache:
      directory: {cache}
    deployments:
      coder:
        model: qwen2.5-0.5b-instruct
        variant: q4_k_m
        keep_alive_secs: {coder_keep_alive}
        max_concurrency: 2
        max_queue_depth: 1
        queue_timeout_ms: 25
      reviewer:
        model: qwen2.5-0.5b-instruct
        variant: q4_k_m
        max_concurrency: 1
origins:
  "coder.test":
    action:
      type: ai_proxy
      providers:
        - name: local-coder
          provider_type: managed_model
          deployment: coder
          models: [coder]
  "reviewer.test":
    action:
      type: ai_proxy
      providers:
        - name: local-reviewer
          provider_type: managed_model
          deployment: reviewer
          models: [reviewer]
"#,
        cache = cache.display(),
    )
}

fn conflicting_yaml(cache: &Path) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  model_host:
    cache:
      directory: {cache}
    deployments:
      coder:
        model: qwen2.5-0.5b-instruct
        variant: q4_k_m
      reviewer:
        model: qwen2.5-0.5b-instruct
        variant: q4_k_m
origins:
  "coder.test":
    action:
      type: ai_proxy
      providers:
        - name: local
          provider_type: managed_model
          deployment: coder
          models: [shared]
  "reviewer.test":
    action:
      type: ai_proxy
      providers:
        - name: local
          provider_type: managed_model
          deployment: reviewer
          models: [shared]
"#,
        cache = cache.display(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_startup_reload_is_atomic_and_collects_every_origin() {
    let temp = tempfile::tempdir().expect("temp dir");
    let config_path = temp.path().join("sb.yml");
    let runtime = model_runtime_manager();

    std::fs::write(&config_path, empty_yaml()).expect("write empty config");
    sbproxy_core::server::reload_from_config_path(config_path.to_str().expect("config path"))
        .expect("reload empty startup");
    let empty_revision = runtime.current_revision();
    assert!(runtime.current_desired().deployments.is_empty());

    std::fs::write(&config_path, managed_yaml(temp.path(), 30)).expect("write managed config");
    sbproxy_core::server::reload_from_config_path(config_path.to_str().expect("config path"))
        .expect("reload first managed config");

    assert!(Arc::ptr_eq(&runtime, &model_runtime_manager()));
    assert!(runtime.current_revision() > empty_revision);
    let desired = runtime.current_desired();
    assert_eq!(desired.deployments.len(), 2);
    assert!(desired
        .route_for("coder.test", "local-coder", "coder")
        .is_some());
    assert!(desired
        .route_for("reviewer.test", "local-reviewer", "reviewer")
        .is_some());

    let permit = runtime
        .admit_request("coder", sbproxy_model_host::PriorityClass::Standard)
        .await
        .expect("admit managed request");
    assert_eq!(
        runtime
            .status("coder")
            .await
            .expect("coder status")
            .active_requests,
        1,
    );
    let mut context = sbproxy_core::context::RequestContext::new();
    context.managed_model_permit = Some(permit);
    drop(context);
    assert_eq!(
        runtime
            .status("coder")
            .await
            .expect("coder status")
            .active_requests,
        0,
        "dropping the request context releases deployment capacity",
    );

    let held = runtime
        .admit_request("coder", sbproxy_model_host::PriorityClass::Standard)
        .await
        .expect("hold the only active slot");
    let second = runtime
        .admit_request("coder", sbproxy_model_host::PriorityClass::Batch)
        .await
        .expect("second active slot");
    let rejection = runtime
        .admit_request("coder", sbproxy_model_host::PriorityClass::Interactive)
        .await
        .expect_err("bounded queue must time out");
    assert_eq!(
        rejection.reason,
        sbproxy_model_host::AdmissionReason::QueueTimeout,
    );
    drop(second);
    drop(held);

    let held = runtime
        .admit_request("coder", sbproxy_model_host::PriorityClass::Standard)
        .await
        .expect("hold capacity through drain");
    let drain_runtime = Arc::clone(&runtime);
    let drain = tokio::spawn(async move { drain_runtime.drain("coder").await });
    for _ in 0..100 {
        if runtime.status("coder").await.is_some_and(|status| {
            status.state == sbproxy_model_host::DeploymentRuntimeState::Draining
        }) {
            break;
        }
        tokio::task::yield_now().await;
    }
    let rejection = runtime
        .admit_request("coder", sbproxy_model_host::PriorityClass::Interactive)
        .await
        .expect_err("draining deployment rejects new work");
    assert_eq!(
        rejection.reason,
        sbproxy_model_host::AdmissionReason::Draining,
    );
    drop(held);
    let drain_report = drain.await.expect("drain task").expect("drain result");
    assert_eq!(drain_report.active_at_start, 1);
    assert!(!drain_report.timed_out);

    let before = runtime.statuses().await;
    let reviewer_generation = before
        .iter()
        .find(|status| status.deployment == "reviewer")
        .expect("reviewer status")
        .generation;

    std::fs::write(&config_path, managed_yaml(temp.path(), 60)).expect("write changed config");
    sbproxy_core::server::reload_from_config_path(config_path.to_str().expect("config path"))
        .expect("reload one-deployment change");
    let after = runtime.statuses().await;
    assert_eq!(
        after
            .iter()
            .find(|status| status.deployment == "reviewer")
            .expect("reviewer status after reload")
            .generation,
        reviewer_generation,
    );

    let stable_revision = runtime.current_revision();
    let stable_pipeline_revision = sbproxy_core::reload::current_pipeline()
        .config_revision
        .clone();
    std::fs::write(&config_path, conflicting_yaml(temp.path())).expect("write conflict config");
    let error =
        sbproxy_core::server::reload_from_config_path(config_path.to_str().expect("config path"))
            .expect_err("conflicting public route must fail before commit");
    assert!(error.to_string().contains("conflicting route"));
    assert_eq!(runtime.current_revision(), stable_revision);
    assert_eq!(runtime.current_desired().deployments.len(), 2);
    assert_eq!(
        sbproxy_core::reload::current_pipeline().config_revision,
        stable_pipeline_revision,
    );
}

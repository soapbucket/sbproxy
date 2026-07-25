// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Validation-mode pipeline construction must not spawn background tasks.
//!
//! A validation pipeline is built to answer "would this config construct?"
//! and is then dropped. Health-check probes spawned during construction
//! outlive that drop, hold an `Arc` on the discarded pipeline, and keep
//! issuing real requests at the operator's upstreams. Any caller that
//! validates repeatedly accumulates them without bound.
//!
//! These tests are behavioural rather than structural: they point a health
//! check at a real listener and count the connections that arrive.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use sbproxy_core::pipeline::CompiledPipeline;

/// Accept connections on an ephemeral port, counting each one.
///
/// Returns the bound port and the shared counter. The listener task runs
/// until the test ends.
async fn counting_listener() -> (u16, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind probe listener");
    let port = listener.local_addr().expect("listener addr").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_task = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    hits_task.fetch_add(1, Ordering::SeqCst);
                    drop(stream);
                }
                Err(_) => return,
            }
        }
    });
    (port, hits)
}

/// A config whose only origin load-balances onto a health-checked target.
///
/// `interval_secs: 1` matters: `tokio::time::interval` fires its first
/// tick immediately, so a spawned probe reaches the listener within
/// milliseconds rather than after a full period.
fn health_checked_yaml(port: u16) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "lb.test":
    action:
      type: load_balancer
      targets:
        - url: "http://127.0.0.1:{port}"
          health_check:
            path: /healthz
            interval_secs: 1
            timeout_ms: 200
"#
    )
}

/// Give any spawned probe a generous window to reach the listener.
async fn settle() {
    tokio::time::sleep(std::time::Duration::from_millis(750)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validation_construction_spawns_no_health_probes() {
    let (port, hits) = counting_listener().await;
    let compiled = sbproxy_config::compile_config(&health_checked_yaml(port)).expect("compile");

    let pipeline = CompiledPipeline::from_config_for_validation(compiled).expect("construct");
    drop(pipeline);
    settle().await;

    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "validation-mode construction spawned a health probe; it must not, \
         because the pipeline it holds has already been dropped"
    );
}

/// Guards the test above: if runtime mode also stopped probing, the
/// assertion of zero would pass for the wrong reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_construction_still_spawns_health_probes() {
    let (port, hits) = counting_listener().await;
    let compiled = sbproxy_config::compile_config(&health_checked_yaml(port)).expect("compile");

    let pipeline = CompiledPipeline::from_config(compiled).expect("construct");
    settle().await;

    assert!(
        hits.load(Ordering::SeqCst) > 0,
        "runtime-mode construction stopped spawning health probes; the \
         validation-mode test above would then pass vacuously"
    );
    drop(pipeline);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_validation_does_not_accumulate_probes() {
    let (port, hits) = counting_listener().await;
    let yaml = health_checked_yaml(port);

    for _ in 0..5 {
        let compiled = sbproxy_config::compile_config(&yaml).expect("compile");
        drop(CompiledPipeline::from_config_for_validation(compiled).expect("construct"));
    }
    settle().await;

    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "repeated validation accumulated health probes; this is the admin \
         config-write path, which validates on every save"
    );
}

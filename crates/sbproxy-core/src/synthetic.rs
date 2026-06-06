//! Synthetic-transaction probe driver.
//!
//! Background task that fires an in-process request through the
//! compiled handler chain on a fixed cadence and feeds the verdict
//! back into the [`sbproxy_observe::SyntheticProbeState`] cache that
//! backs the `synthetic_pipeline` `/readyz` probe.
//!
//! The synthetic origin is required to be a non-network action
//! (`static`, `mock`, `echo`, `noop`) so the probe never reaches a
//! real upstream. The driver enforces a per-run timeout budget so a
//! stuck pipeline cannot wedge readiness reporting.
//!
//! See `crates/sbproxy-observe/src/synthetic.rs` for the cache shape
//! and `crates/sbproxy-config/src/types.rs::SyntheticProbeConfig`
//! for the config schema.

use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Uri};
use sbproxy_config::SyntheticProbeConfig;
use sbproxy_observe::{metrics, SyntheticProbeState};
use tokio::time::{interval, timeout};
use tracing::{debug, warn};

use crate::dispatch::dispatch_h3_request;

/// Minimum acceptable HTTP status the synthetic response can carry
/// before the driver flags the run as a failure. Status `>=` this is
/// treated as success; everything below is success too. The cutoff
/// is the conventional client-error boundary.
const SYNTHETIC_FAILURE_STATUS_CUTOFF: u16 = 400;

/// Run one synthetic round trip, applying the timeout budget and
/// feeding the verdict into `state`. Public for testability; the
/// background loop drives this on a cadence.
pub async fn run_one(config: &SyntheticProbeConfig, state: &SyntheticProbeState) {
    let start = std::time::Instant::now();
    let request = match build_request(config) {
        Ok(r) => r,
        Err(reason) => {
            record_failure(state, reason);
            return;
        }
    };

    let client_ip = "127.0.0.1".parse().expect("loopback ip parses");
    let fut = dispatch_h3_request(
        request.method,
        request.uri,
        request.headers,
        request.body,
        client_ip,
    );

    let budget = Duration::from_millis(config.timeout_ms);
    let outcome = timeout(budget, fut).await;

    match outcome {
        Err(_) => {
            record_failure(state, "timeout");
        }
        Ok(Err(e)) => {
            debug!(error = %e, "synthetic probe dispatch error");
            record_failure(state, "dispatch_error");
        }
        Ok(Ok(resp)) if resp.status >= SYNTHETIC_FAILURE_STATUS_CUTOFF => {
            let reason = if resp.status == 404 {
                "origin_not_found"
            } else if resp.status == 401 || resp.status == 403 {
                "unauthorized"
            } else if resp.status >= 500 {
                "upstream_5xx"
            } else {
                "client_4xx"
            };
            record_failure(state, reason);
        }
        Ok(Ok(_)) => {
            state.record_success(start.elapsed());
        }
    }
}

fn record_failure(state: &SyntheticProbeState, reason: &'static str) {
    metrics::metrics()
        .synthetic_probe_failures
        .with_label_values(&[reason])
        .inc();
    state.record_failure(reason);
}

struct SyntheticRequest {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Option<Bytes>,
}

fn build_request(config: &SyntheticProbeConfig) -> Result<SyntheticRequest, &'static str> {
    let uri: Uri = config.path.parse().map_err(|_| "invalid_path")?;
    let host_value = HeaderValue::from_str(&config.hostname).map_err(|_| "invalid_hostname")?;
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, host_value);
    headers.insert("x-sbproxy-synthetic", HeaderValue::from_static("1"));
    Ok(SyntheticRequest {
        method: Method::GET,
        uri,
        headers,
        body: None,
    })
}

/// Spawn the synthetic-probe background loop. The returned join
/// handle outlives the process; cancelling is via dropping the task
/// (we do not currently surface a stop handle, the same pattern other
/// background tasks in this crate use).
pub fn spawn_loop(config: SyntheticProbeConfig, state: SyntheticProbeState) {
    if !config.enabled {
        return;
    }
    if tokio::runtime::Handle::try_current().is_err() {
        warn!("synthetic probe loop requested but no tokio runtime is current; skipping spawn");
        return;
    }
    let cadence = Duration::from_secs(config.interval_secs.max(1));
    tokio::spawn(async move {
        let mut ticker = interval(cadence);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            run_one(&config, &state).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_observe::ComponentStatus;

    fn cfg(hostname: &str) -> SyntheticProbeConfig {
        SyntheticProbeConfig {
            enabled: true,
            hostname: hostname.to_string(),
            path: "/readyz/synthetic".to_string(),
            interval_secs: 30,
            timeout_ms: 500,
            stale_after_secs: 120,
        }
    }

    #[tokio::test]
    async fn run_one_records_failure_when_origin_unknown() {
        let config = cfg("nonexistent-host-for-synthetic-test.invalid");
        let state = SyntheticProbeState::new();
        run_one(&config, &state).await;
        let (status, detail) = state.current(Duration::from_secs(60));
        assert_eq!(status, ComponentStatus::Unhealthy);
        assert_eq!(detail.unwrap(), "origin_not_found");
    }

    #[tokio::test]
    async fn run_one_records_failure_with_invalid_path() {
        let mut config = cfg("__synthetic.local");
        config.path = " not a uri ".to_string();
        let state = SyntheticProbeState::new();
        run_one(&config, &state).await;
        let (status, detail) = state.current(Duration::from_secs(60));
        assert_eq!(status, ComponentStatus::Unhealthy);
        assert_eq!(detail.unwrap(), "invalid_path");
    }

    #[tokio::test]
    async fn run_one_records_success_when_static_origin_serves_200() {
        use compact_str::CompactString;
        use std::collections::HashMap;

        // Reserve a unique sentinel so this test does not race with
        // another test that loads its own pipeline through the global
        // ArcSwap. The driver looks up by hostname so the rest of the
        // origin set is irrelevant.
        let hostname = "__synthetic.test_success.local";

        let origin = sbproxy_config::CompiledOrigin {
            hostname: CompactString::new(hostname),
            origin_id: CompactString::new(hostname),
            workspace_id: CompactString::default(),
            tenant_id: compact_str::CompactString::const_new("__default__"),
            action_config: serde_json::json!({
                "type": "static",
                "status": 200,
                "body": "synthetic ok",
            }),
            auth_config: None,
            policy_configs: Vec::new(),
            transform_configs: Vec::new(),
            cors: None,
            hsts: None,
            compression: None,
            session: None,
            properties: None,
            sessions: None,
            user: None,
            force_ssl: false,
            allowed_methods: smallvec::smallvec![],
            request_modifiers: smallvec::smallvec![],
            response_modifiers: smallvec::smallvec![],
            variables: None,
            forward_rules: Vec::new(),
            fallback_origin: None,
            error_pages: None,
            problem_details: None,
            proxy_status: None,
            message_signatures: None,
            olp: None,
            web_bot_auth_publish: None,
            idempotency: None,
            bot_detection: None,
            threat_protection: None,
            on_request: Vec::new(),
            on_response: Vec::new(),
            response_cache: None,
            mirror: None,
            extensions: HashMap::new(),
            expose_openapi: false,
            stream_safety: Vec::new(),
            rate_limits: None,
            auto_content_negotiate: None,
            content_signal: None,
            token_bytes_ratio: None,
            agent_skills: Vec::new(),
            agents_md: None,
            ai_txt: None,
            agents_json: None,
            outbound_credential: None,
            outbound_web_bot_auth: false,
            observability: None,
        };
        let mut host_map = HashMap::new();
        host_map.insert(CompactString::new(hostname), 0);
        let compiled = sbproxy_config::CompiledConfig {
            origins: vec![origin],
            host_map,
            server: sbproxy_config::ProxyServerConfig::default(),
            l2_store: None,
            messenger: None,
            mesh: None,
            access_log: None,
            agent_classes: None,
            rate_limits: None,
            audit: None,
            session_ledger: None,
        };
        let pipeline = crate::pipeline::CompiledPipeline::from_config(compiled)
            .expect("static origin pipeline compiles");
        crate::reload::load_pipeline(pipeline);

        let config = cfg(hostname);
        let state = SyntheticProbeState::new();
        run_one(&config, &state).await;
        let (status, detail) = state.current(Duration::from_secs(60));
        assert_eq!(
            status,
            ComponentStatus::Healthy,
            "expected synthetic success: {:?}",
            detail
        );
        assert!(detail.unwrap().starts_with("latency_ms="));
    }
}

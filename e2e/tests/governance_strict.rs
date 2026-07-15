//! Multi-process strict-governance acceptance coverage (WOR-1845).
//!
//! This test is ignored by default because it needs a live Redis endpoint and
//! a prebuilt sbproxy binary. Run it with `REDIS_URL=redis://127.0.0.1:6379`.

use std::net::TcpListener;
use std::sync::{Arc, Barrier};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sbproxy_e2e::{MockUpstream, ProxyHarness};

const LIMIT: usize = 25;
const REQUESTS: usize = 100;

#[derive(Clone, Copy)]
enum LimitMode {
    Requests,
    Money,
}

fn pick_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("ephemeral address")
        .port()
}

fn config(
    admin_port: u16,
    store_path: &str,
    redis_url: &str,
    upstream_url: &str,
    key_id: &str,
    limit_mode: LimitMode,
) -> String {
    let redis_url = serde_json::to_string(redis_url).expect("quote Redis URL");
    let (seed_limit, model_prices) = match limit_mode {
        LimitMode::Requests => (format!("max_requests_per_minute: {LIMIT}"), String::new()),
        LimitMode::Money => (
            "max_budget_usd: 0.000025".to_string(),
            r#"
      model_prices:
        gpt-4o-mini:
          input_per_million: 0.0
          output_per_million: 1.0"#
                .to_string(),
        ),
    };
    format!(
        r#"
proxy:
  http_bind_port: 0
  admin:
    enabled: true
    port: {admin_port}
    username: admin
    password: secret
  key_management:
    enabled: true
    store:
      backend: embedded
      path: "{store_path}"
    crypto:
      pepper: strict-governance-e2e-pepper
      master_key: strict-governance-e2e-master
    governance:
      consistency: strict
      backend:
        type: redis
        url: {redis_url}
      lease_ttl_secs: 5
      terminal_retention_secs: 60
      failure_mode: closed
      missing_rate: zero_cost
      default_max_output_tokens: 32
    seed:
      keys:
        - key_id: {key_id}
          secret: shared-secret
          name: strict-load-key
          {seed_limit}
          allowed_models: [gpt-4o-mini]
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      require_governed_key: true
      providers:
        - name: openai
          api_key: stub
          base_url: "{upstream_url}"
          allow_private_base_url: true
          default_model: gpt-4o-mini
          models: [gpt-4o-mini]
{model_prices}
"#
    )
}

fn chat(base_url: &str, token: &str) -> u16 {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("HTTP client")
        .post(format!("{base_url}/v1/chat/completions"))
        .header("host", "ai.localhost")
        .header("authorization", format!("Bearer {token}"))
        // Correlation IDs are caller-controlled and must never collapse
        // independent governance reservations into one idempotent record.
        .header("x-request-id", "shared-client-correlation-id")
        .json(&serde_json::json!({
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "strict admission"}],
            "max_tokens": 1
        }))
        .send()
        .expect("governed chat request")
        .status()
        .as_u16()
}

fn exercise_two_gateway_load(limit_mode: LimitMode) -> (Vec<u16>, serde_json::Value, usize) {
    let redis_url = std::env::var("REDIS_URL").expect("REDIS_URL is required");
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("wall clock")
        .as_nanos();
    let key_id = format!("strict{}{}", std::process::id(), suffix);
    let token = format!("sk-{key_id}-shared-secret");
    let store_a = format!(
        "{}/governance-a-{suffix}.redb",
        std::env::temp_dir().display()
    );
    let store_b = format!(
        "{}/governance-b-{suffix}.redb",
        std::env::temp_dir().display()
    );
    let _ = std::fs::remove_file(&store_a);
    let _ = std::fs::remove_file(&store_b);

    let upstream = MockUpstream::start(serde_json::json!({
        "id": "chatcmpl-governed",
        "object": "chat.completion",
        "model": "gpt-4o-mini",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "ok"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    }))
    .expect("mock upstream");
    let admin_a = pick_port();
    let admin_b = pick_port();
    let proxy_a = ProxyHarness::start_with_yaml(&config(
        admin_a,
        &store_a,
        &redis_url,
        &upstream.base_url(),
        &key_id,
        limit_mode,
    ))
    .expect("start gateway A");
    let proxy_b = ProxyHarness::start_with_yaml(&config(
        admin_b,
        &store_b,
        &redis_url,
        &upstream.base_url(),
        &key_id,
        limit_mode,
    ))
    .expect("start gateway B");
    ProxyHarness::wait_for_port(admin_a, Duration::from_secs(10)).expect("admin A ready");
    ProxyHarness::wait_for_port(admin_b, Duration::from_secs(10)).expect("admin B ready");

    let bases = [proxy_a.base_url(), proxy_b.base_url()];
    let barrier = Arc::new(Barrier::new(REQUESTS + 1));
    let mut workers = Vec::with_capacity(REQUESTS);
    for index in 0..REQUESTS {
        let base = bases[index % bases.len()].clone();
        let token = token.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            chat(&base, &token)
        }));
    }
    barrier.wait();
    let statuses = workers
        .into_iter()
        .map(|worker| worker.join().expect("request worker"))
        .collect::<Vec<_>>();

    let usage = reqwest::blocking::Client::new()
        .get(format!(
            "http://127.0.0.1:{admin_a}/admin/keys/{key_id}/usage"
        ))
        .basic_auth("admin", Some("secret"))
        .send()
        .expect("admin usage")
        .error_for_status()
        .expect("usage status")
        .json::<serde_json::Value>()
        .expect("usage JSON");
    let upstream_requests = upstream.captured().len();

    drop(proxy_b);
    drop(proxy_a);
    let _ = std::fs::remove_file(&store_a);
    let _ = std::fs::remove_file(&store_b);

    (statuses, usage, upstream_requests)
}

#[test]
#[ignore = "requires REDIS_URL and a prebuilt sbproxy binary"]
fn two_gateways_never_accept_more_than_the_shared_strict_request_limit() {
    let (statuses, usage, upstream_requests) = exercise_two_gateway_load(LimitMode::Requests);
    let accepted = statuses.iter().filter(|status| **status == 200).count();
    let denied = statuses.iter().filter(|status| **status == 429).count();
    assert_eq!(accepted, LIMIT, "statuses: {statuses:?}");
    assert_eq!(denied, REQUESTS - LIMIT, "statuses: {statuses:?}");
    assert_eq!(upstream_requests, LIMIT);

    let rpm = &usage["dimensions"]["requests_per_minute"];
    assert_eq!(rpm["limit"].as_u64(), Some(LIMIT as u64));
    assert_eq!(rpm["used"].as_u64(), Some(LIMIT as u64));
    assert_eq!(rpm["reserved"].as_u64(), Some(0));
    assert_eq!(rpm["remaining"].as_u64(), Some(0));
    assert_eq!(usage["consistency"], "strict");
    assert_eq!(usage["backend"]["status"], "healthy");
}

#[test]
#[ignore = "requires REDIS_URL and a prebuilt sbproxy binary"]
fn two_gateways_never_exceed_shared_money_by_more_than_one_micro_usd() {
    let (statuses, usage, upstream_requests) = exercise_two_gateway_load(LimitMode::Money);
    let accepted = statuses.iter().filter(|status| **status == 200).count();
    let denied = statuses.iter().filter(|status| **status == 402).count();
    assert_eq!(accepted, LIMIT, "statuses: {statuses:?}");
    assert_eq!(denied, REQUESTS - LIMIT, "statuses: {statuses:?}");
    assert_eq!(upstream_requests, LIMIT);

    let money = &usage["dimensions"]["budget_micro_usd"];
    let limit = money["limit"].as_u64().expect("money limit");
    let used = money["used"].as_u64().expect("money used");
    assert_eq!(limit, LIMIT as u64);
    assert!(used <= limit + 1, "used={used}, limit={limit}");
    assert_eq!(used, LIMIT as u64);
    assert_eq!(money["reserved"].as_u64(), Some(0));
    assert_eq!(money["remaining"].as_u64(), Some(0));
    assert_eq!(usage["consistency"], "strict");
    assert_eq!(usage["backend"]["status"], "healthy");
}

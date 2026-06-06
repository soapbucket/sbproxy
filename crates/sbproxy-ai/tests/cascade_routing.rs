//! Integration tests for the WOR-489 cascade routing strategy.
//!
//! Each test stands up a small one-shot TCP server per tier so the
//! cascade dispatch path runs end-to-end through the real
//! `AiClient::forward_cascade` API. The cases cover the four
//! behaviours called out in the ticket plus the cascade metric:
//!
//! 1. A tier whose response scores below `quality_threshold` falls
//!    through to the next tier.
//! 2. A tier whose response is at or above the threshold short-
//!    circuits the cascade.
//! 3. A `max_total_cost` cap cuts the cascade short mid-walk.
//! 4. An empty / refused response on a tier falls through.
//! 5. The per-tier outcome metric ticks on every dispatch.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};

use sbproxy_ai::ai_metrics::cascade_tier_outcome_value;
use sbproxy_ai::client::AiClient;
use sbproxy_ai::handler::AiHandlerConfig;
use sbproxy_ai::routing::{CascadeConfig, CascadeTier};

/// Spawn a one-shot mock that accepts a single connection and
/// replies with `body` framed as an HTTP/1.1 response. The
/// listener stays alive for the duration of the test via the
/// returned `SocketAddr` (which captures the bind side) so each
/// request reaches its own pre-staged mock.
fn one_shot_json(body: &str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let owned = body.to_string();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            // Drain the request line + headers so the client side
            // reads its response cleanly. We do not care what the
            // request looks like for these tests.
            let _ = stream.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                owned.len(),
                owned
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.shutdown(std::net::Shutdown::Write);
        }
    });
    addr
}

/// Build a minimal handler config JSON with one provider per
/// `(name, addr)` pair. We round-trip through serde_json so the
/// integration test does not have to enumerate every field of
/// `AiHandlerConfig` (some fields are `pub(crate)` and not
/// constructible from outside the crate).
fn handler_config(providers: &[(&str, SocketAddr)]) -> AiHandlerConfig {
    let providers_json: Vec<serde_json::Value> = providers
        .iter()
        .map(|(name, addr)| {
            serde_json::json!({
                "name": name,
                "provider_type": "openai",
                "api_key": "test-key",
                "base_url": format!("http://{addr}"),
                // The mock listens on a loopback address; opt in so the
                // WOR-603 base_url SSRF guard does not reject it.
                "allow_private_base_url": true,
            })
        })
        .collect();
    let cfg = serde_json::json!({
        "providers": providers_json,
        "routing": "round_robin",
    });
    AiHandlerConfig::from_config(cfg).expect("handler config from json")
}

fn chat_body(prompt: &str) -> serde_json::Value {
    serde_json::json!({
        "model": "ignored-set-by-tier",
        "messages": [{"role": "user", "content": prompt}]
    })
}

/// Minimal OpenAI Chat response shape with an optional
/// `confidence_score` field. Cascade inspects the top-level field;
/// other paths in the body are kept realistic so future scorers
/// can rely on the same fixture shape.
fn chat_response(content: &str, score: Option<f32>) -> String {
    let mut v = serde_json::json!({
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    });
    if let Some(s) = score {
        v.as_object_mut()
            .unwrap()
            .insert("confidence_score".to_string(), serde_json::json!(s));
    }
    serde_json::to_string(&v).unwrap()
}

#[tokio::test]
async fn cascade_below_threshold_falls_through_to_next_tier() {
    // Tier 1 emits a low-confidence response; tier 2 emits a high-
    // confidence one. The cascade must skip tier 1 and return tier
    // 2's body.
    let addr1 = one_shot_json(&chat_response("rough answer", Some(0.4)));
    let addr2 = one_shot_json(&chat_response("polished answer", Some(0.95)));
    let cfg = handler_config(&[("cheap", addr1), ("smart", addr2)]);
    let cascade = CascadeConfig {
        tiers: vec![
            CascadeTier {
                provider_id: "cheap".to_string(),
                model: "cheap-model".to_string(),
                quality_threshold: 0.8,
                cost_cap: None,
            },
            CascadeTier {
                provider_id: "smart".to_string(),
                model: "smart-model".to_string(),
                quality_threshold: 0.8,
                cost_cap: None,
            },
        ],
        max_total_cost: None,
    };

    let client = AiClient::new();
    let out = client
        .forward_cascade(
            &cfg,
            &cascade,
            "/v1/chat/completions",
            &chat_body("hi"),
            &sbproxy_ai::attribution::AttributionTags::default(),
            "chat_completions",
        )
        .await
        .expect("cascade dispatch");

    assert!(out.accepted, "tier 2 should have accepted");
    assert_eq!(out.tier_index, 1);
    assert_eq!(out.provider_name, "smart");
    assert_eq!(out.model, "smart-model");
    let body: serde_json::Value = serde_json::from_slice(&out.body).expect("json");
    assert_eq!(
        body["choices"][0]["message"]["content"].as_str().unwrap(),
        "polished answer"
    );
}

#[tokio::test]
async fn cascade_above_threshold_short_circuits() {
    // Tier 1 already meets the threshold; tier 2 must not be
    // contacted. Pointing tier 2 at a closed port asserts the
    // short-circuit: if the cascade dialled tier 2 the request
    // would error out.
    let addr1 = one_shot_json(&chat_response("great answer", Some(0.99)));
    // Bind + immediately drop so the address is closed.
    let closed = {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        let a = l.local_addr().expect("local_addr");
        drop(l);
        a
    };

    let cfg = handler_config(&[("cheap", addr1), ("smart", closed)]);
    let cascade = CascadeConfig {
        tiers: vec![
            CascadeTier {
                provider_id: "cheap".to_string(),
                model: "cheap-model".to_string(),
                quality_threshold: 0.8,
                cost_cap: None,
            },
            CascadeTier {
                provider_id: "smart".to_string(),
                model: "smart-model".to_string(),
                quality_threshold: 0.8,
                cost_cap: None,
            },
        ],
        max_total_cost: None,
    };

    let client = AiClient::new();
    let before = cascade_tier_outcome_value(0, "accepted");
    let out = client
        .forward_cascade(
            &cfg,
            &cascade,
            "/v1/chat/completions",
            &chat_body("hi"),
            &sbproxy_ai::attribution::AttributionTags::default(),
            "chat_completions",
        )
        .await
        .expect("cascade dispatch");

    assert!(out.accepted);
    assert_eq!(out.tier_index, 0);
    assert_eq!(out.provider_name, "cheap");
    let after = cascade_tier_outcome_value(0, "accepted");
    assert!(after > before, "tier 0 accepted counter should have ticked");
}

#[tokio::test]
async fn cascade_cost_cap_stops_retry_mid_cascade() {
    // Tier 1 fails the threshold; tier 2's projected cost would
    // exceed `max_total_cost`. The cascade must record a cost_cap
    // outcome for tier 2 and return tier 1's (sub-threshold) body
    // as the best available answer.
    let addr1 = one_shot_json(&chat_response("rough", Some(0.2)));
    let addr2 = one_shot_json(&chat_response("never reached", Some(0.99)));
    let cfg = handler_config(&[("cheap", addr1), ("expensive", addr2)]);
    // Cap chosen between the projected per-call costs of the two
    // tiers so tier 0 (gpt-4o-mini, roughly 384 micro-USD per
    // 512+512 call) dispatches but the cumulative cost of tier 1
    // (gpt-4o, roughly 6400 micro-USD per 512+512 call) trips the
    // cap. The numbers come from
    // `sbproxy_ai::budget::estimate_cost`.
    let cascade = CascadeConfig {
        tiers: vec![
            CascadeTier {
                provider_id: "cheap".to_string(),
                model: "gpt-4o-mini".to_string(),
                quality_threshold: 0.8,
                cost_cap: None,
            },
            CascadeTier {
                provider_id: "expensive".to_string(),
                model: "gpt-4o".to_string(),
                quality_threshold: 0.8,
                cost_cap: None,
            },
        ],
        max_total_cost: Some(500),
    };

    let client = AiClient::new();
    let before_cost_cap = cascade_tier_outcome_value(1, "cost_cap");
    let out = client
        .forward_cascade(
            &cfg,
            &cascade,
            "/v1/chat/completions",
            &chat_body("hi"),
            &sbproxy_ai::attribution::AttributionTags::default(),
            "chat_completions",
        )
        .await
        .expect("cascade dispatch");

    // Tier 0 ran and produced a sub-threshold response (the body
    // we return). Tier 1 was skipped by the cost cap.
    assert!(!out.accepted, "no tier should have accepted");
    assert_eq!(out.tier_index, 0);
    let after_cost_cap = cascade_tier_outcome_value(1, "cost_cap");
    assert!(
        after_cost_cap > before_cost_cap,
        "tier 1 cost_cap counter should have ticked"
    );
}

#[tokio::test]
async fn cascade_empty_response_falls_through() {
    // Tier 1 emits an empty `content`; cascade must treat the
    // response as a refusal and advance to tier 2 even though
    // tier 1 carried no `confidence_score` (which would otherwise
    // default to `1.0`).
    let addr1 = one_shot_json(&chat_response("", None));
    let addr2 = one_shot_json(&chat_response("real answer", Some(0.95)));
    let cfg = handler_config(&[("cheap", addr1), ("smart", addr2)]);
    let cascade = CascadeConfig {
        tiers: vec![
            CascadeTier {
                provider_id: "cheap".to_string(),
                model: "cheap-model".to_string(),
                quality_threshold: 0.5,
                cost_cap: None,
            },
            CascadeTier {
                provider_id: "smart".to_string(),
                model: "smart-model".to_string(),
                quality_threshold: 0.5,
                cost_cap: None,
            },
        ],
        max_total_cost: None,
    };

    let client = AiClient::new();
    let out = client
        .forward_cascade(
            &cfg,
            &cascade,
            "/v1/chat/completions",
            &chat_body("hi"),
            &sbproxy_ai::attribution::AttributionTags::default(),
            "chat_completions",
        )
        .await
        .expect("cascade dispatch");
    assert!(out.accepted);
    assert_eq!(out.tier_index, 1);
    assert_eq!(out.provider_name, "smart");
}

#[tokio::test]
async fn cascade_metric_increments_per_tier_outcome() {
    // Mirrors the below-threshold test but asserts the metric
    // counters tick for both tiers: `retry` on tier 0, `accepted`
    // on tier 1.
    let addr1 = one_shot_json(&chat_response("low", Some(0.3)));
    let addr2 = one_shot_json(&chat_response("high", Some(0.9)));
    let cfg = handler_config(&[("cheap-m", addr1), ("smart-m", addr2)]);
    let cascade = CascadeConfig {
        tiers: vec![
            CascadeTier {
                provider_id: "cheap-m".to_string(),
                model: "cheap-model".to_string(),
                quality_threshold: 0.7,
                cost_cap: None,
            },
            CascadeTier {
                provider_id: "smart-m".to_string(),
                model: "smart-model".to_string(),
                quality_threshold: 0.7,
                cost_cap: None,
            },
        ],
        max_total_cost: None,
    };
    let before_retry = cascade_tier_outcome_value(0, "retry");
    let before_accept = cascade_tier_outcome_value(1, "accepted");

    let client = AiClient::new();
    let out = client
        .forward_cascade(
            &cfg,
            &cascade,
            "/v1/chat/completions",
            &chat_body("hi"),
            &sbproxy_ai::attribution::AttributionTags::default(),
            "chat_completions",
        )
        .await
        .expect("cascade dispatch");
    assert!(out.accepted);

    let after_retry = cascade_tier_outcome_value(0, "retry");
    let after_accept = cascade_tier_outcome_value(1, "accepted");
    assert!(after_retry > before_retry, "tier 0 retry should tick");
    assert!(after_accept > before_accept, "tier 1 accepted should tick");
}

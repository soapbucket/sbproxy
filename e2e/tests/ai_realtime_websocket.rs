//! Acceptance coverage for AI Realtime WebSocket admission and credentials.
//!
//! These tests exercise the real HTTP/1.1 upgrade path. The capture server
//! records only completed upstream WebSocket handshakes, so a failed admission
//! assertion is deliberately "no upstream 101/upgrade", not "no TCP connect":
//! Pingora may connect to the selected peer before a later request filter
//! returns an HTTP error.

mod websocket_common;

use std::path::Path;
use std::time::Duration;

use reqwest::Method;
use sbproxy_e2e::ProxyHarness;
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Error as WebSocketError;

use websocket_common::{
    assert_clean_close, assert_text_echo, dial_websocket, spawn_echo_ws_server, CapturedUpgrade,
};

const REALTIME_HOST: &str = "ai-realtime.localhost";
const ORIGINAL_MODEL: &str = "gpt-realtime";
const DOWNGRADE_MODEL: &str = "gpt-4o-mini";

const LUA_CREDENTIAL_MODIFIER: &str = r#"    request_modifiers:
      - lua_script: |
          function modify_request(req, ctx)
            return {
              set_headers = {
                ["Authorization"] = "Bearer lua-secret",
                ["x-api-key"] = "lua-api-key"
              }
            }
          end
    outbound_credential:
      type: vault_secret
      secret: "origin-secret"
      header: "x-origin-secret"
      scheme: ""
"#;

fn realtime_config(
    upstream_http_url: &str,
    provider_api_key: &str,
    proxy_fields: &str,
    budget: &str,
    origin_fields: &str,
) -> String {
    let provider_api_key = serde_json::to_string(provider_api_key).expect("quote provider key");
    format!(
        r#"
proxy:
  http_bind_port: 0
{proxy_fields}origins:
  "{REALTIME_HOST}":
    action:
      type: ai_proxy
      providers:
        - name: openai
          provider_type: openai
          accept_native_credentials_for: openai
          api_key: {provider_api_key}
          base_url: "{upstream_http_url}"
          allow_private_base_url: true
          default_model: {ORIGINAL_MODEL}
          models: [{ORIGINAL_MODEL}, {DOWNGRADE_MODEL}]
      routing:
        strategy: round_robin
{budget}{origin_fields}"#
    )
}

fn key_management_fields(admin_port: u16, store_path: &Path) -> String {
    let store_path = serde_json::to_string(&store_path.display().to_string())
        .expect("quote embedded store path");
    format!(
        r#"  admin:
    enabled: true
    port: {admin_port}
    username: admin
    password: secret
  key_management:
    enabled: true
    store:
      backend: embedded
      path: {store_path}
    crypto:
      pepper: realtime-e2e-pepper
      master_key: realtime-e2e-master
    inbound:
      headers:
        - name: x-sb-api
          scheme: ""
      require: true
"#
    )
}

fn native_key_management_fields(store_path: &Path, policy_fields: &str) -> String {
    let store_path = serde_json::to_string(&store_path.display().to_string())
        .expect("quote embedded store path");
    format!(
        r#"  key_management:
    enabled: true
    store:
      backend: embedded
      path: {store_path}
    crypto:
      pepper: realtime-native-e2e-pepper
      master_key: realtime-native-e2e-master
    inbound:
      require: false
      provider_hints:
        - provider: openai
          header: authorization
          scheme: "Bearer "
          value_prefix: "sk-"
        - provider: openai
          header: x-native-provider-credential
          value_prefix: "opaque-"
      native_key_policy:
        allowed_providers: [openai]
{policy_fields}"#
    )
}

fn pick_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("ephemeral admin listener")
        .local_addr()
        .expect("admin listener address")
        .port()
}

async fn admin_json(
    admin_port: u16,
    method: Method,
    path: &str,
    body: Value,
    expected_status: u16,
) -> Value {
    let response = reqwest::Client::new()
        .request(method, format!("http://127.0.0.1:{admin_port}{path}"))
        .basic_auth("admin", Some("secret"))
        .json(&body)
        .send()
        .await
        .expect("admin request");
    let status = response.status().as_u16();
    let text = response.text().await.unwrap_or_default();
    assert_eq!(status, expected_status, "admin {path}: {text}");
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("admin {path} response must be JSON: {error}: {text}"))
}

struct MintedKey {
    id: String,
    token: String,
}

async fn mint_key(admin_port: u16, body: Value) -> MintedKey {
    let response = admin_json(admin_port, Method::POST, "/admin/keys", body, 201).await;
    MintedKey {
        id: response["key"]["key_id"]
            .as_str()
            .expect("mint response key id")
            .to_string(),
        token: response["token"]
            .as_str()
            .expect("mint response token")
            .to_string(),
    }
}

fn assert_handshake_status(error: WebSocketError, expected: u16) {
    match error {
        WebSocketError::Http(response) => assert_eq!(
            response.status().as_u16(),
            expected,
            "unexpected failed-upgrade response: {response:?}"
        ),
        other => panic!("expected an HTTP {expected} handshake error, got {other:?}"),
    }
}

fn one_capture(captures: &[CapturedUpgrade]) -> &CapturedUpgrade {
    assert_eq!(
        captures.len(),
        1,
        "exactly one upstream WebSocket upgrade was expected: {captures:?}"
    );
    &captures[0]
}

#[test]
fn provider_auth_replaces_caller_and_lua_credentials_while_frames_relay() {
    let runtime = tokio::runtime::Runtime::new().expect("Tokio runtime");
    runtime.block_on(async {
        let upstream = spawn_echo_ws_server().await;
        let config = realtime_config(
            upstream.http_url(),
            "provider-secret",
            "",
            "",
            LUA_CREDENTIAL_MODIFIER,
        );
        let harness = ProxyHarness::start_with_yaml(&config).expect("start realtime proxy");

        let (mut websocket, response) = dial_websocket(
            &harness,
            REALTIME_HOST,
            "/v1/realtime?model=gpt-realtime",
            &[
                ("authorization", "Bearer caller-secret"),
                ("proxy-authorization", "Basic caller-proxy-secret"),
                ("dpop", "caller-proof"),
                ("x-api-key", "caller-api-key"),
                ("api-key", "caller-azure-key"),
                ("x-goog-api-key", "caller-google-key"),
                ("x-sb-api", "caller-sidecar-key"),
                ("openai-beta", "realtime=v1"),
            ],
        )
        .await
        .expect("realtime upgrade");
        assert_eq!(response.status().as_u16(), 101);
        assert_text_echo(&mut websocket, "provider-auth-echo").await;

        let captures = upstream.captured();
        let capture = one_capture(&captures);
        assert_eq!(
            capture.header_values("authorization"),
            ["Bearer provider-secret"],
            "the selected provider credential must replace caller and Lua values"
        );
        for name in [
            "proxy-authorization",
            "dpop",
            "x-api-key",
            "api-key",
            "x-goog-api-key",
            "x-sb-api",
            "x-origin-secret",
        ] {
            assert!(
                capture.header_values(name).is_empty(),
                "{name} must be scrubbed: {capture:?}"
            );
        }
        assert_eq!(capture.header("openai-beta"), Some("realtime=v1"));
        assert_eq!(capture.header("upgrade"), Some("websocket"));
        assert!(
            capture.header("sec-websocket-key").is_some(),
            "WebSocket handshake metadata must survive"
        );

        assert_clean_close(&mut websocket).await;
    });
}

#[test]
fn bound_custom_header_credential_wins_over_provider_auth() {
    let runtime = tokio::runtime::Runtime::new().expect("Tokio runtime");
    runtime.block_on(async {
        let upstream = spawn_echo_ws_server().await;
        let temp = tempfile::tempdir().expect("key store tempdir");
        let admin_port = pick_port();
        let proxy_fields = key_management_fields(admin_port, &temp.path().join("keys.redb"));
        let config = realtime_config(
            upstream.http_url(),
            "provider-secret",
            &proxy_fields,
            "",
            "",
        );
        let harness =
            ProxyHarness::start_with_yaml(&config).expect("start governed realtime proxy");
        ProxyHarness::wait_for_port(admin_port, Duration::from_secs(5))
            .expect("admin listener ready");

        admin_json(
            admin_port,
            Method::POST,
            "/admin/credentials",
            json!({
                "id": "realtime-bound",
                "secret": "bound-secret",
                "header": "x-realtime-auth",
                "scheme": "Token "
            }),
            201,
        )
        .await;
        let key = mint_key(
            admin_port,
            json!({"name": "bound-realtime", "credential_id": "realtime-bound"}),
        )
        .await;

        let (mut websocket, response) = dial_websocket(
            &harness,
            REALTIME_HOST,
            "/v1/realtime?model=gpt-realtime",
            &[
                ("x-sb-api", key.token.as_str()),
                ("authorization", "Bearer caller-secret"),
                ("x-realtime-auth", "Token caller-secret"),
            ],
        )
        .await
        .expect("bound realtime upgrade");
        assert_eq!(response.status().as_u16(), 101);
        assert_text_echo(&mut websocket, "bound-auth-echo").await;

        let captures = upstream.captured();
        let capture = one_capture(&captures);
        assert_eq!(
            capture.header_values("x-realtime-auth"),
            ["Token bound-secret"],
            "the bound custom-header credential must be authoritative"
        );
        assert!(
            capture.header_values("authorization").is_empty(),
            "provider and caller Authorization must not coexist with the bound credential"
        );
        assert!(
            capture.header_values("x-sb-api").is_empty(),
            "the governed inbound token must not reach the provider"
        );

        assert_clean_close(&mut websocket).await;
    });
}

#[test]
fn missing_trusted_credential_returns_503_without_upstream_upgrade() {
    let runtime = tokio::runtime::Runtime::new().expect("Tokio runtime");
    runtime.block_on(async {
        let upstream = spawn_echo_ws_server().await;
        let config = realtime_config(upstream.http_url(), "   ", "", "", "");
        let harness = ProxyHarness::start_with_yaml(&config).expect("start realtime proxy");

        let error = match dial_websocket(
            &harness,
            REALTIME_HOST,
            "/v1/realtime?model=gpt-realtime",
            &[("authorization", "Bearer caller-secret")],
        )
        .await
        {
            Ok(_) => panic!("missing trusted credential must not upgrade"),
            Err(error) => error,
        };
        assert_handshake_status(error, 503);
        assert!(
            upstream.captured().is_empty(),
            "the upstream may receive TCP, but it must not receive a WebSocket upgrade"
        );
    });
}

#[test]
fn realtime_budget_block_log_and_downgrade_are_enforced_before_upgrade() {
    let runtime = tokio::runtime::Runtime::new().expect("Tokio runtime");
    runtime.block_on(async {
        let upstream = spawn_echo_ws_server().await;

        let block_budget = r#"      budget:
        on_exceed: block
        limits:
          - scope: workspace
            max_tokens: 0
"#;
        let block_config =
            realtime_config(upstream.http_url(), "provider-secret", "", block_budget, "");
        let block_harness =
            ProxyHarness::start_with_yaml(&block_config).expect("start block proxy");
        let error = match dial_websocket(
            &block_harness,
            REALTIME_HOST,
            "/v1/realtime?model=gpt-realtime",
            &[],
        )
        .await
        {
            Ok(_) => panic!("block budget must not upgrade"),
            Err(error) => error,
        };
        assert_handshake_status(error, 402);
        assert!(
            upstream.captured().is_empty(),
            "budget block must not complete an upstream upgrade"
        );
        drop(block_harness);

        let log_budget = r#"      budget:
        on_exceed: log
        limits:
          - scope: workspace
            max_tokens: 0
"#;
        let log_config =
            realtime_config(upstream.http_url(), "provider-secret", "", log_budget, "");
        let log_harness = ProxyHarness::start_with_yaml(&log_config).expect("start log proxy");
        let (mut log_websocket, response) = dial_websocket(
            &log_harness,
            REALTIME_HOST,
            "/v1/realtime?model=gpt-realtime",
            &[],
        )
        .await
        .expect("log budget upgrades");
        assert_eq!(response.status().as_u16(), 101);
        assert_text_echo(&mut log_websocket, "log-budget-echo").await;
        assert_clean_close(&mut log_websocket).await;
        assert_eq!(
            upstream.captured().len(),
            1,
            "log mode must complete one upstream upgrade"
        );
        drop(log_harness);

        let downgrade_budget = format!(
            r#"      budget:
        on_exceed: downgrade
        limits:
          - scope: workspace
            max_tokens: 0
            downgrade_to: {DOWNGRADE_MODEL}
"#
        );
        let downgrade_config = realtime_config(
            upstream.http_url(),
            "provider-secret",
            "",
            &downgrade_budget,
            "",
        );
        let downgrade_harness =
            ProxyHarness::start_with_yaml(&downgrade_config).expect("start downgrade proxy");
        let (mut downgrade_websocket, response) = dial_websocket(
            &downgrade_harness,
            REALTIME_HOST,
            "/v1/realtime?voice=alloy&model=gpt-realtime&temperature=0.5&model=ignored",
            &[],
        )
        .await
        .expect("downgrade budget upgrades");
        assert_eq!(response.status().as_u16(), 101);
        assert_text_echo(&mut downgrade_websocket, "downgrade-budget-echo").await;

        let captures = upstream.captured();
        assert_eq!(captures.len(), 2, "log and downgrade must both upgrade");
        let capture = captures.last().expect("downgrade capture");
        let absolute_uri =
            if capture.uri.starts_with("http://") || capture.uri.starts_with("https://") {
                capture.uri.clone()
            } else {
                format!("http://provider.test{}", capture.uri)
            };
        let parsed = reqwest::Url::parse(&absolute_uri).expect("captured realtime URI");
        let query: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
        let models: Vec<&str> = query
            .iter()
            .filter_map(|(name, value)| (name == "model").then_some(value.as_str()))
            .collect();
        assert_eq!(
            models,
            [DOWNGRADE_MODEL],
            "downgrade must leave one authoritative model query"
        );
        assert!(
            query
                .iter()
                .any(|(name, value)| name == "voice" && value == "alloy"),
            "unrelated voice query must survive: {query:?}"
        );
        assert!(
            query
                .iter()
                .any(|(name, value)| name == "temperature" && value == "0.5"),
            "unrelated temperature query must survive: {query:?}"
        );

        assert_clean_close(&mut downgrade_websocket).await;
    });
}

#[test]
fn native_realtime_custom_carrier_becomes_the_only_upstream_credential() {
    let runtime = tokio::runtime::Runtime::new().expect("Tokio runtime");
    runtime.block_on(async {
        let upstream = spawn_echo_ws_server().await;
        let temp = tempfile::tempdir().expect("native key store tempdir");
        let proxy_fields = native_key_management_fields(&temp.path().join("keys.redb"), "");
        let config = realtime_config(
            upstream.http_url(),
            "operator-secret-must-not-be-used",
            &proxy_fields,
            "",
            "",
        );
        let harness = ProxyHarness::start_with_yaml(&config).expect("start native realtime proxy");
        let canary = "opaque-caller-native-canary";

        let (mut websocket, response) = dial_websocket(
            &harness,
            REALTIME_HOST,
            "/v1/realtime?model=gpt-realtime",
            &[
                (
                    "authorization",
                    "Bearer caller-controlled-non-provider-value",
                ),
                ("x-native-provider-credential", canary),
                ("x-api-key", "competing-caller-key"),
            ],
        )
        .await
        .expect("native realtime upgrade");
        assert_eq!(response.status().as_u16(), 101);
        assert_text_echo(&mut websocket, "native-auth-echo").await;

        let captures = upstream.captured();
        let capture = one_capture(&captures);
        let expected = format!("Bearer {canary}");
        assert_eq!(
            capture.header_values("authorization"),
            [expected.as_str()],
            "the caller-owned native credential must be authoritative"
        );
        assert!(
            capture
                .header_values("x-native-provider-credential")
                .is_empty(),
            "the original custom carrier must be scrubbed"
        );
        assert!(capture.header_values("x-api-key").is_empty());
        assert!(
            !format!("{capture:?}").contains("operator-secret-must-not-be-used"),
            "operator and caller credentials must not coexist"
        );

        assert_clean_close(&mut websocket).await;
    });
}

#[test]
fn native_realtime_fails_closed_for_required_model_and_pii_policy() {
    let runtime = tokio::runtime::Runtime::new().expect("Tokio runtime");
    runtime.block_on(async {
        let upstream = spawn_echo_ws_server().await;
        let model_temp = tempfile::tempdir().expect("model key store tempdir");
        let model_proxy_fields = native_key_management_fields(
            &model_temp.path().join("keys.redb"),
            "        allowed_models: [gpt-realtime]\n",
        );
        let model_config = realtime_config(
            upstream.http_url(),
            "operator-secret",
            &model_proxy_fields,
            "",
            "",
        );
        let model_harness =
            ProxyHarness::start_with_yaml(&model_config).expect("start model policy proxy");
        for path in ["/v1/realtime?model=gpt-denied", "/v1/realtime"] {
            let error = match dial_websocket(
                &model_harness,
                REALTIME_HOST,
                path,
                &[(
                    "authorization",
                    "Bearer sk-proj-realtime-model-policy-0123456789",
                )],
            )
            .await
            {
                Ok(_) => panic!("required realtime model policy must refuse this upgrade"),
                Err(error) => error,
            };
            assert_handshake_status(error, 403);
        }
        assert!(
            upstream.captured().is_empty(),
            "model-policy denials must not complete an upstream upgrade"
        );
        drop(model_harness);

        let pii_temp = tempfile::tempdir().expect("PII key store tempdir");
        let pii_proxy_fields = native_key_management_fields(
            &pii_temp.path().join("keys.redb"),
            "        require_pii_redaction: [email]\n",
        );
        let pii_config = realtime_config(
            upstream.http_url(),
            "operator-secret",
            &pii_proxy_fields,
            r#"      pii:
        enabled: true
        defaults: true
        redact_request: true
"#,
            "",
        );
        let pii_harness =
            ProxyHarness::start_with_yaml(&pii_config).expect("start PII policy proxy");
        let error = match dial_websocket(
            &pii_harness,
            REALTIME_HOST,
            "/v1/realtime?model=gpt-realtime",
            &[(
                "authorization",
                "Bearer sk-proj-realtime-pii-policy-0123456789",
            )],
        )
        .await
        {
            Ok(_) => panic!("required realtime PII policy must refuse the upgrade"),
            Err(error) => error,
        };
        assert_handshake_status(error, 403);
        assert!(
            upstream.captured().is_empty(),
            "PII-policy denial must not complete an upstream upgrade"
        );
    });
}

#[test]
fn accepted_socket_continues_echo_and_close_after_policy_blocks_new_upgrades() {
    let runtime = tokio::runtime::Runtime::new().expect("Tokio runtime");
    runtime.block_on(async {
        let upstream = spawn_echo_ws_server().await;
        let temp = tempfile::tempdir().expect("key store tempdir");
        let admin_port = pick_port();
        let proxy_fields = key_management_fields(admin_port, &temp.path().join("keys.redb"));
        let config = realtime_config(
            upstream.http_url(),
            "provider-secret",
            &proxy_fields,
            "",
            "",
        );
        let harness =
            ProxyHarness::start_with_yaml(&config).expect("start governed realtime proxy");
        ProxyHarness::wait_for_port(admin_port, Duration::from_secs(5))
            .expect("admin listener ready");
        let key = mint_key(admin_port, json!({"name": "draining-realtime"})).await;

        let (mut accepted, response) = dial_websocket(
            &harness,
            REALTIME_HOST,
            "/v1/realtime?model=gpt-realtime",
            &[("x-sb-api", key.token.as_str())],
        )
        .await
        .expect("initial governed upgrade");
        assert_eq!(response.status().as_u16(), 101);
        assert_eq!(upstream.captured().len(), 1);

        admin_json(
            admin_port,
            Method::PATCH,
            &format!("/admin/keys/{}", key.id),
            json!({"expected_revision": 1, "max_budget_tokens": 0}),
            200,
        )
        .await;

        let error = match dial_websocket(
            &harness,
            REALTIME_HOST,
            "/v1/realtime?model=gpt-realtime",
            &[("x-sb-api", key.token.as_str())],
        )
        .await
        {
            Ok(_) => panic!("patched zero-token policy must block new upgrades"),
            Err(error) => error,
        };
        assert_handshake_status(error, 402);
        assert_eq!(
            upstream.captured().len(),
            1,
            "the blocked request must not complete a second upstream upgrade"
        );

        assert_text_echo(&mut accepted, "already-accepted-session").await;
        assert_clean_close(&mut accepted).await;
    });
}

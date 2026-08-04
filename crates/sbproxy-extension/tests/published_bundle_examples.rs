//! Executable contract for the published extension bundle example.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use http::{Request, StatusCode};
use sbproxy_config::{BundleManifest, ExtensionBundlesConfig};
use sbproxy_extension::bundle::{
    build_javascript_action, build_javascript_policy, build_javascript_transform,
    build_proxy_wasm_filter, build_wasm_action, AiExtensionChain, BundleRegistry,
    DynamicBundleRegistry, PaymentExtensionChain,
};
use sbproxy_plugin::{
    ActionHandler, ActionOutcome, AiExtensionDecision, AiExtensionEvent, AiExtensionEventPayload,
    AiExtensionMessage, AiExtensionRole, AiExtensionStreamChunk, AiExtensionToolCall,
    ExtensionHookKind, ExtensionRuntime, PaymentExtensionDecision, PaymentExtensionEvent,
    PaymentExtensionOutcome, PaymentExtensionPhase, PolicyDecision, PolicyEnforcer,
    TransformContext, TransformHandler, AI_EXTENSION_EVENT_SCHEMA_VERSION,
};
use sha2::{Digest, Sha256};

fn example_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("extension crate should have a crates directory")
        .parent()
        .expect("crates directory should have a workspace root")
        .join("examples/extension-bundles")
}

fn load_registry() -> Arc<DynamicBundleRegistry> {
    let root = example_root();
    let yaml = std::fs::read_to_string(root.join("sb.yml"))
        .expect("the published extension bundle config should be readable");
    let compiled = sbproxy_config::compile_config(&yaml)
        .expect("the published extension bundle config should compile");
    DynamicBundleRegistry::load(&compiled.extension_bundles, &root, &BTreeSet::new())
        .expect("every published extension bundle should load")
}

fn bundle_directories(root: &Path) -> Vec<PathBuf> {
    let mut directories = std::fs::read_dir(root.join("bundles"))
        .expect("the published bundles directory should be readable")
        .map(|entry| {
            entry
                .expect("bundle directory entry should be readable")
                .path()
        })
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    directories.sort();
    directories
}

fn ai_event(sequence: u64, payload: AiExtensionEventPayload) -> AiExtensionEvent {
    AiExtensionEvent {
        schema_version: AI_EXTENSION_EVENT_SCHEMA_VERSION,
        sequence,
        request_id: Some("worked-example-request".to_owned()),
        model: Some("worked-example-model".to_owned()),
        payload,
    }
}

#[test]
fn published_bundle_manifests_pin_the_exact_entry_digest_and_load() {
    let root = example_root();
    let directories = bundle_directories(&root);
    assert_eq!(
        directories.len(),
        6,
        "the worked example should cover six bundles"
    );

    for directory in directories {
        let bytes = std::fs::read(directory.join("bundle.yaml"))
            .expect("the bundle manifest should be readable");
        let manifest = BundleManifest::parse_yaml(&bytes)
            .expect("the published bundle manifest should validate");
        let artifact = std::fs::read(directory.join(&manifest.entry))
            .expect("the declared entry artifact should be readable");
        let actual = hex::encode(Sha256::digest(&artifact));
        assert_eq!(
            manifest.sha256.as_deref(),
            Some(actual.as_str()),
            "{} must pin the exact entry bytes",
            manifest.name
        );
    }

    let registry = load_registry();
    let inventory = registry.inventory();
    assert_eq!(inventory.summary.bundles, 6);
    assert_eq!(inventory.summary.hooks, 11);
    assert!(inventory
        .bundles
        .iter()
        .any(|bundle| bundle.runtime == ExtensionRuntime::Javascript));
    assert!(inventory
        .bundles
        .iter()
        .any(|bundle| bundle.runtime == ExtensionRuntime::Wasm));
    assert!(inventory
        .bundles
        .iter()
        .any(|bundle| bundle.runtime == ExtensionRuntime::ProxyWasm));
    assert!(inventory
        .hooks
        .iter()
        .any(|hook| hook.kind == ExtensionHookKind::Payment));
    assert!(inventory
        .hooks
        .iter()
        .any(|hook| hook.kind == ExtensionHookKind::Transform));
    assert!(inventory
        .hooks
        .iter()
        .any(|hook| hook.kind == ExtensionHookKind::AiStreamEvent));
    assert!(inventory
        .hooks
        .iter()
        .any(|hook| hook.kind == ExtensionHookKind::ProxyWasmFilter));
}

#[tokio::test]
async fn published_javascript_typescript_and_envelope_wasm_hooks_execute() {
    let registry = load_registry();

    let javascript = registry
        .action("hello_javascript")
        .expect("the JavaScript action should be registered");
    let javascript = build_javascript_action(
        javascript,
        serde_json::json!({"response_header": "x-extension-runtime"}),
    )
    .expect("the JavaScript action should initialize");
    let mut request = Request::builder()
        .uri("https://extension.local/javascript")
        .body(Bytes::new())
        .unwrap();
    let outcome = javascript.handle(&mut request, &mut ()).await.unwrap();
    match outcome {
        ActionOutcome::Response {
            status,
            headers,
            body,
        } => {
            assert_eq!(status, StatusCode::OK.as_u16());
            assert!(headers
                .iter()
                .any(|(name, value)| { name == "x-extension-runtime" && value == "javascript" }));
            assert_eq!(body, Bytes::from_static(b"hello from JavaScript\n"));
        }
        ActionOutcome::Proxy | ActionOutcome::Responded => {
            panic!("the worked action should return its response envelope")
        }
    }

    let transform = registry
        .transform("example_javascript_transform")
        .expect("the JavaScript transform should be registered");
    let transform = build_javascript_transform(transform, serde_json::json!({}))
        .expect("the JavaScript transform should initialize");
    let mut body = BytesMut::from(&b"hello from JavaScript\n"[..]);
    transform
        .apply(
            &mut body,
            Some("text/plain; charset=utf-8"),
            &TransformContext::new("javascript.extension.local"),
        )
        .await
        .unwrap();
    assert_eq!(&body[..], b"hello from a JavaScript transform\n");

    let typescript = registry
        .policy("require_example_header")
        .expect("the TypeScript policy should be registered");
    let typescript = build_javascript_policy(
        typescript,
        serde_json::json!({"header_name": "x-extension-example"}),
    )
    .expect("the load-time-transpiled TypeScript policy should initialize");
    let missing = Request::builder()
        .uri("https://extension.local/typescript")
        .body(Bytes::new())
        .unwrap();
    assert_eq!(
        typescript.enforce(&missing, &mut ()).await.unwrap(),
        PolicyDecision::Deny {
            status: 403,
            message: "missing x-extension-example".to_owned(),
        }
    );
    let present = Request::builder()
        .uri("https://extension.local/typescript")
        .header("x-extension-example", "present")
        .body(Bytes::new())
        .unwrap();
    assert_eq!(
        typescript.enforce(&present, &mut ()).await.unwrap(),
        PolicyDecision::Allow
    );

    let wasm = registry
        .action("queued_envelope")
        .expect("the envelope WASM action should be registered");
    let wasm = build_wasm_action(wasm, serde_json::json!({}))
        .expect("the envelope WASM action should initialize");
    let mut request = Request::builder()
        .uri("https://extension.local/wasm")
        .body(Bytes::new())
        .unwrap();
    let outcome = wasm.handle(&mut request, &mut ()).await.unwrap();
    match outcome {
        ActionOutcome::Response { status, body, .. } => {
            assert_eq!(status, StatusCode::ACCEPTED.as_u16());
            assert_eq!(body, Bytes::from_static(b"queued"));
        }
        ActionOutcome::Proxy | ActionOutcome::Responded => {
            panic!("the envelope WASM action should return its response envelope")
        }
    }
}

#[tokio::test]
async fn published_ai_payment_and_proxy_wasm_hooks_execute() {
    let registry = load_registry();
    let chain = AiExtensionChain::from_registry(registry.as_ref())
        .expect("the published AI hooks should initialize");
    for kind in [
        ExtensionHookKind::AiGuardrailInput,
        ExtensionHookKind::AiGuardrailOutput,
        ExtensionHookKind::AiToolCall,
        ExtensionHookKind::AiStreamEvent,
        ExtensionHookKind::AiClose,
    ] {
        assert!(
            chain.has_kind(kind),
            "the AI event kind {kind:?} should be present"
        );
    }

    let mut session = chain.start_session();
    let events = [
        ai_event(
            1,
            AiExtensionEventPayload::GuardrailInput {
                stage: "original".to_owned(),
                messages: vec![AiExtensionMessage {
                    role: AiExtensionRole::User,
                    content: "hello".to_owned(),
                    name: None,
                    tool_call_id: None,
                }],
            },
        ),
        ai_event(
            2,
            AiExtensionEventPayload::ToolCall {
                call: AiExtensionToolCall {
                    index: 0,
                    id: Some("call-1".to_owned()),
                    name: "lookup".to_owned(),
                    arguments_json: r#"{"id":1}"#.to_owned(),
                },
            },
        ),
        ai_event(
            3,
            AiExtensionEventPayload::GuardrailOutput {
                content: "safe output".to_owned(),
            },
        ),
        ai_event(
            4,
            AiExtensionEventPayload::Stream {
                chunk: AiExtensionStreamChunk::ContentDelta {
                    index: 0,
                    text: "hello".to_owned(),
                },
            },
        ),
        ai_event(
            5,
            AiExtensionEventPayload::Stream {
                chunk: AiExtensionStreamChunk::MessageStop {
                    finish_reason: "stop".to_owned(),
                },
            },
        ),
        ai_event(
            6,
            AiExtensionEventPayload::Close {
                finish_reason: Some("stop".to_owned()),
                content_bytes: 5,
                content_delta_count: 1,
                tool_call_count: 1,
                prompt_tokens: Some(2),
                completion_tokens: Some(1),
            },
        ),
    ];
    for event in events {
        assert_eq!(
            session.dispatch(&event).await.unwrap(),
            AiExtensionDecision::Release
        );
    }
    session.finish().unwrap();

    let payments = PaymentExtensionChain::from_registry(registry.as_ref())
        .expect("the published payment hook should initialize");
    let x402 = PaymentExtensionEvent::builder(
        PaymentExtensionPhase::Verify,
        PaymentExtensionOutcome::Started,
        "x402",
        1_000_000,
        "USD",
    )
    .method("exact")
    .network("eip155:84532")
    .asset("USDC")
    .intent_id("worked-example-intent")
    .request_id("worked-example-request")
    .build()
    .unwrap();
    assert_eq!(
        payments.enforce_started(&x402).await.unwrap(),
        PaymentExtensionDecision::Continue
    );

    let http_filter = registry
        .proxy_wasm_filter("example_http_filter")
        .expect("the Proxy-Wasm HTTP filter should be registered");
    let http_filter = build_proxy_wasm_filter(http_filter, serde_json::json!({}))
        .expect("the Proxy-Wasm HTTP filter should initialize");
    let mut filter_session = http_filter.start_session().unwrap();
    let headers = filter_session
        .on_request_headers(
            vec![
                (":method".to_owned(), "GET".to_owned()),
                (":path".to_owned(), "/worked-example".to_owned()),
            ],
            false,
        )
        .unwrap();
    assert!(headers.local_response.is_none());
    let response_headers = filter_session
        .on_response_headers(
            vec![("content-type".to_owned(), "text/plain".to_owned())],
            true,
        )
        .unwrap();
    assert!(response_headers
        .headers
        .contains(&("x-extension-filter".to_owned(), "proxy-wasm".to_owned())));
    filter_session.finish().unwrap();
}

#[test]
fn published_config_uses_a_config_relative_local_bundle_directory() {
    let root = example_root();
    let yaml = std::fs::read_to_string(root.join("sb.yml")).unwrap();
    let compiled = sbproxy_config::compile_config(&yaml).unwrap();

    assert_eq!(
        compiled.extension_bundles,
        ExtensionBundlesConfig {
            bundles_dir: Some("bundles".to_owned()),
            sources: Vec::new(),
        }
    );
}

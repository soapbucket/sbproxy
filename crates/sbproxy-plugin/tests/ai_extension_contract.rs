use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use sbproxy_plugin::{
    AiExtensionDecision, AiExtensionEnforcement, AiExtensionEvent, AiExtensionEventPayload,
    AiExtensionHook, AiExtensionHookRegistration, AiExtensionMessage, AiExtensionRole,
    AiExtensionStreamChunk, AiExtensionToolCall, ExtensionHookKind, PluginResult,
    AI_EXTENSION_EVENT_SCHEMA_VERSION,
};

struct ReleaseHook;

impl AiExtensionHook for ReleaseHook {
    fn handle<'a>(
        &'a self,
        _event: &'a AiExtensionEvent,
    ) -> Pin<Box<dyn Future<Output = PluginResult<AiExtensionDecision>> + Send + 'a>> {
        Box::pin(async { Ok(AiExtensionDecision::Release) })
    }
}

#[test]
fn ai_event_contract_serializes_without_provider_wire_fields() {
    let event = AiExtensionEvent {
        schema_version: AI_EXTENSION_EVENT_SCHEMA_VERSION,
        sequence: 7,
        request_id: Some("req-safe".to_owned()),
        model: Some("model-safe".to_owned()),
        payload: AiExtensionEventPayload::GuardrailInput {
            stage: "original".to_owned(),
            messages: vec![AiExtensionMessage {
                role: AiExtensionRole::User,
                content: "hello".to_owned(),
                name: None,
                tool_call_id: None,
            }],
        },
    };

    let value = serde_json::to_value(&event).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "schema_version": 1,
            "sequence": 7,
            "request_id": "req-safe",
            "model": "model-safe",
            "event": "guardrail_input",
            "stage": "original",
            "messages": [{"role": "user", "content": "hello"}],
        })
    );
    let encoded = value.to_string().to_ascii_lowercase();
    for forbidden in [
        "authorization",
        "api_key",
        "provider_headers",
        "payment-signature",
    ] {
        assert!(!encoded.contains(forbidden));
    }
    assert_eq!(event.hook_kind(), ExtensionHookKind::AiGuardrailInput);
}

#[test]
fn stream_and_complete_tool_events_have_stable_shapes() {
    let stream = AiExtensionEvent {
        schema_version: AI_EXTENSION_EVENT_SCHEMA_VERSION,
        sequence: 8,
        request_id: None,
        model: None,
        payload: AiExtensionEventPayload::Stream {
            chunk: AiExtensionStreamChunk::ContentDelta {
                index: 2,
                text: "part".to_owned(),
            },
        },
    };
    assert_eq!(
        serde_json::to_value(&stream).unwrap(),
        serde_json::json!({
            "schema_version": 1,
            "sequence": 8,
            "event": "stream",
            "chunk": {"kind": "content_delta", "index": 2, "text": "part"},
        })
    );
    assert_eq!(stream.hook_kind(), ExtensionHookKind::AiStreamEvent);

    let tool = AiExtensionEvent {
        schema_version: AI_EXTENSION_EVENT_SCHEMA_VERSION,
        sequence: 9,
        request_id: None,
        model: None,
        payload: AiExtensionEventPayload::ToolCall {
            call: AiExtensionToolCall {
                index: 1,
                id: Some("call-1".to_owned()),
                name: "search".to_owned(),
                arguments_json: r#"{"q":"soap"}"#.to_owned(),
            },
        },
    };
    assert_eq!(tool.hook_kind(), ExtensionHookKind::AiToolCall);
    assert_eq!(
        serde_json::to_value(&tool).unwrap()["call"]["arguments_json"],
        r#"{"q":"soap"}"#
    );
}

#[tokio::test]
async fn link_time_registration_uses_the_awaited_hook_contract() {
    let registration = AiExtensionHookRegistration {
        id: "fixture-release",
        kind: ExtensionHookKind::AiClose,
        enforcement: AiExtensionEnforcement::Block,
        factory: || Arc::new(ReleaseHook),
    };
    let event = AiExtensionEvent {
        schema_version: AI_EXTENSION_EVENT_SCHEMA_VERSION,
        sequence: 10,
        request_id: None,
        model: None,
        payload: AiExtensionEventPayload::Close {
            finish_reason: Some("stop".to_owned()),
            content_bytes: 4,
            content_delta_count: 1,
            tool_call_count: 0,
            prompt_tokens: None,
            completion_tokens: None,
        },
    };

    assert_eq!(registration.kind, event.hook_kind());
    assert_eq!(
        (registration.factory)().handle(&event).await.unwrap(),
        AiExtensionDecision::Release
    );
}

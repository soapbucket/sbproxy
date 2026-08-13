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

#[test]
fn decision_enum_is_non_exhaustive_and_carries_the_mutate_variant() {
    // The enum gained `#[non_exhaustive]` and `Mutate` in the same
    // release, so the public break happens exactly once. An out-of-tree
    // matcher must carry a wildcard arm, and the documented reading of
    // an unknown decision is Release: a matcher that does not
    // understand a verdict must not invent a refusal or apply a payload
    // it cannot see.
    let decision = AiExtensionDecision::Mutate {
        body: b"redacted text".to_vec(),
        code: "pii_redacted".to_owned(),
    };
    let outcome = match decision {
        AiExtensionDecision::Block { .. } => "block",
        AiExtensionDecision::Flag { .. } => "flag",
        AiExtensionDecision::Mutate { .. } => "mutate",
        AiExtensionDecision::Release => "release",
        // Compile-time proof of `#[non_exhaustive]`: this test crate is
        // external to the enum's crate, so without the attribute this
        // wildcard is unreachable and rejected under `-D warnings`. An
        // unknown decision reads as a release.
        _ => "release",
    };
    assert_eq!(outcome, "mutate");
}

#[test]
fn mutation_contract_is_per_kind() {
    // Content-bearing kinds accept mutation; lifecycle kinds refuse.
    let mut input = AiExtensionEventPayload::GuardrailInput {
        stage: "original".to_owned(),
        messages: vec![AiExtensionMessage {
            role: AiExtensionRole::User,
            content: "raw".to_owned(),
            name: None,
            tool_call_id: None,
        }],
    };
    assert!(input.accepts_mutation());
    // The input body is the JSON of the canonical message list.
    input
        .apply_mutation(br#"[{"role":"user","content":"clean"}]"#)
        .unwrap();
    assert_eq!(
        input,
        AiExtensionEventPayload::GuardrailInput {
            stage: "original".to_owned(),
            messages: vec![AiExtensionMessage {
                role: AiExtensionRole::User,
                content: "clean".to_owned(),
                name: None,
                tool_call_id: None,
            }],
        }
    );
    // The stage is host-owned: the mutate body is the content shape
    // alone, so a guest cannot relabel the evaluation stage.
    assert!(input
        .apply_mutation(br#"{"stage":"rag_augmented","messages":[]}"#)
        .is_err());

    // Output content is plain UTF-8 text, not JSON.
    let mut output = AiExtensionEventPayload::GuardrailOutput {
        content: "raw".to_owned(),
    };
    assert!(output.accepts_mutation());
    output.apply_mutation(b"clean text").unwrap();
    assert_eq!(
        output,
        AiExtensionEventPayload::GuardrailOutput {
            content: "clean text".to_owned(),
        }
    );
    assert!(output.apply_mutation(&[0xFF, 0xFE]).is_err());

    // Tool calls take the JSON of the call shape.
    let mut tool = AiExtensionEventPayload::ToolCall {
        call: AiExtensionToolCall {
            index: 0,
            id: Some("call-1".to_owned()),
            name: "search".to_owned(),
            arguments_json: "{}".to_owned(),
        },
    };
    assert!(tool.accepts_mutation());
    tool.apply_mutation(
        br#"{"index":0,"id":"call-1","name":"search","arguments_json":"{\"q\":\"safe\"}"}"#,
    )
    .unwrap();
    assert!(tool.apply_mutation(b"not json").is_err());

    // Stream chunks take the JSON of the chunk shape.
    let mut chunk = AiExtensionEventPayload::Stream {
        chunk: AiExtensionStreamChunk::ContentDelta {
            index: 0,
            text: "raw".to_owned(),
        },
    };
    assert!(chunk.accepts_mutation());
    chunk
        .apply_mutation(br#"{"kind":"content_delta","index":0,"text":"clean"}"#)
        .unwrap();
    assert_eq!(
        chunk,
        AiExtensionEventPayload::Stream {
            chunk: AiExtensionStreamChunk::ContentDelta {
                index: 0,
                text: "clean".to_owned(),
            },
        }
    );

    // Lifecycle events refuse regardless of body.
    let mut close = AiExtensionEventPayload::Close {
        finish_reason: None,
        content_bytes: 0,
        content_delta_count: 0,
        tool_call_count: 0,
        prompt_tokens: None,
        completion_tokens: None,
    };
    assert!(!close.accepts_mutation());
    assert_eq!(close.apply_mutation(b"{}"), Err("event_not_mutable"));
}

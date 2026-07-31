//! Parser for the ratified [A2A 1.0](https://a2a-protocol.org/latest/specification/)
//! JSON-RPC binding.
//!
//! Unlike the two `v0` draft parsers this module is **not** behind a
//! feature flag. Those are gated off by default and nothing in the
//! workspace enables them, which meant the proxy ran on the forgeable
//! header envelope alone. Gating the ratified spec the same way would
//! repeat that mistake: a parser nobody compiles cannot govern
//! anything.
//!
//! A2A 1.0 defines three bindings (JSON-RPC 2.0, gRPC, and HTTP+JSON)
//! and requires them to be functionally equivalent. This module covers
//! JSON-RPC, the common deployment; the other two map onto the same
//! [`V1Request`] when they are added.

use serde::{Deserialize, Serialize};

/// The A2A 1.0 method a request invokes.
///
/// Closed enum rather than a bare string so policy code matches
/// exhaustively and a new spec method surfaces as a compile error
/// instead of falling into a catch-all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum V1Method {
    /// `SendMessage`: initiate a task or get a direct response.
    SendMessage,
    /// `SendStreamingMessage`: initiate with server-streamed events.
    SendStreamingMessage,
    /// `GetTask`: read current task state.
    GetTask,
    /// `ListTasks`: enumerate tasks.
    ListTasks,
    /// `CancelTask`: request cancellation.
    CancelTask,
    /// `SubscribeToTask`: attach a stream to an existing task.
    SubscribeToTask,
    /// `CreateTaskPushNotificationConfig`: register a webhook the agent
    /// will POST task updates to. The security-relevant one: the URL is
    /// caller-supplied and the agent dials it.
    CreateTaskPushNotificationConfig,
    /// `GetTaskPushNotificationConfig`: read one webhook registration.
    GetTaskPushNotificationConfig,
    /// `ListTaskPushNotificationConfigs`: enumerate registrations.
    ListTaskPushNotificationConfigs,
    /// `DeleteTaskPushNotificationConfig`: remove a registration.
    DeleteTaskPushNotificationConfig,
    /// `GetExtendedAgentCard`: fetch the authenticated agent card.
    GetExtendedAgentCard,
}

impl V1Method {
    /// Parse the JSON-RPC `method` string. Returns `None` for anything
    /// outside the spec's method set.
    pub fn from_wire(method: &str) -> Option<Self> {
        Some(match method {
            "SendMessage" => Self::SendMessage,
            "SendStreamingMessage" => Self::SendStreamingMessage,
            "GetTask" => Self::GetTask,
            "ListTasks" => Self::ListTasks,
            "CancelTask" => Self::CancelTask,
            "SubscribeToTask" => Self::SubscribeToTask,
            "CreateTaskPushNotificationConfig" => Self::CreateTaskPushNotificationConfig,
            "GetTaskPushNotificationConfig" => Self::GetTaskPushNotificationConfig,
            "ListTaskPushNotificationConfigs" => Self::ListTaskPushNotificationConfigs,
            "DeleteTaskPushNotificationConfig" => Self::DeleteTaskPushNotificationConfig,
            "GetExtendedAgentCard" => Self::GetExtendedAgentCard,
            _ => return None,
        })
    }

    /// Stable label for metrics and audit events.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::SendMessage => "SendMessage",
            Self::SendStreamingMessage => "SendStreamingMessage",
            Self::GetTask => "GetTask",
            Self::ListTasks => "ListTasks",
            Self::CancelTask => "CancelTask",
            Self::SubscribeToTask => "SubscribeToTask",
            Self::CreateTaskPushNotificationConfig => "CreateTaskPushNotificationConfig",
            Self::GetTaskPushNotificationConfig => "GetTaskPushNotificationConfig",
            Self::ListTaskPushNotificationConfigs => "ListTaskPushNotificationConfigs",
            Self::DeleteTaskPushNotificationConfig => "DeleteTaskPushNotificationConfig",
            Self::GetExtendedAgentCard => "GetExtendedAgentCard",
        }
    }
}

/// Fields the proxy extracts from an A2A 1.0 JSON-RPC request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct V1Request {
    /// Which spec method, when it is one this build recognises.
    pub method: Option<V1Method>,
    /// `params.taskId`, when present.
    pub task_id: Option<String>,
    /// `params.contextId`. The natural correlation key for a run: task
    /// ids nest under it.
    pub context_id: Option<String>,
    /// Webhook URL from a `CreateTaskPushNotificationConfig` request.
    ///
    /// Caller-supplied, and the upstream agent will POST task artifacts
    /// to it, which makes it a server-side request forgery surface by
    /// protocol design. Validate before forwarding.
    pub push_notification_url: Option<String>,
}

/// Parse an A2A 1.0 JSON-RPC request body.
///
/// Returns `None` when the body is not a JSON object. A valid object
/// with unrecognised fields still yields a usable [`V1Request`], so a
/// spec revision that adds params does not blind the proxy to the ones
/// it already understands.
pub fn parse_request(body: &[u8]) -> Option<V1Request> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let obj = v.as_object()?;

    let method = obj
        .get("method")
        .and_then(|m| m.as_str())
        .and_then(V1Method::from_wire);

    let params = obj.get("params").and_then(|p| p.as_object());
    let str_param = |name: &str| {
        params
            .and_then(|p| p.get(name))
            .and_then(|v| v.as_str())
            .map(str::to_string)
    };

    // The webhook URL only carries meaning on the registration method.
    // Reading it from any other method would let a caller smuggle a URL
    // past a validator that keys on the field alone.
    let push_notification_url = if method == Some(V1Method::CreateTaskPushNotificationConfig) {
        params
            .and_then(|p| p.get("pushNotificationConfig"))
            .and_then(|c| c.as_object())
            .and_then(|c| c.get("url"))
            .and_then(|u| u.as_str())
            .map(str::to_string)
            // Some producers put `url` directly on params rather than
            // nesting it under `pushNotificationConfig`.
            .or_else(|| str_param("url"))
    } else {
        None
    };

    Some(V1Request {
        method,
        task_id: str_param("taskId"),
        context_id: str_param("contextId"),
        push_notification_url,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_send_message_with_context_and_task() {
        let body = br#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "SendMessage",
            "params": { "taskId": "task-7", "contextId": "run-3" }
        }"#;
        let req = parse_request(body).expect("valid json-rpc");
        assert_eq!(req.method, Some(V1Method::SendMessage));
        assert_eq!(req.task_id.as_deref(), Some("task-7"));
        assert_eq!(req.context_id.as_deref(), Some("run-3"));
    }

    #[test]
    fn extracts_the_webhook_url_from_a_registration() {
        let body = br#"{
            "jsonrpc": "2.0",
            "id": 2,
            "method": "CreateTaskPushNotificationConfig",
            "params": {
                "taskId": "task-7",
                "pushNotificationConfig": { "url": "https://client.example/hook" }
            }
        }"#;
        let req = parse_request(body).expect("valid json-rpc");
        assert_eq!(
            req.push_notification_url.as_deref(),
            Some("https://client.example/hook")
        );
    }

    #[test]
    fn ignores_a_webhook_url_on_a_method_that_does_not_register_one() {
        // A caller must not be able to park a URL on an unrelated method
        // and have a validator that keys on the field alone treat it as
        // a registration, or skip validating a real one.
        let body = br#"{
            "jsonrpc": "2.0",
            "method": "SendMessage",
            "params": { "url": "http://169.254.169.254/latest/meta-data/" }
        }"#;
        let req = parse_request(body).expect("valid json-rpc");
        assert_eq!(req.push_notification_url, None);
    }

    #[test]
    fn an_unknown_method_still_yields_the_other_fields() {
        let body = br#"{
            "jsonrpc": "2.0",
            "method": "SomeFutureMethod",
            "params": { "contextId": "run-9" }
        }"#;
        let req = parse_request(body).expect("valid json-rpc");
        assert_eq!(req.method, None);
        assert_eq!(req.context_id.as_deref(), Some("run-9"));
    }

    #[test]
    fn a_non_object_body_is_not_a_request() {
        assert!(parse_request(b"[1,2,3]").is_none());
        assert!(parse_request(b"not json").is_none());
    }

    #[test]
    fn every_spec_method_round_trips_through_its_label() {
        for m in [
            V1Method::SendMessage,
            V1Method::SendStreamingMessage,
            V1Method::GetTask,
            V1Method::ListTasks,
            V1Method::CancelTask,
            V1Method::SubscribeToTask,
            V1Method::CreateTaskPushNotificationConfig,
            V1Method::GetTaskPushNotificationConfig,
            V1Method::ListTaskPushNotificationConfigs,
            V1Method::DeleteTaskPushNotificationConfig,
            V1Method::GetExtendedAgentCard,
        ] {
            assert_eq!(V1Method::from_wire(m.as_label()), Some(m));
        }
    }
}

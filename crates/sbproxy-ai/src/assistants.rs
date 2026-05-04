//! OpenAI Assistants API passthrough routing.
//!
//! Provides endpoint classification for Assistants API requests so the gateway
//! can route them to the correct provider without inspecting the full request body.

use serde::{Deserialize, Serialize};

/// Configuration for the Assistants API passthrough.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AssistantConfig {
    /// Whether the Assistants API passthrough is enabled.
    pub enabled: bool,
}

/// Classified endpoint for an incoming Assistants API request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssistantEndpoint {
    /// POST /v1/assistants
    CreateAssistant,
    /// GET /v1/assistants/{id}
    GetAssistant(String),
    /// GET /v1/assistants
    ListAssistants,
    /// POST /v1/threads
    CreateThread,
    /// POST /v1/threads/{thread_id}/messages
    CreateMessage(String),
    /// POST /v1/threads/{thread_id}/runs
    CreateRun(String),
    /// GET /v1/threads/{thread_id}/runs/{run_id}
    GetRun(String, String),
    /// Unrecognised path or method combination.
    Unknown,
}

/// Routes Assistants API requests to the correct endpoint variant.
pub struct AssistantHandler;

impl AssistantHandler {
    /// Classify an incoming request by `path` and HTTP `method`.
    ///
    /// Supports:
    /// - `POST /v1/assistants` - create assistant
    /// - `GET  /v1/assistants` - list assistants
    /// - `GET  /v1/assistants/{id}` - get assistant by ID
    /// - `POST /v1/threads` - create thread
    /// - `POST /v1/threads/{id}/messages` - create message in thread
    /// - `POST /v1/threads/{id}/runs` - start a run on a thread
    /// - `GET  /v1/threads/{id}/runs/{run_id}` - get run status
    pub fn route_request(path: &str, method: &str) -> AssistantEndpoint {
        let path = path.trim_end_matches('/');
        let method = method.to_uppercase();

        // --- Strip optional /v1 prefix ---
        let path = path.strip_prefix("/v1").unwrap_or(path);

        // --- Split path into segments ---
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        match (method.as_str(), segments.as_slice()) {
            // POST /assistants
            ("POST", ["assistants"]) => AssistantEndpoint::CreateAssistant,

            // GET /assistants
            ("GET", ["assistants"]) => AssistantEndpoint::ListAssistants,

            // GET /assistants/{id}
            ("GET", ["assistants", id]) => AssistantEndpoint::GetAssistant(id.to_string()),

            // POST /threads
            ("POST", ["threads"]) => AssistantEndpoint::CreateThread,

            // POST /threads/{thread_id}/messages
            ("POST", ["threads", thread_id, "messages"]) => {
                AssistantEndpoint::CreateMessage(thread_id.to_string())
            }

            // POST /threads/{thread_id}/runs
            ("POST", ["threads", thread_id, "runs"]) => {
                AssistantEndpoint::CreateRun(thread_id.to_string())
            }

            // GET /threads/{thread_id}/runs/{run_id}
            ("GET", ["threads", thread_id, "runs", run_id]) => {
                AssistantEndpoint::GetRun(thread_id.to_string(), run_id.to_string())
            }

            _ => AssistantEndpoint::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_create_assistant() {
        assert_eq!(
            AssistantHandler::route_request("/v1/assistants", "POST"),
            AssistantEndpoint::CreateAssistant
        );
    }

    #[test]
    fn route_list_assistants() {
        assert_eq!(
            AssistantHandler::route_request("/v1/assistants", "GET"),
            AssistantEndpoint::ListAssistants
        );
    }

    #[test]
    fn route_get_assistant() {
        assert_eq!(
            AssistantHandler::route_request("/v1/assistants/asst_abc123", "GET"),
            AssistantEndpoint::GetAssistant("asst_abc123".to_string())
        );
    }

    #[test]
    fn route_create_thread() {
        assert_eq!(
            AssistantHandler::route_request("/v1/threads", "POST"),
            AssistantEndpoint::CreateThread
        );
    }

    #[test]
    fn route_create_message() {
        assert_eq!(
            AssistantHandler::route_request("/v1/threads/thread_xyz/messages", "POST"),
            AssistantEndpoint::CreateMessage("thread_xyz".to_string())
        );
    }

    #[test]
    fn route_create_run() {
        assert_eq!(
            AssistantHandler::route_request("/v1/threads/thread_xyz/runs", "POST"),
            AssistantEndpoint::CreateRun("thread_xyz".to_string())
        );
    }

    #[test]
    fn route_get_run() {
        assert_eq!(
            AssistantHandler::route_request("/v1/threads/thread_xyz/runs/run_abc", "GET"),
            AssistantEndpoint::GetRun("thread_xyz".to_string(), "run_abc".to_string())
        );
    }

    #[test]
    fn route_unknown_paths() {
        assert_eq!(
            AssistantHandler::route_request("/v1/unknown", "GET"),
            AssistantEndpoint::Unknown
        );
        assert_eq!(
            AssistantHandler::route_request("/v1/assistants/id", "DELETE"),
            AssistantEndpoint::Unknown
        );
    }

    #[test]
    fn route_without_v1_prefix() {
        assert_eq!(
            AssistantHandler::route_request("/assistants", "POST"),
            AssistantEndpoint::CreateAssistant
        );
    }
}

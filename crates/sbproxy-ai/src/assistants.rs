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
///
/// Covers the OpenAI Assistants v2 surface: assistants and assistant
/// files, threads and thread messages, runs (including the run-cancel
/// and create-thread-and-run convenience paths).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssistantEndpoint {
    /// POST /v1/assistants
    CreateAssistant,
    /// GET /v1/assistants/{id}
    GetAssistant(String),
    /// POST /v1/assistants/{id}
    ModifyAssistant(String),
    /// DELETE /v1/assistants/{id}
    DeleteAssistant(String),
    /// GET /v1/assistants
    ListAssistants,
    /// GET /v1/assistants/{assistant_id}/files
    ListAssistantFiles(String),
    /// GET /v1/assistants/{assistant_id}/files/{file_id}
    GetAssistantFile(String, String),
    /// POST /v1/threads
    CreateThread,
    /// GET /v1/threads/{thread_id}
    GetThread(String),
    /// POST /v1/threads/{thread_id}
    ModifyThread(String),
    /// DELETE /v1/threads/{thread_id}
    DeleteThread(String),
    /// POST /v1/threads/{thread_id}/messages
    CreateMessage(String),
    /// GET /v1/threads/{thread_id}/messages
    ListMessages(String),
    /// GET /v1/threads/{thread_id}/messages/{message_id}
    GetMessage(String, String),
    /// POST /v1/threads/{thread_id}/runs
    CreateRun(String),
    /// GET /v1/threads/{thread_id}/runs
    ListRuns(String),
    /// GET /v1/threads/{thread_id}/runs/{run_id}
    GetRun(String, String),
    /// POST /v1/threads/{thread_id}/runs/{run_id}
    ModifyRun(String, String),
    /// POST /v1/threads/{thread_id}/runs/{run_id}/cancel
    CancelRun(String, String),
    /// POST /v1/threads/runs (create-thread-and-run convenience)
    CreateThreadAndRun,
    /// Unrecognised path or method combination.
    Unknown,
}

/// Routes Assistants API requests to the correct endpoint variant.
pub struct AssistantHandler;

impl AssistantHandler {
    /// Classify an incoming request by `path` and HTTP `method`.
    ///
    /// Covers the full OpenAI Assistants v2 surface: assistants
    /// (create/list/get/modify/delete plus file sub-paths), threads
    /// (create/get/modify/delete), thread messages (create/list/get),
    /// and runs (create/list/get/modify/cancel plus the
    /// create-thread-and-run convenience path).
    pub fn route_request(path: &str, method: &str) -> AssistantEndpoint {
        let path = path.trim_end_matches('/');
        let method = method.to_uppercase();

        // --- Strip optional /v1 prefix ---
        let path = path.strip_prefix("/v1").unwrap_or(path);

        // --- Split path into segments ---
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        match (method.as_str(), segments.as_slice()) {
            // Assistants collection.
            ("POST", ["assistants"]) => AssistantEndpoint::CreateAssistant,
            ("GET", ["assistants"]) => AssistantEndpoint::ListAssistants,

            // Single assistant.
            ("GET", ["assistants", id]) => AssistantEndpoint::GetAssistant(id.to_string()),
            ("POST", ["assistants", id]) => AssistantEndpoint::ModifyAssistant(id.to_string()),
            ("DELETE", ["assistants", id]) => AssistantEndpoint::DeleteAssistant(id.to_string()),

            // Assistant files.
            ("GET", ["assistants", id, "files"]) => {
                AssistantEndpoint::ListAssistantFiles(id.to_string())
            }
            ("GET", ["assistants", id, "files", file_id]) => {
                AssistantEndpoint::GetAssistantFile(id.to_string(), file_id.to_string())
            }

            // Threads collection.
            ("POST", ["threads"]) => AssistantEndpoint::CreateThread,
            // Create-thread-and-run convenience path.
            ("POST", ["threads", "runs"]) => AssistantEndpoint::CreateThreadAndRun,

            // Single thread.
            ("GET", ["threads", id]) => AssistantEndpoint::GetThread(id.to_string()),
            ("POST", ["threads", id]) => AssistantEndpoint::ModifyThread(id.to_string()),
            ("DELETE", ["threads", id]) => AssistantEndpoint::DeleteThread(id.to_string()),

            // Thread messages.
            ("POST", ["threads", thread_id, "messages"]) => {
                AssistantEndpoint::CreateMessage(thread_id.to_string())
            }
            ("GET", ["threads", thread_id, "messages"]) => {
                AssistantEndpoint::ListMessages(thread_id.to_string())
            }
            ("GET", ["threads", thread_id, "messages", message_id]) => {
                AssistantEndpoint::GetMessage(thread_id.to_string(), message_id.to_string())
            }

            // Thread runs.
            ("POST", ["threads", thread_id, "runs"]) => {
                AssistantEndpoint::CreateRun(thread_id.to_string())
            }
            ("GET", ["threads", thread_id, "runs"]) => {
                AssistantEndpoint::ListRuns(thread_id.to_string())
            }
            ("GET", ["threads", thread_id, "runs", run_id]) => {
                AssistantEndpoint::GetRun(thread_id.to_string(), run_id.to_string())
            }
            ("POST", ["threads", thread_id, "runs", run_id]) => {
                AssistantEndpoint::ModifyRun(thread_id.to_string(), run_id.to_string())
            }
            ("POST", ["threads", thread_id, "runs", run_id, "cancel"]) => {
                AssistantEndpoint::CancelRun(thread_id.to_string(), run_id.to_string())
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
        // PUT is not used anywhere in the Assistants API.
        assert_eq!(
            AssistantHandler::route_request("/v1/assistants/id", "PUT"),
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

    // --- v2 surface additions ---

    #[test]
    fn route_modify_assistant() {
        assert_eq!(
            AssistantHandler::route_request("/v1/assistants/asst_xyz", "POST"),
            AssistantEndpoint::ModifyAssistant("asst_xyz".to_string())
        );
    }

    #[test]
    fn route_delete_assistant() {
        assert_eq!(
            AssistantHandler::route_request("/v1/assistants/asst_xyz", "DELETE"),
            AssistantEndpoint::DeleteAssistant("asst_xyz".to_string())
        );
    }

    #[test]
    fn route_list_assistant_files() {
        assert_eq!(
            AssistantHandler::route_request("/v1/assistants/asst_xyz/files", "GET"),
            AssistantEndpoint::ListAssistantFiles("asst_xyz".to_string())
        );
    }

    #[test]
    fn route_get_assistant_file() {
        assert_eq!(
            AssistantHandler::route_request("/v1/assistants/asst_xyz/files/file_abc", "GET"),
            AssistantEndpoint::GetAssistantFile("asst_xyz".to_string(), "file_abc".to_string())
        );
    }

    #[test]
    fn route_get_thread() {
        assert_eq!(
            AssistantHandler::route_request("/v1/threads/thread_xyz", "GET"),
            AssistantEndpoint::GetThread("thread_xyz".to_string())
        );
    }

    #[test]
    fn route_modify_thread() {
        assert_eq!(
            AssistantHandler::route_request("/v1/threads/thread_xyz", "POST"),
            AssistantEndpoint::ModifyThread("thread_xyz".to_string())
        );
    }

    #[test]
    fn route_delete_thread() {
        assert_eq!(
            AssistantHandler::route_request("/v1/threads/thread_xyz", "DELETE"),
            AssistantEndpoint::DeleteThread("thread_xyz".to_string())
        );
    }

    #[test]
    fn route_list_messages() {
        assert_eq!(
            AssistantHandler::route_request("/v1/threads/thread_xyz/messages", "GET"),
            AssistantEndpoint::ListMessages("thread_xyz".to_string())
        );
    }

    #[test]
    fn route_get_message() {
        assert_eq!(
            AssistantHandler::route_request("/v1/threads/thread_xyz/messages/msg_abc", "GET"),
            AssistantEndpoint::GetMessage("thread_xyz".to_string(), "msg_abc".to_string())
        );
    }

    #[test]
    fn route_list_runs() {
        assert_eq!(
            AssistantHandler::route_request("/v1/threads/thread_xyz/runs", "GET"),
            AssistantEndpoint::ListRuns("thread_xyz".to_string())
        );
    }

    #[test]
    fn route_modify_run() {
        assert_eq!(
            AssistantHandler::route_request("/v1/threads/thread_xyz/runs/run_abc", "POST"),
            AssistantEndpoint::ModifyRun("thread_xyz".to_string(), "run_abc".to_string())
        );
    }

    #[test]
    fn route_cancel_run() {
        assert_eq!(
            AssistantHandler::route_request("/v1/threads/thread_xyz/runs/run_abc/cancel", "POST"),
            AssistantEndpoint::CancelRun("thread_xyz".to_string(), "run_abc".to_string())
        );
    }

    #[test]
    fn route_create_thread_and_run() {
        assert_eq!(
            AssistantHandler::route_request("/v1/threads/runs", "POST"),
            AssistantEndpoint::CreateThreadAndRun
        );
    }
}

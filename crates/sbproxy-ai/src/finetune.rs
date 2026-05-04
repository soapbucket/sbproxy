//! Fine-tuning API routing.
//!
//! Classifies requests to the OpenAI fine-tuning API endpoints so the gateway
//! can forward them to the correct provider.

use serde::{Deserialize, Serialize};

/// Configuration for fine-tuning API support.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FinetuneConfig {
    /// Whether fine-tuning API passthrough is enabled.
    pub enabled: bool,
}

/// Classified endpoint for an incoming fine-tuning API request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinetuneEndpoint {
    /// POST /v1/fine_tuning/jobs
    CreateJob,
    /// GET /v1/fine_tuning/jobs
    ListJobs,
    /// GET /v1/fine_tuning/jobs/{id}
    GetJob(String),
    /// POST /v1/fine_tuning/jobs/{id}/cancel
    CancelJob(String),
    /// GET /v1/fine_tuning/jobs/{id}/events
    ListEvents(String),
    /// Unrecognised path or method.
    Unknown,
}

/// Routes fine-tuning API requests to the correct endpoint variant.
pub struct FinetuneHandler;

impl FinetuneHandler {
    /// Classify an incoming request by `path` and HTTP `method`.
    ///
    /// Supports:
    /// - `POST /v1/fine_tuning/jobs` - create a fine-tuning job
    /// - `GET  /v1/fine_tuning/jobs` - list all jobs
    /// - `GET  /v1/fine_tuning/jobs/{id}` - get a specific job
    /// - `POST /v1/fine_tuning/jobs/{id}/cancel` - cancel a job
    /// - `GET  /v1/fine_tuning/jobs/{id}/events` - list events for a job
    pub fn route_request(path: &str, method: &str) -> FinetuneEndpoint {
        let path = path.trim_end_matches('/');
        let method = method.to_uppercase();

        // --- Strip optional /v1 prefix ---
        let path = path.strip_prefix("/v1").unwrap_or(path);

        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        match (method.as_str(), segments.as_slice()) {
            // POST /fine_tuning/jobs
            ("POST", ["fine_tuning", "jobs"]) => FinetuneEndpoint::CreateJob,

            // GET /fine_tuning/jobs
            ("GET", ["fine_tuning", "jobs"]) => FinetuneEndpoint::ListJobs,

            // GET /fine_tuning/jobs/{id}
            ("GET", ["fine_tuning", "jobs", id]) => FinetuneEndpoint::GetJob(id.to_string()),

            // POST /fine_tuning/jobs/{id}/cancel
            ("POST", ["fine_tuning", "jobs", id, "cancel"]) => {
                FinetuneEndpoint::CancelJob(id.to_string())
            }

            // GET /fine_tuning/jobs/{id}/events
            ("GET", ["fine_tuning", "jobs", id, "events"]) => {
                FinetuneEndpoint::ListEvents(id.to_string())
            }

            _ => FinetuneEndpoint::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_create_job() {
        assert_eq!(
            FinetuneHandler::route_request("/v1/fine_tuning/jobs", "POST"),
            FinetuneEndpoint::CreateJob
        );
    }

    #[test]
    fn route_list_jobs() {
        assert_eq!(
            FinetuneHandler::route_request("/v1/fine_tuning/jobs", "GET"),
            FinetuneEndpoint::ListJobs
        );
    }

    #[test]
    fn route_get_job() {
        assert_eq!(
            FinetuneHandler::route_request("/v1/fine_tuning/jobs/ftjob-abc", "GET"),
            FinetuneEndpoint::GetJob("ftjob-abc".to_string())
        );
    }

    #[test]
    fn route_cancel_job() {
        assert_eq!(
            FinetuneHandler::route_request("/v1/fine_tuning/jobs/ftjob-abc/cancel", "POST"),
            FinetuneEndpoint::CancelJob("ftjob-abc".to_string())
        );
    }

    #[test]
    fn route_list_events() {
        assert_eq!(
            FinetuneHandler::route_request("/v1/fine_tuning/jobs/ftjob-abc/events", "GET"),
            FinetuneEndpoint::ListEvents("ftjob-abc".to_string())
        );
    }

    #[test]
    fn route_unknown() {
        assert_eq!(
            FinetuneHandler::route_request("/v1/fine_tuning/jobs/id", "DELETE"),
            FinetuneEndpoint::Unknown
        );
    }
}

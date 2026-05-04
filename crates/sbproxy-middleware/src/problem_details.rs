//! RFC 9457 Problem Details for HTTP APIs.
//!
//! Produces `application/problem+json` response bodies that give clients
//! machine-readable error context.

/// Generate an RFC 9457 problem details JSON string.
pub fn problem_details_json(status: u16, title: &str, detail: &str, instance: &str) -> String {
    serde_json::json!({
        "type": "about:blank",
        "title": title,
        "status": status,
        "detail": detail,
        "instance": instance,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_problem_details_fields() {
        let body = problem_details_json(404, "Not Found", "Origin not configured", "/api/data");
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["type"], "about:blank");
        assert_eq!(parsed["title"], "Not Found");
        assert_eq!(parsed["status"], 404);
        assert_eq!(parsed["detail"], "Origin not configured");
        assert_eq!(parsed["instance"], "/api/data");
    }

    #[test]
    fn test_problem_details_is_valid_json() {
        let body = problem_details_json(500, "Internal Error", "Unexpected failure", "/health");
        assert!(serde_json::from_str::<serde_json::Value>(&body).is_ok());
    }
}

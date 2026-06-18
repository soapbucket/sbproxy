//! Disabled chat playground handler.
//!
//! Real wiring (route the request through the production AI dispatch
//! path and stream a model's response back to the dashboard) is not
//! available in OSS builds yet. Until that implementation lands, this
//! handler gates the path with an explicit disabled response instead
//! of advertising a stable endpoint that always returns 501.
//!
//! The route lives on the admin server (next to `/admin/reload`)
//! because the playground is operator-only and shares the admin
//! port's basic-auth gate. The actual proxy listener stays focused
//! on production traffic.

/// Path reserved for the playground chat endpoint.
pub const CHAT_PATH: &str = "/admin/api/playground/chat";

/// Body returned while the playground is gated off.
const DISABLED_BODY: &str = r#"{"error":"feature disabled","feature":"admin_chat_playground","detail":"admin chat playground is not wired in this build; use configured AI proxy origins for live model traffic"}"#;

/// Dispatch the playground chat route. Returns `None` when the path
/// is not ours (letting the caller fall through to the next route)
/// and `Some((status, ct, body))` otherwise.
///
/// `POST` returns 404 with a JSON feature-disabled envelope. Other
/// verbs (including GET) return 405 Method Not Allowed so a curious
/// operator pinging the route in a browser sees a clear shape signal.
pub fn dispatch(method: &str, path: &str) -> Option<(u16, &'static str, String)> {
    if path != CHAT_PATH {
        return None;
    }
    if method.eq_ignore_ascii_case("POST") {
        return Some((404, "application/json", DISABLED_BODY.to_string()));
    }
    Some((
        405,
        "application/json",
        r#"{"error":"method not allowed"}"#.to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_matching_path_returns_none() {
        assert!(dispatch("POST", "/admin/api/health").is_none());
        assert!(dispatch("POST", "/api/requests").is_none());
        assert!(dispatch("POST", "/admin/api/playground/chat/extra").is_none());
    }

    #[test]
    fn post_returns_feature_disabled_404() {
        let (status, ct, body) = dispatch("POST", CHAT_PATH).expect("matched");
        assert_eq!(status, 404);
        assert_eq!(ct, "application/json");
        assert!(body.contains("feature disabled"));
        assert!(body.contains("admin_chat_playground"));
        assert!(!body.contains("not implemented"));
    }

    #[test]
    fn non_post_returns_405() {
        for method in ["GET", "PUT", "DELETE", "PATCH"] {
            let (status, _, _) = dispatch(method, CHAT_PATH).expect("matched");
            assert_eq!(status, 405, "expected 405 for {method}");
        }
    }
}

//! Chat playground stub handler.
//!
//! Real wiring (route the request through `proxy_router.oneshot`
//! and stream a model's response back to the dashboard) is deferred
//! to a follow-up ticket. This stub returns a 501 with a JSON body
//! explaining where the real handler will live, so the front-end
//! scaffold and the cargo feature can land independently of the
//! integration work.
//!
//! The route lives on the admin server (next to `/admin/reload`)
//! because the playground is operator-only and shares the admin
//! port's basic-auth gate. The actual proxy listener stays focused
//! on production traffic.

/// Path the playground stub responds on. The follow-up ticket
/// (separate from WOR-227) keeps this path stable when it lands the
/// real handler.
pub const CHAT_PATH: &str = "/admin/api/playground/chat";

/// Body returned by the stub handler. The text names the follow-up
/// integration work and points at the proxy router primitive the
/// real handler will call.
const STUB_BODY: &str = r#"{"error":"not implemented","ticket":"WOR-227 follow-up","detail":"chat playground stub; real handler will route through proxy_router.oneshot and stream the model response back to /admin/ui"}"#;

/// Dispatch the playground chat route. Returns `None` when the path
/// is not ours (letting the caller fall through to the next route)
/// and `Some((status, ct, body))` otherwise.
///
/// `POST` returns 501 Not Implemented. Other verbs (including GET)
/// return 405 Method Not Allowed so a curious operator pinging the
/// route in a browser sees a clear shape signal rather than a 501.
pub fn dispatch(method: &str, path: &str) -> Option<(u16, &'static str, String)> {
    if path != CHAT_PATH {
        return None;
    }
    if method.eq_ignore_ascii_case("POST") {
        return Some((501, "application/json", STUB_BODY.to_string()));
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
    fn post_returns_501_with_pointer_to_follow_up() {
        let (status, ct, body) = dispatch("POST", CHAT_PATH).expect("matched");
        assert_eq!(status, 501);
        assert_eq!(ct, "application/json");
        assert!(body.contains("WOR-227"));
        assert!(body.contains("proxy_router.oneshot"));
    }

    #[test]
    fn non_post_returns_405() {
        for method in ["GET", "PUT", "DELETE", "PATCH"] {
            let (status, _, _) = dispatch(method, CHAT_PATH).expect("matched");
            assert_eq!(status, 405, "expected 405 for {method}");
        }
    }
}

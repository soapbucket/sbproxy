//! The notifier's admin API, as one pure async dispatcher over method,
//! path, and body.
//!
//! `sbproxy-core` owns the listener, its authentication, and its rate
//! limiter. This owns what the routes mean. Handing back
//! `(status, content_type, body)` keeps the two apart, and lets every test
//! below drive the real routes with no socket.
//!
//! Authentication is not here: the caller has already established that the
//! request may administer this proxy.

use serde::Deserialize;

use super::{Notifier, NotifierSummary, NotifyError};

/// The route prefix this surface claims.
pub const ADMIN_PREFIX: &str = "/admin/notifications";

/// What a handler answers with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response content type.
    pub content_type: &'static str,
    /// Response body.
    pub body: String,
}

impl AdminResponse {
    fn json(status: u16, body: String) -> Self {
        Self {
            status,
            content_type: "application/json",
            body,
        }
    }

    fn error(status: u16, code: &str, message: &str) -> Self {
        Self::json(
            status,
            serde_json::json!({"error": message, "code": code}).to_string(),
        )
    }

    fn from_refusal(error: &NotifyError) -> Self {
        Self::error(error.http_status(), error.outcome(), &error.to_string())
    }

    fn encode<T: serde::Serialize>(status: u16, value: &T) -> Self {
        match serde_json::to_string(value) {
            Ok(body) => Self::json(status, body),
            Err(_) => Self::error(500, "error", "notifier response serialization failed"),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateBody {
    url: String,
    event_types: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateBody {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    event_types: Option<Vec<String>>,
    #[serde(default)]
    active: Option<bool>,
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(64)
        .collect()
}

fn decode<T: for<'de> Deserialize<'de>>(
    body: Option<&[u8]>,
) -> std::result::Result<T, AdminResponse> {
    let Some(body) = body else {
        return Err(AdminResponse::error(
            400,
            "invalid",
            "a JSON body is required",
        ));
    };
    serde_json::from_slice(body).map_err(|error| {
        AdminResponse::error(
            400,
            "invalid",
            &format!("malformed body: {}", sanitize(&error.to_string())),
        )
    })
}

fn decode_optional<T: for<'de> Deserialize<'de> + Default>(
    body: Option<&[u8]>,
) -> std::result::Result<T, AdminResponse> {
    match body {
        None => Ok(T::default()),
        Some(bytes) if bytes.iter().all(u8::is_ascii_whitespace) => Ok(T::default()),
        Some(bytes) => serde_json::from_slice(bytes).map_err(|error| {
            AdminResponse::error(
                400,
                "invalid",
                &format!("malformed body: {}", sanitize(&error.to_string())),
            )
        }),
    }
}

/// Route an admin request to the notifier.
///
/// Returns `None` when `path` is not one of this surface's routes, so the
/// caller falls through to its own routing table.
pub async fn dispatch(
    notifier: &Notifier,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> Option<AdminResponse> {
    let path_only = path.split('?').next().unwrap_or(path);
    let rest = path_only.strip_prefix(ADMIN_PREFIX)?;

    Some(match (method, rest) {
        ("GET", "") => match notifier.summary().await {
            Ok(summary) => AdminResponse::encode::<NotifierSummary>(200, &summary),
            Err(error) => AdminResponse::from_refusal(&error),
        },
        ("GET", "/subscriptions") => match notifier.list_subscriptions().await {
            Ok(items) => AdminResponse::encode(200, &serde_json::json!({"items": items})),
            Err(error) => AdminResponse::from_refusal(&error),
        },
        ("POST", "/subscriptions") => {
            let parsed: CreateBody = match decode(body) {
                Ok(parsed) => parsed,
                Err(response) => return Some(response),
            };
            match notifier
                .create_subscription(parsed.url, parsed.event_types)
                .await
            {
                // The secret is in this response and nowhere else. A
                // receiver that loses it rotates rather than reading it
                // back, which is why no GET carries it.
                Ok((view, secret)) => AdminResponse::encode(
                    201,
                    &serde_json::json!({"subscription": view, "signing_secret": secret}),
                ),
                Err(error) => AdminResponse::from_refusal(&error),
            }
        }
        ("GET", "/deadletters") => match notifier.list_deadletters().await {
            Ok(items) => AdminResponse::encode(200, &serde_json::json!({"items": items})),
            Err(error) => AdminResponse::from_refusal(&error),
        },
        (method, rest) if rest.starts_with("/deadletters/") => {
            let tail = rest.trim_start_matches("/deadletters/");
            match (method, tail.split_once('/')) {
                ("POST", Some((delivery_id, "replay"))) if !delivery_id.is_empty() => {
                    match notifier.replay(delivery_id).await {
                        Ok(event_id) => AdminResponse::encode(
                            202,
                            &serde_json::json!({"event_id": event_id, "replayed": true}),
                        ),
                        Err(error) => AdminResponse::from_refusal(&error),
                    }
                }
                _ => AdminResponse::error(404, "not_found", "no such route"),
            }
        }
        (method, rest) if rest.starts_with("/subscriptions/") => {
            let tail = rest.trim_start_matches("/subscriptions/");
            let (subscription_id, action) = match tail.split_once('/') {
                Some((id, action)) => (id, action),
                None => (tail, ""),
            };
            if subscription_id.is_empty() {
                return Some(AdminResponse::error(404, "not_found", "no such route"));
            }
            match (method, action) {
                ("GET", "") => match notifier.get_subscription(subscription_id).await {
                    Ok(view) => AdminResponse::encode(200, &view),
                    Err(error) => AdminResponse::from_refusal(&error),
                },
                ("PATCH", "") | ("PUT", "") => {
                    let parsed: UpdateBody = match decode_optional(body) {
                        Ok(parsed) => parsed,
                        Err(response) => return Some(response),
                    };
                    match notifier
                        .update_subscription(
                            subscription_id,
                            parsed.url,
                            parsed.event_types,
                            parsed.active,
                        )
                        .await
                    {
                        Ok(view) => AdminResponse::encode(200, &view),
                        Err(error) => AdminResponse::from_refusal(&error),
                    }
                }
                ("DELETE", "") => match notifier.delete_subscription(subscription_id).await {
                    Ok(()) => AdminResponse::encode(200, &serde_json::json!({"deleted": true})),
                    Err(error) => AdminResponse::from_refusal(&error),
                },
                ("POST", "rotate") => match notifier.rotate_signing_key(subscription_id).await {
                    Ok((view, secret)) => AdminResponse::encode(
                        200,
                        &serde_json::json!({"subscription": view, "signing_secret": secret}),
                    ),
                    Err(error) => AdminResponse::from_refusal(&error),
                },
                _ => AdminResponse::error(405, "invalid", "method not allowed on this route"),
            }
        }
        _ => AdminResponse::error(404, "not_found", "no such route"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::{AttemptOutcome, DeliveryTransport};
    use sbproxy_platform::storage::EmbeddedKvStore;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    struct AlwaysDelivers;

    #[async_trait::async_trait]
    impl DeliveryTransport for AlwaysDelivers {
        async fn attempt(
            &self,
            _url: &str,
            _headers: Vec<(&'static str, String)>,
            _body: Vec<u8>,
        ) -> AttemptOutcome {
            AttemptOutcome::Delivered { status: 200 }
        }
    }

    fn temp_path() -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        format!(
            "{}/sbproxy_notify_admin_test_{}_{}.redb",
            std::env::temp_dir().display(),
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        )
    }

    async fn notifier(path: &str) -> Notifier {
        let store = Arc::new(EmbeddedKvStore::open(path, "notifications").expect("open"));
        Notifier::start_with_transport(store, 16, Arc::new(AlwaysDelivers))
            .await
            .expect("notifier")
    }

    async fn call(
        notifier: &Notifier,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> AdminResponse {
        dispatch(notifier, method, path, body)
            .await
            .expect("route exists")
    }

    /// The seam this surface hangs off: a path outside the prefix falls
    /// through so the core router keeps working, and one inside it never
    /// does.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn only_this_prefix_is_claimed() {
        let path = temp_path();
        let notifier = notifier(&path).await;
        assert!(dispatch(&notifier, "GET", "/admin/keys", None)
            .await
            .is_none());
        assert!(
            dispatch(&notifier, "GET", "/admin/notifications/nope", None)
                .await
                .is_some()
        );
        drop(notifier);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_subscription_can_be_created_read_updated_rotated_and_deleted_over_the_routes() {
        let path = temp_path();
        let notifier = notifier(&path).await;

        let created = call(
            &notifier,
            "POST",
            "/admin/notifications/subscriptions",
            Some(br#"{"url":"https://receiver.example/hook","event_types":["key_minted"]}"#),
        )
        .await;
        assert_eq!(created.status, 201);
        let created: serde_json::Value = serde_json::from_str(&created.body).expect("json");
        let id = created["subscription"]["subscription_id"]
            .as_str()
            .expect("id")
            .to_string();
        let secret = created["signing_secret"]
            .as_str()
            .expect("secret")
            .to_string();
        assert_eq!(secret.len(), 64);

        let listed = call(&notifier, "GET", "/admin/notifications/subscriptions", None).await;
        assert_eq!(listed.status, 200);
        assert!(
            !listed.body.contains(&secret),
            "the signing secret must never come back from a listing"
        );

        let updated = call(
            &notifier,
            "PATCH",
            &format!("/admin/notifications/subscriptions/{id}"),
            Some(br#"{"active":false}"#),
        )
        .await;
        assert_eq!(updated.status, 200);
        assert!(updated.body.contains("\"active\":false"));

        let rotated = call(
            &notifier,
            "POST",
            &format!("/admin/notifications/subscriptions/{id}/rotate"),
            None,
        )
        .await;
        assert_eq!(rotated.status, 200);
        let rotated: serde_json::Value = serde_json::from_str(&rotated.body).expect("json");
        assert_ne!(rotated["signing_secret"].as_str(), Some(secret.as_str()));

        let deleted = call(
            &notifier,
            "DELETE",
            &format!("/admin/notifications/subscriptions/{id}"),
            None,
        )
        .await;
        assert_eq!(deleted.status, 200);

        // Deleting an id that is already gone is a 404, not a second
        // success an operator would read as "it was still there".
        let again = call(
            &notifier,
            "DELETE",
            &format!("/admin/notifications/subscriptions/{id}"),
            None,
        )
        .await;
        assert_eq!(again.status, 404);

        drop(notifier);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_malformed_or_unusable_subscription_is_refused_with_a_reason() {
        let path = temp_path();
        let notifier = notifier(&path).await;

        let no_body = call(
            &notifier,
            "POST",
            "/admin/notifications/subscriptions",
            None,
        )
        .await;
        assert_eq!(no_body.status, 400);

        let bad_scheme = call(
            &notifier,
            "POST",
            "/admin/notifications/subscriptions",
            Some(br#"{"url":"ftp://receiver.example/hook","event_types":["*"]}"#),
        )
        .await;
        assert_eq!(bad_scheme.status, 400);
        assert!(bad_scheme.body.contains("invalid"));

        let no_filters = call(
            &notifier,
            "POST",
            "/admin/notifications/subscriptions",
            Some(br#"{"url":"https://receiver.example/hook","event_types":[]}"#),
        )
        .await;
        assert_eq!(no_filters.status, 400);

        // An unknown field is refused rather than silently ignored, so a
        // typo in an automation is visible the first time it runs.
        let unknown_field = call(
            &notifier,
            "POST",
            "/admin/notifications/subscriptions",
            Some(br#"{"url":"https://a.example/h","event_types":["*"],"retries":9}"#),
        )
        .await;
        assert_eq!(unknown_field.status, 400);

        drop(notifier);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_summary_reports_the_bounds_an_operator_plans_against() {
        let path = temp_path();
        let notifier = notifier(&path).await;
        let response = call(&notifier, "GET", "/admin/notifications", None).await;
        assert_eq!(response.status, 200);
        let summary: serde_json::Value = serde_json::from_str(&response.body).expect("json");
        assert_eq!(summary["subscriptions"], serde_json::json!(0));
        assert_eq!(
            summary["max_attempts"],
            serde_json::json!(super::super::MAX_ATTEMPTS)
        );
        assert_eq!(
            summary["deadletter_capacity"],
            serde_json::json!(super::super::MAX_DEADLETTERS)
        );
        drop(notifier);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replaying_an_unknown_delivery_is_a_404() {
        let path = temp_path();
        let notifier = notifier(&path).await;
        let response = call(
            &notifier,
            "POST",
            "/admin/notifications/deadletters/dlv_nope/replay",
            None,
        )
        .await;
        assert_eq!(response.status, 404);
        drop(notifier);
        std::fs::remove_file(&path).ok();
    }
}

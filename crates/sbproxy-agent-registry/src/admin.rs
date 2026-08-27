//! The admin API surface, as one pure async function over method, path, and
//! body.
//!
//! # Why a dispatcher rather than a router
//!
//! `sbproxy-core` owns the admin listener, its authentication, its rate
//! limiter, and its response encoding. This crate owns what the routes
//! mean. Handing back `(status, content_type, body)` keeps the two apart:
//! every test below drives the real dispatcher with no listener, and the
//! core side is a few lines that already know how to answer.
//!
//! Authentication is emphatically not here. [`dispatch`] assumes its caller
//! has already established that the request is allowed to administer this
//! proxy; the one exception is the rotation route, which additionally
//! demands the registration access token issued at submission, because that
//! is the submitter's own credential rather than the operator's.
//!
//! # Where the public self-service endpoint went
//!
//! RFC 7591 describes an unauthenticated `POST /register` on the data
//! plane. This ships the queue on the admin API instead, which means an
//! operator (or an automation holding an admin credential) submits on the
//! agent's behalf. An unauthenticated write path that mints credentials and
//! consumes durable storage is a different security decision from the one
//! this ticket was asked to make, and shipping it quietly inside a storage
//! port would be the wrong way to make it. An operator who wants public
//! self-service fronts this route with their own gateway rule today.

use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::error::RegistryError;
use crate::registration::{AgentMetadata, ApprovalState, TenantScope};
use crate::service::AgentRegistry;

/// What a handler answers with: an HTTP status, a content type, and a body.
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

    fn from_refusal(error: &RegistryError) -> Self {
        Self::error(error.http_status(), error.outcome(), &error.to_string())
    }

    fn encode<T: serde::Serialize>(status: u16, value: &T) -> Self {
        match serde_json::to_string(value) {
            Ok(body) => Self::json(status, body),
            Err(_) => Self::error(500, "error", "agent registry response serialization failed"),
        }
    }
}

/// `POST .../registrations` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterBody {
    agent_metadata: AgentMetadata,
}

/// Body of a decision route.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionBody {
    #[serde(default)]
    reason: Option<String>,
}

/// `POST .../rotate` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RotateBody {
    registration_access_token: String,
}

/// The route prefix every path below hangs off.
pub const ADMIN_PREFIX: &str = "/admin/agent-registry";

/// Route an admin request to the registry.
///
/// Returns `None` when `path` is not one of this surface's routes, so the
/// caller can fall through to its own routing table rather than having to
/// know this crate's paths.
///
/// `actor` is the admin operator the session resolved, which lands on the
/// decision event and in the stored record. `None` is honest rather than a
/// placeholder: an admin token with no operator behind it decided.
///
/// `tenant` is that operator's scope, from `proxy.admin.operators[].tenant`.
/// `None` is a deployment-wide operator. A scoped operator sees and acts
/// only inside its own tenant, and the two deployment-wide routes, the
/// catalog listing and the feed refresh, are refused to it outright rather
/// than silently narrowed. That is `dispatch_ai_chargeback`'s rule, for the
/// same reason it gives: a quietly filtered answer reads as a fact about
/// the deployment rather than about the caller's permissions.
pub async fn dispatch(
    registry: &AgentRegistry,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    actor: Option<&str>,
    tenant: Option<&str>,
    now: DateTime<Utc>,
) -> Option<AdminResponse> {
    let path_only = path.split('?').next().unwrap_or(path);
    let query = path.split_once('?').map(|(_, query)| query).unwrap_or("");
    let rest = path_only.strip_prefix(ADMIN_PREFIX)?;
    let scope = TenantScope::from_principal(tenant);

    Some(match (method, rest) {
        ("GET", "") => match registry.summary(&scope, now).await {
            Ok(summary) => AdminResponse::encode(200, &summary),
            Err(error) => AdminResponse::from_refusal(&error),
        },
        ("GET", "/catalog") if scope.is_scoped() => deployment_wide_refusal("read the catalog"),
        ("GET", "/catalog") => {
            let catalog = registry.catalog();
            let entries = catalog.sorted_entries();
            AdminResponse::encode(
                200,
                &serde_json::json!({
                    "generated_at": catalog.generated_at(),
                    "expires_at": catalog.expires_at(),
                    "expired": catalog.is_expired(now),
                    "entries": entries,
                }),
            )
        }
        ("POST", "/refresh") if scope.is_scoped() => deployment_wide_refusal("refresh the feed"),
        ("POST", "/refresh") => match registry.refresh(now).await {
            Ok(applied) => AdminResponse::encode(200, &serde_json::json!({"entries": applied})),
            Err(error) => AdminResponse::from_refusal(&error),
        },
        ("GET", "/registrations") => {
            let state = match parse_state_filter(query) {
                Ok(state) => state,
                Err(response) => return Some(response),
            };
            match registry.list(&scope, state).await {
                Ok(items) => AdminResponse::encode(200, &serde_json::json!({"items": items})),
                Err(error) => AdminResponse::from_refusal(&error),
            }
        }
        ("POST", "/registrations") => {
            let parsed: RegisterBody = match decode(body) {
                Ok(parsed) => parsed,
                Err(response) => return Some(response),
            };
            match registry
                .register(&scope, parsed.agent_metadata, actor, now)
                .await
            {
                Ok((secrets, view)) => AdminResponse::encode(
                    201,
                    &serde_json::json!({"secrets": secrets, "registration": view}),
                ),
                Err(error) => AdminResponse::from_refusal(&error),
            }
        }
        (method, rest) if rest.starts_with("/registrations/") => {
            let tail = rest.trim_start_matches("/registrations/");
            let (agent_id, action) = match tail.split_once('/') {
                Some((agent_id, action)) => (agent_id, action),
                None => (tail, ""),
            };
            if agent_id.is_empty() {
                return Some(AdminResponse::error(404, "not_found", "no such route"));
            }
            match (method, action) {
                ("GET", "") => match registry.get(&scope, agent_id).await {
                    Ok(view) => AdminResponse::encode(200, &view),
                    Err(error) => AdminResponse::from_refusal(&error),
                },
                ("POST", "approve") => {
                    let parsed: DecisionBody = match decode_optional(body) {
                        Ok(parsed) => parsed,
                        Err(response) => return Some(response),
                    };
                    match registry
                        .approve(
                            &scope,
                            agent_id,
                            parsed.reason,
                            actor.map(str::to_owned),
                            now,
                        )
                        .await
                    {
                        Ok(view) => AdminResponse::encode(200, &view),
                        Err(error) => AdminResponse::from_refusal(&error),
                    }
                }
                ("POST", "reject") => {
                    let parsed: DecisionBody = match decode_optional(body) {
                        Ok(parsed) => parsed,
                        Err(response) => return Some(response),
                    };
                    let Some(reason) = parsed.reason.filter(|reason| !reason.trim().is_empty())
                    else {
                        return Some(AdminResponse::error(
                            400,
                            "invalid",
                            "reject requires a reason",
                        ));
                    };
                    match registry
                        .reject(&scope, agent_id, reason, actor.map(str::to_owned), now)
                        .await
                    {
                        Ok(view) => AdminResponse::encode(200, &view),
                        Err(error) => AdminResponse::from_refusal(&error),
                    }
                }
                ("POST", "revoke") => {
                    let parsed: DecisionBody = match decode_optional(body) {
                        Ok(parsed) => parsed,
                        Err(response) => return Some(response),
                    };
                    match registry
                        .revoke(
                            &scope,
                            agent_id,
                            parsed.reason,
                            actor.map(str::to_owned),
                            now,
                        )
                        .await
                    {
                        Ok(view) => AdminResponse::encode(200, &view),
                        Err(error) => AdminResponse::from_refusal(&error),
                    }
                }
                ("POST", "rotate") => {
                    let parsed: RotateBody = match decode(body) {
                        Ok(parsed) => parsed,
                        Err(response) => return Some(response),
                    };
                    match registry
                        .rotate_secret(&scope, agent_id, &parsed.registration_access_token, now)
                        .await
                    {
                        Ok(rotated) => AdminResponse::encode(200, &rotated),
                        Err(error) => AdminResponse::from_refusal(&error),
                    }
                }
                _ => AdminResponse::error(405, "invalid", "method not allowed on this route"),
            }
        }
        _ => AdminResponse::error(404, "not_found", "no such route"),
    })
}

/// The refusal a tenant-scoped operator gets on a deployment-wide route.
fn deployment_wide_refusal(what: &str) -> AdminResponse {
    AdminResponse::error(
        403,
        "forbidden",
        &format!("the agent catalog is deployment-wide; a tenant-scoped operator cannot {what}"),
    )
}

fn parse_state_filter(query: &str) -> std::result::Result<Option<ApprovalState>, AdminResponse> {
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let Some(("state", value)) = pair.split_once('=') else {
            continue;
        };
        return match value {
            "pending" => Ok(Some(ApprovalState::Pending)),
            "approved" => Ok(Some(ApprovalState::Approved)),
            "rejected" => Ok(Some(ApprovalState::Rejected)),
            "revoked" => Ok(Some(ApprovalState::Revoked)),
            other => Err(AdminResponse::error(
                400,
                "invalid",
                &format!(
                    "unknown state filter {:?}; expected pending, approved, rejected, or revoked",
                    sanitize(other)
                ),
            )),
        };
    }
    Ok(None)
}

/// Strip anything that could forge a line in a log or a response body from a
/// caller-supplied string, and bound it.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registration::{Purpose, RequestedScope};
    use crate::service::AgentRegistryOptions;
    use sbproxy_platform::storage::{EmbeddedKvStore, MemoryKv};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).expect("fixed instant")
    }

    fn temp_path() -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!(
            "{}/sbproxy_agent_admin_test_{}_{}.redb",
            std::env::temp_dir().display(),
            std::process::id(),
            n
        )
    }

    fn registry(path: &str) -> AgentRegistry {
        let store = EmbeddedKvStore::open(path, "agent_registry").expect("open store");
        AgentRegistry::new(
            Arc::new(store),
            Arc::new(MemoryKv::new("agent_registry")),
            AgentRegistryOptions::default(),
        )
        .expect("registry")
    }

    fn register_body() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "agent_metadata": AgentMetadata {
                vendor: "Acme".into(),
                purpose: Purpose::Search,
                contact_url: "https://acme.example.com/bots".into(),
                expected_user_agents: vec!["AcmeBot/1.0".into()],
                expected_reverse_dns_suffixes: vec![],
                expected_keyids: vec![],
                requested_scopes: vec![RequestedScope::CrawlPublic],
            }
        }))
        .expect("body")
    }

    async fn call(
        registry: &AgentRegistry,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> AdminResponse {
        dispatch(registry, method, path, body, Some("casey"), None, now())
            .await
            .expect("route exists")
    }

    async fn call_as(
        registry: &AgentRegistry,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        tenant: Option<&str>,
    ) -> AdminResponse {
        dispatch(registry, method, path, body, Some("casey"), tenant, now())
            .await
            .expect("route exists")
    }

    /// A tenant-scoped operator must not be able to revoke another
    /// tenant's approved agent. The port had dropped the workspace
    /// dimension the enterprise queue scoped every operation by, and the
    /// dispatcher read only the operator's username off the principal, so
    /// a `tenant: acme` operator could revoke `globex`'s agents and the
    /// audit trail would show only that they had.
    #[tokio::test]
    async fn a_tenant_scoped_operator_cannot_reach_another_tenants_registration() {
        let path = temp_path();
        let registry = registry(&path);

        // Globex submits and is approved by a deployment-wide operator.
        let created = call_as(
            &registry,
            "POST",
            "/admin/agent-registry/registrations",
            Some(&register_body()),
            Some("globex"),
        )
        .await;
        assert_eq!(created.status, 201);
        let created: serde_json::Value = serde_json::from_str(&created.body).expect("json");
        assert_eq!(
            created["registration"]["tenant"],
            serde_json::json!("globex")
        );
        let agent_id = created["registration"]["agent_id"]
            .as_str()
            .expect("agent id")
            .to_string();
        assert_eq!(
            call_as(
                &registry,
                "POST",
                &format!("/admin/agent-registry/registrations/{agent_id}/approve"),
                None,
                Some("globex"),
            )
            .await
            .status,
            200
        );

        // Acme cannot see it, read it, or revoke it.
        let listed = call_as(
            &registry,
            "GET",
            "/admin/agent-registry/registrations",
            None,
            Some("acme"),
        )
        .await;
        assert_eq!(listed.status, 200);
        assert!(
            !listed.body.contains(&agent_id),
            "another tenant's registration must not appear in the listing: {}",
            listed.body
        );

        let read = call_as(
            &registry,
            "GET",
            &format!("/admin/agent-registry/registrations/{agent_id}"),
            None,
            Some("acme"),
        )
        .await;
        assert_eq!(
            read.status, 404,
            "and reading it is indistinguishable from absent"
        );

        let revoked = call_as(
            &registry,
            "POST",
            &format!("/admin/agent-registry/registrations/{agent_id}/revoke"),
            Some(br#"{"reason":"not mine"}"#),
            Some("acme"),
        )
        .await;
        assert_eq!(revoked.status, 404);

        // The agent is still approved, which is the property the 404 is
        // there to protect.
        let still = call_as(
            &registry,
            "GET",
            &format!("/admin/agent-registry/registrations/{agent_id}"),
            None,
            Some("globex"),
        )
        .await;
        assert_eq!(still.status, 200);
        assert!(
            still.body.contains("\"state\":\"approved\""),
            "{}",
            still.body
        );

        // A deployment-wide operator still sees everything.
        let all = call(
            &registry,
            "GET",
            "/admin/agent-registry/registrations",
            None,
        )
        .await;
        assert!(all.body.contains(&agent_id));

        std::fs::remove_file(&path).ok();
    }

    /// The catalog is one signed feed for the whole proxy, so a
    /// tenant-scoped operator is refused outright rather than handed a
    /// silently narrowed answer. That is `dispatch_ai_chargeback`'s rule
    /// and it is here for the reason that one gives: a quietly filtered
    /// result reads as a fact about the deployment.
    #[tokio::test]
    async fn a_tenant_scoped_operator_is_refused_the_deployment_wide_catalog() {
        let path = temp_path();
        let registry = registry(&path);

        let refused = call_as(
            &registry,
            "GET",
            "/admin/agent-registry/catalog",
            None,
            Some("acme"),
        )
        .await;
        assert_eq!(refused.status, 403);
        assert!(refused.body.contains("deployment-wide"), "{}", refused.body);

        let refused = call_as(
            &registry,
            "POST",
            "/admin/agent-registry/refresh",
            None,
            Some("acme"),
        )
        .await;
        assert_eq!(refused.status, 403);

        // Deployment-wide operators are not refused.
        assert_eq!(
            call(&registry, "GET", "/admin/agent-registry/catalog", None)
                .await
                .status,
            200
        );

        // The summary is allowed for both and says which scope it covers.
        let scoped = call_as(
            &registry,
            "GET",
            "/admin/agent-registry",
            None,
            Some("acme"),
        )
        .await;
        assert_eq!(scoped.status, 200);
        assert!(
            scoped.body.contains("\"scope\":\"acme\""),
            "{}",
            scoped.body
        );
        assert!(
            scoped.body.contains("\"catalog_writable\":false"),
            "{}",
            scoped.body
        );

        let global = call(&registry, "GET", "/admin/agent-registry", None).await;
        assert!(global.body.contains("\"scope\":\"all\""), "{}", global.body);
        assert!(
            global.body.contains("\"catalog_writable\":true"),
            "{}",
            global.body
        );

        std::fs::remove_file(&path).ok();
    }

    /// One tenant's refusal must not refuse another tenant's identical
    /// description: the durable replay index is keyed per tenant.
    #[tokio::test]
    async fn a_refusal_in_one_tenant_does_not_burn_another_tenants_description() {
        let path = temp_path();
        let registry = registry(&path);

        let created = call_as(
            &registry,
            "POST",
            "/admin/agent-registry/registrations",
            Some(&register_body()),
            Some("acme"),
        )
        .await;
        let created: serde_json::Value = serde_json::from_str(&created.body).expect("json");
        let agent_id = created["registration"]["agent_id"].as_str().expect("id");
        assert_eq!(
            call_as(
                &registry,
                "POST",
                &format!("/admin/agent-registry/registrations/{agent_id}/reject"),
                Some(br#"{"reason":"no"}"#),
                Some("acme"),
            )
            .await
            .status,
            200
        );

        // Acme is refused for good; globex is not.
        assert_eq!(
            call_as(
                &registry,
                "POST",
                "/admin/agent-registry/registrations",
                Some(&register_body()),
                Some("acme"),
            )
            .await
            .status,
            409
        );
        assert_eq!(
            call_as(
                &registry,
                "POST",
                "/admin/agent-registry/registrations",
                Some(&register_body()),
                Some("globex"),
            )
            .await
            .status,
            201
        );

        std::fs::remove_file(&path).ok();
    }

    /// The seam this whole surface hangs off: a path outside the prefix has
    /// to fall through so the core router keeps working, and a path inside
    /// it must never fall through to a 404 the core would answer instead.
    #[tokio::test]
    async fn only_this_prefix_is_claimed() {
        let path = temp_path();
        let registry = registry(&path);
        assert!(
            dispatch(&registry, "GET", "/admin/keys", None, None, None, now())
                .await
                .is_none(),
            "an unrelated admin route must fall through"
        );
        assert!(
            dispatch(
                &registry,
                "GET",
                "/admin/agent-registry/nope",
                None,
                None,
                None,
                now()
            )
            .await
            .is_some(),
            "an unknown route under the prefix is this surface's 404, not the core's"
        );
        std::fs::remove_file(&path).ok();
    }

    /// A full life through the HTTP surface, which is the thing that
    /// regresses: the queue can be perfect and the routes still wrong.
    #[tokio::test]
    async fn a_registration_can_be_submitted_listed_approved_and_revoked_over_the_routes() {
        let path = temp_path();
        let registry = registry(&path);

        let created = call(
            &registry,
            "POST",
            "/admin/agent-registry/registrations",
            Some(&register_body()),
        )
        .await;
        assert_eq!(created.status, 201);
        let created: serde_json::Value = serde_json::from_str(&created.body).expect("json");
        let agent_id = created["registration"]["agent_id"]
            .as_str()
            .expect("agent id")
            .to_string();
        let token = created["secrets"]["registration_access_token"]
            .as_str()
            .expect("token")
            .to_string();

        let listed = call(
            &registry,
            "GET",
            "/admin/agent-registry/registrations?state=pending",
            None,
        )
        .await;
        assert_eq!(listed.status, 200);
        assert!(listed.body.contains(&agent_id));
        assert!(
            !listed.body.contains("client_secret"),
            "a listing must not carry credential material"
        );

        // Reject demands a reason; approve does not.
        let refused = call(
            &registry,
            "POST",
            &format!("/admin/agent-registry/registrations/{agent_id}/reject"),
            Some(b"{}"),
        )
        .await;
        assert_eq!(refused.status, 400);

        let approved = call(
            &registry,
            "POST",
            &format!("/admin/agent-registry/registrations/{agent_id}/approve"),
            None,
        )
        .await;
        assert_eq!(approved.status, 200);
        assert!(approved.body.contains("\"decided_by\":\"casey\""));

        let rotated = call(
            &registry,
            "POST",
            &format!("/admin/agent-registry/registrations/{agent_id}/rotate"),
            Some(
                serde_json::to_vec(&serde_json::json!({"registration_access_token": token}))
                    .expect("body")
                    .as_slice(),
            ),
        )
        .await;
        assert_eq!(rotated.status, 200);

        let revoked = call(
            &registry,
            "POST",
            &format!("/admin/agent-registry/registrations/{agent_id}/revoke"),
            Some(br#"{"reason":"withdrawn"}"#),
        )
        .await;
        assert_eq!(revoked.status, 200);

        // A second approval of a terminal registration is refused, and the
        // refusal carries the vocabulary an operator scripts against.
        let again = call(
            &registry,
            "POST",
            &format!("/admin/agent-registry/registrations/{agent_id}/approve"),
            None,
        )
        .await;
        assert_eq!(again.status, 422);
        assert!(again.body.contains("invalid_transition"));

        std::fs::remove_file(&path).ok();
    }

    /// A rotation presented without the submitter's token is a 401 whether
    /// or not the registration exists, so the route is not an oracle.
    #[tokio::test]
    async fn rotation_over_the_route_needs_the_submitters_own_token() {
        let path = temp_path();
        let registry = registry(&path);
        let created = call(
            &registry,
            "POST",
            "/admin/agent-registry/registrations",
            Some(&register_body()),
        )
        .await;
        let created: serde_json::Value = serde_json::from_str(&created.body).expect("json");
        let agent_id = created["registration"]["agent_id"].as_str().expect("id");

        let wrong = call(
            &registry,
            "POST",
            &format!("/admin/agent-registry/registrations/{agent_id}/rotate"),
            Some(br#"{"registration_access_token":"rat_wrong"}"#),
        )
        .await;
        assert_eq!(wrong.status, 401);

        let missing = call(
            &registry,
            "POST",
            "/admin/agent-registry/registrations/no-such-agent/rotate",
            Some(br#"{"registration_access_token":"rat_wrong"}"#),
        )
        .await;
        assert_eq!(
            missing.status, 401,
            "an unknown id must answer exactly as a wrong token does"
        );
        assert_eq!(wrong.body, missing.body);

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn a_bad_state_filter_is_refused_rather_than_ignored() {
        let path = temp_path();
        let registry = registry(&path);
        let response = call(
            &registry,
            "GET",
            "/admin/agent-registry/registrations?state=pendign",
            None,
        )
        .await;
        assert_eq!(response.status, 400);
        assert!(response.body.contains("pendign"));

        // A control character in the filter cannot forge a line.
        let response = call(
            &registry,
            "GET",
            "/admin/agent-registry/registrations?state=a%0Ab",
            None,
        )
        .await;
        assert_eq!(response.status, 400);
        assert!(!response.body.contains('\n'));

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn the_summary_route_answers_without_a_configured_feed() {
        let path = temp_path();
        let registry = registry(&path);
        let response = call(&registry, "GET", "/admin/agent-registry", None).await;
        assert_eq!(response.status, 200);
        let summary: serde_json::Value = serde_json::from_str(&response.body).expect("json");
        assert_eq!(summary["feed_configured"], serde_json::json!(false));
        assert_eq!(summary["bootstrap_keys"], serde_json::json!(0));

        let refresh = call(&registry, "POST", "/admin/agent-registry/refresh", None).await;
        assert_eq!(refresh.status, 400);
        std::fs::remove_file(&path).ok();
    }
}

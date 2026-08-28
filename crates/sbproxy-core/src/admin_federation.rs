//! OpenID Federation operator surface (`GET /admin/federation`).
//!
//! `sbproxy-federation` ships its own `GET /admin/status` for a host
//! that embeds the crate's axum router. sbproxy is not that host: it
//! serves the well-known route from the Pingora request path, so the
//! crate's route is never mounted and an operator running
//! `proxy.federation` had no way to ask what the proxy is publishing
//! short of decoding the signed JWS by hand.
//!
//! This is the same JSON, under the proxy's own authenticated admin
//! API. It is behind the operator-auth gate rather than
//! unauthenticated, because the peer-trust half of the response (which
//! anchors are pinned, how many peers are cached) is operational state
//! rather than something the entity configuration already publishes.
//!
//! A console page for this is separate scope, under the admin console
//! epic; `docs/admin-api-reference.md` says so beside the route.

use serde_json::json;

/// Response tuple shared by the admin dispatchers.
type Resp = (u16, &'static str, String);

/// Dispatch `/admin/federation`. Returns `None` for paths this module
/// does not own so the caller falls through to the next dispatcher.
pub fn dispatch(method: &str, path: &str) -> Option<Resp> {
    let path_only = path.split('?').next().unwrap_or(path);
    match path_only {
        "/admin/federation" if method.eq_ignore_ascii_case("GET") => Some(status()),
        "/admin/federation" => Some((
            405,
            "application/json",
            r#"{"error":"method not allowed"}"#.to_string(),
        )),
        _ => None,
    }
}

/// `GET /admin/federation`: what this proxy publishes as its entity
/// configuration, and what it requires of a peer.
fn status() -> Resp {
    let pipeline = crate::reload::current_pipeline();
    let Some(issuer) = pipeline.federation_issuer.as_ref() else {
        return (
            200,
            "application/json",
            json!({ "enabled": false }).to_string(),
        );
    };
    let config = issuer.config();
    // A failure here is the same failure the well-known route answers
    // 503 with. Reporting `null` rather than a 500 keeps the rest of
    // the response, which is the static configuration an operator is
    // usually here to check, available while it is broken.
    let cache_remaining_secs = issuer
        .current()
        .ok()
        .map(|document| document.cache_max_age_secs(chrono::Utc::now()));
    let peer_trust = match pipeline.federation_peer_verifier.as_ref() {
        Some(verifier) => json!({
            "configured": true,
            "required": verifier.required(),
            "header": verifier.header(),
            "pinned_anchors": verifier.anchor_count(),
            "cached_peer_decisions": verifier.cached_peers(),
        }),
        None => json!({ "configured": false }),
    };
    (
        200,
        "application/json",
        json!({
            "enabled": true,
            "entity_id": config.entity_id,
            "signing_algorithm": format!("{:?}", config.signing_key.algorithm),
            "signing_kid": config.signing_key.kid,
            "published_keys": config.published_jwks.keys.len(),
            "authority_hints": config.authority_hints.len(),
            "trust_marks": config.trust_marks.len(),
            "metadata_policy_configured": config.metadata_policy.is_some(),
            "lifetime_secs": config.lifetime.as_secs(),
            "refresh_margin_secs": config.refresh_margin.as_secs(),
            "cache_remaining_secs": cache_remaining_secs,
            "peer_trust": peer_trust,
        })
        .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_process_without_the_block_reports_disabled_rather_than_404() {
        // The default test pipeline configures no federation identity.
        // An operator polling the route needs "off", not a 404 they
        // have to tell apart from a typo in the path.
        let (status_code, _, body) = dispatch("GET", "/admin/federation").expect("route is owned");
        assert_eq!(status_code, 200);
        assert!(body.contains("\"enabled\":false"), "{body}");
    }

    #[test]
    fn other_methods_and_paths_are_not_claimed_as_success() {
        assert_eq!(
            dispatch("POST", "/admin/federation").map(|(status, _, _)| status),
            Some(405)
        );
        assert!(dispatch("GET", "/admin/cache").is_none());
    }
}

//! CoMP marketplace operator surface (`GET /admin/licensing`).
//!
//! `sbproxy-licensing` ships its own `GET /admin/status` for a host
//! that mounts the crate's axum router. sbproxy is not that host: it
//! serves `/.well-known/iab-comp/*` from the Pingora request path, so
//! the crate's route is never mounted and an operator running `comp:`
//! had no way to ask what the proxy is publishing short of fetching
//! the manifest as a buyer would and counting tiers by hand.
//!
//! This is the same field set, per origin, under the proxy's own
//! authenticated admin API. Behind the operator-auth gate rather than
//! unauthenticated: the manifest half of the answer is already public,
//! but which origins have a bridge configured at all, and whether a
//! rotation has been activated, is operational state a publisher has
//! not published.
//!
//! No secret and no license payload appears here. The signing key is
//! named by its `kid`, never by its material, and no token this bridge
//! has minted is retained anywhere this route can read.
//!
//! A console page for this is separate scope, under the admin console
//! epic; `docs/admin-api-reference.md` says so beside the route.

use serde_json::json;

/// Response tuple shared by the admin dispatchers.
type Resp = (u16, &'static str, String);

/// Dispatch `/admin/licensing`. Returns `None` for paths this module
/// does not own so the caller falls through to the next dispatcher.
pub fn dispatch(method: &str, path: &str) -> Option<Resp> {
    let path_only = path.split('?').next().unwrap_or(path);
    match path_only {
        "/admin/licensing" if method.eq_ignore_ascii_case("GET") => Some(status()),
        "/admin/licensing" => Some((
            405,
            "application/json",
            r#"{"error":"method not allowed"}"#.to_string(),
        )),
        _ => None,
    }
}

/// `GET /admin/licensing`: every origin with a CoMP marketplace
/// bridge, what its manifest publishes, and which quote-signing key is
/// live.
fn status() -> Resp {
    let pipeline = crate::reload::current_pipeline();
    let mut origins = Vec::new();
    for (index, origin) in pipeline.config.origins.iter().enumerate() {
        let Some(marketplace) = pipeline
            .comp_marketplaces
            .get(index)
            .and_then(Option::as_ref)
        else {
            continue;
        };
        let report = sbproxy_licensing::admin::StatusResponse::of(marketplace);
        let manifest = marketplace.manifest();
        origins.push(json!({
            "hostname": origin.hostname.as_str(),
            "publisher_domain": report.publisher_domain,
            "publisher_name": manifest.publisher.name,
            "tier_count": report.tier_count,
            // The two counts differ whenever a catalog carries `cap` or
            // `public` tiers, and only the OLP ones can be redeemed for
            // a token. An operator reading "12 tiers" and seeing one
            // redeem a day wants to know that eleven of them were never
            // redeemable.
            "olp_tier_count": manifest
                .tiers
                .iter()
                .filter(|tier| {
                    matches!(
                        tier.authorization,
                        sbproxy_licensing::comp::CompAuthorization::Olp
                    )
                })
                .count(),
            // `null` means no rotation has been activated, and every
            // quote request fails closed until one is. That is worth
            // being able to see without reading a rejection rate.
            "active_signing_kid": report.active_signing_kid,
            "trusted_kid_count": report.trusted_kid_count,
            "manifest_hash": manifest.manifest_hash,
            "generated_at": manifest.generated_at,
            "endpoints": {
                "manifest": manifest.endpoints.manifest,
                "quote": manifest.endpoints.quote,
                "redeem": manifest.endpoints.redeem,
            },
        }));
    }
    (
        200,
        "application/json",
        json!({
            "enabled": !origins.is_empty(),
            "origins": origins,
        })
        .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_process_without_the_block_reports_disabled_rather_than_404() {
        // The default test pipeline configures no marketplace. An
        // operator polling the route needs "off", not a 404 they have
        // to tell apart from a typo in the path.
        let (status_code, _, body) = dispatch("GET", "/admin/licensing").expect("route is owned");
        assert_eq!(status_code, 200);
        assert!(body.contains("\"enabled\":false"), "{body}");
        assert!(body.contains("\"origins\":[]"), "{body}");
    }

    #[test]
    fn other_methods_and_paths_are_not_claimed_as_success() {
        assert_eq!(
            dispatch("POST", "/admin/licensing").map(|(status, _, _)| status),
            Some(405)
        );
        assert!(dispatch("GET", "/admin/federation").is_none());
    }
}

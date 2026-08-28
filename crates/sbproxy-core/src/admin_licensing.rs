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

/// Project one origin's `olp:` block, or `null` when it has none.
///
/// The OLP issuer mints the same bearer license tokens the CoMP bridge
/// hands back, and until WOR-2673 it had no operator surface at all: an
/// operator could not ask which kid is signing, what issuer the tokens
/// claim, how long they live, or whether the RFC 7662 / RFC 7009 pair
/// is even mounted, short of minting one and decoding it.
///
/// Config-derived and read-only. The signing key is named by its `kid`,
/// never by its material, and no minted token is retained anywhere this
/// can read.
fn olp_report(origin: &sbproxy_config::CompiledOrigin) -> serde_json::Value {
    let Some(olp) = origin.olp.as_ref().filter(|olp| olp.enabled) else {
        return json!({ "enabled": false });
    };
    let introspect = match olp.introspect.as_ref().filter(|cfg| cfg.enabled) {
        Some(cfg) => json!({
            "enabled": true,
            "introspect_path": cfg.introspect_path,
            "revoke_path": cfg.revoke_path,
            // Which store answers "is this jti revoked" is the field an
            // operator needs when a revocation did not take on the
            // replica they are looking at. The variant name only: the
            // `redb` path and especially the `redis` URL are operator
            // configuration, and a Redis URL routinely carries a
            // password in its userinfo.
            "revocation_store": match cfg.revocation_store {
                sbproxy_config::OlpRevocationStoreConfig::Memory => "memory",
                sbproxy_config::OlpRevocationStoreConfig::Redb { .. } => "redb",
                sbproxy_config::OlpRevocationStoreConfig::Redis { .. } => "redis",
            },
        }),
        None => json!({ "enabled": false }),
    };
    json!({
        "enabled": true,
        "signing_kid": olp.key_id,
        "issuer": olp.issuer,
        "default_scope": olp.default_scope,
        "default_ttl_secs": olp.default_ttl_secs,
        // Whether the Encrypted Media Standard content-key claim is
        // stamped on issued tokens. The seed itself never appears.
        "content_key_configured": olp.content_key_seed.is_some(),
        "introspect": introspect,
    })
}

/// `GET /admin/licensing`: every origin with a CoMP marketplace bridge
/// or an OLP issuer, what each publishes, and which keys are live.
fn status() -> Resp {
    let pipeline = crate::reload::current_pipeline();
    let mut origins = Vec::new();
    for (index, origin) in pipeline.config.origins.iter().enumerate() {
        let marketplace = pipeline
            .comp_marketplaces
            .get(index)
            .and_then(Option::as_ref);
        let olp = olp_report(origin);
        // An origin with neither is not a licensing origin and would
        // only pad the list. One with an OLP issuer and no bridge is:
        // it mints license tokens, which is the thing this route is for.
        if marketplace.is_none() && olp["enabled"] != true {
            continue;
        }
        let Some(marketplace) = marketplace else {
            origins.push(json!({
                "hostname": origin.hostname.as_str(),
                "comp": { "enabled": false },
                "olp": olp,
            }));
            continue;
        };
        let report = sbproxy_licensing::admin::StatusResponse::of(marketplace);
        let manifest = marketplace.manifest();
        origins.push(json!({
            "hostname": origin.hostname.as_str(),
            "olp": olp,
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

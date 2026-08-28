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
fn olp_report(olp: Option<&sbproxy_config::OlpConfig>) -> serde_json::Value {
    let Some(olp) = olp.filter(|olp| olp.enabled) else {
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

/// Project one origin's licensing state, or `None` when it has
/// neither a CoMP bridge nor an OLP issuer.
///
/// Its own function rather than a branch inside [`status`] so the shape
/// is testable without installing a process-global pipeline. The two
/// halves are symmetric on purpose (WOR-2673 re-review N2): `comp` and
/// `olp` are both always present and both always carry `enabled`, so a
/// consumer reads one field to answer "does this origin have a bridge"
/// rather than telling `false` apart from a key that is not there.
/// The previous shape emitted `comp` only on the branch that had *no*
/// bridge, which under any truthiness check made a bridged origin read
/// as unbridged.
fn origin_report(
    hostname: &str,
    olp: Option<&sbproxy_config::OlpConfig>,
    marketplace: Option<&std::sync::Arc<sbproxy_licensing::comp::CompMarketplace>>,
) -> Option<serde_json::Value> {
    let olp = olp_report(olp);
    // An origin with neither is not a licensing origin and would only
    // pad the list. One with an OLP issuer and no bridge is: it mints
    // license tokens, which is the thing this route is for.
    let Some(marketplace) = marketplace else {
        if olp["enabled"] != true {
            return None;
        }
        return Some(json!({
            "hostname": hostname,
            "comp": { "enabled": false },
            "olp": olp,
        }));
    };
    let report = sbproxy_licensing::admin::StatusResponse::of(marketplace);
    let manifest = marketplace.manifest();
    Some(json!({
        "hostname": hostname,
        "comp": {
            "enabled": true,
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
        },
        "olp": olp,
    }))
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
        if let Some(report) =
            origin_report(origin.hostname.as_str(), origin.olp.as_ref(), marketplace)
        {
            origins.push(report);
        }
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

    /// A marketplace with one OLP tier and one `cap` tier, so the two
    /// counts this route reports differ and a test can tell them apart.
    fn marketplace() -> std::sync::Arc<sbproxy_licensing::comp::CompMarketplace> {
        use sbproxy_licensing::comp::{
            CompAuthorization, CompEndpoints, CompManifest, CompMarketplace, CompPricing,
            CompPricingModel, CompPublisher, CompTier, InMemoryBuyerKeyRegistry, OlpBridgeSigner,
            COMP_VERSION,
        };
        use sbproxy_licensing::keys::{KeyManager, MasterKey};
        use sbproxy_licensing::revocation::{InMemoryRevocation, Revocation};
        use std::sync::Arc;

        let keys = KeyManager::new(MasterKey::new(vec![0x61u8; 32]).expect("32-byte key"));
        keys.set_active("2026-q3-001").expect("derive");
        let tier = |id: &str, authorization| CompTier {
            id: id.into(),
            name: id.into(),
            description: "a tier".into(),
            license: format!("urn:rsl:{id}:default"),
            shape: "json-envelope".into(),
            pricing: CompPricing {
                model: CompPricingModel::PerRequest,
                currency: "USD".into(),
                amount: None,
                amount_micros: Some(2500),
            },
            authorization,
            rate_caps: None,
            route_glob: "/**".into(),
        };
        let manifest = Arc::new(CompManifest {
            comp_version: COMP_VERSION.into(),
            publisher: CompPublisher {
                name: "Example Publishing Co.".into(),
                domain: "licensing.test".into(),
                contact: "licensing@example.test".into(),
                verified_at: None,
            },
            tiers: vec![
                tier("tier_search", CompAuthorization::Cap),
                tier("tier_inference", CompAuthorization::Olp),
            ],
            endpoints: CompEndpoints {
                manifest: "https://licensing.test/.well-known/iab-comp/manifest.json".into(),
                quote: "https://licensing.test/.well-known/iab-comp/quote".into(),
                redeem: "https://licensing.test/.well-known/iab-comp/redeem".into(),
            },
            robots_url: "https://licensing.test/robots.txt".into(),
            llms_url: "https://licensing.test/llms.txt".into(),
            rsl_url: "https://licensing.test/licenses.xml".into(),
            generated_at: "2026-08-28T00:00:00Z".into(),
            manifest_hash: "sha256:fixture".into(),
        });
        let revocation: Arc<dyn Revocation> = Arc::new(InMemoryRevocation::new());
        let bridge = Arc::new(OlpBridgeSigner::new(
            [0x62u8; 32],
            "olp-2026-q3",
            "https://licensing.test",
            "ai-input",
            3600,
        ));
        Arc::new(CompMarketplace::new(
            keys,
            manifest,
            revocation,
            bridge,
            Arc::new(InMemoryBuyerKeyRegistry::new()),
        ))
    }

    /// An enabled OLP block, with the introspect pair off.
    fn olp_config() -> sbproxy_config::OlpConfig {
        serde_json::from_value(serde_json::json!({
            "enabled": true,
            "signing_key": "1122334455667788990011223344556677889900112233445566778899001122",
            "key_id": "2026-q3",
            "issuer": "https://licensing.test",
        }))
        .expect("olp fixture parses")
    }

    /// WOR-2673 re-review N2: `comp.enabled` is present on both
    /// branches, so one field answers "does this origin have a bridge".
    ///
    /// The previous shape emitted `comp` only where there was no
    /// bridge, and put the bridge's own fields flat at the origin
    /// level. A consumer reading `origin.comp.enabled`, which is the
    /// only shape the route ever presented for that field and the one
    /// `docs/admin-api-reference.md` invites, got `false` without a
    /// bridge and `undefined` with one. Under any truthiness check
    /// those are the same answer and it is the wrong one.
    #[test]
    fn comp_enabled_is_present_on_both_branches() {
        let bridged = origin_report("licensing.test", Some(&olp_config()), Some(&marketplace()))
            .expect("an origin with a bridge is reported");
        assert_eq!(
            bridged["comp"]["enabled"], true,
            "a bridged origin must say so under the same key as an unbridged one: {bridged}"
        );

        let issuer_only = origin_report("issuer.test", Some(&olp_config()), None)
            .expect("an origin with only an OLP issuer is reported");
        assert_eq!(issuer_only["comp"]["enabled"], false, "{issuer_only}");

        // The symmetry the fix is for: both keys present on both
        // branches, so neither is `undefined` on either.
        for report in [&bridged, &issuer_only] {
            assert!(report["comp"].is_object(), "{report}");
            assert!(report["olp"].is_object(), "{report}");
            assert!(report["comp"]["enabled"].is_boolean(), "{report}");
            assert!(report["olp"]["enabled"].is_boolean(), "{report}");
        }
    }

    /// The bridge's own fields live under `comp`, not flat at the
    /// origin level, so the two halves nest the same way.
    #[test]
    fn the_bridge_fields_are_nested_under_comp() {
        let report = origin_report("licensing.test", Some(&olp_config()), Some(&marketplace()))
            .expect("reported");
        let comp = &report["comp"];
        assert_eq!(comp["publisher_domain"], "licensing.test", "{report}");
        assert_eq!(comp["publisher_name"], "Example Publishing Co.", "{report}");
        // Two tiers, one of them redeemable. An operator reading a tier
        // count and a redeem rate needs the difference.
        assert_eq!(comp["tier_count"], 2, "{report}");
        assert_eq!(comp["olp_tier_count"], 1, "{report}");
        assert_eq!(comp["active_signing_kid"], "comp-2026-q3-001", "{report}");
        assert_eq!(comp["trusted_kid_count"], 1, "{report}");
        assert_eq!(
            comp["endpoints"]["redeem"], "https://licensing.test/.well-known/iab-comp/redeem",
            "{report}"
        );
        assert!(
            report.get("publisher_domain").is_none(),
            "the flat spelling must be gone, or a consumer reads both: {report}"
        );
    }

    /// An origin with neither is not a licensing origin and does not
    /// pad the list.
    #[test]
    fn an_origin_with_neither_is_not_reported() {
        assert!(origin_report("plain.test", None, None).is_none());
        let disabled: sbproxy_config::OlpConfig = serde_json::from_value(serde_json::json!({
            "enabled": false,
            "signing_key": "1122334455667788990011223344556677889900112233445566778899001122",
            "key_id": "2026-q3",
            "issuer": "https://licensing.test",
        }))
        .expect("olp fixture parses");
        assert!(origin_report("plain.test", Some(&disabled), None).is_none());
    }

    /// No key material on either branch. The signing key is named by
    /// its kid, the EMS seed is reduced to a boolean, and the
    /// revocation store to its variant name.
    #[test]
    fn no_key_material_reaches_either_branch() {
        const SEED: &str = "1122334455667788990011223344556677889900112233445566778899001122";
        let mut olp = olp_config();
        olp.content_key_seed = Some(SEED.to_string());
        let report =
            origin_report("licensing.test", Some(&olp), Some(&marketplace())).expect("reported");
        let rendered = report.to_string();
        assert!(
            !rendered.contains(SEED),
            "a seed reached the route: {rendered}"
        );
        assert_eq!(report["olp"]["signing_kid"], "2026-q3", "{report}");
        assert_eq!(report["olp"]["content_key_configured"], true, "{report}");
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

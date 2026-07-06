//! Admin cache manager (WOR-1754 / WOR-1755).
//!
//! Two operator surfaces mounted on the admin server:
//!
//! - Response cache: `GET /admin/cache` reports whether caching is
//!   enabled and which backend serves it, and `POST /admin/cache/purge`
//!   evicts entries (all, by key, or by prefix).
//! - Dynamic key-policy cache: `POST /admin/cache/key-policy/evict`
//!   drops a key's cached policy (or all of them) so the next request
//!   re-reads the keystore; on the Redis tier this fans the invalidation
//!   out to the fleet.
//!
//! Routing mirrors the other `admin_*` dispatchers; the RBAC + CSRF gate
//! in the connection handler runs before these POSTs, so purge/evict are
//! already restricted to the `admin` role.

use serde_json::json;

/// Response tuple shared by the admin dispatchers.
type Resp = (u16, &'static str, String);

/// Dispatch `/admin/cache*` routes. Returns `None` for paths this module
/// does not own so the caller falls through to the next dispatcher.
pub fn dispatch(method: &str, path: &str, body: Option<&str>) -> Option<Resp> {
    let path_only = path.split('?').next().unwrap_or(path);
    match path_only {
        "/admin/cache" if method.eq_ignore_ascii_case("GET") => Some(cache_stats()),
        "/admin/cache/purge" if method.eq_ignore_ascii_case("POST") => Some(cache_purge(body)),
        "/admin/cache/key-policy/evict" if method.eq_ignore_ascii_case("POST") => {
            Some(key_policy_evict(body))
        }
        _ => None,
    }
}

/// `GET /admin/cache`: response-cache status. `enabled` is false when no
/// origin turned on response caching (the pipeline holds no backend).
fn cache_stats() -> Resp {
    let store = crate::reload::current_pipeline().cache_store.clone();
    let body = match store {
        Some(s) => {
            let backend = s.backend_name();
            // Prefix purge needs a key scan; only memory and redis support
            // it (file hashes keys into filenames, memcached has no scan).
            let prefix_purge = matches!(backend, "memory" | "redis");
            json!({
                "enabled": true,
                "backend": backend,
                "prefix_purge_supported": prefix_purge,
            })
        }
        None => json!({ "enabled": false }),
    };
    (200, "application/json", body.to_string())
}

/// `POST /admin/cache/purge`: evict response-cache entries. Body selects
/// the scope: `{"key": "..."}` deletes one entry, `{"prefix": "..."}`
/// deletes a prefix, and an empty body clears everything.
fn cache_purge(body: Option<&str>) -> Resp {
    let store = match crate::reload::current_pipeline().cache_store.clone() {
        Some(s) => s,
        None => {
            return (
                409,
                "application/json",
                r#"{"error":"response cache not enabled"}"#.to_string(),
            )
        }
    };
    let parsed: serde_json::Value = body
        .and_then(|b| serde_json::from_str(b).ok())
        .unwrap_or_else(|| json!({}));
    let key = parsed.get("key").and_then(|v| v.as_str());
    let prefix = parsed.get("prefix").and_then(|v| v.as_str());

    let outcome = if let Some(k) = key {
        store
            .delete(k)
            .map(|_| json!({ "purged": "key", "key": k }))
    } else if let Some(p) = prefix {
        store
            .delete_prefix(p)
            .map(|n| json!({ "purged": "prefix", "prefix": p, "removed": n }))
    } else {
        store.clear().map(|_| json!({ "purged": "all" }))
    };
    match outcome {
        Ok(v) => (200, "application/json", v.to_string()),
        Err(e) => (
            500,
            "application/json",
            format!(
                r#"{{"error":"purge failed: {}"}}"#,
                e.to_string().replace('"', "'")
            ),
        ),
    }
}

/// `POST /admin/cache/key-policy/evict`: drop a key's cached policy so the
/// next request re-reads the keystore. Body `{"id": "..."}` evicts one
/// key; an empty body evicts all. On the Redis keystore tier this
/// publishes the invalidation to every replica.
fn key_policy_evict(body: Option<&str>) -> Resp {
    let plane = match crate::key_plane::current_key_plane() {
        Some(p) => p,
        None => {
            return (
                409,
                "application/json",
                r#"{"error":"dynamic key plane not enabled"}"#.to_string(),
            )
        }
    };
    let parsed: serde_json::Value = body
        .and_then(|b| serde_json::from_str(b).ok())
        .unwrap_or_else(|| json!({}));
    let cache = plane.cache().clone();
    match parsed.get("id").and_then(|v| v.as_str()) {
        Some(id) => {
            let owned = id.to_string();
            crate::key_plane::block_on_keystore(async move { cache.invalidate(&owned).await });
            (
                200,
                "application/json",
                json!({ "evicted": id }).to_string(),
            )
        }
        None => {
            crate::key_plane::block_on_keystore(async move { cache.invalidate_all().await });
            (
                200,
                "application/json",
                json!({ "evicted": "all" }).to_string(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_ignores_unowned_paths() {
        assert!(dispatch("GET", "/admin/keys", None).is_none());
        assert!(dispatch("POST", "/api/requests", None).is_none());
    }

    #[test]
    fn cache_stats_reports_disabled_without_backend() {
        // The default test pipeline has no response cache configured.
        let (status, _, body) = cache_stats();
        assert_eq!(status, 200);
        assert!(body.contains("\"enabled\":false"));
    }

    #[test]
    fn purge_without_cache_is_409() {
        let (status, _, body) = cache_purge(None);
        assert_eq!(status, 409);
        assert!(body.contains("not enabled"));
    }
}

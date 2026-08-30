//! WOR-1553: the admin key/credential lifecycle REST API.
//!
//! Mounted in the existing `/admin` server (shared bind + basic auth). Routes:
//!
//! ```text
//! POST   /admin/keys                      mint a key (plaintext token shown once)
//! GET    /admin/keys                      list keys (no secrets)
//! GET    /admin/keys/policy-schema        fetch the server-driven policy contract
//! GET    /admin/keys/{id}                 fetch one key
//! GET    /admin/keys/{id}/usage           fetch governed usage and backend health
//! POST   /admin/keys/{id}/effective-policy/preview
//!                                            evaluate policy without dispatch or reserve
//! PATCH  /admin/keys/{id}                 update policy/attribution
//! DELETE /admin/keys/{id}                 delete a key
//! POST   /admin/keys/{id}/revoke          mark revoked (terminal)
//! POST   /admin/keys/{id}/block           mark blocked
//! POST   /admin/keys/{id}/unblock         mark active
//! POST   /admin/keys/{id}/rotate          rotate (see admin rotation, WOR-1554)
//! POST   /admin/credentials               create an upstream credential
//! GET    /admin/credentials               list credentials (no secrets)
//! GET    /admin/credentials/{id}          fetch one credential
//! PATCH  /admin/credentials/{id}          update credential metadata
//! DELETE /admin/credentials/{id}          delete a credential
//! POST   /admin/credentials/{id}/revoke|block|unblock
//! POST   /admin/credentials/{id}/rotate  rotate with a graced overlap (WOR-2567)
//! POST   /admin/break-glass               request an emergency grant (WOR-2573)
//! GET    /admin/break-glass               list grants and the review queue
//! POST   /admin/break-glass/{id}/approve  approve, toward the quorum
//! POST   /admin/break-glass/{id}/review   record the post-access review
//! GET    /admin/crypto/root-of-trust      root-of-trust mode and liveness (WOR-2568)
//! ```
//!
//! The three routes added in WOR-2568 and WOR-2573 are JSON only. A
//! console page for the break-glass request/approve/review flow and for
//! the root-of-trust panel is deferred to WOR-2574, which owns the admin
//! console; these routes are what that page reads and are complete on
//! their own for an operator with curl.
//!
//! Every mutation goes through the store then invalidates the cache so the
//! change takes effect on the next request without a reload. Responses never
//! carry a hash, an envelope, or plaintext (apart from the one-time minted
//! token on create).
//!
//! When that invalidation cannot reach the shared cache tier, the mutation
//! still landed but the rest of the fleet has not heard about it. The 2xx
//! response then carries a `cache_propagation` object saying so, and
//! `sbproxy_key_cache_invalidation_failures_total` counts it. Reporting a
//! clean revoke while every peer keeps accepting the key is the failure this
//! exists to prevent.

use std::cell::RefCell;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::key_plane::{block_on_keystore, current_key_plane, KeyPlane};
use sbproxy_ai::governance::{GovernanceError, GovernanceLimits, SnapshotKey};
use sbproxy_keystore::record::{
    BudgetOverride, CredentialMaterial, CredentialRecord, KeyRecord, LeasePlatform, RecordBudget,
    RecordStatus,
};
use sbproxy_keystore::KeyPolicyCasResult;

type Resp = (u16, &'static str, String);

thread_local! {
    /// Set by [`invalidate`] when a cache-tier invalidation did not
    /// propagate; drained by [`dispatch`] into the response body.
    ///
    /// A thread-local rather than a return value because twelve handlers
    /// call `invalidate` and each builds its own response. Threading a
    /// `Result` through all of them puts the reporting back in the hands
    /// of whichever handler someone writes next, which is exactly how the
    /// failure went unreported in the first place; folding it in at the
    /// one dispatch seam covers every route in this module, including the
    /// ones that do not exist yet.
    ///
    /// Same-thread by construction: `dispatch` is synchronous and
    /// `block_on_keystore` runs its future on a scoped thread it joins
    /// before returning, so nothing here crosses a thread or an await.
    static PROPAGATION_FAILURE: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Route entry point. Returns `Some(response)` for paths this module owns and
/// `None` so the caller can fall through to the rest of the admin dispatcher.
pub fn dispatch(method: &str, path: &str, body: Option<&str>) -> Option<Resp> {
    // Cleared on the way in as well as drained on the way out. The drain
    // below is a `take`, so today nothing can be left behind; the clear is
    // here because the admin listener reuses threads across requests, so
    // the cost of that invariant being wrong once is a propagation failure
    // reported against a later, unrelated key mutation on the same thread.
    // `admin_cache`'s evict routes invalidate too, but they answer 502
    // directly and never write this slot.
    PROPAGATION_FAILURE.with(|slot| *slot.borrow_mut() = None);
    let resp = route(method, path, body)?;
    Some(with_propagation_warning(resp))
}

/// Fold a failed cache-tier invalidation into an otherwise successful
/// response.
///
/// Not a 5xx: the store write landed, and telling the operator the revoke
/// failed when it did not would send them to re-run a mutation that is
/// already applied. What is true is narrower. The record changed here and
/// the shared tier was not told, so peer replicas keep answering with the
/// previous record until their TTL lapses. The body says that; the counter
/// makes it alertable without anyone parsing response bodies.
fn with_propagation_warning(resp: Resp) -> Resp {
    let Some(detail) = PROPAGATION_FAILURE.with(|slot| slot.borrow_mut().take()) else {
        return resp;
    };
    let (status, content_type, body) = resp;
    if !(200..300).contains(&status) {
        return (status, content_type, body);
    }
    let Ok(serde_json::Value::Object(mut map)) = serde_json::from_str::<serde_json::Value>(&body)
    else {
        return (status, content_type, body);
    };
    map.insert(
        "cache_propagation".to_string(),
        json!({
            "status": "failed",
            "detail": detail,
            "effect": "other replicas may serve the previous record until their cache TTL lapses",
        }),
    );
    (
        status,
        content_type,
        serde_json::Value::Object(map).to_string(),
    )
}

fn route(method: &str, path: &str, body: Option<&str>) -> Option<Resp> {
    if path == "/admin/keys" {
        return Some(if method.eq_ignore_ascii_case("GET") {
            list_keys()
        } else if method.eq_ignore_ascii_case("POST") {
            count_key_operation("mint", create_key(body))
        } else {
            method_not_allowed()
        });
    }
    if path == "/admin/keys/policy-schema" {
        return Some(if method.eq_ignore_ascii_case("GET") {
            get_key_policy_schema()
        } else {
            method_not_allowed()
        });
    }
    if let Some(rest) = path.strip_prefix("/admin/keys/") {
        return Some(key_subroute(method, rest, body));
    }
    if path == "/admin/credentials" {
        return Some(if method.eq_ignore_ascii_case("GET") {
            list_credentials()
        } else if method.eq_ignore_ascii_case("POST") {
            create_credential(body)
        } else {
            method_not_allowed()
        });
    }
    if let Some(rest) = path.strip_prefix("/admin/credentials/") {
        return Some(credential_subroute(method, rest, body));
    }
    // WOR-2573. Mounted here rather than in `admin.rs` because a
    // break-glass grant exists to reach keys and credentials, and its
    // audit records land on the same `key_audit` channel this module
    // already writes.
    if path == "/admin/break-glass" {
        return Some(if method.eq_ignore_ascii_case("GET") {
            ok(crate::break_glass::list(Utc::now()))
        } else if method.eq_ignore_ascii_case("POST") {
            create_break_glass_grant(body)
        } else {
            method_not_allowed()
        });
    }
    if let Some(rest) = path.strip_prefix("/admin/break-glass/") {
        return Some(break_glass_subroute(method, rest, body));
    }
    // WOR-2568.
    if path == "/admin/crypto/root-of-trust" {
        return Some(if method.eq_ignore_ascii_case("GET") {
            get_root_of_trust()
        } else {
            method_not_allowed()
        });
    }
    None
}

fn key_subroute(method: &str, rest: &str, body: Option<&str>) -> Resp {
    let mut parts = rest.splitn(2, '/');
    let id = parts.next().unwrap_or("");
    let action = parts.next();
    if id.is_empty() {
        return not_found("missing key id");
    }
    match action {
        None => {
            if method.eq_ignore_ascii_case("GET") {
                get_key(id)
            } else if method.eq_ignore_ascii_case("PATCH") {
                count_key_operation("update", update_key(id, body))
            } else if method.eq_ignore_ascii_case("DELETE") {
                count_key_operation("delete", delete_key(id))
            } else {
                method_not_allowed()
            }
        }
        Some("usage") if method.eq_ignore_ascii_case("GET") => get_key_usage(id),
        Some("effective-policy/preview") if method.eq_ignore_ascii_case("POST") => {
            preview_effective_key_policy(id, body)
        }
        // WOR-2561: temporary, auto-expiring budget overrides. Counted
        // like every other arm here: the route CAS-writes the same
        // `KeyRecord` through `store_key_if_revision`, so it is the key
        // resource, and raising a spending ceiling is the mutation an
        // operator most wants on a "key operations by type" panel.
        Some("budget-override") => {
            if method.eq_ignore_ascii_case("POST") {
                count_key_operation("budget_override_grant", grant_budget_override(id, body))
            } else if method.eq_ignore_ascii_case("DELETE") {
                count_key_operation("budget_override_clear", clear_budget_override(id, body))
            } else {
                method_not_allowed()
            }
        }
        Some(action) if method.eq_ignore_ascii_case("POST") => match action {
            "revoke" => {
                count_key_operation("revoke", set_key_status(id, RecordStatus::Revoked, body))
            }
            "block" => {
                count_key_operation("block", set_key_status(id, RecordStatus::Blocked, body))
            }
            "unblock" => {
                count_key_operation("unblock", set_key_status(id, RecordStatus::Active, body))
            }
            "rotate" => count_key_operation("rotate", rotate_key(id, body)),
            _ => not_found("unknown key action"),
        },
        Some(_) => method_not_allowed(),
    }
}

fn credential_subroute(method: &str, rest: &str, body: Option<&str>) -> Resp {
    let mut parts = rest.splitn(2, '/');
    let id = parts.next().unwrap_or("");
    let action = parts.next();
    if id.is_empty() {
        return not_found("missing credential id");
    }
    match action {
        None => {
            if method.eq_ignore_ascii_case("GET") {
                get_credential(id)
            } else if method.eq_ignore_ascii_case("PATCH") {
                update_credential(id, body)
            } else if method.eq_ignore_ascii_case("DELETE") {
                delete_credential(id)
            } else {
                method_not_allowed()
            }
        }
        Some(action) if method.eq_ignore_ascii_case("POST") => match action {
            "revoke" => set_credential_status(id, RecordStatus::Revoked),
            "block" => set_credential_status(id, RecordStatus::Blocked),
            "unblock" => set_credential_status(id, RecordStatus::Active),
            // WOR-2567: the credential half of the rotation story. Counted
            // on the same `sbproxy_key_operations_total` series the key
            // rotation is, because an operator's "how often do we rotate"
            // panel should not have to know which resource kind it was.
            "rotate" => count_key_operation("credential_rotate", rotate_credential(id, body)),
            _ => not_found("unknown credential action"),
        },
        Some(_) => method_not_allowed(),
    }
}

// --- Key handlers ---

/// Three-way PATCH state: absent leaves a field unchanged, JSON `null` clears
/// a nullable value, and a concrete value replaces it.
#[derive(Debug, Clone, Default)]
enum Patch<T> {
    /// Field was absent.
    #[default]
    Missing,
    /// Field was explicitly JSON `null`.
    Null,
    /// Field carried a concrete replacement value.
    Value(T),
}

impl<'de, T> Deserialize<'de> for Patch<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(match Option::<T>::deserialize(deserializer)? {
            Some(value) => Self::Value(value),
            None => Self::Null,
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct KeyMutation {
    expected_revision: Option<u64>,
    name: Patch<String>,
    max_requests_per_minute: Patch<u64>,
    max_tokens_per_minute: Patch<u64>,
    /// SLO priority lane: `interactive` | `standard` | `batch`.
    priority: Patch<String>,
    max_budget_tokens: Patch<u64>,
    max_budget_usd: Patch<f64>,
    allowed_models: Patch<Vec<String>>,
    blocked_models: Patch<Vec<String>>,
    allowed_providers: Patch<Vec<String>>,
    blocked_providers: Patch<Vec<String>>,
    require_pii_redaction: Patch<Vec<String>>,
    principal_selectors: Patch<Vec<serde_json::Value>>,
    /// Pin a model for this key. JSON `null` clears the pin.
    route_to_model: Patch<String>,
    /// Route-local compression selector. JSON `null` clears the selector.
    compression_profile: Patch<String>,
    allowed_tools: Patch<Vec<String>>,
    inject_tools: Patch<Vec<serde_json::Value>>,
    /// Federated-MCP injection ref. JSON `null` clears it.
    inject_mcp: Patch<serde_json::Value>,
    bypass_prompt_injection: Patch<bool>,
    allow_content_capture: Patch<bool>,
    project: Patch<String>,
    user: Patch<String>,
    tags: Patch<Vec<String>>,
    /// Free-form string metadata; replaces the record's map wholesale.
    metadata: Patch<std::collections::BTreeMap<String, String>>,
    tenant: Patch<String>,
    /// Upstream credential this key presents. JSON `null` clears the
    /// binding and returns the key to the origin's own resolver.
    credential_id: Patch<String>,
    /// RFC 3339 expiry. JSON `null` clears it.
    expires_at: Patch<DateTime<Utc>>,
}

/// Reject mutation values that would store an invalid policy: an unknown
/// priority lane, or an `inject_mcp` value that is not an object carrying
/// the required `ref` string. Runs before [`apply_key_mutation`] so a bad
/// PATCH is a 400, never a silently-stored record the AI seam later drops.
fn validate_key_mutation(m: &KeyMutation) -> Result<(), String> {
    if let Some(0) = m.expected_revision {
        return Err("expected_revision must be at least 1".to_string());
    }
    if let Patch::Value(p) = &m.priority {
        if sbproxy_ai::identity::KeyPriority::parse(p).is_none() {
            return Err(format!(
                "priority '{p}' is not a lane; use interactive, standard, or batch"
            ));
        }
    }
    if let Patch::Value(selector) = &m.compression_profile {
        sbproxy_ai::compression::CompressionSelector::parse(selector).map_err(|_| {
            "compression_profile must be on, off, or a valid profile name".to_string()
        })?;
    }
    if let Patch::Value(v) = &m.inject_mcp {
        let has_ref = v
            .as_object()
            .and_then(|o| o.get("ref"))
            .and_then(|r| r.as_str())
            .is_some_and(|s| !s.is_empty());
        if !has_ref {
            return Err(
                "inject_mcp must be an object with a non-empty `ref` naming a federated \
                 MCP gateway, e.g. {\"ref\": \"toolhub\"}"
                    .to_string(),
            );
        }
    }
    if let Patch::Value(selectors) = &m.principal_selectors {
        for (index, selector) in selectors.iter().enumerate() {
            serde_json::from_value::<sbproxy_ai::identity::PrincipalSelectorConfig>(
                selector.clone(),
            )
            .map_err(|error| format!("principal_selectors[{index}] is invalid: {error}"))?;
        }
    }
    if let Patch::Value(value) = &m.max_budget_usd {
        if !value.is_finite() || *value < 0.0 {
            return Err("max_budget_usd must be a finite non-negative number".to_string());
        }
    }
    for (field, is_null) in [
        ("allowed_models", matches!(&m.allowed_models, Patch::Null)),
        ("blocked_models", matches!(&m.blocked_models, Patch::Null)),
        (
            "allowed_providers",
            matches!(&m.allowed_providers, Patch::Null),
        ),
        (
            "blocked_providers",
            matches!(&m.blocked_providers, Patch::Null),
        ),
        (
            "require_pii_redaction",
            matches!(&m.require_pii_redaction, Patch::Null),
        ),
        (
            "principal_selectors",
            matches!(&m.principal_selectors, Patch::Null),
        ),
        ("inject_tools", matches!(&m.inject_tools, Patch::Null)),
        ("tags", matches!(&m.tags, Patch::Null)),
        ("metadata", matches!(&m.metadata, Patch::Null)),
        (
            "bypass_prompt_injection",
            matches!(&m.bypass_prompt_injection, Patch::Null),
        ),
        (
            "allow_content_capture",
            matches!(&m.allow_content_capture, Patch::Null),
        ),
    ] {
        if is_null {
            return Err(format!(
                "{field} does not accept null; use its explicit empty or false value"
            ));
        }
    }
    Ok(())
}

fn apply_nullable<T: Clone>(target: &mut Option<T>, patch: &Patch<T>) {
    match patch {
        Patch::Missing => {}
        Patch::Null => *target = None,
        Patch::Value(value) => *target = Some(value.clone()),
    }
}

fn apply_replacement<T: Clone>(target: &mut T, patch: &Patch<T>) {
    if let Patch::Value(value) = patch {
        *target = value.clone();
    }
}

/// Apply fields present in a validated mutation onto a record.
fn apply_key_mutation(rec: &mut KeyRecord, m: &KeyMutation) {
    apply_nullable(&mut rec.name, &m.name);
    apply_nullable(&mut rec.max_requests_per_minute, &m.max_requests_per_minute);
    apply_nullable(&mut rec.max_tokens_per_minute, &m.max_tokens_per_minute);
    apply_nullable(&mut rec.priority, &m.priority);
    if !matches!(&m.max_budget_tokens, Patch::Missing)
        || !matches!(&m.max_budget_usd, Patch::Missing)
    {
        let mut b = rec.budget.clone().unwrap_or_default();
        apply_nullable(&mut b.max_tokens, &m.max_budget_tokens);
        apply_nullable(&mut b.max_cost_usd, &m.max_budget_usd);
        rec.budget = if b.max_tokens.is_none() && b.max_cost_usd.is_none() {
            None
        } else {
            Some(b)
        };
    }
    apply_replacement(&mut rec.allowed_models, &m.allowed_models);
    apply_replacement(&mut rec.blocked_models, &m.blocked_models);
    apply_replacement(&mut rec.allowed_providers, &m.allowed_providers);
    apply_replacement(&mut rec.blocked_providers, &m.blocked_providers);
    apply_replacement(&mut rec.require_pii_redaction, &m.require_pii_redaction);
    apply_replacement(&mut rec.principal_selectors, &m.principal_selectors);
    apply_nullable(&mut rec.route_to_model, &m.route_to_model);
    apply_nullable(&mut rec.compression_profile, &m.compression_profile);
    apply_nullable(&mut rec.allowed_tools, &m.allowed_tools);
    apply_replacement(&mut rec.inject_tools, &m.inject_tools);
    apply_nullable(&mut rec.inject_mcp, &m.inject_mcp);
    if let Patch::Value(value) = &m.bypass_prompt_injection {
        rec.bypass_prompt_injection = *value;
    }
    if let Patch::Value(value) = &m.allow_content_capture {
        rec.allow_content_capture = *value;
    }
    apply_nullable(&mut rec.project, &m.project);
    apply_nullable(&mut rec.user, &m.user);
    apply_replacement(&mut rec.tags, &m.tags);
    apply_replacement(&mut rec.metadata, &m.metadata);
    apply_nullable(&mut rec.tenant_id, &m.tenant);
    apply_nullable(&mut rec.credential_id, &m.credential_id);
    apply_nullable(&mut rec.expires_at, &m.expires_at);
}

/// Reject a `credential_id` binding that names a credential which does not
/// exist, is not active, or belongs to another tenant.
///
/// Checked here AND again at resolution time in
/// [`crate::key_plane::KeyPlane::resolve_credential_secret`], because either
/// record's tenant can be patched after the binding was made. One check is not
/// enough.
///
/// `key_tenant` is the tenant the key will have once the mutation applies.
fn validate_credential_binding(
    plane: &KeyPlane,
    m: &KeyMutation,
    key_tenant: Option<&str>,
) -> Result<(), Resp> {
    let Patch::Value(credential_id) = &m.credential_id else {
        return Ok(());
    };
    // An older node in the fleet drops `credential_id` when it replicates the
    // record, resolves the key without a binding, and dispatches on the
    // origin's shared credential. Refuse to create such a record until every
    // node has declared it understands the field.
    match block_on_keystore(async {
        crate::key_capability::check_fleet_capability(crate::key_capability::CAP_CREDENTIAL_BINDING)
            .await
    }) {
        crate::key_capability::FleetCapability::Satisfied => {}
        crate::key_capability::FleetCapability::Missing(nodes) => {
            return Err(conflict(&format!(
                "credential binding needs every node upgraded; these have not declared \
                 support: {}",
                nodes.join(", ")
            )));
        }
        crate::key_capability::FleetCapability::Unknown(reason) => {
            return Err(conflict(&format!(
                "cannot confirm every node supports credential binding: {reason}"
            )));
        }
    }
    match load_credential(plane, credential_id) {
        Ok(Some(cred)) => {
            if !cred.is_usable() {
                return Err(bad_request(
                    "credential_id names a credential that is not active",
                ));
            }
            if cred.tenant_id.is_some() && cred.tenant_id.as_deref() != key_tenant {
                return Err(bad_request("credential_id belongs to a different tenant"));
            }
            Ok(())
        }
        Ok(None) => Err(bad_request("credential_id names an unknown credential")),
        Err(e) => Err(internal_error(&e)),
    }
}

fn create_key(body: Option<&str>) -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let m: KeyMutation = match parse_body(body) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if let Err(e) = validate_key_mutation(&m) {
        return bad_request(&e);
    }
    if m.expected_revision.is_some() {
        return bad_request("expected_revision is only valid for key mutation");
    }
    let new_tenant = match &m.tenant {
        Patch::Value(t) => Some(t.as_str()),
        _ => None,
    };
    if let Err(resp) = validate_credential_binding(&plane, &m, new_tenant) {
        return resp;
    }
    let minted = plane.crypto().mint_key();
    let now = Utc::now();
    let mut rec = KeyRecord::new(minted.key_id.clone(), minted.secret_hash.clone(), now);
    apply_key_mutation(&mut rec, &m);

    let store = plane.cache().store().clone();
    let put = rec.clone();
    if let Err(e) = block_on_keystore(async move { store.put_key(put).await }) {
        return internal_error(&format!("store key: {e:#}"));
    }
    invalidate(&plane, &minted.key_id);
    // Tenant-scoped so the `key_minted` typed event (WOR-2571) and the
    // chain entry both attribute the mint; the record is at hand here.
    audit_mutation_scoped(
        "create",
        "key",
        &minted.key_id,
        rec.tenant_id.as_deref(),
        None,
    );

    created(json!({
        // The plaintext token is shown exactly once and never stored.
        "token": minted.token,
        "key": KeyView::from(&rec),
    }))
}

fn list_keys() -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let store = plane.cache().store().clone();
    match block_on_keystore(async move { store.list_keys().await }) {
        Ok(keys) => {
            // WOR-2567: the `kind="key"` half of
            // `sbproxy_key_rotation_age_days`, which
            // `docs/configuration.md` names as the alert target for
            // `inbound_key_days`. Published from the same read that
            // already retires lapsed overrides below, so a deployment
            // that never lists never pays and the number is refreshed by
            // the thing that was going to look at it anyway.
            let rotation_now = Utc::now();
            if let Some(oldest) = keys.iter().map(|k| k.rotation_age_days(rotation_now)).max() {
                sbproxy_observe::metrics::record_rotation_age_days("key", oldest as f64);
            }
            // WOR-2561: listing is a read the operator trusts, so lapsed
            // budget overrides are retired (and their expiry audited) here.
            //
            // Bounded, because each retirement is a blocking store write
            // plus two cache invalidations on the request thread. A
            // tenant whose keys all lapsed at once (one launch window,
            // one TTL) would otherwise make the first `GET /admin/keys`
            // after expiry do one redb write per key before rendering
            // anything. Past the cap the remaining lapsed grants are
            // simply shown as what they are: `KeyView` already hides an
            // expired override and `effective_budget` already ignores
            // one, so the only thing deferred is the bookkeeping write
            // and its expiry record, which the next read picks up.
            let mut budget = MAX_RETIREMENTS_PER_LIST;
            let views: Vec<KeyView> = keys
                .into_iter()
                .map(|rec| {
                    if budget > 0 && rec.budget_override.is_some() {
                        budget -= 1;
                        KeyView::from(&retire_expired_override(&plane, rec))
                    } else {
                        KeyView::from(&rec)
                    }
                })
                .collect();
            ok(json!({ "keys": views }))
        }
        Err(e) => internal_error(&format!("list keys: {e:#}")),
    }
}

/// How many lapsed budget overrides one `GET /admin/keys` will retire
/// before deferring the rest to a later read.
///
/// The retirement is bookkeeping, never enforcement, so a bound here
/// costs an expiry record its promptness and nothing else. Sized to keep
/// the worst-case listing latency in the same order as an ordinary one:
/// each retirement is a compare-and-swap store write plus a record and a
/// resolved-credential invalidation, all on the request thread.
const MAX_RETIREMENTS_PER_LIST: usize = 32;

fn get_key(id: &str) -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    match load_key(&plane, id) {
        Ok(Some(rec)) => {
            let rec = retire_expired_override(&plane, rec);
            ok(json!({ "key": KeyView::from(&rec) }))
        }
        Ok(None) => not_found("key not found"),
        Err(e) => internal_error(&e),
    }
}

fn get_key_policy_schema() -> Resp {
    ok(json!({
        "schema_version":
            sbproxy_ai::effective_key_policy::EFFECTIVE_KEY_POLICY_SCHEMA_VERSION,
        "fields": sbproxy_ai::effective_key_policy::PolicyField::descriptors(),
    }))
}

const MAX_POLICY_PREVIEW_BODY_BYTES: usize = 64 * 1024;
const MAX_POLICY_PREVIEW_ITEMS: usize = 128;
const MAX_POLICY_PREVIEW_STRING_BYTES: usize = 512;

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PolicyPreviewSample {
    origin_tenant_id: Option<String>,
    at: Option<DateTime<Utc>>,
    model: Option<String>,
    provider: Option<String>,
    tools: Option<Vec<String>>,
    principal: Option<PolicyPreviewPrincipal>,
    active_pii_rules: Option<Vec<String>>,
    prompt_injection_detected: Option<bool>,
    estimated_tokens: Option<u64>,
    estimated_micro_usd: Option<u64>,
    usage: Option<PolicyPreviewUsage>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PolicyPreviewPrincipal {
    virtual_key: Option<String>,
    team: Option<String>,
    project: Option<String>,
    user: Option<String>,
    roles: Vec<String>,
    claims: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PolicyPreviewUsage {
    requests_in_window: u64,
    tokens_in_window: u64,
    total_tokens: u64,
    total_micro_usd: u64,
}

#[derive(Debug, Serialize)]
struct PreviewLifecycleDecision {
    allowed: bool,
    reason_code: &'static str,
    status: sbproxy_ai::effective_key_policy::EffectiveKeyStatus,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
struct PreviewTenantDecision {
    allowed: bool,
    reason_code: &'static str,
    origin_tenant_id: String,
    effective_tenant_id: String,
}

#[derive(Debug, Serialize)]
struct PreviewModelDecision {
    allowed: bool,
    reason_code: &'static str,
    requested: Option<String>,
    effective: Option<String>,
    routed: bool,
}

#[derive(Debug, Serialize)]
struct PreviewProviderDecision {
    allowed: bool,
    reason_code: &'static str,
    provider: Option<String>,
}

#[derive(Debug, Serialize)]
struct PreviewToolsDecision {
    allowed: bool,
    reason_code: &'static str,
    requested_count: usize,
    denied: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PreviewPrincipalDecision {
    allowed: bool,
    reason_code: &'static str,
}

#[derive(Debug, Serialize)]
struct PreviewCounterDecision {
    allowed: bool,
    limit: Option<u64>,
    current: u64,
    requested: u64,
    projected: Option<u64>,
    reason_code: &'static str,
}

#[derive(Debug, Serialize)]
struct PreviewRateLimitDecision {
    allowed: bool,
    reason_code: &'static str,
    requests_per_minute: PreviewCounterDecision,
    tokens_per_minute: PreviewCounterDecision,
}

#[derive(Debug, Serialize)]
struct PreviewBudgetDecision {
    allowed: bool,
    reason_code: &'static str,
    tokens: PreviewCounterDecision,
    micro_usd: PreviewCounterDecision,
}

#[derive(Debug, Serialize)]
struct PreviewPriorityDecision {
    allowed: bool,
    reason_code: &'static str,
    lane: &'static str,
}

#[derive(Debug, Serialize)]
struct PreviewPiiDecision {
    allowed: bool,
    reason_code: &'static str,
    required: Vec<String>,
    missing: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PreviewPromptInjectionDecision {
    allowed: bool,
    reason_code: &'static str,
    mode: &'static str,
    detected: Option<bool>,
}

#[derive(Debug, Serialize)]
struct PreviewGuardrailDecision {
    allowed: bool,
    reason_code: &'static str,
    pii: PreviewPiiDecision,
    prompt_injection: PreviewPromptInjectionDecision,
}

#[derive(Debug, Serialize)]
struct EffectivePolicyPreviewDecisions {
    allowed: bool,
    lifecycle: PreviewLifecycleDecision,
    tenant: PreviewTenantDecision,
    model: PreviewModelDecision,
    provider: PreviewProviderDecision,
    tools: PreviewToolsDecision,
    principal: PreviewPrincipalDecision,
    rate_limits: PreviewRateLimitDecision,
    budget: PreviewBudgetDecision,
    priority: PreviewPriorityDecision,
    guardrails: PreviewGuardrailDecision,
}

struct PolicyPreviewLimits {
    requests_per_minute: Option<u64>,
    tokens_per_minute: Option<u64>,
    total_tokens: Option<u64>,
    total_micro_usd: Option<u64>,
}

fn preview_effective_key_policy(id: &str, body: Option<&str>) -> Resp {
    let plane = match plane_or_err() {
        Ok(plane) => plane,
        Err(response) => return response,
    };
    let record = match load_key(&plane, id) {
        Ok(Some(record)) => record,
        Ok(None) => return not_found("key not found"),
        Err(error) => return internal_error(&error),
    };
    let sample = match parse_policy_preview_sample(body) {
        Ok(sample) => sample,
        Err(response) => return response,
    };
    let origin_tenant_id = sample
        .origin_tenant_id
        .clone()
        .or_else(|| record.tenant_id.clone())
        .unwrap_or_else(|| "__default__".to_string());
    let (tenant_allowed, tenant_reason_code) = match record.tenant_id.as_deref() {
        None => (true, "inherited"),
        Some(tenant) if tenant == origin_tenant_id => (true, "match"),
        Some(_) => (false, "mismatch"),
    };
    // A cross-tenant sample is a normal deny result. Lower the displayed
    // canonical policy in its owning tenant so the preview can still return
    // the complete secret-free contract without weakening request-path checks.
    let policy_origin = if tenant_allowed {
        origin_tenant_id.as_str()
    } else {
        record
            .tenant_id
            .as_deref()
            .unwrap_or(origin_tenant_id.as_str())
    };
    // WOR-2561: lower the policy at the sample's instant, so a preview dated
    // before an override's expiry shows the raised caps and one dated after
    // shows the base, matching what enforcement would do at that time.
    let at = sample.at.unwrap_or_else(Utc::now);
    let policy =
        match crate::key_policy::key_record_to_effective_policy_at(&record, policy_origin, at) {
            Ok(policy) => policy,
            Err(error) => {
                tracing::warn!(
                    reason = error.safe_reason(),
                    "admin key policy preview: stored policy rejected"
                );
                return internal_error("stored key policy is invalid");
            }
        };
    let policy_version = match policy.policy_version() {
        Ok(version) => version,
        Err(_) => return internal_error("effective policy serialization failed"),
    };
    let decisions = match evaluate_policy_preview(
        &record,
        &policy,
        sample,
        at,
        origin_tenant_id,
        tenant_allowed,
        tenant_reason_code,
    ) {
        Ok(decisions) => decisions,
        Err(error) => return internal_error(error),
    };

    ok(json!({
        "effective_policy": policy,
        "policy_version": policy_version,
        "decisions": decisions,
    }))
}

fn parse_policy_preview_sample(body: Option<&str>) -> Result<PolicyPreviewSample, Resp> {
    let body = body.unwrap_or("");
    if body.len() > MAX_POLICY_PREVIEW_BODY_BYTES {
        return Err(bad_request("policy preview sample body is too large"));
    }
    let sample = if body.is_empty() {
        PolicyPreviewSample::default()
    } else {
        serde_json::from_str::<PolicyPreviewSample>(body)
            .map_err(|_| bad_request("invalid policy preview sample"))?
    };
    validate_policy_preview_sample(&sample).map_err(bad_request)?;
    Ok(sample)
}

fn validate_policy_preview_sample(sample: &PolicyPreviewSample) -> Result<(), &'static str> {
    for value in [
        sample.origin_tenant_id.as_deref(),
        sample.model.as_deref(),
        sample.provider.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_policy_preview_string(value)?;
    }
    for values in [sample.tools.as_deref(), sample.active_pii_rules.as_deref()]
        .into_iter()
        .flatten()
    {
        validate_policy_preview_strings(values)?;
    }
    if let Some(principal) = sample.principal.as_ref() {
        for value in [
            principal.virtual_key.as_deref(),
            principal.team.as_deref(),
            principal.project.as_deref(),
            principal.user.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_policy_preview_string(value)?;
        }
        validate_policy_preview_strings(&principal.roles)?;
        if principal.claims.len() > MAX_POLICY_PREVIEW_ITEMS {
            return Err("policy preview sample has too many claim fields");
        }
        for name in principal.claims.keys() {
            validate_policy_preview_string(name)?;
        }
    }
    Ok(())
}

fn validate_policy_preview_strings(values: &[String]) -> Result<(), &'static str> {
    if values.len() > MAX_POLICY_PREVIEW_ITEMS {
        return Err("policy preview sample list is too large");
    }
    for value in values {
        validate_policy_preview_string(value)?;
    }
    Ok(())
}

fn validate_policy_preview_string(value: &str) -> Result<(), &'static str> {
    if value.is_empty() || value.len() > MAX_POLICY_PREVIEW_STRING_BYTES {
        return Err("policy preview sample string has an invalid length");
    }
    Ok(())
}

fn evaluate_policy_preview(
    record: &KeyRecord,
    policy: &sbproxy_ai::effective_key_policy::EffectiveKeyPolicy,
    sample: PolicyPreviewSample,
    at: DateTime<Utc>,
    origin_tenant_id: String,
    tenant_allowed: bool,
    tenant_reason_code: &'static str,
) -> Result<EffectivePolicyPreviewDecisions, &'static str> {
    use sbproxy_ai::effective_key_policy::EffectiveKeyStatus;

    let lifecycle_reason_code = match policy.status {
        EffectiveKeyStatus::Revoked => "revoked",
        EffectiveKeyStatus::Blocked => "blocked",
        EffectiveKeyStatus::Active if policy.expires_at.is_some_and(|expires| expires <= at) => {
            "expired"
        }
        EffectiveKeyStatus::Active => "active",
    };
    let lifecycle = PreviewLifecycleDecision {
        allowed: lifecycle_reason_code == "active",
        reason_code: lifecycle_reason_code,
        status: policy.status,
        expires_at: policy.expires_at,
    };
    let tenant = PreviewTenantDecision {
        allowed: tenant_allowed,
        reason_code: tenant_reason_code,
        origin_tenant_id: origin_tenant_id.clone(),
        effective_tenant_id: policy.tenant_id.clone(),
    };

    let requested_model = sample.model.clone();
    let effective_model = policy
        .route_to_model
        .clone()
        .or_else(|| requested_model.clone());
    let routed = policy.route_to_model.is_some();
    let (model_allowed, model_reason_code) = match effective_model.as_deref() {
        None => (true, "not_sampled"),
        Some(model) if policy.blocked_models.iter().any(|blocked| blocked == model) => {
            (false, "blocked")
        }
        Some(model)
            if !policy.allowed_models.is_empty()
                && !policy.allowed_models.iter().any(|allowed| allowed == model) =>
        {
            (false, "not_allowed")
        }
        Some(_) => (true, "allowed"),
    };
    let model = PreviewModelDecision {
        allowed: model_allowed,
        reason_code: model_reason_code,
        requested: requested_model,
        effective: effective_model,
        routed,
    };

    let (provider_allowed, provider_reason_code) = match sample.provider.as_deref() {
        None => (true, "not_sampled"),
        Some(provider)
            if policy
                .blocked_providers
                .iter()
                .any(|blocked| blocked == provider) =>
        {
            (false, "blocked")
        }
        Some(provider)
            if !policy.allowed_providers.is_empty()
                && !policy
                    .allowed_providers
                    .iter()
                    .any(|allowed| allowed == provider) =>
        {
            (false, "not_allowed")
        }
        Some(_) => (true, "allowed"),
    };
    let provider = PreviewProviderDecision {
        allowed: provider_allowed,
        reason_code: provider_reason_code,
        provider: sample.provider,
    };

    let (requested_count, denied, tools_reason_code) = match sample.tools {
        None => (0, Vec::new(), "not_sampled"),
        Some(tools) => {
            let denied = tools
                .iter()
                .filter(|tool| !policy.is_tool_allowed(tool))
                .cloned()
                .collect::<Vec<_>>();
            let reason = if denied.is_empty() {
                if policy.allowed_tools.is_none() {
                    "unrestricted"
                } else {
                    "allowed"
                }
            } else {
                "not_allowed"
            };
            (tools.len(), denied, reason)
        }
    };
    let tools = PreviewToolsDecision {
        allowed: denied.is_empty(),
        reason_code: tools_reason_code,
        requested_count,
        denied,
    };

    let principal = match sample.principal {
        None if policy.principal_selectors.is_empty() => PreviewPrincipalDecision {
            allowed: true,
            reason_code: "unrestricted",
        },
        None => PreviewPrincipalDecision {
            allowed: true,
            reason_code: "not_sampled",
        },
        Some(principal) => {
            let principal = policy_preview_principal(principal, &origin_tenant_id);
            let allowed = policy.matches_principal(&principal);
            PreviewPrincipalDecision {
                allowed,
                reason_code: if allowed { "matched" } else { "not_matched" },
            }
        }
    };

    let usage = sample.usage.unwrap_or_default();
    let estimated_tokens = sample.estimated_tokens.unwrap_or(0);
    let estimated_micro_usd = sample.estimated_micro_usd.unwrap_or(0);
    let limits = policy_preview_limits(record, at)?;
    let requests_per_minute =
        preview_counter(limits.requests_per_minute, usage.requests_in_window, 1);
    let tokens_per_minute = preview_counter(
        limits.tokens_per_minute,
        usage.tokens_in_window,
        estimated_tokens,
    );
    let rate_limits_allowed = requests_per_minute.allowed && tokens_per_minute.allowed;
    let rate_limits = PreviewRateLimitDecision {
        allowed: rate_limits_allowed,
        reason_code: if rate_limits_allowed {
            "within_limits"
        } else {
            "limit_exceeded"
        },
        requests_per_minute,
        tokens_per_minute,
    };
    let budget_tokens = preview_counter(limits.total_tokens, usage.total_tokens, estimated_tokens);
    let budget_micro_usd = preview_counter(
        limits.total_micro_usd,
        usage.total_micro_usd,
        estimated_micro_usd,
    );
    let budget_allowed = budget_tokens.allowed && budget_micro_usd.allowed;
    let budget = PreviewBudgetDecision {
        allowed: budget_allowed,
        reason_code: if budget_allowed {
            "within_limits"
        } else {
            "limit_exceeded"
        },
        tokens: budget_tokens,
        micro_usd: budget_micro_usd,
    };
    let priority = PreviewPriorityDecision {
        allowed: true,
        reason_code: "selected_lane",
        lane: policy.priority.as_str(),
    };

    let pii = match sample.active_pii_rules {
        None => PreviewPiiDecision {
            allowed: true,
            reason_code: "not_sampled",
            required: policy.require_pii_redaction.clone(),
            missing: Vec::new(),
        },
        Some(active) => {
            let missing = policy
                .require_pii_redaction
                .iter()
                .filter(|required| !active.iter().any(|rule| rule == *required))
                .cloned()
                .collect::<Vec<_>>();
            PreviewPiiDecision {
                allowed: missing.is_empty(),
                reason_code: if missing.is_empty() {
                    "satisfied"
                } else {
                    "missing_required_rules"
                },
                required: policy.require_pii_redaction.clone(),
                missing,
            }
        }
    };
    let prompt_injection = if policy.bypass_prompt_injection {
        PreviewPromptInjectionDecision {
            allowed: true,
            reason_code: "bypassed",
            mode: "bypass",
            detected: sample.prompt_injection_detected,
        }
    } else {
        let detected = sample.prompt_injection_detected;
        PreviewPromptInjectionDecision {
            allowed: detected != Some(true),
            reason_code: match detected {
                Some(true) => "detected",
                Some(false) => "not_detected",
                None => "not_sampled",
            },
            mode: "enforce",
            detected,
        }
    };
    let guardrails_allowed = pii.allowed && prompt_injection.allowed;
    let guardrails = PreviewGuardrailDecision {
        allowed: guardrails_allowed,
        reason_code: if guardrails_allowed {
            "satisfied"
        } else {
            "guardrail_denied"
        },
        pii,
        prompt_injection,
    };

    let allowed = lifecycle.allowed
        && tenant.allowed
        && model.allowed
        && provider.allowed
        && tools.allowed
        && principal.allowed
        && rate_limits.allowed
        && budget.allowed
        && priority.allowed
        && guardrails.allowed;
    Ok(EffectivePolicyPreviewDecisions {
        allowed,
        lifecycle,
        tenant,
        model,
        provider,
        tools,
        principal,
        rate_limits,
        budget,
        priority,
        guardrails,
    })
}

fn policy_preview_limits(
    record: &KeyRecord,
    at: DateTime<Utc>,
) -> Result<PolicyPreviewLimits, &'static str> {
    // WOR-2561: preview against the budget that would be enforced at the
    // sample's instant, so a preview dated past an override's expiry shows
    // the base caps the request path would apply then.
    let budget = record.effective_budget(at);
    let total_micro_usd = budget
        .as_ref()
        .and_then(|budget| budget.max_cost_usd)
        .map(policy_preview_usd_to_micro_usd)
        .transpose()?;
    Ok(PolicyPreviewLimits {
        requests_per_minute: record.max_requests_per_minute,
        tokens_per_minute: record.max_tokens_per_minute,
        total_tokens: budget.as_ref().and_then(|budget| budget.max_tokens),
        total_micro_usd,
    })
}

fn policy_preview_usd_to_micro_usd(value: f64) -> Result<u64, &'static str> {
    const MICRO_USD_PER_USD: f64 = 1_000_000.0;

    if !value.is_finite() || value < 0.0 {
        return Err("stored max_budget_usd is not a finite non-negative number");
    }
    let rounded = (value * MICRO_USD_PER_USD).round();
    if !rounded.is_finite() || rounded < 0.0 || rounded >= u64::MAX as f64 {
        return Err("stored max_budget_usd cannot be represented as integer micro-USD");
    }
    Ok(rounded as u64)
}

fn policy_preview_principal(
    sample: PolicyPreviewPrincipal,
    tenant_id: &str,
) -> sbproxy_plugin::Principal {
    let mut principal = sbproxy_plugin::Principal::anonymous_for(tenant_id.into());
    principal.virtual_key = sample
        .virtual_key
        .map(|name| sbproxy_plugin::VirtualKeyRef {
            name,
            allowed_providers: Vec::new(),
        });
    principal.attrs.team = sample.team;
    principal.attrs.project = sample.project;
    principal.attrs.user = sample.user;
    principal.attrs.roles = sample.roles;
    principal.attrs.claims = if sample.claims.is_empty() {
        None
    } else {
        Some(sample.claims)
    };
    principal
}

fn preview_counter(limit: Option<u64>, current: u64, requested: u64) -> PreviewCounterDecision {
    let projected = current.checked_add(requested);
    let allowed = projected.is_some_and(|projected| limit.is_none_or(|limit| projected <= limit));
    let reason_code = match (projected, limit) {
        (None, _) => "overflow",
        (Some(_), None) => "unlimited",
        (Some(projected), Some(limit)) if projected <= limit => "within_limit",
        (Some(_), Some(_)) => "limit_exceeded",
    };
    PreviewCounterDecision {
        allowed,
        limit,
        current,
        requested,
        projected,
        reason_code,
    }
}

fn get_key_usage(id: &str) -> Resp {
    let plane = match plane_or_err() {
        Ok(plane) => plane,
        Err(response) => return response,
    };
    let record = match load_key(&plane, id) {
        Ok(Some(record)) => record,
        Ok(None) => return not_found("key not found"),
        Err(error) => return internal_error(&error),
    };
    let limits = match governance_limits(&record) {
        Ok(limits) => limits,
        Err(error) => return internal_error(error),
    };
    let snapshot_key = SnapshotKey {
        key_id: record.key_id,
        policy_revision: record.policy_revision,
        limits,
    };
    let store = plane.governance_store();
    match block_on_keystore(async move { store.snapshot(snapshot_key).await }) {
        Ok(snapshot) => ok(json!({ "usage": snapshot })),
        Err(GovernanceError::BackendUnavailable { .. }) => governance_backend_unavailable(),
        Err(error) => internal_error(&format!("governance snapshot: {error}")),
    }
}

fn governance_limits(record: &KeyRecord) -> Result<GovernanceLimits, &'static str> {
    // WOR-2561: the usage snapshot reports the limits enforcement is holding
    // the key to right now, which is the effective budget: base caps plus any
    // unexpired override.
    let budget = record.effective_budget(Utc::now());
    let total_micro_usd = budget
        .as_ref()
        .and_then(|budget| budget.max_cost_usd)
        .map(usd_to_micro_usd)
        .transpose()?;

    Ok(GovernanceLimits {
        requests_per_window: record.max_requests_per_minute,
        tokens_per_window: record.max_tokens_per_minute,
        total_tokens: budget.as_ref().and_then(|budget| budget.max_tokens),
        total_micro_usd,
        window_millis: 60_000,
    })
}

fn usd_to_micro_usd(value: f64) -> Result<u64, &'static str> {
    const MICRO_USD_PER_USD: f64 = 1_000_000.0;

    if !value.is_finite() || value < 0.0 {
        return Err("stored max_budget_usd is not a finite non-negative number");
    }
    let rounded = (value * MICRO_USD_PER_USD).round();
    if !rounded.is_finite() || rounded < 0.0 || rounded >= u64::MAX as f64 {
        return Err("stored max_budget_usd cannot be represented as integer micro-USD");
    }
    Ok(rounded as u64)
}

fn update_key(id: &str, body: Option<&str>) -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let m: KeyMutation = match parse_body(body) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if let Err(e) = validate_key_mutation(&m) {
        return bad_request(&e);
    }
    let expected_revision = match m.expected_revision {
        Some(revision) => revision,
        None => return bad_request("expected_revision is required"),
    };
    let mut rec = match load_key(&plane, id) {
        Ok(Some(r)) => r,
        Ok(None) => return not_found("key not found"),
        Err(e) => return internal_error(&e),
    };
    // The tenant the key will have AFTER this mutation: an explicit value
    // wins, otherwise the one already stored.
    let effective_tenant = match &m.tenant {
        Patch::Value(t) => Some(t.clone()),
        Patch::Null => None,
        Patch::Missing => rec.tenant_id.clone(),
    };
    if let Err(resp) = validate_credential_binding(&plane, &m, effective_tenant.as_deref()) {
        return resp;
    }
    if rec.policy_revision != expected_revision {
        return revision_conflict(id, expected_revision, rec.policy_revision);
    }
    if rec.status == RecordStatus::Revoked {
        return terminal_key(id, rec.policy_revision);
    }
    apply_key_mutation(&mut rec, &m);
    // WOR-2561: a raise only exists relative to a base budget. A PATCH that
    // removes the base entirely leaves any override with nothing to raise,
    // so it goes with it rather than lingering as a badge over no budget.
    if rec.budget.is_none() {
        rec.budget_override = None;
    }
    rec.updated_at = Utc::now();
    let rec = match store_key_if_revision(&plane, rec, expected_revision) {
        Ok(rec) => rec,
        Err(response) => return response,
    };
    invalidate(&plane, id);
    audit_mutation("update", "key", id);
    ok(json!({ "key": KeyView::from(&rec) }))
}

fn delete_key(id: &str) -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let store = plane.cache().store().clone();
    let owned = id.to_string();
    if let Err(e) = block_on_keystore(async move { store.delete_key(&owned).await }) {
        return internal_error(&format!("delete key: {e:#}"));
    }
    invalidate(&plane, id);
    audit_mutation("delete", "key", id);
    ok(json!({ "deleted": true, "key_id": id }))
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RevisionRequest {
    expected_revision: Option<u64>,
}

fn set_key_status(id: &str, status: RecordStatus, body: Option<&str>) -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let request: RevisionRequest = match parse_body(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if request.expected_revision == Some(0) {
        return bad_request("expected_revision must be at least 1");
    }
    let mut rec = match load_key(&plane, id) {
        Ok(Some(r)) => r,
        Ok(None) => return not_found("key not found"),
        Err(e) => return internal_error(&e),
    };
    let expected_revision = request.expected_revision.unwrap_or(rec.policy_revision);
    if rec.policy_revision != expected_revision {
        return revision_conflict(id, expected_revision, rec.policy_revision);
    }
    if rec.status == RecordStatus::Revoked {
        return terminal_key(id, rec.policy_revision);
    }
    let prior_status = rec.status;
    rec.status = status;
    rec.updated_at = Utc::now();
    let rec = match store_key_if_revision(&plane, rec, expected_revision) {
        Ok(rec) => rec,
        Err(response) => return response,
    };
    invalidate(&plane, id);
    audit_mutation_scoped(
        status_verb(status),
        "key",
        id,
        rec.tenant_id.as_deref(),
        Some((prior_status, status)),
    );
    ok(json!({ "key": KeyView::from(&rec) }))
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RotateRequest {
    /// Optional optimistic revision. Omitted actions use the server-read value.
    expected_revision: Option<u64>,
    /// Seconds the prior secret keeps working alongside the new one.
    grace_secs: Option<i64>,
}

/// Default rotation grace window: one hour. Matches the transition windows used
/// by hosted gateways so a client fleet can pick up the new token before the old
/// one stops working.
const DEFAULT_ROTATE_GRACE_SECS: i64 = 3600;

/// WOR-1554: rotate a key with a grace-period dual-key. Mints a fresh secret for
/// the same key_id, keeps the prior hash valid until the grace window expires,
/// and returns the new plaintext token once. Both tokens authenticate during
/// the window (the resolve path accepts the prior hash while it is unexpired);
/// after it, only the new token works, with no extra cleanup needed.
fn rotate_key(id: &str, body: Option<&str>) -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let req: RotateRequest = match parse_body(body) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if req.expected_revision == Some(0) {
        return bad_request("expected_revision must be at least 1");
    }
    let grace_secs = req.grace_secs.unwrap_or(DEFAULT_ROTATE_GRACE_SECS).max(0);
    let mut rec = match load_key(&plane, id) {
        Ok(Some(r)) => r,
        Ok(None) => return not_found("key not found"),
        Err(e) => return internal_error(&e),
    };
    let expected_revision = req.expected_revision.unwrap_or(rec.policy_revision);
    if rec.policy_revision != expected_revision {
        return revision_conflict(id, expected_revision, rec.policy_revision);
    }
    if rec.status == RecordStatus::Revoked {
        return terminal_key(id, rec.policy_revision);
    }
    // Refuse before minting, and mint from the record's own id rather than
    // the URL path segment.
    //
    // `format_token` builds `sbp_<id>_<secret>` from whatever string it is
    // handed, while `parse_minted_token` asserts an exact 85 characters and
    // a 16-lowercase-hex id. A config-seeded id such as `seed0001` produces
    // a 77-character token that parses on no inbound path at all, so the
    // `200 OK` would hand the operator a credential that authenticates
    // nowhere while the grace window quietly runs out on the one that still
    // worked. A 409 naming the reason is the only honest answer: there is
    // no token shape this endpoint can mint for a non-conforming id that
    // the current resolver would accept.
    if !sbproxy_keystore::crypto::is_conforming_key_id(&rec.key_id) {
        return conflict(
            "key id is not in the minted format (16 lowercase hex characters), so a rotated \
             token could not be parsed back by the inbound resolver; create a replacement key \
             with POST /admin/keys and retire this one instead of rotating it",
        );
    }
    let minted = plane.crypto().mint_secret(&rec.key_id);
    let now = Utc::now();
    // The current secret becomes the graced prior secret.
    rec.prev_secret_hash = Some(rec.secret_hash.clone());
    rec.prev_hash_expires_at = Some(now + chrono::Duration::seconds(grace_secs));
    // WOR-2567: what `sbproxy_key_rotation_age_days{kind="key"}` measures
    // from. `updated_at` moves on any policy patch, so it cannot answer
    // "when was this secret last replaced".
    rec.rotated_at = Some(now);
    rec.secret_hash = minted.secret_hash;
    rec.updated_at = now;
    let rec = match store_key_if_revision(&plane, rec, expected_revision) {
        Ok(rec) => rec,
        Err(response) => return response,
    };
    invalidate(&plane, id);
    // Tenant-scoped for the same reason as the mint above (WOR-2571).
    audit_mutation_scoped("rotate", "key", id, rec.tenant_id.as_deref(), None);

    ok(json!({
        // Same `sbp_<key_id>_<secret>` shape create_key returns, so a
        // rotated token is self-identifying on the minted-key sweep just
        // like a freshly created one.
        "token": minted.token,
        "grace_expires_at": rec.prev_hash_expires_at,
        "key": KeyView::from(&rec),
    }))
}

// --- Temporary budget overrides (WOR-2561) ---

/// Longest accepted `reason` on a budget-override grant, so one pathological
/// note cannot dominate the record or the audit trail.
const MAX_BUDGET_OVERRIDE_REASON_BYTES: usize = 256;

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct BudgetOverrideGrantRequest {
    /// Optional optimistic revision. Omitted grants use the server-read value.
    expected_revision: Option<u64>,
    /// Extra total tokens on top of the base `budget.max_tokens`.
    max_tokens_increase: Option<u64>,
    /// Extra USD on top of the base `budget.max_cost_usd`.
    max_cost_usd_increase: Option<f64>,
    /// Seconds from now until the raise expires. Exclusive with `expires_at`.
    ttl_secs: Option<i64>,
    /// Absolute expiry instant. Exclusive with `ttl_secs`.
    expires_at: Option<DateTime<Utc>>,
    /// Optional operator note, kept on the record and in the audit diff.
    reason: Option<String>,
}

/// Grant a temporary raise on the key's base budget. The raise applies at
/// once (the policy cache is invalidated the same way every other key
/// mutation invalidates it) and stops applying at its expiry with no further
/// call: expiry is evaluated lazily wherever the budget is read.
fn grant_budget_override(id: &str, body: Option<&str>) -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let req: BudgetOverrideGrantRequest = match parse_body(body) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if req.expected_revision == Some(0) {
        return bad_request("expected_revision must be at least 1");
    }
    if req.max_tokens_increase.is_none() && req.max_cost_usd_increase.is_none() {
        return bad_request("budget override needs max_tokens_increase or max_cost_usd_increase");
    }
    if req.max_tokens_increase == Some(0) {
        return bad_request("max_tokens_increase must be a positive integer");
    }
    if let Some(value) = req.max_cost_usd_increase {
        if !value.is_finite() || value <= 0.0 {
            return bad_request("max_cost_usd_increase must be a finite positive number");
        }
    }
    if req
        .reason
        .as_ref()
        .is_some_and(|reason| reason.len() > MAX_BUDGET_OVERRIDE_REASON_BYTES)
    {
        return bad_request("reason is longer than 256 bytes");
    }
    let now = Utc::now();
    let expires_at = match (req.ttl_secs, req.expires_at) {
        (Some(_), Some(_)) => {
            return bad_request("use ttl_secs or expires_at, not both");
        }
        (None, None) => {
            return bad_request("budget override needs an expiry: ttl_secs or expires_at");
        }
        (Some(ttl), None) => {
            if ttl < 1 {
                return bad_request("ttl_secs must be at least 1");
            }
            now + chrono::Duration::seconds(ttl)
        }
        (None, Some(instant)) => {
            if instant <= now {
                return bad_request("expires_at must be in the future");
            }
            instant
        }
    };
    let mut rec = match load_key(&plane, id) {
        Ok(Some(r)) => r,
        Ok(None) => return not_found("key not found"),
        Err(e) => return internal_error(&e),
    };
    let expected_revision = req.expected_revision.unwrap_or(rec.policy_revision);
    if rec.policy_revision != expected_revision {
        return revision_conflict(id, expected_revision, rec.policy_revision);
    }
    if rec.status == RecordStatus::Revoked {
        return terminal_key(id, rec.policy_revision);
    }
    // A raise only lifts caps that exist. Refusing here, rather than storing
    // a no-op grant, is what tells the operator the number on their screen
    // will not change.
    let Some(base) = rec.budget.as_ref() else {
        return bad_request(
            "key has no base budget to raise; set max_budget_tokens or max_budget_usd first",
        );
    };
    if req.max_tokens_increase.is_some() && base.max_tokens.is_none() {
        return bad_request(
            "max_tokens_increase raises max_budget_tokens, which this key does not cap",
        );
    }
    if req.max_cost_usd_increase.is_some() && base.max_cost_usd.is_none() {
        return bad_request(
            "max_cost_usd_increase raises max_budget_usd, which this key does not cap",
        );
    }
    // Refuse a raise whose applied sum the enforcement path could not
    // represent, so the stored record can never fail closed at lowering.
    if let (Some(base_usd), Some(increase)) = (base.max_cost_usd, req.max_cost_usd_increase) {
        if usd_to_micro_usd(base_usd + increase).is_err() {
            return bad_request(
                "max_cost_usd_increase plus the base cap cannot be represented as micro-USD",
            );
        }
    }
    let before = rec.budget_override.clone();
    rec.budget_override = Some(BudgetOverride {
        max_tokens_increase: req.max_tokens_increase,
        max_cost_usd_increase: req.max_cost_usd_increase,
        expires_at,
        // WOR-2094's thread-local names the authenticated operator; a grant
        // arriving outside an authenticated admin dispatch is recorded as
        // unattributed rather than inventing an identity.
        granted_by: crate::admin::current_admin_actor()
            .filter(|actor| !actor.is_empty())
            .unwrap_or_else(|| "unattributed".to_string()),
        granted_at: now,
        reason: req.reason,
    });
    rec.updated_at = now;
    let rec = match store_key_if_revision(&plane, rec, expected_revision) {
        Ok(rec) => rec,
        Err(response) => return response,
    };
    invalidate(&plane, id);
    audit_budget_override(
        "budget_override_grant",
        id,
        rec.tenant_id.as_deref(),
        before.as_ref(),
        rec.budget_override.as_ref(),
        true,
    );
    ok(json!({ "key": KeyView::from(&rec) }))
}

/// End a raise early. The base budget resumes immediately. Clearing a raise
/// that already lapsed retires it exactly the way a read would, with the
/// expiry audit record rather than a clear record.
fn clear_budget_override(id: &str, body: Option<&str>) -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let request: RevisionRequest = match parse_body(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if request.expected_revision == Some(0) {
        return bad_request("expected_revision must be at least 1");
    }
    let mut rec = match load_key(&plane, id) {
        Ok(Some(r)) => r,
        Ok(None) => return not_found("key not found"),
        Err(e) => return internal_error(&e),
    };
    let expected_revision = request.expected_revision.unwrap_or(rec.policy_revision);
    if rec.policy_revision != expected_revision {
        return revision_conflict(id, expected_revision, rec.policy_revision);
    }
    if rec.status == RecordStatus::Revoked {
        return terminal_key(id, rec.policy_revision);
    }
    let Some(before) = rec.budget_override.take() else {
        return not_found("no budget override to clear");
    };
    let now = Utc::now();
    let was_active = before.is_active(now);
    rec.updated_at = now;
    let rec = match store_key_if_revision(&plane, rec, expected_revision) {
        Ok(rec) => rec,
        Err(response) => return response,
    };
    invalidate(&plane, id);
    audit_budget_override(
        if was_active {
            "budget_override_clear"
        } else {
            "budget_override_expire"
        },
        id,
        rec.tenant_id.as_deref(),
        Some(&before),
        None,
        was_active,
    );
    ok(json!({ "key": KeyView::from(&rec) }))
}

/// Retire a lapsed override from a record the admin plane is about to show.
///
/// Enforcement never needs this: [`KeyRecord::effective_budget`] ignores an
/// expired override wherever the budget is read. This is bookkeeping, so the
/// expiry lands in the audit trail exactly once and the record stops carrying
/// a grant that no longer does anything. The write is a compare-and-swap at
/// the revision this read observed: whichever reader wins emits the audit
/// record, a loser just returns what it read (the view already hides expired
/// overrides), and a backend without CAS skips retirement rather than risking
/// a lost concurrent mutation.
fn retire_expired_override(plane: &KeyPlane, rec: KeyRecord) -> KeyRecord {
    let now = Utc::now();
    let expired = rec
        .budget_override
        .as_ref()
        .is_some_and(|grant| !grant.is_active(now));
    if !expired {
        return rec;
    }
    let mut cleared = rec.clone();
    let before = cleared.budget_override.take();
    cleared.updated_at = now;
    match store_key_if_revision(plane, cleared, rec.policy_revision) {
        Ok(stored) => {
            invalidate(plane, &stored.key_id);
            audit_budget_override(
                "budget_override_expire",
                &stored.key_id,
                stored.tenant_id.as_deref(),
                before.as_ref(),
                None,
                false,
            );
            stored
        }
        Err(response) => {
            // Losing this CAS is expected under a polling console: a
            // concurrent PATCH bumped the revision between the read and
            // the retirement write. Enforcement is unaffected either
            // way (`effective_budget` filters on `is_active(now)`
            // wherever the budget is read) and the next admin read
            // retries, so this is not an error. It is still a write
            // that did not happen, and swallowing it entirely left no
            // way to tell "retirement is racing" from "retirement is
            // broken".
            tracing::debug!(
                key_id = %rec.key_id,
                status = response.0,
                "budget-override retirement lost its compare-and-swap; the lapsed grant stays \
                 on the record until the next admin read"
            );
            rec
        }
    }
}

/// Secret-free audit projection of one override, for the audit diff.
fn budget_override_audit_value(grant: &BudgetOverride) -> serde_json::Value {
    json!({
        "max_tokens_increase": grant.max_tokens_increase,
        "max_cost_usd_increase": grant.max_cost_usd_increase,
        "expires_at": grant.expires_at,
        "granted_by": grant.granted_by,
        "reason": grant.reason,
    })
}

/// Emit a `key_audit` record for a budget-override mutation. `attributed`
/// distinguishes an operator's act (grant, early clear) from time doing the
/// work (expiry), which carries no actor.
fn audit_budget_override(
    op: &str,
    id: &str,
    tenant_id: Option<&str>,
    before: Option<&BudgetOverride>,
    after: Option<&BudgetOverride>,
    attributed: bool,
) {
    let mut entry = sbproxy_observe::KeyAuditEntry::new(op, "key", id);
    if attributed {
        if let Some(actor) = crate::admin::current_admin_actor() {
            entry = entry.with_actor(actor);
        }
    }
    if let Some(tenant_id) = tenant_id {
        entry = entry.with_tenant_id(tenant_id);
    }
    entry = entry.with_diff(
        Some(json!({
            "budget_override": before.map(budget_override_audit_value)
        })),
        Some(json!({
            "budget_override": after.map(budget_override_audit_value)
        })),
    );
    entry.emit();
}

// --- Credential handlers ---

#[derive(Default, Deserialize)]
struct CredentialCreate {
    /// Optional stable id; generated when omitted.
    id: Option<String>,
    name: Option<String>,
    provider: Option<String>,
    kind: Option<String>,
    /// A secret reference resolved by the vault at use (`vault://`, `awssm://`).
    vault_ref: Option<String>,
    /// A plaintext secret to envelope-encrypt at rest (needs a master key).
    secret: Option<String>,
    tenant: Option<String>,
    /// Upstream header this credential is written to. Defaults to
    /// `authorization`.
    header: Option<String>,
    /// Scheme prefix on the header value. Defaults to `Bearer `. Send an empty
    /// string for raw-value headers such as `x-api-key`.
    scheme: Option<String>,
    /// Lease this credential from a dynamic-secrets mount instead of
    /// storing anything static (WOR-2569). Mutually exclusive with
    /// `secret` and `vault_ref`.
    #[serde(default)]
    lease: Option<LeaseRequest>,
}

/// The `lease:` block of a credential create (WOR-2569).
#[derive(Debug, Deserialize)]
struct LeaseRequest {
    /// Secret reference naming the dynamic-secrets mount, for example
    /// `vault://aws/creds/sbproxy-bedrock`.
    reference: String,
    /// `aws`, `gcp`, `azure`, or `database`.
    platform: String,
    /// The mount's configured lease lifetime, in seconds. Resolved
    /// material is never cached past it.
    lease_duration_secs: u64,
}

/// Redacted `Debug` (WOR-2640). `secret` is the plaintext credential an
/// operator POSTs to the admin API; a `{:?}` of a rejected request body
/// would put it in the admin log.
impl std::fmt::Debug for CredentialCreate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialCreate")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("provider", &self.provider)
            .field("kind", &self.kind)
            .field("vault_ref", &self.vault_ref)
            .field("secret", &self.secret.as_ref().map(|_| "[REDACTED]"))
            .field("tenant", &self.tenant)
            .field("header", &self.header)
            .field("scheme", &self.scheme)
            // Non-exhaustive: `lease` was added without an arm here, and
            // the next credential-shaped field would be too. `finish()`
            // renders an untrue exhaustive struct and invites exactly that.
            .finish_non_exhaustive()
    }
}

#[derive(Default, Deserialize)]
struct CredentialUpdate {
    name: Option<String>,
    provider: Option<String>,
    kind: Option<String>,
    vault_ref: Option<String>,
    secret: Option<String>,
    tenant: Option<String>,
}

/// Redacted `Debug` (WOR-2640). As [`CredentialCreate`].
impl std::fmt::Debug for CredentialUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialUpdate")
            .field("name", &self.name)
            .field("provider", &self.provider)
            .field("kind", &self.kind)
            .field("vault_ref", &self.vault_ref)
            .field("secret", &self.secret.as_ref().map(|_| "[REDACTED]"))
            .field("tenant", &self.tenant)
            .finish()
    }
}

fn create_credential(body: Option<&str>) -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let c: CredentialCreate = match parse_body(body) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let id =
        c.id.clone()
            .unwrap_or_else(sbproxy_keystore::crypto::random_id);
    // Reject a header the proxy could never legally set on an upstream
    // request, at the boundary rather than at dispatch time.
    let credential_header = c
        .header
        .as_deref()
        .map(|h| h.trim().to_ascii_lowercase())
        .unwrap_or_else(sbproxy_keystore::record::default_cred_header);
    if http::header::HeaderName::from_bytes(credential_header.as_bytes()).is_err() {
        return bad_request("header is not a valid HTTP header name");
    }
    if sbproxy_config::types::credential_header_is_reserved(&credential_header) {
        return bad_request("header may not be used to carry a credential");
    }
    let material = match &c.lease {
        Some(lease) => {
            if c.secret.is_some() || c.vault_ref.is_some() {
                return bad_request(
                    "a leased credential stores nothing static, so lease is mutually exclusive \
                     with secret and vault_ref",
                );
            }
            match build_leased_material(lease, c.provider.as_deref()) {
                Ok(m) => m,
                Err(e) => return bad_request(&e),
            }
        }
        None => match build_material(&plane, &id, c.vault_ref.as_deref(), c.secret.as_deref()) {
            Ok(m) => m,
            Err(e) => return bad_request(&e),
        },
    };
    let now = Utc::now();
    let rec = CredentialRecord {
        id: id.clone(),
        name: c.name.unwrap_or_else(|| id.clone()),
        provider: c.provider,
        kind: c.kind.unwrap_or_else(|| "ai_provider".to_string()),
        header: credential_header,
        scheme: c
            .scheme
            .unwrap_or_else(sbproxy_keystore::record::default_cred_scheme),
        material,
        status: RecordStatus::Active,
        tenant_id: c.tenant,
        metadata: Default::default(),
        created_at: now,
        updated_at: now,
        source: sbproxy_keystore::record::RecordSource::Api,
        rotated_at: None,
        prev_material: None,
        prev_material_expires_at: None,
    };
    if let Err(e) = store_credential(&plane, rec.clone()) {
        return internal_error(&e);
    }
    invalidate(&plane, &id);
    // Tenant-scoped for the same reason as the key mint (WOR-2571).
    audit_mutation_scoped("create", "credential", &id, rec.tenant_id.as_deref(), None);
    created(json!({ "credential": CredentialView::from(&rec) }))
}

fn list_credentials() -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let store = plane.cache().store().clone();
    match block_on_keystore(async move { store.list_credentials().await }) {
        Ok(mut creds) => {
            // WOR-2567: retire material whose overlap window has closed, on
            // the same read that publishes the rotation gauge and for the
            // same reason `list_keys` retires lapsed budget overrides here.
            // The field doc promises the store does not keep a retired
            // secret indefinitely, and nothing else makes that true: the
            // resolution path only declines to serve it.
            //
            // Bounded, because each retirement is a blocking store write on
            // the request thread. Past the cap the rest are retired by the
            // next listing; what is deferred is the write, never the
            // refusal to serve, which `usable_prev_material` already
            // enforces from the record itself.
            let retire_now = Utc::now();
            let mut retired = 0usize;
            for record in creds.iter_mut() {
                if retired >= MAX_RETIREMENTS_PER_LIST {
                    break;
                }
                if record.retire_expired_prev_material(retire_now) {
                    retired += 1;
                    if let Err(e) = store_credential(&plane, record.clone()) {
                        tracing::warn!(
                            credential_id = %record.id,
                            error = %e,
                            "could not retire a credential's expired rotation overlap; the \
                             material stays on disk until the next listing"
                        );
                    } else {
                        invalidate(&plane, &record.id);
                    }
                }
            }
            let creds = creds;
            // WOR-2567: publish the oldest un-rotated credential's age
            // here rather than from a timer. This route is what the admin
            // console and the operator's own scripts already poll, so the
            // gauge is refreshed by the thing that was going to look at
            // it anyway, and a deployment that never lists never pays.
            // Compared against `key_management.crypto.rotation.credential_days`,
            // this is what turns "rotate periodically" into an alert.
            let now = Utc::now();
            if let Some(oldest) = creds.iter().map(|c| c.rotation_age_days(now)).max() {
                sbproxy_observe::metrics::record_rotation_age_days("credential", oldest as f64);
            }
            let views: Vec<CredentialView> = creds.iter().map(CredentialView::from).collect();
            ok(json!({ "credentials": views }))
        }
        Err(e) => internal_error(&format!("list credentials: {e:#}")),
    }
}

fn get_credential(id: &str) -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    match load_credential(&plane, id) {
        Ok(Some(rec)) => ok(json!({ "credential": CredentialView::from(&rec) })),
        Ok(None) => not_found("credential not found"),
        Err(e) => internal_error(&e),
    }
}

fn update_credential(id: &str, body: Option<&str>) -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let c: CredentialUpdate = match parse_body(body) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut rec = match load_credential(&plane, id) {
        Ok(Some(r)) => r,
        Ok(None) => return not_found("credential not found"),
        Err(e) => return internal_error(&e),
    };
    if let Some(v) = c.name {
        rec.name = v;
    }
    if c.provider.is_some() {
        rec.provider = c.provider;
    }
    if let Some(v) = c.kind {
        rec.kind = v;
    }
    if c.tenant.is_some() {
        rec.tenant_id = c.tenant;
    }
    if c.vault_ref.is_some() || c.secret.is_some() {
        match build_material(&plane, id, c.vault_ref.as_deref(), c.secret.as_deref()) {
            Ok(m) => rec.material = m,
            Err(e) => return bad_request(&e),
        }
    }
    rec.updated_at = Utc::now();
    if let Err(e) = store_credential(&plane, rec.clone()) {
        return internal_error(&e);
    }
    invalidate(&plane, id);
    audit_mutation("update", "credential", id);
    ok(json!({ "credential": CredentialView::from(&rec) }))
}

fn delete_credential(id: &str) -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    // Refuse while keys still bind this credential. Deleting it would leave
    // those keys resolving to nothing, and since a bound key fails closed
    // rather than falling back, every request on them would start returning
    // 503 with no obvious cause. Name the keys so the operator can unbind
    // them (PATCH with `"credential_id": null`) and retry.
    let bound = {
        let store = plane.cache().store().clone();
        match block_on_keystore(async move { store.list_keys().await }) {
            Ok(keys) => keys
                .into_iter()
                .filter(|k| k.credential_id.as_deref() == Some(id))
                .map(|k| k.key_id)
                .collect::<Vec<_>>(),
            Err(e) => return internal_error(&format!("list keys: {e:#}")),
        }
    };
    if !bound.is_empty() {
        return conflict(&format!(
            "credential is bound by {} key(s): {}. Clear credential_id on them first.",
            bound.len(),
            bound.join(", ")
        ));
    }
    let store = plane.cache().store().clone();
    let owned = id.to_string();
    if let Err(e) = block_on_keystore(async move { store.delete_credential(&owned).await }) {
        return internal_error(&format!("delete credential: {e:#}"));
    }
    invalidate(&plane, id);
    audit_mutation("delete", "credential", id);
    ok(json!({ "deleted": true, "id": id }))
}

fn set_credential_status(id: &str, status: RecordStatus) -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let mut rec = match load_credential(&plane, id) {
        Ok(Some(r)) => r,
        Ok(None) => return not_found("credential not found"),
        Err(e) => return internal_error(&e),
    };
    let prior_status = rec.status;
    rec.status = status;
    rec.updated_at = Utc::now();
    if let Err(e) = store_credential(&plane, rec.clone()) {
        return internal_error(&e);
    }
    invalidate(&plane, id);
    audit_mutation_scoped(
        status_verb(status),
        "credential",
        id,
        rec.tenant_id.as_deref(),
        Some((prior_status, status)),
    );
    ok(json!({ "credential": CredentialView::from(&rec) }))
}

/// Turn a `lease:` request block into leased material, refusing the
/// combinations that cannot work (WOR-2569).
///
/// The refusal on an unsupported provider is the load-bearing one.
/// Accepting `leased` for OpenAI and quietly reading the reference once
/// would produce a credential that looks leased on the admin view, never
/// expires, and is exactly as static as the thing it replaced. Naming the
/// limitation costs an operator one error and saves them that.
///
/// # Errors
///
/// An unknown platform, a zero lease duration, or a provider whose
/// platform cannot mint short-lived credentials.
fn build_leased_material(
    lease: &LeaseRequest,
    provider: Option<&str>,
) -> Result<CredentialMaterial, String> {
    let platform = match lease.platform.trim().to_ascii_lowercase().as_str() {
        "aws" => LeasePlatform::Aws,
        "gcp" => LeasePlatform::Gcp,
        "azure" => LeasePlatform::Azure,
        "database" => LeasePlatform::Database,
        other => {
            return Err(format!(
                "lease.platform '{other}' is not a platform that can mint short-lived \
                 credentials. Use aws, gcp, azure, or database. Most AI provider API keys have \
                 no short-TTL issuance to lease against, so there is nothing to mint"
            ))
        }
    };
    if lease.reference.trim().is_empty() {
        return Err("lease.reference must name a dynamic-secrets mount".to_string());
    }
    if lease.lease_duration_secs == 0 {
        return Err(
            "lease.lease_duration_secs must be greater than zero; it is the ceiling on how long \
             resolved material may be cached"
                .to_string(),
        );
    }
    if !platform.accepts_provider(provider) {
        return Err(format!(
            "provider '{}' cannot be leased against platform '{}'. Leasing needs a platform that \
             mints short-lived credentials (AWS, GCP, or Azure IAM, or a Vault-fronted database \
             mount); an AI provider API key has no short-TTL issuance to lease against, so a \
             leased record would be exactly as static as a stored one",
            provider.unwrap_or("(none)"),
            platform.label()
        ));
    }
    Ok(CredentialMaterial::Leased {
        reference: lease.reference.trim().to_string(),
        platform,
        lease_duration_secs: lease.lease_duration_secs,
    })
}

/// Build credential material from the request, preferring a vault reference.
fn build_material(
    plane: &KeyPlane,
    id: &str,
    vault_ref: Option<&str>,
    secret: Option<&str>,
) -> Result<CredentialMaterial, String> {
    if let Some(reference) = vault_ref {
        Ok(CredentialMaterial::VaultRef {
            reference: reference.to_string(),
        })
    } else if let Some(secret) = secret {
        // WOR-2568: `seal_async` through `block_on_keystore`, not the
        // synchronous `seal`. Under a customer-managed root the wrap is a
        // call to the external key service, and the synchronous path
        // refuses outright rather than falling back to a local wrap. This
        // is the admin path, which is what `block_on_keystore` is for.
        let crypto = plane.crypto().clone();
        let record_id = id.to_string();
        let plaintext = secret.as_bytes().to_vec();
        let envelope =
            block_on_keystore(async move { crypto.seal_async(&record_id, &plaintext).await })
                .map_err(|e| format!("seal credential: {e:#}"))?;
        Ok(CredentialMaterial::Envelope { envelope })
    } else {
        Err("credential requires either vault_ref or secret".to_string())
    }
}

/// Body of `POST /admin/credentials/{id}/rotate` (WOR-2567).
#[derive(Deserialize)]
struct RotateCredentialBody {
    /// New plaintext secret, sealed into an envelope under whichever root
    /// of trust is configured. Mutually exclusive with `vault_ref`.
    #[serde(default)]
    secret: Option<String>,
    /// New secret reference. Mutually exclusive with `secret`.
    #[serde(default)]
    vault_ref: Option<String>,
    /// How long the previous material stays usable, in seconds. Defaults
    /// to `key_management.crypto.rotation.credential_grace_secs`. Zero
    /// retires the old material immediately, which is the right choice
    /// when the old secret is known to be compromised.
    #[serde(default)]
    grace_secs: Option<u64>,
}

/// Rotate an upstream credential's material with a bounded overlap window.
///
/// `rotate_key` has done this for inbound keys since WOR-1554, and
/// rotating an upstream credential was a full `PATCH` overwrite with no
/// overlap: the instant the write landed, every request presented the new
/// secret, and if that secret was not yet live at the provider the
/// deployment took the outage. This is the same dual-validity shape from
/// the other side.
///
/// What "dual validity" means here is narrower than for an inbound key and
/// worth stating plainly, because the two are easy to conflate. sbproxy
/// *presents* an upstream credential rather than validating one, so there
/// is no old-value acceptance to do. The overlap is a fallback: the new
/// material is what every request uses, and the previous material is
/// reached only when the new one will not open or the upstream refuses it,
/// and only while the window is open. A rotation that works never presents
/// the retired secret at all.
///
/// The response never carries either secret. Unlike `rotate_key`, which
/// mints a token and shows it once, this endpoint is given the new secret
/// by the operator, so there is nothing to show back.
fn rotate_credential(id: &str, body: Option<&str>) -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let request: RotateCredentialBody = match body {
        Some(raw) if !raw.trim().is_empty() => match serde_json::from_str(raw) {
            Ok(v) => v,
            // Not the raw serde message. This body carries a plaintext
            // upstream credential and serde's `invalid type` text embeds
            // the offending scalar, so a mistyped field would answer
            // `invalid type: string "sk-live-...", expected u64`. The
            // create and update bodies carry one too and get the same
            // scrub inside `parse_body`; this route parses on its own
            // path, hence the second call.
            Err(e) => {
                return bad_request(&format!(
                    "invalid JSON body: {}",
                    sbproxy_config::origin_profile::redact_serde_message(&e.to_string())
                ))
            }
        },
        _ => return bad_request("rotate requires a new secret or vault_ref"),
    };
    if request.secret.is_some() && request.vault_ref.is_some() {
        return bad_request("rotate accepts either secret or vault_ref, not both");
    }
    let mut rec = match load_credential(&plane, id) {
        Ok(Some(r)) => r,
        Ok(None) => return not_found("credential not found"),
        Err(e) => return internal_error(&e),
    };
    if rec.status == RecordStatus::Revoked {
        // Revoked is terminal for a key and is terminal here too: a
        // rotation that quietly reactivated a revoked credential would
        // make revocation reversible by anyone who can rotate.
        return (
            409,
            "application/json",
            r#"{"error":"credential is revoked; revocation is terminal"}"#.to_string(),
        );
    }
    let material = match build_material(
        &plane,
        id,
        request.vault_ref.as_deref(),
        request.secret.as_deref(),
    ) {
        Ok(m) => m,
        Err(e) => return bad_request(&e),
    };
    let grace_secs = request
        .grace_secs
        .unwrap_or_else(|| plane.credential_rotation_grace_secs());
    // `chrono::Duration::seconds` is `expect(try_seconds(..))` and panics
    // past `i64::MAX / 1_000`, and a bare `as i64` on a large `u64` wraps
    // negative, which would silently produce an already-expired overlap
    // while the 200 response reported the window as open. This value comes
    // straight off an admin JSON body, so both are reachable by anyone who
    // can call the route. `lifecycle.rs`'s `registry_duration` is the same
    // refusal for the same trap on config values; the unwrap ratchet cannot
    // see either, because the `expect` lives in chrono.
    let Some(overlap) = i64::try_from(grace_secs)
        .ok()
        .and_then(chrono::Duration::try_seconds)
    else {
        return bad_request(&format!(
            "grace_secs is {grace_secs}, which is not a duration sbproxy can represent; use a \
             value below {}",
            i64::MAX / 1_000
        ));
    };
    let now = Utc::now();
    // A rotation whose previous overlap has already lapsed must not carry
    // that older material forward; retire it before the new one takes its
    // place.
    rec.retire_expired_prev_material(now);
    let previous = std::mem::replace(&mut rec.material, material);
    if grace_secs == 0 {
        rec.prev_material = None;
        rec.prev_material_expires_at = None;
    } else {
        rec.prev_material = Some(previous);
        rec.prev_material_expires_at = Some(now + overlap);
    }
    rec.rotated_at = Some(now);
    rec.updated_at = now;
    if let Err(e) = store_credential(&plane, rec.clone()) {
        return internal_error(&e);
    }
    // Drop both the record cache and the resolved-secret cache: without
    // the second, every replica keeps presenting the pre-rotation
    // plaintext it already opened until its own TTL lapses, which is the
    // failure mode a rotation exists to close.
    invalidate(&plane, id);
    audit_mutation_scoped("rotate", "credential", id, rec.tenant_id.as_deref(), None);
    ok(json!({
        "credential": CredentialView::from(&rec),
        "overlap": {
            "grace_secs": grace_secs,
            "previous_material_expires_at": rec.prev_material_expires_at,
            "effect": if grace_secs == 0 {
                "the previous material was retired immediately"
            } else {
                "the previous material is used only if the new material will not resolve, and only until it expires"
            },
        },
    }))
}

// --- Break-glass (WOR-2573) and root of trust (WOR-2568) ---

/// Body of `POST /admin/break-glass`.
///
/// `Default` only so this can go through `parse_body`, which carries
/// the serde-message scrub. The empty-body case is refused above it,
/// before a default could be used: a grant with no justification, no
/// scope, and a zero TTL is exactly what the route rejects.
#[derive(Deserialize, Default)]
struct BreakGlassRequestBody {
    /// Why this grant is needed. Read by the post-access reviewer.
    justification: String,
    /// Key or credential ids, or tenant names, this grant covers.
    #[serde(default)]
    scope: Vec<String>,
    /// Requested lifetime. Refused above
    /// `key_management.break_glass.max_ttl_secs` rather than clamped.
    ttl_secs: u64,
}

/// Body of `POST /admin/break-glass/{id}/review`.
#[derive(Deserialize, Default)]
struct BreakGlassReviewBody {
    /// The reviewer's note. Bounded and non-secret; it lands in the audit
    /// chain beside the grant.
    #[serde(default)]
    note: String,
}

fn break_glass_subroute(method: &str, rest: &str, body: Option<&str>) -> Resp {
    let mut parts = rest.splitn(2, '/');
    let id = parts.next().unwrap_or("");
    let action = parts.next();
    if id.is_empty() {
        return not_found("missing break-glass grant id");
    }
    let Some(actor) = crate::admin::current_admin_actor() else {
        return break_glass_error(&crate::break_glass::BreakGlassError::NoActor);
    };
    if !method.eq_ignore_ascii_case("POST") {
        return method_not_allowed();
    }
    match action {
        Some("approve") => match crate::break_glass::approve(id, &actor) {
            Ok(grant) => ok(json!({ "grant": grant_view(&grant) })),
            Err(e) => break_glass_error(&e),
        },
        Some("review") => {
            let note = match body {
                Some(raw) if !raw.trim().is_empty() => {
                    // Through `parse_body`'s scrub, not a raw `{e}`.
                    // `parse_body`'s own doc says the point of putting
                    // the scrub there is that "a route added later
                    // gets it without anyone remembering", and these
                    // two break-glass bodies were the two routes that
                    // parsed on their own path and did not.
                    match parse_body::<BreakGlassReviewBody>(Some(raw)) {
                        Ok(v) => v.note,
                        Err(resp) => return resp,
                    }
                }
                _ => String::new(),
            };
            match crate::break_glass::review(id, &actor, &note) {
                Ok(grant) => ok(json!({ "grant": grant_view(&grant) })),
                Err(e) => break_glass_error(&e),
            }
        }
        _ => not_found("unknown break-glass action"),
    }
}

fn create_break_glass_grant(body: Option<&str>) -> Resp {
    let Some(actor) = crate::admin::current_admin_actor() else {
        return break_glass_error(&crate::break_glass::BreakGlassError::NoActor);
    };
    let request: BreakGlassRequestBody = match body {
        // As the review route below: `parse_body` carries the scrub.
        Some(raw) if !raw.trim().is_empty() => match parse_body(Some(raw)) {
            Ok(v) => v,
            Err(resp) => return resp,
        },
        _ => return bad_request("break-glass requires justification, scope, and ttl_secs"),
    };
    match crate::break_glass::request(
        &actor,
        &request.justification,
        request.scope,
        request.ttl_secs,
    ) {
        Ok(grant) => created(json!({ "grant": grant_view(&grant) })),
        Err(e) => break_glass_error(&e),
    }
}

/// The JSON view of one grant, rendered against the live config so the
/// "approvals still needed" count reflects the configured quorum.
fn grant_view(grant: &crate::break_glass::Grant) -> serde_json::Value {
    match current_key_plane() {
        Some(plane) => grant.view(Utc::now(), plane.break_glass()),
        None => json!({ "id": grant.id }),
    }
}

/// Map a break-glass refusal onto an HTTP status.
///
/// 403 for the two that are authorization decisions (self-approval, not an
/// approver), 409 for a state mismatch, 404 for an unknown id, 400 for a
/// malformed request. A self-approval attempt gets its own status because
/// it is the one an operator is most likely to try and most needs to
/// understand was deliberate.
fn break_glass_error(error: &crate::break_glass::BreakGlassError) -> Resp {
    use crate::break_glass::BreakGlassError as E;
    let status = match error {
        E::Disabled => 409,
        E::NoActor => 401,
        E::TtlOutOfRange(_) | E::UnscopedRequest | E::NoJustification => 400,
        E::NotFound => 404,
        E::SelfApproval | E::SelfReview | E::NotAnApprover(_) => 403,
        E::AlreadyApproved | E::WrongState(_) | E::RegistryFull(_) => 409,
    };
    (
        status,
        "application/json",
        json!({ "error": error.to_string() }).to_string(),
    )
}

/// `GET /admin/crypto/root-of-trust` (WOR-2568).
///
/// The page a security reviewer opens first: is our root of trust
/// customer-held right now, when did we last confirm the key service still
/// authorizes us, and how long after a revocation does decryption actually
/// stop. That last number is the product claim, so it is printed rather
/// than left for the reader to derive from a TTL somewhere else.
///
/// A JSON route rather than a console page. The console surface is
/// WOR-2574's; this route is what that page will read, and it is complete
/// on its own for an operator with curl.
fn get_root_of_trust() -> Resp {
    let Some(plane) = current_key_plane() else {
        return ok(json!({
            "mode": "disabled",
            "detail": "key_management is not enabled, so no key plane holds a root of trust",
        }));
    };
    let Some(root) = plane.crypto().root_of_trust() else {
        return ok(json!({
            "mode": "local",
            "detail": "the envelope data key is wrapped by a key derived from \
                       key_management.crypto.master_key, which this process holds. Revoking an \
                       external grant does not stop decryption in this mode.",
            "rotation": {
                "master_key_days": plane.master_key_crypto_period_days(),
                "credential_days": plane.credential_crypto_period_days(),
                "inbound_key_days": plane.inbound_key_crypto_period_days(),
            },
        }));
    };
    let window = root.revocation_window().as_secs();
    let status = crate::key_root_of_trust::describe(root);
    ok(json!({
        "mode": "customer_managed",
        "kek": root.kek_name(),
        "revocation_window_secs": window,
        "detail": format!(
            "the envelope data key is wrapped by the external key service and is never held \
             here. After the customer revokes sbproxy's grant, decryption of customer-managed \
             credentials stops within {window} seconds, or at the next failed liveness probe, \
             whichever comes first. The {window} seconds is the whole exposure, not the first \
             of two: a decrypted credential inherits the time left on the data key that opened \
             it rather than starting a fresh window."
        ),
        "liveness": status,
        "rotation": {
            "master_key_days": plane.master_key_crypto_period_days(),
            "credential_days": plane.credential_crypto_period_days(),
            "inbound_key_days": plane.inbound_key_crypto_period_days(),
        },
    }))
}

// --- Response DTOs (never carry secrets) ---

#[derive(Serialize)]
struct KeyView {
    key_id: String,
    policy_revision: u64,
    /// Digest of the canonical secret-free effective policy when the record
    /// owns a tenant.
    ///
    /// Tenantless records inherit the request origin, so they have no single
    /// runtime digest. Their origin-scoped digest is available from policy
    /// preview. `None` also keeps malformed legacy records listable without
    /// pretending they have a request-enforceable policy.
    policy_digest: Option<String>,
    name: Option<String>,
    status: RecordStatus,
    max_requests_per_minute: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens_per_minute: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<String>,
    budget: Option<RecordBudget>,
    /// WOR-2561: the active temporary raise on the base budget, when one is
    /// granted and unexpired at view time. An expired override is never
    /// shown: the read path retires it, and the view recomputes activity
    /// against the clock so the two cannot disagree.
    #[serde(skip_serializing_if = "Option::is_none")]
    budget_override: Option<BudgetOverride>,
    /// The budget the enforcement path is comparing spend against right now:
    /// the base caps plus any active override. Equals `budget` when no
    /// override is active.
    #[serde(skip_serializing_if = "Option::is_none")]
    effective_budget: Option<RecordBudget>,
    allowed_models: Vec<String>,
    blocked_models: Vec<String>,
    allowed_providers: Vec<String>,
    blocked_providers: Vec<String>,
    allowed_tools: Option<Vec<String>>,
    require_pii_redaction: Vec<String>,
    principal_selectors: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    route_to_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    compression_profile: Option<String>,
    inject_tools: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    inject_mcp: Option<serde_json::Value>,
    bypass_prompt_injection: bool,
    allow_content_capture: bool,
    project: Option<String>,
    user: Option<String>,
    tags: Vec<String>,
    metadata: std::collections::BTreeMap<String, String>,
    tenant_id: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    source: sbproxy_keystore::record::RecordSource,
    /// True while a rotation grace window is open (the prior secret still works).
    ///
    /// WOR-2346: this used to be `prev_secret_hash.is_some()`, and nothing
    /// ever clears `prev_secret_hash`, so every key that had ever been
    /// rotated reported `true` forever. The flag disagreed with its own
    /// documentation and with the code that decides the question.
    ///
    /// The authority is `KeyRecord::verify_secret`, which accepts the
    /// prior hash only while `prev_hash_expires_at > now`. This is
    /// computed the same way, so the badge an operator reads and the
    /// check the request path performs cannot disagree. It self-clears
    /// when the window lapses, which is why no "confirm rotation" action
    /// is needed to make it honest.
    rotation_pending: bool,
}

impl From<&KeyRecord> for KeyView {
    fn from(r: &KeyRecord) -> Self {
        let now = Utc::now();
        Self {
            key_id: r.key_id.clone(),
            policy_revision: r.policy_revision,
            policy_digest: key_record_policy_digest(r),
            name: r.name.clone(),
            status: r.status,
            max_requests_per_minute: r.max_requests_per_minute,
            max_tokens_per_minute: r.max_tokens_per_minute,
            priority: r.priority.clone(),
            budget: r.budget.clone(),
            budget_override: r.active_budget_override(now).cloned(),
            effective_budget: r.effective_budget(now),
            allowed_models: r.allowed_models.clone(),
            blocked_models: r.blocked_models.clone(),
            allowed_providers: r.allowed_providers.clone(),
            blocked_providers: r.blocked_providers.clone(),
            allowed_tools: r.allowed_tools.clone(),
            require_pii_redaction: r.require_pii_redaction.clone(),
            principal_selectors: r.principal_selectors.clone(),
            route_to_model: r.route_to_model.clone(),
            compression_profile: r.compression_profile.clone(),
            inject_tools: r.inject_tools.clone(),
            inject_mcp: r.inject_mcp.clone(),
            bypass_prompt_injection: r.bypass_prompt_injection,
            allow_content_capture: r.allow_content_capture,
            project: r.project.clone(),
            user: r.user.clone(),
            tags: r.tags.clone(),
            metadata: r.metadata.clone(),
            tenant_id: r.tenant_id.clone(),
            expires_at: r.expires_at,
            created_at: r.created_at,
            updated_at: r.updated_at,
            source: r.source,
            rotation_pending: r.prev_secret_hash.is_some()
                && r.prev_hash_expires_at.is_some_and(|exp| exp > Utc::now()),
        }
    }
}

fn key_record_policy_digest(record: &KeyRecord) -> Option<String> {
    let policy_origin = record.tenant_id.as_deref()?;
    crate::key_policy::key_record_to_effective_policy(record, policy_origin)
        .ok()?
        .policy_digest()
        .ok()
}

#[derive(Serialize)]
struct CredentialView {
    id: String,
    name: String,
    provider: Option<String>,
    kind: String,
    /// Upstream header this credential is presented in. Not a secret.
    header: String,
    /// Scheme prefix on the header value. Not a secret.
    scheme: String,
    status: RecordStatus,
    tenant_id: Option<String>,
    /// How the secret is held, without revealing it.
    storage: &'static str,
    /// The reference naming where the material comes from: a secret
    /// reference for a `vault_ref` credential, or the dynamic-secrets
    /// mount for a `leased` one. Non-secret either way, and absent for an
    /// envelope or plaintext credential.
    vault_ref: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    source: sbproxy_keystore::record::RecordSource,
    /// When the material was last rotated, distinct from `updated_at`
    /// which any metadata patch moves (WOR-2567).
    rotated_at: Option<DateTime<Utc>>,
    /// Days since the last rotation, or since creation when it has never
    /// been rotated. The number an operator compares against the named
    /// crypto period in `key_management.crypto.rotation`.
    rotation_age_days: i64,
    /// Whether a rotation overlap window is currently open, and when it
    /// closes. Never says what the previous material was.
    rotation_overlap_expires_at: Option<DateTime<Utc>>,
    /// Names the customer-managed root of trust this credential's
    /// envelope is wrapped under, when it is (WOR-2568). Absent for a
    /// locally-wrapped envelope, a vault reference, or plaintext. Not a
    /// secret: it is the mount and key name the operator configured.
    root_of_trust: Option<String>,
    /// Lease platform and duration for a leased credential (WOR-2569).
    /// Absent for every other storage shape. Never the leased material.
    #[serde(skip_serializing_if = "Option::is_none")]
    lease: Option<serde_json::Value>,
}

impl From<&CredentialRecord> for CredentialView {
    fn from(r: &CredentialRecord) -> Self {
        let (storage, vault_ref) = match &r.material {
            CredentialMaterial::VaultRef { reference } => ("vault_ref", Some(reference.clone())),
            CredentialMaterial::Envelope { .. } => ("encrypted", None),
            CredentialMaterial::Plaintext { .. } => ("plaintext", None),
            CredentialMaterial::Leased { reference, .. } => ("leased", Some(reference.clone())),
        };
        let lease = match &r.material {
            CredentialMaterial::Leased {
                platform,
                lease_duration_secs,
                ..
            } => Some(json!({
                "platform": platform.label(),
                "lease_duration_secs": lease_duration_secs,
                "detail": "material is minted on demand and never cached past the lease; \
                           sbproxy re-leases at use time rather than renewing ahead of expiry",
            })),
            _ => None,
        };
        Self {
            id: r.id.clone(),
            name: r.name.clone(),
            provider: r.provider.clone(),
            kind: r.kind.clone(),
            header: r.header.clone(),
            scheme: r.scheme.clone(),
            status: r.status,
            tenant_id: r.tenant_id.clone(),
            storage,
            vault_ref,
            created_at: r.created_at,
            updated_at: r.updated_at,
            source: r.source,
            rotated_at: r.rotated_at,
            rotation_age_days: r.rotation_age_days(Utc::now()),
            rotation_overlap_expires_at: r.prev_material_expires_at.filter(|at| *at > Utc::now()),
            root_of_trust: match &r.material {
                CredentialMaterial::Envelope { envelope } => envelope.kek.clone(),
                _ => None,
            },
            lease,
        }
    }
}

// --- Shared helpers ---

fn plane_or_err() -> Result<Arc<KeyPlane>, Resp> {
    current_key_plane().ok_or_else(|| {
        (
            409,
            "application/json",
            r#"{"error":"key_management is not enabled"}"#.to_string(),
        )
    })
}

fn load_key(plane: &KeyPlane, id: &str) -> Result<Option<KeyRecord>, String> {
    let store = plane.cache().store().clone();
    let owned = id.to_string();
    block_on_keystore(async move { store.get_key(&owned).await }).map_err(|e| format!("{e:#}"))
}

fn store_key_if_revision(
    plane: &KeyPlane,
    rec: KeyRecord,
    expected_revision: u64,
) -> Result<KeyRecord, Resp> {
    let store = plane.cache().store().clone();
    let key_id = rec.key_id.clone();
    match block_on_keystore(async move {
        store
            .put_key_if_revision(rec.clone(), expected_revision)
            .await
            .map(|result| (result, rec))
    }) {
        Ok((KeyPolicyCasResult::Applied { policy_revision }, mut stored)) => {
            stored.policy_revision = policy_revision;
            Ok(stored)
        }
        Ok((KeyPolicyCasResult::Conflict { actual_revision }, _)) => Err(revision_conflict(
            &key_id,
            expected_revision,
            actual_revision,
        )),
        Ok((KeyPolicyCasResult::NotFound, _)) => Err(not_found("key not found")),
        Ok((KeyPolicyCasResult::Unsupported, _)) => Err(atomic_mutation_unsupported()),
        Err(error) => Err(internal_error(&format!("store key mutation: {error:#}"))),
    }
}

fn load_credential(plane: &KeyPlane, id: &str) -> Result<Option<CredentialRecord>, String> {
    let store = plane.cache().store().clone();
    let owned = id.to_string();
    block_on_keystore(async move { store.get_credential(&owned).await })
        .map_err(|e| format!("{e:#}"))
}

fn store_credential(plane: &KeyPlane, rec: CredentialRecord) -> Result<(), String> {
    let store = plane.cache().store().clone();
    block_on_keystore(async move { store.put_credential(rec).await }).map_err(|e| format!("{e:#}"))
}

fn invalidate(plane: &KeyPlane, id: &str) {
    let cache = plane.cache().clone();
    let owned = id.to_string();
    if let Err(error) = block_on_keystore(async move { cache.invalidate(&owned).await }) {
        // L1 was dropped regardless; what failed is the shared tier and the
        // announcement to peers. Recorded on three surfaces because each
        // answers a different question: the log for the operator reading
        // this replica, the counter for the alert, and the slot for the
        // response body so the caller who asked for the revoke is told.
        //
        // The chain rather than `%error`: displaying an `anyhow::Error`
        // renders only its outermost context, which is the generic "reach
        // the shared cache tier to invalidate an id" and names no cause.
        // The tier's own error already carries a redacted DSN.
        let detail = format!("{error:#}");
        tracing::warn!(
            key_id = %id,
            error = %detail,
            "keystore cache-tier invalidation did not propagate; peer replicas will \
             serve the previous record until their cache TTL lapses"
        );
        sbproxy_observe::metrics::record_key_cache_invalidation_failure("key");
        PROPAGATION_FAILURE.with(|slot| {
            *slot.borrow_mut() = Some(detail);
        });
    }
    // A credential's resolved secret is cached separately from its record, so
    // a rotation has to drop both on the same signal or the old secret keeps
    // going upstream until the TTL lapses.
    plane.invalidate_resolved_credential(id);
}

/// WOR-2572: map one admin key-operation response onto
/// `sbproxy_key_operations_total{operation, outcome}` before returning
/// it. Sits at the dispatch seam rather than inside each handler so a
/// return path a handler grows later is already counted, and the
/// outcome comes from the status class the handler actually returned:
/// 2xx is `ok`, 5xx is `error` (the store or governance backend
/// failed), everything else is `refused` (a 4xx the caller can fix).
/// The three are never folded: a rate panel that cannot tell a busy
/// console from an outage answers no operator question.
///
/// Scope is the key resource, and the test is which record the route
/// writes rather than which URL it hangs off. Every mutation that loads
/// and CAS-writes a `KeyRecord` is counted, which includes
/// `/admin/keys/{id}/budget-override` in both directions
/// (`budget_override_grant`, `budget_override_clear`): it raises a
/// spending ceiling on the same record `update` edits, and leaving it
/// off meant its 500s and its twelve refusal paths were invisible to
/// `rate(sbproxy_key_operations_total{outcome="error"}[5m])`.
/// `/admin/credentials` mutations are not counted here, because they
/// write a different record; a credential surface gets its own family
/// rather than silently doubling this one's.
///
/// The closed `operation` set is therefore `mint`, `update`, `delete`,
/// `revoke`, `block`, `unblock`, `rotate`, `budget_override_grant`,
/// `budget_override_clear`: nine values times three outcomes, which is
/// the declared cardinality in `docs/observability.md`.
fn count_key_operation(operation: &'static str, resp: Resp) -> Resp {
    let outcome = match resp.0 {
        200..=299 => "ok",
        500..=599 => "error",
        _ => "refused",
    };
    sbproxy_observe::metrics::record_key_operation(operation, outcome);
    resp
}

fn status_verb(status: RecordStatus) -> &'static str {
    match status {
        RecordStatus::Active => "unblock",
        RecordStatus::Blocked => "block",
        RecordStatus::Revoked => "revoke",
    }
}

/// Emit an audit record for a key/credential mutation. Wired to the audit sink
/// in WOR-1557; here it stamps the structured event onto the tracing pipeline.
///
/// WOR-2094: names the acting operator (from the admin dispatch
/// thread-local) so the trail answers who changed what, not just that
/// something changed.
fn audit_mutation(op: &str, kind: &str, id: &str) {
    audit_mutation_scoped(op, kind, id, None, None);
}

/// [`audit_mutation`] with tenant scope and a secret-free status diff
/// for mutations where both are cheaply at hand (WOR-2094).
fn audit_mutation_scoped(
    op: &str,
    kind: &str,
    id: &str,
    tenant_id: Option<&str>,
    status_diff: Option<(RecordStatus, RecordStatus)>,
) {
    let mut entry = sbproxy_observe::KeyAuditEntry::new(op, kind, id);
    if let Some(actor) = crate::admin::current_admin_actor() {
        // WOR-2573: an action taken while this operator holds an active
        // break-glass grant carries the grant id, so a reviewer pulls the
        // whole session by one key instead of correlating timestamps.
        // Tagged here, at the one audit seam every key and credential
        // mutation in this module already funnels through, rather than at
        // each handler: a handler added later is tagged by construction.
        if let Some(grant_id) = crate::break_glass::tag_action(&actor) {
            entry = entry.with_context(format!("break_glass_grant={grant_id}"));
        }
        entry = entry.with_actor(actor);
    }
    if let Some(tenant_id) = tenant_id {
        entry = entry.with_tenant_id(tenant_id);
    }
    if let Some((before, after)) = status_diff {
        entry = entry.with_diff(
            Some(json!({ "status": status_label(before) })),
            Some(json!({ "status": status_label(after) })),
        );
    }
    entry.emit();
}

/// Closed status vocabulary for the audit diff; never a secret.
fn status_label(status: RecordStatus) -> &'static str {
    match status {
        RecordStatus::Active => "active",
        RecordStatus::Blocked => "blocked",
        RecordStatus::Revoked => "revoked",
    }
}

/// Parse an admin JSON body, scrubbing serde's message before it reaches
/// the 400.
///
/// serde's `invalid type` rendering embeds the offending scalar, so a body
/// that lands a value on a field of the wrong type answers with that value
/// quoted back. Three bodies through this function carry a plaintext
/// upstream credential (`CredentialCreate`, `CredentialUpdate`, and the
/// rotate body on its own path), so the scrub is applied here rather than
/// at one call site: a route added later gets it without anyone
/// remembering. `redact_serde_message` is the same one-rule scrub
/// `origin_profile` uses, and quoting is what it keys on, so a quoted
/// secret is exactly the shape it removes.
fn parse_body<T: for<'de> Deserialize<'de> + Default>(body: Option<&str>) -> Result<T, Resp> {
    match body {
        None | Some("") => Ok(T::default()),
        Some(b) => serde_json::from_str(b).map_err(|e| {
            bad_request(&format!(
                "invalid JSON body: {}",
                sbproxy_config::origin_profile::redact_serde_message(&e.to_string())
            ))
        }),
    }
}

fn ok(value: serde_json::Value) -> Resp {
    (200, "application/json", value.to_string())
}

fn created(value: serde_json::Value) -> Resp {
    (201, "application/json", value.to_string())
}

fn bad_request(msg: &str) -> Resp {
    (400, "application/json", json!({ "error": msg }).to_string())
}

/// A mutation refused because it would break something still in use.
fn conflict(msg: &str) -> Resp {
    (409, "application/json", json!({ "error": msg }).to_string())
}

fn revision_conflict(key_id: &str, expected_revision: u64, current_revision: u64) -> Resp {
    (
        409,
        "application/json",
        json!({
            "error": "key policy revision conflict",
            "key_id": key_id,
            "expected_revision": expected_revision,
            "current_revision": current_revision,
        })
        .to_string(),
    )
}

fn terminal_key(key_id: &str, current_revision: u64) -> Resp {
    (
        409,
        "application/json",
        json!({
            "error": "revoked key is terminal",
            "key_id": key_id,
            "current_revision": current_revision,
        })
        .to_string(),
    )
}

fn atomic_mutation_unsupported() -> Resp {
    (
        409,
        "application/json",
        json!({
            "error": "configured key store does not support atomic key policy mutation",
        })
        .to_string(),
    )
}

fn not_found(msg: &str) -> Resp {
    (404, "application/json", json!({ "error": msg }).to_string())
}

fn method_not_allowed() -> Resp {
    (
        405,
        "application/json",
        r#"{"error":"method not allowed"}"#.to_string(),
    )
}

fn governance_backend_unavailable() -> Resp {
    (
        503,
        "application/json",
        r#"{"error":"governance backend unavailable"}"#.to_string(),
    )
}

fn internal_error(msg: &str) -> Resp {
    tracing::warn!(error = %msg, "admin key API: internal error");
    (
        500,
        "application/json",
        json!({ "error": "internal error" }).to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use sbproxy_ai::governance::{
        CounterSnapshot, GovernanceBackendHealth, GovernanceBackendStatus, GovernanceConsistency,
        GovernanceError, GovernanceSnapshot, GovernanceStore, Release, ReleaseRequest,
        RenewRequest, Reservation, ReserveRequest, SettleRequest, Settlement, SnapshotKey,
    };
    use sbproxy_keystore::crypto::KeyCrypto;
    use sbproxy_keystore::{KeyStore, MemoryKeyStore, TtlCache, TtlCacheConfig};

    struct RecordingGovernanceStore {
        snapshots: Mutex<Vec<SnapshotKey>>,
        unavailable: bool,
    }

    impl RecordingGovernanceStore {
        fn healthy() -> Self {
            Self {
                snapshots: Mutex::new(Vec::new()),
                unavailable: false,
            }
        }

        fn unavailable() -> Self {
            Self {
                snapshots: Mutex::new(Vec::new()),
                unavailable: true,
            }
        }

        fn snapshot_requests(&self) -> Vec<SnapshotKey> {
            self.snapshots.lock().clone()
        }

        fn backend_health(&self) -> GovernanceBackendHealth {
            GovernanceBackendHealth {
                backend: "redis".to_string(),
                consistency: GovernanceConsistency::Strict,
                status: if self.unavailable {
                    GovernanceBackendStatus::Unavailable
                } else {
                    GovernanceBackendStatus::Healthy
                },
                checked_at_millis: 1_700_000_000_000,
            }
        }
    }

    fn counter(
        limit: Option<u64>,
        used: u64,
        reserved: u64,
        reset_at_millis: Option<u64>,
    ) -> CounterSnapshot {
        CounterSnapshot {
            limit,
            used,
            reserved,
            remaining: limit.map(|value| value.saturating_sub(used.saturating_add(reserved))),
            reset_at_millis,
        }
    }

    #[async_trait]
    impl GovernanceStore for RecordingGovernanceStore {
        async fn reserve(&self, _request: ReserveRequest) -> Result<Reservation, GovernanceError> {
            Err(GovernanceError::BackendUnavailable { backend: "redis" })
        }

        async fn renew(&self, _request: RenewRequest) -> Result<Reservation, GovernanceError> {
            Err(GovernanceError::BackendUnavailable { backend: "redis" })
        }

        async fn settle(&self, _request: SettleRequest) -> Result<Settlement, GovernanceError> {
            Err(GovernanceError::BackendUnavailable { backend: "redis" })
        }

        async fn release(&self, _request: ReleaseRequest) -> Result<Release, GovernanceError> {
            Err(GovernanceError::BackendUnavailable { backend: "redis" })
        }

        async fn snapshot(&self, key: SnapshotKey) -> Result<GovernanceSnapshot, GovernanceError> {
            self.snapshots.lock().push(key.clone());
            if self.unavailable {
                return Err(GovernanceError::BackendUnavailable { backend: "redis" });
            }

            Ok(GovernanceSnapshot {
                key_id: key.key_id,
                policy_revision: key.policy_revision,
                requests_per_window: counter(
                    key.limits.requests_per_window,
                    2,
                    1,
                    Some(1_700_000_040_000),
                ),
                tokens_per_window: counter(
                    key.limits.tokens_per_window,
                    100,
                    20,
                    Some(1_700_000_040_000),
                ),
                total_tokens: counter(key.limits.total_tokens, 200, 40, None),
                total_micro_usd: counter(key.limits.total_micro_usd, 3_000_000, 500_000, None),
                backend: self.backend_health(),
            })
        }

        async fn health(&self) -> GovernanceBackendHealth {
            self.backend_health()
        }
    }

    fn install_test_plane_with_governance(
        store: Arc<MemoryKeyStore>,
        governance_store: Arc<dyn GovernanceStore>,
    ) {
        let crypto = KeyCrypto::new(b"pepper".to_vec(), b"master".to_vec());
        let store: Arc<dyn KeyStore> = store;
        let cache = Arc::new(TtlCache::new(store, TtlCacheConfig::default()));
        // `governance_store` here is a test double (`RecordingGovernanceStore`),
        // never the concrete `InMemoryGovernanceStore`, so there is no
        // approximate store to hand off for dissemination.
        let plane = Arc::new(crate::key_plane::KeyPlane::from_parts_with_governance(
            crypto,
            cache,
            false,
            false,
            None,
            sbproxy_config::KeyGovernanceConfig::default(),
            governance_store,
            None,
        ));
        crate::key_plane::install_key_plane_for_test(plane);
    }

    /// A store that is down for every operation, so a handler's 5xx
    /// path is the real store-error path rather than a synthetic
    /// status.
    struct DownStore;
    #[async_trait]
    impl KeyStore for DownStore {
        async fn get_key(&self, _: &str) -> anyhow::Result<Option<KeyRecord>> {
            anyhow::bail!("store down")
        }
        async fn list_keys(&self) -> anyhow::Result<Vec<KeyRecord>> {
            anyhow::bail!("store down")
        }
        async fn put_key(&self, _: KeyRecord) -> anyhow::Result<()> {
            anyhow::bail!("store down")
        }
        async fn put_key_if_revision(
            &self,
            _: KeyRecord,
            _: u64,
        ) -> anyhow::Result<KeyPolicyCasResult> {
            anyhow::bail!("store down")
        }
        async fn delete_key(&self, _: &str) -> anyhow::Result<()> {
            anyhow::bail!("store down")
        }
        async fn get_credential(&self, _: &str) -> anyhow::Result<Option<CredentialRecord>> {
            anyhow::bail!("store down")
        }
        async fn list_credentials(&self) -> anyhow::Result<Vec<CredentialRecord>> {
            anyhow::bail!("store down")
        }
        async fn put_credential(&self, _: CredentialRecord) -> anyhow::Result<()> {
            anyhow::bail!("store down")
        }
        async fn delete_credential(&self, _: &str) -> anyhow::Result<()> {
            anyhow::bail!("store down")
        }
        async fn revision(&self) -> anyhow::Result<u64> {
            anyhow::bail!("store down")
        }
    }

    /// Install a key plane whose store fails every call, so a
    /// handler's 5xx path is the real store-error path rather than a
    /// synthetic status.
    fn install_down_plane() {
        let crypto = KeyCrypto::new(b"pepper".to_vec(), b"master".to_vec());
        let store: Arc<dyn KeyStore> = Arc::new(DownStore);
        let cache = Arc::new(TtlCache::new(store, TtlCacheConfig::default()));
        let plane = Arc::new(crate::key_plane::KeyPlane::from_parts(
            crypto, cache, false, false, None,
        ));
        crate::key_plane::install_key_plane_for_test(plane);
    }

    fn install_test_plane_with_store(store: Arc<MemoryKeyStore>) {
        let crypto = KeyCrypto::new(b"pepper".to_vec(), b"master".to_vec());
        let store: Arc<dyn KeyStore> = store;
        let cache = Arc::new(TtlCache::new(store, TtlCacheConfig::default()));
        let plane = Arc::new(crate::key_plane::KeyPlane::from_parts(
            crypto, cache, false, false, None,
        ));
        crate::key_plane::install_key_plane_for_test(plane);
    }

    fn install_test_plane() {
        install_test_plane_with_store(Arc::new(MemoryKeyStore::new()));
    }

    /// Install a plane whose break-glass block is enabled with the given
    /// quorum and roster.
    fn install_break_glass_plane(quorum: usize, approvers: &[&str]) {
        install_break_glass_plane_with(quorum, approvers, true);
    }

    /// The same, with `enabled` under the caller's control.
    ///
    /// Every break-glass route test used to go through the `enabled: true`
    /// form, which is why re-adding `review`'s kill-switch guard reddened
    /// nothing: no test in the workspace ever installed a disabled block.
    fn install_break_glass_plane_with(quorum: usize, approvers: &[&str], enabled: bool) {
        let crypto = KeyCrypto::new(b"pepper".to_vec(), b"master".to_vec());
        let store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
        let cache = Arc::new(TtlCache::new(store, TtlCacheConfig::default()));
        let plane = Arc::new(
            crate::key_plane::KeyPlane::from_parts(crypto, cache, false, false, None)
                .with_break_glass(sbproxy_config::types::BreakGlassConfig {
                    enabled,
                    approvers: approvers.iter().map(|a| a.to_string()).collect(),
                    quorum,
                    max_ttl_secs: 3600,
                    review_window_secs: 86_400,
                }),
        );
        crate::key_plane::install_key_plane_for_test(plane);
    }

    fn parse(resp: &Resp) -> serde_json::Value {
        serde_json::from_str(&resp.2).unwrap()
    }

    #[test]
    fn a_credential_carries_its_own_upstream_presentation() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();
        let resp = dispatch(
            "POST",
            "/admin/credentials",
            Some(r#"{"id":"anthropic","secret":"s","header":"X-Api-Key","scheme":""}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 201, "{}", resp.2);
        let v = parse(&resp);
        // Normalised to lowercase, because that is how it is written upstream.
        assert_eq!(v["credential"]["header"], "x-api-key");
        assert_eq!(v["credential"]["scheme"], "");
    }

    #[test]
    fn a_credential_defaults_to_bearer_authorization() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();
        let resp = dispatch(
            "POST",
            "/admin/credentials",
            Some(r#"{"id":"openai","secret":"s"}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 201, "{}", resp.2);
        let v = parse(&resp);
        assert_eq!(v["credential"]["header"], "authorization");
        assert_eq!(v["credential"]["scheme"], "Bearer ");
    }

    #[test]
    fn a_credential_header_that_cannot_be_set_upstream_is_rejected() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();
        for bad in ["not a header", "host", "content-length"] {
            let body = format!(r#"{{"id":"c","secret":"s","header":"{bad}"}}"#);
            let resp = dispatch("POST", "/admin/credentials", Some(&body)).unwrap();
            assert_eq!(resp.0, 400, "{bad} must be rejected: {}", resp.2);
        }
    }

    #[test]
    fn hop_by_hop_credential_headers_are_rejected_at_admin_creation() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();
        for (index, header) in ["keep-alive", "proxy-connection", "te", "trailer"]
            .into_iter()
            .enumerate()
        {
            let body = format!(r#"{{"id":"hop-{index}","secret":"s","header":"{header}"}}"#);
            let resp = dispatch("POST", "/admin/credentials", Some(&body)).unwrap();
            assert_eq!(
                resp.0, 400,
                "{header} must be rejected before storage: {}",
                resp.2
            );
        }
    }

    #[test]
    fn a_credential_header_cannot_claim_realtime_protocol_or_proxy_owned_metadata() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();
        for bad in [
            "OpenAI-Beta",
            "SEC-WebSocket-Key",
            "Upgrade",
            "TraceParent",
            "TRACESTATE",
            "Signature-Input",
            "Signature",
            "Signature-Agent",
        ] {
            let body = format!(r#"{{"id":"c","secret":"s","header":"{bad}"}}"#);
            let resp = dispatch("POST", "/admin/credentials", Some(&body)).unwrap();
            assert_eq!(resp.0, 400, "{bad} must be rejected: {}", resp.2);
        }
    }

    #[test]
    fn binding_a_key_to_a_missing_credential_is_rejected() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();
        let resp = create_key(Some(r#"{"credential_id":"does-not-exist"}"#));
        assert_eq!(resp.0, 400, "{}", resp.2);
        assert!(resp.2.contains("unknown credential"), "{}", resp.2);
    }

    #[test]
    fn binding_across_tenants_is_rejected_but_within_one_is_accepted() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();
        assert_eq!(
            dispatch(
                "POST",
                "/admin/credentials",
                Some(r#"{"id":"cred-a","secret":"s","tenant":"tenant-a"}"#),
            )
            .unwrap()
            .0,
            201
        );

        let wrong = create_key(Some(r#"{"credential_id":"cred-a","tenant":"tenant-b"}"#));
        assert_eq!(wrong.0, 400, "{}", wrong.2);
        assert!(wrong.2.contains("different tenant"), "{}", wrong.2);

        let right = create_key(Some(r#"{"credential_id":"cred-a","tenant":"tenant-a"}"#));
        assert_eq!(right.0, 201, "{}", right.2);
    }

    #[test]
    fn binding_to_a_revoked_credential_is_rejected() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();
        assert_eq!(
            dispatch(
                "POST",
                "/admin/credentials",
                Some(r#"{"id":"cred-r","secret":"s"}"#),
            )
            .unwrap()
            .0,
            201
        );
        assert_eq!(
            dispatch("POST", "/admin/credentials/cred-r/revoke", None)
                .unwrap()
                .0,
            200
        );
        let resp = create_key(Some(r#"{"credential_id":"cred-r"}"#));
        assert_eq!(resp.0, 400, "{}", resp.2);
        assert!(resp.2.contains("not active"), "{}", resp.2);
    }

    #[test]
    fn deleting_a_bound_credential_is_refused_and_names_the_keys() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();
        assert_eq!(
            dispatch(
                "POST",
                "/admin/credentials",
                Some(r#"{"id":"cred-b","secret":"s"}"#),
            )
            .unwrap()
            .0,
            201
        );
        let created = create_key(Some(r#"{"credential_id":"cred-b"}"#));
        assert_eq!(created.0, 201, "{}", created.2);
        let key_id = parse(&created)["key"]["key_id"]
            .as_str()
            .unwrap()
            .to_string();

        let refused = dispatch("DELETE", "/admin/credentials/cred-b", None).unwrap();
        assert_eq!(refused.0, 409, "{}", refused.2);
        assert!(
            refused.2.contains(&key_id),
            "the refusal must name the bound key so an operator can act: {}",
            refused.2
        );

        // Unbind, then the delete goes through.
        let unbound = dispatch(
            "PATCH",
            &format!("/admin/keys/{key_id}"),
            Some(r#"{"expected_revision":1,"credential_id":null}"#),
        )
        .unwrap();
        assert_eq!(unbound.0, 200, "{}", unbound.2);
        assert_eq!(
            dispatch("DELETE", "/admin/credentials/cred-b", None)
                .unwrap()
                .0,
            200
        );
    }

    #[test]
    fn key_lifecycle_via_dispatch() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();

        // Create: returns the one-time token and no hash.
        let resp = dispatch(
            "POST",
            "/admin/keys",
            Some(r#"{"name":"ci","max_requests_per_minute":60}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 201);
        let v = parse(&resp);
        let token = v["token"].as_str().unwrap().to_string();
        // The minted shape is self-identifying, so the sweep can accept or
        // reject a header value without a store lookup. Assert the whole
        // contract, not just the prefix.
        assert!(token.starts_with(sbproxy_keystore::crypto::TOKEN_PREFIX));
        assert_eq!(token.len(), sbproxy_keystore::crypto::TOKEN_LEN);
        assert!(
            sbproxy_keystore::crypto::parse_minted_token(&token).is_some(),
            "a minted token must round-trip through the strict parser"
        );
        let key_id = v["key"]["key_id"].as_str().unwrap().to_string();
        assert_eq!(v["key"]["policy_revision"], 1);
        assert!(
            !resp.2.contains("secret_hash"),
            "response must not leak the hash"
        );

        // List + get.
        assert!(dispatch("GET", "/admin/keys", None)
            .unwrap()
            .2
            .contains(&key_id));
        assert_eq!(
            dispatch("GET", &format!("/admin/keys/{key_id}"), None)
                .unwrap()
                .0,
            200
        );

        // Update.
        assert_eq!(
            dispatch(
                "PATCH",
                &format!("/admin/keys/{key_id}"),
                Some(r#"{"expected_revision":1,"max_requests_per_minute":5}"#)
            )
            .unwrap()
            .0,
            200
        );

        // Reversible status transitions and rotation each advance revision.
        let resp = dispatch(
            "POST",
            &format!("/admin/keys/{key_id}/block"),
            Some(r#"{"expected_revision":2}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 200);
        assert_eq!(parse(&resp)["key"]["policy_revision"], 3);
        assert_eq!(
            dispatch(
                "POST",
                &format!("/admin/keys/{key_id}/unblock"),
                Some(r#"{"expected_revision":3}"#),
            )
            .unwrap()
            .0,
            200
        );

        let stale_rotate = dispatch(
            "POST",
            &format!("/admin/keys/{key_id}/rotate"),
            Some(r#"{"expected_revision":3,"grace_secs":120}"#),
        )
        .unwrap();
        assert_eq!(stale_rotate.0, 409);
        assert_eq!(parse(&stale_rotate)["current_revision"], 4);
        assert!(!stale_rotate.2.contains("token"));
        assert!(!stale_rotate.2.contains("hash"));

        let resp = dispatch(
            "POST",
            &format!("/admin/keys/{key_id}/rotate"),
            Some(r#"{"expected_revision":4,"grace_secs":120}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 200);
        let v = parse(&resp);
        let rotated_token = v["token"].as_str().unwrap().to_string();
        // WOR-2537: a rotated token must come back in the same
        // `sbp_<key_id>_<secret>` shape create_key uses, not the legacy
        // `sk-` shape, so the minted-key sweep (which only recognizes the
        // strict shape) can find it too.
        assert!(rotated_token.starts_with(sbproxy_keystore::crypto::TOKEN_PREFIX));
        assert_eq!(rotated_token.len(), sbproxy_keystore::crypto::TOKEN_LEN);
        let (rotated_key_id, _) = sbproxy_keystore::crypto::parse_minted_token(&rotated_token)
            .expect("a rotated token must round-trip through the strict parser");
        assert_eq!(rotated_key_id, key_id);
        assert_eq!(v["key"]["rotation_pending"], true);
        assert_eq!(v["key"]["policy_revision"], 5);
        assert!(
            v["key"]["rotation_pending"].as_bool().unwrap(),
            "a 120s grace window opened moments ago is genuinely still open"
        );

        // Revocation is terminal. Neither unblock nor rotation may change it.
        let resp = dispatch(
            "POST",
            &format!("/admin/keys/{key_id}/revoke"),
            Some(r#"{"expected_revision":5}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 200);
        assert_eq!(parse(&resp)["key"]["status"], "revoked");
        assert_eq!(parse(&resp)["key"]["policy_revision"], 6);

        for action in ["unblock", "block", "rotate"] {
            let resp = dispatch(
                "POST",
                &format!("/admin/keys/{key_id}/{action}"),
                Some(r#"{"expected_revision":6}"#),
            )
            .unwrap();
            assert_eq!(resp.0, 409, "terminal action {action}: {}", resp.2);
            assert!(!resp.2.contains("token"));
            assert!(!resp.2.contains("hash"));
        }
        let resp = dispatch(
            "PATCH",
            &format!("/admin/keys/{key_id}"),
            Some(r#"{"expected_revision":6,"name":"must not change"}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 409);

        // Delete -> gone.
        assert_eq!(
            dispatch("DELETE", &format!("/admin/keys/{key_id}"), None)
                .unwrap()
                .0,
            200
        );
        assert_eq!(
            dispatch("GET", &format!("/admin/keys/{key_id}"), None)
                .unwrap()
                .0,
            404
        );
    }

    #[test]
    fn key_views_expose_secret_free_policy_digest_and_patch_changes_it() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();

        let created = dispatch(
            "POST",
            "/admin/keys",
            Some(
                r#"{"name":"governed","tenant":"tenant-a",
                    "allowed_models":["gpt-4.1"],"allowed_providers":["openai"]}"#,
            ),
        )
        .unwrap();
        assert_eq!(created.0, 201, "create failed: {}", created.2);
        let created_json = parse(&created);
        let key_id = created_json["key"]["key_id"].as_str().unwrap().to_string();
        let token = created_json["token"].as_str().unwrap();
        let created_digest = created_json["key"]["policy_digest"]
            .as_str()
            .expect("create response policy digest")
            .to_string();
        assert!(created_digest.starts_with("sha256:"));
        assert_eq!(created_digest.len(), "sha256:".len() + 64);
        assert!(!created_digest.contains(token));

        let plane = current_key_plane().unwrap();
        let stored = load_key(&plane, &key_id).unwrap().unwrap();
        let expected = crate::key_policy::key_record_to_effective_policy(&stored, "tenant-a")
            .unwrap()
            .policy_digest()
            .unwrap();
        assert_eq!(created_digest, expected);
        assert!(!created.2.contains(&stored.secret_hash));

        let listed = parse(&dispatch("GET", "/admin/keys", None).unwrap());
        let listed_key = listed["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|key| key["key_id"] == key_id)
            .expect("created key in list response");
        assert_eq!(listed_key["policy_digest"], created_digest);

        let fetched = parse(&dispatch("GET", &format!("/admin/keys/{key_id}"), None).unwrap());
        assert_eq!(fetched["key"]["policy_digest"], created_digest);

        let patched = dispatch(
            "PATCH",
            &format!("/admin/keys/{key_id}"),
            Some(r#"{"expected_revision":1,"blocked_models":["gpt-4o"]}"#),
        )
        .unwrap();
        assert_eq!(patched.0, 200, "patch failed: {}", patched.2);
        let patched_json = parse(&patched);
        let patched_digest = patched_json["key"]["policy_digest"]
            .as_str()
            .expect("patch response policy digest");
        assert_ne!(patched_digest, created_digest);

        let fetched = parse(&dispatch("GET", &format!("/admin/keys/{key_id}"), None).unwrap());
        assert_eq!(fetched["key"]["policy_digest"], patched_digest);
    }

    #[test]
    fn tenantless_key_digest_is_origin_scoped_to_policy_preview() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();

        let created = dispatch(
            "POST",
            "/admin/keys",
            Some(r#"{"name":"shared","allowed_models":["gpt-4.1"]}"#),
        )
        .unwrap();
        assert_eq!(created.0, 201, "create failed: {}", created.2);
        let created_json = parse(&created);
        let key_id = created_json["key"]["key_id"].as_str().unwrap();
        assert!(created_json["key"]["tenant_id"].is_null());
        assert!(
            created_json["key"]["policy_digest"].is_null(),
            "a tenantless record has no single runtime digest"
        );

        let preview = |tenant: &str| {
            let body = json!({"origin_tenant_id": tenant}).to_string();
            parse(
                &dispatch(
                    "POST",
                    &format!("/admin/keys/{key_id}/effective-policy/preview"),
                    Some(&body),
                )
                .unwrap(),
            )
        };
        let tenant_a = preview("tenant-a");
        let tenant_b = preview("tenant-b");

        assert_eq!(tenant_a["effective_policy"]["tenant_id"], "tenant-a");
        assert_eq!(tenant_b["effective_policy"]["tenant_id"], "tenant-b");
        assert_ne!(
            tenant_a["policy_version"]["digest"], tenant_b["policy_version"]["digest"],
            "the inherited tenant participates in the runtime policy digest"
        );
    }

    #[test]
    fn malformed_legacy_policy_has_null_digest_without_breaking_list_or_get() {
        let _g = crate::key_plane::test_plane_guard();
        let store = Arc::new(MemoryKeyStore::new());
        install_test_plane_with_store(store.clone());

        let mut legacy = KeyRecord::new(
            "legacy-malformed".to_string(),
            "sensitive-stored-verifier".to_string(),
            Utc::now(),
        );
        legacy.name = Some("legacy record".to_string());
        legacy.principal_selectors = vec![json!({"unknown": "value"})];
        block_on_keystore(store.put_key(legacy)).unwrap();

        let fetched = dispatch("GET", "/admin/keys/legacy-malformed", None).unwrap();
        assert_eq!(fetched.0, 200, "get failed: {}", fetched.2);
        assert!(parse(&fetched)["key"]["policy_digest"].is_null());
        assert!(!fetched.2.contains("sensitive-stored-verifier"));

        let listed = dispatch("GET", "/admin/keys", None).unwrap();
        assert_eq!(listed.0, 200, "list failed: {}", listed.2);
        let listed_json = parse(&listed);
        let legacy_view = listed_json["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|key| key["key_id"] == "legacy-malformed")
            .expect("legacy record in list response");
        assert!(legacy_view["policy_digest"].is_null());
        assert!(!listed.2.contains("sensitive-stored-verifier"));
    }

    #[test]
    fn rotating_a_config_seeded_key_id_refuses_rather_than_minting_a_dead_token() {
        let _g = crate::key_plane::test_plane_guard();
        let store = Arc::new(MemoryKeyStore::new());
        install_test_plane_with_store(store.clone());

        // `seed0001` is the id `examples/ai-dynamic-keys/sb.yml` used to
        // seed and `docs/tapes/ai-dynamic-keys.tape` used to rotate, so this
        // is the shipped demo's own key id rather than a contrived one; the
        // example moved to a conforming id in the same change. Nothing
        // validates the field: `lower_seed_key` takes
        // `key_management.seed.keys[].key_id` verbatim, so any string an
        // operator writes there still reaches this endpoint.
        let seeded = KeyRecord::new(
            "seed0001".to_string(),
            "seeded-secret-hash".to_string(),
            Utc::now(),
        );
        block_on_keystore(store.put_key(seeded)).unwrap();

        let resp = dispatch("POST", "/admin/keys/seed0001/rotate", Some("{}")).unwrap();
        assert_eq!(
            resp.0, 409,
            "a non-conforming key id must be refused, not rotated: {}",
            resp.2
        );
        assert!(
            !resp.2.contains("sbp_"),
            "the refusal must not carry a token: {}",
            resp.2
        );

        // The prior secret is untouched, so whatever still holds the old
        // token keeps working. A 200 here would have opened a grace window
        // that expires onto a token nothing can parse.
        let after = block_on_keystore(store.get_key("seed0001"))
            .unwrap()
            .unwrap();
        assert_eq!(after.secret_hash, "seeded-secret-hash");
        assert!(after.prev_secret_hash.is_none());

        // The reason the refusal exists: the token this endpoint would have
        // built for that id parses on no inbound path.
        let would_have_minted = format!("sbp_seed0001_{}", "a".repeat(64));
        assert!(sbproxy_keystore::crypto::parse_minted_token(&would_have_minted).is_none());
        assert!(sbproxy_keystore::crypto::parse_token(&would_have_minted).is_none());
    }

    #[test]
    fn advanced_policy_fields_validate_and_roundtrip() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();

        // Valid lane + tpm + inject_mcp + metadata all land on the view.
        let resp = dispatch(
            "POST",
            "/admin/keys",
            Some(
                r#"{"name":"lanes","priority":"interactive","max_tokens_per_minute":50000,
                    "compression_profile":"coding-agent",
                    "inject_mcp":{"ref":"toolhub"},"metadata":{"owner":"platform"}}"#,
            ),
        )
        .unwrap();
        assert_eq!(resp.0, 201, "create failed: {}", resp.2);
        let v = parse(&resp);
        let key_id = v["key"]["key_id"].as_str().unwrap().to_string();
        assert_eq!(v["key"]["priority"], "interactive");
        assert_eq!(v["key"]["max_tokens_per_minute"], 50000);
        assert_eq!(v["key"]["inject_mcp"]["ref"], "toolhub");
        assert_eq!(v["key"]["compression_profile"], "coding-agent");
        assert_eq!(v["key"]["metadata"]["owner"], "platform");

        // Unknown lane and a ref-less inject_mcp are 400s, not stored.
        assert_eq!(
            dispatch(
                "PATCH",
                &format!("/admin/keys/{key_id}"),
                Some(r#"{"expected_revision":1,"priority":"urgent"}"#)
            )
            .unwrap()
            .0,
            400
        );
        assert_eq!(
            dispatch(
                "PATCH",
                &format!("/admin/keys/{key_id}"),
                Some(r#"{"expected_revision":1,"compression_profile":"Bad Name"}"#)
            )
            .unwrap()
            .0,
            400
        );
        assert_eq!(
            dispatch(
                "PATCH",
                &format!("/admin/keys/{key_id}"),
                Some(r#"{"expected_revision":1,"inject_mcp":{"format":"openai"}}"#)
            )
            .unwrap()
            .0,
            400
        );

        // Explicit null clears nullable values.
        let resp = dispatch(
            "PATCH",
            &format!("/admin/keys/{key_id}"),
            Some(
                r#"{"expected_revision":1,"priority":null,"compression_profile":null,
                    "inject_mcp":null}"#,
            ),
        )
        .unwrap();
        assert_eq!(resp.0, 200);
        let v = parse(&resp);
        assert_eq!(v["key"]["policy_revision"], 2);
        assert!(v["key"]["priority"].is_null());
        assert!(v["key"]["compression_profile"].is_null());
        assert!(v["key"]["inject_mcp"].is_null());
    }

    #[test]
    fn key_patch_has_flat_revisioned_tri_state_semantics() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();

        let resp = dispatch(
            "POST",
            "/admin/keys",
            Some(
                r#"{"name":"governed","max_requests_per_minute":60,
                    "max_tokens_per_minute":50000,"priority":"interactive",
                    "max_budget_tokens":1000000,"max_budget_usd":25.0,
                    "allowed_models":["gpt-4.1"],"blocked_models":["gpt-4o"],
                    "allowed_providers":["openai"],"blocked_providers":["vertex"],
                    "allowed_tools":["search"],
                    "require_pii_redaction":["email"],
                    "principal_selectors":[{"team":"platform"}],
                    "route_to_model":"gpt-4.1","compression_profile":"coding-agent",
                    "inject_tools":[{"name":"search"}],
                    "inject_mcp":{"ref":"toolhub"},"bypass_prompt_injection":true,
                    "project":"search","user":"alice","tags":["prod"],
                    "metadata":{"owner":"platform"},"tenant":"tenant-a",
                    "expires_at":"2030-01-01T00:00:00Z"}"#,
            ),
        )
        .unwrap();
        assert_eq!(resp.0, 201, "create failed: {}", resp.2);
        let created = parse(&resp);
        let key_id = created["key"]["key_id"].as_str().unwrap().to_string();
        assert_eq!(created["key"]["policy_revision"], 1);
        assert_eq!(created["key"]["blocked_providers"], json!(["vertex"]));
        assert_eq!(created["key"]["allowed_tools"], json!(["search"]));
        assert_eq!(created["key"]["compression_profile"], "coding-agent");

        // Absent fields stay unchanged while a concrete value replaces one.
        let resp = dispatch(
            "PATCH",
            &format!("/admin/keys/{key_id}"),
            Some(r#"{"expected_revision":1,"project":"recommendations"}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 200, "value patch failed: {}", resp.2);
        let updated = parse(&resp);
        assert_eq!(updated["key"]["policy_revision"], 2);
        assert_eq!(updated["key"]["project"], "recommendations");
        assert_eq!(updated["key"]["name"], "governed");
        assert_eq!(updated["key"]["blocked_providers"], json!(["vertex"]));
        assert_eq!(updated["key"]["allowed_tools"], json!(["search"]));

        // An explicit empty tool allowlist is distinct from unrestricted.
        let resp = dispatch(
            "PATCH",
            &format!("/admin/keys/{key_id}"),
            Some(r#"{"expected_revision":2,"allowed_tools":[]}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 200, "empty allowlist patch failed: {}", resp.2);
        let deny_all_tools = parse(&resp);
        assert_eq!(deny_all_tools["key"]["policy_revision"], 3);
        assert_eq!(deny_all_tools["key"]["allowed_tools"], json!([]));

        // Null clears nullable scalars, budget members, and the optional tool
        // allowlist. Empty collections replace other collection policy, and
        // false remains an explicit value.
        let resp = dispatch(
            "PATCH",
            &format!("/admin/keys/{key_id}"),
            Some(
                r#"{"expected_revision":3,"name":null,
                    "max_requests_per_minute":null,"max_tokens_per_minute":null,
                    "priority":null,"max_budget_tokens":null,"max_budget_usd":null,
                    "allowed_models":[],"blocked_models":[],"allowed_providers":[],
                    "blocked_providers":[],"allowed_tools":null,"require_pii_redaction":[],
                    "principal_selectors":[],"route_to_model":null,
                    "compression_profile":null,"inject_tools":[],
                    "inject_mcp":null,"bypass_prompt_injection":false,
                    "project":null,"user":null,"tags":[],"metadata":{},
                    "tenant":null,"expires_at":null}"#,
            ),
        )
        .unwrap();
        assert_eq!(resp.0, 200, "clear patch failed: {}", resp.2);
        let cleared = parse(&resp);
        assert_eq!(cleared["key"]["policy_revision"], 4);
        for field in [
            "name",
            "max_requests_per_minute",
            "max_tokens_per_minute",
            "priority",
            "budget",
            "route_to_model",
            "compression_profile",
            "allowed_tools",
            "inject_mcp",
            "project",
            "user",
            "tenant_id",
            "expires_at",
        ] {
            assert!(
                cleared["key"][field].is_null(),
                "field {field} was not cleared"
            );
        }
        for field in [
            "allowed_models",
            "blocked_models",
            "allowed_providers",
            "blocked_providers",
            "require_pii_redaction",
            "principal_selectors",
            "inject_tools",
            "tags",
        ] {
            assert_eq!(cleared["key"][field], json!([]), "field {field}");
        }
        assert_eq!(cleared["key"]["metadata"], json!({}));
        assert_eq!(cleared["key"]["bypass_prompt_injection"], false);

        // A stale writer is denied and learns only the current revision.
        let stale = dispatch(
            "PATCH",
            &format!("/admin/keys/{key_id}"),
            Some(r#"{"expected_revision":3,"name":"stale"}"#),
        )
        .unwrap();
        assert_eq!(stale.0, 409);
        let conflict = parse(&stale);
        assert_eq!(conflict["key_id"], key_id);
        assert_eq!(conflict["expected_revision"], 3);
        assert_eq!(conflict["current_revision"], 4);
        for forbidden in ["token", "secret", "hash", "record"] {
            assert!(!stale.2.contains(forbidden), "conflict leaked {forbidden}");
        }

        let current = dispatch("GET", &format!("/admin/keys/{key_id}"), None).unwrap();
        assert_eq!(parse(&current)["key"]["policy_revision"], 4);
        assert!(parse(&current)["key"]["name"].is_null());
    }

    #[test]
    fn invalid_key_policy_input_is_rejected_before_write() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();

        assert_eq!(
            dispatch(
                "POST",
                "/admin/keys",
                Some(r#"{"name":"bad","unknown_policy":true}"#),
            )
            .unwrap()
            .0,
            400
        );
        assert_eq!(
            dispatch(
                "POST",
                "/admin/keys",
                Some(r#"{"expires_at":"not-a-date"}"#),
            )
            .unwrap()
            .0,
            400
        );
        assert_eq!(
            dispatch(
                "POST",
                "/admin/keys",
                Some(r#"{"principal_selectors":[42]}"#),
            )
            .unwrap()
            .0,
            400
        );

        let created = dispatch("POST", "/admin/keys", Some(r#"{"name":"stable"}"#)).unwrap();
        let key_id = parse(&created)["key"]["key_id"]
            .as_str()
            .unwrap()
            .to_string();

        for body in [
            r#"{"expected_revision":1,"unknown_policy":true}"#,
            r#"{"expected_revision":1,"expires_at":"not-a-date"}"#,
            r#"{"name":"missing revision"}"#,
            r#"{"expected_revision":1,"tags":null}"#,
            r#"{"expected_revision":1,"allowed_tools":"search"}"#,
            r#"{"expected_revision":1,"metadata":null}"#,
            r#"{"expected_revision":1,"bypass_prompt_injection":null}"#,
            r#"{"expected_revision":1,"principal_selectors":[42]}"#,
            r#"{"expected_revision":1,"principal_selectors":[{"unknown":"value"}]}"#,
        ] {
            let resp = dispatch("PATCH", &format!("/admin/keys/{key_id}"), Some(body)).unwrap();
            assert_eq!(resp.0, 400, "body {body}: {}", resp.2);
        }

        let invalid_action = dispatch(
            "POST",
            &format!("/admin/keys/{key_id}/block"),
            Some(r#"{"expected_revision":1,"unknown_policy":true}"#),
        )
        .unwrap();
        assert_eq!(invalid_action.0, 400);

        let current = dispatch("GET", &format!("/admin/keys/{key_id}"), None).unwrap();
        assert_eq!(parse(&current)["key"]["policy_revision"], 1);
        assert_eq!(parse(&current)["key"]["name"], "stable");
        assert_eq!(parse(&current)["key"]["status"], "active");
    }

    #[test]
    fn credential_lifecycle_via_dispatch() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();

        // Encrypted credential: plaintext must not appear in the response.
        let resp = dispatch(
            "POST",
            "/admin/credentials",
            Some(r#"{"id":"openai","provider":"openai","secret":"sk-up"}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 201);
        let v = parse(&resp);
        assert_eq!(v["credential"]["storage"], "encrypted");
        assert!(
            !resp.2.contains("sk-up"),
            "plaintext secret leaked into response"
        );

        // Vault-ref credential surfaces the reference (not a secret).
        let resp = dispatch(
            "POST",
            "/admin/credentials",
            Some(r#"{"id":"anthropic","vault_ref":"vault://anthropic"}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 201);
        let v = parse(&resp);
        assert_eq!(v["credential"]["storage"], "vault_ref");
        assert_eq!(v["credential"]["vault_ref"], "vault://anthropic");

        assert_eq!(dispatch("GET", "/admin/credentials", None).unwrap().0, 200);
        assert_eq!(
            dispatch("DELETE", "/admin/credentials/openai", None)
                .unwrap()
                .0,
            200
        );
    }

    #[test]
    fn unowned_paths_fall_through() {
        // dispatch returns None for paths it does not own, so the rest of the
        // admin dispatcher still handles them.
        assert!(dispatch("GET", "/admin/reload", None).is_none());
        assert!(dispatch("GET", "/api/stats", None).is_none());
        assert!(dispatch("POST", "/healthz", None).is_none());
    }

    #[test]
    fn key_policy_schema_is_server_driven_and_does_not_require_a_key_plane() {
        let _g = crate::key_plane::test_plane_guard();

        let response = dispatch("GET", "/admin/keys/policy-schema", None).unwrap();
        assert_eq!(response.0, 200, "schema failed: {}", response.2);
        let schema = parse(&response);
        assert_eq!(
            schema["schema_version"],
            sbproxy_ai::effective_key_policy::EFFECTIVE_KEY_POLICY_SCHEMA_VERSION
        );
        assert_eq!(
            schema["fields"].as_array().unwrap().len(),
            sbproxy_ai::effective_key_policy::PolicyField::ALL.len()
        );

        let field = |name: &str| {
            schema["fields"]
                .as_array()
                .unwrap()
                .iter()
                .find(|field| field["wire_name"] == name)
                .unwrap_or_else(|| panic!("missing schema field {name}"))
        };
        assert_eq!(field("display_name")["mutation"]["fields"], json!(["name"]));
        assert_eq!(field("display_name")["editor"], "text");
        assert_eq!(field("display_name")["clear_semantics"], "null");
        assert_eq!(field("tenant_id")["mutation"]["fields"], json!(["tenant"]));
        assert_eq!(
            field("status")["mutation"],
            json!({
                "kind": "action",
                "fields": ["block", "unblock", "revoke"]
            })
        );
        assert_eq!(
            field("allowed_tools")["clear_semantics"],
            "null_means_unrestricted"
        );
        assert!(schema["fields"].as_array().unwrap().iter().all(|field| {
            field["wire_name"] == field["preview_field"]
                && field["enforcement_proof"]
                    .as_str()
                    .is_some_and(|proof| !proof.is_empty())
        }));

        assert_eq!(
            dispatch("POST", "/admin/keys/policy-schema", Some("{}"))
                .unwrap()
                .0,
            405
        );
    }

    #[test]
    fn key_policy_preview_returns_canonical_policy_version_and_allow_decisions() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();

        let created = dispatch(
            "POST",
            "/admin/keys",
            Some(
                r#"{"name":"production chat","tenant":"tenant-a",
                    "expires_at":"2030-01-01T00:00:00Z",
                    "allowed_models":["gpt-4.1"],"blocked_models":["gpt-4o"],
                    "route_to_model":"gpt-4.1","allowed_providers":["openai"],
                    "blocked_providers":["vertex"],"allowed_tools":["search"],
                    "principal_selectors":[{"team":"platform"}],
                    "require_pii_redaction":["email"],
                    "max_requests_per_minute":60,"max_tokens_per_minute":50000,
                    "max_budget_tokens":1000000,"max_budget_usd":25.0,
                    "priority":"interactive"}"#,
            ),
        )
        .unwrap();
        assert_eq!(created.0, 201, "create failed: {}", created.2);
        let created_json = parse(&created);
        let key_id = created_json["key"]["key_id"].as_str().unwrap();
        let token = created_json["token"].as_str().unwrap();

        let sample = json!({
            "origin_tenant_id": "tenant-a",
            "at": "2029-01-01T00:00:00Z",
            "model": "gpt-4o",
            "provider": "openai",
            "tools": ["search"],
            "principal": {
                "virtual_key": "production-chat",
                "team": "platform",
                "project": "search",
                "user": "alice",
                "roles": ["developer"],
                "claims": {"environment": "production"}
            },
            "active_pii_rules": ["email", "phone"],
            "estimated_tokens": 1000,
            "estimated_micro_usd": 2_000_000,
            "usage": {
                "requests_in_window": 2,
                "tokens_in_window": 1000,
                "total_tokens": 100_000,
                "total_micro_usd": 3_000_000
            }
        });
        let body = serde_json::to_string(&sample).unwrap();
        let response = dispatch(
            "POST",
            &format!("/admin/keys/{key_id}/effective-policy/preview"),
            Some(&body),
        )
        .unwrap();
        assert_eq!(response.0, 200, "preview failed: {}", response.2);
        let preview = parse(&response);

        assert_eq!(preview["effective_policy"]["key_id"], key_id);
        assert_eq!(
            preview["effective_policy"]["display_name"],
            "production chat"
        );
        assert_eq!(preview["effective_policy"]["tenant_id"], "tenant-a");
        assert_eq!(preview["effective_policy"]["policy_revision"], 1);
        assert_eq!(preview["policy_version"]["revision"], 1);
        assert!(preview["policy_version"]["digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        assert_eq!(preview["decisions"]["allowed"], true);
        assert_eq!(preview["decisions"]["lifecycle"]["reason_code"], "active");
        assert_eq!(preview["decisions"]["tenant"]["reason_code"], "match");
        assert_eq!(preview["decisions"]["model"]["requested"], "gpt-4o");
        assert_eq!(preview["decisions"]["model"]["effective"], "gpt-4.1");
        assert_eq!(preview["decisions"]["model"]["routed"], true);
        assert_eq!(preview["decisions"]["provider"]["allowed"], true);
        assert_eq!(preview["decisions"]["tools"]["denied"], json!([]));
        assert_eq!(preview["decisions"]["principal"]["reason_code"], "matched");
        assert_eq!(
            preview["decisions"]["rate_limits"]["requests_per_minute"],
            json!({
                "allowed": true,
                "limit": 60,
                "current": 2,
                "requested": 1,
                "projected": 3,
                "reason_code": "within_limit"
            })
        );
        assert_eq!(
            preview["decisions"]["rate_limits"]["tokens_per_minute"]["projected"],
            2000
        );
        assert_eq!(
            preview["decisions"]["budget"]["tokens"]["projected"],
            101_000
        );
        assert_eq!(
            preview["decisions"]["budget"]["micro_usd"]["projected"],
            5_000_000
        );
        assert_eq!(preview["decisions"]["priority"]["lane"], "interactive");
        assert_eq!(
            preview["decisions"]["guardrails"]["pii"]["missing"],
            json!([])
        );
        assert_eq!(
            preview["decisions"]["guardrails"]["prompt_injection"]["mode"],
            "enforce"
        );
        let unchanged = dispatch("GET", &format!("/admin/keys/{key_id}"), None).unwrap();
        assert_eq!(
            parse(&unchanged)["key"],
            created_json["key"],
            "preview must not mutate the stored key policy"
        );

        for forbidden in [token, "secret_hash", "prev_secret_hash", "hash_alg"] {
            assert!(
                !response.2.contains(forbidden),
                "preview response leaked {forbidden}"
            );
        }
    }

    #[test]
    fn key_policy_preview_reports_every_denial_in_one_response() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();

        let created = dispatch(
            "POST",
            "/admin/keys",
            Some(
                r#"{"tenant":"tenant-a","expires_at":"2025-01-01T00:00:00Z",
                    "allowed_models":["gpt-4.1"],"blocked_models":["gpt-4o"],
                    "allowed_providers":["openai"],"blocked_providers":["vertex"],
                    "allowed_tools":["search"],
                    "principal_selectors":[{"team":"platform"}],
                    "require_pii_redaction":["email"],
                    "max_requests_per_minute":3,"max_tokens_per_minute":1000,
                    "max_budget_tokens":5000,"max_budget_usd":2.0,
                    "priority":"batch"}"#,
            ),
        )
        .unwrap();
        let key_id = parse(&created)["key"]["key_id"]
            .as_str()
            .unwrap()
            .to_string();
        let sample = json!({
            "origin_tenant_id": "tenant-b",
            "at": "2029-01-01T00:00:00Z",
            "model": "gpt-4o",
            "provider": "vertex",
            "tools": ["search", "shell"],
            "principal": {"team": "finance"},
            "active_pii_rules": [],
            "estimated_tokens": 500,
            "estimated_micro_usd": 500_000,
            "usage": {
                "requests_in_window": 3,
                "tokens_in_window": 750,
                "total_tokens": 4800,
                "total_micro_usd": 1_750_000
            }
        });
        let body = serde_json::to_string(&sample).unwrap();
        let response = dispatch(
            "POST",
            &format!("/admin/keys/{key_id}/effective-policy/preview"),
            Some(&body),
        )
        .unwrap();
        assert_eq!(response.0, 200, "preview failed: {}", response.2);
        let decisions = &parse(&response)["decisions"];

        assert_eq!(decisions["allowed"], false);
        assert_eq!(decisions["lifecycle"]["reason_code"], "expired");
        assert_eq!(decisions["tenant"]["reason_code"], "mismatch");
        assert_eq!(decisions["model"]["reason_code"], "blocked");
        assert_eq!(decisions["provider"]["reason_code"], "blocked");
        assert_eq!(decisions["tools"]["denied"], json!(["shell"]));
        assert_eq!(decisions["principal"]["reason_code"], "not_matched");
        assert_eq!(decisions["rate_limits"]["allowed"], false);
        assert_eq!(decisions["budget"]["allowed"], false);
        assert_eq!(decisions["priority"]["lane"], "batch");
        assert_eq!(decisions["guardrails"]["pii"]["missing"], json!(["email"]));
        assert_eq!(decisions["guardrails"]["allowed"], false);
        let unchanged = dispatch("GET", &format!("/admin/keys/{key_id}"), None).unwrap();
        assert_eq!(parse(&unchanged)["key"], parse(&created)["key"]);
    }

    #[test]
    fn key_policy_preview_defaults_context_and_rejects_unbounded_or_unknown_samples() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();
        let created = dispatch(
            "POST",
            "/admin/keys",
            Some(r#"{"name":"bounded","tenant":"tenant-a"}"#),
        )
        .unwrap();
        let key_id = parse(&created)["key"]["key_id"]
            .as_str()
            .unwrap()
            .to_string();
        let path = format!("/admin/keys/{key_id}/effective-policy/preview");

        let defaulted = dispatch("POST", &path, Some("{}")).unwrap();
        assert_eq!(defaulted.0, 200, "default preview failed: {}", defaulted.2);
        assert_eq!(
            parse(&defaulted)["decisions"]["tenant"]["origin_tenant_id"],
            "tenant-a"
        );

        for body in [
            r#"{"unknown":true}"#.to_string(),
            r#"{"principal":{"unknown":true}}"#.to_string(),
            serde_json::to_string(&json!({"tools": vec!["tool"; 129]})).unwrap(),
            serde_json::to_string(&json!({"model": "x".repeat(513)})).unwrap(),
            "{".to_string(),
            format!(r#"{{"model":"{}"}}"#, "x".repeat(70_000)),
        ] {
            let response = dispatch("POST", &path, Some(&body)).unwrap();
            assert_eq!(response.0, 400, "body was accepted: {}", response.2);
            assert!(!response.2.contains(&"x".repeat(513)));
        }

        let missing = dispatch(
            "POST",
            "/admin/keys/missing/effective-policy/preview",
            Some("{}"),
        )
        .unwrap();
        assert_eq!(missing.0, 404);
        assert_eq!(parse(&missing), json!({"error": "key not found"}));
        assert_eq!(dispatch("GET", &path, None).unwrap().0, 405);
    }

    #[test]
    fn key_usage_returns_integer_limits_counters_and_safe_backend_health() {
        let _g = crate::key_plane::test_plane_guard();
        let key_store = Arc::new(MemoryKeyStore::new());
        let governance = Arc::new(RecordingGovernanceStore::healthy());
        install_test_plane_with_governance(key_store, governance.clone());

        let created = dispatch(
            "POST",
            "/admin/keys",
            Some(
                r#"{"name":"must-not-appear","max_requests_per_minute":60,
                    "max_tokens_per_minute":50000,"max_budget_tokens":1000000,
                    "max_budget_usd":25.1234564,
                    "metadata":{"redis_url":"redis://operator:top-secret@redis.internal",
                    "node_id":"node-secret","artifact":"artifact-secret"}}"#,
            ),
        )
        .unwrap();
        assert_eq!(created.0, 201, "create failed: {}", created.2);
        let created_json = parse(&created);
        let key_id = created_json["key"]["key_id"].as_str().unwrap().to_string();
        let token = created_json["token"].as_str().unwrap().to_string();

        let response = dispatch("GET", &format!("/admin/keys/{key_id}/usage"), None).unwrap();
        assert_eq!(response.0, 200, "usage failed: {}", response.2);
        let usage = &parse(&response)["usage"];
        assert_eq!(usage["key_id"], key_id);
        assert_eq!(usage["policy_revision"], 1);
        assert_eq!(
            usage["requests_per_window"],
            json!({
                "limit": 60,
                "used": 2,
                "reserved": 1,
                "remaining": 57,
                "reset_at_millis": 1_700_000_040_000_u64,
            })
        );
        assert_eq!(usage["tokens_per_window"]["limit"], 50_000);
        assert_eq!(usage["tokens_per_window"]["used"], 100);
        assert_eq!(usage["tokens_per_window"]["reserved"], 20);
        assert_eq!(usage["tokens_per_window"]["remaining"], 49_880);
        assert_eq!(usage["total_tokens"]["limit"], 1_000_000);
        assert_eq!(usage["total_tokens"]["reset_at_millis"], json!(null));
        assert_eq!(usage["total_micro_usd"]["limit"], 25_123_456);
        assert_eq!(usage["total_micro_usd"]["used"], 3_000_000);
        assert_eq!(usage["total_micro_usd"]["reserved"], 500_000);
        assert_eq!(usage["total_micro_usd"]["remaining"], 21_623_456);
        assert_eq!(usage["backend"]["backend"], "redis");
        assert_eq!(usage["backend"]["consistency"], "strict");
        assert_eq!(usage["backend"]["status"], "healthy");
        assert_eq!(usage["backend"]["checked_at_millis"], 1_700_000_000_000_u64);

        let snapshots = governance.snapshot_requests();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].key_id, key_id);
        assert_eq!(snapshots[0].policy_revision, 1);
        assert_eq!(snapshots[0].limits.window_millis, 60_000);
        assert_eq!(snapshots[0].limits.total_micro_usd, Some(25_123_456));

        for forbidden in [
            token.as_str(),
            "must-not-appear",
            "top-secret",
            "redis.internal",
            "node-secret",
            "artifact-secret",
            "secret_hash",
        ] {
            assert!(
                !response.2.contains(forbidden),
                "usage response leaked {forbidden}"
            );
        }
    }

    #[test]
    fn key_usage_returns_not_found_without_calling_governance_storage() {
        let _g = crate::key_plane::test_plane_guard();
        let key_store = Arc::new(MemoryKeyStore::new());
        let governance = Arc::new(RecordingGovernanceStore::unavailable());
        install_test_plane_with_governance(key_store, governance.clone());

        let missing = dispatch("GET", "/admin/keys/missing/usage", None).unwrap();
        assert_eq!(missing.0, 404);
        assert_eq!(parse(&missing), json!({ "error": "key not found" }));
        assert!(governance.snapshot_requests().is_empty());
    }

    #[test]
    fn key_usage_returns_generic_secret_free_service_unavailable_for_backend_errors() {
        let _g = crate::key_plane::test_plane_guard();
        let key_store = Arc::new(MemoryKeyStore::new());
        let governance = Arc::new(RecordingGovernanceStore::unavailable());
        install_test_plane_with_governance(key_store, governance.clone());

        let created = dispatch(
            "POST",
            "/admin/keys",
            Some(r#"{"name":"unavailable-key","max_requests_per_minute":5}"#),
        )
        .unwrap();
        let key_id = parse(&created)["key"]["key_id"]
            .as_str()
            .unwrap()
            .to_string();
        let response = dispatch("GET", &format!("/admin/keys/{key_id}/usage"), None).unwrap();
        assert_eq!(response.0, 503);
        assert_eq!(
            parse(&response),
            json!({ "error": "governance backend unavailable" })
        );
        for forbidden in ["redis", "unavailable-key", &key_id] {
            assert!(
                !response.2.contains(forbidden),
                "backend error leaked {forbidden}"
            );
        }
    }

    #[test]
    fn key_usage_rejects_malformed_legacy_monetary_limits_before_snapshot() {
        let _g = crate::key_plane::test_plane_guard();
        let key_store = Arc::new(MemoryKeyStore::new());
        let governance = Arc::new(RecordingGovernanceStore::healthy());
        install_test_plane_with_governance(key_store.clone(), governance.clone());

        for (index, value) in [-1.0, f64::NAN, f64::INFINITY, f64::MAX]
            .into_iter()
            .enumerate()
        {
            let key_id = format!("legacy-{index}");
            let mut record =
                KeyRecord::new(key_id.clone(), "hash-must-not-leak".to_string(), Utc::now());
            record.budget = Some(RecordBudget {
                max_tokens: Some(100),
                max_cost_usd: Some(value),
            });
            let store = key_store.clone();
            block_on_keystore(async move { store.put_key(record).await }).unwrap();

            let response = dispatch("GET", &format!("/admin/keys/{key_id}/usage"), None).unwrap();
            assert_eq!(response.0, 500, "value {value:?}: {}", response.2);
            assert_eq!(parse(&response), json!({ "error": "internal error" }));
            assert!(!response.2.contains("hash-must-not-leak"));
            assert!(!response.2.contains(&key_id));
        }

        assert!(
            governance.snapshot_requests().is_empty(),
            "malformed monetary policies must not reach governance storage"
        );
    }

    /// WOR-2346: `rotation_pending` has to mean what it says.
    ///
    /// Driven through the `KeyView` conversion rather than the dispatcher
    /// because the interesting case is a grace window that has already
    /// lapsed, and the dispatcher cannot travel in time.
    #[test]
    fn rotation_pending_tracks_the_grace_window_not_merely_the_prior_hash() {
        use sbproxy_keystore::record::KeyRecord;

        let now = Utc::now();
        let mut record = KeyRecord::new("k-rotation", "hash-current", now);
        assert!(
            !KeyView::from(&record).rotation_pending,
            "a key that was never rotated has no window open"
        );

        // Rotation just happened: window open, prior secret still valid.
        record.prev_secret_hash = Some("hash-previous".to_string());
        record.prev_hash_expires_at = Some(now + chrono::Duration::seconds(120));
        assert!(
            KeyView::from(&record).rotation_pending,
            "an unexpired window is genuinely pending"
        );

        // The window has lapsed. `verify_secret` stopped accepting the
        // prior hash at this instant, so the badge has to agree. Nothing
        // clears `prev_secret_hash`, which is exactly why reading it
        // alone reported `true` forever.
        record.prev_hash_expires_at = Some(now - chrono::Duration::seconds(1));
        assert!(
            record.prev_secret_hash.is_some(),
            "the prior hash is still on the record, which is the trap"
        );
        assert!(
            !record.verify_secret("anything", b"pepper", now),
            "the authority has already closed the window"
        );
        assert!(
            !KeyView::from(&record).rotation_pending,
            "an expired window must not keep reporting pending"
        );

        // A prior hash with no expiry at all cannot be verified against
        // either, so it must not read as pending.
        record.prev_hash_expires_at = None;
        assert!(!KeyView::from(&record).rotation_pending);
    }

    // --- Temporary budget overrides (WOR-2561) ---

    /// Mint a key with a token/cost base budget and return its id.
    fn mint_budgeted_key(max_tokens: Option<u64>, max_usd: Option<f64>) -> String {
        let mut body = serde_json::Map::new();
        if let Some(tokens) = max_tokens {
            body.insert("max_budget_tokens".into(), json!(tokens));
        }
        if let Some(usd) = max_usd {
            body.insert("max_budget_usd".into(), json!(usd));
        }
        let resp = dispatch(
            "POST",
            "/admin/keys",
            Some(&serde_json::Value::Object(body).to_string()),
        )
        .unwrap();
        assert_eq!(resp.0, 201, "{}", resp.2);
        parse(&resp)["key"]["key_id"].as_str().unwrap().to_string()
    }

    #[test]
    fn a_budget_override_grant_raises_the_effective_budget_and_names_the_grantor() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane_with_governance(
            Arc::new(MemoryKeyStore::new()),
            Arc::new(RecordingGovernanceStore::healthy()),
        );
        let _actor = crate::admin::set_current_admin_actor(Some((
            "casey".to_string(),
            sbproxy_config::types::AdminRole::Admin,
        )));
        let id = mint_budgeted_key(Some(1_000), Some(5.0));

        let resp = dispatch(
            "POST",
            &format!("/admin/keys/{id}/budget-override"),
            Some(r#"{"max_tokens_increase":500,"max_cost_usd_increase":10.0,"ttl_secs":60,"reason":"launch-day spike"}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 200, "{}", resp.2);
        let key = &parse(&resp)["key"];
        // The base is untouched; the raise and the enforced sum ride beside it.
        assert_eq!(key["budget"]["max_tokens"], 1_000);
        assert_eq!(key["budget_override"]["max_tokens_increase"], 500);
        assert_eq!(key["budget_override"]["granted_by"], "casey");
        assert_eq!(key["budget_override"]["reason"], "launch-day spike");
        assert!(key["budget_override"]["expires_at"].is_string());
        assert_eq!(key["effective_budget"]["max_tokens"], 1_500);
        assert_eq!(key["effective_budget"]["max_cost_usd"], 15.0);

        // The grant is in the audit trail, attributed to the operator.
        let events = sbproxy_observe::audit_ring::recent_audit_events(
            5,
            Some("key"),
            Some("budget_override_grant"),
            Some(&id),
        );
        assert_eq!(events.len(), 1, "exactly one grant event for this key");
        assert_eq!(events[0].actor.as_deref(), Some("casey"));

        // The usage snapshot asks the governance store for the raised caps,
        // not the base, so the operator's remaining-budget view matches
        // enforcement.
        let usage = dispatch("GET", &format!("/admin/keys/{id}/usage"), None).unwrap();
        assert_eq!(usage.0, 200, "{}", usage.2);
        assert_eq!(parse(&usage)["usage"]["total_tokens"]["limit"], 1_500);
    }

    #[test]
    fn a_budget_override_grant_is_validated_at_the_boundary() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();
        let budgeted = mint_budgeted_key(Some(1_000), None);
        let unbudgeted = mint_budgeted_key(None, None);

        for (id, body, why) in [
            (
                &unbudgeted,
                r#"{"max_tokens_increase":500,"ttl_secs":60}"#,
                "no base budget to raise",
            ),
            (
                &budgeted,
                r#"{"ttl_secs":60}"#,
                "no increase on either axis",
            ),
            (
                &budgeted,
                r#"{"max_tokens_increase":0,"ttl_secs":60}"#,
                "zero token increase",
            ),
            (
                &budgeted,
                r#"{"max_cost_usd_increase":10.0,"ttl_secs":60}"#,
                "cost increase on a key with no cost cap",
            ),
            (&budgeted, r#"{"max_tokens_increase":500}"#, "no expiry"),
            (
                &budgeted,
                r#"{"max_tokens_increase":500,"ttl_secs":60,"expires_at":"2030-01-01T00:00:00Z"}"#,
                "both expiry forms",
            ),
            (
                &budgeted,
                r#"{"max_tokens_increase":500,"expires_at":"2001-01-01T00:00:00Z"}"#,
                "expiry in the past",
            ),
            (
                &budgeted,
                r#"{"max_tokens_increase":500,"ttl_secs":0}"#,
                "zero ttl",
            ),
        ] {
            let resp = dispatch(
                "POST",
                &format!("/admin/keys/{id}/budget-override"),
                Some(body),
            )
            .unwrap();
            assert_eq!(resp.0, 400, "{why}: {}", resp.2);
        }

        // A revoked key is terminal for grants like every other mutation.
        let revoked = mint_budgeted_key(Some(1_000), None);
        let resp = dispatch("POST", &format!("/admin/keys/{revoked}/revoke"), None).unwrap();
        assert_eq!(resp.0, 200, "{}", resp.2);
        let resp = dispatch(
            "POST",
            &format!("/admin/keys/{revoked}/budget-override"),
            Some(r#"{"max_tokens_increase":500,"ttl_secs":60}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 409, "{}", resp.2);
    }

    #[test]
    fn clearing_a_budget_override_restores_the_base_at_once() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();
        let id = mint_budgeted_key(Some(1_000), None);
        let resp = dispatch(
            "POST",
            &format!("/admin/keys/{id}/budget-override"),
            Some(r#"{"max_tokens_increase":500,"ttl_secs":600}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 200, "{}", resp.2);

        let resp = dispatch("DELETE", &format!("/admin/keys/{id}/budget-override"), None).unwrap();
        assert_eq!(resp.0, 200, "{}", resp.2);
        let key = &parse(&resp)["key"];
        assert!(key["budget_override"].is_null());
        assert_eq!(key["effective_budget"]["max_tokens"], 1_000);
        let events = sbproxy_observe::audit_ring::recent_audit_events(
            5,
            Some("key"),
            Some("budget_override_clear"),
            Some(&id),
        );
        assert_eq!(events.len(), 1, "the early clear is audited");

        // With nothing left to clear, the route says so.
        let resp = dispatch("DELETE", &format!("/admin/keys/{id}/budget-override"), None).unwrap();
        assert_eq!(resp.0, 404, "{}", resp.2);
    }

    #[test]
    fn an_expired_override_is_retired_and_audited_by_the_next_admin_read() {
        let _g = crate::key_plane::test_plane_guard();
        let store = Arc::new(MemoryKeyStore::new());
        install_test_plane_with_store(store.clone());
        let id = mint_budgeted_key(Some(1_000), None);

        // Persist an already-expired override straight into the store, the
        // state a restarted process finds after a raise lapsed while it was
        // down. No admin call ever saw this grant expire.
        let mut rec = block_on_keystore(store.get_key(&id)).unwrap().unwrap();
        rec.budget_override = Some(BudgetOverride {
            max_tokens_increase: Some(500),
            max_cost_usd_increase: None,
            expires_at: Utc::now() - chrono::Duration::seconds(5),
            granted_by: "casey".into(),
            granted_at: Utc::now() - chrono::Duration::seconds(65),
            reason: None,
        });
        block_on_keystore(store.put_key(rec)).unwrap();

        // The read shows the base budget alone, never the lapsed raise.
        let resp = dispatch("GET", &format!("/admin/keys/{id}"), None).unwrap();
        assert_eq!(resp.0, 200, "{}", resp.2);
        let key = &parse(&resp)["key"];
        assert!(key["budget_override"].is_null());
        assert_eq!(key["effective_budget"]["max_tokens"], 1_000);

        // The read also retired the grant from the record and wrote the
        // expiry into the audit trail, exactly once.
        let stored = block_on_keystore(store.get_key(&id)).unwrap().unwrap();
        assert!(stored.budget_override.is_none());
        let events = sbproxy_observe::audit_ring::recent_audit_events(
            5,
            Some("key"),
            Some("budget_override_expire"),
            Some(&id),
        );
        assert_eq!(events.len(), 1, "expiry lands in the audit trail once");
        assert!(events[0].actor.is_none(), "time has no operator");

        // A second read finds nothing to retire and audits nothing new.
        let resp = dispatch("GET", &format!("/admin/keys/{id}"), None).unwrap();
        assert_eq!(resp.0, 200, "{}", resp.2);
        let events = sbproxy_observe::audit_ring::recent_audit_events(
            5,
            Some("key"),
            Some("budget_override_expire"),
            Some(&id),
        );
        assert_eq!(events.len(), 1, "retirement is not repeated");
    }

    #[test]
    fn policy_preview_reflects_the_override_at_the_sample_instant() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();
        let id = mint_budgeted_key(Some(1_000), None);
        let resp = dispatch(
            "POST",
            &format!("/admin/keys/{id}/budget-override"),
            Some(r#"{"max_tokens_increase":500,"expires_at":"2029-01-01T00:00:00Z"}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 200, "{}", resp.2);

        // Sampled before the expiry: the raised cap admits 1,200 tokens.
        let before = dispatch(
            "POST",
            &format!("/admin/keys/{id}/effective-policy/preview"),
            Some(r#"{"at":"2028-12-31T00:00:00Z","estimated_tokens":1200}"#),
        )
        .unwrap();
        assert_eq!(before.0, 200, "{}", before.2);
        let decisions = &parse(&before)["decisions"];
        assert_eq!(decisions["budget"]["tokens"]["limit"], 1_500);
        assert_eq!(decisions["budget"]["allowed"], true);

        // Sampled after: the base cap governs and refuses the same request.
        let after = dispatch(
            "POST",
            &format!("/admin/keys/{id}/effective-policy/preview"),
            Some(r#"{"at":"2029-01-01T00:00:01Z","estimated_tokens":1200}"#),
        )
        .unwrap();
        assert_eq!(after.0, 200, "{}", after.2);
        let decisions = &parse(&after)["decisions"];
        assert_eq!(decisions["budget"]["tokens"]["limit"], 1_000);
        assert_eq!(decisions["budget"]["allowed"], false);
    }

    /// WOR-2572: every admin key-lifecycle route lands on
    /// `sbproxy_key_operations_total` with an outcome derived from the
    /// status class the handler actually returned. The three outcome
    /// values are asserted separately on purpose: folding a refusal into
    /// `ok` (or an outage into `refused`) is the labeling defect the
    /// ticket exists to rule out.
    #[test]
    fn key_operations_move_at_the_admin_seam_with_separate_outcomes() {
        let _g = crate::key_plane::test_plane_guard();
        let op_count = key_operation_count;

        let before_mint_ok = op_count("mint", "ok");
        let before_mint_error = op_count("mint", "error");
        let before_rotate_ok = op_count("rotate", "ok");
        let before_rotate_refused = op_count("rotate", "refused");
        let before_block_ok = op_count("block", "ok");
        let before_unblock_ok = op_count("unblock", "ok");
        let before_update_ok = op_count("update", "ok");
        let before_revoke_ok = op_count("revoke", "ok");
        let before_delete_ok = op_count("delete", "ok");

        // A dead store is an `error`: the operator asked for something
        // legitimate and the infrastructure could not do it.
        install_down_plane();
        let resp = dispatch("POST", "/admin/keys", None).unwrap();
        assert_eq!(resp.0, 500, "{}", resp.2);
        assert_eq!(
            op_count("mint", "error") - before_mint_error,
            1.0,
            "a store failure must land on outcome=error, not be folded into ok or refused"
        );

        // The healthy plane: one of each operation, all `ok`.
        install_test_plane();
        let resp = dispatch("POST", "/admin/keys", Some(r#"{"name":"m"}"#)).unwrap();
        assert_eq!(resp.0, 201, "{}", resp.2);
        let minted = parse(&resp);
        let key_id = minted["key"]["key_id"]
            .as_str()
            .expect("minted key id")
            .to_string();
        // `update_key` requires an explicit `expected_revision`; the
        // status and rotate routes default it to the record's current
        // value, which is why only this call carries a body.
        let revision = minted["key"]["policy_revision"]
            .as_u64()
            .expect("minted policy revision");
        let resp = dispatch(
            "PATCH",
            &format!("/admin/keys/{key_id}"),
            Some(&format!(r#"{{"expected_revision":{revision}}}"#)),
        )
        .unwrap();
        assert_eq!(resp.0, 200, "{}", resp.2);
        let resp = dispatch("POST", &format!("/admin/keys/{key_id}/rotate"), None).unwrap();
        assert_eq!(resp.0, 200, "{}", resp.2);
        let resp = dispatch("POST", &format!("/admin/keys/{key_id}/block"), None).unwrap();
        assert_eq!(resp.0, 200, "{}", resp.2);
        let resp = dispatch("POST", &format!("/admin/keys/{key_id}/unblock"), None).unwrap();
        assert_eq!(resp.0, 200, "{}", resp.2);
        let resp = dispatch("POST", &format!("/admin/keys/{key_id}/revoke"), None).unwrap();
        assert_eq!(resp.0, 200, "{}", resp.2);

        // A rotate against a revoked (terminal) key is a refusal the
        // operator can understand, not an error.
        let resp = dispatch("POST", &format!("/admin/keys/{key_id}/rotate"), None).unwrap();
        assert!((400..500).contains(&resp.0), "{}", resp.2);
        let resp = dispatch("DELETE", &format!("/admin/keys/{key_id}"), None).unwrap();
        assert_eq!(resp.0, 200, "{}", resp.2);

        assert_eq!(op_count("mint", "ok") - before_mint_ok, 1.0);
        assert_eq!(op_count("update", "ok") - before_update_ok, 1.0);
        assert_eq!(op_count("rotate", "ok") - before_rotate_ok, 1.0);
        assert_eq!(op_count("block", "ok") - before_block_ok, 1.0);
        assert_eq!(op_count("unblock", "ok") - before_unblock_ok, 1.0);
        assert_eq!(op_count("revoke", "ok") - before_revoke_ok, 1.0);
        assert_eq!(op_count("delete", "ok") - before_delete_ok, 1.0);
        assert_eq!(
            op_count("rotate", "refused") - before_rotate_refused,
            1.0,
            "a terminal-key rotate is a refusal, its own label value"
        );
        assert_eq!(
            op_count("mint", "error") - before_mint_error,
            1.0,
            "the healthy-plane run must not have added error outcomes"
        );
    }

    /// Sum `sbproxy_key_operations_total` across every series carrying
    /// this `(operation, outcome)` pair.
    fn key_operation_count(operation: &str, outcome: &str) -> f64 {
        let want = [
            format!("operation={operation}"),
            format!("outcome={outcome}"),
        ];
        let mut total = 0.0;
        for family in prometheus::gather() {
            if family.name() != "sbproxy_key_operations_total" {
                continue;
            }
            for metric in family.get_metric() {
                let labels: Vec<String> = metric
                    .get_label()
                    .iter()
                    .map(|pair| format!("{}={}", pair.name(), pair.value()))
                    .collect();
                if want.iter().all(|label| labels.contains(label)) {
                    total += metric.get_counter().value();
                }
            }
        }
        total
    }

    /// Fix round on the #1177 review, red-first: the budget-override
    /// route was the one arm of `key_subroute` with no
    /// `count_key_operation` wrapper, so raising a spending ceiling was
    /// invisible on `sbproxy_key_operations_total` and so were its 500s
    /// and its twelve refusal paths. The alert operators are told to
    /// run, `rate(sbproxy_key_operations_total{outcome="error"}[5m])`,
    /// stayed flat while the route 500'd.
    ///
    /// All three outcomes, because the seam derives them from the
    /// status class and a route that only ever proves `ok` proves the
    /// least interesting third of the contract.
    #[test]
    fn budget_override_routes_are_counted_like_every_other_key_mutation() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();
        let id = mint_budgeted_key(Some(1_000), None);

        let before_grant_ok = key_operation_count("budget_override_grant", "ok");
        let before_grant_refused = key_operation_count("budget_override_grant", "refused");
        let before_clear_ok = key_operation_count("budget_override_clear", "ok");
        let before_clear_refused = key_operation_count("budget_override_clear", "refused");

        let resp = dispatch(
            "POST",
            &format!("/admin/keys/{id}/budget-override"),
            Some(r#"{"max_tokens_increase":500,"ttl_secs":600}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 200, "{}", resp.2);

        // A raise on an axis the base budget does not cap is a refusal
        // the caller can fix, not an outage.
        let resp = dispatch(
            "POST",
            &format!("/admin/keys/{id}/budget-override"),
            Some(r#"{"max_cost_usd_increase":10.0,"ttl_secs":600}"#),
        )
        .unwrap();
        assert!((400..500).contains(&resp.0), "{}", resp.2);

        let resp = dispatch("DELETE", &format!("/admin/keys/{id}/budget-override"), None).unwrap();
        assert_eq!(resp.0, 200, "{}", resp.2);
        // Nothing left to clear: the 404 is a refusal.
        let resp = dispatch("DELETE", &format!("/admin/keys/{id}/budget-override"), None).unwrap();
        assert_eq!(resp.0, 404, "{}", resp.2);

        assert_eq!(
            key_operation_count("budget_override_grant", "ok") - before_grant_ok,
            1.0,
            "a granted raise must reach sbproxy_key_operations_total"
        );
        assert_eq!(
            key_operation_count("budget_override_grant", "refused") - before_grant_refused,
            1.0,
            "a refused raise must be countable, or outcome=refused cannot show a caller \
             hammering the route"
        );
        assert_eq!(
            key_operation_count("budget_override_clear", "ok") - before_clear_ok,
            1.0,
            "an early clear must reach the counter too"
        );
        assert_eq!(
            key_operation_count("budget_override_clear", "refused") - before_clear_refused,
            1.0,
            "clearing a raise that is not there is a refusal"
        );

        // The store goes down under a legitimate grant: `error`, never
        // folded into `refused`.
        let before_grant_error = key_operation_count("budget_override_grant", "error");
        install_down_plane();
        let resp = dispatch(
            "POST",
            &format!("/admin/keys/{id}/budget-override"),
            Some(r#"{"max_tokens_increase":500,"ttl_secs":600}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 500, "{}", resp.2);
        assert_eq!(
            key_operation_count("budget_override_grant", "error") - before_grant_error,
            1.0,
            "a store outage on the raise route must page, not read as a caller mistake"
        );
    }

    /// Poll `path` until `predicate` matches an NDJSON line or five
    /// seconds pass. The file egress flushes per drained batch on its
    /// own OS thread, so a plain read races the worker.
    fn poll_events_file(
        path: &std::path::Path,
        predicate: impl Fn(&str) -> bool,
    ) -> Option<String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Some(line) = content.lines().find(|line| predicate(line)) {
                    return Some(line.to_string());
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        None
    }

    /// WOR-2571, the real call sites, red-first: before the bridge in
    /// `KeyAuditEntry::emit`, this test timed out polling for
    /// `key_revoked` because the admin mutations reached the `key_audit`
    /// channel and nothing else. Drives the actual admin routes
    /// (mint, rotate, block, revoke) against a test plane with a file
    /// egress installed, then checks the NDJSON the SIEM would ingest:
    /// all four events, attributed to the tenant, and neither minted
    /// plaintext token's secret anywhere in the feed. One egress
    /// install per process, which nextest's process-per-test model
    /// guarantees.
    #[test]
    fn admin_key_lifecycle_operations_reach_the_siem_event_feed() {
        use sbproxy_observe::EventType;

        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();

        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("key-lifecycle.ndjson");
        let egress = sbproxy_observe::EventEgress::start(
            sbproxy_observe::EventSinkTarget::File { path: path.clone() },
            sbproxy_observe::EventTypeMask::from_types(&[
                EventType::KeyMinted,
                EventType::KeyRotated,
                EventType::KeyBlocked,
                EventType::KeyRevoked,
            ]),
            64,
        )
        .expect("file egress starts");
        sbproxy_observe::install_event_egress(egress)
            .expect("this test's own event egress installs exactly once in its own process");

        let minted = parse(
            &dispatch("POST", "/admin/keys", Some(r#"{"tenant":"acme"}"#))
                .expect("keys route is owned"),
        );
        let key_id = minted["key"]["key_id"]
            .as_str()
            .expect("mint returns the key id")
            .to_string();
        let mint_secret = minted["token"]
            .as_str()
            .expect("mint returns the one-time token")
            .rsplit('_')
            .next()
            .expect("token carries a secret segment")
            .to_string();

        let rotated = parse(
            &dispatch("POST", &format!("/admin/keys/{key_id}/rotate"), None)
                .expect("rotate route is owned"),
        );
        let rotate_secret = rotated["token"]
            .as_str()
            .expect("rotate returns the one-time token")
            .rsplit('_')
            .next()
            .expect("token carries a secret segment")
            .to_string();

        let blocked = dispatch("POST", &format!("/admin/keys/{key_id}/block"), None)
            .expect("block route is owned");
        assert_eq!(blocked.0, 200, "{}", blocked.2);
        let revoked = dispatch("POST", &format!("/admin/keys/{key_id}/revoke"), None)
            .expect("revoke route is owned");
        assert_eq!(revoked.0, 200, "{}", revoked.2);

        // The revoke is the last mutation, so once it is on disk the
        // other three had every chance to arrive.
        poll_events_file(&path, |line| line.contains("key_revoked"))
            .expect("the revoke must reach the egress");
        let content = std::fs::read_to_string(&path).expect("events file is readable");

        for (event_type, op) in [
            ("key_minted", "create"),
            ("key_rotated", "rotate"),
            ("key_blocked", "block"),
            ("key_revoked", "revoke"),
        ] {
            let line = content
                .lines()
                .find(|line| line.contains(event_type))
                .unwrap_or_else(|| panic!("no {event_type} event in the feed: {content}"));
            let event: serde_json::Value = serde_json::from_str(line).expect("event line parses");
            assert_eq!(event["event_type"], event_type);
            assert_eq!(event["tenant_id"], "acme", "{event}");
            assert_eq!(event["data"]["op"], op);
            assert_eq!(event["data"]["resource"], "key");
            assert_eq!(event["data"]["id"], key_id.as_str());
            assert_eq!(event["data"]["outcome"], "applied");
        }

        let blocked_event: serde_json::Value = serde_json::from_str(
            content
                .lines()
                .find(|line| line.contains("key_blocked"))
                .expect("checked above"),
        )
        .expect("event line parses");
        assert_eq!(blocked_event["data"]["prior_status"], "active");
        assert_eq!(blocked_event["data"]["new_status"], "blocked");

        assert!(
            !content.contains(&mint_secret),
            "the minted token's secret segment must never reach the typed feed: {content}"
        );
        assert!(
            !content.contains(&rotate_secret),
            "the rotated token's secret segment must never reach the typed feed: {content}"
        );
        assert!(
            !content.contains("secret_hash"),
            "no verifier material may reach the typed feed: {content}"
        );
    }

    /// WOR-2640: the admin API takes a plaintext credential in the
    /// request body, and a `{:?}` of a rejected body would put it in
    /// the admin log.
    #[test]
    fn debug_never_renders_an_admin_credential_secret() {
        let create = CredentialCreate {
            id: Some("cred-1".to_string()),
            secret: Some("SENTINEL-SECRET-9f3a".to_string()),
            ..CredentialCreate::default()
        };
        let rendered = format!("{create:?}");
        assert!(
            !rendered.contains("SENTINEL-SECRET-9f3a"),
            "the posted credential reached Debug: {rendered}"
        );
        assert!(rendered.contains("cred-1"), "lost the id: {rendered}");

        let update = CredentialUpdate {
            secret: Some("SENTINEL-SECRET-9f3a".to_string()),
            ..CredentialUpdate::default()
        };
        assert!(!format!("{update:?}").contains("SENTINEL-SECRET-9f3a"));

        // Absent stays visibly absent: an operator debugging a
        // "credential has no material" error needs that distinction.
        let empty = CredentialUpdate::default();
        assert!(format!("{empty:?}").contains("secret: None"));
    }

    // --- WOR-2567: credential rotation with a graced overlap ---

    /// The seam: rotating an upstream credential keeps the previous
    /// material usable for a bounded window, and the response says the
    /// window is open without saying what the previous material was.
    ///
    /// Before this the only way to change an upstream secret was a
    /// `PATCH` overwrite: the instant it landed every request presented
    /// the new value, and a value the provider had not activated yet took
    /// the deployment down with it.
    #[test]
    fn rotating_a_credential_opens_a_bounded_overlap_window() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();

        let created = dispatch(
            "POST",
            "/admin/credentials",
            Some(r#"{"id":"cred-rot","name":"openai","secret":"sk-old-secret"}"#),
        )
        .unwrap();
        assert_eq!(created.0, 201, "{}", created.2);
        assert!(
            parse(&created)["credential"]["rotated_at"].is_null(),
            "a credential that has never been rotated has no rotation timestamp"
        );

        let rotated = dispatch(
            "POST",
            "/admin/credentials/cred-rot/rotate",
            Some(r#"{"secret":"sk-new-secret","grace_secs":300}"#),
        )
        .unwrap();
        assert_eq!(rotated.0, 200, "{}", rotated.2);
        let body = parse(&rotated);
        assert_eq!(body["overlap"]["grace_secs"], 300);
        assert!(
            !body["overlap"]["previous_material_expires_at"].is_null(),
            "the overlap window must have a stated end: {}",
            rotated.2
        );
        assert!(
            !body["credential"]["rotated_at"].is_null(),
            "a rotation stamps rotated_at, which is what rotation age is measured from"
        );
        // The one thing this response must never do.
        for forbidden in ["sk-old-secret", "sk-new-secret"] {
            assert!(
                !rotated.2.contains(forbidden),
                "a rotation response leaked credential material: {}",
                rotated.2
            );
        }

        // The overlap is visible on the record, again without the value.
        let fetched = dispatch("GET", "/admin/credentials/cred-rot", None).unwrap();
        assert!(
            !parse(&fetched)["credential"]["rotation_overlap_expires_at"].is_null(),
            "the overlap window is visible on the detail view: {}",
            fetched.2
        );
        for forbidden in ["sk-old-secret", "sk-new-secret"] {
            assert!(!fetched.2.contains(forbidden), "{}", fetched.2);
        }
    }

    /// `grace_secs: 0` retires the old material immediately, which is
    /// what an operator rotating a compromised secret needs. An overlap
    /// that could not be turned off would keep a leaked key working for
    /// five minutes after the operator did the one thing that was
    /// supposed to stop it.
    #[test]
    fn a_zero_grace_rotation_retires_the_previous_material_at_once() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();
        dispatch(
            "POST",
            "/admin/credentials",
            Some(r#"{"id":"cred-burn","name":"openai","secret":"sk-leaked"}"#),
        )
        .unwrap();
        let rotated = dispatch(
            "POST",
            "/admin/credentials/cred-burn/rotate",
            Some(r#"{"secret":"sk-fresh","grace_secs":0}"#),
        )
        .unwrap();
        assert_eq!(rotated.0, 200, "{}", rotated.2);
        let body = parse(&rotated);
        assert_eq!(body["overlap"]["grace_secs"], 0);
        assert!(
            body["overlap"]["previous_material_expires_at"].is_null(),
            "a zero grace leaves no overlap window at all: {}",
            rotated.2
        );
        assert!(
            body["credential"]["rotation_overlap_expires_at"].is_null(),
            "{}",
            rotated.2
        );
    }

    /// Revocation stays terminal. A rotate that reactivated a revoked
    /// credential would make revocation reversible by anyone who can
    /// rotate, which is a strictly wider set than anyone who can
    /// un-revoke, because un-revoking is not an operation at all.
    #[test]
    fn a_revoked_credential_cannot_be_rotated_back_into_service() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();
        dispatch(
            "POST",
            "/admin/credentials",
            Some(r#"{"id":"cred-dead","name":"openai","secret":"sk-old"}"#),
        )
        .unwrap();
        dispatch("POST", "/admin/credentials/cred-dead/revoke", None).unwrap();
        let rotated = dispatch(
            "POST",
            "/admin/credentials/cred-dead/rotate",
            Some(r#"{"secret":"sk-new"}"#),
        )
        .unwrap();
        assert_eq!(rotated.0, 409, "{}", rotated.2);
        assert!(rotated.2.contains("terminal"), "{}", rotated.2);
    }

    // --- WOR-2573: break-glass ---

    /// The seam: a grant needs a quorum of *other* operators, and the
    /// requester is never one of them even when the roster names them.
    ///
    /// A two-person rule one person can satisfy is not a two-person rule,
    /// and the roster is exactly where somebody would otherwise close the
    /// gap by adding themselves.
    #[test]
    fn a_break_glass_grant_needs_a_quorum_and_refuses_self_approval() {
        let _g = crate::key_plane::test_plane_guard();
        crate::break_glass::reset_for_test();
        install_break_glass_plane(2, &["alice", "bob", "carol"]);

        let _actor = crate::admin::set_current_admin_actor(Some((
            "alice".to_string(),
            sbproxy_config::types::AdminRole::Admin,
        )));
        let requested = dispatch(
            "POST",
            "/admin/break-glass",
            Some(r#"{"justification":"incident 4412","scope":["cred-openai"],"ttl_secs":600}"#),
        )
        .unwrap();
        assert_eq!(requested.0, 201, "{}", requested.2);
        let grant_id = parse(&requested)["grant"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(parse(&requested)["grant"]["state"], "pending_approval");

        // Alice is on the roster and still cannot approve her own request.
        let self_approve = dispatch(
            "POST",
            &format!("/admin/break-glass/{grant_id}/approve"),
            None,
        )
        .unwrap();
        assert_eq!(self_approve.0, 403, "{}", self_approve.2);
        assert!(
            self_approve
                .2
                .contains("cannot be approved by the operator who requested it"),
            "{}",
            self_approve.2
        );

        // One approval is not the quorum of two.
        let _bob = crate::admin::set_current_admin_actor(Some((
            "bob".to_string(),
            sbproxy_config::types::AdminRole::Admin,
        )));
        let first = dispatch(
            "POST",
            &format!("/admin/break-glass/{grant_id}/approve"),
            None,
        )
        .unwrap();
        assert_eq!(first.0, 200, "{}", first.2);
        assert_eq!(parse(&first)["grant"]["state"], "pending_approval");
        assert_eq!(parse(&first)["grant"]["approvals_needed"], 1);

        // Somebody not on the roster cannot make up the difference.
        let _mallory = crate::admin::set_current_admin_actor(Some((
            "mallory".to_string(),
            sbproxy_config::types::AdminRole::Admin,
        )));
        let outsider = dispatch(
            "POST",
            &format!("/admin/break-glass/{grant_id}/approve"),
            None,
        )
        .unwrap();
        assert_eq!(outsider.0, 403, "{}", outsider.2);

        // The second roster approver activates it.
        let _carol = crate::admin::set_current_admin_actor(Some((
            "carol".to_string(),
            sbproxy_config::types::AdminRole::Admin,
        )));
        let second = dispatch(
            "POST",
            &format!("/admin/break-glass/{grant_id}/approve"),
            None,
        )
        .unwrap();
        assert_eq!(second.0, 200, "{}", second.2);
        assert_eq!(parse(&second)["grant"]["state"], "active");
        assert_eq!(parse(&second)["grant"]["approvals_needed"], 0);
    }

    /// A grant with no scope is refused. An unscoped break-glass grant is
    /// a standing admin credential with extra paperwork, and shipping one
    /// would make the whole feature theatre.
    #[test]
    fn an_unscoped_or_over_long_break_glass_request_is_refused() {
        let _g = crate::key_plane::test_plane_guard();
        crate::break_glass::reset_for_test();
        install_break_glass_plane(2, &["alice", "bob"]);
        let _actor = crate::admin::set_current_admin_actor(Some((
            "alice".to_string(),
            sbproxy_config::types::AdminRole::Admin,
        )));

        let unscoped = dispatch(
            "POST",
            "/admin/break-glass",
            Some(r#"{"justification":"incident","scope":[],"ttl_secs":600}"#),
        )
        .unwrap();
        assert_eq!(unscoped.0, 400, "{}", unscoped.2);
        assert!(unscoped.2.contains("non-empty scope"), "{}", unscoped.2);

        // Above the cap is refused rather than clamped, so the requester
        // finds out now instead of when the grant expires early.
        let too_long = dispatch(
            "POST",
            "/admin/break-glass",
            Some(r#"{"justification":"incident","scope":["c1"],"ttl_secs":99999}"#),
        )
        .unwrap();
        assert_eq!(too_long.0, 400, "{}", too_long.2);
        assert!(too_long.2.contains("max_ttl_secs"), "{}", too_long.2);

        let unjustified = dispatch(
            "POST",
            "/admin/break-glass",
            Some(r#"{"justification":"","scope":["c1"],"ttl_secs":600}"#),
        )
        .unwrap();
        assert_eq!(unjustified.0, 400, "{}", unjustified.2);
    }

    /// Actions taken while a grant is active carry the grant id, so a
    /// reviewer pulls the whole session by one key instead of correlating
    /// timestamps against a window they have to reconstruct.
    #[test]
    fn an_action_under_an_active_grant_is_tagged_with_the_grant_id() {
        let _g = crate::key_plane::test_plane_guard();
        crate::break_glass::reset_for_test();
        install_break_glass_plane(1, &["bob"]);

        let _alice = crate::admin::set_current_admin_actor(Some((
            "alice".to_string(),
            sbproxy_config::types::AdminRole::Admin,
        )));
        let requested = dispatch(
            "POST",
            "/admin/break-glass",
            Some(r#"{"justification":"incident 55","scope":["cred-x"],"ttl_secs":600}"#),
        )
        .unwrap();
        let grant_id = parse(&requested)["grant"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        let _bob = crate::admin::set_current_admin_actor(Some((
            "bob".to_string(),
            sbproxy_config::types::AdminRole::Admin,
        )));
        let approved = dispatch(
            "POST",
            &format!("/admin/break-glass/{grant_id}/approve"),
            None,
        )
        .unwrap();
        assert_eq!(parse(&approved)["grant"]["state"], "active");

        // Alice, holding the active grant, mints a key. The audit seam
        // every key mutation funnels through tags it.
        let _alice = crate::admin::set_current_admin_actor(Some((
            "alice".to_string(),
            sbproxy_config::types::AdminRole::Admin,
        )));
        let minted = dispatch("POST", "/admin/keys", Some(r#"{"name":"emergency"}"#)).unwrap();
        assert_eq!(minted.0, 201, "{}", minted.2);

        let listed = dispatch("GET", "/admin/break-glass", None).unwrap();
        let body = parse(&listed);
        let grant = body["grants"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["id"] == grant_id.as_str())
            .expect("the grant is listed");
        assert_eq!(
            grant["actions_taken"], 1,
            "the mint taken under the grant is counted against it: {}",
            listed.2
        );
    }

    // --- WOR-2569: leased credentials ---

    /// The seam: `lease` is refused for a provider whose platform cannot
    /// mint short-lived credentials, and the refusal names the limitation.
    ///
    /// This is the acceptance line that matters most, because the failure
    /// it prevents is silent. Accepting `lease` for OpenAI and reading the
    /// reference once would produce a record that reads "leased" on the
    /// admin view, never expires, and is exactly as static as the stored
    /// secret it replaced. An operator would believe they had short-lived
    /// upstream credentials and would not.
    #[test]
    fn leasing_is_refused_for_a_provider_that_cannot_mint_short_lived_credentials() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();

        let refused = dispatch(
            "POST",
            "/admin/credentials",
            Some(
                r#"{"id":"cred-openai-leased","name":"openai","provider":"openai",
                    "lease":{"reference":"vault://aws/creds/x","platform":"aws",
                             "lease_duration_secs":900}}"#,
            ),
        )
        .unwrap();
        assert_eq!(refused.0, 400, "{}", refused.2);
        assert!(
            refused.2.contains("no short-TTL issuance to lease against"),
            "the refusal must name why, not just say no: {}",
            refused.2
        );

        // A platform that does not exist is refused with the four that do.
        let bad_platform = dispatch(
            "POST",
            "/admin/credentials",
            Some(
                r#"{"id":"cred-bad-platform","provider":"bedrock",
                    "lease":{"reference":"vault://aws/creds/x","platform":"openai",
                             "lease_duration_secs":900}}"#,
            ),
        )
        .unwrap();
        assert_eq!(bad_platform.0, 400, "{}", bad_platform.2);
        assert!(
            bad_platform.2.contains("aws, gcp, azure, or database"),
            "{}",
            bad_platform.2
        );

        // A zero lease is refused: it is the cache ceiling, and a zero
        // ceiling would mean the material may never be served at all.
        let zero = dispatch(
            "POST",
            "/admin/credentials",
            Some(
                r#"{"id":"cred-zero","provider":"bedrock",
                    "lease":{"reference":"vault://aws/creds/x","platform":"aws",
                             "lease_duration_secs":0}}"#,
            ),
        )
        .unwrap();
        assert_eq!(zero.0, 400, "{}", zero.2);
    }

    /// A leased credential stores nothing static, and the admin view says
    /// so without ever naming material.
    #[test]
    fn a_leased_credential_reports_its_platform_and_lease_and_no_material() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();

        let created = dispatch(
            "POST",
            "/admin/credentials",
            Some(
                r#"{"id":"cred-bedrock","name":"bedrock-prod","provider":"bedrock",
                    "lease":{"reference":"vault://aws/creds/sbproxy-bedrock","platform":"aws",
                             "lease_duration_secs":900}}"#,
            ),
        )
        .unwrap();
        assert_eq!(created.0, 201, "{}", created.2);
        let body = parse(&created);
        assert_eq!(body["credential"]["storage"], "leased");
        assert_eq!(body["credential"]["lease"]["platform"], "aws");
        assert_eq!(body["credential"]["lease"]["lease_duration_secs"], 900);
        // The mount reference is not a secret and an operator has to be
        // able to read it to fix a typo; the leased material never appears
        // because it is never stored.
        assert_eq!(
            body["credential"]["vault_ref"],
            "vault://aws/creds/sbproxy-bedrock"
        );

        // Mixing lease with a stored secret is refused rather than one
        // silently winning.
        let mixed = dispatch(
            "POST",
            "/admin/credentials",
            Some(
                r#"{"id":"cred-mixed","provider":"bedrock","secret":"sk-static",
                    "lease":{"reference":"vault://aws/creds/x","platform":"aws",
                             "lease_duration_secs":900}}"#,
            ),
        )
        .unwrap();
        assert_eq!(mixed.0, 400, "{}", mixed.2);
        assert!(mixed.2.contains("mutually exclusive"), "{}", mixed.2);
        assert!(!mixed.2.contains("sk-static"), "{}", mixed.2);
    }

    /// The post-access review cannot be closed by the operator who used
    /// the grant, and cannot be closed by somebody off the roster.
    ///
    /// `approve` had both checks and `review` had neither, so the
    /// requester could wait for their own grant to expire and then clear
    /// it off the review queue and off
    /// `sbproxy_break_glass_open{state="awaiting_review"}`, which is the
    /// one alert the feature is built around. Untested until now, so
    /// reverting either check left the whole gate green.
    #[test]
    fn a_break_glass_review_refuses_the_requester_and_anyone_off_the_roster() {
        let _g = crate::key_plane::test_plane_guard();
        crate::break_glass::reset_for_test();
        install_break_glass_plane(1, &["bob", "dave"]);

        let _alice = crate::admin::set_current_admin_actor(Some((
            "alice".to_string(),
            sbproxy_config::types::AdminRole::Admin,
        )));
        let requested = dispatch(
            "POST",
            "/admin/break-glass",
            Some(r#"{"justification":"incident 71","scope":["cred-x"],"ttl_secs":1}"#),
        )
        .unwrap();
        assert_eq!(requested.0, 201, "{}", requested.2);
        let grant_id = parse(&requested)["grant"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        let _bob = crate::admin::set_current_admin_actor(Some((
            "bob".to_string(),
            sbproxy_config::types::AdminRole::Admin,
        )));
        let approved = dispatch(
            "POST",
            &format!("/admin/break-glass/{grant_id}/approve"),
            None,
        )
        .unwrap();
        assert_eq!(parse(&approved)["grant"]["state"], "active");

        // Let the one-second TTL lapse so the grant is awaiting review.
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // Alice used the grant. She cannot sign off on it.
        let _alice = crate::admin::set_current_admin_actor(Some((
            "alice".to_string(),
            sbproxy_config::types::AdminRole::Admin,
        )));
        let self_review = dispatch(
            "POST",
            &format!("/admin/break-glass/{grant_id}/review"),
            Some(r#"{"note":"looks fine to me"}"#),
        )
        .unwrap();
        assert_eq!(self_review.0, 403, "{}", self_review.2);
        assert!(
            self_review
                .2
                .contains("cannot be reviewed by the operator who requested it"),
            "{}",
            self_review.2
        );

        // Neither can somebody who is not an approver.
        let _mallory = crate::admin::set_current_admin_actor(Some((
            "mallory".to_string(),
            sbproxy_config::types::AdminRole::Admin,
        )));
        let outsider = dispatch(
            "POST",
            &format!("/admin/break-glass/{grant_id}/review"),
            Some(r#"{"note":"nothing to see"}"#),
        )
        .unwrap();
        assert_eq!(outsider.0, 403, "{}", outsider.2);

        // The grant is still on the review queue after both attempts.
        let listed = dispatch("GET", "/admin/break-glass", None).unwrap();
        let body = parse(&listed);
        let grant = body["grants"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["id"] == grant_id.as_str())
            .expect("listed");
        assert_eq!(
            grant["state"], "awaiting_review",
            "a refused review must leave the grant on the queue: {}",
            listed.2
        );

        // A roster approver who is not the requester closes it.
        let _dave = crate::admin::set_current_admin_actor(Some((
            "dave".to_string(),
            sbproxy_config::types::AdminRole::Admin,
        )));
        let reviewed = dispatch(
            "POST",
            &format!("/admin/break-glass/{grant_id}/review"),
            Some(r#"{"note":"rotation confirmed"}"#),
        )
        .unwrap();
        assert_eq!(reviewed.0, 200, "{}", reviewed.2);
        assert_eq!(parse(&reviewed)["grant"]["state"], "reviewed");
    }

    /// A grant awaiting review must still be closeable after the kill
    /// switch is thrown, and after the block is deleted outright.
    ///
    /// Both are strands, and both were live. `review` carries no `enabled`
    /// guard, deliberately: the other three routes create or extend access
    /// and this one closes it out, so a switch that blocked it would leave
    /// every open grant unreviewable, with `list()` still publishing the
    /// queue and `sbproxy_break_glass_open{state="awaiting_review"}` pinned
    /// above zero for the life of the process. Grants live in a
    /// process-global `OnceLock` and survive a config reload, so "they are
    /// gone anyway" was never true.
    ///
    /// Deleting the block reaches the same place by a different route: the
    /// default is `enabled: false, approvers: []`, the compiler validates
    /// the roster only while `enabled` is true, so every operator becomes
    /// `NotAnApprover`. An empty roster therefore falls back to "any admin
    /// who is not the requester", which keeps the property the roster is
    /// there for.
    ///
    /// Re-adding `if !cfg.enabled { return Err(Disabled) }` to `review`
    /// reddens the first half. Dropping the `approvers.is_empty()` guard
    /// reddens the second.
    #[test]
    fn a_grant_stays_reviewable_after_the_kill_switch_and_after_the_block_is_deleted() {
        for (label, approvers, enabled) in [
            ("kill switch thrown", &["bob"][..], false),
            ("block deleted", &[][..], false),
        ] {
            let _g = crate::key_plane::test_plane_guard();
            crate::break_glass::reset_for_test();
            // Requested and approved while the feature was on.
            install_break_glass_plane(1, &["bob"]);
            let _alice = crate::admin::set_current_admin_actor(Some((
                "alice".to_string(),
                sbproxy_config::types::AdminRole::Admin,
            )));
            let requested = dispatch(
                "POST",
                "/admin/break-glass",
                Some(r#"{"justification":"incident 9","scope":["cred-openai"],"ttl_secs":1}"#),
            )
            .unwrap();
            assert_eq!(requested.0, 201, "{label}: {}", requested.2);
            let grant_id = parse(&requested)["grant"]["id"]
                .as_str()
                .unwrap()
                .to_string();
            let _bob = crate::admin::set_current_admin_actor(Some((
                "bob".to_string(),
                sbproxy_config::types::AdminRole::Admin,
            )));
            dispatch(
                "POST",
                &format!("/admin/break-glass/{grant_id}/approve"),
                None,
            )
            .unwrap();
            std::thread::sleep(std::time::Duration::from_millis(1100));

            // Now the operator turns it off, or deletes the block.
            install_break_glass_plane_with(1, approvers, enabled);

            // Read before the review, because the counter assertion
            // below is a strict increase against a process-global
            // registry.
            let grants_before_review = break_glass_grants_total(if approvers.is_empty() {
                "reviewed_without_roster"
            } else {
                "reviewed"
            });

            let reviewed = dispatch(
                "POST",
                &format!("/admin/break-glass/{grant_id}/review"),
                Some(r#"{"note":"closed out after the switch"}"#),
            )
            .unwrap();
            assert_eq!(
                reviewed.0, 200,
                "{label}: a grant awaiting review must still close out, or the queue strands \
                 and the awaiting_review gauge never comes back down: {}",
                reviewed.2
            );
            assert_eq!(parse(&reviewed)["grant"]["state"], "reviewed", "{label}");

            // The empty-roster case closes out through the fallback, and
            // that has to be distinguishable in *both* records: four
            // operator-facing surfaces advertise the label, one of them
            // `docs/metrics-stability.md`, which is a compatibility
            // contract.
            //
            // Both are asserted, separately, because one variable
            // feeding two calls makes a metric-only regression unlikely
            // and not detected, and an earlier round of this test said
            // it pinned the counter when it read only the audit ring.
            // The counter assertion is a strict increase rather than an
            // exact value: `prometheus::gather()` reads a process-global
            // registry and sibling tests move the same family
            // concurrently, so "it moved" is the whole claim the
            // regression needs and the only one that cannot go flaky.
            // Same reasoning, and the same shape, as
            // `settlement_gate.rs:3329`.
            let expected = if approvers.is_empty() {
                "reviewed_without_roster"
            } else {
                "reviewed"
            };
            let events = sbproxy_observe::audit_ring::recent_audit_events(
                10,
                Some("key"),
                Some("break_glass_review"),
                None,
            );
            let closed = events
                .iter()
                .find(|e| e.detail.as_deref().is_some_and(|d| d.contains(expected)))
                .unwrap_or_else(|| {
                    panic!(
                        "{label}: no break_glass_review record with outcome {expected}: {events:?}"
                    )
                });
            assert_eq!(closed.actor.as_deref(), Some("alice"), "{label}");
            assert!(
                break_glass_grants_total(expected) > grants_before_review,
                "{label}: sbproxy_break_glass_grants_total{{event={expected}}} did not \
                 move; the audit record carries the outcome but the counter that \
                 `docs/metrics-stability.md` promises does not"
            );
        }
    }

    /// One `sbproxy_break_glass_grants_total` series, or 0 before
    /// anything has created it.
    ///
    /// Reads the process-global registry, so callers compare a before
    /// and after rather than an absolute: a sibling test on another
    /// thread may move the same series in between.
    fn break_glass_grants_total(event: &str) -> f64 {
        prometheus::gather()
            .into_iter()
            .find(|family| family.name() == "sbproxy_break_glass_grants_total")
            .map(|family| {
                family
                    .get_metric()
                    .iter()
                    .filter(|metric| {
                        metric
                            .get_label()
                            .iter()
                            .any(|label| label.name() == "event" && label.value() == event)
                    })
                    .map(|metric| metric.get_counter().value())
                    .sum()
            })
            .unwrap_or(0.0)
    }

    /// A refused approval or review reaches the audit channel.
    ///
    /// The two refusals are the controls this feature is bought for, and
    /// both returned before any record was written: an operator caught
    /// trying to close their own grant left an HTTP 403 and nothing else.
    /// Deleting either `RefusedGrant::audit` call reddens this.
    #[test]
    fn a_refused_break_glass_review_reaches_the_audit_channel() {
        let _g = crate::key_plane::test_plane_guard();
        crate::break_glass::reset_for_test();
        install_break_glass_plane(1, &["bob"]);

        let _alice = crate::admin::set_current_admin_actor(Some((
            "alice".to_string(),
            sbproxy_config::types::AdminRole::Admin,
        )));
        let requested = dispatch(
            "POST",
            "/admin/break-glass",
            Some(r#"{"justification":"incident 11","scope":["cred-openai"],"ttl_secs":1}"#),
        )
        .unwrap();
        let grant_id = parse(&requested)["grant"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        // alice tries to close her own grant.
        let refused = dispatch(
            "POST",
            &format!("/admin/break-glass/{grant_id}/review"),
            Some(r#"{"note":"nothing to see"}"#),
        )
        .unwrap();
        assert_eq!(refused.0, 403, "{}", refused.2);

        let events = sbproxy_observe::audit_ring::recent_audit_events(
            10,
            Some("key"),
            Some("break_glass_review"),
            None,
        );
        let refusal = events
            .iter()
            .find(|e| e.actor.as_deref() == Some("alice"))
            .unwrap_or_else(|| {
                panic!("a refused self-review must reach the audit channel: {events:?}")
            });
        // The ring renders a record with no `before` as
        // `"{resource}: {outcome}"`, so this is what it can show: the
        // record exists, on the right channel, attributed to the operator
        // who was refused. The reason vocabulary inside it is pinned by
        // `break_glass::tests::a_refusal_record_names_its_rule_and_bounds_its_context`.
        let detail = refusal.detail.clone().unwrap_or_default();
        assert!(
            detail.contains("refused"),
            "the refusal must reach the audit channel as a refusal: {detail}"
        );
    }

    /// The two break-glass bodies parse through `parse_body`, which is
    /// where the serde-message scrub lives.
    ///
    /// `parse_body`'s own doc says the point of putting it there is that a
    /// route added later inherits it; these two parsed on their own path
    /// and did not. Reverting either to a raw `serde_json::from_str` plus
    /// `format!("invalid JSON body: {e}")` reddens this.
    #[test]
    fn a_malformed_break_glass_body_is_scrubbed_before_it_is_echoed() {
        let _g = crate::key_plane::test_plane_guard();
        crate::break_glass::reset_for_test();
        install_break_glass_plane(1, &["bob"]);
        let _alice = crate::admin::set_current_admin_actor(Some((
            "alice".to_string(),
            sbproxy_config::types::AdminRole::Admin,
        )));

        for (route, body) in [
            (
                "/admin/break-glass".to_string(),
                r#"{"justification":"SENTINEL-BODY-4f2a","scope":[],"ttl_secs":"not-a-number"}"#,
            ),
            (
                "/admin/break-glass/bg_missing/review".to_string(),
                r#"{"note":SENTINEL-BODY-4f2a}"#,
            ),
        ] {
            let resp = dispatch("POST", &route, Some(body)).unwrap();
            assert_eq!(resp.0, 400, "{route}: {}", resp.2);
            assert!(
                !resp.2.contains("SENTINEL-BODY-4f2a"),
                "{route}: the serde message must go through the scrub, or a body value \
                 reaches the response verbatim: {}",
                resp.2
            );
        }
    }

    /// The reviewer's note reaches the audit record whole, whatever the
    /// scope carried.
    ///
    /// The note and the scope shared one 256-byte context string, and
    /// scope was bounded at 64 entries of 256 bytes, which is sixty-four
    /// times the context cap. A grant with a large scope silently dropped
    /// `approvals=`, `ttl_secs=` and the note, so the sign-off the whole
    /// feature exists to produce vanished on exactly the grants most
    /// likely to want it.
    #[test]
    fn a_reviewers_note_survives_a_large_scope() {
        let _g = crate::key_plane::test_plane_guard();
        crate::break_glass::reset_for_test();
        install_break_glass_plane(1, &["bob"]);

        let _alice = crate::admin::set_current_admin_actor(Some((
            "alice".to_string(),
            sbproxy_config::types::AdminRole::Admin,
        )));
        let scope: Vec<String> = (0..40)
            .map(|i| format!("cred-with-a-long-name-{i:03}"))
            .collect();
        let request = serde_json::json!({
            "justification": "incident 72",
            "scope": scope,
            "ttl_secs": 1,
        });
        let requested = dispatch("POST", "/admin/break-glass", Some(&request.to_string())).unwrap();
        assert_eq!(requested.0, 201, "{}", requested.2);
        let grant_id = parse(&requested)["grant"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        let _bob = crate::admin::set_current_admin_actor(Some((
            "bob".to_string(),
            sbproxy_config::types::AdminRole::Admin,
        )));
        dispatch(
            "POST",
            &format!("/admin/break-glass/{grant_id}/approve"),
            None,
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));

        let reviewed = dispatch(
            "POST",
            &format!("/admin/break-glass/{grant_id}/review"),
            Some(r#"{"note":"SENTINEL-NOTE-4f2a reviewed, no other credential touched"}"#),
        )
        .unwrap();
        assert_eq!(reviewed.0, 200, "{}", reviewed.2);

        assert_eq!(
            parse(&reviewed)["grant"]["reviewed_note"],
            "SENTINEL-NOTE-4f2a reviewed, no other credential touched",
            "the reviewer's note must survive whole, whatever the scope carried. It used to \
             share a 256-byte context string with a scope bounded two orders of magnitude \
             higher, so a large scope silently evicted the sign-off: {}",
            reviewed.2
        );

        // And it is still there on the listing a reviewer reads later.
        let listed = dispatch("GET", "/admin/break-glass", None).unwrap();
        let body = parse(&listed);
        let grant = body["grants"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["id"] == grant_id.as_str())
            .expect("listed");
        assert!(
            grant["reviewed_note"]
                .as_str()
                .unwrap_or_default()
                .contains("SENTINEL-NOTE-4f2a"),
            "{}",
            listed.2
        );
    }
}

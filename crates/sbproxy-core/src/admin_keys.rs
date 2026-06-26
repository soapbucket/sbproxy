//! WOR-1553: the admin key/credential lifecycle REST API.
//!
//! Mounted in the existing `/admin` server (shared bind + basic auth). Routes:
//!
//! ```text
//! POST   /admin/keys                      mint a key (plaintext token shown once)
//! GET    /admin/keys                      list keys (no secrets)
//! GET    /admin/keys/{id}                 fetch one key
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
//! ```
//!
//! Every mutation goes through the store then invalidates the cache so the
//! change takes effect on the next request without a reload. Responses never
//! carry a hash, an envelope, or plaintext (apart from the one-time minted
//! token on create).

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::key_plane::{block_on_keystore, current_key_plane, KeyPlane};
use sbproxy_keystore::record::{
    CredentialMaterial, CredentialRecord, KeyRecord, RecordBudget, RecordStatus,
};

type Resp = (u16, &'static str, String);

/// Route entry point. Returns `Some(response)` for paths this module owns and
/// `None` so the caller can fall through to the rest of the admin dispatcher.
pub fn dispatch(method: &str, path: &str, body: Option<&str>) -> Option<Resp> {
    if path == "/admin/keys" {
        return Some(if method.eq_ignore_ascii_case("GET") {
            list_keys()
        } else if method.eq_ignore_ascii_case("POST") {
            create_key(body)
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
                update_key(id, body)
            } else if method.eq_ignore_ascii_case("DELETE") {
                delete_key(id)
            } else {
                method_not_allowed()
            }
        }
        Some(action) if method.eq_ignore_ascii_case("POST") => match action {
            "revoke" => set_key_status(id, RecordStatus::Revoked),
            "block" => set_key_status(id, RecordStatus::Blocked),
            "unblock" => set_key_status(id, RecordStatus::Active),
            "rotate" => rotate_key(id, body),
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
            _ => not_found("unknown credential action"),
        },
        Some(_) => method_not_allowed(),
    }
}

// --- Key handlers ---

#[derive(Debug, Default, Deserialize)]
struct KeyMutation {
    name: Option<String>,
    max_requests_per_minute: Option<u64>,
    max_tokens_per_minute: Option<u64>,
    max_budget_tokens: Option<u64>,
    max_budget_usd: Option<f64>,
    allowed_models: Option<Vec<String>>,
    blocked_models: Option<Vec<String>>,
    allowed_providers: Option<Vec<String>>,
    require_pii_redaction: Option<Vec<String>>,
    principal_selectors: Option<Vec<serde_json::Value>>,
    /// Pin a model for this key. An empty string or "null" clears the pin.
    route_to_model: Option<String>,
    inject_tools: Option<Vec<serde_json::Value>>,
    bypass_prompt_injection: Option<bool>,
    project: Option<String>,
    user: Option<String>,
    tags: Option<Vec<String>>,
    tenant: Option<String>,
    /// RFC 3339 expiry. The literal string "null" or an empty string clears it.
    expires_at: Option<String>,
}

/// Apply the mutation fields that are present onto a record. Budget is set when
/// either budget field is present.
fn apply_key_mutation(rec: &mut KeyRecord, m: &KeyMutation) {
    if let Some(v) = &m.name {
        rec.name = Some(v.clone());
    }
    if m.max_requests_per_minute.is_some() {
        rec.max_requests_per_minute = m.max_requests_per_minute;
    }
    if m.max_tokens_per_minute.is_some() {
        rec.max_tokens_per_minute = m.max_tokens_per_minute;
    }
    if m.max_budget_tokens.is_some() || m.max_budget_usd.is_some() {
        let mut b = rec.budget.clone().unwrap_or_default();
        if m.max_budget_tokens.is_some() {
            b.max_tokens = m.max_budget_tokens;
        }
        if m.max_budget_usd.is_some() {
            b.max_cost_usd = m.max_budget_usd;
        }
        rec.budget = Some(b);
    }
    if let Some(v) = &m.allowed_models {
        rec.allowed_models = v.clone();
    }
    if let Some(v) = &m.blocked_models {
        rec.blocked_models = v.clone();
    }
    if let Some(v) = &m.allowed_providers {
        rec.allowed_providers = v.clone();
    }
    if let Some(v) = &m.require_pii_redaction {
        rec.require_pii_redaction = v.clone();
    }
    if let Some(v) = &m.principal_selectors {
        rec.principal_selectors = v.clone();
    }
    if let Some(v) = &m.route_to_model {
        rec.route_to_model = if v.is_empty() || v == "null" {
            None
        } else {
            Some(v.clone())
        };
    }
    if let Some(v) = &m.inject_tools {
        rec.inject_tools = v.clone();
    }
    if let Some(v) = m.bypass_prompt_injection {
        rec.bypass_prompt_injection = v;
    }
    if let Some(v) = &m.project {
        rec.project = Some(v.clone());
    }
    if let Some(v) = &m.user {
        rec.user = Some(v.clone());
    }
    if let Some(v) = &m.tags {
        rec.tags = v.clone();
    }
    if let Some(v) = &m.tenant {
        rec.tenant_id = Some(v.clone());
    }
    if let Some(v) = &m.expires_at {
        rec.expires_at = if v.is_empty() || v == "null" {
            None
        } else {
            parse_rfc3339(v)
        };
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
    audit_mutation("create", "key", &minted.key_id);

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
            let views: Vec<KeyView> = keys.iter().map(KeyView::from).collect();
            ok(json!({ "keys": views }))
        }
        Err(e) => internal_error(&format!("list keys: {e:#}")),
    }
}

fn get_key(id: &str) -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    match load_key(&plane, id) {
        Ok(Some(rec)) => ok(json!({ "key": KeyView::from(&rec) })),
        Ok(None) => not_found("key not found"),
        Err(e) => internal_error(&e),
    }
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
    let mut rec = match load_key(&plane, id) {
        Ok(Some(r)) => r,
        Ok(None) => return not_found("key not found"),
        Err(e) => return internal_error(&e),
    };
    apply_key_mutation(&mut rec, &m);
    rec.updated_at = Utc::now();
    if let Err(e) = store_key(&plane, rec.clone()) {
        return internal_error(&e);
    }
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

fn set_key_status(id: &str, status: RecordStatus) -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let mut rec = match load_key(&plane, id) {
        Ok(Some(r)) => r,
        Ok(None) => return not_found("key not found"),
        Err(e) => return internal_error(&e),
    };
    rec.status = status;
    rec.updated_at = Utc::now();
    if let Err(e) = store_key(&plane, rec.clone()) {
        return internal_error(&e);
    }
    invalidate(&plane, id);
    audit_mutation(status_verb(status), "key", id);
    ok(json!({ "key": KeyView::from(&rec) }))
}

#[derive(Debug, Default, Deserialize)]
struct RotateRequest {
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
    let grace_secs = req.grace_secs.unwrap_or(DEFAULT_ROTATE_GRACE_SECS).max(0);
    let mut rec = match load_key(&plane, id) {
        Ok(Some(r)) => r,
        Ok(None) => return not_found("key not found"),
        Err(e) => return internal_error(&e),
    };
    let minted = plane.crypto().mint_secret();
    let now = Utc::now();
    // The current secret becomes the graced prior secret.
    rec.prev_secret_hash = Some(rec.secret_hash.clone());
    rec.prev_hash_expires_at = Some(now + chrono::Duration::seconds(grace_secs));
    rec.secret_hash = minted.secret_hash;
    rec.updated_at = now;
    if let Err(e) = store_key(&plane, rec.clone()) {
        return internal_error(&e);
    }
    invalidate(&plane, id);
    audit_mutation("rotate", "key", id);

    let token = format!("sk-{}-{}", id, minted.secret);
    ok(json!({
        "token": token,
        "grace_expires_at": rec.prev_hash_expires_at,
        "key": KeyView::from(&rec),
    }))
}

// --- Credential handlers ---

#[derive(Debug, Default, Deserialize)]
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
}

#[derive(Debug, Default, Deserialize)]
struct CredentialUpdate {
    name: Option<String>,
    provider: Option<String>,
    kind: Option<String>,
    vault_ref: Option<String>,
    secret: Option<String>,
    tenant: Option<String>,
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
    let material = match build_material(&plane, &id, c.vault_ref.as_deref(), c.secret.as_deref()) {
        Ok(m) => m,
        Err(e) => return bad_request(&e),
    };
    let now = Utc::now();
    let rec = CredentialRecord {
        id: id.clone(),
        name: c.name.unwrap_or_else(|| id.clone()),
        provider: c.provider,
        kind: c.kind.unwrap_or_else(|| "ai_provider".to_string()),
        material,
        status: RecordStatus::Active,
        tenant_id: c.tenant,
        metadata: Default::default(),
        created_at: now,
        updated_at: now,
        source: sbproxy_keystore::record::RecordSource::Api,
    };
    if let Err(e) = store_credential(&plane, rec.clone()) {
        return internal_error(&e);
    }
    invalidate(&plane, &id);
    audit_mutation("create", "credential", &id);
    created(json!({ "credential": CredentialView::from(&rec) }))
}

fn list_credentials() -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let store = plane.cache().store().clone();
    match block_on_keystore(async move { store.list_credentials().await }) {
        Ok(creds) => {
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
    rec.status = status;
    rec.updated_at = Utc::now();
    if let Err(e) = store_credential(&plane, rec.clone()) {
        return internal_error(&e);
    }
    invalidate(&plane, id);
    audit_mutation(status_verb(status), "credential", id);
    ok(json!({ "credential": CredentialView::from(&rec) }))
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
        let envelope = plane
            .crypto()
            .seal(id, secret.as_bytes())
            .map_err(|e| format!("seal credential: {e:#}"))?;
        Ok(CredentialMaterial::Envelope { envelope })
    } else {
        Err("credential requires either vault_ref or secret".to_string())
    }
}

// --- Response DTOs (never carry secrets) ---

#[derive(Serialize)]
struct KeyView {
    key_id: String,
    name: Option<String>,
    status: RecordStatus,
    max_requests_per_minute: Option<u64>,
    max_tokens_per_minute: Option<u64>,
    budget: Option<RecordBudget>,
    allowed_models: Vec<String>,
    blocked_models: Vec<String>,
    allowed_providers: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    require_pii_redaction: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    principal_selectors: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    route_to_model: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    inject_tools: Vec<serde_json::Value>,
    bypass_prompt_injection: bool,
    project: Option<String>,
    user: Option<String>,
    tags: Vec<String>,
    tenant_id: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    source: sbproxy_keystore::record::RecordSource,
    /// True while a rotation grace window is open (the prior secret still works).
    rotation_pending: bool,
}

impl From<&KeyRecord> for KeyView {
    fn from(r: &KeyRecord) -> Self {
        Self {
            key_id: r.key_id.clone(),
            name: r.name.clone(),
            status: r.status,
            max_requests_per_minute: r.max_requests_per_minute,
            max_tokens_per_minute: r.max_tokens_per_minute,
            budget: r.budget.clone(),
            allowed_models: r.allowed_models.clone(),
            blocked_models: r.blocked_models.clone(),
            allowed_providers: r.allowed_providers.clone(),
            require_pii_redaction: r.require_pii_redaction.clone(),
            principal_selectors: r.principal_selectors.clone(),
            route_to_model: r.route_to_model.clone(),
            inject_tools: r.inject_tools.clone(),
            bypass_prompt_injection: r.bypass_prompt_injection,
            project: r.project.clone(),
            user: r.user.clone(),
            tags: r.tags.clone(),
            tenant_id: r.tenant_id.clone(),
            expires_at: r.expires_at,
            created_at: r.created_at,
            updated_at: r.updated_at,
            source: r.source,
            rotation_pending: r.prev_secret_hash.is_some(),
        }
    }
}

#[derive(Serialize)]
struct CredentialView {
    id: String,
    name: String,
    provider: Option<String>,
    kind: String,
    status: RecordStatus,
    tenant_id: Option<String>,
    /// How the secret is held, without revealing it.
    storage: &'static str,
    /// The vault reference (only for vault-ref credentials; never a secret).
    vault_ref: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    source: sbproxy_keystore::record::RecordSource,
}

impl From<&CredentialRecord> for CredentialView {
    fn from(r: &CredentialRecord) -> Self {
        let (storage, vault_ref) = match &r.material {
            CredentialMaterial::VaultRef { reference } => ("vault_ref", Some(reference.clone())),
            CredentialMaterial::Envelope { .. } => ("encrypted", None),
            CredentialMaterial::Plaintext { .. } => ("plaintext", None),
        };
        Self {
            id: r.id.clone(),
            name: r.name.clone(),
            provider: r.provider.clone(),
            kind: r.kind.clone(),
            status: r.status,
            tenant_id: r.tenant_id.clone(),
            storage,
            vault_ref,
            created_at: r.created_at,
            updated_at: r.updated_at,
            source: r.source,
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

fn store_key(plane: &KeyPlane, rec: KeyRecord) -> Result<(), String> {
    let store = plane.cache().store().clone();
    block_on_keystore(async move { store.put_key(rec).await }).map_err(|e| format!("{e:#}"))
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
    block_on_keystore(async move { cache.invalidate(&owned).await });
}

fn parse_rfc3339(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&Utc))
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
fn audit_mutation(op: &str, kind: &str, id: &str) {
    sbproxy_observe::KeyAuditEntry::new(op, kind, id).emit();
}

fn parse_body<T: for<'de> Deserialize<'de> + Default>(body: Option<&str>) -> Result<T, Resp> {
    match body {
        None | Some("") => Ok(T::default()),
        Some(b) => {
            serde_json::from_str(b).map_err(|e| bad_request(&format!("invalid JSON body: {e}")))
        }
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
    use sbproxy_keystore::crypto::KeyCrypto;
    use sbproxy_keystore::{KeyStore, MemoryKeyStore, TtlCache, TtlCacheConfig};

    fn install_test_plane() {
        let crypto = KeyCrypto::new(b"pepper".to_vec(), b"master".to_vec());
        let store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
        let cache = Arc::new(TtlCache::new(store, TtlCacheConfig::default()));
        let plane = Arc::new(crate::key_plane::KeyPlane::from_parts(
            crypto, cache, false, false, None,
        ));
        crate::key_plane::install_key_plane(plane);
    }

    fn parse(resp: &Resp) -> serde_json::Value {
        serde_json::from_str(&resp.2).unwrap()
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
        assert!(token.starts_with("sk-"));
        let key_id = v["key"]["key_id"].as_str().unwrap().to_string();
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
                Some(r#"{"max_requests_per_minute":5}"#)
            )
            .unwrap()
            .0,
            200
        );

        // Revoke -> status revoked.
        let resp = dispatch("POST", &format!("/admin/keys/{key_id}/revoke"), None).unwrap();
        assert_eq!(resp.0, 200);
        assert_eq!(parse(&resp)["key"]["status"], "revoked");

        // Unblock -> active, then rotate -> new token + grace window open.
        assert_eq!(
            dispatch("POST", &format!("/admin/keys/{key_id}/unblock"), None)
                .unwrap()
                .0,
            200
        );
        let resp = dispatch(
            "POST",
            &format!("/admin/keys/{key_id}/rotate"),
            Some(r#"{"grace_secs":120}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 200);
        let v = parse(&resp);
        assert!(v["token"]
            .as_str()
            .unwrap()
            .starts_with(&format!("sk-{key_id}-")));
        assert_eq!(v["key"]["rotation_pending"], true);

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
}

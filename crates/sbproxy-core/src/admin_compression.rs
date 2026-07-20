//! Admin routes for externally stored AI compression session state.

use crate::admin::AdminPrincipal;
use base64::Engine as _;
use sbproxy_ai::compression::{
    CompressionBackend, CompressionConsistency, CompressionRecordId, CompressionRecordMetadata,
    CompressionSessionRecord, CompressionSessionStore, ListPage, ListRequest, PurgePage,
    PurgeRequest, RecordKind, StoreError,
};
use sbproxy_config::types::AdminRole;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::str::FromStr as _;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const SESSIONS_PATH: &str = "/admin/compression/sessions";
const PURGE_PATH: &str = "/admin/compression/sessions/purge";
const DEFAULT_PAGE_SIZE: u16 = 100;
const MAX_PAGE_SIZE: u16 = 500;
const MAX_CURSOR_BYTES: usize = 16 * 1024;
const PURGE_CONFIRMATION: &str = "purge-compression-sessions";

/// Content-free audit event for one summary-content inspection attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompressionAuditEvent {
    /// Authenticated operator name, or `None` for an unauthenticated attempt.
    pub operator: Option<String>,
    /// Stable role label, including `unauthenticated`.
    pub role: String,
    /// Valid opaque record ID, if the route supplied one.
    pub record_id: Option<String>,
    /// Tenant learned from stored metadata after authorization.
    pub tenant_id: Option<String>,
    /// Origin learned from stored metadata after authorization.
    pub origin: Option<String>,
    /// Stable operation label.
    pub action: String,
    /// Closed attempt outcome.
    pub outcome: String,
}

/// A compression-content audit event could not be durably recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("compression audit unavailable")]
pub struct CompressionAuditError;

/// Fallible sink used to record content inspection before content is returned.
pub trait CompressionAuditSink: Send + Sync {
    /// Persist or forward one content-free inspection event.
    fn record(&self, event: &CompressionAuditEvent) -> Result<(), CompressionAuditError>;
}

/// Default structured tracing sink for compression-content audit events.
#[derive(Debug, Default)]
pub struct TracingCompressionAuditSink;

impl CompressionAuditSink for TracingCompressionAuditSink {
    fn record(&self, event: &CompressionAuditEvent) -> Result<(), CompressionAuditError> {
        tracing::info!(
            target: "sbproxy::admin::audit",
            operator = event.operator.as_deref().unwrap_or("unauthenticated"),
            role = %event.role,
            record_id = event.record_id.as_deref().unwrap_or("invalid"),
            tenant_id = event.tenant_id.as_deref().unwrap_or("unknown"),
            origin = event.origin.as_deref().unwrap_or("unknown"),
            action = %event.action,
            outcome = %event.outcome,
            "compression content inspection"
        );
        Ok(())
    }
}

#[derive(Clone)]
struct AdminStore {
    backend: CompressionBackend,
    store: Arc<dyn CompressionSessionStore>,
}

#[derive(Debug, Clone)]
struct OriginPolicy {
    origin: String,
    backend: CompressionBackend,
    allow_content: bool,
}

/// Immutable admin view of the state adapters and current origin policies.
#[derive(Clone, Default)]
pub(crate) struct CompressionAdminRegistry {
    stores: Vec<AdminStore>,
    origins: Vec<OriginPolicy>,
}

impl CompressionAdminRegistry {
    pub(crate) fn from_current_pipeline() -> Self {
        let pipeline = crate::reload::current_pipeline();
        Self::from_pipeline(&pipeline)
    }

    fn from_pipeline(pipeline: &crate::pipeline::CompiledPipeline) -> Self {
        let mut stores = Vec::new();
        let mut origins = Vec::new();
        for (index, origin) in pipeline.config.origins.iter().enumerate() {
            let Some(runtime_set) = pipeline.compression_runtimes.get_set(index) else {
                continue;
            };
            for runtime in runtime_set.runtimes() {
                let Some(store) = runtime.admin_store() else {
                    continue;
                };
                let backend = store.backend();
                if !stores
                    .iter()
                    .any(|existing: &AdminStore| existing.backend == backend)
                {
                    stores.push(AdminStore {
                        backend,
                        store: store.clone(),
                    });
                }
                let normalized_origin = normalize_origin(origin.hostname.as_str());
                if !origins.iter().any(|existing: &OriginPolicy| {
                    existing.origin == normalized_origin && existing.backend == backend
                }) {
                    origins.push(OriginPolicy {
                        origin: normalized_origin,
                        backend,
                        allow_content: runtime.allows_admin_content_inspection(),
                    });
                }
            }
        }
        if !stores
            .iter()
            .any(|entry| entry.backend == CompressionBackend::Redis)
        {
            if let Some(store) = crate::compression_runtime::redis_admin_store(
                &pipeline.config.server,
                pipeline.config.l2_store.as_deref(),
            ) {
                stores.push(AdminStore {
                    backend: CompressionBackend::Redis,
                    store,
                });
            }
        }
        // Mirror of the Redis fallback: replicated session state written
        // under an earlier configuration stays manageable after every
        // mesh-backed pipeline is removed, as long as the replicated
        // substrate itself is still running.
        if !stores
            .iter()
            .any(|entry| entry.backend == CompressionBackend::Mesh)
        {
            if let Some(store) = crate::compression_runtime::mesh_admin_store() {
                stores.push(AdminStore {
                    backend: CompressionBackend::Mesh,
                    store,
                });
            }
        }
        Self::finish(stores, origins)
    }

    #[cfg(test)]
    fn from_parts<S>(stores: Vec<Arc<S>>, origins: Vec<(String, CompressionBackend, bool)>) -> Self
    where
        S: CompressionSessionStore + 'static,
    {
        let stores = stores
            .into_iter()
            .map(|store| AdminStore {
                backend: store.backend(),
                store,
            })
            .collect();
        let origins = origins
            .into_iter()
            .map(|(origin, backend, allow_content)| OriginPolicy {
                origin: normalize_origin(&origin),
                backend,
                allow_content,
            })
            .collect();
        Self::finish(stores, origins)
    }

    fn finish(mut stores: Vec<AdminStore>, origins: Vec<OriginPolicy>) -> Self {
        stores.sort_by_key(|entry| backend_rank(entry.backend));
        stores.dedup_by_key(|entry| entry.backend);
        Self { stores, origins }
    }

    fn selected_stores(&self, backend: Option<CompressionBackend>) -> Vec<&AdminStore> {
        self.stores
            .iter()
            .filter(|entry| backend.is_none_or(|wanted| entry.backend == wanted))
            .collect()
    }

    async fn load(
        &self,
        id: &CompressionRecordId,
    ) -> Result<
        Option<(
            CompressionSessionRecord,
            CompressionBackend,
            CompressionConsistency,
        )>,
        StoreError,
    > {
        for entry in &self.stores {
            if let Some(record) = entry.store.load(id).await? {
                return Ok(Some((record, entry.backend, entry.store.consistency())));
            }
        }
        Ok(None)
    }

    fn allows_content(&self, origin: &str, backend: CompressionBackend) -> bool {
        let origin = normalize_origin(origin);
        self.origins.iter().any(|policy| {
            policy.origin == origin && policy.backend == backend && policy.allow_content
        })
    }
}

/// Async admin response with optional route-specific security headers.
pub(crate) struct AdminCompressionResponse {
    pub(crate) status: u16,
    pub(crate) content_type: &'static str,
    pub(crate) body: String,
    pub(crate) headers: Vec<(String, String)>,
}

/// Dispatch a compression admin route against the current pipeline snapshot.
pub(crate) async fn dispatch(
    method: &str,
    path: &str,
    body: Option<&str>,
    principal: Option<&AdminPrincipal>,
    csrf_header: Option<&str>,
    audit: &dyn CompressionAuditSink,
) -> Option<AdminCompressionResponse> {
    let registry = CompressionAdminRegistry::from_current_pipeline();
    dispatch_with_registry(method, path, body, principal, csrf_header, &registry, audit).await
}

async fn dispatch_with_registry(
    method: &str,
    path: &str,
    body: Option<&str>,
    principal: Option<&AdminPrincipal>,
    csrf_header: Option<&str>,
    registry: &CompressionAdminRegistry,
    audit: &dyn CompressionAuditSink,
) -> Option<AdminCompressionResponse> {
    let path_only = path.split('?').next().unwrap_or(path);
    if path_only != SESSIONS_PATH && !path_only.starts_with(&format!("{SESSIONS_PATH}/")) {
        return None;
    }

    if path_only == SESSIONS_PATH {
        return Some(if method.eq_ignore_ascii_case("GET") {
            match require_reader(principal) {
                Ok(()) => list_records(path, registry).await,
                Err(response) => response,
            }
        } else {
            method_not_allowed()
        });
    }

    if path_only == PURGE_PATH {
        return Some(if method.eq_ignore_ascii_case("POST") {
            match require_admin(principal, csrf_header) {
                Ok(()) => purge_records(body, registry).await,
                Err(response) => response,
            }
        } else {
            method_not_allowed()
        });
    }

    let rest = path_only
        .strip_prefix(&format!("{SESSIONS_PATH}/"))
        .unwrap_or_default();
    if let Some(id_text) = rest.strip_suffix("/content") {
        return Some(inspect_content(method, id_text, principal, registry, audit).await);
    }
    if rest.contains('/') {
        return Some(not_found());
    }
    let id = match CompressionRecordId::from_str(rest) {
        Ok(id) => id,
        Err(_) => return Some(bad_request("invalid record id")),
    };
    Some(match method.to_ascii_uppercase().as_str() {
        "GET" => match require_reader(principal) {
            Ok(()) => get_record(id, registry).await,
            Err(response) => response,
        },
        "DELETE" => match require_admin(principal, csrf_header) {
            Ok(()) => delete_record(id, registry).await,
            Err(response) => response,
        },
        _ => method_not_allowed(),
    })
}

async fn list_records(path: &str, registry: &CompressionAdminRegistry) -> AdminCompressionResponse {
    let query = match parse_query(path) {
        Ok(query) => query,
        Err(response) => return response,
    };
    const ALLOWED: [&str; 6] = ["tenant", "origin", "backend", "conflict", "cursor", "limit"];
    if query.keys().any(|key| !ALLOWED.contains(&key.as_str())) {
        return bad_request("unknown query parameter");
    }
    let backend = match query.get("backend").map(|value| parse_backend(value)) {
        Some(Ok(backend)) => Some(backend),
        Some(Err(response)) => return response,
        None => None,
    };
    let conflict = match query.get("conflict").map(|value| parse_bool(value)) {
        Some(Ok(value)) => Some(value),
        Some(Err(response)) => return response,
        None => None,
    };
    let limit = match parse_limit(query.get("limit")) {
        Ok(limit) => limit,
        Err(response) => return response,
    };
    let origin = query.get("origin").map(|value| normalize_origin(value));
    if origin.as_deref() == Some("") {
        return bad_request("origin cannot be empty");
    }
    let tenant_id = query.get("tenant").cloned();
    if tenant_id
        .as_deref()
        .is_some_and(|tenant| tenant.trim().is_empty())
    {
        return bad_request("tenant cannot be empty");
    }
    let request = ListRequest {
        tenant_id,
        origin,
        expired: None,
        expiration_cutoff_unix_ms: 0,
        conflict,
        cursor: None,
        limit,
    };
    match list_across_stores(
        registry,
        backend,
        query.get("cursor").map(String::as_str),
        request,
    )
    .await
    {
        Ok(page) => json_response(
            200,
            serde_json::json!({
                "records": page.records,
                "next_cursor": page.next_cursor,
            }),
        ),
        Err(error) => store_error_response(error),
    }
}

async fn list_across_stores(
    registry: &CompressionAdminRegistry,
    backend: Option<CompressionBackend>,
    cursor: Option<&str>,
    mut request: ListRequest,
) -> Result<ListPage, StoreError> {
    let stores = registry.selected_stores(backend);
    let decoded = cursor.map(decode_cursor).transpose()?;
    let start = match decoded.as_ref() {
        Some(cursor) => stores
            .iter()
            .position(|entry| entry.backend == cursor.backend)
            .ok_or(StoreError::InvalidCursor)?,
        None => 0,
    };
    let mut records = Vec::with_capacity(usize::from(request.limit));
    for (index, entry) in stores.iter().enumerate().skip(start) {
        let remaining = usize::from(request.limit).saturating_sub(records.len());
        if remaining == 0 {
            return Ok(ListPage {
                records,
                next_cursor: Some(encode_cursor(&AdminCursor {
                    backend: entry.backend,
                    store_cursor: None,
                })?),
            });
        }
        request.limit = u16::try_from(remaining).map_err(|_| StoreError::InvalidRequest)?;
        request.cursor = if index == start {
            decoded
                .as_ref()
                .and_then(|cursor| cursor.store_cursor.clone())
        } else {
            None
        };
        let page = entry.store.list(&request).await?;
        if page.records.len() > remaining {
            return Err(StoreError::Unavailable);
        }
        records.extend(page.records);
        if let Some(store_cursor) = page.next_cursor {
            return Ok(ListPage {
                records,
                next_cursor: Some(encode_cursor(&AdminCursor {
                    backend: entry.backend,
                    store_cursor: Some(store_cursor),
                })?),
            });
        }
    }
    Ok(ListPage {
        records,
        next_cursor: None,
    })
}

async fn get_record(
    id: CompressionRecordId,
    registry: &CompressionAdminRegistry,
) -> AdminCompressionResponse {
    match registry.load(&id).await {
        Ok(Some((record, backend, consistency))) => json_response(
            200,
            serde_json::json!({
                "record": CompressionRecordMetadata::from_record(
                    id,
                    backend,
                    consistency,
                    &record,
                ),
            }),
        ),
        Ok(None) => not_found(),
        Err(error) => store_error_response(error),
    }
}

async fn inspect_content(
    method: &str,
    id_text: &str,
    principal: Option<&AdminPrincipal>,
    registry: &CompressionAdminRegistry,
    audit: &dyn CompressionAuditSink,
) -> AdminCompressionResponse {
    let id = CompressionRecordId::from_str(id_text).ok();
    if !method.eq_ignore_ascii_case("GET") {
        return audit_then(
            audit,
            content_event(principal, id, None, "method_not_allowed"),
            method_not_allowed(),
        );
    }
    let Some(principal) = principal else {
        return audit_then(
            audit,
            content_event(None, id, None, "unauthenticated"),
            unauthorized(),
        );
    };
    if principal.role != AdminRole::Admin {
        return audit_then(
            audit,
            content_event(Some(principal), id, None, "forbidden_role"),
            forbidden("admin role required"),
        );
    }
    let Some(id) = id else {
        return audit_then(
            audit,
            content_event(Some(principal), None, None, "invalid_record_id"),
            bad_request("invalid record id"),
        );
    };

    let (record, backend, consistency) = match registry.load(&id).await {
        Ok(Some(found)) => found,
        Ok(None) => {
            return audit_then(
                audit,
                content_event(Some(principal), Some(id), None, "missing"),
                not_found(),
            )
        }
        Err(_) => {
            return audit_then(
                audit,
                content_event(Some(principal), Some(id), None, "backend_error"),
                service_unavailable("compression state unavailable"),
            )
        }
    };
    let event_record = Some(&record);
    if record.kind != RecordKind::Live {
        return audit_then(
            audit,
            content_event(Some(principal), Some(id), event_record, "missing"),
            not_found(),
        );
    }
    if record.expires_at_unix_ms <= unix_time_ms() {
        return audit_then(
            audit,
            content_event(Some(principal), Some(id), event_record, "expired"),
            not_found(),
        );
    }
    if !registry.allows_content(&record.origin, backend) {
        return audit_then(
            audit,
            content_event(Some(principal), Some(id), event_record, "disabled"),
            forbidden("content inspection is disabled"),
        );
    }

    let response = AdminCompressionResponse {
        status: 200,
        content_type: "application/json",
        body: serde_json::json!({
            "record": CompressionRecordMetadata::from_record(id, backend, consistency, &record),
            "summary": record.summary,
        })
        .to_string(),
        headers: vec![
            ("Cache-Control".to_string(), "no-store".to_string()),
            ("Pragma".to_string(), "no-cache".to_string()),
            ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
        ],
    };
    audit_then(
        audit,
        content_event(Some(principal), Some(id), event_record, "success"),
        response,
    )
}

fn audit_then(
    audit: &dyn CompressionAuditSink,
    event: CompressionAuditEvent,
    response: AdminCompressionResponse,
) -> AdminCompressionResponse {
    if audit.record(&event).is_err() {
        service_unavailable("audit unavailable")
    } else {
        response
    }
}

fn content_event(
    principal: Option<&AdminPrincipal>,
    id: Option<CompressionRecordId>,
    record: Option<&CompressionSessionRecord>,
    outcome: &str,
) -> CompressionAuditEvent {
    CompressionAuditEvent {
        operator: principal.map(|principal| principal.username.clone()),
        role: principal.map_or_else(
            || "unauthenticated".to_string(),
            |principal| role_label(principal.role).to_string(),
        ),
        record_id: id.map(|id| id.to_string()),
        tenant_id: record.map(|record| record.tenant_id.clone()),
        origin: record.map(|record| record.origin.clone()),
        action: "inspect_compression_content".to_string(),
        outcome: outcome.to_string(),
    }
}

async fn delete_record(
    id: CompressionRecordId,
    registry: &CompressionAdminRegistry,
) -> AdminCompressionResponse {
    let mut deleted = false;
    let mut versions = BTreeMap::new();
    for entry in &registry.stores {
        match entry.store.delete(&id).await {
            Ok(result) => {
                deleted |= result.deleted;
                if let Some(version) = result.logical_version {
                    versions.insert(backend_label(entry.backend), version);
                }
            }
            Err(error) => return store_error_response(error),
        }
    }
    json_response(
        200,
        serde_json::json!({
            "deleted": deleted,
            "logical_versions": versions,
        }),
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PurgeBody {
    tenant: Option<String>,
    origin: Option<String>,
    conflict: Option<bool>,
    backend: Option<String>,
    cursor: Option<String>,
    limit: Option<u64>,
    #[serde(default)]
    all: bool,
    confirmation: Option<String>,
}

async fn purge_records(
    body: Option<&str>,
    registry: &CompressionAdminRegistry,
) -> AdminCompressionResponse {
    let body = match body.and_then(|body| serde_json::from_str::<PurgeBody>(body).ok()) {
        Some(body) => body,
        None => return bad_request("invalid purge request"),
    };
    let has_destructive_scope = body.tenant.is_some() || body.origin.is_some();
    let has_scoped_filters = has_destructive_scope || body.conflict.is_some();
    if !has_destructive_scope && !body.all {
        return bad_request("purge requires a tenant or origin scope");
    }
    if body.all && body.confirmation.as_deref() != Some(PURGE_CONFIRMATION) {
        return bad_request("all-record purge confirmation is invalid");
    }
    if body.all && has_scoped_filters {
        return bad_request("all-record purge cannot include scoped filters");
    }
    if body
        .tenant
        .as_deref()
        .is_some_and(|tenant| tenant.trim().is_empty())
    {
        return bad_request("tenant cannot be empty");
    }
    let origin = body.origin.map(|origin| normalize_origin(&origin));
    if origin.as_deref() == Some("") {
        return bad_request("origin cannot be empty");
    }
    let backend = match body.backend.as_deref().map(parse_backend) {
        Some(Ok(backend)) => Some(backend),
        Some(Err(response)) => return response,
        None => None,
    };
    let limit = match body.limit {
        Some(0) => return bad_request("limit must be greater than zero"),
        Some(value) => u16::try_from(value.min(u64::from(MAX_PAGE_SIZE))).unwrap_or(MAX_PAGE_SIZE),
        None => DEFAULT_PAGE_SIZE,
    };
    let request = PurgeRequest {
        tenant_id: body.tenant,
        origin,
        expired_before_unix_ms: None,
        conflict: body.conflict,
        cursor: None,
        limit,
    };
    match purge_across_stores(registry, backend, body.cursor.as_deref(), request).await {
        Ok(page) => json_response(
            200,
            serde_json::json!({
                "deleted": page.deleted,
                "next_cursor": page.next_cursor,
            }),
        ),
        Err(error) => store_error_response(error),
    }
}

async fn purge_across_stores(
    registry: &CompressionAdminRegistry,
    backend: Option<CompressionBackend>,
    cursor: Option<&str>,
    mut request: PurgeRequest,
) -> Result<PurgePage, StoreError> {
    let stores = registry.selected_stores(backend);
    let decoded = cursor.map(decode_cursor).transpose()?;
    let start = match decoded.as_ref() {
        Some(cursor) => stores
            .iter()
            .position(|entry| entry.backend == cursor.backend)
            .ok_or(StoreError::InvalidCursor)?,
        None => 0,
    };
    let Some(entry) = stores.get(start) else {
        return Ok(PurgePage {
            deleted: 0,
            next_cursor: None,
        });
    };
    request.cursor = decoded.and_then(|cursor| cursor.store_cursor);
    let page = entry.store.purge(&request).await?;
    let next_cursor = match page.next_cursor {
        Some(store_cursor) => Some(encode_cursor(&AdminCursor {
            backend: entry.backend,
            store_cursor: Some(store_cursor),
        })?),
        None => stores
            .get(start + 1)
            .map(|next| {
                encode_cursor(&AdminCursor {
                    backend: next.backend,
                    store_cursor: None,
                })
            })
            .transpose()?,
    };
    Ok(PurgePage {
        deleted: page.deleted,
        next_cursor,
    })
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminCursor {
    backend: CompressionBackend,
    store_cursor: Option<String>,
}

fn encode_cursor(cursor: &AdminCursor) -> Result<String, StoreError> {
    let bytes = serde_json::to_vec(cursor).map_err(|_| StoreError::InvalidCursor)?;
    if bytes.len() > MAX_CURSOR_BYTES {
        return Err(StoreError::InvalidCursor);
    }
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_cursor(cursor: &str) -> Result<AdminCursor, StoreError> {
    if cursor.len() > MAX_CURSOR_BYTES.saturating_mul(2) {
        return Err(StoreError::InvalidCursor);
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| StoreError::InvalidCursor)?;
    if bytes.len() > MAX_CURSOR_BYTES {
        return Err(StoreError::InvalidCursor);
    }
    serde_json::from_slice(&bytes).map_err(|_| StoreError::InvalidCursor)
}

fn parse_query(path: &str) -> Result<BTreeMap<String, String>, AdminCompressionResponse> {
    let mut values = BTreeMap::new();
    let Some(query) = path.split_once('?').map(|(_, query)| query) else {
        return Ok(values);
    };
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if values
            .insert(key.into_owned(), value.into_owned())
            .is_some()
        {
            return Err(bad_request("duplicate query parameter"));
        }
    }
    Ok(values)
}

fn parse_limit(value: Option<&String>) -> Result<u16, AdminCompressionResponse> {
    match value {
        None => Ok(DEFAULT_PAGE_SIZE),
        Some(value) => match value.parse::<u64>() {
            Ok(0) | Err(_) => Err(bad_request("limit must be a positive integer")),
            Ok(value) => {
                Ok(u16::try_from(value.min(u64::from(MAX_PAGE_SIZE))).unwrap_or(MAX_PAGE_SIZE))
            }
        },
    }
}

fn parse_backend(value: &str) -> Result<CompressionBackend, AdminCompressionResponse> {
    match value {
        "redis" => Ok(CompressionBackend::Redis),
        "mesh" => Ok(CompressionBackend::Mesh),
        _ => Err(bad_request("invalid backend")),
    }
}

fn parse_bool(value: &str) -> Result<bool, AdminCompressionResponse> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(bad_request("invalid boolean filter")),
    }
}

fn normalize_origin(origin: &str) -> String {
    origin.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn backend_rank(backend: CompressionBackend) -> u8 {
    match backend {
        CompressionBackend::Redis => 0,
        CompressionBackend::Mesh => 1,
    }
}

fn backend_label(backend: CompressionBackend) -> &'static str {
    match backend {
        CompressionBackend::Redis => "redis",
        CompressionBackend::Mesh => "mesh",
    }
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn require_reader(principal: Option<&AdminPrincipal>) -> Result<(), AdminCompressionResponse> {
    principal.map(|_| ()).ok_or_else(unauthorized)
}

fn require_admin(
    principal: Option<&AdminPrincipal>,
    csrf_header: Option<&str>,
) -> Result<(), AdminCompressionResponse> {
    let principal = principal.ok_or_else(unauthorized)?;
    if principal.role != AdminRole::Admin {
        return Err(forbidden("admin role required"));
    }
    if principal.via_session {
        let valid = match (csrf_header, principal.csrf.as_deref()) {
            (Some(provided), Some(expected)) => {
                constant_time_eq(provided.as_bytes(), expected.as_bytes())
            }
            _ => false,
        };
        if !valid {
            return Err(forbidden("CSRF token missing or invalid"));
        }
    }
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

fn role_label(role: AdminRole) -> &'static str {
    match role {
        AdminRole::Admin => "admin",
        AdminRole::ReadOnly => "read_only",
    }
}

fn store_error_response(error: StoreError) -> AdminCompressionResponse {
    match error {
        StoreError::InvalidCursor | StoreError::InvalidRequest => {
            bad_request("invalid compression state request")
        }
        StoreError::Unavailable | StoreError::CorruptRecord | StoreError::UnsupportedSchema => {
            service_unavailable("compression state unavailable")
        }
    }
}

fn json_response(status: u16, value: serde_json::Value) -> AdminCompressionResponse {
    AdminCompressionResponse {
        status,
        content_type: "application/json",
        body: value.to_string(),
        headers: Vec::new(),
    }
}

fn bad_request(error: &str) -> AdminCompressionResponse {
    json_response(400, serde_json::json!({"error": error}))
}

fn unauthorized() -> AdminCompressionResponse {
    json_response(401, serde_json::json!({"error": "Unauthorized"}))
}

fn forbidden(error: &str) -> AdminCompressionResponse {
    json_response(403, serde_json::json!({"error": error}))
}

fn not_found() -> AdminCompressionResponse {
    json_response(404, serde_json::json!({"error": "not found"}))
}

fn method_not_allowed() -> AdminCompressionResponse {
    json_response(405, serde_json::json!({"error": "method not allowed"}))
}

fn service_unavailable(error: &str) -> AdminCompressionResponse {
    json_response(503, serde_json::json!({"error": error}))
}

#[cfg(test)]
mod tests {
    use super::{
        dispatch_with_registry, CompressionAdminRegistry, CompressionAuditError,
        CompressionAuditEvent, CompressionAuditSink,
    };
    use crate::admin::AdminPrincipal;
    use async_trait::async_trait;
    use sbproxy_ai::compression::{
        CommitError, CompressionBackend, CompressionConsistency, CompressionRecordId,
        CompressionRecordMetadata, CompressionSessionRecord, CompressionSessionStore, DeleteResult,
        ListPage, ListRequest, MessageDigest, PurgePage, PurgeRequest, RecordKind, StoreError,
        UpdatePermit, RECORD_SCHEMA_VERSION,
    };
    use sbproxy_config::types::AdminRole;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[derive(Default)]
    struct TestStore {
        records: Mutex<HashMap<CompressionRecordId, CompressionSessionRecord>>,
        load_calls: Mutex<u64>,
        list_requests: Mutex<Vec<ListRequest>>,
        list_next_cursor: Mutex<Option<String>>,
        purge_requests: Mutex<Vec<PurgeRequest>>,
        deleted: Mutex<Vec<CompressionRecordId>>,
        error: Mutex<Option<StoreError>>,
    }

    #[async_trait]
    impl CompressionSessionStore for TestStore {
        fn backend(&self) -> CompressionBackend {
            CompressionBackend::Redis
        }

        fn consistency(&self) -> CompressionConsistency {
            CompressionConsistency::Serialized
        }

        async fn load(
            &self,
            id: &CompressionRecordId,
        ) -> Result<Option<CompressionSessionRecord>, StoreError> {
            *self.load_calls.lock().unwrap() += 1;
            if let Some(error) = *self.error.lock().unwrap() {
                return Err(error);
            }
            Ok(self.records.lock().unwrap().get(id).cloned())
        }

        async fn acquire_update(
            &self,
            _id: &CompressionRecordId,
            _lease_ttl: Duration,
        ) -> Result<Option<UpdatePermit>, StoreError> {
            unreachable!("admin tests never acquire update permits")
        }

        async fn commit(
            &self,
            _permit: &UpdatePermit,
            _expected_logical_version: Option<u64>,
            _record: &CompressionSessionRecord,
            _ttl: Duration,
        ) -> Result<(), CommitError> {
            unreachable!("admin tests never commit records")
        }

        async fn release(&self, _permit: UpdatePermit) -> Result<(), StoreError> {
            unreachable!("admin tests never release update permits")
        }

        async fn list(&self, request: &ListRequest) -> Result<ListPage, StoreError> {
            self.list_requests.lock().unwrap().push(request.clone());
            if let Some(error) = *self.error.lock().unwrap() {
                return Err(error);
            }
            let records = self
                .records
                .lock()
                .unwrap()
                .iter()
                .map(|(id, record)| {
                    CompressionRecordMetadata::from_record(
                        *id,
                        self.backend(),
                        self.consistency(),
                        record,
                    )
                })
                .collect();
            Ok(ListPage {
                records,
                next_cursor: self.list_next_cursor.lock().unwrap().clone(),
            })
        }

        async fn delete(&self, id: &CompressionRecordId) -> Result<DeleteResult, StoreError> {
            if let Some(error) = *self.error.lock().unwrap() {
                return Err(error);
            }
            self.deleted.lock().unwrap().push(*id);
            Ok(DeleteResult {
                deleted: self.records.lock().unwrap().remove(id).is_some(),
                logical_version: None,
            })
        }

        async fn purge(&self, request: &PurgeRequest) -> Result<PurgePage, StoreError> {
            self.purge_requests.lock().unwrap().push(request.clone());
            if let Some(error) = *self.error.lock().unwrap() {
                return Err(error);
            }
            Ok(PurgePage {
                deleted: 2,
                next_cursor: None,
            })
        }
    }

    #[derive(Default)]
    struct RecordingAudit {
        events: Mutex<Vec<CompressionAuditEvent>>,
        fail: Mutex<bool>,
    }

    impl CompressionAuditSink for RecordingAudit {
        fn record(&self, event: &CompressionAuditEvent) -> Result<(), CompressionAuditError> {
            self.events.lock().unwrap().push(event.clone());
            if *self.fail.lock().unwrap() {
                Err(CompressionAuditError)
            } else {
                Ok(())
            }
        }
    }

    fn principal(role: AdminRole, via_session: bool) -> AdminPrincipal {
        AdminPrincipal {
            username: "operator-a".to_string(),
            role,
            via_session,
            csrf: via_session.then(|| "csrf-a".to_string()),
        }
    }

    fn id(seed: u8) -> CompressionRecordId {
        CompressionRecordId::derive("tenant-a", "api.example.com", [seed; 16])
    }

    fn record(summary: &str, expires_at_unix_ms: u64) -> CompressionSessionRecord {
        CompressionSessionRecord {
            schema_version: RECORD_SCHEMA_VERSION,
            logical_version: 4,
            tenant_id: "tenant-a".to_string(),
            origin: "api.example.com".to_string(),
            summary: summary.to_string(),
            protected_prefix_count: 1,
            protected_prefix_digest: MessageDigest::for_messages(&[json!({
                "role": "system",
                "content": "protected"
            })]),
            covered_history_count: 6,
            covered_history_digest: MessageDigest::for_messages(&[json!({
                "role": "user",
                "content": "history"
            })]),
            covered_input_tokens: 300,
            summary_tokens: 40,
            summarizer_provider: "provider-a".to_string(),
            summarizer_model: "summary-model".to_string(),
            writer_node: "node-a".to_string(),
            parent_logical_version: Some(3),
            conflict_detected: false,
            created_at_unix_ms: 1_000,
            updated_at_unix_ms: 2_000,
            expires_at_unix_ms,
            kind: RecordKind::Live,
        }
    }

    fn registry(store: Arc<TestStore>, allow_content: bool) -> CompressionAdminRegistry {
        CompressionAdminRegistry::from_parts(
            vec![store],
            vec![(
                "api.example.com".to_string(),
                CompressionBackend::Redis,
                allow_content,
            )],
        )
    }

    #[test]
    fn disabled_summary_policy_keeps_the_configured_redis_admin_store() {
        let mut pipeline = crate::pipeline::CompiledPipeline::default();
        let l2_config = sbproxy_config::L2CacheConfig {
            driver: "redis".to_string(),
            params: sbproxy_config::L2CacheParams {
                dsn: "redis://redis.internal:6379/0".to_string(),
                ..sbproxy_config::L2CacheParams::default()
            },
        };
        pipeline.config.l2_store =
            Some(sbproxy_config::build_l2_store(&l2_config).expect("compile general L2 store"));
        pipeline.config.server.l2_cache = Some(l2_config);

        let registry = CompressionAdminRegistry::from_pipeline(&pipeline);
        assert_eq!(
            registry
                .selected_stores(Some(CompressionBackend::Redis))
                .len(),
            1,
            "external records must remain manageable after summary_buffer is disabled"
        );
        assert!(registry.origins.is_empty());
    }

    #[tokio::test]
    async fn metadata_routes_are_bounded_filterable_content_free_and_fail_closed() {
        let store = Arc::new(TestStore::default());
        store
            .records
            .lock()
            .unwrap()
            .insert(id(1), record("sensitive summary", u64::MAX));
        let registry = registry(store.clone(), false);
        let audit = RecordingAudit::default();
        let readonly = principal(AdminRole::ReadOnly, false);

        let response = dispatch_with_registry(
            "GET",
            "/admin/compression/sessions?tenant=tenant-a&origin=API.Example.COM.&backend=redis&conflict=false&limit=999",
            None,
            Some(&readonly),
            None,
            &registry,
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(response.status, 200);
        assert!(!response.body.contains("sensitive summary"));
        assert!(!response.body.contains("session_id"));
        assert!(response.body.contains("\"backend\":\"redis\""));
        let request = store.list_requests.lock().unwrap().pop().unwrap();
        assert_eq!(request.tenant_id.as_deref(), Some("tenant-a"));
        assert_eq!(request.origin.as_deref(), Some("api.example.com"));
        assert_eq!(request.expired, None);
        assert_eq!(request.conflict, Some(false));
        assert_eq!(request.limit, 500);

        let detail = dispatch_with_registry(
            "GET",
            &format!("/admin/compression/sessions/{}", id(1)),
            None,
            Some(&readonly),
            None,
            &registry,
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(detail.status, 200);
        assert!(detail.body.contains("\"schema_version\":1"));
        assert!(!detail.body.contains("sensitive summary"));

        let defaults = dispatch_with_registry(
            "GET",
            "/admin/compression/sessions",
            None,
            Some(&readonly),
            None,
            &registry,
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(defaults.status, 200);
        assert_eq!(
            store.list_requests.lock().unwrap().last().unwrap().limit,
            100
        );

        // The mesh backend is a valid filter; without a configured mesh
        // store the page is honestly empty rather than an error.
        let mesh_filter = dispatch_with_registry(
            "GET",
            "/admin/compression/sessions?backend=mesh",
            None,
            Some(&readonly),
            None,
            &registry,
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(mesh_filter.status, 200);
        assert!(mesh_filter.body.contains("\"records\":[]"));

        // The backend vocabulary stays closed.
        let unknown_backend = dispatch_with_registry(
            "GET",
            "/admin/compression/sessions?backend=tape",
            None,
            Some(&readonly),
            None,
            &registry,
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(unknown_backend.status, 400);

        let expired_filter = dispatch_with_registry(
            "GET",
            "/admin/compression/sessions?expired=true",
            None,
            Some(&readonly),
            None,
            &registry,
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(expired_filter.status, 400);

        *store.list_next_cursor.lock().unwrap() = Some("store-next".to_string());
        let first_page = dispatch_with_registry(
            "GET",
            "/admin/compression/sessions?limit=1",
            None,
            Some(&readonly),
            None,
            &registry,
            &audit,
        )
        .await
        .unwrap();
        let cursor = serde_json::from_str::<serde_json::Value>(&first_page.body).unwrap()
            ["next_cursor"]
            .as_str()
            .unwrap()
            .to_string();
        *store.list_next_cursor.lock().unwrap() = None;
        let second_page = dispatch_with_registry(
            "GET",
            &format!("/admin/compression/sessions?limit=1&cursor={cursor}"),
            None,
            Some(&readonly),
            None,
            &registry,
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(second_page.status, 200);
        assert_eq!(
            store
                .list_requests
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .cursor
                .as_deref(),
            Some("store-next")
        );

        *store.error.lock().unwrap() = Some(StoreError::Unavailable);
        let failed = dispatch_with_registry(
            "GET",
            "/admin/compression/sessions",
            None,
            Some(&readonly),
            None,
            &registry,
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(failed.status, 503);
        assert!(!failed.body.contains("records"));
    }

    #[tokio::test]
    async fn content_inspection_is_admin_opt_in_audit_first_and_non_cacheable() {
        let store = Arc::new(TestStore::default());
        let record_id = id(2);
        store
            .records
            .lock()
            .unwrap()
            .insert(record_id, record("sensitive summary", u64::MAX));
        let audit = RecordingAudit::default();
        let readonly = principal(AdminRole::ReadOnly, false);
        let admin = principal(AdminRole::Admin, false);

        let unauthenticated = dispatch_with_registry(
            "GET",
            &format!("/admin/compression/sessions/{record_id}/content"),
            None,
            None,
            None,
            &registry(store.clone(), true),
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(unauthenticated.status, 401);
        assert_eq!(*store.load_calls.lock().unwrap(), 0);

        let denied = dispatch_with_registry(
            "GET",
            &format!("/admin/compression/sessions/{record_id}/content"),
            None,
            Some(&readonly),
            None,
            &registry(store.clone(), true),
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(denied.status, 403);
        assert!(!denied.body.contains("sensitive summary"));
        assert_eq!(*store.load_calls.lock().unwrap(), 0);

        let disabled = dispatch_with_registry(
            "GET",
            &format!("/admin/compression/sessions/{record_id}/content"),
            None,
            Some(&admin),
            None,
            &registry(store.clone(), false),
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(disabled.status, 403);

        store.records.lock().unwrap().remove(&record_id);
        let missing = dispatch_with_registry(
            "GET",
            &format!("/admin/compression/sessions/{record_id}/content"),
            None,
            Some(&admin),
            None,
            &registry(store.clone(), true),
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(missing.status, 404);

        store
            .records
            .lock()
            .unwrap()
            .insert(record_id, record("sensitive summary", 1));
        let expired = dispatch_with_registry(
            "GET",
            &format!("/admin/compression/sessions/{record_id}/content"),
            None,
            Some(&admin),
            None,
            &registry(store.clone(), true),
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(expired.status, 404);

        *store.error.lock().unwrap() = Some(StoreError::Unavailable);
        let backend_failed = dispatch_with_registry(
            "GET",
            &format!("/admin/compression/sessions/{record_id}/content"),
            None,
            Some(&admin),
            None,
            &registry(store.clone(), true),
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(backend_failed.status, 503);
        *store.error.lock().unwrap() = None;
        store
            .records
            .lock()
            .unwrap()
            .insert(record_id, record("sensitive summary", u64::MAX));

        let success = dispatch_with_registry(
            "GET",
            &format!("/admin/compression/sessions/{record_id}/content"),
            None,
            Some(&admin),
            None,
            &registry(store.clone(), true),
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(success.status, 200);
        assert!(success.body.contains("sensitive summary"));
        assert!(success
            .headers
            .contains(&("Cache-Control".to_string(), "no-store".to_string())));
        assert!(success
            .headers
            .contains(&("Pragma".to_string(), "no-cache".to_string())));
        assert!(success
            .headers
            .contains(&("X-Content-Type-Options".to_string(), "nosniff".to_string())));

        *audit.fail.lock().unwrap() = true;
        let audit_failed = dispatch_with_registry(
            "GET",
            &format!("/admin/compression/sessions/{record_id}/content"),
            None,
            Some(&admin),
            None,
            &registry(store, true),
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(audit_failed.status, 503);
        assert!(!audit_failed.body.contains("sensitive summary"));
        assert_eq!(audit.events.lock().unwrap().len(), 8);
        let encoded = serde_json::to_string(&*audit.events.lock().unwrap()).unwrap();
        assert!(!encoded.contains("sensitive summary"));
        assert!(!encoded.contains("csrf-a"));
        for outcome in [
            "unauthenticated",
            "forbidden_role",
            "disabled",
            "missing",
            "expired",
            "backend_error",
            "success",
        ] {
            assert!(encoded.contains(outcome));
        }
    }

    #[tokio::test]
    async fn delete_and_purge_require_admin_csrf_and_explicit_bounded_scope() {
        let store = Arc::new(TestStore::default());
        let record_id = id(3);
        store
            .records
            .lock()
            .unwrap()
            .insert(record_id, record("summary", u64::MAX));
        let registry = registry(store.clone(), false);
        let audit = RecordingAudit::default();
        let readonly = principal(AdminRole::ReadOnly, false);
        let session_admin = principal(AdminRole::Admin, true);

        let forbidden = dispatch_with_registry(
            "DELETE",
            &format!("/admin/compression/sessions/{record_id}"),
            None,
            Some(&readonly),
            None,
            &registry,
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(forbidden.status, 403);

        let csrf_denied = dispatch_with_registry(
            "DELETE",
            &format!("/admin/compression/sessions/{record_id}"),
            None,
            Some(&session_admin),
            None,
            &registry,
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(csrf_denied.status, 403);

        let deleted = dispatch_with_registry(
            "DELETE",
            &format!("/admin/compression/sessions/{record_id}"),
            None,
            Some(&session_admin),
            Some("csrf-a"),
            &registry,
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(deleted.status, 200);
        assert!(deleted.body.contains("\"deleted\":true"));

        let idempotent = dispatch_with_registry(
            "DELETE",
            &format!("/admin/compression/sessions/{record_id}"),
            None,
            Some(&session_admin),
            Some("csrf-a"),
            &registry,
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(idempotent.status, 200);
        assert!(idempotent.body.contains("\"deleted\":false"));

        let unsafe_purge = dispatch_with_registry(
            "POST",
            "/admin/compression/sessions/purge",
            Some("{}"),
            Some(&session_admin),
            Some("csrf-a"),
            &registry,
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(unsafe_purge.status, 400);

        for body in [r#"{"conflict":false}"#, r#"{"conflict":true}"#] {
            let conflict_only = dispatch_with_registry(
                "POST",
                "/admin/compression/sessions/purge",
                Some(body),
                Some(&session_admin),
                Some("csrf-a"),
                &registry,
                &audit,
            )
            .await
            .unwrap();
            assert_eq!(
                conflict_only.status, 400,
                "conflict is a broad filter, not a destructive boundary"
            );
        }

        let wrong_confirmation = dispatch_with_registry(
            "POST",
            "/admin/compression/sessions/purge",
            Some(r#"{"all":true,"confirmation":"yes"}"#),
            Some(&session_admin),
            Some("csrf-a"),
            &registry,
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(wrong_confirmation.status, 400);

        let mixed_all_scope = dispatch_with_registry(
            "POST",
            "/admin/compression/sessions/purge",
            Some(r#"{"all":true,"confirmation":"purge-compression-sessions","tenant":"tenant-a"}"#),
            Some(&session_admin),
            Some("csrf-a"),
            &registry,
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(mixed_all_scope.status, 400);

        let zero_expiry = dispatch_with_registry(
            "POST",
            "/admin/compression/sessions/purge",
            Some(r#"{"expired_before":0}"#),
            Some(&session_admin),
            Some("csrf-a"),
            &registry,
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(zero_expiry.status, 400);

        let expired_scope = dispatch_with_registry(
            "POST",
            "/admin/compression/sessions/purge",
            Some(r#"{"expired_before":1234}"#),
            Some(&session_admin),
            Some("csrf-a"),
            &registry,
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(expired_scope.status, 400);

        let scoped = dispatch_with_registry(
            "POST",
            "/admin/compression/sessions/purge",
            Some(r#"{"tenant":"tenant-a","limit":25}"#),
            Some(&session_admin),
            Some("csrf-a"),
            &registry,
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(scoped.status, 200);
        assert_eq!(
            store
                .purge_requests
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .tenant_id
                .as_deref(),
            Some("tenant-a")
        );

        let purged = dispatch_with_registry(
            "POST",
            "/admin/compression/sessions/purge",
            Some(r#"{"all":true,"confirmation":"purge-compression-sessions","limit":999}"#),
            Some(&session_admin),
            Some("csrf-a"),
            &registry,
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(purged.status, 200);
        assert!(purged.body.contains("\"deleted\":2"));
        let request = store.purge_requests.lock().unwrap().pop().unwrap();
        assert_eq!(request.limit, 500);
        assert!(request.tenant_id.is_none());
        assert!(request.origin.is_none());
    }
}

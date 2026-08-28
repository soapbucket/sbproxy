//! RFC 8628 Device Authorization Grant for the MCP Auth Gateway.
//!
//! Headless MCP clients (CLI tools, SSH-only hosts, embedded agents)
//! cannot run a browser to complete the standard authorization-code
//! flow. The device-code grant addresses this by splitting the flow
//! across two devices: the client requests a `device_code` plus a
//! short user-friendly `user_code` from the AS, displays the user_code
//! and a verification URL to the human, and polls /token while the
//! human authorizes the request from any browser.
//!
//! This module implements:
//!
//! * `device_authorization` - the `POST /device_authorization` HTTP
//!   handler. Mints a `device_code`, a Crockford-base32 `user_code`,
//!   and persists the in-flight state under the workspace
//!   `EphemeralKv` so /verify and the /token poll can read it.
//! * `verify_get` / `verify_post` - the user-facing browser flow
//!   that resolves a typed-in `user_code` to its device_code, runs (or
//!   simulates, in this slice) the upstream PKCE flow, and marks the
//!   device-code state as `authorized` with the resulting token.
//! * [`DeviceCodeStore`] - thin wrapper around `EphemeralKv` with the
//!   broker's key naming convention (`device:<code>` and
//!   `device:user:<user_code>`).
//!
//! The token-side polling logic lives in `token.rs` so all grant
//! types share the same DPoP / cnf.jkt injection machinery.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    Form, Json,
};
use base64::Engine;
use bytes::Bytes;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use sbproxy_storage::EphemeralKv;

use crate::AppState;

// --- RFC 8628 grant URN ---

/// The RFC 8628 §3.1 grant_type URN polled at /token.
pub const DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

// --- Default knobs ---

/// Crockford-base32 alphabet (RFC 4648 §6 with letters O, I, L, U
/// dropped). Drops the visually ambiguous characters so the human can
/// re-type the user_code from a phone screen without errors.
const CROCKFORD_BASE32: &[u8] = b"ABCDEFGHJKMNPQRSTVWXYZ0123456789";

/// Length of the user_code on display (8 chars, formatted as XXXX-XXXX).
/// 32^8 yields 1.1 trillion possible codes, more than enough entropy
/// for a 10-minute lifetime even at 1k requests/sec.
const USER_CODE_LEN: usize = 8;

/// Cap for the `slow_down` interval doubling. RFC 8628 §3.5 caps the
/// guidance at "a few minutes"; we cap at 60 seconds because longer
/// intervals frustrate humans waiting at the CLI prompt.
const SLOW_DOWN_INTERVAL_CAP_SECS: u64 = 60;

// --- Consent-form CSRF defense ---

/// How long a `/verify` form token stays usable.
///
/// Long enough for a human to read a code off a device screen and type
/// it, short enough that a token captured from a stale tab is useless.
const VERIFY_FORM_TOKEN_TTL: Duration = Duration::from_secs(600);

/// Hidden form field carrying the per-form token.
const VERIFY_FORM_TOKEN_FIELD: &str = "form_token";

/// Mint a single-use form token for `subject` and store it.
///
/// The token is random, and the row records the subject that was
/// signed in when the form was rendered, so a token minted for one user
/// cannot approve as another.
async fn mint_verify_form_token(app: &AppState, subject: &str) -> Option<String> {
    let mut raw = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    let key = verify_form_token_key(app, &token);
    app.security_store
        .put(
            &key,
            Bytes::from(subject.as_bytes().to_vec()),
            VERIFY_FORM_TOKEN_TTL,
        )
        .await
        .ok()?;
    Some(token)
}

/// Redeem a form token. Returns true only when the token existed and
/// was minted for `subject`. Single use: the row is taken, not read.
async fn redeem_verify_form_token(app: &AppState, token: &str, subject: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    let key = verify_form_token_key(app, token);
    match app.security_store.take(&key).await {
        Ok(Some(bytes)) => bytes.as_ref() == subject.as_bytes(),
        _ => false,
    }
}

fn verify_form_token_key(app: &AppState, token: &str) -> String {
    format!("verify:csrf:{}:{token}", app.security_namespace)
}

/// Whether the request's `Origin` (or, failing that, `Referer`) is this
/// broker's own origin.
///
/// Fails closed when both are absent. Every browser that can submit
/// this form sends `Origin` on a cross-site POST and on a same-origin
/// one; a request carrying neither header is not the consent page.
fn verify_same_origin(app: &AppState, headers: &HeaderMap) -> bool {
    // Two origins are legitimate, and accepting only one of them broke
    // the shipped page.
    //
    // 1. The broker's own external origin. This is where the built-in
    //    consent page is served from, so it is what a browser reports
    //    when that page submits.
    // 2. The configured `device_code_verification_uri`, when an
    //    operator points users at a branded page of their own. Naming
    //    one used to *replace* the expected origin, so the moment a
    //    custom page was configured the broker's own page stopped
    //    working against itself.
    //
    // `validate_startup` refuses `device_code_enabled` without a
    // parseable base URL, so the first entry is present whenever this
    // handler can run. The empty-list case therefore cannot be
    // reached from a booted broker, and failing closed on it is the
    // right answer if it ever is.
    let mut expected = Vec::with_capacity(2);
    if let Ok(base) = url::Url::parse(&app.config.external_base_url) {
        expected.push(base.origin());
    }
    if let Ok(configured) = url::Url::parse(&resolve_verification_uri(&app.config)) {
        let origin = configured.origin();
        if !expected.contains(&origin) {
            expected.push(origin);
        }
    }
    if expected.is_empty() {
        return false;
    }
    let stated = headers
        .get(header::ORIGIN)
        .or_else(|| headers.get(header::REFERER))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| url::Url::parse(value).ok());
    match stated {
        Some(url) => expected.contains(&url.origin()),
        None => false,
    }
}

/// Headers every `/verify` response carries.
///
/// `no-store` keeps the form token out of the browser cache, and the
/// two framing headers keep the Approve button out of an attacker's
/// iframe: a clickjacked approval needs no forged request at all.
fn harden_verify_response(response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("frame-ancestors 'none'"),
    );
}

// --- Request / response models ---

/// `POST /device_authorization` request body. Per RFC 8628 §3.1 the
/// content type is `application/x-www-form-urlencoded`. We accept a
/// `client_id` (CIMD or pre-registered), an optional `scope`, and an
/// optional `resource` (RFC 8707) the issued token should be bound to.
#[derive(Debug, Deserialize)]
pub struct DeviceAuthorizationRequest {
    /// Client identifier, either an opaque pre-registered id or a
    /// CIMD URL when the AS supports the parecki draft.
    pub client_id: Option<String>,
    /// Optional whitespace-separated scope list.
    pub scope: Option<String>,
    /// Optional resource indicator (RFC 8707) the issued token is
    /// bound to. Forwarded verbatim to the upstream when /verify
    /// completes the standard authorization-code dance.
    pub resource: Option<String>,
}

/// Response body for `POST /device_authorization`, RFC 8628 §3.2.
#[derive(Debug, Serialize)]
pub struct DeviceAuthorizationResponse {
    /// Opaque code the client polls /token with.
    pub device_code: String,
    /// Short, human-typeable code displayed to the user.
    pub user_code: String,
    /// Verification URL the human visits.
    pub verification_uri: String,
    /// `verification_uri` with the user_code prefilled as a query
    /// param. Optional per RFC 8628 §3.3.1 but every realistic CLI
    /// renders this so the user can click the link in their terminal.
    pub verification_uri_complete: String,
    /// Lifetime of the code in seconds.
    pub expires_in: u64,
    /// Minimum poll interval the client MUST honor.
    pub interval: u64,
}

/// Persisted device-code state. Serialized as JSON in the
/// `EphemeralKv` value, keyed off `device:<device_code>`.
#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceCodeState {
    /// Mirrors the inbound `client_id`. Re-validated on every poll
    /// against the request's `client_id` to prevent code-substitution
    /// attacks (stealing one client's code, polling as another).
    pub client_id: String,
    /// Whitespace-separated scope from the original request.
    pub scope: Option<String>,
    /// RFC 8707 resource indicator from the original request.
    pub resource: Option<String>,
    /// Human-typeable code. Tracked here so /token can return
    /// `expired_token` when the user_code reverse index has TTL'd out.
    pub user_code: String,
    /// Status machine: `pending` (initial), `authorized` (user
    /// completed /verify, token stored), `denied` (user clicked
    /// "deny"), `expired` (TTL elapsed; set lazily on poll).
    pub status: DeviceCodeStatus,
    /// JSON body returned by the upstream /token endpoint when the
    /// /verify flow completed. Present only when `status == authorized`.
    pub authorized_token: Option<serde_json::Value>,
    /// Issued-at, seconds since UNIX epoch. Used to derive
    /// `expires_at` and to surface the absolute expiry time on the
    /// /verify HTML page.
    pub issued_at: i64,
    /// Absolute expiry, seconds since UNIX epoch. Polls past this
    /// value return `expired_token`.
    pub expires_at: i64,
    /// Current minimum polling interval. Doubles on each `slow_down`
    /// up to a 60-second cap.
    pub interval_secs: u64,
    /// Wall-clock of the previous /token poll, seconds since UNIX
    /// epoch. Compared against `interval_secs` to decide whether the
    /// next poll trips `slow_down`.
    pub last_polled_at: Option<i64>,
}

impl std::fmt::Debug for DeviceCodeState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceCodeState")
            .field("client_id", &self.client_id)
            .field("scope", &self.scope)
            .field("resource", &self.resource)
            .field("user_code", &"[REDACTED]")
            .field("status", &self.status)
            .field(
                "authorized_token",
                &self.authorized_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("interval_secs", &self.interval_secs)
            .field("last_polled_at", &self.last_polled_at)
            .finish()
    }
}

/// Identity inserted by the host only after its normal authentication
/// chain has established the browser user's subject. The standalone
/// broker does not synthesize this value, so device consent fails
/// closed unless hosted behind an authenticated sbproxy path.
#[derive(Clone, Debug)]
pub struct AuthenticatedDeviceUser {
    /// Stable subject to place in the broker-minted access token.
    pub subject: String,
}

/// State machine for an in-flight device-code authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceCodeStatus {
    /// User has not yet visited /verify.
    Pending,
    /// User authorized; an upstream token is stored.
    Authorized,
    /// User clicked "deny" on /verify.
    Denied,
}

/// User decision applied to a pending device authorization.
pub enum DeviceDecision {
    /// Approve and persist the complete token response.
    Approved(serde_json::Value),
    /// Deny without storing token material.
    Denied,
}

/// Result of an atomic pending-to-final transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceDecisionOutcome {
    /// This caller won the transition.
    Applied,
    /// Another caller already finalized the decision.
    AlreadyFinal(DeviceCodeStatus),
    /// The code expired or was already consumed.
    Missing,
}

/// Result of one atomic RFC 8628 token poll.
#[derive(Debug)]
pub enum DevicePollOutcome {
    /// The device code is absent or was already consumed.
    Missing,
    /// The caller did not match the client that requested the code.
    InvalidClient,
    /// The user has not decided yet.
    Pending,
    /// The caller exceeded the polling interval.
    SlowDown,
    /// The code expired.
    Expired,
    /// The user denied consent.
    Denied,
    /// This caller atomically consumed the approved state.
    ///
    /// Boxed because the state is two orders of magnitude larger than
    /// any other variant here, and every poll that is not the one
    /// winning poll returns one of those. Carrying the approved state
    /// inline would make the whole enum that size on every `Pending`
    /// and `SlowDown` answer.
    Authorized(Box<DeviceCodeState>),
}

// --- Store ---

/// Thin facade over [`EphemeralKv`] with the device-code key naming
/// convention. The broker's [`AppState`] holds an `Arc` to this so
/// `/device_authorization`, `/verify`, and `/token` all read and write
/// the same backend.
pub struct DeviceCodeStore {
    kv: Arc<dyn EphemeralKv>,
}

impl DeviceCodeStore {
    /// Wrap an [`EphemeralKv`] with the device-code prefix.
    pub fn new(kv: Arc<dyn EphemeralKv>) -> Self {
        Self { kv }
    }

    /// Convenience: arc-wrap the store for handler injection.
    pub fn arc(kv: Arc<dyn EphemeralKv>) -> Arc<Self> {
        Arc::new(Self::new(kv))
    }

    /// Persist the state under `device:<device_code>` plus a reverse
    /// index `device:user:<user_code>` so the browser /verify path
    /// can resolve a typed code without scanning every key.
    pub async fn put(
        &self,
        device_code: &str,
        state: &DeviceCodeState,
        ttl: Duration,
    ) -> Result<(), DeviceCodeError> {
        let bytes = serialize_state(state)?;
        let reverse_key = user_code_key(&state.user_code);
        let reverse_value = Bytes::copy_from_slice(device_code.as_bytes());
        let claimed_reverse = self
            .kv
            .compare_exchange(&reverse_key, None, Some((reverse_value.clone(), ttl)))
            .await
            .map_err(|e| DeviceCodeError::Storage(format!("{e}")))?;
        if !claimed_reverse {
            return Err(DeviceCodeError::Contention(
                "user code collision; mint a fresh code".to_string(),
            ));
        }
        let claimed_primary = self
            .kv
            .compare_exchange(&device_key(device_code), None, Some((bytes, ttl)))
            .await
            .map_err(|e| DeviceCodeError::Storage(format!("{e}")))?;
        if !claimed_primary {
            let _ = self
                .kv
                .compare_exchange(&reverse_key, Some(reverse_value), None)
                .await;
            return Err(DeviceCodeError::Contention(
                "device code collision; mint a fresh code".to_string(),
            ));
        }
        Ok(())
    }

    /// Read the state for a given device_code.
    pub async fn get(&self, device_code: &str) -> Result<Option<DeviceCodeState>, DeviceCodeError> {
        let raw = self
            .kv
            .get(&device_key(device_code))
            .await
            .map_err(|e| DeviceCodeError::Storage(format!("{e}")))?;
        match raw {
            Some(bytes) => {
                let state: DeviceCodeState = serde_json::from_slice(&bytes)
                    .map_err(|e| DeviceCodeError::Serialize(format!("{e}")))?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    /// Resolve a user_code to its device_code via the reverse index.
    pub async fn resolve_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<String>, DeviceCodeError> {
        let raw = self
            .kv
            .get(&user_code_key(user_code))
            .await
            .map_err(|e| DeviceCodeError::Storage(format!("{e}")))?;
        Ok(raw.and_then(|b| String::from_utf8(b.to_vec()).ok()))
    }

    /// Update a state in place, preserving the original TTL by deriving
    /// a remaining-time TTL from `expires_at`. Callers should hold a
    /// state read on entry and pass the mutated copy back here.
    pub async fn update(
        &self,
        device_code: &str,
        state: &DeviceCodeState,
    ) -> Result<(), DeviceCodeError> {
        let key = device_key(device_code);
        for _ in 0..16 {
            let Some(current) = self
                .kv
                .get(&key)
                .await
                .map_err(|e| DeviceCodeError::Storage(format!("{e}")))?
            else {
                return Err(DeviceCodeError::Contention(
                    "device code disappeared during update".to_string(),
                ));
            };
            if self
                .kv
                .compare_exchange(
                    &key,
                    Some(current),
                    Some((serialize_state(state)?, remaining_ttl(state))),
                )
                .await
                .map_err(|e| DeviceCodeError::Storage(format!("{e}")))?
            {
                return Ok(());
            }
        }
        Err(DeviceCodeError::Contention(
            "device code update contention limit reached".to_string(),
        ))
    }

    /// Atomically finalize a pending code. A denial or approval that
    /// already won is immutable.
    pub async fn decide(
        &self,
        device_code: &str,
        decision: DeviceDecision,
    ) -> Result<DeviceDecisionOutcome, DeviceCodeError> {
        let key = device_key(device_code);
        for _ in 0..16 {
            let Some(current) = self
                .kv
                .get(&key)
                .await
                .map_err(|e| DeviceCodeError::Storage(format!("{e}")))?
            else {
                return Ok(DeviceDecisionOutcome::Missing);
            };
            let mut state = deserialize_state(&current)?;
            if state.status != DeviceCodeStatus::Pending {
                return Ok(DeviceDecisionOutcome::AlreadyFinal(state.status));
            }
            match &decision {
                DeviceDecision::Approved(token) => {
                    state.status = DeviceCodeStatus::Authorized;
                    state.authorized_token = Some(token.clone());
                }
                DeviceDecision::Denied => {
                    state.status = DeviceCodeStatus::Denied;
                    state.authorized_token = None;
                }
            }
            if self
                .kv
                .compare_exchange(
                    &key,
                    Some(current),
                    Some((serialize_state(&state)?, remaining_ttl(&state))),
                )
                .await
                .map_err(|e| DeviceCodeError::Storage(format!("{e}")))?
            {
                return Ok(DeviceDecisionOutcome::Applied);
            }
        }
        Err(DeviceCodeError::Contention(
            "device decision contention limit reached".to_string(),
        ))
    }

    /// Apply polling rate state and, when approved, atomically consume
    /// the primary row. Exactly one concurrent poller can receive the
    /// authorized token.
    pub async fn poll_and_consume(
        &self,
        device_code: &str,
        client_id: &str,
        now: i64,
    ) -> Result<DevicePollOutcome, DeviceCodeError> {
        let key = device_key(device_code);
        for _ in 0..16 {
            let Some(current) = self
                .kv
                .get(&key)
                .await
                .map_err(|e| DeviceCodeError::Storage(format!("{e}")))?
            else {
                return Ok(DevicePollOutcome::Missing);
            };
            let mut state = deserialize_state(&current)?;
            if state.client_id != client_id {
                return Ok(DevicePollOutcome::InvalidClient);
            }
            if now >= state.expires_at {
                if self
                    .kv
                    .compare_exchange(&key, Some(current), None)
                    .await
                    .map_err(|e| DeviceCodeError::Storage(format!("{e}")))?
                {
                    self.remove_reverse_index(device_code, &state.user_code)
                        .await;
                    return Ok(DevicePollOutcome::Expired);
                }
                continue;
            }
            if state.status == DeviceCodeStatus::Denied {
                return Ok(DevicePollOutcome::Denied);
            }
            let too_fast = apply_poll_rate_limit(&mut state, now);
            if state.status == DeviceCodeStatus::Authorized && !too_fast {
                if self
                    .kv
                    .compare_exchange(&key, Some(current), None)
                    .await
                    .map_err(|e| DeviceCodeError::Storage(format!("{e}")))?
                {
                    self.remove_reverse_index(device_code, &state.user_code)
                        .await;
                    return Ok(DevicePollOutcome::Authorized(Box::new(state)));
                }
                continue;
            }
            if self
                .kv
                .compare_exchange(
                    &key,
                    Some(current),
                    Some((serialize_state(&state)?, remaining_ttl(&state))),
                )
                .await
                .map_err(|e| DeviceCodeError::Storage(format!("{e}")))?
            {
                return Ok(if too_fast {
                    DevicePollOutcome::SlowDown
                } else {
                    DevicePollOutcome::Pending
                });
            }
        }
        Err(DeviceCodeError::Contention(
            "device poll contention limit reached".to_string(),
        ))
    }

    async fn remove_reverse_index(&self, device_code: &str, user_code: &str) {
        let _ = self
            .kv
            .compare_exchange(
                &user_code_key(user_code),
                Some(Bytes::copy_from_slice(device_code.as_bytes())),
                None,
            )
            .await;
    }

    /// Delete the primary state and reverse index for a given
    /// device_code. Called once after the /token poll has redeemed
    /// the code so a replay cannot mint a second token.
    pub async fn delete(&self, device_code: &str, user_code: &str) -> Result<(), DeviceCodeError> {
        self.kv
            .delete(&device_key(device_code))
            .await
            .map_err(|e| DeviceCodeError::Storage(format!("{e}")))?;
        self.kv
            .delete(&user_code_key(user_code))
            .await
            .map_err(|e| DeviceCodeError::Storage(format!("{e}")))?;
        Ok(())
    }
}

/// Errors surfaced by the device-code subsystem. Map onto the RFC
/// 8628 §3.5 error codes inside the /token handler.
#[derive(Debug)]
pub enum DeviceCodeError {
    /// EphemeralKv backend rejected a read or write.
    Storage(String),
    /// Internal serialization failure (state did not round-trip).
    Serialize(String),
    /// A bounded CAS retry or unique-code claim could not make progress.
    Contention(String),
}

impl std::fmt::Display for DeviceCodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceCodeError::Storage(s) => write!(f, "device code storage: {s}"),
            DeviceCodeError::Serialize(s) => write!(f, "device code serialize: {s}"),
            DeviceCodeError::Contention(s) => write!(f, "device code contention: {s}"),
        }
    }
}

impl std::error::Error for DeviceCodeError {}

fn deserialize_state(bytes: &Bytes) -> Result<DeviceCodeState, DeviceCodeError> {
    serde_json::from_slice(bytes).map_err(|e| DeviceCodeError::Serialize(format!("{e}")))
}

fn serialize_state(state: &DeviceCodeState) -> Result<Bytes, DeviceCodeError> {
    serde_json::to_vec(state)
        .map(Bytes::from)
        .map_err(|e| DeviceCodeError::Serialize(format!("{e}")))
}

fn remaining_ttl(state: &DeviceCodeState) -> Duration {
    Duration::from_secs(state.expires_at.saturating_sub(unix_now()).max(1) as u64)
}

// --- Key helpers ---

/// Primary key: `device:<device_code>`.
fn device_key(device_code: &str) -> String {
    format!("device:{device_code}")
}

/// Reverse index key: `device:user:<user_code>`. The user_code is
/// uppercased and dashes are stripped before lookup so the user can
/// type it in any cosmetic form.
fn user_code_key(user_code: &str) -> String {
    format!("device:user:{}", normalize_user_code(user_code))
}

/// Normalize a user_code into the canonical form: uppercase,
/// dash-stripped, whitespace-stripped. Browser-side and CLI-side
/// callers see the formatted `XXXX-XXXX` form; the storage layer keys
/// off the raw eight characters.
pub fn normalize_user_code(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

// --- Handlers ---

/// `POST {base_path}/device_authorization` handler.
pub async fn device_authorization(
    State(app): State<AppState>,
    Form(form): Form<DeviceAuthorizationRequest>,
) -> Response {
    let cfg = &app.config;
    if !cfg.device_code_enabled {
        return oauth_error(
            StatusCode::NOT_FOUND,
            "unsupported_grant_type",
            "device authorization grant is disabled",
        );
    }

    let store = match app.device_code_store.as_ref() {
        Some(s) => s.clone(),
        None => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "device code store not configured",
            );
        }
    };

    let client_id = match form.client_id {
        Some(s) if !s.is_empty() => s,
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing client_id",
            );
        }
    };
    let resource = form.resource.unwrap_or_else(|| cfg.resource_uri.clone());
    if !crate::authorize::is_resource_bound(&resource, cfg) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "requested resource is not enrolled for this broker",
        );
    }

    if !cfg.scopes_supported.is_empty()
        && form
            .scope
            .as_deref()
            .is_none_or(|scope| scope.trim().is_empty())
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "a supported scope is required",
        );
    }
    if let Some(scope) = form.scope.as_deref() {
        for requested in scope.split_whitespace() {
            if !cfg
                .scopes_supported
                .iter()
                .any(|supported| supported == requested)
            {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_scope",
                    "requested scope is not supported by this server",
                );
            }
        }
    }

    // Mint the codes. 256 bits of entropy for the device_code matches
    // the access-token strength and is comfortably URL-safe.
    let device_code = mint_device_code();
    let user_code = mint_user_code();
    let now = unix_now();
    let lifetime = cfg.device_code_lifetime_secs.max(60);
    let interval = cfg.device_code_polling_interval_secs.max(1);

    let state = DeviceCodeState {
        client_id,
        scope: form.scope,
        resource: Some(resource),
        user_code: user_code.clone(),
        status: DeviceCodeStatus::Pending,
        authorized_token: None,
        issued_at: now,
        expires_at: now + lifetime as i64,
        interval_secs: interval,
        last_polled_at: None,
    };

    if let Err(e) = store
        .put(&device_code, &state, Duration::from_secs(lifetime))
        .await
    {
        tracing::error!(error = %e, "device_authorization: store put failed");
        return oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "device code persistence failed",
        );
    }

    let verification_uri = resolve_verification_uri(cfg);
    let verification_uri_complete = format!(
        "{}?user_code={}",
        verification_uri,
        format_user_code(&user_code)
    );

    let resp = DeviceAuthorizationResponse {
        device_code,
        user_code: format_user_code(&user_code),
        verification_uri,
        verification_uri_complete,
        expires_in: lifetime,
        interval,
    };

    let mut response = (StatusCode::OK, Json(resp)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// `GET {base_path}/verify` query string. RFC 8628 §3.3.1 lets the
/// AS prefill the user_code via `?user_code=XXXX-XXXX`.
#[derive(Debug, Deserialize)]
pub(crate) struct VerifyQuery {
    pub user_code: Option<String>,
}

/// `GET {base_path}/verify` handler. Returns a tiny self-contained
/// HTML form so the user can paste their user_code and approve or
/// deny.
///
/// The page is a consent surface, so it is rendered only for a caller
/// the host process already authenticated, and it carries a single-use
/// form token bound to that subject. An operator replacing this page
/// with a branded one keeps the same contract: `POST /verify` needs a
/// `user_code`, an `action` of exactly `approve` or `deny`, and the
/// `form_token` this handler minted, and the session cookie the host
/// authenticates with must be `SameSite=Lax` or stricter. See
/// `docs/mcp-oauth-gateway.md`.
pub(crate) async fn verify_get(
    State(app): State<AppState>,
    authenticated_user: Option<axum::extract::Extension<AuthenticatedDeviceUser>>,
    Query(q): Query<VerifyQuery>,
) -> Response {
    if !app.config.device_code_enabled {
        return (StatusCode::NOT_FOUND, "device authorization disabled").into_response();
    }

    let Some(axum::extract::Extension(authenticated_user)) = authenticated_user else {
        return (StatusCode::UNAUTHORIZED, "authentication required").into_response();
    };
    if authenticated_user.subject.trim().is_empty() {
        return (StatusCode::UNAUTHORIZED, "authentication required").into_response();
    }

    let Some(form_token) = mint_verify_form_token(&app, &authenticated_user.subject).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "consent form token could not be issued",
        )
            .into_response();
    };

    let prefilled = q.user_code.unwrap_or_default();
    let mut response = Html(verify_html(&prefilled, &form_token)).into_response();
    harden_verify_response(&mut response);
    response
}

/// `POST {base_path}/verify` body. The HTML form posts the typed
/// user_code plus an `action` of either `approve` or `deny`.
#[derive(Debug, Deserialize)]
pub(crate) struct VerifySubmission {
    pub user_code: Option<String>,
    /// Either `approve` or `deny`.
    pub action: Option<String>,
    /// Single-use token minted by `verify_get` for this signed-in
    /// subject. Absent or unknown means the submission did not come
    /// from a form this broker rendered.
    pub form_token: Option<String>,
}

/// `POST {base_path}/verify` handler. Requires host-established user
/// identity, resolves the user code, applies an exact approve/deny
/// decision, and stores a freshly signed broker access token on
/// approval.
pub(crate) async fn verify_post(
    State(app): State<AppState>,
    authenticated_user: Option<axum::extract::Extension<AuthenticatedDeviceUser>>,
    headers: HeaderMap,
    Form(form): Form<VerifySubmission>,
) -> Response {
    if !app.config.device_code_enabled {
        return (StatusCode::NOT_FOUND, "device authorization disabled").into_response();
    }

    let Some(axum::extract::Extension(authenticated_user)) = authenticated_user else {
        return (StatusCode::UNAUTHORIZED, "authentication required").into_response();
    };
    if authenticated_user.subject.trim().is_empty() {
        return (StatusCode::UNAUTHORIZED, "authentication required").into_response();
    }

    // CSRF. This handler mints an access token carrying the signed-in
    // browser user's `sub`, from ambient credentials, on a form POST:
    // without these two checks any page a signed-in user loads can
    // approve an attacker's device code and hand the attacker a token
    // as that user. Both checks must pass. The origin check is what
    // stops a cross-site POST, and the single-use token bound to the
    // subject is what stops a same-origin injection or a replay of a
    // captured body.
    if !verify_same_origin(&app, &headers) {
        crate::metrics::record_broker_decision("verify", "csrf_refused");
        tracing::warn!(
            target: "mcp_gateway::decision",
            event = "mcp_oauth_verify_decision",
            outcome = "rejected",
            reason = "cross_origin",
            "device consent refused: Origin and Referer are absent or not this broker"
        );
        let mut response = (
            StatusCode::FORBIDDEN,
            Html(verify_error_html(
                "this request did not come from the authorization page",
            )),
        )
            .into_response();
        harden_verify_response(&mut response);
        return response;
    }
    let form_token = form.form_token.clone().unwrap_or_default();
    if !redeem_verify_form_token(&app, &form_token, &authenticated_user.subject).await {
        crate::metrics::record_broker_decision("verify", "csrf_refused");
        tracing::warn!(
            target: "mcp_gateway::decision",
            event = "mcp_oauth_verify_decision",
            outcome = "rejected",
            reason = "form_token",
            "device consent refused: form token missing, expired, already used, or minted for another subject"
        );
        let mut response = (
            StatusCode::FORBIDDEN,
            Html(verify_error_html(
                "this authorization form has expired; reload the page and try again",
            )),
        )
            .into_response();
        harden_verify_response(&mut response);
        return response;
    }

    let store = match app.device_code_store.as_ref() {
        Some(s) => s.clone(),
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "device code store not configured",
            )
                .into_response();
        }
    };

    let raw_user_code = match form.user_code {
        Some(s) if !s.is_empty() => s,
        _ => return Html(verify_error_html("user_code required")).into_response(),
    };

    let approve = match form.action.as_deref() {
        Some("approve") => true,
        Some("deny") => false,
        _ => return Html(verify_error_html("action must be approve or deny")).into_response(),
    };

    let device_code = match store.resolve_user_code(&raw_user_code).await {
        Ok(Some(dc)) => dc,
        Ok(None) => {
            return Html(verify_error_html("user_code unknown or expired")).into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "verify_post: reverse lookup failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "device code lookup failed",
            )
                .into_response();
        }
    };

    let state = match store.get(&device_code).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Html(verify_error_html("device code expired")).into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "verify_post: state read failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "device code lookup failed",
            )
                .into_response();
        }
    };

    let decision = if approve {
        let Some(signing_key) = app.config.broker_signing_key.as_ref() else {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "broker signing key required for device authorization",
            )
                .into_response();
        };
        let issuer = crate::well_known::broker_issuer(&app.config);
        if issuer.is_empty() {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "broker issuer required for device authorization",
            )
                .into_response();
        }
        let mut jti_bytes = [0_u8; 16];
        rand::thread_rng().fill_bytes(&mut jti_bytes);
        let claims = crate::at_jwt::AtJwtClaims {
            iss: issuer,
            sub: authenticated_user.subject,
            aud: serde_json::Value::String(
                state
                    .resource
                    .clone()
                    .unwrap_or_else(|| app.config.resource_uri.clone()),
            ),
            exp: state.expires_at,
            iat: unix_now(),
            jti: jti_bytes.iter().map(|b| format!("{b:02x}")).collect(),
            client_id: state.client_id.clone(),
            scope: state.scope.clone(),
            auth_time: Some(unix_now()),
            acr: None,
            amr: None,
            act: None,
            cnf: None,
            actor: None,
            principal: None,
            tnx: None,
            purpose: None,
        };
        let token = match crate::at_jwt::mint_at_jwt(&claims, signing_key) {
            Ok(token) => token,
            Err(e) => {
                tracing::error!(error = %e, "device token mint failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "token mint failed").into_response();
            }
        };
        DeviceDecision::Approved(serde_json::json!({
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": state.expires_at.saturating_sub(unix_now()),
        }))
    } else {
        DeviceDecision::Denied
    };

    match store.decide(&device_code, decision).await {
        Ok(DeviceDecisionOutcome::Applied) => {}
        Ok(DeviceDecisionOutcome::AlreadyFinal(_)) => {
            return (
                StatusCode::CONFLICT,
                Html(verify_error_html(
                    "device authorization was already decided",
                )),
            )
                .into_response();
        }
        Ok(DeviceDecisionOutcome::Missing) => {
            return Html(verify_error_html("device code expired")).into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "verify_post: atomic state transition failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "device code update failed",
            )
                .into_response();
        }
    }

    let body = if approve {
        verify_success_html("Device authorized. You may close this window.")
    } else {
        verify_success_html("Device authorization denied.")
    };
    Html(body).into_response()
}

// --- Mint helpers ---

/// Mint a 32-byte URL-safe device_code.
fn mint_device_code() -> String {
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

/// Mint an 8-character Crockford-base32 user_code, raw (no dashes).
/// The display form `XXXX-XXXX` is rendered by [`format_user_code`].
fn mint_user_code() -> String {
    let mut buf = [0u8; USER_CODE_LEN];
    rand::thread_rng().fill_bytes(&mut buf);
    let mut out = String::with_capacity(USER_CODE_LEN);
    for b in buf.iter() {
        out.push(CROCKFORD_BASE32[(*b as usize) % CROCKFORD_BASE32.len()] as char);
    }
    out
}

/// Format an 8-char user_code as `XXXX-XXXX`.
pub fn format_user_code(raw: &str) -> String {
    let normalized = normalize_user_code(raw);
    if normalized.len() == USER_CODE_LEN {
        format!("{}-{}", &normalized[..4], &normalized[4..])
    } else {
        normalized
    }
}

/// Resolve the verification URI advertised in /device_authorization.
/// Order of precedence: explicit verification URI, then the legacy
/// environment override or configured external base URL, then a
/// relative-path fallback.
fn resolve_verification_uri(cfg: &crate::config::McpGatewayConfig) -> String {
    if !cfg.device_code_verification_uri.is_empty() {
        return cfg.device_code_verification_uri.clone();
    }
    let base = std::env::var("MCP_GATEWAY_BASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| cfg.external_base_url.clone());
    let path = cfg.base_path.trim_end_matches('/');
    if base.is_empty() {
        format!("{path}/verify")
    } else {
        format!("{}{}/verify", base.trim_end_matches('/'), path)
    }
}

/// UNIX seconds-since-epoch.
pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Update the rate-limit state for a poll. Returns the new state
/// alongside whether the poller tripped slow_down. Public so the
/// /token handler can call into it without re-implementing the math.
pub fn apply_poll_rate_limit(state: &mut DeviceCodeState, now: i64) -> bool {
    let last = state.last_polled_at.unwrap_or(0);
    let elapsed = now.saturating_sub(last);
    let too_fast = last > 0 && (elapsed as u64) < state.interval_secs;
    state.last_polled_at = Some(now);
    if too_fast {
        let doubled = state.interval_secs.saturating_mul(2);
        state.interval_secs = doubled.min(SLOW_DOWN_INTERVAL_CAP_SECS);
    }
    too_fast
}

// --- HTML stubs ---

/// Render the /verify form. Inline CSS keeps this self-contained;
/// operators wanting a branded experience can override this handler
/// downstream.
fn verify_html(prefilled: &str, form_token: &str) -> String {
    let safe = html_escape(prefilled);
    let token = html_escape(form_token);
    format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Authorize device</title>
<style>body{{font-family:system-ui;max-width:32rem;margin:4rem auto;padding:1rem}}
input{{font-size:1.25rem;padding:.5rem;width:100%;box-sizing:border-box}}
button{{font-size:1rem;padding:.5rem 1rem;margin-right:.5rem}}</style>
</head><body>
<h1>Authorize device</h1>
<p>Enter the code shown on your device.</p>
<form method="POST" action="">
<label for="user_code">User code</label>
<input id="user_code" name="user_code" value="{safe}" autocomplete="off" autofocus>
<input type="hidden" name="{field}" value="{token}">
<p>
<button type="submit" name="action" value="approve">Approve</button>
<button type="submit" name="action" value="deny">Deny</button>
</p>
</form></body></html>"#,
        safe = safe,
        field = VERIFY_FORM_TOKEN_FIELD,
        token = token
    )
}

/// Render a success page after /verify completes.
fn verify_success_html(message: &str) -> String {
    let safe = html_escape(message);
    format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Device authorized</title></head>
<body><h1>{safe}</h1></body></html>"#,
        safe = safe
    )
}

/// Render an error page.
fn verify_error_html(message: &str) -> String {
    let safe = html_escape(message);
    format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Error</title></head>
<body><h1>Error</h1><p>{safe}</p></body></html>"#,
        safe = safe
    )
}

/// Minimal HTML escaper. Sufficient for rendering a user-supplied
/// user_code into an `<input value="...">` attribute or `<h1>` body.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

// --- Error helper ---

/// Render an OAuth-shaped JSON error response.
fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    (
        status,
        headers,
        Json(serde_json::json!({
            "error": error,
            "error_description": description,
        })),
    )
        .into_response()
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::McpGatewayConfig;
    use crate::session::InMemorySessionStore;
    use axum::body::Body;
    use axum::http::Request;
    use axum::Router;
    use http_body_util::BodyExt;
    use sbproxy_storage::mock::MockEphemeralKv;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn enabled_config() -> McpGatewayConfig {
        McpGatewayConfig {
            device_code_enabled: true,
            device_code_lifetime_secs: 600,
            device_code_polling_interval_secs: 5,
            device_code_verification_uri: "https://broker.example/mcp/oauth/verify".to_string(),
            resource_uri: "https://mcp.example".to_string(),
            scopes_supported: vec!["read".to_string()],
            broker_signing_key: Some(crate::config::JwkKey::Pem {
                pem: include_str!("../../sbproxy-modules/src/auth/dpop_test_ec_p256.pem")
                    .to_string(),
                alg: "ES256".to_string(),
                kid: Some("device-test-key".to_string()),
                public_jwk: None,
            }),
            ..McpGatewayConfig::default()
        }
    }

    fn authenticated(app: Router) -> Router {
        app.layer(axum::extract::Extension(AuthenticatedDeviceUser {
            subject: "user-123".to_string(),
        }))
    }

    fn build_app(cfg: McpGatewayConfig) -> Router {
        let store = InMemorySessionStore::arc(Duration::from_secs(60));
        let kv: Arc<dyn EphemeralKv> = Arc::new(MockEphemeralKv::new());
        let dc_store = Some(DeviceCodeStore::arc(kv));
        crate::router_full_with_par(
            Arc::new(cfg),
            store,
            None,
            None,
            None,
            None,
            None,
            dc_store,
            None,
        )
    }

    async fn post_form(app: Router, uri: &str, body: &str) -> (StatusCode, String) {
        post_form_from(app, uri, body, Some(CONSENT_ORIGIN)).await
    }

    /// The origin `enabled_config`'s `device_code_verification_uri`
    /// lives on. Every legitimate consent POST carries it.
    const CONSENT_ORIGIN: &str = "https://broker.example";

    async fn post_form_from(
        app: Router,
        uri: &str,
        body: &str,
        origin: Option<&str>,
    ) -> (StatusCode, String) {
        let mut req = Request::builder().method("POST").uri(uri).header(
            axum::http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        );
        if let Some(origin) = origin {
            req = req.header(axum::http::header::ORIGIN, origin);
        }
        let req = req.body(Body::from(body.to_string())).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&body).to_string())
    }

    /// Render the consent page and pull the single-use form token out
    /// of it, the way a browser would.
    async fn consent_form_token(app: Router) -> String {
        let req = Request::builder()
            .method("GET")
            .uri("/mcp/oauth/verify")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "consent page must render");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8_lossy(&body).to_string();
        let marker = "name=\"form_token\" value=\"";
        let start = body.find(marker).expect("form carries a token") + marker.len();
        let rest = &body[start..];
        let end = rest.find('"').expect("token is quoted");
        rest[..end].to_string()
    }

    #[tokio::test]
    async fn device_authorization_happy_path() {
        let app = build_app(enabled_config());
        let (status, body) = post_form(
            app,
            "/mcp/oauth/device_authorization",
            "client_id=cli&scope=read",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v["device_code"].as_str().unwrap().len() >= 32);
        let user_code = v["user_code"].as_str().unwrap();
        assert_eq!(user_code.len(), 9);
        assert!(user_code.contains('-'));
        assert_eq!(v["expires_in"].as_u64().unwrap(), 600);
        assert_eq!(v["interval"].as_u64().unwrap(), 5);
        assert!(v["verification_uri_complete"]
            .as_str()
            .unwrap()
            .contains("user_code="));
    }

    #[tokio::test]
    async fn device_authorization_disabled_returns_404() {
        let mut cfg = enabled_config();
        cfg.device_code_enabled = false;
        let app = build_app(cfg);
        let (status, _) = post_form(app, "/mcp/oauth/device_authorization", "client_id=cli").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn device_authorization_rejects_missing_client_id() {
        let app = build_app(enabled_config());
        let (status, body) = post_form(app, "/mcp/oauth/device_authorization", "scope=read").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid_request"));
    }

    #[tokio::test]
    async fn device_authorization_rejects_a_missing_scope_when_the_server_requires_one() {
        let app = build_app(enabled_config());
        let (status, body) =
            post_form(app, "/mcp/oauth/device_authorization", "client_id=cli").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid_scope"), "{body}");
    }

    #[tokio::test]
    async fn device_authorization_rejects_a_scope_outside_the_server_grant() {
        let app = build_app(enabled_config());
        let (status, body) = post_form(
            app,
            "/mcp/oauth/device_authorization",
            "client_id=cli&scope=write",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid_scope"), "{body}");
    }

    #[tokio::test]
    async fn device_authorization_rejects_an_unenrolled_resource() {
        let app = build_app(enabled_config());
        let (status, body) = post_form(
            app,
            "/mcp/oauth/device_authorization",
            "client_id=cli&resource=https%3A%2F%2Fevil.example",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid_target"), "{body}");
    }

    #[test]
    fn user_codes_are_unique_across_minting() {
        // Birthday-paradox check: 1000 codes from a 32^8 space should
        // collide with vanishingly small probability (P~5e-7). One in
        // a thousand passes is acceptable; if this trips we will know
        // the entropy source is broken.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let code = mint_user_code();
            assert_eq!(code.len(), USER_CODE_LEN);
            assert!(seen.insert(code), "user_code collision in 1000 mints");
        }
    }

    #[test]
    fn normalize_user_code_strips_dashes_and_lowercases() {
        assert_eq!(normalize_user_code("ab12-cd34"), "AB12CD34");
        assert_eq!(normalize_user_code(" ab 12 cd 34 "), "AB12CD34");
        assert_eq!(normalize_user_code("AB12CD34"), "AB12CD34");
    }

    #[test]
    fn format_user_code_groups_into_quartets() {
        assert_eq!(format_user_code("ABCDEFGH"), "ABCD-EFGH");
        assert_eq!(format_user_code("abcd-efgh"), "ABCD-EFGH");
    }

    #[tokio::test]
    async fn verify_get_renders_form_with_prefilled_user_code() {
        let app = authenticated(build_app(enabled_config()));
        let req = Request::builder()
            .method("GET")
            .uri("/mcp/oauth/verify?user_code=ABCD-EFGH")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::X_FRAME_OPTIONS)
                .and_then(|value| value.to_str().ok()),
            Some("DENY"),
            "the Approve button must not be framable"
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("ABCD-EFGH"));
        assert!(body_str.contains("Approve"));
        assert!(body_str.contains("Deny"));
        assert!(
            body_str.contains("name=\"form_token\""),
            "the form must carry a CSRF token"
        );
    }

    #[tokio::test]
    async fn verify_get_requires_an_authenticated_user() {
        // The page is a consent surface. Rendering it anonymously would
        // mint a form token bound to nobody.
        let app = build_app(enabled_config());
        let req = Request::builder()
            .method("GET")
            .uri("/mcp/oauth/verify")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn verify_post_without_a_form_token_is_refused() {
        // The CSRF scenario: an attacker gets a signed-in victim's
        // browser to POST their own user_code with action=approve. The
        // browser attaches the session cookie and the host resolves the
        // victim; only the absent form token stops the approval.
        let app = authenticated(build_app(enabled_config()));
        let (status, body) = post_form(
            app,
            "/mcp/oauth/verify",
            "user_code=ABCD-EFGH&action=approve",
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.contains("expired"), "{body}");
    }

    #[tokio::test]
    async fn verify_post_from_another_origin_is_refused() {
        let app = authenticated(build_app(enabled_config()));
        let token = consent_form_token(app.clone()).await;
        let (status, _) = post_form_from(
            app,
            "/mcp/oauth/verify",
            &format!("user_code=ABCD-EFGH&action=approve&form_token={token}"),
            Some("https://attacker.example"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn verify_post_with_neither_origin_nor_referer_is_refused() {
        // Fail closed. A submission with no origin evidence at all is
        // not the consent page.
        let app = authenticated(build_app(enabled_config()));
        let token = consent_form_token(app.clone()).await;
        let (status, _) = post_form_from(
            app,
            "/mcp/oauth/verify",
            &format!("user_code=ABCD-EFGH&action=approve&form_token={token}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_consent_form_token_is_single_use() {
        let app = authenticated(build_app(enabled_config()));
        let token = consent_form_token(app.clone()).await;
        let form = format!("user_code=ZZZZ-ZZZZ&action=approve&form_token={token}");
        let (first, _) = post_form(app.clone(), "/mcp/oauth/verify", &form).await;
        assert_eq!(first, StatusCode::OK, "the token is good once");
        let (second, _) = post_form(app, "/mcp/oauth/verify", &form).await;
        assert_eq!(second, StatusCode::FORBIDDEN, "and not twice");
    }

    #[tokio::test]
    async fn verify_post_marks_state_authorized_then_polled_path_works() {
        // Mint a fresh device_code, then POST /verify with action=approve.
        // The state should flip to Authorized.
        let _env = crate::test_env::EnvVarGuard::set(&[(
            "MCP_GATEWAY_BASE_URL",
            Some("https://broker.example"),
        )]);
        let cfg = enabled_config();
        let store = InMemorySessionStore::arc(Duration::from_secs(60));
        let kv: Arc<dyn EphemeralKv> = Arc::new(MockEphemeralKv::new());
        let dc_store = DeviceCodeStore::arc(kv.clone());
        let app = crate::router_full_with_par(
            Arc::new(cfg),
            store,
            None,
            None,
            None,
            None,
            None,
            Some(dc_store.clone()),
            None,
        );

        // 1. /device_authorization. The config advertises
        // `scopes_supported`, so a supported scope is required here.
        let (status, body) = post_form(
            app.clone(),
            "/mcp/oauth/device_authorization",
            "client_id=cli&scope=read",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let user_code = v["user_code"].as_str().unwrap().to_string();
        let device_code = v["device_code"].as_str().unwrap().to_string();

        // 2. Render the consent page for the signed-in user, then POST
        // the form it produced, the way a browser would.
        let app = authenticated(app);
        let token = consent_form_token(app.clone()).await;
        let body_form = format!(
            "user_code={}&action=approve&form_token={token}",
            urlencode(&user_code)
        );
        let (status, _) = post_form(app, "/mcp/oauth/verify", &body_form).await;
        assert_eq!(status, StatusCode::OK);

        // 3. State should be Authorized.
        let state = dc_store.get(&device_code).await.unwrap().expect("state");
        assert_eq!(state.status, DeviceCodeStatus::Authorized);
        let token = state.authorized_token.unwrap();
        let access_token = token["access_token"].as_str().unwrap();
        assert_ne!(access_token, "device-flow-pending");
        assert_eq!(access_token.split('.').count(), 3);
    }

    #[tokio::test]
    async fn verify_post_requires_an_authenticated_user() {
        let app = build_app(enabled_config());
        let (status, _) = post_form(
            app,
            "/mcp/oauth/verify",
            "user_code=ABCD-EFGH&action=approve",
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn missing_or_unknown_action_never_approves() {
        for action in ["", "&action=unexpected"] {
            let app = build_app(enabled_config());
            // `enabled_config` advertises `scopes_supported`, so device
            // authorization now requires a supported scope. This test is
            // about the verify action, not about scope, so ask for one.
            let (status, body) = post_form(
                app.clone(),
                "/mcp/oauth/device_authorization",
                "client_id=cli&scope=read",
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let issued: serde_json::Value = serde_json::from_str(&body).unwrap();
            let user_code = issued["user_code"].as_str().unwrap();
            let app = authenticated(app);
            let token = consent_form_token(app.clone()).await;
            let form = format!(
                "user_code={}{}&form_token={token}",
                urlencode(user_code),
                action
            );
            let (status, body) = post_form(app, "/mcp/oauth/verify", &form).await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("action must be approve or deny"));
        }
    }

    #[tokio::test]
    async fn verify_post_with_unknown_user_code_returns_error_page() {
        let app = authenticated(build_app(enabled_config()));
        let token = consent_form_token(app.clone()).await;
        let body_form = format!("user_code=ZZZZ-ZZZZ&action=approve&form_token={token}");
        let (status, body) = post_form(app, "/mcp/oauth/verify", &body_form).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("user_code unknown"));
    }

    #[test]
    fn poll_rate_limit_doubles_interval_when_too_fast() {
        let mut state = DeviceCodeState {
            client_id: "c".to_string(),
            scope: None,
            resource: None,
            user_code: "ABCDEFGH".to_string(),
            status: DeviceCodeStatus::Pending,
            authorized_token: None,
            issued_at: 0,
            expires_at: 600,
            interval_secs: 5,
            last_polled_at: Some(100),
        };
        // 100s ago + 5s interval => poll at 102 is too fast.
        let too_fast = apply_poll_rate_limit(&mut state, 102);
        assert!(too_fast);
        assert_eq!(state.interval_secs, 10);
        // A second too-fast poll doubles again.
        state.last_polled_at = Some(102);
        let too_fast = apply_poll_rate_limit(&mut state, 105);
        assert!(too_fast);
        assert_eq!(state.interval_secs, 20);
    }

    #[test]
    fn poll_rate_limit_caps_at_60_seconds() {
        let mut state = DeviceCodeState {
            client_id: "c".to_string(),
            scope: None,
            resource: None,
            user_code: "ABCDEFGH".to_string(),
            status: DeviceCodeStatus::Pending,
            authorized_token: None,
            issued_at: 0,
            expires_at: 600,
            interval_secs: 40,
            last_polled_at: Some(100),
        };
        let too_fast = apply_poll_rate_limit(&mut state, 101);
        assert!(too_fast);
        // 40 doubled to 80, capped at 60.
        assert_eq!(state.interval_secs, SLOW_DOWN_INTERVAL_CAP_SECS);
    }

    #[test]
    fn poll_rate_limit_does_not_trip_when_interval_elapsed() {
        let mut state = DeviceCodeState {
            client_id: "c".to_string(),
            scope: None,
            resource: None,
            user_code: "ABCDEFGH".to_string(),
            status: DeviceCodeStatus::Pending,
            authorized_token: None,
            issued_at: 0,
            expires_at: 600,
            interval_secs: 5,
            last_polled_at: Some(100),
        };
        // 100s ago + 5s interval, poll at 110 => well past.
        let too_fast = apply_poll_rate_limit(&mut state, 110);
        assert!(!too_fast);
        // Interval should NOT double on a well-behaved poll.
        assert_eq!(state.interval_secs, 5);
    }

    #[tokio::test]
    async fn store_round_trip_serializes_state_correctly() {
        let kv: Arc<dyn EphemeralKv> = Arc::new(MockEphemeralKv::new());
        let store = DeviceCodeStore::new(kv);
        let state = DeviceCodeState {
            client_id: "cli".to_string(),
            scope: Some("read write".to_string()),
            resource: Some("https://api.example/r".to_string()),
            user_code: "ABCDEFGH".to_string(),
            status: DeviceCodeStatus::Pending,
            authorized_token: None,
            issued_at: 1000,
            expires_at: 1600,
            interval_secs: 5,
            last_polled_at: None,
        };
        store
            .put("dc1", &state, Duration::from_secs(60))
            .await
            .unwrap();
        let got = store.get("dc1").await.unwrap().unwrap();
        assert_eq!(got.client_id, "cli");
        assert_eq!(got.user_code, "ABCDEFGH");
        // Reverse index resolves.
        let dc = store.resolve_user_code("ABCDEFGH").await.unwrap();
        assert_eq!(dc.as_deref(), Some("dc1"));
        // Cosmetic dashes in the input are ignored by the resolver.
        let dc = store.resolve_user_code("ABCD-EFGH").await.unwrap();
        assert_eq!(dc.as_deref(), Some("dc1"));
    }

    #[test]
    fn device_state_debug_redacts_user_code_and_token() {
        let mut state = pending_state();
        state.user_code = "USER-CODE-CANARY".to_string();
        state.status = DeviceCodeStatus::Authorized;
        state.authorized_token = Some(serde_json::json!({"access_token":"TOKEN-CANARY"}));
        let rendered = format!("{state:?}");
        assert!(!rendered.contains("USER-CODE-CANARY"), "{rendered}");
        assert!(!rendered.contains("TOKEN-CANARY"), "{rendered}");
        assert!(rendered.contains("[REDACTED]"), "{rendered}");
    }

    fn pending_state() -> DeviceCodeState {
        DeviceCodeState {
            client_id: "cli".to_string(),
            scope: Some("tools:call".to_string()),
            resource: Some("https://api.example/r".to_string()),
            user_code: "ABCDEFGH".to_string(),
            status: DeviceCodeStatus::Pending,
            authorized_token: None,
            issued_at: unix_now(),
            expires_at: unix_now() + 600,
            interval_secs: 1,
            last_polled_at: None,
        }
    }

    #[tokio::test]
    async fn denial_is_immutable_and_cannot_be_overwritten_by_approval() {
        let store = DeviceCodeStore::new(Arc::new(MockEphemeralKv::new()));
        store
            .put("dc-atomic", &pending_state(), Duration::from_secs(600))
            .await
            .unwrap();
        assert_eq!(
            store
                .decide("dc-atomic", DeviceDecision::Denied)
                .await
                .unwrap(),
            DeviceDecisionOutcome::Applied
        );
        let outcome = store
            .decide(
                "dc-atomic",
                DeviceDecision::Approved(serde_json::json!({"access_token": "must-not-win"})),
            )
            .await
            .unwrap();
        assert_eq!(
            outcome,
            DeviceDecisionOutcome::AlreadyFinal(DeviceCodeStatus::Denied)
        );
        let state = store.get("dc-atomic").await.unwrap().unwrap();
        assert_eq!(state.status, DeviceCodeStatus::Denied);
        assert!(state.authorized_token.is_none());
    }

    #[tokio::test]
    async fn synchronized_concurrent_redemption_returns_one_token() {
        let store = Arc::new(DeviceCodeStore::new(Arc::new(MockEphemeralKv::new())));
        let mut approved = pending_state();
        approved.status = DeviceCodeStatus::Authorized;
        approved.authorized_token = Some(serde_json::json!({"access_token": "one-token"}));
        store
            .put("dc-redeem", &approved, Duration::from_secs(600))
            .await
            .unwrap();
        let gate = Arc::new(tokio::sync::Barrier::new(3));
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let store = store.clone();
            let gate = gate.clone();
            tasks.push(tokio::spawn(async move {
                gate.wait().await;
                store
                    .poll_and_consume("dc-redeem", "cli", unix_now() + 2)
                    .await
            }));
        }
        gate.wait().await;
        let mut authorized = 0;
        let mut missing = 0;
        for task in tasks {
            match task.await.unwrap().unwrap() {
                DevicePollOutcome::Authorized(state) => {
                    authorized += 1;
                    assert_eq!(state.authorized_token.unwrap()["access_token"], "one-token");
                }
                DevicePollOutcome::Missing => missing += 1,
                other => panic!("unexpected poll outcome: {other:?}"),
            }
        }
        assert_eq!((authorized, missing), (1, 1));
    }

    /// Tiny URL-form encoder for test fixtures.
    fn urlencode(s: &str) -> String {
        s.bytes()
            .flat_map(|b| {
                if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                    vec![b as char]
                } else {
                    format!("%{b:02X}").chars().collect()
                }
            })
            .collect()
    }
}

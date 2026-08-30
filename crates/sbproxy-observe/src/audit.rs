//! Config change + security audit logging.
//!
//! Four channels:
//!
//! * `config_audit` (via [`ConfigAuditEntry::emit`]) - configuration
//!   change events: hot reloads, mesh broadcasts, API-driven origin
//!   updates.
//! * `security_audit` (via [`SecurityAuditEntry::emit`]) - security-
//!   relevant request rejections: HTTP framing violations
//!   (request smuggling defense), policy-driven blocks worth
//!   forwarding to a SIEM. Designed so each channel can be routed
//!   to a dedicated sink (security log into the SOC's alert
//!   pipeline; config audit into the change-management log).
//! * `key_audit` (via [`KeyAuditEntry::emit`]) - key/credential
//!   lifecycle mutations.
//! * `sbproxy::admin::audit` (via [`AdminActionAuditEntry::emit`]) -
//!   authenticated admin-console actions.
//!
//! All four channels also push a normalized copy onto
//! [`crate::audit_ring`], which is a bounded in-memory sample and is
//! explicitly not durable.
//!
//! # What is tamper-evident and what is not
//!
//! A tracing target is a stream, not a record: whoever can write the log
//! file can rewrite it, and nothing downstream can tell. `security_audit`
//! is the one channel that also has a durable, tamper-evident form
//! (WOR-2318). With `audit.sink: chain` set, every
//! [`SecurityAuditEntry`] is additionally appended to a SHA-256
//! hash-chained, Ed25519-signed file that
//! [`crate::audit_chain::verify_security_audit_chain`] and
//! `sbproxy audit verify` re-derive from genesis. Editing one record
//! there breaks its own digest and every link after it.
//!
//! `config_audit` has the same durable form, opt-in on `audit.config_path`.
//! `key_audit` and the admin-console's `sbproxy::admin::audit` target join
//! it too (WOR-2478), opt-in on `audit.key_path` / `audit.admin_path`.
//! `key_audit`'s chained record is not [`KeyAuditEntry`] itself: that type
//! ships a before/after diff of a credential record, and a diff is exactly
//! the field that must never enter a file designed to be impossible to
//! quietly amend. [`KeyAuditChainEntry`] carries the metadata instead, plus
//! a keyed-HMAC-SHA256 fingerprint of each before/after field in place of
//! its value; see that type's docs and [`crate::audit_chain`] for the key.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;

/// A structured record of a single configuration change event.
///
/// `Deserialize` and `Clone` exist so this is a
/// [`sbproxy_meter::ledger::LedgerPayload`]; see [`crate::audit_chain`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigAuditEntry {
    /// RFC 3339 timestamp of the change.
    pub timestamp: String,
    /// Source that triggered the change, e.g. `"file_watcher"`, `"api"`,
    /// or `"mesh_broadcast"`.
    pub source: String,
    /// Hostnames of origins that were added in this update.
    pub origins_added: Vec<String>,
    /// Hostnames of origins that were removed in this update.
    pub origins_removed: Vec<String>,
    /// Hostnames of origins whose configuration was modified in this update.
    pub origins_modified: Vec<String>,
    /// WOR-1067: tenant the audited change resolves to. Empty for
    /// proxy-wide config changes (no tenant scope). Downstream
    /// SIEM / ClickHouse can partition by this field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Operator that performed the change, when it came through an
    /// authenticated admin surface (WOR-2094). Absent for file-watcher
    /// and mesh-broadcast changes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Config revision before the change, when known (WOR-2094).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prior_revision: Option<String>,
    /// Config revision after the change, when known (WOR-2094).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_revision: Option<String>,
    /// Why the reload was refused, when this entry records a rejection
    /// rather than an applied change (WOR-2486). `None` on an accepted
    /// reload. The actual contract this field keeps, and does not, is
    /// on [`Self::with_rejection_reason`]; read it before pointing a
    /// sink at this field that assumes more than that.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
}

impl ConfigAuditEntry {
    /// Serialize the entry to JSON and emit it via tracing at INFO level.
    ///
    /// The record is written to the `config_audit` target so operators can
    /// route it to a dedicated sink independently of the main application log.
    ///
    /// WOR-75: the wall-clock time of one emission lands on the
    /// `sbproxy_audit_emit_duration_seconds{channel="config"}`
    /// histogram with the active trace as exemplar so dashboards can
    /// flag a slow audit sink and hop straight to the originating span.
    /// The `outcome` label is `ok` when JSON serialization succeeds and
    /// the entry reaches the chain (when one is configured),
    /// `serialize_error` when the JSON encode fails, and `chain_error`
    /// when a configured chain rejected the append (in each case the
    /// audit was dropped from that path, which is itself worth
    /// alerting on).
    pub fn emit(&self) {
        let started = std::time::Instant::now();
        let outcome = match serde_json::to_string(self) {
            Ok(json) => {
                tracing::info!(target: "config_audit", "{}", json);
                "ok"
            }
            Err(_) => "serialize_error",
        };
        // WOR-2094: normalized copy for the admin console's runtime
        // sample; the collector remains the durable consumer.
        //
        // WOR-2486: a rejection's detail leads with the reason rather
        // than the same "revision X -> Y" shape an accepted reload
        // gets. Without this, a rejected reload with no revision change
        // and no origin delta rendered as "revision rev-5 -> ?; +0 -0
        // ~0 origins" in the ring, which reads exactly like an
        // accepted no-op reload rather than a refusal.
        let detail = match self.rejection_reason.as_deref() {
            Some(reason) => format!("rejected: {reason}"),
            None => format!(
                "revision {} -> {}; +{} -{} ~{} origins",
                self.prior_revision.as_deref().unwrap_or("?"),
                self.next_revision.as_deref().unwrap_or("?"),
                self.origins_added.len(),
                self.origins_removed.len(),
                self.origins_modified.len(),
            ),
        };
        crate::audit_ring::push_audit_event(crate::audit_ring::AuditRingEvent::new(
            "config",
            self.source.clone(),
            self.actor.clone(),
            self.tenant_id.clone(),
            None,
            None,
            Some(detail),
        ));
        // WOR-2470: the durable, tamper-evident half, on the same terms
        // as the security channel: ordered after the ring and the
        // tracing line because those two are what the running system is
        // watched through and neither should wait on a disk. A `false`
        // here means the entry did not reach the chain it was promised,
        // and folds into the `outcome` label below so that failure is
        // visible on the histogram rather than silent.
        let chain_ok = crate::audit_chain::append_config_audit(self);
        let outcome = if !chain_ok { "chain_error" } else { outcome };
        // WOR-2318: the `events:` egress sees this channel as
        // `config_reloaded`.
        //
        // The variant name is narrower than the channel: a mesh
        // broadcast and an API-driven origin update land here too, and
        // `source` distinguishes them inside `data`. Minting three new
        // variants for one closed enum that consumers already match on
        // exhaustively would be the more expensive answer to a
        // distinction the payload already carries.
        //
        // Every field of this entry is a config fact: which origins
        // moved, which revision to which revision, and the operator name
        // an authenticated admin surface supplied. No config *value* is
        // in here, which matters because a webhook sink ships these
        // bytes off the box and config values are where the credentials
        // live.
        crate::event_sink::publish_proxy_event(crate::events::EventType::ConfigReloaded, || {
            crate::events::ProxyEvent::new(
                crate::events::EventType::ConfigReloaded,
                String::new(),
                self.tenant_id.clone().unwrap_or_default(),
                serde_json::to_value(self).unwrap_or_else(
                    |_| serde_json::json!({ "error": "config audit entry did not serialize" }),
                ),
            )
        });
        crate::metrics::record_audit_emit_duration(
            "config",
            outcome,
            started.elapsed().as_secs_f64(),
        );
    }
}

// --- Helpers ---

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

// --- Security audit channel ---

/// A structured record of a security-relevant request rejection.
/// Emits to the `security_audit` tracing target so SOC tooling can
/// route it separately from operational logs.
///
/// The schema deliberately omits the offending header value; the
/// `reason` discriminator is enough for triage and including
/// attacker-controlled data in a SIEM log would be a poisoning
/// vector. Operators who need the full headers should enable
/// `request_validator` body capture or the proxy's debug body log,
/// which has its own redaction policy.
///
/// Every field here is safe to ship onward, and that is a property this
/// type is required to keep. `api_key_id` is the public id and never the
/// secret, `key_provider` is a label, and nothing carries a token, a
/// header value, or a resolved config value. It matters more than it used
/// to: with `audit.sink: chain` these bytes are appended verbatim to a
/// durable, hash-chained file, so a field that could carry a credential
/// would carry it into a record that is designed to be impossible to
/// quietly remove. Adding a field means answering that question first.
///
/// `Deserialize` and `Clone` exist so this is a
/// [`sbproxy_meter::ledger::LedgerPayload`]; see [`crate::audit_chain`].
/// The consequence is that the serialized shape is on-disk contract for
/// any deployment with the chain turned on: reordering a field or
/// changing a `skip_serializing_if` invalidates entries already written.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityAuditEntry {
    /// RFC 3339 timestamp.
    pub timestamp: String,
    /// Event class. Request refusals use `"framing_violation"` and the
    /// policy / auth labels. Workspace budget transitions use
    /// `"rate_limit_auto_suspend"` and `"rate_limit_resume"` (WOR-2711).
    /// New classes extend this enum-as-string surface.
    pub event_type: String,
    /// Stable machine-readable reason. For framing violations this
    /// is one of `dual_cl_te`, `duplicate_cl`, `malformed_te`,
    /// `duplicate_te`, `control_chars`. Matches the
    /// `sbproxy_http_framing_blocks_total{reason}` metric label
    /// exactly.
    pub reason: String,
    /// Origin hostname the request was destined for (when known).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Client IP address (when known).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    /// Per-request correlation ID (when minted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// HTTP method.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// HTTP status the proxy will return (always `400` for
    /// framing violations today).
    pub status_code: u16,
    /// WOR-1067: tenant the offending request resolves to. Empty
    /// when the request never reached origin routing (early-stage
    /// framing violation, no Host header). Downstream SIEM partitions
    /// by this field for per-tenant deny dashboards.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Recognized native provider label. Never contains credential material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_provider: Option<String>,
    /// Inbound credential mode (`none`, `minted`, or `native`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_mode: Option<String>,
    /// Public id of the key this event is attributed to, when one
    /// resolved. The canonical accountability id, never the secret:
    /// a denial names the key that was denied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_id: Option<String>,
    /// Kind of non-request entity this event targeted, when the event is
    /// a state-machine transition rather than a refused HTTP request.
    /// `"workspace"` for rate-limit budget AutoSuspend / resume
    /// (WOR-2711). Omitted on request-shaped records so existing chained
    /// entries stay byte-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_kind: Option<String>,
    /// Identifier of the targeted entity, when [`Self::target_kind`] is
    /// set. The workspace name for rate-limit budget transitions
    /// (WOR-2711). Secret-free: a workspace id, never a credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
}

impl SecurityAuditEntry {
    /// Build a framing-violation audit entry. Convenience over the
    /// raw struct constructor; future event classes get their own
    /// helpers.
    pub fn framing_violation(
        reason: impl Into<String>,
        hostname: Option<String>,
        client_ip: Option<IpAddr>,
        request_id: Option<String>,
        method: Option<String>,
    ) -> Self {
        Self {
            timestamp: now_rfc3339(),
            event_type: "framing_violation".to_string(),
            reason: reason.into(),
            hostname,
            client_ip: client_ip.map(|ip| ip.to_string()),
            request_id,
            method,
            status_code: 400,
            tenant_id: None,
            key_provider: None,
            key_mode: None,
            api_key_id: None,
            target_kind: None,
            target_id: None,
        }
    }

    /// Build a policy-violation audit entry. `event_type` is the
    /// enforcing policy's stable label (`rate_limit`, `ip_filter`,
    /// `request_limit`, `waf`, `prompt_injection`, `credential_exposure`,
    /// `threat_protection`, `body_threat_protection`, `api_deprecation`,
    /// `ddos`, `concurrent_limit`, `policy`); the
    /// matching `record_policy` Prometheus counter uses the same string.
    /// `api_deprecation` is the one entry with no `policies:` list
    /// equivalent: the `410 Gone` refusal is route lifecycle rather
    /// than a policy, and it lands here because a refusal reaching no
    /// audit channel is not enforcement.
    /// `reason` is a free-form, machine-readable detail (the policy's
    /// deny message, the matched rule id, ...). `status_code` is the
    /// HTTP status the proxy returns to the client.
    pub fn policy_violation(
        event_type: impl Into<String>,
        reason: impl Into<String>,
        status_code: u16,
        hostname: Option<String>,
        client_ip: Option<IpAddr>,
        request_id: Option<String>,
        method: Option<String>,
    ) -> Self {
        Self {
            timestamp: now_rfc3339(),
            event_type: event_type.into(),
            reason: reason.into(),
            hostname,
            client_ip: client_ip.map(|ip| ip.to_string()),
            request_id,
            method,
            status_code,
            tenant_id: None,
            key_provider: None,
            key_mode: None,
            api_key_id: None,
            target_kind: None,
            target_id: None,
        }
    }

    /// Build an auth-failure audit entry. `event_type` is one of the
    /// closed strings `auth_denied`, `auth_denied_with_headers`,
    /// `auth_digest_challenge`, `forward_auth_denied` so SIEM rules can
    /// route by failure mode. `reason` carries the auth scheme that
    /// rejected the request (`api_key`, `jwt`, `oauth`, ...).
    pub fn auth_failure(
        event_type: impl Into<String>,
        auth_type: impl Into<String>,
        status_code: u16,
        hostname: Option<String>,
        client_ip: Option<IpAddr>,
        request_id: Option<String>,
        method: Option<String>,
    ) -> Self {
        Self {
            timestamp: now_rfc3339(),
            event_type: event_type.into(),
            reason: auth_type.into(),
            hostname,
            client_ip: client_ip.map(|ip| ip.to_string()),
            request_id,
            method,
            status_code,
            tenant_id: None,
            key_provider: None,
            key_mode: None,
            api_key_id: None,
            target_kind: None,
            target_id: None,
        }
    }

    /// Build a workspace rate-limit budget transition (WOR-2711).
    ///
    /// `event_type` is `"rate_limit_auto_suspend"` or `"rate_limit_resume"`.
    /// `target_id` is the workspace the budget keyed on. Request-shaped
    /// fields stay empty: this is a state-machine transition, not a
    /// refused HTTP request. Status is 429 on AutoSuspend and 200 on
    /// resume. `tenant_id` repeats the workspace so existing SIEM
    /// partitions still see it.
    pub fn rate_limit_budget_transition(
        event_type: impl Into<String>,
        reason: impl Into<String>,
        target_id: impl Into<String>,
    ) -> Self {
        let event_type = event_type.into();
        let target_id = target_id.into();
        let status_code = if event_type == "rate_limit_resume" {
            200
        } else {
            429
        };
        Self {
            timestamp: now_rfc3339(),
            event_type,
            reason: reason.into(),
            hostname: None,
            client_ip: None,
            request_id: None,
            method: None,
            status_code,
            tenant_id: Some(target_id.clone()),
            key_provider: None,
            key_mode: None,
            api_key_id: None,
            target_kind: Some("workspace".to_string()),
            target_id: Some(target_id),
        }
    }

    /// WOR-1067: builder-style setter for the tenant id. Returns
    /// `self` so call sites can chain `SecurityAuditEntry::policy_violation(...).with_tenant_id(ctx.tenant_id.to_string())`.
    pub fn with_tenant_id(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Stamp the request's credential classification without retaining the
    /// credential itself.
    pub fn with_key_context(
        mut self,
        key_provider: Option<impl Into<String>>,
        key_mode: impl Into<String>,
    ) -> Self {
        self.key_provider = key_provider.map(Into::into);
        self.key_mode = Some(key_mode.into());
        self
    }

    /// Name the key this event is attributed to (WOR-2093). Takes the
    /// canonical public id; a denial that resolved a key names it so
    /// the SIEM can pivot from the event to the credential.
    pub fn with_api_key_id(mut self, api_key_id: Option<impl Into<String>>) -> Self {
        self.api_key_id = api_key_id.map(Into::into);
        self
    }

    /// Serialize the entry to JSON and emit it via tracing at WARN
    /// level. WARN (not INFO) so default subscribers surface
    /// security events in operational dashboards while still
    /// letting downstream SIEM filter by target.
    ///
    /// WOR-75: the wall-clock time of one emission lands on the
    /// `sbproxy_audit_emit_duration_seconds{channel="security"}`
    /// histogram with the active trace as exemplar. The `outcome`
    /// label is `ok` on success, `serialize_error` if the JSON encode
    /// fails, and `chain_error` if a configured chain rejected the
    /// append (in each case the audit was dropped from that path).
    ///
    /// WOR-2318: when `audit.sink: chain` is configured the same entry is
    /// also appended to the hash-chained, Ed25519-signed file at
    /// `audit.path`. That append happens inside the measured region on
    /// purpose, so a chain whose disk has gone slow shows up on the
    /// histogram that already exists for exactly this question rather than
    /// needing a second one. With no chain installed the extra cost is one
    /// relaxed load of a `OnceLock`.
    pub fn emit(&self) {
        let started = std::time::Instant::now();
        let outcome = match serde_json::to_string(self) {
            Ok(json) => {
                tracing::warn!(target: "security_audit", "{}", json);
                "ok"
            }
            Err(_) => "serialize_error",
        };
        // WOR-2094: normalized copy for the admin console's runtime
        // sample; the collector remains the durable consumer.
        crate::audit_ring::push_audit_event(crate::audit_ring::AuditRingEvent::new(
            "security",
            self.event_type.clone(),
            None,
            self.tenant_id.clone(),
            self.api_key_id.clone(),
            self.request_id.clone(),
            Some(self.reason.clone()),
        ));
        // WOR-2318: the durable, tamper-evident half. Ordered after the
        // ring and the tracing line because those two are what the running
        // system is watched through and neither should wait on a disk.
        // WOR-2478: the append result folds into `outcome` below, so a
        // chain that will not take the entry is visible on the histogram
        // rather than silently discarded.
        let chain_ok = crate::audit_chain::append_security_audit(self);
        let outcome = if !chain_ok { "chain_error" } else { outcome };
        // WOR-2318: and the egress half. Last, and outside anything that
        // can block: this is a bitmask test and a `try_send` when an
        // `events:` sink is configured, one relaxed load when it is not.
        self.publish_to_event_egress();
        crate::metrics::record_audit_emit_duration(
            "security",
            outcome,
            started.elapsed().as_secs_f64(),
        );
    }

    /// Which [`crate::events::EventType`] this entry is, for the
    /// `events:` egress.
    ///
    /// `event_type` here is an open string; the egress filter is a closed
    /// enum of thirteen. The split follows what a SIEM rule would route on:
    /// the four values [`Self::auth_failure`] documents are the
    /// credential ones, and everything else that reaches this channel
    /// (framing violations plus every policy label
    /// [`Self::policy_violation`] lists) is the proxy refusing a request
    /// on a rule.
    ///
    /// The prefix test rather than an exact match is deliberate:
    /// `auth_denied_with_headers` and `auth_digest_challenge` are auth
    /// outcomes and a new `auth_*` value should not silently become a
    /// policy denial in somebody's dashboard.
    fn egress_event_type(&self) -> crate::events::EventType {
        let is_auth =
            self.event_type.starts_with("auth_") || self.event_type.starts_with("forward_auth_");
        if is_auth {
            crate::events::EventType::AuthDenied
        } else {
            crate::events::EventType::PolicyDenied
        }
    }

    /// Hand this entry to the `events:` egress, if one is configured and
    /// selects its type.
    ///
    /// The whole entry becomes the event's `data`, unchanged. That is
    /// safe for exactly the reason the hash chain is safe to write it:
    /// this type is documented and reviewed as secret-free, `api_key_id`
    /// is the public id, `key_provider` is a label, and no field carries
    /// a token, a header value, or a resolved config value. A webhook
    /// sink puts these bytes on a third-party endpoint, so a field added
    /// to the struct without answering that question leaks to two places
    /// now rather than one.
    fn publish_to_event_egress(&self) {
        crate::event_sink::publish_proxy_event(self.egress_event_type(), || {
            crate::events::ProxyEvent::new(
                self.egress_event_type(),
                self.hostname.clone().unwrap_or_default(),
                self.tenant_id.clone().unwrap_or_default(),
                serde_json::to_value(self).unwrap_or_else(|_| {
                    // Infallible for this struct's field types. If it
                    // ever is not, an event that says so beats an event
                    // that never arrives.
                    serde_json::json!({ "error": "security audit entry did not serialize" })
                }),
            )
        });
    }
}

impl ConfigAuditEntry {
    /// Convenience constructor that fills in the current timestamp automatically.
    pub fn new(
        source: impl Into<String>,
        origins_added: Vec<String>,
        origins_removed: Vec<String>,
        origins_modified: Vec<String>,
    ) -> Self {
        Self {
            timestamp: now_rfc3339(),
            source: source.into(),
            origins_added,
            origins_removed,
            origins_modified,
            tenant_id: None,
            actor: None,
            prior_revision: None,
            next_revision: None,
            rejection_reason: None,
        }
    }

    /// WOR-1067: builder-style setter for the tenant id. Returns
    /// `self` so call sites can chain
    /// `ConfigAuditEntry::new(...).with_tenant_id("acme")`.
    pub fn with_tenant_id(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Attach the operator that performed the change (WOR-2094).
    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    /// Attach the revision pair the change moved between (WOR-2094).
    pub fn with_revisions(
        mut self,
        prior: Option<impl Into<String>>,
        next: Option<impl Into<String>>,
    ) -> Self {
        self.prior_revision = prior.map(Into::into);
        self.next_revision = next.map(Into::into);
        self
    }

    /// Attach the reason a reload was refused (WOR-2486).
    ///
    /// The honest contract, not the aspirational one: `reason` is
    /// **bounded** to 512 bytes here, the same ceiling `RedactedReason`
    /// uses on the decision-audit side, and this record ships to the
    /// same third-party sinks `events:` does. It is **not** scrubbed
    /// of config content in general. A compile or validation error
    /// routinely echoes a fragment of the document it is complaining
    /// about, an invalid CEL expression, an unrecognized key, an
    /// origin hostname, because naming the offending fragment is how a
    /// validation error explains itself; nothing here tells that fragment
    /// apart from ordinary error prose.
    ///
    /// The one thing callers are expected to scrub before this is
    /// called is the config **path**: `crate::path_redact` (in
    /// `sbproxy-core`) strips the filesystem path a reload was told to
    /// read out of the error text first, because that path is this
    /// node's local layout and every call site knows it in advance. A
    /// resolved secret should not appear either, by the convention
    /// every secret-reference resolver in this codebase already
    /// follows (report the unresolved reference, never the value), but
    /// that convention lives in the resolvers, not enforced here: this
    /// function performs no content inspection of its own. If your
    /// threat model needs a stronger guarantee than "bounded, path-
    /// scrubbed, and secrets-by-convention", read the reason before
    /// wiring a sink you do not already trust with your config's shape.
    pub fn with_rejection_reason(mut self, reason: impl AsRef<str>) -> Self {
        self.rejection_reason = Some(sbproxy_util::truncate_utf8(reason.as_ref(), 512).to_owned());
        self
    }
}

// --- Key-management audit channel (WOR-1557) ---

/// A structured record of a single key or credential mutation.
///
/// Emitted on the `key_audit` target for every create / update / delete /
/// revoke / block / unblock / rotate so an operator can route key-lifecycle
/// changes to a dedicated sink and reconstruct who changed what. The record
/// carries the public `id` and a before/after diff, never a plaintext secret,
/// a hash, or an envelope. The diff is the seam the verifiable ledger
/// (WOR-1539) hash-chains downstream.
#[derive(Debug, Serialize)]
pub struct KeyAuditEntry {
    /// RFC 3339 timestamp of the mutation.
    pub timestamp: String,
    /// The operation: `create`, `update`, `delete`, `revoke`, `block`,
    /// `unblock`, or `rotate`.
    pub op: String,
    /// The resource kind: `key` or `credential`.
    pub resource: String,
    /// The public record id (key_id or credential id). Never a secret.
    pub id: String,
    /// The principal that performed the mutation, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Tenant the record belongs to, when scoped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Redacted snapshot of the record before the mutation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<serde_json::Value>,
    /// Redacted snapshot of the record after the mutation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<serde_json::Value>,
    /// What happened: `applied` for a mutation, or for a `resolve` record
    /// `ok`, `refused`, or `error` (WOR-2570). Passed through in the clear,
    /// never fingerprinted: an outcome is not an identifier, and a trail
    /// whose outcomes are all opaque hashes tells an investigator nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    /// Bounded, non-secret context for the record: which cache layer
    /// answered a resolution, which fingerprint epoch an HMAC'd `id` was
    /// computed under, or the break-glass grant an admin action ran under
    /// (WOR-2570, WOR-2573). Truncated to 256 bytes. Never a secret, a
    /// header value, a payload, or a URL with userinfo.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

/// The durable half of a key/credential mutation (WOR-2478).
///
/// Carries every metadata field [`KeyAuditEntry`] does - `timestamp`,
/// `op`, `resource`, `id`, `actor`, `tenant_id` - and nothing that field
/// list did not already promise was secret-free. In place of `before` /
/// `after` it carries a keyed-HMAC-SHA256 fingerprint of each field the
/// snapshot named, so a chain reader can tell that two mutations set the
/// same field to the same value without the chain file ever holding that
/// value; see `crate::audit_chain::fingerprint_key_audit_snapshot` for
/// how a fingerprint is computed and the key it runs under.
///
/// `Deserialize` and `Clone` exist so this is a
/// [`sbproxy_meter::ledger::LedgerPayload`]; see [`crate::audit_chain`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyAuditChainEntry {
    /// RFC 3339 timestamp of the mutation.
    pub timestamp: String,
    /// The operation: `create`, `update`, `delete`, `revoke`, `block`,
    /// `unblock`, or `rotate`.
    pub op: String,
    /// The resource kind: `key` or `credential`.
    pub resource: String,
    /// The public record id (key_id or credential id). Never a secret.
    pub id: String,
    /// The principal that performed the mutation, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Tenant the record belongs to, when scoped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// A short, non-secret tag identifying which fingerprint key produced
    /// this record's fingerprints: `hex(HMAC(derived_key, b"epoch"))[..8]`
    /// (WOR-2478 I4). An ephemeral master key (no
    /// `key_management.crypto.master_key` configured) re-derives a fresh
    /// fingerprint key on every boot, and a rotated one re-derives on the
    /// next; either silently re-bases every fingerprint that follows.
    /// Two records with different `key_epoch` values were fingerprinted
    /// under different keys, and their fingerprints must never be
    /// compared for equality. Empty before a fingerprint key has been
    /// installed, in step with `before_fingerprint` / `after_fingerprint`
    /// also being empty under the same condition.
    pub key_epoch: String,
    /// Before-mutation field fingerprints, keyed by the field's own name
    /// when that name is on the closed key-audit field-name allowlist, or
    /// by the field name's own keyed fingerprint (prefixed `f:`)
    /// otherwise (WOR-2478 I3/M6) - a caller-supplied field name never
    /// lands verbatim in this map unless it was reviewed onto the
    /// allowlist first. Each value is a keyed-HMAC-SHA256 fingerprint,
    /// hex, that also binds the field's own name, so two different
    /// fields set to the same value fingerprint differently. Empty when
    /// the mutation carried no `before` snapshot, or no fingerprint key
    /// has been installed yet.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub before_fingerprint: BTreeMap<String, String>,
    /// The same, for the value after the mutation.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub after_fingerprint: BTreeMap<String, String>,
    /// The outcome, in the clear. See [`KeyAuditEntry::outcome`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    /// Bounded non-secret context, in the clear. See
    /// [`KeyAuditEntry::context`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

// --- Admin-action audit channel (WOR-2478) ---

/// A structured record of one authenticated admin-console action.
///
/// Not what performs the `sbproxy::admin::audit` tracing emission itself:
/// each of the four call sites in `crates/sbproxy-core/src/admin.rs`
/// independently logs to that tracing target immediately before building
/// one of these (WOR-2094's original ring-push shape), and this type
/// carries the same fact onward rather than duplicating the log line.
/// [`Self::emit`] pushes a normalized copy onto the shared audit ring
/// and, if a chain is installed, appends it to the durable admin chain
/// (WOR-2478). Every field here is what the audit ring's
/// `AuditRingEvent` already carries for the `admin` channel: the
/// operator, the tenant, the public key id (never the secret), a request
/// correlation id, and a bounded free-text `detail` (an HTTP method and
/// path, or a role label; never a header value or a credential). Chained
/// verbatim, the same as [`SecurityAuditEntry`] and [`ConfigAuditEntry`]:
/// nothing here needs the fingerprinting [`KeyAuditChainEntry`] does.
///
/// `Deserialize` and `Clone` exist so this is a
/// [`sbproxy_meter::ledger::LedgerPayload`]; see [`crate::audit_chain`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminActionAuditEntry {
    /// RFC 3339 timestamp.
    pub timestamp: String,
    /// The admin action: `admin_action`, `login`, `login_failed`,
    /// `inspect_request_content`, `read_audit_chain`, or
    /// `read_audit_chain_denied`.
    ///
    /// The last two are reads rather than mutations, and they are here for
    /// the reason Vault audits its own audit reads: "who looked at the
    /// trail, and who was refused it" is a question an investigator asks
    /// about the investigation itself, and it can only be answered if the
    /// looking was recorded at the time.
    pub action: String,
    /// The operator username, when the request resolved one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Tenant scope, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Public key id the action is attributed to, when one resolved.
    /// Never the secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_id: Option<String>,
    /// Request correlation id, when the action is request-scoped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Bounded, machine-readable detail: an HTTP method and path, or a
    /// role label. Capped in [`Self::new`] by the same
    /// `crate::audit_ring::bound_detail` helper the ring itself caps
    /// `AuditRingEvent::detail` with (WOR-2478 I5), so the ring's copy
    /// and the chain's copy of one action are never capped at two
    /// different lengths.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl AdminActionAuditEntry {
    /// Build an entry for `action`, stamped now. `detail` is bounded the
    /// same way `AuditRingEvent::new` bounds it (WOR-2478 I5): both the
    /// ring and the chain carry the same capped value for one action
    /// rather than the ring silently disagreeing with what got chained.
    pub fn new(
        action: impl Into<String>,
        actor: Option<String>,
        tenant_id: Option<String>,
        api_key_id: Option<String>,
        request_id: Option<String>,
        detail: Option<String>,
    ) -> Self {
        Self {
            timestamp: now_rfc3339(),
            action: action.into(),
            actor,
            tenant_id,
            api_key_id,
            request_id,
            detail: detail.map(|d| crate::audit_ring::bound_detail(&d)),
        }
    }

    /// Push a normalized copy onto the shared audit ring (WOR-2094,
    /// unchanged shape) and append the same record to the admin audit
    /// chain, if one is installed (WOR-2478).
    pub fn emit(&self) {
        let started = std::time::Instant::now();
        crate::audit_ring::push_audit_event(crate::audit_ring::AuditRingEvent::new(
            "admin",
            self.action.clone(),
            self.actor.clone(),
            self.tenant_id.clone(),
            self.api_key_id.clone(),
            self.request_id.clone(),
            self.detail.clone(),
        ));
        let chain_ok = crate::audit_chain::append_admin_audit(self);
        let outcome = if chain_ok { "ok" } else { "chain_error" };
        // WOR-2572: the dedicated audit-write-failure counter, fed from
        // the same real append result the histogram's outcome label
        // folds in. Touches the series on success too, so a healthy
        // channel exports an explicit 0. `admin_path` is the console
        // action trail, not a key-management channel, which is why the
        // family is `sbproxy_audit_write_failures_total` rather than
        // being named for the key plane.
        crate::metrics::record_audit_write_outcome("admin_path", chain_ok);
        crate::metrics::record_audit_emit_duration(
            "admin",
            outcome,
            started.elapsed().as_secs_f64(),
        );
    }
}

impl KeyAuditEntry {
    /// Start an entry for `op` on a `resource` with public `id`, stamped now.
    pub fn new(op: impl Into<String>, resource: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            timestamp: now_rfc3339(),
            op: op.into(),
            resource: resource.into(),
            id: id.into(),
            actor: None,
            tenant_id: None,
            before: None,
            after: None,
            outcome: None,
            context: None,
        }
    }

    /// Attach the acting principal.
    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    /// Attach the outcome, in the clear (WOR-2570).
    pub fn with_outcome(mut self, outcome: impl Into<String>) -> Self {
        self.outcome = Some(outcome.into());
        self
    }

    /// Attach bounded, non-secret context, in the clear (WOR-2570).
    ///
    /// Truncated to 256 bytes here rather than at each call site, so a
    /// later caller cannot widen it by forgetting to.
    pub fn with_context(mut self, context: impl AsRef<str>) -> Self {
        self.context = Some(sbproxy_util::truncate_utf8(context.as_ref(), 256).to_owned());
        self
    }

    /// Attach the owning tenant.
    pub fn with_tenant_id(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Attach the before/after redacted snapshots for the change diff.
    pub fn with_diff(
        mut self,
        before: Option<serde_json::Value>,
        after: Option<serde_json::Value>,
    ) -> Self {
        self.before = before;
        self.after = after;
        self
    }

    /// Serialize and emit on the `key_audit` tracing target at INFO level.
    ///
    /// Also pushes a normalized copy onto the in-memory audit ring so
    /// the admin console can show the mutation without collector
    /// wiring (WOR-2094), and appends the durable half to the key audit
    /// chain, if one is installed (WOR-2478). The tracing line and the
    /// ring keep the raw `before`/`after` diff exactly as before; the
    /// chain never sees it. See [`KeyAuditChainEntry`].
    ///
    /// The `outcome` label folds in the chain append result the same way
    /// [`ConfigAuditEntry::emit`] and [`SecurityAuditEntry::emit`] do:
    /// `ok` on success, `serialize_error` when the tracing JSON encode
    /// fails, `chain_error` when a configured key chain rejected the
    /// append.
    ///
    /// WOR-2478 M8: the [`KeyAuditChainEntry`] itself - the fingerprint
    /// maps and the epoch tag - is only built when a key chain is
    /// actually installed. `append_key_audit` already treats an
    /// uninstalled chain as a no-op, but computing an HMAC per
    /// before/after field on every mutation to build an entry that would
    /// only be discarded is not free; a deployment that never set
    /// `audit.key_path` pays one relaxed load of a `OnceLock` here and
    /// nothing more, the same posture the other three channels already
    /// have with no chain configured.
    pub fn emit(&self) {
        let started = std::time::Instant::now();
        let outcome = match serde_json::to_string(self) {
            Ok(json) => {
                tracing::info!(target: "key_audit", "{}", json);
                "ok"
            }
            Err(_) => "serialize_error",
        };
        crate::audit_ring::push_audit_event(crate::audit_ring::AuditRingEvent::new(
            "key",
            self.op.clone(),
            self.actor.clone(),
            self.tenant_id.clone(),
            Some(self.id.clone()),
            None,
            Some(match (&self.before, &self.after, &self.outcome) {
                (Some(before), Some(after), _) => {
                    format!("{}: {before} -> {after}", self.resource)
                }
                // WOR-2570: a `resolve` record carries no diff, so the
                // outcome is what the console has to show instead of a
                // bare resource name.
                (_, _, Some(outcome)) => format!("{}: {outcome}", self.resource),
                _ => self.resource.clone(),
            }),
        ));
        // WOR-2478: the durable half. Metadata only, plus a keyed-HMAC
        // fingerprint of each before/after field; the raw diff never
        // reaches the chain. Built only when a chain is installed (M8).
        let chain_ok = if crate::audit_chain::key_audit_chain_installed() {
            let chain_entry = KeyAuditChainEntry {
                timestamp: self.timestamp.clone(),
                op: self.op.clone(),
                resource: self.resource.clone(),
                id: self.id.clone(),
                actor: self.actor.clone(),
                tenant_id: self.tenant_id.clone(),
                key_epoch: crate::audit_chain::key_audit_fingerprint_epoch(),
                before_fingerprint: crate::audit_chain::fingerprint_key_audit_snapshot(
                    self.before.as_ref(),
                ),
                after_fingerprint: crate::audit_chain::fingerprint_key_audit_snapshot(
                    self.after.as_ref(),
                ),
                outcome: self.outcome.clone(),
                context: self.context.clone(),
            };
            crate::audit_chain::append_key_audit(&chain_entry)
        } else {
            true
        };
        let outcome = if !chain_ok { "chain_error" } else { outcome };
        // WOR-2572: the dedicated audit-write-failure counter. `ok` here
        // means every sink this emission was promised was reached: the
        // tracing serialize succeeded AND a configured chain accepted
        // the append. Sourced from those real results, never a default.
        crate::metrics::record_audit_write_outcome("key_path", outcome == "ok");
        // WOR-2571: the `events:` egress sees the four alertable
        // lifecycle operations as typed events (`key_minted`,
        // `key_revoked`, `key_rotated`, `key_blocked`), the same bridge
        // shape `ConfigAuditEntry::emit` uses for `config_reloaded`.
        // Bridging here rather than at each admin route makes the SIEM
        // feed exactly as wide as the `key_audit` channel for the
        // mapped operations: a mutation cannot reach the chain and
        // miss the feed. The payload is the allowlist
        // [`key_lifecycle_event`] builds, never this entry's raw
        // before/after diff.
        //
        // The bridge is unconditional on the write outcome above, and
        // deliberately so: a chain that rejected the append is exactly
        // when the SIEM copy matters most. The counter reports the
        // durability hole, the feed still carries the mutation.
        if let Some(event_type) = key_lifecycle_event_type(&self.op) {
            // WOR-2596: the same allowlisted payload, once, feeding two
            // consumers. Built here rather than inside the publish
            // closure because the CEF line needs the sequence number the
            // JSON payload carries, and building it twice would hand the
            // two copies different sequence numbers, which is worse than
            // having no sequence at all: a receiver correlating them
            // would see a hole in each.
            // Neither consumer configured means neither pays. The
            // sequence number is drawn inside `key_lifecycle_event`, so
            // building it for nobody would also burn sequence numbers a
            // receiver would then read as holes.
            let cef_wanted = tracing::event_enabled!(target: "key_audit_cef", tracing::Level::INFO);
            if cef_wanted || crate::event_sink::wants_event(event_type) {
                let event = key_lifecycle_event(self, event_type);
                if cef_wanted {
                    // A flattened copy for a SIEM that cannot take JSON.
                    // ArcSight CEF, the form Vault's own audit device
                    // emits, on its own tracing target so a deployment
                    // routes it (or does not) with the logging config it
                    // already has.
                    tracing::info!(target: "key_audit_cef", "{}", key_event_to_cef(&event));
                }
                crate::event_sink::publish_proxy_event(event_type, move || event);
            } else {
                crate::notify::wants(event_type.as_str()).then(|| {
                    crate::event_sink::publish_proxy_event(event_type, || {
                        key_lifecycle_event(self, event_type)
                    })
                });
            }
        }
        crate::metrics::record_audit_emit_duration("key", outcome, started.elapsed().as_secs_f64());
    }
}

/// The typed [`crate::events::EventType`] a key/credential lifecycle
/// operation bridges to on the `events:` egress, or `None` for an
/// operation the SIEM feed does not carry (WOR-2571).
///
/// The mapping is by operation, not by resource: `revoke` on a key and
/// `revoke` on an upstream credential both bridge to `key_revoked`,
/// with the payload's `resource` field telling the two apart. That is
/// deliberate, and it is what a SIEM rule shaped like "alert when a
/// credential is revoked" needs; minting a second five-variant family
/// for credentials would double the closed set to say the same four
/// things.
///
/// `update`, `delete`, and `unblock` map to `None` on purpose, and so
/// do the three budget-override ops (`budget_override_grant`,
/// `budget_override_clear`, `budget_override_expire`). They stay on the
/// `key_audit` channel (the tracing target, the admin ring, and the
/// hash chain when `audit.key_path` is set), which records every
/// mutation; the typed feed carries the four operations the WOR-2571
/// alerting surface names. `credential_resolved`, the fifth type, is
/// not minted here at all: it is a read, not a mutation, and publishes
/// from the resolution path in `sbproxy-core`.
///
/// So the honest scope of this feed is "key existence and key
/// authority", not "key mutations". Raising a spending ceiling for a
/// day reaches `key_audit`, the admin ring, and the hash chain and does
/// not reach the typed feed, exactly as editing `max_budget_usd`
/// durably through `update` already does not. Widening it is a
/// deliberate decision about the closed `EventType` set rather than an
/// oversight to patch per feature; a budget event would want its own
/// type and the same explicit payload allowlist
/// [`key_lifecycle_event`] uses, and would have to exclude `reason`,
/// which is free operator text bound for a webhook.
fn key_lifecycle_event_type(op: &str) -> Option<crate::events::EventType> {
    match op {
        "create" => Some(crate::events::EventType::KeyMinted),
        "revoke" => Some(crate::events::EventType::KeyRevoked),
        "rotate" => Some(crate::events::EventType::KeyRotated),
        "block" => Some(crate::events::EventType::KeyBlocked),
        _ => None,
    }
}

/// Build the typed event for one key/credential lifecycle mutation
/// (WOR-2571).
///
/// The payload is an explicit allowlist, not a serialization of the
/// entry: `op`, `resource`, the public `id`, `outcome`, the acting
/// principal when known, the owning tenant, and, when the mutation
/// carried a status diff, the closed-vocabulary `prior_status` /
/// `new_status` labels. Nothing else crosses. In particular the
/// `before`/`after` snapshots do not pass through as values: the chain
/// fingerprints them rather than carrying them (see
/// [`KeyAuditChainEntry`]), and a webhook sink ships these bytes off
/// the box, so the SIEM copy carries strictly less than the local
/// record, never more. This is Vault's `audit_non_hmac_request_keys`
/// posture read in reverse, and the qualifier matters: Vault HMACs
/// everything and exempts a named list, while this carries a named
/// list in the clear and withholds the rest. Same end state, opposite
/// mechanism. Named non-secret fields cross by exception; everything
/// unnamed is withheld rather than hashed.
///
/// `outcome` is always `applied` today because [`KeyAuditEntry::emit`]
/// runs only after the store accepted the mutation; refusals are owned
/// by the key-plane refusal surface (WOR-2567), not this event.
fn key_lifecycle_event(
    entry: &KeyAuditEntry,
    event_type: crate::events::EventType,
) -> crate::events::ProxyEvent {
    let mut data = serde_json::json!({
        "op": entry.op,
        "resource": entry.resource,
        "id": entry.id,
        "outcome": "applied",
    });
    if let Some(actor) = &entry.actor {
        data["actor"] = serde_json::json!(actor);
    }
    let status_of = |snapshot: Option<&serde_json::Value>| {
        snapshot
            .and_then(|snapshot| snapshot.get("status"))
            .and_then(|status| status.as_str())
            .map(str::to_owned)
    };
    if let Some(prior) = status_of(entry.before.as_ref()) {
        data["prior_status"] = serde_json::json!(prior);
    }
    if let Some(new) = status_of(entry.after.as_ref()) {
        data["new_status"] = serde_json::json!(new);
    }
    // WOR-2596: the per-(instance, tenant) gapless sequence WOR-2384
    // already built for `mcp_governance_decision`, applied to this
    // family. The argument for it is the same one and worth restating:
    // the local Ed25519 audit chain's signing key sits in the same
    // process that writes the rows, so a consumer that only has the
    // chain is trusting this process about this process. A sequence hole
    // is detectable by the receiver with no help from here, which is a
    // different and weaker-but-independent check.
    //
    // The feed is still a lossy real-time copy and `docs/events.md` still
    // says so. What changes is that a loss is now *visible* rather than
    // indistinguishable from quiet.
    let tenant = entry.tenant_id.clone().unwrap_or_default();
    // Namespaced, not the bare tenant. `evidence_seq` keys its counters by
    // the string it is given, and `mcp_governance_decision` already draws
    // on the bare tenant id. Sharing one counter between two event
    // families would give neither family a gapless sequence of its own: a
    // SIEM rule filtered to `key_revoked` would see 3, 7, 12 and read two
    // holes that are not holes, which is worse than carrying no sequence
    // at all. The prefix costs one map entry per (family, tenant) against
    // `MAX_TRACKED_TENANTS` and buys the property the field claims.
    data["sbproxy.evidence.seq"] = serde_json::json!(crate::evidence_seq::next_seq(&format!(
        "key_lifecycle/{tenant}"
    )));
    data["sbproxy.evidence.instance"] = serde_json::json!(crate::instance::instance_id());
    crate::events::ProxyEvent::new(event_type, String::new(), tenant, data)
}

/// Render one key-lifecycle event as an ArcSight Common Event Format
/// line (WOR-2596).
///
/// # Why CEF, and why not LEEF
///
/// The ticket asked for both. CEF ships here and LEEF does not, and that
/// is a decision rather than an omission. CEF is what HashiCorp Vault's
/// own audit device emits natively, and it is the flattened form
/// ArcSight, Splunk, and QRadar all have a supported ingest path for.
/// LEEF is IBM QRadar's own format, and QRadar reads CEF; shipping both
/// would double the field-mapping surface, and every mapping is a place
/// where a later field addition can silently stop crossing, in exchange
/// for a second path to one vendor that already has one. If a deployment
/// turns up that genuinely cannot read CEF, LEEF is a small addition on
/// top of this function's extension map.
///
/// # Shape
///
/// `CEF:0|Soap Bucket|sbproxy|<version>|<signature>|<name>|<severity>|<extensions>`
///
/// The seven pipe-delimited header fields are fixed by the format. The
/// extension map carries `rt` (event time), `suser` (the acting
/// principal), `outcome`, `duid` (the record id), and `cs1`/`cs2` with
/// their required `cs1Label`/`cs2Label` partners, which is CEF's only
/// sanctioned way to carry a field the standard does not name.
///
/// Severity follows the operation's meaning rather than a constant:
/// revocation and blocking are the two an analyst wants surfacing above
/// a mint, because they are what a compromise response looks like.
///
/// # Escaping
///
/// CEF escapes `\` and `|` in header fields, and `\` and `=` in extension
/// values. Getting this wrong does not merely garble a line: an
/// unescaped `=` inside a value splits one extension into two, which is
/// how a field an attacker controls becomes a field an attacker
/// *injects*. Every value here is either a closed vocabulary or an
/// operator-supplied id, and the ids are escaped rather than trusted.
pub(crate) fn key_event_to_cef(event: &crate::events::ProxyEvent) -> String {
    let data = &event.data;
    let field = |name: &str| -> Option<String> {
        data.get(name)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };
    let op = field("op").unwrap_or_default();
    let resource = field("resource").unwrap_or_default();
    let signature = format!("sbproxy.key.{op}");
    let name = format!("{resource} {op}");
    let severity = match op.as_str() {
        "revoke" => 7,
        "block" => 6,
        "rotate" => 4,
        _ => 3,
    };
    let mut extensions = vec![
        format!("rt={}", event.timestamp),
        format!(
            "outcome={}",
            cef_extension_escape(&field("outcome").unwrap_or_default())
        ),
        format!(
            "duid={}",
            cef_extension_escape(&field("id").unwrap_or_default())
        ),
        "cs1Label=resource".to_string(),
        format!("cs1={}", cef_extension_escape(&resource)),
    ];
    if let Some(actor) = field("actor") {
        extensions.push(format!("suser={}", cef_extension_escape(&actor)));
    }
    if !event.tenant_id.is_empty() {
        extensions.push("cs2Label=tenant".to_string());
        extensions.push(format!("cs2={}", cef_extension_escape(&event.tenant_id)));
    }
    if let Some(seq) = data.get("sbproxy.evidence.seq").and_then(|v| v.as_u64()) {
        extensions.push("cn1Label=evidenceSeq".to_string());
        extensions.push(format!("cn1={seq}"));
    }
    if let Some(instance) = field("sbproxy.evidence.instance") {
        extensions.push("cs3Label=evidenceInstance".to_string());
        extensions.push(format!("cs3={}", cef_extension_escape(&instance)));
    }
    format!(
        "CEF:0|Soap Bucket|sbproxy|{}|{}|{}|{}|{}",
        cef_header_escape(env!("CARGO_PKG_VERSION")),
        cef_header_escape(&signature),
        cef_header_escape(&name),
        severity,
        extensions.join(" ")
    )
}

/// Escape a CEF header field: backslash, the pipe delimiter, and the
/// newlines that would end the record early.
///
/// The newline arms are unreachable today, because every header input is a
/// closed vocabulary (`key_lifecycle_event_type` maps four literals) and
/// the version comes from `CARGO_PKG_VERSION`. They are here because the
/// module doc presents the escaping as the defense, and a defense that
/// holds only because of a property two functions away is one refactor
/// from being wrong. Its sibling `cef_extension_escape` already covers all
/// four; the asymmetry was the accident.
fn cef_header_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

/// Escape a CEF extension value: backslash, the `=` that separates a key
/// from its value, and the newlines that would end the record early.
fn cef_extension_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('=', "\\=")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry() -> ConfigAuditEntry {
        ConfigAuditEntry {
            timestamp: "2026-04-16T12:00:00Z".to_string(),
            source: "file_watcher".to_string(),
            origins_added: vec!["api.example.com".to_string()],
            origins_removed: vec![],
            origins_modified: vec!["legacy.example.com".to_string()],
            tenant_id: None,
            actor: None,
            prior_revision: None,
            next_revision: None,
            rejection_reason: None,
        }
    }

    #[test]
    fn key_audit_emit_lands_on_the_ring_with_actor_tenant_and_diff() {
        KeyAuditEntry::new("rotate", "key", "sbp_audit_ring_key")
            .with_actor("operator-jo")
            .with_tenant_id("tenant-r")
            .with_diff(
                Some(serde_json::json!({ "status": "active" })),
                Some(serde_json::json!({ "status": "active" })),
            )
            .emit();
        let events = crate::audit_ring::recent_audit_events(10, Some("key"), Some("rotate"), None);
        let event = events
            .iter()
            .find(|e| e.api_key_id.as_deref() == Some("sbp_audit_ring_key"))
            .expect("key mutation reaches the audit ring");
        assert_eq!(event.actor.as_deref(), Some("operator-jo"));
        assert_eq!(event.tenant_id.as_deref(), Some("tenant-r"));
        assert!(
            event
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("status")),
            "the diff summary names what changed: {event:?}"
        );
    }

    #[test]
    fn security_audit_emit_names_the_denied_key_on_the_ring() {
        SecurityAuditEntry::auth_failure(
            "auth_denied",
            "virtual_key",
            403,
            Some("api.ring-test".to_string()),
            None,
            Some("req-ring-security".to_string()),
            Some("POST".to_string()),
        )
        .with_tenant_id("tenant-s")
        .with_key_context(Some("anthropic"), "native")
        .with_api_key_id(Some("native:tenant-s:api:anthropic"))
        .emit();
        let events = crate::audit_ring::recent_audit_events(
            10,
            Some("security"),
            Some("auth_denied"),
            Some("native:tenant-s:api:anthropic"),
        );
        assert_eq!(events.len(), 1, "denial names the key: {events:?}");
        assert_eq!(events[0].request_id.as_deref(), Some("req-ring-security"));
        assert_eq!(events[0].detail.as_deref(), Some("virtual_key"));
    }

    #[test]
    fn config_audit_emit_lands_on_the_ring_with_revision_pair() {
        ConfigAuditEntry::new("api", vec!["added.example".into()], vec![], vec![])
            .with_actor("operator-cfg")
            .with_revisions(Some("r-prior-cfg-test"), Some("r-next-cfg-test"))
            .emit();
        let events = crate::audit_ring::recent_audit_events(10, Some("config"), Some("api"), None);
        let event = events
            .iter()
            .find(|e| e.actor.as_deref() == Some("operator-cfg"))
            .expect("config change reaches the audit ring");
        let detail = event.detail.as_deref().unwrap_or_default();
        assert!(
            detail.contains("r-prior-cfg-test") && detail.contains("r-next-cfg-test"),
            "the revision pair is on the event: {detail}"
        );
    }

    /// WOR-2486: a rejected reload's ring entry has to say so. Before
    /// this fix a rejection with no revision change and no origin delta
    /// rendered identically to an accepted no-op reload
    /// (`"revision X -> ?; +0 -0 ~0 origins"`), which is indistinguishable
    /// from a real accepted reload that happened to touch nothing.
    #[test]
    fn a_rejected_reload_names_itself_on_the_ring() {
        ConfigAuditEntry::new("file_watcher", vec![], vec![], vec![])
            .with_actor("operator-cfg-reject")
            .with_rejection_reason("origin \"ring-reject.example\": invalid regex")
            .emit();
        let events =
            crate::audit_ring::recent_audit_events(10, Some("config"), Some("file_watcher"), None);
        let event = events
            .iter()
            .find(|e| e.actor.as_deref() == Some("operator-cfg-reject"))
            .expect("rejected reload reaches the audit ring");
        let detail = event.detail.as_deref().unwrap_or_default();
        assert!(
            detail.starts_with("rejected:"),
            "a rejection must not read like an accepted no-op reload: {detail}"
        );
        assert!(
            detail.contains("ring-reject.example"),
            "the reason must be on the event: {detail}"
        );
    }

    #[test]
    fn serialization_contains_all_fields() {
        let entry = make_entry();
        let json = serde_json::to_string(&entry).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(v["timestamp"], "2026-04-16T12:00:00Z");
        assert_eq!(v["source"], "file_watcher");
        assert_eq!(v["origins_added"][0], "api.example.com");
        assert!(v["origins_removed"].as_array().unwrap().is_empty());
        assert_eq!(v["origins_modified"][0], "legacy.example.com");
    }

    #[test]
    fn emit_does_not_panic() {
        // emit() writes to tracing; verify it does not panic even without a subscriber.
        let entry = make_entry();
        entry.emit();
    }

    #[test]
    fn new_helper_sets_source_and_lists() {
        let entry = ConfigAuditEntry::new(
            "api",
            vec!["new.example.com".to_string()],
            vec!["old.example.com".to_string()],
            vec![],
        );
        assert_eq!(entry.source, "api");
        assert_eq!(entry.origins_added, vec!["new.example.com"]);
        assert_eq!(entry.origins_removed, vec!["old.example.com"]);
        assert!(entry.origins_modified.is_empty());
        // Timestamp must be a non-empty RFC 3339 string.
        assert!(entry.timestamp.contains('T'));
    }

    #[test]
    fn security_framing_violation_serializes_required_fields() {
        let entry = SecurityAuditEntry::framing_violation(
            "dual_cl_te",
            Some("api.example.com".to_string()),
            Some("203.0.113.7".parse().unwrap()),
            Some("req-abc123".to_string()),
            Some("POST".to_string()),
        );
        let json = serde_json::to_string(&entry).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(v["event_type"], "framing_violation");
        assert_eq!(v["reason"], "dual_cl_te");
        assert_eq!(v["hostname"], "api.example.com");
        assert_eq!(v["client_ip"], "203.0.113.7");
        assert_eq!(v["request_id"], "req-abc123");
        assert_eq!(v["method"], "POST");
        assert_eq!(v["status_code"], 400);
        assert!(v["timestamp"].as_str().unwrap().contains('T'));
    }

    #[test]
    fn security_audit_skips_none_optional_fields_from_json() {
        let entry = SecurityAuditEntry::framing_violation("duplicate_cl", None, None, None, None);
        let json = serde_json::to_string(&entry).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Required fields present.
        assert_eq!(v["event_type"], "framing_violation");
        assert_eq!(v["reason"], "duplicate_cl");
        assert_eq!(v["status_code"], 400);
        // Optional fields absent (not stringified None).
        assert!(v.get("hostname").is_none());
        assert!(v.get("client_ip").is_none());
        assert!(v.get("request_id").is_none());
        assert!(v.get("method").is_none());
    }

    /// WOR-2711: adding optional workspace target fields must not rewrite
    /// existing chained framing_violation records. `skip_serializing_if`
    /// keeps those keys out when they are unset.
    #[test]
    fn framing_violation_json_omits_target_kind_and_target_id() {
        let entry = SecurityAuditEntry::framing_violation("duplicate_cl", None, None, None, None);
        let json = serde_json::to_string(&entry).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            v.get("target_kind").is_none(),
            "vanilla framing_violation must not grow target_kind: {json}"
        );
        assert!(
            v.get("target_id").is_none(),
            "vanilla framing_violation must not grow target_id: {json}"
        );
    }

    /// WOR-2711: AutoSuspend and resume are workspace transitions, not
    /// request refusals. The constructor fills the new target fields and
    /// leaves the request-shaped ones empty.
    #[test]
    fn rate_limit_budget_transition_names_the_workspace_not_a_request() {
        let suspend = SecurityAuditEntry::rate_limit_budget_transition(
            "rate_limit_auto_suspend",
            "auto_suspend_threshold_exceeded: 2 consecutive throttles >= 2",
            "acme-ws",
        );
        assert_eq!(suspend.event_type, "rate_limit_auto_suspend");
        assert_eq!(
            suspend.reason,
            "auto_suspend_threshold_exceeded: 2 consecutive throttles >= 2"
        );
        assert_eq!(suspend.status_code, 429);
        assert_eq!(suspend.hostname, None);
        assert_eq!(suspend.client_ip, None);
        assert_eq!(suspend.request_id, None);
        assert_eq!(suspend.method, None);
        assert_eq!(suspend.target_kind.as_deref(), Some("workspace"));
        assert_eq!(suspend.target_id.as_deref(), Some("acme-ws"));

        let json = serde_json::to_string(&suspend).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["target_kind"], "workspace");
        assert_eq!(v["target_id"], "acme-ws");

        let resume = SecurityAuditEntry::rate_limit_budget_transition(
            "rate_limit_resume",
            "manual resume via admin",
            "acme-ws",
        );
        assert_eq!(resume.event_type, "rate_limit_resume");
        assert_eq!(resume.reason, "manual resume via admin");
        assert_eq!(resume.status_code, 200);
        assert_eq!(resume.target_kind.as_deref(), Some("workspace"));
        assert_eq!(resume.target_id.as_deref(), Some("acme-ws"));
    }

    /// WOR-2711: `SecurityAuditEntry::emit` is the only path that reaches
    /// `append_security_audit`. A transition built by the constructor
    /// must land on an installed security chain.
    #[test]
    fn rate_limit_budget_transition_emit_reaches_an_installed_security_chain() {
        let path =
            std::env::temp_dir().join(format!("sb-audit-rlb-emit-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let seed = "ab".repeat(32);
        let chain = crate::audit_chain::SecurityAuditChain::open(&path, &seed, "rlb-emit-test")
            .expect("chain opens");
        if crate::audit_chain::install_security_audit_chain(chain).is_err() {
            let _ = std::fs::remove_file(&path);
            return;
        }

        let entry = SecurityAuditEntry::rate_limit_budget_transition(
            "rate_limit_auto_suspend",
            "auto_suspend_threshold_exceeded: 2 consecutive throttles >= 2",
            "ws-chain",
        );
        let emitted = serde_json::to_string(&entry).expect("entry serializes");
        entry.emit();

        let content = std::fs::read_to_string(&path).expect("chain is readable");
        assert!(
            content.contains(&emitted),
            "emit() reached the chain: {content}"
        );
        assert!(
            content.contains("rate_limit_auto_suspend"),
            "event_type reached the chain: {content}"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn security_audit_records_native_key_context_without_secret_material() {
        let entry = SecurityAuditEntry::auth_failure(
            "auth_denied",
            "native_provider_key",
            403,
            Some("api.example.com".to_string()),
            None,
            Some("req-native".to_string()),
            Some("POST".to_string()),
        )
        .with_key_context(Some("openai"), "native");
        let json = serde_json::to_string(&entry).unwrap();

        assert!(json.contains("\"key_provider\":\"openai\""));
        assert!(json.contains("\"key_mode\":\"native\""));
        assert!(!json.contains("sk-caller-owned-canary"));
    }

    #[test]
    fn security_audit_emit_does_not_panic() {
        let entry = SecurityAuditEntry::framing_violation("control_chars", None, None, None, None);
        entry.emit();
    }

    #[test]
    fn serialization_roundtrip_preserves_all_lists() {
        let entry = ConfigAuditEntry {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            source: "mesh_broadcast".to_string(),
            origins_added: vec!["a.com".to_string(), "b.com".to_string()],
            origins_removed: vec!["c.com".to_string()],
            origins_modified: vec!["d.com".to_string(), "e.com".to_string()],
            tenant_id: None,
            actor: None,
            prior_revision: None,
            next_revision: None,
            rejection_reason: None,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        let added = v["origins_added"].as_array().unwrap();
        assert_eq!(added.len(), 2);
        assert_eq!(added[0], "a.com");
        assert_eq!(added[1], "b.com");

        let removed = v["origins_removed"].as_array().unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0], "c.com");

        let modified = v["origins_modified"].as_array().unwrap();
        assert_eq!(modified.len(), 2);
    }

    /// WOR-1067: config audit entry carries tenant_id when set; the
    /// field is omitted from the rendered JSON when None so existing
    /// downstream parsers stay happy.
    #[test]
    fn config_audit_entry_carries_tenant_id_round_trip() {
        let entry =
            ConfigAuditEntry::new("file_watcher", vec![], vec![], vec![]).with_tenant_id("acme");
        let json = serde_json::to_string(&entry).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["tenant_id"], "acme");

        let entry_anon = ConfigAuditEntry::new("file_watcher", vec![], vec![], vec![]);
        let json_anon = serde_json::to_string(&entry_anon).unwrap();
        let v_anon: serde_json::Value = serde_json::from_str(&json_anon).unwrap();
        assert!(v_anon.get("tenant_id").is_none());
    }

    /// WOR-2486: an accepted reload carries no `rejection_reason`; a
    /// rejected one does, bounded and never the raw unbounded string.
    #[test]
    fn config_audit_entry_rejection_reason_round_trips_and_is_bounded() {
        let accepted = ConfigAuditEntry::new("file_watcher", vec![], vec![], vec![]);
        let json = serde_json::to_string(&accepted).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            v.get("rejection_reason").is_none(),
            "an accepted reload must not carry a rejection_reason field"
        );

        let rejected = ConfigAuditEntry::new("file_watcher", vec![], vec![], vec![])
            .with_rejection_reason(
                "origin \"api.example.com\": model_rate_limits[0]: invalid regex",
            );
        let json = serde_json::to_string(&rejected).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            v["rejection_reason"],
            "origin \"api.example.com\": model_rate_limits[0]: invalid regex"
        );

        let long_reason = "x".repeat(1000);
        let bounded = ConfigAuditEntry::new("file_watcher", vec![], vec![], vec![])
            .with_rejection_reason(&long_reason);
        assert!(
            bounded.rejection_reason.as_ref().expect("set").len() <= 512,
            "the reason must be bounded before it reaches a record shipped to a third-party sink"
        );
    }

    /// A record serialized before `rejection_reason` existed must still
    /// deserialize: `#[serde(default)]` is what makes that true, and the
    /// sibling `Option` fields on this struct (`tenant_id`, `actor`,
    /// `prior_revision`, `next_revision`) lack it, so a JSON payload
    /// missing any of those fails to parse. This pins the new field to
    /// the safer contract rather than repeating that gap.
    #[test]
    fn config_audit_entry_without_rejection_reason_field_still_deserializes() {
        let json = r#"{
            "timestamp": "2026-01-01T00:00:00Z",
            "source": "file_watcher",
            "origins_added": [],
            "origins_removed": [],
            "origins_modified": []
        }"#;
        let entry: ConfigAuditEntry = serde_json::from_str(json).expect("old-shape record parses");
        assert!(entry.rejection_reason.is_none());
    }

    /// WOR-1067: security audit entry carries tenant_id when set; the
    /// field is omitted when None to keep existing SIEM ingest pipelines
    /// unchanged for proxy-wide events.
    #[test]
    fn security_audit_entry_carries_tenant_id_round_trip() {
        let entry = SecurityAuditEntry::policy_violation(
            "rate_limit",
            "exceeded",
            429,
            Some("api.acme.example".to_string()),
            None,
            None,
            None,
        )
        .with_tenant_id("acme");
        let json = serde_json::to_string(&entry).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["tenant_id"], "acme");

        let entry_anon =
            SecurityAuditEntry::framing_violation("duplicate_cl", None, None, None, None);
        let json_anon = serde_json::to_string(&entry_anon).unwrap();
        let v_anon: serde_json::Value = serde_json::from_str(&json_anon).unwrap();
        assert!(v_anon.get("tenant_id").is_none());
    }

    /// WOR-2486 fix round 1, C2: verifies the claim `sbproxy_tls::mtls`'s
    /// CN sanitizer's doc comment relies on, rather than assuming it.
    ///
    /// `sbproxy_meter::ledger::UsageLedger::append_checked` writes one
    /// `serde_json::to_string(&entry)` result per `writeln!` call to the
    /// hash-chained file: exactly this crate's own serialization, not a
    /// hand-rolled format. A `reason` (or any other free-text field)
    /// carrying a raw newline must not be able to start a second NDJSON
    /// record inside a value meant to hold one field, because every
    /// downstream chain reader (`sbproxy audit verify`, a SIEM's NDJSON
    /// parser) treats one physical line as one record.
    #[test]
    fn security_audit_entry_reason_cannot_split_the_chained_ndjson_line() {
        let entry = SecurityAuditEntry::auth_failure(
            "auth_mtls_rejected",
            "mtls:untrusted_issuer cn=evil.example\ncn=trusted.example",
            495,
            None,
            None,
            None,
            None,
        );
        // The exact call `UsageLedger::append_checked` makes before its
        // own `writeln!`.
        let line = serde_json::to_string(&entry).expect("entry serializes");
        assert_eq!(
            line.lines().count(),
            1,
            "a raw newline in a field must not produce a second physical line: {line:?}"
        );
        // And the value round-trips: JSON escaping, not data loss, is
        // what prevents the split.
        let parsed: serde_json::Value = serde_json::from_str(&line).expect("line parses");
        assert_eq!(
            parsed["reason"],
            "mtls:untrusted_issuer cn=evil.example\ncn=trusted.example"
        );
    }

    // --- WOR-2318: the `events:` egress bridge ---

    #[test]
    fn auth_failures_map_to_auth_denied_and_everything_else_to_policy_denied() {
        use crate::events::EventType;

        // The four values `auth_failure` documents, plus the shape a
        // future `auth_*` value would take.
        for auth in [
            "auth_denied",
            "auth_denied_with_headers",
            "auth_digest_challenge",
            "forward_auth_denied",
            "auth_something_new",
        ] {
            let entry = SecurityAuditEntry::auth_failure(auth, "jwt", 401, None, None, None, None);
            assert_eq!(
                entry.egress_event_type(),
                EventType::AuthDenied,
                "{auth} must not land in a policy dashboard"
            );
        }

        // Framing plus the policy labels `policy_violation` documents.
        for policy in [
            "framing_violation",
            "rate_limit",
            "ip_filter",
            "waf",
            "prompt_injection",
            "credential_exposure",
            // WOR-2552: the `websocket` action's two enforcement
            // verdicts. Named here because this is the assertion that
            // says which feed a SIEM rule finds them on.
            "websocket_message_too_large",
            "websocket_subprotocol_violation",
            // WOR-2563 and WOR-2565, for the same reason: a structural
            // body refusal and a post-sunset `410 Gone` are both proxy
            // refusals on a rule, so both belong on `policy_denied`.
            "body_threat_protection",
            "api_deprecation",
            // WOR-2711: workspace budget transitions share this feed.
            "rate_limit_auto_suspend",
            "rate_limit_resume",
        ] {
            let entry = SecurityAuditEntry::policy_violation(
                policy, "blocked", 403, None, None, None, None,
            );
            assert_eq!(
                entry.egress_event_type(),
                EventType::PolicyDenied,
                "{policy}"
            );
        }
    }

    /// The egress payload is the entry verbatim, so this is the field
    /// audit made executable: every key that reaches a third-party
    /// webhook is named here, and adding one to the struct without
    /// adding it here fails.
    #[test]
    fn the_egress_payload_carries_only_the_documented_secret_free_fields() {
        let entry = SecurityAuditEntry::policy_violation(
            "rate_limit",
            "exceeded",
            429,
            Some("api.acme.example".to_string()),
            Some("203.0.113.7".parse().expect("test ip")),
            Some("req-1".to_string()),
            Some("POST".to_string()),
        )
        .with_tenant_id("acme")
        .with_key_context(Some("openai"), "native")
        .with_api_key_id(Some("sk_deadbeef"));

        let payload = serde_json::to_value(&entry).expect("entry serializes");
        let object = payload.as_object().expect("entry is a JSON object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();

        assert_eq!(
            keys,
            vec![
                "api_key_id",
                "client_ip",
                "event_type",
                "hostname",
                "key_mode",
                "key_provider",
                "method",
                "reason",
                "request_id",
                "status_code",
                "tenant_id",
                "timestamp",
            ],
            "a field was added to SecurityAuditEntry. It now ships to any \
             configured events: webhook, so confirm it cannot carry a \
             credential before adding it to this list."
        );
        assert_eq!(object["api_key_id"], "sk_deadbeef");
    }

    #[test]
    fn publishing_to_a_missing_egress_is_a_no_op() {
        // The default deployment: no `events:` block, so the publish is
        // one relaxed load and the payload is never built.
        SecurityAuditEntry::framing_violation("duplicate_cl", None, None, None, None)
            .publish_to_event_egress();
        ConfigAuditEntry::new("file_watcher", vec![], vec![], vec![]).emit();
    }

    // --- WOR-2478: config audit entries become chainable ---

    /// End to end through the public emitter, which is the path a config
    /// change actually takes: with a chain installed, `emit()` must reach
    /// the file (not merely compile against `LedgerPayload`), and a
    /// successful append must keep the `outcome` label at `ok` rather than
    /// folding to `chain_error`.
    ///
    /// The chain is process-global and first-write-wins (see
    /// `crate::audit_chain`'s own tests), so this tolerates another test in
    /// the same process having already claimed the slot; under nextest
    /// every test gets its own process, so that branch is only the `cargo
    /// test --lib` fallback path.
    #[test]
    fn config_audit_emit_lands_on_an_installed_chain_with_an_ok_outcome() {
        let path =
            std::env::temp_dir().join(format!("sb-audit-config-emit-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let seed = "cd".repeat(32);
        let chain = crate::audit_chain::ConfigAuditChain::open(&path, &seed, "audit-emit-test")
            .expect("chain opens");
        if crate::audit_chain::install_config_audit_chain(chain).is_err() {
            let _ = std::fs::remove_file(&path);
            return;
        }

        let entry =
            ConfigAuditEntry::new("api", vec!["chained.example".to_string()], vec![], vec![])
                .with_actor("operator-chain-test")
                .with_revisions(Some("r-chain-prior"), Some("r-chain-next"));
        let emitted = serde_json::to_string(&entry).expect("entry serializes");
        entry.emit();

        let content = std::fs::read_to_string(&path).expect("chain is readable");
        assert!(
            content.contains(&emitted),
            "emit() reached the chain: {content}"
        );

        let ok_exemplar = crate::exemplars::last_recorded_for_test(
            "sbproxy_audit_emit_duration_seconds",
            &[("channel", "config"), ("outcome", "ok")],
        );
        assert!(
            ok_exemplar.is_some(),
            "a successful chain append must keep the outcome label at ok"
        );

        let _ = std::fs::remove_file(&path);
    }

    // Note on the `chain_error` branch: `ConfigAuditEntry::emit` and
    // `SecurityAuditEntry::emit` fold `chain_ok` (from
    // `crate::audit_chain::append_config_audit` /
    // `append_security_audit`) into `outcome` inline:
    // `if !chain_ok { "chain_error" } else { outcome }`. Forcing
    // `chain_ok` to `false` from this module has no injection point: a
    // read-only chain file does not reproduce it (the ledger holds its
    // file descriptor open for the process lifetime and POSIX checks
    // permissions at `open(2)`, not per `write(2)`, so a later `chmod`
    // never reaches the writer), and a payload that refuses to serialize
    // would require changing `ConfigAuditEntry` / `SecurityAuditEntry`'s
    // derive, which is out of scope here. `crate::audit_chain`'s own
    // `a_failed_append_reports_false_and_latches_the_degraded_flag` test
    // already proves `append` returns `false` on a failing chain via a
    // serialize-refusing payload; the one-line fold above is verified by
    // inspection rather than by a second injected failure.

    // --- WOR-2478: key audit entries become chainable, metadata only ---

    /// End to end through the public emitter, the same shape as
    /// `config_audit_emit_lands_on_an_installed_chain_with_an_ok_outcome`
    /// above, over the key channel. Unlike the config/security twins, the
    /// chained bytes are never expected to equal the emitted tracing
    /// line (the chain carries fingerprints, not the diff), so this
    /// asserts on the metadata and the fingerprint fields instead of a
    /// substring match.
    #[test]
    fn key_audit_emit_lands_on_an_installed_chain_with_an_ok_outcome() {
        let path =
            std::env::temp_dir().join(format!("sb-audit-key-emit-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let seed = "12".repeat(32);
        let chain = crate::audit_chain::KeyAuditChain::open(&path, &seed, "audit-emit-test")
            .expect("chain opens");
        if crate::audit_chain::install_key_audit_chain(chain).is_err() {
            let _ = std::fs::remove_file(&path);
            return;
        }
        // Any process that already claimed `KEY_CHAIN` above has also had
        // a chance to install a fingerprint key; install one here too so
        // this test's assertions on non-empty fingerprints hold even when
        // this is the very first WOR-2478 test in the process.
        crate::audit_chain::install_key_audit_fingerprint_key(b"test-master-for-key-emit");

        KeyAuditEntry::new("rotate", "key", "sbp_chain_emit_key")
            .with_actor("operator-chain-test")
            .with_tenant_id("tenant-chain-test")
            .with_diff(
                Some(serde_json::json!({ "status": "active" })),
                Some(serde_json::json!({ "status": "rotated" })),
            )
            .emit();

        let content = std::fs::read_to_string(&path).expect("chain is readable");
        assert!(
            content.contains("sbp_chain_emit_key"),
            "the metadata reached the chain: {content}"
        );
        assert!(
            content.contains("before_fingerprint") && content.contains("after_fingerprint"),
            "the fingerprints reached the chain: {content}"
        );

        let ok_exemplar = crate::exemplars::last_recorded_for_test(
            "sbproxy_audit_emit_duration_seconds",
            &[("channel", "key"), ("outcome", "ok")],
        );
        assert!(
            ok_exemplar.is_some(),
            "a successful chain append must keep the outcome label at ok"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// The non-negotiable proof behind the whole ticket: a key mutation
    /// whose before/after diff carries something that looks exactly like
    /// a real upstream credential must never write that value to the
    /// chain file, in either its plaintext or fingerprinted form's
    /// namesake bytes - and (WOR-2478 I3/M6(c)) the same holds for a
    /// diff field's own NAME, not just its value: a caller that starts
    /// diffing a field nobody reviewed must not get to name that field
    /// in the chain either. Greps the raw file contents, not a parsed
    /// structure, so there is nowhere for either canary to hide.
    #[test]
    fn a_key_mutation_with_a_secret_before_after_value_never_writes_the_secret_to_the_chain() {
        let path =
            std::env::temp_dir().join(format!("sb-audit-key-secret-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let seed = "34".repeat(32);
        let chain = crate::audit_chain::KeyAuditChain::open(&path, &seed, "audit-secret-test")
            .expect("chain opens");
        if crate::audit_chain::install_key_audit_chain(chain).is_err() {
            let _ = std::fs::remove_file(&path);
            return;
        }
        crate::audit_chain::install_key_audit_fingerprint_key(b"test-master-for-secret-test");

        let planted_secret = "sk-planted-canary-do-not-leak-4f8a91";
        let rotated_secret = "sk-rotated-canary-do-not-leak-9b21c7";
        // A second canary planted as the diff's own FIELD NAME, not its
        // value: `upstream_secret` is not on the key-audit field-name
        // allowlist either, but naming the canary distinctly here means
        // a regression that started copying non-allowlisted names
        // verbatim would be caught by this assertion specifically,
        // rather than only by the (also-not-allowlisted) `upstream_secret`
        // name coincidentally being absent too.
        let planted_field_name = "sk-planted-field-name-canary-77aa21";

        let mut before = serde_json::Map::new();
        before.insert(
            "upstream_secret".to_string(),
            serde_json::Value::String(planted_secret.to_string()),
        );
        before.insert(
            planted_field_name.to_string(),
            serde_json::Value::String("before".to_string()),
        );
        let mut after = serde_json::Map::new();
        after.insert(
            "upstream_secret".to_string(),
            serde_json::Value::String(rotated_secret.to_string()),
        );
        after.insert(
            planted_field_name.to_string(),
            serde_json::Value::String("after".to_string()),
        );

        KeyAuditEntry::new("update", "credential", "cred-secret-test")
            .with_actor("operator-secret-test")
            .with_diff(
                Some(serde_json::Value::Object(before)),
                Some(serde_json::Value::Object(after)),
            )
            .emit();

        let content = std::fs::read_to_string(&path).expect("chain is readable");
        assert!(
            content.contains("cred-secret-test"),
            "the metadata reached the chain: {content}"
        );
        assert!(
            !content.contains(planted_secret),
            "the planted secret VALUE must never reach the chain file: {content}"
        );
        assert!(
            !content.contains(rotated_secret),
            "the rotated secret VALUE must never reach the chain file either: {content}"
        );
        assert!(
            !content.contains(planted_field_name),
            "a caller-supplied field NAME must never reach the chain file verbatim: {content}"
        );
        assert!(
            content.contains("before_fingerprint") && content.contains("after_fingerprint"),
            "fingerprints stand in for the diff: {content}"
        );

        let _ = std::fs::remove_file(&path);
    }

    // --- WOR-2571: key-lifecycle events on the `events:` egress ---

    #[test]
    fn key_lifecycle_ops_map_to_their_event_types_and_nothing_else_maps() {
        use crate::events::EventType;
        assert_eq!(
            key_lifecycle_event_type("create"),
            Some(EventType::KeyMinted)
        );
        assert_eq!(
            key_lifecycle_event_type("revoke"),
            Some(EventType::KeyRevoked)
        );
        assert_eq!(
            key_lifecycle_event_type("rotate"),
            Some(EventType::KeyRotated)
        );
        assert_eq!(
            key_lifecycle_event_type("block"),
            Some(EventType::KeyBlocked)
        );
        // The mutations the typed feed does not carry: they stay on the
        // `key_audit` channel, which records every operation.
        assert_eq!(key_lifecycle_event_type("update"), None);
        assert_eq!(key_lifecycle_event_type("delete"), None);
        assert_eq!(key_lifecycle_event_type("unblock"), None);
        // The mapping is a closed match, not a prefix or substring test.
        assert_eq!(key_lifecycle_event_type("created"), None);
        assert_eq!(key_lifecycle_event_type(""), None);
    }

    #[test]
    fn key_lifecycle_payload_carries_the_allowlisted_fields() {
        let entry = KeyAuditEntry::new("block", "key", "sbp_payload_key")
            .with_actor("ops@example.com")
            .with_tenant_id("acme")
            .with_diff(
                Some(serde_json::json!({ "status": "active" })),
                Some(serde_json::json!({ "status": "blocked" })),
            );
        let event = key_lifecycle_event(&entry, crate::events::EventType::KeyBlocked);

        assert_eq!(event.event_type, crate::events::EventType::KeyBlocked);
        assert_eq!(event.tenant_id, "acme");
        assert_eq!(event.hostname, "");
        assert_eq!(event.data["op"], "block");
        assert_eq!(event.data["resource"], "key");
        assert_eq!(event.data["id"], "sbp_payload_key");
        assert_eq!(event.data["actor"], "ops@example.com");
        assert_eq!(event.data["outcome"], "applied");
        assert_eq!(event.data["prior_status"], "active");
        assert_eq!(event.data["new_status"], "blocked");
    }

    #[test]
    fn key_lifecycle_payload_omits_what_it_does_not_know() {
        let entry = KeyAuditEntry::new("create", "key", "sbp_sparse_key");
        let event = key_lifecycle_event(&entry, crate::events::EventType::KeyMinted);

        assert_eq!(event.tenant_id, "");
        let object = event.data.as_object().expect("payload is an object");
        assert!(!object.contains_key("actor"), "{:?}", event.data);
        assert!(!object.contains_key("prior_status"), "{:?}", event.data);
        assert!(!object.contains_key("new_status"), "{:?}", event.data);
    }

    /// The payload is an allowlist, not a pass-through: a diff value
    /// beyond the closed `status` label never crosses, even when a
    /// (hypothetical, adversarial) caller plants one. This is the SIEM
    /// half of `key_chain_snapshot_values_are_fingerprinted_not_carried`
    /// above: the chain fingerprints the diff, the typed event drops it.
    #[test]
    fn key_lifecycle_payload_never_carries_diff_values_beyond_status() {
        let planted = "sk-plaintext-material-that-must-not-cross";
        let entry = KeyAuditEntry::new("revoke", "credential", "cred-posture-test").with_diff(
            Some(serde_json::json!({ "status": "active", "upstream_secret": planted })),
            Some(serde_json::json!({ "status": "revoked", "upstream_secret": planted })),
        );
        let event = key_lifecycle_event(&entry, crate::events::EventType::KeyRevoked);

        let line = serde_json::to_string(&event).expect("event serializes");
        assert!(
            !line.contains(planted),
            "a diff value crossed onto the SIEM payload: {line}"
        );
        assert!(
            !line.contains("upstream_secret"),
            "a diff field name crossed onto the SIEM payload: {line}"
        );
        assert_eq!(event.data["prior_status"], "active");
        assert_eq!(event.data["new_status"], "revoked");
    }

    /// Poll `path` until `predicate` matches a full NDJSON line or the
    /// deadline passes. The file egress flushes per drained batch on its
    /// own thread, so a plain read races the worker.
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

    /// WOR-2571, the seam itself, red-first: before the bridge in
    /// [`KeyAuditEntry::emit`], this test timed out polling for
    /// `key_minted` because every lifecycle mutation stopped at the
    /// tracing target, the ring, and the chain, and nothing reached the
    /// `events:` egress. Installs this process's one egress (one test
    /// per process under nextest, the same shape as the
    /// `action_dispatch` governance-evidence tests) with a mask that
    /// deliberately excludes `key_blocked`, so the same run also proves
    /// the mask filters the new kinds: the blocked mutation lands
    /// before the rotate, and its event must never appear even after
    /// the rotate's has.
    #[test]
    fn key_audit_emit_reaches_the_event_egress_and_honors_the_mask() {
        use crate::events::EventType;

        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("key-lifecycle-events.ndjson");
        let egress = crate::event_sink::EventEgress::start(
            crate::event_sink::EventSinkTarget::File { path: path.clone() },
            crate::event_sink::EventTypeMask::from_types(&[
                EventType::KeyMinted,
                EventType::KeyRevoked,
                EventType::KeyRotated,
            ]),
            64,
        )
        .expect("file egress starts");
        crate::event_sink::install_event_egress(egress)
            .expect("this test's own event egress installs exactly once in its own process");

        KeyAuditEntry::new("create", "key", "sbp_seam_key")
            .with_actor("ops@example.com")
            .with_tenant_id("acme")
            .emit();
        KeyAuditEntry::new("block", "key", "sbp_seam_key")
            .with_tenant_id("acme")
            .with_diff(
                Some(serde_json::json!({ "status": "active" })),
                Some(serde_json::json!({ "status": "blocked" })),
            )
            .emit();
        KeyAuditEntry::new("rotate", "key", "sbp_seam_key")
            .with_tenant_id("acme")
            .emit();

        // The rotate emitted after the block, so once it is on disk the
        // masked-out block had every chance to arrive and did not.
        let rotated = poll_events_file(&path, |line| line.contains("key_rotated"))
            .expect("the rotate mutation must reach the egress");
        assert!(rotated.contains("sbp_seam_key"), "{rotated}");

        let content = std::fs::read_to_string(&path).expect("events file is readable");
        let minted = content
            .lines()
            .find(|line| line.contains("key_minted"))
            .expect("the create mutation must reach the egress");
        let minted: serde_json::Value = serde_json::from_str(minted).expect("minted line parses");
        assert_eq!(minted["event_type"], "key_minted");
        assert_eq!(minted["tenant_id"], "acme");
        assert_eq!(minted["data"]["op"], "create");
        assert_eq!(minted["data"]["resource"], "key");
        assert_eq!(minted["data"]["id"], "sbp_seam_key");
        assert_eq!(minted["data"]["actor"], "ops@example.com");
        assert_eq!(minted["data"]["outcome"], "applied");
        assert!(
            !content.contains("key_blocked"),
            "a masked-out kind was delivered anyway: {content}"
        );
    }

    // --- WOR-2596: CEF, and the gapless sequence ---

    /// The seam: a key-lifecycle event renders as a well-formed CEF line
    /// with the seven header fields the format fixes and the extension
    /// keys a SIEM rule reads.
    #[test]
    fn a_key_lifecycle_event_renders_as_cef() {
        let entry = KeyAuditEntry::new("revoke", "key", "sbp_cef_key")
            .with_actor("operator-jo")
            .with_tenant_id("acme")
            .with_diff(
                Some(serde_json::json!({ "status": "active" })),
                Some(serde_json::json!({ "status": "revoked" })),
            );
        let event = key_lifecycle_event(&entry, crate::events::EventType::KeyRevoked);
        let line = key_event_to_cef(&event);

        assert!(line.starts_with("CEF:0|Soap Bucket|sbproxy|"), "{line}");
        let header: Vec<&str> = line.splitn(8, '|').collect();
        assert_eq!(header.len(), 8, "CEF fixes seven header fields: {line}");
        assert_eq!(header[4], "sbproxy.key.revoke", "{line}");
        assert_eq!(header[5], "key revoke", "{line}");
        assert_eq!(
            header[6], "7",
            "a revocation outranks a mint on the analyst's queue: {line}"
        );
        let extensions = header[7];
        assert!(extensions.contains("duid=sbp_cef_key"), "{extensions}");
        assert!(extensions.contains("suser=operator-jo"), "{extensions}");
        assert!(extensions.contains("outcome=applied"), "{extensions}");
        assert!(
            extensions.contains("cs2Label=tenant") && extensions.contains("cs2=acme"),
            "a custom string field needs its label, or the receiver cannot name it: {extensions}"
        );
        assert!(
            extensions.contains("cn1Label=evidenceSeq") && extensions.contains("cn1="),
            "the gapless sequence has to survive the flattening: {extensions}"
        );
    }

    /// An `=` inside a value splits one extension into two, which is how
    /// a field an operator controls becomes a field an operator
    /// *injects*. Ids are operator-chosen, so they are escaped rather
    /// than trusted.
    #[test]
    fn cef_escapes_the_characters_that_would_split_a_record() {
        let entry = KeyAuditEntry::new("create", "credential", "id=with|pipe\\and-backslash");
        let event = key_lifecycle_event(&entry, crate::events::EventType::KeyMinted);
        let line = key_event_to_cef(&event);
        assert!(
            line.contains("duid=id\\=with|pipe\\\\and-backslash"),
            "the `=` must be escaped and the `\\` doubled: {line}"
        );
        // Header fields escape the pipe; extension values do not have to,
        // because the extension section is not pipe-delimited.
        assert_eq!(
            line.matches("CEF:0|Soap Bucket|sbproxy|").count(),
            1,
            "{line}"
        );
    }

    /// The feed carries a per-(instance, tenant) sequence so a SIEM can
    /// see a hole where a lossy transport dropped a record. The chain's
    /// signing key lives in this process, so a check the receiver can run
    /// without trusting this process is worth its two fields.
    #[test]
    fn the_key_lifecycle_feed_numbers_its_records_per_tenant() {
        let tenant = "wor2596-seq-tenant";
        let seq_of = |op: &str| {
            let entry = KeyAuditEntry::new(op, "key", "sbp_seq").with_tenant_id(tenant);
            let event = key_lifecycle_event(&entry, crate::events::EventType::KeyMinted);
            (
                event.data["sbproxy.evidence.seq"].as_u64().expect("a seq"),
                event.data["sbproxy.evidence.instance"]
                    .as_str()
                    .expect("an instance")
                    .to_string(),
            )
        };
        let (first, instance) = seq_of("create");
        // A governance record for the same tenant, drawing on the bare
        // tenant id the way `action_dispatch` does. It must not move this
        // family's counter: two families sharing one counter would give
        // neither a gapless sequence, and a SIEM rule filtered to
        // `key_revoked` would read the other family's draws as holes.
        let _ = crate::evidence_seq::next_seq(tenant);
        let (second, again) = seq_of("revoke");
        let (third, _) = seq_of("rotate");
        assert_eq!(
            second,
            first + 1,
            "strictly monotonic with no gaps, even across an interleaved governance record"
        );
        assert_eq!(third, second + 1);
        assert_eq!(
            instance, again,
            "the sequence's identity is (instance, tenant), so the instance must be stable \
             within a process"
        );
    }
}

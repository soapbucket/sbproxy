//! Config change + security audit logging.
//!
//! Two channels:
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

use serde::Serialize;
use std::net::IpAddr;

/// A structured record of a single configuration change event.
#[derive(Debug, Serialize)]
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
}

impl ConfigAuditEntry {
    /// Serialize the entry to JSON and emit it via tracing at INFO level.
    ///
    /// The record is written to the `config_audit` target so operators can
    /// route it to a dedicated sink independently of the main application log.
    pub fn emit(&self) {
        if let Ok(json) = serde_json::to_string(self) {
            tracing::info!(target: "config_audit", "{}", json);
        }
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
#[derive(Debug, Serialize)]
pub struct SecurityAuditEntry {
    /// RFC 3339 timestamp.
    pub timestamp: String,
    /// Event class. Today: `"framing_violation"`. New classes
    /// extend this enum-as-string surface.
    pub event_type: String,
    /// Stable machine-readable reason. For framing violations this
    /// is one of `dual_cl_te`, `duplicate_cl`, `malformed_te`,
    /// `duplicate_te`, `control_chars`. Matches the
    /// `sbproxy_http_framing_blocks_total{reason}` metric label
    /// exactly.
    pub reason: String,
    /// Origin hostname the request was destined for (when known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Client IP address (when known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    /// Per-request correlation ID (when minted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// HTTP method.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// HTTP status the proxy will return (always `400` for
    /// framing violations today).
    pub status_code: u16,
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
        }
    }

    /// Build a policy-violation audit entry. `event_type` is the
    /// enforcing policy's stable label (`rate_limit`, `ip_filter`,
    /// `request_limit`, `waf`, `prompt_injection`, `credential_exposure`,
    /// `threat_protection`, `ddos`, `concurrent_limit`, `policy`); the
    /// matching `record_policy` Prometheus counter uses the same string.
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
        }
    }

    /// Serialize the entry to JSON and emit it via tracing at WARN
    /// level. WARN (not INFO) so default subscribers surface
    /// security events in operational dashboards while still
    /// letting downstream SIEM filter by target.
    pub fn emit(&self) {
        if let Ok(json) = serde_json::to_string(self) {
            tracing::warn!(target: "security_audit", "{}", json);
        }
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
        }
    }
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
        }
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
}

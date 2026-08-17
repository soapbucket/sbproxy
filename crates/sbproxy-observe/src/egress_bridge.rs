// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Bridge from [`sbproxy_security::egress::record_egress_refused`] to the
//! typed [`crate::events::EventType::EgressRefused`] event (WOR-2486).
//!
//! `sbproxy-security` is a leaf crate and cannot depend on this one (this
//! crate depends on it, for the PII redactor), so the funnel every egress
//! purpose already shares, `record_egress_refused`, cannot call
//! [`crate::event_sink::publish_proxy_event`] directly. It calls a
//! function pointer instead, installed once at boot with
//! [`sbproxy_security::egress::install_egress_refused_hook`]; [`bridge`]
//! is the function that pointer names.
//!
//! One seam closes five egress purposes at once: DNS-rebind and SSRF
//! attempts (`ai_provider`, `mcp_upstream`, `openapi_tool`), credential
//! egress (`token_exchange`), telemetry exfiltration
//! (`webhook`, `usage_sink`), and artifact-fetch tampering
//! (`model_artifact`, `engine_artifact`, `bundle_hook`), because every one
//! of them already goes through `record_egress_refused` before this
//! change and none of the call sites needed to change.

use sbproxy_security::egress::{EgressDenied, EgressPurpose};

use crate::events::{EventType, ProxyEvent};

/// Build the [`ProxyEvent`] one refusal turns into.
///
/// Split from [`bridge`] so the field set is testable without a running
/// egress: [`crate::audit::SecurityAuditEntry`]'s own bridge is tested
/// the same way, against `egress_event_type()` rather than the full
/// publish path.
///
/// `purpose`, `reason`, and `origin` are already the closed, bounded
/// labels `record_egress_refused` itself puts on the Prometheus series
/// (see that function's doc): none of them can carry a URL, a header
/// value, or a credential. `tenant` is the caller's tenant id or the
/// `"unset"` sentinel `record_egress_refused` substitutes for an empty
/// one. All four are safe to ship to a third-party `events:` sink
/// unchanged.
fn build_event(purpose: EgressPurpose, reason: EgressDenied, tenant: &str, origin: &str) -> ProxyEvent {
    ProxyEvent::new(
        EventType::EgressRefused,
        origin.to_owned(),
        tenant.to_owned(),
        serde_json::json!({
            "purpose": purpose.as_label(),
            "reason": reason.as_label(),
            "tenant": tenant,
            "origin": origin,
        }),
    )
}

/// The hook installed on [`sbproxy_security::egress::record_egress_refused`].
///
/// Matches [`sbproxy_security::egress::EgressRefusedHook`]'s signature
/// exactly; register it once at boot with
/// [`sbproxy_security::egress::install_egress_refused_hook`]. A no-op,
/// at the cost of one relaxed load, when no `events:` egress is
/// installed or it was not asked for `egress_refused`.
pub fn bridge(purpose: EgressPurpose, reason: EgressDenied, tenant: &str, origin: &str) {
    crate::event_sink::publish_proxy_event(EventType::EgressRefused, || {
        build_event(purpose, reason, tenant, origin)
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Red-first: before this bridge existed, nothing built a
    /// `ProxyEvent` for an egress refusal at all. Pins the wire name and
    /// every field a SIEM rule would select on.
    #[test]
    fn build_event_carries_purpose_reason_tenant_and_origin() {
        let event = build_event(
            EgressPurpose::TokenExchange,
            EgressDenied::UnlistedHost,
            "acme",
            "mcp-upstream",
        );
        assert_eq!(event.event_type, EventType::EgressRefused);
        assert_eq!(event.hostname, "mcp-upstream");
        assert_eq!(event.tenant_id, "acme");
        assert_eq!(event.data["purpose"], "token_exchange");
        assert_eq!(event.data["reason"], "unlisted_host");
        assert_eq!(event.data["tenant"], "acme");
        assert_eq!(event.data["origin"], "mcp-upstream");
    }

    /// The payload carries only the closed, bounded labels
    /// `record_egress_refused` already puts on the metric: nothing here
    /// can be a URL, a header, or a credential, which is what makes it
    /// safe to ship to a third-party `events:` webhook unchanged.
    #[test]
    fn build_event_payload_has_no_extra_fields() {
        let event = build_event(
            EgressPurpose::AiProvider,
            EgressDenied::PrivateAddress,
            "",
            "openai",
        );
        let object = event.data.as_object().expect("data is a JSON object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["origin", "purpose", "reason", "tenant"]);
    }

    /// Publishing with no `events:` egress installed must not panic.
    /// Mirrors `SecurityAuditEntry`'s
    /// `publishing_to_a_missing_egress_is_a_no_op`.
    #[test]
    fn bridge_is_a_no_op_with_no_egress_installed() {
        bridge(
            EgressPurpose::ModelArtifact,
            EgressDenied::DnsResolutionFailed,
            "acme",
            "artifact-host",
        );
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Unified Principal + Credential model for the credentials epic.
//!
//! ## Design
//!
//! Today's auth pipeline returns [`crate::traits::AuthDecision`]: a
//! coarse `Allow { sub, source } | Deny | DenyWithHeaders` enum that
//! carries enough information for the request to proceed but no
//! attribution surface beyond the subject string. The credentials
//! epic introduces a richer carrier:
//!
//! * Every auth provider returns a [`Principal`] on Allow.
//! * AI virtual key resolution overrides the principal with the
//!   virtual-key view (project / user / tags / metadata).
//! * Policies, scripts, MCP RBAC, and the access log all read the
//!   same principal.
//!
//! ## Migration timeline
//!
//! PR1 (this commit): the types ship in `sbproxy-plugin` alongside
//! the existing `AuthDecision`. No call site is migrated yet; this
//! lets the rest of the credentials epic build against a stable
//! shape.
//!
//! PR2+ (per provider): each `AuthProvider::check_request_with_subject`
//! gains a `_principal` companion that returns `Option<Principal>`.
//! Internal consumers (`request_phase.rs`, access log, AI dispatch)
//! migrate to read from `Principal` first and fall back to
//! `AuthDecision` until every provider is converted.
//!
//! PR-final: the `AuthDecision` type is removed and the trait major
//! version bump (`sbproxy-plugin 0.2 -> 0.3`) lands. The
//! `Principal`-based shape becomes the only one.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Tenant identifier carried on every request after
/// `request_phase.rs` resolves the matched origin. The
/// reserved id `__default__` is the synthetic single-tenant fallback;
/// an operator never declares it explicitly.
///
/// The type is a newtype over `String` so callers cannot accidentally
/// swap it with another stringly-typed id (origin id, workspace id,
/// session id). Cheap to clone (small string optimisation is the
/// `String` default; per-tenant fan-out paths can wrap this in `Arc`
/// when the same id reaches many code paths).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TenantId(pub String);

impl TenantId {
    /// Construct the reserved synthetic single-tenant id.
    pub fn default_tenant() -> Self {
        Self("__default__".to_string())
    }

    /// Borrow the underlying string slice without allocating.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True when this is the synthetic single-tenant fallback.
    pub fn is_default(&self) -> bool {
        self.0 == "__default__"
    }
}

impl From<String> for TenantId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for TenantId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which provider produced this principal. Mirrors the closed-enum
/// `auth_type` slug carried on the access log (`crates/sbproxy-observe/src/access_log.rs`)
/// plus the `VirtualKey` and `Plugin` variants for AI gateway matches
/// and out-of-tree providers.
///
/// Renaming or removing a variant is a breaking change for downstream
/// log readers; add new variants at the end of the enum to keep
/// serialised forms stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalSource {
    /// `Authorization: Bearer <token>` matched a configured static token.
    Bearer,
    /// API key matched on a configured header or query parameter.
    ApiKey,
    /// JWT validated against an issuer / audience / required-claims
    /// gate.
    Jwt,
    /// HTTP Basic Auth matched a configured user record.
    Basic,
    /// OIDC Relying-Party login produced a sealed session cookie that
    /// validated.
    Oidc,
    /// AI gateway virtual key matched on the inbound request's
    /// authorisation header.
    VirtualKey,
    /// HTTP Message Signatures (RFC 9421) Bot Auth.
    BotAuth,
    /// Capability token (CAP) matched.
    Cap,
    /// Forward-auth endpoint returned 2xx with an optional subject
    /// header.
    ForwardAuth,
    /// Out-of-tree auth plugin registered via `AuthProvider`.
    Plugin,
}

impl PrincipalSource {
    /// Canonical lowercase slug used in `principal_kind` access-log
    /// columns and `sbproxy_*` metric labels. Stable across releases.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bearer => "bearer",
            Self::ApiKey => "api_key",
            Self::Jwt => "jwt",
            Self::Basic => "basic_auth",
            Self::Oidc => "oidc",
            Self::VirtualKey => "virtual_key",
            Self::BotAuth => "bot_auth",
            Self::Cap => "cap",
            Self::ForwardAuth => "forward_auth",
            Self::Plugin => "plugin",
        }
    }
}

/// Reference to an AI virtual key the request matched. Populated on
/// AI gateway origins; absent for non-AI traffic.
///
/// Kept as a separate sub-struct so the AI handler can stamp it
/// without overwriting the rest of the principal (the inbound auth
/// provider still owns `sub`, `source`, `attrs.roles`, and so on).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VirtualKeyRef {
    /// Operator-supplied stable name of the matched virtual key.
    pub name: String,
    /// Allowed upstream providers, copied from the virtual key's
    /// config block. Empty allows all configured providers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_providers: Vec<String>,
}

/// Open-ended attribution attributes attached to a principal. Every
/// field is `Option` so the caller never has to invent placeholder
/// values; downstream queries `GROUP BY project` cope with NULL
/// naturally.
///
/// `metadata` is a `BTreeMap` rather than a `HashMap` for stable
/// JSON / serde ordering so log lines round-trip identically across
/// runs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrincipalAttrs {
    /// Project the principal belongs to. Drives the per-credential
    /// attribution metric and the ClickHouse `project` column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// User the principal represents (or the owner of the credential).
    /// Distinct from the `RequestContext.user_id` which the proxy
    /// may resolve from a JWT `sub` claim or an inbound header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Team / cost-center grouping. Drives the per-credential
    /// attribution metric's `team` partition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team: Option<String>,
    /// Operator-supplied tags. Each tag is stamped as a separate
    /// attribution row so `(project, tag)` cross-tabs make sense.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Free-form metadata copied off the credential. Stored as a
    /// `BTreeMap` for deterministic serialisation; the proxy never
    /// reads this map directly, it just fans it out to the access
    /// log and downstream policies.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
    /// Roles claimed by the principal. JWT validators populate this
    /// from claims; bearer / api-key providers populate it from the
    /// matched credential's `roles:` block.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    /// Verbatim JWT claims payload (or an OIDC userinfo response).
    /// Carried for CEL / Lua / JS / WASM policy scripts that want to
    /// inspect a custom claim the proxy does not know about. Absent
    /// for non-JWT principals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Map<String, serde_json::Value>>,
}

/// Unified inbound identity carrier.
///
/// PR1 ships the type; downstream PRs migrate each consumer to read
/// `Principal` instead of [`crate::traits::AuthDecision`]. The two
/// types coexist during the migration window; the final PR removes
/// `AuthDecision` and bumps the `sbproxy-plugin` trait major version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    /// Tenant the request resolves to. Stamped on the principal at
    /// auth time so downstream policies do not have to thread
    /// `RequestContext` through every decision.
    pub tenant_id: TenantId,
    /// Subject identifier. The exact shape depends on `source`:
    /// JWT `sub` claim, basic-auth username, virtual key name, etc.
    /// May be empty for sources that authenticate without binding to
    /// a subject (Bearer token shared across callers, anonymous
    /// forward-auth pass-through).
    pub sub: String,
    /// Which provider produced this principal.
    pub source: PrincipalSource,
    /// AI virtual key context, when the AI gateway matched one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtual_key: Option<VirtualKeyRef>,
    /// Attribution + claims surface. Empty for un-attributed
    /// principals (anonymous bearer, no metadata configured).
    #[serde(default)]
    pub attrs: PrincipalAttrs,
}

impl Principal {
    /// Anonymous principal for the synthetic single-tenant fallback.
    /// Used by call sites that need to construct a principal before
    /// any auth provider has run.
    pub fn anonymous() -> Self {
        Self {
            tenant_id: TenantId::default_tenant(),
            sub: String::new(),
            source: PrincipalSource::Plugin,
            virtual_key: None,
            attrs: PrincipalAttrs::default(),
        }
    }

    /// Anonymous principal scoped to a specific tenant. Used by Noop
    /// auth and by providers that authenticate without binding to a
    /// subject (shared bearer token, anonymous API key match).
    pub fn anonymous_for(tenant_id: TenantId) -> Self {
        Self {
            tenant_id,
            sub: String::new(),
            source: PrincipalSource::Plugin,
            virtual_key: None,
            attrs: PrincipalAttrs::default(),
        }
    }

    /// True when the principal carries no subject and no attribution
    /// surface. Hot-path policies use this to short-circuit before
    /// allocating selector strings.
    pub fn is_anonymous(&self) -> bool {
        self.sub.is_empty()
            && self.virtual_key.is_none()
            && self.attrs.project.is_none()
            && self.attrs.user.is_none()
            && self.attrs.team.is_none()
            && self.attrs.tags.is_empty()
            && self.attrs.metadata.is_empty()
            && self.attrs.roles.is_empty()
    }
}

// --- Credential model ---

/// Where a credential's secret material lives. Mirrors today's
/// `${ENV}` / `file:` / `secret:` / `vault://` patterns; future
/// vault backends plug in by adding variants to the `Vault` arm
/// rather than widening the enum.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SecretRef {
    /// Plain literal value. Used for tests; never written to YAML in
    /// production.
    Literal(String),
    /// Environment variable reference. Resolved at config-load and
    /// on hot reload.
    Env {
        /// Environment variable name (without leading `$`).
        name: String,
    },
    /// On-disk file. Path is resolved relative to the proxy's
    /// working directory.
    File {
        /// Filesystem path. Resolved relative to the proxy's working
        /// directory on Unix; absolute paths are honoured verbatim.
        path: String,
    },
    /// Static `secret:` reference resolved through the operator's
    /// `proxy.secrets` block.
    StaticSecret {
        /// Name of the static secret entry in `proxy.secrets`.
        name: String,
    },
    /// `vault://<backend>/<path>` URI. The backend prefix selects the
    /// vault backend (hashi, aws, kubernetes, file, sqlite, ...).
    Vault {
        /// Vault reference URI in the form
        /// `vault://<backend>/<path>[?version=<n>][&key=<json-field>]`.
        uri: String,
    },
}

/// Operator-declared credential. Sits under `proxy.credentials[]`,
/// `tenant.credentials[]`, or `origin.credentials[]` in the new
/// config schema and carries the same attribution
/// surface as [`Principal::attrs`] plus the secret material.
///
/// The `Credential` type is the source-of-truth for attribution: when
/// a credential matches, its `attrs` block is copied onto the
/// resolved `Principal` so the rest of the pipeline sees a single
/// shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    /// Operator-supplied stable name. Unique within a scope; PR2
    /// rejects duplicates at compile.
    pub name: String,
    /// Credential kind (`ai_provider`, `inbound_api_key`,
    /// `inbound_bearer`, ...). The string set is open so out-of-tree
    /// plugins can register new kinds.
    pub kind: String,
    /// Where the secret material lives.
    pub secret: SecretRef,
    /// Attribution surface copied onto matched principals.
    #[serde(default)]
    pub attrs: PrincipalAttrs,
    /// Optional expiry timestamp (RFC 3339). Past expiry, the
    /// credential is treated as not matching even if its secret
    /// material is present and correct.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Optional rotation policy / owner metadata. Free-form so
    /// operator workflows can stamp whatever they want here without
    /// requiring a schema change.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub policy: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic `__default__` tenant round-trips through serde and
    /// the typed `is_default` predicate.
    #[test]
    fn tenant_id_default_round_trips() {
        let t = TenantId::default_tenant();
        assert_eq!(t.as_str(), "__default__");
        assert!(t.is_default());
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, "\"__default__\"");
        let back: TenantId = serde_json::from_str(&json).unwrap();
        assert!(back.is_default());
    }

    /// `PrincipalSource::as_str` matches the closed-enum slug the
    /// access-log column reads.
    #[test]
    fn principal_source_slugs_match_access_log_column() {
        assert_eq!(PrincipalSource::Bearer.as_str(), "bearer");
        assert_eq!(PrincipalSource::ApiKey.as_str(), "api_key");
        assert_eq!(PrincipalSource::VirtualKey.as_str(), "virtual_key");
        assert_eq!(PrincipalSource::Plugin.as_str(), "plugin");
    }

    /// The `anonymous` constructor short-circuits the `is_anonymous`
    /// predicate, which downstream hot-path policies use to skip
    /// selector resolution.
    #[test]
    fn anonymous_principal_short_circuits() {
        let p = Principal::anonymous();
        assert!(p.is_anonymous());
        assert!(p.tenant_id.is_default());
    }

    /// Adding any attribute makes the principal non-anonymous.
    #[test]
    fn principal_with_project_is_not_anonymous() {
        let mut p = Principal::anonymous();
        p.attrs.project = Some("foundation".to_string());
        assert!(!p.is_anonymous());
    }

    /// `Principal::anonymous_for` carries the supplied tenant and is
    /// otherwise indistinguishable from `Principal::anonymous` under
    /// the `is_anonymous` predicate.
    #[test]
    fn anonymous_for_tenant_is_anonymous_predicate() {
        let p = Principal::anonymous_for(TenantId::from("acme"));
        assert!(p.is_anonymous());
        assert_eq!(p.tenant_id.as_str(), "acme");
        assert!(!p.tenant_id.is_default());
    }

    /// `SecretRef` round-trips through serde with the tagged-enum
    /// `type:` discriminator.
    #[test]
    fn secret_ref_tagged_enum_round_trips() {
        let env = SecretRef::Env {
            name: "OPENAI_API_KEY".to_string(),
        };
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains(r#""type":"env""#));
        let back: SecretRef = serde_json::from_str(&json).unwrap();
        assert_eq!(back, env);

        let vault = SecretRef::Vault {
            uri: "vault://hashi/secret/data/openai-prod".to_string(),
        };
        let json = serde_json::to_string(&vault).unwrap();
        assert!(json.contains(r#""type":"vault""#));
    }

    /// `Credential` carries all the attribution fields a `Principal`
    /// gets stamped from. Sanity-check the round trip.
    #[test]
    fn credential_round_trips() {
        let mut metadata = BTreeMap::new();
        metadata.insert("cost_center".to_string(), "eng-001".to_string());
        let attrs = PrincipalAttrs {
            project: Some("foundation".to_string()),
            team: Some("frontend".to_string()),
            tags: vec!["internal".to_string(), "prod".to_string()],
            metadata,
            ..PrincipalAttrs::default()
        };

        let cred = Credential {
            name: "openai-team-frontend".to_string(),
            kind: "ai_provider".to_string(),
            secret: SecretRef::Env {
                name: "OPENAI_API_KEY".to_string(),
            },
            attrs,
            expires_at: Some("2027-01-01T00:00:00Z".to_string()),
            policy: BTreeMap::new(),
        };
        let json = serde_json::to_string(&cred).unwrap();
        let back: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, cred.name);
        assert_eq!(back.attrs.project, Some("foundation".to_string()));
        assert_eq!(back.attrs.tags.len(), 2);
    }
}

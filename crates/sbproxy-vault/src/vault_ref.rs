// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Typed parser for provider-specific credential-reference URIs.
//!
//! ## Grammar
//!
//! ```text
//! <scheme>://<backend-name>/<provider-path>[?version=<n>][&key=<json-field>]
//! ```
//!
//! The scheme selects the provider type. The authority selects the
//! operator-configured backend instance within the request's resolution
//! scope.
//!
//! Examples:
//!
//! ```text
//! vault://primary/secret/data/openai-prod?key=api_key
//! awssm://primary/prod/openai-keys?version=3&key=api_key
//! gcpsm://primary/projects/acme/secrets/openai-key?version=latest
//! k8ssecret://primary/sbproxy-secrets/openai-key
//! secretfile://local/openai-prod?key=api_key
//! secret://local/openai-prod
//! ```
//!
//! The parser is pure syntax: it does not verify that
//! `<backend-name>` has a registered implementation, that
//! `<provider-path>` is shaped correctly for the backend, or that
//! `<key>` points at a real JSON field. Those checks land at dispatch
//! time inside each backend implementation.
//!
//! ## Backward compatibility
//!
//! `${ENV_VAR}`, `file:/path/to/secret`, and `secret:<name>` shapes
//! ship a sibling parser; the resolver tries each in turn. Reserved
//! URI schemes such as `https://` and `file://` are not treated as
//! secret references and pass through as literals.
//!
//! ## Multi-tenant resolution
//!
//! The URI itself is intentionally tenant-agnostic:
//! `awssm://primary/prod/openai-key` does not name a tenant. The
//! `<backend-name>` authority is the operator-chosen name of a backend
//! block configured at proxy, tenant, or origin scope. Resolution order
//! at request time is origin scope first, then tenant scope, then proxy
//! scope; the first scope that declares a matching `(provider type,
//! backend name)` pair serves the reference.

use std::collections::BTreeMap;
use std::fmt;

/// Provider type selected by a secret-reference URI scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VaultProviderType {
    /// HashiCorp Vault KV, selected by `vault://`.
    HashiCorp,
    /// AWS Secrets Manager, selected by `awssm://`.
    AwsSecretsManager,
    /// GCP Secret Manager, selected by `gcpsm://`.
    GcpSecretManager,
    /// Kubernetes Secret objects, selected by `k8ssecret://`.
    KubernetesSecret,
    /// Local file-backed secret store, selected by `secretfile://`.
    SecretFile,
    /// Local static secret map, selected by `secret://`.
    LocalSecret,
}

impl VaultProviderType {
    /// Convert a URI scheme into the corresponding provider type.
    pub fn from_scheme(scheme: &str) -> Option<Self> {
        match scheme {
            "vault" => Some(Self::HashiCorp),
            "awssm" => Some(Self::AwsSecretsManager),
            "gcpsm" => Some(Self::GcpSecretManager),
            "k8ssecret" => Some(Self::KubernetesSecret),
            "secretfile" => Some(Self::SecretFile),
            "secret" => Some(Self::LocalSecret),
            _ => None,
        }
    }

    /// Canonical URI scheme for this provider type.
    pub fn scheme(self) -> &'static str {
        match self {
            Self::HashiCorp => "vault",
            Self::AwsSecretsManager => "awssm",
            Self::GcpSecretManager => "gcpsm",
            Self::KubernetesSecret => "k8ssecret",
            Self::SecretFile => "secretfile",
            Self::LocalSecret => "secret",
        }
    }

    /// Stable metric label for this provider type.
    pub fn metric_label(self) -> &'static str {
        match self {
            Self::HashiCorp => "hashicorp",
            Self::AwsSecretsManager => "aws_secrets_manager",
            Self::GcpSecretManager => "gcp_secret_manager",
            Self::KubernetesSecret => "kubernetes_secret",
            Self::SecretFile => "file",
            Self::LocalSecret => "local",
        }
    }
}

impl fmt::Display for VaultProviderType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.scheme())
    }
}

/// One parsed provider-specific secret reference. Cheap to clone
/// (string fields only); intended to be carried in compiled config and
/// resolved once per request without re-parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultRef {
    /// Provider type selected by the URI scheme.
    pub provider_type: VaultProviderType,
    /// Backend instance name from the URI authority.
    pub backend: String,
    /// Path within the backend. Backend-specific shape; the parser
    /// keeps it verbatim.
    pub path: String,
    /// Optional `version=<n>` pin. Backends that do not support
    /// versioning ignore this at resolve time.
    pub version: Option<String>,
    /// Optional `key=<json-field>` sub-field selector. When set, the
    /// resolver expects the backend secret to be a JSON document and
    /// extracts this field.
    pub key: Option<String>,
    /// Any additional query parameters carried verbatim for
    /// backend-specific use. The resolver does not interpret them.
    pub extra: BTreeMap<String, String>,
}

/// Parse errors. Each variant carries the offending input so the
/// caller can stamp a helpful diagnostic on the config-load error site.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VaultRefError {
    /// Input did not contain a supported URI scheme separator.
    #[error("missing secret-reference URI scheme in `{0}`")]
    MissingPrefix(String),
    /// URI scheme did not match `^[a-z][a-z0-9+.-]*$`.
    #[error("invalid secret-reference URI scheme `{0}` in `{1}`")]
    InvalidScheme(String, String),
    /// URI scheme is reserved for literal URLs, not secret references.
    #[error("reserved URI scheme `{0}` is not a secret reference in `{1}`")]
    ReservedScheme(String, String),
    /// URI scheme is syntactically valid but not in the provider table.
    #[error("unsupported secret-reference URI scheme `{0}` in `{1}`")]
    UnknownScheme(String, String),
    /// Empty backend authority (e.g. `awssm:///path`).
    #[error("missing backend in `{0}`")]
    MissingBackend(String),
    /// Empty path segment (e.g. `awssm://primary/`).
    #[error("missing path in `{0}`")]
    MissingPath(String),
    /// A query parameter was malformed (e.g. `?key` without `=value`).
    #[error("malformed query parameter `{0}` in `{1}`")]
    MalformedQueryParam(String, String),
}

impl VaultRef {
    /// Parse a provider-specific URI string into a typed [`VaultRef`].
    ///
    /// Pure syntax parser: every shape that fits the grammar parses,
    /// regardless of whether the backend / path / key make semantic
    /// sense. Dispatch-time validation lives in each backend.
    pub fn parse(input: &str) -> Result<Self, VaultRefError> {
        let (scheme, after_scheme) = input
            .split_once("://")
            .ok_or_else(|| VaultRefError::MissingPrefix(input.to_string()))?;

        if !is_valid_reference_scheme(scheme) {
            return Err(VaultRefError::InvalidScheme(
                scheme.to_string(),
                input.to_string(),
            ));
        }
        if is_reserved_uri_scheme(scheme) {
            return Err(VaultRefError::ReservedScheme(
                scheme.to_string(),
                input.to_string(),
            ));
        }
        let provider_type = VaultProviderType::from_scheme(scheme)
            .ok_or_else(|| VaultRefError::UnknownScheme(scheme.to_string(), input.to_string()))?;

        // Split off the query string first; the rest is
        // `<backend-name>/<provider-path>`.
        let (path_part, query_part) = match after_scheme.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (after_scheme, None),
        };

        // Backend is the URI authority; path is everything after the
        // first `/`.
        let (backend, path) = match path_part.split_once('/') {
            Some((b, p)) => (b, p),
            None => (path_part, ""),
        };

        if backend.is_empty() {
            return Err(VaultRefError::MissingBackend(input.to_string()));
        }
        if path.is_empty() {
            return Err(VaultRefError::MissingPath(input.to_string()));
        }

        // Decode the query string into version / key / extra.
        let mut version: Option<String> = None;
        let mut key: Option<String> = None;
        let mut extra: BTreeMap<String, String> = BTreeMap::new();

        if let Some(query) = query_part {
            for raw_pair in query.split('&') {
                if raw_pair.is_empty() {
                    continue;
                }
                let (k, v) = raw_pair.split_once('=').ok_or_else(|| {
                    VaultRefError::MalformedQueryParam(raw_pair.to_string(), input.to_string())
                })?;
                match k {
                    "version" => version = Some(v.to_string()),
                    "key" => key = Some(v.to_string()),
                    _ => {
                        extra.insert(k.to_string(), v.to_string());
                    }
                }
            }
        }

        Ok(Self {
            provider_type,
            backend: backend.to_string(),
            path: path.to_string(),
            version,
            key,
            extra,
        })
    }

    /// Render the parsed reference back to its canonical URI form.
    /// Useful for logging and for round-trip tests; the resolver path
    /// itself never re-serialises a parsed reference.
    pub fn to_uri(&self) -> String {
        let mut out = format!(
            "{}://{}/{}",
            self.provider_type.scheme(),
            self.backend,
            self.path
        );
        let mut params: Vec<(String, String)> = Vec::new();
        if let Some(v) = &self.version {
            params.push(("version".to_string(), v.clone()));
        }
        if let Some(k) = &self.key {
            params.push(("key".to_string(), k.clone()));
        }
        for (k, v) in &self.extra {
            params.push((k.clone(), v.clone()));
        }
        if !params.is_empty() {
            out.push('?');
            out.push_str(
                &params
                    .into_iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("&"),
            );
        }
        out
    }
}

/// True when the string is shaped like a non-reserved secret-reference
/// URI. Unknown non-reserved schemes return `true` so config
/// validation can reject them as unsupported references instead of
/// silently passing them through as literals.
pub fn looks_like_secret_reference_uri(s: &str) -> bool {
    let Some((scheme, _)) = s.split_once("://") else {
        return false;
    };
    is_valid_reference_scheme(scheme) && !is_reserved_uri_scheme(scheme)
}

/// Compatibility name for callers that predate provider-specific
/// schemes. The semantics are now general secret-reference URI
/// detection, not `vault://`-only detection.
pub fn looks_like_vault_uri(s: &str) -> bool {
    looks_like_secret_reference_uri(s)
}

fn is_valid_reference_scheme(scheme: &str) -> bool {
    let mut chars = scheme.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '+' | '.' | '-'))
}

fn is_reserved_uri_scheme(scheme: &str) -> bool {
    matches!(scheme, "http" | "https" | "ws" | "wss" | "file" | "data")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal `vault://<backend>/<path>` parses as HashiCorp Vault
    /// with no query block.
    #[test]
    fn parses_hashicorp_uri() {
        let r = VaultRef::parse("vault://primary/secret/data/openai-prod").unwrap();
        assert_eq!(r.provider_type, VaultProviderType::HashiCorp);
        assert_eq!(r.backend, "primary");
        assert_eq!(r.path, "secret/data/openai-prod");
        assert!(r.version.is_none());
        assert!(r.key.is_none());
        assert!(r.extra.is_empty());
    }

    /// AWS Secrets Manager references preserve both common query
    /// parameters and provider-specific extras.
    #[test]
    fn parses_aws_style_reference() {
        let r = VaultRef::parse(
            "awssm://primary/prod/openai-keys?version=3&key=api_key&stage=AWSCURRENT",
        )
        .unwrap();
        assert_eq!(r.provider_type, VaultProviderType::AwsSecretsManager);
        assert_eq!(r.backend, "primary");
        assert_eq!(r.path, "prod/openai-keys");
        assert_eq!(r.version.as_deref(), Some("3"));
        assert_eq!(r.key.as_deref(), Some("api_key"));
        assert_eq!(r.extra.get("stage").map(String::as_str), Some("AWSCURRENT"));
    }

    /// GCP Secret Manager support is in the parser table before the
    /// concrete backend lands.
    #[test]
    fn parses_gcp_style_reference() {
        let r = VaultRef::parse("gcpsm://primary/projects/acme/secrets/openai-key?version=latest")
            .unwrap();
        assert_eq!(r.provider_type, VaultProviderType::GcpSecretManager);
        assert_eq!(r.backend, "primary");
        assert_eq!(r.path, "projects/acme/secrets/openai-key");
        assert_eq!(r.version.as_deref(), Some("latest"));
    }

    /// Kubernetes Secret references keep the provider path opaque.
    #[test]
    fn parses_kubernetes_style_reference() {
        let r = VaultRef::parse("k8ssecret://primary/sbproxy-secrets/openai-key").unwrap();
        assert_eq!(r.provider_type, VaultProviderType::KubernetesSecret);
        assert_eq!(r.backend, "primary");
        assert_eq!(r.path, "sbproxy-secrets/openai-key");
    }

    /// File and local static-map schemes are non-reserved local
    /// secret-reference schemes.
    #[test]
    fn parses_local_store_references() {
        let file_ref = VaultRef::parse("secretfile://local/openai-prod?key=api_key").unwrap();
        assert_eq!(file_ref.provider_type, VaultProviderType::SecretFile);
        assert_eq!(file_ref.key.as_deref(), Some("api_key"));

        let static_ref = VaultRef::parse("secret://local/openai-prod").unwrap();
        assert_eq!(static_ref.provider_type, VaultProviderType::LocalSecret);
        assert_eq!(static_ref.backend, "local");
        assert_eq!(static_ref.path, "openai-prod");
    }

    /// Round-trip: parse then re-serialise. The canonical form is
    /// reproducible.
    #[test]
    fn round_trips_canonical_form() {
        let input = "awssm://primary/prod/openai-keys?version=3&key=api_key";
        let r = VaultRef::parse(input).unwrap();
        assert_eq!(r.to_uri(), input);
    }

    /// Extras are sorted alphabetically on round-trip so the output is
    /// deterministic regardless of the input order.
    #[test]
    fn extras_round_trip_in_sorted_order() {
        let r = VaultRef::parse("vault://primary/secret?namespace=team-a&mount=secret").unwrap();
        let rendered = r.to_uri();
        // `mount` comes before `namespace` alphabetically; the
        // `BTreeMap` over extras guarantees that order on output.
        assert_eq!(
            rendered,
            "vault://primary/secret?mount=secret&namespace=team-a"
        );
    }

    /// Missing URI scheme returns a typed error with the offending
    /// input quoted so the operator sees where the bad reference came
    /// from.
    #[test]
    fn rejects_missing_scheme() {
        let err = VaultRef::parse("plain-string").unwrap_err();
        assert!(matches!(err, VaultRefError::MissingPrefix(s) if s == "plain-string"));
    }

    /// Uppercase schemes fail the lowercase reference grammar.
    #[test]
    fn rejects_invalid_scheme() {
        let err = VaultRef::parse("Vault://primary/secret").unwrap_err();
        assert!(matches!(
            err,
            VaultRefError::InvalidScheme(scheme, _) if scheme == "Vault"
        ));
    }

    /// Reserved URL schemes are literals, not secret references.
    #[test]
    fn rejects_reserved_scheme() {
        let err = VaultRef::parse("https://example.com/key").unwrap_err();
        assert!(matches!(
            err,
            VaultRefError::ReservedScheme(scheme, _) if scheme == "https"
        ));
    }

    /// Non-reserved URI-shaped values with unsupported schemes are
    /// secret references, but not supported ones.
    #[test]
    fn rejects_unknown_scheme() {
        let err = VaultRef::parse("custom://primary/key").unwrap_err();
        assert!(matches!(
            err,
            VaultRefError::UnknownScheme(scheme, _) if scheme == "custom"
        ));
    }

    /// Empty backend authority (`awssm:///path`) is rejected.
    #[test]
    fn rejects_empty_backend() {
        let err = VaultRef::parse("awssm:///some/path").unwrap_err();
        assert!(matches!(err, VaultRefError::MissingBackend(_)));
    }

    /// Empty path segment (`awssm://primary/`) is rejected. A backend
    /// with no path is meaningless; backends that want to refer to a
    /// root-level secret use a single segment after the slash.
    #[test]
    fn rejects_empty_path() {
        let err = VaultRef::parse("awssm://primary/").unwrap_err();
        assert!(matches!(err, VaultRefError::MissingPath(_)));
    }

    /// A backend without any path segment at all is also rejected.
    #[test]
    fn rejects_no_path_separator() {
        let err = VaultRef::parse("awssm://primary").unwrap_err();
        assert!(matches!(err, VaultRefError::MissingPath(_)));
    }

    /// A bare `?key` without `=value` is malformed.
    #[test]
    fn rejects_malformed_query_param() {
        let err = VaultRef::parse("vault://primary/secret?key").unwrap_err();
        assert!(matches!(
            err,
            VaultRefError::MalformedQueryParam(p, _) if p == "key"
        ));
    }

    /// An empty query parameter between two `&`s is skipped, not an
    /// error. Matches the lax URI-query convention.
    #[test]
    fn skips_empty_query_segments() {
        let r = VaultRef::parse("vault://primary/secret?&key=api_key&").unwrap();
        assert_eq!(r.key.as_deref(), Some("api_key"));
    }

    /// Reference detection accepts any syntactically valid
    /// non-reserved URI scheme so unknown schemes can be rejected
    /// explicitly later.
    #[test]
    fn looks_like_secret_reference_uri_distinguishes_shapes() {
        assert!(looks_like_secret_reference_uri("vault://primary/x"));
        assert!(looks_like_secret_reference_uri("awssm://primary/x"));
        assert!(looks_like_secret_reference_uri("custom://primary/x"));
        assert!(!looks_like_secret_reference_uri("${OPENAI_API_KEY}"));
        assert!(!looks_like_secret_reference_uri("file:/etc/secrets/openai"));
        assert!(!looks_like_secret_reference_uri("https://example.com"));
        assert!(!looks_like_secret_reference_uri(
            "file://etc/secrets/openai"
        ));
        assert!(!looks_like_secret_reference_uri("secret:openai"));
        assert!(!looks_like_secret_reference_uri("plain-string"));
    }

    /// The compatibility name now uses the general reference detector.
    #[test]
    fn looks_like_vault_uri_uses_general_reference_detection() {
        assert!(looks_like_vault_uri("awssm://primary/x"));
        assert!(!looks_like_vault_uri("https://example.com"));
    }
}

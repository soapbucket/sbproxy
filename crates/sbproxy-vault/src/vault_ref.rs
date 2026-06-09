// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Typed parser for the unified credential-reference URI.
//!
//! ## Grammar
//!
//! ```text
//! vault://<backend>/<path>[?version=<n>][&key=<json-field>]
//! ```
//!
//! Examples (all valid):
//!
//! ```text
//! vault://hashi/secret/data/openai-prod?key=api_key
//! vault://aws/prod/openai-keys?key=api_key
//! vault://k8s/default/sbproxy-secrets/openai-key
//! vault://file/etc/sbproxy/secrets/openai
//! vault://env/OPENAI_API_KEY
//! vault://sqlite/credentials/openai?version=3&key=current
//! ```
//!
//! The parser is pure syntax: it does NOT verify that `<backend>` has
//! a registered implementation, that `<path>` is shaped correctly for
//! the backend, or that `<key>` points at a real JSON field. Those
//! checks land at dispatch time inside each backend implementation.
//!
//! ## Backward compatibility
//!
//! `${ENV_VAR}`, `file:/path/to/secret`, and `secret:<name>` shapes
//! ship a sibling parser; the resolver tries each in turn. The
//! parser is the first carve of the work; the resolver wiring
//! (try-each-in-turn) lands alongside the first concrete backend.
//!
//! ## Multi-tenant resolution
//!
//! The URI itself is intentionally tenant-agnostic: `vault://hashi/...`
//! does not name a tenant. The `<backend>` segment is the
//! operator-chosen name of a backend block configured at proxy,
//! tenant, or origin scope. Resolution order at request time is
//! origin scope first, then tenant scope, then proxy scope; the
//! first scope that declares the named backend serves the
//! reference. The same `vault://hashi/secret/data/openai-prod`
//! reference can therefore resolve to different physical Vault
//! instances across tenants without rewriting the reference,
//! because each tenant redeclares the `hashi` backend block with
//! its own endpoint and token.
//!
//! The request's tenant id (stamped on `RequestContext.tenant_id`
//! by the routing layer) is the resolution context, not part of
//! the URI.

use std::collections::BTreeMap;

/// One parsed `vault://...` reference. Cheap to clone (string fields
/// only); intended to be carried in compiled config and resolved once
/// per request without re-parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultRef {
    /// Backend name (the prefix after `vault://`).
    pub backend: String,
    /// Path within the backend. Backend-specific shape; the parser
    /// keeps it verbatim.
    pub path: String,
    /// Optional `version=<n>` pin. Backends that do not support
    /// versioning ignore this at resolve time.
    pub version: Option<String>,
    /// Optional `key=<json-field>` sub-field selector. When set,
    /// the resolver expects the backend secret to be a JSON document
    /// and extracts this field.
    pub key: Option<String>,
    /// Any additional query parameters carried verbatim for
    /// backend-specific use. The resolver does not interpret them.
    pub extra: BTreeMap<String, String>,
}

/// Parse errors. Each variant carries the offending input so the
/// caller can stamp a helpful diagnostic on the config-load error
/// site.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VaultRefError {
    /// Input did not start with the `vault://` prefix.
    #[error("missing `vault://` prefix in `{0}`")]
    MissingPrefix(String),
    /// Empty backend segment (e.g. `vault:///path`).
    #[error("missing backend in `{0}`")]
    MissingBackend(String),
    /// Empty path segment (e.g. `vault://hashi/`).
    #[error("missing path in `{0}`")]
    MissingPath(String),
    /// A query parameter was malformed (e.g. `?key` without `=value`).
    #[error("malformed query parameter `{0}` in `{1}`")]
    MalformedQueryParam(String, String),
}

impl VaultRef {
    /// Parse a `vault://...` URI string into a typed [`VaultRef`].
    ///
    /// Pure syntax parser: every shape that fits the grammar parses,
    /// regardless of whether the backend / path / key make semantic
    /// sense. Dispatch-time validation lives in each backend.
    pub fn parse(input: &str) -> Result<Self, VaultRefError> {
        let after_prefix = input
            .strip_prefix("vault://")
            .ok_or_else(|| VaultRefError::MissingPrefix(input.to_string()))?;

        // Split off the query string first; the rest is `<backend>/<path>`.
        let (path_part, query_part) = match after_prefix.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (after_prefix, None),
        };

        // Backend is everything up to the first `/`; path is the rest.
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
            backend: backend.to_string(),
            path: path.to_string(),
            version,
            key,
            extra,
        })
    }

    /// Render the parsed reference back to its canonical `vault://`
    /// form. Useful for logging and for round-trip tests; the
    /// resolver path itself never re-serialises a parsed reference.
    pub fn to_uri(&self) -> String {
        let mut out = format!("vault://{}/{}", self.backend, self.path);
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

/// True when the string is shaped like a `vault://` reference.
/// Cheap pre-check used by the resolver to decide which sub-parser
/// owns the input.
pub fn looks_like_vault_uri(s: &str) -> bool {
    s.starts_with("vault://")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal `vault://<backend>/<path>` parses with no query block.
    #[test]
    fn parses_minimal_uri() {
        let r = VaultRef::parse("vault://env/OPENAI_API_KEY").unwrap();
        assert_eq!(r.backend, "env");
        assert_eq!(r.path, "OPENAI_API_KEY");
        assert!(r.version.is_none());
        assert!(r.key.is_none());
        assert!(r.extra.is_empty());
    }

    /// Both `version` and `key` query parameters land on the typed
    /// fields; everything else lands in `extra`.
    #[test]
    fn parses_full_uri_with_version_key_and_extras() {
        let r = VaultRef::parse(
            "vault://hashi/secret/data/openai-prod?version=3&key=api_key&mount=secret",
        )
        .unwrap();
        assert_eq!(r.backend, "hashi");
        assert_eq!(r.path, "secret/data/openai-prod");
        assert_eq!(r.version.as_deref(), Some("3"));
        assert_eq!(r.key.as_deref(), Some("api_key"));
        assert_eq!(r.extra.get("mount").map(String::as_str), Some("secret"));
    }

    /// AWS-shaped reference with a single `key` field. Confirms the
    /// parser does not require a multi-segment path.
    #[test]
    fn parses_aws_style_reference() {
        let r = VaultRef::parse("vault://aws/prod/openai-keys?key=api_key").unwrap();
        assert_eq!(r.backend, "aws");
        assert_eq!(r.path, "prod/openai-keys");
        assert_eq!(r.key.as_deref(), Some("api_key"));
    }

    /// Kubernetes-style reference with no query block but a
    /// multi-segment path.
    #[test]
    fn parses_kubernetes_style_reference() {
        let r = VaultRef::parse("vault://k8s/default/sbproxy-secrets/openai-key").unwrap();
        assert_eq!(r.backend, "k8s");
        assert_eq!(r.path, "default/sbproxy-secrets/openai-key");
    }

    /// Round-trip: parse then re-serialise. The canonical form is
    /// reproducible.
    #[test]
    fn round_trips_canonical_form() {
        let input = "vault://hashi/secret/data/openai-prod?version=3&key=api_key";
        let r = VaultRef::parse(input).unwrap();
        assert_eq!(r.to_uri(), input);
    }

    /// Extras are sorted alphabetically on round-trip so the output
    /// is deterministic regardless of the input order.
    #[test]
    fn extras_round_trip_in_sorted_order() {
        let r = VaultRef::parse("vault://hashi/secret?mount=secret&namespace=team-a").unwrap();
        let rendered = r.to_uri();
        // `mount` comes before `namespace` alphabetically; the
        // `BTreeMap` over extras guarantees that order on output.
        assert_eq!(
            rendered,
            "vault://hashi/secret?mount=secret&namespace=team-a"
        );
    }

    /// Missing `vault://` prefix returns a typed error with the
    /// offending input quoted so the operator sees where the bad
    /// reference came from.
    #[test]
    fn rejects_missing_prefix() {
        let err = VaultRef::parse("http://hashi/secret").unwrap_err();
        assert!(matches!(err, VaultRefError::MissingPrefix(s) if s == "http://hashi/secret"));
    }

    /// Empty backend segment (`vault:///path`) is rejected.
    #[test]
    fn rejects_empty_backend() {
        let err = VaultRef::parse("vault:///some/path").unwrap_err();
        assert!(matches!(err, VaultRefError::MissingBackend(_)));
    }

    /// Empty path segment (`vault://hashi/`) is rejected. A backend
    /// with no path is meaningless; backends that want to refer to
    /// a root-level secret use a single segment after the slash.
    #[test]
    fn rejects_empty_path() {
        let err = VaultRef::parse("vault://hashi/").unwrap_err();
        assert!(matches!(err, VaultRefError::MissingPath(_)));
    }

    /// A backend without any path segment at all is also rejected.
    /// (`vault://hashi` with no slash.)
    #[test]
    fn rejects_no_path_separator() {
        let err = VaultRef::parse("vault://hashi").unwrap_err();
        assert!(matches!(err, VaultRefError::MissingPath(_)));
    }

    /// A bare `?key` without `=value` is malformed.
    #[test]
    fn rejects_malformed_query_param() {
        let err = VaultRef::parse("vault://hashi/secret?key").unwrap_err();
        assert!(matches!(
            err,
            VaultRefError::MalformedQueryParam(p, _) if p == "key"
        ));
    }

    /// An empty query parameter between two `&`s is skipped, not an
    /// error. Matches the lax URI-query convention.
    #[test]
    fn skips_empty_query_segments() {
        let r = VaultRef::parse("vault://hashi/secret?&key=api_key&").unwrap();
        assert_eq!(r.key.as_deref(), Some("api_key"));
    }

    /// `looks_like_vault_uri` is the cheap pre-check the resolver
    /// uses to pick between the `vault://` parser and the legacy
    /// `${ENV}` / `file:` / `secret:` parsers.
    #[test]
    fn looks_like_vault_uri_distinguishes_shapes() {
        assert!(looks_like_vault_uri("vault://env/X"));
        assert!(!looks_like_vault_uri("${OPENAI_API_KEY}"));
        assert!(!looks_like_vault_uri("file:/etc/secrets/openai"));
        assert!(!looks_like_vault_uri("secret:openai"));
        assert!(!looks_like_vault_uri("plain-string"));
    }

    /// Empty input fails the `vault://` prefix check; the error
    /// quotes the empty string so the operator sees "bad reference
    /// was empty".
    #[test]
    fn rejects_empty_input() {
        let err = VaultRef::parse("").unwrap_err();
        assert!(matches!(err, VaultRefError::MissingPrefix(s) if s.is_empty()));
    }
}

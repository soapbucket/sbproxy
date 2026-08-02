//! Load-time check that every secret reference names a backend that is
//! actually declared (WOR-2227).
//!
//! A `secret://<backend>/<key>` reference resolves at handler build
//! against the exact `(provider type, backend name)` pair the binary
//! registered from `proxy.secrets.backends`. Nothing before this check
//! looked at the authority, so a config naming a backend that exists
//! nowhere compiled clean, validated clean, and planned clean, then died
//! at boot with a resolver error from a layer the operator had not been
//! reading. Three shipped examples were broken that way and no lane
//! noticed.
//!
//! The scheme picks the backend `type:`, so a name alone is not enough:
//! `secret://cache/key` against a `cache` declared as `hashicorp` fails
//! at boot exactly like a `cache` that was never declared, because the
//! manager keys on the pair rather than the name.
//!
//! The check is pure syntax plus one lookup. It opens no socket, reads
//! no secrets file, and resolves no value, so it holds on a machine that
//! has none of the credentials. That is what lets `sbproxy validate` and
//! the `validate_examples` sweep inherit it without a new lane.

use crate::types::{SecretBackendConfig, SecretsConfig};

/// The `proxy.secrets.backends[].type` each reference scheme resolves
/// against, taken from the variant doc comments on
/// [`crate::types::SecretBackendConfig`].
///
/// The pairing is exact rather than advisory: `VaultManager` keys its
/// registrations on `(provider type, backend name)`, so a `local`
/// backend named `cache` does not serve `vault://cache/...` and a
/// `hashicorp` one does not serve `secret://cache/...`.
const SCHEME_BACKEND_TYPES: &[(&str, &str)] = &[
    ("secret", "local"),
    ("secretfile", "file"),
    ("vault", "hashicorp"),
    ("awssm", "aws"),
    ("gcpsm", "gcp"),
    ("azurekv", "azure"),
    ("k8ssecret", "k8s"),
];

/// Reject every secret reference in the document whose authority is not
/// declared under `proxy.secrets.backends` with a matching backend
/// `type:`.
///
/// Walks the parsed YAML rather than the typed config so the opaque
/// blocks reach the check too: `action`, `authentication`, `policies`,
/// `transforms`, `variables`, and both `extensions` maps are
/// `serde_json::Value` in the schema, and a credential inside one of
/// them resolves through the same manager as a typed field.
///
/// # Errors
///
/// Returns an error naming every offending field path, its reference,
/// and what is missing.
pub(crate) fn check_secret_backend_references(
    yaml: &str,
    secrets: Option<&SecretsConfig>,
) -> anyhow::Result<()> {
    // The typed parse in `compile_config` owns malformed YAML and has
    // already produced the operator-facing error by the time this runs,
    // so a second failure here would be noise on top of it.
    let Ok(root) = serde_yaml::from_str::<serde_yaml::Value>(yaml) else {
        return Ok(());
    };

    let declared = declared_backends(secrets);
    let mut problems: Vec<String> = Vec::new();
    walk("", &root, &declared, &mut problems);

    match problems.len() {
        0 => Ok(()),
        1 => anyhow::bail!("config compile: {}", problems[0]),
        count => {
            let list = problems.join("\n  - ");
            anyhow::bail!(
                "config compile: {count} secret references do not resolve against \
                 proxy.secrets.backends:\n  - {list}"
            )
        }
    }
}

/// Index the declared backends as `(type, name)` pairs, the same shape
/// the runtime manager registers.
fn declared_backends(secrets: Option<&SecretsConfig>) -> Vec<(&str, &str)> {
    let Some(secrets) = secrets else {
        return Vec::new();
    };
    secrets
        .backends
        .iter()
        .map(|backend| match backend {
            SecretBackendConfig::Local { name, .. } => ("local", name.as_str()),
            SecretBackendConfig::File { name, .. } => ("file", name.as_str()),
            SecretBackendConfig::Hashicorp { name, .. } => ("hashicorp", name.as_str()),
            SecretBackendConfig::Aws { name, .. } => ("aws", name.as_str()),
            SecretBackendConfig::Gcp { name, .. } => ("gcp", name.as_str()),
            SecretBackendConfig::Azure { name, .. } => ("azure", name.as_str()),
            SecretBackendConfig::K8s { name, .. } => ("k8s", name.as_str()),
        })
        .collect()
}

/// Walk the value tree, stamping each finding with the dotted path the
/// operator can search their document for.
fn walk(path: &str, value: &serde_yaml::Value, declared: &[(&str, &str)], out: &mut Vec<String>) {
    match value {
        serde_yaml::Value::String(text) => {
            if let Some(problem) = reference_problem(path, text, declared) {
                out.push(problem);
            }
        }
        serde_yaml::Value::Mapping(map) => {
            for (key, child) in map {
                let key = key.as_str().unwrap_or("?");
                let child_path = if path.is_empty() {
                    key.to_string()
                } else {
                    format!("{path}.{key}")
                };
                walk(&child_path, child, declared, out);
            }
        }
        serde_yaml::Value::Sequence(items) => {
            for (index, child) in items.iter().enumerate() {
                walk(&format!("{path}[{index}]"), child, declared, out);
            }
        }
        // Numbers, booleans, and null cannot carry a reference. Tagged
        // values never arrive here: `scan_yaml_hazards` rejects custom
        // YAML tags earlier in `compile_config`.
        _ => {}
    }
}

/// Diagnose one scalar. `None` means the value is either not a secret
/// reference at all or resolves against a declared backend.
fn reference_problem(path: &str, value: &str, declared: &[(&str, &str)]) -> Option<String> {
    let reference = value.trim();
    let (scheme, rest) = reference.split_once("://")?;

    // Only the seven schemes the resolver claims. Anything else is a URL
    // the operator meant literally, and passing it through is what the
    // parser already does.
    let scheme_kind = SCHEME_BACKEND_TYPES
        .iter()
        .find(|(candidate, _)| *candidate == scheme)
        .map(|(_, kind)| *kind)?;

    let (authority_and_key, query) = match rest.split_once('?') {
        Some((head, tail)) => (head, Some(tail)),
        None => (rest, None),
    };
    let Some((authority, key)) = authority_and_key.split_once('/') else {
        return Some(malformed(path, reference, scheme));
    };
    if authority.is_empty() || key.is_empty() {
        return Some(malformed(path, reference, scheme));
    }

    // `vault://env/NAME` is the deprecated environment alias: the
    // resolver rewrites it to `${NAME}` before any backend is consulted,
    // so it needs no declaration and must not be rejected during the
    // compatibility window. Only that exact shape takes the shortcut,
    // matching `sbproxy_vault::legacy_vault_env_name`.
    if scheme == "vault" && authority == "env" && query.is_none() && is_env_var_name(key) {
        return None;
    }

    let required = legacy_alias_backend_type(scheme, authority).unwrap_or(scheme_kind);
    if declared
        .iter()
        .any(|(kind, name)| *kind == required && *name == authority)
    {
        return None;
    }

    // The name exists but under a different `type:`. Name what was
    // declared and hand back the scheme that reads it, because the
    // operator is one character from a working config either way.
    let mismatched: Vec<&str> = declared
        .iter()
        .filter(|(_, name)| *name == authority)
        .map(|(kind, _)| *kind)
        .collect();
    if !mismatched.is_empty() {
        let declared_kinds = mismatched.join("` and a `");
        let suggestion = scheme_for_backend_type(mismatched[0]);
        return Some(format!(
            "{path} selects secret backend `{authority}` through `{reference}`, but \
             proxy.secrets.backends declares `{authority}` as a `{declared_kinds}` backend and \
             the `{scheme}://` scheme resolves only against a `{required}` backend. Read from \
             the backend you declared with `{suggestion}://{authority}/...`, or declare a \
             `{required}` backend named `{authority}`."
        ));
    }

    // `env` and `file` are the two authorities operators reach for by
    // reflex, and both are wrong: the environment and file forms are not
    // URIs and never touch a backend. Say so, because the generic
    // message reads as "declare a backend named env" and sends the
    // reader off to configure something they do not need.
    if authority == "env" {
        let concrete = if is_env_var_name(key) {
            format!("write `env:{key}` or `${{{key}}}`")
        } else {
            "write `env:NAME` or `${NAME}`".to_string()
        };
        return Some(format!(
            "{path} is `{reference}`, which is not the environment form. In a \
             `{scheme}://<backend>/<key>` reference the authority is the name of a backend \
             declared under proxy.secrets.backends, so this asks for a `{required}` backend \
             literally named `env` and none is declared. To read the environment variable, \
             {concrete}; to read a file, write `file:/path/to/secret`. Neither needs any \
             proxy.secrets configuration."
        ));
    }
    if authority == "file" {
        return Some(format!(
            "{path} is `{reference}`, which is not the file form. In a \
             `{scheme}://<backend>/<key>` reference the authority is the name of a backend \
             declared under proxy.secrets.backends, so this asks for a `{required}` backend \
             literally named `file` and none is declared. To read a file, write \
             `file:/{key}`; to read an environment variable, write `env:NAME` or `${{NAME}}`. \
             Neither needs any proxy.secrets configuration."
        ));
    }

    Some(format!(
        "{path} selects secret backend `{authority}` through `{reference}`, but \
         proxy.secrets.backends declares no `{required}` backend named `{authority}`. Declare \
         one under proxy.secrets.backends, or point the field at a backend that is already \
         declared."
    ))
}

/// A reference with the right scheme and no usable `<backend>/<key>`
/// split. The resolver fails on these too, just later and with the
/// removed `secret:<name>` migration text mangled onto the front.
fn malformed(path: &str, reference: &str, scheme: &str) -> String {
    format!(
        "{path} is `{reference}`, which is not a usable secret reference. The form is \
         `{scheme}://<backend>/<key>`, where `<backend>` names an entry under \
         proxy.secrets.backends and `<key>` is the secret to read."
    )
}

/// The backend `type:` a legacy `vault://<alias>/...` reference needs.
///
/// `vault://aws/x` is still accepted and resolves as `awssm://aws/x`, so
/// it wants an `aws` backend named `aws`, not a `hashicorp` one. Mirrors
/// `sbproxy_vault::legacy_vault_reference_replacement`; `vault://hashi/`
/// is a no-op rewrite and falls through to the scheme's own type.
fn legacy_alias_backend_type(scheme: &str, authority: &str) -> Option<&'static str> {
    if scheme != "vault" {
        return None;
    }
    match authority {
        "aws" => Some("aws"),
        "k8s" => Some("k8s"),
        "file" => Some("file"),
        _ => None,
    }
}

/// The scheme that reads a given backend `type:`. Used only to suggest
/// the fix for a name declared under the wrong type.
fn scheme_for_backend_type(kind: &str) -> &str {
    SCHEME_BACKEND_TYPES
        .iter()
        .find(|(_, candidate)| *candidate == kind)
        .map(|(scheme, _)| *scheme)
        .unwrap_or(kind)
}

/// Mirrors `sbproxy_vault::vault_ref::is_env_var_name`. Duplicated
/// rather than imported because `sbproxy-config` is a public crate and
/// does not depend on the vault crate, which drags in the AWS, GCP,
/// Azure, and Kubernetes SDKs.
fn is_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use crate::compiler::compile_config;

    /// A config whose only interesting field is `api_key`, so a failure
    /// names the secret rule rather than an unrelated origin default.
    fn ai_config(secrets_block: &str, api_key: &str) -> String {
        format!(
            r#"
proxy:
  http_bind_port: 18080
{secrets_block}
origins:
  api.example.com:
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: {api_key}
"#
        )
    }

    const LOCAL_BACKEND: &str = r#"  secrets:
    backends:
      - type: local
        name: cache
        entries:
          openai-prod: sk-fixture
"#;

    const HASHICORP_BACKEND: &str = r#"  secrets:
    backends:
      - type: hashicorp
        name: cache
        addr: https://vault.example.test/v1
        auth:
          type: token
          token: fixture-token
"#;

    /// The reported bug: an authority that exists nowhere used to
    /// compile and then fail at boot.
    #[test]
    fn undeclared_backend_fails_compile_with_the_field_path() {
        let yaml = ai_config("", "secret://no-such-backend/openai-prod");
        let Err(error) = compile_config(&yaml) else {
            panic!("a reference to an undeclared backend must not compile");
        };
        let error = error.to_string();
        assert!(
            error.contains("origins.api.example.com.action.providers[0].api_key"),
            "the error must name the field path: {error}"
        );
        assert!(
            error.contains("no-such-backend") && error.contains("proxy.secrets.backends"),
            "the error must name the backend and where to declare one: {error}"
        );
    }

    /// The name is declared, but under a type that cannot serve the
    /// scheme. Same boot failure, so the same load failure.
    #[test]
    fn declared_backend_of_the_wrong_kind_fails_compile() {
        let yaml = ai_config(HASHICORP_BACKEND, "secret://cache/openai-prod");
        let Err(error) = compile_config(&yaml) else {
            panic!("`secret://` must not resolve against a hashicorp backend");
        };
        let error = error.to_string();
        assert!(
            error.contains("hashicorp") && error.contains("local"),
            "the error must contrast the declared type with the required one: {error}"
        );
        assert!(
            error.contains("vault://cache/"),
            "the error must offer the scheme that reads the declared backend: {error}"
        );
    }

    /// The trap that produced three broken examples. The generic
    /// message would tell the reader to declare a backend named `env`.
    #[test]
    fn secret_scheme_with_an_env_authority_points_at_the_environment_form() {
        let yaml = ai_config("", "secret://env/OPENAI_API_KEY");
        let Err(error) = compile_config(&yaml) else {
            panic!("`secret://env/NAME` must not compile");
        };
        let error = error.to_string();
        assert!(
            error.contains("not the environment form"),
            "the error must say the shape is not the environment form: {error}"
        );
        assert!(
            error.contains("env:OPENAI_API_KEY") && error.contains("file:/path/to/secret"),
            "the error must point at both configuration-free forms: {error}"
        );
    }

    /// The same reflex with the file authority.
    #[test]
    fn secret_scheme_with_a_file_authority_points_at_the_file_form() {
        let yaml = ai_config("", "secretfile://file/etc/sbproxy/openai");
        let Err(error) = compile_config(&yaml) else {
            panic!("`secretfile://file/...` must not compile");
        };
        let error = error.to_string();
        assert!(
            error.contains("not the file form") && error.contains("file:/etc/sbproxy/openai"),
            "the error must point at the file form: {error}"
        );
    }

    /// The two forms that need no configuration at all keep compiling.
    #[test]
    fn env_and_file_forms_still_compile_untouched() {
        for reference in ["env:OPENAI_API_KEY", "file:/etc/sbproxy/openai"] {
            let yaml = ai_config("", reference);
            compile_config(&yaml)
                .unwrap_or_else(|error| panic!("{reference} must still compile: {error:#}"));
        }
    }

    /// A declared backend of the matching type resolves, so the check
    /// is not simply rejecting every reference.
    #[test]
    fn declared_backend_of_the_matching_kind_compiles() {
        let yaml = ai_config(LOCAL_BACKEND, "secret://cache/openai-prod");
        compile_config(&yaml).expect("a declared local backend must serve `secret://`");
    }

    /// The deprecated `vault://env/NAME` alias resolves to an
    /// environment variable without consulting any backend, so the
    /// check must leave it alone for the length of its window.
    #[test]
    fn the_legacy_vault_env_alias_still_compiles() {
        let yaml = ai_config("", "vault://env/OPENAI_API_KEY");
        compile_config(&yaml).expect("the legacy env alias must survive its deprecation window");
    }

    /// The other legacy aliases rewrite the scheme but keep the
    /// authority, so they need a backend of the rewritten type.
    #[test]
    fn legacy_provider_aliases_require_the_rewritten_backend_type() {
        let declared = r#"  secrets:
    backends:
      - type: aws
        name: aws
        region: us-east-1
        mount_prefix: prod/
        auth:
          type: default_chain
"#;
        compile_config(&ai_config(declared, "vault://aws/prod/openai-key"))
            .expect("`vault://aws/...` resolves against an `aws` backend named `aws`");

        let Err(error) = compile_config(&ai_config("", "vault://aws/prod/openai-key")) else {
            panic!("`vault://aws/...` must not compile without that backend");
        };
        let error = error.to_string();
        assert!(
            error.contains("`aws` backend"),
            "the error must name the rewritten backend type: {error}"
        );
    }

    /// A reference with no key segment fails at load rather than
    /// reaching the resolver, where the removed `secret:<name>`
    /// migration text gets mangled onto the front of it.
    #[test]
    fn a_reference_with_no_key_segment_fails_compile() {
        let yaml = ai_config("", "secret://openai-prod");
        let Err(error) = compile_config(&yaml) else {
            panic!("`secret://<name>` has no key segment and must not compile");
        };
        let error = error.to_string();
        assert!(
            error.contains("secret://<backend>/<key>"),
            "the error must show the reference form: {error}"
        );
    }

    /// Reserved and unknown schemes are literals, not secret
    /// references, and must not be dragged into the check.
    #[test]
    fn non_secret_uri_schemes_are_left_alone() {
        let yaml = r#"
proxy:
  http_bind_port: 18080
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.test
    variables:
      docs: "custom://primary/not-a-secret"
"#;
        compile_config(yaml).expect("a non-secret URI scheme must compile");
    }

    /// Every offending field is reported in one pass, so a config with
    /// three broken references does not take three compile cycles.
    #[test]
    fn every_offending_reference_is_reported_at_once() {
        let yaml = r#"
proxy:
  http_bind_port: 18080
origins:
  api.example.com:
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: secret://missing-one/key
        - name: anthropic
          api_key: secret://missing-two/key
"#;
        let Err(error) = compile_config(yaml) else {
            panic!("both references must be rejected");
        };
        let error = error.to_string();
        assert!(
            error.contains("missing-one") && error.contains("missing-two"),
            "both offending references must appear: {error}"
        );
    }
}

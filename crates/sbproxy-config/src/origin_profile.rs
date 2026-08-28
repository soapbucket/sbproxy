//! Project-owned origin profiles, and the pure composition resolver
//! that turns them into the `origins:` map (WOR-2434, WOR-2435).
//!
//! A project repository knows what its own service does. It does not
//! know the hostname the service answers on, because a hostname is an
//! environment fact. So a project commits a hostless
//! [`OriginProfile`]: an action, some policies, some transforms, and
//! the inputs it needs from whoever deploys it. The runtime config
//! repository owns `proxy:`, [`crate::ConfigFile::origin_defaults`] and
//! [`crate::ConfigFile::origin_sources`], and supplies the hosts. This
//! module layers the two and produces the origins.
//!
//! # The trust boundary has two halves
//!
//! **Write side.** [`OriginProfileSpec`] is an allowlist, not a deny
//! list. `RawOriginConfig` has 52 fields and gains more regularly, so a
//! deny list would make every future field a silent privilege grant to
//! every project repository, with no review step that would catch it.
//! Unclassified has to mean forbidden. A field a project may not set is
//! not merely rejected here, it is unrepresentable: there is no
//! [`OriginProfileSpec`] field that could hold it, and the profile
//! document is `deny_unknown_fields`, so the refusal is the parser's.
//! [`PLATFORM_OWNED_ORIGIN_FIELDS`] names the other half, and
//! `every_raw_origin_field_is_classified` fails when a new field lands
//! on neither list.
//!
//! **Read side.** A profile is a confined document
//! ([`crate::confined_template`]). It reaches the composing process
//! environment through neither `${VAR}` nor `{{env.X}}`, carries no
//! host-backed secret reference (`env:NAME`, `file:/path`,
//! `vault://env/NAME`), and names no host path the proxy opens. The
//! only variables it resolves are the ones it declared and the entry
//! bound.
//!
//! # Why the resolve runs on untyped values
//!
//! Three reasons, each one load-bearing:
//!
//! 1. `request_modifiers:` and `response_modifiers:` deserialize into
//!    `RequestModifierConfig` / `ResponseModifierConfig`, which are
//!    `deny_unknown_fields` and have no `name` field. A `name:` merge
//!    key cannot survive a typed parse, so the merge has to happen
//!    before one.
//! 2. `policies: []` and an absent `policies:` are the same value once
//!    parsed into `Vec<_>` behind `#[serde(default)]`. The scenario the
//!    whole floor concept exists to prevent, a project deleting the
//!    platform WAF by shipping an empty list, is undetectable after
//!    that parse.
//! 3. `merge_yaml_value` and [`crate::config_merge`] both replace
//!    sequences wholesale, deliberately, because element identity in a
//!    generic YAML list is not knowable. That reasoning is correct and
//!    stays. This is not a generic merge: it carries a table of which
//!    list keys merge by `name`, so it can require identity where a
//!    generic merge cannot.
//!
//! So the layers merge as `serde_yaml::Value`, the bookkeeping keys are
//! stripped, and `RawOriginConfig` is deserialized once at the end.
//!
//! # Layering
//!
//! Later layers win: `origin_defaults`, then the profile `base:`, then
//! the profile `environments.<env>:` the entry selected, then the
//! entry `overrides:`. The runtime bookends the stack, so a project can
//! be given room without being given the last word.
//!
//! # No filesystem, no network
//!
//! Nothing in this module opens a file or a socket. The caller fetches
//! the profile documents (WOR-2437) and hands them in as text. Every
//! test here runs with no `git` binary present.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};

use crate::confined_template::{resolve_confined_fragment, ConfinedTemplateError};
use crate::types::{
    is_secret_reference, EnvironmentTier, OriginSourceEntry, OriginSourcesConfig, RawOriginConfig,
};

/// The four origin list keys whose entries merge by `name:` rather than
/// replacing wholesale.
///
/// Every other sequence in an origin replaces, matching the generic
/// merge contract. These four are the lists a platform floor is written
/// in and a project needs to extend, and each one is a list of tagged
/// objects where a `name:` is a meaningful identity rather than a
/// guess.
pub const PROFILE_LIST_MERGE_KEYS: &[&str] = &[
    "policies",
    "transforms",
    "request_modifiers",
    "response_modifiers",
];

/// Keys the resolver reads for its own bookkeeping and strips before
/// the composed origin is deserialized.
///
/// They are stripped rather than tolerated because the modules the
/// lists feed are `deny_unknown_fields`: a surviving `name:` on a
/// `rate_limit_budget` policy fails the module parse at boot, which is
/// long after the compose that put it there.
const BOOKKEEPING_KEYS: &[&str] = &["name", "locked", "disabled"];

/// Mapping keys in a profile whose string value must be a secret
/// reference rather than the secret itself.
///
/// Secrets stay a runtime concern throughout: a project declares that it
/// needs one and the entry supplies the reference, exactly as
/// `source.credential` refuses an inline literal. The check runs on the
/// document **after** `{{vars.X}}` substitution, so it also polices what
/// an entry bound: an entry that binds a raw token into a declared input
/// is refused the same way the profile would have been for writing one.
///
/// # What this list cannot see
///
/// It is a list of key names, the same shape and the same limit as
/// `HOST_FILE_KEYS` in [`crate::confined_template`]. A secret written
/// under a key nobody thought of (`x_auth`, `upstream_pass`) is not
/// refused, and neither is one hidden inside a URL
/// (`https://user:token@host`) or inside a script body. What closes that
/// gap is not a longer list: it is that the only spelling a profile has
/// for a working secret is `secret://backend/name`, whose backend the
/// project cannot declare, because `proxy.secrets` is on
/// [`crate::AUTHORITY_DENIED_PATHS`] and has no `OriginProfileSpec`
/// field. A literal smuggled past this list is a literal that still has
/// to be a valid upstream credential, which is a mistake rather than an
/// escalation.
const PROFILE_SECRET_KEYS: &[&str] = &[
    "access_token",
    "api_key",
    "apikey",
    "auth_token",
    "bearer_token",
    "client_secret",
    "credential",
    "hmac_key",
    "passphrase",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "secret_key",
    "shared_secret",
    "signing_key",
    "token",
    "webhook_secret",
];

/// The fields of `RawOriginConfig` a project profile may not set, each
/// with the reason it belongs to whoever runs the proxy.
///
/// This list plus the fields of [`OriginProfileSpec`] must cover
/// `RawOriginConfig` exactly. `every_raw_origin_field_is_classified`
/// asserts it, so a new origin field fails a test that tells the author
/// to classify it rather than quietly becoming writable by every
/// project repository in the fleet.
///
/// Where a platform-owned field has a legitimate project-facing knob,
/// the knob is a declared [`OriginProfileInput`] the runtime binds, not
/// a passthrough.
pub const PLATFORM_OWNED_ORIGIN_FIELDS: &[(&str, &str)] = &[
    (
        "tenant_id",
        "names a tenant declared under `proxy.tenants[]`; a project choosing its own tenant \
         chooses its own quota, its own credentials and its own audit scope",
    ),
    (
        "credentials",
        "origin-scope credential material. Secrets stay a runtime concern throughout: a \
         project declares that it needs one, the entry supplies the reference",
    ),
    (
        "filters",
        "Proxy-Wasm filter attachments. `filters[].failure_posture` accepts `open`, so a \
         project able to write this list flips a platform security filter to fail-open while \
         the config still advertises protection",
    ),
    (
        "hsts",
        "a transport-security header whose max-age outlives the config that set it",
    ),
    (
        "session",
        "session cookie name, domain and flags. A project able to widen the cookie domain \
         reads another origin's session",
    ),
    (
        "properties",
        "custom-property capture, echo and redaction. Redaction is an operator promise",
    ),
    (
        "sessions",
        "session-id capture, including whether an id is auto-generated for anonymous callers",
    ),
    (
        "user",
        "user-id capture. What identifies a person in the logs is not a per-service decision",
    ),
    (
        "force_ssl",
        "`force_ssl: false` silently drops the HTTPS redirect, and the deny list the design \
         first reached for would have missed it",
    ),
    (
        "allowed_methods",
        "an empty list allows every method, so a project able to write this widens whatever \
         the platform narrowed",
    ),
    (
        "forward_rules",
        "inline child origins. Each one is a whole origin body reached by path prefix, so \
         this field is the entire boundary again one level down",
    ),
    (
        "fallback_origin",
        "where traffic goes when the upstream fails, which is a routing fact the platform owns",
    ),
    (
        "response_cache",
        "a project that caches an authenticated response has it served to somebody else",
    ),
    (
        "variables",
        "template variables read by every other block. A project-facing knob is a declared \
         `input`, which the runtime binds and the confined pass checks",
    ),
    (
        "on_request",
        "extension hooks: arbitrary code on the request path",
    ),
    (
        "on_response",
        "extension hooks: arbitrary code on the response path",
    ),
    (
        "bot_detection",
        "a platform-wide security posture, not a per-service preference",
    ),
    (
        "threat_protection",
        "IP reputation and blocklists, which are a platform-wide security posture",
    ),
    (
        "proxy_status",
        "the RFC 9209 identity token this deployment stamps on every error",
    ),
    (
        "traffic_capture",
        "refused at config compile outright; a profile naming it would fail later and more \
         confusingly than failing here",
    ),
    (
        "mirror",
        "fire-and-forget copies of live requests to a second upstream, which is an exfiltration \
         primitive",
    ),
    (
        "message_signatures",
        "RFC 9421 signing and verification keys, which live on the host",
    ),
    (
        "olp",
        "the license-token issuer and its published key, which is deployment identity",
    ),
    (
        "web_bot_auth_publish",
        "publishes this deployment's own signing-key directory",
    ),
    (
        "idempotency",
        "cross-request state keyed by a client header, shared by every caller of the origin",
    ),
    (
        "connection_pool",
        "upstream connection shape, which is a capacity decision for whoever runs the fleet",
    ),
    (
        "timeouts",
        "upstream deadlines. One origin's generous read timeout is every origin's worker pool",
    ),
    (
        "extensions",
        "opaque per-origin blocks read by out-of-tree consumers, so nothing here can say what \
         a value does",
    ),
    (
        "stream_safety",
        "an empty list disables streaming safety even where the hook is wired, so this field \
         is a security floor a project could lower",
    ),
    (
        "outbound_credential",
        "mints or resolves the credential the proxy sends upstream",
    ),
    (
        "outbound_web_bot_auth",
        "signs outbound requests with the proxy's own key, so it lends this deployment's \
         identity to whatever the origin calls",
    ),
    (
        "attestation",
        "the consumption record's role and agreement, which is a billing and audit fact",
    ),
    (
        "observability",
        "origin-scope log sinks, redaction and decision-audit selection. A project able to \
         write this turns off the record of what it did",
    ),
];

// --- The profile document ------------------------------------------

/// What a project repository commits, conventionally at
/// `sbproxy/origin.yaml`.
///
/// It never names a hostname. There is no field that could hold one:
/// the hosts come from [`OriginSourceEntry::hosts`] in the runtime
/// config, which is the one thing the project does not know.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OriginProfile {
    /// Profile name. Every refusal this module raises names it, so make
    /// it the name the team that owns the repository would recognize.
    pub name: String,
    /// Values this profile needs from whoever deploys it, bound per
    /// entry through [`OriginSourceEntry::inputs`] and read in the
    /// document as `{{vars.NAME}}`.
    #[serde(default)]
    pub inputs: Vec<OriginProfileInput>,
    /// The origins this profile declares, keyed by a profile origin
    /// name that [`OriginSourceEntry::hosts`] binds hosts to.
    ///
    /// A map from day one. An API host plus a webhook host is the
    /// common case, and turning a single origin into a map later would
    /// break every committed entry and every fixture.
    #[serde(default)]
    pub spec: BTreeMap<String, OriginProfileOrigin>,
}

/// One value a profile declares that it needs from its deployer.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OriginProfileInput {
    /// The name bound in the document as `{{vars.NAME}}`.
    pub name: String,
    /// What the value is for, shown to whoever writes the entry.
    #[serde(default)]
    pub description: String,
    /// Value used when the entry binds none. Absent makes the input
    /// required, and an entry that binds nothing for it is a resolve
    /// error naming both the input and the entry.
    #[serde(default)]
    #[schemars(with = "Option<serde_json::Value>")]
    pub default: Option<serde_yaml::Value>,
}

/// One named origin inside a profile: a `base:` layer that applies
/// everywhere, and structural differences per environment.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OriginProfileOrigin {
    /// The layer that applies in every environment.
    #[serde(default)]
    pub base: OriginProfileSpec,
    /// Structural differences only, selected by
    /// [`OriginSourceEntry::environment`]. An environment the entry
    /// does not name contributes nothing.
    #[serde(default)]
    pub environments: BTreeMap<String, OriginProfileSpec>,
}

/// Exactly the origin fields a project may set.
///
/// The allowlist, spelled as a struct so that everything else is
/// unrepresentable rather than merely rejected. See
/// [`PLATFORM_OWNED_ORIGIN_FIELDS`] for the other half and the reason
/// each field is there.
///
/// Every field is `Option`, and deliberately so even where
/// `RawOriginConfig` uses a bare `Vec`. `policies: []` and an absent
/// `policies:` are different statements from a project, and collapsing
/// them into an empty vec is what makes a floor deletion invisible.
///
/// The list-valued fields are untyped on purpose: the merge runs before
/// the typed parse, and the typed modifier structs reject the `name:`
/// key the merge is keyed on.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OriginProfileSpec {
    /// What the origin does: proxy, redirect, static, and the rest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<serde_json::Value>")]
    pub action: Option<Value>,
    /// The authentication shape. The project declares what kind of
    /// credential the origin accepts; the secret reference itself comes
    /// from the entry through a declared input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<serde_json::Value>")]
    pub authentication: Option<Value>,
    /// Policy entries, merged against `origin_defaults` by `name:`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<Vec<serde_json::Value>>")]
    pub policies: Option<Vec<Value>>,
    /// Transform pipeline entries, merged by `name:`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<Vec<serde_json::Value>>")]
    pub transforms: Option<Vec<Value>>,
    /// Request modifiers, merged by `name:`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<Vec<serde_json::Value>>")]
    pub request_modifiers: Option<Vec<Value>>,
    /// Response modifiers, merged by `name:`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<Vec<serde_json::Value>>")]
    pub response_modifiers: Option<Vec<Value>>,
    /// CORS configuration. The service knows its own browser clients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<serde_json::Value>")]
    pub cors: Option<Value>,
    /// Response compression configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<serde_json::Value>")]
    pub compression: Option<Value>,
    /// Per-status custom error bodies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<serde_json::Value>")]
    pub error_pages: Option<Value>,
    /// RFC 9457 problem-details rendering for this service's errors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<serde_json::Value>")]
    pub problem_details: Option<Value>,
    /// RFC 9745 deprecation announcement for this service's own API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<serde_json::Value>")]
    pub deprecation: Option<Value>,
    /// Whether to serve this service's OpenAPI document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expose_openapi: Option<bool>,
    /// This service's `/AGENTS.md` body, served verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agents_md: Option<String>,
    /// This service's `/ai.txt` body, served verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_txt: Option<String>,
    /// This service's agents.json manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<serde_json::Value>")]
    pub agents_json: Option<Value>,
    /// This service's Agent Skills advertisement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<serde_json::Value>")]
    pub agent_skills: Option<Value>,
    /// Default content shape for a caller that sends no `Accept`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_content_shape: Option<String>,
    /// The `Content-Signal` value this service asserts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_signal: Option<String>,
    /// Tokens-per-byte ratio for this service's Markdown projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_bytes_ratio: Option<f32>,
}

impl OriginProfileSpec {
    /// This layer as a mapping the resolver can merge.
    ///
    /// Serializing the typed struct rather than keeping the parsed YAML
    /// is what makes the allowlist load-bearing: a key that is not a
    /// field here never reaches the merge, because it never survived
    /// the parse.
    fn to_mapping(&self) -> Result<Mapping, OriginResolveError> {
        match serde_yaml::to_value(self) {
            Ok(Value::Mapping(mapping)) => Ok(mapping),
            Ok(_) | Err(_) => Err(OriginResolveError::LayerNotAMapping),
        }
    }
}

// --- Errors ----------------------------------------------------------

/// A composition was refused. Every variant names the entry, and where
/// the failure is about a document it names the profile too, so an
/// operator reading one line knows which repository to go and fix.
///
/// No variant carries a config value: an entry credential and a bound
/// input are both secret-shaped, and a refusal that echoed one would
/// put it in every log that saw the refusal.
#[derive(Debug, thiserror::Error)]
pub enum OriginResolveError {
    /// `origin_defaults` has a list entry with no `name:`.
    #[error(
        "origin_defaults: `{list}` entry {index} has no `name:`. A default has to be \
         addressable to be overridable, so give it one"
    )]
    UnnamedDefault {
        /// Which of [`PROFILE_LIST_MERGE_KEYS`] the entry is in.
        list: &'static str,
        /// Zero-based position of the offending entry.
        index: usize,
    },
    /// `origin_defaults` is present but is not a mapping of origin keys.
    #[error("origin_defaults: `{list}` is not a list")]
    DefaultsListShape {
        /// Which of [`PROFILE_LIST_MERGE_KEYS`] has the wrong shape.
        list: &'static str,
    },
    /// Two `origin_sources` entries share a name.
    #[error("origin_sources: entry name `{entry}` is declared twice")]
    DuplicateEntryName {
        /// The repeated name.
        entry: String,
    },
    /// An entry left a required string empty.
    #[error("origin_sources entry `{entry}`: `{field}` must not be empty")]
    EmptyField {
        /// The entry name.
        entry: String,
        /// The field that was blank.
        field: &'static str,
    },
    /// An entry carries a credential inline rather than by reference.
    #[error(
        "origin_sources entry `{entry}`: `credential` must be a reference \
         (`env:NAME`, `${{NAME}}`, `file:/path`, or `secret://backend/name`), not an inline \
         literal. A token in a config file is a token in every copy of that file"
    )]
    InlineCredential {
        /// The entry name. Never the credential.
        entry: String,
    },
    /// An entry set its fetch timeout to zero.
    #[error(
        "origin_sources entry `{entry}`: `timeout_secs` must be at least 1. A zero timeout \
         kills the fetch the moment it starts, so the entry could never compose"
    )]
    ZeroTimeout {
        /// The entry name.
        entry: String,
    },
    /// A production-tier runtime has an entry that is not pinned.
    #[error(
        "origin_sources entry `{entry}`: tier `production` requires an immutable pin, and \
         this entry has none, so it follows the default branch. Pin a full commit sha, or a \
         tag spelled `refs/tags/<name>`"
    )]
    UnpinnedInProductionTier {
        /// The entry name.
        entry: String,
    },
    /// A production-tier runtime has an entry pinned to a movable ref.
    #[error(
        "origin_sources entry `{entry}`: tier `production` requires an immutable pin, and \
         `{revision}` is not one. Pin a full commit sha, or spell a tag `refs/tags/{revision}`. \
         A bare name is refused because git does not tell a tag from a branch by spelling"
    )]
    MovableRefInProductionTier {
        /// The entry name.
        entry: String,
        /// The revision as authored.
        revision: String,
    },
    /// Two entries claim the same `origins:` map key.
    #[error(
        "origin_sources: entry `{entry}` ({repo}) and entry `{other_entry}` ({other_repo}) \
         both claim host `{host}`. Last-wins is the failure this check exists to prevent"
    )]
    DuplicateHost {
        /// The contested map key.
        host: String,
        /// The entry that claimed it second.
        entry: String,
        /// That entry's repository, credential-stripped.
        repo: String,
        /// The entry that claimed it first.
        other_entry: String,
        /// That entry's repository, credential-stripped.
        other_repo: String,
    },
    /// An entry claims a host a hand-written `origins:` key declares.
    #[error(
        "origin_sources: entry `{entry}` ({repo}) claims host `{host}`, which this config \
         already declares under `origins:`. Remove one of the two"
    )]
    HostAlreadyDeclared {
        /// The contested map key.
        host: String,
        /// The entry that claimed it.
        entry: String,
        /// That entry's repository, credential-stripped.
        repo: String,
    },
    /// The profile document is not YAML, or is not a profile.
    #[error("origin_sources entry `{entry}`: the profile document does not parse: {source}")]
    Parse {
        /// The entry name.
        entry: String,
        /// The parse failure.
        #[source]
        source: serde_yaml::Error,
    },
    /// The profile document parses as YAML but is not a valid profile.
    ///
    /// This is where the write-side allowlist speaks. Every field a
    /// project may set is a field of [`OriginProfileSpec`], so anything
    /// else arrives here as an unknown key naming itself.
    #[error(
        "origin_sources entry `{entry}`: profile `{profile}` is not a valid origin profile: \
         {source}"
    )]
    ProfileParse {
        /// The entry name.
        entry: String,
        /// The profile name.
        profile: String,
        /// The parse failure, which names the offending key.
        #[source]
        source: serde_yaml::Error,
    },
    /// The profile carries a secret inline rather than by reference.
    #[error(
        "origin_sources entry `{entry}`: profile `{profile}` sets `{path}` to a literal. A \
         profile declares that it needs a secret and the entry supplies the reference; write \
         `secret://backend/name`, or bind a declared input to one"
    )]
    InlineSecret {
        /// The entry name.
        entry: String,
        /// The profile name.
        profile: String,
        /// The field path inside the profile. Never the value.
        path: String,
    },
    /// The profile document reached past the confinement boundary.
    #[error("origin_sources entry `{entry}`: {source}")]
    Confined {
        /// The entry name.
        entry: String,
        /// What the confined pass refused. Boxed because it is by some
        /// way the largest thing any variant here carries, and every
        /// other refusal would otherwise pay for it on the stack.
        #[source]
        source: Box<ConfinedTemplateError>,
    },
    /// A declared input has neither a bound value nor a default.
    #[error(
        "origin_sources entry `{entry}`: profile `{profile}` declares input `{input}`, the \
         entry binds no value for it, and the profile gives it no default"
    )]
    UnboundInput {
        /// The entry name.
        entry: String,
        /// The profile name.
        profile: String,
        /// The input the profile declared.
        input: String,
    },
    /// An entry binds an input the profile does not declare.
    #[error(
        "origin_sources entry `{entry}`: binds input `{input}`, which profile `{profile}` \
         does not declare. It declares: {declared}"
    )]
    UnknownInput {
        /// The entry name.
        entry: String,
        /// The profile name.
        profile: String,
        /// The name the entry bound.
        input: String,
        /// The names the profile actually declares.
        declared: String,
    },
    /// A bound input value cannot cross into the template binding set.
    #[error(
        "origin_sources entry `{entry}`: the value bound for input `{input}` is not \
         representable as a template binding (a mapping with a non-string key, or a YAML tag)"
    )]
    InputValue {
        /// The entry name.
        entry: String,
        /// The input name. Never the value.
        input: String,
    },
    /// An entry binds hosts to a profile origin the profile does not
    /// declare.
    #[error(
        "origin_sources entry `{entry}`: binds hosts to origin `{profile_origin}`, which \
         profile `{profile}` does not declare. It declares: {declared}"
    )]
    UnknownProfileOrigin {
        /// The entry name.
        entry: String,
        /// The profile name.
        profile: String,
        /// The profile origin name the entry bound.
        profile_origin: String,
        /// The profile origin names the profile actually declares.
        declared: String,
    },
    /// A project layer touched a locked default.
    #[error(
        "origin_sources entry `{entry}`: profile `{profile}` overrides `{list}` entry \
         `{name}`, which `origin_defaults` locked"
    )]
    LockedDefault {
        /// The entry name.
        entry: String,
        /// The profile name.
        profile: String,
        /// Which of [`PROFILE_LIST_MERGE_KEYS`] the entry is in.
        list: String,
        /// The locked entry's name.
        name: String,
    },
    /// A project layer wrote `locked:` itself.
    #[error(
        "origin_sources entry `{entry}`: profile `{profile}` sets `locked:` on `{list}` \
         entry `{name}`. Locking is the runtime config's verb; a project cannot lock a value \
         against the platform that deploys it"
    )]
    ProjectLock {
        /// The entry name.
        entry: String,
        /// The profile name.
        profile: String,
        /// Which of [`PROFILE_LIST_MERGE_KEYS`] the entry is in.
        list: String,
        /// The entry's name, or `?` when it has none.
        name: String,
    },
    /// A merge-key list is not a list in one of the layers.
    #[error(
        "origin_sources entry `{entry}`: profile `{profile}` sets `{list}` to something that \
         is not a list"
    )]
    ListShape {
        /// The entry name.
        entry: String,
        /// The profile name.
        profile: String,
        /// Which of [`PROFILE_LIST_MERGE_KEYS`] has the wrong shape.
        list: String,
    },
    /// The composed origin is not a valid origin.
    #[error("origin_sources entry `{entry}`: composed origin `{host}` is not valid: {source}")]
    Compose {
        /// The entry name.
        entry: String,
        /// The map key the composed origin would have taken.
        host: String,
        /// The deserialization failure.
        #[source]
        source: serde_yaml::Error,
    },
    /// A layer serialized to something that is not a mapping. Not
    /// reachable from any document; present so the resolver has no
    /// `unwrap`.
    #[error("internal: an origin layer is not a mapping")]
    LayerNotAMapping,
}

// --- Resolver inputs and report --------------------------------------

/// One entry paired with the profile document it deploys.
///
/// The document is text rather than a parsed profile because the
/// confined pass runs on text, and because the bindings are per entry:
/// two entries may deploy the same repository with different inputs and
/// must not share a resolved document.
#[derive(Debug, Clone, Copy)]
pub struct ProfileBinding<'a> {
    /// The runtime entry that deploys the profile.
    pub entry: &'a OriginSourceEntry,
    /// The profile document exactly as committed.
    pub document: &'a str,
}

/// A default a project switched off, recorded so the drop is auditable.
///
/// There is no delete verb, matching the existing merge contract.
/// `disabled: true` leaves a record; an absence would not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DroppedDefault {
    /// The entry whose profile switched it off.
    pub entry: String,
    /// The profile that switched it off.
    pub profile: String,
    /// Which of [`PROFILE_LIST_MERGE_KEYS`] the entry was in.
    pub list: String,
    /// The dropped entry's `name:`.
    pub name: String,
}

/// One host an entry claims, before anything is fetched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostClaim {
    /// The `origins:` map key that will be created.
    pub host: String,
    /// The entry that claims it.
    pub entry: String,
    /// The profile origin name inside that entry's profile.
    pub profile_origin: String,
    /// The entry's repository, credential-stripped.
    pub repo: String,
}

/// What a composition produced.
#[derive(Debug, Default)]
pub struct OriginResolution {
    /// The composed `origins:` map, keyed by hostname.
    pub origins: BTreeMap<String, RawOriginConfig>,
    /// Every default a project switched off, in composition order.
    pub drops: Vec<DroppedDefault>,
    /// Profile origins no entry bound hosts to. Not an error: one entry
    /// may deploy the API half of a profile and leave the webhook half
    /// to another environment.
    pub unbound_profile_origins: Vec<String>,
}

// --- Load-time validation --------------------------------------------

/// Check `origin_defaults` at config load.
///
/// The one rule the block has of its own: every entry in a
/// [`PROFILE_LIST_MERGE_KEYS`] list carries a `name:`. A default with no
/// name is a default no project can address, so it can be neither
/// overridden nor locked, and the operator who wrote it would find that
/// out at the first compose rather than here.
///
/// # Errors
///
/// Returns [`OriginResolveError::UnnamedDefault`] naming the list and
/// the position, or [`OriginResolveError::DefaultsListShape`] when one
/// of those keys is not a list at all.
pub fn validate_origin_defaults(defaults: &Mapping) -> Result<(), OriginResolveError> {
    for list in PROFILE_LIST_MERGE_KEYS {
        let Some(value) = defaults.get(*list) else {
            continue;
        };
        let Some(items) = value.as_sequence() else {
            return Err(OriginResolveError::DefaultsListShape { list });
        };
        for (index, item) in items.iter().enumerate() {
            let named = item
                .as_mapping()
                .and_then(|entry| entry.get("name"))
                .and_then(Value::as_str)
                .is_some_and(|name| !name.trim().is_empty());
            if !named {
                return Err(OriginResolveError::UnnamedDefault { list, index });
            }
        }
    }
    Ok(())
}

/// Check `origin_sources` at config load, with no repository fetched.
///
/// Four rules, all answerable from the document alone: entry names are
/// unique, the required strings are non-empty, a credential is a
/// reference rather than a literal, and a production-tier runtime pins
/// every entry to something immutable.
///
/// The tier comes from [`OriginSourcesConfig::tier`], which is a
/// property of this document, rather than from the entry's own
/// `environment:`. An entry that could declare its own tier could
/// declare its way out of the rule.
///
/// # Errors
///
/// Returns the [`OriginResolveError`] variant naming the entry and what
/// about it was refused.
pub fn validate_origin_sources(sources: &OriginSourcesConfig) -> Result<(), OriginResolveError> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for entry in &sources.entries {
        if entry.name.trim().is_empty() {
            return Err(OriginResolveError::EmptyField {
                entry: entry.name.clone(),
                field: "name",
            });
        }
        if !seen.insert(entry.name.as_str()) {
            return Err(OriginResolveError::DuplicateEntryName {
                entry: entry.name.clone(),
            });
        }
        if entry.repo.trim().is_empty() {
            return Err(OriginResolveError::EmptyField {
                entry: entry.name.clone(),
                field: "repo",
            });
        }
        if entry.path.trim().is_empty() {
            return Err(OriginResolveError::EmptyField {
                entry: entry.name.clone(),
                field: "path",
            });
        }
        if let Some(credential) = entry.credential.as_deref() {
            if !is_secret_reference(credential) {
                return Err(OriginResolveError::InlineCredential {
                    entry: entry.name.clone(),
                });
            }
        }
        if entry.timeout_secs == 0 {
            return Err(OriginResolveError::ZeroTimeout {
                entry: entry.name.clone(),
            });
        }
        let signed = entry.verify_signature;
        if sources.tier == EnvironmentTier::Production && !signed {
            tracing::warn!(
                entry = %entry.name,
                repo = %crate::source::redact_repo(&entry.repo),
                "origin_sources entry is unsigned in a production-tier runtime; the pin is \
                 transport trust plus whatever the git host authenticated, and nothing more"
            );
        }
        if sources.tier == EnvironmentTier::Production {
            match entry.revision.as_deref() {
                None => {
                    return Err(OriginResolveError::UnpinnedInProductionTier {
                        entry: entry.name.clone(),
                    })
                }
                Some(revision) if !revision_is_immutable(revision) => {
                    return Err(OriginResolveError::MovableRefInProductionTier {
                        entry: entry.name.clone(),
                        revision: revision.to_string(),
                    })
                }
                Some(_) => {}
            }
        }
        // Read so the entry's transport fields have a live consumer
        // rather than only a schema entry, and so an operator sees the
        // posture of every entry at boot rather than at the first
        // fetch.
        let timeout_secs = entry.timeout_secs;
        tracing::debug!(
            entry = %entry.name,
            repo = %crate::source::redact_repo(&entry.repo),
            path = %entry.path,
            verify_signature = signed,
            timeout_secs,
            has_credential = entry.credential.is_some(),
            "origin_sources entry accepted"
        );
    }
    Ok(())
}

/// Whether a revision names something git cannot move underneath the
/// fleet.
///
/// A full commit sha, or a tag written the long way. A bare name is
/// not, because git does not distinguish a tag from a branch by
/// spelling and a rule that guessed would be a rule a branch could walk
/// straight through. `refs/tags/<name>` is what `git fetch` takes, so
/// the long spelling costs the operator nothing.
///
/// Public because the load path reports the pin state as a metric and
/// the admin surface reports it per entry, and both have to answer the
/// question exactly the way [`validate_origin_sources`] answers it. A
/// second spelling of this predicate is a detector narrower than its
/// enforcer.
#[must_use]
pub fn revision_is_immutable(revision: &str) -> bool {
    crate::source::is_full_commit_sha(revision)
        || revision
            .strip_prefix("refs/tags/")
            .is_some_and(|tag| !tag.is_empty())
}

/// Every `origins:` map key the declared entries will claim, and who
/// claims it, with no repository fetched.
///
/// Answerable from the runtime document alone, because
/// [`OriginSourceEntry::hosts`] is where hosts are named. That is what
/// lets an operator see a collision before an aggregator has run, and
/// what lets the admin surface answer "which project owns this
/// hostname" on a node that has never fetched anything.
///
/// A wildcard is not special here. Overlap is not a collision: an exact
/// key beats a wildcard and the longest matching suffix wins between
/// wildcards, all of which the compiler already settles. The only
/// question this asks is whether two writers claim the **same map key**.
///
/// # Errors
///
/// Returns [`OriginResolveError::DuplicateHost`] naming both entries
/// and both repositories, or [`OriginResolveError::HostAlreadyDeclared`]
/// when a hand-written `origins:` key is already there.
pub fn claimed_hosts(
    entries: &[OriginSourceEntry],
    hand_written: &BTreeSet<String>,
) -> Result<Vec<HostClaim>, OriginResolveError> {
    let mut claims: Vec<HostClaim> = Vec::new();
    let mut by_host: BTreeMap<&str, usize> = BTreeMap::new();
    for entry in entries {
        for (profile_origin, hosts) in &entry.hosts {
            for host in hosts {
                if hand_written.contains(host) {
                    return Err(OriginResolveError::HostAlreadyDeclared {
                        host: host.clone(),
                        entry: entry.name.clone(),
                        repo: crate::source::redact_repo(&entry.repo),
                    });
                }
                if let Some(first) = by_host.get(host.as_str()) {
                    let other = &claims[*first];
                    return Err(OriginResolveError::DuplicateHost {
                        host: host.clone(),
                        entry: entry.name.clone(),
                        repo: crate::source::redact_repo(&entry.repo),
                        other_entry: other.entry.clone(),
                        other_repo: other.repo.clone(),
                    });
                }
                by_host.insert(host.as_str(), claims.len());
                claims.push(HostClaim {
                    host: host.clone(),
                    entry: entry.name.clone(),
                    profile_origin: profile_origin.clone(),
                    repo: crate::source::redact_repo(&entry.repo),
                });
            }
        }
    }
    Ok(claims)
}

// --- The resolver ----------------------------------------------------

/// Compose `origin_defaults`, the fetched profiles and their entries
/// into the `origins:` map.
///
/// Pure: no filesystem, no network, no globals. The caller fetches the
/// documents and hands them in as text.
///
/// # Errors
///
/// Returns the [`OriginResolveError`] naming the entry, and where the
/// failure is about a document, the profile as well.
pub fn resolve_origins(
    defaults: Option<&Mapping>,
    bindings: &[ProfileBinding<'_>],
    hand_written: &BTreeSet<String>,
) -> Result<OriginResolution, OriginResolveError> {
    if let Some(defaults) = defaults {
        validate_origin_defaults(defaults)?;
    }
    let entries: Vec<OriginSourceEntry> = bindings
        .iter()
        .map(|binding| binding.entry.clone())
        .collect();
    // The collision check runs first and on the runtime document alone,
    // so two entries fighting over a hostname are named even when one
    // of their profiles would also have failed to parse.
    claimed_hosts(&entries, hand_written)?;

    let mut resolution = OriginResolution::default();
    for binding in bindings {
        let entry = binding.entry;
        let profile = parse_profile(entry, binding.document)?;
        for name in profile.spec.keys() {
            if !entry.hosts.contains_key(name) {
                resolution
                    .unbound_profile_origins
                    .push(format!("{}:{name}", entry.name));
            }
        }
        for (profile_origin, hosts) in &entry.hosts {
            let Some(declared) = profile.spec.get(profile_origin) else {
                return Err(OriginResolveError::UnknownProfileOrigin {
                    entry: entry.name.clone(),
                    profile: profile.name.clone(),
                    profile_origin: profile_origin.clone(),
                    declared: names_of(profile.spec.keys()),
                });
            };
            let composed = compose_one(defaults, entry, &profile, declared, &mut resolution.drops)?;
            for host in hosts {
                let origin: RawOriginConfig =
                    serde_yaml::from_value(Value::Mapping(composed.clone())).map_err(|source| {
                        OriginResolveError::Compose {
                            entry: entry.name.clone(),
                            host: host.clone(),
                            source,
                        }
                    })?;
                tracing::info!(
                    host = %host,
                    entry = %entry.name,
                    profile = %profile.name,
                    profile_origin = %profile_origin,
                    repo = %crate::source::redact_repo(&entry.repo),
                    environment = entry.environment.as_deref().unwrap_or("(base only)"),
                    "composed origin from a project profile"
                );
                resolution.origins.insert(host.clone(), origin);
            }
        }
    }
    for drop in &resolution.drops {
        tracing::info!(
            entry = %drop.entry,
            profile = %drop.profile,
            list = %drop.list,
            name = %drop.name,
            "project profile disabled an origin_defaults entry"
        );
    }
    Ok(resolution)
}

/// Resolve the confined document against the entry's bindings and parse
/// it as a profile.
fn parse_profile(
    entry: &OriginSourceEntry,
    document: &str,
) -> Result<OriginProfile, OriginResolveError> {
    // The declarations are read from the document as authored, before
    // anything is substituted, because the bindings the substitution
    // needs are the ones the declarations name.
    let declared: DeclaredInputs =
        serde_yaml::from_str(document).map_err(|source| OriginResolveError::Parse {
            entry: entry.name.clone(),
            source,
        })?;
    let profile_name = declared.name.clone();
    let declared_names: BTreeSet<&str> = declared
        .inputs
        .iter()
        .map(|input| input.name.as_str())
        .collect();
    for bound in entry.inputs.keys() {
        if !declared_names.contains(bound.as_str()) {
            return Err(OriginResolveError::UnknownInput {
                entry: entry.name.clone(),
                profile: profile_name,
                input: bound.clone(),
                declared: names_of(declared.inputs.iter().map(|input| &input.name)),
            });
        }
    }
    let mut bindings = std::collections::HashMap::with_capacity(declared.inputs.len());
    for input in &declared.inputs {
        let value = entry
            .inputs
            .get(&input.name)
            .or(input.default.as_ref())
            .ok_or_else(|| OriginResolveError::UnboundInput {
                entry: entry.name.clone(),
                profile: profile_name.clone(),
                input: input.name.clone(),
            })?;
        let json = serde_json::to_value(value).map_err(|_| OriginResolveError::InputValue {
            entry: entry.name.clone(),
            input: input.name.clone(),
        })?;
        bindings.insert(input.name.clone(), json);
    }
    // The one place the boundary is enforced. `resolve_confined_fragment`
    // seals the process environment, refuses every host-backed secret
    // reference, refuses every host path on `HOST_FILE_KEYS`, and
    // refuses a `{{vars.X}}` the entry did not bind.
    let label = format!("origin profile `{profile_name}` (entry `{}`)", entry.name);
    let resolved = resolve_confined_fragment(&label, document, &bindings).map_err(|source| {
        OriginResolveError::Confined {
            entry: entry.name.clone(),
            source: Box::new(source),
        }
    })?;
    // Run on the resolved text, so a literal an entry bound into a
    // declared input is refused exactly as one the profile wrote.
    let resolved_value: Value =
        serde_yaml::from_str(&resolved).map_err(|source| OriginResolveError::Parse {
            entry: entry.name.clone(),
            source,
        })?;
    refuse_inline_secrets(&resolved_value, "", &entry.name, &profile_name)?;
    // The typed parse is the allowlist. Everything a project may set is
    // a field of `OriginProfileSpec`; everything else fails here as an
    // unknown key rather than being carried and dropped.
    serde_yaml::from_value(resolved_value).map_err(|source| OriginResolveError::ProfileParse {
        entry: entry.name.clone(),
        profile: profile_name,
        source,
    })
}

/// Walk a resolved profile and refuse a secret written out in full.
fn refuse_inline_secrets(
    value: &Value,
    path: &str,
    entry: &str,
    profile: &str,
) -> Result<(), OriginResolveError> {
    match value {
        Value::Mapping(map) => {
            for (key, child) in map {
                let name = key.as_str().unwrap_or("?");
                let child_path = if path.is_empty() {
                    name.to_string()
                } else {
                    format!("{path}.{name}")
                };
                if let Some(text) = child.as_str() {
                    let lowered = name.to_ascii_lowercase();
                    if PROFILE_SECRET_KEYS.contains(&lowered.as_str())
                        && !text.trim().is_empty()
                        && !is_secret_reference(text)
                    {
                        return Err(OriginResolveError::InlineSecret {
                            entry: entry.to_string(),
                            profile: profile.to_string(),
                            path: child_path,
                        });
                    }
                }
                refuse_inline_secrets(child, &child_path, entry, profile)?;
            }
        }
        Value::Sequence(items) => {
            for (index, item) in items.iter().enumerate() {
                refuse_inline_secrets(item, &format!("{path}[{index}]"), entry, profile)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// The `name:` and `inputs:` of a profile, read before substitution.
///
/// Deliberately not `deny_unknown_fields`: this reads two keys off a
/// document whose full shape is checked by [`OriginProfile`] after the
/// confined pass has run.
#[derive(Debug, Deserialize)]
struct DeclaredInputs {
    name: String,
    #[serde(default)]
    inputs: Vec<OriginProfileInput>,
}

/// Layer one profile origin into a single composed origin mapping.
fn compose_one(
    defaults: Option<&Mapping>,
    entry: &OriginSourceEntry,
    profile: &OriginProfile,
    declared: &OriginProfileOrigin,
    drops: &mut Vec<DroppedDefault>,
) -> Result<Mapping, OriginResolveError> {
    let mut accumulated = defaults.cloned().unwrap_or_default();
    let mut context = LayerContext {
        entry,
        profile: &profile.name,
        author: LayerAuthor::Project,
        drops,
    };
    layer(&mut accumulated, &declared.base.to_mapping()?, &mut context)?;
    if let Some(environment) = entry.environment.as_deref() {
        if let Some(overlay) = declared.environments.get(environment) {
            layer(&mut accumulated, &overlay.to_mapping()?, &mut context)?;
        }
    }
    if let Some(overrides) = entry.overrides.as_ref() {
        context.author = LayerAuthor::Runtime;
        layer(&mut accumulated, overrides, &mut context)?;
    }
    strip_bookkeeping(&mut accumulated);
    Ok(accumulated)
}

/// Who wrote the layer being applied.
///
/// `locked:` protects a default from the project, not from the platform
/// that wrote it. The entry `overrides:` block is the runtime config
/// speaking, so it passes through a lock; the profile is not, so it does
/// not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LayerAuthor {
    Runtime,
    Project,
}

/// Per-layer context, so the recursion does not thread five arguments.
struct LayerContext<'a> {
    entry: &'a OriginSourceEntry,
    profile: &'a str,
    author: LayerAuthor,
    drops: &'a mut Vec<DroppedDefault>,
}

/// Apply one layer over the accumulated origin.
fn layer(
    accumulated: &mut Mapping,
    over: &Mapping,
    context: &mut LayerContext<'_>,
) -> Result<(), OriginResolveError> {
    for (key, value) in over {
        let name = key.as_str().unwrap_or_default();
        if PROFILE_LIST_MERGE_KEYS.contains(&name) {
            let over_items = value
                .as_sequence()
                .ok_or_else(|| OriginResolveError::ListShape {
                    entry: context.entry.name.clone(),
                    profile: context.profile.to_string(),
                    list: name.to_string(),
                })?;
            let base_items = match accumulated.get(key) {
                Some(existing) => existing
                    .as_sequence()
                    .ok_or_else(|| OriginResolveError::ListShape {
                        entry: context.entry.name.clone(),
                        profile: context.profile.to_string(),
                        list: name.to_string(),
                    })?
                    .clone(),
                None => Vec::new(),
            };
            let merged = merge_named_list(&base_items, over_items, name, context)?;
            accumulated.insert(key.clone(), Value::Sequence(merged));
            continue;
        }
        match (accumulated.get_mut(key), value) {
            (Some(Value::Mapping(existing)), Value::Mapping(incoming)) => {
                merge_plain(existing, incoming);
            }
            _ => {
                accumulated.insert(key.clone(), value.clone());
            }
        }
    }
    Ok(())
}

/// The generic half of the merge, below the four named lists.
///
/// Maps recurse, everything else replaces, matching the contract
/// [`crate::config_merge`] already commits to. An ordinary sequence has
/// no knowable element identity, so guessing at one produces silent
/// duplicates.
fn merge_plain(base: &mut Mapping, over: &Mapping) {
    for (key, value) in over {
        match (base.get_mut(key), value) {
            (Some(Value::Mapping(existing)), Value::Mapping(incoming)) => {
                merge_plain(existing, incoming);
            }
            _ => {
                base.insert(key.clone(), value.clone());
            }
        }
    }
}

/// Merge one of the four lists by `name:`.
///
/// The whole table, in one place:
///
/// * A name in the accumulated layers and absent from `over` survives
///   unchanged.
/// * A name in both merges field by field, with `over` winning per
///   field.
/// * A name only in `over` is appended after the existing entries, in
///   `over` order.
/// * A locked existing entry that a project layer touches is a refusal
///   naming the entry, the profile and the source entry.
/// * `disabled: true` from `over` drops the entry and records the drop.
/// * An unnamed `over` entry is always an addition.
fn merge_named_list(
    base: &[Value],
    over: &[Value],
    list: &str,
    context: &mut LayerContext<'_>,
) -> Result<Vec<Value>, OriginResolveError> {
    let mut result: Vec<Option<Value>> = base.iter().cloned().map(Some).collect();
    let mut appended: Vec<Value> = Vec::new();
    for item in over {
        let incoming_name = entry_name(item);
        if context.author == LayerAuthor::Project && flag(item, "locked") {
            return Err(OriginResolveError::ProjectLock {
                entry: context.entry.name.clone(),
                profile: context.profile.to_string(),
                list: list.to_string(),
                name: incoming_name.unwrap_or("?").to_string(),
            });
        }
        let existing = incoming_name.and_then(|name| {
            result.iter().position(|slot| {
                slot.as_ref()
                    .and_then(|value| entry_name(value))
                    .is_some_and(|existing| existing == name)
            })
        });
        match existing {
            Some(index) => {
                let Some(slot) = result.get_mut(index) else {
                    continue;
                };
                let Some(current) = slot.as_mut() else {
                    continue;
                };
                if context.author == LayerAuthor::Project && flag(current, "locked") {
                    return Err(OriginResolveError::LockedDefault {
                        entry: context.entry.name.clone(),
                        profile: context.profile.to_string(),
                        list: list.to_string(),
                        name: incoming_name.unwrap_or("?").to_string(),
                    });
                }
                if flag(item, "disabled") {
                    context.drops.push(DroppedDefault {
                        entry: context.entry.name.clone(),
                        profile: context.profile.to_string(),
                        list: list.to_string(),
                        name: incoming_name.unwrap_or("?").to_string(),
                    });
                    *slot = None;
                    continue;
                }
                match (current, item) {
                    (Value::Mapping(existing_map), Value::Mapping(incoming_map)) => {
                        merge_plain(existing_map, incoming_map);
                    }
                    (slot_value, incoming) => {
                        *slot_value = incoming.clone();
                    }
                }
            }
            None => {
                if flag(item, "disabled") {
                    // A `disabled: true` entry with nothing to disable is
                    // still a statement that it must not run. Appending it
                    // and stripping the flag would install exactly what
                    // the author asked to switch off.
                    context.drops.push(DroppedDefault {
                        entry: context.entry.name.clone(),
                        profile: context.profile.to_string(),
                        list: list.to_string(),
                        name: incoming_name.unwrap_or("?").to_string(),
                    });
                    continue;
                }
                appended.push(item.clone());
            }
        }
    }
    let mut merged: Vec<Value> = result.into_iter().flatten().collect();
    merged.extend(appended);
    Ok(merged)
}

/// The `name:` of a list entry, when it has one.
fn entry_name(value: &Value) -> Option<&str> {
    value
        .as_mapping()
        .and_then(|map| map.get("name"))
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty())
}

/// Whether a list entry sets a bookkeeping boolean.
fn flag(value: &Value, key: &str) -> bool {
    value
        .as_mapping()
        .and_then(|map| map.get(key))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// Remove `name`, `locked` and `disabled` from the four merged lists.
///
/// Only at the immediate element level of those four keys. Deeper is
/// wrong: `name` is a meaningful field inside a header modifier, a
/// transform argument and half the module configs, and a strip that
/// recursed would quietly change what those mean.
fn strip_bookkeeping(origin: &mut Mapping) {
    for list in PROFILE_LIST_MERGE_KEYS {
        let Some(Value::Sequence(items)) = origin.get_mut(*list) else {
            continue;
        };
        for item in items.iter_mut() {
            let Value::Mapping(map) = item else {
                continue;
            };
            for key in BOOKKEEPING_KEYS {
                map.remove(*key);
            }
        }
    }
}

/// A sorted, comma-joined name list for an error message.
fn names_of<'a, I, S>(names: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str> + 'a,
{
    let mut collected: Vec<String> = names
        .into_iter()
        .map(|name| name.as_ref().to_string())
        .collect();
    if collected.is_empty() {
        return "(none)".to_string();
    }
    collected.sort();
    collected.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ratchet. `RawOriginConfig` has 52 fields today and gains more
    /// regularly; every one of them has to be either a field of
    /// [`OriginProfileSpec`] or an entry in
    /// [`PLATFORM_OWNED_ORIGIN_FIELDS`] with a written reason.
    ///
    /// Derived from the schemas rather than from a hand-written list of
    /// field names, so it moves the moment the struct moves rather than
    /// the moment somebody remembers. A deny list would make every new
    /// field a silent privilege grant to every project repository in the
    /// fleet, with no review step that would catch it; this is the
    /// review step.
    #[test]
    fn every_raw_origin_field_is_classified() {
        let origin_fields = schema_properties::<RawOriginConfig>();
        let profile_fields = schema_properties::<OriginProfileSpec>();
        let platform: BTreeSet<String> = PLATFORM_OWNED_ORIGIN_FIELDS
            .iter()
            .map(|(field, _)| (*field).to_string())
            .collect();

        assert!(
            origin_fields.len() >= 50,
            "the sweep found only {} origin fields, which means it broke rather than that the \
             struct shrank",
            origin_fields.len()
        );

        let unclassified: Vec<&String> = origin_fields
            .iter()
            .filter(|field| !profile_fields.contains(*field) && !platform.contains(*field))
            .collect();
        assert!(
            unclassified.is_empty(),
            "these `RawOriginConfig` fields are on neither side of the project write boundary: \
             {unclassified:#?}. Classify each one: add it to `OriginProfileSpec` if a project \
             repository may set it, or to `PLATFORM_OWNED_ORIGIN_FIELDS` with the reason it \
             belongs to whoever runs the proxy. Unclassified means forbidden, and leaving it \
             unclassified is how a new field becomes a silent privilege grant"
        );

        let both: Vec<&String> = profile_fields.intersection(&platform).collect();
        assert!(
            both.is_empty(),
            "these fields are both project-writable and platform-owned, which cannot both be \
             true: {both:#?}"
        );

        for field in &profile_fields {
            assert!(
                origin_fields.contains(field),
                "`OriginProfileSpec` names `{field}`, which is not a field of \
                 `RawOriginConfig`; a composed origin carrying it would fail to deserialize"
            );
        }
        for (field, reason) in PLATFORM_OWNED_ORIGIN_FIELDS {
            assert!(
                origin_fields.contains(*field),
                "`{field}` is classified platform-owned but is no longer a field of \
                 `RawOriginConfig`; delete the entry rather than leaving a stale reason"
            );
            assert!(!reason.is_empty(), "`{field}` has no written reason");
        }
    }

    /// The four merge keys are all project-writable. A merge key a
    /// project cannot write is a merge key nothing exercises.
    #[test]
    fn every_merge_key_is_a_field_a_project_may_set() {
        let profile_fields = schema_properties::<OriginProfileSpec>();
        for key in PROFILE_LIST_MERGE_KEYS {
            assert!(
                profile_fields.contains(*key),
                "`{key}` merges by name but no project can write it"
            );
        }
    }

    fn schema_properties<T: schemars::JsonSchema>() -> BTreeSet<String> {
        let schema = serde_json::to_value(schemars::schema_for!(T)).expect("schema serializes");
        schema
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .map(|properties| properties.keys().cloned().collect())
            .unwrap_or_default()
    }

    #[test]
    fn only_a_sha_or_a_long_spelled_tag_is_an_immutable_pin() {
        assert!(revision_is_immutable(
            "0123456789abcdef0123456789abcdef01234567"
        ));
        assert!(revision_is_immutable("refs/tags/v1.4.2"));
        assert!(!revision_is_immutable("v1.4.2"));
        assert!(!revision_is_immutable("main"));
        assert!(!revision_is_immutable("refs/heads/main"));
        assert!(!revision_is_immutable("refs/tags/"));
        assert!(!revision_is_immutable("0123456"));
    }

    #[test]
    fn bookkeeping_is_stripped_only_at_the_element_level_of_the_merge_keys() {
        let mut origin: Mapping = serde_yaml::from_str(
            "policies:\n  - name: waf\n    locked: true\n    type: waf\n    rules:\n      \
             - name: sqli\n        action: block\nvariables:\n  name: keep-me\n",
        )
        .expect("fixture parses");
        strip_bookkeeping(&mut origin);
        let policies = origin
            .get("policies")
            .and_then(Value::as_sequence)
            .expect("policies")
            .clone();
        assert!(policies[0].get("name").is_none());
        assert!(policies[0].get("locked").is_none());
        assert_eq!(
            policies[0]
                .get("rules")
                .and_then(Value::as_sequence)
                .and_then(|rules| rules.first())
                .and_then(|rule| rule.get("name"))
                .and_then(Value::as_str),
            Some("sqli"),
            "a nested `name` is a real field and must survive"
        );
        assert_eq!(
            origin.get("variables").and_then(|v| v.get("name")),
            Some(&Value::String("keep-me".to_string())),
            "a `name` outside the four lists is untouched"
        );
    }

    #[test]
    fn an_entry_name_must_be_a_non_blank_string() {
        assert_eq!(
            entry_name(&serde_yaml::from_str::<Value>("name: waf").expect("parses")),
            Some("waf")
        );
        assert_eq!(
            entry_name(&serde_yaml::from_str::<Value>("name: \"  \"").expect("parses")),
            None
        );
        assert_eq!(
            entry_name(&serde_yaml::from_str::<Value>("name: 7").expect("parses")),
            None,
            "a numeric name is not an identity the merge can key on"
        );
        assert_eq!(
            entry_name(&serde_yaml::from_str::<Value>("type: waf").expect("parses")),
            None
        );
    }

    #[test]
    fn names_of_sorts_and_says_none_when_there_are_none() {
        assert_eq!(names_of(Vec::<String>::new()), "(none)");
        assert_eq!(names_of(vec!["b", "a", "c"]), "a, b, c");
    }

    #[test]
    fn an_inline_secret_is_named_by_its_path_and_never_by_its_value() {
        let document: Value = serde_yaml::from_str(
            "spec:\n  api:\n    base:\n      policies:\n        - name: upstream\n          \
             client_secret: LITERAL-VALUE\n",
        )
        .expect("fixture parses");
        let error = refuse_inline_secrets(&document, "", "checkout", "checkout")
            .expect_err("a literal must be refused");
        let text = error.to_string();
        assert!(
            text.contains("spec.api.base.policies[0].client_secret"),
            "{text}"
        );
        assert!(!text.contains("LITERAL-VALUE"), "{text}");
    }

    #[test]
    fn a_provider_uri_is_the_one_secret_spelling_a_profile_keeps() {
        let document: Value = serde_yaml::from_str(
            "authentication:\n  type: api_key\n  api_key: secret://prod/checkout\n",
        )
        .expect("fixture parses");
        refuse_inline_secrets(&document, "", "checkout", "checkout")
            .expect("a provider URI resolves against a backend the project cannot declare");
    }

    #[test]
    fn an_empty_secret_value_is_not_a_literal() {
        let document: Value =
            serde_yaml::from_str("authentication:\n  api_key: \"\"\n").expect("fixture parses");
        refuse_inline_secrets(&document, "", "checkout", "checkout")
            .expect("an empty value carries no secret");
    }

    #[test]
    fn a_defaults_list_that_is_not_a_list_is_named() {
        let defaults: Mapping =
            serde_yaml::from_str("policies:\n  waf: true\n").expect("fixture parses");
        assert!(matches!(
            validate_origin_defaults(&defaults).expect_err("refused"),
            OriginResolveError::DefaultsListShape { list: "policies" }
        ));
    }

    #[test]
    fn an_entry_with_a_blank_required_field_is_named() {
        let sources: OriginSourcesConfig = serde_yaml::from_str(
            "entries:\n  - name: checkout\n    repo: \"  \"\n    path: p.yaml\n",
        )
        .expect("fixture parses");
        assert!(matches!(
            validate_origin_sources(&sources).expect_err("refused"),
            OriginResolveError::EmptyField { field: "repo", .. }
        ));
    }

    #[test]
    fn the_generic_half_of_the_merge_recurses_maps_and_replaces_sequences() {
        let mut base: Mapping =
            serde_yaml::from_str("a:\n  b: 1\n  c: 2\nlist: [1, 2, 3]\n").expect("parses");
        let over: Mapping = serde_yaml::from_str("a:\n  c: 9\nlist: [4]\n").expect("parses");
        merge_plain(&mut base, &over);
        assert_eq!(
            base.get("a").and_then(|a| a.get("b")),
            Some(&Value::Number(1.into()))
        );
        assert_eq!(
            base.get("a").and_then(|a| a.get("c")),
            Some(&Value::Number(9.into()))
        );
        assert_eq!(
            base.get("list").and_then(Value::as_sequence).map(Vec::len),
            Some(1),
            "an ordinary sequence replaces wholesale"
        );
    }
}

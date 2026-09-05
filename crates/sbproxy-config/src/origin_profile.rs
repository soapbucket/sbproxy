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
//! list. `RawOriginConfig` has 53 fields and gains more regularly, so a
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

/// The keys that make a `request_modifiers:` or `response_modifiers:`
/// entry opaque to [`effect_keys`].
///
/// Those two lists have no `type:` discriminator, so what an entry does
/// is read off the leaf paths it writes. A script body writes nothing
/// declaratively: `RequestModifierConfig` and `ResponseModifierConfig`
/// both take `lua_script`, `js_script`, `rego_module` and
/// `rego_module_path`, and all four can return `set_headers`. So a
/// project entry carrying one has effect keys that intersect nothing,
/// lands after the floor, and wins whatever it writes
/// (WOR-2432 re-review N3).
///
/// A project addition carrying one of these into a list that holds any
/// locked entry is therefore refused outright, which is the same
/// wider-than-the-hazard posture the type rule already takes: the
/// comparison cannot read the body, so the honest answer is that it
/// cannot clear it.
///
/// The typed lists need no equivalent. A `policies:` or `transforms:`
/// entry running a script is discriminated by its own `type:`
/// (`rego`, `lua`, ...), which [`effect_keys`] already compares.
const MODIFIER_SCRIPT_KEYS: &[&str] =
    &["js_script", "lua_script", "rego_module", "rego_module_path"];

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

/// The origin fields a project profile may set, as strings.
///
/// The same set as [`OriginProfileSpec`]'s fields, spelled here because
/// the runtime needs it as data: `validate_origin_body` asks whether a
/// key in `origin_defaults` is a real origin field, and building a
/// schema per config load to answer that would be absurd.
/// `every_raw_origin_field_is_classified` asserts this list is exactly
/// [`OriginProfileSpec`]'s schema properties, so the duplication cannot
/// drift.
pub const PROFILE_WRITABLE_ORIGIN_FIELDS: &[&str] = &[
    "action",
    "agent_skills",
    "agents_json",
    "agents_md",
    "ai_txt",
    "authentication",
    "compression",
    "content_signal",
    "cors",
    "default_content_shape",
    "deprecation",
    "error_pages",
    "expose_openapi",
    "policies",
    "problem_details",
    "request_modifiers",
    "response_modifiers",
    "token_bytes_ratio",
    "transforms",
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
        "names an installed extension bundle to run on the request path. The distinction \
         from the allowed `request_modifiers[].lua_script` is capability, not code: a script \
         body runs in an interpreter with no network, no filesystem, no clock and no crypto, \
         while a bundle is host code the operator installed and granted, so naming one is \
         spending a grant the project never made",
    ),
    (
        "on_response",
        "the same grant on the response path, where the bundle additionally sees the \
         upstream's body",
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
        "comp",
        "the CoMP marketplace bridge: it mints with the `olp` block's signing key, sets the \
         prices this deployment sells at, and names the buyer keys allowed to redeem, so a \
         project that could set it could mint licenses under the host's identity",
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
/// input are both secret-shaped, and a refusal that echoed one would put
/// it in every log that saw the refusal.
///
/// The twenty hand-written variants hold that by construction. The three
/// that report a deserialization failure ([`Self::Parse`],
/// [`Self::ProfileParse`], [`Self::Compose`]) would not: serde renders
/// the offending value into its own message, so `invalid type: string
/// "sk-live-...", expected f32` is a secret in a refusal. They carry a
/// `redact_serde_message` rendering instead of the error itself, which
/// keeps the backtick-quoted field names serde uses for identifiers and
/// replaces every double-quoted value with `[redacted]`. The cost is the
/// `#[source]` chain on those three, which is the right trade: a chain
/// only a `{:#}` formatter prints is worth less than a value that cannot
/// leak.
#[derive(Debug, thiserror::Error)]
pub enum OriginResolveError {
    /// A runtime-authored origin block has a list entry with no `name:`.
    #[error(
        "{block}: `{list}` entry {index} has no `name:`. A default has to be addressable to \
         be overridable, so give it one"
    )]
    UnnamedDefault {
        /// Which block: `origin_defaults`, or one entry's `overrides:`.
        block: String,
        /// Which of [`PROFILE_LIST_MERGE_KEYS`] the entry is in.
        list: &'static str,
        /// Zero-based position of the offending entry.
        index: usize,
    },
    /// A runtime-authored origin block names a key that is not an origin
    /// field.
    #[error(
        "{block}: `{key}` is not a field of an origin, so nothing would ever read it. \
         Neither block carries `deny_unknown_fields`, because the merge runs before the \
         typed parse, so this check is what stops a typo reaching the aggregator"
    )]
    UnknownOriginKey {
        /// Which block: `origin_defaults`, or one entry's `overrides:`.
        block: String,
        /// The key as authored.
        key: String,
    },
    /// A runtime-authored origin block names a policy or transform type
    /// the dispatcher does not know.
    #[error(
        "{block}: `{list}` entry `{name}` has `type: {kind}`, which no module answers to. \
         Every composed origin inherits this entry, so the whole fleet would refuse to boot"
    )]
    UnknownEntryType {
        /// Which block: `origin_defaults`, or one entry's `overrides:`.
        block: String,
        /// `policies` or `transforms`.
        list: &'static str,
        /// The entry's `name:`.
        name: String,
        /// The unrecognized `type:`.
        kind: String,
    },
    /// A runtime-authored `policies:` or `transforms:` entry has no
    /// `type:`.
    #[error(
        "{block}: `{list}` entry `{name}` has no `type:`. Without one nothing dispatches it, \
         and a project overriding it by name would be overriding nothing"
    )]
    MissingEntryType {
        /// Which block: `origin_defaults`, or one entry's `overrides:`.
        block: String,
        /// `policies` or `transforms`.
        list: &'static str,
        /// The entry's `name:`.
        name: String,
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
    #[error("origin_sources entry `{entry}`: the profile document does not parse: {reason}")]
    Parse {
        /// The entry name.
        entry: String,
        /// The parse failure, with every quoted value redacted.
        reason: String,
    },
    /// The profile document parses as YAML but is not a valid profile.
    ///
    /// This is where the write-side allowlist speaks. Every field a
    /// project may set is a field of [`OriginProfileSpec`], so anything
    /// else arrives here as an unknown key naming itself.
    #[error(
        "origin_sources entry `{entry}`: profile `{profile}` is not a valid origin profile: \
         {reason}"
    )]
    ProfileParse {
        /// The entry name.
        entry: String,
        /// The profile name.
        profile: String,
        /// The parse failure. Names the offending key, which serde
        /// quotes with backticks, and never the value, which it quotes
        /// with `"`.
        reason: String,
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
    /// A project layer added an entry that would shadow a locked one.
    ///
    /// Boxed: six names is more than any other variant carries, and
    /// unboxed it would push every `Result` in this module over
    /// `clippy::result_large_err`'s threshold, so every refusal would
    /// pay for this one on the stack.
    #[error("{0}")]
    LockedEffectShadowed(Box<LockedEffectShadow>),
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
    #[error("origin_sources entry `{entry}`: composed origin `{host}` is not valid: {reason}")]
    Compose {
        /// The entry name.
        entry: String,
        /// The map key the composed origin would have taken.
        host: String,
        /// The deserialization failure, with every quoted value redacted.
        reason: String,
    },
    /// A layer serialized to something that is not a mapping. Not
    /// reachable from any document; present so the resolver has no
    /// `unwrap`.
    #[error("internal: an origin layer is not a mapping")]
    LayerNotAMapping,
}

/// Why a project addition was refused for shadowing a locked entry.
///
/// A struct rather than enum fields so the variant can be boxed; see
/// [`OriginResolveError::LockedEffectShadowed`].
#[derive(Debug)]
pub struct LockedEffectShadow {
    /// The `origin_sources` entry being composed.
    pub entry: String,
    /// The profile that carried the addition.
    pub profile: String,
    /// Which of [`PROFILE_LIST_MERGE_KEYS`] the addition is in.
    pub list: String,
    /// The locked entry it would shadow.
    pub locked: String,
    /// The addition's own `name:`, or `(unnamed)`.
    pub addition: String,
    /// The effect the two share: `type=<value>`, or the dotted leaf path
    /// both write.
    pub shadowed: String,
}

impl std::fmt::Display for LockedEffectShadow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "origin_sources entry `{}`: profile `{}` adds `{}` entry `{}`, which shadows the \
             locked entry `{}` through `{}`. A lock binds what the entry does, not what it is \
             called, so the addition is refused rather than layered after it. Ask whoever owns \
             `origin_defaults` to carry it",
            self.entry, self.profile, self.list, self.addition, self.locked, self.shadowed
        )
    }
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
    /// The commit this document was read at, when the caller resolved
    /// one.
    ///
    /// The resolver stays pure: it never asks a repository anything, so
    /// the sha is the fetching caller's to supply. `None` is honest
    /// rather than empty, and it is what a fixture or an offline compose
    /// from a file on disk reports; the provenance then names the
    /// repository and the requested revision without claiming a commit
    /// nobody resolved.
    pub commit: Option<&'a str>,
}

impl<'a> ProfileBinding<'a> {
    /// One entry paired with the document it deploys, with no resolved
    /// commit.
    ///
    /// A constructor rather than only a literal, because `commit` was
    /// added to a public struct after PR1 shipped and every external
    /// literal is a source break. `#[non_exhaustive]` would be worse
    /// here than the break it prevents: this is an input type, so a
    /// literal is the natural way to write one, and the attribute takes
    /// literals away entirely. A constructor with a `with_` for the
    /// optional half leaves both spellings working.
    #[must_use]
    pub const fn new(entry: &'a OriginSourceEntry, document: &'a str) -> Self {
        Self {
            entry,
            document,
            commit: None,
        }
    }

    /// The same binding with the commit the caller resolved.
    #[must_use]
    pub const fn with_commit(mut self, commit: &'a str) -> Self {
        self.commit = Some(commit);
        self
    }
}

/// A default a project switched off, recorded so the drop is auditable.
///
/// There is no delete verb, matching the existing merge contract.
/// `disabled: true` leaves a record; an absence would not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DroppedDefault {
    /// The entry whose profile switched it off.
    pub entry: String,
    /// The profile that switched it off.
    pub profile: String,
    /// Which of [`PROFILE_LIST_MERGE_KEYS`] the entry was in.
    pub list: String,
    /// The dropped entry's `name:`.
    pub name: String,
    /// The composition layer that switched it off.
    pub dropped_by: CompositionLayer,
    /// The composition layer that had introduced it, when one had.
    ///
    /// `None` for a `disabled: true` naming something no earlier layer
    /// had put there. That case is not a silent no-op: the entry is
    /// dropped rather than appended, so the record is the only trace,
    /// and an operator reading a drop with no introducer is reading a
    /// profile switching off something that was never on.
    pub introduced_by: Option<CompositionLayer>,
}

// --- Composition provenance (WOR-2440) -------------------------------

/// Which composition layer wrote a leaf.
///
/// The four layers of one composed origin, in application order. The
/// answer to "who do I talk to about this policy" is different for each
/// of them: `origin_defaults` and an entry `overrides:` block are the
/// platform's runtime document, `spec.base` and `spec.environments[env]`
/// are the project's repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "layer", rename_all = "snake_case")]
pub enum CompositionLayer {
    /// The platform floor every composed origin starts from.
    OriginDefaults,
    /// The project profile's environment-independent layer.
    ProfileBase,
    /// The project profile's layer for the environment this entry
    /// selected.
    ProfileEnvironment {
        /// The `environments:` key, which is [`OriginSourceEntry::environment`].
        environment: String,
    },
    /// The runtime entry's `overrides:` block, layered last.
    EntryOverride,
}

impl CompositionLayer {
    /// The config path this layer is spelled at, which is what an
    /// operator greps for.
    #[must_use]
    pub fn path(&self) -> String {
        match self {
            Self::OriginDefaults => "origin_defaults".to_string(),
            Self::ProfileBase => "spec.base".to_string(),
            Self::ProfileEnvironment { environment } => {
                format!("spec.environments[{environment}]")
            }
            Self::EntryOverride => "origin_sources.entries[].overrides".to_string(),
        }
    }

    /// Whether the project repository authored this layer.
    ///
    /// The other two are the runtime document, which is the same split
    /// [`LayerAuthor`] enforces during the merge. Kept as one question
    /// rather than a match at every call site, because "is this the
    /// project's to change" is the question provenance exists to answer.
    #[must_use]
    pub(crate) const fn is_project_authored(&self) -> bool {
        matches!(self, Self::ProfileBase | Self::ProfileEnvironment { .. })
    }
}

/// Where one leaf of a composed origin came from.
///
/// No value, ever. Provenance says which layer set a leaf and which
/// repository that layer came from; the leaf's value is in the composed
/// document, which is the thing under access control. A composed leaf
/// can be a `secret://backend/name` reference an entry bound, so
/// carrying values here would put a reference into every surface that
/// renders provenance, including a `sbproxy plan` a developer pastes
/// into a ticket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafOrigin {
    /// The layer that last wrote this leaf.
    #[serde(flatten)]
    pub layer: CompositionLayer,
    /// The `origin_sources` entry that deployed the profile. `None` only
    /// for [`CompositionLayer::OriginDefaults`], which no entry owns.
    pub entry: Option<String>,
    /// The profile document's own `name:`, for the two layers the
    /// project authored. `None` for the two runtime-authored layers,
    /// because naming a profile there would credit a repository for a
    /// line the platform wrote.
    pub profile: Option<String>,
    /// The repository the layer was read from and the revision it
    /// resolved to, for the two project-authored layers.
    ///
    /// [`crate::config_merge::Provenance`] rather than a parallel type:
    /// the node-side merge already answers "which repository and which
    /// commit" in exactly this shape, and an operator reading
    /// `/admin/config/effective` beside a composition should not have to
    /// learn a second vocabulary. `Provenance::Local` is never used
    /// here; a runtime-authored layer reports `None` instead, because
    /// the runtime document's own origin is the node's to report and not
    /// the composition's.
    pub source: Option<crate::config_merge::Provenance>,
}

/// Composition provenance for one composed origin.
///
/// A leaf path here is **not** a path into the composed document. The
/// four merged lists are keyed by `name:` (`policies[waf].action_on_match`)
/// because a list index moves whenever an earlier entry is dropped or a
/// project appends one, and an audit trail that renumbered itself
/// between two composes would be worse than none. The composed document
/// carries indices and no names, since `strip_bookkeeping` removes
/// `name:` before the typed parse.
///
/// # What this cannot see
///
/// Attribution is derived by asking which layer last wrote each leaf,
/// not by observing the merge as it runs. The two agree because both
/// read the same per-layer mappings under the same replace rule, and
/// [`Self::unattributed`] is the check on that: a leaf in the composed
/// origin that no layer claims means the derivation and the merge have
/// diverged. An unnamed entry in one of the four lists is matched by
/// value rather than by name, so two byte-identical unnamed entries in
/// different layers are credited to the later one. A list entry whose
/// `name:` literally begins with `#` collides with the placeholder used
/// for unnamed entries.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositionProvenance {
    /// Leaf path to the layer that wrote it, in path order.
    leaves: BTreeMap<String, LeafOrigin>,
    /// Every default this origin's composition switched off.
    drops: Vec<DroppedDefault>,
    /// Composed leaves no layer claimed. Empty in every composition this
    /// repository can produce; see the type's `What this cannot see`.
    unattributed: Vec<String>,
}

impl CompositionProvenance {
    /// The layer that wrote `path`, or `None` when nothing composed
    /// there.
    #[must_use]
    pub fn get(&self, path: &str) -> Option<&LeafOrigin> {
        self.leaves.get(path)
    }

    /// Every recorded `(path, origin)` pair, in path order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &LeafOrigin)> {
        self.leaves.iter()
    }

    /// Every recorded path, in path order.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.leaves.keys().map(String::as_str)
    }

    /// Number of attributed leaves.
    #[must_use]
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether nothing was attributed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Every default this origin's composition dropped.
    #[must_use]
    pub fn drops(&self) -> &[DroppedDefault] {
        &self.drops
    }

    /// Composed leaves no layer claimed.
    #[must_use]
    pub fn unattributed(&self) -> &[String] {
        &self.unattributed
    }

    /// Render this origin's provenance as aligned text.
    ///
    /// The form `sbproxy plan` prints. A human reading "why is this WAF
    /// rule here" needs the layer and the repository on the same line as
    /// the field, and needs it without a JSON tool, which is the whole
    /// point of the surface.
    #[must_use]
    pub fn render(&self, host: &str) -> String {
        let mut out = String::new();
        out.push_str(host);
        out.push('\n');
        if self.leaves.is_empty() {
            out.push_str("  (nothing composed)\n");
            return out;
        }
        let width = self
            .leaves
            .keys()
            .map(String::len)
            .max()
            .unwrap_or(0)
            .min(60);
        for (path, origin) in &self.leaves {
            let mut line = format!("  {path:<width$}  {}", origin.layer.path());
            if let Some(entry) = origin.entry.as_deref() {
                line.push_str(&format!("  entry {entry}"));
            }
            if let Some(crate::config_merge::Provenance::Git { repo, commit, .. }) =
                origin.source.as_ref()
            {
                line.push_str(&format!("  {repo}@{}", short_commit(commit)));
            }
            out.push_str(&line);
            out.push('\n');
        }
        for drop in &self.drops {
            let introduced = drop
                .introduced_by
                .as_ref()
                .map_or_else(|| "nothing".to_string(), CompositionLayer::path);
            out.push_str(&format!(
                "  dropped {}[{}]  {} dropped a default introduced by {introduced}  entry {}\n",
                drop.list,
                drop.name,
                drop.dropped_by.path(),
                drop.entry
            ));
        }
        for path in &self.unattributed {
            out.push_str(&format!(
                "  {path}  UNATTRIBUTED: no composition layer claims this leaf, which means the \
                 provenance derivation and the merge have diverged\n"
            ));
        }
        out
    }
}

/// A commit shortened for a human-readable line, left whole when it is
/// not a sha (`HEAD`, a branch name a development tier allows).
fn short_commit(commit: &str) -> &str {
    if commit.len() > 12 && commit.chars().all(|c| c.is_ascii_hexdigit()) {
        &commit[..12]
    } else {
        commit
    }
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
    /// Which layer set each leaf of each composed origin, keyed by the
    /// same hostname `origins` is keyed by (WOR-2440).
    pub provenance: BTreeMap<String, CompositionProvenance>,
    /// The composed origins as the mapping the merge produced, keyed
    /// the same way.
    ///
    /// The same content as [`Self::origins`], and both are kept because
    /// they answer different questions. `origins` is the typed
    /// round-trip: a composition that will not deserialize into
    /// `RawOriginConfig` is refused, and that check has to run. This is
    /// what an aggregator publishes, because `RawOriginConfig` carries
    /// no `skip_serializing_if`, so re-serializing the typed struct
    /// writes all fifty-two fields per origin, most of them nulls and
    /// empty lists nobody authored. At a hundred origins that is a
    /// document several times the size of the one anybody wrote, and it
    /// is also a document whose leaves provenance cannot attribute,
    /// because no layer set them.
    pub composed: BTreeMap<String, Mapping>,
}

// --- Load-time validation --------------------------------------------

/// Check `origin_defaults` at config load.
///
/// See `validate_origin_body` for the three rules and why they run
/// here rather than at the aggregator.
///
/// # Errors
///
/// Returns [`OriginResolveError::UnnamedDefault`],
/// [`OriginResolveError::UnknownOriginKey`],
/// [`OriginResolveError::UnknownEntryType`],
/// [`OriginResolveError::MissingEntryType`], or
/// [`OriginResolveError::DefaultsListShape`], each naming the block and
/// the offending key or position.
pub fn validate_origin_defaults(defaults: &Mapping) -> Result<(), OriginResolveError> {
    validate_origin_defaults_with(defaults, false)
}

/// [`validate_origin_defaults`] with the caller saying whether this
/// document declares an extension bundle source.
///
/// A `type:` this build does not recognize is a refusal when the answer
/// is `false` and a warning when it is `true`. The built-in
/// `KNOWN_POLICY_TYPES` is not the whole vocabulary: an installed
/// extension bundle provides types that are by construction absent from
/// it, and nothing here can resolve the installed set, because bundle
/// sources are paths and URLs this crate deliberately does not fetch. A
/// document that declares no source has no way to acquire such a type,
/// so an unrecognized one there is a typo; a document that declares one
/// may legitimately name a type only the running proxy can see.
///
/// # Errors
///
/// The same set as [`validate_origin_defaults`].
pub fn validate_origin_defaults_with(
    defaults: &Mapping,
    declares_extension_bundles: bool,
) -> Result<(), OriginResolveError> {
    validate_origin_body(
        "origin_defaults",
        defaults,
        TypeRule::Required,
        UnknownTypes::for_document(declares_extension_bundles),
    )
}

/// Whether a `type:` this build does not recognize is a refusal or a
/// warning.
///
/// The bare `KNOWN_POLICY_TYPES` is not the whole vocabulary. The
/// existing validator asks `KNOWN_POLICY_TYPES.contains(t) ||
/// opts.extra_policy_types.contains(t)`, the second half being the
/// escape hatch for a type an installed extension bundle provides, and a
/// bundle-provided type is by construction absent from the built-in list
/// because `reserved_builtin_hook_names` reserves that whole list against
/// bundles. Refusing unconditionally would make the floor strictly less
/// expressive than the origins it is a floor for (WOR-2432 re-review N5).
///
/// `compile_config` cannot resolve the installed set: bundle sources are
/// paths and URLs it deliberately does not fetch. So the question it can
/// answer is whether this document declares any bundle source at all. A
/// document with none has no way to acquire a type outside the built-in
/// list, so an unrecognized one there is a typo and is refused. A
/// document with one warns instead, and the composed origin still meets
/// the real dispatcher at boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnknownTypes {
    /// No extension bundle source is declared, so an unrecognized type
    /// cannot be provided by anything.
    Refuse,
    /// A bundle source is declared, so an unrecognized type may be one
    /// this build cannot see from here.
    Warn,
}

impl UnknownTypes {
    /// The posture for a document that does or does not declare a bundle
    /// source.
    fn for_document(declares_extension_bundles: bool) -> Self {
        if declares_extension_bundles {
            Self::Warn
        } else {
            Self::Refuse
        }
    }
}

/// Whether a `policies:` or `transforms:` entry in a runtime-authored
/// block has to name a `type:`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TypeRule {
    /// `origin_defaults`, the bottom layer. Nothing beneath it supplies
    /// a `type:`, so an entry without one dispatches to nothing.
    Required,
    /// An entry's `overrides:`, the top layer. A named entry there is
    /// usually a partial override of a floor entry that already carries
    /// the type, so demanding one would refuse the block's main use.
    /// A `type:` that *is* written still has to be a real one.
    OptionalButKnown,
}

/// The shared checks for a runtime-authored, origin-shaped block:
/// `origin_defaults` and each entry's `overrides:`.
///
/// Neither block is a `RawOriginConfig`, because the merge runs before
/// the typed parse and the typed modifier structs reject the `name:` key
/// the merge is keyed on. That is the right call and it costs the two
/// blocks their `deny_unknown_fields`, so a misspelled key in either one
/// used to pass `sbproxy validate` clean and then fail every compose at
/// the aggregator, which is the far end of a GitOps loop. These three
/// checks put the refusal back where the operator is.
///
/// * Every top-level key is a real origin field, asked through the same
///   classification the write-boundary ratchet keeps honest, so this can
///   never be narrower than the origin.
/// * Every entry in a merged list carries a `name:`, because a default
///   has to be addressable to be overridable.
/// * Every `policies[]` and `transforms[]` entry names a `type:` the
///   dispatcher knows. `request_modifiers[]` and `response_modifiers[]`
///   have no type discriminator, so they are not checked here.
///
/// # What this cannot see
///
/// A `type:` is required in `origin_defaults` and optional in an entry's
/// `overrides:`, because an override is usually a partial edit of a
/// floor entry that already carries the type. So a named `overrides:`
/// entry that matches nothing in the floor and carries no `type:` is an
/// addition that will fail at compose, and only the two documents
/// together can say that. Neither block is validated against a module's
/// own field set either: this checks the type string, not the
/// configuration under it, which is `compile_config`'s job on the
/// composed origin.
fn validate_origin_body(
    block: &str,
    body: &Mapping,
    type_rule: TypeRule,
    unknown_types: UnknownTypes,
) -> Result<(), OriginResolveError> {
    for key in body.keys() {
        let Some(key) = key.as_str() else {
            continue;
        };
        if !origin_field_exists(key) {
            return Err(OriginResolveError::UnknownOriginKey {
                block: block.to_string(),
                key: key.to_string(),
            });
        }
    }
    for list in PROFILE_LIST_MERGE_KEYS {
        let Some(value) = body.get(*list) else {
            continue;
        };
        let Some(items) = value.as_sequence() else {
            return Err(OriginResolveError::DefaultsListShape { list });
        };
        for (index, item) in items.iter().enumerate() {
            let named = entry_name(item);
            if named.is_none() {
                return Err(OriginResolveError::UnnamedDefault {
                    block: block.to_string(),
                    list,
                    index,
                });
            }
            let known: &[&str] = match *list {
                "policies" => crate::validate::KNOWN_POLICY_TYPES,
                "transforms" => crate::validate::KNOWN_TRANSFORM_TYPES,
                _ => continue,
            };
            let kind = item
                .as_mapping()
                .and_then(|entry| entry.get("type"))
                .and_then(Value::as_str);
            match kind {
                Some(kind) if known.contains(&kind) => {}
                Some(kind) if unknown_types == UnknownTypes::Warn => {
                    tracing::warn!(
                        block,
                        list,
                        name = named.unwrap_or("?"),
                        kind,
                        "origin block names a type this build does not recognize; accepted \
                         because the document declares an extension bundle source that may \
                         provide it, and refused at boot if nothing does"
                    );
                }
                Some(kind) => {
                    return Err(OriginResolveError::UnknownEntryType {
                        block: block.to_string(),
                        list,
                        name: named.unwrap_or("?").to_string(),
                        kind: kind.to_string(),
                    })
                }
                None if type_rule == TypeRule::Required => {
                    return Err(OriginResolveError::MissingEntryType {
                        block: block.to_string(),
                        list,
                        name: named.unwrap_or("?").to_string(),
                    })
                }
                None => {}
            }
        }
    }
    Ok(())
}

/// Whether `key` is a field of `RawOriginConfig`.
///
/// Asked through the two halves of the write boundary rather than
/// through a third list. `every_raw_origin_field_is_classified` asserts
/// that [`PROFILE_WRITABLE_ORIGIN_FIELDS`] plus
/// [`PLATFORM_OWNED_ORIGIN_FIELDS`] is exactly the origin's field set,
/// so this cannot drift narrower than the struct without that test going
/// red first.
fn origin_field_exists(key: &str) -> bool {
    PROFILE_WRITABLE_ORIGIN_FIELDS.contains(&key)
        || PLATFORM_OWNED_ORIGIN_FIELDS
            .iter()
            .any(|(field, _)| *field == key)
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
    validate_origin_sources_with(sources, false)
}

/// [`validate_origin_sources`] with the caller saying whether this
/// document declares an extension bundle source.
///
/// Split out rather than folded in because `compile_config` is the only
/// caller that can answer that question, and every other caller (a test,
/// a tool reading one block) legitimately cannot.
///
/// The flag governs an unrecognized `policies:` or `transforms:`
/// `type:` in an entry's `overrides:`, the same way it does for
/// `origin_defaults`; see [`validate_origin_defaults_with`].
///
/// # Errors
///
/// The same set as [`validate_origin_sources`].
pub fn validate_origin_sources_with(
    sources: &OriginSourcesConfig,
    declares_extension_bundles: bool,
) -> Result<(), OriginResolveError> {
    let unknown_types = UnknownTypes::for_document(declares_extension_bundles);
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
        if let Some(overrides) = entry.overrides.as_ref() {
            // The same shape as `origin_defaults`, written by the same
            // people, and open to the same misspelling for the same
            // reason: it is a `Mapping` because the merge predates the
            // typed parse.
            validate_origin_body(
                &format!("origin_sources entry `{}` overrides", entry.name),
                overrides,
                TypeRule::OptionalButKnown,
                unknown_types,
            )?;
        }
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

/// Per-tier `origin_sources` entry counts, carried on the compiled
/// config and published by the seam that applies one.
///
/// Every tier, always, including the tier that is not in force and the
/// case where the block is absent: a gauge only written for the tier in
/// force keeps the other tier's last reading forever, and one only
/// written when the block is present keeps its last reading when the
/// block is deleted. Those are the two transitions the metric exists to
/// show.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OriginSourceEntryCounts {
    /// `(pinned, unpinned)` when the document is `tier: development`.
    pub development: (usize, usize),
    /// `(pinned, unpinned)` when the document is `tier: production`.
    pub production: (usize, usize),
}

impl OriginSourceEntryCounts {
    /// The counts as `(tier, pinned, unpinned)` rows, one per tier, in
    /// [`EnvironmentTier::ALL`] order. What a metric writer iterates.
    #[must_use]
    pub fn rows(self) -> [(EnvironmentTier, usize, usize); 2] {
        EnvironmentTier::ALL.map(|tier| match tier {
            EnvironmentTier::Development => (tier, self.development.0, self.development.1),
            EnvironmentTier::Production => (tier, self.production.0, self.production.1),
        })
    }
}

/// The per-tier entry counts for a document, for **every** tier.
///
/// A pure function of the block, and deliberately not a metric write.
/// `compile_config` runs on candidate documents as well as on the one a
/// node applies: `ConfigAuthority::publish` validates its payload
/// through it, and `origin_sources` is on
/// [`crate::AUTHORITY_DENIED_PATHS`], so a payload can never carry the
/// block. A write there would drive every series to zero on each
/// publish, which is exactly the reading the shipped dashboard panel and
/// `docs/configuration.md` tell an operator to page on
/// (WOR-2432 re-review N1). So the compile computes and the apply seam
/// publishes.
#[must_use]
pub fn origin_source_entry_counts(
    sources: Option<&OriginSourcesConfig>,
) -> OriginSourceEntryCounts {
    let mut counts = OriginSourceEntryCounts::default();
    let Some(sources) = sources else {
        return counts;
    };
    let pinned = sources
        .entries
        .iter()
        .filter(|entry| entry.revision.as_deref().is_some_and(revision_is_immutable))
        .count();
    let split = (pinned, sources.entries.len().saturating_sub(pinned));
    match sources.tier {
        EnvironmentTier::Development => counts.development = split,
        EnvironmentTier::Production => counts.production = split,
    }
    counts
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
    resolve_origins_with(defaults, bindings, hand_written, false)
}

/// [`resolve_origins`] with the caller saying whether the runtime
/// document declares an extension bundle source.
///
/// The aggregator holds the whole runtime document and is the caller
/// that can answer this; [`resolve_origins`] cannot, because it takes
/// the floor as a bare mapping. Without it the floor's type check would
/// be `Refuse` here while `compile_config` warned on the same document,
/// so a floor naming a bundle-provided policy type would pass
/// `sbproxy validate` and then be hard-refused by the aggregator: the
/// far-end-of-a-GitOps-loop failure these checks exist to move earlier,
/// reintroduced for the bundle case (WOR-2432 verification R2).
///
/// # Errors
///
/// The same set as [`resolve_origins`].
pub fn resolve_origins_with(
    defaults: Option<&Mapping>,
    bindings: &[ProfileBinding<'_>],
    hand_written: &BTreeSet<String>,
    declares_extension_bundles: bool,
) -> Result<OriginResolution, OriginResolveError> {
    if let Some(defaults) = defaults {
        validate_origin_defaults_with(defaults, declares_extension_bundles)?;
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
            let (composed, provenance) =
                compose_one(defaults, binding, &profile, declared, &mut resolution.drops)?;
            for host in hosts {
                let origin: RawOriginConfig =
                    serde_yaml::from_value(Value::Mapping(composed.clone())).map_err(|source| {
                        OriginResolveError::Compose {
                            entry: entry.name.clone(),
                            host: host.clone(),
                            reason: redact_serde_message(&source.to_string()),
                        }
                    })?;
                resolution
                    .provenance
                    .insert(host.clone(), provenance.clone());
                resolution.composed.insert(host.clone(), composed.clone());
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
            reason: redact_serde_message(&source.to_string()),
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
            reason: redact_serde_message(&source.to_string()),
        })?;
    refuse_inline_secrets(&resolved_value, "", &entry.name, &profile_name)?;
    // The typed parse is the allowlist. Everything a project may set is
    // a field of `OriginProfileSpec`; everything else fails here as an
    // unknown key rather than being carried and dropped.
    serde_yaml::from_value(resolved_value).map_err(|source| OriginResolveError::ProfileParse {
        entry: entry.name.clone(),
        profile: profile_name,
        reason: redact_serde_message(&source.to_string()),
    })
}

/// A serde failure message with every value it quoted taken out, bounded.
///
/// Serde spells an identifier with backticks (``unknown field `force_ssl`
/// ``, ``missing field `url` ``) and a *value* with double quotes
/// (`invalid type: string "sk-live-...", expected f32`). That split is
/// what makes this a one-rule scrub rather than a parser: every
/// double-quoted run becomes `"[redacted]"`, and everything else,
/// including the field name the write-boundary refusal has to name,
/// survives.
///
/// Public because the credential rotate route needs the identical scrub
/// on the identical hazard: `POST /admin/credentials/{id}/rotate` is the
/// one admin body carrying a plaintext upstream credential, and serde's
/// `invalid type` text embeds the offending scalar. One scrub with two
/// callers beats two scrubs that drift.
///
/// # What this cannot see
///
/// A value serde renders **without** quoting it. `invalid value: integer
/// 7, expected ...` keeps the `7`, and an unquoted enum variant keeps its
/// text. Both are bounded, non-string shapes that a secret cannot be, so
/// the residue is a number or an identifier rather than a credential. The
/// length cap is the backstop for anything this reasoning misses: a
/// message longer than `MAX_SERDE_MESSAGE_BYTES` is cut on a character
/// boundary and marked, so a pathological rendering cannot put a document
/// in a log line.
pub fn redact_serde_message(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut in_quotes = false;
    let mut escaped = false;
    for character in message.chars() {
        if in_quotes {
            // Inside a quoted run nothing is emitted, and the escape
            // state is tracked so `\"` does not close it. Serde renders a
            // string value with `{:?}`, which escapes an inner quote
            // exactly that way, so a scan that toggled on it would close
            // the run in the middle of the value and then copy the rest
            // out verbatim (WOR-2432 re-review N2).
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                out.push_str("[redacted]\"");
                in_quotes = false;
            }
            continue;
        }
        if character == '"' {
            out.push('"');
            in_quotes = true;
            continue;
        }
        out.push(character);
    }
    if in_quotes {
        // An unterminated quote means the rest of the message was inside
        // it, so nothing more is emitted and the run is closed here.
        out.push_str("[redacted]\"");
    }
    if out.len() > MAX_SERDE_MESSAGE_BYTES {
        let cut = (0..=MAX_SERDE_MESSAGE_BYTES)
            .rev()
            .find(|index| out.is_char_boundary(*index))
            .unwrap_or(0);
        out.truncate(cut);
        out.push_str(" (truncated)");
    }
    out
}

/// Cap on a redacted serde message, in bytes.
///
/// Long enough for the longest real one, which is the write boundary's
/// ``unknown field `x`, expected one of `action`, `authentication`, ...``
/// listing all nineteen allowed fields. Short enough that no rendering
/// puts a document into a log line.
const MAX_SERDE_MESSAGE_BYTES: usize = 512;

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

/// Layer one profile origin into a single composed origin mapping, and
/// record which layer set each leaf.
///
/// The layer list is built before the fold rather than during it,
/// because two things need it: the drop record has to name the layer
/// that had introduced the entry being switched off, and the
/// provenance walk has to ask every layer, in order, which of them last
/// wrote each composed leaf.
fn compose_one(
    defaults: Option<&Mapping>,
    binding: &ProfileBinding<'_>,
    profile: &OriginProfile,
    declared: &OriginProfileOrigin,
    drops: &mut Vec<DroppedDefault>,
) -> Result<(Mapping, CompositionProvenance), OriginResolveError> {
    let entry = binding.entry;
    let mut layers: Vec<(CompositionLayer, Mapping)> = Vec::with_capacity(4);
    if let Some(defaults) = defaults {
        layers.push((CompositionLayer::OriginDefaults, defaults.clone()));
    }
    layers.push((CompositionLayer::ProfileBase, declared.base.to_mapping()?));
    if let Some(environment) = entry.environment.as_deref() {
        if let Some(overlay) = declared.environments.get(environment) {
            layers.push((
                CompositionLayer::ProfileEnvironment {
                    environment: environment.to_string(),
                },
                overlay.to_mapping()?,
            ));
        }
    }
    if let Some(overrides) = entry.overrides.as_ref() {
        layers.push((CompositionLayer::EntryOverride, overrides.clone()));
    }

    // The floor is cloned in rather than layered over an empty mapping.
    // Layering it would run the platform's own document through the
    // merge's project checks, which is a different question from the one
    // those checks answer.
    let mut accumulated = defaults.cloned().unwrap_or_default();
    let first_project_layer = usize::from(defaults.is_some());
    let drops_before = drops.len();
    for index in first_project_layer..layers.len() {
        let (identity, mapping) = &layers[index];
        let mut context = LayerContext {
            entry,
            profile: &profile.name,
            author: if identity.is_project_authored() {
                LayerAuthor::Project
            } else {
                LayerAuthor::Runtime
            },
            drops,
            layer: identity.clone(),
            earlier: &layers[..index],
        };
        layer(&mut accumulated, mapping, &mut context)?;
    }

    let provenance = attribute_leaves(
        &accumulated,
        &layers,
        binding,
        &profile.name,
        drops[drops_before..].to_vec(),
    );
    strip_bookkeeping(&mut accumulated);
    Ok((accumulated, provenance))
}

/// Which layer last wrote each leaf of one composed origin.
///
/// Derived from the composed mapping rather than stamped during the
/// merge, so coverage is exact by construction: every path this returns
/// is a leaf that really composed, and every composed leaf is asked
/// about. The rule is the merge's own, `merge_plain` replaces and the
/// four named lists merge by `name:`, so the last layer carrying a leaf
/// at a path is the layer whose value survived there.
///
/// Runs on the mapping **before** `strip_bookkeeping`, because `name:`
/// is the key the four lists are addressed by and stripping removes it.
fn attribute_leaves(
    composed: &Mapping,
    layers: &[(CompositionLayer, Mapping)],
    binding: &ProfileBinding<'_>,
    profile_name: &str,
    drops: Vec<DroppedDefault>,
) -> CompositionProvenance {
    let per_layer: Vec<BTreeSet<String>> = layers
        .iter()
        .map(|(_, mapping)| leaf_paths_of(mapping))
        .collect();
    let unnamed_per_layer: Vec<Vec<(&str, &Value)>> = layers
        .iter()
        .map(|(_, mapping)| unnamed_list_entries(mapping))
        .collect();

    let mut composed_leaves: Vec<String> = Vec::new();
    let mut unnamed_prefixes: Vec<(String, &Value, &str)> = Vec::new();
    collect_leaves(
        "",
        composed,
        &mut composed_leaves,
        &mut unnamed_prefixes,
        None,
    );

    let mut leaves: BTreeMap<String, LeafOrigin> = BTreeMap::new();
    let mut unattributed: Vec<String> = Vec::new();
    for path in composed_leaves {
        // An unnamed list entry keeps no stable key across layers: its
        // index in the composed list is a position the merge produced,
        // not one any layer wrote. It is also never merged, only
        // appended, so it appears verbatim in the layer that wrote it
        // and matching by value is exact.
        let owner = unnamed_prefixes
            .iter()
            .find(|(prefix, _, _)| path.starts_with(prefix.as_str()))
            .and_then(|(_, value, list)| {
                unnamed_per_layer.iter().rposition(|entries| {
                    entries.iter().any(|(candidate_list, candidate)| {
                        candidate_list == list && candidate == value
                    })
                })
            })
            .or_else(|| per_layer.iter().rposition(|paths| paths.contains(&path)));
        match owner {
            Some(index) => {
                leaves.insert(path, leaf_origin(&layers[index].0, binding, profile_name));
            }
            None => unattributed.push(path),
        }
    }
    CompositionProvenance {
        leaves,
        drops,
        unattributed,
    }
}

/// One attributed leaf, with the repository facts filled in for the two
/// project-authored layers.
fn leaf_origin(
    layer: &CompositionLayer,
    binding: &ProfileBinding<'_>,
    profile_name: &str,
) -> LeafOrigin {
    let project = layer.is_project_authored();
    LeafOrigin {
        layer: layer.clone(),
        entry: match layer {
            CompositionLayer::OriginDefaults => None,
            _ => Some(binding.entry.name.clone()),
        },
        profile: project.then(|| profile_name.to_string()),
        source: project.then(|| crate::config_merge::Provenance::Git {
            repo: crate::source::redact_repo(&binding.entry.repo),
            reference: binding
                .entry
                .revision
                .clone()
                .unwrap_or_else(|| "HEAD".to_string()),
            commit: binding
                .commit
                .map_or_else(|| "(unresolved)".to_string(), str::to_string),
        }),
    }
}

/// Every leaf path in one origin mapping, in the provenance grammar.
fn leaf_paths_of(mapping: &Mapping) -> BTreeSet<String> {
    let mut paths = Vec::new();
    let mut unnamed = Vec::new();
    collect_leaves("", mapping, &mut paths, &mut unnamed, None);
    paths.into_iter().collect()
}

/// Every unnamed entry of the four merged lists, as `(list, entry)`.
fn unnamed_list_entries(mapping: &Mapping) -> Vec<(&str, &Value)> {
    let mut out = Vec::new();
    for list in PROFILE_LIST_MERGE_KEYS {
        let Some(items) = mapping.get(*list).and_then(Value::as_sequence) else {
            continue;
        };
        for item in items {
            if entry_name(item).is_none() {
                out.push((*list, item));
            }
        }
    }
    out
}

/// Walk one origin mapping and record every leaf path.
///
/// A leaf is anything that is not a non-empty mapping, matching
/// [`crate::config_merge::ProvenanceMap`]'s contract: a sequence merges
/// or replaces wholesale, so its elements are not separate leaves, and
/// an empty mapping carries a statement even with no children.
///
/// The four merged lists are the exception, and the reason this is not
/// the merge module's walker: their elements *are* addressed
/// individually, by `name:`, so they are walked and keyed by that name.
/// `unnamed` collects the path prefix of each element that has none,
/// paired with the element itself so the caller can attribute it by
/// value.
fn collect_leaves<'a>(
    prefix: &str,
    mapping: &'a Mapping,
    out: &mut Vec<String>,
    unnamed: &mut Vec<(String, &'a Value, &'a str)>,
    inside_list_entry: Option<&str>,
) {
    for (key, value) in mapping {
        let Some(key) = key.as_str() else {
            continue;
        };
        if inside_list_entry.is_some() && BOOKKEEPING_KEYS.contains(&key) {
            // Stripped from the composed origin, so not a leaf of it.
            continue;
        }
        let path = if prefix.is_empty() {
            key.to_string()
        } else {
            format!("{prefix}.{key}")
        };
        if inside_list_entry.is_none() && PROFILE_LIST_MERGE_KEYS.contains(&key) {
            if let Some(items) = value.as_sequence() {
                for (index, item) in items.iter().enumerate() {
                    let element_key = match entry_name(item) {
                        Some(name) => name.to_string(),
                        None => {
                            let placeholder = format!("#{index}");
                            unnamed.push((format!("{path}[{placeholder}]"), item, key));
                            placeholder
                        }
                    };
                    let element_path = format!("{path}[{element_key}]");
                    match item.as_mapping() {
                        Some(item) => {
                            collect_leaves(&element_path, item, out, unnamed, Some(key));
                        }
                        None => out.push(element_path),
                    }
                }
                continue;
            }
        }
        match value {
            Value::Mapping(child) if !child.is_empty() => {
                collect_leaves(&path, child, out, unnamed, inside_list_entry);
            }
            _ => out.push(path),
        }
    }
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
    /// Which layer is being applied, for the drop record.
    layer: CompositionLayer,
    /// The layers already applied, newest last, so a drop can name the
    /// layer that had introduced what it switched off.
    earlier: &'a [(CompositionLayer, Mapping)],
}

impl LayerContext<'_> {
    /// The drop record for one `disabled: true`, with both layers named.
    fn dropped(&self, list: &str, name: Option<&str>) -> DroppedDefault {
        DroppedDefault {
            entry: self.entry.name.clone(),
            profile: self.profile.to_string(),
            list: list.to_string(),
            name: name.unwrap_or("?").to_string(),
            dropped_by: self.layer.clone(),
            introduced_by: name.and_then(|name| self.introduced_by(list, name)),
        }
    }

    /// The last layer before this one carrying `name` in `list`.
    ///
    /// Last rather than first: an entry a project's `base` layer already
    /// edited and its `environments` layer then disabled was most
    /// recently set by `base`, and that is the layer whose author gets
    /// asked about the drop.
    fn introduced_by(&self, list: &str, name: &str) -> Option<CompositionLayer> {
        self.earlier
            .iter()
            .rev()
            .find(|(_, mapping)| {
                mapping
                    .get(list)
                    .and_then(Value::as_sequence)
                    .is_some_and(|items| {
                        items
                            .iter()
                            .any(|item| entry_name(item).is_some_and(|existing| existing == name))
                    })
            })
            .map(|(identity, _)| identity.clone())
    }
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
/// * A project addition that would shadow a locked entry's effect is the
///   same refusal, because a lock that bound only the name would be one
///   rename away from useless. See [`effect_keys`].
/// * A project layer bringing a script body into a modifier list that
///   holds a lock is refused too, on either arm, because the effect
///   comparison cannot read a program and an override reaches the same
///   place an addition does with a rename saved. See
///   [`opaque_script_over_a_lock`].
/// * A project override of an **unlocked** entry that introduces an
///   effect a lock above it already holds is the same refusal, because
///   `merge_plain` replaces scalars and `type:` is one of them.
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
                // Read before the mutable borrow: what this entry did
                // before the project layer touched it.
                let before = result
                    .get(index)
                    .and_then(Option::as_ref)
                    .map(effect_keys)
                    .unwrap_or_default();
                // Read before the mutable borrow too, and against the
                // incoming entry rather than the merged one: an override
                // that inserts a script body into an unlocked entry
                // sitting after a lock is the same route an addition
                // takes, one rename saved (WOR-2432 verification R1).
                let opaque = if context.author == LayerAuthor::Project {
                    opaque_script_over_a_lock(result[..index].iter().flatten(), item, list)
                } else {
                    None
                };
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
                    let record = context.dropped(list, incoming_name);
                    context.drops.push(record);
                    *slot = None;
                    continue;
                }
                // After the lock check, which is the more precise error,
                // and after the disable branch, which drops the entry so
                // nothing lands at all.
                if let Some((locked, script)) = opaque {
                    return Err(locked_effect_shadowed(
                        context,
                        list,
                        incoming_name,
                        locked,
                        opaque_script_reason(script),
                    ));
                }
                match (current, item) {
                    (Value::Mapping(existing_map), Value::Mapping(incoming_map)) => {
                        merge_plain(existing_map, incoming_map);
                    }
                    (slot_value, incoming) => {
                        *slot_value = incoming.clone();
                    }
                }
                // An override can reach a lock without renaming anything
                // and without adding anything. `merge_plain` replaces
                // scalars, `type:` included, so a project layer matching
                // an **unlocked** floor entry by name can rewrite it into
                // the mechanism a locked entry above it holds, or make it
                // write a header that entry writes, and it already sits
                // after that entry (WOR-2432 re-review N4).
                //
                // Only the effects the merge *introduced* are checked, and
                // only against locks the merged entry already sits after.
                // Both narrowings matter: the floor's own arrangement of
                // two entries touching one thing is the platform's
                // business, and a lock later in the list is not shadowed
                // by an entry before it.
                if context.author == LayerAuthor::Project {
                    let after = result
                        .get(index)
                        .and_then(Option::as_ref)
                        .map(effect_keys)
                        .unwrap_or_default();
                    let introduced: BTreeSet<String> = after.difference(&before).cloned().collect();
                    if let Some((locked, shadowed)) =
                        shadowed_lock(result[..index].iter().flatten(), &introduced)
                    {
                        return Err(locked_effect_shadowed(
                            context,
                            list,
                            incoming_name,
                            locked,
                            shadowed,
                        ));
                    }
                }
            }
            None => {
                if flag(item, "disabled") {
                    // A `disabled: true` entry with nothing to disable is
                    // still a statement that it must not run. Appending it
                    // and stripping the flag would install exactly what
                    // the author asked to switch off.
                    let record = context.dropped(list, incoming_name);
                    context.drops.push(record);
                    continue;
                }
                // A lock has to bind the entry's effect, not its name.
                // Refusing only a same-name override left the project one
                // rename away from the thing the lock existed to stop:
                // append an entry of the same shape, land after the floor,
                // and win whatever is last-write-wins.
                if context.author == LayerAuthor::Project {
                    // An opaque body is checked first, because when one is
                    // present the effect comparison below is answering a
                    // question it cannot see the input to.
                    if let Some((locked, script)) =
                        opaque_script_over_a_lock(result.iter().flatten(), item, list)
                    {
                        return Err(locked_effect_shadowed(
                            context,
                            list,
                            incoming_name,
                            locked,
                            opaque_script_reason(script),
                        ));
                    }
                    if let Some((locked, shadowed)) =
                        shadowed_lock(result.iter().flatten(), &effect_keys(item))
                    {
                        return Err(locked_effect_shadowed(
                            context,
                            list,
                            incoming_name,
                            locked,
                            shadowed,
                        ));
                    }
                }
                appended.push(item.clone());
            }
        }
    }
    let mut merged: Vec<Value> = result.into_iter().flatten().collect();
    merged.extend(appended);
    Ok(merged)
}

/// The refusal a project layer gets for reaching a locked entry.
///
/// One constructor rather than three copies: the addition arm, the
/// override arm and the opaque-script check all raise the same error,
/// and three literals is three places for the boxed struct's fields to
/// drift apart.
fn locked_effect_shadowed(
    context: &LayerContext<'_>,
    list: &str,
    incoming_name: Option<&str>,
    locked: String,
    shadowed: String,
) -> OriginResolveError {
    OriginResolveError::LockedEffectShadowed(Box::new(LockedEffectShadow {
        entry: context.entry.name.clone(),
        profile: context.profile.to_string(),
        list: list.to_string(),
        locked,
        addition: incoming_name.unwrap_or("(unnamed)").to_string(),
        shadowed,
    }))
}

/// How an opaque script body is described in a refusal.
fn opaque_script_reason(script: &str) -> String {
    format!("an opaque `{script}` body, which the effect comparison cannot read")
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

/// The first locked entry in `existing` whose effect `addition` would
/// shadow, with the effect they share.
///
/// Returns `(locked entry name, shared effect key)`.
fn shadowed_lock<'a, I>(existing: I, incoming: &BTreeSet<String>) -> Option<(String, String)>
where
    I: IntoIterator<Item = &'a Value>,
{
    if incoming.is_empty() {
        return None;
    }
    for candidate in existing {
        if !flag(candidate, "locked") {
            continue;
        }
        let locked = effect_keys(candidate);
        if let Some(shared) = incoming.intersection(&locked).next() {
            return Some((
                entry_name(candidate).unwrap_or("(unnamed)").to_string(),
                shared.clone(),
            ));
        }
    }
    None
}

/// The first locked entry in `existing`, and the script key that makes
/// `incoming` unreadable to [`effect_keys`], when both are present.
///
/// Asked from **both** project arms of the merge, against the incoming
/// layer's own entry rather than the merged result. An addition carrying
/// a script is the obvious route; an override is the same route with a
/// rename saved, because `merge_plain` will insert `lua_script` into an
/// unlocked floor entry that already sits after the lock and the
/// declarative comparison sees `{lua_script}` intersecting nothing
/// (WOR-2432 verification R1). Against `incoming` and not the merged
/// value so a floor entry that already carried a script of its own is
/// not retroactively refused by the project layer that edits some other
/// field of it.
///
/// Only the two modifier lists are asked. A `policies:` or `transforms:`
/// entry running a script is discriminated by its own `type:`, which the
/// effect comparison already reads. See [`MODIFIER_SCRIPT_KEYS`].
fn opaque_script_over_a_lock<'a, I>(
    existing: I,
    incoming: &Value,
    list: &str,
) -> Option<(String, &'static str)>
where
    I: IntoIterator<Item = &'a Value>,
{
    if !matches!(list, "request_modifiers" | "response_modifiers") {
        return None;
    }
    let map = incoming.as_mapping()?;
    let script = MODIFIER_SCRIPT_KEYS
        .iter()
        .find(|key| map.contains_key(**key))
        .copied()?;
    let locked = existing
        .into_iter()
        .find(|candidate| flag(candidate, "locked"))?;
    Some((
        entry_name(locked).unwrap_or("(unnamed)").to_string(),
        script,
    ))
}

/// What an entry in one of the four merged lists actually does, reduced
/// to a comparable set.
///
/// Two shapes, because the four lists have two shapes.
///
/// A `policies:` or `transforms:` entry is discriminated by `type:`, and
/// two entries of the same type are two configurations of one mechanism.
/// For a last-write-wins mechanism the later one wins outright; for an
/// additive one (a second WAF runs as well as the first) it does not.
/// This does not try to tell those apart, and refuses on the type alone.
/// That is deliberately wider than the hazard: a project that needs a
/// second policy of a locked type asks the platform to carry it, which
/// is what a lock is for, and the alternative is a per-module table of
/// which mechanisms compose, which nothing else in the tree maintains
/// and which would be wrong the first time a module changed.
///
/// A `request_modifiers:` or `response_modifiers:` entry has no `type:`.
/// What it does is the set of leaf paths it writes, so
/// `headers.set.content-security-policy` is the effect, and a second
/// entry writing the same path shadows the first whatever it is called.
/// Paths are lowercased because a header name is case-insensitive and a
/// comparison that was not would be a boundary its own header could walk
/// through.
///
/// # What this cannot see
///
/// A script body. `lua_script`, `js_script`, `rego_module` and
/// `rego_module_path` on a modifier all return `set_headers`, and what
/// they set is inside a string this function does not read, so an entry
/// carrying one reduces to the key name and intersects nothing. That is
/// not closed here, because reading it would mean interpreting three
/// languages; it is closed one level up, by
/// [`opaque_addition_over_a_lock`] refusing such an addition into a list
/// that holds a lock at all. The same limit applies to any future
/// modifier field whose value is a program rather than a declaration,
/// which is why the list it is closed against is a named const
/// ([`MODIFIER_SCRIPT_KEYS`]) rather than four literals here.
fn effect_keys(entry: &Value) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    let Some(map) = entry.as_mapping() else {
        return keys;
    };
    if let Some(kind) = map.get("type").and_then(Value::as_str) {
        keys.insert(format!("type={}", kind.trim().to_ascii_lowercase()));
        return keys;
    }
    collect_leaf_paths(entry, "", &mut keys);
    keys
}

/// Every dotted leaf path in `value`, lowercased, skipping bookkeeping.
fn collect_leaf_paths(value: &Value, path: &str, out: &mut BTreeSet<String>) {
    match value {
        Value::Mapping(map) => {
            for (key, child) in map {
                let name = key.as_str().unwrap_or("?");
                if path.is_empty() && BOOKKEEPING_KEYS.contains(&name) {
                    continue;
                }
                let child_path = if path.is_empty() {
                    name.to_ascii_lowercase()
                } else {
                    format!("{path}.{}", name.to_ascii_lowercase())
                };
                collect_leaf_paths(child, &child_path, out);
            }
        }
        // A sequence is a leaf for this purpose. Two entries writing the
        // same list-valued key overwrite each other whatever is in the
        // list, and comparing element by element would let a one-element
        // difference slip a shadow past.
        Value::Sequence(_) | Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            if !path.is_empty() {
                out.insert(path.to_string());
            }
        }
        Value::Tagged(_) => {}
    }
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

    /// The ratchet. `RawOriginConfig` has 53 fields today and gains more
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

        // Pinned exactly, not as a floor. Four prose surfaces state
        // this number (this module's header, this test's own doc,
        // `docs/origin-profiles.md` and `docs/configuration.md`), and a
        // `>=` assertion let all four drift to 52 while the struct held
        // 53. An exact count makes adding a field a deliberate edit
        // here, which is the moment to update them.
        assert_eq!(
            origin_fields.len(),
            53,
            "RawOriginConfig has {} fields; update the count in this test's doc comment, this \
             module's header, docs/origin-profiles.md and docs/configuration.md",
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

        // `validate_origin_body` needs the writable set as data rather
        // than as a type, so it is spelled twice. This is what stops the
        // two spellings drifting: a field added to `OriginProfileSpec`
        // and not to the const would make `origin_defaults` refuse a key
        // a project may set.
        let spelled: BTreeSet<String> = PROFILE_WRITABLE_ORIGIN_FIELDS
            .iter()
            .map(|field| (*field).to_string())
            .collect();
        assert_eq!(
            spelled, profile_fields,
            "`PROFILE_WRITABLE_ORIGIN_FIELDS` must be exactly `OriginProfileSpec`'s fields"
        );
        for (field, reason) in PLATFORM_OWNED_ORIGIN_FIELDS {
            assert!(
                origin_fields.contains(*field),
                "`{field}` is classified platform-owned but is no longer a field of \
                 `RawOriginConfig`; delete the entry rather than leaving a stale reason"
            );
            assert!(!reason.is_empty(), "`{field}` has no written reason");
        }
    }

    /// `MODIFIER_SCRIPT_KEYS` is a hand-written list, so the only
    /// question that matters about it is what it is missing.
    ///
    /// It is exactly right today. Nothing made it stay right: a fifth
    /// program-shaped field on either modifier struct would be a hole in
    /// the lock rule that no test noticed, which is the drift this
    /// branch closes everywhere else by deriving both sides of a
    /// classification from `schema_for!`. The const's own doc names the
    /// future field as the reason it is a const rather than four
    /// literals; this is the other half of that (WOR-2432 verification
    /// R3).
    ///
    /// # What this cannot see
    ///
    /// A program-shaped field whose **name** carries none of the markers
    /// below. The markers are the honest half of the guard and they are
    /// listed rather than implied, exactly like the path-marker sweep in
    /// `crate::confined_template`: a field called `handler` or `rule`
    /// would pass this and still be opaque to `effect_keys`. Two signals
    /// are not available here the way they are for the schema sweep,
    /// because neither modifier struct's fields carry a description this
    /// test can read.
    #[test]
    fn every_program_shaped_modifier_field_is_a_modifier_script_key() {
        const PROGRAM_MARKERS: &[&str] = &["script", "module", "wasm", "program", "bytecode"];
        let declared: BTreeSet<String> = MODIFIER_SCRIPT_KEYS
            .iter()
            .map(|key| (*key).to_string())
            .collect();

        let mut fields: BTreeSet<String> = BTreeSet::new();
        fields.extend(schema_properties::<crate::types::RequestModifierConfig>());
        fields.extend(schema_properties::<crate::types::ResponseModifierConfig>());
        assert!(
            fields.len() >= 9,
            "the sweep found only {} modifier fields, which means it broke rather than that \
             the structs shrank",
            fields.len()
        );

        let program_shaped: BTreeSet<String> = fields
            .iter()
            .filter(|field| {
                let lowered = field.to_ascii_lowercase();
                PROGRAM_MARKERS
                    .iter()
                    .any(|marker| lowered.contains(marker))
            })
            .cloned()
            .collect();
        assert_eq!(
            program_shaped, declared,
            "`MODIFIER_SCRIPT_KEYS` must be exactly the program-shaped fields of the two \
             modifier structs. A field on one side and not the other is either a hole in the \
             lock rule (a body `effect_keys` cannot read and nothing refuses) or a stale \
             entry naming a field that no longer exists"
        );

        for key in MODIFIER_SCRIPT_KEYS {
            assert!(
                fields.contains(*key),
                "`{key}` is on the list but is not a field of either modifier struct"
            );
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

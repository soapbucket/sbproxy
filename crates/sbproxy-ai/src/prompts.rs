//! Versioned prompt store (WOR-800).
//!
//! A per-origin, config-declared store of named prompts. Each prompt has
//! one or more numbered versions; a request references one by
//! `"name@version"` (or bare `"name"` for the pinned default version) and
//! the gateway renders it server-side with the request variables before
//! the messages reach the provider.
//!
//! Templates are [minijinja] and may reference two scopes: `request.*`
//! (request-derived fields the dispatcher supplies) and `variables.*`
//! (static values declared on the prompt version). Reusable fragments
//! declared under `partials:` are registered as named templates so a
//! prompt can `{% include "fragment" %}` them. Rendering uses strict
//! undefined behaviour, so a template that references a variable the
//! caller did not supply fails with a clear error rather than silently
//! emitting an empty string.

use std::collections::HashMap;

use serde::Deserialize;

/// Per-origin prompt store: named, versioned prompts plus reusable
/// template fragments.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PromptStore {
    /// Named prompts, keyed by prompt name.
    #[serde(default)]
    pub templates: HashMap<String, NamedPrompt>,
    /// Reusable template fragments, keyed by the name a prompt
    /// `{% include "..." %}`s. Empty when no fragments are declared.
    #[serde(default)]
    pub partials: HashMap<String, String>,
}

/// One named prompt with its versions.
#[derive(Debug, Clone, Deserialize)]
pub struct NamedPrompt {
    /// Version served when a reference omits `@version`. When unset, the
    /// highest numeric version present is used.
    #[serde(default)]
    pub default_version: Option<String>,
    /// Versions keyed by version label (typically a number as a string).
    pub versions: HashMap<String, PromptVersion>,
}

/// One immutable version of a prompt.
#[derive(Debug, Clone, Deserialize)]
pub struct PromptVersion {
    /// The minijinja template source.
    pub template: String,
    /// Static variables exposed to the template under `variables.*`.
    #[serde(default)]
    pub variables: serde_json::Map<String, serde_json::Value>,
}

/// The outcome of rendering a referenced prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedPrompt {
    /// The rendered prompt text.
    pub text: String,
    /// Resolved prompt name (for run metadata).
    pub name: String,
    /// Resolved version label (for run metadata).
    pub version: String,
}

/// Why a prompt reference failed to render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptError {
    /// No prompt with this name is configured.
    UnknownPrompt(String),
    /// The prompt exists but the requested (or resolved) version does not.
    UnknownVersion {
        /// Prompt name.
        name: String,
        /// The version label that could not be found.
        version: String,
    },
    /// The prompt has no versions and no resolvable default.
    NoVersion(String),
    /// The template failed to render (missing variable, bad partial, ...).
    Render(String),
}

impl std::fmt::Display for PromptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PromptError::UnknownPrompt(n) => write!(f, "unknown prompt '{n}'"),
            PromptError::UnknownVersion { name, version } => {
                write!(f, "unknown version '{version}' for prompt '{name}'")
            }
            PromptError::NoVersion(n) => write!(f, "prompt '{n}' has no resolvable version"),
            PromptError::Render(e) => write!(f, "prompt render failed: {e}"),
        }
    }
}

impl std::error::Error for PromptError {}

impl PromptStore {
    /// Resolve and render a `"name"` / `"name@version"` reference against
    /// the supplied request context. The rendered context exposes
    /// `request.*` (from `request_ctx`) and `variables.*` (from the
    /// resolved version's `variables`).
    pub fn render(
        &self,
        reference: &str,
        request_ctx: &serde_json::Value,
    ) -> Result<RenderedPrompt, PromptError> {
        let (name, requested_version) = match reference.split_once('@') {
            Some((n, v)) => (n.trim(), Some(v.trim().to_string())),
            None => (reference.trim(), None),
        };

        let prompt = self
            .templates
            .get(name)
            .ok_or_else(|| PromptError::UnknownPrompt(name.to_string()))?;

        let version = match requested_version {
            Some(v) => v,
            None => prompt
                .default_version
                .clone()
                .or_else(|| highest_numeric_version(&prompt.versions))
                .ok_or_else(|| PromptError::NoVersion(name.to_string()))?,
        };

        let pv = prompt
            .versions
            .get(&version)
            .ok_or_else(|| PromptError::UnknownVersion {
                name: name.to_string(),
                version: version.clone(),
            })?;

        let mut env = minijinja::Environment::new();
        // A reference to a variable the caller did not supply is an error,
        // not a silently-empty string.
        env.set_undefined_behavior(minijinja::UndefinedBehavior::Strict);
        for (pname, psrc) in &self.partials {
            env.add_template_owned(pname.clone(), psrc.clone())
                .map_err(|e| PromptError::Render(e.to_string()))?;
        }

        let ctx = serde_json::json!({
            "request": request_ctx,
            "variables": serde_json::Value::Object(pv.variables.clone()),
        });

        let text = env
            .render_str(&pv.template, ctx)
            .map_err(|e| PromptError::Render(e.to_string()))?;

        Ok(RenderedPrompt {
            text,
            name: name.to_string(),
            version,
        })
    }
}

/// The highest version label that parses as a number, as a string.
fn highest_numeric_version(versions: &HashMap<String, PromptVersion>) -> Option<String> {
    versions
        .keys()
        .filter_map(|k| k.parse::<u64>().ok().map(|n| (n, k)))
        .max_by_key(|(n, _)| *n)
        .map(|(_, k)| k.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> PromptStore {
        serde_json::from_value(serde_json::json!({
            "partials": { "tone": "Be concise." },
            "templates": {
                "greeting": {
                    "default_version": "2",
                    "versions": {
                        "1": { "template": "Hello {{ request.user }}." },
                        "2": {
                            "template": "Hello {{ request.user }}. {% include \"tone\" %} {{ variables.suffix }}",
                            "variables": { "suffix": "Thanks!" }
                        }
                    }
                }
            }
        }))
        .unwrap()
    }

    fn req(user: &str) -> serde_json::Value {
        serde_json::json!({ "user": user })
    }

    #[test]
    fn renders_explicit_version() {
        let r = store().render("greeting@1", &req("Ada")).unwrap();
        assert_eq!(r.text, "Hello Ada.");
        assert_eq!(r.name, "greeting");
        assert_eq!(r.version, "1");
    }

    #[test]
    fn bare_reference_uses_default_version_and_partials_and_variables() {
        let r = store().render("greeting", &req("Ada")).unwrap();
        assert_eq!(r.text, "Hello Ada. Be concise. Thanks!");
        assert_eq!(r.version, "2");
    }

    #[test]
    fn default_version_falls_back_to_highest_numeric() {
        let s: PromptStore = serde_json::from_value(serde_json::json!({
            "templates": {
                "p": { "versions": {
                    "1": { "template": "one" },
                    "3": { "template": "three" },
                    "2": { "template": "two" }
                }}
            }
        }))
        .unwrap();
        assert_eq!(s.render("p", &req("x")).unwrap().version, "3");
    }

    #[test]
    fn unknown_prompt_and_version_error_clearly() {
        let s = store();
        assert_eq!(
            s.render("missing", &req("x")),
            Err(PromptError::UnknownPrompt("missing".to_string()))
        );
        assert_eq!(
            s.render("greeting@9", &req("x")),
            Err(PromptError::UnknownVersion {
                name: "greeting".to_string(),
                version: "9".to_string()
            })
        );
    }

    #[test]
    fn missing_variable_is_an_error_not_empty() {
        // `greeting@1` references `request.user`; omit it.
        let err = store()
            .render("greeting@1", &serde_json::json!({}))
            .unwrap_err();
        assert!(matches!(err, PromptError::Render(_)), "got {err:?}");
    }
}

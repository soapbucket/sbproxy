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
use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwap;
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

// --- WOR-800 PR2: runtime prompt overlay ---
//
// The config-declared `PromptStore` is immutable once compiled. Per
// the WOR-800 acceptance criteria, the operator must also be able to
// add / pin a prompt at runtime (admin API, hot-reload from a
// separate prompt source) without a full config reload.
//
// This module adds a process-global, per-origin runtime overlay. The
// dispatcher's prompt lookup consults the runtime overlay for the
// hostname first; only on a miss does it fall through to the
// config-declared store. Mutations swap a new `Arc<RuntimeOverlay>`
// in via `ArcSwap`, so hot replacement is atomic (an in-flight
// request that already snapshotted the old overlay finishes against
// it; the next request sees the new one).
//
// PR2 ships the overlay + the library API (`install_runtime_prompts`,
// `add_runtime_prompt_version`, `pin_runtime_prompt`,
// `resolve`). PR3 wires the HTTP admin endpoints; PR4 adds the
// redb-backed persistence layer.

/// Per-hostname runtime prompt overlay. Each entry shadows or extends
/// the config-declared store on that origin.
#[derive(Debug, Default, Clone)]
pub struct RuntimePromptOverlay {
    /// Hostname → store. A hostname with no entry falls through to
    /// the config-declared store. A hostname with an entry shadows
    /// only the prompt names defined inside that entry; any prompt
    /// name absent from the entry still falls through to config.
    pub by_host: HashMap<String, PromptStore>,
}

impl RuntimePromptOverlay {
    /// Resolve a prompt reference against the overlay for `host`.
    /// Returns `Some(Ok)` on a hit, `Some(Err)` when the overlay
    /// matched the prompt name but rendering failed (so the caller
    /// surfaces the error to the client rather than silently
    /// falling through to config), and `None` when the overlay has
    /// nothing for that hostname + prompt name combo. The caller
    /// then consults the config-declared store.
    pub fn resolve(
        &self,
        host: &str,
        reference: &str,
        request_ctx: &serde_json::Value,
    ) -> Option<Result<RenderedPrompt, PromptError>> {
        let store = self.by_host.get(host)?;
        let name = reference
            .split_once('@')
            .map(|(n, _)| n)
            .unwrap_or(reference);
        // Only short-circuit when the runtime store has a template
        // for this name; otherwise pass through to config.
        if !store.templates.contains_key(name.trim()) {
            return None;
        }
        Some(store.render(reference, request_ctx))
    }
}

/// Process-global runtime overlay. Reads load the current overlay
/// atomically via `ArcSwap::load`; mutations swap a freshly-built
/// overlay in.
fn overlay_handle() -> &'static ArcSwap<RuntimePromptOverlay> {
    static H: OnceLock<ArcSwap<RuntimePromptOverlay>> = OnceLock::new();
    H.get_or_init(|| ArcSwap::from_pointee(RuntimePromptOverlay::default()))
}

/// Load the current runtime overlay snapshot. Cheap; a single atomic
/// load + an `Arc` clone.
pub fn current_runtime_overlay() -> Arc<RuntimePromptOverlay> {
    overlay_handle().load_full()
}

/// Replace the entire runtime overlay. Useful for bulk reload from a
/// separate prompt source (a future redb scan; a future SIGHUP hook
/// that re-reads a sidecar prompt directory). Atomic; in-flight
/// requests that already snapshotted the old overlay finish against
/// it.
pub fn install_runtime_overlay(overlay: RuntimePromptOverlay) {
    overlay_handle().store(Arc::new(overlay));
}

/// Add (or replace) one version of a runtime prompt on `host`. If
/// the prompt has no existing entry, one is created. If a version
/// with the same label already exists it is overwritten (operators
/// who want immutable versions can refuse re-use at the admin layer
/// in PR3). Returns the prompt's `default_version` after the
/// mutation: either the existing default, or the highest numeric
/// version found in the updated set.
pub fn add_runtime_prompt_version(
    host: &str,
    name: &str,
    version: &str,
    template: String,
    variables: serde_json::Map<String, serde_json::Value>,
) -> Option<String> {
    let handle = overlay_handle();
    let cur = handle.load();
    let mut next = (**cur).clone();
    let store = next.by_host.entry(host.to_string()).or_default();
    let prompt = store
        .templates
        .entry(name.to_string())
        .or_insert_with(|| NamedPrompt {
            default_version: None,
            versions: HashMap::new(),
        });
    prompt.versions.insert(
        version.to_string(),
        PromptVersion {
            template,
            variables,
        },
    );
    let effective_default = prompt
        .default_version
        .clone()
        .or_else(|| highest_numeric_version(&prompt.versions));
    handle.store(Arc::new(next));
    effective_default
}

/// Pin a prompt's default version (the version served when a
/// reference omits `@version`). Returns `Ok(())` on success or an
/// error string when the prompt or version is unknown.
pub fn pin_runtime_prompt(host: &str, name: &str, version: &str) -> Result<(), String> {
    let handle = overlay_handle();
    let cur = handle.load();
    let mut next = (**cur).clone();
    let store = next
        .by_host
        .get_mut(host)
        .ok_or_else(|| format!("no runtime prompts on host '{host}'"))?;
    let prompt = store
        .templates
        .get_mut(name)
        .ok_or_else(|| format!("no runtime prompt named '{name}' on host '{host}'"))?;
    if !prompt.versions.contains_key(version) {
        return Err(format!(
            "version '{version}' not present on runtime prompt '{name}'"
        ));
    }
    prompt.default_version = Some(version.to_string());
    handle.store(Arc::new(next));
    Ok(())
}

#[cfg(test)]
fn reset_runtime_overlay_for_tests() {
    overlay_handle().store(Arc::new(RuntimePromptOverlay::default()));
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

    // --- WOR-800 PR2: runtime overlay ---
    //
    // The overlay-mutation tests use a single dedicated `serial!`-
    // style mutex because the runtime overlay is a process-global
    // singleton; running these tests in parallel against the same
    // global would have them clobber each other. We pin them serially
    // with a `Mutex` rather than a feature gate so they keep running
    // in the default `cargo test` invocation.
    static RUNTIME_OVERLAY_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn runtime_add_then_resolve_matches_request() {
        let _guard = RUNTIME_OVERLAY_MUTEX.lock().unwrap();
        reset_runtime_overlay_for_tests();
        add_runtime_prompt_version(
            "host-a.example.com",
            "summarize",
            "1",
            "Hello {{ request.user }}!".to_string(),
            serde_json::Map::new(),
        );
        let overlay = current_runtime_overlay();
        let req = serde_json::json!({"user": "Ada"});
        let rendered = overlay
            .resolve("host-a.example.com", "summarize", &req)
            .expect("hit")
            .expect("render");
        assert_eq!(rendered.text, "Hello Ada!");
        assert_eq!(rendered.name, "summarize");
        assert_eq!(rendered.version, "1");
    }

    #[test]
    fn runtime_overlay_misses_on_unknown_host() {
        let _guard = RUNTIME_OVERLAY_MUTEX.lock().unwrap();
        reset_runtime_overlay_for_tests();
        add_runtime_prompt_version(
            "host-a.example.com",
            "summarize",
            "1",
            "x".to_string(),
            serde_json::Map::new(),
        );
        let overlay = current_runtime_overlay();
        assert!(overlay
            .resolve("host-b.example.com", "summarize", &serde_json::json!({}))
            .is_none());
    }

    #[test]
    fn runtime_overlay_misses_on_unknown_prompt_name() {
        // Hostname has an entry but the requested prompt name is
        // absent → the dispatcher must fall through to the config
        // store rather than seeing this as an UnknownPrompt error
        // from the overlay.
        let _guard = RUNTIME_OVERLAY_MUTEX.lock().unwrap();
        reset_runtime_overlay_for_tests();
        add_runtime_prompt_version(
            "host-a.example.com",
            "summarize",
            "1",
            "x".to_string(),
            serde_json::Map::new(),
        );
        let overlay = current_runtime_overlay();
        assert!(overlay
            .resolve("host-a.example.com", "other-name", &serde_json::json!({}))
            .is_none());
    }

    #[test]
    fn runtime_overlay_picks_highest_numeric_default() {
        let _guard = RUNTIME_OVERLAY_MUTEX.lock().unwrap();
        reset_runtime_overlay_for_tests();
        add_runtime_prompt_version(
            "host-a.example.com",
            "summarize",
            "1",
            "v1".to_string(),
            serde_json::Map::new(),
        );
        let effective_default = add_runtime_prompt_version(
            "host-a.example.com",
            "summarize",
            "3",
            "v3".to_string(),
            serde_json::Map::new(),
        );
        assert_eq!(effective_default.as_deref(), Some("3"));
        let overlay = current_runtime_overlay();
        let rendered = overlay
            .resolve("host-a.example.com", "summarize", &serde_json::json!({}))
            .expect("hit")
            .expect("render");
        assert_eq!(rendered.version, "3");
    }

    #[test]
    fn pin_runtime_prompt_overrides_default() {
        let _guard = RUNTIME_OVERLAY_MUTEX.lock().unwrap();
        reset_runtime_overlay_for_tests();
        add_runtime_prompt_version(
            "host-a.example.com",
            "summarize",
            "1",
            "v1".to_string(),
            serde_json::Map::new(),
        );
        add_runtime_prompt_version(
            "host-a.example.com",
            "summarize",
            "3",
            "v3".to_string(),
            serde_json::Map::new(),
        );
        // Pin to v1 even though v3 is the highest numeric.
        pin_runtime_prompt("host-a.example.com", "summarize", "1").unwrap();
        let overlay = current_runtime_overlay();
        let rendered = overlay
            .resolve("host-a.example.com", "summarize", &serde_json::json!({}))
            .expect("hit")
            .expect("render");
        assert_eq!(rendered.version, "1");
    }

    #[test]
    fn pin_runtime_prompt_errors_on_unknown_version() {
        let _guard = RUNTIME_OVERLAY_MUTEX.lock().unwrap();
        reset_runtime_overlay_for_tests();
        add_runtime_prompt_version(
            "host-a.example.com",
            "summarize",
            "1",
            "v1".to_string(),
            serde_json::Map::new(),
        );
        let err = pin_runtime_prompt("host-a.example.com", "summarize", "99").unwrap_err();
        assert!(err.contains("99"));
    }

    #[test]
    fn explicit_version_reference_wins_over_default() {
        // `prompt: name@version` MUST honour the requested version
        // even if a different version is pinned as default.
        let _guard = RUNTIME_OVERLAY_MUTEX.lock().unwrap();
        reset_runtime_overlay_for_tests();
        add_runtime_prompt_version(
            "host-a.example.com",
            "summarize",
            "1",
            "v1".to_string(),
            serde_json::Map::new(),
        );
        add_runtime_prompt_version(
            "host-a.example.com",
            "summarize",
            "2",
            "v2".to_string(),
            serde_json::Map::new(),
        );
        pin_runtime_prompt("host-a.example.com", "summarize", "2").unwrap();
        let overlay = current_runtime_overlay();
        let rendered = overlay
            .resolve("host-a.example.com", "summarize@1", &serde_json::json!({}))
            .expect("hit")
            .expect("render");
        assert_eq!(rendered.text, "v1");
        assert_eq!(rendered.version, "1");
    }
}

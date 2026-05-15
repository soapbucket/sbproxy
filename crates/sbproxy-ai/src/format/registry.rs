//! Format registry keyed by inbound HTTP path.
//!
//! The registry is the lookup table the request handler uses to pick a
//! `ChatFormat` for an inbound path. It is built once at startup and
//! held in an `Arc` so per-request lookups are read-only.
//!
//! Registration is opt-in per the ADR: turning on `/v1/messages` for
//! every operator who upgrades would hijack any deployment that
//! already proxies `/v1/messages` to a real Anthropic upstream. The
//! request handler asks the registry whether a path is claimed; an
//! unregistered path falls through to the existing pass-through code
//! path.

use std::collections::HashMap;
use std::sync::Arc;

use super::ChatFormat;

/// Map of inbound HTTP path to the format that claims it.
#[derive(Default, Clone)]
pub struct FormatRegistry {
    inner: HashMap<&'static str, Arc<dyn ChatFormat>>,
}

impl FormatRegistry {
    /// Build an empty registry. Call `register` to add formats.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a format under every path it claims. The first format
    /// to claim a path wins; subsequent registrations for the same
    /// path are ignored and the existing one is returned via the lookup.
    pub fn register<F: ChatFormat>(&mut self, fmt: F) {
        let arc: Arc<dyn ChatFormat> = Arc::new(fmt);
        for path in arc.inbound_paths() {
            self.inner.entry(*path).or_insert_with(|| arc.clone());
        }
    }

    /// Return the format that claims this path, if any.
    pub fn for_path(&self, path: &str) -> Option<Arc<dyn ChatFormat>> {
        // Strip query string before matching.
        let base = path.split('?').next().unwrap_or(path);
        self.inner.get(base).cloned()
    }

    /// Whether the path is claimed by any registered format.
    pub fn claims(&self, path: &str) -> bool {
        self.for_path(path).is_some()
    }
}

impl std::fmt::Debug for FormatRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let paths: Vec<&&str> = self.inner.keys().collect();
        f.debug_struct("FormatRegistry")
            .field("paths", &paths)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::super::{AnthropicMessagesFormat, OpenAiChatFormat, OpenAiResponsesFormat};
    use super::*;

    #[test]
    fn registry_claims_three_default_paths() {
        let mut r = FormatRegistry::new();
        r.register(OpenAiChatFormat);
        r.register(AnthropicMessagesFormat);
        r.register(OpenAiResponsesFormat);

        assert!(r.claims("/v1/chat/completions"));
        assert!(r.claims("/v1/messages"));
        assert!(r.claims("/v1/responses"));
        assert!(!r.claims("/v1/embeddings"));
    }

    #[test]
    fn registry_strips_query_string_on_lookup() {
        let mut r = FormatRegistry::new();
        r.register(OpenAiChatFormat);
        assert!(r.claims("/v1/chat/completions?stream=true"));
    }
}

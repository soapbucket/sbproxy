// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! LoRA adapter routing + cache (WOR-1673).
//!
//! Serving many fine-tunes over one resident base model means keeping
//! a bounded set of adapters loaded and evicting the least-recently
//! used when a new one is requested, rather than swapping the whole
//! base model per adapter. This is the pure policy layer: it decides
//! which adapter a request maps to and which adapter to evict from the
//! engine's adapter slots. The actual runtime load/unload (vLLM's
//! `/v1/load_lora_adapter`) plugs in above it.

use std::collections::HashMap;

use crate::config::LoraAdapter;

/// The outcome of routing a request to an adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterRoute {
    /// The requested name is the base model, not an adapter.
    Base,
    /// Serve this adapter; it was already loaded (LRU refreshed).
    Resident {
        /// Adapter source (repo/path) to serve.
        source: String,
    },
    /// Serve this adapter; load it first, evicting `evict` if set.
    Load {
        /// Adapter source to load.
        source: String,
        /// Adapter name to evict to make room, if any.
        evict: Option<String>,
    },
    /// The requested name is neither the base nor a configured adapter.
    Unknown,
}

/// An LRU cache of loaded LoRA adapters over one base model. Capacity
/// is the engine's `max_loras` (how many adapters can be resident at
/// once).
#[derive(Debug, Clone)]
pub struct LoraCache {
    base_model: String,
    capacity: usize,
    /// Configured adapters: name -> source.
    configured: HashMap<String, String>,
    /// Currently-loaded adapter names, oldest first (LRU front).
    loaded: Vec<String>,
    tick: u64,
}

impl LoraCache {
    /// Build a cache for `base_model` with the configured adapters and
    /// an engine adapter-slot `capacity` (at least 1).
    pub fn new(base_model: impl Into<String>, adapters: &[LoraAdapter], capacity: usize) -> Self {
        Self {
            base_model: base_model.into(),
            capacity: capacity.max(1),
            configured: adapters
                .iter()
                .map(|a| (a.name.clone(), a.source.clone()))
                .collect(),
            loaded: Vec::new(),
            tick: 0,
        }
    }

    /// Currently-loaded adapter names (LRU order, oldest first).
    pub fn loaded(&self) -> &[String] {
        &self.loaded
    }

    /// Route a request for `model` and update the cache. Returns
    /// whether it is the base, a resident adapter, an adapter to load
    /// (with any eviction), or unknown. `Load`/`Resident` mutate the
    /// LRU as if the adapter is now in use.
    pub fn route(&mut self, model: &str) -> AdapterRoute {
        if model == self.base_model {
            return AdapterRoute::Base;
        }
        let Some(source) = self.configured.get(model).cloned() else {
            return AdapterRoute::Unknown;
        };
        self.tick += 1;
        if let Some(pos) = self.loaded.iter().position(|n| n == model) {
            // Already resident: move to most-recent.
            self.loaded.remove(pos);
            self.loaded.push(model.to_string());
            return AdapterRoute::Resident { source };
        }
        // Needs loading; evict LRU if at capacity.
        let evict = if self.loaded.len() >= self.capacity {
            Some(self.loaded.remove(0))
        } else {
            None
        };
        self.loaded.push(model.to_string());
        AdapterRoute::Load { source, evict }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapters() -> Vec<LoraAdapter> {
        vec![
            LoraAdapter {
                name: "a".into(),
                source: "hf:org/a".into(),
            },
            LoraAdapter {
                name: "b".into(),
                source: "hf:org/b".into(),
            },
            LoraAdapter {
                name: "c".into(),
                source: "hf:org/c".into(),
            },
        ]
    }

    #[test]
    fn base_and_unknown_route() {
        let mut c = LoraCache::new("qwen3-8b", &adapters(), 2);
        assert_eq!(c.route("qwen3-8b"), AdapterRoute::Base);
        assert_eq!(c.route("nope"), AdapterRoute::Unknown);
    }

    #[test]
    fn first_use_loads_without_eviction() {
        let mut c = LoraCache::new("base", &adapters(), 2);
        assert_eq!(
            c.route("a"),
            AdapterRoute::Load {
                source: "hf:org/a".into(),
                evict: None
            }
        );
    }

    #[test]
    fn second_use_is_resident() {
        let mut c = LoraCache::new("base", &adapters(), 2);
        c.route("a");
        assert_eq!(
            c.route("a"),
            AdapterRoute::Resident {
                source: "hf:org/a".into()
            }
        );
    }

    #[test]
    fn evicts_lru_at_capacity() {
        let mut c = LoraCache::new("base", &adapters(), 2);
        c.route("a"); // load a
        c.route("b"); // load b -> [a, b]
        c.route("a"); // touch a -> [b, a]
                      // c needs a slot; b is LRU.
        assert_eq!(
            c.route("c"),
            AdapterRoute::Load {
                source: "hf:org/c".into(),
                evict: Some("b".into())
            }
        );
        assert_eq!(c.loaded(), &["a".to_string(), "c".to_string()]);
    }

    #[test]
    fn capacity_is_at_least_one() {
        let mut c = LoraCache::new("base", &adapters(), 0);
        c.route("a");
        // Loading b evicts a (capacity clamped to 1).
        assert_eq!(
            c.route("b"),
            AdapterRoute::Load {
                source: "hf:org/b".into(),
                evict: Some("a".into())
            }
        );
    }
}

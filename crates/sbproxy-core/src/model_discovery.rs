// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Topology-free logical model discovery and public route metadata.

use std::collections::{BTreeMap, BTreeSet};

use bytes::Bytes;

/// Current replica counts for one managed deployment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ManagedDeploymentAvailability {
    /// Current-generation replicas ready for immediate work.
    pub ready_replicas: u32,
    /// Current-generation assigned replicas eligible for a coordinated start.
    pub cold_replicas: u32,
    /// Replica count requested by the committed deployment.
    pub desired_replicas: u32,
}

/// Bounded route class safe to expose to an inference client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicRouteClass {
    /// The selected replica is owned by this process.
    Local,
    /// The selected replica was reached over the authenticated model plane.
    Peer,
    /// The selected provider is outside the managed model plane.
    External,
}

impl PublicRouteClass {
    /// Stable response-header value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Peer => "peer",
            Self::External => "external",
        }
    }
}

impl From<sbproxy_ai::managed_replica::ManagedRouteClass> for PublicRouteClass {
    fn from(value: sbproxy_ai::managed_replica::ManagedRouteClass) -> Self {
        match value {
            sbproxy_ai::managed_replica::ManagedRouteClass::Local => Self::Local,
            sbproxy_ai::managed_replica::ManagedRouteClass::Peer => Self::Peer,
        }
    }
}

#[derive(Default)]
struct LogicalModelAggregate {
    ready_replicas: u32,
    cold_replicas: u32,
    desired_replicas: u32,
    capabilities: BTreeSet<&'static str>,
}

/// Build an OpenAI-compatible logical model list without node or endpoint data.
pub fn logical_model_listing(
    config: &sbproxy_ai::handler::AiHandlerConfig,
    allowed_providers: &[String],
    allowed_models: &[String],
    blocked_models: &[String],
    managed: &BTreeMap<String, ManagedDeploymentAvailability>,
) -> serde_json::Value {
    let mut models = BTreeMap::<String, LogicalModelAggregate>::new();

    for provider in config.providers.iter().filter(|provider| {
        provider.enabled
            && (allowed_providers.is_empty()
                || allowed_providers
                    .iter()
                    .any(|allowed| allowed == provider.name.as_str()))
    }) {
        let provider_type = provider
            .provider_type
            .as_deref()
            .unwrap_or_else(|| provider.name.as_str());
        let mut public_models = provider
            .models
            .iter()
            .map(|model| model.as_str())
            .collect::<Vec<_>>();
        if public_models.is_empty() {
            if let Some(default_model) = provider.default_model.as_ref() {
                public_models.push(default_model.as_str());
            }
        }

        for public_model in public_models {
            if !config.is_model_allowed(public_model)
                || blocked_models.iter().any(|blocked| blocked == public_model)
                || (!allowed_models.is_empty()
                    && !allowed_models.iter().any(|allowed| allowed == public_model))
            {
                continue;
            }
            let aggregate = models.entry(public_model.to_string()).or_default();
            if provider.is_managed_model() {
                let availability = provider
                    .deployment
                    .as_deref()
                    .and_then(|deployment| managed.get(deployment))
                    .copied()
                    .unwrap_or_default();
                aggregate.ready_replicas = aggregate
                    .ready_replicas
                    .saturating_add(availability.ready_replicas);
                aggregate.cold_replicas = aggregate
                    .cold_replicas
                    .saturating_add(availability.cold_replicas);
                aggregate.desired_replicas = aggregate
                    .desired_replicas
                    .saturating_add(availability.desired_replicas);
                aggregate.capabilities.insert("chat_completions");
                aggregate.capabilities.insert("streaming");
                continue;
            }

            aggregate.ready_replicas = aggregate.ready_replicas.saturating_add(1);
            aggregate.desired_replicas = aggregate.desired_replicas.saturating_add(1);
            let provider_info = sbproxy_ai::providers::get_provider_info(provider_type);
            if provider_info.as_ref().is_none_or(|info| info.supports_chat) {
                aggregate.capabilities.insert("chat_completions");
            }
            if provider_info
                .as_ref()
                .is_some_and(|info| info.supports_embeddings)
            {
                aggregate.capabilities.insert("embeddings");
            }
            if provider_info
                .as_ref()
                .is_some_and(|info| info.supports_streaming)
            {
                aggregate.capabilities.insert("streaming");
            }
        }
    }

    let data = models
        .into_iter()
        .map(|(id, aggregate)| {
            let state = if aggregate.ready_replicas > 0 {
                "ready"
            } else if aggregate.cold_replicas > 0 {
                "cold"
            } else {
                "unavailable"
            };
            serde_json::json!({
                "id": id,
                "object": "model",
                "owned_by": "sbproxy",
                "availability": {
                    "state": state,
                    "ready_replicas": aggregate.ready_replicas,
                    "desired_replicas": aggregate.desired_replicas,
                },
                "capabilities": aggregate.capabilities,
            })
        })
        .collect::<Vec<_>>();

    serde_json::json!({ "object": "list", "data": data })
}

/// Response headers that expose only logical model and bounded route class.
pub fn safe_route_headers(
    logical_model: &str,
    route_class: PublicRouteClass,
) -> Vec<(String, String)> {
    vec![
        (
            "x-sbproxy-logical-model".to_string(),
            logical_model.to_string(),
        ),
        (
            "x-sbproxy-route-class".to_string(),
            route_class.as_str().to_string(),
        ),
    ]
}

/// Stable OpenAI-style managed-model error payload.
pub fn managed_error_body(request_id: &str, code: &'static str, retryable: bool) -> Bytes {
    Bytes::from(
        serde_json::to_vec(&serde_json::json!({
            "error": {
                "message": "managed model is temporarily unavailable",
                "type": "managed_model_error",
                "code": code,
                "request_id": request_id,
                "retryable": retryable,
                "sbproxy_reason": code,
            }
        }))
        .expect("static managed error payload"),
    )
}

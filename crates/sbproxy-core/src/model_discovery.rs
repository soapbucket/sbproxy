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
    /// Union of the capability names every entry serving this logical
    /// model publishes. `BTreeSet` so the wire order is stable and a
    /// name a second provider repeats appears once.
    capabilities: BTreeSet<&'static str>,
    /// Tightest known token limits across everything serving this name
    /// (WOR-2647). For a plain model id every contributor resolves the
    /// same numbers, so the narrowing is a no-op; it earns its keep on a
    /// `model_groups:` entry, whose members may serve different upstream
    /// model ids with different windows.
    facts: sbproxy_ai::context_window::ModelFacts,
}

impl LogicalModelAggregate {
    /// Count one provider entry's replicas toward this logical model.
    fn absorb_availability(
        &mut self,
        provider: &sbproxy_ai::ProviderConfig,
        managed: &BTreeMap<String, ManagedDeploymentAvailability>,
    ) {
        if provider.is_managed_model() {
            let availability = provider
                .deployment
                .as_deref()
                .and_then(|deployment| managed.get(deployment))
                .copied()
                .unwrap_or_default();
            self.ready_replicas = self
                .ready_replicas
                .saturating_add(availability.ready_replicas);
            self.cold_replicas = self
                .cold_replicas
                .saturating_add(availability.cold_replicas);
            self.desired_replicas = self
                .desired_replicas
                .saturating_add(availability.desired_replicas);
        } else {
            self.ready_replicas = self.ready_replicas.saturating_add(1);
            self.desired_replicas = self.desired_replicas.saturating_add(1);
        }
    }

    /// Narrow the published limits to the tightest a contributor
    /// declares.
    ///
    /// A caller sizing a prompt to a name that fronts several
    /// deployments has to fit whichever one serves the request, so the
    /// floor is the only number that is true for every outcome.
    /// Publishing the maximum would let a caller build a prompt the
    /// smaller member rejects.
    ///
    /// A contributor whose limit is unknown does not lower the floor:
    /// unknown is not zero, and treating it as one would erase a limit
    /// the other members do declare.
    fn absorb_facts(&mut self, facts: sbproxy_ai::context_window::ModelFacts) {
        fn floor(current: Option<u64>, candidate: Option<u64>) -> Option<u64> {
            match (current, candidate) {
                (Some(current), Some(candidate)) => Some(current.min(candidate)),
                (Some(current), None) => Some(current),
                (None, candidate) => candidate,
            }
        }
        self.facts.context_window = floor(self.facts.context_window, facts.context_window);
        self.facts.max_output_tokens = floor(self.facts.max_output_tokens, facts.max_output_tokens);
    }
}

/// Build an OpenAI-compatible logical model list without node or endpoint data.
///
/// Each entry carries an `availability` object (aggregate state and
/// replica counts for managed deployments) and a `capabilities` array.
///
/// The capability array is
/// [`sbproxy_ai::api_routes::surface_capability_names`], which
/// intersects the per-provider surface matrix the dispatch path
/// consults before it answers 501 with the provider catalog's
/// per-vendor claims. A caller reads this listing and then sends the
/// request it says is supported, so anything named here has to be
/// something the gateway will serve and something the vendor is
/// recorded as exposing. The array used to come from the catalog
/// booleans alone, which disagreed with the matrix on 43 of the 72
/// shipped entries in both directions (WOR-2647).
///
/// ## The array is narrower than the 501 gate, in two ways
///
/// It is a union across the entries that declare *this* model, while
/// the 501 gate scans every allowed provider on the origin and has no
/// model parameter. An origin serving `gpt-4o` on an openai entry and
/// `claude-haiku` on an anthropic one lists no `embeddings` for
/// `claude-haiku`, and `POST /v1/embeddings` naming `claude-haiku` is
/// still admitted by the gate, because the openai entry satisfies it.
///
/// It is also narrower per provider, because the matrix answers on the
/// wire format and the catalog claims answer on the vendor.
///
/// Both differences run the same way: the listing is a subset of the
/// gate, never a superset. Anything named is served; something served
/// may go unnamed. Absence is not a refusal.
///
/// The names are surfaces rather than upstream model features: the array
/// says the gateway will forward `POST /v1/embeddings` for this model,
/// and says nothing about whether the upstream answers 200.
/// Provider-specific model metadata is still deliberately absent, and no
/// provider's native model-list endpoint is called. See
/// `docs/ai-gateway.md`.
pub fn logical_model_listing(
    config: &sbproxy_ai::handler::AiHandlerConfig,
    allowed_providers: &[String],
    allowed_models: &[String],
    blocked_models: &[String],
    managed: &BTreeMap<String, ManagedDeploymentAvailability>,
) -> serde_json::Value {
    let mut models = BTreeMap::<String, LogicalModelAggregate>::new();

    // Hoisted so the alias and group passes below narrow by the same
    // rule as the provider scan. Two copies of a visibility predicate is
    // how one of them ends up wider than the other.
    let provider_filter = |provider: &sbproxy_ai::ProviderConfig| {
        provider.enabled
            && (allowed_providers.is_empty()
                || allowed_providers
                    .iter()
                    .any(|allowed| allowed == provider.name.as_str()))
    };

    for provider in config
        .providers
        .iter()
        .filter(|provider| provider_filter(provider))
    {
        // WOR-2647: the capability names this entry may advertise are
        // the surface matrix the dispatch path enforces, intersected
        // with the provider catalog's per-vendor claims. Resolved once
        // per provider because it is a property of the entry, not of the
        // individual model names it declares.
        let capabilities = sbproxy_ai::api_routes::surface_capability_names(provider);
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
            if !model_visible(config, public_model, allowed_models, blocked_models) {
                continue;
            }
            let aggregate = models.entry(public_model.to_string()).or_default();
            aggregate.absorb_availability(provider, managed);
            aggregate.absorb_facts(sbproxy_ai::context_window::model_facts(public_model));
            // A logical model can be served by several entries, and a
            // request naming it can land on any of them. Union rather
            // than intersect, matching the 501 gate, which admits a
            // surface when any eligible provider handles it. Each
            // operand is already a subset of that gate, so their union
            // is too. `managed_model_group_capabilities_are_the_union`
            // in `tests/managed_replica_dispatch.rs` is what stops this
            // silently becoming last-wins.
            aggregate.capabilities.extend(capabilities.iter().copied());
        }
    }

    // WOR-2647: a `model_aliases:` entry and a `model_groups:` entry are
    // both names a caller may send as `model`, and neither appears in
    // any provider's `models:` list, so the scan above cannot see
    // either. A client that reads this listing to learn what it may
    // address would otherwise be told about every name except the ones
    // the operator published for it.
    //
    // Both passes gate on the model id the name **resolves to**, never on
    // the name itself, because that is what the dispatch path gates. An
    // alias resolves before every model gate, so a credential whose
    // `allowed_models` names the upstream id admits a request that asked
    // for the alias; filtering the listing on the alias name instead
    // would hide a name that works.
    let visible = |model: &str| model_visible(config, model, allowed_models, blocked_models);
    absorb_alias_entries(config, &mut models, &provider_filter, &visible, managed);
    absorb_group_entries(config, &mut models, &provider_filter, &visible, managed);

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
            let mut entry = serde_json::json!({
                "id": id,
                "object": "model",
                // The OpenAI `Model` object declares `created` required,
                // and an SDK-shaped client refuses to deserialize a list
                // without it. This gateway does not know when a model was
                // published and will not invent a date, so the field is
                // the epoch constant: present for the schema, and not a
                // claim about anything.
                "created": 0,
                "owned_by": "sbproxy",
                "availability": {
                    "state": state,
                    "ready_replicas": aggregate.ready_replicas,
                    "desired_replicas": aggregate.desired_replicas,
                },
                "capabilities": aggregate.capabilities,
            });
            // Omitted rather than null when unknown, the same rule the
            // routing base data applies: a client can tell "the gateway
            // was not told" from "the limit is zero".
            if let Some(object) = entry.as_object_mut() {
                if let Some(window) = aggregate.facts.context_window {
                    object.insert("context_window".to_string(), window.into());
                }
                if let Some(max_output) = aggregate.facts.max_output_tokens {
                    object.insert("max_output_tokens".to_string(), max_output.into());
                }
            }
            entry
        })
        .collect::<Vec<_>>();

    serde_json::json!({ "object": "list", "data": data })
}

/// Whether a model id survives the origin's allow/block lists and the
/// calling credential's own two lists.
fn model_visible(
    config: &sbproxy_ai::handler::AiHandlerConfig,
    model: &str,
    allowed_models: &[String],
    blocked_models: &[String],
) -> bool {
    config.is_model_allowed(model)
        && !blocked_models.iter().any(|blocked| blocked == model)
        && (allowed_models.is_empty() || allowed_models.iter().any(|allowed| allowed == model))
}

/// Add one entry per `model_aliases:` name (WOR-2647).
///
/// The alias is gated on the model id it **resolves to**, not on its own
/// name, which is exactly what the dispatch path gates: the alias
/// resolves before every model gate, so a `blocked_models` entry
/// naming the upstream id blocks the alias too, and one naming the alias
/// is never consulted. Listing the alias when its target is blocked
/// would advertise a name that answers 403.
///
/// Facts and capabilities come from the resolved id and from the
/// providers that can actually serve it: the pinned provider when the
/// alias names one, every provider declaring the id when it does not.
fn absorb_alias_entries(
    config: &sbproxy_ai::handler::AiHandlerConfig,
    models: &mut BTreeMap<String, LogicalModelAggregate>,
    provider_filter: &dyn Fn(&sbproxy_ai::ProviderConfig) -> bool,
    visible: &dyn Fn(&str) -> bool,
    managed: &BTreeMap<String, ManagedDeploymentAvailability>,
) {
    for alias in &config.model_aliases {
        let name = alias.alias.as_str();
        let target = alias.model_id.as_str();
        if !visible(target) {
            continue;
        }
        let mut aggregate = LogicalModelAggregate::default();
        let mut served = false;
        for provider in config.providers.iter().filter(|p| provider_filter(p)) {
            let pinned_elsewhere = alias
                .provider
                .as_ref()
                .is_some_and(|pin| pin.as_str() != provider.name.as_str());
            if pinned_elsewhere {
                continue;
            }
            // An unpinned alias spreads over every provider declaring
            // the target. A provider that enumerates no models defers to
            // its upstream catalog and is a wildcard on the dispatch
            // path, so it counts here too.
            let serves = provider.models.is_empty()
                || provider.models.iter().any(|model| model.as_str() == target);
            if !serves {
                continue;
            }
            served = true;
            aggregate.absorb_availability(provider, managed);
            aggregate
                .capabilities
                .extend(sbproxy_ai::api_routes::surface_capability_names(provider));
        }
        if !served {
            continue;
        }
        aggregate.absorb_facts(sbproxy_ai::context_window::model_facts(target));
        models.insert(name.to_string(), aggregate);
    }
}

/// Add one entry per `model_groups:` name (WOR-2657, WOR-2647).
///
/// A group's members may serve different upstream model ids, so the
/// entry answers the three questions a client asks in the three ways
/// that are true for every member it could land on: capabilities are the
/// **union**, matching the 501 gate, which admits a surface when any
/// eligible provider handles it; the token limits are the **floor**,
/// because a prompt has to fit whichever member serves it; and
/// availability is the sum, as it is for a model several providers
/// declare.
///
/// A member whose model the gates refuse contributes nothing, and a
/// group with no surviving member is left off entirely.
fn absorb_group_entries(
    config: &sbproxy_ai::handler::AiHandlerConfig,
    models: &mut BTreeMap<String, LogicalModelAggregate>,
    provider_filter: &dyn Fn(&sbproxy_ai::ProviderConfig) -> bool,
    visible: &dyn Fn(&str) -> bool,
    managed: &BTreeMap<String, ManagedDeploymentAvailability>,
) {
    for group in config.model_group_registry().groups() {
        let mut aggregate = LogicalModelAggregate::default();
        let mut served = false;
        for member in &group.members {
            let Some(provider) = config
                .providers
                .iter()
                .find(|provider| provider.name.as_str() == member.provider.as_str())
            else {
                continue;
            };
            if !provider_filter(provider) || !visible(member.model.as_str()) {
                continue;
            }
            served = true;
            aggregate.absorb_availability(provider, managed);
            aggregate
                .capabilities
                .extend(sbproxy_ai::api_routes::surface_capability_names(provider));
            aggregate.absorb_facts(sbproxy_ai::context_window::model_facts(
                member.model.as_str(),
            ));
        }
        if !served {
            continue;
        }
        models.insert(group.name.as_str().to_string(), aggregate);
    }
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

/// Shared `{"error": {...}}` envelope for every data-plane error response.
///
/// `kind` (serialized as `error.type`) and `message` are the only fields
/// every site needs; every other field is written to the JSON only when
/// set, so a call site with just a message and a type gets exactly that,
/// while [`managed_error_body`] below gets its full narrow shape. This
/// centralizes the envelope construction that used to be hand-rolled with
/// `serde_json::json!` at each AI-proxy error site.
pub struct ErrorEnvelope<'a> {
    kind: &'a str,
    message: &'a str,
    code: Option<&'a str>,
    scope: Option<&'a str>,
    request_id: Option<&'a str>,
    retryable: Option<bool>,
    reason: Option<&'a str>,
}

impl<'a> ErrorEnvelope<'a> {
    /// Start an envelope with the two fields every error response carries.
    pub fn new(kind: &'a str, message: &'a str) -> Self {
        Self {
            kind,
            message,
            code: None,
            scope: None,
            request_id: None,
            retryable: None,
            reason: None,
        }
    }

    /// Sets `error.code`.
    pub fn code(mut self, code: &'a str) -> Self {
        self.code = Some(code);
        self
    }

    /// Sets `error.scope`.
    pub fn scope(mut self, scope: &'a str) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Sets `error.request_id`.
    pub fn request_id(mut self, request_id: &'a str) -> Self {
        self.request_id = Some(request_id);
        self
    }

    /// Sets `error.retryable`.
    pub fn retryable(mut self, retryable: bool) -> Self {
        self.retryable = Some(retryable);
        self
    }

    /// Sets `error.sbproxy_reason`. Kept distinct from `code` for callers
    /// (like [`managed_error_body`]) whose reason and code happen to share
    /// a value today but are conceptually different fields.
    pub fn reason(mut self, reason: &'a str) -> Self {
        self.reason = Some(reason);
        self
    }

    /// Encode as a `{"error": {...}}` JSON body.
    pub fn to_bytes(&self) -> Bytes {
        let mut error = serde_json::Map::new();
        error.insert(
            "message".to_string(),
            serde_json::Value::String(self.message.to_string()),
        );
        error.insert(
            "type".to_string(),
            serde_json::Value::String(self.kind.to_string()),
        );
        if let Some(code) = self.code {
            error.insert(
                "code".to_string(),
                serde_json::Value::String(code.to_string()),
            );
        }
        if let Some(scope) = self.scope {
            error.insert(
                "scope".to_string(),
                serde_json::Value::String(scope.to_string()),
            );
        }
        if let Some(request_id) = self.request_id {
            error.insert(
                "request_id".to_string(),
                serde_json::Value::String(request_id.to_string()),
            );
        }
        if let Some(retryable) = self.retryable {
            error.insert("retryable".to_string(), serde_json::Value::Bool(retryable));
        }
        if let Some(reason) = self.reason {
            error.insert(
                "sbproxy_reason".to_string(),
                serde_json::Value::String(reason.to_string()),
            );
        }
        let mut outer = serde_json::Map::new();
        outer.insert("error".to_string(), serde_json::Value::Object(error));
        Bytes::from(
            serde_json::to_vec(&serde_json::Value::Object(outer)).expect("error envelope encodes"),
        )
    }
}

/// Stable OpenAI-style managed-model error payload.
pub fn managed_error_body(request_id: &str, code: &'static str, retryable: bool) -> Bytes {
    ErrorEnvelope::new(
        "managed_model_error",
        "managed model is temporarily unavailable",
    )
    .code(code)
    .request_id(request_id)
    .retryable(retryable)
    .reason(code)
    .to_bytes()
}

#[cfg(test)]
mod error_envelope_tests {
    use super::*;

    fn parsed(bytes: Bytes) -> serde_json::Value {
        serde_json::from_slice(&bytes).expect("error envelope is valid JSON")
    }

    #[test]
    fn a_bare_envelope_carries_only_message_and_type() {
        let body = parsed(ErrorEnvelope::new("invalid_request_error", "bad input").to_bytes());
        let error = &body["error"];
        assert_eq!(error["message"], "bad input");
        assert_eq!(error["type"], "invalid_request_error");
        // Every optional field is genuinely absent, not null, when unset:
        // a call site with no request_id/retryable/etc. context must not
        // emit a misleading `"request_id": null`.
        for field in ["code", "scope", "request_id", "retryable", "sbproxy_reason"] {
            assert!(
                error.get(field).is_none(),
                "unset field {field} must be absent, not present as null"
            );
        }
    }

    #[test]
    fn every_optional_field_is_present_exactly_when_set() {
        let body = parsed(
            ErrorEnvelope::new("guardrail_violation", "blocked")
                .code("pii_leak")
                .scope("governed_key")
                .request_id("req_123")
                .retryable(false)
                .reason("pii_leak")
                .to_bytes(),
        );
        let error = &body["error"];
        assert_eq!(error["message"], "blocked");
        assert_eq!(error["type"], "guardrail_violation");
        assert_eq!(error["code"], "pii_leak");
        assert_eq!(error["scope"], "governed_key");
        assert_eq!(error["request_id"], "req_123");
        assert_eq!(error["retryable"], false);
        assert_eq!(error["sbproxy_reason"], "pii_leak");
    }

    #[test]
    fn retryable_true_and_false_both_round_trip_as_real_booleans() {
        // Not just "is the field present": a JSON string "false" would be
        // truthy in some client languages, so this must be a real bool.
        let retryable_body = parsed(
            ErrorEnvelope::new("rate_limit_error", "slow down")
                .retryable(true)
                .to_bytes(),
        );
        assert!(retryable_body["error"]["retryable"].is_boolean());
        assert_eq!(retryable_body["error"]["retryable"], true);

        let not_retryable_body = parsed(
            ErrorEnvelope::new("invalid_request_error", "bad input")
                .retryable(false)
                .to_bytes(),
        );
        assert_eq!(not_retryable_body["error"]["retryable"], false);
    }

    #[test]
    fn managed_error_body_matches_its_documented_stable_shape() {
        // managed_error_body is the one call site that populates every
        // field; a downstream integration test
        // (managed_replica_dispatch.rs) also pins this shape end to end.
        let body = parsed(managed_error_body("req_abc", "no_ready_replica", true));
        let error = &body["error"];
        assert_eq!(error["message"], "managed model is temporarily unavailable");
        assert_eq!(error["type"], "managed_model_error");
        assert_eq!(error["code"], "no_ready_replica");
        assert_eq!(error["request_id"], "req_abc");
        assert_eq!(error["retryable"], true);
        assert_eq!(error["sbproxy_reason"], "no_ready_replica");
        // No `scope` on this call site: managed_error_body never sets one.
        assert!(error.get("scope").is_none());
    }
}

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use sbproxy_config::{BundleHookKind, CompiledConfig};
use sbproxy_extension::bundle::{
    AiExtensionChain, BundleRegistry, DynamicBundleRegistry, PaymentExtensionChain,
};
use sbproxy_plugin::{
    collect_linked_extension_declarations, ActionPluginRegistration, AuthPluginRegistration,
    ExtensionBodyMode, ExtensionBundleDeclaration, ExtensionBundleRecord, ExtensionCollision,
    ExtensionDispatch, ExtensionExecution, ExtensionHookKind, ExtensionHookRecord,
    ExtensionInventoryScope, ExtensionInventorySnapshot, ExtensionInventorySummary,
    ExtensionLoadRecord, ExtensionObservation, ExtensionRegistrationSource, ExtensionRuntime,
    ExtensionScopeMode, ExtensionState, PluginKind, PluginRegistration, PluginResult,
    PolicyPluginRegistration, TransformPluginRegistration, EXTENSION_INVENTORY_SCHEMA_VERSION,
};

const UNATTRIBUTED_BUNDLE_ID: &str = "unattributed";

/// Constructors for the shared running and doctor inventory model.
pub(crate) trait ExtensionInventorySnapshotExt: Sized {
    fn running(
        proxy_version: &str,
        config_revision: Option<&str>,
        declarations: &[&ExtensionBundleDeclaration],
        preliminary: ExtensionInventorySnapshot,
        observations: &[ExtensionObservation],
    ) -> PluginResult<Self>;

    fn doctor(
        proxy_version: &str,
        config_revision: Option<&str>,
        declarations: &[&ExtensionBundleDeclaration],
        preliminary: ExtensionInventorySnapshot,
        observations: &[ExtensionObservation],
    ) -> PluginResult<Self>;
}

impl ExtensionInventorySnapshotExt for ExtensionInventorySnapshot {
    fn running(
        proxy_version: &str,
        config_revision: Option<&str>,
        declarations: &[&ExtensionBundleDeclaration],
        preliminary: ExtensionInventorySnapshot,
        observations: &[ExtensionObservation],
    ) -> PluginResult<Self> {
        collect_inventory(
            ExtensionScopeMode::Running,
            proxy_version,
            config_revision,
            declarations,
            preliminary,
            observations,
        )
    }

    fn doctor(
        proxy_version: &str,
        config_revision: Option<&str>,
        declarations: &[&ExtensionBundleDeclaration],
        preliminary: ExtensionInventorySnapshot,
        observations: &[ExtensionObservation],
    ) -> PluginResult<Self> {
        collect_inventory(
            ExtensionScopeMode::Doctor,
            proxy_version,
            config_revision,
            declarations,
            preliminary,
            observations,
        )
    }
}

/// Attachment proof supplied by one successfully compiled pipeline perspective.
pub(crate) struct CompiledExtensionAttachments<'a> {
    pub(crate) scope: ExtensionScopeMode,
    pub(crate) ai_chain: &'a AiExtensionChain,
    /// The attached payment chain, or none when payment dispatch has not
    /// installed one. Carrying the chain rather than a bare flag is what
    /// lets inventory report each payment hook's real lifecycle position
    /// (WOR-2272).
    pub(crate) payment_chain: Option<&'a PaymentExtensionChain>,
}

/// Build the authoritative inventory pinned to one compiled pipeline.
pub(crate) fn compiled_inventory(
    registry: &DynamicBundleRegistry,
    config: &CompiledConfig,
    config_revision: &str,
    attachments: CompiledExtensionAttachments<'_>,
) -> PluginResult<ExtensionInventorySnapshot> {
    let declarations = collect_linked_extension_declarations()?;
    let mut preliminary = registry.inventory().clone();
    preliminary
        .hooks
        .extend(unattributed_registration_hooks(&declarations));
    let mut active = active_extension_hooks(config, registry);
    record_lifecycle_attachments(
        &declarations,
        &preliminary.hooks,
        attachments.ai_chain,
        attachments.payment_chain,
        &mut active,
    );
    let observations = compiled_observations(&declarations, &preliminary.hooks, &active);
    match attachments.scope {
        ExtensionScopeMode::Running => ExtensionInventorySnapshot::running(
            env!("CARGO_PKG_VERSION"),
            Some(config_revision),
            &declarations,
            preliminary,
            &observations,
        ),
        ExtensionScopeMode::Doctor => ExtensionInventorySnapshot::doctor(
            env!("CARGO_PKG_VERSION"),
            Some(config_revision),
            &declarations,
            preliminary,
            &observations,
        ),
    }
}

/// Inspect linked and configured extensions without claiming a running state.
pub(crate) fn doctor_inventory(
    config: Option<&sbproxy_config::ExtensionBundlesConfig>,
    base_dir: &Path,
    config_revision: Option<&str>,
) -> ExtensionInventorySnapshot {
    let declarations = match collect_linked_extension_declarations() {
        Ok(declarations) => declarations,
        Err(error) => {
            return failed_doctor_inventory(
                Vec::new(),
                empty_preliminary(ExtensionScopeMode::Doctor),
                "link",
                &error.to_string(),
                config_revision,
            );
        }
    };
    let mut preliminary = match config {
        Some(config) => {
            let reserved = match reserved_extension_hook_names() {
                Ok(reserved) => reserved,
                Err(error) => {
                    return failed_doctor_inventory(
                        declarations,
                        empty_preliminary(ExtensionScopeMode::Doctor),
                        "link",
                        &error.to_string(),
                        config_revision,
                    );
                }
            };
            let fetch_context = match crate::config_source::build_extension_fetch_context(config) {
                Ok(context) => context,
                Err(error) => {
                    return failed_doctor_inventory(
                        declarations,
                        empty_preliminary(ExtensionScopeMode::Doctor),
                        "source",
                        &error.to_string(),
                        config_revision,
                    );
                }
            };
            match DynamicBundleRegistry::load_with_context(
                config,
                base_dir,
                &reserved,
                &fetch_context,
            ) {
                Ok(registry) => registry.inventory().clone(),
                Err(error) => {
                    let rendered = error.to_string();
                    let (phase, detail) = split_load_error(&rendered);
                    let mut preliminary = empty_preliminary(ExtensionScopeMode::Doctor);
                    if phase == "collision" {
                        preliminary.collisions.push(ExtensionCollision {
                            match_key: UNATTRIBUTED_BUNDLE_ID.to_owned(),
                            registrations: vec![UNATTRIBUTED_BUNDLE_ID.to_owned()],
                            winner: None,
                            resolution: detail.to_owned(),
                        });
                    }
                    return failed_doctor_inventory(
                        declarations,
                        preliminary,
                        phase,
                        detail,
                        config_revision,
                    );
                }
            }
        }
        None => empty_preliminary(ExtensionScopeMode::Doctor),
    };
    preliminary
        .hooks
        .extend(unattributed_registration_hooks(&declarations));
    ExtensionInventorySnapshot::doctor(
        env!("CARGO_PKG_VERSION"),
        config_revision,
        &declarations,
        preliminary,
        &[],
    )
    .unwrap_or_else(|error| {
        failed_doctor_inventory(
            Vec::new(),
            empty_preliminary(ExtensionScopeMode::Doctor),
            "inventory",
            &error.to_string(),
            config_revision,
        )
    })
}

fn failed_doctor_inventory(
    declarations: Vec<&ExtensionBundleDeclaration>,
    mut preliminary: ExtensionInventorySnapshot,
    phase: &str,
    detail: &str,
    config_revision: Option<&str>,
) -> ExtensionInventorySnapshot {
    preliminary
        .hooks
        .extend(unattributed_registration_hooks(&declarations));
    let observations = [ExtensionObservation {
        bundle_id: UNATTRIBUTED_BUNDLE_ID.to_owned(),
        hook_id: None,
        state: ExtensionState::Failed,
        position: None,
        phase: phase.to_owned(),
        status: "failed".to_owned(),
        detail: Some(detail.to_owned()),
    }];
    ExtensionInventorySnapshot::doctor(
        env!("CARGO_PKG_VERSION"),
        config_revision,
        &declarations,
        preliminary,
        &observations,
    )
    .unwrap_or_else(|_| {
        let mut snapshot = ExtensionInventorySnapshot {
            schema_version: EXTENSION_INVENTORY_SCHEMA_VERSION,
            scope: ExtensionInventoryScope {
                mode: ExtensionScopeMode::Doctor,
                proxy_version: env!("CARGO_PKG_VERSION").to_owned(),
                config_revision: config_revision.map(str::to_owned),
            },
            summary: ExtensionInventorySummary::default(),
            bundles: vec![ExtensionBundleRecord {
                id: UNATTRIBUTED_BUNDLE_ID.to_owned(),
                name: "Unattributed extension load".to_owned(),
                version: "unknown".to_owned(),
                package: None,
                source: ExtensionRegistrationSource::Directory,
                runtime: ExtensionRuntime::Rust,
                state: ExtensionState::Failed,
                hook_ids: Vec::new(),
                load: ExtensionLoadRecord {
                    phase: sanitize_text(phase, 64, false),
                    status: "failed".to_owned(),
                    detail: Some(sanitize_text(detail, 512, true)),
                },
            }],
            hooks: Vec::new(),
            collisions: Vec::new(),
        };
        snapshot.summary = summarize(&snapshot);
        snapshot
    })
}

fn empty_preliminary(mode: ExtensionScopeMode) -> ExtensionInventorySnapshot {
    ExtensionInventorySnapshot {
        schema_version: EXTENSION_INVENTORY_SCHEMA_VERSION,
        scope: ExtensionInventoryScope {
            mode,
            proxy_version: env!("CARGO_PKG_VERSION").to_owned(),
            config_revision: None,
        },
        summary: ExtensionInventorySummary::default(),
        bundles: Vec::new(),
        hooks: Vec::new(),
        collisions: Vec::new(),
    }
}

fn split_load_error(error: &str) -> (&str, &str) {
    let error = error.strip_prefix("bundle.").unwrap_or(error);
    error.split_once(": ").unwrap_or(("load", error))
}

/// Names a dynamic bundle may not claim because this binary already owns them.
pub(crate) fn reserved_extension_hook_names() -> PluginResult<BTreeSet<(BundleHookKind, String)>> {
    let declarations = collect_linked_extension_declarations()?;
    let mut names = sbproxy_config::reserved_builtin_hook_names();
    for hook in unattributed_registration_hooks(&declarations) {
        if let Some(kind) = bundle_hook_kind(hook.kind) {
            names.insert((kind, hook.match_key));
        }
    }
    for declaration in declarations {
        for hook in declaration.hooks {
            if let Some(kind) = bundle_hook_kind(hook.kind) {
                names.insert((kind, hook.match_key.to_owned()));
            }
        }
    }
    Ok(names)
}

/// Attached hooks and the position each one holds in its real chain.
///
/// Inventory used to carry only the set of attached keys and then invent
/// a position by sorting hook identities alphabetically and counting.
/// That reported an order the pipeline never runs: two Proxy-Wasm filters
/// listed `b` then `a` came back as `a` at 0 and `b` at 1, the reverse of
/// their execution order, and a hook attached at several chain slots
/// collapsed to one entry. Positions now come from the same enumeration
/// the compiler walks (WOR-2272).
#[derive(Debug, Default)]
struct AttachedChains {
    /// Attached hooks, mapped to a chain position where one is known.
    ///
    /// Presence of the key is the attachment fact. The inner `Option` is
    /// separate on purpose: a hook can be provably attached while its
    /// position is not derivable, and reporting no position is honest
    /// where inventing one was the original defect.
    positions: BTreeMap<(ExtensionHookKind, String), Option<u32>>,
}

impl AttachedChains {
    /// Record an attachment at a known chain position.
    ///
    /// Origins are walked in config order and each chain in execution
    /// order, so the first recorded position is the earliest attachment
    /// site in the document. A hook attached to several origins, or
    /// twice in one chain, reports that site rather than whichever one
    /// happened to be written last.
    fn attach(&mut self, kind: ExtensionHookKind, match_key: String, position: u32) {
        self.positions
            .entry((kind, match_key))
            .and_modify(|slot| {
                if slot.is_none() {
                    *slot = Some(position);
                }
            })
            .or_insert(Some(position));
    }

    /// Record an attachment whose chain position is not derivable.
    fn attach_without_position(&mut self, kind: ExtensionHookKind, match_key: String) {
        self.positions.entry((kind, match_key)).or_insert(None);
    }

    fn position(&self, kind: ExtensionHookKind, match_key: &str) -> Option<u32> {
        self.positions
            .get(&(kind, match_key.to_owned()))
            .copied()
            .flatten()
    }

    fn is_attached(&self, kind: ExtensionHookKind, match_key: &str) -> bool {
        self.positions.contains_key(&(kind, match_key.to_owned()))
    }
}

fn active_extension_hooks(
    config: &CompiledConfig,
    registry: &dyn BundleRegistry,
) -> AttachedChains {
    let mut active = AttachedChains::default();
    for origin in &config.origins {
        for (position, filter) in origin.filters.iter().enumerate() {
            if registry.proxy_wasm_filter(&filter.type_name).is_some() {
                active.attach(
                    ExtensionHookKind::ProxyWasmFilter,
                    filter.type_name.clone(),
                    position as u32,
                );
            }
        }
        // An origin has exactly one action and one auth provider, so
        // both are position 0 by construction rather than by counting.
        record_configured_action(&origin.action_config, registry, 0, &mut active);
        if let Some(auth) = &origin.auth_config {
            record_configured_hook(auth, ExtensionHookKind::Auth, false, 0, &mut active);
        }
        for (position, policy) in origin.policy_configs.iter().enumerate() {
            let dynamic =
                configured_type(policy).is_some_and(|name| registry.policy(name).is_some());
            record_configured_hook(
                policy,
                ExtensionHookKind::Policy,
                dynamic,
                position as u32,
                &mut active,
            );
        }
        // A disabled transform never runs, so it takes no slot and the
        // transforms after it keep the positions the pipeline gives them.
        let mut transform_position = 0u32;
        for transform in &origin.transform_configs {
            let enabled = serde_json::from_value::<sbproxy_modules::transform::TransformConfig>(
                transform.clone(),
            )
            .is_ok_and(|wrapper| !wrapper.disabled);
            if enabled {
                let dynamic = configured_type(transform)
                    .is_some_and(|name| registry.transform(name).is_some());
                record_configured_hook(
                    transform,
                    ExtensionHookKind::Transform,
                    dynamic,
                    transform_position,
                    &mut active,
                );
                transform_position = transform_position.saturating_add(1);
            }
        }
        for rule in &origin.forward_rules {
            if let Some(value) = rule.get("origin").and_then(|origin| origin.get("action")) {
                record_configured_action(value, registry, 0, &mut active);
            }
        }
        if let Some(value) = origin
            .fallback_origin
            .as_ref()
            .and_then(|fallback| fallback.get("origin"))
            .and_then(|origin| origin.get("action"))
        {
            record_configured_action(value, registry, 0, &mut active);
        }
    }
    active
}

fn record_lifecycle_attachments(
    declarations: &[&ExtensionBundleDeclaration],
    hooks: &[ExtensionHookRecord],
    ai_chain: &AiExtensionChain,
    payment_chain: Option<&PaymentExtensionChain>,
    active: &mut AttachedChains,
) {
    // AI and payment hooks are not attached by an origin's config; they
    // attach by being present in their prepared chain. Read the position
    // straight off that chain, per kind for AI (each event kind is its
    // own chain) and across the whole chain for payments (one lifecycle
    // chain sees every phase).
    let mut ai_positions = BTreeMap::<(ExtensionHookKind, String), u32>::new();
    let mut per_kind = BTreeMap::<ExtensionHookKind, u32>::new();
    for (kind, match_key) in ai_chain.dispatch_order() {
        let next = per_kind.entry(kind).or_default();
        ai_positions.entry((kind, match_key)).or_insert(*next);
        *next = next.saturating_add(1);
    }
    let payment_positions = payment_chain
        .map(|chain| {
            chain
                .dispatch_order()
                .into_iter()
                .enumerate()
                .map(|(position, match_key)| (match_key, position as u32))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();

    let payment_attached = payment_chain.is_some();
    let mut record = |kind: ExtensionHookKind, match_key: &str| {
        // Attachment is still decided by the chain carrying this kind,
        // exactly as before. Only the position is new, and it is claimed
        // only when this hook is one the chain can name.
        let attached =
            ai_chain.has_kind(kind) || (payment_attached && kind == ExtensionHookKind::Payment);
        if !attached {
            return;
        }
        if let Some(position) = ai_positions.get(&(kind, match_key.to_owned())) {
            active.attach(kind, match_key.to_owned(), *position);
            return;
        }
        if kind == ExtensionHookKind::Payment {
            if let Some(position) = payment_positions.get(match_key) {
                active.attach(kind, match_key.to_owned(), *position);
                return;
            }
        }
        active.attach_without_position(kind, match_key.to_owned());
    };

    for hook in hooks {
        record(hook.kind, &hook.match_key);
    }
    for hook in declarations
        .iter()
        .flat_map(|declaration| declaration.hooks)
    {
        record(hook.kind, hook.match_key);
    }
}

fn record_configured_action(
    value: &serde_json::Value,
    registry: &dyn BundleRegistry,
    position: u32,
    active: &mut AttachedChains,
) {
    let dynamic = configured_type(value).is_some_and(|name| registry.action(name).is_some());
    record_configured_hook(value, ExtensionHookKind::Action, dynamic, position, active);
}

fn record_configured_hook(
    value: &serde_json::Value,
    kind: ExtensionHookKind,
    dynamic: bool,
    position: u32,
    active: &mut AttachedChains,
) {
    let Some(name) = configured_type(value) else {
        return;
    };
    if dynamic || linked_registration_exists(kind, name) {
        active.attach(kind, name.to_owned(), position);
    }
}

fn configured_type(value: &serde_json::Value) -> Option<&str> {
    value.get("type").and_then(serde_json::Value::as_str)
}

fn linked_registration_exists(kind: ExtensionHookKind, name: &str) -> bool {
    match kind {
        ExtensionHookKind::Action => {
            inventory::iter::<ActionPluginRegistration>().any(|item| item.name == name)
        }
        ExtensionHookKind::Auth => {
            inventory::iter::<AuthPluginRegistration>().any(|item| item.name == name)
        }
        ExtensionHookKind::Policy => {
            inventory::iter::<PolicyPluginRegistration>().any(|item| item.name == name)
        }
        ExtensionHookKind::Transform => {
            inventory::iter::<TransformPluginRegistration>().any(|item| item.name == name)
        }
        _ => inventory::iter::<PluginRegistration>()
            .any(|item| plugin_hook_kind(item.kind) == kind && item.name == name),
    }
}

fn compiled_observations(
    declarations: &[&ExtensionBundleDeclaration],
    preliminary_hooks: &[ExtensionHookRecord],
    active: &AttachedChains,
) -> Vec<ExtensionObservation> {
    let mut hooks = preliminary_hooks
        .iter()
        .map(|hook| {
            (
                hook.id.clone(),
                hook.bundle_id.clone(),
                hook.kind,
                hook.match_key.clone(),
                hook.registration,
            )
        })
        .collect::<Vec<_>>();
    for declaration in declarations {
        hooks.extend(declaration.hooks.iter().map(|hook| {
            (
                hook.id.to_owned(),
                declaration.id.to_owned(),
                hook.kind,
                hook.match_key.to_owned(),
                ExtensionRegistrationSource::LinkTime,
            )
        }));
    }
    // Reporting order stays sorted by identity so the JSON is stable
    // across runs. The position no longer comes from this ordering: it
    // is read from the chain the pipeline actually executes.
    hooks.sort_by(|left, right| {
        (left.2, left.3.as_str(), left.0.as_str()).cmp(&(
            right.2,
            right.3.as_str(),
            right.0.as_str(),
        ))
    });

    hooks
        .into_iter()
        .map(|(id, bundle_id, kind, match_key, source)| {
            let attached = active.is_attached(kind, &match_key);
            let position = attached
                .then(|| active.position(kind, &match_key))
                .flatten();
            ExtensionObservation {
                bundle_id,
                hook_id: Some(id),
                state: if attached {
                    ExtensionState::Active
                } else if source == ExtensionRegistrationSource::LinkTime {
                    ExtensionState::Installed
                } else {
                    ExtensionState::Unconsumed
                },
                position,
                phase: "pipeline_compile".to_owned(),
                status: if attached {
                    "attached".to_owned()
                } else {
                    "not_attached".to_owned()
                },
                detail: None,
            }
        })
        .collect()
}

fn unattributed_registration_hooks(
    declarations: &[&ExtensionBundleDeclaration],
) -> Vec<ExtensionHookRecord> {
    let declared = declarations
        .iter()
        .flat_map(|declaration| declaration.hooks)
        .map(|hook| (hook.kind, hook.match_key))
        .collect::<BTreeSet<_>>();
    let mut registrations = Vec::<(ExtensionHookKind, &'static str)>::new();
    registrations.extend(
        inventory::iter::<ActionPluginRegistration>()
            .map(|item| (ExtensionHookKind::Action, item.name)),
    );
    registrations.extend(
        inventory::iter::<AuthPluginRegistration>()
            .map(|item| (ExtensionHookKind::Auth, item.name)),
    );
    registrations.extend(
        inventory::iter::<PolicyPluginRegistration>()
            .map(|item| (ExtensionHookKind::Policy, item.name)),
    );
    registrations.extend(
        inventory::iter::<TransformPluginRegistration>()
            .map(|item| (ExtensionHookKind::Transform, item.name)),
    );
    for item in inventory::iter::<PluginRegistration> {
        let pair = (plugin_hook_kind(item.kind), item.name);
        if !registrations.contains(&pair) {
            registrations.push(pair);
        }
    }
    registrations.retain(|registration| !declared.contains(registration));
    registrations.sort();

    let mut seen = BTreeMap::<(ExtensionHookKind, &'static str), u32>::new();
    registrations
        .into_iter()
        .map(|(kind, name)| {
            let occurrence = seen.entry((kind, name)).or_default();
            let suffix = if *occurrence == 0 {
                String::new()
            } else {
                format!(":{}", *occurrence + 1)
            };
            *occurrence = occurrence.saturating_add(1);
            ExtensionHookRecord {
                id: format!(
                    "{UNATTRIBUTED_BUNDLE_ID}:{}:{name}{suffix}",
                    hook_kind_label(kind)
                ),
                bundle_id: UNATTRIBUTED_BUNDLE_ID.to_owned(),
                kind,
                registration: ExtensionRegistrationSource::LinkTime,
                dispatch: ExtensionDispatch::Exclusive,
                match_key: name.to_owned(),
                position: None,
                state: ExtensionState::Installed,
                detail: None,
                runtime: ExtensionRuntime::Rust,
                execution: ExtensionExecution {
                    phase: hook_phase(kind).to_owned(),
                    body_mode: ExtensionBodyMode::None,
                    timeout_ms: None,
                    max_buffer_bytes: None,
                },
                capabilities: Vec::new(),
            }
        })
        .collect()
}

const fn plugin_hook_kind(kind: PluginKind) -> ExtensionHookKind {
    match kind {
        PluginKind::Action => ExtensionHookKind::Action,
        PluginKind::Auth => ExtensionHookKind::Auth,
        PluginKind::Policy => ExtensionHookKind::Policy,
        PluginKind::Transform => ExtensionHookKind::Transform,
    }
}

const fn bundle_hook_kind(kind: ExtensionHookKind) -> Option<BundleHookKind> {
    match kind {
        ExtensionHookKind::Policy => Some(BundleHookKind::Policy),
        ExtensionHookKind::Transform => Some(BundleHookKind::Transform),
        ExtensionHookKind::Action => Some(BundleHookKind::Action),
        ExtensionHookKind::ProxyWasmFilter => Some(BundleHookKind::ProxyWasm),
        ExtensionHookKind::AiToolCall => Some(BundleHookKind::AiToolCall),
        ExtensionHookKind::AiGuardrailInput => Some(BundleHookKind::AiGuardrailInput),
        ExtensionHookKind::AiGuardrailOutput => Some(BundleHookKind::AiGuardrailOutput),
        ExtensionHookKind::AiStreamEvent => Some(BundleHookKind::AiStreamEvent),
        ExtensionHookKind::AiClose => Some(BundleHookKind::AiClose),
        ExtensionHookKind::AiFailure => Some(BundleHookKind::AiFailure),
        ExtensionHookKind::Payment => Some(BundleHookKind::Payment),
        ExtensionHookKind::Auth
        | ExtensionHookKind::Startup
        | ExtensionHookKind::Identity
        | ExtensionHookKind::MlClassifier
        | ExtensionHookKind::AnomalyDetector
        | ExtensionHookKind::Mcp => None,
    }
}

const fn hook_kind_label(kind: ExtensionHookKind) -> &'static str {
    match kind {
        ExtensionHookKind::Action => "action",
        ExtensionHookKind::Auth => "auth",
        ExtensionHookKind::Policy => "policy",
        ExtensionHookKind::Transform => "transform",
        ExtensionHookKind::Startup => "startup",
        ExtensionHookKind::Identity => "identity",
        ExtensionHookKind::MlClassifier => "ml_classifier",
        ExtensionHookKind::AnomalyDetector => "anomaly_detector",
        ExtensionHookKind::Mcp => "mcp",
        ExtensionHookKind::ProxyWasmFilter => "proxy_wasm_filter",
        ExtensionHookKind::AiToolCall => "ai_tool_call",
        ExtensionHookKind::AiGuardrailInput => "ai_guardrail_input",
        ExtensionHookKind::AiGuardrailOutput => "ai_guardrail_output",
        ExtensionHookKind::AiStreamEvent => "ai_stream_event",
        ExtensionHookKind::AiClose => "ai_close",
        ExtensionHookKind::AiFailure => "ai_failure",
        ExtensionHookKind::Payment => "payment",
    }
}

const fn hook_phase(kind: ExtensionHookKind) -> &'static str {
    match kind {
        ExtensionHookKind::Auth | ExtensionHookKind::Identity => "authentication",
        ExtensionHookKind::Transform => "body",
        ExtensionHookKind::Startup => "startup",
        ExtensionHookKind::AiToolCall
        | ExtensionHookKind::AiGuardrailInput
        | ExtensionHookKind::AiGuardrailOutput
        | ExtensionHookKind::AiStreamEvent
        | ExtensionHookKind::AiClose
        | ExtensionHookKind::AiFailure => "ai",
        ExtensionHookKind::Payment => "payment",
        ExtensionHookKind::Mcp => "mcp",
        ExtensionHookKind::ProxyWasmFilter => "http",
        ExtensionHookKind::Action
        | ExtensionHookKind::Policy
        | ExtensionHookKind::MlClassifier
        | ExtensionHookKind::AnomalyDetector => "request",
    }
}

fn collect_inventory(
    mode: ExtensionScopeMode,
    proxy_version: &str,
    config_revision: Option<&str>,
    declarations: &[&ExtensionBundleDeclaration],
    preliminary: ExtensionInventorySnapshot,
    observations: &[ExtensionObservation],
) -> PluginResult<ExtensionInventorySnapshot> {
    let mut bundles = preliminary.bundles;
    let mut hooks = preliminary.hooks;
    let mut collisions = preliminary.collisions;
    let linked_state = state_without_running_evaluation(mode, ExtensionState::Installed);

    if mode == ExtensionScopeMode::Doctor {
        for bundle in &mut bundles {
            bundle.state = ExtensionState::NotEvaluated;
            bundle.load.phase = "doctor_validation".to_owned();
            bundle.load.status = "validated".to_owned();
        }
        for hook in &mut hooks {
            hook.state = ExtensionState::NotEvaluated;
            hook.position = None;
        }
    }

    for declaration in declarations {
        let hook_ids = declaration
            .hooks
            .iter()
            .map(|hook| hook.id.to_owned())
            .collect::<Vec<_>>();
        bundles.push(ExtensionBundleRecord {
            id: declaration.id.to_owned(),
            name: declaration.name.to_owned(),
            version: declaration.version.to_owned(),
            package: declaration.package.map(str::to_owned),
            source: ExtensionRegistrationSource::LinkTime,
            runtime: declaration.runtime,
            state: linked_state,
            hook_ids,
            load: ExtensionLoadRecord {
                phase: "link".to_owned(),
                status: "installed".to_owned(),
                detail: None,
            },
        });
        hooks.extend(declaration.hooks.iter().map(|hook| {
            ExtensionHookRecord {
                id: hook.id.to_owned(),
                bundle_id: declaration.id.to_owned(),
                kind: hook.kind,
                registration: ExtensionRegistrationSource::LinkTime,
                dispatch: hook.dispatch,
                match_key: hook.match_key.to_owned(),
                position: None,
                state: linked_state,
                detail: None,
                runtime: declaration.runtime,
                execution: hook.execution.to_owned(),
                capabilities: hook
                    .capabilities
                    .iter()
                    .map(|capability| (*capability).to_owned())
                    .collect(),
            }
        }));
    }

    attach_orphan_hooks(&mut bundles, &mut hooks, mode);
    add_detected_collisions(&hooks, &mut collisions);

    let mut observed_bundles = BTreeSet::new();
    for observation in observations {
        apply_observation(
            observation,
            mode,
            &mut bundles,
            &mut hooks,
            &mut observed_bundles,
        );
    }
    apply_collision_states(&collisions, &mut hooks);
    derive_bundle_states(&mut bundles, &hooks, &observed_bundles);
    sanitize_records(&mut bundles, &mut hooks, &mut collisions);

    let mut snapshot = ExtensionInventorySnapshot {
        schema_version: EXTENSION_INVENTORY_SCHEMA_VERSION,
        scope: ExtensionInventoryScope {
            mode,
            proxy_version: proxy_version.to_owned(),
            config_revision: config_revision.map(str::to_owned),
        },
        summary: ExtensionInventorySummary::default(),
        bundles,
        hooks,
        collisions,
    };
    snapshot.sort_stably()?;
    snapshot.summary = summarize(&snapshot);
    Ok(snapshot)
}

const fn state_without_running_evaluation(
    mode: ExtensionScopeMode,
    running_state: ExtensionState,
) -> ExtensionState {
    match mode {
        ExtensionScopeMode::Running => running_state,
        ExtensionScopeMode::Doctor => match running_state {
            ExtensionState::Failed => ExtensionState::Failed,
            ExtensionState::Shadowed => ExtensionState::Shadowed,
            ExtensionState::Installed
            | ExtensionState::Available
            | ExtensionState::Active
            | ExtensionState::NotEvaluated
            | ExtensionState::Unconsumed => ExtensionState::NotEvaluated,
        },
    }
}

fn attach_orphan_hooks(
    bundles: &mut Vec<ExtensionBundleRecord>,
    hooks: &mut [ExtensionHookRecord],
    mode: ExtensionScopeMode,
) {
    let bundle_ids = bundles
        .iter()
        .map(|bundle| bundle.id.clone())
        .collect::<BTreeSet<_>>();
    let orphan_indices = hooks
        .iter()
        .enumerate()
        .filter_map(|(index, hook)| (!bundle_ids.contains(&hook.bundle_id)).then_some(index))
        .collect::<Vec<_>>();
    if orphan_indices.is_empty() {
        add_missing_hook_ids(bundles, hooks);
        return;
    }

    let source = orphan_indices
        .first()
        .map(|index| hooks[*index].registration)
        .unwrap_or(ExtensionRegistrationSource::LinkTime);
    let runtime = orphan_indices
        .first()
        .map(|index| hooks[*index].runtime)
        .unwrap_or(ExtensionRuntime::Rust);
    let hook_ids = orphan_indices
        .iter()
        .map(|index| hooks[*index].id.clone())
        .collect::<Vec<_>>();
    for index in orphan_indices {
        hooks[index].bundle_id = UNATTRIBUTED_BUNDLE_ID.to_owned();
        hooks[index].state = state_without_running_evaluation(mode, hooks[index].state);
    }

    if let Some(bundle) = bundles
        .iter_mut()
        .find(|bundle| bundle.id == UNATTRIBUTED_BUNDLE_ID)
    {
        bundle.hook_ids.extend(hook_ids);
    } else {
        bundles.push(ExtensionBundleRecord {
            id: UNATTRIBUTED_BUNDLE_ID.to_owned(),
            name: "Unattributed extensions".to_owned(),
            version: "unknown".to_owned(),
            package: None,
            source,
            runtime,
            state: state_without_running_evaluation(mode, ExtensionState::Installed),
            hook_ids,
            load: ExtensionLoadRecord {
                phase: "inventory".to_owned(),
                status: "unattributed".to_owned(),
                detail: Some(
                    "Linked registrations did not declare a containing bundle.".to_owned(),
                ),
            },
        });
    }
    add_missing_hook_ids(bundles, hooks);
}

fn add_missing_hook_ids(bundles: &mut [ExtensionBundleRecord], hooks: &[ExtensionHookRecord]) {
    for hook in hooks {
        if let Some(bundle) = bundles
            .iter_mut()
            .find(|bundle| bundle.id == hook.bundle_id)
        {
            if !bundle.hook_ids.iter().any(|id| id == &hook.id) {
                bundle.hook_ids.push(hook.id.clone());
            }
        }
    }
}

fn add_detected_collisions(
    hooks: &[ExtensionHookRecord],
    collisions: &mut Vec<ExtensionCollision>,
) {
    let mut claims = BTreeMap::<(ExtensionHookKind, String), Vec<String>>::new();
    for hook in hooks {
        if hook.dispatch == ExtensionDispatch::Exclusive {
            claims
                .entry((hook.kind, hook.match_key.clone()))
                .or_default()
                .push(hook.id.clone());
        }
    }
    for ((_kind, match_key), mut registrations) in claims {
        registrations.sort();
        registrations.dedup();
        if registrations.len() < 2
            || collisions
                .iter()
                .any(|collision| collision.match_key == match_key)
        {
            continue;
        }
        collisions.push(ExtensionCollision {
            match_key,
            registrations,
            winner: None,
            resolution: "rejected duplicate exclusive registrations".to_owned(),
        });
    }
}

fn apply_observation(
    observation: &ExtensionObservation,
    mode: ExtensionScopeMode,
    bundles: &mut Vec<ExtensionBundleRecord>,
    hooks: &mut [ExtensionHookRecord],
    observed_bundles: &mut BTreeSet<String>,
) {
    let state = observation.state;
    if let Some(hook_id) = observation.hook_id.as_deref() {
        if let Some(hook) = hooks.iter_mut().find(|hook| hook.id == hook_id) {
            hook.state = state;
            hook.position = if mode == ExtensionScopeMode::Running {
                observation.position
            } else {
                None
            };
            hook.detail = observation
                .detail
                .as_deref()
                .map(|detail| sanitize_text(detail, 512, true));
            return;
        }
    }

    let bundle_id = if bundles
        .iter()
        .any(|bundle| bundle.id == observation.bundle_id)
    {
        observation.bundle_id.as_str()
    } else {
        ensure_unattributed_failure_bundle(bundles, mode);
        UNATTRIBUTED_BUNDLE_ID
    };
    if let Some(bundle) = bundles.iter_mut().find(|bundle| bundle.id == bundle_id) {
        bundle.state = state;
        bundle.load = ExtensionLoadRecord {
            phase: sanitize_text(&observation.phase, 64, false),
            status: sanitize_text(&observation.status, 64, false),
            detail: observation
                .detail
                .as_deref()
                .map(|detail| sanitize_text(detail, 512, true)),
        };
        observed_bundles.insert(bundle.id.clone());
    }
}

fn ensure_unattributed_failure_bundle(
    bundles: &mut Vec<ExtensionBundleRecord>,
    mode: ExtensionScopeMode,
) {
    if bundles
        .iter()
        .any(|bundle| bundle.id == UNATTRIBUTED_BUNDLE_ID)
    {
        return;
    }
    bundles.push(ExtensionBundleRecord {
        id: UNATTRIBUTED_BUNDLE_ID.to_owned(),
        name: "Unattributed extension load".to_owned(),
        version: "unknown".to_owned(),
        package: None,
        source: ExtensionRegistrationSource::Directory,
        runtime: ExtensionRuntime::Rust,
        state: state_without_running_evaluation(mode, ExtensionState::Failed),
        hook_ids: Vec::new(),
        load: ExtensionLoadRecord {
            phase: "inventory".to_owned(),
            status: "unattributed".to_owned(),
            detail: None,
        },
    });
}

fn apply_collision_states(collisions: &[ExtensionCollision], hooks: &mut [ExtensionHookRecord]) {
    for collision in collisions {
        for registration in &collision.registrations {
            let Some(hook) = hooks.iter_mut().find(|hook| hook.id == *registration) else {
                continue;
            };
            hook.state = match collision.winner.as_deref() {
                Some(winner) if winner != registration => ExtensionState::Shadowed,
                Some(_) => hook.state,
                None => ExtensionState::Failed,
            };
        }
    }
}

fn derive_bundle_states(
    bundles: &mut [ExtensionBundleRecord],
    hooks: &[ExtensionHookRecord],
    observed_bundles: &BTreeSet<String>,
) {
    for bundle in bundles {
        if observed_bundles.contains(&bundle.id) {
            continue;
        }
        let states = hooks
            .iter()
            .filter(|hook| hook.bundle_id == bundle.id)
            .map(|hook| hook.state)
            .collect::<Vec<_>>();
        if states.is_empty() {
            continue;
        }
        bundle.state = if states.contains(&ExtensionState::Active) {
            ExtensionState::Active
        } else if states.contains(&ExtensionState::Failed) {
            ExtensionState::Failed
        } else if states
            .iter()
            .all(|state| *state == ExtensionState::Shadowed)
        {
            ExtensionState::Shadowed
        } else if states.contains(&ExtensionState::Available) {
            ExtensionState::Available
        } else if states.contains(&ExtensionState::Unconsumed) {
            ExtensionState::Unconsumed
        } else if states.contains(&ExtensionState::NotEvaluated) {
            ExtensionState::NotEvaluated
        } else {
            ExtensionState::Installed
        };
    }
}

fn sanitize_records(
    bundles: &mut [ExtensionBundleRecord],
    hooks: &mut [ExtensionHookRecord],
    collisions: &mut [ExtensionCollision],
) {
    for bundle in bundles {
        bundle.load.phase = sanitize_text(&bundle.load.phase, 64, false);
        bundle.load.status = sanitize_text(&bundle.load.status, 64, false);
        bundle.load.detail = bundle
            .load
            .detail
            .as_deref()
            .map(|detail| sanitize_text(detail, 512, true));
    }
    for hook in hooks {
        hook.detail = hook
            .detail
            .as_deref()
            .map(|detail| sanitize_text(detail, 512, true));
    }
    for collision in collisions {
        collision.resolution = sanitize_text(&collision.resolution, 512, true);
    }
}

fn sanitize_text(value: &str, maximum: usize, redact_paths: bool) -> String {
    let safe = value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    let mut safe = if redact_paths {
        safe.split_whitespace()
            .map(|token| {
                if looks_like_absolute_path(token) {
                    "<path>"
                } else {
                    token
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        safe
    };
    if safe.len() > maximum {
        let mut boundary = maximum;
        while !safe.is_char_boundary(boundary) {
            boundary = boundary.saturating_sub(1);
        }
        safe.truncate(boundary);
    }
    safe
}

fn looks_like_absolute_path(token: &str) -> bool {
    let token = token.trim_matches(|character: char| {
        matches!(
            character,
            '`' | '\'' | '"' | '(' | ')' | '[' | ']' | ',' | ';'
        )
    });
    if token.contains("://") {
        return false;
    }
    token.starts_with('/')
        || token.starts_with('\\')
        || token
            .as_bytes()
            .get(1)
            .is_some_and(|character| *character == b':')
}

fn summarize(snapshot: &ExtensionInventorySnapshot) -> ExtensionInventorySummary {
    let failed_bundles = snapshot
        .bundles
        .iter()
        .filter(|bundle| bundle.state == ExtensionState::Failed)
        .count();
    let failed_hooks = snapshot
        .hooks
        .iter()
        .filter(|hook| hook.state == ExtensionState::Failed)
        .count();
    ExtensionInventorySummary {
        bundles: bounded_count(snapshot.bundles.len()),
        hooks: bounded_count(snapshot.hooks.len()),
        active: bounded_count(
            snapshot
                .hooks
                .iter()
                .filter(|hook| hook.state == ExtensionState::Active)
                .count(),
        ),
        available: bounded_count(
            snapshot
                .hooks
                .iter()
                .filter(|hook| hook.state == ExtensionState::Available)
                .count(),
        ),
        failed: bounded_count(failed_bundles.saturating_add(failed_hooks)),
        collisions: bounded_count(snapshot.collisions.len()),
    }
}

fn bounded_count(count: usize) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::{compiled_observations, AttachedChains};
    use sbproxy_config::BundleHookKind;
    use sbproxy_plugin::{
        ExtensionBodyMode, ExtensionBundleDeclaration, ExtensionBundleRecord, ExtensionCollision,
        ExtensionDispatch, ExtensionExecution, ExtensionHookDeclaration, ExtensionHookKind,
        ExtensionHookRecord, ExtensionInventoryScope, ExtensionInventorySnapshot,
        ExtensionInventorySummary, ExtensionLoadRecord, ExtensionObservation,
        ExtensionRegistrationSource, ExtensionRuntime, ExtensionScopeMode, ExtensionState,
        EXTENSION_INVENTORY_SCHEMA_VERSION,
    };

    use super::{bundle_hook_kind, hook_kind_label, hook_phase, ExtensionInventorySnapshotExt};

    static LINKED_HOOKS: [ExtensionHookDeclaration; 1] = [ExtensionHookDeclaration {
        id: "linked-policy",
        kind: ExtensionHookKind::Policy,
        dispatch: ExtensionDispatch::Exclusive,
        match_key: "linked_policy",
        execution: ExtensionExecution {
            phase: "request",
            body_mode: ExtensionBodyMode::None,
            timeout_ms: None,
            max_buffer_bytes: None,
        },
        capabilities: &["headers", "request"],
    }];

    static LINKED_BUNDLE: ExtensionBundleDeclaration = ExtensionBundleDeclaration {
        id: "linked-bundle",
        name: "Linked bundle",
        version: "1.2.3",
        package: Some("linked-package"),
        runtime: ExtensionRuntime::Rust,
        hooks: &LINKED_HOOKS,
    };

    fn empty_preliminary() -> ExtensionInventorySnapshot {
        ExtensionInventorySnapshot {
            schema_version: EXTENSION_INVENTORY_SCHEMA_VERSION,
            scope: ExtensionInventoryScope {
                mode: ExtensionScopeMode::Running,
                proxy_version: "fixture".to_owned(),
                config_revision: None,
            },
            summary: ExtensionInventorySummary::default(),
            bundles: Vec::new(),
            hooks: Vec::new(),
            collisions: Vec::new(),
        }
    }

    fn bundle(id: &str, hook_ids: &[&str]) -> ExtensionBundleRecord {
        ExtensionBundleRecord {
            id: id.to_owned(),
            name: format!("Bundle {id}"),
            version: "1.0.0".to_owned(),
            package: Some(format!("{id}.js")),
            source: ExtensionRegistrationSource::Directory,
            runtime: ExtensionRuntime::Javascript,
            state: ExtensionState::Available,
            hook_ids: hook_ids.iter().map(|id| (*id).to_owned()).collect(),
            load: ExtensionLoadRecord {
                phase: "candidate_load".to_owned(),
                status: "ok".to_owned(),
                detail: None,
            },
        }
    }

    fn hook(id: &str, bundle_id: &str, match_key: &str) -> ExtensionHookRecord {
        ExtensionHookRecord {
            id: id.to_owned(),
            bundle_id: bundle_id.to_owned(),
            kind: ExtensionHookKind::Policy,
            registration: ExtensionRegistrationSource::Directory,
            dispatch: ExtensionDispatch::Exclusive,
            match_key: match_key.to_owned(),
            position: None,
            state: ExtensionState::Available,
            detail: None,
            runtime: ExtensionRuntime::Javascript,
            execution: ExtensionExecution {
                phase: "request".to_owned(),
                body_mode: ExtensionBodyMode::Buffered,
                timeout_ms: Some(50),
                max_buffer_bytes: Some(1_048_576),
            },
            capabilities: vec!["write".to_owned(), "read".to_owned()],
        }
    }

    #[test]
    fn extension_inventory_empty_snapshot_has_stable_schema_and_counts() {
        let snapshot = ExtensionInventorySnapshot::running(
            "proxy-version",
            Some("revision"),
            &[],
            empty_preliminary(),
            &[],
        )
        .expect("empty inventory should be valid");

        assert_eq!(snapshot.schema_version, EXTENSION_INVENTORY_SCHEMA_VERSION);
        assert_eq!(snapshot.scope.mode, ExtensionScopeMode::Running);
        assert_eq!(snapshot.scope.proxy_version, "proxy-version");
        assert_eq!(snapshot.scope.config_revision.as_deref(), Some("revision"));
        assert_eq!(snapshot.summary, ExtensionInventorySummary::default());
        assert!(snapshot.bundles.is_empty());
        assert!(snapshot.hooks.is_empty());
        assert!(snapshot.collisions.is_empty());
    }

    #[test]
    fn payment_hook_uses_the_dynamic_bundle_inventory_contract() {
        assert_eq!(
            bundle_hook_kind(ExtensionHookKind::Payment),
            Some(BundleHookKind::Payment)
        );
        assert_eq!(hook_kind_label(ExtensionHookKind::Payment), "payment");
        assert_eq!(hook_phase(ExtensionHookKind::Payment), "payment");
    }

    #[test]
    fn extension_inventory_sorts_records_and_nested_values_stably() {
        let mut preliminary = empty_preliminary();
        preliminary.bundles = vec![bundle("z", &["z-hook"]), bundle("a", &["a-hook"])];
        preliminary.hooks = vec![hook("z-hook", "z", "z"), hook("a-hook", "a", "a")];

        let snapshot =
            ExtensionInventorySnapshot::running("proxy-version", None, &[], preliminary, &[])
                .expect("inventory should sort");

        assert_eq!(
            snapshot
                .bundles
                .iter()
                .map(|bundle| bundle.id.as_str())
                .collect::<Vec<_>>(),
            ["a", "z"]
        );
        assert_eq!(
            snapshot
                .hooks
                .iter()
                .map(|hook| hook.id.as_str())
                .collect::<Vec<_>>(),
            ["a-hook", "z-hook"]
        );
        assert_eq!(snapshot.hooks[0].capabilities, ["read", "write"]);
    }

    #[test]
    fn extension_inventory_synthesizes_unattributed_bundle_for_orphan_hooks() {
        let mut preliminary = empty_preliminary();
        preliminary.hooks = vec![hook("orphan-hook", "missing-bundle", "orphan")];

        let snapshot =
            ExtensionInventorySnapshot::running("proxy-version", None, &[], preliminary, &[])
                .expect("orphan hooks should remain visible");

        assert_eq!(snapshot.bundles.len(), 1);
        assert_eq!(snapshot.bundles[0].id, "unattributed");
        assert_eq!(snapshot.bundles[0].hook_ids, ["orphan-hook"]);
        assert_eq!(snapshot.hooks[0].bundle_id, "unattributed");
    }

    #[test]
    fn extension_inventory_doctor_marks_linked_lifecycle_not_evaluated() {
        let snapshot = ExtensionInventorySnapshot::doctor(
            "proxy-version",
            None,
            &[&LINKED_BUNDLE],
            empty_preliminary(),
            &[],
        )
        .expect("linked inventory should be valid");

        assert_eq!(snapshot.scope.mode, ExtensionScopeMode::Doctor);
        assert_eq!(snapshot.bundles[0].state, ExtensionState::NotEvaluated);
        assert_eq!(snapshot.hooks[0].state, ExtensionState::NotEvaluated);
        assert_eq!(snapshot.hooks[0].capabilities, ["headers", "request"]);
    }

    #[test]
    fn extension_inventory_running_observations_mark_active_and_unconsumed_hooks() {
        let mut preliminary = empty_preliminary();
        preliminary.bundles = vec![bundle("dynamic", &["active-hook", "idle-hook"])];
        preliminary.hooks = vec![
            hook("idle-hook", "dynamic", "idle"),
            hook("active-hook", "dynamic", "active"),
        ];
        let observations = [
            ExtensionObservation {
                bundle_id: "dynamic".to_owned(),
                hook_id: Some("active-hook".to_owned()),
                state: ExtensionState::Active,
                position: Some(0),
                phase: "pipeline_compile".to_owned(),
                status: "attached".to_owned(),
                detail: None,
            },
            ExtensionObservation {
                bundle_id: "dynamic".to_owned(),
                hook_id: Some("idle-hook".to_owned()),
                state: ExtensionState::Unconsumed,
                position: None,
                phase: "pipeline_compile".to_owned(),
                status: "not_attached".to_owned(),
                detail: None,
            },
        ];

        let snapshot = ExtensionInventorySnapshot::running(
            "proxy-version",
            Some("revision"),
            &[],
            preliminary,
            &observations,
        )
        .expect("running observations should apply");

        assert_eq!(snapshot.bundles[0].state, ExtensionState::Active);
        assert_eq!(snapshot.summary.active, 1);
        assert_eq!(snapshot.summary.available, 0);
        assert_eq!(snapshot.hooks[0].position, Some(0));
        assert_eq!(snapshot.hooks[1].state, ExtensionState::Unconsumed);
    }

    fn proxy_wasm_hook(id: &str, match_key: &str) -> ExtensionHookRecord {
        let mut record = hook(id, "dynamic", match_key);
        record.kind = ExtensionHookKind::ProxyWasmFilter;
        record.dispatch = ExtensionDispatch::Chain;
        record
    }

    #[test]
    fn chain_positions_follow_execution_order_not_hook_names() {
        // The filters run `zeta` then `alpha`. Sorting hook identities
        // and counting reported the reverse, so an operator reading
        // inventory saw a filter order the proxy never executes.
        let mut active = AttachedChains::default();
        active.attach(ExtensionHookKind::ProxyWasmFilter, "zeta".to_owned(), 0);
        active.attach(ExtensionHookKind::ProxyWasmFilter, "alpha".to_owned(), 1);

        let hooks = [
            proxy_wasm_hook("alpha-hook", "alpha"),
            proxy_wasm_hook("zeta-hook", "zeta"),
        ];
        let observations = compiled_observations(&[], &hooks, &active);

        let position_of = |hook_id: &str| {
            observations
                .iter()
                .find(|observation| observation.hook_id.as_deref() == Some(hook_id))
                .and_then(|observation| observation.position)
        };
        assert_eq!(position_of("zeta-hook"), Some(0));
        assert_eq!(position_of("alpha-hook"), Some(1));
    }

    #[test]
    fn a_hook_attached_at_several_sites_reports_the_first_one() {
        // Deterministic reporting for the multi-origin case: origins are
        // walked in config order, so the earliest site in the document
        // wins regardless of which one was recorded last.
        let mut active = AttachedChains::default();
        active.attach(ExtensionHookKind::Policy, "shared".to_owned(), 2);
        active.attach(ExtensionHookKind::Policy, "shared".to_owned(), 7);

        let hooks = [hook("shared-hook", "dynamic", "shared")];
        let observations = compiled_observations(&[], &hooks, &active);

        assert_eq!(observations[0].position, Some(2));
        assert_eq!(observations[0].state, ExtensionState::Active);
    }

    #[test]
    fn an_attachment_without_a_derivable_position_stays_attached() {
        // Attachment and position are separate facts. A hook the chain
        // cannot name is still attached; claiming a position for it was
        // the original defect, so it reports none.
        let mut active = AttachedChains::default();
        active.attach_without_position(ExtensionHookKind::Policy, "opaque".to_owned());

        let hooks = [hook("opaque-hook", "dynamic", "opaque")];
        let observations = compiled_observations(&[], &hooks, &active);

        assert_eq!(observations[0].state, ExtensionState::Active);
        assert_eq!(observations[0].position, None);
        assert!(active.is_attached(ExtensionHookKind::Policy, "opaque"));
    }

    #[test]
    fn a_known_position_wins_over_an_earlier_unknown_one() {
        let mut active = AttachedChains::default();
        active.attach_without_position(ExtensionHookKind::Payment, "settle".to_owned());
        active.attach(ExtensionHookKind::Payment, "settle".to_owned(), 3);

        assert_eq!(
            active.position(ExtensionHookKind::Payment, "settle"),
            Some(3)
        );
    }

    #[test]
    fn extension_inventory_degraded_observation_keeps_safe_load_detail() {
        let mut preliminary = empty_preliminary();
        preliminary.bundles = vec![bundle("dynamic", &[])];
        let observations = [ExtensionObservation {
            bundle_id: "dynamic".to_owned(),
            hook_id: None,
            state: ExtensionState::Failed,
            position: None,
            phase: "initialization".to_owned(),
            status: "degraded".to_owned(),
            detail: Some("sandbox timed out".to_owned()),
        }];

        let snapshot = ExtensionInventorySnapshot::running(
            "proxy-version",
            None,
            &[],
            preliminary,
            &observations,
        )
        .expect("degraded observation should remain reportable");

        assert_eq!(snapshot.bundles[0].state, ExtensionState::Failed);
        assert_eq!(snapshot.bundles[0].load.phase, "initialization");
        assert_eq!(snapshot.bundles[0].load.status, "degraded");
        assert_eq!(
            snapshot.bundles[0].load.detail.as_deref(),
            Some("sandbox timed out")
        );
        assert_eq!(snapshot.summary.failed, 1);
    }

    #[test]
    fn extension_inventory_collision_marks_loser_shadowed() {
        let mut preliminary = empty_preliminary();
        preliminary.bundles = vec![bundle("a", &["a-hook"]), bundle("b", &["b-hook"])];
        preliminary.hooks = vec![hook("a-hook", "a", "shared"), hook("b-hook", "b", "shared")];
        preliminary.collisions = vec![ExtensionCollision {
            match_key: "shared".to_owned(),
            registrations: vec!["b-hook".to_owned(), "a-hook".to_owned()],
            winner: Some("a-hook".to_owned()),
            resolution: "linked registration takes precedence".to_owned(),
        }];

        let snapshot =
            ExtensionInventorySnapshot::running("proxy-version", None, &[], preliminary, &[])
                .expect("resolved collision should remain reportable");

        assert_eq!(snapshot.summary.collisions, 1);
        assert_eq!(snapshot.collisions[0].registrations, ["a-hook", "b-hook"]);
        assert_eq!(snapshot.hooks[0].state, ExtensionState::Available);
        assert_eq!(snapshot.hooks[1].state, ExtensionState::Shadowed);
    }

    #[test]
    fn extension_inventory_sanitizes_and_bounds_observation_detail() {
        let mut preliminary = empty_preliminary();
        preliminary.bundles = vec![bundle("dynamic", &[])];
        let unsafe_detail = format!("line one\n/tmp/private/config.yml {}", "🙂".repeat(300));
        let observations = [ExtensionObservation {
            bundle_id: "dynamic".to_owned(),
            hook_id: None,
            state: ExtensionState::Failed,
            position: None,
            phase: "load\nphase".to_owned(),
            status: "failed\rstatus".to_owned(),
            detail: Some(unsafe_detail),
        }];

        let snapshot = ExtensionInventorySnapshot::running(
            "proxy-version",
            None,
            &[],
            preliminary,
            &observations,
        )
        .expect("unsafe diagnostic text should be sanitized");
        let load = &snapshot.bundles[0].load;
        let detail = load
            .detail
            .as_deref()
            .expect("detail should remain present");

        assert!(!load.phase.contains('\n'));
        assert!(!load.status.contains('\r'));
        assert!(!detail.contains('\n'));
        assert!(!detail.contains("/tmp/private/config.yml"));
        assert!(detail.len() <= 512, "detail was {} bytes", detail.len());
    }
}

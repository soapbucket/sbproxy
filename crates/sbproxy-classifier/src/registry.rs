//! Multi-tenant registry: tenant id (an origin's hostname, by convention)
//! to per-tenant heuristic classification state.
//!
//! Ported from the enterprise `sbproxy-classifier` crate's `registry.rs`,
//! dropped to the fields this port serves: a compiled [`Classifier`] (label
//! patterns) and [`Normalizer`] (regex rules) per tenant. The enterprise
//! version also carries a `ModelSelectionState` for per-origin overrides of
//! named embedding / judge / intent / content-type ONNX models; this port
//! does not carry the LLM-judge backend or a named-model registry (out of
//! WOR-2665's scope, see `docs/classifier-sidecar.md`), so there is nothing
//! for that override to select between.
//!
//! Every tenant is registered at runtime via the TCP `register` command (or
//! the future gRPC equivalent); there is no config file and no hostname
//! pattern matching here, mirroring the enterprise design exactly.
//!
//! The registry is protected by a single [`RwLock`]:
//! - Reads dominate (one per inbound classify call), so the writer-rare
//!   pattern of `RwLock` wins over `Mutex` here.
//! - Entries are wrapped in [`Arc`] so a handler can snapshot a `Tenant`
//!   reference, release the lock, and run inference without holding the
//!   registry locked for the duration.
//!
//! Registration is additive (insert or replace). Deletion is explicit.
//! There is no default tenant: a classify request for an unregistered
//! tenant id is an error, not a silent fallback to some other tenant's
//! patterns.

use crate::config::{ClassificationConfig, LabelConfig, NormalizationConfig, NormalizationRule};
use crate::heuristic::{Classifier, CompiledLabel};
use crate::normalize::{CompiledRule, Normalizer};
use crate::protocol::{AdminResponse, TenantConfig, TenantInfo, TenantPageResponse};

use regex::RegexBuilder;
use serde::Serialize;
use std::collections::BTreeMap;
#[cfg(test)]
use std::collections::BTreeSet;
use std::ops::Bound::{Excluded, Unbounded};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
#[cfg(test)]
use std::time::{Duration, Instant};
#[cfg(test)]
use tokio::time::sleep;
use tracing::{debug, info};

const MAX_PATTERN_LENGTH: usize = 4096;
const MAX_TENANT_ID_BYTES: usize = 128;
const DEFAULT_MAX_TENANTS: usize = 64;
const DEFAULT_MAX_PATTERNS_PER_TENANT: usize = 64;
const DEFAULT_MAX_NORMALIZATION_RULES_PER_TENANT: usize = 64;
const DEFAULT_MAX_SOURCE_BYTES_PER_TENANT: usize = 256 * 1024;
const DEFAULT_MAX_CONFIG_BYTES_PER_TENANT: usize = 256 * 1024;
const DEFAULT_MAX_LIST_PAGE: usize = 32;
const DEFAULT_MAX_LIST_MATERIALIZED_BYTES: usize = 256 * 1024;
const DEFAULT_MAX_ADMIN_LIST_RESPONSE_BYTES: usize = 256 * 1024;
const DEFAULT_MAX_HTTP_LIST_RESPONSE_BYTES: usize = 256 * 1024;
const DEFAULT_MAX_COMPILED_PROGRAM_BYTES: usize = 32 * 1024 * 1024;
const DEFAULT_CLASSIFIER_PROGRAM_BYTES: usize = 48 * 1024;
const DEFAULT_ENABLED_NORMALIZATION_RULE_BYTES: usize = 64 * 1024;

/// Per-pattern compiled-program ceiling handed to the regex builder.
///
/// This is the same number [`CompiledProgramWeights::reservation_bytes`]
/// charges per classifier pattern, and that identity is the whole point: a
/// builder limit above the charged weight makes
/// `DEFAULT_MAX_COMPILED_PROGRAM_BYTES` a name rather than a bound. A 10 MiB
/// builder limit against a 48 KiB charge let one admitted pattern hold 213
/// times what the budget thought it had reserved.
pub(crate) const CLASSIFIER_PATTERN_SIZE_LIMIT: usize = DEFAULT_CLASSIFIER_PROGRAM_BYTES;

/// Per-rule compiled-program ceiling handed to the regex builder, matching
/// the weight charged per enabled normalization rule for the same reason.
pub(crate) const NORMALIZATION_RULE_SIZE_LIMIT: usize = DEFAULT_ENABLED_NORMALIZATION_RULE_BYTES;

/// Internal config used to build a [`Tenant`] from the wire-protocol
/// [`TenantConfig`].
struct TenantBuildConfig {
    labels: Vec<LabelConfig>,
    classification: ClassificationConfig,
    normalization: NormalizationConfig,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TenantPageBoundary {
    AdminTcp,
    Http,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CompiledProgramWeights {
    pub(crate) classifier_pattern_bytes: usize,
    pub(crate) enabled_normalization_rule_bytes: usize,
}

impl CompiledProgramWeights {
    pub(crate) fn reservation_bytes(
        &self,
        classifier_patterns: usize,
        enabled_normalization_rules: usize,
    ) -> usize {
        classifier_patterns
            .saturating_mul(self.classifier_pattern_bytes)
            .saturating_add(
                enabled_normalization_rules.saturating_mul(self.enabled_normalization_rule_bytes),
            )
    }
}

#[derive(Clone, Debug)]
pub(crate) struct TenantRegistryLimits {
    max_tenants: usize,
    max_patterns_per_tenant: usize,
    max_normalization_rules_per_tenant: usize,
    max_source_bytes_per_tenant: usize,
    max_config_bytes_per_tenant: usize,
    max_list_page: usize,
    max_list_materialized_bytes: usize,
    max_admin_list_response_bytes: usize,
    max_http_list_response_bytes: usize,
    max_compiled_program_bytes: usize,
    compiled_program_weights: CompiledProgramWeights,
}

impl TenantRegistryLimits {
    pub(crate) fn production_defaults() -> Self {
        Self {
            max_tenants: DEFAULT_MAX_TENANTS,
            max_patterns_per_tenant: DEFAULT_MAX_PATTERNS_PER_TENANT,
            max_normalization_rules_per_tenant: DEFAULT_MAX_NORMALIZATION_RULES_PER_TENANT,
            max_source_bytes_per_tenant: DEFAULT_MAX_SOURCE_BYTES_PER_TENANT,
            max_config_bytes_per_tenant: DEFAULT_MAX_CONFIG_BYTES_PER_TENANT,
            max_list_page: DEFAULT_MAX_LIST_PAGE,
            max_list_materialized_bytes: DEFAULT_MAX_LIST_MATERIALIZED_BYTES,
            max_admin_list_response_bytes: DEFAULT_MAX_ADMIN_LIST_RESPONSE_BYTES,
            max_http_list_response_bytes: DEFAULT_MAX_HTTP_LIST_RESPONSE_BYTES,
            max_compiled_program_bytes: DEFAULT_MAX_COMPILED_PROGRAM_BYTES,
            compiled_program_weights: CompiledProgramWeights {
                classifier_pattern_bytes: DEFAULT_CLASSIFIER_PROGRAM_BYTES,
                enabled_normalization_rule_bytes: DEFAULT_ENABLED_NORMALIZATION_RULE_BYTES,
            },
        }
    }

    #[cfg(test)]
    pub(crate) fn with_max_tenants(mut self, value: usize) -> Self {
        self.max_tenants = value;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_max_list_page(mut self, value: usize) -> Self {
        self.max_list_page = value;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_max_list_materialized_bytes(mut self, value: usize) -> Self {
        self.max_list_materialized_bytes = value;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_max_admin_list_response_bytes(mut self, value: usize) -> Self {
        self.max_admin_list_response_bytes = value;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_max_http_list_response_bytes(mut self, value: usize) -> Self {
        self.max_http_list_response_bytes = value;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_max_compiled_program_bytes(mut self, value: usize) -> Self {
        self.max_compiled_program_bytes = value;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_compiled_program_weights(mut self, weights: CompiledProgramWeights) -> Self {
        self.compiled_program_weights = weights;
        self
    }

    pub(crate) fn max_patterns_per_tenant(&self) -> usize {
        self.max_patterns_per_tenant
    }

    pub(crate) fn max_normalization_rules_per_tenant(&self) -> usize {
        self.max_normalization_rules_per_tenant
    }

    pub(crate) fn max_source_bytes_per_tenant(&self) -> usize {
        self.max_source_bytes_per_tenant
    }

    pub(crate) fn max_config_bytes_per_tenant(&self) -> usize {
        self.max_config_bytes_per_tenant
    }

    #[cfg(test)]
    pub(crate) fn with_max_config_bytes_per_tenant(mut self, value: usize) -> Self {
        self.max_config_bytes_per_tenant = value;
        self
    }

    pub(crate) fn max_list_page(&self) -> usize {
        self.max_list_page
    }

    pub(crate) fn max_list_materialized_bytes(&self) -> usize {
        self.max_list_materialized_bytes
    }

    pub(crate) fn max_admin_list_response_bytes(&self) -> usize {
        self.max_admin_list_response_bytes
    }

    pub(crate) fn max_http_list_response_bytes(&self) -> usize {
        self.max_http_list_response_bytes
    }

    pub(crate) fn compiled_program_weights(&self) -> CompiledProgramWeights {
        self.compiled_program_weights
    }
}

#[derive(Default)]
struct BudgetState {
    live_slots: usize,
    live_compiled_program_bytes: usize,
}

#[derive(Default)]
struct ReservationProbeState {
    current_bytes: usize,
    peak_bytes: usize,
}

pub(crate) struct CompiledReservationProbe {
    state: Mutex<ReservationProbeState>,
}

impl Default for CompiledReservationProbe {
    fn default() -> Self {
        Self {
            state: Mutex::new(ReservationProbeState::default()),
        }
    }
}

impl CompiledReservationProbe {
    fn acquire(&self, bytes: usize) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.current_bytes = state.current_bytes.saturating_add(bytes);
        state.peak_bytes = state.peak_bytes.max(state.current_bytes);
    }

    fn release(&self, bytes: usize) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.current_bytes = state.current_bytes.saturating_sub(bytes);
    }

    #[cfg(test)]
    pub(crate) fn current_bytes(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .current_bytes
    }

    #[cfg(test)]
    pub(crate) fn peak_bytes(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .peak_bytes
    }

    #[cfg(test)]
    pub(crate) async fn wait_for_current_bytes(
        &self,
        target: usize,
        timeout: Duration,
    ) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.current_bytes() == target {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "timed out waiting for compiled reservation bytes {target}"
                ));
            }
            sleep(Duration::from_millis(10)).await;
        }
    }
}

#[derive(Default)]
struct CompileProbeState {
    started: usize,
    completed: usize,
    classifier_programs_started: usize,
    enabled_normalizer_programs_started: usize,
    warnings_emitted: usize,
}

pub(crate) struct TenantCompileProbe {
    state: Mutex<CompileProbeState>,
}

impl Default for TenantCompileProbe {
    fn default() -> Self {
        Self {
            state: Mutex::new(CompileProbeState::default()),
        }
    }
}

impl TenantCompileProbe {
    fn record_started(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.started = state.started.saturating_add(1);
    }

    fn record_completed(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.completed = state.completed.saturating_add(1);
    }

    fn add_classifier_programs(&self, count: usize) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.classifier_programs_started = state.classifier_programs_started.saturating_add(count);
    }

    fn add_enabled_normalizer_programs(&self, count: usize) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.enabled_normalizer_programs_started = state
            .enabled_normalizer_programs_started
            .saturating_add(count);
    }

    fn add_warning(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.warnings_emitted = state.warnings_emitted.saturating_add(1);
    }

    #[cfg(test)]
    pub(crate) fn started(&self) -> usize {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).started
    }

    #[cfg(test)]
    pub(crate) fn completed(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .completed
    }

    #[cfg(test)]
    pub(crate) fn classifier_programs_started(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .classifier_programs_started
    }

    #[cfg(test)]
    pub(crate) fn enabled_normalizer_programs_started(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .enabled_normalizer_programs_started
    }

    #[cfg(test)]
    pub(crate) fn disabled_normalizer_programs_started(&self) -> usize {
        0
    }

    #[cfg(test)]
    pub(crate) fn warnings_emitted(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .warnings_emitted
    }

    #[cfg(test)]
    pub(crate) async fn wait_for_completed(
        &self,
        target: usize,
        timeout: Duration,
    ) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.completed() >= target {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("timed out waiting for completed compiles {target}"));
            }
            sleep(Duration::from_millis(10)).await;
        }
    }

    #[cfg(test)]
    pub(crate) async fn wait_for_enabled_normalizer_programs(
        &self,
        target: usize,
        timeout: Duration,
    ) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.enabled_normalizer_programs_started() >= target {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "timed out waiting for enabled normalizer programs {target}"
                ));
            }
            sleep(Duration::from_millis(10)).await;
        }
    }

    #[cfg(test)]
    pub(crate) fn forbid_compilation(&self) -> CompileSentinel<'_> {
        CompileSentinel {
            before: self.started(),
            probe: self,
        }
    }
}

#[cfg(test)]
pub(crate) struct CompileSentinel<'a> {
    before: usize,
    probe: &'a TenantCompileProbe,
}

#[cfg(test)]
impl CompileSentinel<'_> {
    #[cfg(test)]
    pub(crate) fn assert_not_triggered(&self) {
        assert_eq!(self.probe.started(), self.before);
    }
}

#[derive(Default)]
struct TenantListBoundaryStats {
    response_admissions: usize,
    response_admission_refusals: usize,
    page_serializations: usize,
    lifetime_materialized_entries: usize,
    lifetime_materialized_bytes: usize,
    lifetime_string_clones: usize,
    lifetime_materializations_without_response_admission: usize,
    lifetime_string_clones_without_response_admission: usize,
    current_window_materialized_entries: usize,
    current_window_materialized_bytes: usize,
    peak_materialized_entries: usize,
    peak_materialized_bytes: usize,
    total_materialized_entries: usize,
    total_materialized_bytes: usize,
    materializations_without_page_budget: usize,
    page_budget_acquired_in_window: bool,
    response_admitted_in_window: bool,
}

#[derive(Default)]
struct TenantListProbeState {
    admin_tcp: TenantListBoundaryStats,
    http: TenantListBoundaryStats,
}

pub(crate) struct TenantListProbe {
    state: Mutex<TenantListProbeState>,
}

impl Default for TenantListProbe {
    fn default() -> Self {
        Self {
            state: Mutex::new(TenantListProbeState::default()),
        }
    }
}

impl TenantListProbe {
    fn boundary_mut(
        state: &mut TenantListProbeState,
        boundary: TenantPageBoundary,
    ) -> &mut TenantListBoundaryStats {
        match boundary {
            TenantPageBoundary::AdminTcp => &mut state.admin_tcp,
            TenantPageBoundary::Http => &mut state.http,
        }
    }

    #[cfg(test)]
    fn boundary_ref(
        state: &TenantListProbeState,
        boundary: TenantPageBoundary,
    ) -> &TenantListBoundaryStats {
        match boundary {
            TenantPageBoundary::AdminTcp => &state.admin_tcp,
            TenantPageBoundary::Http => &state.http,
        }
    }

    fn record_page_budget_acquired(&self, boundary: TenantPageBoundary) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let stats = Self::boundary_mut(&mut state, boundary);
        stats.current_window_materialized_entries = 0;
        stats.current_window_materialized_bytes = 0;
        stats.page_budget_acquired_in_window = true;
        stats.response_admitted_in_window = false;
    }

    fn record_response_admission(&self, boundary: TenantPageBoundary) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let stats = Self::boundary_mut(&mut state, boundary);
        stats.response_admissions = stats.response_admissions.saturating_add(1);
        stats.response_admitted_in_window = true;
    }

    fn record_response_admission_refusal(&self, boundary: TenantPageBoundary) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let stats = Self::boundary_mut(&mut state, boundary);
        stats.response_admission_refusals = stats.response_admission_refusals.saturating_add(1);
    }

    fn record_page_serialization(&self, boundary: TenantPageBoundary) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let stats = Self::boundary_mut(&mut state, boundary);
        stats.page_serializations = stats.page_serializations.saturating_add(1);
    }

    fn record_string_clone(&self, boundary: TenantPageBoundary, count: usize) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let stats = Self::boundary_mut(&mut state, boundary);
        stats.lifetime_string_clones = stats.lifetime_string_clones.saturating_add(count);
        if !stats.response_admitted_in_window {
            stats.lifetime_string_clones_without_response_admission = stats
                .lifetime_string_clones_without_response_admission
                .saturating_add(count);
        }
    }

    fn record_materialized_entry(&self, boundary: TenantPageBoundary, persistent_bytes: usize) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let stats = Self::boundary_mut(&mut state, boundary);
        stats.lifetime_materialized_entries = stats.lifetime_materialized_entries.saturating_add(1);
        stats.lifetime_materialized_bytes = stats
            .lifetime_materialized_bytes
            .saturating_add(persistent_bytes);
        stats.current_window_materialized_entries =
            stats.current_window_materialized_entries.saturating_add(1);
        stats.current_window_materialized_bytes = stats
            .current_window_materialized_bytes
            .saturating_add(persistent_bytes);
        stats.total_materialized_entries = stats.total_materialized_entries.saturating_add(1);
        stats.total_materialized_bytes = stats
            .total_materialized_bytes
            .saturating_add(persistent_bytes);
        stats.peak_materialized_entries = stats
            .peak_materialized_entries
            .max(stats.current_window_materialized_entries);
        stats.peak_materialized_bytes = stats
            .peak_materialized_bytes
            .max(stats.current_window_materialized_bytes);
        if !stats.page_budget_acquired_in_window {
            stats.materializations_without_page_budget =
                stats.materializations_without_page_budget.saturating_add(1);
        }
        if !stats.response_admitted_in_window {
            stats.lifetime_materializations_without_response_admission = stats
                .lifetime_materializations_without_response_admission
                .saturating_add(1);
        }
    }

    #[cfg(test)]
    pub(crate) fn lifetime_response_admissions(&self, boundary: TenantPageBoundary) -> usize {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Self::boundary_ref(&state, boundary).response_admissions
    }

    #[cfg(test)]
    pub(crate) fn lifetime_response_admission_refusals(
        &self,
        boundary: TenantPageBoundary,
    ) -> usize {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Self::boundary_ref(&state, boundary).response_admission_refusals
    }

    #[cfg(test)]
    pub(crate) fn page_serializations(&self, boundary: TenantPageBoundary) -> usize {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Self::boundary_ref(&state, boundary).page_serializations
    }

    #[cfg(test)]
    pub(crate) fn lifetime_materialized_entries(&self, boundary: TenantPageBoundary) -> usize {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Self::boundary_ref(&state, boundary).lifetime_materialized_entries
    }

    #[cfg(test)]
    #[cfg(test)]
    pub(crate) fn lifetime_string_clones(&self, boundary: TenantPageBoundary) -> usize {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Self::boundary_ref(&state, boundary).lifetime_string_clones
    }

    #[cfg(test)]
    pub(crate) fn lifetime_materializations_without_response_admission(
        &self,
        boundary: TenantPageBoundary,
    ) -> usize {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Self::boundary_ref(&state, boundary).lifetime_materializations_without_response_admission
    }

    #[cfg(test)]
    pub(crate) fn lifetime_string_clones_without_response_admission(
        &self,
        boundary: TenantPageBoundary,
    ) -> usize {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Self::boundary_ref(&state, boundary).lifetime_string_clones_without_response_admission
    }

    #[cfg(test)]
    pub(crate) fn peak_materialized_entries(&self, boundary: TenantPageBoundary) -> usize {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Self::boundary_ref(&state, boundary).peak_materialized_entries
    }

    #[cfg(test)]
    pub(crate) fn peak_materialized_bytes(&self, boundary: TenantPageBoundary) -> usize {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Self::boundary_ref(&state, boundary).peak_materialized_bytes
    }

    #[cfg(test)]
    pub(crate) fn total_materialized_entries(&self, boundary: TenantPageBoundary) -> usize {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Self::boundary_ref(&state, boundary).total_materialized_entries
    }

    #[cfg(test)]
    pub(crate) fn total_materialized_bytes(&self, boundary: TenantPageBoundary) -> usize {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Self::boundary_ref(&state, boundary).total_materialized_bytes
    }

    #[cfg(test)]
    pub(crate) fn materializations_without_page_budget(
        &self,
        boundary: TenantPageBoundary,
    ) -> usize {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Self::boundary_ref(&state, boundary).materializations_without_page_budget
    }

    #[cfg(test)]
    pub(crate) fn forbid_page_serialization(
        &self,
        boundary: TenantPageBoundary,
    ) -> ListSentinel<'_> {
        ListSentinel {
            before: self.page_serializations(boundary),
            boundary,
            probe: self,
            reader: ListCounter::Serializations,
        }
    }

    #[cfg(test)]
    pub(crate) fn forbid_page_materialization(
        &self,
        boundary: TenantPageBoundary,
    ) -> ListSentinel<'_> {
        ListSentinel {
            before: self.lifetime_materialized_entries(boundary),
            boundary,
            probe: self,
            reader: ListCounter::Materializations,
        }
    }

    #[cfg(test)]
    pub(crate) fn reset_materialization(&self, boundary: TenantPageBoundary) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let stats = Self::boundary_mut(&mut state, boundary);
        stats.current_window_materialized_entries = 0;
        stats.current_window_materialized_bytes = 0;
        stats.peak_materialized_entries = 0;
        stats.peak_materialized_bytes = 0;
        stats.total_materialized_entries = 0;
        stats.total_materialized_bytes = 0;
        stats.materializations_without_page_budget = 0;
        stats.page_budget_acquired_in_window = false;
        stats.response_admitted_in_window = false;
    }
}

#[cfg(test)]
enum ListCounter {
    Serializations,
    Materializations,
}

#[cfg(test)]
pub(crate) struct ListSentinel<'a> {
    before: usize,
    boundary: TenantPageBoundary,
    probe: &'a TenantListProbe,
    reader: ListCounter,
}

#[cfg(test)]
impl ListSentinel<'_> {
    #[cfg(test)]
    pub(crate) fn assert_not_triggered(&self) {
        let current = match self.reader {
            ListCounter::Serializations => self.probe.page_serializations(self.boundary),
            ListCounter::Materializations => {
                self.probe.lifetime_materialized_entries(self.boundary)
            }
        };
        assert_eq!(current, self.before);
    }
}

#[derive(Clone)]
pub(crate) struct TenantRegistryBudget {
    limits: TenantRegistryLimits,
    state: Arc<Mutex<BudgetState>>,
    list_probe: Option<Arc<TenantListProbe>>,
    reservation_probe: Option<Arc<CompiledReservationProbe>>,
}

impl TenantRegistryBudget {
    #[cfg(test)]
    pub(crate) fn new(limits: TenantRegistryLimits) -> Result<Self, String> {
        if limits.max_tenants == 0 {
            return Err("registry max_tenants must be positive".to_string());
        }
        if limits.max_list_page == 0 {
            return Err("registry max_list_page must be positive".to_string());
        }
        Ok(Self {
            limits,
            state: Arc::new(Mutex::new(BudgetState::default())),
            list_probe: None,
            reservation_probe: None,
        })
    }

    pub(crate) fn production_defaults() -> Self {
        Self {
            limits: TenantRegistryLimits::production_defaults(),
            state: Arc::new(Mutex::new(BudgetState::default())),
            list_probe: None,
            reservation_probe: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_test_list_probe(mut self, probe: Arc<TenantListProbe>) -> Self {
        self.list_probe = Some(probe);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_test_reservation_probe(
        mut self,
        probe: Arc<CompiledReservationProbe>,
    ) -> Self {
        self.reservation_probe = Some(probe);
        self
    }

    fn limits(&self) -> &TenantRegistryLimits {
        &self.limits
    }

    fn list_probe(&self) -> Option<&Arc<TenantListProbe>> {
        self.list_probe.as_ref()
    }

    fn acquire_slot(&self) -> Result<Arc<TenantSlotReservation>, String> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.live_slots >= self.limits.max_tenants {
            return Err(format!(
                "tenant registry is at its {}-tenant limit",
                self.limits.max_tenants
            ));
        }
        state.live_slots = state.live_slots.saturating_add(1);
        drop(state);
        Ok(Arc::new(TenantSlotReservation {
            state: Arc::clone(&self.state),
        }))
    }

    fn acquire_compiled_program_bytes(
        &self,
        bytes: usize,
    ) -> Result<Arc<CompiledProgramReservation>, String> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let next = state.live_compiled_program_bytes.saturating_add(bytes);
        if next > self.limits.max_compiled_program_bytes {
            return Err(format!(
                "compiled program budget would exceed {} bytes",
                self.limits.max_compiled_program_bytes
            ));
        }
        state.live_compiled_program_bytes = next;
        drop(state);
        if let Some(probe) = &self.reservation_probe {
            probe.acquire(bytes);
        }
        Ok(Arc::new(CompiledProgramReservation {
            state: Arc::clone(&self.state),
            bytes,
            probe: self.reservation_probe.clone(),
        }))
    }
}

struct TenantSlotReservation {
    state: Arc<Mutex<BudgetState>>,
}

impl Drop for TenantSlotReservation {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.live_slots = state.live_slots.saturating_sub(1);
    }
}

struct CompiledProgramReservation {
    state: Arc<Mutex<BudgetState>>,
    bytes: usize,
    probe: Option<Arc<CompiledReservationProbe>>,
}

impl Drop for CompiledProgramReservation {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.live_compiled_program_bytes =
            state.live_compiled_program_bytes.saturating_sub(self.bytes);
        drop(state);
        if let Some(probe) = &self.probe {
            probe.release(self.bytes);
        }
    }
}

struct PendingTenantSlot {
    slot_reservation: Arc<TenantSlotReservation>,
    in_flight_attempts: AtomicUsize,
}

impl PendingTenantSlot {
    fn new(slot_reservation: Arc<TenantSlotReservation>) -> Self {
        Self {
            slot_reservation,
            in_flight_attempts: AtomicUsize::new(1),
        }
    }
}

struct PendingSlotGuard {
    pending_first_registrations: Arc<Mutex<BTreeMap<String, Arc<PendingTenantSlot>>>>,
    tenant_id: String,
    pending_slot: Arc<PendingTenantSlot>,
}

impl PendingSlotGuard {
    fn new(
        pending_first_registrations: Arc<Mutex<BTreeMap<String, Arc<PendingTenantSlot>>>>,
        tenant_id: &str,
        pending_slot: Arc<PendingTenantSlot>,
    ) -> Self {
        Self {
            pending_first_registrations,
            tenant_id: tenant_id.to_string(),
            pending_slot,
        }
    }
}

impl Drop for PendingSlotGuard {
    fn drop(&mut self) {
        let remaining = self
            .pending_slot
            .in_flight_attempts
            .fetch_sub(1, Ordering::AcqRel)
            .saturating_sub(1);
        if remaining != 0 {
            return;
        }
        let mut pending = self
            .pending_first_registrations
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if pending
            .get(&self.tenant_id)
            .is_some_and(|existing| Arc::ptr_eq(existing, &self.pending_slot))
            && self.pending_slot.in_flight_attempts.load(Ordering::Acquire) == 0
        {
            pending.remove(&self.tenant_id);
        }
    }
}

#[derive(Clone)]
pub(crate) struct TenantCompiler {
    workers: Arc<CompilerWorkerGate>,
    probe: Option<Arc<TenantCompileProbe>>,
}

impl TenantCompiler {
    #[cfg(test)]
    pub(crate) fn bounded(workers: usize) -> Result<Self, String> {
        if workers == 0 {
            return Err("tenant compiler requires at least one worker".to_string());
        }
        Ok(Self {
            workers: Arc::new(CompilerWorkerGate::new(workers)),
            probe: None,
        })
    }

    pub(crate) fn production_defaults() -> Self {
        Self {
            workers: Arc::new(CompilerWorkerGate::new(1)),
            probe: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_test_probe(mut self, probe: Arc<TenantCompileProbe>) -> Self {
        self.probe = Some(probe);
        self
    }

    #[cfg(test)]
    fn compile(&self, build: &TenantBuildConfig) -> Result<CompiledTenantArtifacts, String> {
        let _permit = self.workers.acquire_blocking();
        self.compile_borrowed(build)
    }

    fn compile_borrowed(
        &self,
        build: &TenantBuildConfig,
    ) -> Result<CompiledTenantArtifacts, String> {
        let (compiled_labels, compiled_rules) =
            compile_enabled_regexes(build, self.probe.as_deref())?;

        let classifier_patterns = build
            .labels
            .iter()
            .map(|label| label.patterns.len())
            .sum::<usize>();
        let enabled_normalization_rules = compiled_rules.len();

        if let Some(probe) = &self.probe {
            probe.record_started();
            probe.add_classifier_programs(classifier_patterns);
            probe.add_enabled_normalizer_programs(enabled_normalization_rules);
        }

        let classifier = Classifier::from_compiled(
            compiled_labels,
            build.classification.confidence_threshold,
            &build.classification.default_label,
            build.classification.default_boost,
        );
        let label_names = classifier.label_names();
        let normalizer = Normalizer::from_compiled(
            build.normalization.unicode_nfkc,
            build.normalization.trim,
            compiled_rules,
        );

        if let Some(probe) = &self.probe {
            probe.record_completed();
        }

        Ok(CompiledTenantArtifacts {
            classifier,
            normalizer,
            label_names,
        })
    }

    async fn compile_async(
        &self,
        build: TenantBuildConfig,
    ) -> Result<CompiledTenantArtifacts, String> {
        let permit = self.workers.acquire().await;
        let compiler = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            compiler.compile_borrowed(&build)
        })
        .await
        .map_err(|_| "tenant compiler worker failed".to_string())?
    }
}

struct CompiledTenantArtifacts {
    classifier: Classifier,
    normalizer: Normalizer,
    label_names: Vec<String>,
}

struct CompilerWorkerGate {
    max_workers: usize,
    state: Mutex<CompilerWorkerState>,
    wake: Condvar,
    notify: tokio::sync::Notify,
}

#[derive(Default)]
struct CompilerWorkerState {
    in_use: usize,
}

impl CompilerWorkerGate {
    fn new(max_workers: usize) -> Self {
        Self {
            max_workers,
            state: Mutex::new(CompilerWorkerState::default()),
            wake: Condvar::new(),
            notify: tokio::sync::Notify::new(),
        }
    }

    #[cfg(test)]
    fn acquire_blocking(self: &Arc<Self>) -> CompilerWorkerPermit {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        while state.in_use >= self.max_workers {
            state = self.wake.wait(state).unwrap_or_else(|e| e.into_inner());
        }
        state.in_use = state.in_use.saturating_add(1);
        drop(state);
        CompilerWorkerPermit {
            gate: Arc::clone(self),
        }
    }

    async fn acquire(self: &Arc<Self>) -> CompilerWorkerPermit {
        loop {
            let notified = self.notify.notified();
            {
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if state.in_use < self.max_workers {
                    state.in_use = state.in_use.saturating_add(1);
                    return CompilerWorkerPermit {
                        gate: Arc::clone(self),
                    };
                }
            }
            notified.await;
        }
    }

    fn release(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.in_use = state.in_use.saturating_sub(1);
        drop(state);
        self.wake.notify_one();
        self.notify.notify_waiters();
    }
}

struct CompilerWorkerPermit {
    gate: Arc<CompilerWorkerGate>,
}

impl Drop for CompilerWorkerPermit {
    fn drop(&mut self) {
        self.gate.release();
    }
}

struct PendingTenantRegistration {
    build: TenantBuildConfig,
    slot_reservation: Arc<TenantSlotReservation>,
    slot_was_new: bool,
    pending_slot_guard: Option<PendingSlotGuard>,
    compiled_reservation: Arc<CompiledProgramReservation>,
}

/// A compiled tenant with its own classifier and normalizer.
pub(crate) struct Tenant {
    pub(crate) classifier: Classifier,
    pub(crate) normalizer: Normalizer,
    pub(crate) label_names: Vec<String>,
    slot_reservation: Arc<TenantSlotReservation>,
    _compiled_reservation: Arc<CompiledProgramReservation>,
}

/// Thread-safe registry of tenant configs.
pub(crate) struct Registry {
    tenants: RwLock<BTreeMap<String, Arc<Tenant>>>,
    pending_first_registrations: Arc<Mutex<BTreeMap<String, Arc<PendingTenantSlot>>>>,
    budget: TenantRegistryBudget,
    compiler: TenantCompiler,
}

impl Default for Registry {
    fn default() -> Self {
        Self::new_empty()
    }
}

impl Registry {
    /// Create an empty registry. Tenants are registered at runtime.
    pub(crate) fn new_empty() -> Self {
        let budget = TenantRegistryBudget::production_defaults();
        let compiler = TenantCompiler::production_defaults();
        Self::new(budget, compiler)
    }

    pub(crate) fn new(budget: TenantRegistryBudget, compiler: TenantCompiler) -> Self {
        Self {
            tenants: RwLock::new(BTreeMap::new()),
            pending_first_registrations: Arc::new(Mutex::new(BTreeMap::new())),
            budget,
            compiler,
        }
    }

    /// Look up a tenant by id. Returns `None` if the tenant is not
    /// registered, or if `tenant_id` is absent/empty.
    pub(crate) fn get(&self, tenant_id: Option<&str>) -> Option<Arc<Tenant>> {
        match tenant_id {
            Some(id) if !id.is_empty() => {
                let tenants = self.tenants.read().unwrap_or_else(|e| e.into_inner());
                tenants.get(id).cloned()
            }
            _ => {
                debug!("classify request with no tenant id");
                None
            }
        }
    }

    /// Register or update a tenant from an inline config. Compiles regex
    /// patterns immediately, so subsequent classify requests are fast.
    #[cfg(test)]
    pub(crate) fn register(
        &self,
        tenant_id: &str,
        tenant_config: &TenantConfig,
    ) -> Result<(), String> {
        let pending = self.prepare_registration(tenant_id, tenant_config)?;
        let compiled = self.compiler.compile(&pending.build)?;
        self.commit_registration(
            tenant_id,
            pending.slot_reservation,
            pending.slot_was_new,
            pending.pending_slot_guard,
            pending.compiled_reservation,
            compiled,
        )
    }

    /// Register without compiling regex programs on an async runtime worker.
    /// Capacity is reserved before config cloning, queueing, or compilation.
    pub(crate) async fn register_async(
        &self,
        tenant_id: &str,
        tenant_config: &TenantConfig,
    ) -> Result<(), String> {
        let pending = self.prepare_registration(tenant_id, tenant_config)?;
        let PendingTenantRegistration {
            build,
            slot_reservation,
            slot_was_new,
            pending_slot_guard,
            compiled_reservation,
        } = pending;
        let compiled = self.compiler.compile_async(build).await?;
        self.commit_registration(
            tenant_id,
            slot_reservation,
            slot_was_new,
            pending_slot_guard,
            compiled_reservation,
            compiled,
        )
    }

    /// Remove a tenant. Future requests for this tenant id are refused
    /// (there is no fallback tenant).
    pub(crate) fn delete(&self, tenant_id: &str) -> bool {
        let mut tenants = self.tenants.write().unwrap_or_else(|e| e.into_inner());
        let existed = tenants.remove(tenant_id).is_some();
        if existed {
            info!(
                tenant = %crate::tcp::sanitize(tenant_id, MAX_TENANT_ID_BYTES),
                "deleted tenant"
            );
        }
        existed
    }

    /// List all registered tenants in deterministic key order.
    #[cfg(test)]
    pub(crate) fn list(&self) -> Vec<TenantInfo> {
        let tenants = self.tenants.read().unwrap_or_else(|e| e.into_inner());
        tenants
            .iter()
            .map(|(id, tenant)| TenantInfo {
                id: id.clone(),
                labels: tenant.label_names.clone(),
            })
            .collect()
    }

    /// Build one visible page, admitting response bytes before any String
    /// clones for the page payload.
    #[cfg(test)]
    pub(crate) fn list_page<I, S>(
        &self,
        boundary: TenantPageBoundary,
        visible_tenants: I,
        page_size: usize,
        cursor: Option<&str>,
    ) -> Result<TenantPage, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let visible = visible_tenants
            .into_iter()
            .map(|tenant| tenant.as_ref().to_string())
            .collect::<BTreeSet<_>>();
        self.list_page_where(boundary, page_size, cursor, |tenant| {
            visible.contains(tenant)
        })
    }

    /// Build one visible page without first cloning or materializing the
    /// complete registry. The visibility predicate is evaluated against
    /// borrowed, ordered tenant ids while the registry read lock is held.
    pub(crate) fn list_page_where<F>(
        &self,
        boundary: TenantPageBoundary,
        page_size: usize,
        cursor: Option<&str>,
        mut is_visible: F,
    ) -> Result<TenantPage, String>
    where
        F: FnMut(&str) -> bool,
    {
        if page_size == 0 || page_size > self.budget.limits().max_list_page() {
            return Err(format!(
                "page_size must be in 1..={}",
                self.budget.limits().max_list_page()
            ));
        }

        let probe = self.budget.list_probe().cloned();
        if let Some(probe) = &probe {
            probe.record_page_budget_acquired(boundary);
        }

        let tenants = self.tenants.read().unwrap_or_else(|e| e.into_inner());
        let mut borrowed = Vec::with_capacity(page_size.saturating_add(1));
        let range = match cursor {
            Some(cursor) => tenants.range::<str, _>((Excluded(cursor), Unbounded)),
            None => tenants.range::<str, _>((Unbounded, Unbounded)),
        };
        for (tenant_id, tenant) in range {
            if !is_visible(tenant_id) {
                continue;
            }
            borrowed.push(BorrowedTenantProjection {
                id: tenant_id.as_str(),
                labels: &tenant.label_names,
            });
            if borrowed.len() > page_size {
                break;
            }
        }
        let has_more = borrowed.len() > page_size;
        if has_more {
            borrowed.pop();
        }
        let next_cursor = has_more
            .then(|| borrowed.last().map(|tenant| tenant.id))
            .flatten();

        let response_bytes = match boundary {
            TenantPageBoundary::AdminTcp => estimated_admin_response_bytes(&borrowed, next_cursor)?,
            TenantPageBoundary::Http => estimated_http_response_bytes(&borrowed, next_cursor)?,
        };
        let response_limit = match boundary {
            TenantPageBoundary::AdminTcp => self.budget.limits().max_admin_list_response_bytes(),
            TenantPageBoundary::Http => self.budget.limits().max_http_list_response_bytes(),
        };
        if response_bytes > response_limit {
            if let Some(probe) = &probe {
                probe.record_response_admission_refusal(boundary);
            }
            return Err(format!(
                "tenant page exceeds the {response_limit}-byte {:?} response budget",
                boundary
            ));
        }

        let materialized_bytes = borrowed
            .iter()
            .map(|tenant| tenant.id.len() + tenant.labels.iter().map(String::len).sum::<usize>())
            .sum::<usize>();
        if materialized_bytes > self.budget.limits().max_list_materialized_bytes() {
            if let Some(probe) = &probe {
                probe.record_response_admission_refusal(boundary);
            }
            return Err(format!(
                "tenant page exceeds the {}-byte materialization budget",
                self.budget.limits().max_list_materialized_bytes()
            ));
        }
        if let Some(probe) = &probe {
            probe.record_response_admission(boundary);
            probe.record_page_serialization(boundary);
        }

        let mut materialized = Vec::with_capacity(borrowed.len());
        for tenant in borrowed {
            let id = tenant.id.to_string();
            if let Some(probe) = &probe {
                probe.record_string_clone(boundary, 1);
            }
            let mut labels = Vec::with_capacity(tenant.labels.len());
            for label in tenant.labels {
                labels.push(label.clone());
                if let Some(probe) = &probe {
                    probe.record_string_clone(boundary, 1);
                }
            }
            let persistent_bytes = id.len() + labels.iter().map(String::len).sum::<usize>();
            if let Some(probe) = &probe {
                probe.record_materialized_entry(boundary, persistent_bytes);
            }
            materialized.push(TenantInfo { id, labels });
        }

        Ok(TenantPage {
            tenants: materialized,
            next_cursor: next_cursor.map(str::to_string),
        })
    }

    /// Number of currently registered tenants.
    pub(crate) fn tenant_count(&self) -> usize {
        self.tenants.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    #[cfg(test)]
    pub(crate) fn snapshot_ids(&self) -> BTreeSet<String> {
        self.tenants
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect()
    }

    fn prepare_registration(
        &self,
        tenant_id: &str,
        tenant_config: &TenantConfig,
    ) -> Result<PendingTenantRegistration, String> {
        validate_tenant_id(tenant_id)?;
        let (classifier_patterns, enabled_normalization_rules) =
            self.validate_config_shape(tenant_config)?;
        let (slot_reservation, slot_was_new, pending_slot_guard) = {
            let tenants = self.tenants.read().unwrap_or_else(|e| e.into_inner());
            match tenants.get(tenant_id) {
                Some(existing) => (Arc::clone(&existing.slot_reservation), false, None),
                None => {
                    let mut pending = self
                        .pending_first_registrations
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    match pending.get(tenant_id) {
                        Some(existing) => {
                            existing.in_flight_attempts.fetch_add(1, Ordering::AcqRel);
                            (
                                Arc::clone(&existing.slot_reservation),
                                false,
                                Some(PendingSlotGuard::new(
                                    Arc::clone(&self.pending_first_registrations),
                                    tenant_id,
                                    Arc::clone(existing),
                                )),
                            )
                        }
                        None => {
                            let slot_reservation = self.budget.acquire_slot()?;
                            let pending_slot =
                                Arc::new(PendingTenantSlot::new(Arc::clone(&slot_reservation)));
                            pending.insert(tenant_id.to_string(), Arc::clone(&pending_slot));
                            let guard = PendingSlotGuard::new(
                                Arc::clone(&self.pending_first_registrations),
                                tenant_id,
                                pending_slot,
                            );
                            (slot_reservation, true, Some(guard))
                        }
                    }
                }
            }
        };
        let compiled_bytes = self
            .budget
            .limits()
            .compiled_program_weights()
            .reservation_bytes(classifier_patterns, enabled_normalization_rules);
        let compiled_reservation = self.budget.acquire_compiled_program_bytes(compiled_bytes)?;
        let build = Self::tenant_config_to_build(tenant_config)?;
        Ok(PendingTenantRegistration {
            build,
            slot_reservation,
            slot_was_new,
            pending_slot_guard,
            compiled_reservation,
        })
    }

    fn commit_registration(
        &self,
        tenant_id: &str,
        mut slot_reservation: Arc<TenantSlotReservation>,
        slot_was_new: bool,
        _pending_slot_guard: Option<PendingSlotGuard>,
        compiled_reservation: Arc<CompiledProgramReservation>,
        compiled: CompiledTenantArtifacts,
    ) -> Result<(), String> {
        let mut tenants = self.tenants.write().unwrap_or_else(|e| e.into_inner());
        // Two concurrent first registrations for the same id share one pending
        // slot reservation until a committed tenant exists.
        if slot_was_new {
            if let Some(existing) = tenants.get(tenant_id) {
                slot_reservation = Arc::clone(&existing.slot_reservation);
            }
        }
        info!(
            tenant = %crate::tcp::sanitize(tenant_id, MAX_TENANT_ID_BYTES),
            labels = compiled.label_names.len(),
            "registered tenant"
        );
        tenants.insert(
            tenant_id.to_string(),
            Arc::new(Tenant {
                classifier: compiled.classifier,
                normalizer: compiled.normalizer,
                label_names: compiled.label_names,
                slot_reservation,
                _compiled_reservation: compiled_reservation,
            }),
        );
        Ok(())
    }

    fn validate_config_shape(
        &self,
        tenant_config: &TenantConfig,
    ) -> Result<(usize, usize), String> {
        if tenant_config.labels.is_empty() {
            return Err("tenant config must have at least one label".to_string());
        }
        let pattern_count = tenant_config
            .labels
            .iter()
            .map(|label| label.patterns.len())
            .sum::<usize>();
        if pattern_count > self.budget.limits().max_patterns_per_tenant() {
            return Err(format!(
                "tenant config exceeds the {} aggregate-pattern limit",
                self.budget.limits().max_patterns_per_tenant()
            ));
        }
        let rule_count = tenant_config
            .normalization
            .as_ref()
            .map_or(0, |normalization| normalization.rules.len());
        if rule_count > self.budget.limits().max_normalization_rules_per_tenant() {
            return Err(format!(
                "tenant config exceeds the {} normalization-rule limit",
                self.budget.limits().max_normalization_rules_per_tenant()
            ));
        }
        let source_bytes = tenant_config
            .labels
            .iter()
            .flat_map(|label| label.patterns.iter())
            .map(String::len)
            .sum::<usize>()
            + tenant_config
                .normalization
                .iter()
                .flat_map(|normalization| normalization.rules.iter())
                .map(|rule| rule.pattern.len() + rule.replace.len())
                .sum::<usize>();
        if source_bytes > self.budget.limits().max_source_bytes_per_tenant() {
            return Err(format!(
                "tenant config exceeds the {}-byte source limit",
                self.budget.limits().max_source_bytes_per_tenant()
            ));
        }
        let config_bytes = encoded_messagepack_len(tenant_config)?;
        if config_bytes > self.budget.limits().max_config_bytes_per_tenant() {
            return Err(format!(
                "tenant config exceeds the {}-byte encoded limit",
                self.budget.limits().max_config_bytes_per_tenant()
            ));
        }
        let enabled_rule_count = tenant_config
            .normalization
            .as_ref()
            .map_or(0, |normalization| {
                normalization
                    .rules
                    .iter()
                    .filter(|rule| rule.enabled)
                    .count()
            });
        Ok((pattern_count, enabled_rule_count))
    }

    fn tenant_config_to_build(tc: &TenantConfig) -> Result<TenantBuildConfig, String> {
        if tc.labels.is_empty() {
            return Err("tenant config must have at least one label".to_string());
        }

        let labels = tc
            .labels
            .iter()
            .map(|label| LabelConfig {
                name: label.name.clone(),
                patterns: label.patterns.clone(),
                weight: label.weight,
            })
            .collect();

        let classification = match &tc.classification {
            Some(classification) => ClassificationConfig {
                confidence_threshold: classification.confidence_threshold,
                default_label: classification.default_label.clone(),
                default_boost: classification.default_boost,
            },
            None => ClassificationConfig::default(),
        };

        let normalization = match &tc.normalization {
            Some(normalization) => NormalizationConfig {
                unicode_nfkc: normalization.unicode_nfkc,
                trim: normalization.trim,
                rules: normalization
                    .rules
                    .iter()
                    .map(|rule| NormalizationRule {
                        name: rule.name.clone(),
                        pattern: rule.pattern.clone(),
                        replace: rule.replace.clone(),
                        enabled: rule.enabled,
                    })
                    .collect(),
            },
            None => NormalizationConfig::default(),
        };

        Ok(TenantBuildConfig {
            labels,
            classification,
            normalization,
        })
    }
}

#[derive(Debug)]
pub(crate) struct TenantPage {
    pub(crate) tenants: Vec<TenantInfo>,
    pub(crate) next_cursor: Option<String>,
}

impl TenantPage {
    pub(crate) fn into_admin_response(self) -> AdminResponse {
        AdminResponse {
            ok: true,
            cmd: "list".to_string(),
            tenant: None,
            error: None,
            tenants: Some(self.tenants),
            next_cursor: self.next_cursor,
        }
    }

    pub(crate) fn into_http_response(self) -> TenantPageResponse {
        TenantPageResponse {
            tenants: self.tenants,
            next_cursor: self.next_cursor,
        }
    }
}

struct BorrowedTenantProjection<'a> {
    id: &'a str,
    labels: &'a [String],
}

#[derive(Default)]
struct CountingWriter {
    bytes: usize,
}

impl std::io::Write for CountingWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(buffer.len())
            .ok_or_else(|| std::io::Error::other("serialized length overflow"))?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn encoded_messagepack_len<T: Serialize>(value: &T) -> Result<usize, String> {
    let mut writer = CountingWriter::default();
    rmp_serde::encode::write_named(&mut writer, value)
        .map_err(|error| format!("tenant page serialization failed: {error}"))?;
    Ok(writer.bytes)
}

#[cfg(test)]
fn encoded_json_len<T: Serialize>(value: &T) -> Result<usize, String> {
    let mut writer = CountingWriter::default();
    serde_json::to_writer(&mut writer, value)
        .map_err(|error| format!("tenant page serialization failed: {error}"))?;
    Ok(writer.bytes)
}

fn checked_length_add(total: &mut usize, addend: usize) -> Result<(), String> {
    *total = total
        .checked_add(addend)
        .ok_or_else(|| "tenant page size estimation overflow".to_string())?;
    Ok(())
}

fn json_string_len(value: &str) -> usize {
    let mut total = 2usize;
    for ch in value.chars() {
        total += match ch {
            '"' | '\\' => 2,
            '\u{08}' | '\u{0C}' | '\n' | '\r' | '\t' => 2,
            '\u{00}'..='\u{1F}' => 6,
            _ => ch.len_utf8(),
        };
    }
    total
}

fn estimated_http_labels_bytes(labels: &[String]) -> Result<usize, String> {
    let mut total = 1usize;
    for (index, label) in labels.iter().enumerate() {
        if index != 0 {
            checked_length_add(&mut total, 1)?;
        }
        checked_length_add(&mut total, json_string_len(label))?;
    }
    checked_length_add(&mut total, 1)?;
    Ok(total)
}

fn estimated_http_tenant_bytes(tenant: &BorrowedTenantProjection<'_>) -> Result<usize, String> {
    let mut total = "{\"id\":".len();
    checked_length_add(&mut total, json_string_len(tenant.id))?;
    checked_length_add(&mut total, ",\"labels\":".len())?;
    checked_length_add(&mut total, estimated_http_labels_bytes(tenant.labels)?)?;
    checked_length_add(&mut total, "}".len())?;
    Ok(total)
}

fn estimated_http_response_bytes(
    borrowed: &[BorrowedTenantProjection<'_>],
    next_cursor: Option<&str>,
) -> Result<usize, String> {
    let mut total = "{\"tenants\":[".len();
    for (index, tenant) in borrowed.iter().enumerate() {
        if index != 0 {
            checked_length_add(&mut total, 1)?;
        }
        checked_length_add(&mut total, estimated_http_tenant_bytes(tenant)?)?;
    }
    checked_length_add(&mut total, "]".len())?;
    if let Some(cursor) = next_cursor {
        checked_length_add(&mut total, ",\"next_cursor\":".len())?;
        checked_length_add(&mut total, json_string_len(cursor))?;
    }
    checked_length_add(&mut total, "}".len())?;
    Ok(total)
}

fn msgpack_map_prefix_len(entries: usize) -> Result<usize, String> {
    if entries <= 15 {
        Ok(1)
    } else if u16::try_from(entries).is_ok() {
        Ok(3)
    } else if u32::try_from(entries).is_ok() {
        Ok(5)
    } else {
        Err("tenant page size estimation overflow".to_string())
    }
}

fn msgpack_array_prefix_len(entries: usize) -> Result<usize, String> {
    if entries <= 15 {
        Ok(1)
    } else if u16::try_from(entries).is_ok() {
        Ok(3)
    } else if u32::try_from(entries).is_ok() {
        Ok(5)
    } else {
        Err("tenant page size estimation overflow".to_string())
    }
}

fn msgpack_str_len(value: &str) -> Result<usize, String> {
    let bytes = value.len();
    let prefix: usize = if bytes <= 31 {
        1
    } else if u8::try_from(bytes).is_ok() {
        2
    } else if u16::try_from(bytes).is_ok() {
        3
    } else if u32::try_from(bytes).is_ok() {
        5
    } else {
        return Err("tenant page size estimation overflow".to_string());
    };
    prefix
        .checked_add(bytes)
        .ok_or_else(|| "tenant page size estimation overflow".to_string())
}

fn estimated_admin_labels_bytes(labels: &[String]) -> Result<usize, String> {
    let mut total = msgpack_array_prefix_len(labels.len())?;
    for label in labels {
        checked_length_add(&mut total, msgpack_str_len(label)?)?;
    }
    Ok(total)
}

fn estimated_admin_tenant_bytes(tenant: &BorrowedTenantProjection<'_>) -> Result<usize, String> {
    let mut total = msgpack_map_prefix_len(2)?;
    checked_length_add(&mut total, msgpack_str_len("id")?)?;
    checked_length_add(&mut total, msgpack_str_len(tenant.id)?)?;
    checked_length_add(&mut total, msgpack_str_len("labels")?)?;
    checked_length_add(&mut total, estimated_admin_labels_bytes(tenant.labels)?)?;
    Ok(total)
}

fn estimated_admin_response_bytes(
    borrowed: &[BorrowedTenantProjection<'_>],
    next_cursor: Option<&str>,
) -> Result<usize, String> {
    let entry_count = 3 + usize::from(next_cursor.is_some());
    let mut total = msgpack_map_prefix_len(entry_count)?;
    checked_length_add(&mut total, msgpack_str_len("ok")?)?;
    checked_length_add(&mut total, 1)?;
    checked_length_add(&mut total, msgpack_str_len("cmd")?)?;
    checked_length_add(&mut total, msgpack_str_len("list")?)?;
    checked_length_add(&mut total, msgpack_str_len("tenants")?)?;
    checked_length_add(&mut total, msgpack_array_prefix_len(borrowed.len())?)?;
    for tenant in borrowed {
        checked_length_add(&mut total, estimated_admin_tenant_bytes(tenant)?)?;
    }
    if let Some(cursor) = next_cursor {
        checked_length_add(&mut total, msgpack_str_len("next_cursor")?)?;
        checked_length_add(&mut total, msgpack_str_len(cursor)?)?;
    }
    Ok(total)
}

/// Compile every label pattern and every enabled normalization rule exactly
/// once, under the per-pattern ceilings the compiled-program budget charges.
///
/// Returns the programs rather than dropping them: this used to validate and
/// throw the results away, leaving `Classifier::from_labels` and
/// `Normalizer::from_config` to build the identical set a second time, which
/// doubled both peak compile memory and registration latency for every
/// tenant.
fn compile_enabled_regexes(
    build: &TenantBuildConfig,
    probe: Option<&TenantCompileProbe>,
) -> Result<(Vec<CompiledLabel>, Vec<CompiledRule>), String> {
    let mut labels = Vec::with_capacity(build.labels.len());
    for label in &build.labels {
        let mut regexes = Vec::with_capacity(label.patterns.len());
        for pattern in &label.patterns {
            if pattern.len() > MAX_PATTERN_LENGTH {
                if let Some(probe) = probe {
                    probe.add_warning();
                }
                return Err(format!(
                    "label '{}' pattern exceeds the {}-byte limit",
                    label.name, MAX_PATTERN_LENGTH
                ));
            }
            regexes.push(
                RegexBuilder::new(pattern)
                    .size_limit(CLASSIFIER_PATTERN_SIZE_LIMIT)
                    .build()
                    .map_err(|error| {
                        compile_refusal(
                            &format!("label '{}'", label.name),
                            "pattern",
                            CLASSIFIER_PATTERN_SIZE_LIMIT,
                            &error,
                        )
                    })?,
            );
        }
        labels.push(CompiledLabel::new(
            label.name.clone(),
            label.weight,
            regexes,
        ));
    }

    let mut rules = Vec::new();
    for rule in build.normalization.rules.iter().filter(|rule| rule.enabled) {
        if rule.pattern.len() > MAX_PATTERN_LENGTH {
            if let Some(probe) = probe {
                probe.add_warning();
            }
            return Err(format!(
                "normalization rule '{}' exceeds the {}-byte limit",
                rule.name, MAX_PATTERN_LENGTH
            ));
        }
        let regex = RegexBuilder::new(&rule.pattern)
            .size_limit(NORMALIZATION_RULE_SIZE_LIMIT)
            .build()
            .map_err(|error| {
                compile_refusal(
                    &format!("normalization rule '{}'", rule.name),
                    "rule",
                    NORMALIZATION_RULE_SIZE_LIMIT,
                    &error,
                )
            })?;
        rules.push(CompiledRule::new(regex, rule.replace.clone()));
    }

    Ok((labels, rules))
}

/// Wording for a pattern the compiler refused, keeping a budget refusal
/// legible as one.
///
/// The per-pattern ceiling is the weight the compiled-program budget
/// charges, which is 213 times smaller than the builder default this crate
/// used to pass. A pattern well inside `MAX_PATTERN_LENGTH` can compile past
/// it, and calling that "invalid regex" sends the operator looking for a
/// syntax mistake that is not there. A size refusal therefore names the
/// budget and the number; everything else keeps the syntax wording.
fn compile_refusal(subject: &str, charged_per: &str, limit: usize, error: &regex::Error) -> String {
    match error {
        regex::Error::CompiledTooBig(_) => format!(
            "{subject} exceeds the {limit}-byte compiled-program budget charged per {charged_per}"
        ),
        _ => format!("{subject} has invalid regex: {error}"),
    }
}

/// Bound and character-check a caller-supplied tenant id at registration.
///
/// Nothing downstream can recover from an id the paging budget cannot carry:
/// a single oversized id makes every `list` page containing it exceed the
/// response budget, and because a cursor is only produced on a successful
/// page, enumeration never gets past it. The charset matches the HTTP
/// cursor's, so every registered id can round-trip as a `/tenants` cursor.
pub(crate) fn validate_tenant_id(tenant_id: &str) -> Result<(), String> {
    if tenant_id.is_empty() {
        return Err("tenant id must not be empty".to_string());
    }
    if tenant_id.len() > MAX_TENANT_ID_BYTES {
        return Err(format!(
            "tenant id exceeds the {MAX_TENANT_ID_BYTES}-byte limit"
        ));
    }
    if !tenant_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(
            "tenant id may contain only ASCII letters, digits, '.', '_', and '-'".to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{TenantClassification, TenantLabel};
    use std::sync::Arc;

    struct TenantFixture {
        id: String,
        labels: Vec<String>,
    }

    fn sample_config() -> TenantConfig {
        TenantConfig {
            labels: vec![TenantLabel {
                name: "greeting".to_string(),
                patterns: vec![r"(?i)^(hi|hello)\b".to_string()],
                weight: 1.0,
            }],
            classification: Some(TenantClassification {
                confidence_threshold: 0.1,
                default_label: "greeting".to_string(),
                default_boost: 0.9,
            }),
            normalization: None,
        }
    }

    fn tenant_fixtures(count: usize) -> Vec<TenantFixture> {
        (0..count)
            .map(|index| TenantFixture {
                id: format!("tenant-{index:02}.example"),
                labels: vec!["greeting".to_string()],
            })
            .collect()
    }

    fn borrowed_tenants(fixtures: &[TenantFixture]) -> Vec<BorrowedTenantProjection<'_>> {
        fixtures
            .iter()
            .map(|tenant| BorrowedTenantProjection {
                id: tenant.id.as_str(),
                labels: &tenant.labels,
            })
            .collect()
    }

    fn materialized_tenants(fixtures: &[TenantFixture]) -> Vec<TenantInfo> {
        fixtures
            .iter()
            .map(|tenant| TenantInfo {
                id: tenant.id.clone(),
                labels: tenant.labels.clone(),
            })
            .collect()
    }

    fn actual_boundary_response_bytes(
        boundary: TenantPageBoundary,
        fixtures: &[TenantFixture],
        next_cursor: Option<&str>,
    ) -> usize {
        match boundary {
            TenantPageBoundary::AdminTcp => encoded_messagepack_len(&AdminResponse {
                ok: true,
                cmd: "list".to_string(),
                tenant: None,
                error: None,
                tenants: Some(materialized_tenants(fixtures)),
                next_cursor: next_cursor.map(str::to_string),
            })
            .expect("admin response serializes"),
            TenantPageBoundary::Http => encoded_json_len(&TenantPageResponse {
                tenants: materialized_tenants(fixtures),
                next_cursor: next_cursor.map(str::to_string),
            })
            .expect("http response serializes"),
        }
    }

    fn registry_for_boundary(
        boundary: TenantPageBoundary,
        response_limit: usize,
        list_probe: Arc<TenantListProbe>,
    ) -> Registry {
        let limits = TenantRegistryLimits::production_defaults()
            .with_max_tenants(8)
            .with_max_list_page(4)
            .with_max_list_materialized_bytes(4096)
            .with_max_admin_list_response_bytes(match boundary {
                TenantPageBoundary::AdminTcp => response_limit,
                TenantPageBoundary::Http => 4096,
            })
            .with_max_http_list_response_bytes(match boundary {
                TenantPageBoundary::AdminTcp => 4096,
                TenantPageBoundary::Http => response_limit,
            });
        let budget = TenantRegistryBudget::new(limits)
            .expect("limits are valid")
            .with_test_list_probe(list_probe);
        let compiler = TenantCompiler::bounded(1).expect("single worker compiler is valid");
        Registry::new(budget, compiler)
    }

    fn populate_registry(registry: &Registry, fixtures: &[TenantFixture]) {
        for tenant in fixtures {
            registry
                .register(tenant.id.as_str(), &sample_config())
                .expect("fixture tenant registers");
        }
    }

    fn assert_boundary_response_admission(boundary: TenantPageBoundary) {
        let all_fixtures = tenant_fixtures(4);
        let page_fixtures = &all_fixtures[..3];
        let next_cursor = Some(page_fixtures[2].id.as_str());
        let exact_bytes = actual_boundary_response_bytes(boundary, page_fixtures, next_cursor);

        let admitted_probe = Arc::new(TenantListProbe::default());
        let admitted_registry =
            registry_for_boundary(boundary, exact_bytes, Arc::clone(&admitted_probe));
        populate_registry(&admitted_registry, &all_fixtures);
        let page = admitted_registry
            .list_page_where(boundary, 3, None, |_| true)
            .expect("exact response-byte ceiling is admitted");
        assert_eq!(
            page.tenants
                .iter()
                .map(|tenant| tenant.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "tenant-00.example",
                "tenant-01.example",
                "tenant-02.example",
            ]
        );
        assert_eq!(page.next_cursor.as_deref(), next_cursor);
        assert_eq!(admitted_probe.lifetime_response_admissions(boundary), 1);
        assert_eq!(admitted_probe.page_serializations(boundary), 1);
        assert_eq!(admitted_probe.lifetime_materialized_entries(boundary), 3);
        assert_eq!(admitted_probe.lifetime_string_clones(boundary), 6);

        let refused_probe = Arc::new(TenantListProbe::default());
        let refused_registry =
            registry_for_boundary(boundary, exact_bytes - 1, Arc::clone(&refused_probe));
        populate_registry(&refused_registry, &all_fixtures);
        let no_page_serialization = refused_probe.forbid_page_serialization(boundary);
        let no_page_materialization = refused_probe.forbid_page_materialization(boundary);
        let error = refused_registry
            .list_page_where(boundary, 3, None, |_| true)
            .expect_err("one-byte larger page must be refused");
        no_page_serialization.assert_not_triggered();
        no_page_materialization.assert_not_triggered();
        assert!(error.contains("response budget"));
        assert_eq!(refused_probe.lifetime_response_admissions(boundary), 0);
        assert_eq!(
            refused_probe.lifetime_response_admission_refusals(boundary),
            1
        );
        assert_eq!(refused_probe.page_serializations(boundary), 0);
        assert_eq!(refused_probe.lifetime_materialized_entries(boundary), 0);
        assert_eq!(refused_probe.lifetime_string_clones(boundary), 0);
    }

    #[test]
    fn unregistered_tenant_returns_none() {
        let registry = Registry::new_empty();
        assert!(registry.get(Some("nobody.example")).is_none());
    }

    #[test]
    fn missing_tenant_id_returns_none() {
        let registry = Registry::new_empty();
        assert!(registry.get(None).is_none());
        assert!(registry.get(Some("")).is_none());
    }

    #[test]
    fn register_then_get_round_trips() {
        let registry = Registry::new_empty();
        registry
            .register("tenant.example", &sample_config())
            .expect("valid config registers");
        let tenant = registry.get(Some("tenant.example")).expect("registered");
        assert_eq!(tenant.label_names, vec!["greeting".to_string()]);
        assert_eq!(registry.tenant_count(), 1);
    }

    #[test]
    fn register_rejects_empty_label_list() {
        let registry = Registry::new_empty();
        let config = TenantConfig {
            labels: vec![],
            classification: None,
            normalization: None,
        };
        let err = registry
            .register("tenant.example", &config)
            .expect_err("empty labels must be rejected");
        assert!(err.contains("at least one label"));
    }

    #[test]
    fn register_is_deterministic_for_snapshot_ids() {
        let registry = Registry::new_empty();
        registry.register("b.example", &sample_config()).unwrap();
        registry.register("a.example", &sample_config()).unwrap();
        assert_eq!(
            registry.snapshot_ids(),
            ["a.example".to_string(), "b.example".to_string()]
                .into_iter()
                .collect()
        );
    }

    #[test]
    fn list_and_list_page_round_trip_in_test_scope() {
        let registry = Registry::new_empty();
        populate_registry(&registry, &tenant_fixtures(2));
        assert_eq!(
            registry
                .list()
                .into_iter()
                .map(|tenant| tenant.id)
                .collect::<Vec<_>>(),
            vec![
                "tenant-00.example".to_string(),
                "tenant-01.example".to_string()
            ]
        );
        let page = registry
            .list_page(TenantPageBoundary::Http, ["tenant-01.example"], 1, None)
            .expect("scoped page succeeds");
        assert_eq!(
            page.tenants
                .into_iter()
                .map(|tenant| tenant.id)
                .collect::<Vec<_>>(),
            vec!["tenant-01.example".to_string()]
        );
    }

    #[test]
    fn estimated_http_response_bytes_match_json_with_escaping_and_cursor() {
        let fixtures = vec![
            TenantFixture {
                id: "tenant-\"00\"".to_string(),
                labels: vec!["line\nfeed".to_string(), "tab\tvalue".to_string()],
            },
            TenantFixture {
                id: "tenant-\\01".to_string(),
                labels: vec!["ctrl\u{0007}".to_string()],
            },
        ];
        let borrowed = borrowed_tenants(&fixtures);
        let estimated =
            estimated_http_response_bytes(&borrowed, Some("cursor-\"quoted\"")).unwrap();
        let actual = encoded_json_len(&TenantPageResponse {
            tenants: materialized_tenants(&fixtures),
            next_cursor: Some("cursor-\"quoted\"".to_string()),
        })
        .expect("http response serializes");
        assert_eq!(estimated, actual);
    }

    #[test]
    fn estimated_admin_response_bytes_match_messagepack_named_map() {
        let fixtures = tenant_fixtures(3);
        let borrowed = borrowed_tenants(&fixtures);
        let estimated =
            estimated_admin_response_bytes(&borrowed, Some("tenant-02.example")).unwrap();
        let actual = encoded_messagepack_len(&AdminResponse {
            ok: true,
            cmd: "list".to_string(),
            tenant: None,
            error: None,
            tenants: Some(materialized_tenants(&fixtures)),
            next_cursor: Some("tenant-02.example".to_string()),
        })
        .expect("admin response serializes");
        assert_eq!(estimated, actual);
    }

    #[test]
    fn admin_response_budget_admission_is_exact_and_precedes_serialization() {
        assert_boundary_response_admission(TenantPageBoundary::AdminTcp);
    }

    #[test]
    fn http_response_budget_admission_is_exact_and_precedes_serialization() {
        assert_boundary_response_admission(TenantPageBoundary::Http);
    }

    /// Nothing used to bound or character-check the tenant id itself, while
    /// the list path budgets the page it has to serialize. One 300 KiB id
    /// therefore broke `list` and `GET /tenants` from that tenant onward,
    /// with no cursor to page past it, until the process restarted.
    #[test]
    fn oversized_or_out_of_charset_tenant_ids_are_refused_at_registration() {
        let registry = Registry::new_empty();
        let config = sample_config();

        let oversized = "a".repeat(MAX_TENANT_ID_BYTES + 1);
        let error = registry
            .register(&oversized, &config)
            .expect_err("an id past the page budget must never enter the map");
        assert!(error.contains("tenant id exceeds"), "unexpected: {error}");

        for (case, id) in [
            ("newline", "tenant\n.example"),
            ("space", "tenant .example"),
            ("quote", "tenant\"example"),
            ("non-ascii", "tenant\u{00e9}.example"),
        ] {
            let error = registry.register(id, &config).expect_err(case);
            assert!(
                error.contains("tenant id may contain only"),
                "{case}: unexpected refusal: {error}"
            );
        }

        assert!(registry.snapshot_ids().is_empty());
        // The charset is the HTTP cursor's, so a legal id round-trips.
        registry
            .register("tenant-01.example", &config)
            .expect("an in-charset id still registers");
    }

    /// The compiled-program budget charged 48 KiB per classifier pattern
    /// while the regex builder allowed each one 10 MiB, so the 32 MiB process
    /// budget was a name rather than a bound: ~682 admitted patterns could
    /// hold ~6.8 GiB. The builder ceiling is now the charged weight.
    #[test]
    fn a_pattern_compiling_past_its_charged_weight_is_refused() {
        assert_eq!(
            CLASSIFIER_PATTERN_SIZE_LIMIT,
            DEFAULT_CLASSIFIER_PROGRAM_BYTES
        );
        assert_eq!(
            NORMALIZATION_RULE_SIZE_LIMIT,
            DEFAULT_ENABLED_NORMALIZATION_RULE_BYTES
        );

        // Nested counted repetition well inside MAX_PATTERN_LENGTH whose
        // compiled program is far larger than the charged per-pattern weight.
        let heavy = format!("(?:{}){{200}}", "[0-9a-z]{200}");
        assert!(heavy.len() < MAX_PATTERN_LENGTH);
        assert!(
            RegexBuilder::new(&heavy)
                .size_limit(CLASSIFIER_PATTERN_SIZE_LIMIT)
                .build()
                .is_err(),
            "the charged per-pattern weight must be the builder's ceiling too"
        );

        let registry = Registry::new_empty();
        let error = registry
            .register(
                "tenant-heavy.example",
                &TenantConfig {
                    labels: vec![TenantLabel {
                        name: "heavy".to_string(),
                        patterns: vec![heavy],
                        weight: 1.0,
                    }],
                    classification: None,
                    normalization: None,
                },
            )
            .expect_err("a pattern past its charged weight must be refused");
        assert!(
            error.contains("exceeds the 49152-byte compiled-program budget charged per pattern"),
            "a budget refusal must read as one, not as a syntax error: {error}"
        );
    }

    /// Both tenant-id log sinks run the caller-supplied id through the
    /// shared `sanitize` walk. They took it verbatim, on a level that
    /// survives `release_max_level_info`, so an id carrying a newline forged
    /// log records into whatever ships the operator's log to a SIEM.
    #[test]
    fn tenant_id_log_sinks_sanitize_before_writing() {
        let source = include_str!("registry.rs");
        for marker in ["\"registered tenant\"", "\"deleted tenant\""] {
            let at = source
                .find(marker)
                .unwrap_or_else(|| panic!("{marker} log site is present"));
            let statement = &source[at.saturating_sub(200)..at];
            assert!(
                statement.contains("crate::tcp::sanitize(tenant_id"),
                "{marker} must sanitize its tenant id before logging it"
            );
        }
    }
}

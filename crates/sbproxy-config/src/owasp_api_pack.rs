//! The `owasp_api_top10` pseudo-policy: parse, validate, and expand into
//! concrete synthesized policy entries before the module-layer dispatch
//! in `sbproxy-modules::compile.rs` ever sees them (WOR-2491).
//!
//! `owasp_api_top10` is not a real [`crate::snapshot::CompiledOrigin`]
//! policy. It is a directive read and consumed by
//! [`expand_owasp_pack`], called from `compiler::compile_origin` before
//! the origin's `policies:` list is handed to the module crate. The
//! entry is removed from that list during expansion, so it never
//! reaches `Policy::from_config`'s type-string match arms; only the
//! synthesized entries it produces (or the operator's own
//! already-authored policies, when a per-item back-off fires) do.
//!
//! ```yaml
//! policies:
//!   - type: owasp_api_top10
//!     enable: all                # or: [api1, api4, api5, api7, api8]
//!     posture: report_only       # pack-wide default; a per_item entry
//!                                 # can override one item's posture
//!     per_item:
//!       api1:
//!         posture: enforce
//! ```
//!
//! Each of the ten OWASP API Security Top 10 (2023) items gets one row
//! in [`ITEM_TABLE`]. A row's [`ItemRow::pieces`] list holds zero or
//! more independently-backing-off synthesized policies: `api1` and
//! `api5` synthesize one apiece (sharing a single `object_authz` entry
//! when both are enabled), `api4` synthesizes four (`request_limit`,
//! `rate_limiting`, `concurrent_limit`, `ddos_protection`), and `api8`
//! synthesizes two (`security_headers`, `http_framing`). Each piece
//! backs off on its own, so an operator who authors just one of the
//! underlying policy types still gets the pack's coverage for the
//! rest - [`PackManifestEntry::reason`] names exactly which pieces were
//! added and which the operator's own config already covers.
//!
//! `api7` has an empty `pieces` list but is not `NotCovered`: its
//! control (the proxy's outbound SSRF guard) already runs
//! unconditionally outside the policy chain, so
//! [`ItemRow::already_enforced_reason`] reports
//! [`PackItemState::Enforced`] with nothing added to `policies`. `api2`,
//! `api6`, and `api10` report [`PackItemState::NotCovered`] with a
//! reason naming the gap; no synthesis is wired for them in this pack
//! version.
//!
//! `api1`'s and `api5`'s shared `object_authz` entry always reports
//! [`PackItemState::NeedsOperatorInput`] regardless of posture: with
//! `object_rules` and `function_rules` both empty, neither BOLA
//! ownership checking nor BFLA role checking nor the enumeration
//! sub-check has anything to evaluate (confirmed by tracing
//! `sbproxy-modules::policy::object_authz::ObjectAuthzPolicy::decide` -
//! the enumeration counter is only populated *inside* the `object_rules`
//! match loop, so it stays inert without at least one operator-authored
//! rule; see [`synth_object_authz`]'s doc comment). The state names what
//! is missing, not whether the free fallback happens to be blocking or
//! auditing - and here there is no free fallback yet, only a slot ready
//! for one the moment an operator adds rules.
//!
//! `api3` and `api9` do not fit the `ItemRow`/`SynthPiece` table shape
//! at all, so [`expand_owasp_pack`] special-cases both before it ever
//! consults [`ITEM_TABLE`] for them (their table rows exist only so
//! every [`PackItem`] variant still has one, per that invariant, and
//! are marked unused in their own fields):
//!
//! - `api3` ([`expand_api3_entry`]) splits into a request half that
//!   synthesizes nothing (`openapi_validation` and `request_validator`
//!   both require operator-supplied content - a spec or a schema - with
//!   no universal default, the same structural gap as `api1`'s
//!   ownership rules; the pack only detects whether the operator
//!   already authored one and says so) and a response half that
//!   synthesizes a `json_projection` *transform* (not a policy) onto
//!   the origin's `transforms:` list, but only when the operator
//!   supplies `per_item.api3.response_exclude_fields` - the field list
//!   this pack cannot infer. This is the plan ledger's 2026-08-18
//!   correction: the response-side gap the original research called
//!   "no control at all" is real at the *policy* layer but not at the
//!   *transform* layer, where `JsonProjectionTransform`
//!   (`sbproxy-modules::transform::json`) already strips named fields
//!   from buffered response bodies via `response_body_filter`.
//! - `api9` ([`expand_api9_entry`]) sets the origin-level
//!   `expose_openapi` boolean (`RawOriginConfig::expose_openapi`,
//!   confirmed origin-scoped at `types.rs:7580-7585`, not
//!   server-level) directly, since that field is not a `type:` entry
//!   in either list this pack otherwise touches.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

/// One of the ten OWASP API Security Top 10 (2023) risk items this pack
/// can address. Every variant has a row in [`ITEM_TABLE`], even when
/// that row has no synthesis wired yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PackItem {
    /// API1:2023 - Broken Object Level Authorization.
    Api1,
    /// API2:2023 - Broken Authentication.
    Api2,
    /// API3:2023 - Broken Object Property Level Authorization.
    Api3,
    /// API4:2023 - Unrestricted Resource Consumption.
    Api4,
    /// API5:2023 - Broken Function Level Authorization.
    Api5,
    /// API6:2023 - Unrestricted Access to Sensitive Business Flows.
    Api6,
    /// API7:2023 - Server Side Request Forgery.
    Api7,
    /// API8:2023 - Security Misconfiguration.
    Api8,
    /// API9:2023 - Improper Inventory Management.
    Api9,
    /// API10:2023 - Unsafe Consumption of APIs.
    Api10,
}

impl PackItem {
    /// Every item, in ascending OWASP numbering order. [`expand_owasp_pack`]
    /// walks enabled items in this order so the resulting
    /// [`PackManifest`] has a stable, deterministic entry order
    /// regardless of the order the operator wrote `enable: [...]` in.
    /// This order is also load bearing for `api5`: it must resolve
    /// after `api1` so `api5`'s row can detect that `api1` already
    /// synthesized their shared `object_authz` entry this run.
    pub const ALL: [PackItem; 10] = [
        PackItem::Api1,
        PackItem::Api2,
        PackItem::Api3,
        PackItem::Api4,
        PackItem::Api5,
        PackItem::Api6,
        PackItem::Api7,
        PackItem::Api8,
        PackItem::Api9,
        PackItem::Api10,
    ];

    /// The canonical lowercase name (`api1`..`api10`) used in
    /// `enable:`/`per_item:` YAML, error messages, and manifest output.
    pub fn canonical_name(self) -> &'static str {
        match self {
            PackItem::Api1 => "api1",
            PackItem::Api2 => "api2",
            PackItem::Api3 => "api3",
            PackItem::Api4 => "api4",
            PackItem::Api5 => "api5",
            PackItem::Api6 => "api6",
            PackItem::Api7 => "api7",
            PackItem::Api8 => "api8",
            PackItem::Api9 => "api9",
            PackItem::Api10 => "api10",
        }
    }

    /// Parses an operator-supplied item name. Case-insensitive
    /// (`API1`, `Api1`, and `api1` all resolve to [`PackItem::Api1`]),
    /// since the design sketch's own YAML examples use uppercase.
    /// Returns `None` for anything outside the closed set of ten names.
    pub fn parse(raw: &str) -> Option<PackItem> {
        match raw.to_ascii_lowercase().as_str() {
            "api1" => Some(PackItem::Api1),
            "api2" => Some(PackItem::Api2),
            "api3" => Some(PackItem::Api3),
            "api4" => Some(PackItem::Api4),
            "api5" => Some(PackItem::Api5),
            "api6" => Some(PackItem::Api6),
            "api7" => Some(PackItem::Api7),
            "api8" => Some(PackItem::Api8),
            "api9" => Some(PackItem::Api9),
            "api10" => Some(PackItem::Api10),
            _ => None,
        }
    }

    /// A comma-separated list of every accepted item name, for error
    /// messages that reject an unknown item.
    pub fn accepted_names() -> String {
        PackItem::ALL
            .iter()
            .map(|item| item.canonical_name())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// The official OWASP API Security Top 10 (2023) title for this
    /// item, verbatim (WOR-2491 task 4: pinned by the manifest admin
    /// endpoint contract and rendered by `sbproxy plan`'s text output).
    /// Matches this variant's own doc comment above.
    pub fn title(self) -> &'static str {
        match self {
            PackItem::Api1 => "Broken Object Level Authorization",
            PackItem::Api2 => "Broken Authentication",
            PackItem::Api3 => "Broken Object Property Level Authorization",
            PackItem::Api4 => "Unrestricted Resource Consumption",
            PackItem::Api5 => "Broken Function Level Authorization",
            PackItem::Api6 => "Unrestricted Access to Sensitive Business Flows",
            PackItem::Api7 => "Server Side Request Forgery",
            PackItem::Api8 => "Security Misconfiguration",
            PackItem::Api9 => "Improper Inventory Management",
            PackItem::Api10 => "Unsafe Consumption of APIs",
        }
    }
}

/// Pack-wide or per-item enforcement posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackPosture {
    /// Synthesized policies block on violation, where the underlying
    /// module supports blocking.
    Enforce,
    /// Synthesized policies audit violations but let the request
    /// through, via the underlying module's own report-only switch.
    ReportOnly,
}

impl PackPosture {
    /// Parses `"enforce"` or `"report_only"` (case-insensitive). Any
    /// other value returns `None`.
    fn parse(raw: &str) -> Option<PackPosture> {
        match raw.to_ascii_lowercase().as_str() {
            "enforce" => Some(PackPosture::Enforce),
            "report_only" => Some(PackPosture::ReportOnly),
            _ => None,
        }
    }

    /// The wire label used by the manifest admin endpoint and by
    /// `sbproxy plan`'s text renderer (WOR-2491 task 4): the same two
    /// spellings this enum's `Serialize` impl produces, exposed as a
    /// plain function so a text-only caller (the plan renderer) does
    /// not need to round-trip through `serde_json::to_value` to get
    /// the same string a JSON caller sees.
    pub fn label(self) -> &'static str {
        match self {
            PackPosture::Enforce => "enforce",
            PackPosture::ReportOnly => "report_only",
        }
    }
}

impl Default for PackPosture {
    /// `report_only`: the same default `expand_owasp_pack` falls back
    /// to when the operator's `owasp_api_top10` entry omits `posture`
    /// entirely, so an operator dropping in `enable: all` sight-unseen
    /// does not start every synthesized item out blocking traffic.
    fn default() -> Self {
        PackPosture::ReportOnly
    }
}

/// Per-item outcome recorded in a [`PackManifest`].
///
/// Named after the design sketch's honesty requirement: `enable: all`
/// must never silently no-op on an item, so every enabled item gets one
/// of these, including the items this pack version does not yet cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackItemState {
    /// The pack synthesized a policy entry for this item and it
    /// enforces (blocks on violation).
    Enforced,
    /// The pack synthesized a policy entry for this item in
    /// report-only/audit mode.
    ReportOnly,
    /// The operator already authored a policy of the type this item
    /// would have synthesized. The pack backed off and left the
    /// operator's entry, and its posture, exactly as configured.
    OperatorAuthored,
    /// This item is enabled and needs operator-supplied context (for
    /// example an ownership or role mapping) before it can enforce
    /// anything beyond a context-free fallback. The pack may still
    /// have synthesized something (`api1`/`api5`'s shared `object_authz`
    /// entry does), so `synthesized_types` can be non-empty here; the
    /// state names what is still missing, not whether anything at all
    /// is running.
    NeedsOperatorInput,
    /// This item is enabled but nothing was added to the compiled
    /// chain for it: either this pack version has no synthesis wired
    /// for it yet, or (per the design sketch) it has no gateway
    /// control today. The `reason` field says which.
    NotCovered,
}

impl PackItemState {
    /// The wire label used by the manifest admin endpoint and by
    /// `sbproxy plan`'s text renderer (WOR-2491 task 4): the same
    /// five spellings this enum's `Serialize` impl produces
    /// (`#[serde(rename_all = "snake_case")]`), exposed as a plain
    /// function so a text-only caller (the plan renderer) does not
    /// need to round-trip through `serde_json::to_value` to get the
    /// same string a JSON caller sees.
    pub fn label(self) -> &'static str {
        match self {
            PackItemState::Enforced => "enforced",
            PackItemState::ReportOnly => "report_only",
            PackItemState::OperatorAuthored => "operator_authored",
            PackItemState::NeedsOperatorInput => "needs_operator_input",
            PackItemState::NotCovered => "not_covered",
        }
    }
}

/// One item's outcome inside a [`PackManifest`].
#[derive(Debug, Clone, Serialize)]
pub struct PackManifestEntry {
    /// Which OWASP API Security Top 10 item this entry describes.
    pub item: PackItem,
    /// The resolved outcome for this item.
    pub state: PackItemState,
    /// Human-readable explanation of `state`, safe to surface to an
    /// operator verbatim. For a multi-piece item (`api4`, `api8`) this
    /// is every piece's fragment joined in `pieces` order, so a partial
    /// back-off (the operator authored one of several underlying
    /// policy types) is named explicitly rather than folded into a
    /// single generic sentence.
    pub reason: String,
    /// Config `type` strings the pack added to the origin's policy
    /// *or transform* chain for this item (`api3`'s response half adds
    /// a `transforms:` entry, `json_projection`; every other
    /// non-empty entry here is a `policies:` type). Empty for
    /// `OperatorAuthored` (the pack added nothing; every piece backed
    /// off to the operator's own entry) and for `NotCovered`. Can be a
    /// *subset* of an item's possible types under a partial back-off:
    /// an origin that already authors `rate_limiting` itself still
    /// gets `request_limit`, `concurrent_limit`, and `ddos_protection`
    /// from `api4`'s row, and only those three appear here. Can also
    /// be non-empty for `NeedsOperatorInput`: `api1`/`api5` synthesize
    /// an (as yet inert) `object_authz` entry while still reporting
    /// that state, because real coverage needs an operator-authored
    /// rule this pack cannot infer. Always empty for `api9`: its
    /// control is a boolean field, not a `type:` entry in either list.
    pub synthesized_types: Vec<&'static str>,
}

/// The full per-item outcome of expanding one origin's `owasp_api_top10`
/// pack entry. `None` on [`crate::snapshot::CompiledOrigin::owasp_pack_manifest`]
/// means the origin had no `owasp_api_top10` policy at all; `Some` with
/// an empty `entries` list cannot happen (`enable` is required, and an
/// empty `enable: []` list still deserializes but resolves to a
/// zero-entry manifest, which is the honest, if unusual, outcome for a
/// pack that turns nothing on).
#[derive(Debug, Clone, Default, Serialize)]
pub struct PackManifest {
    /// One entry per item named in `enable` (or all ten, for
    /// `enable: all`), in [`PackItem::ALL`] order.
    pub entries: Vec<PackManifestEntry>,
    /// The pack-wide posture this origin's `owasp_api_top10` entry
    /// declared (`posture:`, defaulting to [`PackPosture::ReportOnly`]
    /// when absent). WOR-2491 task 4: this is the single `posture`
    /// value the manifest admin endpoint and `sbproxy plan` surface
    /// per origin. A `per_item.<name>.posture` override changes what
    /// that one item's synthesized JSON carries (see
    /// [`synth_object_authz`]) without changing this field; this is
    /// the pack-wide default, not a per-item resolved value.
    pub posture: PackPosture,
}

impl PackManifest {
    /// Looks up this manifest's entry for one item, if the item was
    /// enabled.
    pub fn entry_for(&self, item: PackItem) -> Option<&PackManifestEntry> {
        self.entries.iter().find(|entry| entry.item == item)
    }
}

/// Raw deserialized shape of a `type: owasp_api_top10` policy entry.
/// `type` itself is not declared here: it is read by the caller to
/// find this entry, and `serde_json::from_value` silently ignores the
/// extra key since this struct has no `deny_unknown_fields`.
#[derive(Debug, Clone, Deserialize)]
struct RawPackConfig {
    /// `"all"` or an explicit list of item names.
    enable: RawEnable,
    /// Pack-wide default posture. Defaults to `report_only` when
    /// absent: an operator dropping in `enable: all` sight-unseen
    /// should not have every synthesized item start out blocking
    /// traffic.
    #[serde(default)]
    posture: Option<String>,
    /// Per-item posture overrides, keyed by item name.
    #[serde(default)]
    per_item: HashMap<String, RawPerItem>,
}

/// The `enable:` value: either the literal string `"all"` or a list of
/// item names. Untagged because the two shapes are structurally
/// distinct in YAML/JSON (a scalar vs. a sequence), so there is no
/// ambiguity to resolve.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum RawEnable {
    /// Expected to be the literal string `"all"`; checked in
    /// [`parse_enable`], not by serde, so a misspelling produces the
    /// same "accepted list" error shape as an unknown item name would.
    All(String),
    /// An explicit list of item names.
    List(Vec<String>),
}

/// One `per_item.<name>` override entry.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPerItem {
    /// Posture override for this one item.
    #[serde(default)]
    posture: Option<String>,
    /// `api3`-only: field names to strip from JSON response bodies via
    /// a synthesized `json_projection` transform (see
    /// [`expand_api3_entry`]). Rejected on any other item; rejected if
    /// present but empty (omit the key instead - an empty list is not
    /// the same request as "strip nothing").
    #[serde(default)]
    response_exclude_fields: Option<Vec<String>>,
}

/// Returns true when the JSON value's `type` field equals `wanted`.
///
/// A local copy of `compiler::config_type_is`: small enough that
/// sharing it across the module boundary is not worth the coupling.
fn config_type_is(value: &serde_json::Value, wanted: &str) -> bool {
    value.get("type").and_then(|v| v.as_str()) == Some(wanted)
}

/// Outcome of synthesizing one policy inside a multi-piece item's row.
struct PieceSynthesis {
    /// The synthesized policy JSON to append to the origin's
    /// `policies:` list.
    policy: serde_json::Value,
    /// Config `type` string of `policy`, for
    /// [`PackManifestEntry::synthesized_types`].
    synthesized_type: &'static str,
    /// Human-readable fragment folded into the item's
    /// [`PackManifestEntry::reason`].
    reason: String,
}

/// One independently-backing-off policy inside an [`ItemRow`]. Most
/// items have exactly one piece; `api4` has four and `api8` has two, so
/// an operator who authors just one of the underlying policy types
/// still gets the pack's coverage for the rest, with the manifest
/// reason naming exactly which pieces backed off and which the pack
/// added. `api1` and `api5` each have exactly one piece too, but both
/// point at `object_authz`/`bola`: enabling both together produces one
/// shared entry, not two (see `shared_backoff_reason`).
struct SynthPiece {
    /// Config `type` strings whose presence in the origin's *original*,
    /// operator-authored policies (captured before this pack's
    /// expansion begins) backs this piece off entirely.
    backoff_types: &'static [&'static str],
    /// Manifest fragment used when the operator already authored one of
    /// `backoff_types`.
    operator_backoff_reason: &'static str,
    /// Manifest fragment used when this piece is not synthesized
    /// because an earlier item's row in this same expansion pass
    /// already added one of `backoff_types` (the `api1`/`api5` shared
    /// `object_authz` case). `None` for pieces whose `backoff_types`
    /// never overlap another item's row; for those this branch cannot
    /// happen.
    shared_backoff_reason: Option<&'static str>,
    /// Synthesizes this one policy entry.
    synth: fn(PackPosture) -> PieceSynthesis,
}

/// One row of the per-item expansion table.
///
/// `pieces` is empty for items with no synthesis target at all.
/// [`ItemRow::already_enforced_reason`] distinguishes "genuinely
/// nothing to add, and nothing is covered" (`api2`, `api3`, `api6`,
/// `api9`, `api10` in this pack version: [`PackItemState::NotCovered`],
/// `uncovered_reason` explains the gap) from "genuinely nothing to add,
/// because the control is already unconditionally enforced outside the
/// policy chain" (`api7`'s SSRF guard: [`PackItemState::Enforced`],
/// `already_enforced_reason` explains why there is nothing to
/// synthesize).
struct ItemRow {
    /// The item this row describes.
    item: PackItem,
    /// Independently-backing-off policies this item synthesizes. Empty
    /// when this item adds nothing to the policy chain.
    pieces: &'static [SynthPiece],
    /// Manifest state used once at least one piece is present for this
    /// item (freshly synthesized, or shared with an earlier item's
    /// row). [`PackItemState::Enforced`] for items whose synthesized
    /// defaults are safe to block blind (`api4`, `api8`);
    /// [`PackItemState::NeedsOperatorInput`] for items whose synthesis
    /// still needs operator-authored rules regardless of posture
    /// (`api1`, `api5`). Unused when `pieces` is empty.
    covered_state: PackItemState,
    /// Reason used when `pieces` is empty and the item is nonetheless
    /// already enforced outside the policy chain (`api7` only). `None`
    /// for every other empty-`pieces` row.
    already_enforced_reason: Option<&'static str>,
    /// Manifest reason used when `pieces` is empty and
    /// `already_enforced_reason` is `None`: this pack version has no
    /// synthesis wired for the item, or it has no gateway control
    /// today.
    uncovered_reason: &'static str,
}

/// Synthesizes `api1`/`api5`'s shared `object_authz` policy: empty
/// `object_rules` (no operator-supplied ownership mapping exists yet)
/// plus `enumeration.enabled: true`. `posture` threads into
/// `object_authz`'s own `test_mode` switch: `report_only` sets
/// `test_mode: true` (violations audited, request passes); `enforce`
/// sets `test_mode: false` (violations blocked).
///
/// The enumeration flag is set now as a slot ready for the moment an
/// operator adds an `object_rules` entry with an `object_param`, not
/// because it detects anything on its own today. Tracing
/// `ObjectAuthzPolicy::decide` (`sbproxy-modules::policy::object_authz`)
/// shows the enumeration counter is only populated *inside* the
/// `object_rules` match loop (`enumeration_hit` is set from a matched
/// rule's captured `object_param`), so with `object_rules` empty the
/// enumeration check's own `if let Some(obj_id) = enumeration_hit`
/// never has a value to test, regardless of `enumeration.enabled`. This
/// pack cannot synthesize an `object_rules` entry that only enumerates
/// without also enforcing BOLA ownership, because `decide()` ties any
/// matching rule's owner check to the same loop: a rule with no
/// `object_param` skips enumeration but still enforces BOLA, and a rule
/// with one enforces BOLA on the way to counting it. There is
/// currently no way to get one without the other from config alone.
fn synth_object_authz(posture: PackPosture) -> PieceSynthesis {
    let test_mode = matches!(posture, PackPosture::ReportOnly);
    let policy = serde_json::json!({
        "type": "object_authz",
        "test_mode": test_mode,
        "enumeration": { "enabled": true },
    });
    let mode_note = if test_mode {
        "test_mode: true, so a future violation is audited but the request passes"
    } else {
        "test_mode: false, so a future violation is blocked"
    };
    PieceSynthesis {
        policy,
        synthesized_type: "object_authz",
        reason: format!(
            "synthesized object_authz with empty object_rules and enumeration.enabled: true \
             ({mode_note}). With object_rules empty this entry has no rule to match against any \
             path, so it does not yet block or flag anything: real BOLA coverage needs an \
             operator-authored object_rules entry, which this pack cannot infer. \
             enumeration.enabled is set now so it activates the moment such a rule is added, \
             without a second config change."
        ),
    }
}

/// Synthesizes `api5`'s own `object_authz` entry for the case where
/// `api5` is enabled without `api1` (so there is no shared entry to
/// join). `function_rules` is explicitly empty: real BFLA coverage
/// needs an operator-authored rule naming the privileged path, method
/// set, and required role, which this pack cannot infer. `posture`
/// threads into `test_mode` for consistency with [`synth_object_authz`],
/// though with `function_rules` empty `decide()`'s BFLA loop never
/// runs either way, so `test_mode` has no observable effect until an
/// operator adds a rule.
fn synth_object_authz_bfla_only(posture: PackPosture) -> PieceSynthesis {
    let test_mode = matches!(posture, PackPosture::ReportOnly);
    let policy = serde_json::json!({
        "type": "object_authz",
        "test_mode": test_mode,
        "function_rules": [],
    });
    PieceSynthesis {
        policy,
        synthesized_type: "object_authz",
        reason: "synthesized object_authz with empty function_rules. Real BFLA coverage needs \
                  operator-authored function_rules naming the privileged path, method set, and \
                  required role, which this pack cannot infer; with function_rules empty, \
                  decide()'s BFLA loop never runs, so nothing is refused regardless of posture. \
                  Enabling api1 alongside this item shares one object_authz entry instead of \
                  adding a second; neither has a fallback that fires without operator-authored \
                  rules."
            .to_string(),
    }
}

/// Synthesizes `api4`'s `request_limit` piece: body size, header count,
/// and URL length caps that never reach a rate limiter. Values (1 MiB
/// body, 64 headers, 2048-character URL) are the research sketch's own
/// numbers, verified against `RequestLimitPolicy`'s real fields
/// (`request_limit.rs`) - `max_body_size`, `max_header_count`, and
/// `max_url_length` all exist and default to unchecked (`None`) when
/// absent, so leaving `max_header_size` and
/// `max_query_string_length` unset here is a deliberate "only the
/// vetted three" choice, not an oversight. `request_limit` has no
/// report-only knob (`check_request` returns `Err` unconditionally over
/// any configured limit), so `posture` has no effect on this piece.
fn synth_request_limit(_posture: PackPosture) -> PieceSynthesis {
    let policy = serde_json::json!({
        "type": "request_limit",
        "max_body_size": 1_048_576,
        "max_header_count": 64,
        "max_url_length": 2048,
    });
    PieceSynthesis {
        policy,
        synthesized_type: "request_limit",
        reason: "synthesized request_limit (max_body_size: 1 MiB, max_header_count: 64, \
                  max_url_length: 2048): shapes that never reach a rate limiter, safe for \
                  virtually any JSON API. request_limit has no report-only mode; posture has no \
                  effect on this piece."
            .to_string(),
    }
}

/// Synthesizes `api4`'s `rate_limiting` piece: a high-ceiling token
/// bucket meant to catch a runaway or scripted client rather than
/// constrain normal traffic. With no `key` expression configured, the
/// enforcer buckets per caller (client IP) by default, so this is a
/// per-caller budget, not a shared one. `rate_limiting` has no
/// report-only knob, so `posture` has no effect on this piece.
fn synth_rate_limiting(_posture: PackPosture) -> PieceSynthesis {
    let policy = serde_json::json!({
        "type": "rate_limiting",
        "requests_per_second": 100.0,
        "burst": 200,
    });
    PieceSynthesis {
        policy,
        synthesized_type: "rate_limiting",
        reason: "synthesized rate_limiting (requests_per_second: 100, burst: 200, per-caller by \
                  default since no key is set): a high ceiling meant to catch a runaway or \
                  scripted client, not to constrain normal traffic. rate_limiting has no \
                  report-only mode; posture has no effect on this piece."
            .to_string(),
    }
}

/// Synthesizes `api4`'s `concurrent_limit` piece: a shared in-flight
/// budget for the whole origin (`key_by` left unset, which
/// `ConcurrentLimitPolicy::from_config` defaults to `"global"` - one
/// counter for the policy mount, confirmed at `concurrent_limit.rs`).
/// This backstops a stalled or slow upstream piling up requests, a
/// different failure mode than the per-caller rate limit above.
/// `concurrent_limit` has no report-only knob, so `posture` has no
/// effect on this piece.
fn synth_concurrent_limit(_posture: PackPosture) -> PieceSynthesis {
    let policy = serde_json::json!({
        "type": "concurrent_limit",
        "max": 200,
    });
    PieceSynthesis {
        policy,
        synthesized_type: "concurrent_limit",
        reason: "synthesized concurrent_limit (max: 200, key_by left unset so it defaults to \
                  global: one shared in-flight budget for the whole origin): a backstop against \
                  a stalled or slow upstream piling up requests. concurrent_limit has no \
                  report-only mode; posture has no effect on this piece."
            .to_string(),
    }
}

/// Synthesizes `api4`'s `ddos_protection` piece with no fields set, so
/// `ddos.rs`'s own defaults apply unchanged: 100 requests/second per IP
/// in a sliding 1-second window, 300-second block
/// (`default_ddos_threshold`/`default_ddos_block_duration`, confirmed
/// at `ddos.rs`; `DdosPolicy::from_config` succeeds against an empty
/// object). Already the conservative, high-ceiling shape this item
/// needs, so there is nothing to override. `ddos_protection` has no
/// report-only knob, so `posture` has no effect on this piece.
fn synth_ddos_protection(_posture: PackPosture) -> PieceSynthesis {
    let policy = serde_json::json!({ "type": "ddos_protection" });
    PieceSynthesis {
        policy,
        synthesized_type: "ddos_protection",
        reason: "synthesized ddos_protection with no fields set, so ddos.rs's own defaults \
                  apply unchanged (100 requests/second per IP in a sliding 1-second window, \
                  300-second block): already the conservative, high-ceiling shape this item \
                  needs. ddos_protection has no report-only mode; posture has no effect on this \
                  piece."
            .to_string(),
    }
}

/// Synthesizes `api8`'s `security_headers` piece: a baseline unlikely
/// to affect any API response. HSTS and CSP are deliberately left out -
/// HSTS assumes the origin is always served over TLS and CSP is highly
/// response-shape-specific (inline scripts, embedded assets), so
/// neither is safe to default blind per the research sketch. Fields
/// verified against `SecHeadersPolicy` (`sec_headers.rs`): the
/// canonical `headers: [{name, value}]` array format. `security_headers`
/// has no report-only knob (it injects unconditionally), so `posture`
/// has no effect on this piece.
fn synth_security_headers(_posture: PackPosture) -> PieceSynthesis {
    let policy = serde_json::json!({
        "type": "security_headers",
        "headers": [
            { "name": "X-Content-Type-Options", "value": "nosniff" },
            { "name": "X-Frame-Options", "value": "DENY" },
            { "name": "Referrer-Policy", "value": "no-referrer" },
        ],
    });
    PieceSynthesis {
        policy,
        synthesized_type: "security_headers",
        reason: "synthesized security_headers with a baseline unlikely to affect any API \
                  response: X-Content-Type-Options: nosniff, X-Frame-Options: DENY, \
                  Referrer-Policy: no-referrer. HSTS and CSP are left out: HSTS assumes the \
                  origin is always served over TLS and CSP is highly response-shape-specific, so \
                  neither is safe to default blind. security_headers has no report-only mode; \
                  posture has no effect on this piece."
            .to_string(),
    }
}

/// Synthesizes `api8`'s `http_framing` piece with no fields: the
/// module's defense set (dual Content-Length/Transfer-Encoding,
/// duplicate headers, malformed Transfer-Encoding, control characters)
/// is hard-coded and always active (`http_framing.rs`'s own doc
/// comment: "No tunable knobs today"). `http_framing` has no
/// report-only knob, so `posture` has no effect on this piece.
fn synth_http_framing(_posture: PackPosture) -> PieceSynthesis {
    let policy = serde_json::json!({ "type": "http_framing" });
    PieceSynthesis {
        policy,
        synthesized_type: "http_framing",
        reason: "synthesized http_framing with no fields: the module's defense set (dual \
                  Content-Length/Transfer-Encoding, duplicate headers, malformed \
                  Transfer-Encoding, control characters) is hard-coded and always active. \
                  http_framing has no report-only mode; posture has no effect on this piece."
            .to_string(),
    }
}

/// Builds `api3`'s manifest entry. Does not use the `SynthPiece`
/// table: the request half never synthesizes anything (see below) and
/// the response half needs a field list from `per_item.api3`, not
/// just a posture, plus it writes to `transforms`, a different `Vec`
/// than every other item in this pack touches - neither fits
/// `SynthPiece::synth: fn(PackPosture) -> PieceSynthesis`.
///
/// Request side (mass assignment / unexpected input fields): `openapi_validation::from_config`
/// (`crates/sbproxy-modules/src/policy/openapi_validation.rs`) requires
/// `spec` or `spec_file`; `request_validator::from_config`
/// (`crates/sbproxy-modules/src/policy/request_validator.rs`) requires
/// `schema`. Neither has a universal default the way `api4`'s numeric
/// limits do, so this pack cannot synthesize either - the same
/// structural gap as `api1`'s ownership rules. This half is advisory
/// only: it detects whether the operator already authors one of the
/// two and says so, but never gates `state` on its own (an operator
/// who supplies `response_exclude_fields` without a request-side
/// validator still gets `Enforced`, not `NeedsOperatorInput`, because
/// the response half is genuinely, unconditionally active either way).
///
/// Response side (excessive data exposure): synthesizes a
/// `json_projection` transform (`sbproxy-modules::transform::json::JsonProjectionTransform`,
/// `fields: exclude_fields`, `exclude: true`) onto the origin's
/// `transforms:` list when `per_item.api3.response_exclude_fields` is
/// supplied - the plan ledger's 2026-08-18 correction: this transform
/// already strips named fields from buffered JSON response bodies via
/// `response_body_filter`, so the response-side gap is a missing
/// *field list*, not a missing *mechanism*. Absent the list, nothing
/// is synthesized and the reason names the transform by module path
/// plus the missing field list, never "no capability" (per the same
/// ruling). `json_projection` has no report-only knob, so pack-wide
/// `posture` has no effect on this half either.
fn expand_api3_entry(
    operator_authored_types: &HashSet<String>,
    response_exclude_fields: Option<&[String]>,
    transforms: &mut Vec<serde_json::Value>,
) -> PackManifestEntry {
    let request_covered = operator_authored_types.contains("openapi_validation")
        || operator_authored_types.contains("request_validator");
    let request_reason = if request_covered {
        "request side: origin already authors openapi_validation or request_validator; the \
         pack leaves it exactly as configured, including its own mode."
            .to_string()
    } else {
        "request side: no openapi_validation or request_validator policy configured, so mass \
         assignment / unexpected input fields are not checked. The pack cannot synthesize \
         either because both require operator-supplied content (an OpenAPI spec or a JSON \
         Schema) with no universal default, the same structural gap as api1's ownership rules. \
         Configure openapi_validation (mode: log to bootstrap against real traffic, or mode: \
         enforce with a spec already in hand) or request_validator directly."
            .to_string()
    };

    let mut synthesized_types = Vec::new();
    let (response_reason, response_synthesized) = match response_exclude_fields {
        Some(fields) => {
            let policy = serde_json::json!({
                "type": "json_projection",
                "fields": fields,
                "exclude": true,
            });
            transforms.push(policy);
            synthesized_types.push("json_projection");
            (
                format!(
                    "response side: synthesized json_projection (fields: [{}], exclude: true) \
                     onto the origin's transform chain, stripping these fields from every JSON \
                     response body via response_body_filter. json_projection has no \
                     report-only mode; posture has no effect on this half.",
                    fields.join(", ")
                ),
                true,
            )
        }
        None => (
            "response side: no per_item.api3.response_exclude_fields supplied, so nothing was \
             synthesized. sbproxy-modules::transform::json::JsonProjectionTransform (config \
             type json_projection) already strips named fields from buffered JSON response \
             bodies via response_body_filter, but needs an operator-supplied field list this \
             pack cannot infer. Set per_item.api3.response_exclude_fields: [field, ...] to \
             enable it."
                .to_string(),
            false,
        ),
    };

    let state = if response_synthesized {
        PackItemState::Enforced
    } else {
        PackItemState::NeedsOperatorInput
    };

    PackManifestEntry {
        item: PackItem::Api3,
        state,
        reason: format!("{request_reason} {response_reason}"),
        synthesized_types,
    }
}

/// Builds `api9`'s manifest entry. Does not use the `SynthPiece`
/// table: its control is `RawOriginConfig::expose_openapi`, a single
/// origin-level `bool` field (confirmed origin-scoped, not
/// server-level, at `types.rs:7580-7585`), not a `type:` entry in
/// `policies:` or `transforms:`, so there is nothing for
/// `operator_authored_types`-style detection to key off - the caller
/// reads the field's own prior value instead and passes it in as
/// `was_already_true`.
///
/// Always reports [`PackItemState::Enforced`] when this item is
/// enabled: turning emission on never blocks traffic (it serves a
/// live OpenAPI document built from the compiled config at
/// `/.well-known/openapi.json`), matching the design sketch's "this is
/// a report, not a block." The reason still draws the real tradeoff
/// (route-shape disclosure) rather than presenting it as a free win,
/// and names what emission does and does not cover either way.
fn expand_api9_entry(was_already_true: bool) -> PackManifestEntry {
    let reason = if was_already_true {
        "origin already sets expose_openapi: true; the pack makes no change. The live OpenAPI \
         document is served at /.well-known/openapi.json (and .yaml), built from this compiled \
         config, so it cannot drift the way a hand-maintained spec does. It only reflects what \
         this gateway routes: a backend route sbproxy never sees (a shadow API) is not listed, \
         and there is no sunset/deprecation enforcement for an old version still reachable \
         through versioning."
            .to_string()
    } else {
        "set expose_openapi: true for this origin (was false, the default): serves a live \
         OpenAPI document at /.well-known/openapi.json (and .yaml), built from this compiled \
         config, so it cannot drift the way a hand-maintained spec does. This is a real \
         route-shape-disclosure tradeoff, not a free win: review whether this origin's route \
         shape is safe to publish before shipping enable: all or api9 to production. It only \
         reflects what this gateway routes: a backend route sbproxy never sees (a shadow API) \
         is not listed, and there is no sunset/deprecation enforcement for an old version still \
         reachable through versioning."
            .to_string()
    };
    PackManifestEntry {
        item: PackItem::Api9,
        state: PackItemState::Enforced,
        reason,
        synthesized_types: Vec::new(),
    }
}

/// The `api1` piece: shared with `api5`, see [`synth_object_authz`].
const API1_PIECES: [SynthPiece; 1] = [SynthPiece {
    backoff_types: &["object_authz", "bola"],
    operator_backoff_reason: "origin already authors an object_authz/bola policy; the pack \
                               leaves it exactly as configured, including its own posture",
    shared_backoff_reason: None,
    synth: synth_object_authz,
}];

/// The `api5` piece: backs off the same way `api1`'s does when the
/// operator already authors `object_authz`/`bola`, and additionally
/// shares `api1`'s synthesized entry (adding nothing of its own) when
/// `api1` is also enabled and not backed off - see
/// [`SynthPiece::shared_backoff_reason`]. `api5` only ever synthesizes
/// its own entry (`synth_object_authz_bfla_only`) when it is enabled
/// without `api1`.
const API5_PIECES: [SynthPiece; 1] = [SynthPiece {
    backoff_types: &["object_authz", "bola"],
    operator_backoff_reason: "origin already authors an object_authz/bola policy; the pack \
                               leaves it exactly as configured, including any function_rules \
                               and its own posture",
    shared_backoff_reason: Some(
        "shares the object_authz entry api1's row already synthesized for this origin; \
         function_rules stays empty either way, since neither item has a fallback that fires \
         without operator-authored rules",
    ),
    synth: synth_object_authz_bfla_only,
}];

/// `api4`'s four independently-backing-off pieces.
const API4_PIECES: [SynthPiece; 4] = [
    SynthPiece {
        backoff_types: &["request_limit", "request_limiting"],
        operator_backoff_reason: "origin already authors a request_limit/request_limiting \
                                   policy; the pack leaves it exactly as configured",
        shared_backoff_reason: None,
        synth: synth_request_limit,
    },
    SynthPiece {
        backoff_types: &["rate_limiting"],
        operator_backoff_reason: "origin already authors a rate_limiting policy; the pack \
                                   leaves it exactly as configured",
        shared_backoff_reason: None,
        synth: synth_rate_limiting,
    },
    SynthPiece {
        backoff_types: &["concurrent_limit", "concurrent_limiting"],
        operator_backoff_reason: "origin already authors a concurrent_limit/concurrent_limiting \
                                   policy; the pack leaves it exactly as configured",
        shared_backoff_reason: None,
        synth: synth_concurrent_limit,
    },
    SynthPiece {
        backoff_types: &["ddos", "ddos_protection"],
        operator_backoff_reason: "origin already authors a ddos/ddos_protection policy; the \
                                   pack leaves it exactly as configured",
        shared_backoff_reason: None,
        synth: synth_ddos_protection,
    },
];

/// `api8`'s two independently-backing-off pieces. A managed `waf`
/// (Core Rule Set) default is intentionally not part of this row: the
/// task brief scopes `api8` to `security_headers` and `http_framing`
/// only. `waf`'s own `test_mode` knob (`waf/policy.rs`) makes it a
/// reasonable candidate for a future version of this pack (matching
/// the research sketch), but adding it is deferred rather than folded
/// in here. Configure `waf` directly for CRS-based coverage today.
const API8_PIECES: [SynthPiece; 2] = [
    SynthPiece {
        backoff_types: &["security_headers"],
        operator_backoff_reason: "origin already authors a security_headers policy; the pack \
                                   leaves it exactly as configured",
        shared_backoff_reason: None,
        synth: synth_security_headers,
    },
    SynthPiece {
        backoff_types: &["http_framing"],
        operator_backoff_reason: "origin already authors an http_framing policy; the pack \
                                   leaves it exactly as configured",
        shared_backoff_reason: None,
        synth: synth_http_framing,
    },
];

/// The per-item expansion table. One row per [`PackItem`], in
/// [`PackItem::ALL`] order.
const ITEM_TABLE: [ItemRow; 10] = [
    ItemRow {
        item: PackItem::Api1,
        pieces: &API1_PIECES,
        covered_state: PackItemState::NeedsOperatorInput,
        already_enforced_reason: None,
        uncovered_reason: "",
    },
    ItemRow {
        item: PackItem::Api2,
        pieces: &[],
        covered_state: PackItemState::NotCovered,
        already_enforced_reason: None,
        uncovered_reason: "no synthesis wired for this item; strong authentication is an \
                            operator choice of provider (jwt, oidc, api_key, bearer_token, \
                            etc.) the pack cannot make for you. Configure an authentication \
                            block directly.",
    },
    ItemRow {
        // Unused: `expand_owasp_pack`'s main loop special-cases api3
        // via `expand_api3_entry` before it ever calls `item_row` for
        // this variant (api3's response half needs the `transforms`
        // Vec and a per-item field list, neither of which fits this
        // row's `pieces`/`covered_state`/`uncovered_reason` shape).
        // This row exists only so every `PackItem` variant still has
        // exactly one entry, per `item_row`'s own doc comment.
        item: PackItem::Api3,
        pieces: &[],
        covered_state: PackItemState::NotCovered,
        already_enforced_reason: None,
        uncovered_reason: "",
    },
    ItemRow {
        item: PackItem::Api4,
        pieces: &API4_PIECES,
        covered_state: PackItemState::Enforced,
        already_enforced_reason: None,
        uncovered_reason: "",
    },
    ItemRow {
        item: PackItem::Api5,
        pieces: &API5_PIECES,
        covered_state: PackItemState::NeedsOperatorInput,
        already_enforced_reason: None,
        uncovered_reason: "",
    },
    ItemRow {
        item: PackItem::Api6,
        pieces: &[],
        covered_state: PackItemState::NotCovered,
        already_enforced_reason: None,
        uncovered_reason: "no purpose-built control exists for sensitive-business-flow abuse; \
                            composing rate_limiting, concurrent_limiting, object_authz \
                            function_rules, and bot/web-bot-auth checks is the operator's job, \
                            since which flows are sensitive is inherently business-specific.",
    },
    ItemRow {
        item: PackItem::Api7,
        pieces: &[],
        covered_state: PackItemState::NotCovered,
        already_enforced_reason: Some(
            "SSRF protection is not a policy this pack can toggle: sbproxy's outbound dial path \
             already refuses private/loopback/link-local upstream targets by default at every \
             call site that dials a caller-influenced or configured URL (webhook targets, AI \
             provider base URLs, RAG HTTP providers, alerting channels, A2A push targets, \
             external guardrails), independent of whether this pack is enabled at all. Review \
             proxy.extensions.upstream.allow_private_cidrs directly if it looks unusually \
             broad; this pack does not compute that check from here.",
        ),
        uncovered_reason: "",
    },
    ItemRow {
        item: PackItem::Api8,
        pieces: &API8_PIECES,
        covered_state: PackItemState::Enforced,
        already_enforced_reason: None,
        uncovered_reason: "",
    },
    ItemRow {
        // Unused: `expand_owasp_pack`'s main loop special-cases api9
        // via `expand_api9_entry` before it ever calls `item_row` for
        // this variant (api9's control is the origin-level
        // `expose_openapi` bool, not a `type:` entry `SynthPiece`
        // back-off detection can key off). This row exists only so
        // every `PackItem` variant still has exactly one entry, per
        // `item_row`'s own doc comment.
        item: PackItem::Api9,
        pieces: &[],
        covered_state: PackItemState::NotCovered,
        already_enforced_reason: None,
        uncovered_reason: "",
    },
    ItemRow {
        item: PackItem::Api10,
        pieces: &[],
        covered_state: PackItemState::NotCovered,
        already_enforced_reason: None,
        uncovered_reason: "no gateway control exists for this item today: sbproxy's own \
                            outbound calls to third-party APIs have no response-handling \
                            safety net (redirect limits, response-size caps, content-type \
                            validation) beyond SSRF's destination checks.",
    },
];

/// Looks up an item's table row. Every [`PackItem`] variant has exactly
/// one row in [`ITEM_TABLE`], so this only returns `None` if a future
/// edit adds a variant without adding its row; callers turn that into
/// an `anyhow` error rather than a panic.
fn item_row(item: PackItem) -> Option<&'static ItemRow> {
    ITEM_TABLE.iter().find(|row| row.item == item)
}

/// Parses and validates an item name for the given YAML context
/// (`"enable"` or `"per_item"`), producing the "accepted list" error
/// shape an unknown name gets.
fn parse_item_or_bail(hostname: &str, raw: &str, context: &str) -> anyhow::Result<PackItem> {
    PackItem::parse(raw).ok_or_else(|| {
        anyhow::anyhow!(
            "origin '{hostname}': owasp_api_top10 {context} names an unknown item {raw:?}; \
             accepted names are {}",
            PackItem::accepted_names()
        )
    })
}

/// Resolves the `enable:` value into a validated, deduplicated list of
/// items, in the order the operator wrote them (order does not matter
/// downstream: [`expand_owasp_pack`] walks [`PackItem::ALL`] order).
fn parse_enable(hostname: &str, raw: &RawEnable) -> anyhow::Result<Vec<PackItem>> {
    match raw {
        RawEnable::All(word) => {
            if !word.eq_ignore_ascii_case("all") {
                anyhow::bail!(
                    "origin '{hostname}': owasp_api_top10 enable must be \"all\" or a list of \
                     item names; got the string {word:?}"
                );
            }
            Ok(PackItem::ALL.to_vec())
        }
        RawEnable::List(names) => {
            let mut seen = HashSet::new();
            let mut items = Vec::with_capacity(names.len());
            for name in names {
                let item = parse_item_or_bail(hostname, name, "enable")?;
                if !seen.insert(item) {
                    anyhow::bail!(
                        "origin '{hostname}': owasp_api_top10 enable lists {} more than once; \
                         list each item once",
                        item.canonical_name()
                    );
                }
                items.push(item);
            }
            Ok(items)
        }
    }
}

/// Expands the origin's `owasp_api_top10` policy entry (if any) into
/// concrete synthesized policies (appended to `policies`) and
/// transforms (appended to `transforms`, `api3`'s response half
/// only), and removes the pseudo-policy entry itself so it never
/// reaches `sbproxy-modules::compile.rs`'s type-string match arms.
/// Also flips `*expose_openapi` to `true` when `api9` is enabled and
/// it was not already (see [`expand_api9_entry`]).
///
/// Returns `Ok(None)` when the origin has no `owasp_api_top10` entry -
/// `transforms` and `*expose_openapi` are left untouched in that case.
/// Returns `Err` for: more than one `owasp_api_top10` entry on the
/// origin, an unknown item name in `enable` or `per_item`, a duplicate
/// item name within `enable`, a `per_item` override for an item not
/// named in `enable`, a `response_exclude_fields` override on any item
/// other than `api3`, an empty `response_exclude_fields` list, or a
/// malformed `posture`/`enable` value.
///
/// `pub(crate)`: `compiler::compile_origin` is this crate's only
/// caller and its own public entry point (`compile_config`) already
/// covers the pack end to end, so this expansion step does not need
/// to be reachable outside `sbproxy-config` on its own.
pub(crate) fn expand_owasp_pack(
    hostname: &str,
    policies: &mut Vec<serde_json::Value>,
    transforms: &mut Vec<serde_json::Value>,
    expose_openapi: &mut bool,
) -> anyhow::Result<Option<PackManifest>> {
    let pack_indices: Vec<usize> = policies
        .iter()
        .enumerate()
        .filter(|&(_, p)| config_type_is(p, "owasp_api_top10"))
        .map(|(i, _)| i)
        .collect();

    if pack_indices.is_empty() {
        return Ok(None);
    }
    if pack_indices.len() > 1 {
        anyhow::bail!(
            "origin '{hostname}': {} owasp_api_top10 pack entries found; only one is supported \
             per origin. Merge the enable/posture/per_item settings into a single entry.",
            pack_indices.len()
        );
    }

    let raw_value = policies.remove(pack_indices[0]);
    let raw: RawPackConfig = serde_json::from_value(raw_value).map_err(|e| {
        anyhow::anyhow!("origin '{hostname}': owasp_api_top10 pack config failed to parse: {e}")
    })?;

    let enabled_items = parse_enable(hostname, &raw.enable)?;
    let enabled_set: HashSet<PackItem> = enabled_items.iter().copied().collect();

    let pack_posture = match &raw.posture {
        Some(s) => PackPosture::parse(s).ok_or_else(|| {
            anyhow::anyhow!(
                "origin '{hostname}': owasp_api_top10 posture {s:?} is not valid; use \
                 \"enforce\" or \"report_only\""
            )
        })?,
        None => PackPosture::ReportOnly,
    };

    let mut per_item_posture: HashMap<PackItem, PackPosture> = HashMap::new();
    let mut api3_response_exclude_fields: Option<Vec<String>> = None;
    for (key, entry) in &raw.per_item {
        let item = parse_item_or_bail(hostname, key, "per_item")?;
        if !enabled_set.contains(&item) {
            anyhow::bail!(
                "origin '{hostname}': owasp_api_top10 per_item.{key} overrides an item that is \
                 not enabled; add {} to enable (or use enable: all) first, or remove this \
                 override",
                item.canonical_name()
            );
        }
        if let Some(posture_raw) = &entry.posture {
            let posture = PackPosture::parse(posture_raw).ok_or_else(|| {
                anyhow::anyhow!(
                    "origin '{hostname}': owasp_api_top10 per_item.{key}.posture {posture_raw:?} \
                     is not valid; use \"enforce\" or \"report_only\""
                )
            })?;
            per_item_posture.insert(item, posture);
        }
        if let Some(fields) = &entry.response_exclude_fields {
            if item != PackItem::Api3 {
                anyhow::bail!(
                    "origin '{hostname}': owasp_api_top10 per_item.{key}.response_exclude_fields \
                     is only valid for api3; {} does not accept it",
                    item.canonical_name()
                );
            }
            if fields.is_empty() {
                anyhow::bail!(
                    "origin '{hostname}': owasp_api_top10 per_item.api3.response_exclude_fields \
                     must not be empty; omit the key entirely to leave the response side \
                     unsynthesized"
                );
            }
            api3_response_exclude_fields = Some(fields.clone());
        }
    }

    // Snapshot of type strings the OPERATOR already authored, taken
    // before any pack synthesis runs. This is what distinguishes "the
    // operator wrote this, back off entirely"
    // (`PackItemState::OperatorAuthored`) from "an earlier item in this
    // same pack run already synthesized this" (`api1`/`api5` sharing
    // `object_authz`: the second item's row must not add a duplicate,
    // but the pack, not the operator, is the reason).
    let operator_authored_types: HashSet<String> = policies
        .iter()
        .filter_map(|p| p.get("type").and_then(|v| v.as_str()).map(str::to_string))
        .collect();
    let mut pack_synthesized_types: HashSet<&'static str> = HashSet::new();

    let mut entries = Vec::with_capacity(enabled_items.len());
    for item in PackItem::ALL {
        if !enabled_set.contains(&item) {
            continue;
        }

        // api3 and api9 do not fit the ItemRow/SynthPiece table (see
        // both functions' doc comments): resolve them directly and
        // skip the generic per-row machinery below entirely.
        if item == PackItem::Api3 {
            entries.push(expand_api3_entry(
                &operator_authored_types,
                api3_response_exclude_fields.as_deref(),
                transforms,
            ));
            continue;
        }
        if item == PackItem::Api9 {
            let was_already_true = *expose_openapi;
            if !was_already_true {
                *expose_openapi = true;
            }
            entries.push(expand_api9_entry(was_already_true));
            continue;
        }

        let row = item_row(item).ok_or_else(|| {
            anyhow::anyhow!(
                "internal error: owasp_api_top10 has no ITEM_TABLE row for {item:?}; this is a \
                 bug in sbproxy-config, not a config error"
            )
        })?;
        let resolved_posture = per_item_posture.get(&item).copied().unwrap_or(pack_posture);

        if row.pieces.is_empty() {
            let entry = match row.already_enforced_reason {
                Some(reason) => PackManifestEntry {
                    item,
                    state: PackItemState::Enforced,
                    reason: reason.to_string(),
                    synthesized_types: Vec::new(),
                },
                None => PackManifestEntry {
                    item,
                    state: PackItemState::NotCovered,
                    reason: row.uncovered_reason.to_string(),
                    synthesized_types: Vec::new(),
                },
            };
            entries.push(entry);
            continue;
        }

        let mut synthesized_types = Vec::new();
        let mut fragments: Vec<String> = Vec::new();
        let mut any_operator_backoff = false;
        let mut any_present = false;

        for piece in row.pieces {
            let operator_hit = piece
                .backoff_types
                .iter()
                .any(|t| operator_authored_types.contains(*t));
            if operator_hit {
                any_operator_backoff = true;
                fragments.push(piece.operator_backoff_reason.to_string());
                continue;
            }
            let shared_hit = piece
                .backoff_types
                .iter()
                .any(|t| pack_synthesized_types.contains(t));
            if shared_hit {
                any_present = true;
                if let Some(reason) = piece.shared_backoff_reason {
                    fragments.push(reason.to_string());
                }
                continue;
            }
            let synthesis = (piece.synth)(resolved_posture);
            policies.push(synthesis.policy);
            pack_synthesized_types.insert(synthesis.synthesized_type);
            synthesized_types.push(synthesis.synthesized_type);
            fragments.push(synthesis.reason);
            any_present = true;
        }

        let state = if any_present {
            row.covered_state
        } else {
            debug_assert!(
                any_operator_backoff,
                "a non-empty pieces list must either synthesize/share something or back off"
            );
            PackItemState::OperatorAuthored
        };
        entries.push(PackManifestEntry {
            item,
            state,
            reason: fragments.join(" "),
            synthesized_types,
        });
    }

    Ok(Some(PackManifest {
        entries,
        posture: pack_posture,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owasp_policy(json: serde_json::Value) -> Vec<serde_json::Value> {
        vec![json]
    }

    #[test]
    fn no_pack_entry_returns_none_and_leaves_policies_untouched() {
        let mut policies = vec![serde_json::json!({"type": "rate_limiting"})];
        let manifest =
            expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false).expect("expand");
        assert!(manifest.is_none());
        assert_eq!(policies.len(), 1);
    }

    #[test]
    fn unknown_item_name_in_enable_is_refused_with_accepted_list() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api1", "api99"],
        }));
        let err = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("api99"), "names the bad value: {err}");
        assert!(err.contains("api1, api2"), "lists accepted names: {err}");
        assert!(err.contains("api10"), "accepted list reaches api10: {err}");
    }

    #[test]
    fn unknown_item_name_in_per_item_is_refused_with_accepted_list() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api1"],
            "per_item": {"api99": {"posture": "enforce"}},
        }));
        let err = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("api99"));
        assert!(err.contains("api1, api2"));
    }

    #[test]
    fn duplicate_item_in_enable_list_is_refused() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api1", "api1"],
        }));
        let err = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("more than once"), "{err}");
        assert!(err.contains("api1"), "{err}");
    }

    #[test]
    fn duplicate_pack_policy_entries_are_refused() {
        let mut policies = vec![
            serde_json::json!({"type": "owasp_api_top10", "enable": ["api1"]}),
            serde_json::json!({"type": "owasp_api_top10", "enable": ["api4"]}),
        ];
        let err = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("owasp_api_top10 pack entries found"), "{err}");
    }

    #[test]
    fn per_item_override_for_a_non_enabled_item_is_refused() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api1"],
            "per_item": {"api4": {"posture": "enforce"}},
        }));
        let err = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not enabled"), "{err}");
        assert!(err.contains("api4"), "{err}");
    }

    #[test]
    fn invalid_posture_value_is_refused() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api1"],
            "posture": "blocking",
        }));
        let err = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("blocking"), "{err}");
    }

    #[test]
    fn pack_entry_is_removed_from_policies() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api1"],
        }));
        expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false).expect("expand");
        assert!(
            !policies
                .iter()
                .any(|p| config_type_is(p, "owasp_api_top10")),
            "pack entry must be consumed, not passed through"
        );
    }

    #[test]
    fn api1_synthesizes_object_authz_report_only_test_mode_by_default() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api1"],
        }));
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .expect("expand")
            .expect("some");
        let entry = manifest.entry_for(PackItem::Api1).expect("api1 entry");
        // Ruling (plan ledger): api1's state is always
        // needs_operator_input, not enforced/report_only, since empty
        // object_rules means no real ownership check runs either way.
        assert_eq!(entry.state, PackItemState::NeedsOperatorInput);
        assert_eq!(entry.synthesized_types, vec!["object_authz"]);

        let synthesized = policies
            .iter()
            .find(|&p| config_type_is(p, "object_authz"))
            .expect("synthesized object_authz present");
        assert_eq!(
            synthesized.get("test_mode").and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn posture_enforce_threads_test_mode_false_into_synthesized_object_authz() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api1"],
            "posture": "enforce",
        }));
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .expect("expand")
            .expect("some");
        let entry = manifest.entry_for(PackItem::Api1).expect("api1 entry");
        // The state stays needs_operator_input regardless of posture;
        // only the synthesized JSON's test_mode field moves.
        assert_eq!(entry.state, PackItemState::NeedsOperatorInput);

        let synthesized = policies
            .iter()
            .find(|&p| config_type_is(p, "object_authz"))
            .expect("synthesized object_authz present");
        assert_eq!(
            synthesized.get("test_mode").and_then(|v| v.as_bool()),
            Some(false)
        );
    }

    #[test]
    fn per_item_posture_override_wins_over_pack_posture() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api1"],
            "posture": "report_only",
            "per_item": {"api1": {"posture": "enforce"}},
        }));
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .expect("expand")
            .expect("some");
        let entry = manifest.entry_for(PackItem::Api1).expect("api1 entry");
        assert_eq!(entry.state, PackItemState::NeedsOperatorInput);

        // The override's effect is visible on the synthesized JSON,
        // not on the (posture-independent) manifest state for api1.
        let synthesized = policies
            .iter()
            .find(|&p| config_type_is(p, "object_authz"))
            .expect("synthesized object_authz present");
        assert_eq!(
            synthesized.get("test_mode").and_then(|v| v.as_bool()),
            Some(false),
            "per_item override (enforce) must win over the pack-wide report_only default"
        );
    }

    #[test]
    fn back_off_when_operator_already_authored_object_authz() {
        let mut policies = vec![
            serde_json::json!({"type": "owasp_api_top10", "enable": ["api1"]}),
            serde_json::json!({
                "type": "object_authz",
                "test_mode": false,
                "object_rules": [],
            }),
        ];
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .expect("expand")
            .expect("some");
        let entry = manifest.entry_for(PackItem::Api1).expect("api1 entry");
        assert_eq!(entry.state, PackItemState::OperatorAuthored);
        assert!(entry.synthesized_types.is_empty());

        let object_authz_count = policies
            .iter()
            .filter(|p| config_type_is(p, "object_authz"))
            .count();
        assert_eq!(object_authz_count, 1, "no second object_authz was added");
    }

    #[test]
    fn back_off_also_recognises_the_bola_alias() {
        let mut policies = vec![
            serde_json::json!({"type": "owasp_api_top10", "enable": ["api1"]}),
            serde_json::json!({"type": "bola", "object_rules": []}),
        ];
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .expect("expand")
            .expect("some");
        let entry = manifest.entry_for(PackItem::Api1).expect("api1 entry");
        assert_eq!(entry.state, PackItemState::OperatorAuthored);
    }

    #[test]
    fn enable_all_covers_every_item() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": "all",
        }));
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .expect("expand")
            .expect("some");
        assert_eq!(manifest.entries.len(), 10);
        for item in PackItem::ALL {
            assert!(
                manifest.entry_for(item).is_some(),
                "{item:?} missing from manifest"
            );
        }
    }

    #[test]
    fn manifest_posture_defaults_to_report_only() {
        // WOR-2491 task 4: the manifest admin endpoint and `sbproxy
        // plan` both surface this field per origin.
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api1"],
        }));
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .expect("expand")
            .expect("some");
        assert_eq!(manifest.posture, PackPosture::ReportOnly);
        assert_eq!(manifest.posture.label(), "report_only");
    }

    #[test]
    fn manifest_posture_reflects_explicit_pack_wide_value() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api1"],
            "posture": "enforce",
        }));
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .expect("expand")
            .expect("some");
        assert_eq!(manifest.posture, PackPosture::Enforce);
        assert_eq!(manifest.posture.label(), "enforce");
    }

    #[test]
    fn item_titles_match_official_owasp_2023_names() {
        // Pinned verbatim (WOR-2491 task 4): the manifest admin
        // endpoint contract and `sbproxy plan`'s text renderer both
        // surface these exact strings.
        let expected = [
            (PackItem::Api1, "Broken Object Level Authorization"),
            (PackItem::Api2, "Broken Authentication"),
            (PackItem::Api3, "Broken Object Property Level Authorization"),
            (PackItem::Api4, "Unrestricted Resource Consumption"),
            (PackItem::Api5, "Broken Function Level Authorization"),
            (
                PackItem::Api6,
                "Unrestricted Access to Sensitive Business Flows",
            ),
            (PackItem::Api7, "Server Side Request Forgery"),
            (PackItem::Api8, "Security Misconfiguration"),
            (PackItem::Api9, "Improper Inventory Management"),
            (PackItem::Api10, "Unsafe Consumption of APIs"),
        ];
        for (item, title) in expected {
            assert_eq!(item.title(), title, "{item:?}");
        }
    }

    #[test]
    fn item_state_labels_match_the_manifest_endpoint_contract() {
        let expected = [
            (PackItemState::Enforced, "enforced"),
            (PackItemState::ReportOnly, "report_only"),
            (PackItemState::OperatorAuthored, "operator_authored"),
            (PackItemState::NeedsOperatorInput, "needs_operator_input"),
            (PackItemState::NotCovered, "not_covered"),
        ];
        for (state, label) in expected {
            assert_eq!(state.label(), label, "{state:?}");
        }
    }

    #[test]
    fn items_with_no_synthesis_report_not_covered() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api2"],
        }));
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .expect("expand")
            .expect("some");
        let entry = manifest.entry_for(PackItem::Api2).expect("api2 entry");
        assert_eq!(entry.state, PackItemState::NotCovered);
        assert!(entry.synthesized_types.is_empty());
        assert!(!policies.iter().any(|p| p.get("type").is_some()));
    }

    #[test]
    fn item_parse_is_case_insensitive() {
        assert_eq!(PackItem::parse("API1"), Some(PackItem::Api1));
        assert_eq!(PackItem::parse("Api10"), Some(PackItem::Api10));
        assert_eq!(PackItem::parse("api11"), None);
    }

    // --- WOR-2491 task 2: api4, api5, api7, api8 ---

    #[test]
    fn api4_synthesizes_all_four_pieces_enforced_when_nothing_authored() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api4"],
        }));
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .expect("expand")
            .expect("some");
        let entry = manifest.entry_for(PackItem::Api4).expect("api4 entry");
        assert_eq!(entry.state, PackItemState::Enforced);
        let mut types = entry.synthesized_types.clone();
        types.sort_unstable();
        assert_eq!(
            types,
            vec![
                "concurrent_limit",
                "ddos_protection",
                "rate_limiting",
                "request_limit",
            ]
        );

        let request_limit = policies
            .iter()
            .find(|p| config_type_is(p, "request_limit"))
            .expect("request_limit present");
        assert_eq!(
            request_limit.get("max_body_size").and_then(|v| v.as_u64()),
            Some(1_048_576)
        );
        assert_eq!(
            request_limit
                .get("max_header_count")
                .and_then(|v| v.as_u64()),
            Some(64)
        );
        assert_eq!(
            request_limit.get("max_url_length").and_then(|v| v.as_u64()),
            Some(2048)
        );

        let rate_limiting = policies
            .iter()
            .find(|p| config_type_is(p, "rate_limiting"))
            .expect("rate_limiting present");
        assert_eq!(
            rate_limiting
                .get("requests_per_second")
                .and_then(|v| v.as_f64()),
            Some(100.0)
        );
        assert_eq!(
            rate_limiting.get("burst").and_then(|v| v.as_u64()),
            Some(200)
        );

        let concurrent_limit = policies
            .iter()
            .find(|p| config_type_is(p, "concurrent_limit"))
            .expect("concurrent_limit present");
        assert_eq!(
            concurrent_limit.get("max").and_then(|v| v.as_u64()),
            Some(200)
        );

        assert!(
            policies
                .iter()
                .any(|p| config_type_is(p, "ddos_protection")),
            "ddos_protection present"
        );
    }

    #[test]
    fn api4_partial_backoff_when_operator_authors_one_subpolicy() {
        let mut policies = vec![
            serde_json::json!({"type": "owasp_api_top10", "enable": ["api4"]}),
            serde_json::json!({"type": "rate_limiting", "requests_per_second": 5.0}),
        ];
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .expect("expand")
            .expect("some");
        let entry = manifest.entry_for(PackItem::Api4).expect("api4 entry");
        // Some pieces still synthesized, so the item as a whole is
        // still Enforced, not OperatorAuthored.
        assert_eq!(entry.state, PackItemState::Enforced);
        let mut types = entry.synthesized_types.clone();
        types.sort_unstable();
        assert_eq!(
            types,
            vec!["concurrent_limit", "ddos_protection", "request_limit"],
            "rate_limiting is excluded: the operator's own entry stands"
        );
        assert!(
            entry.reason.contains("already authors a rate_limiting"),
            "the manifest reason names the partial back-off: {}",
            entry.reason
        );

        let rate_limiting_entries: Vec<_> = policies
            .iter()
            .filter(|p| config_type_is(p, "rate_limiting"))
            .collect();
        assert_eq!(
            rate_limiting_entries.len(),
            1,
            "no second rate_limiting was added"
        );
        assert_eq!(
            rate_limiting_entries[0]
                .get("requests_per_second")
                .and_then(|v| v.as_f64()),
            Some(5.0),
            "the operator's own rate_limiting is untouched"
        );
    }

    #[test]
    fn api4_backs_off_entirely_when_operator_authors_all_four() {
        let mut policies = vec![
            serde_json::json!({"type": "owasp_api_top10", "enable": ["api4"]}),
            serde_json::json!({"type": "request_limit"}),
            serde_json::json!({"type": "rate_limiting"}),
            serde_json::json!({"type": "concurrent_limit", "max": 10}),
            serde_json::json!({"type": "ddos"}),
        ];
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .expect("expand")
            .expect("some");
        let entry = manifest.entry_for(PackItem::Api4).expect("api4 entry");
        assert_eq!(entry.state, PackItemState::OperatorAuthored);
        assert!(entry.synthesized_types.is_empty());
    }

    #[test]
    fn api5_alone_synthesizes_its_own_entry_with_empty_function_rules() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api5"],
        }));
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .expect("expand")
            .expect("some");
        let entry = manifest.entry_for(PackItem::Api5).expect("api5 entry");
        assert_eq!(entry.state, PackItemState::NeedsOperatorInput);
        assert_eq!(entry.synthesized_types, vec!["object_authz"]);

        let object_authz_entries: Vec<_> = policies
            .iter()
            .filter(|p| config_type_is(p, "object_authz"))
            .collect();
        assert_eq!(object_authz_entries.len(), 1);
        assert_eq!(
            object_authz_entries[0]
                .get("function_rules")
                .and_then(|v| v.as_array())
                .map(|a| a.len()),
            Some(0)
        );
        // api5 alone must not also enable api1's enumeration block; that
        // is api1's own concern, added only when api1 is also enabled.
        assert!(object_authz_entries[0].get("enumeration").is_none());
    }

    #[test]
    fn api1_and_api5_share_one_object_authz_entry_not_two() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api1", "api5"],
        }));
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .expect("expand")
            .expect("some");

        let object_authz_entries: Vec<_> = policies
            .iter()
            .filter(|p| config_type_is(p, "object_authz"))
            .collect();
        assert_eq!(
            object_authz_entries.len(),
            1,
            "api1 and api5 must share one object_authz entry, not two"
        );

        let api1_entry = manifest.entry_for(PackItem::Api1).expect("api1 entry");
        assert_eq!(api1_entry.state, PackItemState::NeedsOperatorInput);
        assert_eq!(api1_entry.synthesized_types, vec!["object_authz"]);

        let api5_entry = manifest.entry_for(PackItem::Api5).expect("api5 entry");
        assert_eq!(api5_entry.state, PackItemState::NeedsOperatorInput);
        assert!(
            api5_entry.synthesized_types.is_empty(),
            "api5's row did not add the entry itself, api1's did: {:?}",
            api5_entry.synthesized_types
        );
        assert!(
            api5_entry.reason.contains("shares the object_authz entry"),
            "{}",
            api5_entry.reason
        );
    }

    #[test]
    fn api5_backs_off_when_operator_already_authors_object_authz() {
        let mut policies = vec![
            serde_json::json!({"type": "owasp_api_top10", "enable": ["api1", "api5"]}),
            serde_json::json!({"type": "object_authz", "function_rules": []}),
        ];
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .expect("expand")
            .expect("some");
        assert_eq!(
            manifest.entry_for(PackItem::Api1).unwrap().state,
            PackItemState::OperatorAuthored
        );
        assert_eq!(
            manifest.entry_for(PackItem::Api5).unwrap().state,
            PackItemState::OperatorAuthored
        );
        let object_authz_count = policies
            .iter()
            .filter(|p| config_type_is(p, "object_authz"))
            .count();
        assert_eq!(object_authz_count, 1, "no synthesized entry was added");
    }

    #[test]
    fn api7_reports_enforced_with_nothing_synthesized() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api7"],
        }));
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .expect("expand")
            .expect("some");
        let entry = manifest.entry_for(PackItem::Api7).expect("api7 entry");
        assert_eq!(entry.state, PackItemState::Enforced);
        assert!(entry.synthesized_types.is_empty());
        assert!(
            entry.reason.contains("not a policy this pack can toggle"),
            "{}",
            entry.reason
        );
        assert!(
            policies.is_empty(),
            "api7 adds nothing to the policy chain: {policies:?}"
        );
    }

    #[test]
    fn api8_synthesizes_security_headers_and_http_framing_enforced() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api8"],
        }));
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .expect("expand")
            .expect("some");
        let entry = manifest.entry_for(PackItem::Api8).expect("api8 entry");
        assert_eq!(entry.state, PackItemState::Enforced);
        let mut types = entry.synthesized_types.clone();
        types.sort_unstable();
        assert_eq!(types, vec!["http_framing", "security_headers"]);

        let headers = policies
            .iter()
            .find(|p| config_type_is(p, "security_headers"))
            .and_then(|p| p.get("headers"))
            .and_then(|v| v.as_array())
            .expect("security_headers.headers present");
        let names: Vec<&str> = headers
            .iter()
            .filter_map(|h| h.get("name").and_then(|n| n.as_str()))
            .collect();
        assert!(names.contains(&"X-Content-Type-Options"));
        assert!(names.contains(&"X-Frame-Options"));
        assert!(names.contains(&"Referrer-Policy"));
        assert!(
            policies.iter().any(|p| config_type_is(p, "http_framing")),
            "http_framing present"
        );
    }

    #[test]
    fn api8_partial_backoff_when_operator_authors_security_headers() {
        let mut policies = vec![
            serde_json::json!({"type": "owasp_api_top10", "enable": ["api8"]}),
            serde_json::json!({"type": "security_headers", "headers": []}),
        ];
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .expect("expand")
            .expect("some");
        let entry = manifest.entry_for(PackItem::Api8).expect("api8 entry");
        assert_eq!(entry.state, PackItemState::Enforced);
        assert_eq!(entry.synthesized_types, vec!["http_framing"]);

        let security_headers_entries: Vec<_> = policies
            .iter()
            .filter(|p| config_type_is(p, "security_headers"))
            .collect();
        assert_eq!(security_headers_entries.len(), 1);
        assert_eq!(
            security_headers_entries[0]
                .get("headers")
                .and_then(|v| v.as_array())
                .map(|a| a.len()),
            Some(0),
            "the operator's own (empty) security_headers is untouched"
        );
    }

    // --- WOR-2491 task 3: api3, api9 ---

    #[test]
    fn api3_needs_operator_input_when_nothing_is_configured() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api3"],
        }));
        let mut transforms = Vec::new();
        let manifest = expand_owasp_pack("h", &mut policies, &mut transforms, &mut false)
            .expect("expand")
            .expect("some");
        let entry = manifest.entry_for(PackItem::Api3).expect("api3 entry");
        assert_eq!(entry.state, PackItemState::NeedsOperatorInput);
        assert!(entry.synthesized_types.is_empty());
        assert!(
            entry
                .reason
                .contains("no openapi_validation or request_validator"),
            "names the request-side gap: {}",
            entry.reason
        );
        assert!(
            entry.reason.contains("json_projection"),
            "names the existing response-side transform by config type, not \"no capability\": {}",
            entry.reason
        );
        assert!(transforms.is_empty(), "nothing synthesized: {transforms:?}");
    }

    #[test]
    fn api3_request_side_backs_off_when_openapi_validation_already_authored() {
        let mut policies = vec![
            serde_json::json!({"type": "owasp_api_top10", "enable": ["api3"]}),
            serde_json::json!({
                "type": "openapi_validation",
                "spec": {"openapi": "3.0.0"},
            }),
        ];
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .expect("expand")
            .expect("some");
        let entry = manifest.entry_for(PackItem::Api3).expect("api3 entry");
        // No response_exclude_fields supplied, so the item as a whole
        // still needs operator input (the response half), even though
        // the request half is covered by the operator's own policy.
        assert_eq!(entry.state, PackItemState::NeedsOperatorInput);
        assert!(
            entry
                .reason
                .contains("origin already authors openapi_validation"),
            "{}",
            entry.reason
        );
    }

    #[test]
    fn api3_request_side_backs_off_when_request_validator_already_authored() {
        let mut policies = vec![
            serde_json::json!({"type": "owasp_api_top10", "enable": ["api3"]}),
            serde_json::json!({
                "type": "request_validator",
                "schema": {"type": "object"},
            }),
        ];
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .expect("expand")
            .expect("some");
        let entry = manifest.entry_for(PackItem::Api3).expect("api3 entry");
        assert!(
            entry
                .reason
                .contains("origin already authors openapi_validation"),
            "same shared fragment covers both policy types: {}",
            entry.reason
        );
    }

    #[test]
    fn api3_synthesizes_json_projection_transform_when_exclude_fields_supplied() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api3"],
            "per_item": {
                "api3": {"response_exclude_fields": ["ssn", "internal_notes"]},
            },
        }));
        let mut transforms = Vec::new();
        let manifest = expand_owasp_pack("h", &mut policies, &mut transforms, &mut false)
            .expect("expand")
            .expect("some");
        let entry = manifest.entry_for(PackItem::Api3).expect("api3 entry");
        // Response side alone is real, unconditional coverage, so the
        // item reports Enforced even with no request-side policy
        // configured; the reason still names that gap explicitly.
        assert_eq!(entry.state, PackItemState::Enforced);
        assert_eq!(entry.synthesized_types, vec!["json_projection"]);
        assert!(
            entry
                .reason
                .contains("no openapi_validation or request_validator"),
            "request-side gap still named even though state is Enforced: {}",
            entry.reason
        );

        let projection = transforms
            .iter()
            .find(|t| config_type_is(t, "json_projection"))
            .expect("synthesized json_projection present");
        assert_eq!(
            projection.get("exclude").and_then(|v| v.as_bool()),
            Some(true)
        );
        let fields: Vec<&str> = projection
            .get("fields")
            .and_then(|v| v.as_array())
            .expect("fields array")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(fields, vec!["ssn", "internal_notes"]);

        // The pack policy entry must be removed and no policy-chain
        // entry added: this is a transform, not a policy.
        assert!(policies.is_empty(), "{policies:?}");
    }

    #[test]
    fn api3_response_exclude_fields_rejected_on_a_different_item() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api1"],
            "per_item": {
                "api1": {"response_exclude_fields": ["ssn"]},
            },
        }));
        let err = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("only valid for api3"), "{err}");
    }

    #[test]
    fn api3_response_exclude_fields_rejected_when_empty() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api3"],
            "per_item": {
                "api3": {"response_exclude_fields": []},
            },
        }));
        let err = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("must not be empty"), "{err}");
    }

    #[test]
    fn api9_sets_expose_openapi_true_when_absent() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api9"],
        }));
        let mut expose_openapi = false;
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut expose_openapi)
            .expect("expand")
            .expect("some");
        assert!(expose_openapi, "api9 must flip expose_openapi to true");
        let entry = manifest.entry_for(PackItem::Api9).expect("api9 entry");
        assert_eq!(entry.state, PackItemState::Enforced);
        assert!(entry.synthesized_types.is_empty());
        assert!(
            entry.reason.contains("set expose_openapi: true"),
            "{}",
            entry.reason
        );
        assert!(
            entry.reason.contains("route-shape-disclosure"),
            "names the real tradeoff, not a free win: {}",
            entry.reason
        );
    }

    #[test]
    fn api9_backs_off_reason_when_expose_openapi_already_true() {
        let mut policies = owasp_policy(serde_json::json!({
            "type": "owasp_api_top10",
            "enable": ["api9"],
        }));
        let mut expose_openapi = true;
        let manifest = expand_owasp_pack("h", &mut policies, &mut Vec::new(), &mut expose_openapi)
            .expect("expand")
            .expect("some");
        assert!(expose_openapi, "must stay true");
        let entry = manifest.entry_for(PackItem::Api9).expect("api9 entry");
        assert_eq!(entry.state, PackItemState::Enforced);
        assert!(
            entry
                .reason
                .contains("origin already sets expose_openapi: true"),
            "{}",
            entry.reason
        );
    }
}
